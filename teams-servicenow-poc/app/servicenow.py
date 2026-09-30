import json
import logging
import os
import re
import time
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

from app.servicenow_errors import (
    ServiceNowErrorCategory,
    category_for_status,
    write_possibly_applied,
)

load_dotenv()

logger = logging.getLogger(__name__)


class ServiceNowError(Exception):
    """
    ServiceNow transport failure.

    DEMO-02: ``category`` classifies the failure (``None`` = unclassified).
    ``possibly_applied`` is True only when a write request was sent and its
    outcome could not be confirmed.  Messages are fixed text — never response
    bodies, URLs, headers or tokens.
    """

    category: Optional[ServiceNowErrorCategory] = None

    def __init__(
        self,
        message: str = "ServiceNow request failed",
        *,
        category: Optional[ServiceNowErrorCategory] = None,
        possibly_applied: bool = False,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        if category is not None:
            self.category = category
        self.possibly_applied = possibly_applied
        self.status_code = status_code


class ServiceNowNotFound(ServiceNowError):
    """Raised when the requested incident does not exist in ServiceNow."""

    category = ServiceNowErrorCategory.NOT_FOUND


class ServiceNowUnavailable(ServiceNowError):
    category = ServiceNowErrorCategory.UNAVAILABLE


class ServiceNowTimeout(ServiceNowError):
    category = ServiceNowErrorCategory.TIMEOUT


class ServiceNowAuthError(ServiceNowError):
    category = ServiceNowErrorCategory.AUTH_FAILED


class ServiceNowForbidden(ServiceNowError):
    category = ServiceNowErrorCategory.FORBIDDEN


class ServiceNowRejected(ServiceNowError):
    category = ServiceNowErrorCategory.REJECTED


class ServiceNowRateLimited(ServiceNowError):
    category = ServiceNowErrorCategory.RATE_LIMITED


class ServiceNowServerError(ServiceNowError):
    category = ServiceNowErrorCategory.SERVER_ERROR


class ServiceNowInvalidResponse(ServiceNowError):
    category = ServiceNowErrorCategory.INVALID_RESPONSE


class ServiceNowUserNotFound(ServiceNowError):
    category = ServiceNowErrorCategory.NOT_FOUND


class ServiceNowAmbiguousUser(ServiceNowError):
    category = ServiceNowErrorCategory.REJECTED


class ServiceNowUserLookupFailed(ServiceNowError):
    category = ServiceNowErrorCategory.SERVER_ERROR


_ERROR_CLASSES: dict[ServiceNowErrorCategory, type[ServiceNowError]] = {
    cls.category: cls
    for cls in (ServiceNowNotFound, ServiceNowUnavailable, ServiceNowTimeout,
                ServiceNowAuthError, ServiceNowForbidden, ServiceNowRejected,
                ServiceNowRateLimited, ServiceNowServerError, ServiceNowInvalidResponse)
}

# Connect 10 s (unreachable instance fails fast), everything else 30 s.
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

_SYS_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_ITEM_REF_RE = re.compile(r"^CAT[0-9]{4}$")

# DEMO-06: real ServiceNow catalog item sys_ids for this instance, e.g.
#   SERVICENOW_CATALOG_SYS_IDS=CAT0001=<32-hex sys_id>,CAT0006=<32-hex sys_id>
# Items without an entry keep the fixture placeholder (ordering them fails
# safely with a controlled ❌ reply).
CATALOG_SYS_IDS_ENV = "SERVICENOW_CATALOG_SYS_IDS"


def catalog_sys_ids_from_env() -> dict[str, str]:
    """
    Validated ``item_ref`` → ``sys_id`` map from ``SERVICENOW_CATALOG_SYS_IDS``.
    Malformed entries are ignored and logged by position only.
    """
    raw = os.getenv(CATALOG_SYS_IDS_ENV, "") or ""
    mapping: dict[str, str] = {}
    for position, entry in enumerate(p for p in raw.split(",") if p.strip()):
        ref, sep, sys_id = (part.strip() for part in entry.partition("="))
        if sep and _ITEM_REF_RE.fullmatch(ref) and _SYS_ID_RE.fullmatch(sys_id):
            mapping[ref] = sys_id
        else:
            logger.warning("%s: ignored invalid entry at position %d",
                           CATALOG_SYS_IDS_ENV, position)
    return mapping


def _http_error(status_code: int, *, what: str, write_sent: bool) -> ServiceNowError:
    category = category_for_status(status_code)
    return _ERROR_CLASSES[category](
        f"{what} failed: HTTP {status_code}",
        possibly_applied=write_sent and write_possibly_applied(status_code),
        status_code=status_code,
    )


def _transport_error(exc: httpx.HTTPError, *, what: str, write_sent: bool) -> ServiceNowError:
    """
    Classify an httpx failure.  Connection-phase failures mean the request
    never reached ServiceNow; anything later leaves a write's outcome unknown.
    """
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
        return ServiceNowUnavailable(f"{what} failed: could not connect")
    if isinstance(exc, httpx.TimeoutException):
        return ServiceNowTimeout(f"{what} failed: timed out", possibly_applied=write_sent)
    return ServiceNowUnavailable(f"{what} failed: connection error", possibly_applied=write_sent)


# Incident numbers must be INC followed by exactly 7 to 10 digits.
_INCIDENT_NUMBER_RE = re.compile(r"^INC\d{7,10}$")


def _validate_incident_number(incident_number: str) -> str:
    """
    Normalise and validate a ServiceNow incident number.

    Strips whitespace and upper-cases the input so that values
    like 'inc0010002' are accepted, then verifies the format is
    INC followed by 7 to 10 digits.

    Returns the normalised value on success; raises ValueError
    on failure without echoing the raw user input into the message.
    """
    normalised = incident_number.strip().upper()
    if not _INCIDENT_NUMBER_RE.fullmatch(normalised):
        raise ValueError(
            "Incident number must be INC followed by 7 to 10 digits."
        )
    return normalised


class ServiceNowClient:
    def __init__(self):
        self.instance = os.getenv("SERVICENOW_INSTANCE")
        self.client_id = os.getenv("SERVICENOW_CLIENT_ID")
        self.client_secret = os.getenv("SERVICENOW_CLIENT_SECRET")

        if not self.instance:
            raise ValueError("SERVICENOW_INSTANCE is not configured")

        if not self.client_id:
            raise ValueError("SERVICENOW_CLIENT_ID is not configured")

        if not self.client_secret:
            raise ValueError("SERVICENOW_CLIENT_SECRET is not configured")

        self.instance = self.instance.rstrip("/")

        self._access_token: str | None = None
        self._token_expires_at: float = 0

        # Test seam only: an httpx transport (e.g. MockTransport).
        self._transport: httpx.AsyncBaseTransport | None = None

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, transport=self._transport)

    def _invalidate_token(self) -> None:
        self._access_token = None
        self._token_expires_at = 0

    async def _get_access_token(self) -> str:
        """
        Get a ServiceNow OAuth access token using
        the Client Credentials grant.
        """

        # Reuse existing token if it is still valid.
        if (
            self._access_token
            and time.time() < self._token_expires_at
        ):
            return self._access_token

        token_url = f"{self.instance}/oauth_token.do"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # Token failures happen before any business request is sent, so they
        # can never leave a write half-done (possibly_applied=False).
        try:
            async with self._http() as client:
                response = await client.post(
                    token_url,
                    data=data,
                )
        except httpx.HTTPError as exc:
            error = _transport_error(exc, what="ServiceNow OAuth", write_sent=False)
            logger.warning("servicenow oauth: %s", error.category.value)
            raise error from None

        if response.status_code != 200:
            status = response.status_code
            if status in (400, 401, 403):
                # Rejected credentials are an integration/configuration problem.
                error = ServiceNowAuthError(f"ServiceNow OAuth failed: HTTP {status}",
                                            status_code=status)
            else:
                error = _http_error(status, what="ServiceNow OAuth", write_sent=False)
            logger.warning("servicenow oauth: %s status=%d", error.category.value, status)
            raise error

        try:
            token_data = response.json()
        except ValueError:
            raise ServiceNowAuthError("ServiceNow OAuth response was not valid JSON") from None

        if not isinstance(token_data, dict):
            raise ServiceNowAuthError("ServiceNow OAuth response was not an object")

        access_token = token_data.get("access_token")
        try:
            expires_in = int(token_data.get("expires_in", 1800))
        except (TypeError, ValueError):
            expires_in = 1800

        if not access_token or not isinstance(access_token, str):
            raise ServiceNowAuthError(
                "ServiceNow OAuth response did not contain an access token"
            )

        self._access_token = access_token

        # Refresh slightly before actual expiry.
        self._token_expires_at = (
            time.time() + max(expires_in - 60, 60)
        )

        return access_token

    async def _request(
        self,
        method: str,
        url: str,
        *,
        write: bool = False,
        **kwargs: Any,
    ) -> dict:
        """
        Make an authenticated ServiceNow API request.

        DEMO-02: every failure is raised as a classified ``ServiceNowError``.
        *write* marks a side-effecting request, so failures after it was sent
        carry ``possibly_applied=True``.  Never retried here.
        """

        access_token = await self._get_access_token()

        headers = kwargs.pop("headers", {})

        headers.update(
            {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        try:
            async with self._http() as client:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    **kwargs,
                )
        except httpx.HTTPError as exc:
            error = _transport_error(exc, what="ServiceNow API", write_sent=write)
            logger.warning("servicenow %s: %s possibly_applied=%s",
                           method, error.category.value, error.possibly_applied)
            raise error from None

        if response.status_code >= 400:
            if response.status_code == 401:
                # Force a fresh token next time; this request is not retried.
                self._invalidate_token()
            error = _http_error(response.status_code, what="ServiceNow API", write_sent=write)
            logger.warning("servicenow %s: %s status=%d possibly_applied=%s",
                           method, error.category.value, response.status_code,
                           error.possibly_applied)
            raise error

        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            body = None
        if not isinstance(body, dict):
            logger.warning("servicenow %s: %s possibly_applied=%s", method,
                           ServiceNowErrorCategory.INVALID_RESPONSE.value, write)
            raise ServiceNowInvalidResponse("ServiceNow API returned an unexpected body",
                                            possibly_applied=write)
        return body

    @staticmethod
    def _record(body: dict, *, write: bool) -> dict:
        """The ``result`` object of a create/update response."""
        result = body.get("result")
        if not isinstance(result, dict):
            raise ServiceNowInvalidResponse("ServiceNow API result was not an object",
                                            possibly_applied=write)
        return result

    async def create_incident(
        self,
        short_description: str,
        description: str,
        impact: str = "3",
        urgency: str = "3",
    ) -> dict:
        """
        Create a ServiceNow incident.
        """

        url = f"{self.instance}/api/now/table/incident"

        payload = {
            "short_description": short_description,
            "description": description,
            "impact": impact,
            "urgency": urgency,
        }

        response = await self._request(
            "POST",
            url,
            write=True,
            json=payload,
        )

        return self._record(response, write=True)

    async def get_user_by_email_or_upn(
        self,
        email_or_upn: str,
    ) -> str:
        """
        Query sys_user table for an active user matching exact email or user_name (UPN).
        Returns the 32-character hex sys_id of the matching user.
        Raises ServiceNowUserNotFound, ServiceNowAmbiguousUser, or ServiceNowUserLookupFailed.
        """
        if not isinstance(email_or_upn, str) or not email_or_upn.strip():
            raise ServiceNowUserNotFound("No valid email or UPN provided")

        target = email_or_upn.strip()
        url = f"{self.instance}/api/now/table/sys_user"
        params = {
            "sysparm_query": f"active=true^email={target}^ORactive=true^user_name={target}",
            "sysparm_fields": "sys_id,user_name,email,active",
            "sysparm_limit": "2",
        }

        try:
            response = await self._request("GET", url, params=params)
        except ServiceNowError as exc:
            raise ServiceNowUserLookupFailed(
                f"ServiceNow user lookup failed: {exc}",
                status_code=getattr(exc, "status_code", None),
            ) from None

        results = response.get("result", [])
        if not isinstance(results, list):
            raise ServiceNowUserLookupFailed("ServiceNow user lookup result was not a list")

        if len(results) == 0:
            raise ServiceNowUserNotFound(f"User {target} not found in ServiceNow")

        if len(results) > 1:
            raise ServiceNowAmbiguousUser(f"Multiple active users found in ServiceNow for {target}")

        user_rec = results[0]
        if not isinstance(user_rec, dict):
            raise ServiceNowUserLookupFailed("ServiceNow user record was not an object")

        sys_id = user_rec.get("sys_id")
        if not isinstance(sys_id, str) or not _SYS_ID_RE.fullmatch(sys_id):
            raise ServiceNowUserLookupFailed("ServiceNow user record returned an invalid sys_id")

        return sys_id

    async def get_ritm_for_request(
        self,
        req_sys_id: str,
    ) -> dict:
        """
        Query sc_req_item table for the single RITM associated with a given sc_request sys_id.
        Validates req_sys_id as a strict 32-character hex string.
        Fails safely if 0 or >1 RITM records are returned.
        """
        if not isinstance(req_sys_id, str) or not _SYS_ID_RE.fullmatch(req_sys_id):
            raise ValueError("req_sys_id must be 32 lower-case hex characters.")

        url = f"{self.instance}/api/now/table/sc_req_item"
        params = {
            "sysparm_query": f"request={req_sys_id}",
            "sysparm_fields": "sys_id,number,opened_by,requested_for,request",
            "sysparm_limit": "2",
        }

        try:
            response = await self._request("GET", url, params=params)
        except ServiceNowError as exc:
            raise ServiceNowError(
                f"RITM lookup failed: {exc}",
                possibly_applied=True,
                status_code=getattr(exc, "status_code", None),
            ) from None

        results = response.get("result", [])
        if not isinstance(results, list):
            raise ServiceNowInvalidResponse("ServiceNow RITM lookup result was not a list", possibly_applied=True)

        if len(results) == 0:
            raise ServiceNowInvalidResponse(
                "Expected exactly one RITM record for request, but found 0",
                possibly_applied=True,
            )

        if len(results) > 1:
            raise ServiceNowInvalidResponse(
                "Expected exactly one RITM record for request, but found multiple",
                possibly_applied=True,
            )

        ritm_rec = results[0]
        if not isinstance(ritm_rec, dict):
            raise ServiceNowInvalidResponse("ServiceNow RITM record was not an object", possibly_applied=True)

        ritm_sys_id = ritm_rec.get("sys_id")
        if not isinstance(ritm_sys_id, str) or not _SYS_ID_RE.fullmatch(ritm_sys_id):
            raise ServiceNowInvalidResponse("ServiceNow RITM record returned an invalid sys_id", possibly_applied=True)

        return ritm_rec

    @staticmethod
    def _extract_field_value(body: dict, field_name: str) -> Optional[str]:
        result = body.get("result", {})
        if not isinstance(result, dict):
            return None
        raw = result.get(field_name)
        if isinstance(raw, dict):
            return raw.get("value")
        if isinstance(raw, str):
            return raw
        return None

    async def update_request_requested_for(
        self,
        req_sys_id: str,
        ritm_sys_id: str,
        requested_for_sys_id: str,
    ) -> None:
        """
        Execute post-creation PATCH on sc_request and sc_req_item to set requested_for.
        Validates all sys_ids as 32-character hex values.
        Performs read-only GET verification afterwards.
        Never retries on failure.
        """
        if not isinstance(req_sys_id, str) or not _SYS_ID_RE.fullmatch(req_sys_id):
            raise ValueError("req_sys_id must be 32 lower-case hex characters.")
        if not isinstance(ritm_sys_id, str) or not _SYS_ID_RE.fullmatch(ritm_sys_id):
            raise ValueError("ritm_sys_id must be 32 lower-case hex characters.")
        if not isinstance(requested_for_sys_id, str) or not _SYS_ID_RE.fullmatch(requested_for_sys_id):
            raise ValueError("requested_for_sys_id must be 32 lower-case hex characters.")

        # 1. PATCH sc_request
        req_url = f"{self.instance}/api/now/table/sc_request/{req_sys_id}"
        await self._request(
            "PATCH",
            req_url,
            write=True,
            json={"requested_for": requested_for_sys_id},
        )

        # 2. PATCH sc_req_item
        ritm_url = f"{self.instance}/api/now/table/sc_req_item/{ritm_sys_id}"
        await self._request(
            "PATCH",
            ritm_url,
            write=True,
            json={"requested_for": requested_for_sys_id},
        )

        # 3. Read-only GET verification
        req_check = await self._request(
            "GET",
            req_url,
            params={"sysparm_fields": "sys_id,requested_for"},
        )
        req_val = self._extract_field_value(req_check, "requested_for")

        ritm_check = await self._request(
            "GET",
            ritm_url,
            params={"sysparm_fields": "sys_id,requested_for"},
        )
        ritm_val = self._extract_field_value(ritm_check, "requested_for")

        if req_val != requested_for_sys_id or ritm_val != requested_for_sys_id:
            raise ServiceNowError(
                "requested_for verification failed",
                possibly_applied=True,
            )

    async def create_service_request(
        self,
        sys_id: str,
        variables: dict[str, str],
        requested_for_sys_id: str | None = None,
    ) -> dict:
        """
        Create a ServiceNow service catalog request.
        """
        if not isinstance(sys_id, str) or not _SYS_ID_RE.fullmatch(sys_id):
            raise ValueError("sys_id must be 32 lower-case hex characters.")
        if not isinstance(variables, dict):
            raise ValueError("variables must be a dict.")
        if requested_for_sys_id is not None:
            if not isinstance(requested_for_sys_id, str) or not _SYS_ID_RE.fullmatch(requested_for_sys_id):
                raise ValueError("requested_for_sys_id must be 32 lower-case hex characters.")

        url = f"{self.instance}/api/sn_sc/v1/servicecatalog/items/{sys_id}/order_now"

        payload: dict[str, Any] = {
            "sysparm_quantity": "1",
            "variables": variables,
        }

        response = await self._request(
            "POST",
            url,
            write=True,
            json=payload,
        )

        record = self._record(response, write=True)

        if requested_for_sys_id is not None:
            req_sys_id = record.get("sys_id") or record.get("request_id")
            if not isinstance(req_sys_id, str) or not _SYS_ID_RE.fullmatch(req_sys_id):
                raise ServiceNowInvalidResponse(
                    "ServiceNow order_now response returned an invalid sys_id",
                    possibly_applied=True,
                )

            ritm_rec = await self.get_ritm_for_request(req_sys_id)
            ritm_sys_id = ritm_rec.get("sys_id")
            ritm_number = ritm_rec.get("number")

            await self.update_request_requested_for(
                req_sys_id=req_sys_id,
                ritm_sys_id=ritm_sys_id,
                requested_for_sys_id=requested_for_sys_id,
            )

            record["ritm_number"] = ritm_number
            record["ritm_sys_id"] = ritm_sys_id
            record["requested_for_sys_id"] = requested_for_sys_id

        return record

    async def get_incident(
        self,
        incident_number: str,
    ) -> dict:
        """
        Find an incident using its incident number.

        The incident number is normalised (strip + upper-case) and
        validated before any network request is made.
        """

        normalised = _validate_incident_number(incident_number)

        url = f"{self.instance}/api/now/table/incident"

        params = {
            "sysparm_query": f"number={normalised}",
            "sysparm_fields": "sys_id,number,short_description,state,impact,urgency,priority",
            "sysparm_limit": "1",
        }

        response = await self._request(
            "GET",
            url,
            params=params,
        )

        results = response.get("result", [])

        if not isinstance(results, list):
            raise ServiceNowInvalidResponse("ServiceNow lookup result was not a list")

        if not results:
            raise ServiceNowNotFound(
                "The requested incident was not found."
            )

        if not isinstance(results[0], dict):
            raise ServiceNowInvalidResponse("ServiceNow lookup record was not an object")

        return results[0]

    async def update_incident(
        self,
        incident_number: str,
        fields: dict,
    ) -> dict:
        """
        Update an existing incident using its incident number.

        The incident number is normalised and validated before any
        network request is made.  Only explicitly allowed fields
        are accepted.
        """

        # Validate and normalise before touching ServiceNow.
        normalised = _validate_incident_number(incident_number)

        allowed_fields = {
            "short_description",
            "description",
            "impact",
            "urgency",
        }

        payload = {
            key: value
            for key, value in fields.items()
            if key in allowed_fields and value is not None
        }

        if not payload:
            raise ServiceNowError(
                "No valid fields were provided for update"
            )

        # get_incident also validates, but we pass the already-normalised
        # value so no double-normalisation ambiguity exists.
        incident = await self.get_incident(normalised)

        # The sys_id comes from ServiceNow; it must be a plain 32-hex id
        # before it is placed in a URL path.  Nothing has been written yet.
        sys_id = incident.get("sys_id")
        if not isinstance(sys_id, str) or not _SYS_ID_RE.fullmatch(sys_id):
            raise ServiceNowInvalidResponse("ServiceNow lookup returned an invalid sys_id")

        url = (
            f"{self.instance}/api/now/table/incident/{sys_id}"
        )

        response = await self._request(
            "PATCH",
            url,
            write=True,
            json=payload,
        )

        return self._record(response, write=True)
