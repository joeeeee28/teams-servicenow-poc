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

    async def create_service_request(
        self,
        sys_id: str,
        variables: dict[str, str],
    ) -> dict:
        """
        Create a ServiceNow service catalog request.
        """
        if not isinstance(sys_id, str) or not _SYS_ID_RE.fullmatch(sys_id):
            raise ValueError("sys_id must be 32 lower-case hex characters.")
        if not isinstance(variables, dict):
            raise ValueError("variables must be a dict.")

        url = f"{self.instance}/api/sn_sc/v1/servicecatalog/items/{sys_id}/order_now"

        payload = {
            "sysparm_quantity": "1",
            "variables": variables,
        }

        response = await self._request(
            "POST",
            url,
            write=True,
            json=payload,
        )

        return self._record(response, write=True)

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
