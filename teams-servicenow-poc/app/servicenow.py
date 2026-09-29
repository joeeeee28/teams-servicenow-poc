import logging
import os
import re
import time
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class ServiceNowError(Exception):
    pass


class ServiceNowNotFound(ServiceNowError):
    """Raised when the requested incident does not exist in ServiceNow."""
    pass


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

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                token_url,
                data=data,
            )

        if response.status_code != 200:
            raise ServiceNowError(
                f"ServiceNow OAuth failed: HTTP {response.status_code}"
            )

        token_data = response.json()

        access_token = token_data.get("access_token")
        expires_in = int(token_data.get("expires_in", 1800))

        if not access_token:
            raise ServiceNowError(
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
        **kwargs: Any,
    ) -> dict:
        """
        Make an authenticated ServiceNow API request.
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

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method,
                url,
                headers=headers,
                **kwargs,
            )

        if response.status_code >= 400:
            raise ServiceNowError(
                f"ServiceNow API failed: HTTP {response.status_code}"
            )

        return response.json()

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
            json=payload,
        )

        return response["result"]

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

        if not results:
            raise ServiceNowNotFound(
                "The requested incident was not found."
            )

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

        sys_id = incident["sys_id"]

        url = (
            f"{self.instance}/api/now/table/incident/{sys_id}"
        )

        response = await self._request(
            "PATCH",
            url,
            json=payload,
        )

        return response["result"]
