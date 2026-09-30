"""
app/servicenow_errors.py — Typed ServiceNow failure categories (DEMO-02).

PURPOSE
───────
Every ServiceNow transport failure is classified into one
``ServiceNowErrorCategory``, and every category has a fixed, concise,
user-facing message.  Messages are built only from the category, the
operation and a validated incident number: never from exception text,
response bodies, URLs, headers or tokens.

OUTCOME CERTAINTY
─────────────────
For create/update, a failure is either:

  * **not applied**: ServiceNow certainly did not make the change (the request
    never reached it, or it was refused with 4xx / 503).  The user is told
    that no change was made.
  * **possibly applied** (``outcome_unknown``): the write request was sent and
    the outcome could not be confirmed (timeout while waiting, connection lost
    after sending, 500/502/504, or a 2xx response that could not be parsed).
    The user is told the result could not be confirmed and to check before
    retrying.  Nothing is ever retried automatically.

Reads never have side effects; their messages say only that the lookup failed.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class ServiceNowErrorCategory(str, Enum):
    """Controlled failure categories.  Values are the gateway ``error_code``."""

    UNAVAILABLE = "SERVICENOW_UNAVAILABLE"            # connection failure / 503
    TIMEOUT = "SERVICENOW_TIMEOUT"                    # no response in time
    AUTH_FAILED = "SERVICENOW_AUTH_FAILED"            # OAuth failure / 401
    FORBIDDEN = "SERVICENOW_FORBIDDEN"                # 403 — integration lacks rights
    NOT_FOUND = "NOT_FOUND"                           # 404 / empty lookup (existing code)
    REJECTED = "SERVICENOW_REJECTED"                  # 400 and other 4xx
    RATE_LIMITED = "SERVICENOW_RATE_LIMITED"          # 429
    SERVER_ERROR = "SERVICENOW_SERVER_ERROR"          # 500 / 502 / 504 / other 5xx
    INVALID_RESPONSE = "SERVICENOW_INVALID_RESPONSE"  # malformed / unexpected body


CATEGORY_CODES = frozenset(c.value for c in ServiceNowErrorCategory)


def category_from_code(error_code: Optional[str]) -> Optional[ServiceNowErrorCategory]:
    """The category for a gateway ``error_code`` (None if not a category)."""
    try:
        return ServiceNowErrorCategory(error_code)
    except ValueError:
        return None


def category_for_status(status_code: int) -> ServiceNowErrorCategory:
    """Category for an HTTP error status (>= 400)."""
    if status_code == 401:
        return ServiceNowErrorCategory.AUTH_FAILED
    if status_code == 403:
        return ServiceNowErrorCategory.FORBIDDEN
    if status_code == 404:
        return ServiceNowErrorCategory.NOT_FOUND
    if status_code == 429:
        return ServiceNowErrorCategory.RATE_LIMITED
    if status_code == 503:
        return ServiceNowErrorCategory.UNAVAILABLE
    if status_code >= 500:
        return ServiceNowErrorCategory.SERVER_ERROR
    return ServiceNowErrorCategory.REJECTED


# Statuses a server returns without having processed a write.  A 503 is a
# refusal (maintenance / hibernating instance); 500/502/504 may follow a write.
_NOT_APPLIED_STATUSES = frozenset({503})


def write_possibly_applied(status_code: int) -> bool:
    """True if an HTTP error on a *sent* write leaves the outcome unknown."""
    return status_code >= 500 and status_code not in _NOT_APPLIED_STATUSES


# ===========================================================================
# User-facing messages
# ===========================================================================

_READ = {
    ServiceNowErrorCategory.UNAVAILABLE:
        "I couldn't reach ServiceNow right now, so I couldn't retrieve incident {n}. "
        "Please try again.",
    ServiceNowErrorCategory.TIMEOUT:
        "ServiceNow didn't respond in time, so I couldn't retrieve incident {n}. "
        "Please try again.",
    ServiceNowErrorCategory.AUTH_FAILED:
        "The ServiceNow integration is temporarily unavailable, so I couldn't "
        "retrieve incident {n}.",
    ServiceNowErrorCategory.FORBIDDEN:
        "The ServiceNow integration isn't permitted to read incident {n}. "
        "Please contact IT support.",
    ServiceNowErrorCategory.NOT_FOUND:
        "I couldn't find incident {n}.",
    ServiceNowErrorCategory.REJECTED:
        "ServiceNow rejected the lookup for incident {n}.",
    ServiceNowErrorCategory.RATE_LIMITED:
        "ServiceNow is temporarily rate-limiting requests. Please try again shortly.",
    ServiceNowErrorCategory.SERVER_ERROR:
        "ServiceNow is having problems right now, so I couldn't retrieve incident {n}. "
        "Please try again later.",
    ServiceNowErrorCategory.INVALID_RESPONSE:
        "ServiceNow returned an unexpected response, so I couldn't retrieve incident {n}. "
        "Please try again later.",
}

_NOT_APPLIED = {
    ServiceNowErrorCategory.UNAVAILABLE:
        "I couldn't reach ServiceNow right now. No change was made. Please try again.",
    ServiceNowErrorCategory.TIMEOUT:
        "I couldn't reach ServiceNow in time. No change was made. Please try again.",
    ServiceNowErrorCategory.AUTH_FAILED:
        "The ServiceNow integration is temporarily unavailable. No change was made.",
    ServiceNowErrorCategory.FORBIDDEN:
        "The ServiceNow integration isn't permitted to make this change. "
        "No change was made. Please contact IT support.",
    ServiceNowErrorCategory.NOT_FOUND:
        "I couldn't find incident {n}. No change was made.",
    ServiceNowErrorCategory.REJECTED:
        "ServiceNow rejected the request. No change was made. "
        "Please check the details and try again.",
    ServiceNowErrorCategory.RATE_LIMITED:
        "ServiceNow is temporarily rate-limiting requests. No change was made. "
        "Please try again shortly.",
    ServiceNowErrorCategory.SERVER_ERROR:
        "ServiceNow is having problems right now. No change was made. "
        "Please try again later.",
    ServiceNowErrorCategory.INVALID_RESPONSE:
        "ServiceNow returned an unexpected response. No change was made. "
        "Please try again later.",
}

_UNCONFIRMED_REASON = {
    ServiceNowErrorCategory.TIMEOUT: "ServiceNow didn't respond in time.",
    ServiceNowErrorCategory.UNAVAILABLE: "The connection to ServiceNow was lost.",
    ServiceNowErrorCategory.SERVER_ERROR: "ServiceNow reported an error after receiving the request.",
    ServiceNowErrorCategory.INVALID_RESPONSE: "ServiceNow returned an unexpected response.",
}

_UNCONFIRMED_CREATE = (
    "{reason} I couldn't confirm whether the incident was created. Please check "
    "your incidents in ServiceNow before trying again. I won't retry automatically."
)
_UNCONFIRMED_UPDATE = (
    "{reason} I couldn't confirm whether incident {n} was updated. Please check its "
    "status before trying again. I won't retry automatically."
)
_UNCONFIRMED_CREATE_REQUEST = (
    "{reason} I couldn't confirm whether your service request was created — it may or "
    "may not exist. Please check your requests in ServiceNow before trying again. "
    "I won't retry automatically."
)
_UNCONFIRMED = {
    "create": _UNCONFIRMED_CREATE,
    "update": _UNCONFIRMED_UPDATE,
    "create_request": _UNCONFIRMED_CREATE_REQUEST,   # DEMO-06
}


def failure_message(
    category: ServiceNowErrorCategory,
    *,
    operation: str,
    possibly_applied: bool = False,
    incident_number: Optional[str] = None,
) -> str:
    """
    Fixed user-facing message.  *operation* is ``"read"``, ``"create"``,
    ``"update"`` or ``"create_request"`` (DEMO-06); *incident_number* must
    already be validated.
    """
    n = incident_number or "the incident"
    if category is ServiceNowErrorCategory.NOT_FOUND and not incident_number:
        # A 404 without a target record (e.g. on create) is a configuration
        # problem, not a missing incident.
        category = ServiceNowErrorCategory.AUTH_FAILED
    if operation == "read":
        return _READ[category].format(n=n)
    if possibly_applied:
        reason = _UNCONFIRMED_REASON.get(category, "ServiceNow didn't confirm the result.")
        return _UNCONFIRMED[operation].format(reason=reason, n=n)
    return _NOT_APPLIED[category].format(n=n)
