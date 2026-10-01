"""
app/request_status.py — Service Request & RITM status presentation (DEMO-07).

PURPOSE
───────
Turns the request or RITM record returned by the Tool Gateway into a Teams reply,
and supplies safe messages for the not-found / denied / failure cases.

Only allowlisted fields are shown, in a fixed order.  Anything else in the
record — ``sys_id``, reference links, custom fields — is never displayed.
Fields that are missing or empty are omitted, never invented.

PURITY
──────
No ServiceNow, gateway, network, credential or environment access.  The
orchestration (identity → authorization → gateway) lives in ``app/main.py``.
"""

from __future__ import annotations

from typing import Any

# (record field, label) — allowable fields for REQ replies
REQUEST_STATUS_FIELDS: tuple[tuple[str, str], ...] = (
    ("short_description", "Short description"),
    ("request_state", "Request state"),
    ("stage", "Stage"),
    ("approval", "Approval"),
    ("opened_by", "Opened by"),
    ("requested_for", "Requested for"),
)

# (record field, label) — allowable fields for RITM replies
RITM_STATUS_FIELDS: tuple[tuple[str, str], ...] = (
    ("request", "Request number"),
    ("short_description", "Short description"),
    ("cat_item", "Catalog item"),
    ("state", "State"),
    ("stage", "Stage"),
    ("approval", "Approval"),
    ("opened_by", "Opened by"),
    ("requested_for", "Requested for"),
)

NOT_AUTHORISED_REQUEST_MESSAGE = (
    "⛔ You are not authorised to view this service request.\n\n"
    "Please contact your IT administrator if you believe this is incorrect."
)


def request_not_found_message(number: str) -> str:
    return f"I couldn't find request {number}."


def request_lookup_failed_message(number: str) -> str:
    return (
        f"I couldn't retrieve request {number} right now. "
        "Please try again later."
    )


def _display(value: Any) -> str | None:
    """
    Plain display text for a record value.

    Reference fields may arrive as ``{"display_value": ..., "link": ...,
    "value": <sys_id>}``; only ``display_value`` is ever shown.
    """
    if isinstance(value, dict):
        value = value.get("display_value") or value.get("value")
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def format_request_status(record: dict[str, Any], req_number: str) -> str:
    """Teams reply for a successfully retrieved REQ."""
    number = _display(record.get("number")) or req_number
    lines = [f"📦 **Service Request {number}**", ""]
    for field_name, label in REQUEST_STATUS_FIELDS:
        text = _display(record.get(field_name))
        if text is not None:
            lines.append(f"**{label}:** {text}")
    return "\n".join(lines)


def format_ritm_status(record: dict[str, Any], ritm_number: str) -> str:
    """Teams reply for a successfully retrieved RITM."""
    number = _display(record.get("number")) or ritm_number
    lines = [f"📦 **Requested Item {number}**", ""]
    for field_name, label in RITM_STATUS_FIELDS:
        text = _display(record.get(field_name))
        if text is not None:
            lines.append(f"**{label}:** {text}")
    return "\n".join(lines)
