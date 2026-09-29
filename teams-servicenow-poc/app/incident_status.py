"""
app/incident_status.py — Incident status presentation (BL-008).

PURPOSE
───────
Turns the incident record returned by the BL-005 Tool Gateway
(``ServiceNowToolAction.GET_INCIDENT``) into a Teams reply, and supplies the
safe messages for the not-found / denied / failure cases.

Only allowlisted fields are shown, in a fixed order.  Anything else in the
record — ``sys_id``, reference links, custom fields, work notes — is never
displayed.  Fields that are missing or empty are omitted, never invented.

PURITY
──────
No ServiceNow, gateway, network, credential or environment access.  The
orchestration (identity → authorization → gateway) lives in ``app/main.py``.
"""

from __future__ import annotations

from typing import Any

# (record field, label) — the ONLY fields that can appear in a status reply.
# The adapter currently returns number, short_description, state, impact,
# urgency and priority; the remaining fields are shown only if a future
# approved adapter contract returns them.
STATUS_FIELDS: tuple[tuple[str, str], ...] = (
    ("short_description", "Short description"),
    ("description", "Description"),
    ("state", "State"),
    ("impact", "Impact"),
    ("urgency", "Urgency"),
    ("priority", "Priority"),
    ("assignment_group", "Assignment group"),
    ("assigned_to", "Assigned to"),
)

NOT_AUTHORISED_MESSAGE = (
    "⛔ You are not authorised to view this incident.\n\n"
    "Please contact your IT administrator if you believe this is incorrect."
)


def not_found_message(incident_number: str) -> str:
    return f"I couldn't find incident {incident_number}."


def lookup_failed_message(incident_number: str) -> str:
    return (
        f"I couldn't retrieve incident {incident_number} right now. "
        "Please try again later."
    )


def _display(value: Any) -> str | None:
    """
    Plain display text for a record value.

    Reference fields may arrive as ``{"display_value": ..., "link": ...,
    "value": <sys_id>}``; only ``display_value`` is ever shown.
    """
    if isinstance(value, dict):
        value = value.get("display_value")
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def format_incident_status(incident: dict[str, Any], incident_number: str) -> str:
    """Teams reply for a successfully retrieved incident."""
    number = _display(incident.get("number")) or incident_number
    lines = [f"📋 **Incident {number}**", ""]
    for field_name, label in STATUS_FIELDS:
        text = _display(incident.get(field_name))
        if text is not None:
            lines.append(f"**{label}:** {text}")
    return "\n".join(lines)
