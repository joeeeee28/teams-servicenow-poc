"""
app/router.py — Deterministic message router (BL-001 corrective patch).

DESIGN INTENT
─────────────
This module provides a *conservative*, pattern-only router that classifies
an incoming message before any AI/LLM or network call is made.

For incident-status routing the router uses *whole-message* regular
expressions anchored at both ends (via ``re.fullmatch``).  It does NOT
perform substring extraction: a message that contains an incident number
surrounded by arbitrary text is NOT matched.

This prevents inputs such as

    status of INC0010002; DROP TABLE incident
    status of INC0010002<script>
    status of INC0010002 foo

from being routed as incident_status.

SECURITY NOTE
─────────────
The router is NOT the security boundary.  ``app.servicenow._validate_incident_number``
must remain, and does remain, unchanged.  It independently validates the
incident number before any ServiceNow operation.

PURITY GUARANTEE
────────────────
``route_message`` is a pure function:
  - it does not import anything from ``app.servicenow``
  - it does not instantiate ``ServiceNowClient``
  - it does not perform any network operation
"""

import re
from typing import Optional

from app.incident_update import parse_update_command

# ---------------------------------------------------------------------------
# Approved whole-message pattern for incident_status
# ---------------------------------------------------------------------------
# Anchored at both ends so that any extra prefix or suffix text
# (e.g. ";", "<script>", "foo") causes the match to fail.
#
# Approved lead-in phrases (all optional):
#   INC0010002
#   status of INC0010002
#   check INC0010002
#   check status of INC0010002
#   what is the status of INC0010002
#
# Case-insensitive; leading/trailing whitespace stripped before matching.

_INCIDENT_STATUS_RE = re.compile(
    r"""
    \A                              # start of string (after strip)
    (?:                             # optional approved lead-in
        (?:what\s+is\s+the\s+)?     # "what is the " (optional)
        (?:check\s+)?               # "check " (optional)
        status\s+of\s+              # "status of "
        |
        check\s+                    # bare "check "
    )?
    (INC\d{7,10})                   # capture group 1: the incident number
    \Z                              # end of string — no trailing content allowed
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RouteResult:
    """Lightweight, immutable-by-convention result object."""

    __slots__ = ("intent", "incident_number")

    def __init__(self, intent: str, incident_number: Optional[str] = None) -> None:
        self.intent = intent
        self.incident_number = incident_number

    def __repr__(self) -> str:
        return (
            f"RouteResult(intent={self.intent!r}, "
            f"incident_number={self.incident_number!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RouteResult):
            return NotImplemented
        return self.intent == other.intent and self.incident_number == other.incident_number


def route_message(message: str) -> Optional[RouteResult]:
    """
    Attempt to deterministically route *message* without calling any
    external service.

    Returns a :class:`RouteResult` if the message matches an approved
    whole-message pattern, or ``None`` if no deterministic route is found
    (the caller should fall through to AI classification).

    Parameters
    ----------
    message:
        Raw message text from the Teams user.  Leading/trailing whitespace
        is stripped internally before matching.

    Returns
    -------
    RouteResult | None
    """
    normalised = message.strip()

    # ── Incident-status ──────────────────────────────────────────────────────
    m = _INCIDENT_STATUS_RE.fullmatch(normalised)
    if m:
        # Normalise to upper-case regardless of how the user typed it.
        incident_number = m.group(1).upper()
        return RouteResult(intent="incident_status", incident_number=incident_number)

    # ── Incident update (BL-009) ─────────────────────────────────────────────
    # Whole-message grammar in app.incident_update; never executes anything —
    # the caller starts a collection that still requires confirmation.
    command = parse_update_command(normalised)
    if command is not None:
        return RouteResult(intent="incident_update", incident_number=command.incident_number)

    # ── No deterministic route ───────────────────────────────────────────────
    return None
