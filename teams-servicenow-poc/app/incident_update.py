"""
app/incident_update.py — Controlled incident update: parsing, collection and
confirmation summary (BL-009).

LIFECYCLE
─────────
    IDLE ──► COLLECTING ──► READY_FOR_CONFIRMATION ──► EXECUTING ──► COMPLETED / FAILED
                 │                    │
                 └──► CANCELLED ◄─────┘ ──► IDLE

This module owns everything up to READY_FOR_CONFIRMATION.  Confirmation
(BL-003), authorization (BL-004) and execution through the Tool Gateway
(BL-005) are orchestrated by ``app/main.py``.

UPDATEABLE FIELDS
─────────────────
Exactly ``short_description``, ``description``, ``impact``, ``urgency`` — the
same allowlist as ``UpdateIncidentToolRequest`` and the adapter.  Impact and
urgency accept only "1", "2", "3".  Other ServiceNow fields (priority, state,
assignment group, …) are recognised only so they can be refused.

COMMAND GRAMMAR (whole message, case-insensitive)
────────────────────────────────────────────────
    <verb> [the] [incident] INC#                       → ask what to change
    <verb> [the] [incident] INC# <items>
    <verb> [the] <field> of [the] [incident] INC# [<connector> <value>] [<sep> <items>]

    verb       update | change | set | modify | edit
    item       [the] <field> [<connector> <value>]      (a bare field = "ask me for it")
    connector  to | = | : | as | is | should be          (optional before a digit)
    sep        , | and | , and

A level value is one token.  A text value runs until the next
"<sep> <field> <connector>" or the end of the message and is treated purely
as data — it is shown back to the user and needs explicit confirmation.
Anything that does not fit the grammar (e.g. "update INC0010002; DROP TABLE",
"update INC0010002 and delete it") is not an update command.

PURITY
──────
No ServiceNow, gateway, network, credential or environment access.  Message
content is never logged.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from app.confirmation import _CANCEL_PHRASES
from app.incident_collection import (
    IMPACT_ERROR,
    SHORT_DESCRIPTION_LENGTH_ERROR,
    SHORT_DESCRIPTION_MAX_LENGTH,
    URGENCY_ERROR,
)
from app.state import ConversationPhase, ConversationState

logger = logging.getLogger(__name__)


# ===========================================================================
# Contract
# ===========================================================================

UPDATE_INCIDENT_ACTION = "update_incident"

UPDATE_FIELDS: tuple[str, ...] = (
    "short_description",
    "description",
    "impact",
    "urgency",
)

_LEVEL_FIELDS = frozenset({"impact", "urgency"})
_VALID_LEVELS = frozenset({"1", "2", "3"})
_LEVEL_ERRORS = {"impact": IMPACT_ERROR, "urgency": URGENCY_ERROR}
_INCIDENT_NUMBER_RE = re.compile(r"^INC\d{7,10}$")

FIELD_LABELS = {
    "short_description": "Short description",
    "description": "Description",
    "impact": "Impact",
    "urgency": "Urgency",
}

# Supported field spellings → canonical name.
_SUPPORTED_RE = r"short[\s_-]*description|title|description|impact|urgency"
# Recognised but NOT updateable in BL-009.
_UNSUPPORTED_RE = (
    r"priority|state|status|assignment[\s_-]*group|assigned[\s_-]*to|"
    r"category|subcategory|caller|configuration[\s_-]*item|work[\s_-]*notes|"
    r"comments|close[\s_-]*notes|resolution"
)
_FIELD_RE = rf"(?:{_SUPPORTED_RE}|{_UNSUPPORTED_RE})"

_VERB = r"(?:update|change|set|modify|edit)"
_LEAD = r"(?:please\s+)?(?:(?:can|could)\s+you\s+(?:please\s+)?)?"
_CONNECTOR = r"(?::|=|\bto\b|\bas\b|\bis\b|\bshould\s+be\b)"
_SEP = r"(?:,\s*and\b|,|\band\b)"

_FORM_INCIDENT_FIRST = re.compile(
    rf"{_LEAD}{_VERB}\s+(?:the\s+)?(?:incident\s+)?(?P<num>INC\d+)"
    r"(?:\s+(?P<tail>.+))?",
    re.IGNORECASE | re.DOTALL,
)
_FORM_FIELD_FIRST = re.compile(
    rf"{_LEAD}{_VERB}\s+(?:the\s+)?(?P<field>{_FIELD_RE})\s+(?:of|for|on)\s+"
    r"(?:the\s+)?(?:incident\s+)?(?P<num>INC\d+)(?:\s+(?P<rest>.+))?",
    re.IGNORECASE | re.DOTALL,
)

_ITEM_START = re.compile(rf"(?:the\s+)?(?P<field>{_FIELD_RE})\b", re.IGNORECASE)
_CONNECTOR_AT = re.compile(rf"\s*{_CONNECTOR}\s*", re.IGNORECASE)
_BARE_DIGITS_AT = re.compile(r"\s+(?P<value>\d+)\b")
_LEVEL_TOKEN_AT = re.compile(r"(?P<value>[^\s,]+)")
_SEP_AT = re.compile(rf"\s*{_SEP}\s*", re.IGNORECASE)
_TEXT_BOUNDARY = re.compile(
    rf"\s*{_SEP}\s*(?:the\s+)?(?:{_FIELD_RE})\b\s*{_CONNECTOR}",
    re.IGNORECASE,
)
# Optional lead-in on follow-up messages ("actually, impact to 1").
_FOLLOW_UP_LEAD = re.compile(
    r"^\s*(?:(?:actually|sorry|correction|oh|no)\b[\s,]*)*"
    r"(?:please\s+)?(?:(?:change|set|update|make)\s+)?",
    re.IGNORECASE,
)
_BARE_VALUE_RE = re.compile(r"^\s*([A-Za-z0-9]+)\s*[.!)]?\s*$")


def _canonical(field: str) -> str | None:
    """Canonical supported field name, or None for an unsupported field."""
    name = re.sub(r"[\s_-]+", " ", field.lower())
    if name in ("short description", "title"):
        return "short_description"
    if name in ("description", "impact", "urgency"):
        return name
    return None


def _unsupported_label(field: str) -> str:
    return re.sub(r"[\s_-]+", " ", field.lower())


# ===========================================================================
# Parsing
# ===========================================================================

@dataclass(frozen=True)
class ParsedItems:
    """Items in message order: (canonical field or None, raw field, value or None)."""

    items: tuple[tuple[str | None, str, str | None], ...]

    @property
    def unsupported(self) -> tuple[str, ...]:
        return tuple(_unsupported_label(raw) for f, raw, _ in self.items if f is None)


@dataclass(frozen=True)
class UpdateCommand:
    """A syntactically valid update command.  Values are NOT yet validated."""

    incident_number: str
    items: ParsedItems

    @property
    def unsupported(self) -> tuple[str, ...]:
        return self.items.unsupported


def _parse_items(text: str) -> ParsedItems | None:
    """Parse a list of field items; None unless the WHOLE text is items."""
    text = text.strip()
    if not text:
        return ParsedItems(())

    items: list[tuple[str | None, str, str | None]] = []
    pos = 0
    while True:
        start = _ITEM_START.match(text, pos)
        if not start:
            return None
        raw = start.group("field")
        field = _canonical(raw)
        pos = start.end()
        value: str | None = None

        connector = _CONNECTOR_AT.match(text, pos)
        if connector:
            pos = connector.end()
            if field in _LEVEL_FIELDS:
                token = _LEVEL_TOKEN_AT.match(text, pos)
                if not token:
                    return None
                value = token.group("value").rstrip(".!")
                pos = token.end()
            else:
                boundary = _TEXT_BOUNDARY.search(text, pos)
                end = boundary.start() if boundary else len(text)
                value = text[pos:end].strip()
                pos = end
        elif field in _LEVEL_FIELDS:
            digits = _BARE_DIGITS_AT.match(text, pos)
            if digits:
                value = digits.group("value")
                pos = digits.end()

        items.append((field, raw, value))

        if pos >= len(text) or not text[pos:].strip(" .!"):
            return ParsedItems(tuple(items))
        sep = _SEP_AT.match(text, pos)
        if not sep:
            return None
        pos = sep.end()


def parse_update_command(message: str) -> UpdateCommand | None:
    """
    Parse a whole-message update command.  Returns None for anything that is
    not unambiguously an update command for one valid incident number.
    """
    text = (message or "").strip()

    m = _FORM_FIELD_FIRST.fullmatch(text)
    if m:
        tail = m.group("field") + (" " + m.group("rest") if m.group("rest") else "")
    else:
        m = _FORM_INCIDENT_FIRST.fullmatch(text)
        if not m:
            return None
        tail = m.group("tail") or ""

    number = m.group("num").upper()
    if not _INCIDENT_NUMBER_RE.fullmatch(number):
        return None

    items = _parse_items(tail)
    if items is None:
        return None
    return UpdateCommand(incident_number=number, items=items)


# ===========================================================================
# Validation
# ===========================================================================

def validate_update_value(field: str, value: str) -> str:
    """Validate one update value; raises ValueError with a user-safe message."""
    if field not in UPDATE_FIELDS:
        raise ValueError("That field cannot be updated.")
    if not isinstance(value, str):
        raise ValueError("That value cannot be empty.")
    if field in _LEVEL_FIELDS:
        value = value.strip()
        if value not in _VALID_LEVELS:
            raise ValueError(_LEVEL_ERRORS[field])
        return value
    if field == "short_description":
        value = " ".join(value.split())
        if not value:
            raise ValueError("The short description cannot be empty.")
        if len(value) > SHORT_DESCRIPTION_MAX_LENGTH:
            raise ValueError(SHORT_DESCRIPTION_LENGTH_ERROR)
        return value
    value = value.strip()
    if not value:
        raise ValueError("The description cannot be empty.")
    return value


def validated_update(state: ConversationState) -> tuple[str, dict[str, str]]:
    """
    Re-validate the pending update held in *state* immediately before
    execution.  Returns ``(incident_number, changes)`` containing only
    allowlisted fields.  Raises ValueError if anything is missing/invalid.
    """
    if state.pending_action != UPDATE_INCIDENT_ACTION:
        raise ValueError("pending action is not update_incident")
    number = (state.incident_number or "").strip().upper()
    if not _INCIDENT_NUMBER_RE.fullmatch(number):
        raise ValueError("invalid incident number")
    details = state.collected_details or {}
    raw_changes = details.get("changes")
    if not isinstance(raw_changes, dict) or not raw_changes:
        raise ValueError("no changes")
    if details.get("requested"):
        raise ValueError("fields still requested")
    changes = {}
    for field in UPDATE_FIELDS:
        if field in raw_changes:
            changes[field] = validate_update_value(field, raw_changes[field])
    if set(raw_changes) - set(UPDATE_FIELDS):
        raise ValueError("unsupported field in changes")
    return number, changes


# ===========================================================================
# Current values
# ===========================================================================

def current_values(incident: dict[str, Any] | None) -> dict[str, str]:
    """Current values of updateable fields as actually returned by ServiceNow."""
    snapshot: dict[str, str] = {}
    for field in UPDATE_FIELDS:
        value = (incident or {}).get(field)
        if isinstance(value, dict):
            value = value.get("display_value")
        if isinstance(value, (str, int)) and str(value).strip():
            snapshot[field] = str(value).strip()
    return snapshot


# ===========================================================================
# Collection
# ===========================================================================

@dataclass(frozen=True)
class UpdateResult:
    reply: str
    phase: ConversationPhase
    errors: tuple[str, ...] = ()
    cancelled: bool = False

    @property
    def ready(self) -> bool:
        return self.phase is ConversationPhase.READY_FOR_CONFIRMATION


def unsupported_fields_message(fields: tuple[str, ...]) -> str:
    names = ", ".join(dict.fromkeys(fields))
    return (
        f"I can't update {names}. Only the short description, description, "
        "impact and urgency can be changed here. Priority is calculated by "
        "ServiceNow from impact and urgency."
    )


def _prompt(number: str, requested: list[str]) -> str:
    if requested:
        field = requested[0]
        if field in _LEVEL_FIELDS:
            return (
                f"What should the new {field} be? Please choose 1, 2, or 3 "
                "(1 = High, 2 = Medium, 3 = Low)."
            )
        return f"What should the new {FIELD_LABELS[field].lower()} be?"
    return (
        f"What would you like to change on {number}? You can update the short "
        "description, description, impact or urgency — for example "
        "\"impact to 1\" or \"description to …\"."
    )


def build_update_summary(number: str, changes: dict[str, str], current: dict[str, str]) -> str:
    """Before → after summary using only real current values."""
    lines = []
    for field in UPDATE_FIELDS:
        if field not in changes:
            continue
        before = current.get(field)
        before_text = before if before is not None else "(current value not available)"
        lines.append(f"- **{FIELD_LABELS[field]}:** {before_text} → {changes[field]}")
    return (
        f"📝 You're asking me to update **{number}**:\n\n"
        + "\n".join(lines)
        + "\n\nShall I apply these changes? "
        "Reply **yes** to confirm or **cancel** to cancel."
    )


def _apply_items(
    items: ParsedItems,
    changes: dict[str, str],
    requested: list[str],
    current: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    if items.unsupported:
        errors.append(unsupported_fields_message(items.unsupported))
    for field, _raw, value in items.items:
        if field is None:
            continue
        if value is None:
            if field not in requested:
                requested.append(field)
            changes.pop(field, None)
            continue
        try:
            new_value = validate_update_value(field, value)
        except ValueError as exc:
            errors.append(str(exc))
            if field not in requested:
                requested.append(field)
            continue
        if current.get(field) == new_value:
            errors.append(f"{FIELD_LABELS[field]} is already {new_value}.")
            changes.pop(field, None)
            if field in requested:
                requested.remove(field)
            continue
        changes[field] = new_value
        if field in requested:
            requested.remove(field)
    return errors


def _finish(state: ConversationState, changes, requested, current, errors) -> UpdateResult:
    number = state.incident_number or ""
    state.collected_details = {
        "changes": dict(changes),
        "requested": list(requested),
        "current": dict(current),
    }
    if changes and not requested and not errors:
        state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        logger.debug("incident_update: ready_for_confirmation fields=%s", sorted(changes))
        return UpdateResult(
            reply=build_update_summary(number, changes, current),
            phase=state.phase,
        )
    parts = list(errors)
    if requested or not changes:
        parts.append(_prompt(number, requested))
    else:
        parts.append("Please send a corrected value or **cancel**.")
    logger.debug(
        "incident_update: collecting fields=%s requested=%s errors=%d",
        sorted(changes), requested, len(errors),
    )
    return UpdateResult(reply="\n\n".join(parts), phase=state.phase, errors=tuple(errors))


def start_update_collection(
    state: ConversationState,
    command: UpdateCommand,
    current: dict[str, str],
) -> UpdateResult:
    """
    Begin an update for an incident whose current values were read through
    the gateway: ``IDLE → COLLECTING`` (→ READY_FOR_CONFIRMATION if the command
    already contained valid changes).  A terminal phase is first returned to
    IDLE through its normal transition.
    """
    if state.phase in (
        ConversationPhase.COMPLETED,
        ConversationPhase.FAILED,
        ConversationPhase.CANCELLED,
    ):
        state.transition_to(ConversationPhase.IDLE)
    if state.phase is not ConversationPhase.IDLE:
        raise ValueError(f"Cannot start an update from phase '{state.phase.value}'.")

    state.transition_to(ConversationPhase.COLLECTING)
    state.intent = UPDATE_INCIDENT_ACTION
    state.pending_action = UPDATE_INCIDENT_ACTION
    state.incident_number = command.incident_number
    state.summary = None

    changes: dict[str, str] = {}
    requested: list[str] = []
    errors = _apply_items(command.items, changes, requested, current)
    return _finish(state, changes, requested, current, errors)


def process_update_message(state: ConversationState, message: str) -> UpdateResult:
    """Handle one message while collecting an update (phase COLLECTING)."""
    if (
        state.phase is not ConversationPhase.COLLECTING
        or state.pending_action != UPDATE_INCIDENT_ACTION
    ):
        raise ValueError("Update collection requires an update in phase 'collecting'.")

    if (message or "").strip().lower() in _CANCEL_PHRASES:
        state.transition_to(ConversationPhase.CANCELLED)
        state.transition_to(ConversationPhase.IDLE)
        logger.debug("incident_update: cancelled")
        return UpdateResult(
            reply=(
                "❌ Cancelled. The incident has not been changed.\n\n"
                "Let me know if there is anything else I can help with."
            ),
            phase=state.phase,
            cancelled=True,
        )

    details = state.collected_details or {}
    changes = {
        k: v for k, v in dict(details.get("changes") or {}).items() if k in UPDATE_FIELDS
    }
    requested = [f for f in details.get("requested") or [] if f in UPDATE_FIELDS]
    current = {
        k: v for k, v in dict(details.get("current") or {}).items() if k in UPDATE_FIELDS
    }

    stripped = _FOLLOW_UP_LEAD.sub("", message or "", count=1)
    items = _parse_items(stripped) if stripped.strip() else None

    if items is not None and items.items:
        errors = _apply_items(items, changes, requested, current)
    elif requested:
        # A bare answer to the field that was asked for.
        field = requested[0]
        value = message or ""
        if field in _LEVEL_FIELDS:
            bare = _BARE_VALUE_RE.match(value)
            value = bare.group(1) if bare else value
        errors = _apply_items(
            ParsedItems(((field, field, value),)), changes, requested, current
        )
    else:
        errors = [
            "I didn't recognise that as a change. Please name the field and the "
            "new value, for example \"impact to 1\"."
        ]
    return _finish(state, changes, requested, current, errors)
