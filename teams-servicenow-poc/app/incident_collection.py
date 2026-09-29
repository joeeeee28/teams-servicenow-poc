"""
app/incident_collection.py — Incident detail collection (BL-006).

PURPOSE
───────
Collects the fields required to create an incident while the conversation
is in ``ConversationPhase.COLLECTING`` and, once every field is present and
valid, moves the conversation to ``READY_FOR_CONFIRMATION`` with a summary
built only from the collected values.

    IDLE ──► COLLECTING ──► READY_FOR_CONFIRMATION     (BL-006 stops here)
                 │
                 └──► CANCELLED ──► IDLE               (user cancels)

Confirmation (BL-003), authorization (BL-004) and execution (BL-005) are
NOT performed here.

REQUIRED FIELDS (collection order)
──────────────────────────────────
    1. short_description   non-empty, single line, ≤ 160 characters
    2. description         non-empty, user-provided text
    3. impact              exactly "1", "2" or "3"
    4. urgency             exactly "1", "2" or "3"

The contract matches ``app.models.CreateIncidentRequest`` and the BL-005
gateway (``CreateIncidentToolRequest``).  Words such as "high" or "low" are
rejected — there is no implicit mapping.

EXTRACTION (deterministic, no LLM)
──────────────────────────────────
* Labelled values anywhere in a message:
      "impact 2", "impact is 2", "urgency: 1", "change urgency to 3",
      "actually impact should be 1", "short description: VPN down",
      "title: VPN down", "change the description to ..."
  A later labelled value replaces the earlier one (corrections).
* Unlabelled free text fills the text fields: if both are missing, the text
  becomes the description and its first sentence (if ≤ 160 characters)
  becomes the short description.  Otherwise it fills whichever text field
  is missing.
* A bare answer ("2") fills impact/urgency only when that field is the one
  currently being asked for.
Nothing is ever defaulted or inferred: missing values are asked for.

PURITY
──────
This module does not call ServiceNow, the Tool Gateway, Ollama, Teams or any
network service, and does not read credentials or environment variables.
Message content is never logged; only field names are.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.confirmation import _CANCEL_PHRASES
from app.models import CreateIncidentRequest
from app.state import ConversationPhase, ConversationState

logger = logging.getLogger(__name__)


# ===========================================================================
# Contract
# ===========================================================================

CREATE_INCIDENT_ACTION = "create_incident"

# Collection order.  These are the ONLY keys that may appear in the
# collected incident payload.
INCIDENT_FIELDS: tuple[str, ...] = (
    "short_description",
    "description",
    "impact",
    "urgency",
)

SHORT_DESCRIPTION_MAX_LENGTH = 160  # app.models.CreateIncidentRequest

_VALID_LEVELS = frozenset({"1", "2", "3"})

IMPACT_ERROR = "Impact must be 1, 2, or 3."
URGENCY_ERROR = "Urgency must be 1, 2, or 3."
SHORT_DESCRIPTION_LENGTH_ERROR = (
    f"The short description must be {SHORT_DESCRIPTION_MAX_LENGTH} characters "
    "or fewer. Please provide a concise title."
)
EMPTY_TEXT_ERROR = "That value cannot be empty."

_LEVEL_ERRORS = {"impact": IMPACT_ERROR, "urgency": URGENCY_ERROR}

_FIELD_LABELS = {
    "short_description": "Short description",
    "description": "Description",
    "impact": "Impact",
    "urgency": "Urgency",
}

_PROMPTS = {
    "short_description": (
        "Please provide a short description — a brief title for the issue "
        f"(up to {SHORT_DESCRIPTION_MAX_LENGTH} characters)."
    ),
    "description": "Please describe the issue in more detail.",
    "impact": (
        "What impact is this having? Please choose 1, 2, or 3 "
        "(1 = High, 2 = Medium, 3 = Low)."
    ),
    "urgency": (
        "What is the urgency? Please choose 1, 2, or 3 "
        "(1 = High, 2 = Medium, 3 = Low)."
    ),
}

# Questions asking what the bot needs (answered, never captured as data).
_HELP_PHRASES = (
    "what details",
    "which details",
    "details do you need",
    "what information",
    "what do you need",
)


# ===========================================================================
# Result / errors
# ===========================================================================

class IncidentCollectionError(Exception):
    """Raised when the collector is used from a phase it does not own."""


@dataclass(frozen=True)
class CollectionResult:
    """
    Outcome of processing one message.  Describes what happened; the
    caller persists the (already mutated) state and sends ``reply``.
    """

    reply: str
    phase: ConversationPhase
    missing: tuple[str, ...]
    errors: tuple[str, ...] = ()
    captured: tuple[str, ...] = ()
    cancelled: bool = False

    @property
    def ready(self) -> bool:
        return self.phase is ConversationPhase.READY_FOR_CONFIRMATION


# ===========================================================================
# Parsing
# ===========================================================================

# "impact 2", "impact is 2", "urgency: 1", "urgency to be 3" ...
_LEVEL_LABEL_RE = re.compile(
    r"\b(?P<label>impact|urgency)\b"
    r"(?:\s*(?::|=|-|\bis\b|\bshould\b|\bmust\b|\bwill\b|\bwould\b|\bbe\b"
    r"|\bto\b|\bof\b|\bnow\b|\blevel\b|\brating\b|\bas\b|\bat\b))*"
    r"\s*(?P<value>[A-Za-z0-9]+)\b",
    re.IGNORECASE,
)

# Tokens that make a level label an actual value assignment rather than prose
# ("big impact on my work" is prose).  Words are recognised only so they can
# be REJECTED — they are never mapped to a number.
_LEVEL_WORDS = frozenset(
    {"high", "medium", "low", "critical", "moderate", "severe", "minor",
     "major", "urgent", "normal", "none"}
)

# "short description: ...", "title is ...", "change the description to ..."
_TEXT_LABEL_RE = re.compile(
    r"\b(?P<label>short[\s_-]*description|title|description)\b"
    r"(?:\s*(?::|=|-|–|\bis\b|\bshould\s+be\b|\bwould\s+be\b|\bto\b|\bas\b))+"
    r"\s*",
    re.IGNORECASE,
)

# Leading request phrases on the message that started the workflow,
# e.g. "I need to report an issue", "Create an incident for my VPN issue".
_REQUEST_LEAD_IN_RE = re.compile(
    r"^\s*(?:(?:hi|hello|hey)\b[\s,!.]*)?(?:please\s+)?"
    r"(?:(?:can|could|would)\s+you\s+(?:please\s+)?)?"
    r"(?:i\s+(?:need|want|would\s+like)\s+to\s+|i'd\s+like\s+to\s+|let\s+me\s+)?"
    r"(?:create|raise|open|log|report|submit|file|make)\s+"
    r"(?:(?:an?|the|this|new|it)\s+)*"
    r"(?:incident|ticket|issue|problem|case|it|this)?"
    r"(?:\s+as\s+an?\s+(?:incident|ticket))?"
    r"(?:\s+with\s+(?:it|the\s+service\s+desk|it\s+support|support))?"
    r"\s*(?:(?:for|about|regarding|because|:|-)\s*(?P<rest>.*))?[\s.!]*$",
    re.IGNORECASE | re.DOTALL,
)

# Trailing request clause, e.g. "..., please raise a ticket."
_REQUEST_TAIL_RE = re.compile(
    r"[\s,.;]*(?:please\s+)?(?:can\s+you\s+)?"
    r"(?:create|raise|open|log|file|submit)\s+(?:an?\s+)?(?:incident|ticket)"
    r"(?:\s+for\s+(?:this|it|me))?[\s.!?]*$",
    re.IGNORECASE,
)

# Words that carry no incident content on their own ("Actually", "change the").
_FILLER_WORDS = frozenset(
    {"actually", "change", "set", "update", "make", "the", "please", "and",
     "also", "sorry", "oh", "correction", "wait", "instead", "i", "meant",
     "mean", "it", "ok", "okay", "so", "then", "lets", "let's", "can", "you",
     "my", "a", "an", "with", "should", "be", "is", "to", "now"}
)

_BARE_VALUE_RE = re.compile(r"^\s*([A-Za-z0-9]+)\s*[.!)]?\s*$")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _clean_piece(text: str) -> str:
    text = text.strip(" \t\r\n,;:-–")
    text = re.sub(r"^(?:and|also|with)\b\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*\b(?:and|also|with)$", "", text, flags=re.IGNORECASE)
    return text.strip(" \t\r\n,;:-–")


def _is_filler(text: str) -> bool:
    words = re.findall(r"[a-z']+|\S", text.lower())
    words = [w for w in words if w not in {".", ",", "!", "?", ";", ":"}]
    return all(w in _FILLER_WORDS for w in words)


def _normalise_label(label: str) -> str:
    label = label.lower()
    if label.startswith("short") or label == "title":
        return "short_description"
    return label


def _parse(text: str) -> tuple[list[tuple[str, str]], str]:
    """
    Split *text* into labelled ``(field, raw_value)`` pairs (in message
    order) and the remaining unlabelled free text.
    """
    matches: list[tuple[int, int, str, str | None]] = []  # start, end, field, value

    for m in _LEVEL_LABEL_RE.finditer(text):
        value = m.group("value")
        if value.isdigit() or value.lower() in _LEVEL_WORDS:
            matches.append((m.start(), m.end(), m.group("label").lower(), value))

    for m in _TEXT_LABEL_RE.finditer(text):
        # Value is filled in below: it runs until the next label.
        matches.append((m.start(), m.end(), _normalise_label(m.group("label")), None))

    matches.sort(key=lambda item: item[0])

    # Drop labels that start inside a previous level label's span.
    kept: list[tuple[int, int, str, str | None]] = []
    for item in matches:
        if kept and kept[-1][3] is not None and item[0] < kept[-1][1]:
            continue
        kept.append(item)

    labelled: list[tuple[str, str]] = []
    free_pieces: list[str] = []
    cursor = 0

    for index, (start, end, field_name, value) in enumerate(kept):
        next_start = kept[index + 1][0] if index + 1 < len(kept) else len(text)
        if start > cursor:
            free_pieces.append(text[cursor:start])
        if value is None:
            labelled.append((field_name, _clean_piece(text[end:next_start])))
            cursor = next_start
        else:
            labelled.append((field_name, value))
            cursor = end

    free_pieces.append(text[cursor:])

    cleaned = [_clean_piece(p) for p in free_pieces]
    free_text = " ".join(p for p in cleaned if p and not _is_filler(p))
    return labelled, free_text


def _strip_request_phrases(text: str) -> str:
    """Remove "create an incident for ..." style request wording."""
    m = _REQUEST_LEAD_IN_RE.match(text)
    if m:
        text = m.group("rest") or ""
    return _REQUEST_TAIL_RE.sub("", text).strip()


# ===========================================================================
# Field validation
# ===========================================================================

def _validate_short_description(value: str) -> str:
    value = " ".join(value.split()).rstrip(".").strip()
    if not value:
        raise ValueError(EMPTY_TEXT_ERROR)
    if len(value) > SHORT_DESCRIPTION_MAX_LENGTH:
        raise ValueError(SHORT_DESCRIPTION_LENGTH_ERROR)
    return value


def _validate_description(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(EMPTY_TEXT_ERROR)
    return value


def _validate_level(field_name: str, value: str) -> str:
    value = value.strip()
    if value not in _VALID_LEVELS:
        raise ValueError(_LEVEL_ERRORS[field_name])
    return value


_VALIDATORS = {
    "short_description": _validate_short_description,
    "description": _validate_description,
    "impact": lambda v: _validate_level("impact", v),
    "urgency": lambda v: _validate_level("urgency", v),
}


def _derive_short_description(text: str) -> str | None:
    """First sentence of the user's own text, if it fits as a title."""
    first = _SENTENCE_SPLIT_RE.split(" ".join(text.split()), 1)[0]
    try:
        return _validate_short_description(first.rstrip("!?"))
    except ValueError:
        return None


# ===========================================================================
# Public helpers
# ===========================================================================

def sanitize_details(details: dict[str, Any] | None) -> dict[str, str]:
    """Keep only allowlisted incident fields with string values."""
    return {
        key: value
        for key, value in (details or {}).items()
        if key in INCIDENT_FIELDS and isinstance(value, str)
    }


def missing_fields(details: dict[str, Any] | None) -> tuple[str, ...]:
    """Required fields not yet collected, in collection order."""
    details = sanitize_details(details)
    return tuple(f for f in INCIDENT_FIELDS if not details.get(f))


def validate_incident_payload(details: dict[str, Any]) -> dict[str, str]:
    """
    Validate the complete collected payload against the established
    create-incident contract (``app.models.CreateIncidentRequest``).

    Returns a dict containing exactly ``INCIDENT_FIELDS``.
    Raises ``pydantic.ValidationError`` or ``ValueError``.
    """
    clean = sanitize_details(details)
    missing = missing_fields(clean)
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    for field_name in INCIDENT_FIELDS:
        clean[field_name] = _VALIDATORS[field_name](clean[field_name])

    model = CreateIncidentRequest(**clean)
    return {field_name: getattr(model, field_name) for field_name in INCIDENT_FIELDS}


def build_confirmation_summary(payload: dict[str, str]) -> str:
    """Summary built ONLY from the validated collected values."""
    lines = [
        f"**{_FIELD_LABELS[f]}:** {payload[f]}" for f in INCIDENT_FIELDS
    ]
    return (
        "📋 I have the following incident details:\n\n"
        + "\n".join(lines)
        + "\n\nShall I create this incident? "
        "Reply **yes** to confirm or **cancel** to cancel."
    )


# ===========================================================================
# Collection
# ===========================================================================

def _apply(details: dict[str, str], text: str) -> tuple[list[str], list[str]]:
    """Apply one message to *details* in place. Returns (captured, errors)."""
    captured: list[str] = []
    errors: list[str] = []
    awaiting = next((f for f in INCIDENT_FIELDS if f not in details), None)

    labelled, free_text = _parse(text)

    for field_name, raw in labelled:
        try:
            details[field_name] = _VALIDATORS[field_name](raw)
            captured.append(field_name)
        except ValueError as exc:
            errors.append(str(exc))

    if not free_text:
        if not labelled and text.strip() and awaiting in ("impact", "urgency"):
            errors.append(_LEVEL_ERRORS[awaiting])
        return captured, errors

    if "short_description" not in details and "description" not in details:
        details["description"] = _validate_description(free_text)
        captured.append("description")
        short = _derive_short_description(free_text)
        if short is not None:
            details["short_description"] = short
            captured.append("short_description")
    elif "short_description" not in details:
        try:
            details["short_description"] = _validate_short_description(free_text)
            captured.append("short_description")
        except ValueError as exc:
            errors.append(str(exc))
    elif "description" not in details:
        details["description"] = _validate_description(free_text)
        captured.append("description")
    elif not labelled and awaiting in ("impact", "urgency"):
        # A bare answer to the question that was asked.  Anything that is not
        # exactly 1, 2 or 3 is rejected — never interpreted.
        bare = _BARE_VALUE_RE.match(text)
        try:
            details[awaiting] = _validate_level(awaiting, bare.group(1) if bare else text)
            captured.append(awaiting)
        except ValueError as exc:
            errors.append(str(exc))

    return captured, errors


def _finish(
    state: ConversationState,
    captured: list[str],
    errors: list[str],
    preamble: str = "",
) -> CollectionResult:
    """Move to READY_FOR_CONFIRMATION if complete, otherwise ask for more."""
    details = sanitize_details(state.collected_details)
    missing = missing_fields(details)

    if not missing and not errors:
        try:
            payload = validate_incident_payload(details)
        except (ValidationError, ValueError):
            # Defensive: per-field validation should make this unreachable.
            logger.warning("incident_collection: complete payload failed validation")
            state.collected_details = {}
            errors = ["Some details were invalid. Let's start over."]
            missing = INCIDENT_FIELDS
        else:
            state.collected_details = payload
            state.summary = payload["short_description"]
            state.pending_action = CREATE_INCIDENT_ACTION
            state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
            logger.debug("incident_collection: ready_for_confirmation")
            return CollectionResult(
                reply=build_confirmation_summary(payload),
                phase=state.phase,
                missing=(),
                captured=tuple(captured),
            )

    state.collected_details = details
    parts = [preamble] if preamble else []
    parts.extend(errors)
    if missing:
        parts.append(_PROMPTS[missing[0]])
    elif errors:
        parts.append("Please send a corrected value.")
    logger.debug(
        "incident_collection: captured=%s missing=%s errors=%d",
        captured, list(missing), len(errors),
    )
    return CollectionResult(
        reply="\n\n".join(parts),
        phase=state.phase,
        missing=missing,
        errors=tuple(errors),
        captured=tuple(captured),
    )


def start_incident_collection(
    state: ConversationState,
    message: str = "",
) -> CollectionResult:
    """
    Begin collecting incident details: ``IDLE → COLLECTING``.

    Any details the user already supplied in *message* are captured.  Only
    if every field was genuinely supplied does the conversation continue to
    ``READY_FOR_CONFIRMATION``.

    A conversation left in a terminal phase (COMPLETED / FAILED / CANCELLED)
    is first returned to IDLE via its normal transition.
    """
    if state.phase in (
        ConversationPhase.COMPLETED,
        ConversationPhase.FAILED,
        ConversationPhase.CANCELLED,
    ):
        state.transition_to(ConversationPhase.IDLE)

    if state.phase is not ConversationPhase.IDLE:
        raise IncidentCollectionError(
            f"Cannot start incident collection from phase '{state.phase.value}'."
        )

    state.transition_to(ConversationPhase.COLLECTING)
    state.intent = CREATE_INCIDENT_ACTION
    state.pending_action = CREATE_INCIDENT_ACTION
    state.collected_details = {}

    details: dict[str, str] = {}
    captured, errors = _apply(details, _strip_request_phrases(message or ""))
    state.collected_details = details

    return _finish(
        state, captured, errors, preamble="🎫 I can help create an incident."
    )


def process_collection_message(
    state: ConversationState,
    message: str,
) -> CollectionResult:
    """
    Handle one user message while in ``COLLECTING``.

    * Cancellation phrases (shared with BL-003) → ``CANCELLED → IDLE``.
    * Otherwise capture/correct fields, report invalid values, and either
      ask for the next missing field or move to ``READY_FOR_CONFIRMATION``.
    """
    if state.phase is not ConversationPhase.COLLECTING:
        raise IncidentCollectionError(
            f"Incident collection requires phase 'collecting', "
            f"not '{state.phase.value}'."
        )

    normalised = (message or "").strip().lower()

    if normalised in _CANCEL_PHRASES:
        state.transition_to(ConversationPhase.CANCELLED)
        state.transition_to(ConversationPhase.IDLE)
        logger.debug("incident_collection: cancelled")
        return CollectionResult(
            reply=(
                "❌ Cancelled. No incident has been created.\n\n"
                "Let me know if there is anything else I can help with."
            ),
            phase=state.phase,
            missing=(),
            cancelled=True,
        )

    details = sanitize_details(state.collected_details)

    if any(phrase in normalised for phrase in _HELP_PHRASES):
        state.collected_details = details
        needed = missing_fields(details)
        listing = "\n".join(
            f"{i}. **{_FIELD_LABELS[f]}**" for i, f in enumerate(needed, 1)
        )
        return CollectionResult(
            reply=(
                "🎫 To create the incident, I still need:\n\n"
                f"{listing}\n\n"
                "Impact and urgency must each be 1, 2, or 3. "
                "You can provide several details in one message."
            ),
            phase=state.phase,
            missing=needed,
        )

    captured, errors = _apply(details, message or "")
    state.collected_details = details
    return _finish(state, captured, errors)
