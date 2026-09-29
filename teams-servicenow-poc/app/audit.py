"""
app/audit.py — Security audit logging (BL-010).

PURPOSE
───────
Records security-relevant actions (incident read / create / update requests,
authorization decisions, confirmation decisions, execution outcomes and Tool
Gateway rejections) as structured, machine-readable events on the dedicated
``app.audit`` logger.

Audit logging is OBSERVATION ONLY:
  - it never grants or denies access,
  - it never executes a tool,
  - it never changes an operation's result,
  - a failure to record an event is swallowed (and reported on the normal
    logger) so it can neither break nor bypass the security controls.

PRIVACY BY CONSTRUCTION
───────────────────────
``AuditEvent`` has NO free-text fields.  Every field is an enum, a strictly
validated identifier, or a short ``snake_case`` reason code.  User messages,
incident descriptions, LLM prompts/completions, ServiceNow payloads, tokens,
headers, display names and e-mail addresses therefore cannot be placed in an
audit record — construction fails instead.

EVENT OWNERSHIP
───────────────
    app/main.py                   *_REQUESTED, *_AUTHORIZED, *_DENIED,
                                  *_COMPLETED, *_FAILED, CONFIRMATION_*
    app/tools/servicenow.py       AUTHORIZATION_DENIED (gateway authorization
                                  guard) and TOOL_EXECUTION_REJECTED (gateway
                                  validation guard) — defence-in-depth layer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from app.security.authorization import AuthorizableAction

AUDIT_LOGGER_NAME = "app.audit"

# Failures to record are reported on a SIBLING logger (not a child), so the
# ``app.audit`` channel carries nothing but JSON audit events.
logger = logging.getLogger("app.audit_errors")


# ===========================================================================
# Typed vocabulary
# ===========================================================================

class AuditEventType(str, Enum):
    INCIDENT_READ_REQUESTED = "incident_read_requested"
    INCIDENT_READ_AUTHORIZED = "incident_read_authorized"
    INCIDENT_READ_DENIED = "incident_read_denied"
    INCIDENT_READ_COMPLETED = "incident_read_completed"
    INCIDENT_READ_FAILED = "incident_read_failed"

    INCIDENT_CREATE_REQUESTED = "incident_create_requested"
    INCIDENT_CREATE_AUTHORIZED = "incident_create_authorized"
    INCIDENT_CREATE_DENIED = "incident_create_denied"
    INCIDENT_CREATE_COMPLETED = "incident_create_completed"
    INCIDENT_CREATE_FAILED = "incident_create_failed"

    INCIDENT_UPDATE_REQUESTED = "incident_update_requested"
    INCIDENT_UPDATE_AUTHORIZED = "incident_update_authorized"
    INCIDENT_UPDATE_DENIED = "incident_update_denied"
    INCIDENT_UPDATE_COMPLETED = "incident_update_completed"
    INCIDENT_UPDATE_FAILED = "incident_update_failed"

    CONFIRMATION_REQUESTED = "confirmation_requested"
    CONFIRMATION_ACCEPTED = "confirmation_accepted"
    CONFIRMATION_CANCELLED = "confirmation_cancelled"
    CONFIRMATION_REJECTED = "confirmation_rejected"

    AUTHORIZATION_DENIED = "authorization_denied"
    TOOL_EXECUTION_REJECTED = "tool_execution_rejected"

    # DEMO-03: read-only knowledge search.
    KNOWLEDGE_SEARCH_REQUESTED = "knowledge_search_requested"
    KNOWLEDGE_SEARCH_AUTHORIZED = "knowledge_search_authorized"
    KNOWLEDGE_SEARCH_DENIED = "knowledge_search_denied"
    KNOWLEDGE_SEARCH_COMPLETED = "knowledge_search_completed"
    KNOWLEDGE_SEARCH_FAILED = "knowledge_search_failed"


class AuditOutcome(str, Enum):
    REQUESTED = "requested"
    ALLOWED = "allowed"
    DENIED = "denied"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    ACCEPTED = "accepted"
    CANCELLED = "cancelled"


def _outcomes_for(event_type: AuditEventType) -> frozenset[AuditOutcome]:
    name = event_type.name
    if event_type is AuditEventType.CONFIRMATION_ACCEPTED:
        return frozenset({AuditOutcome.ACCEPTED})
    if event_type is AuditEventType.CONFIRMATION_CANCELLED:
        return frozenset({AuditOutcome.CANCELLED})
    if event_type in (AuditEventType.CONFIRMATION_REJECTED,
                      AuditEventType.TOOL_EXECUTION_REJECTED):
        return frozenset({AuditOutcome.REJECTED})
    if name.endswith("_REQUESTED"):
        return frozenset({AuditOutcome.REQUESTED})
    if name.endswith("_AUTHORIZED"):
        return frozenset({AuditOutcome.ALLOWED})
    if name.endswith("_DENIED"):
        return frozenset({AuditOutcome.DENIED})
    if name.endswith("_COMPLETED"):
        return frozenset({AuditOutcome.SUCCEEDED})
    if name.endswith("_FAILED"):
        return frozenset({AuditOutcome.FAILED, AuditOutcome.REJECTED})
    raise ValueError(f"no outcome mapping for {event_type!r}")  # pragma: no cover


# Canonical (default) outcome for each event type.
DEFAULT_OUTCOME: dict[AuditEventType, AuditOutcome] = {
    t: (AuditOutcome.FAILED if t.name.endswith("_FAILED") else next(iter(_outcomes_for(t))))
    for t in AuditEventType
}

# Tool names the gateway can execute (ServiceNowToolAction values), plus the
# DEMO-03 read-only knowledge search.
AUDIT_TOOLS = frozenset({"get_incident", "create_incident", "update_incident",
                         "knowledge_search"})
MAX_AUDIT_ARTICLES = 5


# ===========================================================================
# Field validation — identifiers only, never free text
# ===========================================================================

_REF_RE = re.compile(r"^[A-Za-z0-9:_\-.|]{1,128}$")
_INCIDENT_RE = re.compile(r"^INC[0-9]{7,10}$")
_REASON_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_CONVERSATION_REF_RE = re.compile(r"^[0-9a-f]{16}$")
_ARTICLE_ID_RE = re.compile(r"^KB[0-9]{7}$")


def safe_ref(value: Any) -> Optional[str]:
    """``value`` if it is a plain identifier, otherwise None (never raises)."""
    if isinstance(value, str) and _REF_RE.fullmatch(value):
        return value
    return None


def safe_incident_number(value: Any) -> Optional[str]:
    """Upper-cased ASCII ``INC`` number if valid, otherwise None (never raises)."""
    if isinstance(value, str):
        candidate = value.strip().upper()
        if _INCIDENT_RE.fullmatch(candidate):
            return candidate
    return None


def conversation_ref(conversation_id: Any) -> Optional[str]:
    """Stable, non-reversible 16-hex-digit reference for a conversation id."""
    if not isinstance(conversation_id, str) or not conversation_id:
        return None
    return hashlib.sha256(conversation_id.encode("utf-8")).hexdigest()[:16]


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def _check(name: str, value: Any, pattern: re.Pattern, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise ValueError(f"audit field '{name}' is required")
        return
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"audit field '{name}' is not a valid identifier")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ===========================================================================
# Audit event
# ===========================================================================

@dataclass(frozen=True)
class AuditEvent:
    """
    One immutable audit record.  All fields are validated on construction;
    invalid values raise ``ValueError`` rather than being recorded.
    """

    event_type: AuditEventType
    outcome: AuditOutcome
    correlation_id: str
    action: Optional[AuthorizableAction] = None
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    conversation_ref: Optional[str] = None
    incident_number: Optional[str] = None
    tool: Optional[str] = None
    reason: Optional[str] = None
    result_count: Optional[int] = None
    article_ids: tuple[str, ...] = ()
    timestamp: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, AuditEventType):
            raise ValueError("audit event_type must be an AuditEventType")
        if not isinstance(self.outcome, AuditOutcome):
            raise ValueError("audit outcome must be an AuditOutcome")
        if self.outcome not in _outcomes_for(self.event_type):
            raise ValueError(
                f"outcome {self.outcome.value!r} is not valid for {self.event_type.value!r}"
            )
        if self.action is not None and not isinstance(self.action, AuthorizableAction):
            raise ValueError("audit action must be an AuthorizableAction")
        _check("correlation_id", self.correlation_id, _REF_RE, required=True)
        _check("request_id", self.request_id, _REF_RE)
        _check("user_id", self.user_id, _REF_RE)
        _check("tenant_id", self.tenant_id, _REF_RE)
        _check("conversation_ref", self.conversation_ref, _CONVERSATION_REF_RE)
        _check("incident_number", self.incident_number, _INCIDENT_RE)
        _check("reason", self.reason, _REASON_RE)
        if self.tool is not None and self.tool not in AUDIT_TOOLS:
            raise ValueError("audit tool must be a known gateway tool")
        if self.result_count is not None and (
            isinstance(self.result_count, bool) or not isinstance(self.result_count, int)
            or not 0 <= self.result_count <= 100
        ):
            raise ValueError("audit result_count must be a small non-negative integer")
        if not isinstance(self.article_ids, tuple) or len(self.article_ids) > MAX_AUDIT_ARTICLES \
                or not all(isinstance(a, str) and _ARTICLE_ID_RE.fullmatch(a)
                           for a in self.article_ids):
            raise ValueError("audit article_ids must be knowledge article identifiers")
        if not isinstance(self.timestamp, str) or not self.timestamp:
            raise ValueError("audit timestamp is required")

    def to_dict(self) -> dict[str, Any]:
        """Structured form; absent optional fields are omitted."""
        data = {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "outcome": self.outcome.value,
            "correlation_id": self.correlation_id,
            "action": self.action.value if self.action else None,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "conversation_ref": self.conversation_ref,
            "incident_number": self.incident_number,
            "tool": self.tool,
            "reason": self.reason,
            "result_count": self.result_count,
            "article_ids": list(self.article_ids) or None,
        }
        return {k: v for k, v in data.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def __repr__(self) -> str:
        return f"AuditEvent({self.to_json()})"

    __str__ = __repr__


# ===========================================================================
# Audit logger
# ===========================================================================

class AuditLogger:
    """
    Emits ``AuditEvent`` records as one JSON line each on the ``app.audit``
    logger (``extra={"audit": <dict>}`` carries the structured form too).

    Inject a custom ``logging.Logger`` (or subclass ``emit``) in tests.
    """

    def __init__(self, sink: Optional[logging.Logger] = None) -> None:
        self._sink = sink or logging.getLogger(AUDIT_LOGGER_NAME)

    def emit(self, event: AuditEvent) -> None:
        self._sink.info(event.to_json(), extra={"audit": event.to_dict()})

    def record(
        self,
        event_type: AuditEventType,
        *,
        correlation_id: Optional[str],
        outcome: Optional[AuditOutcome] = None,
        **fields: Any,
    ) -> Optional[AuditEvent]:
        """
        Build and emit an event.  NEVER raises: a failure to build or emit is
        reported on the module logger (exception type only) and None is
        returned, so callers' security decisions are unaffected.
        """
        try:
            event = AuditEvent(
                event_type=event_type,
                outcome=outcome if outcome is not None else DEFAULT_OUTCOME[event_type],
                correlation_id=correlation_id or new_correlation_id(),
                **fields,
            )
            self.emit(event)
            return event
        except Exception as exc:  # noqa: BLE001 — audit must never break callers
            logger.warning(
                "audit event could not be recorded: %s (%s)",
                getattr(event_type, "value", "unknown"),
                type(exc).__name__,
            )
            return None


# Default application audit logger.
audit_logger = AuditLogger()
