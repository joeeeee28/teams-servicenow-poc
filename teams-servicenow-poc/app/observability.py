"""
app/observability.py — Structured operational observability (BL-011).

PURPOSE
───────
Lets operators follow request flow, latency, outcomes and failures:

    request_started → route_selected → authorization_decision →
    confirmation_decision → tool_started → tool_completed / tool_failed →
    state_transition … → request_completed / request_failed

Events are one JSON line each on the dedicated ``app.observability`` logger.

PASSIVE BY DESIGN
─────────────────
Observability only watches.  It never grants or denies access, never gates
confirmation, never executes or skips a tool and never changes a result.
``ObservabilityLogger.record()`` never raises; a failure to record is reported
on the sibling ``app.observability_errors`` logger (exception type only).

PRIVACY BY CONSTRUCTION
───────────────────────
``ObsEvent`` has no free-text field.  Every value is an enum, a validated
identifier, a number, or an approved metadata key with an enumerated value.
The user is referenced by ``user_ref`` — a 16-hex SHA-256 prefix of
tenant+user, not the raw identifier.  Messages, prompts, completions,
ServiceNow payloads, descriptions, work notes, tokens and headers cannot be
represented in an event.

RELATION TO BL-010
──────────────────
BL-010 audit events are the security record; BL-011 events are operational
telemetry.  They share correlation identifiers (``request_id`` per Teams
message; the operation's ``correlation_id`` while a create/update is in
progress) but are separate channels with separate guarantees.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from app.security.authorization import AuthorizableAction
from app.state import ConversationPhase, add_transition_listener

OBSERVABILITY_LOGGER_NAME = "app.observability"

# Failures to record go to a SIBLING logger so the channel stays pure JSON.
logger = logging.getLogger("app.observability_errors")


# ===========================================================================
# Controlled vocabulary
# ===========================================================================

class ObsEventName(str, Enum):
    REQUEST_STARTED = "request_started"
    REQUEST_COMPLETED = "request_completed"
    REQUEST_FAILED = "request_failed"
    ROUTE_SELECTED = "route_selected"
    STATE_TRANSITION = "state_transition"
    AUTHORIZATION_DECISION = "authorization_decision"
    CONFIRMATION_DECISION = "confirmation_decision"
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"


class ObsComponent(str, Enum):
    API = "api"
    ROUTER = "router"
    AI_CLASSIFIER = "ai_classifier"
    CONVERSATION = "conversation"
    AUTHORIZATION = "authorization"
    CONFIRMATION = "confirmation"
    TOOL_GATEWAY = "tool_gateway"
    KNOWLEDGE = "knowledge"          # DEMO-03 read-only knowledge search
    HISTORY = "history"              # DEMO-04 read-only historical case search


class ObsOutcome(str, Enum):
    STARTED = "started"
    SUCCESS = "success"
    DENIED = "denied"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"


_ALLOWED_OUTCOMES: dict[ObsEventName, frozenset[ObsOutcome]] = {
    ObsEventName.REQUEST_STARTED: frozenset({ObsOutcome.STARTED}),
    ObsEventName.REQUEST_COMPLETED: frozenset({ObsOutcome.SUCCESS}),
    ObsEventName.REQUEST_FAILED: frozenset({ObsOutcome.FAILED}),
    ObsEventName.ROUTE_SELECTED: frozenset({ObsOutcome.SUCCESS}),
    ObsEventName.STATE_TRANSITION: frozenset({ObsOutcome.SUCCESS}),
    ObsEventName.AUTHORIZATION_DECISION: frozenset({ObsOutcome.SUCCESS, ObsOutcome.DENIED}),
    ObsEventName.CONFIRMATION_DECISION: frozenset(
        {ObsOutcome.SUCCESS, ObsOutcome.CANCELLED, ObsOutcome.REJECTED}),
    ObsEventName.TOOL_STARTED: frozenset({ObsOutcome.STARTED}),
    ObsEventName.TOOL_COMPLETED: frozenset({ObsOutcome.SUCCESS}),
    ObsEventName.TOOL_FAILED: frozenset(
        {ObsOutcome.FAILED, ObsOutcome.DENIED, ObsOutcome.REJECTED}),
}

# ServiceNow operation types (ServiceNowToolAction values), plus the DEMO-03
# read-only knowledge search.
OPERATIONS = frozenset({"get_incident", "create_incident", "update_incident",
                        "knowledge_search", "historical_case_search", "search_catalog",
                        "create_request"})

# The ONLY metadata keys, each with its enumerated values.
APPROVED_METADATA: dict[str, frozenset[str]] = {
    "route": frozenset({"incident_status", "incident_update", "none"}),
    "intent": frozenset({
        "diagnose", "find_solution", "create_incident", "incident_status",
        "service_request", "human_escalation", "general",
    }),
    "pending_action": frozenset({"create_incident", "update_incident", "create_request"}),
    "stage": frozenset({"request_stage", "execution_stage", "current_value_read"}),
}

_PHASES = frozenset(p.value for p in ConversationPhase)
_REF_RE = re.compile(r"^[A-Za-z0-9:_\-.|]{1,128}$")
_USER_REF_RE = re.compile(r"^[0-9a-f]{16}$")
_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")


def _check(name: str, value: Any, pattern: re.Pattern, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise ValueError(f"observability field '{name}' is required")
        return
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"observability field '{name}' is not a valid identifier")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def user_ref(user_id: Any, tenant_id: Any) -> Optional[str]:
    """Pseudonymous, stable, non-reversible user reference (None if unknown)."""
    if not isinstance(user_id, str) or not user_id:
        return None
    material = f"{tenant_id if isinstance(tenant_id, str) else ''}:{user_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def elapsed_ms(started: float) -> float:
    """Milliseconds since a ``time.monotonic()`` reading."""
    return round(max(0.0, (time.monotonic() - started) * 1000.0), 3)


# ===========================================================================
# Event
# ===========================================================================

@dataclass(frozen=True)
class ObsEvent:
    event_name: ObsEventName
    component: ObsComponent
    outcome: ObsOutcome
    correlation_id: str
    request_id: Optional[str] = None
    action: Optional[AuthorizableAction] = None
    duration_ms: Optional[float] = None
    user_ref: Optional[str] = None
    operation: Optional[str] = None
    error_code: Optional[str] = None
    phase: Optional[str] = None
    previous_phase: Optional[str] = None
    result_count: Optional[int] = None
    metadata: dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not isinstance(self.event_name, ObsEventName):
            raise ValueError("event_name must be an ObsEventName")
        if not isinstance(self.component, ObsComponent):
            raise ValueError("component must be an ObsComponent")
        if not isinstance(self.outcome, ObsOutcome):
            raise ValueError("outcome must be an ObsOutcome")
        if self.outcome not in _ALLOWED_OUTCOMES[self.event_name]:
            raise ValueError(
                f"outcome {self.outcome.value!r} is not valid for {self.event_name.value!r}")
        if self.action is not None and not isinstance(self.action, AuthorizableAction):
            raise ValueError("action must be an AuthorizableAction")
        _check("correlation_id", self.correlation_id, _REF_RE, required=True)
        _check("request_id", self.request_id, _REF_RE)
        _check("user_ref", self.user_ref, _USER_REF_RE)
        _check("error_code", self.error_code, _CODE_RE)
        if self.operation is not None and self.operation not in OPERATIONS:
            raise ValueError("operation must be a known ServiceNow operation")
        for name in ("phase", "previous_phase"):
            value = getattr(self, name)
            if value is not None and value not in _PHASES:
                raise ValueError(f"{name} must be a ConversationPhase value")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, (int, float))
            or self.duration_ms < 0
        ):
            raise ValueError("duration_ms must be a non-negative number")
        if self.result_count is not None and (
            isinstance(self.result_count, bool) or not isinstance(self.result_count, int)
            or not 0 <= self.result_count <= 100
        ):
            raise ValueError("result_count must be a small non-negative integer")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dict")
        for key, value in self.metadata.items():
            allowed = APPROVED_METADATA.get(key)
            if allowed is None or value not in allowed:
                raise ValueError("metadata may only contain approved keys and values")

    def to_dict(self) -> dict[str, Any]:
        data = {
            "timestamp": self.timestamp,
            "event_name": self.event_name.value,
            "component": self.component.value,
            "outcome": self.outcome.value,
            "correlation_id": self.correlation_id,
            "request_id": self.request_id,
            "action": self.action.value if self.action else None,
            "duration_ms": self.duration_ms,
            "user_ref": self.user_ref,
            "operation": self.operation,
            "error_code": self.error_code,
            "phase": self.phase,
            "previous_phase": self.previous_phase,
            "result_count": self.result_count,
            "metadata": dict(self.metadata) or None,
        }
        return {k: v for k, v in data.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def __repr__(self) -> str:
        return f"ObsEvent({self.to_json()})"

    __str__ = __repr__


# ===========================================================================
# Per-request context (propagates correlation through the request)
# ===========================================================================

@dataclass
class RequestContext:
    correlation_id: str
    request_id: str
    user_ref: Optional[str] = None
    failed_code: Optional[str] = None


_CURRENT: contextvars.ContextVar[Optional[RequestContext]] = contextvars.ContextVar(
    "observability_request", default=None
)


def begin_request(correlation_id: str, request_id: str, user: Optional[str] = None):
    """Bind *ctx* for the current request; returns a token for ``end_request``."""
    return _CURRENT.set(RequestContext(correlation_id, request_id, user))


def end_request(token) -> None:
    try:
        _CURRENT.reset(token)
    except (ValueError, LookupError):  # pragma: no cover — defensive
        _CURRENT.set(None)


def current_request() -> Optional[RequestContext]:
    return _CURRENT.get()


def mark_request_failed(error_code: str) -> None:
    """Flag the current request as failed (reported by request_failed)."""
    ctx = _CURRENT.get()
    if ctx is not None and _CODE_RE.fullmatch(error_code or ""):
        ctx.failed_code = error_code


# ===========================================================================
# Logger
# ===========================================================================

class ObservabilityLogger:
    """Emits ``ObsEvent`` records as JSON lines on ``app.observability``."""

    def __init__(self, sink: Optional[logging.Logger] = None) -> None:
        self._sink = sink or logging.getLogger(OBSERVABILITY_LOGGER_NAME)

    def emit(self, event: ObsEvent) -> None:
        self._sink.info(event.to_json(), extra={"observability": event.to_dict()})

    def record(
        self,
        event_name: ObsEventName,
        component: ObsComponent,
        outcome: ObsOutcome,
        *,
        correlation_id: Optional[str] = None,
        **fields: Any,
    ) -> Optional[ObsEvent]:
        """
        Build and emit an event, filling correlation/request/user from the
        current request context.  NEVER raises.
        """
        try:
            ctx = _CURRENT.get()
            if ctx is not None:
                fields.setdefault("request_id", ctx.request_id)
                fields.setdefault("user_ref", ctx.user_ref)
            corr = correlation_id if isinstance(correlation_id, str) and _REF_RE.fullmatch(
                correlation_id) else (ctx.correlation_id if ctx else str(uuid.uuid4()))
            fields = {k: v for k, v in fields.items() if v is not None or k == "metadata"}
            if fields.get("metadata") is None:
                fields.pop("metadata", None)
            event = ObsEvent(event_name, component, outcome, corr, **fields)
            self.emit(event)
            return event
        except Exception as exc:  # noqa: BLE001 — observability must never break callers
            logger.warning(
                "observability event could not be recorded: %s (%s)",
                getattr(event_name, "value", "unknown"),
                type(exc).__name__,
            )
            return None


observability = ObservabilityLogger()


# ===========================================================================
# State-machine observation (passive listener)
# ===========================================================================

def _on_transition(previous: ConversationPhase, new: ConversationPhase) -> None:
    # Looked up at call time so tests / future sinks can replace
    # ``app.observability.observability`` in one place.
    globals()["observability"].record(
        ObsEventName.STATE_TRANSITION,
        ObsComponent.CONVERSATION,
        ObsOutcome.SUCCESS,
        phase=new.value,
        previous_phase=previous.value,
    )


add_transition_listener(_on_transition)
