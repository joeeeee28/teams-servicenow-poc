"""
app/state.py — Typed conversation state machine (BL-002).

OVERVIEW
────────
Replaces the previous flat ``ConversationState`` dataclass (which used
independent boolean flags such as ``awaiting_confirmation``) with an
explicit state machine based on a single authoritative ``ConversationPhase``
enum.

STATE MODEL
───────────
::

    IDLE ──► COLLECTING ──► READY_FOR_CONFIRMATION ──► EXECUTING ──► COMPLETED ──► IDLE
                 │                   │                      │
                 └──────────────►    ▼                      ▼
                                 CANCELLED              FAILED ──► IDLE
                                     │
                                     ▼
                                    IDLE

VALID TRANSITIONS
─────────────────
    IDLE                  → COLLECTING
    COLLECTING            → READY_FOR_CONFIRMATION
    COLLECTING            → CANCELLED   (BL-006: user cancels during collection)
    READY_FOR_CONFIRMATION → EXECUTING
    READY_FOR_CONFIRMATION → CANCELLED
    EXECUTING             → COMPLETED
    EXECUTING             → FAILED
    COMPLETED             → IDLE
    CANCELLED             → IDLE
    FAILED                → IDLE

All other transitions raise ``InvalidTransitionError``.

PURITY GUARANTEE
────────────────
The state machine does NOT:
  - call ServiceNow
  - call Ollama
  - call Teams
  - perform authorization
  - access credentials
  - perform network operations

It is a pure orchestration primitive.

PERSISTENCE BOUNDARY
────────────────────
``StateRepository`` is an abstract base class keyed by ``StateKey``
(tenant + user + conversation).  ``InMemoryStateRepository`` is the
test/dev implementation; ``app.state_store.SqliteStateRepository``
(DEMO-01) persists state across restarts.  The application selects the
repository explicitly at startup via ``configure_state_repository()``.
Repository failures raise ``StatePersistenceError`` — callers fail safe and
never fall back to another store.

SECURITY
────────
No user message content, credentials, or tokens are logged here.
"""

from __future__ import annotations

import abc
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Union

logger = logging.getLogger(__name__)


# ===========================================================================
# Conversation phase
# ===========================================================================

class ConversationPhase(str, Enum):
    """
    Single authoritative phase for a conversation.

    Using ``str`` as a mixin makes the values JSON-serialisable and
    printable without extra conversion.
    """

    IDLE = "idle"
    """No active workflow.  The bot is waiting for a new user request."""

    COLLECTING = "collecting"
    """The bot is gathering details needed to proceed (e.g. incident fields)."""

    READY_FOR_CONFIRMATION = "ready_for_confirmation"
    """
    All required details are collected; waiting for the user to confirm
    before any side-effecting action is taken.
    """

    EXECUTING = "executing"
    """
    A confirmed action is in progress (reserved for BL-003+).
    The state machine records this phase but does NOT perform execution.
    """

    COMPLETED = "completed"
    """The action completed successfully."""

    CANCELLED = "cancelled"
    """The user cancelled the pending action."""

    FAILED = "failed"
    """The action failed.  ``last_error`` should describe the cause."""


# ===========================================================================
# Valid transition table
# ===========================================================================

_VALID_TRANSITIONS: frozenset[tuple[ConversationPhase, ConversationPhase]] = frozenset(
    {
        (ConversationPhase.IDLE,                   ConversationPhase.COLLECTING),
        (ConversationPhase.COLLECTING,             ConversationPhase.READY_FOR_CONFIRMATION),
        (ConversationPhase.COLLECTING,             ConversationPhase.CANCELLED),
        (ConversationPhase.READY_FOR_CONFIRMATION, ConversationPhase.EXECUTING),
        (ConversationPhase.READY_FOR_CONFIRMATION, ConversationPhase.CANCELLED),
        (ConversationPhase.EXECUTING,              ConversationPhase.COMPLETED),
        (ConversationPhase.EXECUTING,              ConversationPhase.FAILED),
        (ConversationPhase.COMPLETED,              ConversationPhase.IDLE),
        (ConversationPhase.CANCELLED,              ConversationPhase.IDLE),
        (ConversationPhase.FAILED,                 ConversationPhase.IDLE),
    }
)


# ===========================================================================
# Exceptions
# ===========================================================================

class InvalidTransitionError(Exception):
    """
    Raised when a caller attempts a state transition that is not in the
    valid transition table.

    Example::

        raise InvalidTransitionError(
            ConversationPhase.IDLE,
            ConversationPhase.COMPLETED,
        )
    """

    def __init__(
        self,
        from_phase: ConversationPhase,
        to_phase: ConversationPhase,
    ) -> None:
        self.from_phase = from_phase
        self.to_phase = to_phase
        super().__init__(
            f"Invalid transition: {from_phase.value!r} → {to_phase.value!r}"
        )


class StatePersistenceError(Exception):
    """
    Raised when conversation state cannot be loaded, saved or cleared
    (DEMO-01).

    ``operation`` is ``"load"``, ``"save"`` or ``"clear"``.  The message is
    fixed text — it never contains state content, identifiers or driver
    error details.
    """

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"conversation state {operation} failed")


# ===========================================================================
# State key (DEMO-01)
# ===========================================================================

_MAX_KEY_PART_LENGTH = 512


def _key_ref(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8] if value else "-"


@dataclass(frozen=True)
class StateKey:
    """
    Identifies one conversation's state: tenant + user + conversation.

    Two keys that differ in any part address completely separate state, so a
    message from another tenant, another user or another conversation can
    never read or change this conversation's pending action.

    ``tenant_id`` and ``conversation_id`` may be ``""`` when the channel does
    not supply them; ``user_id`` is required.  ``repr`` shows only short
    hashes so a key can never leak identifiers into logs.
    """

    tenant_id: str
    user_id: str
    conversation_id: str = ""

    def __post_init__(self) -> None:
        for name in ("tenant_id", "user_id", "conversation_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) > _MAX_KEY_PART_LENGTH:
                raise ValueError(f"StateKey.{name} must be a string of at most "
                                 f"{_MAX_KEY_PART_LENGTH} characters")
        if not self.user_id.strip():
            raise ValueError("StateKey.user_id is required")

    @classmethod
    def legacy(cls, user_id: str) -> "StateKey":
        """Key for callers that address state by user id only."""
        return cls(tenant_id="", user_id=user_id, conversation_id="")

    def __repr__(self) -> str:
        return (f"StateKey(tenant={_key_ref(self.tenant_id)}, "
                f"user={_key_ref(self.user_id)}, "
                f"conversation={_key_ref(self.conversation_id)})")

    __str__ = __repr__


StateKeyLike = Union[StateKey, str]


def coerce_state_key(key: StateKeyLike) -> StateKey:
    """Accept a ``StateKey`` or a legacy user-id string."""
    if isinstance(key, StateKey):
        return key
    if isinstance(key, str):
        return StateKey.legacy(key)
    raise TypeError("state key must be a StateKey or a user id string")


# ===========================================================================
# Passive transition listeners (BL-011 observability)
# ===========================================================================

# Called as ``listener(previous_phase, new_phase)`` AFTER a successful
# transition.  Listeners are observers only: they cannot veto or alter a
# transition, and any exception they raise is swallowed.
_transition_listeners: list = []


def add_transition_listener(listener) -> None:
    """Register a passive observer of successful phase transitions."""
    if listener not in _transition_listeners:
        _transition_listeners.append(listener)


# ===========================================================================
# Conversation state dataclass
# ===========================================================================

@dataclass
class ConversationState:
    """
    All state associated with a single user's conversation.

    This dataclass is intentionally free of business logic.  Transitions
    are performed by ``transition_to()``, not by mutating ``phase``
    directly.

    Fields
    ──────
    phase
        Current phase of the conversation.  The only authoritative phase
        indicator — do not add supplementary boolean flags.

    intent
        The classified intent of the most recent user request
        (e.g. ``"create_incident"``, ``"incident_status"``).

    summary
        Short human-readable summary of the request, produced by the AI
        classifier or the deterministic router.

    collected_details
        Key/value pairs gathered during the ``COLLECTING`` phase.  The
        exact keys depend on the active workflow (e.g. ``"description"``,
        ``"impact"``).

    pending_action
        Opaque tag identifying what will happen upon confirmation
        (e.g. ``"create_incident"``).  Set when entering
        ``READY_FOR_CONFIRMATION``.

    incident_number
        ServiceNow incident number, if already known (e.g. from the
        deterministic router for ``incident_status`` queries).

    last_error
        Human-readable description of the most recent failure.  Populated
        when entering ``FAILED``; cleared on ``FAILED → IDLE``.

    correlation_id
        Audit correlation identifier (BL-010) shared by every audit event of
        one logical operation (request → confirmation → execution), which
        spans several Teams messages.  Cleared on reset to ``IDLE``.

    created_at / updated_at
        UTC timestamps maintained by the repository on save (DEMO-01).
        ``None`` until the state is first saved.  Not cleared on reset.
    """

    phase: ConversationPhase = ConversationPhase.IDLE
    intent: str | None = None
    summary: str | None = None
    collected_details: dict[str, Any] = field(default_factory=dict)
    pending_action: str | None = None
    incident_number: str | None = None
    last_error: str | None = None
    correlation_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def transition_to(self, new_phase: ConversationPhase) -> "ConversationState":
        """
        Validate and perform a phase transition *in-place*.

        Returns ``self`` so callers can chain if desired.

        Raises
        ──────
        InvalidTransitionError
            If the ``(current_phase, new_phase)`` pair is not in the
            valid transition table.
        """
        pair = (self.phase, new_phase)
        if pair not in _VALID_TRANSITIONS:
            raise InvalidTransitionError(self.phase, new_phase)

        # Clear transient fields on terminal → IDLE resets.
        if new_phase is ConversationPhase.IDLE:
            self.intent = None
            self.summary = None
            self.collected_details = {}
            self.pending_action = None
            self.incident_number = None
            self.last_error = None
            self.correlation_id = None

        previous_phase = self.phase
        self.phase = new_phase

        for listener in tuple(_transition_listeners):
            try:
                listener(previous_phase, new_phase)
            except Exception:  # noqa: BLE001 — observers must never affect state
                logger.debug("transition listener failed")

        return self


# ===========================================================================
# Repository abstraction
# ===========================================================================

class StateRepository(abc.ABC):
    """
    Abstract repository for ``ConversationState`` keyed by ``StateKey``
    (tenant + user + conversation).  A plain string is accepted as a legacy
    user-id key (``StateKey.legacy``).

    Implementations must guarantee isolation between keys: fetching or
    modifying one key's state must never affect another key's state.
    Implementations report storage failures as ``StatePersistenceError``.
    """

    @abc.abstractmethod
    def get(self, key: StateKeyLike) -> ConversationState:
        """
        Return the ``ConversationState`` for *key*.

        If no state exists yet, a new ``ConversationState()`` (in ``IDLE``)
        is returned.  Persistent implementations return a copy; changes are
        stored only by ``save()``.
        """

    @abc.abstractmethod
    def save(self, key: StateKeyLike, state: ConversationState) -> None:
        """Persist *state* for *key*."""

    @abc.abstractmethod
    def clear(self, key: StateKeyLike) -> None:
        """
        Remove the state for *key*.

        After this call, ``get(key)`` must return a fresh
        ``ConversationState()`` in ``IDLE``.
        """


# ===========================================================================
# In-memory implementation (tests / local development)
# ===========================================================================

class InMemoryStateRepository(StateRepository):
    """
    In-memory ``StateRepository`` for tests and local development.

    State is lost on restart.  The running application uses the persistent
    ``app.state_store.SqliteStateRepository`` unless ``STATE_STORE=memory``
    is set explicitly.
    """

    def __init__(self) -> None:
        # Private — never access _store from outside tests.
        self._store: dict[StateKey, ConversationState] = {}

    def get(self, key: StateKeyLike) -> ConversationState:
        key = coerce_state_key(key)
        if key not in self._store:
            self._store[key] = ConversationState()
        return self._store[key]

    def save(self, key: StateKeyLike, state: ConversationState) -> None:
        self._store[coerce_state_key(key)] = state

    def clear(self, key: StateKeyLike) -> None:
        self._store.pop(coerce_state_key(key), None)


# ===========================================================================
# Module-level default repository
# ===========================================================================

# In-memory until the application configures its repository at startup
# (app.main lifespan → app.state_store.create_state_repository).  Tests that
# need isolation should instantiate their own repository.
_default_repo: StateRepository = InMemoryStateRepository()


def configure_state_repository(repo: StateRepository) -> None:
    """Select the repository used by the module-level helpers."""
    global _default_repo
    if not isinstance(repo, StateRepository):
        raise TypeError("repo must be a StateRepository")
    _default_repo = repo


def get_state_repository() -> StateRepository:
    """The repository currently used by the module-level helpers."""
    return _default_repo


# ===========================================================================
# Module-level helper functions (backward-compatible surface)
# ===========================================================================

def get_session(user_id: StateKeyLike) -> ConversationState:
    """
    Return the ``ConversationState`` for *user_id* (a ``StateKey`` or a
    legacy user-id string) from the default repository.  Returns a new IDLE
    state if none exists.
    """
    return _default_repo.get(user_id)


def save_session(user_id: StateKeyLike, state: ConversationState) -> None:
    """Persist *state* for *user_id* in the default repository."""
    _default_repo.save(user_id, state)


def clear_session(user_id: StateKeyLike) -> None:
    """Remove *user_id*'s state from the default repository."""
    _default_repo.clear(user_id)


def update_session(
    user_id: StateKeyLike,
    *,
    intent: str | None = None,
    summary: str | None = None,
    collected_details: dict[str, Any] | None = None,
    awaiting_confirmation: bool | None = None,
    incident_number: str | None = None,
    pending_action: str | None = None,
    last_error: str | None = None,
) -> ConversationState:
    """
    Convenience updater for the default repository.

    Mutates the session in-place and saves it.  Callers that need a
    phase transition should obtain the state object and call
    ``state.transition_to(new_phase)`` directly.

    The ``awaiting_confirmation`` parameter is accepted for backward
    compatibility but is a no-op: phase transitions should be performed
    explicitly via ``state.transition_to()``.

    .. deprecated::
        ``awaiting_confirmation`` — use ``state.transition_to(
        ConversationPhase.READY_FOR_CONFIRMATION)`` instead.
    """
    state = _default_repo.get(user_id)

    if intent is not None:
        state.intent = intent

    if summary is not None:
        state.summary = summary

    if collected_details:
        state.collected_details.update(collected_details)

    if incident_number is not None:
        state.incident_number = incident_number

    if pending_action is not None:
        state.pending_action = pending_action

    if last_error is not None:
        state.last_error = last_error

    # awaiting_confirmation is deliberately ignored — kept only for API
    # compatibility with any callers that have not yet been updated.
    if awaiting_confirmation is not None:
        logger.debug(
            "update_session: awaiting_confirmation is deprecated; "
            "use state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)"
        )

    _default_repo.save(user_id, state)
    return state
