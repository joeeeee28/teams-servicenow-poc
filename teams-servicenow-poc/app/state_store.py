"""
app/state_store.py — Persistent conversation state (DEMO-01).

PURPOSE
───────
``SqliteStateRepository`` implements the BL-002 ``StateRepository`` interface
on a local SQLite file, so multi-turn conversations (collection →
confirmation → execution) survive process restarts without any external
infrastructure.  ``create_state_repository()`` selects the repository from
the environment at application startup.

ISOLATION
─────────
Each record is keyed by ``StateKey`` — tenant + user + conversation.  The
three parts are separate primary-key columns, so a message from another
tenant, user or conversation addresses a different row and can never read or
change this conversation's pending action.  The conversation id is stored as
a SHA-256 digest (as BL-010 does for audit), never in clear.

WHAT IS PERSISTED (allowlist)
─────────────────────────────
phase, pending_action, intent (known intents only), collected incident fields
(create: short_description / description / impact / urgency; update:
changes / requested / current for the same fields; DEMO-06 request:
item_ref / sys_id / item_name / variables, each validated) — only while the operation
is in progress, never for COMPLETED / FAILED — incident_number
(``INC`` + digits only), correlation_id (plain identifier only), last_error
(the gateway's fixed safe message), created_at and updated_at.

WHAT IS NEVER PERSISTED
───────────────────────
``summary`` (LLM classifier output), raw user messages, prompts, completions,
tokens, credentials, API keys, headers, display names, e-mail addresses and
ServiceNow response bodies.  Serialization is an allowlist: any other key or
value type is dropped before it reaches the database.

FAILURE POLICY
──────────────
Storage errors raise ``StatePersistenceError`` (fixed message, no content).
The caller fails the request safely; nothing falls back to another store.
A record that cannot be decoded is treated as absent (a new IDLE state) and
logged without content — an IDLE state has no pending action, so this can
never bypass confirmation or authorization.

The persistence layer is not reachable from the AI classifier: only the
conversation manager in ``app.main`` calls it, through the fixed
``get`` / ``save`` / ``clear`` interface.  No query is ever built from input.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from app.incident_collection import CREATE_INCIDENT_ACTION, INCIDENT_FIELDS
from app.incident_update import UPDATE_FIELDS, UPDATE_INCIDENT_ACTION
from app.request_collection import CREATE_REQUEST_ACTION
from app.state import (
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    StateKeyLike,
    StatePersistenceError,
    StateRepository,
    coerce_state_key,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "conversation_state.db"
MAX_STATE_BYTES = 64 * 1024

_PENDING_ACTIONS = frozenset({CREATE_INCIDENT_ACTION, UPDATE_INCIDENT_ACTION,
                              CREATE_REQUEST_ACTION})
_INTENTS = frozenset({
    "diagnose", "find_solution", "create_incident", "incident_status",
    "service_request", "human_escalation", "general", UPDATE_INCIDENT_ACTION,
})
_INCIDENT_FIELDS = frozenset(INCIDENT_FIELDS)
_UPDATE_FIELDS = frozenset(UPDATE_FIELDS)
_INCIDENT_NUMBER_RE = re.compile(r"^INC[0-9]{7,10}$")
# DEMO-06 request collection (validated exactly as the catalog models do).
_ITEM_REF_RE = re.compile(r"^CAT[0-9]{4}$")
_SYS_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_VARIABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
_MAX_ITEM_NAME = 80
_MAX_VARIABLES = 8
_MAX_VARIABLE_VALUE = 500
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9:_\-.|]{1,128}$")
_MAX_LAST_ERROR = 500
_PHASES_WITH_ACTION = frozenset({
    ConversationPhase.READY_FOR_CONFIRMATION,
    ConversationPhase.EXECUTING,
})
# After execution the collected text is never read again, so it is not kept
# at rest: user-typed descriptions (which may contain anything the user
# typed) are dropped as soon as the operation finishes.
_PHASES_WITHOUT_DETAILS = frozenset({
    ConversationPhase.COMPLETED,
    ConversationPhase.FAILED,
})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversation_state (
    tenant_id        TEXT    NOT NULL,
    user_id          TEXT    NOT NULL,
    conversation_ref TEXT    NOT NULL,
    schema_version   INTEGER NOT NULL,
    state_json       TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, user_id, conversation_ref)
)
"""


class StateDecodeError(ValueError):
    """A stored record does not match the persisted-state schema."""


# ===========================================================================
# Serialization (allowlist)
# ===========================================================================

def _clean_details(details: Any) -> dict[str, Any]:
    """
    Only the fields the create/update incident and (DEMO-06) create-request
    workflows use, each validated; anything else is dropped.
    """
    if not isinstance(details, Mapping):
        return {}
    clean: dict[str, Any] = {}
    for key, value in details.items():
        if key in _INCIDENT_FIELDS and isinstance(value, str):
            clean[key] = value
        elif key in ("changes", "current") and isinstance(value, Mapping):
            clean[key] = {f: v for f, v in value.items()
                          if f in _UPDATE_FIELDS and isinstance(v, str)}
        elif key == "requested" and isinstance(value, (list, tuple)):
            clean[key] = [f for f in value if f in _UPDATE_FIELDS]
        # DEMO-06: service request collection.
        elif key == "item_ref" and isinstance(value, str) and _ITEM_REF_RE.fullmatch(value):
            clean[key] = value
        elif key == "sys_id" and isinstance(value, str) and _SYS_ID_RE.fullmatch(value):
            clean[key] = value
        elif key == "item_name" and isinstance(value, str) and 0 < len(value) <= _MAX_ITEM_NAME:
            clean[key] = value
        elif key == "variables" and isinstance(value, Mapping):
            clean[key] = dict(list(
                (k, v) for k, v in value.items()
                if isinstance(k, str) and _VARIABLE_NAME_RE.fullmatch(k)
                and isinstance(v, str) and len(v) <= _MAX_VARIABLE_VALUE
            )[:_MAX_VARIABLES])
    return clean


def serialize_state(state: ConversationState) -> dict[str, Any]:
    """The persisted form of *state* — allowlisted fields only."""
    if not isinstance(state, ConversationState):
        raise TypeError("state must be a ConversationState")
    last_error = state.last_error if isinstance(state.last_error, str) else None
    phase = ConversationPhase(state.phase)
    return {
        "phase": phase.value,
        "intent": state.intent if state.intent in _INTENTS else None,
        "pending_action": state.pending_action if state.pending_action in _PENDING_ACTIONS else None,
        "collected_details": {} if phase in _PHASES_WITHOUT_DETAILS
        else _clean_details(state.collected_details),
        "incident_number": state.incident_number
        if isinstance(state.incident_number, str)
        and _INCIDENT_NUMBER_RE.fullmatch(state.incident_number) else None,
        "correlation_id": state.correlation_id
        if isinstance(state.correlation_id, str)
        and _CORRELATION_RE.fullmatch(state.correlation_id) else None,
        "last_error": last_error[:_MAX_LAST_ERROR] if last_error else None,
    }


def deserialize_state(data: Any) -> ConversationState:
    """Rebuild a ``ConversationState``; raises ``StateDecodeError`` if invalid."""
    if not isinstance(data, dict):
        raise StateDecodeError("record is not an object")
    try:
        phase = ConversationPhase(data.get("phase"))
    except ValueError:
        raise StateDecodeError("unknown phase") from None
    state = ConversationState(phase=phase)
    if phase not in _PHASES_WITHOUT_DETAILS:
        state.collected_details = _clean_details(data.get("collected_details"))
    # Re-apply the same allowlist the writer used.
    probe = ConversationState(
        phase=phase,
        intent=data.get("intent"),
        pending_action=data.get("pending_action"),
        incident_number=data.get("incident_number"),
        correlation_id=data.get("correlation_id"),
        last_error=data.get("last_error"),
    )
    clean = serialize_state(probe)
    state.intent = clean["intent"]
    state.pending_action = clean["pending_action"]
    state.incident_number = clean["incident_number"]
    state.correlation_id = clean["correlation_id"]
    state.last_error = clean["last_error"]
    if phase in _PHASES_WITH_ACTION and state.pending_action is None:
        raise StateDecodeError("phase requires a pending action")
    return state


def _conversation_ref(conversation_id: str) -> str:
    return hashlib.sha256(conversation_id.encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


# ===========================================================================
# SQLite repository
# ===========================================================================

class SqliteStateRepository(StateRepository):
    """
    ``StateRepository`` backed by a local SQLite database.

    ``get`` returns a copy of the stored state; changes are persisted only by
    ``save``.  One connection is shared behind a lock, so the repository is
    safe to use from the event loop and from worker threads.  Pass
    ``":memory:"`` for a private in-process database (tests).
    """

    def __init__(self, path: str | os.PathLike = DEFAULT_DB_PATH, *, timeout: float = 5.0) -> None:
        self._lock = threading.Lock()
        self._path = str(path)
        try:
            if self._path != ":memory:":
                _prepare_file(Path(self._path))
            self._conn = sqlite3.connect(self._path, timeout=timeout, check_same_thread=False)
            with self._conn:
                if self._path != ":memory:":
                    self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute(_SCHEMA)
        except (sqlite3.Error, OSError):
            logger.error("conversation state store could not be opened")
            raise StatePersistenceError("open") from None

    # -- StateRepository -----------------------------------------------------

    def get(self, key: StateKeyLike) -> ConversationState:
        k = coerce_state_key(key)
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT schema_version, state_json, created_at, updated_at "
                    "FROM conversation_state "
                    "WHERE tenant_id = ? AND user_id = ? AND conversation_ref = ?",
                    (k.tenant_id, k.user_id, _conversation_ref(k.conversation_id)),
                ).fetchone()
        except sqlite3.Error:
            logger.error("conversation state load failed")
            raise StatePersistenceError("load") from None

        if row is None:
            return ConversationState()

        version, state_json, created_at, updated_at = row
        try:
            if version != SCHEMA_VERSION:
                raise StateDecodeError("unsupported schema version")
            state = deserialize_state(json.loads(state_json))
        except (StateDecodeError, ValueError, TypeError):
            logger.warning("conversation state record unreadable; starting new conversation key=%r", k)
            return ConversationState()
        state.created_at = _parse_time(created_at)
        state.updated_at = _parse_time(updated_at)
        return state

    def save(self, key: StateKeyLike, state: ConversationState) -> None:
        k = coerce_state_key(key)
        try:
            state_json = json.dumps(serialize_state(state), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            logger.error("conversation state could not be serialized")
            raise StatePersistenceError("save") from None
        if len(state_json.encode("utf-8")) > MAX_STATE_BYTES:
            logger.error("conversation state exceeds %d bytes", MAX_STATE_BYTES)
            raise StatePersistenceError("save")

        now = _utc_now().isoformat()
        try:
            with self._lock, self._conn:
                row = self._conn.execute(
                    "INSERT INTO conversation_state "
                    "(tenant_id, user_id, conversation_ref, schema_version, state_json, "
                    " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (tenant_id, user_id, conversation_ref) DO UPDATE SET "
                    "schema_version = excluded.schema_version, "
                    "state_json = excluded.state_json, "
                    "updated_at = excluded.updated_at "
                    "RETURNING created_at, updated_at",
                    (k.tenant_id, k.user_id, _conversation_ref(k.conversation_id),
                     SCHEMA_VERSION, state_json, now, now),
                ).fetchone()
        except sqlite3.Error:
            logger.error("conversation state save failed")
            raise StatePersistenceError("save") from None
        state.created_at = _parse_time(row[0])
        state.updated_at = _parse_time(row[1])

    def clear(self, key: StateKeyLike) -> None:
        k = coerce_state_key(key)
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "DELETE FROM conversation_state "
                    "WHERE tenant_id = ? AND user_id = ? AND conversation_ref = ?",
                    (k.tenant_id, k.user_id, _conversation_ref(k.conversation_id)),
                )
        except sqlite3.Error:
            logger.error("conversation state clear failed")
            raise StatePersistenceError("clear") from None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _prepare_file(path: Path) -> None:
    """Create the database directory and file owner-only (0700 / 0600)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)


# ===========================================================================
# Factory
# ===========================================================================

def create_state_repository(env: Mapping[str, str] | None = None) -> StateRepository:
    """
    Repository selected by ``STATE_STORE`` (``sqlite`` — the default — or
    ``memory``).  ``STATE_DB_PATH`` overrides the SQLite file location.

    Raises ``ValueError`` for an unknown store and ``StatePersistenceError``
    if the database cannot be opened — the application must not start
    rather than silently run without persistence.
    """
    env = os.environ if env is None else env
    store = (env.get("STATE_STORE") or "sqlite").strip().lower()
    if store == "sqlite":
        return SqliteStateRepository(env.get("STATE_DB_PATH") or DEFAULT_DB_PATH)
    if store == "memory":
        logger.warning("STATE_STORE=memory: conversation state is NOT persistent")
        return InMemoryStateRepository()
    raise ValueError("STATE_STORE must be 'sqlite' or 'memory'")
