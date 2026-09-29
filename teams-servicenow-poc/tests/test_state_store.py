"""
tests/test_state_store.py — Test suite for DEMO-01 Persistent Conversation State.

Covers the SQLite ``StateRepository`` directly and drives ``app.main.on_message``
end to end on top of it (real BL-003 confirmation, BL-004 authorization,
BL-005 gateway, BL-010 audit, BL-011 observability; only the ServiceNow client
and the LLM classifier are mocked).

Requirement coverage:
 1.  Save / load / update / delete-reset.
 2.  Multi-user, multi-tenant and conversation isolation.
 3.  State transitions persist; transition rules are unchanged.
 4.  Persistence across repository instances (process restart).
 5.  Missing and corrupted records load as a fresh IDLE state.
 6.  Storage failures raise StatePersistenceError; the handler fails safely.
 7.  Sensitive data is never persisted.
 8.  Repository selection at startup never falls back silently.
 9.  BL-001..BL-011 flows (incl. BL-007 concurrent confirmation) work unchanged
     on the persistent store.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.main as main  # noqa: E402
import app.observability as obs  # noqa: E402
from app.audit import AuditEventType, AuditLogger  # noqa: E402
from app.incident_collection import start_incident_collection  # noqa: E402
from app.security.authorization import (  # noqa: E402
    DefaultAuthorizationPolicy,
    UserRole,
    authorize,
)
from app.servicenow import ServiceNowClient  # noqa: E402
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    InvalidTransitionError,
    StateKey,
    StatePersistenceError,
    StateRepository,
    coerce_state_key,
    configure_state_repository,
    get_session,
    get_state_repository,
    save_session,
)
from app.state_store import (  # noqa: E402
    SCHEMA_VERSION,
    SqliteStateRepository,
    create_state_repository,
    deserialize_state,
    serialize_state,
)
from app.tools.servicenow import ServiceNowToolGateway  # noqa: E402

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "demo01-user-aad-oid"
OTHER_USER = "demo01-other-user-aad-oid"
CONV = "19:demo01-conversation@thread.v2"
OTHER_CONV = "19:demo01-other-conversation@thread.v2"
KEY = StateKey(TENANT, USER, CONV)

FULL_MESSAGE = (
    "VPN is down for me and I can't access internal applications. "
    "Impact is 2 and urgency is 1."
)
LLM_SUMMARY = "LLM-SUMMARY-MARKER user cannot reach the VPN"
PASSWORD = "Hunter2-PASSWORD-MARKER"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.TOKEN-MARKER"
CURRENT = {
    "sys_id": "46d44a5dc0a8010e00f3c1a3b0bbf1e4", "number": "INC0010002",
    "short_description": "VPN unavailable", "state": "2", "impact": "3",
    "urgency": "3", "priority": "5", "work_notes": "WORK-NOTE-MARKER",
}
UPDATED = dict(CURRENT, impact="1", priority="3")
CREATED = {"sys_id": "abc123", "number": "INC0012345", "state": "1"}


class AgentPolicy(DefaultAuthorizationPolicy):
    """Keeps every BL-004 check (identity, tenant) but grants the agent role."""

    def resolve_role(self, identity):
        role = super().resolve_role(identity)
        return UserRole.SERVICE_DESK_AGENT if role is UserRole.EMPLOYEE else role


_AGENT = AgentPolicy()


def agent_authorize(identity, action):
    return authorize(identity, action, policy=_AGENT)


def _context(text, *, user=USER, tenant=TENANT, conversation=CONV):
    activity = SimpleNamespace(
        id="1712345678901",
        text=text,
        from_=SimpleNamespace(aad_object_id=user, id=user, name="Demo User"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
        conversation=SimpleNamespace(id=conversation),
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


def _ready_state(**overrides) -> ConversationState:
    state = ConversationState()
    start_incident_collection(state, FULL_MESSAGE)
    assert state.phase is ConversationPhase.READY_FOR_CONFIRMATION
    for name, value in overrides.items():
        setattr(state, name, value)
    return state


class _TempDir(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "state" / "conversation_state.db"

    def _repo(self) -> SqliteStateRepository:
        repo = SqliteStateRepository(self.path)
        self.addCleanup(repo.close)
        return repo

    def _raw_bytes(self) -> bytes:
        return b"".join(p.read_bytes() for p in self.path.parent.iterdir())


# ===========================================================================
# StateKey
# ===========================================================================

class TestStateKey(unittest.TestCase):

    def test_parts_are_distinct(self):
        self.assertNotEqual(StateKey(TENANT, USER, CONV), StateKey(OTHER_TENANT, USER, CONV))
        self.assertNotEqual(StateKey(TENANT, USER, CONV), StateKey(TENANT, OTHER_USER, CONV))
        self.assertNotEqual(StateKey(TENANT, USER, CONV), StateKey(TENANT, USER, OTHER_CONV))

    def test_user_required_and_types_checked(self):
        for bad in ("", "   "):
            with self.subTest(user=bad), self.assertRaises(ValueError):
                StateKey(TENANT, bad, CONV)
        with self.assertRaises(ValueError):
            StateKey(None, USER, CONV)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            StateKey(TENANT, USER, "x" * 513)

    def test_repr_never_contains_identifiers(self):
        text = repr(KEY) + str(KEY)
        for raw in (TENANT, USER, CONV):
            self.assertNotIn(raw, text)

    def test_legacy_string_key(self):
        self.assertEqual(coerce_state_key(USER), StateKey("", USER, ""))
        self.assertIs(coerce_state_key(KEY), KEY)
        with self.assertRaises(TypeError):
            coerce_state_key(123)  # type: ignore[arg-type]


# ===========================================================================
# 1: Save / load / update / delete
# ===========================================================================

class TestCrud(_TempDir):

    def test_is_a_state_repository(self):
        self.assertIsInstance(self._repo(), StateRepository)

    def test_missing_state_is_fresh_idle(self):
        state = self._repo().get(KEY)
        self.assertEqual(state, ConversationState())
        self.assertIsNone(state.created_at)

    def test_save_and_load_round_trip(self):
        repo = self._repo()
        saved = _ready_state(correlation_id="op-create-1", intent="create_incident")
        repo.save(KEY, saved)
        loaded = repo.get(KEY)
        self.assertIsNot(loaded, saved)
        self.assertIs(loaded.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(loaded.pending_action, "create_incident")
        self.assertEqual(loaded.intent, "create_incident")
        self.assertEqual(loaded.collected_details, saved.collected_details)
        self.assertEqual(loaded.correlation_id, "op-create-1")

    def test_all_persisted_fields(self):
        repo = self._repo()
        state = ConversationState(
            phase=ConversationPhase.COLLECTING, intent="update_incident",
            pending_action="update_incident", incident_number="INC0010002",
            collected_details={"changes": {"impact": "1"}, "requested": ["urgency"],
                               "current": {"impact": "3"}},
            last_error="ServiceNow request failed", correlation_id="op-1",
        )
        repo.save(KEY, state)
        loaded = repo.get(KEY)
        for name in ("phase", "intent", "pending_action", "incident_number",
                     "collected_details", "last_error", "correlation_id"):
            self.assertEqual(getattr(loaded, name), getattr(state, name), name)

    def test_finished_operations_keep_no_collected_details(self):
        repo = self._repo()
        for phase in (ConversationPhase.COMPLETED, ConversationPhase.FAILED):
            with self.subTest(phase=phase):
                state = _ready_state(correlation_id="op-1")
                state.transition_to(ConversationPhase.EXECUTING).transition_to(phase)
                state.incident_number = "INC0012345"
                state.last_error = "ServiceNow request failed"
                repo.save(KEY, state)
                loaded = repo.get(KEY)
                self.assertIs(loaded.phase, phase)
                self.assertEqual(loaded.collected_details, {})
                self.assertEqual(loaded.incident_number, "INC0012345")
                self.assertEqual(loaded.correlation_id, "op-1")
                self.assertEqual(loaded.last_error, "ServiceNow request failed")

    def test_timestamps(self):
        repo = self._repo()
        state = _ready_state()
        repo.save(KEY, state)
        first = repo.get(KEY)
        self.assertIsNotNone(first.created_at)
        self.assertEqual(first.created_at.utcoffset().total_seconds(), 0)
        self.assertEqual(state.created_at, first.created_at)
        first.collected_details["impact"] = "3"
        repo.save(KEY, first)
        second = repo.get(KEY)
        self.assertEqual(second.created_at, first.created_at)
        self.assertGreaterEqual(second.updated_at, first.updated_at)

    def test_update_overwrites(self):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        state = repo.get(KEY)
        state.transition_to(ConversationPhase.CANCELLED)
        repo.save(KEY, state)
        self.assertIs(repo.get(KEY).phase, ConversationPhase.CANCELLED)

    def test_changes_without_save_are_not_persisted(self):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        repo.get(KEY).transition_to(ConversationPhase.EXECUTING)
        self.assertIs(repo.get(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_clear_resets(self):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        repo.clear(KEY)
        self.assertEqual(repo.get(KEY), ConversationState())
        repo.clear(KEY)  # clearing a missing key is harmless

    def test_reset_to_idle_is_persisted_clean(self):
        repo = self._repo()
        state = _ready_state(correlation_id="op-1")
        state.transition_to(ConversationPhase.CANCELLED).transition_to(ConversationPhase.IDLE)
        repo.save(KEY, state)
        loaded = repo.get(KEY)
        self.assertIs(loaded.phase, ConversationPhase.IDLE)
        self.assertEqual(loaded.collected_details, {})
        self.assertIsNone(loaded.pending_action)
        self.assertIsNone(loaded.correlation_id)

    def test_legacy_string_key_works(self):
        repo = self._repo()
        repo.save(USER, _ready_state())
        self.assertIs(repo.get(StateKey("", USER, "")).phase,
                      ConversationPhase.READY_FOR_CONFIRMATION)

    def test_in_memory_database(self):
        repo = SqliteStateRepository(":memory:")
        self.addCleanup(repo.close)
        repo.save(KEY, _ready_state())
        self.assertIs(repo.get(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)


# ===========================================================================
# 2: Isolation
# ===========================================================================

class TestIsolation(_TempDir):

    def _assert_isolated(self, other: StateKey):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        self.assertEqual(repo.get(other), ConversationState())
        other_state = repo.get(other)
        other_state.transition_to(ConversationPhase.COLLECTING)
        repo.save(other, other_state)
        repo.clear(other)
        self.assertIs(repo.get(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_multi_user(self):
        self._assert_isolated(StateKey(TENANT, OTHER_USER, CONV))

    def test_multi_tenant(self):
        self._assert_isolated(StateKey(OTHER_TENANT, USER, CONV))

    def test_conversation(self):
        self._assert_isolated(StateKey(TENANT, USER, OTHER_CONV))

    def test_missing_tenant_is_its_own_scope(self):
        self._assert_isolated(StateKey("", USER, CONV))

    def test_key_parts_cannot_be_concatenated_into_each_other(self):
        repo = self._repo()
        repo.save(StateKey("a", "b|c", ""), _ready_state())
        self.assertEqual(repo.get(StateKey("a|b", "c", "")), ConversationState())


# ===========================================================================
# 3: Transitions
# ===========================================================================

class TestTransitions(_TempDir):

    def test_full_cycle_persists_each_phase(self):
        repo = self._repo()
        state = repo.get(KEY)
        for phase in (ConversationPhase.COLLECTING, ConversationPhase.READY_FOR_CONFIRMATION,
                      ConversationPhase.EXECUTING, ConversationPhase.COMPLETED,
                      ConversationPhase.IDLE):
            if phase is ConversationPhase.READY_FOR_CONFIRMATION:
                state.pending_action = "create_incident"
            state.transition_to(phase)
            repo.save(KEY, state)
            state = repo.get(KEY)
            self.assertIs(state.phase, phase)

    def test_rules_unchanged_on_loaded_state(self):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        loaded = repo.get(KEY)
        with self.assertRaises(InvalidTransitionError):
            loaded.transition_to(ConversationPhase.COMPLETED)
        with self.assertRaises(InvalidTransitionError):
            loaded.transition_to(ConversationPhase.IDLE)
        self.assertIs(repo.get(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)


# ===========================================================================
# 4: Persistence across repository instances
# ===========================================================================

class TestRestart(_TempDir):

    def test_state_survives_new_instance(self):
        first = SqliteStateRepository(self.path)
        first.save(KEY, _ready_state(correlation_id="op-1"))
        first.close()
        second = self._repo()
        loaded = second.get(KEY)
        self.assertIs(loaded.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(loaded.correlation_id, "op-1")

    def test_two_open_instances_see_each_others_writes(self):
        a, b = self._repo(), self._repo()
        a.save(KEY, _ready_state())
        self.assertIs(b.get(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        b.clear(KEY)
        self.assertIs(a.get(KEY).phase, ConversationPhase.IDLE)

    def test_file_is_owner_only(self):
        self._repo()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)


# ===========================================================================
# 5: Missing / corrupted records
# ===========================================================================

class TestCorruption(_TempDir):

    def _corrupt(self, *, state_json=None, version=SCHEMA_VERSION):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        with sqlite3.connect(self.path) as conn:
            if state_json is not None:
                conn.execute("UPDATE conversation_state SET state_json = ?", (state_json,))
            conn.execute("UPDATE conversation_state SET schema_version = ?", (version,))
        conn.close()
        return repo

    def _assert_fresh(self, repo):
        with self.assertLogs("app.state_store", level="WARNING") as logs:
            state = repo.get(KEY)
        self.assertEqual(state.phase, ConversationPhase.IDLE)
        self.assertIsNone(state.pending_action)
        self.assertEqual(state.collected_details, {})
        text = "\n".join(logs.output)
        for raw in (USER, TENANT, CONV, "VPN"):
            self.assertNotIn(raw, text)

    def test_invalid_json(self):
        self._assert_fresh(self._corrupt(state_json="{not json"))

    def test_not_an_object(self):
        self._assert_fresh(self._corrupt(state_json="[1, 2]"))

    def test_unknown_phase(self):
        self._assert_fresh(self._corrupt(state_json=json.dumps({"phase": "approved"})))

    def test_unknown_schema_version(self):
        self._assert_fresh(self._corrupt(version=999))

    def test_pending_phase_without_action(self):
        self._assert_fresh(self._corrupt(
            state_json=json.dumps({"phase": "ready_for_confirmation"})))

    def test_tampered_values_are_re_filtered(self):
        repo = self._corrupt(state_json=json.dumps({
            "phase": "ready_for_confirmation", "pending_action": "create_incident",
            "intent": "delete_everything", "incident_number": "INC1; DROP TABLE",
            "correlation_id": "has space", "summary": LLM_SUMMARY,
            "collected_details": {"impact": "2", "password": PASSWORD, "impact_raw": 1},
        }))
        state = repo.get(KEY)
        self.assertIs(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertIsNone(state.intent)
        self.assertIsNone(state.incident_number)
        self.assertIsNone(state.correlation_id)
        self.assertIsNone(state.summary)
        self.assertEqual(state.collected_details, {"impact": "2"})

    def test_details_on_a_finished_record_are_ignored(self):
        repo = self._corrupt(state_json=json.dumps({
            "phase": "completed", "pending_action": "create_incident",
            "collected_details": {"description": f"password {PASSWORD}"},
        }))
        state = repo.get(KEY)
        self.assertIs(state.phase, ConversationPhase.COMPLETED)
        self.assertEqual(state.collected_details, {})

    def test_corrupted_record_is_replaced_on_next_save(self):
        repo = self._corrupt(state_json="{not json")
        with self.assertLogs("app.state_store", level="WARNING"):
            state = repo.get(KEY)
        repo.save(KEY, state)
        self.assertEqual(repo.get(KEY), state)


# ===========================================================================
# 6: Storage failures
# ===========================================================================

class TestStorageFailure(_TempDir):

    def test_operations_on_broken_store_raise(self):
        repo = SqliteStateRepository(self.path)
        repo.close()
        for op, call in (("load", lambda: repo.get(KEY)),
                         ("save", lambda: repo.save(KEY, _ready_state())),
                         ("clear", lambda: repo.clear(KEY))):
            with self.subTest(op=op), self.assertRaises(StatePersistenceError) as ctx:
                call()
            self.assertEqual(ctx.exception.operation, op)
            self.assertNotIn(USER, str(ctx.exception))

    def test_unopenable_store_raises(self):
        self.path.mkdir(parents=True)  # a directory where the file should be
        with self.assertRaises(StatePersistenceError) as ctx:
            SqliteStateRepository(self.path)
        self.assertEqual(ctx.exception.operation, "open")

    def test_unserializable_state_raises(self):
        with self.assertRaises(StatePersistenceError):
            self._repo().save(KEY, "not a state")  # type: ignore[arg-type]

    def test_oversized_state_raises(self):
        state = ConversationState(collected_details={"description": "x" * 70_000})
        with self.assertRaises(StatePersistenceError):
            self._repo().save(KEY, state)

    def test_failed_save_leaves_previous_state(self):
        repo = self._repo()
        repo.save(KEY, _ready_state())
        huge = _ready_state()
        huge.transition_to(ConversationPhase.EXECUTING)
        huge.collected_details["description"] = "x" * 70_000
        with self.assertRaises(StatePersistenceError):
            repo.save(KEY, huge)
        self.assertIs(repo.get(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)


# ===========================================================================
# 7: Sensitive data exclusion
# ===========================================================================

class TestSensitiveData(_TempDir):

    def test_serialization_is_an_allowlist(self):
        state = _ready_state(summary=LLM_SUMMARY, intent="not-an-intent")
        state.collected_details.update({
            "password": PASSWORD, "access_token": TOKEN, "authorization": f"Bearer {TOKEN}",
            "prompt": "SYSTEM PROMPT", "completion": LLM_SUMMARY, "impact_int": 2,
        })
        data = serialize_state(state)
        self.assertEqual(set(data), {"phase", "intent", "pending_action", "collected_details",
                                     "incident_number", "correlation_id", "last_error"})
        self.assertIsNone(data["intent"])
        self.assertEqual(set(data["collected_details"]),
                         {"short_description", "description", "impact", "urgency"})
        blob = json.dumps(data)
        for marker in (LLM_SUMMARY, PASSWORD, TOKEN, "SYSTEM PROMPT", "Bearer"):
            self.assertNotIn(marker, blob)

    def test_update_details_allowlisted(self):
        state = ConversationState(collected_details={
            "changes": {"impact": "1", "work_notes": "WORK-NOTE-MARKER"},
            "requested": ["urgency", "assignment_group"],
            "current": {"impact": "3", "sys_id": CURRENT["sys_id"]},
        })
        self.assertEqual(serialize_state(state)["collected_details"], {
            "changes": {"impact": "1"}, "requested": ["urgency"], "current": {"impact": "3"},
        })

    def test_raw_database_contains_no_sensitive_data(self):
        repo = SqliteStateRepository(self.path)
        state = _ready_state(summary=LLM_SUMMARY)
        state.collected_details["password"] = PASSWORD
        state.collected_details["token"] = TOKEN
        repo.save(KEY, state)
        repo.close()
        raw = self._raw_bytes()
        for marker in (LLM_SUMMARY, PASSWORD, TOKEN, CONV):
            self.assertNotIn(marker.encode(), raw)
        self.assertIn(b"short_description", raw)  # sanity: data was written

    def test_deserialize_never_restores_summary(self):
        self.assertIsNone(deserialize_state({"phase": "idle", "summary": LLM_SUMMARY}).summary)

    def test_persistence_layer_has_no_ai_dependency(self):
        import app.state_store as store

        source = Path(store.__file__).read_text()
        for forbidden in ("app.ai", "classify_message", "ollama", "openai"):
            self.assertNotIn(forbidden, source)


# ===========================================================================
# 8: Repository selection
# ===========================================================================

class TestFactory(_TempDir):

    def test_default_is_sqlite(self):
        repo = create_state_repository({"STATE_DB_PATH": str(self.path)})
        self.addCleanup(repo.close)
        self.assertIsInstance(repo, SqliteStateRepository)
        self.assertTrue(self.path.exists())

    def test_explicit_memory_warns(self):
        with self.assertLogs("app.state_store", level="WARNING") as logs:
            repo = create_state_repository({"STATE_STORE": "memory"})
        self.assertIsInstance(repo, InMemoryStateRepository)
        self.assertIn("NOT persistent", "\n".join(logs.output))

    def test_unknown_store_rejected(self):
        with self.assertRaises(ValueError):
            create_state_repository({"STATE_STORE": "redis"})

    def test_unopenable_store_does_not_fall_back(self):
        self.path.mkdir(parents=True)
        with self.assertRaises(StatePersistenceError):
            create_state_repository({"STATE_DB_PATH": str(self.path)})

    def test_configure_requires_a_repository(self):
        with self.assertRaises(TypeError):
            configure_state_repository(object())  # type: ignore[arg-type]

    async def _lifespan(self, env):
        previous = get_state_repository()
        self.addCleanup(configure_state_repository, previous)
        with patch.dict("os.environ", env), \
             patch.object(main.teams_app, "initialize", AsyncMock()) as init:
            async with main.lifespan(main.app):
                repo = get_state_repository()
        return repo, init

    def test_lifespan_configures_persistent_store(self):
        import asyncio

        repo, init = asyncio.run(self._lifespan({"STATE_DB_PATH": str(self.path)}))
        self.addCleanup(repo.close)
        self.assertIsInstance(repo, SqliteStateRepository)
        init.assert_awaited_once()

    def test_lifespan_fails_closed_when_store_unavailable(self):
        import asyncio

        self.path.mkdir(parents=True)
        previous = get_state_repository()
        with self.assertRaises(StatePersistenceError):
            asyncio.run(self._lifespan({"STATE_DB_PATH": str(self.path)}))
        self.assertIs(get_state_repository(), previous)


# ===========================================================================
# 9: Handler integration on the persistent store (BL-001..BL-011 regression)
# ===========================================================================

class CaptureAudit(AuditLogger):
    def __init__(self):
        super().__init__()
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def types(self):
        return [e.event_type for e in self.events]


class CaptureObs(obs.ObservabilityLogger):
    def __init__(self):
        super().__init__()
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def names(self):
        return [e.event_name for e in self.events]


class _Integration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "conversation_state.db"
        previous = get_state_repository()
        self.addCleanup(configure_state_repository, previous)
        self._use(SqliteStateRepository(self.path))

        self.client = AsyncMock()
        self.client.create_incident.return_value = dict(CREATED)
        self.client.get_incident.return_value = dict(CURRENT)
        self.client.update_incident.return_value = dict(UPDATED)
        self.audit = CaptureAudit()
        self.obs = CaptureObs()
        self.gateway = ServiceNowToolGateway(client=self.client, audit_logger=self.audit)
        self.classify = AsyncMock(return_value={
            "intent": "create_incident", "summary": LLM_SUMMARY, "needs_service_now": True,
        })
        self.authorize = MagicMock(side_effect=agent_authorize)
        patches = [
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.object(main, "authorize", self.authorize),
            patch.object(main, "audit_logger", self.audit),
            patch.object(obs, "observability", self.obs),
            patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT}),
            patch.object(main.servicenow, "create_incident",
                         AsyncMock(side_effect=AssertionError("direct client call"))),
            patch.object(ServiceNowClient, "_request",
                         AsyncMock(side_effect=AssertionError("real ServiceNow call"))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _use(self, repo):
        configure_state_repository(repo)
        if isinstance(repo, SqliteStateRepository):
            self.addCleanup(repo.close)
        return repo

    def _restart(self):
        """Simulate a process restart: a brand-new repository on the same file."""
        get_state_repository().close()
        return self._use(SqliteStateRepository(self.path))

    async def _send(self, text, **kwargs):
        ctx = _context(text, **kwargs)
        await main.on_message(ctx)
        return ctx.send.await_args.args[0]


class TestHandlerFlows(_Integration):

    async def test_create_flow_survives_restart_between_turns(self):
        await self._send(FULL_MESSAGE)
        self.assertIs(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self._restart()
        reply = await self._send("yes")
        self.assertIn("INC0012345", reply)
        self.assertEqual(self.client.create_incident.await_count, 1)
        self._restart()
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.COMPLETED)
        self.assertEqual(state.incident_number, "INC0012345")

    async def test_multi_turn_collection_persists_each_turn(self):
        await self._send("I need to report an issue")
        self.assertIs(get_session(KEY).phase, ConversationPhase.COLLECTING)
        self._restart()
        await self._send("VPN is down for me and I can't access internal applications")
        self._restart()
        await self._send("Impact is 2")
        self._restart()
        await self._send("urgency is 1")
        self._restart()
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(state.collected_details["impact"], "2")
        self.assertEqual(state.collected_details["urgency"], "1")
        self.classify.assert_awaited_once()  # later turns never reach the LLM

    async def test_confirmation_still_required_after_restart(self):
        save_session(KEY, _ready_state())
        self._restart()
        reply = await self._send("sounds good")
        self.assertIn("explicit confirmation", reply)
        self.client.create_incident.assert_not_called()
        self.assertIs(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    async def test_cancel_after_restart(self):
        save_session(KEY, _ready_state())
        self._restart()
        await self._send("cancel")
        self.assertIs(get_session(KEY).phase, ConversationPhase.IDLE)
        self.client.create_incident.assert_not_called()

    async def test_authorization_still_enforced_after_restart(self):
        save_session(KEY, _ready_state())
        self._restart()
        with patch.dict("os.environ", {"TEAMS_TENANT_ID": OTHER_TENANT}):
            reply = await self._send("yes")
        self.assertIn("not authorised", reply)
        self.client.create_incident.assert_not_called()
        self.assertIs(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    async def test_executing_blocks_duplicate_after_restart(self):
        state = _ready_state()
        state.transition_to(ConversationPhase.EXECUTING)
        save_session(KEY, state)
        self._restart()
        reply = await self._send("yes")
        self.assertIn("still being created", reply)
        self.client.create_incident.assert_not_called()
        self.classify.assert_not_called()

    async def test_concurrent_confirmations_create_once(self):
        import asyncio

        release = asyncio.Event()

        async def slow_create(**kwargs):
            await release.wait()
            return dict(CREATED)

        self.client.create_incident.side_effect = slow_create
        save_session(KEY, _ready_state())
        self.classify.reset_mock()
        first_ctx, second_ctx = _context("yes"), _context("yes")
        first = asyncio.create_task(main.on_message(first_ctx))
        for _ in range(1000):
            if get_session(KEY).phase is ConversationPhase.EXECUTING:
                break
            await asyncio.sleep(0)
        else:
            release.set()
            await first
            self.fail("first confirmation never reached EXECUTING")
        await main.on_message(second_ctx)
        release.set()
        await first
        self.assertEqual(self.client.create_incident.await_count, 1)
        self.assertIn("still being created", second_ctx.send.await_args.args[0])
        self.assertIn("INC0012345", first_ctx.send.await_args.args[0])
        self.classify.assert_not_called()

    async def test_update_flow_on_persistent_store(self):
        await self._send("Update INC0010002 impact to 1")
        self._restart()
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(state.incident_number, "INC0010002")
        self.assertEqual(state.collected_details["changes"], {"impact": "1"})
        await self._send("yes")
        self.client.update_incident.assert_awaited_once()
        self.assertIs(get_session(KEY).phase, ConversationPhase.COMPLETED)

    async def test_status_lookup_on_persistent_store(self):
        reply = await self._send("INC0010002")
        self.assertIn("INC0010002", reply)
        self.assertIs(get_session(KEY).phase, ConversationPhase.IDLE)

    async def test_audit_correlation_survives_restart(self):
        await self._send(FULL_MESSAGE)
        requested = self.audit.events[0]
        self.assertIs(requested.event_type, AuditEventType.INCIDENT_CREATE_REQUESTED)
        self._restart()
        await self._send("yes")
        created = [e for e in self.audit.events
                   if e.event_type is AuditEventType.INCIDENT_CREATE_COMPLETED]
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].correlation_id, requested.correlation_id)

    async def test_observability_on_persistent_store(self):
        await self._send(FULL_MESSAGE)
        self._restart()
        await self._send("yes")
        names = self.obs.names()
        self.assertIn(obs.ObsEventName.TOOL_COMPLETED, names)
        self.assertIn(obs.ObsEventName.STATE_TRANSITION, names)
        self.assertEqual(names.count(obs.ObsEventName.REQUEST_COMPLETED), 2)

    async def test_description_not_kept_after_completion(self):
        await self._send(f"VPN broken, my password is {PASSWORD}. Impact is 2 and urgency is 1.")
        self.assertIn(PASSWORD, get_session(KEY).collected_details["description"])
        await self._send("yes")
        get_state_repository().close()
        raw = b"".join(p.read_bytes() for p in self.path.parent.iterdir())
        self._use(SqliteStateRepository(self.path))
        self.assertNotIn(PASSWORD.encode(), raw)
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.COMPLETED)
        self.assertEqual(state.incident_number, "INC0012345")
        self.assertEqual(state.collected_details, {})

    async def test_llm_summary_never_reaches_database(self):
        self.classify.return_value = {
            "intent": "diagnose", "summary": LLM_SUMMARY, "needs_service_now": False,
        }
        await self._send(f"my VPN is broken, password {PASSWORD}")
        get_state_repository().close()
        raw = b"".join(p.read_bytes() for p in self.path.parent.iterdir())
        self._use(SqliteStateRepository(self.path))
        for marker in (LLM_SUMMARY, PASSWORD, CONV):
            self.assertNotIn(marker.encode(), raw)
        self.assertIsNone(get_session(KEY).summary)


class TestHandlerIsolation(_Integration):

    async def _assert_cannot_reach(self, **ctx):
        save_session(KEY, _ready_state())
        self.classify.return_value = {
            "intent": "general", "summary": "x", "needs_service_now": False,
        }
        await self._send("yes", **ctx)
        self.client.create_incident.assert_not_called()
        self.assertIs(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        other = StateKey(ctx.get("tenant", TENANT) or "", ctx.get("user", USER),
                         ctx.get("conversation", CONV))
        self.assertIsNone(get_session(other).pending_action)

    async def test_other_tenant_cannot_confirm(self):
        await self._assert_cannot_reach(tenant=OTHER_TENANT)

    async def test_missing_tenant_cannot_confirm(self):
        await self._assert_cannot_reach(tenant=None)

    async def test_other_user_cannot_confirm(self):
        await self._assert_cannot_reach(user=OTHER_USER)

    async def test_other_conversation_cannot_confirm(self):
        await self._assert_cannot_reach(conversation=OTHER_CONV)

    async def test_owner_can_still_confirm_afterwards(self):
        await self._assert_cannot_reach(conversation=OTHER_CONV)
        await self._send("yes")
        self.assertEqual(self.client.create_incident.await_count, 1)


class FailingRepository(InMemoryStateRepository):
    """In-memory store that fails on demand."""

    def __init__(self, *, fail_get=False, fail_save_phase=None):
        super().__init__()
        self.fail_get = fail_get
        self.fail_save_phase = fail_save_phase

    def get(self, key):
        if self.fail_get:
            raise StatePersistenceError("load")
        return super().get(key)

    def save(self, key, state):
        if state.phase is self.fail_save_phase:
            raise StatePersistenceError("save")
        super().save(key, state)


class TestHandlerFailSafe(_Integration):

    async def test_load_failure_is_controlled_and_takes_no_action(self):
        self._use(FailingRepository(fail_get=True))
        reply = await self._send("yes")
        self.assertIn("no action has been taken", reply)
        self.classify.assert_not_called()
        self.authorize.assert_not_called()
        self.client.create_incident.assert_not_called()
        self.client.get_incident.assert_not_called()
        failed = [e for e in self.obs.events if e.event_name is obs.ObsEventName.REQUEST_FAILED]
        self.assertEqual([e.error_code for e in failed], ["state_persistence_error"])

    async def test_save_failure_before_execution_never_executes(self):
        repo = self._use(FailingRepository(fail_save_phase=ConversationPhase.EXECUTING))
        repo._store[KEY] = _ready_state()
        reply = await self._send("yes")
        self.assertIn("couldn't save", reply)
        self.client.create_incident.assert_not_called()
        self.assertFalse([e for e in self.audit.events
                          if e.event_type is AuditEventType.INCIDENT_CREATE_COMPLETED])

    async def test_save_failure_during_collection_is_controlled(self):
        self._use(FailingRepository(fail_save_phase=ConversationPhase.READY_FOR_CONFIRMATION))
        reply = await self._send(FULL_MESSAGE)
        self.assertIn("couldn't save", reply)
        self.client.create_incident.assert_not_called()

    def _audited(self, event_type):
        return [e for e in self.audit.events if e.event_type is event_type]

    async def test_completion_audited_even_if_save_fails(self):
        repo = self._use(FailingRepository(fail_save_phase=ConversationPhase.COMPLETED))
        repo._store[KEY] = _ready_state()
        reply = await self._send("yes")
        self.assertIn("couldn't save", reply)
        self.assertEqual(self.client.create_incident.await_count, 1)
        completed = self._audited(AuditEventType.INCIDENT_CREATE_COMPLETED)
        self.assertEqual([e.incident_number for e in completed], ["INC0012345"])

    async def test_create_failure_audited_even_if_save_fails(self):
        self.client.create_incident.side_effect = RuntimeError("boom")
        repo = self._use(FailingRepository(fail_save_phase=ConversationPhase.FAILED))
        repo._store[KEY] = _ready_state()
        await self._send("yes")
        self.assertEqual(len(self._audited(AuditEventType.INCIDENT_CREATE_FAILED)), 1)

    async def test_update_completion_audited_even_if_save_fails(self):
        self._use(FailingRepository(fail_save_phase=ConversationPhase.COMPLETED))
        await self._send("Update INC0010002 impact to 1")
        reply = await self._send("yes")
        self.assertIn("couldn't save", reply)
        self.client.update_incident.assert_awaited_once()
        self.assertEqual(len(self._audited(AuditEventType.INCIDENT_UPDATE_COMPLETED)), 1)

    async def test_update_failure_audited_even_if_save_fails(self):
        self.client.update_incident.side_effect = RuntimeError("boom")
        self._use(FailingRepository(fail_save_phase=ConversationPhase.FAILED))
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        self.assertEqual(len(self._audited(AuditEventType.INCIDENT_UPDATE_FAILED)), 1)

    async def test_failure_messages_leak_nothing(self):
        with self.assertLogs("app.main", level="ERROR") as logs:
            self._use(FailingRepository(fail_get=True))
            reply = await self._send("yes")
        text = reply + "\n".join(logs.output)
        for raw in (USER, TENANT, CONV, "Traceback"):
            self.assertNotIn(raw, text)

    async def test_no_fallback_store_is_used(self):
        repo = self._use(FailingRepository(fail_get=True))
        await self._send(FULL_MESSAGE)
        self.assertIs(get_state_repository(), repo)
        self.assertEqual(repo._store, {})


if __name__ == "__main__":
    unittest.main()
