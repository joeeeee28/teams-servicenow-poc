"""
tests/test_observability.py — Test suite for BL-011 Structured Observability.

Observability is passive telemetry.  These tests prove the event schema and
controlled vocabulary, correlation creation/propagation/reset, lifecycle,
routing, state, authorization, confirmation and tool events with latency,
privacy of everything emitted, and that an observability failure can never
change behaviour or bypass authorization / confirmation.

Only the ServiceNow client beneath the real gateway and the LLM network call
are mocked.  No real ServiceNow call is possible.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.ai as ai  # noqa: E402
import app.main as main  # noqa: E402
import app.observability as obs  # noqa: E402
import app.state as state_module  # noqa: E402
from app.ai import SYSTEM_PROMPT  # noqa: E402
from app.audit import AuditLogger  # noqa: E402
from app.incident_collection import start_incident_collection  # noqa: E402
from app.observability import (  # noqa: E402
    APPROVED_METADATA,
    OBSERVABILITY_LOGGER_NAME,
    ObsComponent,
    ObsEvent,
    ObsEventName,
    ObservabilityLogger,
    ObsOutcome,
)
from app.security.authorization import (  # noqa: E402
    AuthorizableAction,
    DefaultAuthorizationPolicy,
    UserRole,
    authorize,
)
from app.security.identity import ANONYMOUS, IdentitySource, UserIdentity  # noqa: E402
from app.servicenow import ServiceNowClient, ServiceNowError, ServiceNowNotFound  # noqa: E402
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InvalidTransitionError,
    clear_session,
    get_session,
    save_session,
)
from app.tools.servicenow import (  # noqa: E402
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    ToolAuthorizationError,
)

N, C, O = ObsEventName, ObsComponent, ObsOutcome
TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "11111111-2222-3333-4444-555555555555"

PASSWORD = "ABC123-PASSWORD"
OAUTH_TOKEN = "OAUTH-TOKEN-XYZ987"
API_KEY = "APIKEY-SECRET-456"
BOT_TOKEN = "TEAMS-BOT-TOKEN-789"
AUTH_HEADER = "Authorization: Bearer " + OAUTH_TOKEN
LLM_COMPLETION = "LLM-COMPLETION-MARKER-4242"
SN_BODY = "SN-RESPONSE-BODY-MARKER"
DISPLAY_NAME = "Alice Displayname"
EMAIL = "alice.private@contoso.com"
RECORD = {
    "sys_id": "46d44a5dc0a8010e00f3c1a3b0bbf1e4", "number": "INC0010002",
    "short_description": f"VPN {SN_BODY}", "description": f"secret body {SN_BODY}",
    "state": "2", "impact": "3", "urgency": "3", "priority": "5",
    "work_notes": f"internal work note {SN_BODY}",
}
CREATED = {"sys_id": "abc", "number": "INC0012345", "description": SN_BODY}


class AgentPolicy(DefaultAuthorizationPolicy):
    def resolve_role(self, identity):
        role = super().resolve_role(identity)
        return UserRole.SERVICE_DESK_AGENT if role is UserRole.EMPLOYEE else role


_AGENT = AgentPolicy()


def agent_authorize(identity, action):
    return authorize(identity, action, policy=_AGENT)


class CaptureObs(ObservabilityLogger):
    def __init__(self, timeline=None, fail=False):
        super().__init__(logging.getLogger("test.obs.capture"))
        self.events: list[ObsEvent] = []
        self.timeline = timeline if timeline is not None else []
        self.fail = fail

    def emit(self, event):
        if self.fail:
            raise RuntimeError("observability sink unavailable")
        self.events.append(event)
        self.timeline.append(("obs", event.event_name, event.component))

    def of(self, name, component=None):
        return [e for e in self.events
                if e.event_name is name and (component is None or e.component is component)]

    def names(self):
        return [e.event_name for e in self.events]

    def blob(self):
        return "\n".join(e.to_json() + repr(e) for e in self.events)


def _context(text, *, tenant=TENANT, activity_id="1712345678901"):
    activity = SimpleNamespace(
        id=activity_id, text=text, token=BOT_TOKEN,
        headers={"Authorization": AUTH_HEADER},
        from_=SimpleNamespace(aad_object_id=USER, id=USER, name=DISPLAY_NAME, email=EMAIL),
        conversation=SimpleNamespace(id="19:conv-abc"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


def _event(**overrides):
    fields = dict(event_name=N.TOOL_COMPLETED, component=C.TOOL_GATEWAY,
                  outcome=O.SUCCESS, correlation_id="corr-1",
                  action=AuthorizableAction.READ_INCIDENT, operation="get_incident",
                  duration_ms=12.5)
    fields.update(overrides)
    return ObsEvent(**fields)


# ===========================================================================
# Schema, controlled names and outcomes
# ===========================================================================

class TestSchema(unittest.TestCase):

    def test_valid_event_and_structured_serialization(self):
        data = json.loads(_event(user_ref="0123456789abcdef", phase="executing",
                                 previous_phase="ready_for_confirmation",
                                 metadata={"stage": "execution_stage"}).to_json())
        self.assertEqual(data["event_name"], "tool_completed")
        self.assertEqual(data["component"], "tool_gateway")
        self.assertEqual(data["outcome"], "success")
        self.assertEqual(data["duration_ms"], 12.5)
        self.assertEqual(data["metadata"], {"stage": "execution_stage"})
        self.assertRegex(data["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        self.assertEqual(set(data) - {
            "timestamp", "event_name", "component", "outcome", "correlation_id",
            "request_id", "action", "duration_ms", "user_ref", "operation",
            "error_code", "phase", "previous_phase", "metadata"}, set())
        self.assertTrue(repr(_event()).startswith("ObsEvent({"))

    def test_required_event_names_present(self):
        self.assertEqual({n.value for n in N}, {
            "request_started", "request_completed", "request_failed", "route_selected",
            "state_transition", "authorization_decision", "confirmation_decision",
            "tool_started", "tool_completed", "tool_failed"})

    def test_controlled_outcomes(self):
        self.assertEqual({o.value for o in O},
                         {"started", "success", "denied", "rejected", "cancelled", "failed"})

    def test_uncontrolled_values_rejected(self):
        for field, bad in (
            ("event_name", "tool_completed"), ("event_name", "user said hi"),
            ("component", "api"), ("outcome", "success"), ("outcome", "pwned"),
            ("outcome", O.DENIED),                      # not valid for tool_completed
            ("correlation_id", None), ("correlation_id", "has spaces"),
            ("request_id", "a b"), ("user_ref", USER), ("user_ref", EMAIL),
            ("error_code", "Some Free Text"), ("operation", "sys_user"),
            ("phase", "hacked"), ("previous_phase", "IDLE"),
            ("duration_ms", -1), ("duration_ms", "12"), ("duration_ms", True),
            ("action", "read_incident"), ("metadata", "x"),
            ("metadata", {"message": "hello"}), ("metadata", {"intent": "free text"}),
            ("metadata", {"route": PASSWORD}),
        ):
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                _event(**{field: bad})

    def test_record_never_raises_and_errors_go_to_sibling_logger(self):
        sink = MagicMock()
        sink.info.side_effect = RuntimeError("disk full")
        with self.assertLogs("app.observability_errors", level="WARNING") as errors:
            self.assertIsNone(ObservabilityLogger(sink).record(
                N.REQUEST_STARTED, C.API, O.STARTED))
            self.assertIsNone(ObservabilityLogger(MagicMock()).record(
                N.REQUEST_STARTED, C.API, O.STARTED, metadata={"message": PASSWORD}))
        self.assertEqual(len(errors.records), 2)
        self.assertNotIn(PASSWORD, "\n".join(errors.output))

    def test_emitted_on_dedicated_channel_as_json_only(self):
        sink = MagicMock()
        sink.info.side_effect = RuntimeError("disk full")
        with self.assertLogs(OBSERVABILITY_LOGGER_NAME, level="DEBUG") as channel:
            ObservabilityLogger().record(N.REQUEST_STARTED, C.API, O.STARTED,
                                         correlation_id="c-1")
            ObservabilityLogger(sink).record(N.REQUEST_STARTED, C.API, O.STARTED)
        self.assertEqual(len(channel.records), 1)
        self.assertEqual(json.loads(channel.records[0].getMessage())["correlation_id"], "c-1")
        self.assertEqual(channel.records[0].observability["event_name"], "request_started")

    def test_user_ref_is_pseudonymous_and_stable(self):
        ref = obs.user_ref(USER, TENANT)
        self.assertRegex(ref, r"^[0-9a-f]{16}$")
        self.assertEqual(ref, obs.user_ref(USER, TENANT))
        self.assertNotEqual(ref, obs.user_ref(USER, OTHER_TENANT))
        self.assertNotIn(USER, ref)
        self.assertIsNone(obs.user_ref("", TENANT))

    def test_approved_metadata_is_closed(self):
        self.assertEqual(set(APPROVED_METADATA), {"route", "intent", "pending_action", "stage"})


# ===========================================================================
# State-machine observation (passive listener)
# ===========================================================================

class TestStateObservation(unittest.TestCase):

    def setUp(self):
        self.capture = CaptureObs()
        p = patch.object(obs, "observability", self.capture)
        p.start()
        self.addCleanup(p.stop)

    def test_transitions_emit_state_events(self):
        s = ConversationState()
        for phase in (ConversationPhase.COLLECTING, ConversationPhase.READY_FOR_CONFIRMATION,
                      ConversationPhase.EXECUTING, ConversationPhase.COMPLETED,
                      ConversationPhase.IDLE):
            s.transition_to(phase)
        pairs = [(e.previous_phase, e.phase) for e in self.capture.of(N.STATE_TRANSITION)]
        self.assertEqual(pairs, [("idle", "collecting"), ("collecting", "ready_for_confirmation"),
                                 ("ready_for_confirmation", "executing"),
                                 ("executing", "completed"), ("completed", "idle")])
        self.assertTrue(all(e.component is C.CONVERSATION for e in self.capture.events))

    def test_invalid_transition_unchanged_and_not_observed(self):
        s = ConversationState()
        with self.assertRaises(InvalidTransitionError):
            s.transition_to(ConversationPhase.EXECUTING)
        self.assertEqual(s.phase, ConversationPhase.IDLE)
        self.assertEqual(self.capture.events, [])

    def test_failing_listener_cannot_affect_state(self):
        def broken(previous, new):
            raise RuntimeError("listener exploded")

        state_module._transition_listeners.append(broken)
        self.addCleanup(state_module._transition_listeners.remove, broken)
        s = ConversationState()
        s.transition_to(ConversationPhase.COLLECTING)
        self.assertEqual(s.phase, ConversationPhase.COLLECTING)
        self.capture.fail = True  # the real observability listener failing too
        s.transition_to(ConversationPhase.CANCELLED)
        s.transition_to(ConversationPhase.IDLE)
        self.assertEqual(s.phase, ConversationPhase.IDLE)

    def test_correlation_id_still_reset_on_idle(self):
        s = ConversationState(phase=ConversationPhase.CANCELLED, correlation_id="op-1")
        s.transition_to(ConversationPhase.IDLE)
        self.assertIsNone(s.correlation_id)


# ===========================================================================
# Integration harness
# ===========================================================================

class _Base(unittest.IsolatedAsyncioTestCase):

    obs_fails = False
    authorize_fn = staticmethod(agent_authorize)

    async def asyncSetUp(self):
        clear_session(USER)
        self.addCleanup(clear_session, USER)
        self.timeline = []
        self.capture = CaptureObs(self.timeline, fail=self.obs_fails)
        self.client = AsyncMock()

        async def get_incident(number):
            self.timeline.append(("servicenow", "get"))
            return dict(RECORD)

        async def create_incident(**kwargs):
            self.timeline.append(("servicenow", "create"))
            return dict(CREATED)

        async def update_incident(**kwargs):
            self.timeline.append(("servicenow", "update"))
            return dict(RECORD, impact="1")

        self.client.get_incident.side_effect = get_incident
        self.client.create_incident.side_effect = create_incident
        self.client.update_incident.side_effect = update_incident
        self.gateway = ServiceNowToolGateway(
            client=self.client, audit_logger=AuditLogger(logging.getLogger("test.audit.null")))
        self.classify = AsyncMock(return_value={
            "intent": "create_incident", "summary": LLM_COMPLETION, "needs_service_now": True})
        self.authorize = MagicMock(side_effect=self.authorize_fn)
        patches = [
            patch.object(obs, "observability", self.capture),
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.object(main, "authorize", self.authorize),
            patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT, "ADMIN_API_KEY": API_KEY}),
            patch.object(ServiceNowClient, "_request",
                         AsyncMock(side_effect=AssertionError("real ServiceNow call"))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    async def _send(self, text, **kwargs):
        ctx = _context(text, **kwargs)
        await main.on_message(ctx)
        return ctx.send.await_args.args[0] if ctx.send.await_args else None

    def _ready_create(self, description="VPN is down for me"):
        s = ConversationState()
        start_incident_collection(s, f"{description}. Impact is 2 and urgency is 1.")
        s.correlation_id = "op-create-1"
        save_session(USER, s)
        # Setup transitions happen outside any request; observe only what follows.
        self.capture.events.clear()
        self.timeline.clear()

    def _index(self, name, component=None):
        for i, item in enumerate(self.timeline):
            if item[0] == "obs" and item[1] is name and (component is None or item[2] is component):
                return i
        self.fail(f"{name} not observed")

    def _assert_clean(self, extra=()):
        blob = self.capture.blob()
        for marker in (PASSWORD, OAUTH_TOKEN, API_KEY, BOT_TOKEN, AUTH_HEADER, "Bearer",
                       "Authorization", "password", LLM_COMPLETION, SN_BODY,
                       "secret body", "work note", RECORD["sys_id"], DISPLAY_NAME, EMAIL,
                       USER, TENANT, "19:conv-abc", *extra):
            self.assertNotIn(marker, blob)


# ===========================================================================
# Request lifecycle, routing, correlation
# ===========================================================================

class TestRequestLifecycle(_Base):

    async def test_request_started_and_completed_with_duration(self):
        await self._send("INC0010002")
        self.assertEqual(self.capture.names()[0], N.REQUEST_STARTED)
        self.assertEqual(self.capture.names()[-1], N.REQUEST_COMPLETED)
        done = self.capture.events[-1]
        self.assertIs(done.component, C.API)
        self.assertIs(done.outcome, O.SUCCESS)
        self.assertGreaterEqual(done.duration_ms, 0)
        self.assertEqual(done.phase, "idle")

    async def test_request_failed_when_handler_fails(self):
        self.classify.side_effect = RuntimeError("ollama down " + LLM_COMPLETION)
        reply = await self._send("hello there")
        self.assertIn("trouble understanding", reply)
        failed = self.capture.of(N.REQUEST_FAILED)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].error_code, "handler_exception")
        self.assertEqual(self.capture.of(N.REQUEST_COMPLETED), [])
        self._assert_clean()

    async def test_empty_message_is_observed(self):
        await self._send("   ")
        self.assertEqual(self.capture.names(), [N.REQUEST_STARTED, N.REQUEST_COMPLETED])

    async def test_router_and_classifier_route_events(self):
        await self._send("INC0010002")
        router = self.capture.of(N.ROUTE_SELECTED, C.ROUTER)[0]
        self.assertEqual(router.metadata, {"route": "incident_status"})
        self.assertEqual(self.capture.of(N.ROUTE_SELECTED, C.AI_CLASSIFIER), [])
        self.capture.events.clear()
        await self._send("I need to report an issue")
        self.assertEqual(self.capture.of(N.ROUTE_SELECTED, C.ROUTER)[0].metadata, {"route": "none"})
        classifier = self.capture.of(N.ROUTE_SELECTED, C.AI_CLASSIFIER)[0]
        self.assertEqual(classifier.metadata, {"intent": "create_incident"})
        self.assertGreaterEqual(classifier.duration_ms, 0)

    async def test_correlation_created_and_propagated_within_request(self):
        await self._send("INC0010002", activity_id="act-42")
        self.assertEqual({e.correlation_id for e in self.capture.events}, {"act-42"})
        self.assertEqual({e.request_id for e in self.capture.events}, {"act-42"})

    async def test_unsafe_activity_id_replaced_by_generated_uuid(self):
        await self._send("INC0010002", activity_id=f"evil <script> {OAUTH_TOKEN}")
        ids = {e.correlation_id for e in self.capture.events}
        self.assertEqual(len(ids), 1)
        self.assertRegex(ids.pop(), r"^[0-9a-f-]{36}$")
        self._assert_clean()

    async def test_operation_correlation_propagates_across_messages(self):
        for i, msg in enumerate(["I need to report an issue", "VPN is down for me.",
                                 "2", "1", "yes"], start=1):
            await self._send(msg, activity_id=f"act-{i}")
        self.assertEqual({e.correlation_id for e in self.capture.events}, {"act-1"})
        self.assertEqual(sorted({e.request_id for e in self.capture.events}),
                         [f"act-{i}" for i in range(1, 6)])

    async def test_correlation_resets_after_operation_ends(self):
        self._ready_create()
        await self._send("yes", activity_id="act-confirm")
        self.assertEqual({e.correlation_id for e in self.capture.events}, {"op-create-1"})
        self.assertEqual(get_session(USER).phase, ConversationPhase.COMPLETED)
        self.capture.events.clear()
        await self._send("INC0010002", activity_id="act-next")
        self.assertEqual({e.correlation_id for e in self.capture.events}, {"act-next"})

    async def test_correlation_resets_after_cancel(self):
        self._ready_create()
        await self._send("cancel", activity_id="act-cancel")
        self.assertIsNone(get_session(USER).correlation_id)
        self.capture.events.clear()
        await self._send("hello", activity_id="act-after")
        self.assertEqual({e.correlation_id for e in self.capture.events}, {"act-after"})

    async def test_concurrent_requests_do_not_share_context(self):
        await asyncio.gather(self._send("INC0010002", activity_id="req-A"),
                             self._send("check INC0010002", activity_id="req-B"))
        for event in self.capture.events:
            self.assertEqual(event.correlation_id, event.request_id)
        self.assertEqual({e.request_id for e in self.capture.events}, {"req-A", "req-B"})


# ===========================================================================
# Authorization, confirmation, tool lifecycle
# ===========================================================================

class TestDecisionsAndTools(_Base):

    async def test_authorization_allowed_and_denied(self):
        await self._send("INC0010002")
        allowed = self.capture.of(N.AUTHORIZATION_DECISION)[0]
        self.assertEqual((allowed.outcome, allowed.action),
                         (O.SUCCESS, AuthorizableAction.READ_INCIDENT))
        self.assertGreaterEqual(allowed.duration_ms, 0)
        self.capture.events.clear()
        await self._send("INC0010002", tenant=OTHER_TENANT)
        denied = self.capture.of(N.AUTHORIZATION_DECISION)[0]
        self.assertIs(denied.outcome, O.DENIED)
        self.assertEqual(self.capture.of(N.TOOL_STARTED), [])

    async def test_update_authorization_stages(self):
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        stages = [(e.action.value, e.metadata.get("stage"))
                  for e in self.capture.of(N.AUTHORIZATION_DECISION)]
        self.assertEqual(stages, [("update_incident", "request_stage"),
                                  ("read_incident", "current_value_read"),
                                  ("update_incident", "execution_stage")])

    async def test_confirmation_decisions(self):
        self._ready_create()
        await self._send("sounds good")
        await self._send("yes")
        outcomes = [e.outcome for e in self.capture.of(N.CONFIRMATION_DECISION)]
        self.assertEqual(outcomes, [O.REJECTED, O.SUCCESS])
        event = self.capture.of(N.CONFIRMATION_DECISION)[1]
        self.assertEqual(event.metadata, {"pending_action": "create_incident"})
        self.assertIs(event.action, AuthorizableAction.CREATE_INCIDENT)
        self.assertGreaterEqual(event.duration_ms, 0)

    async def test_confirmation_cancelled(self):
        self._ready_create()
        await self._send("cancel")
        self.assertIs(self.capture.of(N.CONFIRMATION_DECISION)[0].outcome, O.CANCELLED)
        self.assertEqual(self.capture.of(N.TOOL_STARTED), [])

    async def test_tool_lifecycle_success(self):
        await self._send("INC0010002")
        started, completed = self.capture.of(N.TOOL_STARTED)[0], self.capture.of(N.TOOL_COMPLETED)[0]
        self.assertEqual((started.operation, completed.operation), ("get_incident", "get_incident"))
        self.assertIs(completed.component, C.TOOL_GATEWAY)
        self.assertLess(self.capture.events.index(started), self.capture.events.index(completed))

    async def test_tool_lifecycle_failures(self):
        self.client.get_incident.side_effect = ServiceNowNotFound("gone")
        await self._send("INC0010002")
        read_failed = [(e.operation, e.outcome, e.error_code) for e in self.capture.of(N.TOOL_FAILED)]
        self.assertEqual(read_failed, [("get_incident", O.FAILED, "not_found")])
        self.assertEqual(self.capture.of(N.TOOL_COMPLETED), [])
        self._assert_clean()

        self.client.create_incident.side_effect = ServiceNowError(f"HTTP 500 {AUTH_HEADER}")
        self._ready_create()
        await self._send("yes")
        failed = [(e.operation, e.outcome, e.error_code) for e in self.capture.of(N.TOOL_FAILED)]
        self.assertEqual(failed, [("create_incident", O.FAILED, "execution_error")])
        self.assertEqual(self.capture.of(N.TOOL_COMPLETED), [])
        self._assert_clean()

    async def test_gateway_rejections_observed(self):
        identity = UserIdentity(USER, TENANT, None, None, IdentitySource.AAD_OBJECT_ID)
        read = authorize(identity, AuthorizableAction.READ_INCIDENT)
        await self.gateway.execute(identity, authorize(ANONYMOUS, AuthorizableAction.READ_INCIDENT),
                                   ServiceNowToolAction.GET_INCIDENT, GetIncidentToolRequest("INC0010002"))
        await self.gateway.execute(identity, read, ServiceNowToolAction.GET_INCIDENT,
                                   GetIncidentToolRequest("INC123"))
        await self.gateway.execute(identity, read, "delete_user", None)
        with self.assertRaises(ToolAuthorizationError):
            await self.gateway.execute(identity, read, ServiceNowToolAction.UPDATE_INCIDENT,
                                       GetIncidentToolRequest("INC0010002"), raise_on_error=True)
        failed = [(e.outcome, e.error_code, e.operation) for e in self.capture.of(N.TOOL_FAILED)]
        self.assertEqual(failed, [
            (O.DENIED, "authorization_denied", "get_incident"),
            (O.REJECTED, "validation_error", "get_incident"),
            (O.REJECTED, "validation_error", None),
            (O.DENIED, "authorization_denied", "update_incident"),
        ])
        self.client.get_incident.assert_not_called()

    async def test_tool_latency_reflects_real_duration(self):
        async def slow_get(number):
            await asyncio.sleep(0.05)
            return dict(RECORD)

        self.client.get_incident.side_effect = slow_get
        await self._send("INC0010002")
        tool = self.capture.of(N.TOOL_COMPLETED)[0]
        request = self.capture.of(N.REQUEST_COMPLETED)[0]
        self.assertGreaterEqual(tool.duration_ms, 40)
        self.assertGreaterEqual(request.duration_ms, tool.duration_ms)

    async def test_state_transitions_observed_in_request_context(self):
        self._ready_create()
        await self._send("yes", activity_id="act-9")
        transitions = self.capture.of(N.STATE_TRANSITION)
        self.assertEqual([(t.previous_phase, t.phase) for t in transitions],
                         [("ready_for_confirmation", "executing"), ("executing", "completed")])
        self.assertEqual({(t.correlation_id, t.request_id) for t in transitions},
                         {("op-create-1", "act-9")})


# ===========================================================================
# Security ordering (observability observes, never controls)
# ===========================================================================

class TestOrdering(_Base):

    async def test_authorization_observed_before_protected_tool(self):
        await self._send("INC0010002")
        self.assertLess(self._index(N.AUTHORIZATION_DECISION), self._index(N.TOOL_STARTED))

    async def test_confirmation_and_authorization_before_writes(self):
        self._ready_create()
        await self._send("yes")
        write = self.timeline.index(("servicenow", "create"))
        self.assertLess(self._index(N.CONFIRMATION_DECISION), self._index(N.AUTHORIZATION_DECISION))
        self.assertLess(self._index(N.AUTHORIZATION_DECISION), write)
        self.assertLess(self._index(N.TOOL_STARTED), write)
        self.assertGreater(self._index(N.TOOL_COMPLETED), write)

    async def test_update_write_order(self):
        await self._send("Update INC0010002 impact to 1")
        self.timeline.clear()
        await self._send("yes")
        write = self.timeline.index(("servicenow", "update"))
        self.assertLess(self._index(N.CONFIRMATION_DECISION), write)
        self.assertLess(self._index(N.AUTHORIZATION_DECISION), write)


# ===========================================================================
# Privacy
# ===========================================================================

class TestPrivacy(_Base):

    async def test_no_sensitive_data_in_events_across_all_flows(self):
        await self._send(f"Create an incident with description: my password is {PASSWORD} "
                         f"key {API_KEY} token {OAUTH_TOKEN}")
        await self._send("impact 2")
        await self._send("urgency 1")
        await self._send("yes")
        await self._send("Update INC0010002 description to UPDATE-DESC-SECRET hunter2")
        await self._send("yes")
        await self._send("INC0010002")
        self.assertIn(N.TOOL_COMPLETED, self.capture.names())
        self._assert_clean(extra=("Create an incident", "impact 2", "UPDATE-DESC-SECRET",
                                  "hunter2", "description"))

    async def test_real_emitted_channel_text_is_clean(self):
        with self.assertLogs(OBSERVABILITY_LOGGER_NAME, level="INFO") as channel:
            obs.observability = ObservabilityLogger()  # real sink (restored by patch)
            await self._send(f"status of INC0010002 {PASSWORD}")
            await self._send("INC0010002")
        text = "\n".join(channel.output)
        for line in channel.records:
            json.loads(line.getMessage())
        for marker in (PASSWORD, SN_BODY, "secret body", "work note", USER, EMAIL,
                       DISPLAY_NAME, BOT_TOKEN, "Authorization"):
            self.assertNotIn(marker, text)

    async def test_real_llm_prompt_and_completion_not_logged(self):
        seen = {}

        async def fake_chat(model, messages, format):
            seen["system"] = messages[0]["content"]
            return SimpleNamespace(message=SimpleNamespace(
                content=json.dumps({"intent": "general", "summary": LLM_COMPLETION})))

        with patch.object(main, "classify_message", ai.classify_message), \
             patch.object(ai._ollama, "chat", side_effect=fake_chat):
            await self._send("hello, how are you?")
        self.assertEqual(seen["system"], SYSTEM_PROMPT)
        self.assertEqual(self.capture.of(N.ROUTE_SELECTED, C.AI_CLASSIFIER)[0].metadata,
                         {"intent": "general"})
        blob = self.capture.blob()
        for line in (l.strip() for l in SYSTEM_PROMPT.splitlines() if len(l.strip()) >= 12):
            self.assertNotIn(line, blob)
        self._assert_clean(extra=("hello, how are you",))

    async def test_user_is_pseudonymous(self):
        await self._send("INC0010002")
        refs = {e.user_ref for e in self.capture.events if e.user_ref}
        self.assertEqual(refs, {obs.user_ref(USER, TENANT)})
        self._assert_clean()


# ===========================================================================
# Observability failure cannot change behaviour or bypass security
# ===========================================================================

class TestObservabilityFailure(_Base):

    obs_fails = True

    async def test_business_flows_unchanged(self):
        self.assertIn("VPN", await self._send("INC0010002"))
        self._ready_create()
        self.assertIn("INC0012345", await self._send("yes"))
        self.assertEqual(get_session(USER).phase, ConversationPhase.COMPLETED)
        self.assertEqual(self.capture.events, [])

    async def test_authorization_still_enforced(self):
        self.authorize.side_effect = authorize  # default policy: no UPDATE
        reply = await self._send("Update INC0010002 impact to 1")
        self.assertIn("not authorised", reply)
        reply = await self._send("INC0010002", tenant=OTHER_TENANT)
        self.assertIn("not authorised", reply)
        self.client.update_incident.assert_not_called()
        self.client.get_incident.assert_not_called()

    async def test_confirmation_still_enforced(self):
        self._ready_create()
        reply = await self._send("sounds good")
        self.assertIn("explicit confirmation", reply)
        self.client.create_incident.assert_not_called()
        self.assertEqual(get_session(USER).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    async def test_failures_stay_failures_and_no_internal_error_exposed(self):
        self.client.create_incident.side_effect = ServiceNowError("boom")
        self._ready_create()
        reply = await self._send("yes")
        self.assertNotIn("✅", reply)
        self.assertNotIn("observability", reply.lower())
        self.assertEqual(get_session(USER).phase, ConversationPhase.FAILED)

    async def test_audit_trail_unaffected(self):
        audit = MagicMock()
        with patch.object(main, "audit_logger", audit):
            await self._send("INC0010002")
        recorded = [c.args[0].value for c in audit.record.call_args_list]
        self.assertEqual(recorded, ["incident_read_requested", "incident_read_authorized",
                                    "incident_read_completed"])


if __name__ == "__main__":
    unittest.main()
