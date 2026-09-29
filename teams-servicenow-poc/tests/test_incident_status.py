"""
tests/test_incident_status.py — Test suite for BL-008 Incident Status Lookup.

Flow under test:
    Teams → app.main.on_message → BL-001 router → identity → authorize
    (READ_INCIDENT) → ServiceNowToolGateway (GET_INCIDENT) → mocked adapter
    → safe reply.

Only the ServiceNow client beneath the real gateway and the LLM classifier are
mocked.  No real ServiceNow call is possible.

Coverage:
 1-5    Router: valid routes, lowercase, whitespace, suspicious input,
        workflow phrases unaffected.
 6-8    Authorization: employee allowed, unidentified denied, denial blocks
        execution.
 9-15   Gateway: GET→READ mapping, success, invalid number, missing identity,
        denied decision, action mismatch, no arbitrary queries.
 16-21  Main integration: reaches GET_INCIDENT, success reply, not found,
        failure, no confirmation, BL-006/BL-007 unchanged.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import dataclasses
import inspect
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.incident_status as status_module  # noqa: E402
import app.main as main  # noqa: E402
from app.incident_collection import start_incident_collection  # noqa: E402
from app.incident_status import format_incident_status  # noqa: E402
from app.router import route_message  # noqa: E402
from app.security.authorization import (  # noqa: E402
    AuthorizableAction,
    authorize,
)
from app.security.identity import ANONYMOUS, IdentitySource, UserIdentity  # noqa: E402
from app.servicenow import (  # noqa: E402
    ServiceNowClient,
    ServiceNowError,
    ServiceNowNotFound,
)
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    StateKey,
    clear_session,
    configure_state_repository,
    get_session,
    get_state_repository,
    save_session,
)
from app.tools.servicenow import (  # noqa: E402
    _ACTION_MAPPING,
    CreateIncidentToolRequest,
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
)

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "bl008-user-aad-oid"
# DEMO-01: the conversation-state key app.main derives from _context().
STATE_KEY = StateKey(TENANT, USER)

EMPLOYEE = UserIdentity(
    user_id=USER,
    tenant_id=TENANT,
    display_name="Alice",
    email=None,
    source=IdentitySource.AAD_OBJECT_ID,
)

RECORD = {
    "sys_id": "46d44a5dc0a8010e00f3c1a3b0bbf1e4",
    "number": "INC0010002",
    "short_description": "VPN unavailable",
    "state": "2",
    "impact": "2",
    "urgency": "1",
    "priority": "2",
}


def _context(text: str, tenant: str | None = TENANT):
    activity = SimpleNamespace(
        text=text,
        from_=SimpleNamespace(aad_object_id=USER, id=USER, name="Alice"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


# ===========================================================================
# 1–5: Router (BL-001 router, unchanged)
# ===========================================================================

class TestRouter(unittest.TestCase):

    def test_01_valid_status_requests_route(self):
        for message in (
            "INC0010002",
            "status of INC0010002",
            "check INC0010002",
            "check status of INC0010002",
            "what is the status of INC0010002",
        ):
            with self.subTest(message=message):
                result = route_message(message)
                self.assertIsNotNone(result)
                self.assertEqual(result.intent, "incident_status")
                self.assertEqual(result.incident_number, "INC0010002")

    def test_02_lowercase_normalised(self):
        for message in ("inc0010002", "status of inc0010002", "Check Status Of Inc0010002"):
            with self.subTest(message=message):
                self.assertEqual(route_message(message).incident_number, "INC0010002")

    def test_03_whitespace_handled(self):
        for message in ("  INC0010002  ", "\tstatus of INC0010002\n", "   check   inc0010002   "):
            with self.subTest(message=message):
                self.assertEqual(route_message(message).incident_number, "INC0010002")

    def test_04_suspicious_or_appended_input_not_routed(self):
        for message in (
            "status of INC0010002; DROP TABLE incident",
            "status of INC0010002<script>",
            "check INC0010002 and then delete it",
            "status of INC0010002 -- suspicious text",
            "INC0010002^ORnumber!=INC0010002",
            "number=INC0010002",
            "INC00100",          # too short
            "INC00100020000",    # too long
            "INC-0010002",
        ):
            with self.subTest(message=message):
                self.assertIsNone(route_message(message))

    def test_04b_phrasings_outside_bl001_router_not_routed(self):
        # Router deliberately unchanged in BL-008: these go to the LLM path.
        for message in (
            "Show me INC0010002",
            "Can you check the incident INC0010002?",
            "What happened with INC0010002?",
            "What is the status of INC0010002?",
        ):
            with self.subTest(message=message):
                self.assertIsNone(route_message(message))

    def test_05_workflow_phrases_not_routed(self):
        for message in (
            "I need to report an issue", "Create an incident for my VPN issue",
            "yes", "confirm", "cancel", "never mind", "impact 2", "urgency 1",
        ):
            with self.subTest(message=message):
                self.assertIsNone(route_message(message))


# ===========================================================================
# 6–8: Authorization
# ===========================================================================

class TestAuthorization(unittest.TestCase):

    def setUp(self):
        p = patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT})
        p.start()
        self.addCleanup(p.stop)

    def test_06_employee_may_read_incident(self):
        decision = authorize(EMPLOYEE, AuthorizableAction.READ_INCIDENT)
        self.assertTrue(decision.allowed)
        self.assertIs(decision.action, AuthorizableAction.READ_INCIDENT)

    def test_07_unidentified_or_foreign_identity_denied(self):
        foreign = dataclasses.replace(EMPLOYEE, tenant_id=OTHER_TENANT)
        for identity in (ANONYMOUS, foreign):
            with self.subTest(identity=identity):
                self.assertFalse(authorize(identity, AuthorizableAction.READ_INCIDENT).allowed)

    def test_07b_unconfigured_allowed_tenant_denies(self):
        with patch.dict("os.environ", {"TEAMS_TENANT_ID": ""}):
            self.assertFalse(authorize(EMPLOYEE, AuthorizableAction.READ_INCIDENT).allowed)


class TestDeniedAuthorizationBlocksExecution(unittest.IsolatedAsyncioTestCase):

    async def test_08_denied_decision_never_reaches_client(self):
        client = AsyncMock()
        gateway = ServiceNowToolGateway(client=client)
        with patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT}):
            denied = authorize(ANONYMOUS, AuthorizableAction.READ_INCIDENT)
        result = await gateway.execute(
            EMPLOYEE, denied, ServiceNowToolAction.GET_INCIDENT,
            GetIncidentToolRequest("INC0010002"),
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        client.get_incident.assert_not_called()


# ===========================================================================
# 9–15: Tool Gateway (BL-005, unchanged)
# ===========================================================================

class TestGateway(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        p = patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT})
        p.start()
        self.addCleanup(p.stop)
        self.client = AsyncMock()
        self.client.get_incident.return_value = dict(RECORD)
        self.gateway = ServiceNowToolGateway(client=self.client)
        self.read = authorize(EMPLOYEE, AuthorizableAction.READ_INCIDENT)

    async def _get(self, number, identity=EMPLOYEE, decision=None):
        return await self.gateway.execute(
            identity, decision or self.read, ServiceNowToolAction.GET_INCIDENT,
            GetIncidentToolRequest(number),
        )

    def test_09_get_incident_maps_to_read_incident(self):
        self.assertIs(
            _ACTION_MAPPING[ServiceNowToolAction.GET_INCIDENT],
            AuthorizableAction.READ_INCIDENT,
        )

    async def test_10_valid_number_succeeds_and_is_normalised(self):
        result = await self._get("  inc0010002 ")
        self.assertTrue(result.success)
        self.assertEqual(result.incident_number, "INC0010002")
        self.client.get_incident.assert_awaited_once_with("INC0010002")

    async def test_11_invalid_number_rejected_before_client(self):
        for bad in ("INC123", "INC00100020000", "", "PRB0010002", "INC0010002 OR 1=1"):
            with self.subTest(bad=bad):
                result = await self._get(bad)
                self.assertFalse(result.success)
                self.assertEqual(result.error_code, "VALIDATION_ERROR")
        self.client.get_incident.assert_not_called()

    async def test_12_missing_identity_rejected(self):
        for identity in (None, ANONYMOUS):
            with self.subTest(identity=identity):
                result = await self._get("INC0010002", identity=identity)
                self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.get_incident.assert_not_called()

    async def test_13_denied_authorization_rejected(self):
        with patch.dict("os.environ", {"TEAMS_TENANT_ID": ""}):
            denied = authorize(EMPLOYEE, AuthorizableAction.READ_INCIDENT)
        result = await self._get("INC0010002", decision=denied)
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.get_incident.assert_not_called()

    async def test_14_action_mismatch_rejected(self):
        create = authorize(EMPLOYEE, AuthorizableAction.CREATE_INCIDENT)
        result = await self._get("INC0010002", decision=create)
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        # And a READ decision cannot create.
        result = await self.gateway.execute(
            EMPLOYEE, self.read, ServiceNowToolAction.CREATE_INCIDENT,
            CreateIncidentToolRequest("x", "y", "2", "1"),
        )
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.get_incident.assert_not_called()
        self.client.create_incident.assert_not_called()

    async def test_15_no_arbitrary_servicenow_queries(self):
        for bad in (
            "INC0010002^ORnumberISNOTEMPTY",
            "number=INC0010002",
            "INC0010002&sysparm_fields=*",
            "INC0010002\nsys_user",
        ):
            with self.subTest(bad=bad):
                result = await self._get(bad)
                self.assertEqual(result.error_code, "VALIDATION_ERROR")
        self.client.get_incident.assert_not_called()
        fields = [f.name for f in dataclasses.fields(GetIncidentToolRequest)]
        self.assertEqual(fields, ["incident_number"])
        with self.assertRaises(TypeError):
            GetIncidentToolRequest(incident_number="INC0010002", table="sys_user")


# ===========================================================================
# Presentation
# ===========================================================================

class TestFormatting(unittest.TestCase):

    def test_shows_allowlisted_fields_only(self):
        record = dict(
            RECORD,
            u_custom_secret="internal",
            work_notes="internal note",
            comments="customer comment",
            caller_id={"display_value": "Alice", "link": "https://x/api", "value": "abc"},
        )
        reply = format_incident_status(record, "INC0010002")
        for expected in ("Incident INC0010002", "**Short description:** VPN unavailable",
                         "**State:** 2", "**Impact:** 2", "**Urgency:** 1", "**Priority:** 2"):
            self.assertIn(expected, reply)
        for forbidden in (RECORD["sys_id"], "sys_id", "internal", "customer comment",
                          "https://", "Alice"):
            self.assertNotIn(forbidden, reply)

    def test_missing_fields_omitted_not_invented(self):
        reply = format_incident_status({"number": "INC0010002", "state": "1"}, "INC0010002")
        self.assertIn("**State:** 1", reply)
        for label in ("Short description", "Description", "Impact", "Urgency",
                      "Priority", "Assignment group", "Assigned to"):
            self.assertNotIn(label, reply)

    def test_reference_fields_show_display_value_only(self):
        record = dict(
            RECORD,
            description="Cannot reach intranet",
            assignment_group={"display_value": "Network", "link": "https://x", "value": "sysid1"},
            assigned_to={"link": "https://x", "value": "sysid2"},  # no display value
        )
        reply = format_incident_status(record, "INC0010002")
        self.assertIn("**Description:** Cannot reach intranet", reply)
        self.assertIn("**Assignment group:** Network", reply)
        self.assertNotIn("Assigned to", reply)
        self.assertNotIn("sysid", reply)
        self.assertNotIn("https://", reply)

    def test_presenter_module_is_pure(self):
        source = inspect.getsource(status_module)
        for forbidden in ("import httpx", "app.servicenow", "app.tools", "getenv",
                          "os.environ", "ollama"):
            self.assertNotIn(forbidden, source)


# ===========================================================================
# 16–21: Main integration
# ===========================================================================

class TestMainIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        # DEMO-01: state is keyed by tenant + user + conversation, so each
        # test starts from an empty store (no state leaks between tests).
        previous_repo = get_state_repository()
        configure_state_repository(InMemoryStateRepository())
        self.addCleanup(configure_state_repository, previous_repo)
        clear_session(STATE_KEY)
        self.addCleanup(clear_session, STATE_KEY)

        self.client = AsyncMock()
        self.client.get_incident.return_value = dict(RECORD)
        self.client.create_incident.return_value = {"sys_id": "n", "number": "INC0012345"}
        self.gateway = ServiceNowToolGateway(client=self.client)
        self.classify = AsyncMock(
            return_value={"intent": "general", "summary": "x", "needs_service_now": False}
        )
        patches = [
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT}),
            patch.object(main.servicenow, "get_incident",
                         AsyncMock(side_effect=AssertionError("direct client call"))),
            patch.object(ServiceNowClient, "_request",
                         AsyncMock(side_effect=AssertionError("real ServiceNow call"))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    async def _send(self, text: str, **kwargs) -> str:
        ctx = _context(text, **kwargs)
        await main.on_message(ctx)
        ctx.send.assert_awaited_once()
        return ctx.send.await_args.args[0]

    async def test_16_status_request_reaches_get_incident_gateway(self):
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            await self._send("status of inc0010002")
        execute.assert_awaited_once()
        identity, decision, action, request = execute.call_args.args
        self.assertEqual(identity.user_id, USER)
        self.assertIs(decision.action, AuthorizableAction.READ_INCIDENT)
        self.assertIs(action, ServiceNowToolAction.GET_INCIDENT)
        self.assertEqual(request, GetIncidentToolRequest("INC0010002"))
        self.client.get_incident.assert_awaited_once_with("INC0010002")
        self.classify.assert_not_called()

    async def test_17_successful_lookup_returns_incident_information(self):
        reply = await self._send("check INC0010002")
        self.assertIn("Incident INC0010002", reply)
        self.assertIn("VPN unavailable", reply)
        self.assertIn("**Priority:** 2", reply)
        self.assertNotIn(RECORD["sys_id"], reply)

    async def test_18_not_found_is_safe(self):
        self.client.get_incident.side_effect = ServiceNowNotFound(
            "HTTP 404 https://dev.service-now.com/api/now/table/incident"
        )
        reply = await self._send("INC0010002")
        self.assertEqual(reply, "I couldn't find incident INC0010002.")
        self.assertEqual(self.client.get_incident.await_count, 1)

    async def test_19_servicenow_failure_is_safe_and_not_retried(self):
        self.client.get_incident.side_effect = ServiceNowError(
            "HTTP 401 Bearer SECRET-TOKEN https://dev.service-now.com/oauth_token.do"
        )
        reply = await self._send("INC0010002")
        self.assertIn("couldn't retrieve incident INC0010002", reply)
        for leaked in ("SECRET", "Bearer", "401", "https://", "oauth"):
            self.assertNotIn(leaked, reply)
        self.assertEqual(self.client.get_incident.await_count, 1)

    async def test_19b_gateway_exception_is_safe(self):
        with patch.object(self.gateway, "execute",
                          AsyncMock(side_effect=RuntimeError("password=hunter2"))):
            reply = await self._send("INC0010002")
        self.assertIn("couldn't retrieve incident INC0010002", reply)
        self.assertNotIn("hunter2", reply)

    async def test_19c_denied_user_gets_safe_message_and_no_lookup(self):
        for kwargs in ({"tenant": OTHER_TENANT}, {"tenant": None}):
            with self.subTest(**kwargs):
                reply = await self._send("INC0010002", **kwargs)
                self.assertIn("not authorised to view this incident", reply)
                self.assertNotIn("VPN", reply)
                self.assertNotIn("tenant", reply.lower())
        self.client.get_incident.assert_not_called()

    async def test_20_no_confirmation_and_no_state_change(self):
        before = get_session(STATE_KEY)
        seen = []
        original = ConversationState.transition_to

        def spy(state, new_phase):
            seen.append(new_phase)
            return original(state, new_phase)

        with patch.object(ConversationState, "transition_to", spy):
            reply = await self._send("INC0010002")
        session = get_session(STATE_KEY)
        self.assertEqual(seen, [])
        self.assertEqual(session.phase, ConversationPhase.IDLE)
        self.assertIsNone(session.pending_action)
        self.assertEqual(session.collected_details, {})
        self.assertIs(session, before)
        self.assertNotIn("Shall I", reply)
        self.assertNotIn("confirm", reply.lower())
        self.client.create_incident.assert_not_called()

    async def test_20b_suspicious_input_is_not_looked_up(self):
        self.classify.return_value = {
            "intent": "incident_status", "summary": "x", "needs_service_now": True,
        }
        for message in (
            "status of INC0010002; DROP TABLE incident",
            "check INC0010002 and then delete it",
            "Show me INC0010002",
        ):
            with self.subTest(message=message):
                reply = await self._send(message)
                self.assertIn("provide the incident number", reply)
        self.client.get_incident.assert_not_called()

    async def test_21_bl007_create_flow_unchanged(self):
        state = ConversationState()
        start_incident_collection(
            state, "VPN is down for me. Impact is 2 and urgency is 1."
        )
        save_session(STATE_KEY, state)
        reply = await self._send("yes")
        self.assertIn("INC0012345", reply)
        self.client.create_incident.assert_awaited_once()
        self.client.get_incident.assert_not_called()

        # Lookup after completion is read-only and leaves the result intact.
        reply = await self._send("INC0010002")
        self.assertIn("VPN unavailable", reply)
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.COMPLETED)
        self.assertEqual(session.incident_number, "INC0012345")
        self.client.create_incident.assert_awaited_once()

    async def test_21b_incident_number_during_confirmation_is_not_a_lookup(self):
        state = ConversationState()
        start_incident_collection(
            state, "VPN is down for me. Impact is 2 and urgency is 1."
        )
        save_session(STATE_KEY, state)
        reply = await self._send("INC0010002")
        self.assertIn("explicit confirmation", reply)
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.client.get_incident.assert_not_called()
        self.client.create_incident.assert_not_called()

    async def test_21c_incident_number_during_collection_goes_to_collector(self):
        state = ConversationState()
        start_incident_collection(state, "I need to report an issue")
        save_session(STATE_KEY, state)
        await self._send("INC0010002")
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.COLLECTING)
        self.assertIn("INC0010002", session.collected_details.get("description", ""))
        self.client.get_incident.assert_not_called()


if __name__ == "__main__":
    unittest.main()
