"""
tests/test_incident_update.py — Test suite for BL-009 Controlled Incident Update.

Flow under test:
    Teams → app.main.on_message → router (update grammar) → identity →
    authorize(UPDATE_INCIDENT) → current values via GET_INCIDENT (gateway) →
    COLLECTING → READY_FOR_CONFIRMATION → explicit BL-003 confirmation →
    authorize(UPDATE_INCIDENT) → EXECUTING → gateway UPDATE_INCIDENT →
    COMPLETED / FAILED.

The default BL-004 policy treats every user as EMPLOYEE, who may NOT update
incidents.  Tests that need an authorised updater inject a service-desk-agent
policy explicitly; the default policy itself is never weakened.

Only the ServiceNow client beneath the real gateway and the LLM classifier are
mocked.  No real ServiceNow call is possible.

Sections:
  Routing 1-7, Collection 8-17, Current values 18-21, Confirmation 22-26,
  Authorization 27-29, Gateway 30-38, Execution safety 39-43, Regression 44-47.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.incident_update as update_module  # noqa: E402
import app.main as main  # noqa: E402
from app.confirmation import EXECUTABLE_ACTIONS  # noqa: E402
from app.incident_collection import start_incident_collection  # noqa: E402
from app.incident_update import (  # noqa: E402
    UPDATE_FIELDS,
    parse_update_command,
    process_update_message,
    start_update_collection,
    validated_update,
)
from app.router import route_message  # noqa: E402
from app.security.authorization import (  # noqa: E402
    AuthorizableAction,
    DefaultAuthorizationPolicy,
    UserRole,
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
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    UpdateIncidentToolRequest,
)

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "bl009-user-aad-oid"
# DEMO-01: the conversation-state key app.main derives from _context().
STATE_KEY = StateKey(TENANT, USER)

AGENT = UserIdentity(
    user_id=USER, tenant_id=TENANT, display_name="Bob", email=None,
    source=IdentitySource.AAD_OBJECT_ID,
)

CURRENT = {
    "sys_id": "46d44a5dc0a8010e00f3c1a3b0bbf1e4",
    "number": "INC0010002",
    "short_description": "VPN unavailable",
    "state": "2",
    "impact": "3",
    "urgency": "3",
    "priority": "5",
}
UPDATED = dict(CURRENT, impact="1", urgency="2", priority="2")


class AgentPolicy(DefaultAuthorizationPolicy):
    """Keeps every BL-004 check (identity, tenant) but grants the agent role."""

    def resolve_role(self, identity):
        role = super().resolve_role(identity)
        return UserRole.SERVICE_DESK_AGENT if role is UserRole.EMPLOYEE else role


_AGENT_POLICY = AgentPolicy()


def agent_authorize(identity, action):
    return authorize(identity, action, policy=_AGENT_POLICY)


def _context(text: str, tenant: str | None = TENANT):
    activity = SimpleNamespace(
        text=text,
        from_=SimpleNamespace(aad_object_id=USER, id=USER, name="Bob"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


def _collecting(command: str, current=None) -> ConversationState:
    state = ConversationState()
    start_update_collection(state, parse_update_command(command), dict(current or {
        "short_description": "VPN unavailable", "impact": "3", "urgency": "3",
    }))
    return state


# ===========================================================================
# 1–7: Update intent / routing
# ===========================================================================

class TestRouting(unittest.TestCase):

    def test_01_explicit_update_requests_recognised(self):
        for message in (
            "Update INC0010002",
            "Change INC0010002 impact to 1",
            "Set urgency of INC0010002 to 2",
            "Change the short description of INC0010002 to VPN access issue",
            "Update INC0010002 description to User cannot connect to VPN",
            "please update the incident INC0010002 urgency to 2",
            "Update INC0010002 priority",
        ):
            with self.subTest(message=message):
                route = route_message(message)
                self.assertIsNotNone(route)
                self.assertEqual(route.intent, "incident_update")
                self.assertEqual(route.incident_number, "INC0010002")

    def test_02_incident_number_normalised(self):
        for message in ("update inc0010002", "  Update Inc0010002 impact to 1  "):
            with self.subTest(message=message):
                self.assertEqual(parse_update_command(message).incident_number, "INC0010002")

    def test_03_supported_fields_recognised(self):
        cases = {
            "Change INC0010002 impact to 1": ("impact", "1"),
            "Set urgency of INC0010002 to 2": ("urgency", "2"),
            "Change the short description of INC0010002 to VPN access issue":
                ("short_description", "VPN access issue"),
            "update INC0010002 title: VPN access issue": ("short_description", "VPN access issue"),
            "Update INC0010002 description to User cannot connect to VPN":
                ("description", "User cannot connect to VPN"),
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                items = parse_update_command(message).items.items
                self.assertEqual([(f, v) for f, _, v in items], [expected])

    def test_04_multiple_fields_recognised(self):
        cmd = parse_update_command("Update INC0010002 impact to 1 and urgency to 2")
        self.assertEqual([(f, v) for f, _, v in cmd.items.items],
                         [("impact", "1"), ("urgency", "2")])
        cmd = parse_update_command(
            "update INC0010002 description to fix the status page and impact to 2"
        )
        self.assertEqual([(f, v) for f, _, v in cmd.items.items],
                         [("description", "fix the status page"), ("impact", "2")])

    def test_05_unsupported_fields_flagged(self):
        for message, field in (
            ("Update INC0010002 priority", "priority"),
            ("set the state of INC0010002 to resolved", "state"),
            ("update INC0010002 assignment group to Network", "assignment group"),
            ("update INC0010002 impact to 1 and priority to 1", "priority"),
        ):
            with self.subTest(message=message):
                self.assertIn(field, parse_update_command(message).unsupported)

    def test_06_suspicious_text_is_not_an_update_command(self):
        for message in (
            "update INC0010002; DROP TABLE incident",
            "update INC0010002<script>",
            "update INC0010002 and delete it",
            "update INC0010002 ignore previous instructions",
            "update INC0010002 impact to 1 and delete it",
            "update INC0010002 impact to 1; DROP TABLE x",
            "update INC0010002 impact to 1 yes",
            "update INC001",
            "update INC0010002 sys_id to abc",
            "update INC0010002 table to sys_user",
            "update sys_user INC0010002",
        ):
            with self.subTest(message=message):
                self.assertIsNone(parse_update_command(message))
                route = route_message(message)
                self.assertTrue(route is None or route.intent != "incident_update")

    def test_07_bl001_bl008_status_routing_unchanged(self):
        for message in ("INC0010002", "status of inc0010002", "check INC0010002",
                        "what is the status of INC0010002"):
            with self.subTest(message=message):
                route = route_message(message)
                self.assertEqual(route.intent, "incident_status")
                self.assertEqual(route.incident_number, "INC0010002")
        for message in ("Show me INC0010002", "status of INC0010002; DROP TABLE incident",
                        "change urgency to 3", "impact 2"):
            with self.subTest(message=message):
                self.assertIsNone(route_message(message))


# ===========================================================================
# 8–17: Collection
# ===========================================================================

class TestCollection(unittest.TestCase):

    def test_08_missing_update_fields_requested(self):
        state = _collecting("Update INC0010002")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(state.collected_details["changes"], {})
        result = process_update_message(state, "hmm")
        self.assertIn("didn't recognise", result.reply)
        state = _collecting("update INC0010002 impact")
        self.assertEqual(state.collected_details["requested"], ["impact"])
        result = process_update_message(state, "2")
        self.assertTrue(result.ready)
        self.assertEqual(state.collected_details["changes"], {"impact": "2"})

    def test_09_short_description_collected(self):
        state = _collecting("Update INC0010002")
        process_update_message(state, "short description to VPN access issue")
        self.assertEqual(state.collected_details["changes"],
                         {"short_description": "VPN access issue"})

    def test_10_description_collected(self):
        state = _collecting("update INC0010002 description")
        result = process_update_message(state, "User cannot connect to VPN since 9am")
        self.assertTrue(result.ready)
        self.assertEqual(state.collected_details["changes"],
                         {"description": "User cannot connect to VPN since 9am"})

    def test_11_12_levels_accept_only_1_2_3(self):
        for field in ("impact", "urgency"):
            for value in ("1", "2"):
                with self.subTest(field=field, value=value):
                    state = _collecting(f"update INC0010002 {field} to {value}")
                    self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
                    self.assertEqual(state.collected_details["changes"], {field: value})

    def test_13_invalid_impact_rejected(self):
        for value in ("0", "4", "5", "high", "one", "1.5"):
            with self.subTest(value=value):
                state = _collecting(f"update INC0010002 impact to {value}")
                self.assertEqual(state.phase, ConversationPhase.COLLECTING)
                self.assertEqual(state.collected_details["changes"], {})
                self.assertEqual(state.collected_details["requested"], ["impact"])

    def test_14_invalid_urgency_rejected(self):
        state = _collecting("update INC0010002 urgency")
        for value in ("0", "4", "5", "low", "sure"):
            with self.subTest(value=value):
                result = process_update_message(state, value)
                self.assertIn("Urgency must be 1, 2, or 3.", result.errors)
                self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(state.collected_details["changes"], {})

    def test_15_multiple_corrections(self):
        state = _collecting("update INC0010002 impact to 4 and urgency to 2")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        process_update_message(state, "impact to 5")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        result = process_update_message(state, "actually impact to 1, urgency to 1")
        self.assertTrue(result.ready)
        self.assertEqual(state.collected_details["changes"], {"impact": "1", "urgency": "1"})

    def test_15b_no_op_change_is_refused(self):
        state = _collecting("update INC0010002 impact to 3")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(state.collected_details["changes"], {})

    def test_16_nothing_is_defaulted(self):
        state = _collecting("Update INC0010002 impact to 1")
        self.assertEqual(state.collected_details["changes"], {"impact": "1"})
        number, changes = validated_update(state)
        self.assertEqual(changes, {"impact": "1"})
        for field in ("urgency", "short_description", "description"):
            self.assertNotIn(field, changes)

    def test_17_cancellation(self):
        for phrase in ("cancel", "stop", "never mind", "abort"):
            with self.subTest(phrase=phrase):
                state = _collecting("update INC0010002 urgency")
                result = process_update_message(state, phrase)
                self.assertTrue(result.cancelled)
                self.assertEqual(state.phase, ConversationPhase.IDLE)
                self.assertEqual(state.collected_details, {})
                self.assertIsNone(state.pending_action)
                self.assertIsNone(state.incident_number)

    def test_unsupported_field_during_collection_refused(self):
        state = _collecting("Update INC0010002")
        result = process_update_message(state, "priority to 1")
        self.assertIn("can't update priority", result.reply)
        self.assertEqual(state.collected_details["changes"], {})

    def test_update_module_is_pure(self):
        source = inspect.getsource(update_module)
        for forbidden in ("import httpx", "app.servicenow", "app.tools", "getenv",
                          "os.environ", "ollama", "app.main"):
            self.assertNotIn(forbidden, source)


# ===========================================================================
# Integration harness
# ===========================================================================

class _Base(unittest.IsolatedAsyncioTestCase):

    authorize_fn = staticmethod(agent_authorize)

    async def asyncSetUp(self):
        # DEMO-01: state is keyed by tenant + user + conversation, so each
        # test starts from an empty store (no state leaks between tests).
        previous_repo = get_state_repository()
        configure_state_repository(InMemoryStateRepository())
        self.addCleanup(configure_state_repository, previous_repo)
        clear_session(STATE_KEY)
        self.addCleanup(clear_session, STATE_KEY)

        self.client = AsyncMock()
        self.client.get_incident.return_value = dict(CURRENT)
        self.client.update_incident.return_value = dict(UPDATED)
        self.client.create_incident.return_value = {"sys_id": "n", "number": "INC0012345"}
        self.gateway = ServiceNowToolGateway(client=self.client)
        self.classify = AsyncMock(
            return_value={"intent": "general", "summary": "x", "needs_service_now": False}
        )
        self.authorize = MagicMock(side_effect=self.authorize_fn)
        patches = [
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.object(main, "authorize", self.authorize),
            patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT}),
            patch.object(main.servicenow, "update_incident",
                         AsyncMock(side_effect=AssertionError("direct client call"))),
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

    async def _ready(self, command="Update INC0010002 impact to 1 and urgency to 2") -> str:
        reply = await self._send(command)
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        return reply


# ===========================================================================
# 18–21: Current values
# ===========================================================================

class TestCurrentValues(_Base):

    async def test_18_current_incident_read_before_summary(self):
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            reply = await self._ready()
        execute.assert_awaited_once()
        _identity, decision, action, request = execute.call_args.args
        self.assertIs(action, ServiceNowToolAction.GET_INCIDENT)
        self.assertIs(decision.action, AuthorizableAction.READ_INCIDENT)
        self.assertEqual(request, GetIncidentToolRequest("INC0010002"))
        self.assertIn("**Impact:** 3 → 1", reply)
        self.assertIn("**Urgency:** 3 → 2", reply)
        self.client.update_incident.assert_not_called()

    async def test_19_current_values_never_invented(self):
        # The adapter does not return description; it must not be guessed.
        reply = await self._ready("update INC0010002 description to New text")
        self.assertIn("**Description:** (current value not available) → New text", reply)
        self.client.get_incident.return_value = {"number": "INC0010002", "impact": "2"}
        clear_session(STATE_KEY)
        reply = await self._ready("update INC0010002 urgency to 1")
        self.assertIn("**Urgency:** (current value not available) → 1", reply)

    async def test_20_not_found_is_safe(self):
        self.client.get_incident.side_effect = ServiceNowNotFound(
            "HTTP 404 https://dev.service-now.com/api/now/table/incident"
        )
        reply = await self._send("Update INC0010002 impact to 1")
        self.assertEqual(reply, "I couldn't find incident INC0010002.")
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.IDLE)
        self.client.update_incident.assert_not_called()

    async def test_21_retrieval_failure_prevents_update(self):
        self.client.get_incident.side_effect = ServiceNowError("HTTP 500 Bearer SECRET")
        reply = await self._send("Update INC0010002 impact to 1")
        self.assertIn("couldn't retrieve incident INC0010002", reply)
        self.assertNotIn("→", reply)
        self.assertNotIn("SECRET", reply)
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.IDLE)
        await self._send("yes")
        self.client.update_incident.assert_not_called()

    async def test_21b_read_raising_prevents_update(self):
        with patch.object(self.gateway, "execute",
                          AsyncMock(side_effect=RuntimeError("password=hunter2"))):
            reply = await self._send("Update INC0010002 impact to 1")
        self.assertNotIn("hunter2", reply)
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.IDLE)
        self.client.update_incident.assert_not_called()


# ===========================================================================
# 22–26: Confirmation
# ===========================================================================

class TestConfirmation(_Base):

    async def test_22_summary_shown_before_execution(self):
        reply = await self._ready()
        self.assertIn("You're asking me to update **INC0010002**", reply)
        self.assertIn("Shall I apply these changes?", reply)
        self.client.update_incident.assert_not_called()
        self.assertEqual(get_session(STATE_KEY).pending_action, "update_incident")

    async def test_23_explicit_confirmation_proceeds(self):
        for phrase in ("yes", "confirm", "go ahead", "proceed", "approved", "  YES "):
            with self.subTest(phrase=phrase):
                clear_session(STATE_KEY)
                self.client.update_incident.reset_mock()
                await self._ready()
                await self._send(phrase)
                self.client.update_incident.assert_awaited_once_with(
                    incident_number="INC0010002", fields={"impact": "1", "urgency": "2"}
                )
                self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.COMPLETED)

    async def test_24_ambiguous_confirmation_does_not_proceed(self):
        await self._ready()
        for phrase in ("okay", "sure", "sounds good", "maybe", "yep", "alright",
                       "yes please", "impact to 2", "INC0010002"):
            with self.subTest(phrase=phrase):
                reply = await self._send(phrase)
                self.assertIn("explicit confirmation", reply)
                self.assertEqual(get_session(STATE_KEY).phase,
                                 ConversationPhase.READY_FOR_CONFIRMATION)
        self.client.update_incident.assert_not_called()
        self.classify.assert_not_called()

    async def test_25_cancellation_does_not_execute(self):
        for phrase in ("cancel", "no", "stop", "abort", "never mind"):
            with self.subTest(phrase=phrase):
                clear_session(STATE_KEY)
                await self._ready()
                reply = await self._send(phrase)
                self.assertIn("Cancelled", reply)
                session = get_session(STATE_KEY)
                self.assertEqual(session.phase, ConversationPhase.IDLE)
                self.assertIsNone(session.pending_action)
                self.assertEqual(session.collected_details, {})
        self.client.update_incident.assert_not_called()

    async def test_26_no_confirmation_bypass(self):
        # A complete command never executes by itself.
        await self._send("Update INC0010002 impact to 1 and urgency to 2")
        self.client.update_incident.assert_not_called()
        # Confirmation words outside READY_FOR_CONFIRMATION never execute.
        clear_session(STATE_KEY)
        for phrase in ("yes", "confirm", "go ahead"):
            await self._send(phrase)
        # The LLM cannot trigger an update (no update intent exists).
        self.classify.return_value = {
            "intent": "update_incident", "summary": "update INC0010002 impact 1",
            "incident_number": "INC0010002", "fields": {"impact": "1"},
        }
        await self._send("please bump the impact on my ticket to 1")
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.IDLE)
        self.client.update_incident.assert_not_called()
        # A pending update without executable data is refused, not executed.
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action="update_incident", incident_number="INC0010002",
            collected_details={"changes": {"priority": "1"}},
        )
        save_session(STATE_KEY, state)
        reply = await self._send("yes")
        self.assertIn("missing or invalid", reply)
        self.client.update_incident.assert_not_called()

    def test_26b_update_is_a_bl003_executable_action(self):
        self.assertIn("update_incident", EXECUTABLE_ACTIONS)
        self.assertIn("create_incident", EXECUTABLE_ACTIONS)


# ===========================================================================
# 27–29: Authorization
# ===========================================================================

class TestAuthorization(_Base):

    async def test_27_authorized_update_reaches_gateway(self):
        await self._ready()
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            await self._send("yes")
        identity, decision, action, request = execute.call_args.args
        self.assertEqual(identity.user_id, USER)
        self.assertTrue(decision.allowed)
        self.assertIs(decision.action, AuthorizableAction.UPDATE_INCIDENT)
        self.assertIs(action, ServiceNowToolAction.UPDATE_INCIDENT)
        self.assertEqual(request, UpdateIncidentToolRequest("INC0010002", impact="1", urgency="2"))

    async def test_29_authorization_checked_immediately_before_execution(self):
        await self._ready()
        self.authorize.reset_mock()
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            order = MagicMock()
            order.attach_mock(self.authorize, "authorize")
            order.attach_mock(execute, "execute")
            await self._send("yes")
        names = [c[0] for c in order.mock_calls if c[0] in ("authorize", "execute")]
        self.assertEqual(names, ["authorize", "execute"])
        self.assertIs(self.authorize.call_args.args[1], AuthorizableAction.UPDATE_INCIDENT)

    async def test_29b_revoked_authorization_at_confirmation_blocks(self):
        await self._ready()
        self.authorize.side_effect = authorize  # default policy: EMPLOYEE, no UPDATE
        reply = await self._send("yes")
        self.assertIn("not authorised", reply)
        self.client.update_incident.assert_not_called()
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)


class TestDefaultPolicyDenies(_Base):
    """Test 28: the unmodified BL-004 policy (EMPLOYEE) cannot update."""

    authorize_fn = staticmethod(authorize)

    async def test_28_unauthorized_user_cannot_execute(self):
        reply = await self._send("Update INC0010002 impact to 1")
        self.assertIn("not authorised", reply)
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.IDLE)
        self.client.get_incident.assert_not_called()
        self.client.update_incident.assert_not_called()

    async def test_28b_wrong_tenant_cannot_execute(self):
        self.authorize.side_effect = agent_authorize
        reply = await self._send("Update INC0010002 impact to 1", tenant=OTHER_TENANT)
        self.assertIn("not authorised", reply)
        self.client.get_incident.assert_not_called()
        self.client.update_incident.assert_not_called()

    async def test_28c_status_lookup_still_allowed_for_employee(self):
        reply = await self._send("INC0010002")
        self.assertIn("VPN unavailable", reply)


# ===========================================================================
# 30–38: Tool Gateway (BL-005, unchanged)
# ===========================================================================

class TestGateway(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        p = patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT})
        p.start()
        self.addCleanup(p.stop)
        self.client = AsyncMock()
        self.client.update_incident.return_value = dict(UPDATED)
        self.gateway = ServiceNowToolGateway(client=self.client)
        self.update = agent_authorize(AGENT, AuthorizableAction.UPDATE_INCIDENT)

    async def _run(self, request, identity=AGENT, decision=None,
                   action=ServiceNowToolAction.UPDATE_INCIDENT):
        return await self.gateway.execute(identity, decision or self.update, action, request)

    def test_30_update_maps_to_update_authorization(self):
        self.assertIs(_ACTION_MAPPING[ServiceNowToolAction.UPDATE_INCIDENT],
                      AuthorizableAction.UPDATE_INCIDENT)

    async def test_31_valid_request_succeeds(self):
        result = await self._run(UpdateIncidentToolRequest("inc0010002", impact="1"))
        self.assertTrue(result.success)
        self.client.update_incident.assert_awaited_once_with(
            incident_number="INC0010002", fields={"impact": "1"})

    async def test_32_invalid_field_values_rejected(self):
        for kwargs in ({"impact": "4"}, {"urgency": "0"}, {"impact": "high"},
                       {"short_description": "   "}, {}):
            with self.subTest(kwargs=kwargs):
                result = await self._run(UpdateIncidentToolRequest("INC0010002", **kwargs))
                self.assertEqual(result.error_code, "VALIDATION_ERROR")
        self.client.update_incident.assert_not_called()

    async def test_33_invalid_incident_number_rejected(self):
        for bad in ("INC123", "INC0010002; DROP", "PRB0010002", ""):
            with self.subTest(bad=bad):
                result = await self._run(UpdateIncidentToolRequest(bad, impact="1"))
                self.assertEqual(result.error_code, "VALIDATION_ERROR")
        self.client.update_incident.assert_not_called()

    async def test_34_missing_identity_rejected(self):
        for identity in (None, ANONYMOUS):
            with self.subTest(identity=identity):
                result = await self._run(UpdateIncidentToolRequest("INC0010002", impact="1"),
                                         identity=identity)
                self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.update_incident.assert_not_called()

    async def test_35_denied_authorization_rejected(self):
        denied = authorize(AGENT, AuthorizableAction.UPDATE_INCIDENT)  # default: EMPLOYEE
        self.assertFalse(denied.allowed)
        result = await self._run(UpdateIncidentToolRequest("INC0010002", impact="1"),
                                 decision=denied)
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.update_incident.assert_not_called()

    async def test_36_action_mismatch_rejected(self):
        read = agent_authorize(AGENT, AuthorizableAction.READ_INCIDENT)
        create = agent_authorize(AGENT, AuthorizableAction.CREATE_INCIDENT)
        for decision in (read, create):
            with self.subTest(decision=decision.action):
                result = await self._run(UpdateIncidentToolRequest("INC0010002", impact="1"),
                                         decision=decision)
                self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        result = await self._run(GetIncidentToolRequest("INC0010002"),
                                 action=ServiceNowToolAction.GET_INCIDENT)
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.update_incident.assert_not_called()
        self.client.get_incident.assert_not_called()

    async def test_37_arbitrary_fields_cannot_be_passed(self):
        fields = {f.name for f in dataclasses.fields(UpdateIncidentToolRequest)}
        self.assertEqual(fields, {"incident_number", *UPDATE_FIELDS})
        for extra in ("priority", "state", "assignment_group", "sys_id", "fields"):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                UpdateIncidentToolRequest("INC0010002", **{extra: "1"})

    async def test_38_arbitrary_tables_cannot_be_passed(self):
        for extra in ("table", "path", "query", "sysparm_query", "url"):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                UpdateIncidentToolRequest("INC0010002", impact="1", **{extra: "sys_user"})
        # DEMO-07 added get_request_status and get_ritm_status; the allowlist stays closed.
        self.assertEqual([m.value for m in ServiceNowToolAction],
                         ["get_incident", "create_incident", "update_incident",
                          "search_catalog", "create_request",
                          "get_request_status", "get_ritm_status"])


# ===========================================================================
# 39–43: Execution safety
# ===========================================================================

class TestExecutionSafety(_Base):

    async def test_39_success_returns_actual_servicenow_values(self):
        self.client.update_incident.return_value = dict(UPDATED, priority="3", urgency="3")
        await self._ready()
        reply = await self._send("yes")
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.COMPLETED)
        self.assertEqual(session.incident_number, "INC0010002")
        self.assertIn("ServiceNow confirmed the update", reply)
        self.assertIn("**Impact:** 1", reply)
        self.assertIn("**Urgency:** 3", reply)     # what ServiceNow actually returned
        self.assertIn("**Priority:** 3", reply)
        self.assertNotIn(CURRENT["sys_id"], reply)

    async def test_39b_transition_sequence(self):
        await self._ready()
        seen = []
        original = ConversationState.transition_to

        def spy(state, new_phase):
            seen.append(new_phase)
            return original(state, new_phase)

        with patch.object(ConversationState, "transition_to", spy):
            await self._send("yes")
        self.assertEqual(seen, [ConversationPhase.EXECUTING, ConversationPhase.COMPLETED])

    async def test_39c_executing_persisted_before_side_effect(self):
        seen = {}

        async def update(**kwargs):
            seen["phase"] = get_session(STATE_KEY).phase
            return dict(UPDATED)

        self.client.update_incident.side_effect = update
        await self._ready()
        await self._send("yes")
        self.assertEqual(seen["phase"], ConversationPhase.EXECUTING)

    async def test_40_servicenow_failure_is_safe(self):
        self.client.update_incident.side_effect = ServiceNowError(
            "HTTP 500 Authorization: Bearer SECRET-TOKEN https://dev.service-now.com"
        )
        await self._ready()
        reply = await self._send("yes")
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.FAILED)
        self.assertIn("could not be applied", reply)
        for leaked in ("SECRET", "Bearer", "HTTP 500", "https://", "✅"):
            self.assertNotIn(leaked, reply)

    async def test_40b_gateway_raising_is_safe(self):
        await self._ready()
        with patch.object(self.gateway, "execute",
                          AsyncMock(side_effect=RuntimeError("password=hunter2"))):
            reply = await self._send("yes")
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.FAILED)
        self.assertNotIn("hunter2", reply)
        self.assertNotIn("✅", reply)

    async def test_41_no_automatic_retry(self):
        self.client.update_incident.side_effect = ServiceNowError("timeout")
        await self._ready()
        await self._send("yes")
        await self._send("yes")
        await self._send("confirm")
        self.assertEqual(self.client.update_incident.await_count, 1)
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.FAILED)

    async def test_42_duplicate_confirmation_cannot_execute_twice(self):
        await self._ready()
        await self._send("yes")
        await self._send("yes")
        self.assertEqual(self.client.update_incident.await_count, 1)

    async def test_42b_concurrent_confirmations_execute_once(self):
        release = asyncio.Event()

        async def slow_update(**kwargs):
            await release.wait()
            return dict(UPDATED)

        self.client.update_incident.side_effect = slow_update
        await self._ready()
        first_ctx, second_ctx = _context("yes"), _context("yes")
        first = asyncio.create_task(main.on_message(first_ctx))
        for _ in range(1000):
            if get_session(STATE_KEY).phase is ConversationPhase.EXECUTING:
                break
            await asyncio.sleep(0)
        else:
            release.set()
            await first
            self.fail("first confirmation never reached EXECUTING")
        await main.on_message(second_ctx)
        release.set()
        await first
        self.assertEqual(self.client.update_incident.await_count, 1)
        self.assertIn("still being", second_ctx.send.await_args.args[0])

    async def test_43_no_success_without_servicenow_confirmation(self):
        self.client.update_incident.return_value = {}
        await self._ready()
        reply = await self._send("yes")
        self.assertIn("did not return the updated values", reply)
        self.assertNotIn("**Impact:**", reply)
        # Validation failure inside the gateway is a failure, not success.
        clear_session(STATE_KEY)
        await self._ready()
        with patch.object(main, "UpdateIncidentToolRequest",
                          side_effect=lambda **kw: UpdateIncidentToolRequest(
                              **{**kw, "impact": "9"})):
            reply = await self._send("yes")
        self.assertEqual(get_session(STATE_KEY).phase, ConversationPhase.FAILED)
        self.assertNotIn("✅", reply)


# ===========================================================================
# 44–47: Regression
# ===========================================================================

class TestRegression(_Base):

    async def test_45_incident_creation_still_works(self):
        state = ConversationState()
        start_incident_collection(state, "VPN is down for me. Impact is 2 and urgency is 1.")
        save_session(STATE_KEY, state)
        reply = await self._send("yes")
        self.assertIn("INC0012345", reply)
        self.client.create_incident.assert_awaited_once()
        self.client.update_incident.assert_not_called()

    async def test_46_47_status_lookup_works_without_confirmation(self):
        reply = await self._send("status of INC0010002")
        self.assertIn("VPN unavailable", reply)
        self.assertNotIn("Shall I", reply)
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.IDLE)
        self.client.update_incident.assert_not_called()

    async def test_incident_number_during_update_collection_is_not_a_lookup(self):
        await self._send("Update INC0010002")
        self.client.get_incident.reset_mock()
        reply = await self._send("INC0010003")
        self.assertIn("didn't recognise", reply)
        self.client.get_incident.assert_not_called()
        self.assertEqual(get_session(STATE_KEY).incident_number, "INC0010002")

    async def test_update_command_during_create_collection_is_collection_input(self):
        state = ConversationState()
        start_incident_collection(state, "I need to report an issue")
        save_session(STATE_KEY, state)
        await self._send("update INC0010002 impact to 1")
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.COLLECTING)
        self.assertEqual(session.pending_action, "create_incident")
        self.client.get_incident.assert_not_called()
        self.client.update_incident.assert_not_called()

    async def test_new_request_after_completed_update(self):
        await self._ready()
        await self._send("yes")
        reply = await self._send("Update INC0010002 urgency to 1")
        self.assertIn("Shall I apply", reply)
        self.assertEqual(self.client.update_incident.await_count, 1)


# ===========================================================================
# 48–50: Conversation changed while awaiting (fail-closed phase re-checks)
# ===========================================================================

class TestStateChangeRace(_Base):

    def _slow_read(self):
        release = asyncio.Event()

        async def slow_get(number):
            await release.wait()
            return dict(CURRENT)

        self.client.get_incident.side_effect = slow_get
        return release

    async def _start_and_hold(self, message):
        """Start an update whose current-value read is held open."""
        release = self._slow_read()
        ctx = _context(message)
        task = asyncio.create_task(main.on_message(ctx))
        for _ in range(1000):
            if self.client.get_incident.await_count:
                break
            await asyncio.sleep(0)
        else:
            release.set()
            await task
            self.fail("update start never reached the current-value read")
        return ctx, task, release

    async def test_48_concurrent_update_starts_do_not_overwrite(self):
        """The exact race from the BL-009 review: two starts, one read window."""
        ctx1, task1, release = await self._start_and_hold("Update INC0010002 impact to 1")
        ctx2 = _context("Update INC0010002 urgency to 2")
        task2 = asyncio.create_task(main.on_message(ctx2))
        for _ in range(50):
            await asyncio.sleep(0)
        release.set()
        await asyncio.gather(task1, task2)

        replies = [ctx1.send.await_args.args[0], ctx2.send.await_args.args[0]]
        self.assertEqual(sum("You're asking me to update" in r for r in replies), 1)
        self.assertEqual(sum(r == main._REQUEST_IN_PROGRESS for r in replies), 1)
        self.assertFalse(any("trouble understanding" in r for r in replies))

        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        shown = replies[0] if "You're asking" in replies[0] else replies[1]
        pending = session.collected_details["changes"]
        self.assertEqual(len(pending), 1)
        field, value = next(iter(pending.items()))
        self.assertIn(f"→ {value}", shown)            # pending == what was shown
        self.client.update_incident.assert_not_called()

        await self._send("yes")
        self.client.update_incident.assert_awaited_once_with(
            incident_number="INC0010002", fields=pending
        )

    async def test_49_other_flow_started_during_read_is_not_overwritten(self):
        ctx, task, release = await self._start_and_hold("Update INC0010002 impact to 1")
        # Meanwhile the user starts a create; that conversation must survive.
        start_incident_collection(get_session(STATE_KEY), "I need to report an issue")
        release.set()
        await task

        self.assertEqual(ctx.send.await_args.args[0], main._REQUEST_IN_PROGRESS)
        session = get_session(STATE_KEY)
        self.assertEqual(session.phase, ConversationPhase.COLLECTING)
        self.assertEqual(session.pending_action, "create_incident")
        self.assertNotIn("changes", session.collected_details)
        self.client.update_incident.assert_not_called()

    async def test_50_update_never_executes_outside_ready_for_confirmation(self):
        valid = {"changes": {"impact": "1"}, "requested": [], "current": {"impact": "3"}}
        for phase in (ConversationPhase.IDLE, ConversationPhase.COLLECTING,
                      ConversationPhase.EXECUTING, ConversationPhase.COMPLETED,
                      ConversationPhase.FAILED):
            with self.subTest(phase=phase):
                state = ConversationState(
                    phase=phase, pending_action="update_incident",
                    incident_number="INC0010002", collected_details=dict(valid),
                )
                ctx = _context("yes")
                self.authorize.reset_mock()
                with patch.object(self.gateway, "execute", AsyncMock()) as execute:
                    await main._update_confirmed_incident(ctx, USER, state)
                execute.assert_not_called()
                self.authorize.assert_not_called()
                self.assertEqual(state.phase, phase)
                self.assertEqual(ctx.send.await_args.args[0], main._REQUEST_IN_PROGRESS)
        self.client.update_incident.assert_not_called()


if __name__ == "__main__":
    unittest.main()
