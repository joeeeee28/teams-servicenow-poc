"""
tests/test_incident_creation.py — Test suite for BL-007 Incident Confirmation & Creation.

Drives ``app.main.on_message`` through the real BL-003 confirmation gate,
BL-004 identity/authorization and BL-005 ServiceNowToolGateway.  Only the
ServiceNow client underneath the gateway (and the LLM classifier) are mocked;
no real ServiceNow call is possible.

Requirement coverage:
 1.  Complete BL-006 collection reaches READY_FOR_CONFIRMATION.
 2.  BL-003 evaluate_confirmation is reused.
 3.  Only explicit confirmation proceeds.
 4.  Ambiguous responses do not execute.
 5.  Cancellation does not execute.
 6.  Identity is resolved.
 7.  CREATE_INCIDENT authorization is evaluated.
 8.  Denied authorization does not execute.
 9.  EXECUTING is entered before the side effect.
10.  The ServiceNowToolGateway is used.
11.  The handler never calls ServiceNowClient directly.
12.  CreateIncidentToolRequest carries only the four collected fields.
13.  Missing impact/urgency are never defaulted.
14.  Missing/invalid data prevents execution.
15.  Success transitions EXECUTING → COMPLETED.
16.  The returned incident number is stored and shown.
17.  Success is never claimed unless the gateway confirms it.
18.  Gateway failure transitions EXECUTING → FAILED.
19.  Failure returns a safe error.
20.  CREATE is never automatically retried.
21.  Repeated confirmation never creates duplicate incidents.
22.  No real ServiceNow calls.
23.  BL-008 (incident status) remains untouched.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.main as main  # noqa: E402
from app.incident_collection import start_incident_collection  # noqa: E402
from app.security.authorization import AuthorizableAction  # noqa: E402
from app.servicenow import ServiceNowClient, ServiceNowError  # noqa: E402
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    clear_session,
    get_session,
    save_session,
)
from app.tools.servicenow import (  # noqa: E402
    CreateIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
)

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "bl007-user-aad-oid"

FULL_MESSAGE = (
    "VPN is down for me and I can't access internal applications. "
    "Impact is 2 and urgency is 1."
)
EXPECTED_FIELDS = {
    "short_description": "VPN is down for me and I can't access internal applications",
    "description": "VPN is down for me and I can't access internal applications.",
    "impact": "2",
    "urgency": "1",
}
CREATED = {"sys_id": "abc123", "number": "INC0012345", "state": "1"}


def _context(text: str, user_id: str = USER, tenant: str | None = TENANT):
    activity = SimpleNamespace(
        text=text,
        from_=SimpleNamespace(aad_object_id=user_id, id=user_id, name="Test User"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


class _Base(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        clear_session(USER)
        self.addCleanup(clear_session, USER)

        # Real gateway over a mocked ServiceNow client.
        self.client = AsyncMock()
        self.client.create_incident.return_value = dict(CREATED)
        self.gateway = ServiceNowToolGateway(client=self.client)

        self.classify = AsyncMock(
            return_value={"intent": "general", "summary": "x", "needs_service_now": False}
        )
        patches = [
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT}),
            # The handler must never use the direct client.
            patch.object(main.servicenow, "create_incident",
                         AsyncMock(side_effect=AssertionError("direct client call"))),
            # Any real ServiceNow HTTP attempt fails loudly.
            patch.object(ServiceNowClient, "_request",
                         AsyncMock(side_effect=AssertionError("real ServiceNow call"))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _ready(self, **overrides) -> ConversationState:
        """Put USER in READY_FOR_CONFIRMATION via the real BL-006 collector."""
        state = ConversationState()
        start_incident_collection(state, FULL_MESSAGE)
        assert state.phase is ConversationPhase.READY_FOR_CONFIRMATION
        for key, value in overrides.items():
            setattr(state, key, value)
        save_session(USER, state)
        return state

    async def _send(self, text: str, **ctx_kwargs) -> str:
        ctx = _context(text, **ctx_kwargs)
        await main.on_message(ctx)
        ctx.send.assert_awaited_once()
        return ctx.send.await_args.args[0]


# ===========================================================================
# 1–5: Confirmation boundary
# ===========================================================================

class TestConfirmationBoundary(_Base):

    async def test_01_full_conversation_reaches_ready_then_creates(self):
        self.classify.return_value = {
            "intent": "create_incident", "summary": "VPN", "needs_service_now": True,
        }
        await self._send("I need to report an issue")
        await self._send("My laptop VPN isn't connecting.")
        await self._send("2")
        reply = await self._send("1")
        self.assertEqual(get_session(USER).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertIn("Shall I create this incident?", reply)
        self.client.create_incident.assert_not_called()

        reply = await self._send("yes")
        self.assertEqual(get_session(USER).phase, ConversationPhase.COMPLETED)
        self.assertIn("INC0012345", reply)
        self.client.create_incident.assert_awaited_once_with(
            short_description="My laptop VPN isn't connecting",
            description="My laptop VPN isn't connecting.",
            impact="2",
            urgency="1",
        )

    async def test_02_bl003_gate_is_reused(self):
        self._ready()
        with patch.object(main, "evaluate_confirmation",
                          wraps=main.evaluate_confirmation) as gate:
            await self._send("yes")
        gate.assert_called_once()
        self.assertIs(gate.call_args.args[0], get_session(USER))
        self.assertEqual(gate.call_args.args[1], "yes")

    async def test_03_explicit_confirmations_proceed(self):
        for phrase in ("yes", "confirm", "create it", "go ahead", "proceed",
                       "submit it", "do it", "approved", "  YES  "):
            with self.subTest(phrase=phrase):
                clear_session(USER)
                self.client.create_incident.reset_mock()
                self._ready()
                await self._send(phrase)
                self.client.create_incident.assert_awaited_once()
                self.assertEqual(get_session(USER).phase, ConversationPhase.COMPLETED)

    async def test_04_ambiguous_responses_do_not_execute(self):
        self._ready()
        for phrase in ("okay", "ok", "sure", "sounds good", "maybe", "yes please",
                       "yeah", "fine", "impact 1", "INC0010001"):
            with self.subTest(phrase=phrase):
                reply = await self._send(phrase)
                self.assertIn("explicit confirmation", reply)
                self.assertEqual(get_session(USER).phase,
                                 ConversationPhase.READY_FOR_CONFIRMATION)
        self.client.create_incident.assert_not_called()
        self.classify.assert_not_called()

    async def test_05_cancellation_does_not_execute(self):
        for phrase in ("cancel", "no", "stop", "abort", "never mind", "don't create it"):
            with self.subTest(phrase=phrase):
                clear_session(USER)
                self._ready()
                reply = await self._send(phrase)
                self.assertIn("Cancelled", reply)
                session = get_session(USER)
                self.assertEqual(session.phase, ConversationPhase.IDLE)
                self.assertEqual(session.collected_details, {})
        self.client.create_incident.assert_not_called()

    async def test_05b_confirm_after_cancel_does_not_execute(self):
        self._ready()
        await self._send("cancel")
        await self._send("yes")
        self.client.create_incident.assert_not_called()


# ===========================================================================
# 6–8: Identity and authorization
# ===========================================================================

class TestIdentityAndAuthorization(_Base):

    async def test_06_identity_is_resolved_from_activity(self):
        self._ready()
        with patch.object(main, "resolve_identity", wraps=main.resolve_identity) as resolver, \
             patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            await self._send("yes")
        resolver.assert_called_once()
        self.assertEqual(resolver.call_args.kwargs["channel_tenant_id"], TENANT)
        identity = execute.call_args.args[0]
        self.assertEqual(identity.user_id, USER)
        self.assertEqual(identity.tenant_id, TENANT)

    async def test_06b_channel_data_object_form_resolves_tenant(self):
        activity = SimpleNamespace(
            channel_data=SimpleNamespace(tenant=SimpleNamespace(id=TENANT))
        )
        self.assertEqual(main._channel_tenant_id(activity), TENANT)
        self.assertEqual(main._channel_tenant_id(SimpleNamespace()), "")
        self.assertEqual(
            main._channel_tenant_id(SimpleNamespace(channel_data={"tenant": None})), ""
        )

    async def test_07_create_incident_authorization_evaluated(self):
        self._ready()
        with patch.object(main, "authorize", wraps=main.authorize) as authorize, \
             patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            await self._send("yes")
        authorize.assert_called_once()
        self.assertIs(authorize.call_args.args[1], AuthorizableAction.CREATE_INCIDENT)
        decision = execute.call_args.args[1]
        self.assertTrue(decision.allowed)
        self.assertIs(decision.action, AuthorizableAction.CREATE_INCIDENT)

    async def _assert_denied(self, **ctx_kwargs):
        self._ready()
        with patch.object(self.gateway, "execute", AsyncMock()) as execute:
            reply = await self._send("yes", **ctx_kwargs)
        self.assertIn("not authorised", reply)
        execute.assert_not_called()
        self.client.create_incident.assert_not_called()
        self.assertEqual(get_session(USER).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    async def test_08_wrong_tenant_denied(self):
        await self._assert_denied(tenant=OTHER_TENANT)

    async def test_08b_missing_tenant_denied(self):
        await self._assert_denied(tenant=None)

    async def test_08c_unconfigured_allowed_tenant_denied(self):
        with patch.dict("os.environ", {"TEAMS_TENANT_ID": ""}):
            await self._assert_denied()

    async def test_08d_anonymous_identity_denied(self):
        from app.security.identity import ANONYMOUS

        with patch.object(main, "resolve_identity", return_value=ANONYMOUS):
            await self._assert_denied()

    async def test_08e_denied_user_can_still_cancel(self):
        await self._assert_denied(tenant=OTHER_TENANT)
        await self._send("cancel")
        self.assertEqual(get_session(USER).phase, ConversationPhase.IDLE)
        self.client.create_incident.assert_not_called()


# ===========================================================================
# 9–14: Execution contract
# ===========================================================================

class TestExecutionContract(_Base):

    async def test_09_executing_persisted_before_side_effect(self):
        seen = {}

        async def create(**kwargs):
            seen["phase"] = get_session(USER).phase
            return dict(CREATED)

        self.client.create_incident.side_effect = create
        self._ready()
        await self._send("yes")
        self.assertEqual(seen["phase"], ConversationPhase.EXECUTING)

    async def test_09b_transition_sequence(self):
        self._ready()
        seen = []
        original = ConversationState.transition_to

        def spy(state, new_phase):
            seen.append(new_phase)
            return original(state, new_phase)

        with patch.object(ConversationState, "transition_to", spy):
            await self._send("yes")
        self.assertEqual(seen, [ConversationPhase.EXECUTING, ConversationPhase.COMPLETED])

    async def test_10_gateway_is_used_with_create_action(self):
        self._ready()
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            await self._send("yes")
        execute.assert_awaited_once()
        self.assertIs(execute.call_args.args[2], ServiceNowToolAction.CREATE_INCIDENT)

    async def test_11_handler_never_calls_client_directly(self):
        # main.servicenow.create_incident raises AssertionError if called
        # (see _Base); a successful create proves only the gateway path ran.
        self._ready()
        reply = await self._send("yes")
        self.assertIn("INC0012345", reply)
        main.servicenow.create_incident.assert_not_called()

    async def test_12_request_contains_only_collected_fields(self):
        self._ready(summary="LLM summary that must not be used")
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            await self._send("yes")
        request = execute.call_args.args[3]
        self.assertIsInstance(request, CreateIncidentToolRequest)
        self.assertEqual(
            {f: getattr(request, f) for f in EXPECTED_FIELDS}, EXPECTED_FIELDS
        )
        self.client.create_incident.assert_awaited_once_with(**EXPECTED_FIELDS)

    async def test_12b_extra_collected_keys_never_reach_servicenow(self):
        state = self._ready()
        state.collected_details.update(
            {"priority": "1", "assignment_group": "Network", "caller_id": "admin"}
        )
        await self._send("yes")
        self.client.create_incident.assert_awaited_once_with(**EXPECTED_FIELDS)

    async def _assert_blocked(self, details):
        self._ready(collected_details=details)
        with patch.object(self.gateway, "execute", AsyncMock()) as execute:
            reply = await self._send("yes")
        self.assertIn("missing or invalid", reply)
        self.assertNotIn("✅", reply)
        execute.assert_not_called()
        self.client.create_incident.assert_not_called()
        session = get_session(USER)
        self.assertEqual(session.phase, ConversationPhase.IDLE)
        self.assertIsNone(session.pending_action)

    async def test_13_missing_impact_not_defaulted(self):
        details = dict(EXPECTED_FIELDS)
        del details["impact"]
        await self._assert_blocked(details)

    async def test_13b_missing_urgency_not_defaulted(self):
        details = dict(EXPECTED_FIELDS)
        del details["urgency"]
        await self._assert_blocked(details)

    async def test_14_missing_short_description_blocks(self):
        details = dict(EXPECTED_FIELDS)
        del details["short_description"]
        await self._assert_blocked(details)

    async def test_14b_missing_description_blocks(self):
        details = dict(EXPECTED_FIELDS)
        del details["description"]
        await self._assert_blocked(details)

    async def test_14c_empty_details_block(self):
        await self._assert_blocked({})

    async def test_14d_out_of_contract_values_block(self):
        for field, bad in (("impact", "5"), ("urgency", "4"), ("impact", "high"),
                           ("short_description", "x" * 161), ("description", "   ")):
            with self.subTest(field=field, bad=bad):
                clear_session(USER)
                await self._assert_blocked({**EXPECTED_FIELDS, field: bad})

    async def test_14e_wrong_pending_action_blocks(self):
        # Even if a future executable action were pending, this path only
        # ever creates incidents for pending_action == create_incident.
        with patch("app.confirmation.EXECUTABLE_ACTIONS",
                   frozenset({"create_incident", "update_incident"})):
            self._ready(pending_action="update_incident")
            with patch.object(self.gateway, "execute", AsyncMock()) as execute:
                reply = await self._send("yes")
        self.assertIn("missing or invalid", reply)
        execute.assert_not_called()


# ===========================================================================
# 15–19: Results
# ===========================================================================

class TestResults(_Base):

    async def test_15_16_success_completes_and_shows_real_number(self):
        self.client.create_incident.return_value = {"sys_id": "z", "number": "INC0099887"}
        self._ready()
        reply = await self._send("yes")
        session = get_session(USER)
        self.assertEqual(session.phase, ConversationPhase.COMPLETED)
        self.assertEqual(session.incident_number, "INC0099887")
        self.assertIn("INC0099887", reply)
        self.assertIn("created successfully", reply)
        self.assertIn(EXPECTED_FIELDS["short_description"], reply)

    async def test_16b_success_without_number_is_not_misreported(self):
        self.client.create_incident.return_value = {"sys_id": "z"}
        self._ready()
        reply = await self._send("yes")
        session = get_session(USER)
        self.assertEqual(session.phase, ConversationPhase.COMPLETED)
        self.assertIsNone(session.incident_number)
        self.assertIn("did not return an incident number", reply)
        self.assertIn("do not submit it again", reply)
        self.assertNotIn("****", reply)

    async def test_17_18_19_gateway_failure_fails_safely(self):
        self.client.create_incident.side_effect = ServiceNowError(
            "HTTP 500 Authorization: Bearer SECRET-TOKEN client_secret=abc"
        )
        self._ready()
        reply = await self._send("yes")
        session = get_session(USER)
        self.assertEqual(session.phase, ConversationPhase.FAILED)
        self.assertIsNone(session.incident_number)
        self.assertEqual(session.last_error, "Failed to create incident in ServiceNow.")
        self.assertIn("could not be created", reply)
        self.assertNotIn("✅", reply)
        self.assertNotIn("successfully", reply)
        for secret in ("SECRET-TOKEN", "Bearer", "client_secret", "HTTP 500"):
            self.assertNotIn(secret, reply)

    async def test_17b_gateway_raising_unexpectedly_fails_safely(self):
        self._ready()
        with patch.object(self.gateway, "execute",
                          AsyncMock(side_effect=RuntimeError("password=hunter2"))):
            reply = await self._send("yes")
        session = get_session(USER)
        self.assertEqual(session.phase, ConversationPhase.FAILED)
        self.assertNotIn("hunter2", reply)
        self.assertNotIn("✅", reply)
        self.assertIn("could not be created", reply)

    async def test_17c_gateway_validation_failure_is_not_success(self):
        self._ready()
        with patch.object(main, "CreateIncidentToolRequest",
                          side_effect=lambda **kw: CreateIncidentToolRequest(
                              **{**kw, "impact": "9"})):
            reply = await self._send("yes")
        self.assertEqual(get_session(USER).phase, ConversationPhase.FAILED)
        self.assertIn("could not be created", reply)
        self.client.create_incident.assert_not_called()

    async def test_19b_failure_transition_sequence(self):
        self.client.create_incident.side_effect = ServiceNowError("boom")
        self._ready()
        seen = []
        original = ConversationState.transition_to

        def spy(state, new_phase):
            seen.append(new_phase)
            return original(state, new_phase)

        with patch.object(ConversationState, "transition_to", spy):
            await self._send("yes")
        self.assertEqual(seen, [ConversationPhase.EXECUTING, ConversationPhase.FAILED])


# ===========================================================================
# 20–23: Retry, duplicates, isolation, scope
# ===========================================================================

class TestNoRetryNoDuplicates(_Base):

    async def test_20_create_not_retried_after_failure(self):
        self.client.create_incident.side_effect = ServiceNowError("boom")
        self._ready()
        await self._send("yes")
        await self._send("yes")
        await self._send("confirm")
        self.assertEqual(self.client.create_incident.await_count, 1)
        self.assertEqual(get_session(USER).phase, ConversationPhase.FAILED)

    async def test_21_repeated_confirmation_after_success(self):
        self._ready()
        await self._send("yes")
        await self._send("yes")
        await self._send("go ahead")
        self.assertEqual(self.client.create_incident.await_count, 1)
        self.assertEqual(get_session(USER).incident_number, "INC0012345")

    async def test_21b_concurrent_confirmations_create_once(self):
        release = asyncio.Event()

        async def slow_create(**kwargs):
            await release.wait()
            return dict(CREATED)

        self.client.create_incident.side_effect = slow_create
        self._ready()
        first_ctx, second_ctx = _context("yes"), _context("yes")
        first = asyncio.create_task(main.on_message(first_ctx))
        for _ in range(1000):
            if get_session(USER).phase is ConversationPhase.EXECUTING:
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

    async def test_21c_executing_phase_never_reaches_llm_or_gateway(self):
        self._ready()
        get_session(USER).transition_to(ConversationPhase.EXECUTING)
        with patch.object(self.gateway, "execute", AsyncMock()) as execute:
            reply = await self._send("yes")
        self.assertIn("still being created", reply)
        execute.assert_not_called()
        self.classify.assert_not_called()

    async def test_21d_users_are_isolated(self):
        other = "bl007-other-user"
        self.addCleanup(clear_session, other)
        self._ready()
        other_state = ConversationState()
        start_incident_collection(other_state, FULL_MESSAGE)
        save_session(other, other_state)

        await self._send("yes")
        self.assertEqual(get_session(USER).phase, ConversationPhase.COMPLETED)
        self.assertEqual(get_session(other).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertIsNone(get_session(other).incident_number)
        self.assertEqual(self.client.create_incident.await_count, 1)

    async def test_21e_new_incident_after_completion_requires_new_collection(self):
        self.classify.return_value = {
            "intent": "create_incident", "summary": "x", "needs_service_now": True,
        }
        self._ready()
        await self._send("yes")
        await self._send("Please raise a ticket.")
        session = get_session(USER)
        self.assertEqual(session.phase, ConversationPhase.COLLECTING)
        self.assertIsNone(session.incident_number)
        await self._send("yes")  # a word, not a confirmation, while collecting
        self.assertEqual(self.client.create_incident.await_count, 1)


class TestScope(_Base):

    async def test_22_no_real_servicenow_http(self):
        import httpx

        self._ready()
        with patch.object(httpx.AsyncClient, "send",
                          AsyncMock(side_effect=AssertionError("HTTP"))):
            reply = await self._send("yes")
        self.assertIn("INC0012345", reply)

    async def test_23_incident_status_flow_unchanged(self):
        self.classify.return_value = {
            "intent": "incident_status", "summary": "status", "needs_service_now": True,
        }
        with patch.object(self.gateway, "execute", AsyncMock()) as execute:
            reply = await self._send("What is the status of my ticket?")
        self.assertIn("provide the incident number", reply)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
