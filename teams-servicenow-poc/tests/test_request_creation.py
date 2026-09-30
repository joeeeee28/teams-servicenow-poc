"""
tests/test_request_creation.py — Test suite for DEMO-06 Service Request Creation.

Covers variable collection, contract validation, authorization, Tool Gateway
execution, confirmation gate integration, resilience, audit logging, and state machine transitions.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.main as main
import app.observability as obs
from app.audit import AuditEventType, AuditOutcome
from app.catalog import LocalCatalogRepository
from app.request_collection import (
    CREATE_REQUEST_ACTION,
    process_request_collection_message,
    start_request_collection,
)
from app.security.authorization import AuthorizableAction, authorize
from app.security.identity import IdentitySource, UserIdentity
from app.state import (
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    StateKey,
    configure_state_repository,
    get_session,
    get_state_repository,
    save_session,
)
from app.tools import (
    CreateRequestToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    ToolAuthorizationError,
    ToolResult,
    ToolValidationError,
)

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
USER = "demo06-user-aad-oid"
CONV = "19:demo06-conversation@thread.v2"
KEY = StateKey(TENANT, USER, CONV)

EMPLOYEE = UserIdentity(
    user_id=USER,
    tenant_id=TENANT,
    display_name="Demo User",
    email="demo@example.com",
    source=IdentitySource.AAD_OBJECT_ID,
)


def _context(text, user=USER, tenant=TENANT, conversation=CONV):
    activity = SimpleNamespace(
        id="1712345678901",
        text=text,
        from_=SimpleNamespace(aad_object_id=user, id=user, name="Demo User"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
        conversation=SimpleNamespace(id=conversation),
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


class TestRequestCollectionUnit(unittest.TestCase):

    def setUp(self):
        self.catalog = LocalCatalogRepository.from_fixture()
        self.visio_item = self.catalog.get_item_by_ref("CAT0001")

    def test_start_collection_prompts_for_variable(self):
        session = ConversationState()
        res = start_request_collection(session, self.visio_item)
        self.assertEqual(session.phase, ConversationPhase.COLLECTING)
        self.assertEqual(session.pending_action, CREATE_REQUEST_ACTION)
        self.assertIn("Business justification", res.reply)
        self.assertEqual(res.missing_variables, ("business_justification", "department", "license_duration"))

    def test_process_variable_value_moves_to_confirmation(self):
        session = ConversationState()
        start_request_collection(session, self.visio_item)
        process_request_collection_message(session, self.visio_item, "Vector architecture diagrams")
        process_request_collection_message(session, self.visio_item, "Engineering")
        res = process_request_collection_message(session, self.visio_item, "12 months")
        self.assertEqual(session.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertIn("Request Confirmation", res.reply)
        self.assertIn("Vector architecture diagrams", res.reply)
        self.assertEqual(session.collected_details["variables"]["business_justification"], "Vector architecture diagrams")
        self.assertEqual(session.collected_details["variables"]["department"], "Engineering")
        self.assertEqual(session.collected_details["variables"]["license_duration"], "12 months")

    def test_cancellation_resets_session(self):
        session = ConversationState()
        start_request_collection(session, self.visio_item)
        res = process_request_collection_message(session, self.visio_item, "cancel")
        self.assertTrue(res.cancelled)
        self.assertEqual(session.phase, ConversationPhase.IDLE)


class TestCreateRequestContract(unittest.TestCase):

    def test_valid_request(self):
        req = CreateRequestToolRequest(
            sys_id="a1b2c3d4e5f60718293a4b5c6d7e8f90",
            variables={"business_justification": "Software development"},
        )
        req.validate()

    def test_invalid_sys_id(self):
        req = CreateRequestToolRequest(
            sys_id="invalid-sys-id",
            variables={"business_justification": "Testing"},
        )
        with self.assertRaises(ToolValidationError):
            req.validate()

    def test_closed_contract_extra_fields(self):
        with self.assertRaises(TypeError):
            CreateRequestToolRequest(
                sys_id="a1b2c3d4e5f60718293a4b5c6d7e8f90",
                variables={"business_justification": "Testing"},
                table="sys_user",
            )


class TestRequestGatewayExecution(unittest.IsolatedAsyncioTestCase):

    async def test_gateway_execute_create_request_success(self):
        with patch.dict(os.environ, {"TEAMS_TENANT_ID": TENANT}):
            mock_client = AsyncMock()
            mock_client.create_service_request.return_value = {
                "number": "REQ0010001",
                "sys_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            }
            gateway = ServiceNowToolGateway(client=mock_client)
            authz = authorize(EMPLOYEE, AuthorizableAction.CREATE_REQUEST)

            req = CreateRequestToolRequest(
                sys_id="a1b2c3d4e5f60718293a4b5c6d7e8f90",
                variables={"business_justification": "Design diagrams"},
            )

            result = await gateway.execute(
                identity=EMPLOYEE,
                authorization_decision=authz,
                tool_action=ServiceNowToolAction.CREATE_REQUEST,
                request=req,
            )

            self.assertTrue(result.success)
            self.assertEqual(result.request_number, "REQ0010001")
            mock_client.create_service_request.assert_awaited_once_with(
                sys_id="a1b2c3d4e5f60718293a4b5c6d7e8f90",
                variables={"business_justification": "Design diagrams"},
            )

    async def test_gateway_action_mismatch_denied(self):
        with patch.dict(os.environ, {"TEAMS_TENANT_ID": TENANT}):
            gateway = ServiceNowToolGateway(client=AsyncMock())
            authz = authorize(EMPLOYEE, AuthorizableAction.READ_KNOWLEDGE)  # Wrong action

            req = CreateRequestToolRequest(
                sys_id="a1b2c3d4e5f60718293a4b5c6d7e8f90",
                variables={"business_justification": "Design diagrams"},
            )

            result = await gateway.execute(
                identity=EMPLOYEE,
                authorization_decision=authz,
                tool_action=ServiceNowToolAction.CREATE_REQUEST,
                request=req,
            )

            self.assertFalse(result.success)
            self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")


class TestRequestHandlerIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        previous_store = get_state_repository()
        configure_state_repository(InMemoryStateRepository())
        self.addCleanup(configure_state_repository, previous_store)

        self.audit_events = []
        self.audit_mock = MagicMock()
        self.audit_mock.record = lambda *args, **kwargs: self.audit_events.append((args, kwargs))

        self.gateway_client = AsyncMock()
        self.gateway_client.create_service_request.return_value = {
            "number": "REQ0010099",
            "sys_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        }
        self.gateway = ServiceNowToolGateway(client=self.gateway_client, audit_logger=self.audit_mock)

        self.classify_mock = AsyncMock(side_effect=lambda msg: {
            "intent": "service_request",
            "summary": "Request software item",
        })

        for p in (
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify_mock),
            patch.object(main, "audit_logger", self.audit_mock),
            patch.dict(os.environ, {"TEAMS_TENANT_ID": TENANT}),
        ):
            p.start()
            self.addCleanup(p.stop)

    async def test_full_service_request_flow_end_to_end(self):
        # Turn 1: "I need Microsoft Visio"
        ctx1 = _context("I need Microsoft Visio")
        await main.on_message(ctx1)
        reply1 = ctx1.send.await_args.args[0]
        self.assertIn("Business justification", reply1)
        self.assertEqual(get_session(KEY).phase, ConversationPhase.COLLECTING)

        # Turn 2: Provide business justification
        ctx2 = _context("For drawing architecture charts")
        await main.on_message(ctx2)
        reply2 = ctx2.send.await_args.args[0]
        self.assertIn("Department", reply2)

        # Turn 3: Provide department
        ctx3 = _context("Engineering")
        await main.on_message(ctx3)
        reply3 = ctx3.send.await_args.args[0]
        self.assertIn("License duration", reply3)

        # Turn 4: Provide duration choice
        ctx4 = _context("12 months")
        await main.on_message(ctx4)
        reply4 = ctx4.send.await_args.args[0]
        self.assertIn("Request Confirmation", reply4)
        self.assertIn("For drawing architecture charts", reply4)
        self.assertEqual(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)

        # Turn 5: Explicit confirmation "yes"
        ctx5 = _context("yes")
        await main.on_message(ctx5)
        reply5 = ctx5.send.await_args.args[0]
        self.assertIn("REQ0010099", reply5)
        self.assertIn("created successfully", reply5)
        self.assertEqual(get_session(KEY).phase, ConversationPhase.COMPLETED)

    async def test_cancellation_during_confirmation(self):
        # Turns to reach READY_FOR_CONFIRMATION
        await main.on_message(_context("I need Microsoft Visio"))
        await main.on_message(_context("For drawing charts"))
        await main.on_message(_context("Engineering"))
        await main.on_message(_context("12 months"))

        self.assertEqual(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)

        # Turn: "cancel"
        ctx = _context("cancel")
        await main.on_message(ctx)
        reply = ctx.send.await_args.args[0]
        self.assertIn("Cancelled", reply)
        self.assertEqual(get_session(KEY).phase, ConversationPhase.IDLE)
        self.gateway_client.create_service_request.assert_not_called()


# ===========================================================================
# Regression: SQLite persistence, request numbers, uncertain outcomes
# ===========================================================================

import json  # noqa: E402
import sqlite3  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from app.servicenow import ServiceNowTimeout  # noqa: E402
from app.servicenow_errors import ServiceNowErrorCategory, failure_message  # noqa: E402
from app.state_store import SqliteStateRepository, serialize_state  # noqa: E402

VISIO_SYS_ID = "c0a8010e5d5f4c1b9e2f00000000c001"
RETURNED_SYS_ID = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
VISIO_TURNS = ("For drawing architecture charts", "Engineering", "12 months")


class _HandlerHarness(unittest.IsolatedAsyncioTestCase):
    """Real handler + real gateway; only the ServiceNow client and LLM are mocked."""

    create_result: object = {"number": "REQ0012345", "sys_id": RETURNED_SYS_ID}

    async def asyncSetUp(self):
        # Isolate from a developer's local SERVICENOW_CATALOG_SYS_IDS (loaded
        # from .env): these tests expect the fixture catalog unless a test sets
        # the mapping itself.  patch.dict restores os.environ after each test.
        isolated_env = patch.dict(os.environ)
        isolated_env.start()
        self.addCleanup(isolated_env.stop)
        os.environ.pop("SERVICENOW_CATALOG_SYS_IDS", None)

        previous_store = get_state_repository()
        self.addCleanup(configure_state_repository, previous_store)
        configure_state_repository(InMemoryStateRepository())
        self.audit_events = []
        self.audit_mock = MagicMock()
        self.audit_mock.record = lambda *a, **k: self.audit_events.append((a, k))
        self.client = AsyncMock()
        result = self.create_result
        if isinstance(result, BaseException):
            self.client.create_service_request.side_effect = result
        else:
            self.client.create_service_request.return_value = result
        self.client.create_incident.side_effect = AssertionError("incident created")
        self.client.update_incident.side_effect = AssertionError("incident updated")
        self.gateway = ServiceNowToolGateway(client=self.client, audit_logger=self.audit_mock)
        self.classify = AsyncMock(side_effect=lambda msg: {"intent": "service_request",
                                                           "summary": "x"})
        for p in (
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.object(main, "audit_logger", self.audit_mock),
            patch.dict(os.environ, {"TEAMS_TENANT_ID": TENANT}),
        ):
            p.start()
            self.addCleanup(p.stop)

    async def _send(self, text):
        ctx = _context(text)
        await main.on_message(ctx)
        return ctx.send.await_args.args[0]

    async def _ready(self):
        await self._send("I need Microsoft Visio")
        for answer in VISIO_TURNS:
            reply = await self._send(answer)
        self.assertIs(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        return reply

    def _audited(self, event_type):
        return [k for a, k in self.audit_events if a and a[0] is event_type]


class TestRequestSqlitePersistence(_HandlerHarness):
    """The default SQLite store must carry a request across Teams messages."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "conversation_state.db"
        self._open()

    def _open(self):
        self.repo = SqliteStateRepository(self.path)
        self.addCleanup(self.repo.close)
        configure_state_repository(self.repo)

    def _restart(self):
        """Simulate the next Teams turn arriving at a fresh process."""
        self.repo.close()
        self._open()

    def _stored(self):
        row = sqlite3.connect(self.path).execute(
            "SELECT state_json FROM conversation_state").fetchone()
        return json.loads(row[0])

    async def test_request_flow_survives_every_turn_and_executes_once(self):
        # 1. Start the request.
        reply = await self._send("I need Microsoft Visio")
        self.assertIn("Business justification", reply)
        # 2. Persisted.
        stored = self._stored()
        self.assertEqual(stored["pending_action"], "create_request")
        self.assertEqual(stored["collected_details"], {
            "item_ref": "CAT0001", "sys_id": VISIO_SYS_ID,
            "item_name": "Microsoft Visio", "variables": {}})
        # 3–4. Each next turn arrives at a fresh repository and continues.
        prompts = ("Department", "License duration", "Request Confirmation")
        for answer, expected in zip(VISIO_TURNS, prompts):
            self._restart()
            reply = await self._send(answer)
            self.assertIn(expected, reply)
            state = get_session(KEY)
            self.assertEqual(state.pending_action, "create_request")
            self.assertEqual(state.collected_details["item_ref"], "CAT0001")
        # 5. Confirmation reached, with every value intact.
        self.assertIs(get_session(KEY).phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(get_session(KEY).collected_details["variables"], {
            "business_justification": "For drawing architecture charts",
            "department": "Engineering", "license_duration": "12 months"})
        for text in VISIO_TURNS:
            self.assertIn(text, reply)
        # 6. Executed exactly once, never as an incident.
        self._restart()
        reply = await self._send("yes")
        self.assertIn("REQ0012345", reply)
        self.classify.assert_awaited_once()  # collection/confirmation turns never reach the LLM
        self._restart()
        await self._send("yes")  # a new message after completion: must not re-execute
        self.client.create_service_request.assert_awaited_once_with(
            sys_id=VISIO_SYS_ID,
            variables={"business_justification": "For drawing architecture charts",
                       "department": "Engineering", "license_duration": "12 months"})
        self.client.create_incident.assert_not_called()
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.COMPLETED)
        self.assertEqual(state.collected_details, {})  # DEMO-01: not kept at rest

    async def test_ready_request_survives_restart(self):
        await self._ready()
        self._restart()
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(state.pending_action, "create_request")

    def test_request_details_cleared_once_finished(self):
        for terminal in (ConversationPhase.COMPLETED, ConversationPhase.FAILED):
            with self.subTest(phase=terminal):
                state = ConversationState()
                state.transition_to(ConversationPhase.COLLECTING)
                state.pending_action = "create_request"
                state.collected_details = {
                    "item_ref": "CAT0001", "sys_id": VISIO_SYS_ID,
                    "item_name": "Microsoft Visio",
                    "variables": {"business_justification": "Diagrams"}}
                state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
                state.transition_to(ConversationPhase.EXECUTING)
                state.transition_to(terminal)
                self.repo.save(KEY, state)
                self._restart()
                self.assertEqual(get_session(KEY).collected_details, {})
                self.assertEqual(self._stored()["collected_details"], {})

    def test_invalid_request_details_are_not_persisted(self):
        state = ConversationState(
            phase=ConversationPhase.COLLECTING, pending_action="create_request",
            collected_details={
                "item_ref": "CAT1; DROP", "sys_id": "../../sys_user", "item_name": "x" * 81,
                "variables": {"Bad Name": "v", "ok_name": "y" * 501, "department": "Eng",
                              "count": 3},
                "password": "hunter2",
            })
        details = serialize_state(state)["collected_details"]
        self.assertEqual(details, {"variables": {"department": "Eng"}})


class TestRequestNumbers(_HandlerHarness):

    async def _confirm(self, result):
        self.client.create_service_request.return_value = result
        await self._ready()
        return await self._send("yes")

    async def test_real_request_number_reported(self):
        reply = await self._confirm({"number": "REQ0012345", "sys_id": RETURNED_SYS_ID})
        self.assertIn("✅ Request **REQ0012345** has been created successfully", reply)

    async def test_sys_id_only_is_never_displayed(self):
        reply = await self._confirm({"sys_id": RETURNED_SYS_ID})
        self.assertNotIn(RETURNED_SYS_ID, reply)
        self.assertNotIn(VISIO_SYS_ID, reply)
        self.assertIn("did not return a request number", reply)
        self.assertIn("do not submit it again", reply)

    async def test_no_number_is_never_fabricated(self):
        for result in ({}, {"number": ""}, {"number": "abc"}, {"request_number": 42},
                       {"number": RETURNED_SYS_ID}):
            with self.subTest(result=result):
                configure_state_repository(InMemoryStateRepository())  # fresh conversation
                reply = await self._confirm(result)
                self.assertNotIn("REQ0010001", reply)
                self.assertNotIn("Request **", reply)
                self.assertNotIn(RETURNED_SYS_ID, reply)
                self.assertIn("did not return a request number", reply)
                self.assertIs(get_session(KEY).phase, ConversationPhase.COMPLETED)

    async def test_gateway_never_reports_sys_id_as_number(self):
        authz = authorize(EMPLOYEE, AuthorizableAction.CREATE_REQUEST)
        self.client.create_service_request.return_value = {"sys_id": RETURNED_SYS_ID}
        result = await self.gateway.execute(
            EMPLOYEE, authz, ServiceNowToolAction.CREATE_REQUEST,
            CreateRequestToolRequest(sys_id=VISIO_SYS_ID, variables={}))
        self.assertTrue(result.success)
        self.assertIsNone(result.request_number)
        self.assertNotIn(RETURNED_SYS_ID, result.safe_message)
        self.assertNotIn("REQ0010001", result.safe_message)


class TestSecondRequest(_HandlerHarness):

    async def test_second_request_after_completion_starts_and_completes(self):
        # Request #1 → confirmation → COMPLETED.
        await self._ready()
        self.assertIn("REQ0012345", await self._send("yes"))
        self.assertIs(get_session(KEY).phase, ConversationPhase.COMPLETED)

        # Request #2 in the same conversation starts a fresh collection.
        self.client.create_service_request.return_value = {"number": "REQ0012346"}
        reply = await self._send("I need Microsoft Visio")
        self.assertNotIn("having trouble understanding", reply)
        self.assertIn("Business justification", reply)
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(state.pending_action, "create_request")
        self.assertEqual(state.collected_details["variables"], {})  # nothing carried over

        for answer in ("Second licence for a contractor", "Finance", "3 months"):
            reply = await self._send(answer)
        self.assertIn("Second licence for a contractor", reply)
        self.assertNotIn("For drawing architecture charts", reply)
        self.assertIn("REQ0012346", await self._send("yes"))

        # Exactly two creates: request #1 was never re-submitted.
        calls = self.client.create_service_request.await_args_list
        self.assertEqual([c.kwargs["variables"]["business_justification"] for c in calls],
                         ["For drawing architecture charts", "Second licence for a contractor"])
        self.assertIs(get_session(KEY).phase, ConversationPhase.COMPLETED)


class TestSecondRequestAfterFailureOrCancel(_HandlerHarness):

    async def _second_request(self, justification="Second licence for a contractor"):
        reply = await self._send("I need Microsoft Visio")
        self.assertNotIn("having trouble understanding", reply)
        self.assertIn("Business justification", reply)
        state = get_session(KEY)
        self.assertIs(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(state.pending_action, "create_request")
        self.assertEqual(state.collected_details["variables"], {})
        for answer in (justification, "Finance", "3 months"):
            reply = await self._send(answer)
        self.assertIn(justification, reply)
        self.assertNotIn("For drawing architecture charts", reply)
        return await self._send("yes")

    async def test_second_request_after_failed(self):
        from app.servicenow import ServiceNowUnavailable

        self.client.create_service_request.side_effect = [
            ServiceNowUnavailable("down"), {"number": "REQ0012346"}]
        await self._ready()
        self.assertIn("No change was made", await self._send("yes"))
        self.assertIs(get_session(KEY).phase, ConversationPhase.FAILED)
        await self._send("yes")  # never retried
        self.assertEqual(self.client.create_service_request.await_count, 1)

        self.assertIn("REQ0012346", await self._second_request())
        calls = self.client.create_service_request.await_args_list
        self.assertEqual([c.kwargs["variables"]["business_justification"] for c in calls],
                         ["For drawing architecture charts", "Second licence for a contractor"])
        self.assertIs(get_session(KEY).phase, ConversationPhase.COMPLETED)

    async def test_second_request_after_cancel_at_confirmation(self):
        await self._ready()
        self.assertIn("Cancelled", await self._send("cancel"))
        self.client.create_service_request.assert_not_called()
        self.assertIn("REQ0012345", await self._second_request())
        self.client.create_service_request.assert_awaited_once()
        variables = self.client.create_service_request.await_args.kwargs["variables"]
        self.assertEqual(variables["business_justification"], "Second licence for a contractor")

    async def test_second_request_from_persisted_cancelled_phase(self):
        cancelled = ConversationState()
        cancelled.transition_to(ConversationPhase.COLLECTING)
        cancelled.pending_action = "create_request"
        cancelled.collected_details = {"item_ref": "CAT0002", "variables": {"department": "Old"}}
        cancelled.transition_to(ConversationPhase.CANCELLED)
        save_session(KEY, cancelled)
        self.assertIn("REQ0012345", await self._second_request())
        self.client.create_service_request.assert_awaited_once_with(
            sys_id=VISIO_SYS_ID,
            variables={"business_justification": "Second licence for a contractor",
                       "department": "Finance", "license_duration": "3 months"})


class TestRequestNotFound(_HandlerHarness):

    async def test_404_on_create_request_is_safe_and_not_retried(self):
        from app.servicenow import ServiceNowNotFound

        self.client.create_service_request.side_effect = ServiceNowNotFound("404")
        await self._ready()
        reply = await self._send("yes")
        self.assertTrue(reply.startswith("❌"))
        self.assertIn("No change was made", reply)
        for leaked in (VISIO_SYS_ID, "REQ", "✅", "404", "sys_id", "incident"):
            self.assertNotIn(leaked, reply)
        self.assertIs(get_session(KEY).phase, ConversationPhase.FAILED)
        await self._send("yes")
        self.client.create_service_request.assert_awaited_once()
        failed = self._audited(AuditEventType.REQUEST_CREATE_FAILED)
        self.assertEqual([k["reason"] for k in failed], ["not_found"])


class TestExecutingGuard(_HandlerHarness):

    def _executing(self, pending_action):
        state = ConversationState()
        state.transition_to(ConversationPhase.COLLECTING)
        state.pending_action = pending_action
        state.collected_details = ({"item_ref": "CAT0001", "sys_id": VISIO_SYS_ID,
                                    "item_name": "Microsoft Visio", "variables": {}}
                                   if pending_action == "create_request" else {})
        state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        state.transition_to(ConversationPhase.EXECUTING)
        save_session(KEY, state)

    async def test_request_in_flight_says_service_request(self):
        self._executing("create_request")
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as execute:
            reply = await self._send("yes")
        self.assertEqual(reply, "⏳ Your service request is still being created. "
                                "Please wait for the result before sending another request.")
        self.assertNotIn("incident", reply)
        execute.assert_not_called()  # the gateway is not invoked again
        self.client.create_service_request.assert_not_called()
        self.classify.assert_not_called()
        self.assertIs(get_session(KEY).phase, ConversationPhase.EXECUTING)

    async def test_incident_in_flight_message_unchanged(self):
        for pending in ("create_incident", "update_incident"):
            with self.subTest(pending=pending):
                self._executing(pending)
                reply = await self._send("yes")
                self.assertEqual(reply, "⏳ Your incident is still being created. "
                                        "Please wait for the result before sending another "
                                        "request.")
        self.client.create_service_request.assert_not_called()


CONFIGURED_SYS_ID = "0123456789abcdef0123456789abcdef"  # synthetic test value


class TestCatalogConfiguration(_HandlerHarness):
    """SERVICENOW_CATALOG_SYS_IDS maps catalog refs to real instance sys_ids."""

    def _env(self, value):
        p = patch.dict(os.environ, {"SERVICENOW_CATALOG_SYS_IDS": value})
        p.start()
        self.addCleanup(p.stop)

    def test_parse_accepts_only_valid_entries(self):
        from app.servicenow import catalog_sys_ids_from_env

        other = "fedcba9876543210fedcba9876543210"
        self._env(f" CAT0001 = {CONFIGURED_SYS_ID} , garbage, CAT9={other}, "
                  f"CAT0006=NOT-A-SYS-ID, CAT0002={other}, INC0010002={other},")
        with self.assertLogs("app.servicenow", level="WARNING") as logs:
            mapping = catalog_sys_ids_from_env()
        self.assertEqual(mapping, {"CAT0001": CONFIGURED_SYS_ID, "CAT0002": other})
        self.assertEqual(len(logs.output), 4)
        self.assertNotIn("NOT-A-SYS-ID", "\n".join(logs.output))

    def test_missing_or_empty_configuration(self):
        from app.servicenow import catalog_sys_ids_from_env

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SERVICENOW_CATALOG_SYS_IDS", None)
            self.assertEqual(catalog_sys_ids_from_env(), {})
        self._env("")
        self.assertEqual(catalog_sys_ids_from_env(), {})

    def test_fixture_applies_only_valid_overrides(self):
        repo = LocalCatalogRepository.from_fixture(
            {"CAT0001": CONFIGURED_SYS_ID, "CAT0002": "bad", "CAT9999": CONFIGURED_SYS_ID})
        self.assertEqual(repo.get_item_by_ref("CAT0001").sys_id, CONFIGURED_SYS_ID)
        self.assertEqual(repo.get_item_by_ref("CAT0001").name, "Microsoft Visio")
        # Invalid override ignored: the item keeps its placeholder, still listed.
        self.assertEqual(repo.get_item_by_ref("CAT0002").sys_id,
                         LocalCatalogRepository.from_fixture().get_item_by_ref("CAT0002").sys_id)
        self.assertEqual(LocalCatalogRepository.from_fixture().get_item_by_ref("CAT0001").sys_id,
                         VISIO_SYS_ID)

    async def test_configured_sys_id_is_sent_but_never_shown(self):
        self._env(f"CAT0001={CONFIGURED_SYS_ID}")
        replies = [await self._send("I need Microsoft Visio")]
        for answer in VISIO_TURNS:
            replies.append(await self._send(answer))
        replies.append(await self._send("yes"))
        self.client.create_service_request.assert_awaited_once()
        self.assertEqual(self.client.create_service_request.await_args.kwargs["sys_id"],
                         CONFIGURED_SYS_ID)
        self.assertIn("REQ0012345", replies[-1])
        for reply in replies:
            self.assertNotIn(CONFIGURED_SYS_ID, reply)
            self.assertNotIn(VISIO_SYS_ID, reply)

    async def test_invalid_configuration_fails_safely(self):
        from app.servicenow import ServiceNowNotFound

        self._env("CAT0001=not-a-real-sys-id")
        self.client.create_service_request.side_effect = ServiceNowNotFound("404")
        await self._ready()
        reply = await self._send("yes")
        # The invalid value is never used: the placeholder is sent, ServiceNow
        # rejects it, and the user gets the controlled "no change" reply.
        self.assertEqual(self.client.create_service_request.await_args.kwargs["sys_id"],
                         VISIO_SYS_ID)
        self.assertTrue(reply.startswith("❌"))
        self.assertIn("No change was made", reply)
        for leaked in ("not-a-real-sys-id", VISIO_SYS_ID, "404", "REQ"):
            self.assertNotIn(leaked, reply)
        await self._send("yes")
        self.client.create_service_request.assert_awaited_once()


class TestRequestUncertainOutcome(_HandlerHarness):

    def test_unknown_write_operation_never_raises(self):
        for category in ServiceNowErrorCategory:
            with self.subTest(category=category):
                message = failure_message(category, operation="escalate",
                                          possibly_applied=True)
                self.assertIn("couldn't confirm whether the change was made", message)
                self.assertIn("may or may not have been applied", message)
                self.assertIn("check ServiceNow before trying again", message)
                self.assertIn("won't retry automatically", message)
                self.assertNotIn("incident", message)
                self.assertIsInstance(
                    failure_message(category, operation="escalate"), str)

    def test_create_request_message_unchanged(self):
        self.assertEqual(
            failure_message(ServiceNowErrorCategory.TIMEOUT, operation="create_request",
                            possibly_applied=True),
            "ServiceNow didn't respond in time. I couldn't confirm whether your service "
            "request was created — it may or may not exist. Please check your requests in "
            "ServiceNow before trying again. I won't retry automatically.")


    create_result = ServiceNowTimeout("timed out", possibly_applied=True)

    async def test_create_request_timeout_is_reported_as_unconfirmed(self):
        await self._ready()
        reply = await self._send("yes")
        self.assertTrue(reply.startswith("⚠️"))
        self.assertIn("didn't respond in time", reply)
        self.assertIn("couldn't confirm whether your service request was created", reply)
        self.assertIn("may or may not exist", reply)
        self.assertIn("check your requests in ServiceNow before trying again", reply)
        self.assertIn("won't retry automatically", reply)
        for wrong in ("incident", "the incident", "No change was made", "✅"):
            self.assertNotIn(wrong, reply)
        self.assertIs(get_session(KEY).phase, ConversationPhase.FAILED)
        await self._send("yes")  # a second "yes" must not retry the write
        self.client.create_service_request.assert_awaited_once()
        failed = self._audited(AuditEventType.REQUEST_CREATE_FAILED)
        self.assertEqual([k["reason"] for k in failed], ["servicenow_timeout_unconfirmed"])

    def test_incident_messages_unchanged(self):
        self.assertEqual(
            failure_message(ServiceNowErrorCategory.TIMEOUT, operation="create",
                            possibly_applied=True),
            "ServiceNow didn't respond in time. I couldn't confirm whether the incident was "
            "created. Please check your incidents in ServiceNow before trying again. I won't "
            "retry automatically.")
        self.assertEqual(
            failure_message(ServiceNowErrorCategory.TIMEOUT, operation="update",
                            possibly_applied=True, incident_number="INC0010002"),
            "ServiceNow didn't respond in time. I couldn't confirm whether incident INC0010002 "
            "was updated. Please check its status before trying again. I won't retry "
            "automatically.")


if __name__ == "__main__":
    unittest.main()
