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


if __name__ == "__main__":
    unittest.main()
