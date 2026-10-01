"""
tests/test_request_status.py — Test suite for DEMO-07 Service Request Status Tracking.

Flows under test:
  1. Router: deterministic whole-message status queries for REQ / RITM numbers.
  2. ServiceNow Client: read-only GET requests against sc_request and sc_req_item.
  3. Tool Gateway: GET_REQUEST_STATUS and GET_RITM_STATUS actions, authorization gating, read-only.
  4. Main Handler: processing REQ/RITM status queries, formatting, auth denial, errors, audit logging.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.main as main  # noqa: E402
import app.request_status as request_status_module  # noqa: E402
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
    ConversationState,
    InMemoryStateRepository,
    StateKey,
    configure_state_repository,
    get_session,
)
from app.tools.servicenow import (  # noqa: E402
    GetRequestStatusToolRequest,
    GetRitmStatusToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    ToolAuthorizationError,
    ToolValidationError,
)

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "demo07-user-aad-oid"
STATE_KEY = StateKey(TENANT, USER)

EMPLOYEE = UserIdentity(
    user_id=USER,
    tenant_id=TENANT,
    display_name="Lucius Bagnoli",
    email="lucius@example.com",
    source=IdentitySource.AAD_OBJECT_ID,
)

REQ_RECORD = {
    "sys_id": "req_sys_id_12345",
    "number": "REQ0010005",
    "short_description": "Request for Microsoft Visio",
    "request_state": "in_process",
    "stage": "requested",
    "approval": "approved",
}

RITM_RECORD = {
    "sys_id": "ritm_sys_id_67890",
    "number": "RITM0010005",
    "request": {"display_value": "REQ0010005", "value": "req_sys_id_12345"},
    "short_description": "Microsoft Visio Standard",
    "state": "2",
    "stage": "fulfillment",
    "approval": "approved",
}

ENV_CREDS = {
    "SERVICENOW_INSTANCE": "https://example.service-now.com",
    "SERVICENOW_CLIENT_ID": "dummy_client_id",
    "SERVICENOW_CLIENT_SECRET": "dummy_client_secret",
    "TEAMS_TENANT_ID": TENANT,
}


def _context(text: str, tenant: str | None = TENANT):
    activity = SimpleNamespace(
        text=text,
        from_=SimpleNamespace(aad_object_id=USER, id=USER, name="Lucius Bagnoli"),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


class TestRouterRequestStatus(unittest.TestCase):
    """Router tests for REQ/RITM status lookup."""

    def test_req_positive_cases(self):
        cases = [
            ("REQ0010005", "REQ0010005"),
            ("what is the status of REQ0010005", "REQ0010005"),
            ("check REQ0010005", "REQ0010005"),
            ("status of REQ0010005", "REQ0010005"),
            ("REQ0010005 status", "REQ0010005"),
            ("status REQ0010005", "REQ0010005"),
            (" req0010005 ", "REQ0010005"),
            ("CHECK REQ0010005", "REQ0010005"),
        ]
        for query, expected_num in cases:
            with self.subTest(query=query):
                route = route_message(query)
                self.assertIsNotNone(route)
                self.assertEqual(route.intent, "request_status")
                self.assertEqual(route.request_number, expected_num)

    def test_ritm_positive_cases(self):
        cases = [
            ("RITM0010005", "RITM0010005"),
            ("what is the status of RITM0010005", "RITM0010005"),
            ("check RITM0010005", "RITM0010005"),
            ("status of RITM0010005", "RITM0010005"),
            ("RITM0010005 status", "RITM0010005"),
            ("status RITM0010005", "RITM0010005"),
            (" ritm0010005 ", "RITM0010005"),
            ("CHECK RITM0010005", "RITM0010005"),
        ]
        for query, expected_num in cases:
            with self.subTest(query=query):
                route = route_message(query)
                self.assertIsNotNone(route)
                self.assertEqual(route.intent, "ritm_status")
                self.assertEqual(route.request_number, expected_num)

    def test_malformed_req_ritm_numbers(self):
        cases = [
            "REQ123",  # Too short
            "RITM123",  # Too short
            "REQABCDEFGH",  # Non-digits
            "RITMABCDEFGH",  # Non-digits
        ]
        for query in cases:
            with self.subTest(query=query):
                route = route_message(query)
                self.assertIsNone(route)

    def test_extra_surrounding_text_no_route(self):
        cases = [
            "can you please check REQ0010005 and then create another ticket for me",
            "I ordered RITM0010005 yesterday but I also need Adobe Acrobat today",
        ]
        for query in cases:
            with self.subTest(query=query):
                route = route_message(query)
                self.assertIsNone(route)

    def test_inc_regression(self):
        cases = [
            ("INC0010002", "INC0010002"),
            ("what is the status of INC0010002", "INC0010002"),
            ("check INC0010002", "INC0010002"),
        ]
        for query, expected_num in cases:
            with self.subTest(query=query):
                route = route_message(query)
                self.assertIsNotNone(route)
                self.assertEqual(route.intent, "incident_status")
                self.assertEqual(route.incident_number, expected_num)


class TestServiceNowClientRequestStatus(unittest.IsolatedAsyncioTestCase):
    """ServiceNow client read-only methods for REQ/RITM."""

    async def test_get_request_status_success(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth_token" in str(request.url):
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
            if "sc_request" in str(request.url):
                return httpx.Response(200, json={"result": [REQ_RECORD]})
            return httpx.Response(404)

        with patch.dict(os.environ, ENV_CREDS):
            client = ServiceNowClient()
            client._transport = httpx.MockTransport(handler)
            result = await client.get_request_status("REQ0010005")
            self.assertEqual(result["number"], "REQ0010005")
            self.assertEqual(result["short_description"], "Request for Microsoft Visio")

    async def test_get_ritm_status_success(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth_token" in str(request.url):
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
            if "sc_req_item" in str(request.url):
                return httpx.Response(200, json={"result": [RITM_RECORD]})
            return httpx.Response(404)

        with patch.dict(os.environ, ENV_CREDS):
            client = ServiceNowClient()
            client._transport = httpx.MockTransport(handler)
            result = await client.get_ritm_status("RITM0010005")
            self.assertEqual(result["number"], "RITM0010005")
            self.assertEqual(result["short_description"], "Microsoft Visio Standard")

    async def test_request_not_found(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth_token" in str(request.url):
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
            return httpx.Response(200, json={"result": []})

        with patch.dict(os.environ, ENV_CREDS):
            client = ServiceNowClient()
            client._transport = httpx.MockTransport(handler)
            with self.assertRaises(ServiceNowNotFound):
                await client.get_request_status("REQ9999999")

    async def test_identifier_validation(self):
        with patch.dict(os.environ, ENV_CREDS):
            client = ServiceNowClient()
        with self.assertRaises(ValueError):
            await client.get_request_status("INVALID123")
        with self.assertRaises(ValueError):
            await client.get_ritm_status("INVALID456")


class TestToolGatewayRequestStatus(unittest.IsolatedAsyncioTestCase):
    """Tool gateway tests for request status lookups."""

    async def test_authorization_required(self):
        client = AsyncMock()
        gateway = ServiceNowToolGateway(client)

        req = GetRequestStatusToolRequest("REQ0010005")
        authz_denied = authorize(ANONYMOUS, AuthorizableAction.READ_REQUEST_STATUS)

        result = await gateway.execute(
            ANONYMOUS,
            authz_denied,
            ServiceNowToolAction.GET_REQUEST_STATUS,
            req,
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")

    async def test_successful_get_request_status(self):
        client = AsyncMock()
        client.get_request_status.return_value = REQ_RECORD
        gateway = ServiceNowToolGateway(client)

        req = GetRequestStatusToolRequest("REQ0010005")
        with patch.dict(os.environ, ENV_CREDS):
            authz = authorize(EMPLOYEE, AuthorizableAction.READ_REQUEST_STATUS)
            result = await gateway.execute(
                EMPLOYEE,
                authz,
                ServiceNowToolAction.GET_REQUEST_STATUS,
                req,
            )
        self.assertTrue(result.success)
        self.assertEqual(result.incident["number"], "REQ0010005")
        client.get_request_status.assert_called_once_with("REQ0010005")

    async def test_successful_get_ritm_status(self):
        client = AsyncMock()
        client.get_ritm_status.return_value = RITM_RECORD
        gateway = ServiceNowToolGateway(client)

        req = GetRitmStatusToolRequest("RITM0010005")
        with patch.dict(os.environ, ENV_CREDS):
            authz = authorize(EMPLOYEE, AuthorizableAction.READ_REQUEST_STATUS)
            result = await gateway.execute(
                EMPLOYEE,
                authz,
                ServiceNowToolAction.GET_RITM_STATUS,
                req,
            )
        self.assertTrue(result.success)
        self.assertEqual(result.incident["number"], "RITM0010005")
        client.get_ritm_status.assert_called_once_with("RITM0010005")

    async def test_read_only_enforcement(self):
        """Ensure GET actions do not trigger any POST, PATCH, or DELETE operations."""
        client = AsyncMock()
        client.get_request_status.return_value = REQ_RECORD
        gateway = ServiceNowToolGateway(client)

        req = GetRequestStatusToolRequest("REQ0010005")
        with patch.dict(os.environ, ENV_CREDS):
            authz = authorize(EMPLOYEE, AuthorizableAction.READ_REQUEST_STATUS)
            await gateway.execute(
                EMPLOYEE,
                authz,
                ServiceNowToolAction.GET_REQUEST_STATUS,
                req,
            )

        client.order_catalog_item.assert_not_called()
        client.create_incident.assert_not_called()
        client.update_incident.assert_not_called()


class TestMainRequestStatusHandler(unittest.IsolatedAsyncioTestCase):
    """Main application handler tests for REQ/RITM status."""

    def setUp(self):
        configure_state_repository(InMemoryStateRepository())

    async def test_successful_req_response(self):
        mock_client = AsyncMock()
        mock_client.get_request_status.return_value = REQ_RECORD
        gateway = ServiceNowToolGateway(mock_client)

        ctx = _context("what is the status of REQ0010005")

        with patch.dict(os.environ, ENV_CREDS), patch.object(
            main, "servicenow_gateway", gateway
        ):
            await main.on_message(ctx)

        ctx.send.assert_called_once()
        reply_text = ctx.send.call_args[0][0]
        self.assertIn("REQ0010005", reply_text)
        self.assertIn("Request for Microsoft Visio", reply_text)

    async def test_successful_ritm_response(self):
        mock_client = AsyncMock()
        mock_client.get_ritm_status.return_value = RITM_RECORD
        gateway = ServiceNowToolGateway(mock_client)

        ctx = _context("what is the status of RITM0010005")

        with patch.dict(os.environ, ENV_CREDS), patch.object(
            main, "servicenow_gateway", gateway
        ):
            await main.on_message(ctx)

        ctx.send.assert_called_once()
        reply_text = ctx.send.call_args[0][0]
        self.assertIn("RITM0010005", reply_text)
        self.assertIn("REQ0010005", reply_text)
        self.assertIn("Microsoft Visio Standard", reply_text)

    async def test_request_not_found(self):
        mock_client = AsyncMock()
        mock_client.get_request_status.side_effect = ServiceNowNotFound("Not found")
        gateway = ServiceNowToolGateway(mock_client)

        ctx = _context("status of REQ0019999")

        with patch.dict(os.environ, ENV_CREDS), patch.object(
            main, "servicenow_gateway", gateway
        ):
            await main.on_message(ctx)

        ctx.send.assert_called_once()
        reply_text = ctx.send.call_args[0][0]
        self.assertIn("req0019999", reply_text.lower())

    async def test_authorization_denial(self):
        ctx = _context("status of REQ0010005", tenant=OTHER_TENANT)

        with patch.dict(os.environ, ENV_CREDS):
            await main.on_message(ctx)

        ctx.send.assert_called_once()
        reply_text = ctx.send.call_args[0][0]
        self.assertIn("not authorised", reply_text.lower())


if __name__ == "__main__":
    unittest.main()
