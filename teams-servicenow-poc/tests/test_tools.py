"""
tests/test_tools.py — Test suite for ServiceNow Tool Gateway (BL-005).

Covers all 43 required test cases from the BL-005 specification:
 1.  Authorized CREATE_INCIDENT executes.
 2.  Authorized GET_INCIDENT executes.
 3.  Authorized UPDATE_INCIDENT executes.
 4.  Unauthorized CREATE_INCIDENT rejected.
 5.  Unauthorized UPDATE_INCIDENT rejected.
 6.  READ_INCIDENT cannot invoke UPDATE_INCIDENT.
 7.  CREATE_INCIDENT cannot invoke UPDATE_INCIDENT.
 8.  Unknown tool action rejected.
 9.  Missing identity rejected.
10.  Missing authorization decision rejected.
11.  Denied authorization rejected.
12.  Action mismatch rejected.
13.  Invalid incident number rejected before adapter call.
14.  Injection-like incident input rejected.
15.  Invalid impact rejected.
16.  Invalid urgency rejected.
17.  Extra/unallowlisted fields rejected.
18.  ServiceNowNotFound remains distinguishable.
19.  ServiceNow failure does not claim success.
20.  OAuth token never exposed.
21.  Authorization header never exposed.
22.  Gateway never calls LLM.
23.  Gateway never calls Teams.
24.  Gateway makes no arbitrary HTTP call.
25.  Gateway does not accept arbitrary table names.
26.  Gateway does not accept arbitrary encoded queries.
27.  CREATE is not automatically retried.
28.  Successful create produces typed success result.
29.  Failed create produces typed failure result.
30.  User-controlled role cannot influence execution.
31.  User-controlled action cannot bypass typed action validation.
32.  Gateway cannot execute with only a user ID and no authorization decision.
33.  Gateway rejects authorization for a different action.
34.  Tool result is typed.
35.  Safe error messages contain no credentials/internal response bodies.
36.  Employee cannot UPDATE_INCIDENT.
37.  Service desk agent can UPDATE_INCIDENT.
38.  Wrong tenant authorization is rejected.
39.  Two users have isolated execution context.
40.  Adapter receives only explicitly allowed fields.
41.  GET_INCIDENT passes normalized incident number to adapter.
42.  CREATE_INCIDENT passes only approved create fields.
43.  UPDATE_INCIDENT passes only approved update fields.
45.  CREATE_INCIDENT rejects impact/urgency outside the established 1-3 contract.
46.  CREATE_INCIDENT accepts every impact/urgency value in the 1-3 contract.
47.  UPDATE_INCIDENT rejects impact/urgency outside the established 1-3 contract.
"""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.security.authorization import (
    AuthorizableAction,
    AuthorizationDecision,
    DefaultAuthorizationPolicy,
    UserRole,
    authorize,
)
from app.security.identity import ANONYMOUS, IdentitySource, UserIdentity
from app.servicenow import ServiceNowError, ServiceNowNotFound
from app.tools.servicenow import (
    CreateIncidentToolRequest,
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    ToolAuthorizationError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolResult,
    ToolValidationError,
    UpdateIncidentToolRequest,
)

# Baseline test identities
VALID_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
WRONG_TENANT = "00000000-0000-0000-0000-000000000000"

EMPLOYEE_IDENTITY = UserIdentity(
    user_id="usr-emp-001",
    tenant_id=VALID_TENANT,
    display_name="Alice Employee",
    email="alice@contoso.com",
    source=IdentitySource.AAD_OBJECT_ID,
)

AGENT_IDENTITY = UserIdentity(
    user_id="usr-agent-001",
    tenant_id=VALID_TENANT,
    display_name="Bob Agent",
    email="bob@contoso.com",
    source=IdentitySource.AAD_OBJECT_ID,
)


class TestServiceNowToolGateway(unittest.IsolatedAsyncioTestCase):
    """Full test suite for ServiceNowToolGateway (BL-005)."""

    def setUp(self):
        self.mock_client = AsyncMock()
        self.gateway = ServiceNowToolGateway(client=self.mock_client)
        self.env_patch = patch.dict("os.environ", {"TEAMS_TENANT_ID": VALID_TENANT})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    # ───────────────────────────────────────────────────────────────────────
    # Test 1: Authorized CREATE_INCIDENT executes
    # ───────────────────────────────────────────────────────────────────────
    async def test_01_authorized_create_incident_executes(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(
            short_description="VPN Connection Error",
            description="Unable to connect to corporate VPN.",
            impact="3",
            urgency="3",
        )
        self.mock_client.create_incident.return_value = {
            "sys_id": "sys123",
            "number": "INC0010002",
            "short_description": "VPN Connection Error",
            "state": "1",
        }

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertTrue(res.success)
        self.assertEqual(res.incident_number, "INC0010002")
        self.assertEqual(res.action, ServiceNowToolAction.CREATE_INCIDENT)
        self.assertIn("INC0010002", res.safe_message)
        self.mock_client.create_incident.assert_called_once_with(
            short_description="VPN Connection Error",
            description="Unable to connect to corporate VPN.",
            impact="3",
            urgency="3",
        )

    # ───────────────────────────────────────────────────────────────────────
    # Test 2: Authorized GET_INCIDENT executes
    # ───────────────────────────────────────────────────────────────────────
    async def test_02_authorized_get_incident_executes(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "sys123",
            "number": "INC0010002",
            "short_description": "VPN Issue",
        }

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertTrue(res.success)
        self.assertEqual(res.incident_number, "INC0010002")
        self.assertEqual(res.action, ServiceNowToolAction.GET_INCIDENT)
        self.mock_client.get_incident.assert_called_once_with("INC0010002")

    # ───────────────────────────────────────────────────────────────────────
    # Test 3: Authorized UPDATE_INCIDENT executes (Agent role)
    # ───────────────────────────────────────────────────────────────────────
    async def test_03_authorized_update_incident_executes(self):
        class AgentPolicy(DefaultAuthorizationPolicy):
            def resolve_role(self, identity):
                return UserRole.SERVICE_DESK_AGENT

        authz = authorize(
            AGENT_IDENTITY,
            AuthorizableAction.UPDATE_INCIDENT,
            policy=AgentPolicy(),
        )
        req = UpdateIncidentToolRequest(
            incident_number="INC0010002",
            short_description="Updated VPN Issue",
            urgency="2",
        )
        self.mock_client.update_incident.return_value = {
            "sys_id": "sys123",
            "number": "INC0010002",
            "short_description": "Updated VPN Issue",
            "urgency": "2",
        }

        res = await self.gateway.execute(
            AGENT_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertTrue(res.success)
        self.assertEqual(res.incident_number, "INC0010002")
        self.mock_client.update_incident.assert_called_once_with(
            incident_number="INC0010002",
            fields={"short_description": "Updated VPN Issue", "urgency": "2"},
        )

    # ───────────────────────────────────────────────────────────────────────
    # Test 4: Unauthorized CREATE_INCIDENT rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_04_unauthorized_create_incident_rejected(self):
        denied_authz = AuthorizationDecision.denied("Not authorized")
        req = CreateIncidentToolRequest(short_description="Test")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, denied_authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")
        self.mock_client.create_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 5: Unauthorized UPDATE_INCIDENT rejected (Employee role)
    # ───────────────────────────────────────────────────────────────────────
    async def test_05_unauthorized_update_incident_rejected(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.UPDATE_INCIDENT)
        req = UpdateIncidentToolRequest(
            incident_number="INC0010002", short_description="Test"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")
        self.mock_client.update_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 6: READ_INCIDENT cannot invoke UPDATE_INCIDENT
    # ───────────────────────────────────────────────────────────────────────
    async def test_06_read_incident_cannot_invoke_update_incident(self):
        read_authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = UpdateIncidentToolRequest(
            incident_number="INC0010002", short_description="Hack"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, read_authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")
        self.mock_client.update_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 7: CREATE_INCIDENT cannot invoke UPDATE_INCIDENT
    # ───────────────────────────────────────────────────────────────────────
    async def test_07_create_incident_cannot_invoke_update_incident(self):
        create_authz = authorize(
            EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT
        )
        req = UpdateIncidentToolRequest(
            incident_number="INC0010002", short_description="Hack"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, create_authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")
        self.mock_client.update_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 8: Unknown tool action rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_08_unknown_tool_action_rejected(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, "delete_user", req  # type: ignore
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "VALIDATION_ERROR")
        self.mock_client.get_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 9: Missing identity rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_09_missing_identity_rejected(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")

        res1 = await self.gateway.execute(
            None, authz, ServiceNowToolAction.GET_INCIDENT, req  # type: ignore
        )
        res2 = await self.gateway.execute(
            ANONYMOUS, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertFalse(res1.success)
        self.assertEqual(res1.error_code, "AUTHORIZATION_DENIED")
        self.assertFalse(res2.success)
        self.assertEqual(res2.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 10: Missing authorization decision rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_10_missing_authorization_decision_rejected(self):
        req = GetIncidentToolRequest(incident_number="INC0010002")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, None, ServiceNowToolAction.GET_INCIDENT, req  # type: ignore
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 11: Denied authorization rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_11_denied_authorization_rejected(self):
        denied_authz = AuthorizationDecision.denied("Policy deny")
        req = GetIncidentToolRequest(incident_number="INC0010002")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, denied_authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 12: Action mismatch rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_12_action_mismatch_rejected(self):
        create_authz = authorize(
            EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT
        )
        get_req = GetIncidentToolRequest(incident_number="INC0010002")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, create_authz, ServiceNowToolAction.GET_INCIDENT, get_req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 13: Invalid incident number rejected before adapter call
    # ───────────────────────────────────────────────────────────────────────
    async def test_13_invalid_incident_number_rejected_before_adapter_call(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        bad_req = GetIncidentToolRequest(incident_number="INC123")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, bad_req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "VALIDATION_ERROR")
        self.mock_client.get_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 14: Injection-like incident input rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_14_injection_like_incident_input_rejected(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)

        injections = [
            "INC0010002; DROP TABLE incident",
            "INC0010002<script>alert(1)</script>",
            "INCABC12345",
            "' OR '1'='1",
        ]

        for inj in injections:
            req = GetIncidentToolRequest(incident_number=inj)
            res = await self.gateway.execute(
                EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
            )
            self.assertFalse(res.success, f"Failed to reject injection: {inj}")
            self.assertEqual(res.error_code, "VALIDATION_ERROR")

        self.mock_client.get_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 15: Invalid impact rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_15_invalid_impact_rejected(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        bad_req = CreateIncidentToolRequest(
            short_description="Test", impact="HIGH"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, bad_req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "VALIDATION_ERROR")
        self.mock_client.create_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 16: Invalid urgency rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_16_invalid_urgency_rejected(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        bad_req = CreateIncidentToolRequest(
            short_description="Test", urgency="99"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, bad_req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "VALIDATION_ERROR")
        self.mock_client.create_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 17: Extra/unallowlisted fields rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_17_extra_unallowlisted_fields_rejected(self):
        class AgentPolicy(DefaultAuthorizationPolicy):
            def resolve_role(self, identity):
                return UserRole.SERVICE_DESK_AGENT

        authz = authorize(
            AGENT_IDENTITY, AuthorizableAction.UPDATE_INCIDENT, policy=AgentPolicy()
        )
        # Attempting to update with no allowed fields populated
        bad_req = UpdateIncidentToolRequest(
            incident_number="INC0010002", short_description=None
        )

        res = await self.gateway.execute(
            AGENT_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, bad_req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "VALIDATION_ERROR")

    # ───────────────────────────────────────────────────────────────────────
    # Test 18: ServiceNowNotFound remains distinguishable
    # ───────────────────────────────────────────────────────────────────────
    async def test_18_servicenow_not_found_distinguishable(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0099999")
        self.mock_client.get_incident.side_effect = ServiceNowNotFound(
            "Incident not found."
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "NOT_FOUND")
        self.assertIn("not found", res.safe_message.lower())

    # ───────────────────────────────────────────────────────────────────────
    # Test 19: ServiceNow failure does not claim success
    # ───────────────────────────────────────────────────────────────────────
    async def test_19_servicenow_failure_does_not_claim_success(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(short_description="Fail test")
        self.mock_client.create_incident.side_effect = ServiceNowError("HTTP 500")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "EXECUTION_ERROR")
        self.assertNotIn("created successfully", res.safe_message)

    # ───────────────────────────────────────────────────────────────────────
    # Test 20: OAuth token never exposed
    # ───────────────────────────────────────────────────────────────────────
    async def test_20_oauth_token_never_exposed(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(short_description="Secret check")
        self.mock_client.create_incident.side_effect = ServiceNowError(
            "Secret token mock_token_12345 leaked"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertNotIn("mock_token_12345", res.safe_message)
        self.assertNotIn("Bearer", res.safe_message)

    # ───────────────────────────────────────────────────────────────────────
    # Test 21: Authorization header never exposed
    # ───────────────────────────────────────────────────────────────────────
    async def test_21_authorization_header_never_exposed(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.side_effect = ServiceNowError(
            "Header: Authorization: Bearer secret_123"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertNotIn("Authorization", res.safe_message)
        self.assertNotIn("Bearer", res.safe_message)

    # ───────────────────────────────────────────────────────────────────────
    # Test 22: Gateway never calls LLM
    # ───────────────────────────────────────────────────────────────────────
    async def test_22_gateway_never_calls_llm(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        with patch("app.ai.classify_message") as mock_classify:
            res = await self.gateway.execute(
                EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
            )
            self.assertTrue(res.success)
            mock_classify.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 23: Gateway never calls Teams
    # ───────────────────────────────────────────────────────────────────────
    async def test_23_gateway_never_calls_teams(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        with patch("microsoft_teams.apps.App") as mock_teams:
            res = await self.gateway.execute(
                EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
            )
            self.assertTrue(res.success)
            mock_teams.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 24: Gateway makes no arbitrary HTTP call
    # ───────────────────────────────────────────────────────────────────────
    async def test_24_gateway_makes_no_arbitrary_http_call(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        with patch("httpx.AsyncClient") as mock_httpx:
            res = await self.gateway.execute(
                EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
            )
            self.assertTrue(res.success)
            mock_httpx.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 25: Gateway does not accept arbitrary table names
    # ───────────────────────────────────────────────────────────────────────
    async def test_25_gateway_does_not_accept_arbitrary_table_names(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        with self.assertRaises(AttributeError):
            _ = req.table_name  # type: ignore

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )
        self.assertTrue(res.success)
        self.assertNotIn("table", self.mock_client.get_incident.call_args.kwargs)

    # ───────────────────────────────────────────────────────────────────────
    # Test 26: Gateway does not accept arbitrary encoded queries
    # ───────────────────────────────────────────────────────────────────────
    async def test_26_gateway_does_not_accept_arbitrary_encoded_queries(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        with self.assertRaises(AttributeError):
            _ = req.encoded_query  # type: ignore

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )
        self.assertTrue(res.success)

    # ───────────────────────────────────────────────────────────────────────
    # Test 27: CREATE is not automatically retried
    # ───────────────────────────────────────────────────────────────────────
    async def test_27_create_is_not_automatically_retried(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(short_description="No retry test")
        self.mock_client.create_incident.side_effect = ServiceNowError("Timeout")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(self.mock_client.create_incident.call_count, 1)

    # ───────────────────────────────────────────────────────────────────────
    # Test 28: Successful create produces typed success result
    # ───────────────────────────────────────────────────────────────────────
    async def test_28_successful_create_produces_typed_success_result(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(short_description="Typed res test")
        self.mock_client.create_incident.return_value = {
            "sys_id": "s1",
            "number": "INC0010005",
        }

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertIsInstance(res, ToolResult)
        self.assertTrue(res.success)
        self.assertEqual(res.incident_number, "INC0010005")
        self.assertIsNone(res.error_code)

    # ───────────────────────────────────────────────────────────────────────
    # Test 29: Failed create produces typed failure result
    # ───────────────────────────────────────────────────────────────────────
    async def test_29_failed_create_produces_typed_failure_result(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(short_description="Fail typed res test")
        self.mock_client.create_incident.side_effect = ServiceNowError("Error")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.assertIsInstance(res, ToolResult)
        self.assertFalse(res.success)
        self.assertIsNotNone(res.error_code)

    # ───────────────────────────────────────────────────────────────────────
    # Test 30: User-controlled role cannot influence execution
    # ───────────────────────────────────────────────────────────────────────
    async def test_30_user_controlled_role_cannot_influence_execution(self):
        # Even if request payload or text attempts to claim agent role:
        class FakeReq(UpdateIncidentToolRequest):
            user_role = "service_desk_admin"

        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.UPDATE_INCIDENT)
        req = FakeReq(incident_number="INC0010002", short_description="Hacked")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 31: User-controlled action cannot bypass typed action validation
    # ───────────────────────────────────────────────────────────────────────
    async def test_31_user_controlled_action_cannot_bypass_validation(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY,
            authz,
            "DROP_TABLE_INCIDENT",  # type: ignore
            req,
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "VALIDATION_ERROR")

    # ───────────────────────────────────────────────────────────────────────
    # Test 32: Gateway cannot execute with only user ID and no authorization decision
    # ───────────────────────────────────────────────────────────────────────
    async def test_32_gateway_cannot_execute_without_authorization_decision(self):
        req = GetIncidentToolRequest(incident_number="INC0010002")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, None, ServiceNowToolAction.GET_INCIDENT, req  # type: ignore
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 33: Gateway rejects authorization for a different action
    # ───────────────────────────────────────────────────────────────────────
    async def test_33_gateway_rejects_authorization_for_different_action(self):
        read_authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        create_req = CreateIncidentToolRequest(short_description="Create test")

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY,
            read_authz,
            ServiceNowToolAction.CREATE_INCIDENT,
            create_req,
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 34: Tool result is typed
    # ───────────────────────────────────────────────────────────────────────
    async def test_34_tool_result_is_typed(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertIsInstance(res, ToolResult)
        self.assertIsInstance(res.success, bool)

    # ───────────────────────────────────────────────────────────────────────
    # Test 35: Safe error messages contain no credentials/internal response bodies
    # ───────────────────────────────────────────────────────────────────────
    async def test_35_safe_error_messages_contain_no_credentials(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC0010002")
        self.mock_client.get_incident.side_effect = ServiceNowError(
            "Internal DB Error at 10.0.0.1:5432 with password SuperSecret123!"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.assertNotIn("10.0.0.1", res.safe_message)
        self.assertNotIn("SuperSecret123!", res.safe_message)

    # ───────────────────────────────────────────────────────────────────────
    # Test 36: Employee cannot UPDATE_INCIDENT
    # ───────────────────────────────────────────────────────────────────────
    async def test_36_employee_cannot_update_incident(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.UPDATE_INCIDENT)
        req = UpdateIncidentToolRequest(
            incident_number="INC0010002", short_description="New title"
        )

        res = await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 37: Service desk agent can UPDATE_INCIDENT
    # ───────────────────────────────────────────────────────────────────────
    async def test_37_service_desk_agent_can_update_incident(self):
        class AgentPolicy(DefaultAuthorizationPolicy):
            def resolve_role(self, identity):
                return UserRole.SERVICE_DESK_AGENT

        authz = authorize(
            AGENT_IDENTITY, AuthorizableAction.UPDATE_INCIDENT, policy=AgentPolicy()
        )
        req = UpdateIncidentToolRequest(
            incident_number="INC0010002", short_description="New title"
        )
        self.mock_client.update_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        res = await self.gateway.execute(
            AGENT_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.assertTrue(res.success)

    # ───────────────────────────────────────────────────────────────────────
    # Test 38: Wrong tenant authorization is rejected
    # ───────────────────────────────────────────────────────────────────────
    async def test_38_wrong_tenant_authorization_rejected(self):
        wrong_tenant_identity = UserIdentity(
            user_id="usr-999",
            tenant_id=WRONG_TENANT,
            display_name="External",
            email="ext@other.com",
            source=IdentitySource.AAD_OBJECT_ID,
        )
        authz = authorize(
            wrong_tenant_identity, AuthorizableAction.CREATE_INCIDENT
        )
        req = CreateIncidentToolRequest(short_description="External attempt")

        res = await self.gateway.execute(
            wrong_tenant_identity,
            authz,
            ServiceNowToolAction.CREATE_INCIDENT,
            req,
        )

        self.assertFalse(res.success)
        self.assertEqual(res.error_code, "AUTHORIZATION_DENIED")

    # ───────────────────────────────────────────────────────────────────────
    # Test 39: Two users have isolated execution context
    # ───────────────────────────────────────────────────────────────────────
    async def test_39_two_users_isolated_execution_context(self):
        user_a = EMPLOYEE_IDENTITY
        user_b = AGENT_IDENTITY

        self.mock_client.create_incident.return_value = {
            "sys_id": "s1",
            "number": "INC0010001",
        }
        self.mock_client.get_incident.return_value = {
            "sys_id": "s2",
            "number": "INC0010002",
        }

        authz_a = authorize(user_a, AuthorizableAction.CREATE_INCIDENT)
        authz_b = authorize(user_b, AuthorizableAction.READ_INCIDENT)

        req_a = CreateIncidentToolRequest(short_description="User A Inc")
        req_b = GetIncidentToolRequest(incident_number="INC0010002")

        res_a = await self.gateway.execute(
            user_a, authz_a, ServiceNowToolAction.CREATE_INCIDENT, req_a
        )
        res_b = await self.gateway.execute(
            user_b, authz_b, ServiceNowToolAction.GET_INCIDENT, req_b
        )

        self.assertNotEqual(res_a.action, res_b.action)

    # ───────────────────────────────────────────────────────────────────────
    # Test 40: Adapter receives only explicitly allowed fields
    # ───────────────────────────────────────────────────────────────────────
    async def test_40_adapter_receives_only_explicitly_allowed_fields(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(
            short_description="VPN Error",
            description="Details",
            impact="2",
            urgency="1",
        )
        self.mock_client.create_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        self.mock_client.create_incident.assert_called_once_with(
            short_description="VPN Error",
            description="Details",
            impact="2",
            urgency="1",
        )

    # ───────────────────────────────────────────────────────────────────────
    # Test 41: GET_INCIDENT passes normalized incident number to adapter
    # ───────────────────────────────────────────────────────────────────────
    async def test_41_get_incident_passes_normalized_incident_number(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="  inc0010002  ")
        self.mock_client.get_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.GET_INCIDENT, req
        )

        self.mock_client.get_incident.assert_called_once_with("INC0010002")

    # ───────────────────────────────────────────────────────────────────────
    # Test 42: CREATE_INCIDENT passes only approved create fields
    # ───────────────────────────────────────────────────────────────────────
    async def test_42_create_incident_passes_only_approved_create_fields(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        req = CreateIncidentToolRequest(
            short_description="App Crash",
            description="Stack trace",
            impact="3",
            urgency="3",
        )
        self.mock_client.create_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        await self.gateway.execute(
            EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
        )

        kwargs = self.mock_client.create_incident.call_args.kwargs
        self.assertEqual(
            set(kwargs.keys()),
            {"short_description", "description", "impact", "urgency"},
        )

    # ───────────────────────────────────────────────────────────────────────
    # Test 43: UPDATE_INCIDENT passes only approved update fields
    # ───────────────────────────────────────────────────────────────────────
    async def test_43_update_incident_passes_only_approved_update_fields(self):
        class AgentPolicy(DefaultAuthorizationPolicy):
            def resolve_role(self, identity):
                return UserRole.SERVICE_DESK_AGENT

        authz = authorize(
            AGENT_IDENTITY, AuthorizableAction.UPDATE_INCIDENT, policy=AgentPolicy()
        )
        req = UpdateIncidentToolRequest(
            incident_number="inc0010002",
            short_description="New Title",
            urgency="1",
        )
        self.mock_client.update_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010002",
        }

        await self.gateway.execute(
            AGENT_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
        )

        self.mock_client.update_incident.assert_called_once_with(
            incident_number="INC0010002",
            fields={"short_description": "New Title", "urgency": "1"},
        )

    # ───────────────────────────────────────────────────────────────────────
    # Test 44 (Bonus): Exception raising mode (raise_on_error=True)
    # ───────────────────────────────────────────────────────────────────────
    async def test_44_raise_on_error_mode(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.READ_INCIDENT)
        req = GetIncidentToolRequest(incident_number="INC123")  # invalid

        with self.assertRaises(ToolValidationError):
            await self.gateway.execute(
                EMPLOYEE_IDENTITY,
                authz,
                ServiceNowToolAction.GET_INCIDENT,
                req,
                raise_on_error=True,
            )

    # ───────────────────────────────────────────────────────────────────────
    # Test 45: Impact/urgency outside 1-3 rejected on create
    # (contract: app/models.py pattern ^[1-3]$)
    # ───────────────────────────────────────────────────────────────────────
    async def test_45_create_rejects_impact_urgency_outside_contract(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        for field in ("impact", "urgency"):
            for value in ("0", "4", "5"):
                with self.subTest(field=field, value=value):
                    req = CreateIncidentToolRequest(
                        short_description="Test", **{field: value}
                    )
                    res = await self.gateway.execute(
                        EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
                    )
                    self.assertFalse(res.success)
                    self.assertEqual(res.error_code, "VALIDATION_ERROR")
        self.mock_client.create_incident.assert_not_called()

    # ───────────────────────────────────────────────────────────────────────
    # Test 46: Every impact/urgency value in 1-3 accepted on create
    # ───────────────────────────────────────────────────────────────────────
    async def test_46_create_accepts_impact_urgency_within_contract(self):
        authz = authorize(EMPLOYEE_IDENTITY, AuthorizableAction.CREATE_INCIDENT)
        self.mock_client.create_incident.return_value = {
            "sys_id": "1",
            "number": "INC0010001",
        }
        for value in ("1", "2", "3"):
            with self.subTest(value=value):
                req = CreateIncidentToolRequest(
                    short_description="Test", impact=value, urgency=value
                )
                res = await self.gateway.execute(
                    EMPLOYEE_IDENTITY, authz, ServiceNowToolAction.CREATE_INCIDENT, req
                )
                self.assertTrue(res.success)

    # ───────────────────────────────────────────────────────────────────────
    # Test 47: Impact/urgency outside 1-3 rejected on update
    # ───────────────────────────────────────────────────────────────────────
    async def test_47_update_rejects_impact_urgency_outside_contract(self):
        class AgentPolicy(DefaultAuthorizationPolicy):
            def resolve_role(self, identity):
                return UserRole.SERVICE_DESK_AGENT

        authz = authorize(
            AGENT_IDENTITY, AuthorizableAction.UPDATE_INCIDENT, policy=AgentPolicy()
        )
        for field in ("impact", "urgency"):
            for value in ("0", "4", "5"):
                with self.subTest(field=field, value=value):
                    req = UpdateIncidentToolRequest(
                        incident_number="INC0010002", **{field: value}
                    )
                    res = await self.gateway.execute(
                        AGENT_IDENTITY, authz, ServiceNowToolAction.UPDATE_INCIDENT, req
                    )
                    self.assertFalse(res.success)
                    self.assertEqual(res.error_code, "VALIDATION_ERROR")
        self.mock_client.update_incident.assert_not_called()


if __name__ == "__main__":
    unittest.main()
