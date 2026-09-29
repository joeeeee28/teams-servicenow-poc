"""
tests/test_servicenow_resilience.py — Test suite for DEMO-02 ServiceNow Resilience.

Three layers:
  * the real ``ServiceNowClient`` over an ``httpx.MockTransport`` (no network),
    proving every transport failure is classified, never retried and never
    leaks tokens, URLs or bodies;
  * the ``ServiceNowToolGateway`` mapping categories to typed tool results;
  * ``app.main.on_message`` end to end (real BL-003 confirmation, BL-004
    authorization, BL-005 gateway, BL-010 audit, BL-011 observability).

Requirement coverage:
 1.  Connection failure, timeout, auth failure, 403, 404, 400, 429,
     500/502/503/504, malformed response, unknown gateway exception.
 2.  Typed safe categories and fixed user messages.
 3.  No token / credential / header / body / URL / stack-trace exposure.
 4.  No false success; failed create/update → FAILED.
 5.  No automatic retry of create, update or read.
 6.  Timeout (or other unconfirmed failure) after a sent write is reported as
     "could not be confirmed", never as "not created" / "no change".
 7.  Status lookup failures leave conversation state untouched.
 8.  Persistence failures stay distinguishable from ServiceNow failures.
 9.  Audit / observability record the category without sensitive content.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.main as main  # noqa: E402
import app.observability as obs  # noqa: E402
from app.audit import AuditEventType, AuditLogger  # noqa: E402
from app.incident_collection import start_incident_collection  # noqa: E402
from app.incident_update import parse_update_command, start_update_collection  # noqa: E402
from app.security.authorization import (  # noqa: E402
    AuthorizableAction,
    DefaultAuthorizationPolicy,
    UserRole,
    authorize,
)
from app.security.identity import IdentitySource, UserIdentity  # noqa: E402
from app.servicenow import (  # noqa: E402
    ServiceNowAuthError,
    ServiceNowClient,
    ServiceNowError,
    ServiceNowForbidden,
    ServiceNowInvalidResponse,
    ServiceNowNotFound,
    ServiceNowRateLimited,
    ServiceNowRejected,
    ServiceNowServerError,
    ServiceNowTimeout,
    ServiceNowUnavailable,
)
from app.servicenow_errors import (  # noqa: E402
    ServiceNowErrorCategory as C,
    failure_message,
)
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    StateKey,
    StatePersistenceError,
    configure_state_repository,
    get_session,
    get_state_repository,
    save_session,
)
from app.tools.servicenow import (  # noqa: E402
    CreateIncidentToolRequest,
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    UpdateIncidentToolRequest,
)

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
USER = "demo02-user-aad-oid"
CONV = "19:demo02-conversation@thread.v2"
KEY = StateKey(TENANT, USER, CONV)

INSTANCE = "https://demo02-secret-instance.example.invalid"
CLIENT_ID = "DEMO02-CLIENT-ID-MARKER"
CLIENT_SECRET = "DEMO02-CLIENT-SECRET-MARKER"
TOKEN = "DEMO02-ACCESS-TOKEN-MARKER"
BODY_MARKER = "DEMO02-RESPONSE-BODY-MARKER"
SYS_ID = "46d44a5dc0a8010e00f3c1a3b0bbf1e4"
RECORD = {"sys_id": SYS_ID, "number": "INC0010002", "short_description": "VPN unavailable",
          "state": "2", "impact": "3", "urgency": "3", "priority": "5"}
FULL_MESSAGE = ("VPN is down for me and I can't access internal applications. "
                "Impact is 2 and urgency is 1.")

SECRETS = (TOKEN, CLIENT_ID, CLIENT_SECRET, "Bearer", "Authorization", BODY_MARKER,
           "demo02-secret-instance", "example.invalid", "https://", "Traceback",
           "oauth_token.do", "/api/now")

EMPLOYEE = UserIdentity(user_id=USER, tenant_id=TENANT, display_name=None, email=None,
                        source=IdentitySource.AAD_OBJECT_ID)


class AgentPolicy(DefaultAuthorizationPolicy):
    def resolve_role(self, identity):
        role = super().resolve_role(identity)
        return UserRole.SERVICE_DESK_AGENT if role is UserRole.EMPLOYEE else role


def agent_authorize(identity, action):
    return authorize(identity, action, policy=AgentPolicy())


# ===========================================================================
# Transport harness
# ===========================================================================

class FakeServiceNow:
    """httpx handler: an OAuth endpoint plus a scripted Table API."""

    def __init__(self):
        self.token_calls = 0
        self.api_calls: list[tuple[str, str]] = []
        self.token_response = lambda req: httpx.Response(
            200, json={"access_token": TOKEN, "expires_in": 1800})
        self.get_response = lambda req: httpx.Response(200, json={"result": [dict(RECORD)]})
        self.write_response = lambda req: httpx.Response(
            200, json={"result": dict(RECORD, number="INC0012345")})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth_token.do"):
            self.token_calls += 1
            return self.token_response(request)
        self.api_calls.append((request.method, request.url.path))
        if request.method == "GET":
            return self.get_response(request)
        return self.write_response(request)

    def writes(self):
        return [c for c in self.api_calls if c[0] in ("POST", "PATCH")]


def _client(fake: FakeServiceNow) -> ServiceNowClient:
    with patch.dict(os.environ, {"SERVICENOW_INSTANCE": INSTANCE,
                                 "SERVICENOW_CLIENT_ID": CLIENT_ID,
                                 "SERVICENOW_CLIENT_SECRET": CLIENT_SECRET}):
        client = ServiceNowClient()
    client._transport = httpx.MockTransport(fake)
    return client


def _raise(exc_type):
    def handler(request):
        raise exc_type("simulated " + BODY_MARKER, request=request)
    return handler


def _status(code, body=None):
    return lambda req: httpx.Response(
        code, json=body if body is not None else {"error": {"message": BODY_MARKER,
                                                           "detail": TOKEN}})


def _text(code, text):
    return lambda req: httpx.Response(code, text=text)


# (label, handler, expected exception class, possibly_applied when it hits a sent write)
TRANSPORT_CASES = [
    ("connect_error", _raise(httpx.ConnectError), ServiceNowUnavailable, False),
    ("connect_timeout", _raise(httpx.ConnectTimeout), ServiceNowUnavailable, False),
    ("pool_timeout", _raise(httpx.PoolTimeout), ServiceNowUnavailable, False),
    ("read_timeout", _raise(httpx.ReadTimeout), ServiceNowTimeout, True),
    ("write_timeout", _raise(httpx.WriteTimeout), ServiceNowTimeout, True),
    ("connection_dropped", _raise(httpx.RemoteProtocolError), ServiceNowUnavailable, True),
    ("read_error", _raise(httpx.ReadError), ServiceNowUnavailable, True),
    ("http_400", _status(400), ServiceNowRejected, False),
    ("http_401", _status(401), ServiceNowAuthError, False),
    ("http_403", _status(403), ServiceNowForbidden, False),
    ("http_404", _status(404), ServiceNowNotFound, False),
    ("http_409", _status(409), ServiceNowRejected, False),
    ("http_429", _status(429), ServiceNowRateLimited, False),
    ("http_500", _status(500), ServiceNowServerError, True),
    ("http_502", _status(502), ServiceNowServerError, True),
    ("http_503", _status(503), ServiceNowUnavailable, False),
    ("http_504", _status(504), ServiceNowServerError, True),
    ("not_json", _text(200, f"<html>{BODY_MARKER}</html>"), ServiceNowInvalidResponse, True),
    ("json_array", _status(200, [BODY_MARKER]), ServiceNowInvalidResponse, True),
]


def _assert_no_leak(test, *texts):
    blob = "\n".join(str(t) for t in texts)
    for secret in SECRETS:
        test.assertNotIn(secret, blob)


# ===========================================================================
# 1: Transport classification
# ===========================================================================

class TestTransportClassification(unittest.IsolatedAsyncioTestCase):

    async def _run(self, op, handler, *, target="write"):
        fake = FakeServiceNow()
        if target == "get" or op == "get":
            fake.get_response = handler
        else:
            fake.write_response = handler
        client = _client(fake)
        if op == "get":
            call = client.get_incident("INC0010002")
        elif op == "create":
            call = client.create_incident("VPN down", "details", "2", "1")
        else:
            call = client.update_incident("INC0010002", {"impact": "1"})
        with self.assertRaises(ServiceNowError) as ctx:
            await call
        return ctx.exception, fake

    async def test_every_failure_on_create(self):
        for label, handler, cls, applied in TRANSPORT_CASES:
            with self.subTest(case=label):
                exc, fake = await self._run("create", handler)
                self.assertIsInstance(exc, cls)
                self.assertIs(exc.category, cls.category)
                self.assertEqual(exc.possibly_applied, applied)
                self.assertEqual(len(fake.writes()), 1, "create must never be retried")
                self.assertIsNone(exc.__cause__)
                _assert_no_leak(self, exc, repr(exc))

    async def test_every_failure_on_update_write(self):
        for label, handler, cls, applied in TRANSPORT_CASES:
            with self.subTest(case=label):
                exc, fake = await self._run("update", handler)
                self.assertIsInstance(exc, cls)
                self.assertEqual(exc.possibly_applied, applied)
                self.assertEqual(fake.writes(), [("PATCH", f"/api/now/table/incident/{SYS_ID}")])
                _assert_no_leak(self, exc, repr(exc))

    async def test_every_failure_on_read_is_never_possibly_applied(self):
        for label, handler, cls, _ in TRANSPORT_CASES:
            if label == "http_404":
                continue  # a 404 lookup is covered by test_read_404
            with self.subTest(case=label):
                exc, fake = await self._run("get", handler)
                self.assertIsInstance(exc, cls)
                self.assertFalse(exc.possibly_applied)
                self.assertEqual(len(fake.api_calls), 1, "reads are not retried either")
                _assert_no_leak(self, exc, repr(exc))

    async def test_read_404(self):
        exc, _ = await self._run("get", _status(404))
        self.assertIsInstance(exc, ServiceNowNotFound)

    async def test_update_lookup_failure_never_sends_the_write(self):
        for label, handler, cls, _ in TRANSPORT_CASES:
            with self.subTest(case=label):
                exc, fake = await self._run("update", handler, target="get")
                self.assertIsInstance(exc, cls)
                self.assertFalse(exc.possibly_applied)
                self.assertEqual(fake.writes(), [])

    async def test_malformed_results(self):
        cases = {
            "create_result_not_object": ("create", _status(200, {"result": "x"}), True),
            "create_missing_result": ("create", _status(200, {"nothing": 1}), True),
            "get_result_not_list": ("get", _status(200, {"result": {"number": "x"}}), False),
            "get_record_not_object": ("get", _status(200, {"result": ["x"]}), False),
        }
        for label, (op, handler, applied) in cases.items():
            with self.subTest(case=label):
                exc, _ = await self._run(op, handler)
                self.assertIsInstance(exc, ServiceNowInvalidResponse)
                self.assertEqual(exc.possibly_applied, applied)

    async def test_invalid_sys_id_blocks_the_write(self):
        for bad in ("../../sys_user", "", None, "46d44a5d/../x", "A" * 32):
            with self.subTest(sys_id=bad):
                handler = _status(200, {"result": [dict(RECORD, sys_id=bad)]})
                exc, fake = await self._run("update", handler, target="get")
                self.assertIsInstance(exc, ServiceNowInvalidResponse)
                self.assertFalse(exc.possibly_applied)
                self.assertEqual(fake.writes(), [])

    async def test_empty_lookup_is_not_found(self):
        exc, _ = await self._run("get", _status(200, {"result": []}))
        self.assertIsInstance(exc, ServiceNowNotFound)

    async def test_success_paths_unchanged(self):
        fake = FakeServiceNow()
        client = _client(fake)
        self.assertEqual((await client.get_incident("inc0010002"))["number"], "INC0010002")
        self.assertEqual((await client.create_incident("VPN", "d"))["number"], "INC0012345")
        self.assertEqual((await client.update_incident("INC0010002", {"impact": "1"}))["number"],
                         "INC0012345")
        self.assertEqual(fake.token_calls, 1)  # token cached across calls


class TestOAuthFailures(unittest.IsolatedAsyncioTestCase):

    async def _create_with_token(self, handler):
        fake = FakeServiceNow()
        fake.token_response = handler
        client = _client(fake)
        with self.assertRaises(ServiceNowError) as ctx:
            await client.create_incident("VPN", "d")
        self.assertEqual(fake.writes(), [], "no business request without a token")
        self.assertFalse(ctx.exception.possibly_applied)
        _assert_no_leak(self, ctx.exception, repr(ctx.exception))
        return ctx.exception

    async def test_rejected_credentials(self):
        for code in (400, 401, 403):
            with self.subTest(code=code):
                self.assertIsInstance(await self._create_with_token(_status(code)),
                                      ServiceNowAuthError)

    async def test_token_endpoint_unreachable(self):
        self.assertIsInstance(await self._create_with_token(_raise(httpx.ConnectError)),
                              ServiceNowUnavailable)

    async def test_token_endpoint_timeout(self):
        exc = await self._create_with_token(_raise(httpx.ReadTimeout))
        self.assertIsInstance(exc, ServiceNowTimeout)

    async def test_token_endpoint_rate_limited_or_down(self):
        self.assertIsInstance(await self._create_with_token(_status(429)), ServiceNowRateLimited)
        self.assertIsInstance(await self._create_with_token(_status(500)), ServiceNowServerError)

    async def test_malformed_token_responses(self):
        for label, handler in {
            "not_json": _text(200, "<html>"),
            "not_object": _status(200, [TOKEN]),
            "no_token": _status(200, {"expires_in": 60}),
            "token_not_string": _status(200, {"access_token": 123}),
        }.items():
            with self.subTest(case=label):
                self.assertIsInstance(await self._create_with_token(handler), ServiceNowAuthError)

    async def test_bad_expires_in_falls_back(self):
        fake = FakeServiceNow()
        fake.token_response = _status(200, {"access_token": TOKEN, "expires_in": "soon"})
        await _client(fake).get_incident("INC0010002")

    async def test_401_invalidates_token_without_retrying(self):
        fake = FakeServiceNow()
        fake.get_response = _status(401)
        client = _client(fake)
        with self.assertRaises(ServiceNowAuthError):
            await client.get_incident("INC0010002")
        self.assertEqual((fake.token_calls, len(fake.api_calls)), (1, 1))
        fake.get_response = lambda req: httpx.Response(200, json={"result": [dict(RECORD)]})
        await client.get_incident("INC0010002")
        self.assertEqual(fake.token_calls, 2, "a fresh token is fetched next time")

    async def test_httpx_request_urls_never_logged(self):
        import logging

        httpx_logger = logging.getLogger("httpx")
        previous = httpx_logger.level
        self.addCleanup(httpx_logger.setLevel, previous)
        httpx_logger.setLevel(logging.INFO)  # what the Teams SDK does to it
        fake = FakeServiceNow()
        with self.assertLogs(level="DEBUG") as logs:
            logging.getLogger("demo02.marker").warning("marker")
            await _client(fake).get_incident("INC0010002")
        _assert_no_leak(self, "\n".join(logs.output))
        self.assertEqual(len(fake.api_calls), 1)

    async def test_token_never_sent_to_logs(self):
        fake = FakeServiceNow()
        fake.write_response = _raise(httpx.ReadTimeout)
        client = _client(fake)
        with self.assertLogs("app.servicenow", level="WARNING") as logs, \
                self.assertRaises(ServiceNowTimeout):
            await client.create_incident("VPN", "d")
        _assert_no_leak(self, "\n".join(logs.output))


# ===========================================================================
# 2: Gateway mapping
# ===========================================================================

GATEWAY_CASES = [
    (ServiceNowUnavailable, False), (ServiceNowUnavailable, True),
    (ServiceNowTimeout, False), (ServiceNowTimeout, True),
    (ServiceNowAuthError, False), (ServiceNowForbidden, False),
    (ServiceNowRejected, False), (ServiceNowRateLimited, False),
    (ServiceNowServerError, False), (ServiceNowServerError, True),
    (ServiceNowInvalidResponse, False), (ServiceNowInvalidResponse, True),
]


class TestGatewayMapping(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.client = AsyncMock()
        self.gateway = ServiceNowToolGateway(client=self.client, audit_logger=MagicMock())
        env = patch.dict(os.environ, {"TEAMS_TENANT_ID": TENANT})
        env.start()
        self.addCleanup(env.stop)

    async def _execute(self, action, request):
        authz = agent_authorize(EMPLOYEE, {
            ServiceNowToolAction.GET_INCIDENT: AuthorizableAction.READ_INCIDENT,
            ServiceNowToolAction.CREATE_INCIDENT: AuthorizableAction.CREATE_INCIDENT,
            ServiceNowToolAction.UPDATE_INCIDENT: AuthorizableAction.UPDATE_INCIDENT,
        }[action])
        return await self.gateway.execute(EMPLOYEE, authz, action, request)

    async def test_create(self):
        for cls, applied in GATEWAY_CASES:
            with self.subTest(cls=cls.__name__, applied=applied):
                self.client.create_incident.reset_mock()
                self.client.create_incident.side_effect = cls(
                    f"{TOKEN} {INSTANCE}", possibly_applied=applied)
                res = await self._execute(ServiceNowToolAction.CREATE_INCIDENT,
                                          CreateIncidentToolRequest(short_description="VPN"))
                self.assertFalse(res.success)
                self.assertIsNone(res.incident_number)
                self.assertEqual(res.error_code, cls.category.value)
                self.assertEqual(res.outcome_unknown, applied)
                self.assertEqual(res.safe_message, failure_message(
                    cls.category, operation="create", possibly_applied=applied))
                self.client.create_incident.assert_awaited_once()
                _assert_no_leak(self, res.safe_message)

    async def test_update(self):
        for cls, applied in GATEWAY_CASES:
            with self.subTest(cls=cls.__name__, applied=applied):
                self.client.update_incident.reset_mock()
                self.client.update_incident.side_effect = cls("x", possibly_applied=applied)
                res = await self._execute(ServiceNowToolAction.UPDATE_INCIDENT,
                                          UpdateIncidentToolRequest("INC0010002", impact="1"))
                self.assertFalse(res.success)
                self.assertEqual(res.error_code, cls.category.value)
                self.assertEqual(res.outcome_unknown, applied)
                self.client.update_incident.assert_awaited_once()

    async def test_read_is_never_outcome_unknown(self):
        for cls, applied in GATEWAY_CASES:
            with self.subTest(cls=cls.__name__, applied=applied):
                self.client.get_incident.side_effect = cls("x", possibly_applied=applied)
                res = await self._execute(ServiceNowToolAction.GET_INCIDENT,
                                          GetIncidentToolRequest("INC0010002"))
                self.assertFalse(res.success)
                self.assertFalse(res.outcome_unknown)
                if cls is not ServiceNowRateLimited:  # deliberately generic message
                    self.assertIn("INC0010002", res.safe_message)

    async def test_unclassified_error_keeps_legacy_contract(self):
        self.client.create_incident.side_effect = ServiceNowError(f"HTTP 500 {TOKEN}")
        res = await self._execute(ServiceNowToolAction.CREATE_INCIDENT,
                                  CreateIncidentToolRequest(short_description="VPN"))
        self.assertEqual(res.error_code, "EXECUTION_ERROR")
        self.assertFalse(res.outcome_unknown)
        self.assertEqual(res.safe_message, "Failed to create incident in ServiceNow.")

    async def test_unexpected_exception_is_safe(self):
        self.client.get_incident.side_effect = RuntimeError(f"password {TOKEN}")
        res = await self._execute(ServiceNowToolAction.GET_INCIDENT,
                                  GetIncidentToolRequest("INC0010002"))
        self.assertEqual(res.error_code, "EXECUTION_ERROR")
        _assert_no_leak(self, res.safe_message)

    async def test_raise_on_error_raises_typed_error(self):
        from app.tools.servicenow import ToolServiceNowError

        self.client.create_incident.side_effect = ServiceNowTimeout("x", possibly_applied=True)
        authz = agent_authorize(EMPLOYEE, AuthorizableAction.CREATE_INCIDENT)
        with self.assertRaises(ToolServiceNowError) as ctx:
            await self.gateway.execute(EMPLOYEE, authz, ServiceNowToolAction.CREATE_INCIDENT,
                                       CreateIncidentToolRequest(short_description="VPN"),
                                       raise_on_error=True)
        self.assertTrue(ctx.exception.outcome_unknown)
        self.assertEqual(ctx.exception.error_code, "SERVICENOW_TIMEOUT")

    def test_every_message_is_fixed_and_safe(self):
        for category in C:
            for op in ("read", "create", "update"):
                for applied in (False, True):
                    msg = failure_message(category, operation=op, possibly_applied=applied,
                                          incident_number="INC0010002")
                    self.assertTrue(msg)
                    self.assertLess(len(msg), 300)
                    if op != "read" and applied:
                        self.assertIn("couldn't confirm", msg)
                        self.assertNotIn("No change was made", msg)
                    elif op != "read":
                        self.assertIn("No change was made", msg)
                    for claim in ("successfully", "✅"):
                        self.assertNotIn(claim, msg)

    def test_404_without_record_is_not_reported_as_missing_incident(self):
        msg = failure_message(C.NOT_FOUND, operation="create")
        self.assertNotIn("find incident", msg)
        self.assertIn("No change was made", msg)


# ===========================================================================
# 3: Handler integration
# ===========================================================================

class CaptureAudit(AuditLogger):
    def __init__(self):
        super().__init__()
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def of(self, event_type):
        return [e for e in self.events if e.event_type is event_type]


class CaptureObs(obs.ObservabilityLogger):
    def __init__(self):
        super().__init__()
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def failed_tools(self):
        return [e for e in self.events if e.event_name is obs.ObsEventName.TOOL_FAILED]


def _context(text):
    activity = SimpleNamespace(
        id="1712345678901", text=text,
        from_=SimpleNamespace(aad_object_id=USER, id=USER, name="Demo User"),
        channel_data={"tenant": {"id": TENANT}},
        conversation=SimpleNamespace(id=CONV),
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


def _ready_create():
    state = ConversationState()
    start_incident_collection(state, FULL_MESSAGE)
    state.correlation_id = "op-create-1"
    return state


def _ready_update():
    state = ConversationState()
    start_update_collection(state, parse_update_command("Update INC0010002 impact to 1"),
                            {"short_description": "VPN unavailable", "impact": "3", "urgency": "3"})
    state.correlation_id = "op-update-1"
    return state


class _Integration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        previous = get_state_repository()
        self.repo = InMemoryStateRepository()
        configure_state_repository(self.repo)
        self.addCleanup(configure_state_repository, previous)
        self.fake = FakeServiceNow()
        self.client = _client(self.fake)
        self.audit = CaptureAudit()
        self.obs = CaptureObs()
        self.gateway = ServiceNowToolGateway(client=self.client, audit_logger=self.audit)
        self.classify = AsyncMock(return_value={
            "intent": "general", "summary": "x", "needs_service_now": False})
        patches = [
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "classify_message", self.classify),
            patch.object(main, "authorize", MagicMock(side_effect=agent_authorize)),
            patch.object(main, "audit_logger", self.audit),
            patch.object(obs, "observability", self.obs),
            patch.dict(os.environ, {"TEAMS_TENANT_ID": TENANT}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    async def _send(self, text):
        ctx = _context(text)
        with self.assertLogs(level="DEBUG") as logs:
            await main.on_message(ctx)
        self.logs = "\n".join(logs.output)
        return ctx.send.await_args.args[0]

    def _all_output(self, reply):
        return "\n".join([reply, self.logs,
                          *(e.to_json() for e in self.audit.events),
                          *(e.to_json() for e in self.obs.events)])


class TestCreateResilience(_Integration):

    async def _confirm_with(self, handler):
        self.fake.write_response = handler
        save_session(KEY, _ready_create())
        return await self._send("yes")

    async def test_each_failure_is_safe_failed_and_not_retried(self):
        for label, handler, cls, applied in TRANSPORT_CASES:
            with self.subTest(case=label):
                self.fake.api_calls.clear()
                self.audit.events.clear()
                self.obs.events.clear()
                reply = await self._confirm_with(handler)
                state = get_session(KEY)
                self.assertIs(state.phase, ConversationPhase.FAILED)
                self.assertIsNone(state.incident_number)
                self.assertEqual(len(self.fake.writes()), 1)
                for claim in ("✅", "successfully", "has been created"):
                    self.assertNotIn(claim, reply)
                if applied:
                    self.assertIn("couldn't confirm whether the incident was created", reply)
                    self.assertNotIn("No change was made", reply)
                    self.assertTrue(reply.startswith("⚠️"))
                else:
                    self.assertTrue(reply.startswith("❌"))
                    if cls is not ServiceNowNotFound:
                        self.assertIn("No change was made", reply)
                reason = cls.category.value.lower() + ("_unconfirmed" if applied else "")
                failed = self.audit.of(AuditEventType.INCIDENT_CREATE_FAILED)
                self.assertEqual([e.reason for e in failed], [reason])
                self.assertEqual(self.audit.of(AuditEventType.INCIDENT_CREATE_COMPLETED), [])
                self.assertEqual([e.error_code for e in self.obs.failed_tools()], [reason])
                _assert_no_leak(self, self._all_output(reply))

    async def test_repeated_yes_after_failure_never_retries(self):
        await self._confirm_with(_raise(httpx.ReadTimeout))
        self.fake.write_response = lambda req: httpx.Response(
            200, json={"result": dict(RECORD, number="INC0099999")})
        for _ in range(3):
            reply = await self._send("yes")
            self.assertNotIn("INC0099999", reply)
        self.assertEqual(len(self.fake.writes()), 1)
        self.assertIs(get_session(KEY).phase, ConversationPhase.FAILED)

    async def test_timeout_reply_matches_requirement(self):
        reply = await self._confirm_with(_raise(httpx.ReadTimeout))
        self.assertIn("didn't respond in time", reply)
        self.assertIn("check", reply)
        self.assertIn("won't retry automatically", reply)

    async def test_unavailable_reply_matches_requirement(self):
        reply = await self._confirm_with(_raise(httpx.ConnectError))
        self.assertIn("I couldn't reach ServiceNow right now. No change was made. "
                      "Please try again.", reply)

    async def test_rate_limit_and_auth_replies(self):
        self.assertIn("rate-limiting", await self._confirm_with(_status(429)))
        self.assertIn("temporarily unavailable", await self._confirm_with(_status(401)))

    async def test_success_still_reported_only_on_success(self):
        reply = await self._confirm_with(self.fake.write_response)
        self.assertIn("INC0012345", reply)
        self.assertIs(get_session(KEY).phase, ConversationPhase.COMPLETED)

    async def test_persistence_failure_is_distinct_from_servicenow_failure(self):
        class FailOnFailed(InMemoryStateRepository):
            def save(self, key, state):
                if state.phase is ConversationPhase.FAILED:
                    raise StatePersistenceError("save")
                super().save(key, state)

        repo = FailOnFailed()
        configure_state_repository(repo)
        repo._store[KEY] = _ready_create()
        self.fake.write_response = _raise(httpx.ConnectError)
        reply = await self._send("yes")
        self.assertEqual(reply, main._STATE_NOT_SAVED)
        self.assertNotIn("reach ServiceNow", reply)
        failed = self.audit.of(AuditEventType.INCIDENT_CREATE_FAILED)
        self.assertEqual([e.reason for e in failed], ["servicenow_unavailable"])


class TestUpdateResilience(_Integration):

    async def test_each_write_failure_is_safe_failed_and_not_retried(self):
        for label, handler, cls, applied in TRANSPORT_CASES:
            with self.subTest(case=label):
                self.fake.api_calls.clear()
                self.audit.events.clear()
                self.fake.write_response = handler
                save_session(KEY, _ready_update())
                reply = await self._send("yes")
                self.assertIs(get_session(KEY).phase, ConversationPhase.FAILED)
                self.assertEqual(len(self.fake.writes()), 1)
                self.assertNotIn("✅", reply)
                self.assertNotIn("ServiceNow confirmed", reply)
                if applied:
                    self.assertIn("couldn't confirm whether incident INC0010002 was updated", reply)
                    self.assertNotIn("No change was made", reply)
                reason = cls.category.value.lower() + ("_unconfirmed" if applied else "")
                if cls is ServiceNowNotFound:
                    reason = "not_found"
                failed = self.audit.of(AuditEventType.INCIDENT_UPDATE_FAILED)
                self.assertEqual([e.reason for e in failed], [reason])
                _assert_no_leak(self, self._all_output(reply))

    async def test_lookup_failure_before_write_says_no_change_was_attempted(self):
        self.fake.get_response = _raise(httpx.ConnectError)
        save_session(KEY, _ready_update())
        reply = await self._send("yes")
        self.assertIn("No change was made", reply)
        self.assertEqual(self.fake.writes(), [])

    async def test_current_value_read_failure_is_controlled(self):
        self.fake.get_response = _status(429)
        reply = await self._send("Update INC0010002 impact to 1")
        self.assertIn("rate-limiting", reply)
        self.assertIs(get_session(KEY).phase, ConversationPhase.IDLE)
        self.assertEqual(self.fake.writes(), [])


class TestStatusResilience(_Integration):

    async def test_each_failure_is_safe_and_leaves_state_untouched(self):
        completed = ConversationState(phase=ConversationPhase.COMPLETED,
                                      incident_number="INC0012345", correlation_id="op-9")
        for label, handler, cls, _ in TRANSPORT_CASES:
            with self.subTest(case=label):
                self.fake.api_calls.clear()
                self.audit.events.clear()
                self.fake.get_response = handler
                save_session(KEY, completed)
                reply = await self._send("INC0010002")
                self.assertEqual(len(self.fake.api_calls), 1)
                state = get_session(KEY)
                self.assertIs(state.phase, ConversationPhase.COMPLETED)
                self.assertEqual(state.incident_number, "INC0012345")
                self.assertNotIn("📋", reply)
                if cls is ServiceNowNotFound:
                    self.assertEqual(reply, "I couldn't find incident INC0010002.")
                elif cls is not ServiceNowRateLimited:
                    self.assertIn("INC0010002", reply)
                failed = self.audit.of(AuditEventType.INCIDENT_READ_FAILED)
                self.assertEqual([e.reason for e in failed], [cls.category.value.lower()])
                _assert_no_leak(self, self._all_output(reply))

    async def test_status_replies(self):
        for handler, expected in (
            (_raise(httpx.ConnectError), "couldn't reach ServiceNow"),
            (_raise(httpx.ReadTimeout), "didn't respond in time"),
            (_status(401), "temporarily unavailable"),
            (_status(503), "couldn't reach ServiceNow"),
            (_status(500), "having problems"),
            (_text(200, "<html>"), "unexpected response"),
        ):
            with self.subTest(expected=expected):
                self.fake.get_response = handler
                self.assertIn(expected, await self._send("INC0010002"))


class TestAuditAndObservabilitySafety(_Integration):

    async def test_audit_reasons_are_valid_codes(self):
        for label, handler, cls, applied in TRANSPORT_CASES:
            with self.subTest(case=label):
                self.audit.events.clear()
                self.fake.write_response = handler
                save_session(KEY, _ready_create())
                await self._send("yes")
                for event in self.audit.events:
                    data = json.loads(event.to_json())
                    self.assertLessEqual(set(data), {
                        "timestamp", "event_type", "outcome", "correlation_id", "action",
                        "request_id", "user_id", "tenant_id", "conversation_ref",
                        "incident_number", "tool", "reason"})

    async def test_last_error_is_the_fixed_message(self):
        self.fake.write_response = _raise(httpx.ReadTimeout)
        save_session(KEY, _ready_create())
        await self._send("yes")
        last_error = get_session(KEY).last_error
        self.assertEqual(last_error, failure_message(C.TIMEOUT, operation="create",
                                                     possibly_applied=True))
        _assert_no_leak(self, last_error)


if __name__ == "__main__":
    unittest.main()
