"""
tests/test_audit.py — Test suite for BL-010 Audit Logging.

Audit logging is observation only: these tests prove that the expected
structured events are emitted at the security boundaries, that they carry no
secrets / message content / payloads, that they are ordered correctly relative
to ServiceNow execution, and that an audit failure can never grant access,
execute a tool, or turn a failure into a success.

Only the ServiceNow client beneath the real gateway and the LLM classifier are
mocked.  No real ServiceNow call is possible.

Sections:
  Model 1-7, Privacy 8-16, Authorization 17-22, Confirmation 23-27,
  Execution 28-34, Ordering 35-39, Regression 40-44, Audit failure,
  Correlation.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

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

import app.main as main  # noqa: E402
from app.ai import SYSTEM_PROMPT  # noqa: E402
from app.audit import (  # noqa: E402
    AUDIT_LOGGER_NAME,
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditOutcome,
    DEFAULT_OUTCOME,
    conversation_ref,
    safe_incident_number,
    safe_ref,
)
from app.incident_collection import start_incident_collection  # noqa: E402
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
    clear_session,
    get_session,
    save_session,
)
from app.tools.servicenow import (  # noqa: E402
    CreateIncidentToolRequest,
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    UpdateIncidentToolRequest,
)

E = AuditEventType
TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "00000000-0000-0000-0000-000000000000"
USER = "11111111-2222-3333-4444-555555555555"

# Secret / sensitive markers that must never appear in an audit record.
PASSWORD = "ABC123-PASSWORD"
OAUTH_TOKEN = "OAUTH-TOKEN-XYZ987"
API_KEY = "APIKEY-SECRET-456"
BOT_TOKEN = "TEAMS-BOT-TOKEN-789"
AUTH_HEADER = "Authorization: Bearer " + OAUTH_TOKEN
LLM_SUMMARY = "LLM-SUMMARY-MARKER"
SN_BODY = "SN-RESPONSE-BODY-MARKER"
DISPLAY_NAME = "Alice Displayname"
EMAIL = "alice.private@contoso.com"

RECORD = {
    "sys_id": "46d44a5dc0a8010e00f3c1a3b0bbf1e4",
    "number": "INC0010002",
    "short_description": f"VPN unavailable {SN_BODY}",
    "description": f"secret body {SN_BODY}",
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


class CaptureAudit(AuditLogger):
    """Collects events (and the JSON actually emitted) in order."""

    def __init__(self, timeline=None, fail=False):
        super().__init__(logging.getLogger("test.audit.capture"))
        self.events: list[AuditEvent] = []
        self.timeline = timeline if timeline is not None else []
        self.fail = fail

    def emit(self, event):
        if self.fail:
            raise RuntimeError("audit sink unavailable")
        self.events.append(event)
        self.timeline.append(("audit", event.event_type))

    def types(self):
        return [e.event_type for e in self.events]

    def of(self, event_type):
        return [e for e in self.events if e.event_type is event_type]

    def blob(self):
        return "\n".join(e.to_json() + repr(e) for e in self.events)


def _context(text, *, tenant=TENANT, activity_id="1712345678901", conversation="19:conv-abc"):
    activity = SimpleNamespace(
        id=activity_id,
        text=text,
        token=BOT_TOKEN,
        headers={"Authorization": AUTH_HEADER},
        from_=SimpleNamespace(aad_object_id=USER, id=USER, name=DISPLAY_NAME, email=EMAIL),
        conversation=SimpleNamespace(id=conversation),
        channel_data={"tenant": {"id": tenant}} if tenant else {},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


def _event(**overrides):
    fields = dict(
        event_type=E.INCIDENT_READ_REQUESTED,
        outcome=AuditOutcome.REQUESTED,
        correlation_id="corr-1",
        action=AuthorizableAction.READ_INCIDENT,
        user_id=USER,
        tenant_id=TENANT,
        incident_number="INC0010002",
    )
    fields.update(overrides)
    return AuditEvent(**fields)


# ===========================================================================
# 1–7: Audit model
# ===========================================================================

class TestAuditModel(unittest.TestCase):

    def test_01_valid_event(self):
        event = _event()
        self.assertIs(event.event_type, E.INCIDENT_READ_REQUESTED)
        self.assertIs(event.outcome, AuditOutcome.REQUESTED)

    def test_02_invalid_event_type_rejected(self):
        for bad in ("incident_read_requested", "delete_everything", None, 1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _event(event_type=bad)

    def test_03_invalid_outcome_rejected(self):
        for bad in ("requested", "hacked", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _event(outcome=bad)
        with self.assertRaises(ValueError):  # outcome inconsistent with type
            _event(outcome=AuditOutcome.SUCCEEDED)

    def test_04_required_and_identifier_fields_validated(self):
        with self.assertRaises(ValueError):
            _event(correlation_id=None)
        for field, bad in (
            ("correlation_id", "has spaces"), ("user_id", "Alice Displayname"),
            ("user_id", EMAIL + " x"), ("tenant_id", "t e n a n t"),
            ("incident_number", "INC001"), ("incident_number", "INC0010002; DROP"),
            ("incident_number", "INC" + "٠" * 7), ("reason", "Free text reason"),
            ("reason", "my password is " + PASSWORD), ("tool", "sys_user"),
            ("action", "read_incident"), ("conversation_ref", "19:conv-abc"),
        ):
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                _event(**{field: bad})

    def test_05_serialization_is_structured(self):
        data = json.loads(_event(tool="get_incident", reason="not_found").to_json())
        self.assertEqual(data["event_type"], "incident_read_requested")
        self.assertEqual(data["action"], "read_incident")
        self.assertEqual(data["tool"], "get_incident")
        self.assertEqual(set(data) - {
            "timestamp", "event_type", "outcome", "correlation_id", "action",
            "request_id", "user_id", "tenant_id", "conversation_ref",
            "incident_number", "tool", "reason",
        }, set())
        self.assertNotIn("request_id", data)  # absent optionals omitted
        self.assertTrue(repr(_event()).startswith("AuditEvent({"))

    def test_06_timestamp_present(self):
        ts = _event().to_dict()["timestamp"]
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_07_correlation_id_present(self):
        self.assertEqual(_event().to_dict()["correlation_id"], "corr-1")
        event = AuditLogger(logging.getLogger("test.x")).record(
            E.INCIDENT_READ_REQUESTED, correlation_id=None)
        self.assertTrue(event.correlation_id)

    def test_every_event_type_has_a_default_outcome(self):
        for event_type in E:
            with self.subTest(event_type=event_type):
                AuditEvent(event_type, DEFAULT_OUTCOME[event_type], "c")

    def test_record_never_raises(self):
        sink = MagicMock()
        sink.info.side_effect = RuntimeError("disk full")
        with self.assertLogs("app.audit_errors", level="WARNING") as errors:
            self.assertIsNone(AuditLogger(sink).record(
                E.INCIDENT_READ_REQUESTED, correlation_id="c"))
            self.assertIsNone(AuditLogger(MagicMock()).record(
                E.INCIDENT_READ_REQUESTED, correlation_id="c", reason="Free text!"))
        self.assertEqual(len(errors.records), 2)
        self.assertNotIn("Free text", "\n".join(errors.output))

    def test_audit_channel_carries_only_json(self):
        sink = MagicMock()
        sink.info.side_effect = RuntimeError("disk full")
        with self.assertLogs(AUDIT_LOGGER_NAME, level="DEBUG") as audit_channel:
            AuditLogger().record(E.INCIDENT_READ_REQUESTED, correlation_id="ok-1")
            AuditLogger(sink).record(E.INCIDENT_READ_REQUESTED, correlation_id="c")
        for line in audit_channel.records:
            json.loads(line.getMessage())  # every record is a JSON event

    def test_emitted_on_dedicated_logger_as_json(self):
        with self.assertLogs(AUDIT_LOGGER_NAME, level="INFO") as logs:
            AuditLogger().record(E.INCIDENT_READ_REQUESTED, correlation_id="c-1")
        self.assertEqual(json.loads(logs.records[0].getMessage())["correlation_id"], "c-1")
        self.assertEqual(logs.records[0].audit["event_type"], "incident_read_requested")

    def test_helpers(self):
        self.assertIsNone(safe_ref("has space"))
        self.assertEqual(safe_ref(USER), USER)
        self.assertEqual(safe_incident_number(" inc0010002 "), "INC0010002")
        self.assertIsNone(safe_incident_number("INC" + "٠" * 7))
        self.assertRegex(conversation_ref("19:conv-abc"), r"^[0-9a-f]{16}$")
        self.assertNotIn("conv-abc", conversation_ref("19:conv-abc"))


# ===========================================================================
# Integration harness
# ===========================================================================

class _Base(unittest.IsolatedAsyncioTestCase):

    authorize_fn = staticmethod(agent_authorize)
    audit_fails = False

    async def asyncSetUp(self):
        clear_session(USER)
        self.addCleanup(clear_session, USER)
        self.timeline = []
        self.audit = CaptureAudit(self.timeline, fail=self.audit_fails)

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
        self.gateway = ServiceNowToolGateway(client=self.client, audit_logger=self.audit)
        self.classify = AsyncMock(return_value={
            "intent": "create_incident", "summary": LLM_SUMMARY, "needs_service_now": True,
        })
        self.authorize = MagicMock(side_effect=self.authorize_fn)
        patches = [
            patch.object(main, "servicenow_gateway", self.gateway),
            patch.object(main, "audit_logger", self.audit),
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
        return ctx.send.await_args.args[0]

    def _ready_create(self, description="VPN is down for me"):
        state = ConversationState()
        start_incident_collection(
            state, f"{description}. Impact is 2 and urgency is 1.")
        state.correlation_id = "op-create-1"
        save_session(USER, state)

    def _assert_clean(self, extra=()):
        blob = self.audit.blob()
        for marker in (PASSWORD, OAUTH_TOKEN, API_KEY, BOT_TOKEN, AUTH_HEADER,
                       "Bearer", "Authorization", LLM_SUMMARY, SN_BODY,
                       SYSTEM_PROMPT[:40].strip(), DISPLAY_NAME, EMAIL, "password",
                       RECORD["sys_id"], "work_notes", "internal work note", *extra):
            self.assertNotIn(marker, blob)


# ===========================================================================
# 8–16: Privacy / security
# ===========================================================================

class TestPrivacy(_Base):

    async def test_08_to_16_no_sensitive_data_in_any_audit_record(self):
        message = (f"Create an incident with description: my password is {PASSWORD} "
                   f"key {API_KEY} token {OAUTH_TOKEN}")
        with self.assertLogs(AUDIT_LOGGER_NAME, level="INFO") as real:
            main.audit_logger = AuditLogger()  # also check the real emitted text
            await self._send(message)
        self.assertTrue(real.output)
        for marker in (PASSWORD, API_KEY, OAUTH_TOKEN, "my password", LLM_SUMMARY,
                       DISPLAY_NAME, EMAIL, BOT_TOKEN):
            self.assertNotIn(marker, "\n".join(real.output))

    async def test_08_full_user_message_and_16_description_not_logged(self):
        await self._send(f"Create an incident with description: my password is {PASSWORD}")
        await self._send("impact 2")
        await self._send("urgency 1")
        self.assertIn(E.CONFIRMATION_REQUESTED, self.audit.types())
        await self._send("yes")
        self.assertIn(E.INCIDENT_CREATE_COMPLETED, self.audit.types())
        self._assert_clean(extra=("Create an incident", "description:", "impact 2"))

    async def test_09_10_llm_prompt_and_response_not_logged(self):
        await self._send("I need to report an issue")
        self.classify.assert_awaited()
        self._assert_clean()

    async def test_11_13_oauth_token_and_authorization_header_not_logged(self):
        self.client.get_incident.side_effect = ServiceNowError(f"HTTP 401 {AUTH_HEADER}")
        await self._send("INC0010002")
        self.assertEqual(self.audit.of(E.INCIDENT_READ_FAILED)[0].reason, "execution_error")
        self._assert_clean()

    async def test_12_api_key_not_logged(self):
        await self._send(f"status of INC0010002 {API_KEY}")
        self._assert_clean()

    async def test_14_servicenow_response_body_not_logged(self):
        await self._send("INC0010002")
        self.assertIn(E.INCIDENT_READ_COMPLETED, self.audit.types())
        self._assert_clean()

    async def test_15_password_like_content_not_logged(self):
        self._ready_create(description=f"my password is {PASSWORD}")
        await self._send("yes")
        self._assert_clean()

    async def test_09b_real_llm_prompt_and_completion_not_logged(self):
        """Uses the REAL classify_message; only the Ollama network call is stubbed."""
        import app.ai as ai

        completion = "LLM-COMPLETION-SECRET-4242"
        seen = {}

        async def fake_chat(model, messages, format):
            seen["system"] = messages[0]["content"]
            return SimpleNamespace(message=SimpleNamespace(
                content=json.dumps({"intent": "create_incident", "summary": completion})))

        with patch.object(main, "classify_message", ai.classify_message), \
             patch.object(ai._ollama, "chat", side_effect=fake_chat):
            await self._send("I need to report an issue")
        self.assertEqual(seen["system"], SYSTEM_PROMPT)  # the real prompt was used
        self.assertIn(E.INCIDENT_CREATE_REQUESTED, self.audit.types())
        blob = self.audit.blob()
        prompt_lines = [l.strip() for l in SYSTEM_PROMPT.splitlines() if len(l.strip()) >= 12]
        self.assertGreater(len(prompt_lines), 20)
        for line in prompt_lines:
            self.assertNotIn(line, blob)
        self.assertNotIn(completion, blob)

    async def test_16b_update_description_value_not_logged(self):
        secret = "UPDATE-DESCRIPTION-SECRET my password is hunter2"
        await self._send(f"Update INC0010002 description to {secret}")
        await self._send("yes")
        self.assertEqual(
            self.client.update_incident.await_args.kwargs["fields"], {"description": secret})
        self.assertIn(E.INCIDENT_UPDATE_COMPLETED, self.audit.types())
        self._assert_clean(extra=("UPDATE-DESCRIPTION-SECRET", "hunter2", "description to"))

    async def test_no_display_name_or_email_fields(self):
        await self._send("INC0010002")
        for event in self.audit.events:
            self.assertEqual(event.user_id, USER)
            self.assertEqual(event.tenant_id, TENANT)
            self.assertFalse({"display_name", "email", "name"} & set(event.to_dict()))


# ===========================================================================
# 17–22: Authorization auditing
# ===========================================================================

class TestAuthorizationAuditing(_Base):

    async def test_17_allowed_read(self):
        await self._send("INC0010002")
        event = self.audit.of(E.INCIDENT_READ_AUTHORIZED)[0]
        self.assertIs(event.outcome, AuditOutcome.ALLOWED)
        self.assertIs(event.action, AuthorizableAction.READ_INCIDENT)
        self.assertEqual(event.incident_number, "INC0010002")

    async def test_18_denied_read(self):
        await self._send("INC0010002", tenant=OTHER_TENANT)
        self.assertEqual(len(self.audit.of(E.INCIDENT_READ_DENIED)), 1)
        self.assertEqual(self.audit.of(E.INCIDENT_READ_AUTHORIZED), [])
        self.client.get_incident.assert_not_called()

    async def test_19_allowed_create(self):
        self._ready_create()
        await self._send("yes")
        self.assertEqual(self.audit.of(E.INCIDENT_CREATE_AUTHORIZED)[0].action,
                         AuthorizableAction.CREATE_INCIDENT)

    async def test_20_denied_create(self):
        self._ready_create()
        await self._send("yes", tenant=OTHER_TENANT)
        self.assertEqual(len(self.audit.of(E.INCIDENT_CREATE_DENIED)), 1)
        self.assertEqual(self.audit.of(E.INCIDENT_CREATE_COMPLETED), [])
        self.client.create_incident.assert_not_called()

    async def test_21_allowed_update(self):
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        stages = [e.reason for e in self.audit.of(E.INCIDENT_UPDATE_AUTHORIZED)]
        self.assertEqual(stages, ["request_stage", "execution_stage"])

    async def test_22_denied_update(self):
        self.authorize.side_effect = authorize  # default policy: employees cannot update
        await self._send("Update INC0010002 impact to 1")
        event = self.audit.of(E.INCIDENT_UPDATE_DENIED)[0]
        self.assertIs(event.outcome, AuditOutcome.DENIED)
        self.assertEqual(event.incident_number, "INC0010002")
        self.client.update_incident.assert_not_called()


# ===========================================================================
# 23–27: Confirmation auditing
# ===========================================================================

class TestConfirmationAuditing(_Base):

    async def test_23_confirmation_requested(self):
        await self._send("Update INC0010002 impact to 1")
        event = self.audit.of(E.CONFIRMATION_REQUESTED)[0]
        self.assertIs(event.action, AuthorizableAction.UPDATE_INCIDENT)
        self.assertEqual(event.incident_number, "INC0010002")

    async def test_23b_confirmation_requested_for_create(self):
        await self._send("VPN is down. Impact is 2 and urgency is 1.")
        self.assertEqual(self.audit.of(E.CONFIRMATION_REQUESTED)[0].action,
                         AuthorizableAction.CREATE_INCIDENT)

    async def test_24_confirmation_accepted(self):
        self._ready_create()
        await self._send("yes")
        self.assertEqual(len(self.audit.of(E.CONFIRMATION_ACCEPTED)), 1)

    async def test_25_confirmation_cancelled(self):
        self._ready_create()
        await self._send("cancel")
        event = self.audit.of(E.CONFIRMATION_CANCELLED)[0]
        self.assertEqual(event.correlation_id, "op-create-1")
        self.client.create_incident.assert_not_called()

    async def test_26_ambiguous_confirmation_recorded_as_non_execution(self):
        self._ready_create()
        await self._send("sounds good")
        event = self.audit.of(E.CONFIRMATION_REJECTED)[0]
        self.assertIs(event.outcome, AuditOutcome.REJECTED)
        self.assertEqual(event.reason, "not_explicit_confirmation")
        self.assertEqual(self.audit.of(E.INCIDENT_CREATE_AUTHORIZED), [])
        self.client.create_incident.assert_not_called()

    async def test_27_confirmation_events_contain_no_message(self):
        self._ready_create()
        await self._send(f"sounds good {PASSWORD}")
        await self._send("yes")
        self._assert_clean(extra=("sounds good",))


# ===========================================================================
# 28–34: Execution auditing
# ===========================================================================

class TestExecutionAuditing(_Base):

    async def test_28_read_completed(self):
        await self._send("check INC0010002")
        event = self.audit.of(E.INCIDENT_READ_COMPLETED)[0]
        self.assertIs(event.outcome, AuditOutcome.SUCCEEDED)
        self.assertEqual(event.tool, "get_incident")

    async def test_29_read_failed(self):
        self.client.get_incident.side_effect = ServiceNowNotFound("gone")
        await self._send("INC0010002")
        self.assertEqual(self.audit.of(E.INCIDENT_READ_FAILED)[0].reason, "not_found")
        self.assertEqual(self.audit.of(E.INCIDENT_READ_COMPLETED), [])

    async def test_30_create_completed(self):
        self._ready_create()
        await self._send("yes")
        event = self.audit.of(E.INCIDENT_CREATE_COMPLETED)[0]
        self.assertEqual(event.incident_number, "INC0012345")
        self.assertEqual(event.tool, "create_incident")

    async def test_31_create_failed(self):
        self.client.create_incident.side_effect = ServiceNowError(f"boom {OAUTH_TOKEN}")
        self._ready_create()
        await self._send("yes")
        self.assertEqual(self.audit.of(E.INCIDENT_CREATE_FAILED)[0].reason, "execution_error")
        self.assertEqual(self.audit.of(E.INCIDENT_CREATE_COMPLETED), [])
        self._assert_clean()

    async def test_32_update_completed(self):
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        event = self.audit.of(E.INCIDENT_UPDATE_COMPLETED)[0]
        self.assertEqual((event.incident_number, event.tool), ("INC0010002", "update_incident"))

    async def test_33_update_failed(self):
        self.client.update_incident.side_effect = ServiceNowError("timeout")
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        self.assertEqual(self.audit.of(E.INCIDENT_UPDATE_FAILED)[0].reason, "execution_error")
        self.assertEqual(self.audit.of(E.INCIDENT_UPDATE_COMPLETED), [])

    async def test_34_tool_rejection_audited_by_gateway(self):
        with patch.dict("os.environ", {"TEAMS_TENANT_ID": TENANT}):
            identity = UserIdentity(USER, TENANT, None, None, IdentitySource.AAD_OBJECT_ID)
            read = authorize(identity, AuthorizableAction.READ_INCIDENT)
            denied = authorize(ANONYMOUS, AuthorizableAction.READ_INCIDENT)
            await self.gateway.execute(identity, read, ServiceNowToolAction.GET_INCIDENT,
                                       GetIncidentToolRequest("INC123"), correlation_id="op-9")
            await self.gateway.execute(identity, denied, ServiceNowToolAction.GET_INCIDENT,
                                       GetIncidentToolRequest("INC0010002"))
            await self.gateway.execute(identity, read, "delete_user", None)
            await self.gateway.execute(identity, read, ServiceNowToolAction.UPDATE_INCIDENT,
                                       UpdateIncidentToolRequest("INC0010002", impact="1"))
        rejected = self.audit.of(E.TOOL_EXECUTION_REJECTED)
        self.assertEqual([(e.reason, e.tool, e.correlation_id == "op-9") for e in rejected[:1]],
                         [("validation_error", "get_incident", True)])
        self.assertEqual((rejected[1].reason, rejected[1].tool),
                         ("invalid_tool_action", None))
        denials = self.audit.of(E.AUTHORIZATION_DENIED)
        self.assertEqual(len(denials), 2)  # denied decision + action mismatch
        self.assertEqual(denials[1].action, AuthorizableAction.UPDATE_INCIDENT)
        self.client.get_incident.assert_not_called()
        self.client.update_incident.assert_not_called()


# ===========================================================================
# 35–39: Ordering
# ===========================================================================

class TestOrdering(_Base):

    def _index(self, item):
        return self.timeline.index(item)

    async def test_35_authorization_audited_before_execution(self):
        await self._send("INC0010002")
        self.assertLess(self._index(("audit", E.INCIDENT_READ_AUTHORIZED)),
                        self._index(("servicenow", "get")))

    async def test_36_37_create_order(self):
        self._ready_create()
        await self._send("yes")
        order = [self._index(x) for x in (
            ("audit", E.CONFIRMATION_ACCEPTED),
            ("audit", E.INCIDENT_CREATE_AUTHORIZED),
            ("servicenow", "create"),
            ("audit", E.INCIDENT_CREATE_COMPLETED),
        )]
        self.assertEqual(order, sorted(order))

    async def test_36_37_update_order(self):
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        write = self._index(("servicenow", "update"))
        self.assertLess(self._index(("audit", E.CONFIRMATION_ACCEPTED)), write)
        self.assertLess(self.timeline.index(("audit", E.INCIDENT_UPDATE_AUTHORIZED), 0), write)
        self.assertGreater(self._index(("audit", E.INCIDENT_UPDATE_COMPLETED)), write)

    async def test_38_failure_audited_when_execution_fails(self):
        self.client.update_incident.side_effect = ServiceNowError("boom")
        await self._send("Update INC0010002 impact to 1")
        await self._send("yes")
        self.assertEqual(self.audit.types()[-1], E.INCIDENT_UPDATE_FAILED)

    async def test_39_unauthorized_never_audits_success(self):
        self.authorize.side_effect = authorize
        await self._send("Update INC0010002 impact to 1")
        self._ready_create()
        await self._send("yes", tenant=OTHER_TENANT)
        await self._send("INC0010002", tenant=OTHER_TENANT)
        for success in (E.INCIDENT_UPDATE_COMPLETED, E.INCIDENT_CREATE_COMPLETED,
                        E.INCIDENT_READ_COMPLETED, E.INCIDENT_UPDATE_AUTHORIZED,
                        E.INCIDENT_CREATE_AUTHORIZED, E.INCIDENT_READ_AUTHORIZED):
            self.assertEqual(self.audit.of(success), [], success)
        self.assertFalse([t for t in self.timeline if t[0] == "servicenow"])


# ===========================================================================
# 40–44: Regression
# ===========================================================================

class TestRegression(_Base):

    async def test_42_read_remains_confirmation_free(self):
        reply = await self._send("INC0010002")
        self.assertIn("VPN unavailable", reply)
        self.assertEqual(self.audit.of(E.CONFIRMATION_REQUESTED), [])
        self.assertEqual(get_session(USER).phase, ConversationPhase.IDLE)

    async def test_43_writes_still_require_confirmation(self):
        await self._send("VPN is down. Impact is 2 and urgency is 1.")
        await self._send("Update INC0010002 impact to 1")  # ignored mid-flow
        await self._send("okay")
        self.client.create_incident.assert_not_called()
        self.client.update_incident.assert_not_called()
        self.assertEqual(get_session(USER).phase, ConversationPhase.READY_FOR_CONFIRMATION)

    async def test_44_gateway_restrictions_unchanged(self):
        identity = UserIdentity(USER, TENANT, None, None, IdentitySource.AAD_OBJECT_ID)
        read = authorize(identity, AuthorizableAction.READ_INCIDENT)
        result = await self.gateway.execute(
            identity, read, ServiceNowToolAction.CREATE_INCIDENT,
            CreateIncidentToolRequest("x", "y", "2", "1"))
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.create_incident.assert_not_called()


# ===========================================================================
# Audit failure cannot bypass security
# ===========================================================================

class TestAuditFailure(_Base):

    audit_fails = True

    async def test_unauthorized_update_still_blocked_when_audit_fails(self):
        self.authorize.side_effect = authorize  # default policy denies UPDATE
        reply = await self._send("Update INC0010002 impact to 1")
        self.assertIn("not authorised", reply)
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION, pending_action="update_incident",
            incident_number="INC0010002",
            collected_details={"changes": {"impact": "1"}, "requested": [], "current": {}},
        )
        save_session(USER, state)
        reply = await self._send("yes")
        self.assertIn("not authorised", reply)
        self.client.update_incident.assert_not_called()
        self.client.get_incident.assert_not_called()

    async def test_failed_servicenow_operation_stays_failed(self):
        self.client.update_incident.side_effect = ServiceNowError("boom")
        await self._send("Update INC0010002 impact to 1")
        reply = await self._send("yes")
        self.assertNotIn("✅", reply)
        self.assertEqual(get_session(USER).phase, ConversationPhase.FAILED)

    async def test_operations_unchanged_when_audit_fails(self):
        self.assertIn("VPN unavailable", await self._send("INC0010002"))
        self._ready_create()
        self.assertIn("INC0012345", await self._send("yes"))
        self.assertEqual(self.audit.events, [])

    async def test_gateway_rejection_unchanged_when_audit_fails(self):
        identity = UserIdentity(USER, TENANT, None, None, IdentitySource.AAD_OBJECT_ID)
        result = await self.gateway.execute(
            identity, authorize(ANONYMOUS, AuthorizableAction.READ_INCIDENT),
            ServiceNowToolAction.GET_INCIDENT, GetIncidentToolRequest("INC0010002"))
        self.assertEqual(result.error_code, "AUTHORIZATION_DENIED")
        self.client.get_incident.assert_not_called()


# ===========================================================================
# Correlation
# ===========================================================================

class TestCorrelation(_Base):

    async def test_one_operation_shares_one_correlation_id(self):
        await self._send("I need to report an issue", activity_id="act-1")
        await self._send("VPN is down for me.", activity_id="act-2")
        await self._send("2", activity_id="act-3")
        await self._send("1", activity_id="act-4")
        await self._send("yes", activity_id="act-5")
        self.assertEqual({e.correlation_id for e in self.audit.events}, {"act-1"})
        self.assertEqual([e.request_id for e in self.audit.of(E.CONFIRMATION_ACCEPTED)],
                         ["act-5"])
        self.assertEqual(self.audit.types()[0], E.INCIDENT_CREATE_REQUESTED)
        self.assertEqual(self.audit.types()[-1], E.INCIDENT_CREATE_COMPLETED)
        self.assertIsNone(get_session(USER).correlation_id if
                          get_session(USER).phase is ConversationPhase.IDLE else None)

    async def test_unsafe_activity_id_replaced_by_uuid(self):
        await self._send("INC0010002", activity_id="evil id <script>")
        ids = {e.request_id for e in self.audit.events}
        self.assertEqual(len(ids), 1)
        self.assertRegex(ids.pop(), r"^[0-9a-f-]{36}$")

    async def test_conversation_reference_is_hashed(self):
        await self._send("INC0010002", conversation="19:secret-conversation")
        refs = {e.conversation_ref for e in self.audit.events}
        self.assertEqual(refs, {conversation_ref("19:secret-conversation")})
        self._assert_clean(extra=("secret-conversation",))

    async def test_correlation_cleared_when_operation_ends(self):
        self._ready_create()
        await self._send("cancel")
        self.assertIsNone(get_session(USER).correlation_id)


if __name__ == "__main__":
    unittest.main()
