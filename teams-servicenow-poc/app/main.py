import contextvars
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from microsoft_teams.apps import App, FastAPIAdapter

import app.observability as obs
from app.ai import classify_message
from app.audit import (
    AuditEventType,
    AuditOutcome,
    audit_logger,
    conversation_ref,
    new_correlation_id,
    safe_incident_number,
    safe_ref,
)
from app.models import (
    CreateIncidentRequest,
    UpdateIncidentRequest,
)
from app.servicenow import (
    ServiceNowClient,
    ServiceNowError,
    ServiceNowNotFound,
)
from app.confirmation import ConfirmationDecision, evaluate_confirmation
from app.incident_collection import (
    CREATE_INCIDENT_ACTION,
    process_collection_message,
    start_incident_collection,
    validate_incident_payload,
)
from app.incident_status import (
    NOT_AUTHORISED_MESSAGE,
    format_incident_status,
    lookup_failed_message,
    not_found_message,
)
from app.incident_update import (
    UPDATE_INCIDENT_ACTION,
    current_values,
    parse_update_command,
    process_update_message,
    start_update_collection,
    unsupported_fields_message,
    validated_update,
)
from app.history import (
    CaseOutcome,
    CaseSearchRequest,
    CaseSearchResult,
    HistoricalCaseService,
    LocalHistoricalCaseRepository,
    format_history_answer,
    is_history_question,
)
from app.catalog import is_catalog_browse
from app.catalog.service import UNAVAILABLE_MESSAGE as _CATALOG_UNAVAILABLE
from app.catalog.service import format_catalog_answer
from app.knowledge import (
    KnowledgeOutcome,
    KnowledgeSearchRequest,
    KnowledgeSearchResult,
    KnowledgeService,
    LocalKnowledgeRepository,
    format_knowledge_answer,
)
from app.router import route_message
from app.servicenow_errors import CATEGORY_CODES
from app.security.authorization import AuthorizableAction, authorize
from app.security import identity as _identity_module
from app.security.identity import ANONYMOUS, resolve_identity
from app.tools import (
    CreateIncidentToolRequest,
    GetIncidentToolRequest,
    SearchCatalogToolRequest,
    UpdateIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    ToolResult,
)
from app.state import (
    ConversationPhase,
    StateKey,
    StatePersistenceError,
    configure_state_repository,
    get_session,
    save_session,
    update_session,
)
from app.state_store import create_state_repository


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


class _WarningsOnly(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


# DEMO-02: httpx logs every request (full ServiceNow instance URL and query)
# at INFO.  Internal URLs must not reach the logs; failures are logged by
# app.servicenow as categories instead.  A filter is used because the Teams
# SDK resets the httpx logger level when it creates its HTTP client.
logging.getLogger("httpx").addFilter(_WarningsOnly())
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

_ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() == "true"

app = FastAPI(
    title="Teams ServiceNow POC",
    description="Microsoft Teams AI Service Desk Assistant",
    version="0.1.0",
    docs_url="/docs" if _ENABLE_DOCS else None,
    redoc_url="/redoc" if _ENABLE_DOCS else None,
    openapi_url="/openapi.json" if _ENABLE_DOCS else None,
)

# ============================================================
# MICROSOFT TEAMS ADAPTER
# ============================================================

teams_adapter = FastAPIAdapter(app=app)


teams_app = App(
    client_id=os.getenv("TEAMS_CLIENT_ID"),
    client_secret=os.getenv("TEAMS_CLIENT_SECRET"),
    tenant_id=os.getenv("TEAMS_TENANT_ID"),
    messaging_endpoint="/api/messages",
    http_server_adapter=teams_adapter,
)


# ============================================================
# ADMIN API KEY AUTHENTICATION
# ============================================================

def _get_admin_api_key() -> str:
    """
    Read the ADMIN_API_KEY from the environment at call time.
    Raises RuntimeError if the variable is unset or blank.
    """
    key = os.getenv("ADMIN_API_KEY", "").strip()
    if not key:
        raise RuntimeError("ADMIN_API_KEY is not configured")
    return key


async def require_admin_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
) -> None:
    """
    FastAPI dependency that validates the X-API-Key header
    against the ADMIN_API_KEY environment variable using a
    constant-time comparison to prevent timing attacks.
    """
    try:
        expected = _get_admin_api_key()
    except RuntimeError:
        logger.error("ADMIN_API_KEY is not configured; rejecting request")
        raise HTTPException(status_code=503, detail="Service not configured")

    if not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


# ============================================================
# TEAMS MESSAGE HANDLER
# ============================================================

@teams_app.on_message
async def on_message(context):
    """
    Teams entry point.  BL-011 observes the request lifecycle around the
    unchanged handler: request_started → … → request_completed /
    request_failed, with duration and a correlation id.  Observation is
    passive and never alters the handler's behaviour.
    """
    started = time.monotonic()

    # BL-010: one audit request id per incoming Teams message.
    request_id = safe_ref(getattr(context.activity, "id", None)) or new_correlation_id()
    _AUDIT_REQUEST_ID.set(request_id)

    correlation_id, user, phase = _observation_start(context, request_id)
    token = obs.begin_request(correlation_id, request_id, user)
    obs.observability.record(
        obs.ObsEventName.REQUEST_STARTED, obs.ObsComponent.API, obs.ObsOutcome.STARTED,
        phase=phase,
    )
    try:
        await _handle_message(context)
    except BaseException:
        obs.mark_request_failed("unhandled_exception")
        raise
    finally:
        ctx = obs.current_request()
        failed = ctx.failed_code if ctx else None
        obs.observability.record(
            obs.ObsEventName.REQUEST_FAILED if failed else obs.ObsEventName.REQUEST_COMPLETED,
            obs.ObsComponent.API,
            obs.ObsOutcome.FAILED if failed else obs.ObsOutcome.SUCCESS,
            error_code=failed,
            duration_ms=obs.elapsed_ms(started),
            phase=_observation_phase(context),
        )
        obs.end_request(token)


def _teams_user_id(activity) -> str:
    """Session key for the Teams user (unchanged BL-001..BL-010 logic)."""
    return (
        # Try both attribute names that different SDK versions expose.
        getattr(getattr(activity, "from_", None), "aad_object_id", None)
        or getattr(getattr(activity, "from_", None), "id", None)
        or getattr(getattr(activity, "from_property", None), "aad_object_id", None)
        or getattr(getattr(activity, "from_property", None), "id", None)
        or "unknown-user"
    )


def _state_key(activity) -> StateKey:
    """
    DEMO-01: conversation state is isolated per tenant + user + conversation.
    Uses the same tenant source as authorization and the same user id as
    BL-001..BL-011 session handling.
    """
    conversation_id = getattr(getattr(activity, "conversation", None), "id", None)
    tenant_id = _channel_tenant_id(activity)
    return StateKey(
        tenant_id=tenant_id if isinstance(tenant_id, str) else "",
        user_id=_teams_user_id(activity),
        conversation_id=conversation_id if isinstance(conversation_id, str) else "",
    )


_ACTIVE_PHASES = (
    ConversationPhase.COLLECTING,
    ConversationPhase.READY_FOR_CONFIRMATION,
    ConversationPhase.EXECUTING,
)


def _observation_start(context, request_id: str):
    """
    (correlation_id, user_ref, phase) for a new request — never raises.
    An in-progress operation keeps its BL-010 correlation id; otherwise the
    request gets its own (so a finished operation's id is never reused).
    """
    try:
        activity = context.activity
        identity = _identity_module.resolve_identity(
            activity, channel_tenant_id=_channel_tenant_id(activity))
        user = obs.user_ref(identity.user_id, identity.tenant_id)
        if not (activity.text or "").strip():
            return request_id, user, None
        session = get_session(_state_key(activity))
        if session.phase in _ACTIVE_PHASES and safe_ref(session.correlation_id):
            return session.correlation_id, user, session.phase.value
        return request_id, user, session.phase.value
    except Exception:  # noqa: BLE001 — observability must never break the request
        return request_id, None, None


def _observation_phase(context):
    try:
        if not (context.activity.text or "").strip():
            return None
        return get_session(_state_key(context.activity)).phase.value
    except Exception:  # noqa: BLE001
        return None


def _authorize(identity, action, stage=None):
    """``authorize()`` observed by BL-011 (decision + latency); result unchanged."""
    started = time.monotonic()
    decision = authorize(identity, action)
    obs.observability.record(
        obs.ObsEventName.AUTHORIZATION_DECISION,
        obs.ObsComponent.AUTHORIZATION,
        obs.ObsOutcome.SUCCESS if decision.allowed else obs.ObsOutcome.DENIED,
        action=action,
        duration_ms=obs.elapsed_ms(started),
        metadata={"stage": stage} if stage else None,
    )
    return decision


async def _handle_message(context):

    user_message = (
        context.activity.text or ""
    ).strip()

    if not user_message:

        await context.send(
            "Please tell me what you need help with."
        )

        return


    # --------------------------------------------------------
    # Identify the Teams user
    # --------------------------------------------------------

    user_id = _teams_user_id(context.activity)

    try:

        # ----------------------------------------------------
        # Get existing conversation state (DEMO-01: keyed by
        # tenant + user + conversation)
        # ----------------------------------------------------

        state_key = _state_key(context.activity)
        session = get_session(state_key)


        # ----------------------------------------------------
        # BL-006: Incident collection
        # While collecting, every message goes to the deterministic
        # collector — never to the LLM classifier, ServiceNow or the
        # Tool Gateway.  The collector stops at READY_FOR_CONFIRMATION.
        # ----------------------------------------------------

        if session.phase is ConversationPhase.COLLECTING:

            if session.pending_action == UPDATE_INCIDENT_ACTION:
                # BL-009: collecting an incident update.
                collection = process_update_message(session, user_message)
            else:
                collection = process_collection_message(session, user_message)
            save_session(state_key, session)

            if session.phase is ConversationPhase.READY_FOR_CONFIRMATION:
                _audit_session(AuditEventType.CONFIRMATION_REQUESTED, context, session)

            await context.send(collection.reply)

            return


        # ----------------------------------------------------
        # BL-003: Confirmation gate
        # When the conversation is waiting for confirmation,
        # evaluate the message before any AI classification.
        # The gate is pure: no ServiceNow, no network.
        # ----------------------------------------------------

        if session.phase is ConversationPhase.READY_FOR_CONFIRMATION:

            confirm_started = time.monotonic()
            decision = evaluate_confirmation(session, user_message)
            obs.observability.record(
                obs.ObsEventName.CONFIRMATION_DECISION,
                obs.ObsComponent.CONFIRMATION,
                obs.ObsOutcome.SUCCESS if decision.confirmed
                else obs.ObsOutcome.CANCELLED if decision.cancelled
                else obs.ObsOutcome.REJECTED,
                action=_PENDING_AUDIT_ACTIONS.get(session.pending_action),
                duration_ms=obs.elapsed_ms(confirm_started),
                metadata={"pending_action": session.pending_action}
                if session.pending_action in _PENDING_AUDIT_ACTIONS else None,
            )

            if decision.confirmed:
                _audit_session(AuditEventType.CONFIRMATION_ACCEPTED, context, session)
                if session.pending_action == UPDATE_INCIDENT_ACTION:
                    # BL-009: validate → authorize → EXECUTING → Tool Gateway.
                    await _update_confirmed_incident(context, user_id, session)
                else:
                    # BL-007: validate → authorize → EXECUTING → Tool Gateway.
                    await _create_confirmed_incident(context, user_id, session)
                return

            elif decision.cancelled:
                _audit_session(AuditEventType.CONFIRMATION_CANCELLED, context, session)
                # Transition to CANCELLED, then reset to IDLE.
                session.transition_to(ConversationPhase.CANCELLED)
                session.transition_to(ConversationPhase.IDLE)
                save_session(state_key, session)

                await context.send(
                    "❌ Cancelled. No action has been taken.\n\n"
                    "Let me know if there is anything else I can help with."
                )
                return

            else:
                # Ambiguous — remain in READY_FOR_CONFIRMATION and re-prompt.
                _audit_session(
                    AuditEventType.CONFIRMATION_REJECTED, context, session,
                    reason="not_explicit_confirmation",
                )
                await context.send(
                    "I need an explicit confirmation or cancellation before "
                    "I can proceed.\n\n"
                    "Please reply with **yes** to confirm or **cancel** to "
                    "cancel."
                )
                return


        # ----------------------------------------------------
        # BL-007: a create is in flight.  Never re-enter the
        # workflow (or the LLM) while EXECUTING — this prevents a
        # second message from producing a duplicate incident.
        # ----------------------------------------------------

        if session.phase is ConversationPhase.EXECUTING:

            await context.send(
                "⏳ Your incident is still being created. "
                "Please wait for the result before sending another request."
            )

            return


        # ----------------------------------------------------
        # BL-008: deterministic incident status lookup (BL-001
        # router).  Read-only: no confirmation, no state change,
        # no LLM.  Anything the router does not match exactly
        # falls through to the classifier below.
        # ----------------------------------------------------

        route_started = time.monotonic()
        route = route_message(user_message)
        obs.observability.record(
            obs.ObsEventName.ROUTE_SELECTED, obs.ObsComponent.ROUTER, obs.ObsOutcome.SUCCESS,
            duration_ms=obs.elapsed_ms(route_started),
            metadata={"route": route.intent if route is not None else "none"},
        )

        if route is not None and route.intent == "incident_status":

            await context.send(
                await _lookup_incident_status(context, route.incident_number)
            )

            return

        if route is not None and route.intent == "incident_update":

            # BL-009: starts a collection only; any change still needs
            # explicit confirmation before it is executed.
            await context.send(
                await _start_incident_update(context, user_id, session, user_message)
            )

            return


        # ----------------------------------------------------
        # DEMO-04: "have we seen this before?" — deterministic,
        # read-only, no LLM, no ServiceNow, no state change.
        # ----------------------------------------------------

        if is_history_question(user_message):

            await context.send(await _answer_history(context, user_message))

            return


        # ----------------------------------------------------
        # DEMO-05: explicit "what can I request?" — deterministic,
        # read-only catalog browse through the Tool Gateway.
        # ----------------------------------------------------

        if is_catalog_browse(user_message):

            await context.send(await _answer_catalog(context, user_message, browse=True))

            return


        # ----------------------------------------------------
        # Ask Ollama to classify the current message
        # ----------------------------------------------------

        classify_started = time.monotonic()
        result = await classify_message(
            user_message
        )

        intent = result["intent"]
        summary = result["summary"]
        obs.observability.record(
            obs.ObsEventName.ROUTE_SELECTED, obs.ObsComponent.AI_CLASSIFIER, obs.ObsOutcome.SUCCESS,
            duration_ms=obs.elapsed_ms(classify_started),
            metadata={"intent": intent} if intent in obs.APPROVED_METADATA["intent"] else None,
        )


        # ----------------------------------------------------
        # Store conversation state
        # ----------------------------------------------------

        update_session(
            state_key,
            intent=intent,
            summary=summary,
        )


        # ----------------------------------------------------
        # Generate response
        # ----------------------------------------------------

        if intent in ("diagnose", "find_solution"):

            # DEMO-03: answer from approved knowledge.  Retrieval uses the
            # user's own words (never the LLM summary), is read-only, and
            # never creates, updates or confirms anything.
            response = await _answer_knowledge(context, user_message)


        elif intent == "create_incident":

            # BL-006: start deterministic incident collection.  Details the
            # user already gave are captured from their own message; the
            # LLM summary is never used as an incident field value.
            session = get_session(state_key)

            if session.phase in (
                ConversationPhase.IDLE,
                ConversationPhase.COMPLETED,
                ConversationPhase.FAILED,
                ConversationPhase.CANCELLED,
            ):
                collection = start_incident_collection(session, user_message)
                session.correlation_id = _audit_request_id()
                save_session(state_key, session)

                _audit_session(AuditEventType.INCIDENT_CREATE_REQUESTED, context, session)
                if collection.ready:
                    _audit_session(AuditEventType.CONFIRMATION_REQUESTED, context, session)

                response = collection.reply

            else:
                # Already past collecting — just acknowledge.
                response = (
                    "The incident workflow is already in progress. "
                    "Please confirm or cancel the pending action."
                )



        elif intent == "incident_status":

            response = (
                "📋 I can help check your ServiceNow incident status.\n\n"
                "Please provide the incident number, for example:\n"
                "**INC0010002**"
            )


        elif intent == "service_request":

            # DEMO-05: read-only discovery of approved catalog items from the
            # user's own words (never the LLM summary).  Nothing is requested.
            response = await _answer_catalog(context, user_message)


        elif intent == "human_escalation":

            response = (
                "👤 I can help escalate this to the IT support team."
            )


        else:

            response = (
                "👋 Hi! I'm your Service Desk Assistant.\n\n"
                "I can help with:\n"
                "🔍 IT troubleshooting\n"
                "📚 Finding solutions\n"
                "🎫 ServiceNow incidents\n"
                "📝 Service requests\n"
                "📋 Incident status\n"
                "👤 IT support escalation"
            )


        await context.send(response)


    except StatePersistenceError as exc:

        # DEMO-01: fail safe.  Nothing after the failed load/save ran, and
        # there is no fallback store.
        obs.mark_request_failed("state_persistence_error")
        logger.error("conversation state %s failed; request stopped", exc.operation)

        await context.send(
            _STATE_UNAVAILABLE if exc.operation == "load" else _STATE_NOT_SAVED
        )

    except Exception as exc:

        obs.mark_request_failed("handler_exception")
        logger.error(
            "AI classification error for user %s: %s",
            user_id,
            exc,
        )

        await context.send(
            "I'm having trouble understanding your request right now. "
            "Please try again."
        )


_STATE_UNAVAILABLE = (
    "⚠️ I can't access your conversation right now, so no action has been "
    "taken. Please try again in a moment."
)

_STATE_NOT_SAVED = (
    "⚠️ I couldn't save the progress of this conversation, so I've stopped "
    "here. If you were creating or updating an incident, please check its "
    "status before trying again."
)


# ============================================================
# BL-010: AUDIT HELPERS (observation only — never gate anything)
# ============================================================

_AUDIT_REQUEST_ID: contextvars.ContextVar = contextvars.ContextVar(
    "audit_request_id", default=None
)

_PENDING_AUDIT_ACTIONS = {
    CREATE_INCIDENT_ACTION: AuthorizableAction.CREATE_INCIDENT,
    UPDATE_INCIDENT_ACTION: AuthorizableAction.UPDATE_INCIDENT,
}


def _audit_request_id() -> str:
    request_id = _AUDIT_REQUEST_ID.get()
    if request_id is None:
        request_id = new_correlation_id()
        _AUDIT_REQUEST_ID.set(request_id)
    return request_id


def _audit(event_type, context, *, correlation_id=None, **fields) -> None:
    """
    Record one audit event for the current Teams message.  Identity refs are
    taken from the activity (stable user id + tenant id only — never the
    display name, e-mail, message text or payloads).  Never raises.
    """
    try:
        activity = context.activity
        identity = _identity_module.resolve_identity(
            activity, channel_tenant_id=_channel_tenant_id(activity)
        )
        user_ref = safe_ref(identity.user_id)
        tenant_ref = safe_ref(identity.tenant_id)
        conv_ref = conversation_ref(
            getattr(getattr(activity, "conversation", None), "id", None)
        )
    except Exception:  # noqa: BLE001 — audit must never break the request
        user_ref = tenant_ref = conv_ref = None
    request_id = _audit_request_id()
    audit_logger.record(
        event_type,
        correlation_id=safe_ref(correlation_id) or request_id,
        request_id=request_id,
        user_id=user_ref,
        tenant_id=tenant_ref,
        conversation_ref=conv_ref,
        **fields,
    )


def _audit_session(event_type, context, session, **fields) -> None:
    """Audit event for the operation pending in *session*."""
    fields.setdefault("action", _PENDING_AUDIT_ACTIONS.get(session.pending_action))
    if session.pending_action == UPDATE_INCIDENT_ACTION:
        fields.setdefault("incident_number", safe_incident_number(session.incident_number))
    _audit(event_type, context, correlation_id=session.correlation_id, **fields)


_KNOWN_FAILURE_REASONS = frozenset(
    {"not_found", "execution_error", "validation_error", "authorization_denied"}
    | {code.lower() for code in CATEGORY_CODES}
)


def _failure_reason(tool_result) -> str:
    """
    Audit reason for a failed tool result.  DEMO-02: the ServiceNow failure
    category, suffixed ``_unconfirmed`` when a write may have been applied.
    """
    code = (tool_result.error_code or "execution_error").lower()
    reason = code if code in _KNOWN_FAILURE_REASONS else "execution_error"
    if getattr(tool_result, "outcome_unknown", False):
        reason += "_unconfirmed"
    return reason


def _classified(tool_result) -> bool:
    """
    DEMO-02: a categorized ServiceNow failure whose safe_message is the reply.
    NOT_FOUND for a read/update keeps its existing incident-specific reply; a
    404 on create has no target incident and is reported as a category.
    """
    if tool_result.error_code not in CATEGORY_CODES:
        return False
    return (tool_result.error_code != "NOT_FOUND"
            or tool_result.action is ServiceNowToolAction.CREATE_INCIDENT)


def _read_failure_reply(tool_result, incident_number: str) -> str:
    if tool_result.error_code == "NOT_FOUND":
        return not_found_message(incident_number)
    if _classified(tool_result):
        return tool_result.safe_message
    return lookup_failed_message(incident_number)


def _write_failure_reply(tool_result, legacy: str) -> str:
    """
    Reply for a failed create/update.  An unconfirmed outcome is never
    reported as "could not be created/applied": the write may have happened.
    """
    if _classified(tool_result):
        return ("⚠️ " if tool_result.outcome_unknown else "❌ ") + tool_result.safe_message
    return legacy


# ============================================================
# DEMO-03: ENTERPRISE KNOWLEDGE (read-only, no side effects)
# ============================================================

knowledge_service = KnowledgeService(LocalKnowledgeRepository.from_fixture())

_NOT_AUTHORISED_KNOWLEDGE = (
    "⛔ You are not authorised to search the knowledge base.\n\n"
    "Please contact your IT administrator if you believe this is incorrect."
)


async def _answer_knowledge(context, user_message: str) -> str:
    """
    identity → authorize(READ_KNOWLEDGE) → KnowledgeService.search → grounded,
    cited reply.  No ServiceNow call, no tool gateway, no state change, no
    confirmation.  Audit / observability record ids and counts only — never
    the query text or article bodies.
    """
    base = dict(
        correlation_id=_audit_request_id(),
        action=AuthorizableAction.READ_KNOWLEDGE,
        tool="knowledge_search",
    )
    _audit(AuditEventType.KNOWLEDGE_SEARCH_REQUESTED, context, **base)

    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    if not _authorize(identity, AuthorizableAction.READ_KNOWLEDGE).allowed:
        _audit(AuditEventType.KNOWLEDGE_SEARCH_DENIED, context, **base)
        return _NOT_AUTHORISED_KNOWLEDGE
    _audit(AuditEventType.KNOWLEDGE_SEARCH_AUTHORIZED, context, **base)

    observe = dict(
        action=AuthorizableAction.READ_KNOWLEDGE,
        operation="knowledge_search",
        correlation_id=base["correlation_id"],
    )
    obs.observability.record(obs.ObsEventName.TOOL_STARTED, obs.ObsComponent.KNOWLEDGE,
                             obs.ObsOutcome.STARTED, **observe)
    started = time.monotonic()
    try:
        result = await knowledge_service.search(KnowledgeSearchRequest(user_message))
    except Exception as exc:  # noqa: BLE001 — the service should never raise
        logger.error("knowledge search raised %s", type(exc).__name__)
        result = KnowledgeSearchResult(KnowledgeOutcome.UNAVAILABLE)
    duration = obs.elapsed_ms(started)

    if result.outcome in (KnowledgeOutcome.UNAVAILABLE, KnowledgeOutcome.EMPTY_QUERY):
        unavailable = result.outcome is KnowledgeOutcome.UNAVAILABLE
        reason = "knowledge_unavailable" if unavailable else "empty_query"
        _audit(AuditEventType.KNOWLEDGE_SEARCH_FAILED, context, reason=reason,
               outcome=AuditOutcome.FAILED if unavailable else AuditOutcome.REJECTED, **base)
        obs.observability.record(
            obs.ObsEventName.TOOL_FAILED, obs.ObsComponent.KNOWLEDGE,
            obs.ObsOutcome.FAILED if unavailable else obs.ObsOutcome.REJECTED,
            error_code=reason, duration_ms=duration, **observe,
        )
    else:
        _audit(AuditEventType.KNOWLEDGE_SEARCH_COMPLETED, context,
               result_count=len(result.hits), article_ids=result.article_ids,
               reason="content_withheld" if result.withheld else None, **base)
        obs.observability.record(
            obs.ObsEventName.TOOL_COMPLETED, obs.ObsComponent.KNOWLEDGE,
            obs.ObsOutcome.SUCCESS, result_count=len(result.hits),
            duration_ms=duration, **observe,
        )
    return format_knowledge_answer(result)


# ============================================================
# DEMO-04: HISTORICAL SIMILAR CASES (read-only, no side effects)
# ============================================================

history_service = HistoricalCaseService(LocalHistoricalCaseRepository.from_fixture())

_NOT_AUTHORISED_HISTORY = (
    "⛔ You are not authorised to search past cases.\n\n"
    "Please contact your IT administrator if you believe this is incorrect."
)


async def _answer_history(context, user_message: str) -> str:
    """
    identity → authorize(READ_KNOWLEDGE) → HistoricalCaseService.search →
    pattern summary citing case references.  Sanitized historical evidence is
    governed like knowledge.  No ServiceNow call, no gateway, no state change,
    no confirmation; audit / observability record references and counts only.
    """
    base = dict(
        correlation_id=_audit_request_id(),
        action=AuthorizableAction.READ_KNOWLEDGE,
        tool="historical_case_search",
    )
    _audit(AuditEventType.HISTORICAL_CASE_SEARCH_REQUESTED, context, **base)

    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    if not _authorize(identity, AuthorizableAction.READ_KNOWLEDGE).allowed:
        _audit(AuditEventType.HISTORICAL_CASE_SEARCH_DENIED, context, **base)
        return _NOT_AUTHORISED_HISTORY
    _audit(AuditEventType.HISTORICAL_CASE_SEARCH_AUTHORIZED, context, **base)

    observe = dict(
        action=AuthorizableAction.READ_KNOWLEDGE,
        operation="historical_case_search",
        correlation_id=base["correlation_id"],
    )
    obs.observability.record(obs.ObsEventName.TOOL_STARTED, obs.ObsComponent.HISTORY,
                             obs.ObsOutcome.STARTED, **observe)
    started = time.monotonic()
    try:
        result = await history_service.search(CaseSearchRequest(user_message))
    except Exception as exc:  # noqa: BLE001 — the service should never raise
        logger.error("historical case search raised %s", type(exc).__name__)
        result = CaseSearchResult(CaseOutcome.UNAVAILABLE)
    duration = obs.elapsed_ms(started)

    if result.outcome in (CaseOutcome.UNAVAILABLE, CaseOutcome.NEEDS_TOPIC):
        unavailable = result.outcome is CaseOutcome.UNAVAILABLE
        reason = "history_unavailable" if unavailable else "missing_topic"
        _audit(AuditEventType.HISTORICAL_CASE_SEARCH_FAILED, context, reason=reason,
               outcome=AuditOutcome.FAILED if unavailable else AuditOutcome.REJECTED, **base)
        obs.observability.record(
            obs.ObsEventName.TOOL_FAILED, obs.ObsComponent.HISTORY,
            obs.ObsOutcome.FAILED if unavailable else obs.ObsOutcome.REJECTED,
            error_code=reason, duration_ms=duration, **observe,
        )
    else:
        _audit(AuditEventType.HISTORICAL_CASE_SEARCH_COMPLETED, context,
               result_count=len(result.cases), case_refs=result.case_refs,
               reason="content_withheld" if result.withheld else None, **base)
        obs.observability.record(
            obs.ObsEventName.TOOL_COMPLETED, obs.ObsComponent.HISTORY,
            obs.ObsOutcome.SUCCESS, result_count=len(result.cases),
            duration_ms=duration, **observe,
        )
    return format_history_answer(result)


# ============================================================
# DEMO-05: SERVICE CATALOG DISCOVERY (read-only, via the Tool Gateway)
# ============================================================

_NOT_AUTHORISED_CATALOG = (
    "⛔ You are not authorised to browse the service catalog.\n\n"
    "Please contact your IT administrator if you believe this is incorrect."
)


async def _answer_catalog(context, user_message: str, *, browse: bool = False) -> str:
    """
    identity → authorize(READ_KNOWLEDGE) → Tool Gateway SEARCH_CATALOG →
    display-safe catalog reply.  Read-only: no request is created, nothing in
    ServiceNow changes, no confirmation, no state change.  Audit records item
    references and counts only — never the query text or catalog text.

    *browse* (an explicit "what can I request?" / "show me the catalog")
    lists the catalog with an empty query instead of keyword-searching the
    message.
    """
    base = dict(
        correlation_id=_audit_request_id(),
        action=AuthorizableAction.READ_KNOWLEDGE,
        tool=ServiceNowToolAction.SEARCH_CATALOG.value,
    )
    _audit(AuditEventType.CATALOG_SEARCH_REQUESTED, context, **base)

    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    authz = _authorize(identity, AuthorizableAction.READ_KNOWLEDGE)
    if not authz.allowed:
        _audit(AuditEventType.CATALOG_SEARCH_DENIED, context, **base)
        return _NOT_AUTHORISED_CATALOG
    _audit(AuditEventType.CATALOG_SEARCH_AUTHORIZED, context, **base)

    try:
        tool_result = await servicenow_gateway.execute(
            identity,
            authz,
            ServiceNowToolAction.SEARCH_CATALOG,
            SearchCatalogToolRequest("" if browse else user_message),
            correlation_id=base["correlation_id"],
        )
    except Exception as exc:  # noqa: BLE001 — the gateway should never raise
        logger.error("catalog search: gateway raised %s", type(exc).__name__)
        _audit(AuditEventType.CATALOG_SEARCH_FAILED, context, reason="execution_error", **base)
        return _CATALOG_UNAVAILABLE

    if not tool_result.success or tool_result.catalog is None:
        _audit(AuditEventType.CATALOG_SEARCH_FAILED, context,
               reason=_failure_reason(tool_result), **base)
        return _CATALOG_UNAVAILABLE

    result = tool_result.catalog
    _audit(AuditEventType.CATALOG_SEARCH_COMPLETED, context,
           result_count=len(result.entries), item_refs=result.item_refs,
           reason="content_withheld" if result.withheld else None, **base)
    return format_catalog_answer(result)


# ============================================================
# BL-007: CONFIRMED INCIDENT CREATION
# ============================================================

def _channel_tenant_id(activity) -> str:
    """Tenant ID asserted in Bot Framework channel data ("" if absent)."""
    channel_data = getattr(activity, "channel_data", None)
    if isinstance(channel_data, dict):
        tenant = channel_data.get("tenant")
        return (tenant.get("id", "") if isinstance(tenant, dict) else "") or ""
    tenant = getattr(channel_data, "tenant", None)
    return getattr(tenant, "id", "") or ""


async def _create_confirmed_incident(context, user_id: str, session) -> None:
    """
    Execute a create_incident the user has explicitly confirmed (BL-003).

    Order: validate collected details → resolve identity → authorize
    CREATE_INCIDENT → READY_FOR_CONFIRMATION → EXECUTING → Tool Gateway
    (exactly once, never retried) → COMPLETED or FAILED.

    Nothing is defaulted: incomplete or invalid details stop the workflow
    before any side effect.
    """

    # -- Collected details must be complete and valid (no defaults) --------
    try:
        if session.pending_action != CREATE_INCIDENT_ACTION:
            raise ValueError("pending action is not create_incident")
        payload = validate_incident_payload(session.collected_details)
    except ValueError:
        logger.warning(
            "incident creation blocked: collected details incomplete or invalid "
            "for user=%r",
            user_id,
        )
        _audit_session(
            AuditEventType.INCIDENT_CREATE_FAILED, context, session,
            action=AuthorizableAction.CREATE_INCIDENT, reason="invalid_details",
        )
        session.transition_to(ConversationPhase.CANCELLED)
        session.transition_to(ConversationPhase.IDLE)
        save_session(_state_key(context.activity), session)

        await context.send(
            "⚠️ Some incident details are missing or invalid, so no incident "
            "was created.\n\n"
            "Please start a new incident request."
        )
        return

    # -- BL-004: identity and authorization ------------------------------
    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    authz = _authorize(identity, AuthorizableAction.CREATE_INCIDENT)
    correlation_id = session.correlation_id or _audit_request_id()

    if not authz.allowed:
        logger.warning(
            "authorization denied for user=%r action=%r",
            identity.user_id,
            AuthorizableAction.CREATE_INCIDENT.value,
        )
        _audit(
            AuditEventType.INCIDENT_CREATE_DENIED, context,
            correlation_id=correlation_id, action=AuthorizableAction.CREATE_INCIDENT,
        )
        await context.send(
            "⛔ You are not authorised to perform this action.\n\n"
            "Please contact your IT administrator if you believe "
            "this is incorrect."
        )
        return

    _audit(
        AuditEventType.INCIDENT_CREATE_AUTHORIZED, context,
        correlation_id=correlation_id, action=AuthorizableAction.CREATE_INCIDENT,
    )

    tool_request = CreateIncidentToolRequest(**payload)

    # -- EXECUTING is persisted BEFORE the side effect ---------------------
    session.transition_to(ConversationPhase.EXECUTING)
    save_session(_state_key(context.activity), session)

    # -- BL-005: single gateway call — CREATE is never retried ------------
    try:
        tool_result = await servicenow_gateway.execute(
            identity,
            authz,
            ServiceNowToolAction.CREATE_INCIDENT,
            tool_request,
            correlation_id=correlation_id,
        )
    except Exception as exc:
        logger.error(
            "incident creation: gateway raised %s for user=%r",
            type(exc).__name__,
            user_id,
        )
        tool_result = ToolResult.fail(
            action=ServiceNowToolAction.CREATE_INCIDENT,
            safe_message="A ServiceNow error occurred while creating the incident.",
            error_code="EXECUTION_ERROR",
        )

    if tool_result.success:
        session.incident_number = tool_result.incident_number or None
        session.transition_to(ConversationPhase.COMPLETED)
        # DEMO-01: audit first, so a failed save can never lose the record
        # of a ServiceNow write that already happened.
        _audit(
            AuditEventType.INCIDENT_CREATE_COMPLETED, context,
            correlation_id=correlation_id, action=AuthorizableAction.CREATE_INCIDENT,
            tool=ServiceNowToolAction.CREATE_INCIDENT.value,
            incident_number=safe_incident_number(session.incident_number),
        )
        save_session(_state_key(context.activity), session)

        if session.incident_number:
            await context.send(
                f"✅ Incident **{session.incident_number}** has been "
                f"created successfully.\n\n"
                f"**Short description:** {payload['short_description']}"
            )
        else:
            await context.send(
                "✅ ServiceNow reported the incident as created but did not "
                "return an incident number.\n\n"
                "Please do not submit it again — contact IT support to "
                "confirm the incident number."
            )
        return

    session.last_error = tool_result.safe_message
    session.transition_to(ConversationPhase.FAILED)
    # DEMO-01: audit first, so a failed save can never lose the record of
    # the outcome.
    _audit(
        AuditEventType.INCIDENT_CREATE_FAILED, context,
        correlation_id=correlation_id, action=AuthorizableAction.CREATE_INCIDENT,
        tool=ServiceNowToolAction.CREATE_INCIDENT.value,
        reason=_failure_reason(tool_result),
    )
    save_session(_state_key(context.activity), session)

    await context.send(_write_failure_reply(
        tool_result,
        f"❌ The incident could not be created: {tool_result.safe_message}\n\n"
        "It will not be retried automatically. You can start a new "
        "incident request if needed.",
    ))


# ============================================================
# BL-008: INCIDENT STATUS LOOKUP
# ============================================================

async def _lookup_incident_status(context, incident_number: str) -> str:
    """
    Read one incident through the Tool Gateway and return the Teams reply.

    identity → authorize(READ_INCIDENT) → gateway GET_INCIDENT (once, never
    retried).  Returns a safe message for denial, not-found and failure.
    """
    correlation_id = _audit_request_id()
    read = dict(
        correlation_id=correlation_id,
        action=AuthorizableAction.READ_INCIDENT,
        incident_number=safe_incident_number(incident_number),
    )
    _audit(AuditEventType.INCIDENT_READ_REQUESTED, context, **read)

    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    authz = _authorize(identity, AuthorizableAction.READ_INCIDENT)

    if not authz.allowed:
        logger.warning(
            "authorization denied for user=%r action=%r",
            identity.user_id,
            AuthorizableAction.READ_INCIDENT.value,
        )
        _audit(AuditEventType.INCIDENT_READ_DENIED, context, **read)
        return NOT_AUTHORISED_MESSAGE

    _audit(AuditEventType.INCIDENT_READ_AUTHORIZED, context, **read)
    read["tool"] = ServiceNowToolAction.GET_INCIDENT.value

    try:
        tool_result = await servicenow_gateway.execute(
            identity,
            authz,
            ServiceNowToolAction.GET_INCIDENT,
            GetIncidentToolRequest(incident_number=incident_number),
            correlation_id=correlation_id,
        )
    except Exception as exc:
        logger.error(
            "incident lookup: gateway raised %s for user=%r",
            type(exc).__name__,
            identity.user_id,
        )
        _audit(AuditEventType.INCIDENT_READ_FAILED, context, reason="execution_error", **read)
        return lookup_failed_message(incident_number)

    if tool_result.success and tool_result.incident:
        _audit(AuditEventType.INCIDENT_READ_COMPLETED, context, **read)
        return format_incident_status(tool_result.incident, incident_number)

    _audit(
        AuditEventType.INCIDENT_READ_FAILED, context,
        reason=_failure_reason(tool_result) if not tool_result.success else "empty_result",
        **read,
    )

    return _read_failure_reply(tool_result, incident_number)


# ============================================================
# BL-009: CONTROLLED INCIDENT UPDATE
# ============================================================

_NOT_AUTHORISED_ACTION = (
    "⛔ You are not authorised to perform this action.\n\n"
    "Please contact your IT administrator if you believe "
    "this is incorrect."
)


_REQUEST_IN_PROGRESS = (
    "⏳ You already have a request in progress. Please finish or cancel it "
    "before starting a new update."
)


async def _start_incident_update(context, user_id: str, session, user_message: str) -> str:
    """
    Start collecting an update for one incident.

    identity → authorize(UPDATE_INCIDENT) → read the current values through
    the gateway (GET_INCIDENT, READ_INCIDENT) → IDLE → COLLECTING
    (→ READY_FOR_CONFIRMATION).  Nothing is written here.
    """
    command = parse_update_command(user_message)
    if command is None:  # pragma: no cover — the router already matched
        return "I didn't understand that update request."

    correlation_id = _audit_request_id()
    number = command.incident_number
    upd = dict(
        correlation_id=correlation_id,
        action=AuthorizableAction.UPDATE_INCIDENT,
        incident_number=safe_incident_number(number),
    )
    _audit(AuditEventType.INCIDENT_UPDATE_REQUESTED, context, **upd)

    if command.unsupported:
        _audit(
            AuditEventType.INCIDENT_UPDATE_FAILED, context,
            outcome=AuditOutcome.REJECTED, reason="unsupported_field", **upd,
        )
        return unsupported_fields_message(command.unsupported)

    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    if not _authorize(identity, AuthorizableAction.UPDATE_INCIDENT, "request_stage").allowed:
        logger.warning(
            "authorization denied for user=%r action=%r",
            identity.user_id,
            AuthorizableAction.UPDATE_INCIDENT.value,
        )
        _audit(AuditEventType.INCIDENT_UPDATE_DENIED, context, reason="request_stage", **upd)
        return _NOT_AUTHORISED_ACTION
    _audit(AuditEventType.INCIDENT_UPDATE_AUTHORIZED, context, reason="request_stage", **upd)

    # The current-value read is an incident read in its own right.
    read = dict(upd, action=AuthorizableAction.READ_INCIDENT)
    read_authz = _authorize(identity, AuthorizableAction.READ_INCIDENT, "current_value_read")
    if not read_authz.allowed:
        _audit(AuditEventType.INCIDENT_READ_DENIED, context, **read)
        return _NOT_AUTHORISED_ACTION
    _audit(AuditEventType.INCIDENT_READ_AUTHORIZED, context, **read)
    read["tool"] = ServiceNowToolAction.GET_INCIDENT.value

    try:
        read_result = await servicenow_gateway.execute(
            identity,
            read_authz,
            ServiceNowToolAction.GET_INCIDENT,
            GetIncidentToolRequest(incident_number=number),
            correlation_id=correlation_id,
        )
    except Exception as exc:
        logger.error(
            "incident update: current-value read raised %s for user=%r",
            type(exc).__name__,
            identity.user_id,
        )
        _audit(AuditEventType.INCIDENT_READ_FAILED, context, reason="execution_error", **read)
        return lookup_failed_message(number)

    if not read_result.success or not read_result.incident:
        _audit(
            AuditEventType.INCIDENT_READ_FAILED, context,
            reason=_failure_reason(read_result) if not read_result.success else "empty_result",
            **read,
        )
        return _read_failure_reply(read_result, number)
    _audit(AuditEventType.INCIDENT_READ_COMPLETED, context, **read)

    # The read above awaited, so another message may have changed this
    # user's conversation meanwhile.  Fail closed: never overwrite it.
    session = get_session(_state_key(context.activity))
    if session.phase not in (
        ConversationPhase.IDLE,
        ConversationPhase.COMPLETED,
        ConversationPhase.FAILED,
        ConversationPhase.CANCELLED,
    ):
        logger.warning(
            "incident update not started: conversation changed during read "
            "for user=%r",
            user_id,
        )
        _audit(
            AuditEventType.INCIDENT_UPDATE_FAILED, context,
            outcome=AuditOutcome.REJECTED, reason="conversation_changed", **upd,
        )
        return _REQUEST_IN_PROGRESS

    result = start_update_collection(
        session, command, current_values(read_result.incident)
    )
    session.correlation_id = correlation_id
    save_session(_state_key(context.activity), session)
    if result.ready:
        _audit_session(AuditEventType.CONFIRMATION_REQUESTED, context, session)
    return result.reply


async def _update_confirmed_incident(context, user_id: str, session) -> None:
    """
    Execute an update the user has explicitly confirmed (BL-003).

    Re-validate the pending changes → resolve identity → authorize
    UPDATE_INCIDENT → EXECUTING → Tool Gateway (exactly once, never retried)
    → COMPLETED or FAILED.
    """
    # Fail closed unless the conversation is still awaiting this confirmation.
    if session.phase is not ConversationPhase.READY_FOR_CONFIRMATION:
        logger.warning(
            "incident update not executed: phase is %r for user=%r",
            session.phase.value,
            user_id,
        )
        _audit_session(
            AuditEventType.INCIDENT_UPDATE_FAILED, context, session,
            action=AuthorizableAction.UPDATE_INCIDENT,
            outcome=AuditOutcome.REJECTED, reason="not_awaiting_confirmation",
        )
        await context.send(_REQUEST_IN_PROGRESS)
        return

    try:
        number, changes = validated_update(session)
    except ValueError:
        logger.warning(
            "incident update blocked: pending update missing or invalid for user=%r",
            user_id,
        )
        _audit_session(
            AuditEventType.INCIDENT_UPDATE_FAILED, context, session,
            action=AuthorizableAction.UPDATE_INCIDENT,
            outcome=AuditOutcome.REJECTED, reason="invalid_details",
        )
        session.transition_to(ConversationPhase.CANCELLED)
        session.transition_to(ConversationPhase.IDLE)
        save_session(_state_key(context.activity), session)
        await context.send(
            "⚠️ Some update details are missing or invalid, so the incident "
            "was not changed.\n\n"
            "Please start a new update request."
        )
        return

    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    authz = _authorize(identity, AuthorizableAction.UPDATE_INCIDENT, "execution_stage")
    upd = dict(
        correlation_id=session.correlation_id or _audit_request_id(),
        action=AuthorizableAction.UPDATE_INCIDENT,
        incident_number=safe_incident_number(number),
    )

    if not authz.allowed:
        logger.warning(
            "authorization denied for user=%r action=%r",
            identity.user_id,
            AuthorizableAction.UPDATE_INCIDENT.value,
        )
        _audit(AuditEventType.INCIDENT_UPDATE_DENIED, context, reason="execution_stage", **upd)
        await context.send(_NOT_AUTHORISED_ACTION)
        return
    _audit(AuditEventType.INCIDENT_UPDATE_AUTHORIZED, context, reason="execution_stage", **upd)
    upd["tool"] = ServiceNowToolAction.UPDATE_INCIDENT.value

    tool_request = UpdateIncidentToolRequest(incident_number=number, **changes)

    # -- EXECUTING is persisted BEFORE the side effect ---------------------
    session.transition_to(ConversationPhase.EXECUTING)
    save_session(_state_key(context.activity), session)

    # -- Single gateway call — UPDATE is never retried ---------------------
    try:
        tool_result = await servicenow_gateway.execute(
            identity,
            authz,
            ServiceNowToolAction.UPDATE_INCIDENT,
            tool_request,
            correlation_id=upd["correlation_id"],
        )
    except Exception as exc:
        logger.error(
            "incident update: gateway raised %s for user=%r",
            type(exc).__name__,
            user_id,
        )
        tool_result = ToolResult.fail(
            action=ServiceNowToolAction.UPDATE_INCIDENT,
            safe_message="A ServiceNow error occurred while updating the incident.",
            error_code="EXECUTION_ERROR",
        )

    if tool_result.success:
        session.transition_to(ConversationPhase.COMPLETED)
        # DEMO-01: audit first, so a failed save can never lose the record
        # of a ServiceNow write that already happened.
        _audit(AuditEventType.INCIDENT_UPDATE_COMPLETED, context, **upd)
        save_session(_state_key(context.activity), session)

        if tool_result.incident:
            await context.send(
                "✅ ServiceNow confirmed the update.\n\n"
                + format_incident_status(tool_result.incident, number)
            )
        else:
            await context.send(
                f"✅ ServiceNow confirmed the update to **{number}** but did not "
                "return the updated values.\n\n"
                "Please do not submit it again — check the incident status to "
                "see the current values."
            )
        return

    session.last_error = tool_result.safe_message
    session.transition_to(ConversationPhase.FAILED)
    # DEMO-01: audit first, so a failed save can never lose the record of
    # the outcome.
    _audit(
        AuditEventType.INCIDENT_UPDATE_FAILED, context,
        reason=_failure_reason(tool_result), **upd,
    )
    save_session(_state_key(context.activity), session)

    await context.send(_write_failure_reply(
        tool_result,
        f"❌ The update to {number} could not be applied: "
        f"{tool_result.safe_message}\n\n"
        "It will not be retried automatically.",
    ))


# ============================================================
# APPLICATION LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app):

    # DEMO-01: select the conversation state store before accepting
    # messages.  A store that cannot be opened stops startup — there is no
    # silent fallback to non-persistent state.
    configure_state_repository(create_state_repository())

    await teams_app.initialize()

    yield


app.router.lifespan_context = lifespan


# ============================================================
# SERVICENOW CLIENT
# ============================================================

servicenow = ServiceNowClient()
servicenow_gateway = ServiceNowToolGateway(client=servicenow)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": "Teams ServiceNow AI Service Desk",
    }


# ============================================================
# CREATE SERVICENOW INCIDENT
# ============================================================

@app.post("/incidents", dependencies=[Depends(require_admin_api_key)])
async def create_incident(
    request: CreateIncidentRequest,
):

    try:

        incident = await servicenow.create_incident(
            short_description=request.short_description,
            description=request.description,
            impact=request.impact,
            urgency=request.urgency,
        )

        return {
            "success": True,
            "incident": {
                "number": incident.get("number"),
                "sys_id": incident.get("sys_id"),
                "short_description": incident.get(
                    "short_description"
                ),
                "state": incident.get("state"),
                "impact": incident.get("impact"),
                "urgency": incident.get("urgency"),
                "priority": incident.get("priority"),
            },
        }


    except ServiceNowError as exc:

        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# UPDATE SERVICENOW INCIDENT
# ============================================================

@app.patch("/incidents/{incident_number}", dependencies=[Depends(require_admin_api_key)])
async def update_incident(
    incident_number: str,
    request: UpdateIncidentRequest,
):

    try:

        fields = request.model_dump(
            exclude_none=True
        )

        incident = await servicenow.update_incident(
            incident_number=incident_number,
            fields=fields,
        )

        return {
            "success": True,
            "incident": {
                "number": incident.get("number"),
                "sys_id": incident.get("sys_id"),
                "short_description": incident.get(
                    "short_description"
                ),
                "state": incident.get("state"),
                "impact": incident.get("impact"),
                "urgency": incident.get("urgency"),
                "priority": incident.get("priority"),
            },
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )

    except ServiceNowNotFound as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except ServiceNowError as exc:

        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# LOCAL DEVELOPMENT ENTRY POINT
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
