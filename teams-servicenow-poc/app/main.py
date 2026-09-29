import logging
import os
import secrets
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from microsoft_teams.apps import App, FastAPIAdapter

from app.ai import classify_message
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
from app.router import route_message
from app.security.authorization import AuthorizableAction, authorize
from app.security.identity import ANONYMOUS, resolve_identity
from app.tools import (
    CreateIncidentToolRequest,
    GetIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
    ToolResult,
)
from app.state import (
    ConversationPhase,
    get_session,
    save_session,
    update_session,
)


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
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

    user_id = (
        # Try both attribute names that different SDK versions expose.
        getattr(
            getattr(context.activity, "from_", None),
            "aad_object_id",
            None,
        )
        or getattr(
            getattr(context.activity, "from_", None),
            "id",
            None,
        )
        or getattr(
            getattr(context.activity, "from_property", None),
            "aad_object_id",
            None,
        )
        or getattr(
            getattr(context.activity, "from_property", None),
            "id",
            None,
        )
        or "unknown-user"
    )


    try:

        # ----------------------------------------------------
        # Get existing conversation state
        # ----------------------------------------------------

        session = get_session(user_id)


        # ----------------------------------------------------
        # BL-006: Incident collection
        # While collecting, every message goes to the deterministic
        # collector — never to the LLM classifier, ServiceNow or the
        # Tool Gateway.  The collector stops at READY_FOR_CONFIRMATION.
        # ----------------------------------------------------

        if session.phase is ConversationPhase.COLLECTING:

            collection = process_collection_message(session, user_message)
            save_session(user_id, session)

            await context.send(collection.reply)

            return


        # ----------------------------------------------------
        # BL-003: Confirmation gate
        # When the conversation is waiting for confirmation,
        # evaluate the message before any AI classification.
        # The gate is pure: no ServiceNow, no network.
        # ----------------------------------------------------

        if session.phase is ConversationPhase.READY_FOR_CONFIRMATION:

            decision = evaluate_confirmation(session, user_message)

            if decision.confirmed:
                # BL-007: validate → authorize → EXECUTING → Tool Gateway.
                await _create_confirmed_incident(context, user_id, session)
                return

            elif decision.cancelled:
                # Transition to CANCELLED, then reset to IDLE.
                session.transition_to(ConversationPhase.CANCELLED)
                session.transition_to(ConversationPhase.IDLE)
                save_session(user_id, session)

                await context.send(
                    "❌ Cancelled. No action has been taken.\n\n"
                    "Let me know if there is anything else I can help with."
                )
                return

            else:
                # Ambiguous — remain in READY_FOR_CONFIRMATION and re-prompt.
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

        route = route_message(user_message)

        if route is not None and route.intent == "incident_status":

            await context.send(
                await _lookup_incident_status(context, route.incident_number)
            )

            return


        # ----------------------------------------------------
        # Ask Ollama to classify the current message
        # ----------------------------------------------------

        result = await classify_message(
            user_message
        )

        intent = result["intent"]
        summary = result["summary"]


        # ----------------------------------------------------
        # Store conversation state
        # ----------------------------------------------------

        update_session(
            user_id,
            intent=intent,
            summary=summary,
        )


        # ----------------------------------------------------
        # Generate response
        # ----------------------------------------------------

        if intent == "diagnose":

            response = (
                f"🔍 I understand you're having an issue:\n"
                f"**{summary}**\n\n"
                "I'll help you troubleshoot it."
            )


        elif intent == "find_solution":

            response = (
                f"📚 You're looking for a solution for:\n"
                f"**{summary}**\n\n"
                "I'll help you find the relevant guidance."
            )


        elif intent == "create_incident":

            # BL-006: start deterministic incident collection.  Details the
            # user already gave are captured from their own message; the
            # LLM summary is never used as an incident field value.
            session = get_session(user_id)

            if session.phase in (
                ConversationPhase.IDLE,
                ConversationPhase.COMPLETED,
                ConversationPhase.FAILED,
                ConversationPhase.CANCELLED,
            ):
                collection = start_incident_collection(session, user_message)
                save_session(user_id, session)

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

            response = (
                f"📝 I understand that you want to request:\n"
                f"**{summary}**\n\n"
                "I'll help identify the appropriate IT service."
            )


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


    except Exception as exc:

        logger.error(
            "AI classification error for user %s: %s",
            user_id,
            exc,
        )

        await context.send(
            "I'm having trouble understanding your request right now. "
            "Please try again."
        )


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
        session.transition_to(ConversationPhase.CANCELLED)
        session.transition_to(ConversationPhase.IDLE)
        save_session(user_id, session)

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
    authz = authorize(identity, AuthorizableAction.CREATE_INCIDENT)

    if not authz.allowed:
        logger.warning(
            "authorization denied for user=%r action=%r",
            identity.user_id,
            AuthorizableAction.CREATE_INCIDENT.value,
        )
        await context.send(
            "⛔ You are not authorised to perform this action.\n\n"
            "Please contact your IT administrator if you believe "
            "this is incorrect."
        )
        return

    tool_request = CreateIncidentToolRequest(**payload)

    # -- EXECUTING is persisted BEFORE the side effect ---------------------
    session.transition_to(ConversationPhase.EXECUTING)
    save_session(user_id, session)

    # -- BL-005: single gateway call — CREATE is never retried ------------
    try:
        tool_result = await servicenow_gateway.execute(
            identity,
            authz,
            ServiceNowToolAction.CREATE_INCIDENT,
            tool_request,
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
        save_session(user_id, session)

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
    save_session(user_id, session)

    await context.send(
        f"❌ The incident could not be created: {tool_result.safe_message}\n\n"
        "It will not be retried automatically. You can start a new "
        "incident request if needed."
    )


# ============================================================
# BL-008: INCIDENT STATUS LOOKUP
# ============================================================

async def _lookup_incident_status(context, incident_number: str) -> str:
    """
    Read one incident through the Tool Gateway and return the Teams reply.

    identity → authorize(READ_INCIDENT) → gateway GET_INCIDENT (once, never
    retried).  Returns a safe message for denial, not-found and failure.
    """
    identity = resolve_identity(
        context.activity,
        channel_tenant_id=_channel_tenant_id(context.activity),
    )
    authz = authorize(identity, AuthorizableAction.READ_INCIDENT)

    if not authz.allowed:
        logger.warning(
            "authorization denied for user=%r action=%r",
            identity.user_id,
            AuthorizableAction.READ_INCIDENT.value,
        )
        return NOT_AUTHORISED_MESSAGE

    try:
        tool_result = await servicenow_gateway.execute(
            identity,
            authz,
            ServiceNowToolAction.GET_INCIDENT,
            GetIncidentToolRequest(incident_number=incident_number),
        )
    except Exception as exc:
        logger.error(
            "incident lookup: gateway raised %s for user=%r",
            type(exc).__name__,
            identity.user_id,
        )
        return lookup_failed_message(incident_number)

    if tool_result.success and tool_result.incident:
        return format_incident_status(tool_result.incident, incident_number)

    if tool_result.error_code == "NOT_FOUND":
        return not_found_message(incident_number)

    return lookup_failed_message(incident_number)


# ============================================================
# APPLICATION LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app):

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
