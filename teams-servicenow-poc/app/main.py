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
from app.security.authorization import AuthorizableAction, authorize
from app.security.identity import ANONYMOUS, resolve_identity
from app.tools import (
    CreateIncidentToolRequest,
    ServiceNowToolAction,
    ServiceNowToolGateway,
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
        # Handle follow-up questions during incident flow
        # ----------------------------------------------------

        if session.intent == "create_incident":

            lower_message = user_message.lower()

            if (
                "what details" in lower_message
                or "which details" in lower_message
                or "details do you need" in lower_message
                or "what information" in lower_message
                or "what do you need" in lower_message
            ):

                await context.send(
                    "🎫 To create the incident, I need a few details:\n\n"
                    "1. **What is the problem?**\n"
                    "2. **When did it start?**\n"
                    "3. **What error message are you seeing?**\n"
                    "4. **What troubleshooting have you already tried?**\n"
                    "5. **Is the issue affecting only you or multiple users?**\n\n"
                    "You can provide the details in one message."
                )

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
                # ── BL-004: resolve identity and authorize before EXECUTING ──
                # BL-005 will call authorize() here and then invoke the tool.
                # Identity is resolved from the same activity the message
                # arrived on; Teams authentication has already validated it.
                _identity = resolve_identity(
                    context.activity,
                    channel_tenant_id=(
                        (getattr(context.activity, "channel_data", None) or {})
                        .get("tenant", {}).get("id", "")
                    ),
                )
                _authz = authorize(
                    _identity,
                    AuthorizableAction.CREATE_INCIDENT,
                )

                if not _authz.allowed:
                    logger.warning(
                        "authorization denied for user=%r action=%r",
                        _identity.user_id,
                        AuthorizableAction.CREATE_INCIDENT.value,
                    )
                    await context.send(
                        "⛔ You are not authorised to perform this action.\n\n"
                        "Please contact your IT administrator if you believe "
                        "this is incorrect."
                    )
                    return

                # Transition to EXECUTING phase.
                session.transition_to(ConversationPhase.EXECUTING)
                save_session(user_id, session)

                # ── BL-005: Execute via ServiceNow Tool Gateway ────────────────
                tool_request = CreateIncidentToolRequest(
                    short_description=session.summary or "Service Desk Incident Request",
                    description=session.collected_details.get("description", session.summary or ""),
                    impact=session.collected_details.get("impact", "3"),
                    urgency=session.collected_details.get("urgency", "3"),
                )
                tool_result = await servicenow_gateway.execute(
                    _identity,
                    _authz,
                    ServiceNowToolAction.CREATE_INCIDENT,
                    tool_request,
                )

                if tool_result.success:
                    session.incident_number = tool_result.incident_number
                    session.transition_to(ConversationPhase.COMPLETED)
                    save_session(user_id, session)

                    await context.send(
                        f"✅ Incident **{tool_result.incident_number}** has been "
                        f"created successfully.\n\n"
                        f"**Summary:** {session.summary or ''}"
                    )
                else:
                    session.last_error = tool_result.safe_message
                    session.transition_to(ConversationPhase.FAILED)
                    save_session(user_id, session)

                    await context.send(
                        f"❌ Failed to create incident: {tool_result.safe_message}"
                    )
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

            # BL-003: drive the state machine based on current phase.
            session = get_session(user_id)

            if session.phase is ConversationPhase.IDLE:
                # Start collecting details.
                session.transition_to(ConversationPhase.COLLECTING)
                session.pending_action = "create_incident"
                save_session(user_id, session)

                response = (
                    f"🎫 I can help create an incident for:\n"
                    f"**{summary}**\n\n"
                    "Before I create it, I'll collect a few details.\n\n"
                    "Please tell me:\n"
                    "1. What is the problem?\n"
                    "2. When did it start?\n"
                    "3. What error message are you seeing?\n"
                    "4. What troubleshooting have you already tried?\n"
                    "5. Is the issue affecting only you or multiple users?"
                )

            elif session.phase is ConversationPhase.COLLECTING:
                # Details are arriving — move to confirmation.
                session.summary = summary
                session.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
                save_session(user_id, session)

                response = (
                    f"📋 Here is what I have for the incident:\n"
                    f"**{summary}**\n\n"
                    "Would you like me to submit this? "
                    "Reply **yes** to confirm or **cancel** to cancel."
                )

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
