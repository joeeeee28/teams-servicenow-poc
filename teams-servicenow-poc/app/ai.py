import json
import logging
import os

from ollama import AsyncClient

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ============================================================
# OLLAMA CONFIGURATION
# ============================================================

_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gpt-oss:20b")

# Module-level async client — reused across requests.
_ollama = AsyncClient(host=_OLLAMA_HOST)


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are an AI Service Desk Assistant inside Microsoft Teams.

Classify the user's message into exactly ONE of these intents:

- diagnose
- find_solution
- create_incident
- incident_status
- service_request
- human_escalation
- general

Return ONLY valid JSON in this format:

{
  "intent": "one_allowed_intent",
  "summary": "short summary of the user's request"
}

Classification rules:

diagnose:
The user reports a technical problem or something that is not working.

Examples:
"My VPN is not connecting."
"My laptop is very slow."
"Outlook keeps crashing."
"I cannot connect to Wi-Fi."

find_solution:
The user explicitly asks how to solve, configure, or perform something.

Examples:
"How do I reset my password?"
"How can I configure Outlook?"
"How do I connect to the VPN?"

create_incident:
The user explicitly asks to create, report, log, or raise an incident.

Examples:
"Create an incident for my VPN issue."
"Please raise a ticket."
"Log this issue with IT."
"Report this as an incident."

incident_status:
The user asks about an existing incident.

Examples:
"What is the status of INC0010002?"
"Check my incident."
"Has my ticket been resolved?"

service_request:
The user wants to request an IT service, access, software, hardware,
permission, or other catalog item.

Examples:
"I need SharePoint access."
"Request Adobe installation."
"I need a new laptop."
"Give me access to the finance application."

human_escalation:
The user explicitly wants to speak to or contact IT/helpdesk/support.

Examples:
"I want to talk to IT."
"Connect me to the helpdesk."
"I need a human."

general:
Greetings, casual conversation, or unrelated requests.

IMPORTANT:

A user reporting a problem does NOT automatically mean they want an incident.

For example:

"My VPN is not connecting."

MUST be classified as:

"diagnose"

Only classify as "create_incident" when the user explicitly asks
to create, raise, report, log, or submit an incident.

Do not invent incident numbers.

Do not invent ServiceNow information.

Return ONLY JSON.
"""


# ============================================================
# MESSAGE CLASSIFIER
# ============================================================

_ALLOWED_INTENTS = {
    "diagnose",
    "find_solution",
    "create_incident",
    "incident_status",
    "service_request",
    "human_escalation",
    "general",
}


async def classify_message(message: str) -> dict:
    """
    Classify a Teams user message into one of the allowed intents.

    Uses the Ollama AsyncClient so that the FastAPI event loop is
    never blocked.  Invalid or empty JSON responses are handled
    gracefully: a warning is logged and the intent falls back to
    'general' rather than raising an exception.
    """

    response = await _ollama.chat(
        model=_OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": message,
            },
        ],
        format="json",
    )

    content = response.message.content

    # --------------------------------------------------------
    # Safe JSON parsing — fall back to 'general' on any failure
    # --------------------------------------------------------

    result: dict = {}

    if not content or not content.strip():
        logger.warning(
            "Ollama returned an empty response for message classification; "
            "falling back to intent='general'."
        )
    else:
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            logger.warning(
                "Ollama returned non-JSON content for message classification; "
                "falling back to intent='general'. Raw content length: %d",
                len(content),
            )

    # --------------------------------------------------------
    # Validate and sanitise the parsed result
    # --------------------------------------------------------

    intent = result.get("intent")

    if intent not in _ALLOWED_INTENTS:
        intent = "general"

    summary = result.get("summary") or message

    # ServiceNow access is determined by application logic,
    # NOT by the LLM.
    needs_service_now = intent in {
        "create_incident",
        "incident_status",
        "service_request",
    }

    return {
        "intent": intent,
        "summary": summary,
        "needs_service_now": needs_service_now,
    }
