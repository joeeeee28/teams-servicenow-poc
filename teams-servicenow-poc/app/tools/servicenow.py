"""
app/tools/servicenow.py — ServiceNow Tool Gateway (BL-005).

PURPOSE
───────
Provides a controlled business-operation boundary between identity/authorization
and the low-level ServiceNow transport adapter (app/servicenow.py).

The gateway guarantees:
  1. Typed Tool Action allowlisting (GET_INCIDENT, CREATE_INCIDENT, UPDATE_INCIDENT).
  2. Typed request contract validation (rejects arbitrary fields, scripts, table names).
  3. Strict authorization enforcement (consumes app.security.authorization.authorize()).
  4. Action matching (prevents authorization/tool action mismatch).
  5. Safe error handling (never exposes OAuth tokens, headers, stack traces, or internal details).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from app.security.authorization import AuthorizableAction, AuthorizationDecision
from app.security.identity import UserIdentity
from app.servicenow import ServiceNowClient, ServiceNowError, ServiceNowNotFound

logger = logging.getLogger(__name__)

# Strict Incident number regex: INC followed by 7 to 10 digits
_INCIDENT_NUMBER_RE = re.compile(r"^INC\d{7,10}$")

# Approved impact and urgency values. Must stay consistent with the
# established contract in app/models.py (pattern ^[1-3]$: 1=High, 2=Medium, 3=Low).
_VALID_IMPACT_URGENCY = frozenset({"1", "2", "3"})


# ===========================================================================
# Typed Tool Actions
# ===========================================================================

class ServiceNowToolAction(str, Enum):
    """
    Typed allowlist of executable ServiceNow tool actions.

    Only actions explicitly defined in this Enum can ever be executed by the
    gateway.  Arbitrary strings, table names, scripts, or HTTP methods are
    rejected at the gateway boundary.
    """

    GET_INCIDENT = "get_incident"
    CREATE_INCIDENT = "create_incident"
    UPDATE_INCIDENT = "update_incident"


# Mapping from ServiceNowToolAction to the required AuthorizableAction
_ACTION_MAPPING: dict[ServiceNowToolAction, AuthorizableAction] = {
    ServiceNowToolAction.GET_INCIDENT: AuthorizableAction.READ_INCIDENT,
    ServiceNowToolAction.CREATE_INCIDENT: AuthorizableAction.CREATE_INCIDENT,
    ServiceNowToolAction.UPDATE_INCIDENT: AuthorizableAction.UPDATE_INCIDENT,
}


# ===========================================================================
# Exceptions
# ===========================================================================

class ToolGatewayError(Exception):
    """Base exception for all ServiceNow Tool Gateway errors."""

    def __init__(self, message: str, error_code: str = "GATEWAY_ERROR"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ToolAuthorizationError(ToolGatewayError):
    """Raised when authorization is missing, denied, or mismatched."""

    def __init__(self, message: str = "Authorization check failed"):
        super().__init__(message, error_code="AUTHORIZATION_DENIED")


class ToolValidationError(ToolGatewayError):
    """Raised when request input fails validation or contract checking."""

    def __init__(self, message: str = "Request validation failed"):
        super().__init__(message, error_code="VALIDATION_ERROR")


class ToolNotFoundError(ToolGatewayError):
    """Raised when the target incident does not exist in ServiceNow."""

    def __init__(self, message: str = "The requested incident was not found"):
        super().__init__(message, error_code="NOT_FOUND")


class ToolExecutionError(ToolGatewayError):
    """Raised when ServiceNow execution fails at runtime."""

    def __init__(self, message: str = "ServiceNow execution failed"):
        super().__init__(message, error_code="EXECUTION_ERROR")


# ===========================================================================
# Typed Request Contracts
# ===========================================================================

@dataclass(frozen=True)
class GetIncidentToolRequest:
    """
    Request contract for GET_INCIDENT.

    Fields
    ──────
    incident_number : str
        ServiceNow incident number (e.g. INC0010002).
    """

    incident_number: str

    def validate(self) -> str:
        """
        Validate and return normalized incident_number.
        Raises ToolValidationError on format error.
        """
        if not self.incident_number or not isinstance(self.incident_number, str):
            raise ToolValidationError("Incident number must be a non-empty string.")

        normalised = self.incident_number.strip().upper()
        if not _INCIDENT_NUMBER_RE.fullmatch(normalised):
            raise ToolValidationError("Incident number must be INC followed by 7 to 10 digits.")
        return normalised


@dataclass(frozen=True)
class CreateIncidentToolRequest:
    """
    Request contract for CREATE_INCIDENT.

    Fields
    ──────
    short_description : str
        Brief summary of the issue.
    description : str
        Detailed description of the issue.
    impact : str
        Impact scale ("1" to "3", default "3").
    urgency : str
        Urgency scale ("1" to "3", default "3").
    """

    short_description: str
    description: str = ""
    impact: str = "3"
    urgency: str = "3"

    def validate(self) -> None:
        """
        Validate create incident fields.
        Raises ToolValidationError on invalid input.
        """
        if not self.short_description or not isinstance(self.short_description, str):
            raise ToolValidationError("Short description must be a non-empty string.")

        if len(self.short_description.strip()) == 0:
            raise ToolValidationError("Short description cannot be whitespace only.")

        if str(self.impact) not in _VALID_IMPACT_URGENCY:
            raise ToolValidationError(f"Impact must be one of {sorted(_VALID_IMPACT_URGENCY)}.")

        if str(self.urgency) not in _VALID_IMPACT_URGENCY:
            raise ToolValidationError(f"Urgency must be one of {sorted(_VALID_IMPACT_URGENCY)}.")


@dataclass(frozen=True)
class UpdateIncidentToolRequest:
    """
    Request contract for UPDATE_INCIDENT.

    Fields
    ──────
    incident_number : str
        Target incident number (e.g. INC0010002).
    short_description : Optional[str]
        Optional new short description.
    description : Optional[str]
        Optional new detailed description.
    impact : Optional[str]
        Optional new impact rating.
    urgency : Optional[str]
        Optional new urgency rating.
    """

    incident_number: str
    short_description: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    urgency: Optional[str] = None

    def validate(self) -> tuple[str, dict[str, Any]]:
        """
        Validate update request fields.
        Returns tuple of (normalised_incident_number, allowed_fields_dict).
        Raises ToolValidationError on invalid input.
        """
        if not self.incident_number or not isinstance(self.incident_number, str):
            raise ToolValidationError("Incident number must be a non-empty string.")

        normalised = self.incident_number.strip().upper()
        if not _INCIDENT_NUMBER_RE.fullmatch(normalised):
            raise ToolValidationError("Incident number must be INC followed by 7 to 10 digits.")

        fields: dict[str, Any] = {}
        if self.short_description is not None:
            if not isinstance(self.short_description, str) or len(self.short_description.strip()) == 0:
                raise ToolValidationError("Short description must be a non-empty string.")
            fields["short_description"] = self.short_description.strip()

        if self.description is not None:
            if not isinstance(self.description, str):
                raise ToolValidationError("Description must be a string.")
            fields["description"] = self.description

        if self.impact is not None:
            if str(self.impact) not in _VALID_IMPACT_URGENCY:
                raise ToolValidationError(f"Impact must be one of {sorted(_VALID_IMPACT_URGENCY)}.")
            fields["impact"] = str(self.impact)

        if self.urgency is not None:
            if str(self.urgency) not in _VALID_IMPACT_URGENCY:
                raise ToolValidationError(f"Urgency must be one of {sorted(_VALID_IMPACT_URGENCY)}.")
            fields["urgency"] = str(self.urgency)

        if not fields:
            raise ToolValidationError("At least one valid field must be provided for update.")

        return normalised, fields


# ===========================================================================
# Typed Tool Result
# ===========================================================================

@dataclass(frozen=True)
class ToolResult:
    """
    Typed, immutable result returned by ServiceNowToolGateway.execute().

    Fields
    ──────
    success : bool
        True if the tool operation completed successfully.
    action : ServiceNowToolAction
        The tool action that was evaluated.
    incident_number : Optional[str]
        The ServiceNow incident number (if applicable).
    incident : Optional[dict[str, Any]]
        The safe incident payload returned by ServiceNow (if applicable).
    safe_message : str
        Human-readable message suitable for returning to the user.
        Must NOT contain OAuth tokens, headers, credentials, or raw tracebacks.
    error_code : Optional[str]
        Machine-readable error code on failure (e.g. AUTHORIZATION_DENIED,
        VALIDATION_ERROR, NOT_FOUND, EXECUTION_ERROR).
    """

    success: bool
    action: ServiceNowToolAction
    incident_number: Optional[str] = None
    incident: Optional[dict[str, Any]] = None
    safe_message: str = ""
    error_code: Optional[str] = None

    @classmethod
    def ok(
        cls,
        action: ServiceNowToolAction,
        safe_message: str,
        incident_number: Optional[str] = None,
        incident: Optional[dict[str, Any]] = None,
    ) -> ToolResult:
        """Construct a successful ToolResult."""
        return cls(
            success=True,
            action=action,
            incident_number=incident_number,
            incident=incident,
            safe_message=safe_message,
            error_code=None,
        )

    @classmethod
    def fail(
        cls,
        action: ServiceNowToolAction,
        safe_message: str,
        error_code: str,
    ) -> ToolResult:
        """Construct a failed ToolResult."""
        return cls(
            success=False,
            action=action,
            incident_number=None,
            incident=None,
            safe_message=safe_message,
            error_code=error_code,
        )


# ===========================================================================
# ServiceNow Tool Gateway
# ===========================================================================

class ServiceNowToolGateway:
    """
    Gateway boundary for executing ServiceNow business operations.

    Requires:
      - Valid UserIdentity
      - Valid AuthorizationDecision (allowed=True)
      - Correct action mapping between AuthorizationDecision and ServiceNowToolAction
      - Typed request contract validation
    """

    def __init__(self, client: Optional[ServiceNowClient] = None) -> None:
        """
        Initialize the Tool Gateway.

        Parameters
        ----------
        client: Optional[ServiceNowClient]
            ServiceNow adapter instance. If None, lazy-initializes on execution.
        """
        self._client = client

    def _get_client(self) -> ServiceNowClient:
        """Get or initialize the underlying ServiceNowClient adapter."""
        if self._client is None:
            self._client = ServiceNowClient()
        return self._client

    async def execute(
        self,
        identity: UserIdentity,
        authorization_decision: AuthorizationDecision,
        tool_action: ServiceNowToolAction,
        request: Any,
        *,
        raise_on_error: bool = False,
        correlation_id: Optional[str] = None,
    ) -> ToolResult:
        """
        Execute a ServiceNow tool operation through the secure gateway boundary.

        Parameters
        ----------
        identity: UserIdentity
            Authenticated user identity resolved from Teams context.
        authorization_decision: AuthorizationDecision
            Evaluated decision from app.security.authorization.authorize().
        tool_action: ServiceNowToolAction
            The specific typed tool action being requested.
        request: Any
            Typed request contract (GetIncidentToolRequest, CreateIncidentToolRequest, etc.).
        raise_on_error: bool
            If True, raises typed ToolGatewayError subclass on failure instead of
            returning failure ToolResult.
        correlation_id: Optional[str]
            Optional correlation identifier for logging.

        Returns
        -------
        ToolResult
            Typed result containing success status, safe message, and data.
        """
        try:
            # ── Guard 1: Identity presence and authenticity ─────────────────────
            if identity is None or not isinstance(identity, UserIdentity) or not identity.is_identified:
                raise ToolAuthorizationError("Identity is missing, invalid, or unauthenticated.")

            # ── Guard 2: Authorization decision presence & allowed check ────────
            if (
                authorization_decision is None
                or not isinstance(authorization_decision, AuthorizationDecision)
                or not authorization_decision.allowed
            ):
                reason = authorization_decision.reason if authorization_decision else "Authorization decision missing"
                raise ToolAuthorizationError(f"Authorization denied: {reason}")

            # ── Guard 3: Tool action allowlisting ────────────────────────────────
            if not isinstance(tool_action, ServiceNowToolAction):
                raise ToolValidationError(f"Invalid or unallowlisted tool action: {tool_action!r}")

            # ── Guard 4: Action matching (Authorization vs Tool Action) ─────────
            required_authz_action = _ACTION_MAPPING.get(tool_action)
            if required_authz_action is None or authorization_decision.action != required_authz_action:
                logger.warning(
                    "gateway: action mismatch — authz_action=%r required=%r tool_action=%r user=%r",
                    getattr(authorization_decision, "action", None),
                    required_authz_action,
                    tool_action.value,
                    identity.user_id,
                )
                raise ToolAuthorizationError("Authorization decision does not match requested tool action.")

            # ── Guard 5: Dispatch by Tool Action with typed request validation ──
            if tool_action is ServiceNowToolAction.GET_INCIDENT:
                return await self._execute_get_incident(identity, request)

            elif tool_action is ServiceNowToolAction.CREATE_INCIDENT:
                return await self._execute_create_incident(identity, request)

            elif tool_action is ServiceNowToolAction.UPDATE_INCIDENT:
                return await self._execute_update_incident(identity, request)

            else:
                raise ToolValidationError(f"Unsupported tool action: {tool_action!r}")

        except ToolGatewayError as err:
            logger.warning("gateway error: action=%r code=%r message=%r", tool_action, err.error_code, err.message)
            if raise_on_error:
                raise
            return ToolResult.fail(
                action=tool_action if isinstance(tool_action, ServiceNowToolAction) else ServiceNowToolAction.GET_INCIDENT,
                safe_message=err.message,
                error_code=err.error_code,
            )

        except Exception as exc:
            logger.error("gateway unhandled exception: action=%r exc=%s", tool_action, exc)
            err = ToolExecutionError("A ServiceNow error occurred while executing the request.")
            if raise_on_error:
                raise err
            return ToolResult.fail(
                action=tool_action if isinstance(tool_action, ServiceNowToolAction) else ServiceNowToolAction.GET_INCIDENT,
                safe_message=err.message,
                error_code=err.error_code,
            )

    async def _execute_get_incident(
        self,
        identity: UserIdentity,
        request: Any,
    ) -> ToolResult:
        """Execute GET_INCIDENT tool operation."""
        if not isinstance(request, GetIncidentToolRequest):
            raise ToolValidationError("Request must be an instance of GetIncidentToolRequest.")

        normalised_num = request.validate()
        client = self._get_client()

        try:
            incident = await client.get_incident(normalised_num)
            return ToolResult.ok(
                action=ServiceNowToolAction.GET_INCIDENT,
                safe_message=f"Incident {incident.get('number', normalised_num)} retrieved successfully.",
                incident_number=incident.get("number", normalised_num),
                incident=incident,
            )
        except ServiceNowNotFound:
            raise ToolNotFoundError(f"Incident {normalised_num} was not found.")
        except ServiceNowError as exc:
            raise ToolExecutionError("Failed to retrieve incident from ServiceNow.") from exc

    async def _execute_create_incident(
        self,
        identity: UserIdentity,
        request: Any,
    ) -> ToolResult:
        """
        Execute CREATE_INCIDENT tool operation.

        Idempotency Note
        ────────────────
        CREATE_INCIDENT is a non-idempotent side effect. The gateway does NOT
        automatically retry failed create requests to prevent duplicate ticket
        creation.
        """
        if not isinstance(request, CreateIncidentToolRequest):
            raise ToolValidationError("Request must be an instance of CreateIncidentToolRequest.")

        request.validate()
        client = self._get_client()

        try:
            incident = await client.create_incident(
                short_description=request.short_description,
                description=request.description,
                impact=request.impact,
                urgency=request.urgency,
            )
            inc_number = incident.get("number", "")
            return ToolResult.ok(
                action=ServiceNowToolAction.CREATE_INCIDENT,
                safe_message=f"Incident {inc_number} created successfully.",
                incident_number=inc_number,
                incident=incident,
            )
        except ServiceNowError as exc:
            raise ToolExecutionError("Failed to create incident in ServiceNow.") from exc

    async def _execute_update_incident(
        self,
        identity: UserIdentity,
        request: Any,
    ) -> ToolResult:
        """Execute UPDATE_INCIDENT tool operation."""
        if not isinstance(request, UpdateIncidentToolRequest):
            raise ToolValidationError("Request must be an instance of UpdateIncidentToolRequest.")

        normalised_num, fields = request.validate()
        client = self._get_client()

        try:
            incident = await client.update_incident(
                incident_number=normalised_num,
                fields=fields,
            )
            inc_number = incident.get("number", normalised_num)
            return ToolResult.ok(
                action=ServiceNowToolAction.UPDATE_INCIDENT,
                safe_message=f"Incident {inc_number} updated successfully.",
                incident_number=inc_number,
                incident=incident,
            )
        except ServiceNowNotFound:
            raise ToolNotFoundError(f"Incident {normalised_num} was not found.")
        except ServiceNowError as exc:
            raise ToolExecutionError("Failed to update incident in ServiceNow.") from exc
