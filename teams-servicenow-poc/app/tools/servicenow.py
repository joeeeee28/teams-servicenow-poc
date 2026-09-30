"""
app/tools/servicenow.py — ServiceNow Tool Gateway (BL-005).

PURPOSE
───────
Provides a controlled business-operation boundary between identity/authorization
and the low-level ServiceNow transport adapter (app/servicenow.py).

The gateway guarantees:
  1. Typed Tool Action allowlisting (GET_INCIDENT, CREATE_INCIDENT, UPDATE_INCIDENT,
     SEARCH_CATALOG).
  2. Typed request contract validation (rejects arbitrary fields, scripts, table names).
  3. Strict authorization enforcement (consumes app.security.authorization.authorize()).
  4. Action matching (prevents authorization/tool action mismatch).
  5. Safe error handling (never exposes OAuth tokens, headers, stack traces, or internal details).
  6. DEMO-02: classified ServiceNow failures (``ServiceNowErrorCategory``) with
     fixed user-facing messages, and ``outcome_unknown`` when a create/update
     may have been applied but could not be confirmed.  Nothing is retried.
  7. DEMO-05: read-only SEARCH_CATALOG over the approved service catalog
     (a ``CatalogRepository``; authorized as READ_KNOWLEDGE; nothing is
     requested or changed).
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from app.audit import (
    AuditEventType,
    AuditLogger,
    audit_logger as _default_audit_logger,
    safe_incident_number,
    safe_ref,
)
import app.observability as _obs
from app.security.authorization import AuthorizableAction, AuthorizationDecision
from app.security.identity import UserIdentity
from app.catalog import (
    CatalogRepository,
    CatalogSearchRequest,
    CatalogSearchResult,
    CatalogService,
    CatalogUnavailableError,
    LocalCatalogRepository,
)
from app.servicenow import (
    ServiceNowClient,
    ServiceNowError,
    ServiceNowNotFound,
    catalog_sys_ids_from_env,
)
from app.servicenow_errors import ServiceNowErrorCategory, failure_message

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
    SEARCH_CATALOG = "search_catalog"      # DEMO-05, read-only
    CREATE_REQUEST = "create_request"      # DEMO-06, service request creation


# Mapping from ServiceNowToolAction to the required AuthorizableAction
_ACTION_MAPPING: dict[ServiceNowToolAction, AuthorizableAction] = {
    ServiceNowToolAction.GET_INCIDENT: AuthorizableAction.READ_INCIDENT,
    ServiceNowToolAction.CREATE_INCIDENT: AuthorizableAction.CREATE_INCIDENT,
    ServiceNowToolAction.UPDATE_INCIDENT: AuthorizableAction.UPDATE_INCIDENT,
    ServiceNowToolAction.SEARCH_CATALOG: AuthorizableAction.READ_KNOWLEDGE,
    ServiceNowToolAction.CREATE_REQUEST: AuthorizableAction.CREATE_REQUEST,
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


class ToolServiceNowError(ToolGatewayError):
    """
    DEMO-02: a classified ServiceNow failure.  ``error_code`` is the category
    value; ``message`` is the fixed user-facing text for it.
    """

    def __init__(
        self,
        category: ServiceNowErrorCategory,
        message: str,
        *,
        outcome_unknown: bool = False,
    ):
        super().__init__(message, error_code=category.value)
        self.category = category
        self.outcome_unknown = outcome_unknown


def _servicenow_failure(exc: ServiceNowError, *, operation: str,
                        incident_number: Optional[str] = None) -> Optional[ToolServiceNowError]:
    """Map a classified transport failure to a gateway error (None if unclassified)."""
    category = getattr(exc, "category", None)
    if not isinstance(category, ServiceNowErrorCategory):
        return None
    possibly_applied = operation != "read" and bool(getattr(exc, "possibly_applied", False))
    return ToolServiceNowError(
        category,
        failure_message(category, operation=operation, possibly_applied=possibly_applied,
                        incident_number=incident_number),
        outcome_unknown=possibly_applied,
    )


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


@dataclass(frozen=True)
class SearchCatalogToolRequest:
    """
    Request contract for SEARCH_CATALOG (DEMO-05).  Only free search words:
    no table, field, query, sys_id or catalog id can be supplied.
    """

    query: str
    max_results: int = 5

    def validate(self) -> CatalogSearchRequest:
        if not isinstance(self.query, str):
            raise ToolValidationError("Catalog search must be text.")
        try:
            return CatalogSearchRequest(self.query, max_results=self.max_results)
        except ValueError:
            raise ToolValidationError("Catalog search request is invalid.") from None

    def __repr__(self) -> str:  # never echo user text into logs
        return f"SearchCatalogToolRequest(max_results={self.max_results!r})"


_SYS_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# A ServiceNow request number; anything else (e.g. a sys_id) is never shown.
_REQUEST_NUMBER_RE = re.compile(r"^REQ[0-9]{7,10}$")
_VARIABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")


@dataclass(frozen=True)
class CreateRequestToolRequest:
    """
    Request contract for CREATE_REQUEST (DEMO-06).

    Fields
    ──────
    sys_id : str
        ServiceNow 32-character hex catalog item identifier.
    variables : dict[str, str]
        Dictionary of variable names and string values.
    """

    sys_id: str
    variables: dict[str, str]

    def validate(self) -> None:
        if not isinstance(self.sys_id, str) or not _SYS_ID_RE.fullmatch(self.sys_id):
            raise ToolValidationError("Catalog item sys_id must be 32 lower-case hex characters.")
        if not isinstance(self.variables, dict):
            raise ToolValidationError("Variables must be a dictionary.")
        for k, v in self.variables.items():
            if not isinstance(k, str) or not _VARIABLE_NAME_RE.fullmatch(k):
                raise ToolValidationError(f"Invalid variable name: {k!r}")
            if not isinstance(v, str):
                raise ToolValidationError(f"Variable value for {k!r} must be a string.")

    def __repr__(self) -> str:
        return f"CreateRequestToolRequest(item_ref=***, variables_count={len(self.variables)})"


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
    outcome_unknown: bool = False
    """DEMO-02: True when a create/update may have been applied but could not
    be confirmed.  Such a result is still a failure — never a success."""
    catalog: Optional[CatalogSearchResult] = None
    """DEMO-05: display-safe catalog search result (SEARCH_CATALOG only)."""
    request_number: Optional[str] = None
    """DEMO-06: ServiceNow request/RITM number (CREATE_REQUEST only)."""

    @classmethod
    def ok(
        cls,
        action: ServiceNowToolAction,
        safe_message: str,
        incident_number: Optional[str] = None,
        incident: Optional[dict[str, Any]] = None,
        catalog: Optional[CatalogSearchResult] = None,
        request_number: Optional[str] = None,
    ) -> ToolResult:
        """Construct a successful ToolResult."""
        return cls(
            success=True,
            action=action,
            incident_number=incident_number,
            incident=incident,
            safe_message=safe_message,
            error_code=None,
            catalog=catalog,
            request_number=request_number,
        )

    @classmethod
    def fail(
        cls,
        action: ServiceNowToolAction,
        safe_message: str,
        error_code: str,
        outcome_unknown: bool = False,
    ) -> ToolResult:
        """Construct a failed ToolResult."""
        return cls(
            success=False,
            action=action,
            incident_number=None,
            incident=None,
            safe_message=safe_message,
            error_code=error_code,
            outcome_unknown=outcome_unknown,
        )


def _failure_outcome(error_code: Optional[str]):
    """BL-011 outcome for a failed tool result."""
    if error_code == "AUTHORIZATION_DENIED":
        return _obs.ObsOutcome.DENIED
    if error_code == "VALIDATION_ERROR":
        return _obs.ObsOutcome.REJECTED
    return _obs.ObsOutcome.FAILED


def _obs_error_code(error_code: Optional[str], outcome_unknown: bool) -> str:
    """BL-011 error_code: the failure category, ``_unconfirmed`` if a write may have applied."""
    code = (error_code or "execution_error").lower()
    return code + "_unconfirmed" if outcome_unknown else code


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

    def __init__(
        self,
        client: Optional[ServiceNowClient] = None,
        audit_logger: Optional[AuditLogger] = None,
        catalog: Optional[CatalogRepository] = None,
    ) -> None:
        """
        Initialize the Tool Gateway.

        Parameters
        ----------
        client: Optional[ServiceNowClient]
            ServiceNow adapter instance. If None, lazy-initializes on execution.
        audit_logger: Optional[AuditLogger]
            BL-010 audit sink for gateway rejections (default: app audit logger).
        """
        self._client = client
        self._audit = audit_logger or _default_audit_logger
        self._catalog = catalog

    def _get_catalog(self) -> CatalogService:
        """The approved catalog behind SEARCH_CATALOG (POC: local fixture)."""
        if self._catalog is None:
            self._catalog = LocalCatalogRepository.from_fixture(catalog_sys_ids_from_env())
        return CatalogService(self._catalog)

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
        Execute a tool operation (see ``_execute``), observed by BL-011:
        ``tool_started`` then ``tool_completed`` / ``tool_failed`` with the
        duration.  Observation is passive — the result (or raised error) is
        exactly what ``_execute`` produced.
        """
        started = time.monotonic()
        self._observe_tool(_obs.ObsEventName.TOOL_STARTED, _obs.ObsOutcome.STARTED,
                           identity, tool_action, correlation_id)
        try:
            result = await self._execute(
                identity, authorization_decision, tool_action, request,
                raise_on_error=raise_on_error, correlation_id=correlation_id,
            )
        except ToolGatewayError as err:
            self._observe_tool(_obs.ObsEventName.TOOL_FAILED, _failure_outcome(err.error_code),
                               identity, tool_action, correlation_id,
                               error_code=_obs_error_code(err.error_code,
                                                          getattr(err, "outcome_unknown", False)),
                               duration_ms=_obs.elapsed_ms(started))
            raise
        if result.success:
            extra = {"result_count": len(result.catalog.entries)} if result.catalog else {}
            self._observe_tool(_obs.ObsEventName.TOOL_COMPLETED, _obs.ObsOutcome.SUCCESS,
                               identity, tool_action, correlation_id,
                               duration_ms=_obs.elapsed_ms(started), **extra)
        else:
            self._observe_tool(_obs.ObsEventName.TOOL_FAILED, _failure_outcome(result.error_code),
                               identity, tool_action, correlation_id,
                               error_code=_obs_error_code(result.error_code, result.outcome_unknown),
                               duration_ms=_obs.elapsed_ms(started))
        return result

    @staticmethod
    def _observe_tool(event_name, outcome, identity, tool_action, correlation_id, **fields) -> None:
        known_tool = isinstance(tool_action, ServiceNowToolAction)
        is_identity = isinstance(identity, UserIdentity)
        _obs.observability.record(
            event_name,
            _obs.ObsComponent.TOOL_GATEWAY,
            outcome,
            correlation_id=correlation_id,
            action=_ACTION_MAPPING.get(tool_action) if known_tool else None,
            operation=tool_action.value if known_tool else None,
            user_ref=_obs.user_ref(identity.user_id, identity.tenant_id) if is_identity else None,
            **fields,
        )

    async def _execute(
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

            elif tool_action is ServiceNowToolAction.SEARCH_CATALOG:
                return await self._execute_search_catalog(identity, request)

            elif tool_action is ServiceNowToolAction.CREATE_REQUEST:
                return await self._execute_create_request(identity, request)

            else:
                raise ToolValidationError(f"Unsupported tool action: {tool_action!r}")

        except ToolGatewayError as err:
            logger.warning("gateway error: action=%r code=%r message=%r", tool_action, err.error_code, err.message)
            self._audit_rejection(err, identity, tool_action, request, correlation_id)
            if raise_on_error:
                raise
            return ToolResult.fail(
                action=tool_action if isinstance(tool_action, ServiceNowToolAction) else ServiceNowToolAction.GET_INCIDENT,
                safe_message=err.message,
                error_code=err.error_code,
                outcome_unknown=getattr(err, "outcome_unknown", False),
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

    def _audit_rejection(
        self,
        err: "ToolGatewayError",
        identity: Any,
        tool_action: Any,
        request: Any,
        correlation_id: Optional[str],
    ) -> None:
        """
        BL-010: record a request the gateway itself refused.  Observation only
        — the rejection has already been decided and is returned unchanged.
        NOT_FOUND / EXECUTION_ERROR are execution failures, audited by the
        caller that owns the operation.
        """
        if err.error_code == "AUTHORIZATION_DENIED":
            event_type = AuditEventType.AUTHORIZATION_DENIED
            reason = "authorization_denied"
        elif err.error_code == "VALIDATION_ERROR":
            event_type = AuditEventType.TOOL_EXECUTION_REJECTED
            reason = "validation_error"
        else:
            return
        known_tool = isinstance(tool_action, ServiceNowToolAction)
        if not known_tool:
            reason = "invalid_tool_action"
        is_identity = isinstance(identity, UserIdentity)
        self._audit.record(
            event_type,
            correlation_id=safe_ref(correlation_id),
            action=_ACTION_MAPPING.get(tool_action) if known_tool else None,
            tool=tool_action.value if known_tool else None,
            user_id=safe_ref(identity.user_id) if is_identity else None,
            tenant_id=safe_ref(identity.tenant_id) if is_identity else None,
            incident_number=safe_incident_number(getattr(request, "incident_number", None)),
            reason=reason,
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
            raise (_servicenow_failure(exc, operation="read", incident_number=normalised_num)
                   or ToolExecutionError("Failed to retrieve incident from ServiceNow.")) from None

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
            # Never retried: a create is not idempotent.
            raise (_servicenow_failure(exc, operation="create")
                   or ToolExecutionError("Failed to create incident in ServiceNow.")) from None

    async def _execute_search_catalog(
        self,
        identity: UserIdentity,
        request: Any,
    ) -> ToolResult:
        """Execute SEARCH_CATALOG (DEMO-05): read-only, no ServiceNow write."""
        if not isinstance(request, SearchCatalogToolRequest):
            raise ToolValidationError("Request must be an instance of SearchCatalogToolRequest.")
        search = request.validate()
        try:
            result = await self._get_catalog().search(search)
        except CatalogUnavailableError:
            raise ToolExecutionError("The service catalog is temporarily unavailable.") from None
        return ToolResult.ok(
            action=ServiceNowToolAction.SEARCH_CATALOG,
            safe_message="Catalog searched.",
            catalog=result,
        )

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
            # Never retried: a repeated update could apply twice.
            raise (_servicenow_failure(exc, operation="update", incident_number=normalised_num)
                   or ToolExecutionError("Failed to update incident in ServiceNow.")) from None

    async def _execute_create_request(
        self,
        identity: UserIdentity,
        request: Any,
    ) -> ToolResult:
        """Execute CREATE_REQUEST tool operation."""
        if not isinstance(request, CreateRequestToolRequest):
            raise ToolValidationError("Request must be an instance of CreateRequestToolRequest.")

        request.validate()
        client = self._get_client()

        try:
            result = await client.create_service_request(
                sys_id=request.sys_id,
                variables=request.variables,
            )
            # Only a real REQ number is ever reported; a missing or malformed
            # number is reported as missing — never invented, never a sys_id.
            req_num = next((
                value for value in (result.get("number"), result.get("request_number"))
                if isinstance(value, str) and _REQUEST_NUMBER_RE.fullmatch(value.strip().upper())
            ), None)
            req_num = req_num.strip().upper() if req_num else None
            return ToolResult.ok(
                action=ServiceNowToolAction.CREATE_REQUEST,
                safe_message=(f"Request {req_num} created successfully." if req_num
                              else "ServiceNow reported the request as created without a "
                                   "request number."),
                request_number=req_num,
                incident=result,
            )
        except ServiceNowError as exc:
            # Never retried: a request creation is not idempotent.
            raise (_servicenow_failure(exc, operation="create_request")
                   or ToolExecutionError("Failed to create request in ServiceNow.")) from None
