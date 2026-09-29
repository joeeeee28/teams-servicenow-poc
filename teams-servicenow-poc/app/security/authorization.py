"""
app/security/authorization.py — Deterministic authorization policy (BL-004).

PURPOSE
───────
Provides a deterministic, locally-evaluated authorization layer that sits
between the confirmation gate (BL-003) and the future ServiceNow tool
gateway (BL-005).

The layer answers ONE question:

    "Is this authenticated Teams user, in this tenant, allowed to perform
    this action?"

It does NOT:
  - call ServiceNow
  - call Microsoft Graph or Entra
  - call Teams APIs
  - make any network request
  - read credentials or environment variables
  - infer roles from user names, email prefixes, or LLM output
  - execute side effects

DESIGN PRINCIPLES
─────────────────
DEFAULT DENY
    Any unknown role, unknown action, missing identity, wrong tenant,
    or malformed input returns ``allowed=False``.  The system never
    fails open.

STABLE IDENTITY
    Authorization is keyed on ``UserIdentity.user_id`` (AAD Object ID or
    channel ID), not on display name, email, or LLM-produced text.

NO LLM AUTHORIZATION
    The LLM can propose an intent.  The LLM cannot grant, elevate, or
    bypass authorization.  Authorization is deterministic code only.

NO CREDENTIAL PROXY
    The ServiceNow OAuth credentials are backend service credentials.
    Their existence does not mean the end user is authorized.
    The authorization layer evaluates end-user permission independently.

TENANT ISOLATION
    A valid user from the wrong tenant is denied.  The allowed tenant is
    read from the ``TEAMS_TENANT_ID`` environment variable at call time.
    If the variable is unset, only requests that explicitly supply a
    matching tenant ID are allowed (fail-safe default).

FUTURE EXTENSION
─────────────────
``AuthorizationPolicy`` is an abstract base class.  A future implementation
backed by Entra groups, ServiceNow roles, or enterprise IAM can replace
``DefaultAuthorizationPolicy`` without changing the calling contract.

AUTHORIZATION MATRIX (POC)
──────────────────────────

Action               employee   service_desk_agent   service_desk_admin
──────────────────   ────────   ──────────────────   ──────────────────
READ_INCIDENT          ✓               ✓                    ✓
READ_KNOWLEDGE         ✓               ✓                    ✓
CREATE_INCIDENT        ✓               ✓                    ✓
CREATE_REQUEST         ✓               ✓                    ✓
ESCALATE               ✓               ✓                    ✓
UPDATE_INCIDENT                        ✓                    ✓
ADMIN_OVERRIDE                                              ✓

SECURITY
────────
No user message content, credentials, tokens, or policy internals are
written to log output.  Only user_id, action, and the allow/deny outcome
are logged at DEBUG level.
"""

from __future__ import annotations

import abc
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.security.identity import ANONYMOUS, IdentitySource, UserIdentity

logger = logging.getLogger(__name__)


# ===========================================================================
# Authorisable actions
# ===========================================================================

class AuthorizableAction(str, Enum):
    """
    Typed, closed set of actions that may be authorised.

    Only identifiers in this enum can ever be evaluated.  Arbitrary strings
    from user input, LLM output, or conversation content are NEVER accepted
    as authorisable actions.
    """

    READ_INCIDENT = "read_incident"
    """Read the details or status of an existing incident."""

    CREATE_INCIDENT = "create_incident"
    """Create a new ServiceNow incident."""

    UPDATE_INCIDENT = "update_incident"
    """Update fields on an existing incident.  Requires agent role."""

    READ_KNOWLEDGE = "read_knowledge"
    """Read knowledge base articles."""

    CREATE_REQUEST = "create_request"
    """Submit a service catalog request."""

    ESCALATE = "escalate"
    """Escalate an issue to a human IT support agent."""

    ADMIN_OVERRIDE = "admin_override"
    """
    Administrative override capability.
    Reserved for service_desk_admin role only.
    """


# ===========================================================================
# User roles
# ===========================================================================

class UserRole(str, Enum):
    """
    Roles that govern what a user is permitted to do.

    Roles are NOT inferred from user names, email prefixes, department
    text, or LLM output.  In this POC the default role for any identified
    user from the allowed tenant is ``EMPLOYEE``.  Future integration with
    Entra group membership or ServiceNow role assignments will replace the
    POC role assignment without changing the policy matrix.
    """

    EMPLOYEE = "employee"
    """
    Standard Teams user.  Can read incidents, create incidents, create
    service requests, read knowledge, and escalate.
    """

    SERVICE_DESK_AGENT = "service_desk_agent"
    """
    IT helpdesk agent.  All employee permissions plus the ability to update
    existing incidents.
    """

    SERVICE_DESK_ADMIN = "service_desk_admin"
    """
    IT helpdesk administrator.  All agent permissions plus administrative
    override capability.
    """


# ===========================================================================
# Authorization decision
# ===========================================================================

@dataclass(frozen=True)
class AuthorizationDecision:
    """
    Immutable result returned by :func:`authorize`.

    Fields
    ──────
    allowed : bool
        ``True`` when the identity is permitted to perform ``action``.
        ``False`` in all other cases (default deny).

    action : AuthorizableAction | None
        The action that was evaluated.  ``None`` when the request was
        malformed (e.g. unknown action string supplied).

    role : UserRole | None
        The role that was used in the evaluation.  ``None`` when the
        identity is denied before role lookup (e.g. wrong tenant, empty
        user_id).

    reason : str | None
        A short, safe-to-log explanation.  Must NOT expose internal policy
        details, user roles, or credentials.
    """

    allowed: bool
    action: Optional[AuthorizableAction]
    role: Optional[UserRole]
    reason: Optional[str]

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def permitted(
        cls,
        action: AuthorizableAction,
        role: UserRole,
    ) -> "AuthorizationDecision":
        """Return an allowed decision."""
        return cls(
            allowed=True,
            action=action,
            role=role,
            reason="Authorized.",
        )

    @classmethod
    def denied(
        cls,
        reason: str,
        action: Optional[AuthorizableAction] = None,
        role: Optional[UserRole] = None,
    ) -> "AuthorizationDecision":
        """
        Return a denied decision.

        The *reason* must be safe to log and must not expose internal policy
        details (e.g. which specific group membership is missing).
        """
        return cls(
            allowed=False,
            action=action,
            role=role,
            reason=reason,
        )


# ===========================================================================
# Policy matrix
# ===========================================================================

# Maps each role to the set of actions it is permitted to perform.
# This is the single source of truth for the authorization policy.
# Changes to the policy require a code change and review, NOT runtime config.
_POLICY_MATRIX: dict[UserRole, frozenset[AuthorizableAction]] = {
    UserRole.EMPLOYEE: frozenset(
        {
            AuthorizableAction.READ_INCIDENT,
            AuthorizableAction.READ_KNOWLEDGE,
            AuthorizableAction.CREATE_INCIDENT,
            AuthorizableAction.CREATE_REQUEST,
            AuthorizableAction.ESCALATE,
        }
    ),
    UserRole.SERVICE_DESK_AGENT: frozenset(
        {
            AuthorizableAction.READ_INCIDENT,
            AuthorizableAction.READ_KNOWLEDGE,
            AuthorizableAction.CREATE_INCIDENT,
            AuthorizableAction.CREATE_REQUEST,
            AuthorizableAction.ESCALATE,
            AuthorizableAction.UPDATE_INCIDENT,  # agent-only
        }
    ),
    UserRole.SERVICE_DESK_ADMIN: frozenset(
        {
            AuthorizableAction.READ_INCIDENT,
            AuthorizableAction.READ_KNOWLEDGE,
            AuthorizableAction.CREATE_INCIDENT,
            AuthorizableAction.CREATE_REQUEST,
            AuthorizableAction.ESCALATE,
            AuthorizableAction.UPDATE_INCIDENT,
            AuthorizableAction.ADMIN_OVERRIDE,   # admin-only
        }
    ),
}


# ===========================================================================
# Authorization policy abstraction
# ===========================================================================

class AuthorizationPolicy(abc.ABC):
    """
    Abstract authorization policy.

    Implementations evaluate whether a ``UserIdentity`` is permitted to
    perform an ``AuthorizableAction``.

    Concrete implementations can later be backed by:
    - Entra group membership (Microsoft Graph)
    - ServiceNow user roles
    - Enterprise IAM / RBAC databases

    Without changing the calling contract in ``authorize()``.
    """

    @abc.abstractmethod
    def resolve_role(self, identity: UserIdentity) -> Optional[UserRole]:
        """
        Resolve the authorisation role for *identity*.

        Returns ``None`` when no role can be assigned (the caller should
        then return ``denied``).

        Must NOT perform network calls in the default POC implementation.
        """

    @abc.abstractmethod
    def is_allowed(
        self,
        role: UserRole,
        action: AuthorizableAction,
    ) -> bool:
        """
        Return ``True`` if *role* is permitted to perform *action*.
        """


# ===========================================================================
# Default POC policy
# ===========================================================================

class DefaultAuthorizationPolicy(AuthorizationPolicy):
    """
    Deterministic, locally-evaluated authorization policy for the POC.

    Role resolution (POC):
        Every identified user from the allowed tenant is granted
        ``EMPLOYEE`` by default.  This is a conservative starting point;
        future work replaces this with Entra group lookup.

    Tenant check:
        The allowed tenant is read from the ``TEAMS_TENANT_ID`` environment
        variable.  A missing or blank env var causes the tenant check to
        fail safe (deny all).

    Policy matrix:
        Defined in ``_POLICY_MATRIX`` above.  Never modified at runtime.
    """

    def resolve_role(self, identity: UserIdentity) -> Optional[UserRole]:
        """
        Return ``EMPLOYEE`` for any identified user from the allowed tenant.

        In the POC, all authenticated users from the correct tenant are
        treated as employees.  Future implementation will replace this with
        Entra group membership lookup.

        Returns ``None`` when:
          - identity is ANONYMOUS
          - identity source is UNKNOWN
          - user_id is empty
          - tenant_id is empty or does not match the allowed tenant
        """
        if not identity.is_identified:
            return None
        if identity.user_id == ANONYMOUS.user_id:
            return None
        # Tenant check: read allowed tenant from env at call time.
        allowed_tenant = os.getenv("TEAMS_TENANT_ID", "").strip()
        if not allowed_tenant:
            # Env var unset → fail safe: deny all.
            logger.debug(
                "authorization: TEAMS_TENANT_ID is unset — denying all"
            )
            return None
        if identity.tenant_id != allowed_tenant:
            logger.debug(
                "authorization: tenant mismatch — identity tenant does not match allowed tenant"
            )
            return None
        return UserRole.EMPLOYEE

    def is_allowed(
        self,
        role: UserRole,
        action: AuthorizableAction,
    ) -> bool:
        """
        Check the static policy matrix.
        """
        permitted = _POLICY_MATRIX.get(role, frozenset())
        return action in permitted


# ===========================================================================
# Module-level default policy
# ===========================================================================

_default_policy: AuthorizationPolicy = DefaultAuthorizationPolicy()


# ===========================================================================
# Public authorize() function
# ===========================================================================

def authorize(
    identity: UserIdentity,
    action: AuthorizableAction,
    *,
    policy: Optional[AuthorizationPolicy] = None,
) -> AuthorizationDecision:
    """
    Determine whether *identity* is authorised to perform *action*.

    This is the single authorisation boundary that BL-005 must call before
    invoking any ServiceNow tool.

    Parameters
    ----------
    identity:
        The ``UserIdentity`` resolved from the Teams activity (BL-004).

    action:
        The ``AuthorizableAction`` being requested.  Only typed enum values
        are accepted; arbitrary strings cannot be passed here.

    policy:
        Optional ``AuthorizationPolicy`` override.  If ``None``, the module-
        level ``DefaultAuthorizationPolicy`` is used.  Intended for testing.

    Returns
    -------
    AuthorizationDecision
        Always returns a value — never raises.  ``allowed=False`` for any
        denial condition (default-deny).

    Security guarantees
    ────────────────────
    - Returns ``denied`` for any malformed input.
    - Returns ``denied`` when identity is ANONYMOUS or unidentified.
    - Returns ``denied`` when tenant does not match.
    - Returns ``denied`` when role is not in the policy matrix.
    - Returns ``denied`` when action is not permitted for the role.
    - Only the user_id hash and action name are logged (never tokens or PII).
    - Does NOT call ServiceNow, Graph, or any external API.
    """
    effective_policy = policy if policy is not None else _default_policy

    # ── Guard: identity must be provided ─────────────────────────────────────
    if identity is None or not identity.is_identified:
        logger.debug("authorization: denied — identity is missing or anonymous")
        return AuthorizationDecision.denied(
            "Identity is not established.",
            action=action,
        )

    # ── Guard: empty user_id or tenant_id ────────────────────────────────────
    if not identity.user_id or not identity.tenant_id:
        logger.debug("authorization: denied — user_id or tenant_id is empty")
        return AuthorizationDecision.denied(
            "Identity is incomplete.",
            action=action,
        )

    # ── Resolve role ──────────────────────────────────────────────────────────
    role = effective_policy.resolve_role(identity)
    if role is None:
        logger.debug(
            "authorization: denied — no role for user_id=%r",
            identity.user_id,
        )
        return AuthorizationDecision.denied(
            "Not authorized.",
            action=action,
        )

    # ── Check policy matrix ───────────────────────────────────────────────────
    if effective_policy.is_allowed(role, action):
        logger.debug(
            "authorization: allowed — role=%r action=%r",
            role.value,
            action.value,
        )
        return AuthorizationDecision.permitted(action=action, role=role)

    logger.debug(
        "authorization: denied — role=%r not permitted for action=%r",
        role.value,
        action.value,
    )
    return AuthorizationDecision.denied(
        "Not authorized.",
        action=action,
        role=role,
    )
