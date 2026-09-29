"""
app/security/identity.py — Teams user identity representation (BL-004).

PURPOSE
───────
Provides a typed, stable identity representation for a Teams user whose
authenticity has already been established by the Microsoft Bot Framework /
Teams authentication layer.

This module deliberately does NOT:
  - perform JWT validation (Teams already does this)
  - make network calls to Microsoft Graph or Entra
  - call ServiceNow
  - read credentials or environment variables
  - store personally identifiable information beyond what is necessary

STABLE IDENTITY PRINCIPLE
──────────────────────────
The preferred identifier is the AAD Object ID (``aad_object_id``), which is
stable across name changes, email changes, and UPN changes.

Display name and email are optional — they exist only for human-readable
logging purposes and MUST NOT be used for authorization decisions.

TENANT BOUNDARY
────────────────
The ``tenant_id`` field carries the Azure AD tenant that was asserted by the
Bot Framework during message delivery.  Authorization code uses this to
enforce tenant isolation.

SECURITY
────────
No tokens, authorization headers, or raw activity payloads are logged.
Only the resolved ``user_id`` (stable identifier), ``source``, and
``tenant_id`` may appear in logs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ===========================================================================
# Identity source enum
# ===========================================================================

class IdentitySource(str, Enum):
    """
    Describes how the identity was extracted from the Teams activity.

    This is purely informational and must not be used to grant elevated
    privileges.
    """

    AAD_OBJECT_ID = "aad_object_id"
    """
    Extracted from ``activity.from_.aad_object_id`` — the most stable
    and preferred identifier.
    """

    CHANNEL_ID = "channel_id"
    """
    Extracted from ``activity.from_.id`` — the channel-scoped user ID.
    Less stable than AAD Object ID; used as fallback.
    """

    UNKNOWN = "unknown"
    """
    Could not extract a reliable identifier from the activity.
    Any ``UserIdentity`` with this source must be treated as unauthenticated.
    """


# ===========================================================================
# User identity dataclass
# ===========================================================================

@dataclass(frozen=True)
class UserIdentity:
    """
    Immutable representation of an authenticated Teams user.

    Fields
    ──────
    user_id : str
        Stable, unique identifier for the user within the tenant.
        Derived from ``aad_object_id`` when available, otherwise from the
        Bot Framework channel-scoped ``id``.

    tenant_id : str
        Azure AD tenant ID asserted by the Bot Framework.  Used to enforce
        tenant isolation.  Empty string means unknown/unverifiable.

    display_name : str | None
        Optional human-readable name for logging only.
        MUST NOT be used for authorization decisions.

    email : str | None
        Optional email address for logging only.
        MUST NOT be used for authorization decisions.

    source : IdentitySource
        How the user_id was derived.  Informational only.

    Security notes
    ──────────────
    - ``display_name`` and ``email`` are excluded from ``__repr__`` to
      prevent accidental PII leakage in logs.
    - Only ``user_id`` and ``source`` appear in the default repr.
    - An identity with ``source=UNKNOWN`` or empty ``user_id``/``tenant_id``
      must be denied by the authorization layer.
    """

    user_id: str
    tenant_id: str
    display_name: Optional[str]
    email: Optional[str]
    source: IdentitySource

    def __repr__(self) -> str:
        # Deliberately omit display_name and email to avoid PII in logs.
        return (
            f"UserIdentity("
            f"user_id={self.user_id!r}, "
            f"tenant_id={self.tenant_id!r}, "
            f"source={self.source.value!r})"
        )

    @property
    def is_identified(self) -> bool:
        """
        ``True`` when the identity is considered reliably established:
          - ``user_id`` is non-empty
          - ``tenant_id`` is non-empty
          - ``source`` is not ``UNKNOWN``
        """
        return (
            bool(self.user_id)
            and bool(self.tenant_id)
            and self.source is not IdentitySource.UNKNOWN
        )


# ===========================================================================
# ANONYMOUS sentinel
# ===========================================================================

ANONYMOUS: UserIdentity = UserIdentity(
    user_id="",
    tenant_id="",
    display_name=None,
    email=None,
    source=IdentitySource.UNKNOWN,
)
"""
Sentinel value representing an unauthenticated or unresolvable user.
The authorization layer must deny all actions for ANONYMOUS.
"""


# ===========================================================================
# Identity resolver
# ===========================================================================

def resolve_identity(activity: Any, channel_tenant_id: str = "") -> UserIdentity:
    """
    Extract a ``UserIdentity`` from a Bot Framework activity object.

    This function consumes the identity information that the Teams/Bot
    Framework authentication layer has already validated.  It does NOT
    perform custom token validation.

    Parameters
    ----------
    activity:
        The Bot Framework activity object (``context.activity``).
        Attribute access is used throughout; missing attributes return None.

    channel_tenant_id:
        The tenant ID asserted by the Bot Framework channel data.
        Callers should pass ``activity.channel_data.get("tenant", {}).get("id")``
        or equivalent.  If omitted, the resolver attempts to extract it from
        the activity itself.

    Returns
    -------
    UserIdentity
        A typed identity.  Returns ``ANONYMOUS`` when no reliable identifier
        can be extracted.

    Security notes
    ──────────────
    - Does not log tokens, authorization headers, or activity payloads.
    - Returns ANONYMOUS rather than raising on missing data.
    """
    # ── Attempt to extract from_ (canonical attribute name) ──────────────────
    from_obj = (
        getattr(activity, "from_", None)
        or getattr(activity, "from_property", None)
    )

    if from_obj is None:
        logger.debug("identity_resolver: no from_ on activity — returning ANONYMOUS")
        return ANONYMOUS

    # ── Prefer AAD Object ID (most stable) ───────────────────────────────────
    aad_oid = getattr(from_obj, "aad_object_id", None)
    channel_id = getattr(from_obj, "id", None)

    if aad_oid:
        user_id = aad_oid
        source = IdentitySource.AAD_OBJECT_ID
    elif channel_id:
        user_id = channel_id
        source = IdentitySource.CHANNEL_ID
    else:
        logger.debug("identity_resolver: no user_id found — returning ANONYMOUS")
        return ANONYMOUS

    # ── Resolve tenant_id ────────────────────────────────────────────────────
    tenant_id = channel_tenant_id

    if not tenant_id:
        # Attempt to extract from channel_data dict.
        channel_data = getattr(activity, "channel_data", None) or {}
        if isinstance(channel_data, dict):
            tenant_id = (
                channel_data.get("tenant", {}).get("id", "")
                or ""
            )

    # ── Optional display fields (logging only) ───────────────────────────────
    display_name: Optional[str] = getattr(from_obj, "name", None)
    # Email is not typically present in Bot Framework activity; left as None.
    email: Optional[str] = None

    identity = UserIdentity(
        user_id=user_id,
        tenant_id=tenant_id,
        display_name=display_name,
        email=email,
        source=source,
    )

    logger.debug(
        "identity_resolver: resolved %r source=%r",
        user_id,
        source.value,
    )

    return identity
