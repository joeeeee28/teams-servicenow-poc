"""
app/security — Identity and authorization primitives (BL-004).

Submodules
──────────
identity.py
    UserIdentity dataclass and resolve_identity() helper.
    Consumes identity information already validated by the Teams/Bot
    Framework layer.  Does not perform custom JWT validation.

authorization.py
    AuthorizableAction enum, UserRole enum, AuthorizationDecision value
    object, and the deterministic authorize() function.
    No network calls, no ServiceNow access, no credential reads.
"""
