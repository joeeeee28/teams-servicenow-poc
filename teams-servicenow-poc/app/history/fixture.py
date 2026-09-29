"""
app/history/fixture.py — Local POC historical cases (DEMO-04).

Synthetic, fictional records compiled into the application (no file,
database or network access).  They deliberately contain the kind of data a
real incident export would — caller names, e-mail addresses, phone numbers,
work notes, sys_ids, internal hostnames — to show that none of it can reach a
reply: only the controlled fields (case reference, category, symptom tag,
resolution code) are ever displayed.
"""

HISTORICAL_CASE_RECORDS = (
    # ── VPN ────────────────────────────────────────────────────────────────
    {
        "case_ref": "HC10001", "category": "network", "state": "closed", "eligible": True,
        "symptoms": ["vpn_disconnects"], "resolution": "reauthenticate",
        "description": "VPN drops every few minutes when working from home.",
        "resolution_notes": "User signed out of the VPN client and back in; stable since.",
        "private": {"incident_number": "INC0020101", "caller": "Alex Example",
                    "caller_email": "alex.example@example.com",
                    "work_notes": "Checked gateway vpn-gw02.corp.local 10.20.30.41",
                    "sys_id": "0a1b2c3d4e5f60718293a4b5c6d7e8f9"},
    },
    {
        "case_ref": "HC10002", "category": "network", "state": "resolved", "eligible": True,
        "symptoms": ["vpn_disconnects"], "resolution": "reauthenticate",
        "description": "VPN connection keeps dropping after laptop wakes from sleep.",
        "resolution_notes": "Re-authenticated the VPN session. Token had expired.",
        "private": {"incident_number": "INC0020102", "caller": "Sam Sample",
                    "phone": "+1 555 010 0142"},
    },
    {
        "case_ref": "HC10003", "category": "network", "state": "closed", "eligible": True,
        "symptoms": ["vpn_disconnects", "vpn_cannot_connect"], "resolution": "update_client",
        "description": "VPN disconnects and then will not reconnect on older client version.",
        "resolution_notes": "Updated VPN client to the current release.",
        "private": {"incident_number": "INC0020103"},
    },
    {
        "case_ref": "HC10004", "category": "network", "state": "closed", "eligible": True,
        "symptoms": ["vpn_cannot_connect"], "resolution": "reset_network",
        "description": "VPN cannot connect on hotel Wi-Fi.",
        "resolution_notes": "Reset network adapter and reconnected.",
        "private": {"incident_number": "INC0020104"},
    },
    {   # Open — never used as evidence.
        "case_ref": "HC10005", "category": "network", "state": "in_progress", "eligible": True,
        "symptoms": ["vpn_disconnects"], "resolution": None,
        "description": "VPN disconnects for the whole finance floor.",
        "private": {"incident_number": "INC0020105"},
    },
    {   # Resolved but NOT marked eligible (e.g. sensitive) — never used.
        "case_ref": "HC10006", "category": "network", "state": "closed", "eligible": False,
        "symptoms": ["vpn_disconnects"], "resolution": "service_fix",
        "description": "VPN disconnects during security investigation.",
        "private": {"incident_number": "INC0020106"},
    },
    # ── Outlook ────────────────────────────────────────────────────────────
    {
        "case_ref": "HC10011", "category": "email", "state": "closed", "eligible": True,
        "symptoms": ["outlook_not_syncing"], "resolution": "rebuild_profile",
        "description": "Outlook stopped syncing, inbox stuck since Monday.",
        "resolution_notes": "Created a new Outlook profile; mail synced.",
        "private": {"incident_number": "INC0020111", "caller_email": "pat.demo@example.com"},
    },
    {
        "case_ref": "HC10012", "category": "email", "state": "resolved", "eligible": True,
        "symptoms": ["outlook_not_syncing"], "resolution": "restart_client",
        "description": "Outlook not receiving new email, shows disconnected.",
        "resolution_notes": "Closed and reopened Outlook; was set to work offline.",
        "private": {"incident_number": "INC0020112"},
    },
    {
        "case_ref": "HC10013", "category": "email", "state": "closed", "eligible": True,
        "symptoms": ["outlook_not_syncing"], "resolution": "service_fix",
        "description": "Outlook sync delays for many users.",
        "resolution_notes": "Mail service incident resolved by the provider.",
        "private": {"incident_number": "INC0020113"},
    },
    # ── Teams ──────────────────────────────────────────────────────────────
    {
        "case_ref": "HC10021", "category": "collaboration", "state": "closed", "eligible": True,
        "symptoms": ["teams_no_audio"], "resolution": "select_device",
        "description": "No sound in Teams meetings, microphone not detected.",
        "resolution_notes": "Selected the headset under Teams device settings.",
        "private": {"incident_number": "INC0020121"},
    },
    {
        "case_ref": "HC10022", "category": "collaboration", "state": "closed", "eligible": True,
        "symptoms": ["teams_sign_in"], "resolution": "reauthenticate",
        "description": "Teams keeps asking to sign in.",
        "resolution_notes": "Signed out and in again; cleared stale session.",
        "private": {"incident_number": "INC0020122"},
    },
    # ── Identity ───────────────────────────────────────────────────────────
    {
        "case_ref": "HC10031", "category": "identity", "state": "closed", "eligible": True,
        "symptoms": ["mfa_no_prompt"], "resolution": "reregister_mfa",
        "description": "MFA push notification never arrives on new phone.",
        "resolution_notes": "Re-registered the authenticator app on the new device.",
        "private": {"incident_number": "INC0020131", "phone": "+44 20 7946 0000"},
    },
    {
        "case_ref": "HC10032", "category": "identity", "state": "resolved", "eligible": True,
        "symptoms": ["mfa_code_rejected"], "resolution": "sync_device_time",
        "description": "MFA verification code rejected every time.",
        "resolution_notes": "Phone clock was wrong; enabled automatic time.",
        "private": {"incident_number": "INC0020132"},
    },
    {
        "case_ref": "HC10033", "category": "identity", "state": "closed", "eligible": True,
        "symptoms": ["account_locked"], "resolution": "password_reset",
        "description": "Account locked out after password change.",
        "resolution_notes": "User completed self-service password reset.",
        "private": {"incident_number": "INC0020133",
                    "work_notes": "temporary password was Winter-2026! (rotated)"},
    },
    # ── Hardware ───────────────────────────────────────────────────────────
    {
        "case_ref": "HC10041", "category": "hardware", "state": "closed", "eligible": True,
        "symptoms": ["printer_offline"], "resolution": "replace_hardware",
        "description": "Floor printer offline, network card failed.",
        "resolution_notes": "Replaced network card on printer PRN-07.",
        "private": {"incident_number": "INC0020141"},
    },
)
