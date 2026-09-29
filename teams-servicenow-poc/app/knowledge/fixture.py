"""
app/knowledge/fixture.py — Local POC knowledge content (DEMO-03).

Plain Python records compiled into the application: no file, database or
network access.  Only ``approved`` articles are ever returned.  Some articles
deliberately carry internal notes, contact details or infrastructure details
so the demo shows sanitization removing them.
"""

SOURCE = "IT Knowledge Base"

KNOWLEDGE_RECORDS = (
    {
        "article_id": "KB0010001",
        "title": "VPN Connection Troubleshooting",
        "category": "network",
        "status": "approved",
        "source": SOURCE,
        "metadata": {"keywords": "vpn remote access connect connection tunnel home network",
                     "owner": "network-team", "last_reviewed": "Q3"},
        "body": (
            "Use these steps when the corporate VPN will not connect or keeps disconnecting.\n"
            "1. Check that your internet connection works by opening any public website.\n"
            "2. Quit the VPN client completely and start it again.\n"
            "3. Sign out of the VPN client and sign in again to re-authenticate.\n"
            "4. Reconnect to the corporate VPN profile.\n"
            "5. Restart your computer if the VPN still does not connect.\n"
            "Internal note: gateway vpn-gw01.corp.local (10.20.30.40) is the primary concentrator.\n"
            "If the problem continues, ask the assistant to create an incident."
        ),
    },
    {
        "article_id": "KB0010002",
        "title": "Reset Your Password or Unlock Your Account",
        "category": "identity",
        "status": "approved",
        "source": SOURCE,
        "metadata": {"keywords": "password reset forgot expired locked unlock account sign in login"},
        "body": (
            "Use self-service password reset when you have forgotten your password or your "
            "account is locked.\n"
            "1. Open the self-service password reset page from the company portal.\n"
            "2. Verify your identity with your registered authentication method.\n"
            "3. Choose a new password that meets the password policy.\n"
            "4. Sign in again on all your devices with the new password.\n"
            "Accounts unlock automatically after a successful reset.\n"
            "Work note: helpdesk override procedure is documented for agents only."
        ),
    },
    {
        "article_id": "KB0010003",
        "title": "Multi-Factor Authentication (MFA) Troubleshooting",
        "category": "identity",
        "status": "approved",
        "source": SOURCE,
        "metadata": {"keywords": "mfa multi factor authentication authenticator code "
                                 "verification prompt approve phone sign in login"},
        "body": (
            "Use these steps when MFA prompts do not arrive or verification codes are rejected.\n"
            "1. Make sure the date and time on your phone are set automatically.\n"
            "2. Open the authenticator app and check for pending sign-in requests.\n"
            "3. Use a verification code from the app instead of a push notification.\n"
            "4. If you replaced your phone, register the new device through the company portal.\n"
            "Contact the service desk at servicedesk@example.com or +1 555 010 0199 for help."
        ),
    },
    {
        "article_id": "KB0010004",
        "title": "Microsoft Teams Audio, Video and Sign-in Issues",
        "category": "collaboration",
        "status": "approved",
        "source": SOURCE,
        "metadata": {"keywords": "teams microsoft meeting audio microphone camera video "
                                 "sound call sign in crash"},
        "body": (
            "Use these steps when Microsoft Teams audio, video or sign-in is not working.\n"
            "1. In Teams, open Settings and then Devices, and select the correct microphone, "
            "speaker and camera.\n"
            "2. Close other applications that may be using the camera or microphone.\n"
            "3. Sign out of Teams, quit the application and sign in again.\n"
            "4. Check for Teams updates from the profile menu.\n"
            "5. Restart your computer if the device is still not detected."
        ),
    },
    {
        "article_id": "KB0010005",
        "title": "Outlook Not Syncing or Not Receiving Email",
        "category": "email",
        "status": "approved",
        "source": SOURCE,
        "metadata": {"keywords": "outlook email mail inbox sync syncing receive receiving "
                                 "send stuck offline mailbox"},
        "body": (
            "Use these steps when Outlook is not syncing, is offline, or email is not arriving.\n"
            "1. Check that Outlook is not set to Work Offline on the Send / Receive tab.\n"
            "2. Close Outlook completely and open it again.\n"
            "3. Check your mailbox size and delete or archive large items if it is full.\n"
            "4. Sign in to Outlook on the web to confirm whether new email is arriving.\n"
            "5. Restart your computer if Outlook still does not sync."
        ),
    },
    {
        "article_id": "KB0010006",
        "title": "How to Report an IT Issue and Track Your Incident",
        "category": "service_desk",
        "status": "approved",
        "source": SOURCE,
        "metadata": {"keywords": "incident ticket report raise log issue status track "
                                 "servicenow service desk"},
        "body": (
            "The service desk records IT issues as incidents in ServiceNow.\n"
            "1. Ask the assistant to create an incident and describe what is not working.\n"
            "2. Provide the impact and urgency when asked, then confirm the summary.\n"
            "3. Keep the incident number you receive, for example INC0010002.\n"
            "4. Ask the assistant for the status of your incident number at any time."
        ),
    },
    # Not approved — must never be returned.
    {
        "article_id": "KB0010090",
        "title": "VPN Split Tunnel Configuration (Draft)",
        "category": "network",
        "status": "draft",
        "source": SOURCE,
        "metadata": {"keywords": "vpn split tunnel configuration"},
        "body": "Draft content under review.\n1. Do not use: not yet approved.",
    },
    {
        "article_id": "KB0010091",
        "title": "Legacy Email Client Setup",
        "category": "email",
        "status": "retired",
        "source": SOURCE,
        "metadata": {"keywords": "outlook email legacy setup"},
        "body": "Retired article.\n1. Retired step.",
    },
)
