"""
app/catalog/fixture.py — Approved POC service catalog (DEMO-05).

Plain Python records compiled into the application (no file, database or
network access).  ``sys_id`` values are synthetic placeholders; a
ServiceNow-backed repository would supply real ones.  Only items that are
both ``active`` and ``approved`` can be returned; the last two records show
that inactive / unapproved items never appear.
"""

_JUSTIFICATION = {"name": "business_justification", "label": "Business justification"}
_DEPARTMENT = {"name": "department", "label": "Department"}
_DURATION = {"name": "license_duration", "label": "License duration", "kind": "choice",
             "choices": ["3 months", "6 months", "12 months"]}
_LOCATION = {"name": "delivery_location", "label": "Delivery location"}

CATALOG_RECORDS = (
    {
        "item_ref": "CAT0001", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c001",
        "name": "Microsoft Visio", "category": "software", "active": True, "approved": True,
        "description": "Diagramming software for flowcharts, network diagrams and org charts.",
        "keywords": "visio diagram diagramming flowchart drawing microsoft software license",
        # The mapped ServiceNow item has no catalog variables (verified live),
        # so nothing is collected: the request goes straight to confirmation.
        "variables": [],
    },
    {
        "item_ref": "CAT0002", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c002",
        "name": "Adobe Acrobat Pro", "category": "software", "active": True, "approved": True,
        "description": "Create, edit and sign PDF documents.",
        "keywords": "adobe acrobat pdf edit sign document software license",
        "variables": [_JUSTIFICATION, _DEPARTMENT, _DURATION],
    },
    {
        "item_ref": "CAT0003", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c003",
        "name": "Microsoft Project", "category": "software", "active": True, "approved": True,
        "description": "Project planning and scheduling software.",
        "keywords": "project planning schedule gantt microsoft software license",
        "variables": [_JUSTIFICATION, _DEPARTMENT, _DURATION],
    },
    {
        "item_ref": "CAT0004", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c004",
        "name": "VPN Remote Access", "category": "network", "active": True, "approved": True,
        "description": "Access to the corporate network from outside the office.",
        "keywords": "vpn remote access home network connect",
        "variables": [_JUSTIFICATION, {"name": "access_end_date", "label": "Access end date"}],
    },
    {
        "item_ref": "CAT0005", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c005",
        "name": "SharePoint Site Access", "category": "access", "active": True, "approved": True,
        "description": "Access to a team SharePoint site.",
        "keywords": "sharepoint site team access permission files",
        "variables": [{"name": "site_name", "label": "SharePoint site name"},
                      {"name": "access_level", "label": "Access level", "kind": "choice",
                       "choices": ["Read", "Edit"]},
                      _JUSTIFICATION],
    },
    {
        "item_ref": "CAT0006", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c006",
        "name": "Standard Laptop", "category": "hardware", "active": True, "approved": True,
        "description": "Standard business laptop with the corporate software image.",
        "keywords": "laptop computer notebook new replacement hardware",
        "variables": [_JUSTIFICATION, _LOCATION],
    },
    {
        "item_ref": "CAT0007", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c007",
        "name": "Additional Monitor", "category": "hardware", "active": True, "approved": True,
        "description": "An additional external monitor for your desk.",
        "keywords": "monitor screen display external second hardware",
        "variables": [_LOCATION, {"name": "notes", "label": "Notes", "required": False}],
    },
    # Never returned.
    {
        "item_ref": "CAT0090", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c090",
        "name": "Microsoft Visio 2013 (legacy)", "category": "software",
        "active": False, "approved": True,
        "description": "Retired version.", "keywords": "visio legacy",
    },
    {
        "item_ref": "CAT0091", "sys_id": "c0a8010e5d5f4c1b9e2f00000000c091",
        "name": "Personal Cloud Storage", "category": "software",
        "active": True, "approved": False,
        "description": "Not approved for company data.", "keywords": "cloud storage dropbox",
    },
)
