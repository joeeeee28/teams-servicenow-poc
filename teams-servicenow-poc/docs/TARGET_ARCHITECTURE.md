# Target Architecture — Teams ServiceNow AI Service Desk Assistant

## Overview

This document describes the intended architecture of the Teams-ServiceNow
POC and is updated incrementally as each backlog item (BL-00x) is
implemented.

---

## Layers

```
Teams (Microsoft Bot Framework)
        │
        ▼
FastAPI (app/main.py)
        │
        ├─► Deterministic Router (app/router.py)   ← BL-001
        │           │
        │           └─ Returns RouteResult or None
        │
        ├─► AI Classifier (app/ai.py / Ollama)
        │
        ├─► Conversation State Machine (app/state.py)  ← BL-002
        │           │
        │           └─ ConversationState / InMemoryStateRepository
        │
        ├─► [BL-006] Incident Collection (app/incident_collection.py)
        │
        ├─► [BL-003] Confirmation / Side-effect Gate
        │
        ├─► [BL-004] Identity-aware Authorization
        │
        └─► [BL-005] ServiceNow Tool Gateway (app/servicenow.py)
```

---

## BL-001 — Deterministic Router

`app/router.py` provides `route_message(message: str) -> RouteResult | None`.

- Uses whole-message anchored patterns (`re.fullmatch`).
- Does **not** perform substring extraction; malicious surroundings are
  rejected.
- Is a pure synchronous function: no network, no ServiceNow, no credentials.
- Returns `None` if no deterministic route matches; the caller falls through
  to AI classification.

**Security note:** The router is not the security boundary. Independent
validation in `app/servicenow._validate_incident_number` always runs before
any ServiceNow operation.

---

## BL-002 — Conversation State Machine

`app/state.py` provides the typed conversation state machine.

### Phases

| Phase | Meaning |
|---|---|
| `IDLE` | No active workflow; waiting for a new user request. |
| `COLLECTING` | Gathering details from the user (e.g. incident fields). |
| `READY_FOR_CONFIRMATION` | All details collected; waiting for user confirmation. |
| `EXECUTING` | A confirmed action is in progress (reserved for BL-003+). |
| `COMPLETED` | The action completed successfully. |
| `CANCELLED` | The user cancelled the pending action. |
| `FAILED` | The action failed; `last_error` describes the cause. |

### Valid Transitions

```
IDLE ──────────────────► COLLECTING
COLLECTING ────────────► READY_FOR_CONFIRMATION
COLLECTING ────────────► CANCELLED  (added in BL-006: cancel during collection)
READY_FOR_CONFIRMATION ► EXECUTING
READY_FOR_CONFIRMATION ► CANCELLED
EXECUTING ─────────────► COMPLETED
EXECUTING ─────────────► FAILED
COMPLETED ─────────────► IDLE  (clears all fields)
CANCELLED ─────────────► IDLE  (clears all fields)
FAILED ────────────────► IDLE  (clears all fields)
```

All other transitions raise `InvalidTransitionError`. The phase is never
mutated if the transition is invalid.

### `ConversationState` fields

| Field | Type | Purpose |
|---|---|---|
| `phase` | `ConversationPhase` | Single authoritative phase indicator |
| `intent` | `str \| None` | Classified intent from router or AI |
| `summary` | `str \| None` | Short human-readable request summary |
| `collected_details` | `dict` | Details gathered during COLLECTING |
| `pending_action` | `str \| None` | Tag for what will execute on confirmation |
| `incident_number` | `str \| None` | Known incident number (e.g. from router) |
| `last_error` | `str \| None` | Failure description (set on FAILED) |

**Design rule:** There is one authoritative `phase`. No supplementary boolean
flags (e.g. `awaiting_confirmation`, `executing`) are permitted. This
prevents contradictory state combinations.

### Repository pattern

| Class | Role |
|---|---|
| `StateRepository` | Abstract base class — persistence contract |
| `InMemoryStateRepository` | POC implementation (dict-backed, no network) |

A future Redis or PostgreSQL implementation replaces only
`InMemoryStateRepository` without touching any other module.

### Purity guarantee

The state machine does **not**:
- call ServiceNow
- call Ollama
- call Teams
- perform authorization
- access credentials
- make network requests

### Multi-user isolation

Each user is keyed by their Teams AAD Object ID (or fallback `id`). The
repository guarantees that fetching or mutating user A's state never
affects user B's state.

---


## BL-003 — Confirmation / Side-effect Gate

`app/confirmation.py` provides `evaluate_confirmation(state, message) -> ConfirmationDecision`.

### Security guarantee

A side-effecting action **cannot execute** unless ALL of the following are true:

1. `state.phase` is `READY_FOR_CONFIRMATION`.
2. `state.pending_action` is set and present in `EXECUTABLE_ACTIONS`.
3. The user's message is an exact match against the `_CONFIRM_PHRASES` allowlist.

### `ConfirmationDecision` (value object)

| Field | Type | Meaning |
|---|---|---|
| `confirmed` | `bool` | Gate approved — caller transitions to `EXECUTING` |
| `cancelled` | `bool` | Gate rejected — caller transitions to `CANCELLED` |
| `action` | `str \| None` | The approved `pending_action` identifier |
| `reason` | `str \| None` | Safe-to-log explanation (no user content) |

`confirmed` and `cancelled` are mutually exclusive; both `False` means
the response was ambiguous and the caller should stay in
`READY_FOR_CONFIRMATION`.

### Allowed confirmation phrases (conservative allowlist)

`yes`, `confirm`, `create it`, `go ahead`, `proceed`, `submit it`,
`do it`, `approved`

General positive language (`okay`, `sounds good`, `sure`, `maybe`) is
**not** in the allowlist and will always be denied.

### Cancellation phrases

`cancel`, `no`, `stop`, `don't create it`, `abort`, `never mind`,
`nevermind`, `forget it`

### State transitions driven by the gate

```
READY_FOR_CONFIRMATION + explicit confirm  → EXECUTING
READY_FOR_CONFIRMATION + explicit cancel   → CANCELLED → IDLE
READY_FOR_CONFIRMATION + ambiguous         → (remain READY_FOR_CONFIRMATION)
Any other phase + any message              → denied (no transition)
```

### Purity guarantee

`evaluate_confirmation` is a **pure** function:
- Does not mutate the state object.
- Does not call ServiceNow.
- Does not perform network operations.
- Does not access credentials.
- Does not log message content.

### IDLE safety

When `state.phase` is `IDLE`, any message — including `"yes"`, `"confirm"`,
`"go ahead"` — returns `confirmed=False`. No side effect is possible.

### Stale-confirmation safety

If the state has been reset to `IDLE` (e.g. after `COMPLETED → IDLE`),
a later `"yes"` will be denied because the phase check fails immediately.

### Note on EXECUTING

`EXECUTING` is a handoff point: the gate transitions to it but does **not**
perform execution. Actual execution (ServiceNow call) is the responsibility
of BL-005.

---

## BL-004 — Identity-aware Authorization

`app/security/identity.py` — Identity resolver
`app/security/authorization.py` — Authorization policy

### Authentication vs. Authorization separation

| Concern | Owner |
|---|---|
| **Authentication** | Microsoft Bot Framework / Teams (validates JWT, asserts AAD tenant) |
| **Identity extraction** | `resolve_identity()` — consumes Bot Framework-validated fields |
| **Authorization** | `authorize()` — deterministic, locally-evaluated policy |

BL-004 does **not** implement custom JWT validation. It consumes the identity
information already asserted by Teams authentication.

### Identity model (`UserIdentity`)

| Field | Type | Purpose |
|---|---|---|
| `user_id` | `str` | Stable identifier (prefers `aad_object_id` over channel `id`) |
| `tenant_id` | `str` | Azure AD tenant — used for tenant isolation check |
| `display_name` | `str \| None` | Optional; **logging only**, never used for authorization |
| `email` | `str \| None` | Optional; **logging only**, never used for authorization |
| `source` | `IdentitySource` | `AAD_OBJECT_ID` \| `CHANNEL_ID` \| `UNKNOWN` |

`ANONYMOUS` is the sentinel for unresolvable identity. All actions are
denied for `ANONYMOUS`.

**Stable identity requirement:** The `aad_object_id` is preferred because
it is stable across name changes, email changes, and UPN renames.

### Authorizable actions (`AuthorizableAction`)

```
READ_INCIDENT       read an existing incident
CREATE_INCIDENT     create a new incident
UPDATE_INCIDENT     update an existing incident (agent/admin only)
READ_KNOWLEDGE      read knowledge base articles
CREATE_REQUEST      submit a service catalog request
ESCALATE            escalate to a human support agent
ADMIN_OVERRIDE      administrative override (admin only)
```

Actions are a **closed enum**. Arbitrary strings (from user input, LLM
output, or conversation content) cannot be submitted as authorizable actions.

### User roles (`UserRole`)

```
EMPLOYEE            Standard Teams user
SERVICE_DESK_AGENT  IT helpdesk agent
SERVICE_DESK_ADMIN  IT helpdesk administrator
```

Roles are **not inferred** from display names, email prefixes, department
text, or LLM output. In the POC, all authenticated users from the allowed
tenant receive `EMPLOYEE`. Future implementation replaces this with Entra
group membership lookup.

### Authorization matrix

| Action | EMPLOYEE | SERVICE_DESK_AGENT | SERVICE_DESK_ADMIN |
|---|:---:|:---:|:---:|
| `READ_INCIDENT` | ✓ | ✓ | ✓ |
| `READ_KNOWLEDGE` | ✓ | ✓ | ✓ |
| `CREATE_INCIDENT` | ✓ | ✓ | ✓ |
| `CREATE_REQUEST` | ✓ | ✓ | ✓ |
| `ESCALATE` | ✓ | ✓ | ✓ |
| `UPDATE_INCIDENT` | | ✓ | ✓ |
| `ADMIN_OVERRIDE` | | | ✓ |

### Default-deny posture

| Condition | Outcome |
|---|---|
| `ANONYMOUS` identity | deny |
| `IdentitySource.UNKNOWN` | deny |
| Empty `user_id` | deny |
| Empty `tenant_id` | deny |
| Tenant mismatch | deny |
| `TEAMS_TENANT_ID` env var unset | deny all |
| Unknown role (role resolves to `None`) | deny |
| Action not in role's permitted set | deny |
| Malformed input | deny |

The system **never fails open**.

### Tenant isolation

The allowed tenant is read from `TEAMS_TENANT_ID` at call time.
A user from any other tenant is denied regardless of their user_id or role.
If `TEAMS_TENANT_ID` is unset, all requests are denied (fail-safe default).

### Confirmation → Authorization boundary

The intended sequence (fully implemented in BL-004, BL-005 to complete execution):

```
Confirmation gate (BL-003)
        ↓ decision.confirmed=True
Identity resolver — resolve_identity(activity)
        ↓ UserIdentity
authorize(identity, AuthorizableAction.CREATE_INCIDENT)
        ↓ AuthorizationDecision.allowed=True
[BL-005] ServiceNow Tool Gateway
        ↓
ServiceNow API
```

### `AuthorizationDecision` (value object)

| Field | Type | Meaning |
|---|---|---|
| `allowed` | `bool` | Authorization result |
| `action` | `AuthorizableAction \| None` | Action evaluated |
| `role` | `UserRole \| None` | Role used in evaluation |
| `reason` | `str \| None` | Safe-to-log explanation (no policy internals) |

Frozen dataclass — immutable after construction.

### Future integration points

| Integration | Current POC | Future |
|---|---|---|
| Role assignment | All tenant users → EMPLOYEE | Entra group membership via Graph API |
| ServiceNow roles | Not used | ServiceNow user role lookup via BL-005 |
| Dynamic policy | Static `_POLICY_MATRIX` | `AuthorizationPolicy` ABC implementation |
| Privileged action log | DEBUG only | Audit log / SIEM integration |

---

## BL-005 — ServiceNow Tool Gateway

`app/tools/servicenow.py` — ServiceNow Tool Gateway implementation
`app/tools/__init__.py` — Tool Gateway subpackage exports

### Purpose

The ServiceNow Tool Gateway provides a controlled, typed business-operation boundary between the identity/authorization layer (BL-004) and the low-level ServiceNow transport client (`app/servicenow.py`).

```
Microsoft Teams Activity
        ↓
Identity Resolver (BL-004)
        ↓
Intent & Conversation State Machine (BL-002)
        ↓
Confirmation Gate (BL-003)
        ↓
Authorization Policy (BL-004)
        ↓
ServiceNow Tool Gateway (BL-005)
        ↓
ServiceNow Client Adapter (app/servicenow.py)
        ↓
ServiceNow Table API
```

### Typed Tool Actions (`ServiceNowToolAction`)

Tool actions are defined as a strict, closed Enum:

- `GET_INCIDENT` (`get_incident`): Retrieve incident details by incident number.
- `CREATE_INCIDENT` (`create_incident`): Create a new ServiceNow incident.
- `UPDATE_INCIDENT` (`update_incident`): Update fields on an existing incident (requires agent/admin role).

Arbitrary strings (e.g. `"delete_user"`, `"execute_script"`, `"query_table"`) are rejected at the gateway boundary with `ToolValidationError`.

### Action Matching & Authorization Enforcement

The gateway enforces double-gated authorization:

1. **Authorization Decision Check**: `authorization_decision.allowed` must be `True`.
2. **Action Matching**: `authorization_decision.action` must match the required `AuthorizableAction` mapped to the requested `ServiceNowToolAction`:

| ServiceNow Tool Action | Required Authorizable Action |
|---|---|
| `ServiceNowToolAction.GET_INCIDENT` | `AuthorizableAction.READ_INCIDENT` |
| `ServiceNowToolAction.CREATE_INCIDENT` | `AuthorizableAction.CREATE_INCIDENT` |
| `ServiceNowToolAction.UPDATE_INCIDENT` | `AuthorizableAction.UPDATE_INCIDENT` |

Attempts to invoke `UPDATE_INCIDENT` with a `READ_INCIDENT` or `CREATE_INCIDENT` authorization decision are rejected immediately (`ToolAuthorizationError`).

### Typed Request Contracts

- `GetIncidentToolRequest`: `incident_number` (validated with `^INC\d{7,10}$`).
- `CreateIncidentToolRequest`: `short_description`, `description`, `impact` (`"1"`..`"3"`), `urgency` (`"1"`..`"3"`), consistent with `app/models.py`.
- `UpdateIncidentToolRequest`: `incident_number`, `short_description` (optional), `description` (optional), `impact` (optional, `"1"`..`"3"`), `urgency` (optional, `"1"`..`"3"`).

Arbitrary table names, encoded queries, raw scripts, headers, or sys_id overrides cannot be passed.

### Result & Error Mapping

`ToolResult` is an immutable, typed result containing:
- `success`: `bool`
- `action`: `ServiceNowToolAction`
- `incident_number`: `str | None`
- `incident`: `dict | None`
- `safe_message`: `str` (safe user message; contains no credentials or internal URLs)
- `error_code`: `str | None` (`AUTHORIZATION_DENIED`, `VALIDATION_ERROR`, `NOT_FOUND`, `EXECUTION_ERROR`)

### Non-Idempotency & Retry Policy

`CREATE_INCIDENT` is non-idempotent. The gateway does **not** automatically retry failed creation attempts to prevent duplicate ticket creation in ServiceNow.

---

## BL-006 — Incident Collection

`app/incident_collection.py` collects the fields needed to create an
incident **before** confirmation and before any ServiceNow execution.

```
"I need to report an issue"  → create_incident intent (AI classifier)
        │
        ▼
IDLE ─► COLLECTING ──(all fields valid)──► READY_FOR_CONFIRMATION   ← BL-006 stops here
            │                                      │
            └─► CANCELLED ─► IDLE                  ▼
                                         BL-003 gate → BL-004 → BL-005
```

### Responsibility

- `start_incident_collection(state, message)` — `IDLE → COLLECTING`
  (a terminal COMPLETED / FAILED / CANCELLED phase is first returned to
  `IDLE` through its normal transition). Captures any details already in
  the opening message; request wording such as "create an incident for"
  is stripped first.
- `process_collection_message(state, message)` — handles every message
  while in `COLLECTING`. In `app/main.py` these messages go straight to the
  collector; the LLM classifier is **not** called during collection.
- Both return a `CollectionResult` (`reply`, `phase`, `missing`, `errors`,
  `captured`, `cancelled`). The caller saves the state and sends `reply`.

### Required fields (collection order)

| Field | Rule |
|---|---|
| `short_description` | Non-empty, single line, ≤ 160 characters |
| `description` | Non-empty, user-provided text |
| `impact` | Exactly `"1"`, `"2"` or `"3"` |
| `urgency` | Exactly `"1"`, `"2"` or `"3"` |

The collected payload is stored in `ConversationState.collected_details`
and contains **only** these four keys. Other keys (priority, assignment
group, category, caller, sys_id, …) are dropped and never reach
ServiceNow.

### Deterministic extraction and validation

- Labelled values anywhere in a message: `impact 2`, `urgency: 1`,
  `impact is 2`, `short description: …`, `title: …`, `description: …`.
- Unlabelled free text fills the text fields. If both are missing, the text
  becomes the description and its first sentence becomes the short
  description, but only if it is 160 characters or fewer. Otherwise the
  user is asked for a concise short description. Nothing is truncated.
- A bare answer (`2`) fills impact/urgency only when that field is the
  one being asked for.
- `0`, `4`, `5`, words such as `high`/`medium`/`low`, and free text are
  rejected with "Impact must be 1, 2, or 3." / "Urgency must be 1, 2, or
  3.". There is no word-to-number mapping. The conversation stays in
  `COLLECTING`.
- Missing values are **never** defaulted or inferred. The collector asks
  for them.
- Before `READY_FOR_CONFIRMATION`, the complete payload is re-validated
  against `app.models.CreateIncidentRequest` (the established contract).

### Corrections

A later labelled value replaces the earlier one while collecting:
"Actually impact should be 1", "Change urgency to 3", "Change the
description to …", "The short description should be …". An invalid
correction is rejected and the previous valid value is kept.

### Cancellation

Messages matching the BL-003 cancellation phrases (`cancel`, `stop`,
`never mind`, `abort`, …; the same `_CANCEL_PHRASES` set) during
collection transition `COLLECTING → CANCELLED → IDLE`, which clears all
collected details. No incident is created and no further fields are
requested.

### READY_FOR_CONFIRMATION boundary

When all four fields are valid, the collector sets `pending_action =
"create_incident"` and `summary = short_description`, transitions to
`READY_FOR_CONFIRMATION`, and replies with a summary listing **only** the
four collected values followed by "Shall I create this incident?". It
never transitions to `EXECUTING`. Accepting or rejecting the confirmation
is handled entirely by BL-003. Words such as "okay" or "sure" are not
treated as approval.

### Boundaries

The collector does not import or call ServiceNow, the Tool Gateway, the
LLM, Teams, or any HTTP client. It does not read environment variables
or credentials, and it logs field names only, never message content.

### Known limitations

- Corrections are only possible while in `COLLECTING`.
  `READY_FOR_CONFIRMATION → COLLECTING` is not a valid transition, so after
  the summary the user can only confirm or cancel.
- The collection flow starts only when the AI classifier returns
  `create_incident`.

---

## BL-007 — Incident Confirmation & Creation

`_create_confirmed_incident()` in `app/main.py` runs when the BL-003 gate
returns `confirmed=True` for a conversation in `READY_FOR_CONFIRMATION`.

```
READY_FOR_CONFIRMATION + explicit confirmation (BL-003)
   │
   ├─ collected details incomplete/invalid ─► CANCELLED ─► IDLE   (nothing executed)
   │
   ├─ resolve_identity → authorize(CREATE_INCIDENT)
   │      └─ denied ─► stays READY_FOR_CONFIRMATION           (nothing executed)
   │
   ▼
EXECUTING  (saved before the side effect)
   │
   ▼
ServiceNowToolGateway.execute(CREATE_INCIDENT)    ← called exactly once
   ├─ success ─► COMPLETED  (incident_number stored and shown)
   └─ failure ─► FAILED     (last_error = gateway safe_message)
```

- **No defaults.** The request is built with
  `CreateIncidentToolRequest(**validate_incident_payload(collected_details))`,
  which uses exactly `short_description`, `description`, `impact` and
  `urgency`. Missing or out-of-contract values stop the workflow before
  identity, authorization or execution. The LLM `summary` is never used.
- **Gateway only.** The handler never calls `ServiceNowClient` directly.
  If `execute()` raises unexpectedly, the error is converted to a safe
  failure (`FAILED`), so the conversation never stays in `EXECUTING`.
- **No false success.** Success is reported only when the gateway returns
  `success=True`. If ServiceNow returns no incident number, the user is
  told so and asked not to resubmit.
- **No retry and no duplicates.** CREATE is attempted once. Messages that
  arrive while `EXECUTING` get a "still being created" reply without
  reaching the LLM or the gateway. After `COMPLETED` or `FAILED`, "yes" is
  no longer a confirmation, because the gate requires
  `READY_FOR_CONFIRMATION`. A new incident needs a new BL-006 collection.

---

## Security Notes (all layers)

- Credentials are read from the environment (`.env` / OS env); never
  logged, never embedded in code.
- User message content is **not** logged (only intent/summary after AI
  classification).
- The router rejects messages with arbitrary surrounding text — it uses
  `re.fullmatch`, not substring search.
- `_validate_incident_number` in `app/servicenow.py` independently
  validates incident numbers before every ServiceNow operation.
- Admin API key comparison uses `secrets.compare_digest` (constant-time).
