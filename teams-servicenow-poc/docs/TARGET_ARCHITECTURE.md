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
        ├─► [DEMO-03] Knowledge (app/knowledge/) — read-only, no side effects
        │
        ├─► [DEMO-04] Historical similar cases (app/history/) — read-only, no side effects
        │
        ├─► Conversation State Machine (app/state.py)  ← BL-002
        │           │
        │           └─ ConversationState / StateRepository (StateKey)
        │                      │
        │                      └─ [DEMO-01] SqliteStateRepository (app/state_store.py)
        │
        ├─► [BL-006] Incident Collection (app/incident_collection.py)
        │
        ├─► [BL-003] Confirmation / Side-effect Gate
        │
        ├─► [BL-004] Identity-aware Authorization
        │
        ├─► [BL-005] ServiceNow Tool Gateway (app/servicenow.py)
        │
        ├─► [BL-010] Audit logging (app/audit.py) — observation only
        │
        └─► [BL-011] Structured observability (app/observability.py) — observation only
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
- Routes: `incident_status` (BL-001/BL-008) and `incident_update` (BL-009;
  its grammar lives in `app/incident_update.py`). Routing never executes
  anything.

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
| `StateRepository` | Abstract base class — persistence contract, keyed by `StateKey` |
| `InMemoryStateRepository` | Tests / local development (dict-backed, not persistent) |
| `SqliteStateRepository` | DEMO-01 persistent implementation (`app/state_store.py`) |

A future Redis or PostgreSQL implementation replaces only the repository
without touching any other module. See **DEMO-01** below.

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

## BL-008 — Incident Status Lookup

A read-only lookup of one incident by number. `app/main.py` now calls the
BL-001 router (`route_message`). The call happens after the COLLECTING,
READY_FOR_CONFIRMATION and EXECUTING branches and before the LLM
classifier.

```
message ─► route_message()  (BL-001, unchanged)
              │ incident_status + normalised INC number
              ▼
resolve_identity → authorize(READ_INCIDENT)
              │ denied ─► "not authorised to view this incident"   (no ServiceNow call)
              ▼
ServiceNowToolGateway.execute(GET_INCIDENT, GetIncidentToolRequest)   ← once, no retry
              ├─ success   ─► app/incident_status.format_incident_status()
              ├─ NOT_FOUND ─► "I couldn't find incident INC…."
              └─ failure   ─► "I couldn't retrieve incident INC… right now."
```

- **Routing:** only the existing BL-001 whole-message patterns trigger a
  lookup (a bare number, `status of`, `check`, `check status of`,
  `what is the status of`; case-insensitive; no trailing punctuation).
  Anything else, including appended or suspicious text, goes to the
  classifier. The classifier's `incident_status` reply only asks for an
  incident number and never performs a lookup.
- **Validation:** `^INC\d{7,10}$`, enforced independently by the router,
  the gateway and the adapter.
- **No confirmation, no state change:** the lookup has no side effect. It
  does not transition the conversation or modify the session. An
  incident number sent while COLLECTING or READY_FOR_CONFIRMATION is
  handled by that workflow, not looked up.
- **Displayed fields:** the allowlist in `app/incident_status.STATUS_FIELDS`
  (short description, description, state, impact, urgency, priority,
  assignment group, assigned to). Missing fields are omitted. `sys_id`,
  reference links and any other field are never shown. Reference fields
  show only `display_value`.
- **Adapter contract unchanged:** `ServiceNowClient.get_incident` returns
  `number, short_description, state, impact, urgency, priority` (plus
  `sys_id`). Description, assignment group and assigned to are therefore
  not shown until that contract is extended. Values appear as returned by
  ServiceNow (for example, `State: 2`).

---

## BL-009 — Controlled Incident Update

Updates `short_description`, `description`, `impact` and/or `urgency` of
one existing incident, and nothing else. The update is a side effect, so it
always requires explicit BL-003 confirmation.

```
"Update INC0010002 impact to 1 and urgency to 2"
   │ router: whole-message update grammar (app/incident_update.parse_update_command)
   ▼
resolve_identity → authorize(UPDATE_INCIDENT) ─ denied ─► "not authorised"   (nothing read or stored)
   ▼
gateway GET_INCIDENT (READ_INCIDENT) → current values ─ not found/failure ─► safe message (no state)
   ▼
IDLE → COLLECTING ─(valid changes, nothing outstanding)─► READY_FOR_CONFIRMATION
   │   "Impact: 3 → 1 / Urgency: 3 → 2 … Shall I apply these changes?"
   ▼  explicit confirmation (BL-003; "update_incident" added to EXECUTABLE_ACTIONS)
re-validate changes → resolve_identity → authorize(UPDATE_INCIDENT) ─ denied ─► stays READY
   ▼
EXECUTING → gateway UPDATE_INCIDENT (UpdateIncidentToolRequest), once, no retry
   ├─ success ─► COMPLETED  (reply shows the values ServiceNow returned)
   └─ failure ─► FAILED     (safe message)
```

- **Command grammar.** A message is an update command only if the whole
  message fits: `<update|change|set|modify|edit> [the] [incident] INC#
  [items]` or `<verb> [the] <field> of INC# to <value> [and …]`. Items are
  `<field> [to|=|:|as|is|should be] <value>`, separated by `,` / `and`.
  Appended text such as `; DROP TABLE`, `<script>`, `and delete it` or
  `ignore previous instructions` makes it a non-command, which falls
  through to the classifier. The classifier has no update intent and can
  never trigger an update.
- **Values.** Impact and urgency accept `1`, `2` or `3` only. The short
  description is at most 160 characters. Text values are data: they are
  shown in the summary and need confirmation. A change equal to the
  current value is refused. Nothing is defaulted.
- **Unsupported fields.** Priority, state, assignment group, assigned to,
  category, caller, work notes and similar are recognised only so they can
  be refused with an explanation.
- **Current values** come only from the gateway read. Fields the adapter
  does not return (currently `description`) show "(current value not
  available)" and are never guessed.
- **State.** The update reuses the existing phases.
  `pending_action = "update_incident"` selects the update collector while
  COLLECTING and the update executor after confirmation.
  `collected_details` holds `changes`, `requested` and `current`, and only
  `changes` (re-validated against the four allowed fields) reaches the
  gateway. Cancellation follows COLLECTING/READY → CANCELLED → IDLE and
  clears everything.
- **Authorization.** Update permission is checked when the request starts
  and again immediately before execution. Under the default BL-004 policy
  every user is an `EMPLOYEE`, and employees cannot update incidents. The
  flow only succeeds once a role mapping grants `SERVICE_DESK_AGENT` or
  `SERVICE_DESK_ADMIN`.
- Mid-workflow messages are handled by that workflow. An incident number
  or update command sent while COLLECTING or READY_FOR_CONFIRMATION is not
  treated as a new update or a status lookup.
- **Fail-closed phase re-checks.** After the current-value read, the
  session is read again. If another message changed the conversation
  meanwhile, the new update is not started and the reply is "request in
  progress". The existing conversation is left intact. The executor also
  refuses to run unless the phase is still READY_FOR_CONFIRMATION, and in
  that case skips identity, authorization and the gateway.

---

## BL-010 — Audit Logging

`app/audit.py` records security-relevant actions as structured JSON events
on the dedicated `app.audit` logger. Audit logging is **observation only**.
It is not an authorization mechanism and not an execution mechanism. It never
grants or denies access, never executes a tool, and never changes an
operation's result.

```
Teams request (one request_id per message: activity.id if safe, else UUID)
   │
   ├─ *_REQUESTED                           (operation starts; correlation_id = its request_id)
   ▼
identity → authorization ──► *_AUTHORIZED / *_DENIED
   ▼
confirmation (writes only) ─► CONFIRMATION_REQUESTED / _ACCEPTED / _CANCELLED / _REJECTED
   ▼
Tool Gateway ──────────────► AUTHORIZATION_DENIED / TOOL_EXECUTION_REJECTED   (gateway's own guards)
   ▼
ServiceNow ────────────────► *_COMPLETED only after ServiceNow confirms success, else *_FAILED
```

- **Event types (21):** `incident_{read,create,update}_{requested,authorized,
  denied,completed,failed}`, `confirmation_{requested,accepted,cancelled,
  rejected}`, `authorization_denied` and `tool_execution_rejected`. Each type
  allows only matching `AuditOutcome` values.
- **Fields:** `timestamp` (UTC), `event_type`, `outcome`, `correlation_id`,
  and optionally `action`, `request_id`, `user_id` (AAD object id),
  `tenant_id`, `conversation_ref` (SHA-256 prefix of the conversation id),
  `incident_number`, `tool` and `reason` (a `snake_case` code).
- **Privacy by construction.** `AuditEvent` has no free-text field. Every
  value is an enum, a validated identifier or a reason code, and anything
  else is rejected at construction. Messages, incident descriptions, LLM
  prompts and completions, ServiceNow payloads, tokens, headers, display
  names and e-mail addresses cannot appear in an audit record.
- **Ownership.** `app/main.py` owns the operation, authorization,
  confirmation and outcome events. `ServiceNowToolGateway` owns
  `authorization_denied` and `tool_execution_rejected` for requests its own
  guards refuse. `not_found` and `execution_error` are reported by the
  caller as `*_failed`.
- **Correlation.** A create or update spans several Teams messages. Its
  `correlation_id` is stored in `ConversationState.correlation_id` and
  cleared on reset to IDLE, so every event of one operation shares it. A read
  uses its request id.
- **Failure policy.** `AuditLogger.record()` never raises. A failed event is
  dropped and reported on the sibling `app.audit_errors` logger (exception
  type only), so the `app.audit` channel carries only JSON events. Security
  decisions never depend on audit, so an audit failure cannot bypass
  authorization or confirmation, and cannot turn a failure into a success.
- **Destination.** Standard Python logging only. There is no database, SIEM
  or cloud sink yet.

---

## BL-011 — Structured Observability

`app/observability.py` emits operational telemetry (request flow, latency,
outcomes and failures) as JSON lines on the dedicated `app.observability`
logger. It **observes** each layer and controls none of them:

```
Teams ─► API (on_message)          request_started … request_completed / request_failed  (duration)
          ├─ Identity/Security      user_ref = 16-hex SHA-256(tenant:user), never the raw id
          ├─ Conversation Manager   state_transition        (passive listener on ConversationState)
          ├─ AI Orchestrator        route_selected           (router: route; ai_classifier: intent, duration)
          ├─ Policy/Authorization   authorization_decision   (action, stage, duration)
          ├─ Confirmation           confirmation_decision    (success / cancelled / rejected, duration)
          └─ Tool Gateway           tool_started → tool_completed / tool_failed  (operation, error_code, duration)
                   └─► ServiceNow
```

- **Controlled vocabulary.** There are 10 `ObsEventName`s, 7 `ObsComponent`s
  and 6 `ObsOutcome`s (`started`, `success`, `denied`, `rejected`,
  `cancelled`, `failed`). Each event name allows only matching outcomes.
- **Fields:** `timestamp`, `event_name`, `component`, `outcome`,
  `correlation_id`, and optionally `request_id`, `action`, `duration_ms`
  (monotonic clock), `user_ref`, `operation` (ServiceNow operation type),
  `error_code`, `phase`, `previous_phase` and `metadata`.
- **Privacy by construction.** No field accepts free text. `metadata` accepts
  only the approved keys `route`, `intent`, `pending_action` and `stage`,
  each with an enumerated value set. Messages, prompts, completions,
  ServiceNow bodies, descriptions, work notes, tokens and headers cannot be
  represented.
- **Correlation.** Reuses BL-010's identifiers. Each Teams message gets a
  `request_id` (the activity id if it is a plain identifier, otherwise a
  UUID). While a create/update is active (COLLECTING, READY_FOR_CONFIRMATION
  or EXECUTING), events carry the operation's stored correlation id;
  otherwise they carry the request id. A finished operation's id is
  therefore never reused. The per-request context lives in a `ContextVar`,
  so concurrent requests stay isolated.
- **State hook.** `add_transition_listener()` in `app/state.py` calls
  observers after a successful transition. Observers cannot veto or alter
  it, and any exception they raise is swallowed.
- **Failure policy.** `ObservabilityLogger.record()` never raises. Failures
  go to the sibling `app.observability_errors` logger (exception type only),
  and business behaviour, authorization and confirmation are unaffected.
- **Relation to BL-010.** Audit is the security record (with the AAD
  object id); observability is operational telemetry (pseudonymous). They
  share correlation ids but are separate channels.
- **Destination.** Standard Python logging only. There is no OpenTelemetry,
  Application Insights, SIEM or persistence.

---

## DEMO-01 — Persistent Conversation State

`app/state_store.py` adds `SqliteStateRepository`, a persistent
implementation of the unchanged BL-002 `StateRepository` interface. Multi-turn
conversations (collection → confirmation → execution) now survive process
restarts. It uses a local SQLite file (Python standard library) and needs no
external service.

```
Teams (Bot Framework activity)
   │
   ▼
Conversation Manager (app/main.py on_message)
   │  StateKey = tenant (channel data) + user (AAD object id) + conversation id
   ▼
Persistent State Repository (StateRepository → SqliteStateRepository)
   │  get → copy of stored ConversationState   save → allowlisted fields only
   ▼
AI / Tool orchestration — router, LLM classifier, BL-006/009 collection,
BL-003 confirmation, BL-004 authorization, BL-005 Tool Gateway
(BL-010 audit and BL-011 observability observe every step)
```

- **Isolation.** `StateKey(tenant_id, user_id, conversation_id)` is the
  primary key, with one column per part. A message from another tenant, user
  or Teams conversation addresses a different record. It can never read,
  confirm or cancel this conversation's pending action. A message with no
  tenant has its own empty-tenant scope (and authorization still denies it).
  `StateKey`'s repr shows only short hashes. The tenant comes from the same
  channel data authorization uses, and the user from the same AAD object id
  as before.
- **Selection.** The FastAPI lifespan calls
  `configure_state_repository(create_state_repository())` before Teams
  initialisation. `STATE_STORE=sqlite` is the default; `STATE_DB_PATH`
  overrides the file (default `data/conversation_state.db`, git-ignored). The
  file is created owner-only (0600, directory 0700) in WAL mode.
  `STATE_STORE=memory` must be set explicitly and logs that state is not
  persistent. An unknown store or an unopenable database stops startup. There
  is **no silent fallback** to in-memory state.
- **Copy semantics.** `get` returns a copy; changes are stored only by
  `save`. Every handler mutation is already followed by `save_session`, and
  `EXECUTING` is saved before the Tool Gateway is called (BL-007 duplicate
  protection holds across restarts).
- **Failure policy.** Storage errors raise `StatePersistenceError`, whose
  message is fixed text naming only the operation. The handler catches it,
  records `request_failed` (`state_persistence_error`) and replies with a
  controlled message. A failed load stops before routing, the LLM,
  authorization or the gateway. A failed save stops the request at that
  point. In particular, a failed `EXECUTING` save means the tool is never
  called. Authorization and confirmation cannot be bypassed. After a
  ServiceNow call, the `*_COMPLETED` / `*_FAILED` audit event is emitted
  **before** the state is saved, so a failed save can never lose the audit
  record of a write that already happened.
- **Corrupted records.** An undecodable record, an unknown schema version or
  phase, or `READY_FOR_CONFIRMATION`/`EXECUTING` without a pending action,
  loads as a fresh `IDLE` state. This is logged with no content and no raw
  ids, and the next save overwrites it. `IDLE` has no pending action, so this
  can never skip confirmation. Values are re-filtered through the same
  allowlist on load.
- **Unchanged.** State-machine transition rules, BL-003 confirmation, BL-004
  authorization, BL-005 gateway boundaries and the create/status/update
  business flows. BL-010 audit and BL-011 observability read the same
  session, now addressed by `StateKey`. An operation's audit correlation id
  is persisted, so it survives restarts.

### What is persisted

| Field | Rule |
|---|---|
| `phase` | a `ConversationPhase` value |
| `pending_action` | `create_incident` / `update_incident` only |
| `intent` | known intents only (else dropped) |
| `collected_details` | create: `short_description`, `description`, `impact`, `urgency` (strings). Update: `changes` / `current` (same fields) and `requested` (field names). Every other key is dropped. Kept **only while the operation is in progress** (COLLECTING → EXECUTING); a `COMPLETED` or `FAILED` record stores `{}`, and such details are ignored on load. |
| `incident_number` | `INC` + 7–10 digits only |
| `correlation_id` | plain identifier only (BL-010) |
| `last_error` | the gateway's fixed safe message, ≤ 500 chars |
| `created_at` / `updated_at` | UTC, maintained by the repository |

### What is intentionally NOT persisted

- `summary`: the LLM classifier's output. No prompts or completions are ever
  stored.
- Raw user messages are not stored as such. The incident `short_description`
  and `description` are, however, taken from what the user typed. For a
  create request given in one message, they are close to that message's text.
  They are needed to carry collection across messages (and restarts) up to
  confirmation, and are dropped once the operation completes or fails.
- Access or OAuth tokens, API keys, passwords, secrets and `Authorization`
  headers. None of them are part of `ConversationState`, and serialization is
  an allowlist.
- ServiceNow response bodies, work notes and `sys_id`s. Only the current
  values of the four updateable fields are kept for an update summary.
- Display names, e-mail addresses and the conversation id in clear. The
  conversation id is stored as a SHA-256 digest.

The persistence layer has no AI dependency. The LLM never sees or queries it,
and all SQL is fixed and parameterised.

### Limitations (POC)

- Single process. Concurrent-message protection (`EXECUTING` check) relies on
  one event loop. Multiple workers would need compare-and-set on save.
- No expiry. A conversation left in `EXECUTING` by a crash mid-call stays
  there until cleared, because the transition table has no
  `EXECUTING → IDLE` path.
- Collected `short_description` / `description` text is stored as the user
  typed it while the operation is in progress. If a user types a secret into
  it, the secret is on disk until the operation completes, fails or is
  cancelled, and it is sent to ServiceNow on confirmation. A conversation
  abandoned mid-collection keeps its details, because there is no expiry.

---

## DEMO-02 — ServiceNow Resilience

Every ServiceNow failure is classified, reported with a fixed message, never
retried, and never reported as success. The Tool Gateway stays the only path
to ServiceNow, and the LLM cannot reach it.

```
ServiceNowClient (app/servicenow.py)       httpx / HTTP outcome → typed ServiceNowError
      │   category + possibly_applied            (fixed text; no body, URL, header or token)
      ▼
ServiceNowToolGateway (app/tools/)          → ToolResult(success=False, error_code=<category>,
      │                                                  safe_message, outcome_unknown)
      ▼
app/main.py                                  → Teams reply, FAILED state, audit + observability
```

### Failure categories (`app/servicenow_errors.py`)

| Category (`error_code`) | Source | Write outcome |
|---|---|---|
| `SERVICENOW_UNAVAILABLE` | connect error / connect or pool timeout; HTTP 503 | not applied |
| ″ | connection lost after a write was sent | **unconfirmed** |
| `SERVICENOW_TIMEOUT` | read/write timeout after the request was sent | **unconfirmed** (write) |
| `SERVICENOW_AUTH_FAILED` | OAuth failure (400/401/403, bad token response); API 401 | not applied |
| `SERVICENOW_FORBIDDEN` | API 403 (integration user lacks rights) | not applied |
| `NOT_FOUND` | 404 / empty lookup | not applied |
| `SERVICENOW_REJECTED` | 400 and other 4xx | not applied |
| `SERVICENOW_RATE_LIMITED` | 429 | not applied |
| `SERVICENOW_SERVER_ERROR` | 500 / 502 / 504 / other 5xx | **unconfirmed** (write) |
| `SERVICENOW_INVALID_RESPONSE` | 2xx body not JSON / wrong shape; invalid `sys_id` | **unconfirmed** if the write returned it |

- **Not applied** means the user is told "No change was made."
- **Unconfirmed** (`outcome_unknown`) means the write may have happened. The
  user is told it "couldn't confirm whether the incident was created / was
  updated", to check before trying again, and that it won't retry
  automatically. It is never phrased as "not created" and never as success.
- OAuth failures happen before any business request, so they never make a
  write unconfirmed.
- An update's current-value lookup fails before the `PATCH` is sent, so it is
  always "not applied". A `sys_id` that is not 32 hex characters stops the
  update before a URL is built.
- A 401 clears the cached token, so the next request re-authenticates. The
  failed request itself is not retried.
- Timeouts: connect 10 s, everything else 30 s.
- Unclassified errors (for example a pre-send `ServiceNowError`, or an
  unexpected gateway exception) keep the existing `EXECUTION_ERROR` contract
  and messages.

### Retry policy

Nothing is retried automatically: not create, not update, not reads. A failed
create/update moves to `FAILED`, and a further "yes" cannot re-execute it
(BL-007 / BL-009). The user must start a new request, which goes through
collection, confirmation and authorization again.

### User-facing messages

The messages are fixed text built only from the category, the operation and
a validated incident number. Examples:

- "I couldn't reach ServiceNow right now. No change was made. Please try again."
- "I couldn't find incident INC0010002."
- "The ServiceNow integration is temporarily unavailable. No change was made."
- "ServiceNow is temporarily rate-limiting requests. Please try again shortly."
- "ServiceNow didn't respond in time. I couldn't confirm whether the incident
  was created. Please check your incidents in ServiceNow before trying again.
  I won't retry automatically."

Status-lookup failures return a message and never touch conversation state.
Persistence failures (DEMO-01) keep their own distinct message, and the
ServiceNow category is still audited before the state save.

### Audit and observability

- Audit `*_FAILED` `reason` is the category in lower case (for example
  `servicenow_timeout`), with `_unconfirmed` appended when a write may have
  been applied. BL-011 `tool_failed.error_code` uses the same value.
- `last_error` (persisted) holds the fixed message only.
- Client warnings log the category, HTTP status and `possibly_applied`, never
  the URL.
- `httpx` request logging (which includes the instance URL and query) is
  filtered below WARNING. A filter is used because the Teams SDK resets the
  `httpx` logger level.

### Limitations (POC)

- A 503 on a write is treated as "not applied", on the assumption that
  ServiceNow refuses the request without processing it (maintenance or a
  hibernating instance). A proxy that returns 503 after forwarding would
  break that assumption.
- There is no automatic reconciliation of unconfirmed creates. The user (or
  IT) checks ServiceNow. A future version could look up a
  correlation-tagged incident.
- `Retry-After` on 429 is not surfaced. The message says "shortly".

---

## DEMO-03 — Enterprise Knowledge

Employees can ask troubleshooting questions and get answers drawn only from
approved knowledge, with citations. A knowledge lookup is read-only. It
never calls ServiceNow or the Tool Gateway, never changes conversation state
and never needs confirmation.

```
Teams message
   │
   ▼
app/main.py on_message ── LLM classifier: intent only (diagnose / find_solution)
   │                         (receives the user message, nothing else)
   ▼
_answer_knowledge ── identity → authorize(READ_KNOWLEDGE) → audit / observability
   │
   ▼
KnowledgeService (app/knowledge/service.py)
   │  KnowledgeSearchRequest(user's own words → normalized tokens)
   ▼
KnowledgeRepository (interface) ── LocalKnowledgeRepository (POC, in memory)
   │                               └ future: ServiceNowKnowledgeRepository
   ▼
approval re-check → sanitize (untrusted data) → KnowledgeHit + Citation
   │
   ▼
format_knowledge_answer: extractive steps + "Source: KB… — Title (Source)"
```

### Components

| Module | Role |
|---|---|
| `app/knowledge/models.py` | `KnowledgeArticle` (validated, immutable: `article_id` `KB` + 7 digits, title, body, category, status, source, metadata), `KnowledgeSearchRequest`, `KnowledgeSearchResult`, `KnowledgeHit`, `Citation` |
| `app/knowledge/repository.py` | `KnowledgeRepository` interface; `LocalKnowledgeRepository` |
| `app/knowledge/fixture.py` | Local POC content, compiled in as Python records (VPN, password reset, MFA, Teams, Outlook, incident guidance, plus one draft and one retired article) |
| `app/knowledge/sanitize.py` | Deterministic, rule-based sanitization |
| `app/knowledge/service.py` | `KnowledgeService`, `format_knowledge_answer` |

- **Local POC repository.** It is built once from Python records. There is no
  file, database or network access. Malformed records are skipped and logged
  by position only.
- **Future ServiceNow repository.** A `ServiceNowKnowledgeRepository` would
  implement the same `search(KnowledgeSearchRequest)` through a dedicated,
  allowlisted knowledge endpoint behind its own gateway, never the generic
  Table API. The handler and service would not change.

### Retrieval

- The query is always the user's own message, never the LLM summary.
- The query is normalized: NFKC, casefold, alphanumeric tokens, stopwords
  removed, light suffix stemming, at most 500 characters and 32 tokens. An
  empty result is reported as "please describe the problem".
- Score = 3 × title matches + 2 × keyword matches + 1 × body matches, counted
  over distinct query tokens. Candidates scoring below 3 are dropped. Ties are
  broken by article id. The result is deterministic and doesn't depend on
  input order. At most 3 results are returned (maximum 5).
- Only `approved` articles are returned. The service checks approval again,
  so a faulty repository cannot surface draft or retired content.

### Untrusted content and prompt-injection defense

Article text is data. It is never executed, never used for routing,
authorization, confirmation or tool selection, and in this POC it is **never
sent to the LLM**. The answer is assembled extractively in code. Fixed rules
are applied on top of that, without relying on the LLM:

- **Instruction-like content quarantines the whole article.** This covers
  text such as "ignore/disregard … instructions/policy", "system prompt", "you
  are now", "reveal … password/token/secret", "call/invoke/execute …
  ServiceNow/API/tool", script tags and code fences. A compromised article is
  not shown at all. The count is audited as `content_withheld`.
- **Lines are dropped** when they contain:
  - secrets: `password:` / `token=` / `api key`, "the shared password is",
    `Bearer …`, `Authorization:`, private keys, `sk-…`, JWTs, connection
    strings;
  - internal or private notes: work notes, internal comments, `[Internal]`,
    agent-only, do-not-share;
  - personal data: e-mail addresses, phone numbers;
  - infrastructure details: IP addresses, `*.corp` / `.internal` / `.local`
    hostnames, UNC paths;
  - URLs, HTML and markdown links.
  Each line is first normalized: NFKC (so fullwidth letters become ASCII),
  zero-width, soft-hyphen, control and bidi characters removed, and markdown
  emphasis (`*`, `_`, backticks, `~`) removed. The checks run on that
  normalized text, both the whole line and the step text without its number,
  and the displayed text is built from the same normalized text. Injection
  checks also run on the original line, because code fences are themselves a
  signal.
- Control and bidirectional-override characters are stripped. Lines are
  capped at 300 characters and steps at 8.
- **Metadata** (keywords, owner, review data) is used for ranking only and
  never displayed.
- **Unsafe results are withheld.** An article whose title is unsafe, or that
  has nothing safe left, is withheld.

### Grounding and citations

- Every step shown comes verbatim (after sanitization) from an approved
  article. No procedure, command, URL, credential or policy is generated.
- The best article is shown with a `Source: <KB id> — <Title> (<Source>)`
  line. Other matches are listed as "Related articles" with the same citation
  format.
- Citations can only name articles that were actually retrieved, so they
  can't be fabricated.
- No match gives "I couldn't find an approved knowledge article for that",
  plus an offer to say "create an incident". Nothing is created
  automatically.
- The answer never claims that ServiceNow was checked.

### Integration, authorization and no side effects

- The existing classifier intents `diagnose` and `find_solution` route to
  `_answer_knowledge`. The classifier prompt and the BL-001 router are
  unchanged. Messages in COLLECTING, READY_FOR_CONFIRMATION or EXECUTING
  still go to the collector or the confirmation gate first, so a question can
  never interrupt a pending action.
- `authorize(identity, READ_KNOWLEDGE)` runs first; the action already
  existed in the BL-004 policy for every role. A wrong or missing tenant, or
  an anonymous user, is denied, and the repository is never searched.
- The knowledge package imports no ServiceNow, tool gateway, state, LLM,
  filesystem or network module. Tests enforce this by inspecting the import
  graph.

### Audit and observability

- **Audit:** `knowledge_search_requested / _authorized / _denied / _completed
  / _failed`, with `action=read_knowledge` and `tool=knowledge_search`.
  - `_completed` carries `result_count` and `article_ids` (validated
    `KB` + 7 digits, at most 5), plus `reason=content_withheld` when an
    article was quarantined.
  - `_failed` carries `knowledge_unavailable` or `empty_query`.
- **Observability:** `tool_started` / `tool_completed` / `tool_failed` with
  `component=knowledge`, `operation=knowledge_search`, `duration_ms` and
  `result_count`.
- The query text, article titles and bodies, and the LLM summary are never
  logged. Persistent state gains nothing new; only the existing intent is
  stored.

### Limitations (POC)

- Keyword retrieval with light stemming and no synonyms beyond article
  keywords. There is no semantic or vector search.
- Only `diagnose` / `find_solution` reach knowledge, so if the LLM is
  unavailable (the intent falls back to `general`), knowledge isn't
  consulted.
- Sanitization is rule-based. False positives (for example an article saying
  "execute the following command", or a line with a version number that
  looks like a phone number) are dropped or quarantined, the safe failure
  direction. False negatives are possible for secrets in unusual formats.
- Knowledge is not tenant-scoped. BL-004 restricts use to the configured
  tenant.

---

## DEMO-04 — Historical Similar Cases

Answers "Have we seen this issue before?" from sanitized, resolved historical
cases. The answer summarizes the pattern of fixes and cites case
references. It is read-only: no ServiceNow call, no Tool Gateway, no state
change, no confirmation, and no LLM involvement at all.

```
Teams message ──► on_message (after COLLECTING / READY / EXECUTING handling
   │               and the BL-001 router; before the LLM classifier)
   ▼
is_history_question (deterministic phrases; never a "create/raise/log … incident" request)
   ▼
_answer_history ── identity → authorize(READ_KNOWLEDGE) → audit / observability
   ▼
HistoricalCaseService ── CaseSearchRequest (user's words minus question words)
   ▼
HistoricalCaseRepository (interface) ── LocalHistoricalCaseRepository (POC, in memory)
   ▼                                   └ future: curated ServiceNow export / allowlisted endpoint
eligibility re-check → injection check on case text → CaseEvidence (controlled fields)
   ▼
format_history_answer: pattern of fixes + one cited line per case
```

### Data model (`app/history/models.py`)

A `HistoricalCase` has two kinds of fields.

- **Controlled fields** are the only ones that can be displayed: `case_ref`
  (opaque `HC` + 5 digits), `category`, `symptoms` (`SymptomTag`) and
  `resolution` (`ResolutionCode`). Each enum carries a fixed display label.
- **Untrusted free text** (`description`, `resolution_notes`) is used for
  matching only. It is never displayed, copied, logged or sent to the LLM.
- **`private`** holds source-system fields (incident number, caller, e-mail,
  phone, work notes, `sys_id`). They are never displayed, logged, matched or
  returned.

The source incident number is deliberately not shown. Historical cases may
belong to other users, and showing their numbers would invite status
lookups on someone else's incident.

### Eligibility

A case is used only if it is `resolved` or `closed`, explicitly marked
`eligible`, **and** has a resolution code. The repository filters on this and
the service checks it again. The POC fixture includes an in-progress case and
a closed but ineligible case that are never returned.

### Retrieval

Retrieval uses the same tokenizer as DEMO-03. Question words ("have we seen
… before", "similar", "cases", "issue"…) are removed first.

- Score = 3 × symptom-keyword matches + 1 × free-text matches. A case must
  match at least one symptom keyword.
- Ties are broken by case reference, and the result is deterministic.
- At most 5 cases are returned.
- A question with no topic left ("Have we seen this before?") gets a request
  for the issue. A topic with no match gets "I couldn't find a sufficiently
  similar resolved case", plus an offer to create an incident. Nothing is
  created automatically.

### Answer, grounding and citations

- The answer is built only from controlled labels: the most common
  `ResolutionCode` among the retrieved cases ("most were resolved by … (k of
  n)"), the other fixes, and one line per case:
  `HC… — <category> · <symptom> · resolved by <fix>`.
- Every case that contributes to the pattern is cited. No case is cited that
  wasn't retrieved.
- Case text is never copied verbatim. Tests check that no four-word sequence
  of any case's free text appears in any answer, other than sequences that
  come from the fixed labels.
- The answer says the cases are "for reference, not a diagnosis" and names
  its source. It never claims that ServiceNow was checked.

### Prompt-injection defense and privacy

- Case text can't act as instructions: it is never displayed or sent to the
  LLM, and the answer contains fixed labels only.
- A case whose free text contains instruction-like content is still withheld
  from the evidence, using the DEMO-03 detector
  (`app.knowledge.sanitize.contains_instructions`, which checks both raw and
  normalized text). The withheld count is audited as `content_withheld`.
- Caller names, e-mail addresses, phone numbers, work notes, internal
  comments, credentials, tokens, `sys_id`s, incident numbers and
  infrastructure details can't appear in a reply, because no displayed value
  comes from those fields.

### Authorization, audit and observability

- **Authorization:** `authorize(identity, READ_KNOWLEDGE)` runs before the
  search. Sanitized historical evidence is governed like knowledge, and the
  BL-004 action set is unchanged. A wrong or missing tenant, or an anonymous
  user, is denied and the repository is never searched.
- **Audit:** `historical_case_search_requested / _authorized / _denied /
  _completed / _failed`, with `tool=historical_case_search`.
  - `_completed` carries `result_count` and `case_refs` (validated
    `HC` + 5 digits, at most 5), plus `reason=content_withheld` when a case
    was withheld.
  - `_failed` carries `history_unavailable` or `missing_topic`.
- **Observability:** `tool_started` / `tool_completed` / `tool_failed` with
  `component=history`, `operation=historical_case_search`, `duration_ms` and
  `result_count`.
- The query text and case text are never logged. The history path writes no
  conversation state.

### Limitations (POC)

- Keyword matching over a small synthetic fixture; no semantic search.
- A follow-up "Have we seen this before?" doesn't reuse the earlier message,
  because raw messages are not persisted (DEMO-01). The user is asked to name
  the issue.
- Phrase detection is rule-based. Unusual wording falls through to the
  classifier, which treats it as it did before DEMO-04.
- Cases are not tenant-scoped. BL-004 restricts use to the configured tenant.

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
