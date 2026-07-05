# Planning decision-to-transition doctrine

> **Status:** doctrine — manifest transitions implemented via `agent-os planning transition`  
> **Relation to Agent OS:** extension layer; not part of Agent OS v0.1.0 core behavior  
> **Companion:** [`docs/planning-workspace-layout.md`](planning-workspace-layout.md), [`docs/planning-layer-doctrine.md`](planning-layer-doctrine.md)

This document defines how **recorded owner decisions** relate to **explicit manifest transitions** in a planning workspace. It authorizes nothing by itself. Decision records are evidence; manifest transitions are separate operations performed only when doctrine, validation (where required), and the latest valid owner decision align.

---

## 1. Purpose

Governed planning separates **judgment** from **state change**:

| Concept | Role |
|---------|------|
| **Owner decision record** | Append-only evidence of owner judgment under `decisions/` |
| **Manifest transition** | Explicit operation via `agent-os planning transition` that updates `manifest.json` `status` and `gates` when authorized |
| **Validation** | Read-only structural check (`agent-os planning validate`) — not approval |

**Core rules:**

- Decision records are **evidence**. They document what the owner decided and when.
- Manifest transitions are **separate explicit operations** (`agent-os planning transition`). No decision record mutates `manifest.status` or `gates` by itself.
- No transition creates runs, invokes agents, imports plans into the runner, or approves executor execution.
- `agent-os planning decide` records judgment only. Status and gate updates require `agent-os planning transition` when doctrine authorizes them.

---

## 2. Current planning statuses

Allowed values for `manifest.json` `status`:

| Status | Meaning |
|--------|---------|
| `DRAFT` | Package created; artifacts incomplete or unfilled |
| `CONTEXT_READY` | Context Pack complete enough for spec work |
| `SPEC_READY` | Local Agentic Spec accepted by owner |
| `PLAN_READY` | Implementation Plan complete; not yet planning-audited |
| `PLANNING_AUDIT_READY` | Planning Audit recorded with `PASS` or `PASS_WITH_NOTES` |
| `APPROVED_FOR_RUN_PROPOSALS` | Owner approved plan for deriving Next Run Proposals (one slice at a time) |
| `BLOCKED` | External or owner decision required; no proposals until unblocked |
| `SUPERSEDED` | Replaced by a newer plan or revision; retained for history |
| `CLOSED` | Planning objective complete or abandoned; no further proposals from this plan |

Statuses describe **planning maturity**, not execution state. No status self-advances.

---

## 3. Current owner decision values

Allowed values for `decision` in a `PLANNING_OWNER_DECISION` record (via `agent-os planning decide`):

| Decision | Meaning |
|----------|---------|
| `APPROVE_FOR_RUN_PROPOSALS` | Owner approves the plan for deriving Next Run Proposals |
| `REQUEST_REVISION` | Owner requires material revision before further progress |
| `BLOCK` | Owner blocks planning progress pending resolution |
| `CLOSE` | Owner closes the planning workspace |

### Recording rules

| Decision | Validation requirement | Notes |
|----------|------------------------|-------|
| `APPROVE_FOR_RUN_PROPOSALS` | **Must** pass `agent-os planning validate` (result `OK`) before the record is accepted | Enforced at record time; does not transition manifest |
| `REQUEST_REVISION` | May be recorded when validation fails | Evidence only; does not auto-revise artifacts |
| `BLOCK` | May be recorded when validation fails | Evidence only; does not auto-set `BLOCKED` status |
| `CLOSE` | May be recorded when validation fails | Evidence only; does not auto-set `CLOSED` status |

Decision records remain **historical evidence**. A later decision does not delete earlier records. All records stay inspectable under `decisions/`.

---

## 4. Transition authorization matrix

This matrix defines which owner decision **may authorize** which explicit manifest transition. **Authorization is not automatic.** `agent-os planning transition` must be invoked explicitly, verify preconditions, and fail closed when doctrine is not met.

Legend: **✓** = may authorize (subject to preconditions); **—** = not allowed by default

### `APPROVE_FOR_RUN_PROPOSALS`

| Source status | Target status | Authorized? | Preconditions |
|---------------|---------------|-------------|---------------|
| `PLANNING_AUDIT_READY` | `APPROVED_FOR_RUN_PROPOSALS` | ✓ | Validation `OK`; latest valid decision is `APPROVE_FOR_RUN_PROPOSALS` |
| `PLAN_READY` | `APPROVED_FOR_RUN_PROPOSALS` | ✓ (conditional) | Validation `OK`; planning audit present and acceptable (`PASS` or `PASS_WITH_NOTES`); latest valid decision is `APPROVE_FOR_RUN_PROPOSALS` |
| Any other source | `APPROVED_FOR_RUN_PROPOSALS` | — | Not allowed by default |

`APPROVE_FOR_RUN_PROPOSALS` does **not** approve run proposals, create runs, or invoke agents. It only authorizes a future transition to `APPROVED_FOR_RUN_PROPOSALS` status.

### `REQUEST_REVISION`

| Source status | Target status | Authorized? | Notes |
|---------------|---------------|-------------|-------|
| Any active status | `BLOCKED` | ✓ | Future transition may set `plan_revision_required` |
| Any active status | `DRAFT` | ✓ (via future revision workflow only) | Requires explicit future revision command — not a direct silent rewind |
| Any status | `APPROVED_FOR_RUN_PROPOSALS` | — | Does not approve run proposals |

### `BLOCK`

| Source status | Target status | Authorized? | Notes |
|---------------|---------------|-------------|-------|
| Any active status | `BLOCKED` | ✓ | Does not permanently close the workspace |
| Any status | `CLOSED` | — | Requires a separate `CLOSE` decision |
| Any status | `APPROVED_FOR_RUN_PROPOSALS` | — | Does not approve run proposals |

### `CLOSE`

| Source status | Target status | Authorized? | Notes |
|---------------|---------------|-------------|-------|
| Any active status | `CLOSED` | ✓ | Terminal disposition |
| Any status | `APPROVED_FOR_RUN_PROPOSALS` | — | Must not create runs or approve future proposals |

### `SUPERSEDED`

`SUPERSEDED` is a manifest status, not an owner decision value. Entering it requires:

- An explicit owner decision **or** a future revision/supersession command (not defined in this slice)
- A reference to the superseding `plan_id` (in manifest metadata or a decision record)
- No implicit deletion of the old workspace — retained for history

| Source status | Target status | Authorized? | Notes |
|---------------|---------------|-------------|-------|
| Any active status | `SUPERSEDED` | ✓ (future command) | Must record superseding `plan_id`; old workspace remains on disk |

---

## 5. Active vs terminal statuses

### Active statuses

Work may continue (subject to gates and decisions):

`DRAFT`, `CONTEXT_READY`, `SPEC_READY`, `PLAN_READY`, `PLANNING_AUDIT_READY`, `APPROVED_FOR_RUN_PROPOSALS`, `BLOCKED`

### Terminal statuses

No further planning progress without an explicit future doctrine change:

`CLOSED`, `SUPERSEDED`

### Terminal rules

- Terminal workspaces **must not** be transitioned back to active status without an explicit future doctrine change and command.
- A terminal workspace **must not** produce run proposals.
- `BLOCKED` is **active**, not terminal — it may be unblocked through owner action and a future transition.

---

## 6. Latest decision policy

Future commands that inspect decisions (`planning decisions list`, future transition importers) should follow:

| Policy | Rule |
|--------|------|
| **Append-only history** | Decision files are never deleted or rewritten by Agent OS |
| **Latest valid decision** | Future transition commands should consider the **latest valid** `PLANNING_OWNER_DECISION` by `created_at` unless explicitly told otherwise (e.g. `--decision-id`) |
| **No retroactive override** | Older decisions remain evidence; they do not automatically override newer decisions |
| **Fail closed on malformed records** | Malformed JSON, missing required fields, or invalid `record_type` must fail closed — same behavior as `planning decisions list` today |
| **Decision ≠ transition** | Even the latest `APPROVE_FOR_RUN_PROPOSALS` does not transition manifest without an explicit future transition command |

---

## 7. Gates

Canonical gate keys in `manifest.json` `gates`:

| Gate key | Meaning when open (`true`) |
|----------|----------------------------|
| `planning_owner_decision_required` | Owner must record an acceptable decision before run proposals |
| `planning_audit_required` | Planning Audit not yet `PASS` / `PASS_WITH_NOTES` |
| `plan_revision_required` | Material plan change needed after audit or owner review |
| `run_proposal_allowed` | Plan may feed Next Run Proposal derivation (one slice at a time) |

### Possible transition effects (`agent-os planning transition`)

| Transition outcome | Gate effects |
|--------------------|------------------------------|
| → `APPROVED_FOR_RUN_PROPOSALS` | Sets `run_proposal_allowed: true`; closes `planning_owner_decision_required`, `planning_audit_required`, `plan_revision_required` |
| → `BLOCKED` (from `BLOCK` or `REQUEST_REVISION`) | Sets `plan_revision_required: true`; `run_proposal_allowed: false` |
| → `CLOSED` | Closes all planning gates (`false` for open-required gates; `run_proposal_allowed: false`) |
| → `SUPERSEDED` | Not implemented in current slice — requires future supersession workflow |

Gate changes require `agent-os planning transition`. Decision records alone do not flip gates.

---

## 8. Non-authority statement

**This doctrine does not:**

- Execute code
- Invoke agents or Cursor
- Create runs or run metadata
- Mutate `manifest.json` `status` or `gates` (except via explicit `agent-os planning transition` when authorized)
- Flip gate flags
- Approve runner execution
- Import plans into the runner
- Auto-transition based on decision history
- Substitute for owner judgment at execution closure

Decision records are inspectable evidence. Manifest state changes are a separate, explicit, future operation.

---

## 9. Forbidden shortcuts

The following are **explicitly forbidden** in compatible implementations:

| # | Forbidden shortcut | Why |
|---|-------------------|-----|
| 1 | Decision file creation that silently mutates `manifest.json` | Separates evidence from state |
| 2 | Validation `OK` causing automatic approval or status advance | Validation is structural, not semantic approval |
| 3 | `APPROVE_FOR_RUN_PROPOSALS` creating runner proposals or runs | Approval is planning-scope only |
| 4 | Runner import from a planning workspace without an explicit future command | No implicit plan → run bridge |
| 5 | Auto-transition based on latest decision | Decisions authorize; they do not execute |
| 6 | Agent self-approval | Generated artifacts cannot record owner decisions |
| 7 | Planning audit `PASS` auto-setting `APPROVED_FOR_RUN_PROPOSALS` | Audit informs; owner decides |
| 8 | Terminal status silently rewound to active | Requires explicit future doctrine change |
| 9 | `BLOCK` treated as permanent `CLOSED` | Distinct decisions with distinct transitions |

Violations are process defects, not features to automate away.

---

## 10. Relation to existing commands

| Command | Role in this doctrine |
|---------|----------------------|
| `agent-os planning init` | Bootstrap DRAFT workspace — no decisions, no transitions |
| `agent-os planning status` | Read-only manifest and structure report |
| `agent-os planning validate` | Read-only structural validation; prerequisite for recording `APPROVE_FOR_RUN_PROPOSALS` |
| `agent-os planning decide` | Append one owner decision record — no manifest mutation |
| `agent-os planning decisions list` | Read-only decision history; reports latest valid decision |
| `agent-os planning transition` | Apply explicit manifest transition when latest owner decision and doctrine authorize it; writes one evidence record |

`agent-os planning transition` does not create decisions, runs, or agent invocations. Unsupported targets (including `SUPERSEDED` and artifact-progress statuses) fail closed.

---

## 11. References

- [`docs/planning-layer-doctrine.md`](planning-layer-doctrine.md) — governed planning layer and role boundaries
- [`docs/planning-workspace-layout.md`](planning-workspace-layout.md) — workspace layout, statuses, and gates
- `agent_os/templates/planning/` — planning artifact template contracts
- `examples/planning-workspace-slither-like/` — EXAMPLE_ONLY sample package
