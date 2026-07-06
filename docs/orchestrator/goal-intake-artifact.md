# Goal intake artifact

> **Status:** deterministic scaffold in `CORE_ORCHESTRATOR_002`; read-only status and validation in `CORE_ORCHESTRATOR_003`; owner clarification records in `CORE_ORCHESTRATOR_004`; read-only readiness review in `CORE_ORCHESTRATOR_005`; owner readiness decision records in `CORE_ORCHESTRATOR_006`; read-only draft-preparation authorization preflight in `CORE_ORCHESTRATOR_007`; DRAFT planning workspace scaffold in `CORE_ORCHESTRATOR_008`; planning context transport in `CORE_ORCHESTRATOR_009`  
> **Commands:**
> - `agent-os orchestrator intake <intake-id> --goal "<raw goal>" [PATH]`
> - `agent-os orchestrator clarify <intake-id> --clarification-id <clarification-id> --answer "<owner-provided clarification>" [PATH]`
> - `agent-os orchestrator decide-readiness <intake-id> --decision <decision> --decision-id <decision-id> --summary "<owner summary>" [PATH]`
> - `agent-os orchestrator draft-preflight <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator prepare-planning-draft <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator transport-planning-context <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator status <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator validate <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator readiness <intake-id> [PATH]` (read-only)
> **Output:**
> - `.agent-os/orchestrator/intakes/<intake-id>/goal-intake.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/clarifications/<clarification-id>.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/readiness-decisions/<decision-id>.json`

The goal intake command creates a durable, reviewable JSON artifact from an owner-provided natural-language goal. It is a registrar-only scaffold: it records input and conservative deterministic metadata so later orchestrator slices can consume the artifact without treating prose as authority. It does **not** call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The clarify command records owner-provided clarification context for an existing `GOAL_INTAKE` artifact. It writes a separate `OWNER_CLARIFICATION` JSON file only. It does **not** call an LLM, modify `goal-intake.json`, change `planning_readiness`, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The status and validate commands inspect the goal intake artifact only. They are read-only and do not call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor. Status also reports clarification record counts when present; clarification records are additive context only.

The readiness command performs a read-only readiness review of the goal intake artifact and any owner clarification records. It summarizes intake validity, ambiguity, clarification count, and the next required action. It does **not** call an LLM, modify artifacts, change `planning_readiness`, mark an intake draft-ready, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor. **Readiness review is not owner readiness decision, not approval, and not planning generation.** Owner clarification records do not automatically make an intake draft-ready. Status and readiness also report owner readiness decision counts when present; those records do not generate a planning draft.

The decide-readiness command records an owner-provided readiness decision after readiness review. It writes a separate `OWNER_READINESS_DECISION` JSON file only. It does **not** call an LLM, modify `goal-intake.json`, modify clarification artifacts, change `planning_readiness`, generate planning drafts, create planning workspaces, approve architecture, create runner proposals, create runs, or invoke an executor. **`AUTHORIZE_DRAFT_PREPARATION` authorizes only a future draft-preparation step** — not draft generation now, not planning approval, not architecture approval, and not execution. Future generated drafts would still need independent validation and owner approval.

The draft-preflight command performs a read-only draft-preparation authorization preflight for an existing intake. It runs the current readiness review, loads owner readiness decision records, identifies the latest decision, and checks whether `AUTHORIZE_DRAFT_PREPARATION` remains coherent with the current readiness review snapshot. It does **not** call an LLM, generate planning drafts, create planning workspaces, approve architecture, approve plans, create runner proposals, create runs, or invoke an executor. **Draft-preparation preflight is not draft generation** — it confirms authorization only and points to a separate future draft-preparation command. Future generated drafts would still need independent validation and owner approval.

The prepare-planning-draft command creates a **DRAFT planning workspace scaffold** from an orchestrator intake only after draft-preflight confirms authorization. It uses the same template bootstrap as `agent-os planning init`, writes orchestrator provenance under `evidence/orchestrator-provenance.json`, and records explicit scaffold boundary notes. It does **not** call an LLM, generate architecture decisions, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, or readiness decision artifacts. **Draft scaffold is not a validated workspace, not architecture approval, and not plan approval.** Provenance is traceability only, not authority. Future manual or agent planning, independent validation, and owner approval remain required.

The transport-planning-context command transports owner-provided intake context into an existing DRAFT planning workspace scaffold created by prepare-planning-draft. It copies goal intake fields, owner clarification answers, and the latest owner readiness decision summary into bounded context transport artifacts under `evidence/orchestrator-context-transport.json` and `evidence/orchestrator-context-transport.md`. Transport copies source context only; it does **not** interpret, generate architecture, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, or core planning template files (`context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, `planning-audit.md`). **Transported context is source material only** — not architecture approval, not local agentic spec, not implementation plan, and not plan approval. The planning workspace remains **DRAFT** and is not validated or approved. Context transport provenance is traceability only, not authority. Future architecture decision, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

---

## Read-only inspection and validation

`agent-os orchestrator status` loads an existing `goal-intake.json` and prints operator-readable fields:

- `intake_id`, `artifact_type`, `schema_version`
- `normalized_goal` (or `raw_goal`)
- `ambiguity_level`, `planning_readiness`
- open-question and risk-flag counts
- owner clarification record count and latest clarification metadata when present
- lightweight structural validation result
- explicit boundary note: **no planning draft was created**
- explicit boundary note: clarifications do not change `planning_readiness`

`agent-os orchestrator validate` performs strict structural validation only:

- file exists and JSON is well-formed
- required fields, types, and non-authority flags
- path `intake_id` matches artifact `intake_id`
- `artifact_type` is `GOAL_INTAKE` and `schema_version` is `"0.1"`
- `ambiguity_level` and `planning_readiness` use documented enum values
- `HIGH` ambiguity is coherent with readiness (`REQUIRES_CLARIFICATION`; never `DRAFT_ALLOWED`)
- content does not contain `PLANNING_RUN_SLICE`

**Validation is not approval.** A structurally valid intake may still have `planning_readiness: REQUIRES_CLARIFICATION`. Validation does not require clarification records. Clarification records are additive context, not approval. Validation does not authorize planning workspace generation, runner proposals, runs, or executor invocation. Future draft generation remains future work.

Neither command mutates files, repairs artifacts, infers missing fields, or creates missing directories beyond what already exists on disk.

---

## Read-only readiness review

`agent-os orchestrator readiness` loads an existing `goal-intake.json` and any clarification records under `clarifications/`, then prints a deterministic readiness review:

- `goal_intake_valid` — structural validation result
- `ambiguity_level`, `planning_readiness` — from the intake artifact (unchanged)
- `owner_clarification_count`, `latest_clarification_id` — from clarification records when present
- `readiness_review_state` — conservative review state (never `DRAFT_ALLOWED` or `READY_FOR_DRAFT`)
- `next_required_action` — operator-facing next step
- `blocking_reasons` — when intake or clarification structure is invalid
- `non_authority` — required non-authority flags for the review itself

Deterministic readiness states in this slice:

| State | Meaning |
|-------|---------|
| `BLOCKED_INVALID_INTAKE` | Goal intake structure is invalid |
| `BLOCKED_REQUIRES_CLARIFICATION` | High ambiguity, clarification required, zero clarifications recorded |
| `OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED` | Clarifications exist but owner readiness decision is still required |
| `OWNER_REVIEW_REQUIRED` | Conservative default for intakes not blocked on clarification |

**Readiness review is not owner readiness decision.** It does not approve planning, authorize draft generation, choose architecture, create planning workspace artifacts, create `PLANNING_RUN_SLICE` blocks, create runner proposals, create runs, or invoke an executor. Owner clarification records do not automatically make an intake draft-ready. Future owner readiness decision and draft/export generation remain future work.

Readiness review non-authority flags (all `true`):

```json
{
  "does_not_create_plan": true,
  "does_not_generate_planning_draft": true,
  "does_not_validate_planning_workspace": true,
  "does_not_approve_plan": true,
  "does_not_transition_workspace": true,
  "does_not_create_runner_proposal": true,
  "does_not_create_run": true,
  "does_not_invoke_executor": true,
  "does_not_mark_intake_draft_ready": true,
  "requires_future_owner_readiness_decision": true
}
```

---

## Owner clarification records

`agent-os orchestrator clarify` records owner-provided clarification text for an existing, structurally valid `GOAL_INTAKE` artifact.

Clarification records are:

- **owner-provided** — no LLM-generated clarification exists in this slice
- **additive context** — they do not modify the original `goal-intake.json`
- **not approval** — they do not change `planning_readiness` or mark an intake draft-ready
- **not architecture decisions** — the orchestrator does not infer requirements or choose architecture from clarifications
- **not planning generation** — no planning workspace, runner proposal, run, or executor invocation is created

### Clarification artifact path

```text
.agent-os/orchestrator/intakes/<intake-id>/clarifications/<clarification-id>.json
```

### Clarification artifact schema

| Field | Current deterministic behavior |
|-------|--------------------------------|
| `artifact_type` | Always `OWNER_CLARIFICATION` |
| `schema_version` | Always `"0.1"` |
| `intake_id` | Parent intake identifier |
| `clarification_id` | Filesystem-safe clarification identifier supplied by the operator |
| `owner_answer` | Exact `--answer` value, preserved verbatim |
| `applies_to_open_questions` | Empty list in this slice |
| `explicit_constraints_added` | Empty list in this slice |
| `non_goals_added` | Empty list in this slice |
| `risk_notes` | Empty list in this slice |
| `created_at` | UTC creation timestamp |
| `non_authority` | Required non-authority flags, all `true` |

### Clarification non-authority flags

Every clarification artifact includes:

```json
{
  "does_not_create_plan": true,
  "does_not_validate_workspace": true,
  "does_not_approve_plan": true,
  "does_not_transition_workspace": true,
  "does_not_create_runner_proposal": true,
  "does_not_create_run": true,
  "does_not_invoke_executor": true,
  "does_not_mark_intake_draft_ready": true,
  "does_not_modify_goal_intake": true
}
```

The clarify command refuses to overwrite an existing clarification artifact, rejects invalid intake or clarification identifiers, rejects empty answers, and fails closed before write when the workspace or goal intake is missing or invalid. Future readiness or draft generation remains future work.

---

## Owner readiness decision records

`agent-os orchestrator decide-readiness` records an owner-provided readiness decision for an existing, structurally valid `GOAL_INTAKE` artifact after readiness review.

Readiness decision records are:

- **owner-provided** — no LLM-generated decision exists in this slice
- **non-authoritative** — they do not modify `goal-intake.json` or clarification artifacts
- **not planning approval** — they do not validate or approve a planning workspace
- **not architecture approval** — they do not choose or approve architecture
- **not draft generation** — no planning workspace, planning artifact, runner proposal, run, or executor invocation is created
- **future-draft gate only when authorized** — `AUTHORIZE_DRAFT_PREPARATION` means only that a future slice may attempt draft preparation; it does not generate a draft now

### Readiness decision artifact path

```text
.agent-os/orchestrator/intakes/<intake-id>/readiness-decisions/<decision-id>.json
```

### Allowed decision values

| Decision | Meaning in this slice |
|----------|------------------------|
| `REQUEST_MORE_CLARIFICATION` | Owner requests more clarification before proceeding |
| `BLOCK_INTAKE` | Owner chooses to stop the intake |
| `AUTHORIZE_DRAFT_PREPARATION` | Owner allows a **future** draft-preparation step only |

`AUTHORIZE_DRAFT_PREPARATION` is rejected when readiness review state is `BLOCKED_INVALID_INTAKE` or `BLOCKED_REQUIRES_CLARIFICATION`. It is allowed only when readiness review state is `OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED` or `OWNER_REVIEW_REQUIRED`.

### Readiness decision artifact schema

| Field | Current deterministic behavior |
|-------|--------------------------------|
| `artifact_type` | Always `OWNER_READINESS_DECISION` |
| `schema_version` | Always `"0.1"` |
| `intake_id` | Parent intake identifier |
| `decision_id` | Filesystem-safe decision identifier supplied by the operator |
| `decision` | One of the allowed decision values above |
| `owner_summary` | Exact `--summary` value, preserved verbatim |
| `readiness_review_state_at_decision` | Snapshot from current readiness review |
| `next_required_action_at_decision` | Snapshot from current readiness review |
| `owner_clarification_count_at_decision` | Snapshot from current readiness review |
| `latest_clarification_id_at_decision` | Snapshot from current readiness review (`null` when none) |
| `created_at` | UTC creation timestamp |
| `non_authority` | Required non-authority flags, all `true` |

### Readiness decision non-authority flags

Every readiness decision artifact includes:

```json
{
  "does_not_create_plan": true,
  "does_not_generate_planning_draft": true,
  "does_not_validate_planning_workspace": true,
  "does_not_approve_plan": true,
  "does_not_transition_workspace": true,
  "does_not_create_runner_proposal": true,
  "does_not_create_run": true,
  "does_not_invoke_executor": true,
  "does_not_approve_architecture": true,
  "does_not_modify_goal_intake": true,
  "does_not_modify_clarifications": true,
  "authorizes_future_draft_preparation_only_when_decision_is_authorize": true
}
```

The decide-readiness command refuses to overwrite an existing decision artifact, rejects invalid intake or decision identifiers, rejects empty summaries, rejects unsupported decision values, and fails closed before write when the workspace or goal intake is missing or invalid. Future draft/export generation remains future work and would still require independent validation and owner approval.

---

## Read-only draft-preparation authorization preflight

`agent-os orchestrator draft-preflight` loads an existing `goal-intake.json`, runs the current readiness review, loads owner readiness decision records, and prints a deterministic authorization preflight:

- `goal_intake_valid` — structural validation result
- `current_readiness_review_state`, `current_next_required_action` — from the current readiness review
- `owner_readiness_decision_count` — readiness decision records found
- `latest_decision_id`, `latest_decision`, `latest_decision_created_at` — latest decision by deterministic ordering
- `latest_decision_snapshot_state` — `readiness_review_state_at_decision` from the latest decision when present
- `preflight_state` — authorization preflight result (never `DRAFT_ALLOWED` or `READY_FOR_DRAFT`)
- `next_required_action` — operator-facing next step
- `blocking_reasons` — when intake, decisions, or snapshot coherence block preflight
- `non_authority` — required non-authority flags for the preflight itself

Deterministic preflight states in this slice:

| State | Meaning |
|-------|---------|
| `BLOCKED_INVALID_INTAKE` | Goal intake structure is invalid |
| `BLOCKED_NO_READINESS_DECISION` | No owner readiness decision records exist |
| `BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION` | Latest decision requests more clarification |
| `BLOCKED_LATEST_DECISION_BLOCKS_INTAKE` | Latest decision blocks the intake |
| `BLOCKED_LATEST_DECISION_NOT_AUTHORIZE` | Latest valid decision is not authorization |
| `BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT` | Latest `AUTHORIZE_DRAFT_PREPARATION` snapshot no longer matches current readiness review |
| `BLOCKED_INVALID_READINESS_DECISION` | Latest readiness decision artifact is malformed or invalid |
| `DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED` | Authorization confirmed; no draft generated |

Snapshot coherence compares `readiness_review_state_at_decision`, `next_required_action_at_decision`, `owner_clarification_count_at_decision`, and `latest_clarification_id_at_decision` against the current readiness review. Any mismatch treats authorization as stale.

**Draft-preparation preflight is not draft generation.** It does not create planning workspace artifacts, approve architecture, approve plans, create runner proposals, create runs, or invoke an executor. `AUTHORIZE_DRAFT_PREPARATION` still requires a separate future draft-preparation command. Future runner proposal generation remains separate.

Draft-preparation preflight non-authority flags (all `true`):

```json
{
  "does_not_create_plan": true,
  "does_not_generate_planning_draft": true,
  "does_not_create_planning_workspace": true,
  "does_not_validate_planning_workspace": true,
  "does_not_approve_plan": true,
  "does_not_approve_architecture": true,
  "does_not_transition_workspace": true,
  "does_not_create_runner_proposal": true,
  "does_not_create_run": true,
  "does_not_invoke_executor": true,
  "does_not_modify_goal_intake": true,
  "does_not_modify_clarifications": true,
  "does_not_modify_readiness_decisions": true,
  "requires_separate_future_draft_preparation_command": true,
  "requires_future_independent_validation_before_plan_approval": true,
  "requires_future_owner_approval_before_run_proposals": true
}
```

---

## Artifact schema

The artifact is JSON with these fields:

| Field | Current deterministic behavior |
|-------|--------------------------------|
| `artifact_type` | Always `GOAL_INTAKE` |
| `schema_version` | Always `"0.1"` |
| `intake_id` | Filesystem-safe intake identifier supplied by the operator |
| `raw_goal` | Exact `--goal` value, preserved verbatim |
| `normalized_goal` | Whitespace-normalized `raw_goal`; no semantic rewrite |
| `user_visible_summary` | Same value as `normalized_goal` |
| `explicit_constraints` | Empty list in this slice |
| `inferred_assumptions` | Empty list in this slice |
| `open_questions` | Generic owner clarification prompt |
| `non_goals` | Empty list in this slice |
| `risk_flags` | Empty unless a deterministic broad-product guard fires |
| `ambiguity_level` | `HIGH` for simple broad product-building guards such as `Build me an online slither.io-like game`; otherwise conservative default |
| `planning_readiness` | `REQUIRES_CLARIFICATION` for `HIGH`; otherwise conservative default |
| `created_at` | UTC creation timestamp |
| `non_authority` | Required non-authority flags, all `true` |

Current normalization is intentionally shallow. For example, tabs and newlines collapse to single spaces, but the command does not infer backend, frontend, networking, persistence, deployment target, implementation slices, or architecture choices.

---

## Non-authority flags

Every artifact includes:

```json
{
  "does_not_create_plan": true,
  "does_not_validate_workspace": true,
  "does_not_approve_plan": true,
  "does_not_transition_workspace": true,
  "does_not_create_runner_proposal": true,
  "does_not_create_run": true,
  "does_not_invoke_executor": true,
  "generated_markdown_is_not_machine_authority": true
}
```

These flags are part of the artifact contract. They make explicit that goal intake is not planning approval, planning draft is not a validated workspace, architecture recommendation is not owner decision, implementation plan is not runner proposal, `PLANNING_RUN_SLICE` is not an approved run, generated Markdown prose is not machine authority, planning provenance is not execution authority, runner import remains explicit, and executor invocation remains separate.

---

## Boundary rules

The intake command writes only the goal-intake JSON artifact under the orchestrator intake path. The clarify command writes only clarification JSON artifacts under `clarifications/` for that intake. Status and validate are read-only: they load the goal intake file and report results without mutation.

None of these commands create `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, `planning-audit.md`, `PLANNING_RUN_SLICE` blocks, runs, owner decisions, planning transitions, or executor records.

The intake command refuses to overwrite an existing `goal-intake.json`, rejects invalid intake identifiers, and rejects empty goals. It requires an existing `.agent-os` workspace and does not create a planning workspace. The clarify command refuses to overwrite an existing clarification artifact, rejects invalid clarification identifiers, and rejects empty answers. It requires an existing `.agent-os` workspace and a valid `GOAL_INTAKE` artifact and does not create a planning workspace. Status and validate require an existing workspace and intake artifact; they do not create a planning workspace or orchestrator directories when missing.

Future slices may consume `goal-intake.json`, but the artifact is input provenance and review material only. It is not machine authority for planning, running, or execution.
