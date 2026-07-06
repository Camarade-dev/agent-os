# Goal intake artifact

> **Status:** deterministic scaffold in `CORE_ORCHESTRATOR_002`; read-only status and validation in `CORE_ORCHESTRATOR_003`; owner clarification records in `CORE_ORCHESTRATOR_004`; read-only readiness review in `CORE_ORCHESTRATOR_005`  
> **Commands:**
> - `agent-os orchestrator intake <intake-id> --goal "<raw goal>" [PATH]`
> - `agent-os orchestrator clarify <intake-id> --clarification-id <clarification-id> --answer "<owner-provided clarification>" [PATH]`
> - `agent-os orchestrator status <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator validate <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator readiness <intake-id> [PATH]` (read-only)
> **Output:**
> - `.agent-os/orchestrator/intakes/<intake-id>/goal-intake.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/clarifications/<clarification-id>.json`

The goal intake command creates a durable, reviewable JSON artifact from an owner-provided natural-language goal. It is a registrar-only scaffold: it records input and conservative deterministic metadata so later orchestrator slices can consume the artifact without treating prose as authority. It does **not** call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The clarify command records owner-provided clarification context for an existing `GOAL_INTAKE` artifact. It writes a separate `OWNER_CLARIFICATION` JSON file only. It does **not** call an LLM, modify `goal-intake.json`, change `planning_readiness`, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The status and validate commands inspect the goal intake artifact only. They are read-only and do not call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor. Status also reports clarification record counts when present; clarification records are additive context only.

The readiness command performs a read-only readiness review of the goal intake artifact and any owner clarification records. It summarizes intake validity, ambiguity, clarification count, and the next required action. It does **not** call an LLM, modify artifacts, change `planning_readiness`, mark an intake draft-ready, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor. **Readiness review is not owner readiness decision, not approval, and not planning generation.** Owner clarification records do not automatically make an intake draft-ready. Future owner readiness decision and draft/export generation remain future work.

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
