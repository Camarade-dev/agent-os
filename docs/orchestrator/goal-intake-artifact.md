# Goal intake artifact

> **Status:** deterministic scaffold in `CORE_ORCHESTRATOR_002`; read-only status and validation in `CORE_ORCHESTRATOR_003`  
> **Commands:**
> - `agent-os orchestrator intake <intake-id> --goal "<raw goal>" [PATH]`
> - `agent-os orchestrator status <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator validate <intake-id> [PATH]` (read-only)
> **Output:** `.agent-os/orchestrator/intakes/<intake-id>/goal-intake.json`

The goal intake command creates a durable, reviewable JSON artifact from an owner-provided natural-language goal. It is a registrar-only scaffold: it records input and conservative deterministic metadata so later orchestrator slices can consume the artifact without treating prose as authority. It does **not** call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The status and validate commands inspect that artifact only. They are read-only and do not call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

---

## Read-only inspection and validation

`agent-os orchestrator status` loads an existing `goal-intake.json` and prints operator-readable fields:

- `intake_id`, `artifact_type`, `schema_version`
- `normalized_goal` (or `raw_goal`)
- `ambiguity_level`, `planning_readiness`
- open-question and risk-flag counts
- lightweight structural validation result
- explicit boundary note: **no planning draft was created**

`agent-os orchestrator validate` performs strict structural validation only:

- file exists and JSON is well-formed
- required fields, types, and non-authority flags
- path `intake_id` matches artifact `intake_id`
- `artifact_type` is `GOAL_INTAKE` and `schema_version` is `"0.1"`
- `ambiguity_level` and `planning_readiness` use documented enum values
- `HIGH` ambiguity is coherent with readiness (`REQUIRES_CLARIFICATION`; never `DRAFT_ALLOWED`)
- content does not contain `PLANNING_RUN_SLICE`

**Validation is not approval.** A structurally valid intake may still have `planning_readiness: REQUIRES_CLARIFICATION`. Validation does not authorize planning workspace generation, runner proposals, runs, or executor invocation. Future draft generation remains future work.

Neither command mutates files, repairs artifacts, infers missing fields, or creates missing directories beyond what already exists on disk.

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

The intake command writes only the goal-intake JSON artifact under the orchestrator intake path. Status and validate are read-only: they load that file and report results without mutation.

None of these commands create `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, `planning-audit.md`, `PLANNING_RUN_SLICE` blocks, runs, owner decisions, planning transitions, or executor records.

The intake command refuses to overwrite an existing `goal-intake.json`, rejects invalid intake identifiers, and rejects empty goals. It requires an existing `.agent-os` workspace and does not create a planning workspace. Status and validate require an existing workspace and intake artifact; they do not create a planning workspace or orchestrator directories when missing.

Future slices may consume `goal-intake.json`, but the artifact is input provenance and review material only. It is not machine authority for planning, running, or execution.
