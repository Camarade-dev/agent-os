# Planning workspace layout

> **Status:** layout contract — bootstrap via `agent-os planning init <plan-id>`; weak validation via `agent-os planning validate <plan-id>`  
> **Doctrine:** `docs/planning-layer-doctrine.md`  
> **Templates:** `agent_os/templates/planning/`  
> **Example:** `examples/planning-workspace-slither-like/` (EXAMPLE_ONLY)

This document defines where a **concrete planning package** lives in a target project and how governed planning artifacts are arranged. The layout is a **local artifact contract** — operators fill artifacts manually and advance manifest status via explicit CLI commands (`planning progress`, `planning decide`, `planning transition`). Nothing in this layout executes code, creates runs, or invokes agents.

---

## 1. Root path

Each planning package occupies one directory under the adopting project:

```
.agent-os/planning/<plan-id>/
```

| Segment | Rule |
|---------|------|
| `.agent-os/` | Same workspace root as Agent OS execution runs (`.agent-os/runs/<run-id>/`) |
| `planning/` | Sibling to `runs/`; holds pre-execution artifacts only |
| `<plan-id>` | Stable identifier chosen by the owner (e.g. `slither-game-20260705`, `plan-auth-refactor`) |

Multiple plans may coexist. Only one plan version is **active** per `<plan-id>` unless `revisions/` holds superseded copies.

---

## 2. Directory layout

```
.agent-os/planning/<plan-id>/
  manifest.json
  README.md
  context-pack.md
  local-agentic-spec.md
  implementation-plan.md
  planning-audit.md
  evidence/
  decisions/
  revisions/
```

### `manifest.json`

Machine-readable identity and gate state for the planning package. Updated by explicit CLI commands (`agent-os planning progress` for artifact-readiness statuses; `agent-os planning transition` for owner-decision statuses). Do not edit `manifest.json` manually in the normal flow except for emergency/recovery. No auto-advance.

| Field | Type | Purpose |
|-------|------|---------|
| `plan_id` | string | Same as `<plan-id>` directory name |
| `goal` | string | Owner-stated objective (summary) |
| `status` | string | One of the allowed statuses (§3) |
| `artifact_paths` | object | Relative paths to primary artifacts (defaults below) |
| `created_at` | string | ISO 8601 timestamp |
| `updated_at` | string | ISO 8601 timestamp (optional) |
| `owner` | string | Responsible owner (optional) |
| `gates` | object | Open/closed gate flags (§4); keys use snake_case |
| `authority` | object | Safety flags set at bootstrap (`no_execution`, `no_agent_invocation`, `no_run_creation`, `no_self_approval`) |
| `active_revision` | string | `1` or revision label; which plan body is authoritative |
| `example_only` | boolean | `true` for samples; must not be used for real execution |

Default `artifact_paths`:

```json
{
  "context_pack": "context-pack.md",
  "local_agentic_spec": "local-agentic-spec.md",
  "implementation_plan": "implementation-plan.md",
  "planning_audit": "planning-audit.md"
}
```

Default `gates` (snake_case keys):

```json
{
  "planning_owner_decision_required": true,
  "planning_audit_required": true,
  "plan_revision_required": false,
  "run_proposal_allowed": false
}
```

### `context-pack.md`

Copied or rendered from `agent_os/templates/planning/context-pack.md`. Assembled **read-only** context: goal reference, sources inspected, constraints, unknowns, risks, provenance. Does not define execution scope or approve work.

### `local-agentic-spec.md`

Copied or rendered from `agent_os/templates/planning/local-agentic-spec.md`. Bounded planning intent: in-scope/out-of-scope outcomes, constraints, quality bar, ambiguities. Does **not** authorize execution or repository mutation.

### `implementation-plan.md`

Copied or rendered from `agent_os/templates/planning/implementation-plan.md`. Ordered **slices** (planned runs), each with mission, scope, `allowed_paths`, authority, `check_command` (if applicable), expected evidence, stop conditions, owner gates, and dependencies. Slices are **not executable** until converted to a Next Run Proposal and approved.

**Structured slice blocks:** each slice may include a fenced JSON block with `"artifact_type": "PLANNING_RUN_SLICE"` — a machine-readable contract for **future** runner structured import. Prose sections remain human-readable; import must not infer authority from free text. See [`docs/planning-structured-slice-format.md`](planning-structured-slice-format.md). Blocks are optional today and do not execute anything.

### `planning-audit.md`

Copied or rendered from `agent_os/templates/planning/planning-audit.md`. Independent review of planning artifacts before plan-driven run proposals. Verdict is `PASS`, `PASS_WITH_NOTES`, `FAIL`, or `BLOCKED`. Does **not** approve execution.

### `evidence/`

Planning evidence and provenance: context citations, revision diffs, checklists, owner notes supporting planning claims. Separate from **execution** evidence under `.agent-os/runs/<run-id>/evidence.md`.

**Manifest transition records** (via `agent-os planning transition`) are JSON files named `<UTC_TIMESTAMP>__manifest-transition.json` (e.g. `2026-07-05T20-15-30Z__manifest-transition.json`). Each record has `record_type: PLANNING_MANIFEST_TRANSITION`, `from_status`, `to_status`, the owner `decision` and `decision_file` that authorized the transition, `validation_required` / `validation_result`, `gate_effects`, and authority flags stating the record applies an owner decision only — it does not create decisions, execute, create runs, or invoke agents. Transition writes exactly one evidence file plus an explicit `manifest.json` update; planning artifacts and `decisions/` are not modified.

### `decisions/`

Recorded owner decisions about planning artifacts (spec acceptance, plan approval, audit acknowledgment, gate overrides). One file per decision is recommended.

**CLI-recorded decisions** (via `agent-os planning decide`) are JSON files named `<UTC_TIMESTAMP>__owner-decision.json` (e.g. `2026-07-05T20-15-30Z__owner-decision.json`). Each record has `record_type: PLANNING_OWNER_DECISION`, the decision value (`APPROVE_FOR_RUN_PROPOSALS`, `REQUEST_REVISION`, `BLOCK`, or `CLOSE`), a short `summary`, and authority flags stating the record is evidence only — it does not execute, create runs, mutate `manifest.json`, or approve runner execution.

**Listing decisions** (`agent-os planning decisions list <plan-id>`) is read-only: it prints valid `PLANNING_OWNER_DECISION` JSON records sorted by `created_at`, reports the latest decision, and skips (with a note) JSON files whose `record_type` is not `PLANNING_OWNER_DECISION`. Malformed JSON or invalid owner records fail closed. No files are modified; no runs are created; no agents are invoked.

Manual markdown decision files are also permitted (e.g. `decisions/20260705-spec-accepted.md`).

### `revisions/`

Later plan revisions **not active** unless explicitly approved and referenced in `manifest.json` (`active_revision`). Prevents silent overwrite of an approved plan. Example: `revisions/implementation-plan-v2.md`.

### `README.md`

Local instructions for operators working in this directory: how artifacts relate, where templates live, and a **non-authority notice** — this README does not approve work, create runs, or invoke agents.

---

## 3. Allowed statuses

Statuses describe **planning maturity**, not execution state. Two explicit CLI paths update `manifest.json` status:

- **`agent-os planning progress`** — artifact-readiness transitions (`DRAFT` → `CONTEXT_READY` → `SPEC_READY` → `PLAN_READY` → `PLANNING_AUDIT_READY`). Records artifact readiness only; does not consume owner decisions or approve run proposals.
- **`agent-os planning transition`** — owner-decision transitions (`APPROVED_FOR_RUN_PROPOSALS`, `BLOCKED`, `CLOSED`) when the latest valid owner decision authorizes the target — see [`docs/planning-decision-transition-doctrine.md`](planning-decision-transition-doctrine.md). Decision records alone do not change `status` or `gates`.

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

Recommended progression (gates may block):

```
DRAFT → CONTEXT_READY → SPEC_READY → PLAN_READY → PLANNING_AUDIT_READY
  → APPROVED_FOR_RUN_PROPOSALS → (per-slice proposals via runner) → CLOSED
```

`BLOCKED` and `SUPERSEDED` may be entered from any non-terminal status.

---

## 4. Gate semantics

Gates are recorded in `manifest.json` under `gates` (open = `true`). Closing a gate requires an explicit owner or role-bounded action documented in `decisions/` and an explicit manifest transition (`agent-os planning transition`) — decision records alone do not flip gates ([`docs/planning-decision-transition-doctrine.md`](planning-decision-transition-doctrine.md) §7).

| Transition target | Gate effects applied by `planning transition` |
|-------------------|-----------------------------------------------|
| `APPROVED_FOR_RUN_PROPOSALS` | `run_proposal_allowed: true`; `planning_owner_decision_required`, `planning_audit_required`, `plan_revision_required`: `false` |
| `BLOCKED` | `run_proposal_allowed: false`; `plan_revision_required: true`; `planning_owner_decision_required: false`; `planning_audit_required` preserved (default `true` if absent) |
| `CLOSED` | All planning gates closed (`false` for open-required gates; `run_proposal_allowed: false`) |

| Progress target (`planning progress`) | Gate effects applied by `planning progress` |
|-------------------------------------|---------------------------------------------|
| `CONTEXT_READY`, `SPEC_READY`, `PLAN_READY` | `planning_audit_required: true`; `planning_owner_decision_required: true`; `plan_revision_required: false`; `run_proposal_allowed: false` |
| `PLANNING_AUDIT_READY` | `planning_audit_required: false`; `planning_owner_decision_required: true`; `plan_revision_required: false`; `run_proposal_allowed: false` |

Artifact-progress transitions do **not** approve run proposals. `PLANNING_AUDIT_READY` means planning artifacts and the planning audit are ready for an owner decision — not that run proposals are allowed.

| Gate key | When open | Closed by |
|----------|-----------|-----------|
| `planning_owner_decision_required` | Owner must accept spec, plan, or audit acknowledgment | Owner decision record in `decisions/` |
| `planning_audit_required` | Planning Audit not yet `PASS` / `PASS_WITH_NOTES` | Planning Audit artifact updated; gate cleared via `agent-os planning progress --to PLANNING_AUDIT_READY` |
| `plan_revision_required` | Material plan change needed after audit or owner review | New revision in `revisions/` approved; `active_revision` updated |
| `run_proposal_allowed` | Plan may feed `propose-next-run` (one slice at a time) | Set when status is `APPROVED_FOR_RUN_PROPOSALS` and planning gates above are closed |

**`run_proposal_allowed` does not invoke an executor.** It only signals that an operator may manually derive a Next Run Proposal from an Implementation Plan slice, subject to runner approval gates.

---

## 5. Artifact chain within the workspace

```
Goal (manifest.goal)
  │
  ▼
context-pack.md
  │
  ▼
local-agentic-spec.md
  │
  ▼
implementation-plan.md
  │
  ▼
planning-audit.md
  │
  ▼
Next Run Proposal (runner — not stored as authoritative in this layout)
  │
  ▼
Approved Run → Execution → …
```

Planning Audit sits **before** plan-driven Next Run Proposals. Execution evidence and audit remain under `.agent-os/runs/` or the experimental runner layout — not in `planning/<plan-id>/evidence/` unless copied for planning provenance only.

---

## 6. Hard rules

| # | Rule |
|---|------|
| 1 | A planning workspace **does not execute code** |
| 2 | A planning workspace **does not create runs by itself** |
| 3 | A Planning Audit **does not approve execution** |
| 4 | An Implementation Plan slice is **not executable** until turned into a Next Run Proposal and approved |
| 5 | **No artifact self-approves** — owner decisions are explicit records in `decisions/` |
| 6 | **No Cursor/agent invocation** happens from this layout |
| 7 | Runner and Agent OS core **must not** auto-read or auto-advance this workspace without an explicit operator command (future importers included) |
| 8 | Planning `evidence/` is not a substitute for execution evidence at run closure |

Violations are process defects, not features to automate away.

---

## 7. Bootstrapping a new package

### CLI (registrar only)

After `agent-os init`, create a DRAFT planning workspace:

```bash
agent-os planning init <plan-id> [PATH]
```

This creates `.agent-os/planning/<plan-id>/` with templates copied from `agent_os/templates/planning/`, a DRAFT `manifest.json`, subdirectories, and a non-authority `README.md`. It does **not** execute code, create runs, invoke agents, or validate artifact content.

After orchestrator intake authorization, a DRAFT scaffold may also be created from intake provenance:

```bash
agent-os orchestrator prepare-planning-draft <intake-id> --plan-id <plan-id> [PATH]
```

Requires successful `agent-os orchestrator draft-preflight` first. Creates the same DRAFT workspace layout as `planning init`, plus orchestrator traceability artifacts under `evidence/`:

- `evidence/orchestrator-provenance.json` — links the scaffold to the intake and authorize decision; **provenance is traceability only, not authority**
- `evidence/orchestrator-draft-scaffold-notes.md` — explicit scaffold boundary notes only; **not architecture approval, not plan approval, not workspace validation**

The workspace remains **`DRAFT`** — it is **not validated or approved**. Architecture and implementation plan content are **not generated** (only existing template placeholders). Does **not** generate `PLANNING_RUN_SLICE`; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts.

After scaffold creation, transport owner-provided intake context into the planning workspace:

```bash
agent-os orchestrator transport-planning-context <intake-id> --plan-id <plan-id> [PATH]
```

Requires an existing DRAFT scaffold from `prepare-planning-draft` for the same intake/plan pair, confirmed draft-preflight, and matching orchestrator provenance. Writes bounded context transport artifacts under `evidence/`:

- `evidence/orchestrator-context-transport.json` — structured copy of goal intake context, clarifications, readiness decision, and preflight snapshot; **transported context is source material only, not authority**
- `evidence/orchestrator-context-transport.md` — human-readable copy with explicit boundary notes; **not architecture approval, not implementation plan, not workspace validation**

Transport copies owner-provided context; it does **not** interpret it, generate architecture, generate implementation plans, or generate `PLANNING_RUN_SLICE`. The workspace remains **`DRAFT`** — it is **not validated or approved**. Does **not** mutate core planning templates (`context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, `planning-audit.md`), orchestrator intake artifacts, or orchestrator provenance. Future architecture decision, independent validation, owner approval, and runner proposal generation remain separate.

After context transport, draft the planning workspace `context-pack.md` from transported context:

```bash
agent-os orchestrator draft-context-pack <intake-id> --plan-id <plan-id> [PATH]
```

Requires an existing DRAFT scaffold with matching orchestrator provenance and context transport artifacts for the same intake/plan pair, confirmed draft-preflight, and `context-pack.md` still in the planning init placeholder shape. Writes a bounded source-context draft to `context-pack.md` and provenance under `evidence/`:

- `evidence/orchestrator-context-pack-draft-provenance.json` — links the draft to transport artifacts and authorize decision; **provenance is traceability only, not authority**

The context pack draft copies transported source context only; it does **not** generate architecture, local agentic spec, implementation plan, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, orchestrator provenance, or other planning templates. **Context pack draft is source-context only** — not architecture decision, not approved context pack, not local agentic spec, not implementation plan. The planning workspace remains **`DRAFT`** — it is **not validated or approved**. Future architecture decision, local agentic spec, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

After a coherent context-pack draft exists, run read-only local-agentic-spec draft eligibility preflight:

```bash
agent-os orchestrator local-agentic-spec-preflight <intake-id> --plan-id <plan-id> [PATH]
```

Requires an existing DRAFT scaffold with matching orchestrator provenance, context transport artifacts, and context-pack draft provenance for the same intake/plan pair; confirmed draft-preflight; `context-pack.md` labeled `DRAFT_NON_AUTHORITY` with required boundary notes; and `local-agentic-spec.md`, `implementation-plan.md`, and `planning-audit.md` still in planning init placeholder shape. **Does not write any artifact** — read-only gate only. Local-agentic-spec preflight does **not** generate or mutate `local-agentic-spec.md`; does **not** generate architecture decisions, implementation plans, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, or `context-pack.md`. **Successful preflight is not local agentic spec generation** — not architecture decision, not implementation planning, not validation or approval. A separate future local-agentic-spec draft command remains required. Future architecture decision, implementation plan, independent validation, and owner approval remain required.

After successful local-agentic-spec-preflight, scaffold the planning workspace `local-agentic-spec.md` structure:

```bash
agent-os orchestrator scaffold-local-agentic-spec <intake-id> --plan-id <plan-id> [PATH]
```

Requires an existing DRAFT scaffold with matching orchestrator provenance, context-pack draft provenance, and confirmed local-agentic-spec-preflight for the same intake/plan pair; `local-agentic-spec.md` still in planning init placeholder shape; and `implementation-plan.md` and `planning-audit.md` still in planning init placeholder shape. Writes a bounded `SCAFFOLD_DRAFT_NON_AUTHORITY` structure to `local-agentic-spec.md` and provenance under `evidence/`:

- `evidence/orchestrator-local-agentic-spec-scaffold-provenance.json` — links the scaffold to context-pack draft provenance and preflight state; **provenance is traceability only, not authority**

The local-agentic-spec scaffold provides structure, provenance references, and explicit boundaries only; it does **not** extract or infer requirements, generate user stories or acceptance criteria, generate architecture, implementation plan, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Local-agentic-spec scaffold is not requirements extraction** — not spec approval, not architecture decision, not implementation planning. The planning workspace remains **`DRAFT`** — it is **not validated or approved**. Future requirements extraction, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

After a coherent local-agentic-spec scaffold exists, run read-only requirements extraction eligibility preflight:

```bash
agent-os orchestrator requirements-extraction-preflight <intake-id> --plan-id <plan-id> [PATH]
```

Requires an existing DRAFT scaffold with matching orchestrator provenance, context transport artifacts, context-pack draft provenance, and local-agentic-spec scaffold provenance for the same intake/plan pair; confirmed draft-preparation authorization; `local-agentic-spec.md` labeled `SCAFFOLD_DRAFT_NON_AUTHORITY` with required boundary notes and only scaffold/pending sections; and `implementation-plan.md` and `planning-audit.md` still in planning init placeholder shape. **Does not write any artifact** — read-only gate only. Requirements extraction preflight does **not** extract or infer requirements; does **not** generate user stories or acceptance criteria; does **not** generate architecture decisions, implementation plans, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Successful preflight is not requirements extraction** — not spec approval, not architecture decision, not implementation planning, not validation or approval. A separate future requirements extraction command remains required. Future architecture decision, implementation plan, independent validation, and owner approval remain required.

After successful requirements-extraction-preflight, scaffold empty requirements-extraction containers in the planning workspace `local-agentic-spec.md`:

```bash
agent-os orchestrator scaffold-requirements-extraction <intake-id> --plan-id <plan-id> [PATH]
```

Requires an existing DRAFT scaffold with matching orchestrator provenance, context-pack draft provenance, local-agentic-spec scaffold provenance, and confirmed requirements-extraction-preflight for the same intake/plan pair; `local-agentic-spec.md` still labeled `SCAFFOLD_DRAFT_NON_AUTHORITY` with only scaffold/pending sections; and `implementation-plan.md` and `planning-audit.md` still in planning init placeholder shape. Writes a bounded `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` structure to `local-agentic-spec.md` and provenance under `evidence/`:

- `evidence/orchestrator-requirements-extraction-scaffold-provenance.json` — links the requirements-extraction scaffold to context-pack path, local-agentic-spec scaffold provenance, and preflight state; **provenance is traceability only, not authority**

The requirements-extraction scaffold provides empty requirements containers, provenance references, and explicit boundaries only; it does **not** extract or infer requirements, generate requirements content, generate user stories or acceptance criteria, generate architecture, implementation plan, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements-extraction scaffold is not requirements extraction** — not spec approval, not architecture decision, not implementation planning. Requirements sections contain only explicit empty placeholders such as `NO_REQUIREMENTS_EXTRACTED` and `NOT_GENERATED`. The planning workspace remains **`DRAFT`** — it is **not validated or approved**. Future requirements extraction, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

After a coherent requirements-extraction scaffold exists, record an owner requirements extraction decision:

```bash
agent-os orchestrator decide-requirements-extraction <intake-id> --plan-id <plan-id> --decision <REQUEST_MORE_CONTEXT|BLOCK_REQUIREMENTS_EXTRACTION|AUTHORIZE_REQUIREMENTS_EXTRACTION> --decision-id <decision-id> --summary "<owner summary>" [PATH]
```

Requires an existing DRAFT scaffold with matching requirements-extraction scaffold provenance, post-scaffold coherence, confirmed draft-preparation authorization, and `local-agentic-spec.md` labeled `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` without generated requirements, user stories, acceptance criteria, architecture decisions, implementation tasks, or `PLANNING_RUN_SLICE` content. Writes an append-only decision artifact under `.agent-os/orchestrator/intakes/<intake-id>/requirements-extraction-decisions/<plan-id>/<decision-id>.json`. **Does not extract or infer requirements**; does **not** generate requirements content or requirement IDs; does **not** generate user stories or acceptance criteria; does **not** generate architecture decisions, implementation plans, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, requirements-extraction scaffold provenance, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements extraction owner decision is not requirements extraction** — not requirements approval, not architecture decision, not implementation planning, not validation or approval. `AUTHORIZE_REQUIREMENTS_EXTRACTION` authorizes only a future separate requirements extraction command; authorization is not extraction. `REQUEST_MORE_CONTEXT` and `BLOCK_REQUIREMENTS_EXTRACTION` do not mutate the scaffold or requirements content. Future requirements extraction, requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

Inspect an existing planning workspace (read-only):

```bash
agent-os planning status <plan-id> [PATH]
```

Reports workspace path, manifest status, expected artifact files and directories (present/missing), gate and authority flags from `manifest.json`, and a structural result (`OK` or `BROKEN`). Fails closed when the workspace, manifest, or required structure is missing or invalid. Does **not** create, modify, or delete files.

Weak read-only validation (does not approve execution):

```bash
agent-os planning validate <plan-id> [PATH]
```

Checks manifest fields, authority safety flags, artifact type markers, required sections, and obvious unfilled `{{...}}` placeholders. Reports structural, manifest, and artifact validation results plus a final result (`OK` or `INVALID`). This is **not** semantic validation — it does not judge plan quality, approve execution, infer readiness, or advance status or gates. Does **not** create, modify, or delete files, create runs, or invoke agents.

Apply artifact-progress manifest transitions (no owner decision):

```bash
agent-os planning progress <plan-id> [PATH] --to <status>
```

Supported targets: `CONTEXT_READY`, `SPEC_READY`, `PLAN_READY`, `PLANNING_AUDIT_READY`. Enforces sequential progress from the current status, runs weak per-artifact readiness checks (full validation required for `PLANNING_AUDIT_READY`), updates `manifest.json` (`status`, `gates`, `updated_at`, `last_progress_transition`), and writes exactly one evidence record under `evidence/`:

- Filename: `<UTC_TIMESTAMP>__artifact-progress.json` (filesystem-safe UTC, e.g. `2026-07-05T20-15-30Z__artifact-progress.json`)
- `record_type`: `PLANNING_ARTIFACT_PROGRESS`
- Authority flags: `artifact_progress_only`, `does_not_record_owner_decision`, `does_not_approve_run_proposals`, `does_not_create_runs`, `does_not_execute`, `does_not_invoke_agents`, `does_not_touch_runner`

Does **not** record owner decisions, approve run proposals, create runs, invoke agents, or touch the runner.

### Manual

1. Choose `<plan-id>` and create `.agent-os/planning/<plan-id>/`.
2. Copy `agent_os/templates/planning/*.md` into the directory (rename to kebab-case filenames above).
3. Write `manifest.json` with `status: DRAFT` and gates as appropriate.
4. Write `README.md` with local instructions and non-authority notice.
5. Create empty `evidence/`, `decisions/`, `revisions/` as needed.
6. Fill artifacts in order: Context Pack → Spec → Plan → Planning Audit.
7. Advance artifact-readiness with `agent-os planning progress` (see [`docs/planning-end-to-end-demo.md`](planning-end-to-end-demo.md) for the full lifecycle).
8. Record owner decisions and apply explicit manifest transitions with `agent-os planning decide` and `agent-os planning transition`.

---

## 8. References

- `docs/planning-layer-doctrine.md` — planning doctrine and role boundaries
- `docs/planning-structured-slice-format.md` — `PLANNING_RUN_SLICE` JSON contract for future runner import
- `agent_os/templates/planning/` — artifact templates
- `examples/planning-workspace-slither-like/` — EXAMPLE_ONLY sample package
- `agent-os-runner-experimental/docs/planning-artifact-consumption.md` — future runner read rules
