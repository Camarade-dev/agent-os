# Planning workspace layout

> **Status:** layout contract — bootstrap via `agent-os planning init <plan-id>`; no validation or automation  
> **Doctrine:** `docs/planning-layer-doctrine.md`  
> **Templates:** `agent_os/templates/planning/`  
> **Example:** `examples/planning-workspace-slither-like/` (EXAMPLE_ONLY)

This document defines where a **concrete planning package** lives in a target project and how governed planning artifacts are arranged. The layout is a **local artifact contract** — operators copy templates, fill artifacts, and advance gates manually. Nothing in this layout executes code, creates runs, or invokes agents.

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

Machine-readable identity and gate state for the planning package. Updated manually by the owner or planning roles; no auto-advance.

| Field | Type | Purpose |
|-------|------|---------|
| `plan_id` | string | Same as `<plan-id>` directory name |
| `goal` | string | Owner-stated objective (summary) |
| `status` | string | One of the allowed statuses (§3) |
| `artifact_paths` | object | Relative paths to primary artifacts (defaults below) |
| `created_at` | string | ISO 8601 timestamp |
| `updated_at` | string | ISO 8601 timestamp (optional) |
| `owner` | string | Responsible owner (optional) |
| `gates` | object | Open/closed gate flags (§4) |
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

### `context-pack.md`

Copied or rendered from `agent_os/templates/planning/context-pack.md`. Assembled **read-only** context: goal reference, sources inspected, constraints, unknowns, risks, provenance. Does not define execution scope or approve work.

### `local-agentic-spec.md`

Copied or rendered from `agent_os/templates/planning/local-agentic-spec.md`. Bounded planning intent: in-scope/out-of-scope outcomes, constraints, quality bar, ambiguities. Does **not** authorize execution or repository mutation.

### `implementation-plan.md`

Copied or rendered from `agent_os/templates/planning/implementation-plan.md`. Ordered **slices** (planned runs), each with mission, scope, `allowed_paths`, authority, `check_command` (if applicable), expected evidence, stop conditions, owner gates, and dependencies. Slices are **not executable** until converted to a Next Run Proposal and approved.

### `planning-audit.md`

Copied or rendered from `agent_os/templates/planning/planning-audit.md`. Independent review of planning artifacts before plan-driven run proposals. Verdict is `PASS`, `PASS_WITH_NOTES`, `FAIL`, or `BLOCKED`. Does **not** approve execution.

### `evidence/`

Planning evidence and provenance: context citations, revision diffs, checklists, owner notes supporting planning claims. Separate from **execution** evidence under `.agent-os/runs/<run-id>/evidence.md`.

### `decisions/`

Recorded owner decisions about planning artifacts (spec acceptance, plan approval, audit acknowledgment, gate overrides). One file per decision is recommended (e.g. `decisions/20260705-spec-accepted.md`).

### `revisions/`

Later plan revisions **not active** unless explicitly approved and referenced in `manifest.json` (`active_revision`). Prevents silent overwrite of an approved plan. Example: `revisions/implementation-plan-v2.md`.

### `README.md`

Local instructions for operators working in this directory: how artifacts relate, where templates live, and a **non-authority notice** — this README does not approve work, create runs, or invoke agents.

---

## 3. Allowed statuses

Statuses describe **planning maturity**, not execution state. Transitions are manual; no status self-advances.

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

Gates are recorded in `manifest.json` under `gates` (open = `true`). Closing a gate requires an explicit owner or role-bounded action documented in `decisions/`.

| Gate | When open | Closed by |
|------|-----------|-----------|
| `planning-owner-decision-required` | Owner must accept spec, plan, or audit acknowledgment | Owner decision record in `decisions/` |
| `planning-audit-required` | Planning Audit not yet `PASS` / `PASS_WITH_NOTES` | Planning Audit artifact updated; gate cleared in manifest |
| `plan-revision-required` | Material plan change needed after audit or owner review | New revision in `revisions/` approved; `active_revision` updated |
| `run-proposal-allowed` | Plan may feed `propose-next-run` (one slice at a time) | Set when status is `APPROVED_FOR_RUN_PROPOSALS` and planning gates above are closed |

**`run-proposal-allowed` does not invoke an executor.** It only signals that an operator may manually derive a Next Run Proposal from an Implementation Plan slice, subject to runner approval gates.

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

### Manual

1. Choose `<plan-id>` and create `.agent-os/planning/<plan-id>/`.
2. Copy `agent_os/templates/planning/*.md` into the directory (rename to kebab-case filenames above).
3. Write `manifest.json` with `status: DRAFT` and gates as appropriate.
4. Write `README.md` with local instructions and non-authority notice.
5. Create empty `evidence/`, `decisions/`, `revisions/` as needed.
6. Fill artifacts in order: Context Pack → Spec → Plan → Planning Audit.
7. Record owner decisions and update `manifest.json` status and gates manually.

---

## 8. References

- `docs/planning-layer-doctrine.md` — planning doctrine and role boundaries
- `agent_os/templates/planning/` — artifact templates
- `examples/planning-workspace-slither-like/` — EXAMPLE_ONLY sample package
- `agent-os-runner-experimental/docs/planning-artifact-consumption.md` — future runner read rules
