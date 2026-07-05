# Planning structured slice format

> **Status:** doctrine and schema only — no CLI, no parser, no runner import in this slice  
> **Companion:** `docs/planning-workspace-layout.md`, `docs/planning-layer-doctrine.md`  
> **Runner boundary:** `agent-os-runner-experimental/docs/planning-to-run-boundary.md`, `docs/planning-artifact-consumption.md`

This document defines the **machine-readable contract** for Implementation Plan slices that a future runner import command may consume. It does not implement import, parsing, proposal creation, approval, or execution.

---

## 1. Why free-form Markdown is not enough

Implementation Plan slices today are written as human-readable Markdown: headings, bullet fields, and occasional inline JSON for `allowed_paths`. That format is appropriate for owners, auditors, and planning progress validation.

It is **not** sufficient for governed runner import because:

| Problem | Risk |
|---------|------|
| **Ambiguous field boundaries** | Prose scope paragraphs can be interpreted differently by humans and tools |
| **No stable slice identity** | Headings and table labels vary; weak text search is not a contract |
| **Mixed authority signals** | Narrative text may sound like approval or execution intent without explicit gates |
| **Inline JSON without schema** | `allowed_paths` arrays in prose sections are not tied to a versioned import contract |
| **Semantic inference temptation** | Tools might “helpfully” extract mission/scope from paragraphs and bypass owner gates |

**Doctrine:**

- **Markdown implementation plans remain human-readable.** Owners continue to read and review slices in prose.
- **Structured slice blocks are machine-readable contracts.** A future importer reads only fenced `PLANNING_RUN_SLICE` JSON — not surrounding prose.
- **Future runner import may consume only structured slice blocks.** Prose tables and paragraphs are provenance for humans, not import authority.
- **Free text must never be semantically interpreted into executable authority.** No NLP, no Markdown heading heuristics, no “best effort” field extraction.
- **Missing or ambiguous structured fields must fail closed.** Import refuses rather than guessing.
- **Structured fields still do not execute anything.** They describe what a proposal *may* carry after explicit operator mapping.
- **Imported fields still require proposal creation, approval, and explicit invoke.** `propose-next-run` → `approve-next-run` → `invoke-run --allow-executor` remain separate gates.

Current runner behavior (`planning_source` provenance on `propose-next-run`) is unchanged by this document. Structured blocks are optional in planning workspaces today and become required only when a future import command is invoked.

---

## 2. Canonical format

Structured slices live **inside** `implementation-plan.md` as fenced JSON blocks. Each block is one slice contract.

**Fence:** standard Markdown ` ```json ` … ` ``` ` (language tag `json`).

**Discriminator:** top-level `"artifact_type": "PLANNING_RUN_SLICE"`.

**Placement:** immediately under the human-readable slice section for the same `slice_id`, or in a clearly labeled “Structured slice contract” subsection. Multiple blocks in one file are allowed; each must have a unique `slice_id`.

**Example (canonical):**

```json
{
  "artifact_type": "PLANNING_RUN_SLICE",
  "schema_version": "0.1",
  "slice_id": "slice-001-scaffold",
  "mission": "Create minimal slither-demo/ with index.html, style.css, game.js stubs.",
  "scope": "Scaffold files only; no game logic beyond placeholders.",
  "authority": "L2",
  "allowed_paths": [
    "slither-demo/index.html",
    "slither-demo/style.css",
    "slither-demo/game.js"
  ],
  "check_command": "",
  "expected_evidence": [
    "Three files exist; browser opens blank canvas container."
  ],
  "stop_conditions": [
    "Do not implement loop or snake in this slice."
  ],
  "owner_gates": [
    "Next Run Proposal approval per runner doctrine."
  ],
  "dependencies": ["slice-01-spec-confirmation"],
  "non_authority": {
    "does_not_create_run": true,
    "does_not_approve_proposal": true,
    "does_not_invoke_executor": true,
    "requires_runner_proposal": true,
    "requires_approve_next_run": true,
    "requires_invoke_run_allow_executor": true
  }
}
```

`schema_version` `0.1` is the initial contract. Future versions may add optional fields; importers must reject unknown **required** shapes and forbidden keys (§5).

---

## 3. Field definitions

### Required fields

| Field | Type | Definition |
|-------|------|------------|
| `artifact_type` | string | Must be exactly `PLANNING_RUN_SLICE`. Identifies this JSON block as the import contract (distinct from `allowed_paths`-only arrays elsewhere in the file). |
| `schema_version` | string | Semver-style label for this schema (e.g. `"0.1"`). Importers must understand the version or fail closed. |
| `slice_id` | string | Stable identifier for this slice within the plan (e.g. `slice-001-scaffold`). Must match the operator-supplied `--planning-slice-id` at import time. Unique among all `PLANNING_RUN_SLICE` blocks in the workspace. |
| `mission` | string | Single bounded outcome for one execution cycle. Maps to future `propose-next-run --mission` when explicitly imported — not auto-applied today. |
| `scope` | string | In-scope and out-of-scope summary for this run. Maps to future `propose-next-run --scope`. Prefer alignment with `allowed_paths`. |
| `authority` | string | Autonomy level (e.g. `L0`–`L4`) per Agent OS doctrine. Maps to future `propose-next-run --authority`. |
| `allowed_paths` | array of strings | Repository-relative paths (files or directories) that may change during execution. Non-empty. No `..`, no absolute paths, no drive prefixes. Preferred scope authority for `scope_delta`. |
| `check_command` | string | Verification command for `invoke-run --check-command` when runner policy requires one. May be empty string only if policy allows empty; otherwise import fails closed. |
| `expected_evidence` | array of strings | Closure-grade evidence expectations for auditors and owners. Informational for import; does not create evidence. |
| `stop_conditions` | array of strings | Conditions under which the executor must stop. Informational for prompts and audit; not auto-enforced by import. |
| `owner_gates` | array of strings | Explicit owner or runner gates before/after this slice (e.g. proposal approval). Informational; import does not close gates. |
| `dependencies` | array of strings | Prior slice ids or external prerequisites. Operator checklist only; import does not enforce ordering. |
| `non_authority` | object | Mandatory safety flags (§4). All listed keys must be present and `true`. Documents that the block is not execution authority. |

### Optional fields

| Field | Type | Definition |
|-------|------|------------|
| `notes` | string | Free-form operator notes. Must not be interpreted as authority. |
| `risk_notes` | string | Risk commentary for owners. Non-authoritative. |
| `suggested_timeout_seconds` | number | Hint for executor timeout configuration. Import does not set timeouts unless a future slice explicitly maps it at invoke time. |
| `evidence_labels` | array of strings | Short labels for expected evidence categories (e.g. `manual-browser-check`). Informational only. |

### Forbidden fields

The following must **not** appear in a `PLANNING_RUN_SLICE` block. Presence fails closed at import:

| Forbidden field | Reason |
|-----------------|--------|
| `executor_command` | Implies direct execution |
| `invoke_command` | Implies direct invocation |
| `auto_approve` | Bypasses owner approval gate |
| `auto_invoke` | Bypasses `invoke-run --allow-executor` |
| `decision` | Conflates planning with owner/run decision |
| `owner_decision` | Same |
| `approval` | Same |
| `run_status` | Claims run lifecycle state |
| `audit_result` | Claims execution audit outcome |
| Any field that claims execution occurred | e.g. `executed_at`, `executor_invoked`, `run_id`, `proposal_approved` |

Extensible forbidden pattern: any key suggesting that planning artifacts already created runs, approved proposals, invoked executors, or recorded audit/closure outcomes.

---

## 4. `non_authority` object

Every structured slice must include `non_authority` with **all** of the following keys set to **`true`**:

| Key | Meaning |
|-----|---------|
| `does_not_create_run` | This block does not create `.program-os/runs/` metadata |
| `does_not_approve_proposal` | This block does not approve a Next Run Proposal |
| `does_not_invoke_executor` | This block does not call an executor or agent |
| `requires_runner_proposal` | A `propose-next-run` (or future import-assisted propose) step is still required |
| `requires_approve_next_run` | Owner `approve-next-run` is still required |
| `requires_invoke_run_allow_executor` | `invoke-run --allow-executor` remains a separate explicit step |

If any key is missing or `false`, import must **fail closed**. These flags are descriptive contracts for tooling and auditors; they do not replace runner gates.

---

## 5. Validation expectations (future import)

A future `import` or `propose-from-slice` command (not implemented in this slice) must **fail closed** when:

| Condition | Result |
|-----------|--------|
| No `PLANNING_RUN_SLICE` block exists for the requested `slice_id` | Reject |
| Multiple blocks share the same `slice_id` | Reject |
| JSON is malformed | Reject |
| Required field missing | Reject |
| Unknown dangerous / forbidden field present (§3) | Reject |
| `artifact_type` is not `PLANNING_RUN_SLICE` | Reject (block ignored or import fails per policy) |
| `allowed_paths` is empty | Reject |
| `allowed_paths` entry contains `..`, is absolute, or is otherwise path-traversal | Reject |
| `check_command` is empty when runner policy requires a check command | Reject |
| Any `non_authority` flag missing or `false` | Reject |
| CLI `--planning-slice-id` does not match `slice_id` inside the selected block | Reject |
| Planning workspace not `APPROVED_FOR_RUN_PROPOSALS` with `run_proposal_allowed: true` | Reject (same as current planning reference boundary) |

**Non-goals for import validation:** judging plan quality, inferring fields from Markdown prose, or auto-fixing ambiguous paths.

**After successful validation (future slice):** import may **suggest** or **prefill** proposal fields for operator review. It must not auto-approve, auto-create runs, or auto-invoke. Operator confirmation and existing gates remain mandatory unless a later doctrine explicitly changes that — out of scope here.

---

## 6. Relationship to human-readable slices

Each slice should keep its Markdown section (mission, scope, tables) for owners and `planning validate` weak checks. The structured block is the **runner-import contract** for that slice.

| Layer | Audience | Authority |
|-------|----------|-----------|
| Prose slice section | Humans, planning audit | Planning only — not runner scope |
| `PLANNING_RUN_SLICE` JSON | Future importer | Candidate proposal fields — still gated |
| `planning_source` on proposal/run | Runner provenance | Reference only today; no field override |

Prose and JSON should agree. Drift is a governance defect: owners compare at approval time. Import must not reconcile drift by preferring prose.

---

## 7. References

- `agent_os/templates/planning/implementation-plan.md` — template with structured slice placeholder
- `examples/planning-workspace-slither-like/implementation-plan.md` — EXAMPLE_ONLY sample block
- `docs/planning-workspace-layout.md` — workspace layout
- `docs/planning-end-to-end-demo.md` — lifecycle demo (structured blocks optional today)
- `agent-os-runner-experimental/docs/planning-artifact-consumption.md` — current consumption boundary
- `agent-os-runner-experimental/docs/planning-to-run-boundary.md` — plan → run mapping
