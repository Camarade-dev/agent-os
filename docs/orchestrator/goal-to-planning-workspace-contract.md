# Goal-to-planning workspace contract

> **Status:** doctrine and contract plus deterministic goal-intake scaffold CLI — no LLM adapter, no autonomous generation, no UI  
> **Slice:** `CORE_ORCHESTRATOR_002` adds `agent-os orchestrator intake` for `GOAL_INTAKE` artifact creation only; `CORE_ORCHESTRATOR_003` adds read-only `orchestrator status` and `orchestrator validate`; `CORE_ORCHESTRATOR_004` adds owner clarification records via `orchestrator clarify`; planning workspace drafting remains future work  
> **Companions:** [`goal-intake-artifact.md`](goal-intake-artifact.md), [`architecture-decision-boundary.md`](architecture-decision-boundary.md), [`slither-like-demo-contract.md`](slither-like-demo-contract.md), [`../planning-layer-doctrine.md`](../planning-layer-doctrine.md), [`../planning-workspace-layout.md`](../planning-workspace-layout.md)

This document defines the **formal contract** for a future Agent OS orchestrator that receives a natural-language goal and eventually proposes a **governed planning workspace draft**. It authorizes nothing. The current implementation is limited to deterministic `GOAL_INTAKE` JSON artifact scaffolding; it does not implement architecture generation, planning generation, validation, transition, runner import, or executor invocation.

---

## 1. Purpose and scope

The orchestrator layer sits **upstream** of the existing governed planning workspace:

```
Natural-language goal
  │
  ▼
Goal intake (structured representation)
  │
  ▼
Architecture decision record (proposals + rationale)
  │
  ▼
Planning workspace draft (artifacts + optional PLANNING_RUN_SLICE sketch)
  │
  ▼
[Existing planning lifecycle — manual / CLI, not orchestrator]
  validate → audit → owner decision → transition → (separate) runner import → approval → invoke
```

**In scope for this contract:**

- Minimum structured goal representation
- What a generated planning workspace draft may contain
- Boundary doctrine preserving gate separation
- Independent validation requirements

**Out of scope (explicit non-goals):**

- LLM or agent adapters
- Chat UI or hidden planners
- Autonomous artifact generation
- Architecture selection or implementation-plan generation
- `agent-os planning init` automation from orchestrator output
- `PLANNING_RUN_SLICE` creation in the intake scaffold
- Runner proposal creation or structured import
- Executor invocation
- Modifications to `agent-os-runner-experimental`

---

## 2. Goal intake contract

The current `agent-os orchestrator intake` command normalizes every user goal into a **Goal Intake Record** before any future drafting stage. Free-form prose is provenance only; machine processing uses the structured record. The implemented intake command is deterministic and does not call an LLM.

The intake artifact is written to:

```text
.agent-os/orchestrator/intakes/<intake-id>/goal-intake.json
```

This file is planning-adjacent input. It is not a planning workspace, not a validated workspace, not an owner decision, not a runner proposal, and not an approved run.

Owner clarification records live alongside the intake at:

```text
.agent-os/orchestrator/intakes/<intake-id>/clarifications/<clarification-id>.json
```

Clarification records are owner-provided context only. They do not modify `goal-intake.json`, do not change `planning_readiness`, are not approval, are not architecture decisions, and are not planning generation. No LLM-generated clarification exists in the current implementation.

### 2.1 Minimum fields

| Field | Type | Purpose |
|-------|------|---------|
| `raw_goal` | string | Verbatim user input (e.g. `"Build me an online slither.io-like game"`) |
| `normalized_goal` | string | Whitespace-normalized goal text for the deterministic scaffold; no semantic rewrite in `CORE_ORCHESTRATOR_002` |
| `user_visible_summary` | string | Short summary suitable for manifest `goal` and Context Pack header |
| `explicit_constraints` | string[] | Constraints stated or confirmed by the user |
| `inferred_assumptions` | object[] | Empty in `CORE_ORCHESTRATOR_002`; future inference must be labeled and reviewable |
| `open_questions` | object[] | Each: `{ question, impact, suggested_owner_action, blocks_first_slice }` |
| `non_goals` | string[] | Explicit exclusions to prevent scope creep |
| `risk_flags` | object[] | Each: `{ risk, likelihood, impact, mitigation_planning_only }` |
| `ambiguity_level` | enum | `LOW` \| `MEDIUM` \| `HIGH` |
| `planning_readiness` | enum | `NOT_READY` \| `DRAFT_ALLOWED` \| `REQUIRES_CLARIFICATION`; the deterministic intake scaffold never uses high ambiguity to allow drafts |

### 2.2 Doctrine

| Rule | Meaning |
|------|---------|
| **Inferred assumptions are not facts** | Every `inferred_assumptions` entry must be labeled as inference; none may be written into planning artifacts as settled truth without owner confirmation |
| **Open questions do not block all planning** | `open_questions` must be visible in the draft Context Pack; `blocks_first_slice: true` marks questions that must be resolved before the first `PLANNING_RUN_SLICE` is proposed — other planning may proceed |
| **High ambiguity prevents automatic approval** | When `ambiguity_level` is `HIGH`, the orchestrator must not emit signals that imply planning readiness for owner approval; `planning_readiness` must not be `DRAFT_ALLOWED` without explicit owner clarification |
| **No generated plan may become authoritative without owner decision** | Goal intake output is input to drafting only; owner decision remains mandatory per [`../planning-decision-transition-doctrine.md`](../planning-decision-transition-doctrine.md) |

### 2.3 Example intake shape (illustrative, non-authoritative)

```json
{
  "raw_goal": "Build me an online slither.io-like game",
  "normalized_goal": "Deliver a browser-playable, Slither.io-inspired snake game with real-time multiplayer over the network.",
  "user_visible_summary": "Online Slither-like browser game (multiplayer)",
  "explicit_constraints": [],
  "inferred_assumptions": [
    {
      "assumption": "User wants networked multiplayer, not offline single-player only",
      "basis": "Phrase 'online' and slither.io reference",
      "confidence": "medium",
      "requires_owner_confirmation": true
    }
  ],
  "open_questions": [
    {
      "question": "Target player count per room?",
      "impact": "Affects networking and server design",
      "suggested_owner_action": "Confirm in architecture decision record",
      "blocks_first_slice": false
    }
  ],
  "non_goals": ["Mobile native apps", "Blockchain", "Monetization"],
  "risk_flags": [
    {
      "risk": "Networking complexity exceeds demo scope",
      "likelihood": "high",
      "impact": "Delayed delivery",
      "mitigation_planning_only": "Define first implementation slice boundary without backend"
    }
  ],
  "ambiguity_level": "HIGH",
  "planning_readiness": "REQUIRES_CLARIFICATION"
}
```

---

## 3. Planning workspace draft contract

A **planning workspace draft** is a proposed set of files that **may** be copied or merged into `.agent-os/planning/<plan-id>/` after owner review. Until validated, decided, and transitioned, it is not a governed workspace.

### 3.1 Allowed contents

| Artifact | Draft status | Notes |
|----------|--------------|-------|
| `context-pack.md` | draft | Includes goal reference, constraints, assumptions, open questions, architecture summary pointer |
| `local-agentic-spec.md` | draft | Bounded planning intent; does not authorize execution |
| `implementation-plan.md` | draft | Ordered slices in prose; may include fenced `PLANNING_RUN_SLICE` JSON blocks |
| `planning-audit.md` | draft or checklist | Pre-audit checklist or draft audit — not a PASS verdict |
| `decisions/*.md` | optional draft | Never auto-populated as APPROVE |
| Fenced `PLANNING_RUN_SLICE` JSON | sketch | Machine-readable slice **sketch** per [`../planning-structured-slice-format.md`](../planning-structured-slice-format.md) |

### 3.2 What “draft” means

| Property | Draft | Validated workspace |
|----------|-------|---------------------|
| `agent-os planning validate` | Not yet run or may fail | Structural OK when operator runs validate |
| Owner decision | Not recorded | May exist under `decisions/` |
| Manifest `status` | Not advanced by orchestrator | Advanced only via explicit CLI |
| Runner import | Not performed | Separate explicit operator step |
| Execution | Forbidden | Still forbidden until run approval + invoke |

**Draft means:**

- **not validated** — `planning draft is not a validated workspace`
- **not approved** — no owner `APPROVE_FOR_RUN_PROPOSALS`
- **not transitioned** — orchestrator must not call `planning transition`
- **not executable** — no runs, no executor, no `allowed_paths` authority
- **not runner-authoritative** — prose and JSON sketches are proposals only

### 3.3 Orchestrator output envelope (future)

A future orchestrator may emit a single **Planning Workspace Draft Envelope** containing:

```json
{
  "artifact_type": "PLANNING_WORKSPACE_DRAFT",
  "schema_version": "0.1",
  "plan_id_proposal": "slither-online-demo",
  "goal_intake_ref": "<hash or path>",
  "architecture_decision_ref": "<hash or path>",
  "artifact_drafts": {
    "context_pack": "<markdown>",
    "local_agentic_spec": "<markdown>",
    "implementation_plan": "<markdown>",
    "planning_audit": "<markdown or checklist>"
  },
  "non_authority": {
    "does_not_validate": true,
    "does_not_transition": true,
    "does_not_create_run": true,
    "does_not_import_runner": true,
    "does_not_invoke_executor": true,
    "requires_owner_review": true,
    "requires_planning_validate": true,
    "requires_planning_audit": true,
    "requires_owner_decision": true
  }
}
```

This envelope is **not implemented** in Agent OS core today. It documents the contract only.

---

## 4. Boundary doctrine

The orchestrator layer must preserve these separations. Each phrase is normative:

| Boundary | Doctrine |
|----------|----------|
| Goal intake | **goal intake is not planning approval** |
| Planning draft | **planning draft is not a validated workspace** |
| Architecture | **architecture recommendation is not owner decision** |
| Implementation plan | **implementation plan is not runner proposal** |
| Structured slice | **PLANNING_RUN_SLICE is not an approved run** |
| Markdown prose | **generated Markdown prose is not machine authority** |
| Runner | **runner import remains explicit** and separate from orchestrator output |
| Executor | **executor invocation remains separate** from all planning and orchestrator stages |
| Provenance | **planning provenance is not authority** — source pointers do not substitute for gates |

Additional rules:

- The orchestrator must not bypass owner decision.
- The orchestrator must not bypass `agent-os planning validate`.
- The orchestrator must not transition a planning workspace automatically.
- The orchestrator must not couple planning generation to runner proposal creation.
- The orchestrator must not parse free-form Markdown as machine authority; only fenced `PLANNING_RUN_SLICE` JSON may carry structured slice fields.

---

## 5. Independent validation doctrine

Architecture and infrastructure choices are costly to reverse. Orchestrator output must be auditable by an **independent planning audit pass** before owner approval.

### 5.1 Requirements

| Requirement | Detail |
|-------------|--------|
| **Auditable output** | Goal intake, architecture record, and draft artifacts must be inspectable without re-running the orchestrator |
| **Audit scope** | Assumptions, architecture choices, scope boundaries, first-slice safety, non-goals, open questions |
| **Reject or revise** | Audit may yield `FAIL`, `PASS_WITH_NOTES`, or request revision — same spirit as planning audit doctrine |
| **Independence** | Audit must not be performed by the same context that generated the plan unless explicitly marked `non_independent: true` |
| **Owner gate** | Audit pass does not replace owner decision; owner remains final gate for `APPROVE_FOR_RUN_PROPOSALS` |

### 5.2 Audit checklist (minimum)

The draft `planning-audit.md` or checklist produced by the orchestrator should include:

1. Are inferred assumptions labeled and visible?
2. Are architecture options and rejected alternatives documented?
3. Is the first implementation slice bounded and safe?
4. Does the first `PLANNING_RUN_SLICE` sketch avoid execution authority fields?
5. Are open questions with `blocks_first_slice: true` resolved or escalated?
6. Is `ambiguity_level` consistent with planning readiness?
7. Does any prose imply approval, execution, or runner authority? (must be none)

---

## 6. Relation to existing planning CLI

These commands exist today and remain **operator-driven**; the orchestrator must not invoke them autonomously:

| Command | Role |
|---------|------|
| `agent-os planning init` | Creates workspace from templates — future orchestrator may **propose** draft content for operator merge |
| `agent-os planning validate` | Structural validation — not orchestrator self-certification |
| `agent-os planning progress` | Artifact-readiness status — manual/explicit |
| `agent-os planning decide` | Owner judgment record |
| `agent-os planning transition` | Manifest transition — explicit, gated |

**Implemented intake scaffold:** `agent-os orchestrator intake <intake-id> --goal "<raw goal>" [PATH]` creates a reviewable `GOAL_INTAKE` JSON artifact only.

**Implemented owner clarification:** `agent-os orchestrator clarify <intake-id> --clarification-id <clarification-id> --answer "<owner-provided clarification>" [PATH]` records an `OWNER_CLARIFICATION` JSON artifact only. It does not modify the goal intake, change readiness, generate planning drafts, create runs, or invoke an executor.

**Implemented read-only inspection:** `agent-os orchestrator status <intake-id> [PATH]` and `agent-os orchestrator validate <intake-id> [PATH]` inspect and structurally validate the goal intake artifact. Validation is not approval, not owner decision, and not planning generation. A valid intake may still require clarification; clarification records are additive and not required for structural validation.

**Future work (not implemented):** `agent-os orchestrator draft-export` or any command that auto-runs the planning lifecycle above. Documenting draft-export does not imply implementation.

---

## 7. Non-authority statement

This contract does not approve work, create runs, invoke agents, import planning into the runner, or authorize repository changes. Generated drafts remain proposals until the owner validates, audits, decides, and transitions through existing planning doctrine.
