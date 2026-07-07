# Goal-to-planning workspace contract

> **Status:** doctrine and contract plus deterministic goal-intake scaffold CLI — no LLM adapter, no autonomous generation, no UI  
> **Slice:** `CORE_ORCHESTRATOR_002` adds `agent-os orchestrator intake` for `GOAL_INTAKE` artifact creation only; `CORE_ORCHESTRATOR_003` adds read-only `orchestrator status` and `orchestrator validate`; `CORE_ORCHESTRATOR_004` adds owner clarification records via `orchestrator clarify`; `CORE_ORCHESTRATOR_005` adds read-only `orchestrator readiness` review; `CORE_ORCHESTRATOR_006` adds owner readiness decision records via `orchestrator decide-readiness`; `CORE_ORCHESTRATOR_007` adds read-only `orchestrator draft-preflight` authorization preflight; `CORE_ORCHESTRATOR_008` adds `orchestrator prepare-planning-draft` for DRAFT planning workspace scaffold creation only after confirmed draft-preflight; `CORE_ORCHESTRATOR_009` adds `orchestrator transport-planning-context` for bounded intake context transport into an existing DRAFT scaffold only; `CORE_ORCHESTRATOR_010` adds `orchestrator draft-context-pack` for bounded context pack draft from transported context only; `CORE_ORCHESTRATOR_011` adds read-only `orchestrator local-agentic-spec-preflight` for local-agentic-spec draft eligibility only; `CORE_ORCHESTRATOR_012` adds `orchestrator scaffold-local-agentic-spec` for local-agentic-spec scaffold structure only after confirmed local-agentic-spec-preflight; `CORE_ORCHESTRATOR_013` adds read-only `orchestrator requirements-extraction-preflight` for requirements extraction eligibility only after confirmed local-agentic-spec scaffold; `CORE_ORCHESTRATOR_014` adds `orchestrator scaffold-requirements-extraction` for empty requirements-extraction scaffold containers only after confirmed requirements-extraction-preflight; `CORE_ORCHESTRATOR_015` adds `orchestrator decide-requirements-extraction` for requirements extraction owner decision records only after coherent requirements-extraction scaffold; `CORE_ORCHESTRATOR_016` adds read-only `orchestrator requirements-extraction-execution-check` for requirements extraction pre-execution authorization only after latest plan-scoped `AUTHORIZE_REQUIREMENTS_EXTRACTION`; `CORE_ORCHESTRATOR_017` adds `orchestrator extract-requirements-draft` for deterministic source-bounded requirements draft candidates only after successful requirements-extraction execution check  
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

`agent-os orchestrator readiness` performs a read-only readiness review over the intake and clarification records. It summarizes whether clarification is still required or an explicit owner readiness decision is needed. Readiness review is not owner readiness decision, not approval, not planning generation, and does not authorize draft export. Owner clarification records do not automatically make an intake draft-ready. No planning workspace, runner proposal, run, or executor invocation is created.

Owner readiness decision records live alongside the intake at:

```text
.agent-os/orchestrator/intakes/<intake-id>/readiness-decisions/<decision-id>.json
```

`agent-os orchestrator decide-readiness` records an owner-provided readiness decision after readiness review. Readiness decision is not planning approval, not architecture approval, and not draft generation. `AUTHORIZE_DRAFT_PREPARATION` authorizes only a future draft-preparation step. No planning workspace, planning artifact, runner proposal, run, or executor invocation is created. Future draft/export generation remains future work; any generated draft would still need independent validation and owner approval.

`agent-os orchestrator draft-preflight` performs a read-only draft-preparation authorization preflight over the goal intake, clarification records, and owner readiness decisions. It checks authorization only: whether the latest owner readiness decision is `AUTHORIZE_DRAFT_PREPARATION` and whether its readiness snapshot still matches the current readiness review. Draft-preparation preflight is not draft generation, not planning workspace creation, not architecture approval, not plan approval, and does not create runner proposals, runs, or executor invocations. `AUTHORIZE_DRAFT_PREPARATION` still requires a separate future draft-preparation command. Future generated drafts would still need independent validation and owner approval. Future runner proposal generation remains separate.

`agent-os orchestrator prepare-planning-draft` creates a **DRAFT planning workspace scaffold** under `.agent-os/planning/<plan-id>/` only after draft-preflight confirms `DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED`. It bootstraps the normal planning init template set, writes `evidence/orchestrator-provenance.json` linking to the intake and authorize decision, and records explicit scaffold boundary notes. It does not generate architecture, implementation plans, or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts. **Draft scaffold is not a validated workspace** — future manual or agent planning, independent validation, and owner approval remain required. Provenance is traceability only, not authority.

`agent-os orchestrator transport-planning-context` transports owner-provided intake context into an existing DRAFT planning workspace scaffold created by prepare-planning-draft for the same intake/plan pair. It requires confirmed draft-preflight, matching orchestrator provenance, and workspace status still `DRAFT`. It writes bounded context transport artifacts under `evidence/orchestrator-context-transport.json` and `evidence/orchestrator-context-transport.md`. Transport copies source context only; it does not interpret intake, generate architecture, generate implementation plans, or generate `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts or provenance. **Transported context is source material only** — not architecture decision, not local agentic spec, not implementation plan, and not plan approval. The planning workspace remains `DRAFT` and is not validated or approved. Context transport provenance is traceability only, not authority. Future architecture decision, independent validation, and owner approval remain required.

`agent-os orchestrator draft-context-pack` drafts planning workspace `context-pack.md` from existing context transport artifacts in a DRAFT workspace for the same intake/plan pair. It requires confirmed draft-preflight, matching orchestrator provenance and transport artifacts, and `context-pack.md` still in the planning init placeholder shape. It writes a bounded source-context draft to `context-pack.md` and `evidence/orchestrator-context-pack-draft-provenance.json`. The draft copies transported source context only; it does not generate architecture, local agentic spec, implementation plan, or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts, transport artifacts, orchestrator provenance, or other planning templates. **Context pack draft is source-context only** — not architecture decision, not approved context pack, not local agentic spec, not implementation plan. The planning workspace remains `DRAFT` and is not validated or approved. Context pack draft provenance is traceability only, not authority. Future architecture decision, local agentic spec, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

`agent-os orchestrator local-agentic-spec-preflight` performs a read-only eligibility preflight for whether a future local-agentic-spec draft command may be allowed. It requires a DRAFT planning workspace with coherent orchestrator provenance, context transport artifacts, a `DRAFT_NON_AUTHORITY` context-pack draft with required boundary notes, confirmed draft-preparation authorization, and planning init placeholders still present for `local-agentic-spec.md`, `implementation-plan.md`, and `planning-audit.md`. It does not generate or mutate `local-agentic-spec.md`; does not generate architecture decisions; does not generate implementation plans or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; does not mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, or `context-pack.md`; and does not write a preflight artifact. **Local-agentic-spec preflight is not local agentic spec generation** — not architecture decision, not implementation planning, not validation or approval. Successful preflight confirms only that a separate future local-agentic-spec draft command may be attempted. Future architecture decision, implementation plan, independent validation, and owner approval remain required.

`agent-os orchestrator scaffold-local-agentic-spec` replaces the planning init `local-agentic-spec.md` placeholder with a `SCAFFOLD_DRAFT_NON_AUTHORITY` structure in a DRAFT workspace for the same intake/plan pair after successful local-agentic-spec-preflight. It requires confirmed draft-preflight, matching orchestrator provenance, context-pack draft provenance, and `local-agentic-spec.md` still in planning init placeholder shape. It writes a bounded scaffold to `local-agentic-spec.md` and `evidence/orchestrator-local-agentic-spec-scaffold-provenance.json`. The scaffold provides structure, provenance references, and explicit boundaries only; it does not extract or infer requirements, generate user stories or acceptance criteria, generate architecture decisions, generate implementation plans or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Local-agentic-spec scaffold is not requirements extraction** — not spec approval, not architecture decision, not implementation planning. The planning workspace remains `DRAFT` and is not validated or approved. Scaffold provenance is traceability only, not authority. Future requirements extraction, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

`agent-os orchestrator requirements-extraction-preflight` performs a read-only eligibility preflight for whether a future requirements extraction command may be allowed. It requires a DRAFT planning workspace with coherent orchestrator provenance, context transport artifacts, context-pack draft provenance, a `SCAFFOLD_DRAFT_NON_AUTHORITY` local-agentic-spec scaffold with required boundary notes, confirmed draft-preparation authorization, and `implementation-plan.md` and `planning-audit.md` still in planning init placeholder shape. It does not extract or infer requirements; does not generate user stories or acceptance criteria; does not generate architecture decisions; does not generate implementation plans or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; does not mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`; and does not write a preflight artifact. **Requirements extraction preflight is not requirements extraction** — not spec approval, not architecture decision, not implementation planning, not validation or approval. Successful preflight confirms only that a separate future requirements extraction command may be attempted. Future architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

`agent-os orchestrator scaffold-requirements-extraction` replaces the `SCAFFOLD_DRAFT_NON_AUTHORITY` local-agentic-spec structure with a `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` structure in a DRAFT workspace for the same intake/plan pair after successful requirements-extraction-preflight. It requires confirmed requirements-extraction-preflight, matching orchestrator provenance, context-pack draft provenance, local-agentic-spec scaffold provenance, and `local-agentic-spec.md` still in `SCAFFOLD_DRAFT_NON_AUTHORITY` shape with only scaffold/pending sections. It writes a bounded empty requirements-extraction scaffold to `local-agentic-spec.md` and `evidence/orchestrator-requirements-extraction-scaffold-provenance.json`. The scaffold provides empty requirements containers, provenance references, and explicit boundaries only; it does not extract or infer requirements, generate requirements content, generate user stories or acceptance criteria, generate architecture decisions, generate implementation plans or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements-extraction scaffold is not requirements extraction** — not spec approval, not architecture decision, not implementation planning. Requirements sections contain only explicit empty placeholders such as `NO_REQUIREMENTS_EXTRACTED` and `NOT_GENERATED`. The planning workspace remains `DRAFT` and is not validated or approved. Scaffold provenance is traceability only, not authority. Future requirements extraction, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

`agent-os orchestrator decide-requirements-extraction` records an owner-provided requirements extraction decision for an existing `GOAL_INTAKE` and DRAFT planning workspace after a coherent requirements-extraction scaffold exists. It requires matching requirements-extraction scaffold provenance, post-scaffold coherence checks, confirmed draft-preparation authorization, and `local-agentic-spec.md` labeled `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` without generated requirements content. It writes `.agent-os/orchestrator/intakes/<intake-id>/requirements-extraction-decisions/<plan-id>/<decision-id>.json` with decision values `REQUEST_MORE_CONTEXT`, `BLOCK_REQUIREMENTS_EXTRACTION`, or `AUTHORIZE_REQUIREMENTS_EXTRACTION`. The decision artifact is append-only and non-authoritative. It does not extract or infer requirements; does not generate requirements content or requirement IDs; does not generate user stories or acceptance criteria; does not generate architecture decisions; does not generate implementation plans or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, requirements-extraction scaffold provenance, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements extraction owner decision is not requirements extraction** — not requirements approval, not architecture decision, not implementation planning, not validation or approval. `AUTHORIZE_REQUIREMENTS_EXTRACTION` authorizes only a future separate requirements extraction command; authorization is not extraction. `REQUEST_MORE_CONTEXT` and `BLOCK_REQUIREMENTS_EXTRACTION` do not mutate the scaffold or generate requirements content. Future requirements extraction, requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

`agent-os orchestrator requirements-extraction-execution-check` performs a read-only pre-execution check before any future requirements extraction command may run. It requires a DRAFT planning workspace with coherent requirements-extraction scaffold provenance, `local-agentic-spec.md` in `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` shape with only empty containers, confirmed requirements-extraction preflight state, confirmed draft-preparation authorization, unmodified planning init placeholders, and a latest plan-scoped requirements-extraction owner decision of `AUTHORIZE_REQUIREMENTS_EXTRACTION` whose scaffold/preflight metadata matches current provenance. It does not write any artifact. It does not extract or infer requirements; does not generate requirements content or requirement IDs; does not generate user stories or acceptance criteria; does not generate architecture decisions; does not generate implementation plans or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate any orchestrator, transport, provenance, decision, or planning artifact. **Requirements extraction execution check is not requirements extraction** — not requirements approval, not architecture decision, not implementation planning, not validation or approval. A later `REQUEST_MORE_CONTEXT` or `BLOCK_REQUIREMENTS_EXTRACTION` blocks extraction. Successful check means only that a separate future requirements extraction command may be run separately. Future requirements extraction, requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

`agent-os orchestrator extract-requirements-draft` writes deterministic source-bounded requirement draft candidates into `local-agentic-spec.md` after successful requirements-extraction execution check. It requires a DRAFT planning workspace with coherent requirements-extraction scaffold, confirmed execution check state (`REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NO_EXTRACTION_PERFORMED`), latest plan-scoped `AUTHORIZE_REQUIREMENTS_EXTRACTION` owner decision, `local-agentic-spec.md` still in `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` shape with only empty containers, unmodified planning init placeholders, present context transport JSON and `context-pack.md`, and no existing requirements draft provenance. It replaces `local-agentic-spec.md` with `REQUIREMENTS_DRAFT_NON_AUTHORITY` and writes `evidence/orchestrator-requirements-draft-provenance.json`. Draft candidates use deterministic IDs such as `DRAFT-REQ-001` (never approved-style `REQ-001` / `FR-001` / `NFR-001`). Candidate text is a conservative transformation of explicit source material only; broad goals remain broad unless source explicitly provides more detail. It does **not** approve or validate requirements; does **not** generate user stories or acceptance criteria; does **not** generate architecture decisions, implementation plans, or `PLANNING_RUN_SLICE`; does **not** validate or approve the workspace; does **not** transition status; does **not** create runner proposals, runs, or executor invocations; and does **not** mutate orchestrator intake artifacts, transport artifacts, context-pack draft provenance, requirements-extraction scaffold provenance, requirements-extraction owner decision artifacts, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements draft is not approved requirements** — not architecture decision, not implementation planning, not validation or approval. The planning workspace remains `DRAFT`. Future requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

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

**Implemented read-only readiness review:** `agent-os orchestrator readiness <intake-id> [PATH]` performs a read-only readiness review over the goal intake and clarification records. It does not modify artifacts, authorize draft generation, create planning workspace artifacts, create runs, or invoke an executor.

**Implemented owner readiness decision:** `agent-os orchestrator decide-readiness <intake-id> --decision <decision> --decision-id <decision-id> --summary "<owner summary>" [PATH]` records an `OWNER_READINESS_DECISION` JSON artifact only. It does not modify the goal intake, modify clarifications, change readiness, generate planning drafts, create planning workspaces, approve architecture, create runs, or invoke an executor. `AUTHORIZE_DRAFT_PREPARATION` authorizes only a future draft-preparation step.

**Implemented read-only draft-preparation authorization preflight:** `agent-os orchestrator draft-preflight <intake-id> [PATH]` performs a read-only authorization preflight only. It does not generate planning drafts, create planning workspaces, approve architecture, approve plans, create runner proposals, create runs, or invoke an executor. Confirmed authorization means a future draft-preparation command may be attempted separately; no draft is generated in this slice.

**Implemented DRAFT planning workspace scaffold:** `agent-os orchestrator prepare-planning-draft <intake-id> --plan-id <plan-id> [PATH]` creates a DRAFT planning workspace scaffold only after successful draft-preflight. It does not generate architecture, implementation plans, or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts. Created workspaces remain subject to future manual or agent planning, independent validation, and owner approval.

**Implemented planning context transport:** `agent-os orchestrator transport-planning-context <intake-id> --plan-id <plan-id> [PATH]` transports owner-provided intake context into an existing DRAFT scaffold only. It writes `evidence/orchestrator-context-transport.json` and `evidence/orchestrator-context-transport.md`. Transport is source material only; it does not generate architecture, implementation plans, or `PLANNING_RUN_SLICE`; does not validate or approve the workspace; does not transition status; does not create runner proposals, runs, or executor invocations; and does not mutate orchestrator intake artifacts or provenance. The workspace remains `DRAFT`. Future architecture decision, independent validation, owner approval, and runner proposal generation remain separate future work.

**Future work (not implemented):** `agent-os orchestrator draft-export` or any command that auto-runs the planning lifecycle above. Documenting draft-export does not imply implementation.

---

## 7. Non-authority statement

This contract does not approve work, create runs, invoke agents, import planning into the runner, or authorize repository changes. Generated drafts remain proposals until the owner validates, audits, decides, and transitions through existing planning doctrine.
