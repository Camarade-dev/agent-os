# Goal intake artifact

> **Status:** deterministic scaffold in `CORE_ORCHESTRATOR_002`; read-only status and validation in `CORE_ORCHESTRATOR_003`; owner clarification records in `CORE_ORCHESTRATOR_004`; read-only readiness review in `CORE_ORCHESTRATOR_005`; owner readiness decision records in `CORE_ORCHESTRATOR_006`; read-only draft-preparation authorization preflight in `CORE_ORCHESTRATOR_007`; DRAFT planning workspace scaffold in `CORE_ORCHESTRATOR_008`; planning context transport in `CORE_ORCHESTRATOR_009`; context pack draft from transport in `CORE_ORCHESTRATOR_010`; read-only local-agentic-spec draft preflight in `CORE_ORCHESTRATOR_011`; local-agentic-spec scaffold from context pack in `CORE_ORCHESTRATOR_012`; read-only requirements extraction preflight in `CORE_ORCHESTRATOR_013`; requirements-extraction scaffold from local-agentic-spec scaffold in `CORE_ORCHESTRATOR_014`; requirements extraction owner decision records in `CORE_ORCHESTRATOR_015`; read-only requirements extraction execution check in `CORE_ORCHESTRATOR_016`; deterministic requirements extraction draft in `CORE_ORCHESTRATOR_017`; read-only requirements draft validation preflight in `CORE_ORCHESTRATOR_018`; requirements validation owner decision records in `CORE_ORCHESTRATOR_019`; read-only requirements validation execution check in `CORE_ORCHESTRATOR_020`; deterministic requirements draft validation report in `CORE_ORCHESTRATOR_021`; read-only requirements approval preflight in `CORE_ORCHESTRATOR_022`  
> **Commands:**
> - `agent-os orchestrator intake <intake-id> --goal "<raw goal>" [PATH]`
> - `agent-os orchestrator clarify <intake-id> --clarification-id <clarification-id> --answer "<owner-provided clarification>" [PATH]`
> - `agent-os orchestrator decide-readiness <intake-id> --decision <decision> --decision-id <decision-id> --summary "<owner summary>" [PATH]`
> - `agent-os orchestrator draft-preflight <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator prepare-planning-draft <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator transport-planning-context <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator draft-context-pack <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator local-agentic-spec-preflight <intake-id> --plan-id <plan-id> [PATH]` (read-only)
> - `agent-os orchestrator scaffold-local-agentic-spec <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator requirements-extraction-preflight <intake-id> --plan-id <plan-id> [PATH]` (read-only)
> - `agent-os orchestrator scaffold-requirements-extraction <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator decide-requirements-extraction <intake-id> --plan-id <plan-id> --decision <REQUEST_MORE_CONTEXT|BLOCK_REQUIREMENTS_EXTRACTION|AUTHORIZE_REQUIREMENTS_EXTRACTION> --decision-id <decision-id> --summary "<owner summary>" [PATH]`
> - `agent-os orchestrator requirements-extraction-execution-check <intake-id> --plan-id <plan-id> [PATH]` (read-only)
> - `agent-os orchestrator extract-requirements-draft <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator requirements-draft-validation-preflight <intake-id> --plan-id <plan-id> [PATH]` (read-only)
> - `agent-os orchestrator decide-requirements-validation <intake-id> --plan-id <plan-id> --decision <REQUEST_REQUIREMENTS_DRAFT_REVISION|BLOCK_REQUIREMENTS_VALIDATION|AUTHORIZE_REQUIREMENTS_VALIDATION> --decision-id <decision-id> --summary "<owner summary>" [PATH]`
> - `agent-os orchestrator requirements-validation-execution-check <intake-id> --plan-id <plan-id> [PATH]` (read-only)
> - `agent-os orchestrator validate-requirements-draft <intake-id> --plan-id <plan-id> [PATH]`
> - `agent-os orchestrator requirements-approval-preflight <intake-id> --plan-id <plan-id> [PATH]` (read-only)
> - `agent-os orchestrator status <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator validate <intake-id> [PATH]` (read-only)
> - `agent-os orchestrator readiness <intake-id> [PATH]` (read-only)
> **Output:**
> - `.agent-os/orchestrator/intakes/<intake-id>/goal-intake.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/clarifications/<clarification-id>.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/readiness-decisions/<decision-id>.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/requirements-extraction-decisions/<plan-id>/<decision-id>.json`
> - `.agent-os/orchestrator/intakes/<intake-id>/requirements-validation-decisions/<plan-id>/<decision-id>.json`

The goal intake command creates a durable, reviewable JSON artifact from an owner-provided natural-language goal. It is a registrar-only scaffold: it records input and conservative deterministic metadata so later orchestrator slices can consume the artifact without treating prose as authority. It does **not** call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The clarify command records owner-provided clarification context for an existing `GOAL_INTAKE` artifact. It writes a separate `OWNER_CLARIFICATION` JSON file only. It does **not** call an LLM, modify `goal-intake.json`, change `planning_readiness`, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor.

The status and validate commands inspect the goal intake artifact only. They are read-only and do not call an LLM, use Cursor, invoke an agent, call external APIs, choose architecture, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor. Status also reports clarification record counts when present; clarification records are additive context only.

The readiness command performs a read-only readiness review of the goal intake artifact and any owner clarification records. It summarizes intake validity, ambiguity, clarification count, and the next required action. It does **not** call an LLM, modify artifacts, change `planning_readiness`, mark an intake draft-ready, generate planning artifacts, validate or approve a planning workspace, create runner proposals, create runs, or invoke an executor. **Readiness review is not owner readiness decision, not approval, and not planning generation.** Owner clarification records do not automatically make an intake draft-ready. Status and readiness also report owner readiness decision counts when present; those records do not generate a planning draft.

The decide-readiness command records an owner-provided readiness decision after readiness review. It writes a separate `OWNER_READINESS_DECISION` JSON file only. It does **not** call an LLM, modify `goal-intake.json`, modify clarification artifacts, change `planning_readiness`, generate planning drafts, create planning workspaces, approve architecture, create runner proposals, create runs, or invoke an executor. **`AUTHORIZE_DRAFT_PREPARATION` authorizes only a future draft-preparation step** — not draft generation now, not planning approval, not architecture approval, and not execution. Future generated drafts would still need independent validation and owner approval.

The draft-preflight command performs a read-only draft-preparation authorization preflight for an existing intake. It runs the current readiness review, loads owner readiness decision records, identifies the latest decision, and checks whether `AUTHORIZE_DRAFT_PREPARATION` remains coherent with the current readiness review snapshot. It does **not** call an LLM, generate planning drafts, create planning workspaces, approve architecture, approve plans, create runner proposals, create runs, or invoke an executor. **Draft-preparation preflight is not draft generation** — it confirms authorization only and points to a separate future draft-preparation command. Future generated drafts would still need independent validation and owner approval.

The prepare-planning-draft command creates a **DRAFT planning workspace scaffold** from an orchestrator intake only after draft-preflight confirms authorization. It uses the same template bootstrap as `agent-os planning init`, writes orchestrator provenance under `evidence/orchestrator-provenance.json`, and records explicit scaffold boundary notes. It does **not** call an LLM, generate architecture decisions, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, or readiness decision artifacts. **Draft scaffold is not a validated workspace, not architecture approval, and not plan approval.** Provenance is traceability only, not authority. Future manual or agent planning, independent validation, and owner approval remain required.

The transport-planning-context command transports owner-provided intake context into an existing DRAFT planning workspace scaffold created by prepare-planning-draft. It copies goal intake fields, owner clarification answers, and the latest owner readiness decision summary into bounded context transport artifacts under `evidence/orchestrator-context-transport.json` and `evidence/orchestrator-context-transport.md`. Transport copies source context only; it does **not** interpret, generate architecture, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, or core planning template files (`context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, `planning-audit.md`). **Transported context is source material only** — not architecture approval, not local agentic spec, not implementation plan, and not plan approval. The planning workspace remains **DRAFT** and is not validated or approved. Context transport provenance is traceability only, not authority. Future architecture decision, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The draft-context-pack command drafts planning workspace `context-pack.md` from existing context transport artifacts in a DRAFT workspace created by prepare-planning-draft and transport-planning-context. It copies transported source context into a bounded context pack draft and writes `evidence/orchestrator-context-pack-draft-provenance.json`. The draft is source-context only; it does **not** generate architecture, choose stack/database/networking/deployment, generate local agentic spec, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, context transport artifacts, or other planning template files (`local-agentic-spec.md`, `implementation-plan.md`, `planning-audit.md`). **Context pack draft is not an approved context pack** — not architecture approval, not local agentic spec, not implementation plan, and not plan approval. The planning workspace remains **DRAFT** and is not validated or approved. Context pack draft provenance is traceability only, not authority. Future architecture decision, local agentic spec, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The local-agentic-spec-preflight command performs a read-only eligibility preflight for whether a future local-agentic-spec draft command may be allowed. It requires a DRAFT planning workspace with coherent orchestrator provenance, context transport artifacts, a `DRAFT_NON_AUTHORITY` context-pack draft, confirmed draft-preparation authorization, and planning init placeholders still present for `local-agentic-spec.md`, `implementation-plan.md`, and `planning-audit.md`. It does **not** call an LLM, generate or mutate `local-agentic-spec.md`, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write a preflight artifact. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, context transport artifacts, context-pack draft provenance, or `context-pack.md`. **Local-agentic-spec preflight is not local agentic spec generation** — not architecture decision, not implementation planning, not validation or approval. Successful preflight confirms only that a separate future local-agentic-spec draft command may be attempted. Future architecture decision, implementation plan, independent validation, and owner approval remain required.

The scaffold-local-agentic-spec command replaces the planning init `local-agentic-spec.md` placeholder with a `SCAFFOLD_DRAFT_NON_AUTHORITY` structure in a DRAFT planning workspace after successful local-agentic-spec-preflight. It writes `evidence/orchestrator-local-agentic-spec-scaffold-provenance.json` linking to the context-pack draft and preflight state. The scaffold provides structure, provenance references, and explicit boundaries only; it does **not** call an LLM, extract or infer requirements, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, context transport artifacts, context-pack draft provenance, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Local-agentic-spec scaffold is not requirements extraction** — not spec approval, not architecture decision, not implementation planning. Future requirements extraction, architecture decision, implementation plan, independent validation, and owner approval remain required. Scaffold provenance is traceability only, not authority. Runner proposal generation remains future/separate work.

The requirements-extraction-preflight command performs a read-only eligibility preflight for whether a future requirements extraction command may be allowed. It requires a DRAFT planning workspace with coherent orchestrator provenance, context transport artifacts, context-pack draft provenance, a `SCAFFOLD_DRAFT_NON_AUTHORITY` local-agentic-spec scaffold with required boundary notes, confirmed draft-preparation authorization, and `implementation-plan.md` and `planning-audit.md` still in planning init placeholder shape. It does **not** call an LLM, extract or infer requirements, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write a preflight artifact. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, context transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements extraction preflight is not requirements extraction** — not spec approval, not architecture decision, not implementation planning, not validation or approval. Successful preflight confirms only that a separate future requirements extraction command may be attempted. Future architecture decision, implementation plan, independent validation, and owner approval remain required.

The scaffold-requirements-extraction command replaces the `SCAFFOLD_DRAFT_NON_AUTHORITY` local-agentic-spec structure with a `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` structure in a DRAFT planning workspace after successful requirements-extraction-preflight. It writes `evidence/orchestrator-requirements-extraction-scaffold-provenance.json` linking to the context-pack path, local-agentic-spec scaffold provenance, and preflight state. The scaffold provides empty requirements containers, provenance references, and explicit boundaries only; it does **not** call an LLM, extract or infer requirements, generate requirements content, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, context transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements-extraction scaffold is not requirements extraction** — not spec approval, not architecture decision, not implementation planning. Requirements sections contain only explicit empty placeholders such as `NO_REQUIREMENTS_EXTRACTED` and `NOT_GENERATED`; no requirement IDs with content are created. Future requirements extraction, architecture decision, implementation plan, independent validation, and owner approval remain required. Scaffold provenance is traceability only, not authority. The planning workspace remains **DRAFT** and is not validated or approved. Runner proposal generation remains future/separate work.

The decide-requirements-extraction command records an owner-provided requirements extraction decision for an existing `GOAL_INTAKE` and DRAFT planning workspace after a coherent requirements-extraction scaffold exists. It writes `.agent-os/orchestrator/intakes/<intake-id>/requirements-extraction-decisions/<plan-id>/<decision-id>.json` with decision values `REQUEST_MORE_CONTEXT`, `BLOCK_REQUIREMENTS_EXTRACTION`, or `AUTHORIZE_REQUIREMENTS_EXTRACTION`. The decision artifact is append-only and non-authoritative; it snapshots requirements-extraction scaffold provenance and preflight state at decision time. It does **not** call an LLM, extract or infer requirements, generate requirements content or requirement IDs, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `goal-intake.json`, clarification artifacts, readiness decision artifacts, orchestrator provenance, context transport artifacts, context-pack draft provenance, local-agentic-spec scaffold provenance, requirements-extraction scaffold provenance, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements extraction owner decision is not requirements extraction** — not requirements approval, not architecture decision, not implementation planning, not validation or approval. `AUTHORIZE_REQUIREMENTS_EXTRACTION` authorizes only a future separate requirements extraction command; authorization is not extraction. `REQUEST_MORE_CONTEXT` and `BLOCK_REQUIREMENTS_EXTRACTION` do not mutate the scaffold or generate requirements content. Future requirements extraction, requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The requirements-extraction-execution-check command performs a read-only pre-execution check before any future requirements extraction command may run. It requires a DRAFT planning workspace with coherent requirements-extraction scaffold provenance, `local-agentic-spec.md` labeled `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` with only empty containers (`NO_REQUIREMENTS_EXTRACTED`, `NOT_GENERATED`, `UNDECIDED_NOT_GENERATED`), confirmed requirements-extraction preflight state in provenance, confirmed draft-preparation authorization, unmodified `implementation-plan.md` and `planning-audit.md` placeholders, and at least one valid plan-scoped requirements-extraction owner decision whose latest value (by `created_at`, then `decision_id`) is `AUTHORIZE_REQUIREMENTS_EXTRACTION` with metadata matching current scaffold/provenance. It does **not** call an LLM, extract or infer requirements, generate requirements content or requirement IDs, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write a check artifact. It does **not** modify any orchestrator intake artifact, transport artifact, provenance file, owner decision artifact, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements extraction execution check is not requirements extraction** — not requirements approval, not architecture decision, not implementation planning, not validation or approval. A later `REQUEST_MORE_CONTEXT` or `BLOCK_REQUIREMENTS_EXTRACTION` owner decision blocks extraction even after an older `AUTHORIZE_REQUIREMENTS_EXTRACTION`. Successful check means only that a separate future requirements extraction command may be run separately. Future requirements extraction, requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The extract-requirements-draft command writes deterministic source-bounded requirement draft candidates into `local-agentic-spec.md` after successful requirements-extraction execution check. It requires confirmed execution check state, latest plan-scoped `AUTHORIZE_REQUIREMENTS_EXTRACTION` owner decision, coherent requirements-extraction scaffold, `local-agentic-spec.md` still in `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` shape with only empty containers, unmodified planning init placeholders, present context transport JSON and `context-pack.md`, and no existing requirements draft provenance. It writes `REQUIREMENTS_DRAFT_NON_AUTHORITY` to `local-agentic-spec.md` and `evidence/orchestrator-requirements-draft-provenance.json`. Draft candidates use deterministic IDs such as `DRAFT-REQ-001` (never approved-style `REQ-001` / `FR-001` / `NFR-001`). Each candidate carries a literal `source_bounded: SOURCE_BOUNDED` marker. Candidate text is a conservative transformation of explicit source material only; broad goals remain broad unless source explicitly provides more detail. It does **not** call an LLM, approve or validate requirements, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify orchestrator intake artifacts, transport artifacts, context-pack draft provenance, requirements-extraction scaffold provenance, requirements-extraction owner decision artifacts, `context-pack.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements draft is not approved requirements** — not architecture decision, not implementation planning, not validation or approval. The planning workspace remains **DRAFT** and is not validated or approved. Future requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The requirements-draft-validation-preflight command performs a read-only eligibility preflight for whether a future requirements validation command may be allowed. It requires a DRAFT planning workspace with orchestrator provenance binding the plan to the intake, `local-agentic-spec.md` labeled `REQUIREMENTS_DRAFT_NON_AUTHORITY`, present `evidence/orchestrator-requirements-draft-provenance.json`, coherent source-bounded `DRAFT-REQ-*` candidates with required non-authority markers, provenance matching the draft content, no forbidden downstream artifacts, and a latest plan-scoped `AUTHORIZE_REQUIREMENTS_EXTRACTION` owner decision coherent with draft provenance. It does **not** call an LLM, validate or approve requirements, rewrite or promote the draft, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write any artifact. It does **not** modify orchestrator intake artifacts, transport artifacts, provenance files, owner decision artifacts, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements draft validation preflight is not requirements validation** — not requirements approval, not architecture decision, not implementation planning. Successful preflight confirms only that a separate future requirements validation command may be attempted. Future requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The decide-requirements-validation command records an owner-provided requirements validation decision for an existing `GOAL_INTAKE` and DRAFT planning workspace. It writes `.agent-os/orchestrator/intakes/<intake-id>/requirements-validation-decisions/<plan-id>/<decision-id>.json` with decision values `REQUEST_REQUIREMENTS_DRAFT_REVISION`, `BLOCK_REQUIREMENTS_VALIDATION`, or `AUTHORIZE_REQUIREMENTS_VALIDATION`. The decision artifact is append-only and non-authoritative; it snapshots requirements draft validation preflight state at decision time for `AUTHORIZE_REQUIREMENTS_VALIDATION` only. `AUTHORIZE_REQUIREMENTS_VALIDATION` requires in-memory confirmation that requirements draft validation preflight would succeed; it does **not** persist a preflight artifact. It does **not** call an LLM, validate or approve requirements, promote `DRAFT-REQ-*` to approved requirement IDs, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, write validation reports, validate or approve the workspace, transition workspace status, create runner proposals, create runs, or invoke an executor. It does **not** modify `local-agentic-spec.md`, orchestrator intake artifacts, transport artifacts, provenance files, or other owner decision artifacts. **Requirements validation owner decision is not requirements validation** — not requirements approval, not architecture decision, not implementation planning. `AUTHORIZE_REQUIREMENTS_VALIDATION` authorizes only a future separate requirements validation command; authorization is not validation and is not approval. `REQUEST_REQUIREMENTS_DRAFT_REVISION` and `BLOCK_REQUIREMENTS_VALIDATION` do not mutate the draft or perform validation. Future requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The requirements-validation-execution-check command performs a read-only pre-execution check before any future requirements validation command may run. It requires a DRAFT planning workspace with orchestrator provenance binding the plan to the intake, coherent requirements draft and provenance, confirmed requirements draft validation preflight state, and a latest plan-scoped requirements-validation owner decision of `AUTHORIZE_REQUIREMENTS_VALIDATION` whose preflight/draft metadata matches current state. It does **not** call an LLM, validate or approve requirements, promote `DRAFT-REQ-*` to approved requirement IDs, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, write validation reports, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write any artifact. It does **not** modify orchestrator intake artifacts, transport artifacts, provenance files, owner decision artifacts, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements validation execution check is not requirements validation** — not requirements approval, not architecture decision, not implementation planning, not validation or approval. Owner authorization is not validation and is not approval. A later `REQUEST_REQUIREMENTS_DRAFT_REVISION` or `BLOCK_REQUIREMENTS_VALIDATION` blocks validation even after an older `AUTHORIZE_REQUIREMENTS_VALIDATION`. Successful check means only that a separate future requirements validation command may be run separately. Future requirements validation, architecture decision, implementation plan, independent validation, and owner approval remain required. Runner proposal generation remains future/separate work.

The validate-requirements-draft command performs deterministic requirements draft validation checks and writes a non-authoritative validation report to `evidence/orchestrator-requirements-draft-validation-report.json`. It requires successful requirements validation execution check (`REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_NO_VALIDATION_PERFORMED`), a latest plan-scoped `AUTHORIZE_REQUIREMENTS_VALIDATION` owner decision, coherent requirements draft and provenance, and no existing validation report. It records per-candidate validation results (`PASS`, `NEEDS_REVISION`, or `BLOCKED`) with `approval_status: NOT_APPROVED`, `promotion_status: NOT_PROMOTED`, and `approved_requirement_id: NOT_ASSIGNED`. It does **not** call an LLM, approve requirements, promote `DRAFT-REQ-*` to approved requirement IDs, rewrite `local-agentic-spec.md`, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write owner decision artifacts. It does **not** modify orchestrator intake artifacts, transport artifacts, requirements draft provenance, owner decision artifacts, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Validation report is not approval and not promotion** — `PASS` does not approve requirements and does not assign `REQ-*` ids; `DRAFT-REQ-*` remains draft-only. Future requirements approval requires a separate owner decision. Architecture decision, implementation plan, independent validation, and runner proposal generation remain future/separate work.

The requirements-approval-preflight command performs a read-only eligibility preflight for whether the current requirements draft validation report is structurally admissible to a future owner approval decision. It requires successful requirements validation execution check, an existing validation report with status `REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_NO_APPROVAL_NO_PROMOTION`, next action `FUTURE_REQUIREMENTS_APPROVAL_REQUIRES_OWNER_DECISION`, plan/intake scope match, coherent non-authority flags, candidate coverage matching the current draft, and all candidate validation results `PASS` with `approval_status: NOT_APPROVED`, `promotion_status: NOT_PROMOTED`, and `approved_requirement_id: NOT_ASSIGNED`. It does **not** call an LLM, record owner decisions, approve requirements, promote `DRAFT-REQ-*` to approved requirement IDs, rewrite `local-agentic-spec.md`, modify validation reports, generate user stories or acceptance criteria, generate architecture decisions, choose stack/database/networking/deployment, generate an implementation plan, generate `PLANNING_RUN_SLICE`, validate or approve the workspace, transition workspace status, create runner proposals, create runs, invoke an executor, or write any artifact. It does **not** modify orchestrator intake artifacts, transport artifacts, requirements draft provenance, validation reports, owner decision artifacts, `context-pack.md`, `local-agentic-spec.md`, `implementation-plan.md`, or `planning-audit.md`. **Requirements approval preflight is not owner approval and not promotion** — validation report `PASS` is not approval; `DRAFT-REQ-*` remains draft-only. Future requirements approval requires a separate owner decision command. Architecture decision, implementation plan, independent validation, and runner proposal generation remain future/separate work.

Requirements validation owner decision non-authority flags include (all `true`):

```json
{
  "owner_decision_is_not_validation": true,
  "authorizes_future_validation_only_when_decision_is_authorize": true,
  "authorization_is_not_validation": true,
  "authorization_is_not_approval": true
}
```

The flag `authorizes_future_validation_only_when_decision_is_authorize` documents doctrine only: future validation authorization applies when `decision` is `AUTHORIZE_REQUIREMENTS_VALIDATION`. `REQUEST_REQUIREMENTS_DRAFT_REVISION` and `BLOCK_REQUIREMENTS_VALIDATION` record `source_requirements_draft_validation_preflight_next_action` as `NO_FUTURE_REQUIREMENTS_VALIDATION_AUTHORIZED_BY_THIS_DECISION`.

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
