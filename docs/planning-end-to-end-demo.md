# Planning end-to-end local demo

> **Status:** reproducible local demo for the current planning workflow.
> **Scope:** documentation and operator evidence only. This demo does not add CLI behavior, create repository runtime state, invoke agents, import runner data, or create runs.

This demo shows the local planning lifecycle from an empty Agent OS project to `APPROVED_FOR_RUN_PROPOSALS` for a harmless example goal:

> Build a small Slither-like browser game as static HTML/CSS/JS.

Use a temporary project outside this repository and substitute its path for `<demo-project>` in every command. Do not commit generated `.agent-os/` runtime state from the demo.

## Boundary summary

`APPROVED_FOR_RUN_PROPOSALS` is not execution approval. It only means the filled planning artifacts may be used to prepare future run proposals. Runner integration remains out of scope here, and no run exists until a future explicit runner proposal/import command is implemented and separately approved.

In this demo:

- no agent is invoked
- no Cursor session is invoked
- no run is created
- no runner import happens
- `agent-os planning decide` records an owner decision only
- `agent-os planning transition` is a separate operation that mutates `manifest.json` and writes one transition evidence record

## 0. Prepare an empty demo project

Create or choose an empty local directory outside the Agent OS repository:

```bash
<demo-project>
```

All command output below replaces machine-specific absolute paths with `<demo-project>`.

Current syntax note: for `planning decide` and `planning transition`, the implemented CLI expects the optional project path before command flags. The commands below use the current reproducible order and do not imply a new CLI behavior.

## 1. Initialize demo project and planning workspace

Command:

```bash
agent-os init <demo-project>
agent-os planning init slither-demo <demo-project>
```

Expected stable output lines:

```text
initialized workspace: <demo-project>/.agent-os
created planning workspace: <demo-project>/.agent-os/planning/slither-demo
status: DRAFT
next step: fill context-pack.md
note: no runs were created and no agents were invoked
```

Expected artifact state:

- `<demo-project>/.agent-os/planning/slither-demo/` exists
- `manifest.json` has `status: "DRAFT"`
- `evidence/`, `decisions/`, and `revisions/` exist
- `<demo-project>/.agent-os/runs/` remains empty
- no agents were invoked

## 2. Status after init

Command:

```bash
agent-os planning status slither-demo <demo-project>
```

Expected stable output lines:

```text
planning workspace: <demo-project>/.agent-os/planning/slither-demo
plan_id: slither-demo
status: DRAFT
artifacts:
  manifest.json: present
  README.md: present
  context-pack.md: present
  local-agentic-spec.md: present
  implementation-plan.md: present
  planning-audit.md: present
directories:
  evidence/: present
  decisions/: present
  revisions/: present
gates:
  planning_owner_decision_required: true
  planning_audit_required: true
  plan_revision_required: false
  run_proposal_allowed: false
authority:
  no_execution: true
  no_agent_invocation: true
  no_run_creation: true
  no_self_approval: true
structural result: OK
```

Expected artifact state:

- structural result is `OK`
- status remains `DRAFT`
- all primary planning artifacts and subdirectories are present
- this is read-only inspection

## 3. Validate immediately after init

Command:

```bash
agent-os planning validate slither-demo <demo-project>
```

Expected stable output lines:

```text
planning workspace: <demo-project>/.agent-os/planning/slither-demo
plan_id: slither-demo
status: DRAFT
structural result: OK
manifest validation: OK
artifact validation: INVALID
  - placeholder still present in implementation-plan.md: {{RUN_LABEL_1}}
  - placeholder still present in implementation-plan.md: {{RUN_LABEL_2}}
final validation result: INVALID
```

This is expected and healthy. `planning init` creates a container and copies templates; it does not approve a plan. A freshly initialized planning workspace should not be treated as ready for run proposals.

## 4. Fill planning artifacts manually

Manually edit these files under `<demo-project>/.agent-os/planning/slither-demo/`:

- `context-pack.md`
- `local-agentic-spec.md`
- `implementation-plan.md`
- `planning-audit.md`
- optionally `README.md`

Use `examples/planning-workspace-slither-like/` as the compact sample for the Slither-like browser game. Do not copy it as execution authority; it is marked `EXAMPLE_ONLY`.

Minimum fill requirements:

- artifact type markers remain, for example `CONTEXT_PACK`, `LOCAL_AGENTIC_SPEC`, `IMPLEMENTATION_PLAN`, and `PLANNING_AUDIT`
- no `{{...}}` placeholder tokens remain
- meaningful placeholder prose is replaced, even where weak validation would not catch it
- required sections remain present
- non-authority notices remain present
- the implementation plan includes bounded slices with `allowed_paths`, `check_command`, and stop conditions
- the planning audit records an acceptable verdict, `PASS` or `PASS_WITH_NOTES`
- the plan keeps the boundary that planned runs are not executable until converted into future approved run proposals

Concise Slither-like plan content is enough. Do not duplicate the entire example workspace unless that is useful to the operator.

## 5. Validate after manual fill

Command:

```bash
agent-os planning validate slither-demo <demo-project>
```

Expected stable output lines:

```text
planning workspace: <demo-project>/.agent-os/planning/slither-demo
plan_id: slither-demo
status: DRAFT
structural result: OK
manifest validation: OK
artifact validation: OK
final validation result: OK
note: no files were modified, no runs were created, no agents were invoked
```

Expected artifact state:

- final validation result is `OK`
- validation is read-only
- no files are modified by validation
- no runs are created
- no agents are invoked

## 6. Record owner decision

Command:

```bash
agent-os planning decide slither-demo <demo-project> --decision APPROVE_FOR_RUN_PROPOSALS --summary "Planning artifacts reviewed and approved for run proposals only."
```

Expected stable output lines:

```text
decision recorded
decision: APPROVE_FOR_RUN_PROPOSALS
path: <demo-project>/.agent-os/planning/slither-demo/decisions/<timestamp>__owner-decision.json
manifest status was not changed
no runs were created
no agents were invoked
```

Expected artifact state:

- exactly one `PLANNING_OWNER_DECISION` JSON file is created under `decisions/`
- the latest decision is `APPROVE_FOR_RUN_PROPOSALS`
- `manifest.json` remains unchanged by the decision command
- no run is created
- no agent is invoked
- runner execution is not approved

## 7. List decisions

Command:

```bash
agent-os planning decisions list slither-demo <demo-project>
```

Expected stable output lines:

```text
planning workspace: <demo-project>/.agent-os/planning/slither-demo
plan_id: slither-demo
decision records: 1
latest decision:
  decision: APPROVE_FOR_RUN_PROPOSALS
  summary: Planning artifacts reviewed and approved for run proposals only.
note: read-only; no files modified, no runs created, no agents invoked
```

Expected artifact state:

- count is `1`
- latest decision is `APPROVE_FOR_RUN_PROPOSALS`
- listing is read-only
- no files are modified

## 8. Prepare manifest status for transition

Current residual debt: artifact-progress transitions are not implemented yet. Planning 010 and the current explicit transition command allow `APPROVED_FOR_RUN_PROPOSALS` only from:

- `PLANNING_AUDIT_READY`, or
- `PLAN_READY` when validation is `OK`

Therefore the operator must currently perform one manual status preparation step before transition, or use a fixture/demo manifest already in that state.

Manual operator step:

1. Open `<demo-project>/.agent-os/planning/slither-demo/manifest.json`.
2. Set `status` to `PLANNING_AUDIT_READY` after the audit verdict is `PASS` or `PASS_WITH_NOTES`.
3. Optionally update `updated_at`.
4. Do not manually set `run_proposal_allowed`; the transition command owns that gate update.

Minimal manifest change:

```json
{
  "status": "PLANNING_AUDIT_READY"
}
```

This manual status edit is a documented operator step and current workflow debt. It is not hidden by the demo.

## 9. Apply explicit transition

Command:

```bash
agent-os planning transition slither-demo <demo-project> --to APPROVED_FOR_RUN_PROPOSALS
```

Expected stable output lines:

```text
transition applied
plan_id: slither-demo
from status: PLANNING_AUDIT_READY
to status: APPROVED_FOR_RUN_PROPOSALS
latest decision used: APPROVE_FOR_RUN_PROPOSALS
evidence record: <demo-project>/.agent-os/planning/slither-demo/evidence/<timestamp>__manifest-transition.json
manifest updated explicitly
no runs were created
no agents were invoked
```

Expected artifact state:

- `manifest.json` status becomes `APPROVED_FOR_RUN_PROPOSALS`
- `manifest.json` contains `last_transition`
- gates are updated:
  - `run_proposal_allowed: true`
  - `planning_owner_decision_required: false`
  - `planning_audit_required: false`
  - `plan_revision_required: false`
- exactly one `PLANNING_MANIFEST_TRANSITION` JSON file is created under `evidence/`
- no run is created
- no agent is invoked
- no runner import happens

## 10. Final status

Command:

```bash
agent-os planning status slither-demo <demo-project>
```

Expected stable output lines:

```text
planning workspace: <demo-project>/.agent-os/planning/slither-demo
plan_id: slither-demo
status: APPROVED_FOR_RUN_PROPOSALS
gates:
  planning_owner_decision_required: false
  planning_audit_required: false
  plan_revision_required: false
  run_proposal_allowed: true
structural result: OK
```

Expected artifact state:

- `manifest.json` contains `last_transition`
- `last_transition.from_status` is `PLANNING_AUDIT_READY` if the manual step used that source state
- `last_transition.to_status` is `APPROVED_FOR_RUN_PROPOSALS`
- status inspection remains read-only

## 11. Final validation

Command:

```bash
agent-os planning validate slither-demo <demo-project>
```

Expected stable output lines:

```text
planning workspace: <demo-project>/.agent-os/planning/slither-demo
plan_id: slither-demo
status: APPROVED_FOR_RUN_PROPOSALS
structural result: OK
manifest validation: OK
artifact validation: OK
final validation result: OK
note: no files were modified, no runs were created, no agents were invoked
```

Expected artifact state:

- final validation result is `OK`
- validation is read-only
- no mutation occurs
- the planning workspace remains approved only for future run proposal preparation

## Final state checklist

After the demo completes:

- `.agent-os/planning/slither-demo/manifest.json` has `status: "APPROVED_FOR_RUN_PROPOSALS"`
- `decisions/` contains one owner decision JSON
- `evidence/` contains one manifest transition JSON
- `.agent-os/runs/` is still empty
- no executor, agent, Cursor session, or runner was invoked
- no execution evidence exists because no execution happened

Keep or delete `<demo-project>` as local disposable state. Do not copy the generated `.agent-os/` tree into this repository unless a future explicit documentation fixture slice authorizes that.
