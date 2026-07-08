# Admissible Goal Intake and Plan Audit v0

## Purpose

Before any action reaches the admission queue, Admissible needs an
auditable, offline read on *what was asked for* and *whether the resulting
plan is safe to hand to a local prototype loop*. Two independent
deterministic modules do this:

- `admissible/goal_intake.py` -- turns a free-text prompt into a
  structured `GoalIntake`.
- `admissible/plan_audit.py` -- generates a fixed `PlanCandidate` from a
  `GoalIntake`, and separately audits it into a `PlanAudit`.

Both are keyword/heuristic classifiers, not model calls. Neither calls
Cursor, Claude Code, Codex, Gemini, OpenAI, or any network provider, and
neither executes anything. "It does not need to be perfect, but it must
be auditable" -- every `GoalIntake` field traces back to the `signals`
dict, and every `PlanAudit` reason names the specific gap it found.

## Goal Intake v0

`admissible.goal_intake.analyze_goal(prompt: str) -> GoalIntake` extracts:

| Field | Values |
|---|---|
| `task_type` | `software_build`, `bug_fix`, `refactor`, `explanation`, `deployment`, `general_task` |
| `deliverable` | free text, e.g. `"browser local game"` |
| `project_maturity` | `new_project`, `existing_project`, `unknown` |
| `architecture_choice_burden` | `low`, `medium`, `high` |
| `global_complexity` | `low`, `medium`, `high` |
| `global_risk` | `low`, `medium`, `high` |
| `risk_scope` | `local`, `unspecified` |
| `likely_side_effect_classes` | subset of `file_create`, `file_edit`, `possible_dependency_install`, `possible_server_run`, `possible_network_call`, `possible_deploy`, `possible_destructive_file_op` |
| `missing_context` | list of unresolved questions about scope |
| `clarifying_questions` | the same gaps, phrased as questions |
| `recommended_autonomy_ceiling` | `L1_PROPOSE_ONLY`, `L2_LOCAL_BATCH_APPROVAL`, or `L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS` -- **never `L4` in v0** |
| `initial_non_execution_boundary` | a sentence naming exactly which side effects require explicit authorization first |
| `signals` | per-field list of the keywords/heuristics that fired, for audit |

### Worked example

Prompt: *"Build a small browser-based Slither-like game with a moving
snake, collectible food, growth, collision handling, score display,
restart behavior, and simple visual polish. Keep it local-only. Do not
deploy. Ask before installing dependencies or deleting existing files."*

```
task_type: software_build
deliverable: browser local game
project_maturity: new_project
architecture_choice_burden: medium   (no explicit framework/stack named)
global_complexity: medium            (7 listed features, offset by "simple"/"small"/"local-only")
global_risk: medium                  (dependency-install language, mitigated by explicit local-only scope)
likely_side_effect_classes: [file_create, file_edit, possible_dependency_install, possible_server_run]
recommended_autonomy_ceiling: L2_LOCAL_BATCH_APPROVAL
clarifying_questions: framework vs. no-framework/vanilla; local-only vs. eventual hosting
```

Note `possible_deploy` and `possible_destructive_file_op` are correctly
**absent**: the prompt explicitly negates deploy ("do not deploy"), and
delete language attached to a brand-new project isn't a plausible side
effect (there is nothing pre-existing to delete yet).

## Plan generation v0

`admissible.plan_audit.generate_plan_candidate(goal_intake) -> PlanCandidate`
produces a fixed seven-step v0 skeleton (an eighth, `install_dependencies`,
is inserted when `possible_dependency_install` is a likely side effect):

1. `inspect_workspace`
2. `choose_architecture` -- gated whenever `architecture_choice_burden != "low"`
3. *(optional)* `install_dependencies` -- always gated when present
4. `create_minimal_files`
5. `implement_core_behavior`
6. `verify_locally`
7. `assess_production_readiness`
8. `deployment_gate` ("do not deploy unless authorized") -- always gated

This function only **proposes**. It never judges whether its own output
is acceptable.

## Plan Audit v0

`admissible.plan_audit.audit_plan(plan, goal_intake) -> PlanAudit` is a
**separate function** that only observes a `PlanCandidate` -- it never
generates or rewrites one. This separation is deliberate: a plan
generator that can also mark its own output "OK" could quietly regenerate
around an audit failure. Generation and audit must stay two functions so
that can't happen.

`audit_plan` checks:

1. Is the architecture choice explicit/gated when the burden is
   `medium`/`high`?
2. Is dependency/install language gated when dependency installation is a
   likely side effect?
3. Is there a gated deployment/publish/push boundary at all?
4. Does a local-verification step exist?
5. Does unresolved `missing_context` from goal intake still require
   clarification?

and produces one verdict, using the same highest-severity-wins precedence
style as `admissible.decision.resolve_precedence`:

| Verdict | Meaning |
|---|---|
| `PLAN_BLOCKED` | A required safety gate (architecture, dependency, or deployment) is missing entirely. |
| `PLAN_NEEDS_HUMAN_APPROVAL` | Gates exist, but there's no local verification step. |
| `PLAN_NEEDS_CLARIFICATION` | Gates and verification exist, but goal intake still has open questions. |
| `PLAN_OK_FOR_LOCAL_PROTOTYPE` | Nothing above triggered. |

`PlanAudit.required_gates` lists the `step_id`s of every gated step found,
so the UI can point directly at what needs a human decision.

## Module entry points

- `admissible.goal_intake.analyze_goal`
- `admissible.plan_audit.generate_plan_candidate`
- `admissible.plan_audit.audit_plan`

Both modules are consumed by `admissible.control_surface.ControlSurfaceController.submit_goal`,
which calls them in sequence and appends the results (plus a derived
Admissible transcript message) to the session -- see
`docs/admissible-control-surface.md`.
