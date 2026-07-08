# Admissible Autonomy Levels v0

## Purpose

Autonomy level is a control-surface concept, not a rules-only evaluator
concept. It changes **how much gets bundled into one human decision** and
**which local `ALLOW` actions may be attested as executed without a
per-action click**. It never changes what Admissible decided about a
given action. See `admissible/control_surface.py`
(`AutonomyLevel`, `AUTONOMY_PROFILES`, `available_human_actions`).

## The hard rule

> Autonomy changes default stopping points. Autonomy never overrides a
> rules-only decision.

Concretely, for every autonomy level:

| Admissible decision | Human actions always available | Autonomy's effect |
|---|---|---|
| `REFUSE` | none | **none, at any level.** `REFUSE` is final in v0. |
| `REQUIRE_HUMAN_APPROVAL` | `approve` (scoped), `refuse` | none -- always requires an explicit, scoped human approval |
| `REQUEST_MORE_EVIDENCE` | `request_evidence`, `refuse` | none -- always requires evidence before progression |
| `ALLOW_WITH_LIMITS` | `limit_scope` (scoped), `refuse` | none -- always requires a scope limit (or a safer replacement) before it can be treated as done |
| `ALLOW` | `refuse`, plus `attest_executed` **only if** the action is `is_local_allow_without_missing_evidence` and autonomy level is `L2` or higher | Autonomy only ever adds/removes `attest_executed` on already-`ALLOW`ed local actions |

This table is implemented as one pure function,
`admissible.control_surface.available_human_actions(item, autonomy_level)`,
so the mapping from (decision, autonomy) to permitted human actions has a
single source of truth and is unit-tested directly.

## The five v0 levels

| Level | Label | Default stopping points |
|---|---|---|
| `L0_OBSERVE_ONLY` | Observe only | Every action stops for observation only; no decision controls are offered at all. |
| `L1_PROPOSE_ONLY` | Propose only | Every action stops before any human decision (no attestation). |
| `L2_LOCAL_BATCH_APPROVAL` | Local batch approval | Local `ALLOW` actions may be reviewed/attested as a batch; every gated decision (`REQUIRE_HUMAN_APPROVAL`, `REQUEST_MORE_EVIDENCE`, `ALLOW_WITH_LIMITS`) still stops individually. |
| `L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS` | Local auto-admit with interrupts | Local `ALLOW` actions default to admitted without a per-action click; any gated decision still interrupts. |
| `L4_HIGH_AUTONOMY_HARD_GATES` | High autonomy, hard gates | Broadest default autonomy; **identical** hard gates to every other level -- `REFUSE` / `REQUIRE_HUMAN_APPROVAL` / `REQUEST_MORE_EVIDENCE` always stop. |

`L4` is the highest level defined in v0, but goal intake's
`recommended_autonomy_ceiling` (see
`docs/admissible-goal-intake-and-plan-audit.md`) never recommends it
automatically -- it is a level a human operator opts into, not one the
system proposes for a first-pass, possibly-ambiguous goal.

## What autonomy level does *not* do in v0

- It does not enable any automatic executor. There is no executor at any
  level in this v0 -- `attest_executed` only records that a human/external
  actor already ran something outside this tool.
- It does not change `admissible.evaluator.rules_only` output. The
  evaluator has no notion of autonomy level.
- It does not let a human decision overwrite the original decision label
  on a `DecisionQueueItem`. Every human action becomes a separate,
  additive `HumanDecisionRecord` (see
  `docs/admissible-control-surface.md`).

## Where this is enforced

- `admissible/control_surface.py::available_human_actions` -- the single
  gating function described above.
- `admissible/control_surface.py::ControlSurfaceController.decide` --
  rejects any `decision_type` not in `available_human_actions(...)`, and
  routes `attest_executed` through the unmodified
  `admissible.admitted_execution.validate_executed_after_admission_record`.
- `tests/test_admissible_control_surface.py` -- asserts the level names
  and semantics stay stable and that autonomy never unlocks an action for
  `REFUSE` / `REQUIRE_HUMAN_APPROVAL` / `REQUEST_MORE_EVIDENCE`.
