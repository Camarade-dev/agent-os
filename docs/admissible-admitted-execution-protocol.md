# Admitted Execution Protocol v0

## Purpose

Admitted Execution Protocol v0 defines how Admissible **records** that a
previously admitted local action was executed **outside** Admissible — by a
human operator or an external frontier agent — **after** admission occurred.

This protocol does **not** implement an automatic executor. Admissible never
runs shell commands, calls providers, or mutates workspaces in v0.

## Thesis step

1. **Cursor proposes operations** — raw agent output yields action candidates.
2. **Admissible admits only some operations** — rules-only evaluator produces
   admission decisions and operational admissibility actions.
3. **A human/operator may execute admitted local operations outside
   Admissible** — e.g. editing `game.js` in the Slither demo workspace.
4. **Admissible records execution only after admission** — via manual or
   fixture-backed attestation, referencing the admission decision.

## Distinctions (do not conflate)

| Concept | Meaning |
|---------|---------|
| **Admission decision** | `ALLOW`, `REQUEST_MORE_EVIDENCE`, etc. — whether the action may proceed |
| **Operational admissibility action** | Derived label (`execute`, `request_evidence`, `block`, …) |
| **Execution status** | Lifecycle on the action candidate — whether anything ran |
| **Execution attestation** | External/manual evidence that execution happened after admission |

Admission says *whether* execution may happen. Execution status says *what
happened* (or was attested) after that judgment.

## Execution status values (v0)

| Status | Meaning |
|--------|---------|
| `proposed_only` | Default — action proposed, no admission-driven execution record |
| `admitted_not_executed` | Admitted (`ALLOW`, local, no missing evidence) but not yet executed |
| `executed_after_admission` | Externally attested execution after a matching admission record |
| `blocked` | Execution explicitly blocked or not permitted to be recorded as executed |

## v0 constraints for `executed_after_admission`

Only actions meeting **all** of the following may be marked
`executed_after_admission`:

- Admission decision is `ALLOW`
- Operational admissibility action is `execute` (not `replace_with_safer_step`)
- Risk level is `local`
- No missing evidence on the decision
- `execution_scope` is `local_workspace_only`
- `execution_basis` references a valid `decision_id` and/or `envelope_id` from
  the trace proving admission happened first

**Forbidden** in v0 (validator raises explicit errors):

- `REQUEST_MORE_EVIDENCE` → cannot be `executed_after_admission`
- `REQUIRE_HUMAN_APPROVAL` → cannot be `executed_after_admission`
- `REFUSE` → cannot be `executed_after_admission`
- `ALLOW_WITH_LIMITS` on the **original** action → cannot be
  `executed_after_admission` unless represented as a safer replacement (not the
  original admitted action)

## Execution attestation record

Fixture format: `execution_logs/admitted_local_actions_v0.json`

```json
{
  "schema_version": "admitted_execution_attestation_v0",
  "records": [
    {
      "action_id": "action_001",
      "execution_status": "executed_after_admission",
      "execution_basis": {
        "decision_id": "decision_env_lr_…_admissible_rules_only_v0",
        "envelope_id": "env_lr_…"
      },
      "execution_actor": "human_operator",
      "execution_evidence": {
        "notes": "…",
        "verification": "…"
      },
      "execution_scope": "local_workspace_only",
      "execution_timestamp": "2026-07-08T20:00:00Z"
    }
  ]
}
```

### Fields

| Field | Required | Values |
|-------|----------|--------|
| `execution_status` | yes | see table above |
| `execution_basis` | for `executed_after_admission` | `decision_id`, `envelope_id` |
| `execution_actor` | for `executed_after_admission` | `human_operator`, `external_frontier_agent_after_admission` |
| `execution_evidence` | optional | notes, file paths, manual verification |
| `execution_scope` | for `executed_after_admission` | `local_workspace_only` |
| `execution_timestamp` | for `executed_after_admission` | ISO-8601 UTC |

## Truth trace extensions

When attestations are applied (`admissible.admitted_execution.apply_execution_attestations`):

- `action_candidates[].execution_status` is updated
- `action_candidates[].execution_record` holds attestation fields (when not `proposed_only`)
- `execution_log[]` gains `executed_after_admission` or `admitted_not_executed` events
- Trace root `side_effect_executed` remains **`false`** — Admissible did not execute

Unattested `ALLOW` local actions (no missing evidence) become `admitted_not_executed`.
Non-`ALLOW` actions remain `proposed_only`.

## Truth Console display

When attestations are present, the console shows:

> Execution records are fixture-backed/manual attestations in this v0.
> Admissible did not execute commands.

Executed actions display a distinct `executed_after_admission` badge. The
existing “No side effect executed” disclaimer for Admissible itself is preserved.

## What this protocol is not

- Not an executor class or command runner
- Not provider integration
- Not weakening admission rules
- Not silent downgrade on validation failure — invalid attestations raise
  `AdmittedExecutionValidationError`

## Module entry points

- `admissible.admitted_execution.validate_executed_after_admission_record`
- `admissible.admitted_execution.apply_execution_attestations`
- `admissible.admitted_execution.load_execution_attestation`

CLI:

```bash
python -m admissible.runner.long_run_truth_console \
  --source builder-fixtures \
  --fixtures-dir benchmark/long_run_scenarios/cursor_slither_demo/fixtures/real_captures \
  --execution-log benchmark/long_run_scenarios/cursor_slither_demo/execution_logs/admitted_local_actions_v0.json
```
