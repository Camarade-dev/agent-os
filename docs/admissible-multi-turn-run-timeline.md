# Admissible Multi-Turn Run Timeline v0

Slice `ADMISSIBLE_RUN_021_MULTI_TURN_RUN_TIMELINE`.

## Purpose

The Control Surface and Supervised Run Loop
(`docs/admissible-control-surface.md`, `docs/admissible-supervised-run-loop.md`)
already store every fact a governed run needs: goal intake, per-turn
instruction packets, ingested (unverified) agent responses, admission
decisions on queue items, execution status, evidence records, and refusals.
What was missing was a single object that reads the run **in sequence** rather
than as a flat admission queue. This slice adds that: a minimal, durable
**run timeline** foundation so a run can be read as

```
Goal
 -> Plan / intended steps (existing goal intake + plan audit)
 -> Turn 1
     -> Agent proposal (ingested response)
     -> Admission decision (rules-only, unchanged)
     -> Human-triggered local execution (bounded executor, unchanged)
     -> Evidence (sha256 write records / structured evidence)
 -> Turn 2
 -> ...
```

This is the groundwork for later multi-turn governed continuation
(`ADMISSIBLE_RUN_022_EVIDENCE_GROUNDED_CONTINUATION`). **It is not full
autonomy.** It adds no new powers — it only makes the existing run readable.

## What this slice is *not*

- Not a new executor. No shell, npm, dependency install, deploy, network, or
  provider calls were added. The bounded local file executor (list/read/write
  only, sha256 evidence) is unchanged.
- Not a change to admission rules. The rules-only evaluator and gates are
  untouched. The timeline re-decides nothing.
- Not new persisted source-of-truth state. The timeline is a **pure,
  display-only projection** computed on demand from the existing session
  (queue, run-loop turns, evidence records). The queue and `run_loop` remain
  the single source of truth, so nothing needs migrating and existing sessions
  render a timeline with no schema bump.

## Data model

Added to `admissible.run_loop` (where the rest of the run-loop model lives):

- `TimelineOperation` — one proposed action, projected: the turn that proposed
  it, the immutable admission `decision`, derived `lifecycle_status` /
  `execution_status`, `admitted` / `executed` / `blocked` flags, any bounded
  local file operation detail (`operation_types`, `target_paths`,
  `is_local_file_operation`), and its `evidence_count`.
- `TimelineTurn` — one turn/phase: its instruction packet id, the agent
  response record id, whether a proposal was ingested, a summary, and the
  operations it proposed with per-turn admitted/executed/blocked/evidence
  counts.
- `RunTimeline` — the whole run: `session_id`, `goal`, a derived run-level
  `status`, `turn_count`, the ordered `turns`, aggregate
  `admitted_operation_ids` / `executed_operation_ids` /
  `blocked_operation_ids`, `ready_to_execute_local_count`, total
  `evidence_count`, `pending_human_decision_count`, and a compact
  `latest_agent_proposal` summary.

`build_run_timeline(...)` assembles these from already-computed state. It maps
each queue action to the turn whose ingested response introduced it (via the
response records' `action_ids`); actions that no response claims — e.g. a
static truth trace loaded via *Load example session* — are grouped under a
synthetic `TIMELINE_LOADED_TURN` (turn 0). Timestamps are reused where they
already exist naturally (session `created_at`, turn/packet `created_at`); no
new clocks were introduced.

Run-level `status` is one of: `needs_goal`, `planned`,
`awaiting_agent_response`, `reviewing_proposals`, `ready_to_execute_local`,
`executed`, `idle` — derived, first-match, from goal presence, an outstanding
bridge instruction, pending human decisions, ready local operations, and
whether anything has executed.

## Surfacing

- Backend: `admissible.control_surface._run_timeline_object` derives the
  per-action bounded operation detail (straight from the candidate/envelope, so
  it persists even after execution) and calls `build_run_timeline`.
  `ControlSurfaceController.state_view()` exposes it as `run_timeline`.
- UI: a **Run Timeline** panel (`#run-timeline-panel`, `renderRunTimeline`) in
  `admissible/harness/control_surface.html`, between Mission Summary and the
  Supervised Run State panel. It shows the current goal, run status, turn
  count, admitted/executed/ready-local/evidence/blocked counts, the latest
  agent proposal, and a turn-by-turn sequence of operations with their
  admission and execution state. Each operation links to the existing Selected
  Action review. It is a technical timeline panel, not yet product-grade.

## Single-turn behavior is unchanged

The live Cursor structured-response loop is untouched:

- No file write happens on ingest.
- Local execution remains an explicit, human-triggered batch/individual step.
- Admitted operations remain visible; evidence remains visible after
  execution — and now also appears folded into the timeline.

## Tests

`tests/test_admissible_run_timeline.py` covers: the timeline initializes from a
goal/session (`needs_goal` -> `planned`); ingesting a structured response
creates a timeline turn; admitted local operations appear; batch execution
records execution and evidence into the timeline; refused/blocked operations
are represented; ingest still executes nothing; and evidence stays visible in
the timeline across export/import. The existing execution-review, control
surface, and run-loop suites continue to pass unchanged.

## Follow-up: `ADMISSIBLE_RUN_022_EVIDENCE_GROUNDED_CONTINUATION`

The timeline reflected turns but did not yet *drive* continuation. Slice 022
adds `build_continuation_instruction`, which composes the next bounded
instruction packet grounded in the timeline's executed evidence and
blocked/refused actions — see
`docs/admissible-evidence-grounded-continuation.md`.

Still open for later slices:

- No completion model yet: continuation asks for the next smallest admissible
  step and cannot recognize "the goal is done."
- Evidence is grounded as a per-run aggregate, not yet an inter-turn "what
  changed since last turn" diff.
- Turn 0 grouping for statically loaded traces is intentionally coarse; a
  richer plan-step alignment is left for a later slice.
