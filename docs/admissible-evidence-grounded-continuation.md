# Admissible Evidence-Grounded Continuation v0

Slice `ADMISSIBLE_RUN_022_EVIDENCE_GROUNDED_CONTINUATION`.

## Purpose

The multi-turn run timeline
(`docs/admissible-multi-turn-run-timeline.md`) made a governed run *readable*
in sequence — goal → turn → proposal → admission → local execution → evidence —
but it did not yet *drive* the next turn. After a batch or individual local
execution, Admissible had no way to compose the next instruction for Cursor
grounded in what actually happened; a continuation depended on fragile
conversational memory ("you already wrote index.html, keep going...").

This slice closes that gap. Admissible can now produce a **bounded continuation
instruction** that states, in effect:

- this is the original goal;
- this is the current governed run state (proposed / admitted / executed /
  evidence / blocked counts);
- these actions were executed, with target paths and sha256 evidence where
  available — treat them as done;
- these actions were blocked / refused / not executed — they must **not** be
  treated as done;
- there is no explicit completion signal, so continue with the next smallest
  admissible step;
- propose only structured operations; do not write files directly; do not use
  shell/npm/network/deploy; write only to `.admissible/agent-response.md`.

## This is supervised continuation, not autonomy

**It adds no new powers.** No provider is called. No shell, npm, network,
deploy, dependency install, or arbitrary command execution was added. The
executor is not broadened. Nothing auto-executes. There is no completion model:
the continuation always asks for the *next smallest admissible step* rather than
declaring the goal complete. A human still triggers execution and still ingests
each agent response. This is the groundwork for
`ADMISSIBLE_DEMO_023_MULTI_TURN_LOCAL_BUILD`, not long-running task completion.

## How it works

`build_continuation_instruction(...)` in `admissible/run_loop.py` is a **pure
projection** over already-computed state (goal intake, plan audit, the current
queue, the run-loop `RunLoopState`, and the display-only `RunTimeline`). It
re-decides nothing, executes nothing, persists nothing, and calls no provider.
It returns a `ContinuationInstruction` dataclass:

```
schema_version, available, status, reason, turn_number, goal, instruction_text,
executed_operations, not_completed_operations, pending_execution_operations,
executed_count, evidence_count, not_completed_count
```

### Decision order

1. **No goal** → `available=False`, `status="no_goal"`, no instruction text.
2. **No agent response ingested yet** → first-turn behavior is preserved: it
   returns the standard first instruction packet text unchanged
   (`status="first_turn"`).
3. **Admitted local file operations still pending execution**
   (`run_timeline.ready_to_execute_local_count > 0`) →
   `available=False`, `status="pending_local_execution"`. It does **not** ask
   Cursor to continue; it reports which operations must be executed (or refused)
   first, so the next step is grounded in real evidence rather than an assumed
   result.
4. **Otherwise** → `available=True`,
   `status="evidence_grounded_continuation"`. It reuses
   `generate_instruction_packet` unchanged as the base packet — so every
   non-execution boundary, must-not rule, and the structured-operations-only
   response format carry over verbatim — then wraps it with an evidence preamble
   (original goal, run state so far, executed operations with paths + sha256,
   the blocked/refused/not-completed list) and the strict bridge constraints.

### Evidence grounding

- **Executed operations** come from the timeline's executed ops joined to the
  run-loop `EvidenceRecord`s: action id, turn, `operation_types`,
  `target_paths` / written paths, `sha256`, `execution_status`, evidence count.
  (sha256 lives on the `EvidenceRecord`, produced by the bounded local
  executor; the timeline itself only carries a per-action evidence count.)
- **Not-completed operations** are every non-executed op that is refused
  (`REFUSE`), awaiting a human decision (`REQUIRE_HUMAN_APPROVAL` /
  `REQUEST_MORE_EVIDENCE` / `ALLOW_WITH_LIMITS`, with missing-evidence detail
  where available), or admitted-but-not-executed. They are surfaced explicitly
  as "must NOT be treated as done." Admitted local file ops that are ready to
  run are reported separately as `pending_execution_operations`.

## Surfacing

- Backend: `admissible.control_surface._continuation_instruction(session,
  timeline)` calls `build_continuation_instruction` against the same
  `RunTimeline` object already built for the timeline panel (built once per
  `state_view()` via `_run_timeline_object`). `state_view()` exposes it as
  `continuation_instruction`. It is a derived view field only — it is **not**
  persisted into the session JSON and never advances the run-loop turn (that
  still only happens in `generate_next_instruction_packet`).
- UI: an **Evidence-Grounded Continuation** panel (`#continuation-panel`,
  `renderContinuation`) in `admissible/harness/control_surface.html`, directly
  below the Run Timeline panel. It shows whether a continuation is available,
  why it is blocked when execution is pending, the executed/evidence/not-completed
  counts, the not-completed list, and — when available — the generated
  instruction text with a **Copy continuation instruction** button. It is a
  technical panel for now.

## First-turn behavior is unchanged

The existing first-turn flow is untouched: `generate_next_instruction_packet`
still advances the turn and writes the same packet, the Cursor file bridge still
writes `next-agent-instruction.md` and reads `agent-response.md`, and before any
response is ingested the continuation simply mirrors that first packet. No file
is written on ingest; local execution stays an explicit, human-triggered step.

## Tests

`tests/test_admissible_evidence_grounded_continuation.py` covers: no
continuation without a goal; first-turn behavior preserved when no response is
ingested; no continuation while admitted local operations are pending execution;
continuation after execution includes executed file paths and sha256 evidence;
blocked/refused actions carried forward as not completed; missing-evidence
detail for `REQUEST_MORE_EVIDENCE`; the strict bridge constraints (structured
operations only, no direct file writes, no shell/npm/network/deploy, write only
to `.admissible/agent-response.md`) preserved in the instruction text; the
controller flow (pending → grounded) end to end; that the continuation is
display-only (executes nothing, advances no turn, is not persisted); and the UI
panel markers. The existing run-loop, control-surface, cursor-bridge, and run
timeline suites continue to pass unchanged.

## Remaining gaps before `ADMISSIBLE_DEMO_023_MULTI_TURN_LOCAL_BUILD`

- No completion model: the continuation always asks for the next smallest
  admissible step and cannot yet recognize "the goal is done."
- Grounding is per-run aggregate; there is no inter-turn "what changed since the
  last turn" diff yet.
- The continuation is composed but still human-driven end to end (a human writes
  it to the bridge / copies it, runs the agent, and ingests the reply). It does
  not drive a second local build turn automatically — that is the next slice.
