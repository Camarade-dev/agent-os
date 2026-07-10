# Admissible Live High-Autonomy Cursor Rehearsal (v0)

Slice: `ADMISSIBLE_RUN_030_LIVE_HIGH_AUTONOMY_REHEARSAL_HARDENING`

Builds on [the high-autonomy governed loop](admissible-high-autonomy-governed-loop.md).
Where that slice proved the loop can run without a human driver using a *fixture*
transport, this slice hardens the **file bridge** so the same loop can run against a
real, externally-running Cursor with minimal human driving — no manual prompt copying.

## How this differs from the earlier manual rehearsal

The [manual multi-turn rehearsal](admissible-live-cursor-multi-turn-rehearsal.md) had the
operator click Write instruction, Ingest response, Execute batch, and Copy continuation on
every turn. Here the operator does two things: **submit one goal** and **start the run**
(then optionally enable auto-run). Admissible writes each instruction, detects and ingests
each response, auto-executes admitted low-risk local writes, and composes the next
grounded instruction on its own.

## Cursor is still external (v0)

Admissible never calls Cursor, a provider, or any network API. Cursor runs on its own and
communicates only through two files in the target workspace:

- Admissible writes `.admissible/next-agent-instruction.md`.
- Cursor reads it and writes `.admissible/agent-response.md`.
- Admissible detects the new response, ingests it offline, and continues.

Point Cursor at the workspace once and tell it to keep reading the instruction file and
writing the response file. That is the only integration.

## Automatic instruction dispatch (hardened file bridge)

`FileBridgeAgentTransport` now keeps bridge turn metadata aligned with the controller:

- `write_instruction(text, turn_number, session_id, instruction_id)` writes the instruction,
  archives any leftover response, and records `turn` / `session_id` / instruction sha256 in
  `.admissible/bridge-state.json` (same keys the manual bridge uses).
- `read_response_if_changed()` returns a response **only when it is genuinely new**: it is
  blocked if its content matches the last consumed response (never ingested twice) or if it
  predates the current instruction (a stale leftover).
- `mark_response_consumed()` records the ingest so the same file is not re-read.
- `status_snapshot()` exposes a transport status for the UI:
  `instruction_written · waiting_for_response · response_detected · response_consumed ·
  stale_response_blocked · malformed_response_retry · error`.

## Safe browser auto-tick

The Control Surface panel adds three controls: **Auto-run while safe**, **Pause auto-run**,
and **Step once**. Auto-run calls the `tick` endpoint on a short interval, but:

- Each backend `tick_high_autonomy_run` still advances **at most one safe state-machine
  step**. There is no backend background loop.
- The browser loop only ticks while the run is `running / waiting_for_agent / reviewing /
  auto_executing / recovering / verifying` (the `auto_tick_safe` flag).
- It **stops immediately** on `human_required`, `failed`, `stopped`, `paused`, or a missing
  workspace, and on any request error.
- It never auto-approves anything and never runs when high-autonomy mode is off.

A small status line shows: `Auto-run active / paused / stopped`, the last tick step,
whether it is waiting for Cursor, and whether human action is required.

## What pauses for a human

The controller enters `human_required` and stops auto-run for a genuinely human-critical
proposal — shell command, write outside the workspace, destructive action, secret/env
access, or a non-recoverable `REQUIRE_HUMAN_APPROVAL`. The panel shows a concise reason and
Approve / Refuse buttons.

Approval **records the decision only**. v0 has no automatic shell/network/deploy executor at
any autonomy level, so approving a human-critical action marks it admitted-not-executed — a
human still runs it. Approval never invents execution capability. Recoverable blockers
(npm / deploy) do not pause; they get an automatic local-only recovery instruction and stay
on the queue as *not completed*.

## Minimal live status

The top panel answers only: what is being done now, what is needed now, what is blocking,
the last event, evidence count, verification readiness, and any required human action. Raw
queue, transcript, and bridge logs stay under **Advanced / Debug**. `state_view` also
exposes `live_high_autonomy_rehearsal_status` (workspace path, transport state, instruction/
response paths, current turn, waiting-for-Cursor, stale-blocked, human-required, verification
passed) for the UI and tests — display-only, never an authority source.

## Running a live rehearsal without copy/paste

1. Open the Control Surface and submit the tiny-game goal.
2. Enter the workspace path in the Cursor bridge section (Advanced).
3. Open the workspace in Cursor and tell it to read
   `.admissible/next-agent-instruction.md` and write `.admissible/agent-response.md`.
4. Click **Start high-autonomy run**, then **Auto-run while safe**.
5. Watch the minimal panel. When it says *Waiting for Cursor response*, let Cursor write its
   reply; the next tick ingests and continues automatically.
6. If it pauses for a human-critical action, review the reason and Approve / Refuse.

## What is still not implemented

- No provider or Cursor API integration — Cursor remains a separate process.
- No arbitrary shell / npm / network / deploy executor; approving those records intent only.
- High-autonomy mode is opt-in and never the default; supervised/manual mode is unchanged.
- Response freshness relies on file sha256 + mtime, so Cursor must overwrite the same
  `agent-response.md` per turn (the bridge archives the prior one before each new turn).

## Tests

`tests/test_admissible_live_high_autonomy_hardening.py` — file-bridge instruction writes,
change-only response detection, stale/duplicate blocking, controller↔transport turn-metadata
alignment, bounded auto-execution, human-critical pause + approve/refuse, minimal status,
auto-run HTML markers, and unchanged manual mode.
