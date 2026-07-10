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

> **Update (slice ADMISSIBLE_RUN_032):** this GUI file bridge is now recognised as
> **semi-autonomous only** — a human still has to keep Cursor pointed at the bridge files. A
> [model-agnostic agent transport](admissible-model-agnostic-agent-transport.md) adds a
> *callable* `AgentBackend` (Cursor CLI / headless first) so the loop can invoke the agent
> directly, with the agent confined to an isolated **agent workspace** and no direct write
> authority over the **target workspace**. The file bridge stays available and unchanged as
> the external/manual backend.
>
> **Update (slice ADMISSIBLE_RUN_033):** the callable backend is now configured for the real
> local **Cursor Agent CLI** (`cursor-agent`) in read-only planning mode
> (`--print --output-format text --mode plan --workspace {agent_workspace} --trust {prompt}`).
> Safety validation rejects `--force` / `--yolo` / `--sandbox disabled`, requires `--print` +
> plan mode, and requires the isolated `{agent_workspace}`. Configure it with:
>
> ```powershell
> $env:ADMISSIBLE_CURSOR_CLI_COMMAND = "cursor-agent"
> $env:ADMISSIBLE_CURSOR_CLI_ARGS = "--print --output-format text --mode plan --workspace {agent_workspace} --trust {prompt}"
> $env:ADMISSIBLE_CURSOR_CLI_MODEL_LABEL = "cursor-agent-default"
> ```
>
> Operator smoke before the first real live run (never run from tests):
> `cursor-agent --print --output-format text --mode plan --workspace <agent_workspace> --trust "Reply with exactly: ADMISSIBLE_CURSOR_AGENT_SMOKE_OK"`.
>
> **Update (slice ADMISSIBLE_RUN_034):** a callable backend's response is now persisted in
> durable run state (an `AgentInvocationRecord`), not on the in-memory transport, so it
> survives the browser/server tick lifecycle (a fresh controller per request or a restart) and
> is ingested **exactly once**. The earlier live hang — a Cursor Agent response dispatched on
> one tick, then lost on the next when the controller/transport were reconstructed
> (`ingest_response` → `noop_waiting` forever) — is fixed. Callable backends now show
> `invoking_agent` → `response_ready` → `ingesting_response` → `response_consumed` and never
> "waiting for a response file"; only the file bridge waits on an external file. See
> [the durable handoff section](admissible-model-agnostic-agent-transport.md#durable-callable-response-handoff-across-ticks-slice-admissible_run_034).
>
> **Update (slice ADMISSIBLE_RUN_035):** Cursor Agent now always receives a short adapter
> prompt pointing to the absolute
> `<agent_workspace>/.admissible/next-agent-instruction.md` path. The full governed packet is
> never passed as a raw positional prompt, regardless of length. Cursor Agent must return the
> complete proposal on stdout and must not write any file or
> `.admissible/agent-response.md`. Empty stdout pauses with persisted path/hash/length/exit/
> duration/environment diagnostics and does not re-invoke on ordinary ticks. **Resume alone
> does not retry** — use **Retry backend invocation**, then **Step once**.
>
> **Update (slice ADMISSIBLE_RUN_036):** Admissible now forwards a Windows-aware safe profile
> environment to `cursor-agent` (SystemDrive, APPDATA, LOCALAPPDATA, ProgramData, … with
> bounded `%NAME%` expansion). Manual PowerShell runs worked because they inherited the full
> profile; the earlier minimal allowlist left literal `%SystemDrive%` paths and empty stdout.
> Terminal callable failures pause cleanly (`backend_error`, explicit retry required) and never
> oscillate into file-bridge waiting states.

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
2. Enter the **Target workspace** in the high-autonomy panel (now a top-level field, not an
   Advanced setting) and pick an **Agent backend** (File bridge is the default).
3. Open the workspace in Cursor and tell it to read
   `.admissible/next-agent-instruction.md` and write `.admissible/agent-response.md`.
4. Click **Start high-autonomy run**, then **Auto-run while safe**.
5. Watch the minimal panel. When it says *Waiting for Cursor response*, let Cursor write its
   reply; the next tick ingests and continues automatically.
6. If it pauses for a human-critical action, review the reason and Approve / Refuse.

For the callable Cursor Agent backend, steps 3 and 5 use the isolated agent workspace instead:
Admissible writes the full instruction file there, invokes `cursor-agent` once with the short
pointer adapter, persists stdout, and ingests that stdout on the next tick. No response file is
used.

## What is still not implemented

- No provider or Cursor API integration in the file-bridge path — Cursor remains a separate
  process. The [callable Cursor CLI backend](admissible-model-agnostic-agent-transport.md)
  drives an agent directly, but only when the operator configures a verified CLI command; it
  ships disabled.
- No arbitrary shell / npm / network / deploy executor; approving those records intent only.
  In high-autonomy mode **only admitted low-risk local writes are auto-executed**, by the
  bounded executor, and **human-critical actions still stop**.
- High-autonomy mode is opt-in and never the default; supervised/manual mode is unchanged.
- Response freshness relies on file sha256 + mtime, so Cursor must overwrite the same
  `agent-response.md` per turn (the bridge archives the prior one before each new turn).

## Tests

`tests/test_admissible_live_high_autonomy_hardening.py` — file-bridge instruction writes,
change-only response detection, stale/duplicate blocking, controller↔transport turn-metadata
alignment, bounded auto-execution, human-critical pause + approve/refuse, minimal status,
auto-run HTML markers, and unchanged manual mode.

## Fresh live-run acceptance after Run 038

The `pixel-wanderer-cli-006` source session is regression evidence, not a completed run. A
fresh rehearsal should use the four-file coherent batch and criterion-level checks recorded
in `tests/fixtures/admissible/pixel_wanderer_cli_006_regression.json`.

Expected operator-visible behavior:

1. Independent `index.html`, `style.css`, `game.js`, and `LOCAL_DEV.md` creates can arrive in
   one bounded response within the default limits.
2. A later same-run overwrite is automatic only when disk sha256 still matches latest
   execution evidence; an identical repeated proposal is a no-op.
3. Approval prose for an independently `ALLOW` local write creates no human stop; a genuine
   unresolved decision still does.
4. A 12-turn run enters completion-first closure at turn 10. Already-received responses,
   admitted operations, and deterministic verification finish without another model call.
5. Empty-success is visible and pauses by default. Manual retry is one linked invocation and
   does not duplicate response ingest or target writes.
6. Outcome/progress/usage/execution/remaining cards use canonical metrics; raw queue,
   invocation diagnostics, operation history, and verification records remain advanced data.
7. The final outcome is `completed` only after all mandatory fixture criteria verify. If the
   model budget ends first, the outcome is `stopped_by_budget` with exact unmet criteria and
   pending useful operations.

Step and auto-run are single-flight at both browser and server layers. A concurrent request
returns `tick_already_in_progress`; it does not call Cursor Agent again.
