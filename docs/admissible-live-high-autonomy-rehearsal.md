# Admissible Live High-Autonomy Cursor Rehearsal (v0)

Before another live rehearsal, contract, ledger, exact-path, architecture, instruction, and verification-plan coverage must all be complete. Unsupported runtime criteria produce a visible verification capability gap, not success.

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

## Run 040 live closure rehearsal notes

The `pixel-wanderer-cli-010` fixture captures partial deliverable coverage (README instead of
LOCAL_DEV.md), aggregate pseudo-gate leakage, missing repair transition, null exported
projections, and environment-key collisions. Deterministic replay after RUN_040 completes via
targeted repair without a third provider turn. See
`benchmark/reports/admissible_pixel_wanderer_cli_010_live_audit.md`.

## Gate before the next live run with real browser verification (Run 043)

Before a live rehearsal can honestly claim runtime-verified completion for a browser-based
fixture (e.g. Neon Serpents), the run must show, per mandatory criterion: a
`deterministic_runtime` disposition backed by real `BrowserRuntimeEvidence` with
`status: verified_pass`, or an honest `human_observation_required` /
`runtime_observability_gap` / `verification_capability_gap` — never a static proxy standing in
for a criterion the Mission Contract marks as needing real runtime behavior. See
[admissible-bounded-browser-runtime-verification.md](admissible-bounded-browser-runtime-verification.md)
for the verifier this gate depends on, and
`tests/test_admissible_neon_runtime_regression.py` for the deterministic replay that proves the
gate holds without a real browser.

## Run 044: the runtime-verification step is now automatic, not a manual replay

RUN_043 above was a real, tested verifier that nothing yet *called* — a live rehearsal could
only prove runtime-verified completion by manually replaying
`build_runtime_verification_plan` → `execute_runtime_verification_plan` →
`apply_runtime_evidence_to_ledger`, exactly as
`tests/test_admissible_neon_runtime_regression.py` still does at the plan/evidence layer in
isolation. RUN_044 closes that gap: `tick_high_autonomy_run` itself now auto-triggers this
pipeline once static verification is final and nothing else is pending — no manual replay step,
no extra operator action, and no additional model/provider turn consumed by it. See
[admissible-high-autonomy-governed-loop.md](admissible-high-autonomy-governed-loop.md#run-044-runtime-verification-orchestration)
and
[admissible-bounded-browser-runtime-verification.md](admissible-bounded-browser-runtime-verification.md#run_044-wiring-into-the-high-autonomy-governed-run).

A pending subjective (`human_observation_required`) criterion now pauses the run in its own
`awaiting_human_observation` mode — distinct from the `human_required` pause described above,
which is reserved for genuinely dangerous actions (shell, secrets, destructive writes). The
Control Surface panel shows the exact pending criterion text and objective evidence already
recorded, with **Record observed pass** / **Record observed fail** / **Waive (requires
rationale)** actions
(`POST /api/session/high_autonomy/runtime/human_observation`) — never a generic approval
button. An interrupted runtime attempt (a process restart mid-run) is never auto-resumed; the
panel exposes an explicit **Retry interrupted runtime attempt** action instead
(`POST /api/session/high_autonomy/runtime/retry`), which preserves the interrupted attempt's
id, plan sha, and criteria as lineage on the new attempt.

### Exact gate before the next live Neon run

Everything above is proven with `FixtureBrowserRuntimeProvider` (deterministic, in-process) and
with one real-Chromium controller smoke
(`tests/test_admissible_runtime_live_controller_smoke.py`, opt-in, `-m browser_runtime`) using a
minimal single-criterion fixture. Before the next live Neon Serpents rehearsal specifically:

1. A real build of Neon Serpents must actually exist in the target workspace (all 8 mandatory
   paths), with `window.__NEON__.snapshot()` returning at least the 8 declared fields.
2. Run the live rehearsal with **no** `set_runtime_provider()` override, so the controller uses
   its real default (`admissible.runtime_verification_orchestrator.default_runtime_provider()`
   → `ChromiumCdpRuntimeProvider`), and confirm the four objectively-checkable criteria
   (bot count, restart/no-duplicate-loop, debug interface, debug overlay) reach
   `verified_pass` from real `BrowserRuntimeEvidence`, not a fixture.
3. Confirm the two subjective criteria (camera smoothness, readable background) reach
   `awaiting_human_observation`, and record a genuine human observation for each before
   claiming the run `completed`.
4. Confirm the three criteria with no derivable observable (collision/respawn, live
   leaderboard, repeated restarts) remain `unsupported_verifier` and are either accepted as a
   permanent, documented gap or given an explicit human waiver — never silently passed.
5. Confirm zero external network requests were recorded on the real run, and that the browser
   process, temporary profile, and loopback server were all torn down (`resource_cleanup`),
   with no orphan process left behind.

## Real ACP repair-rehearsal harness (Run 049)

`admissible/diagnostics/acp_repair_rehearsal.py` (diagnostic-only, never
imported by production code) drives one real controlled repair round through
the *actual* production `ControlSurfaceController`/high-autonomy lifecycle
against a deterministic pre-repair state, without depending on a model
"voluntarily" producing a flawed first implementation:

1. `build_deterministic_pre_repair_session()` uses only a scripted
   `FixtureAgentBackend` (zero real calls) to write four application files
   from an explicit `MANDATORY ACCEPTANCE CRITERIA` goal (the RUN_046 Repair
   Probe wording), then ticks the real controller forward until it reaches
   `repair_phase == "repair_needed"` with exactly one of eight criteria
   failing (an R-key restart handler, deliberately omitted) — never a
   hand-constructed `HighAutonomyRunState`, since the controller's own bounded
   verification is what proves the 7-pass/1-fail state, not an assertion.
2. `drive_repair_round()` then performs an explicit, deliberate backend-identity
   swap (PART J.47: a new `backend_id`, linked to the prior fixture attempt,
   never a silent reinterpretation) to the real `CursorAcpBackend`, snapshots
   the target workspace immediately before/after the *first* repair tick (the
   one that invokes the model) to prove the model turn itself caused zero
   mutation, and ticks the real controller to a terminal outcome
   (ingest → admission → bounded write → post-repair static verification →
   completion re-evaluation).

The mechanism is proven deterministically end-to-end with a second
`FixtureAgentBackend` standing in for the repair turn
(`tests/test_admissible_acp_repair_rehearsal.py`, 7 tests, zero real calls) —
including a "wrong repair" case (an irrelevant file write) that correctly
never falsely completes — before spending any of the slice's real-call
budget on the actual `CursorAcpBackend`. See
`benchmark/reports/admissible_run049_acp_promotion_and_repair_rehearsal.md`
for the real call's result (the model's plan-mode response tripped the new
proposal-only tool-event rejection — a correct, safe rejection, not a hard
failure — so the workspace was never mutated and the repair did not complete
in this real attempt).
