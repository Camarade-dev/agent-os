# Admissible High-Autonomy Governed Loop (v0)

Mission authority and completion are governed by the immutable contract described in [admissible-mission-contract.md](admissible-mission-contract.md). A progress ledger is only a projection and cannot narrow explicit requirements.

Slice: `ADMISSIBLE_RUN_029_HIGH_AUTONOMY_GOVERNED_LOOP_V0`

## Why this slice exists

Previous Admissible slices built every *piece* of a governed run — goal intake, admission,
bounded local execution, evidence-grounded continuation, blocker/recovery demos, and the
Cursor file bridge — but the **human was still the driver**. Operators had to copy
continuation text, click ingest, click execute batch, and advance each turn by hand.

This slice introduces the first **tick-driven high-autonomy controller**: the user submits
one goal, starts a high-autonomy run, and Admissible drives the loop through safe,
explicit steps.

This is the real long-running loop substrate — not another operator runbook.

## What is automated

When high-autonomy mode is **explicitly started** (opt-in, L4 autonomy):

1. **Instruction dispatch** — writes the next instruction (first-turn packet or
   evidence-grounded continuation) to the agent bridge via `AgentTransport`.
2. **Response detection** — polls the bridge for a new `agent-response.md` (or fixture
   transport in tests).
3. **Ingest** — calls the existing `ingest_agent_response` path (no direct file writes
   on ingest).
4. **Admission** — unchanged rules-only evaluator; gates are not weakened.
5. **Auto-execution** — admitted `ALLOW` local file operations inside the configured
   workspace are executed through the existing bounded executor, with sha256 evidence.
6. **Recovery** — npm/deploy/shell blockers trigger an automatic local-only recovery
   instruction; blocked actions remain **not completed**.
7. **Verification** — bounded verification runs as an explicit controller step when policy
   says it is safe (after pending local writes are done and no next instruction is due).
8. **Stop** — when verification has run and no further agent responses are expected.

Each step is one `tick_high_autonomy_run` call — no hidden background process.

## What still requires human approval

High-autonomy **never** auto-approves:

| Category | Examples |
|----------|----------|
| `REQUIRE_HUMAN_APPROVAL` (non-recoverable) | Shell commands, secrets/env access |
| Deploy / publish | Production deploy proposals |
| Dependency install | `npm install`, `pip install`, etc. |
| Network / external access | curl, CDN fetches, provider calls |
| Writes outside workspace | Path escape, absolute paths |
| Destructive / irreversible | Deletes, git push, chmod |
| Arbitrary shell | Any command execution |
| Explicit `REQUIRE_HUMAN_APPROVAL` decisions | Cannot be overridden by autonomy level |

**Recoverable blockers** (demo: npm + deploy on turn 3) do **not** pause the run; the
controller writes a recovery instruction asking for a local-only alternative. Those
actions stay on the queue as **not completed**.

## Policy: auto-execution vs pause

`HighAutonomyPolicy` classifies each queue item:

- **auto_executable** — admitted `ALLOW`, structured local op, inside workspace, supported
  by bounded executor, passes content guards.
- **recoverable_blocker** — `install_dependency`, `deploy_code`, etc. with
  `REQUEST_MORE_EVIDENCE` / `REQUIRE_HUMAN_APPROVAL`; recovery continuation is issued.
- **human_critical** — shell, secrets, outside workspace, non-recoverable approval; run
  enters `human_required` and waits for Approve / Refuse.
- **blocked_not_completed** — refused or ineligible; never executed.

Auto-execution is capped per turn (`DEFAULT_MAX_AUTO_EXECUTIONS_PER_TURN = 8`).

## Transport boundary (`AgentTransport`)

```text
write_instruction(text)
read_response_if_changed() -> (text, cursor)
response_cursor
clear_or_archive_response()
```

Implementations:

- **`FileBridgeAgentTransport`** — production path; writes
  `.admissible/next-agent-instruction.md`, reads `.admissible/agent-response.md`.
  Does **not** call Cursor APIs.
- **`FixtureAgentTransport`** — deterministic test transport with scripted responses.

v0 does not fake Cursor integration: Cursor must run externally and write the response
file. Admissible removes manual copy/paste of continuation text.

## Controller API

| Method / route | Purpose |
|----------------|---------|
| `start_high_autonomy_run` | Opt in; set L4; bind workspace + transport |
| `pause_high_autonomy_run` | Operator pause |
| `resume_high_autonomy_run` | Resume paused run |
| `stop_high_autonomy_run` | Stop with reason |
| `tick_high_autonomy_run` | Advance at most one safe step |

HTTP: `/api/session/high_autonomy/{start,pause,resume,stop,tick,approve,refuse}`

## UI

A top-level **High-Autonomy Governed Run** panel shows only:

1. What is being done now
2. What is needed now
3. What is blocking
4. Last meaningful event
5. Evidence / verification summary
6. One primary button (Start / Pause / Resume / Stop / Approve / Refuse)

Manual bridge, queue, timeline, and transcript are under **Advanced / Debug**.

## Human-critical refusal recovery

When a turn proposes genuinely human-critical actions (e.g. `git push`, `git commit`,
`publish`, a shell command, or a write outside the workspace), the loop pauses in
`mode = human_required` and stops the browser auto-run. The state now describes the pause
**per action**, not with a single generic message:

- `human_required_action_ids` / `human_required_action_count` — every currently-open
  human-critical action still awaiting a decision.
- `human_required_actions` — concise `{action_id, action_type, tool_or_command, reason}`
  labels the panel lists so the operator sees exactly what is blocking.

An action only counts as an open human-critical blocker when a human decision is actually
available for it. A capability the rules-only evaluator already `REFUSE`d is
human-critical by capability but offers no human action — it is already blocked and never
pins the loop in `human_required`.

### What happens after **Refuse**

`refuse_high_autonomy_human_action` (route `/api/session/high_autonomy/refuse`):

1. Records a refusal decision — through the existing `decide()` / `HumanDecisionRecord`
   model — against **every** currently-open human-critical action, not just the surfaced
   one. (Refusing only one used to leave the others open, re-entering `human_required` on
   the next tick — the stuck-UI bug this fixes.)
2. Marks those actions refused/closed and **not completed** (`lifecycle = refused_closed`,
   `execution_status` stays `proposed_only` — never executed).
3. Does **not** re-ingest the already-consumed response; stale/duplicate-response
   protection stays intact and a recorded "duplicate response" bridge warning is
   non-fatal.
4. Leaves `human_required` and sets `mode = recovering`, `next_action =
   write_recovery_instruction`.
5. On the next safe tick, composes a **bounded local-only** recovery instruction grounded
   in the refused actions: it names them, says they are not completed and must not be
   retried in their forbidden form, and asks for the next smallest admissible local-only
   structured operation writing only `.admissible/agent-response.md` — no shell, npm, pip,
   git push/commit, publish, deploy, network, CDN, secrets, or paths outside the
   workspace. It is written to `.admissible/next-agent-instruction.md`; `mode` becomes
   `waiting_for_agent` and auto-run may safely continue.

### Why **Approve** does not create forbidden executor powers

`approve_high_autonomy_human_action` records approval/admission **intent only** for the
one targeted action. v0 has no automatic shell/network/deploy executor at any level, so an
approved human-critical action is marked `admitted_not_executed` — a human still runs it
externally. Approval is a deliberate per-action authority grant, so it targets a single
action; a non-approvable proposal (e.g. `REQUEST_MORE_EVIDENCE`) is rejected with a clear
error rather than inventing approval authority. If other human-critical actions remain, the
loop stays in `human_required` for them.

## Manual mode unchanged

Supervised mode is the default. Without calling `start_high_autonomy_run`, behavior is
identical to prior slices: ingest never executes; batch execute remains explicit.

## What this is not

- Not provider integration (no Cursor/OpenAI/Gemini API calls)
- Not arbitrary shell execution
- Not npm / deploy / network execution
- Not weakened admission or content guards
- Not default-on autonomy

## Preparing the final demo

This slice proves the four-turn blocker/recovery demo can run **without a human driver**
using fixture transport. Remaining gap for a true live Cursor high-autonomy run:

1. **External Cursor** must read the instruction file and write the response file each turn.
2. **File bridge polling** in production uses mtime/sha256 on `agent-response.md`.
3. **Turn latency** is human/agent-bound; the browser may call `tick` on an interval while
   `mode === waiting_for_agent`.
4. **Human-critical pauses** need the operator to Approve/Refuse in the minimal panel.
   Refuse always clears every open human-critical action and hands off a local-only
   recovery instruction (see *Human-critical refusal recovery*), so the run continues
   safely without re-entering `human_required`.

The controller, policy, transport, tests, and UI are in place for that live rehearsal
once Cursor is pointed at the workspace.

## Update — model-agnostic agent transport (slice ADMISSIBLE_RUN_032)

The `AgentTransport` above is the **pull / external** shape: write an instruction, then poll
for a response file that a human-driven editor produces. That is semi-autonomous. A later
slice adds a **model-agnostic `AgentBackend`** callable shape so the same tick loop can
*invoke* an agent backend directly (Cursor CLI first; fixture backend in tests), with the
agent confined to an isolated agent workspace and no direct write authority over the target
workspace. See [the model-agnostic agent transport doc](admissible-model-agnostic-agent-transport.md).

The auto-execution described here is unchanged, but the truthful framing is: Admissible has
**no arbitrary executor** and runs no shell/npm/network/deploy — **only admitted low-risk
local writes may be auto-executed** in high-autonomy mode, and **human-critical actions still
stop**.

## Tests

- `tests/test_admissible_high_autonomy_governed_loop.py` — deterministic four-turn flow
  with `FixtureAgentTransport`.
- `tests/test_admissible_live_high_autonomy_hardening.py` — live file-bridge hardening and
  the human-critical pause path.
- `tests/test_admissible_high_autonomy_human_required_recovery.py` — human-critical refusal
  recovery: refusal clears all open actions, exits `human_required`, writes a local-only
  recovery instruction, and approval records intent without inventing an executor.
- `tests/test_admissible_model_agnostic_agent_transport.py` — the callable `AgentBackend`
  shape, workspace safety, and Cursor CLI configuration.
- `tests/test_admissible_cursor_agent_windows_environment.py` — Windows-safe subprocess env
  builder and probe parity (slice ADMISSIBLE_RUN_036).
- `tests/test_admissible_callable_terminal_pause.py` — terminal callable-backend pause,
  exactly-once/no-rebilling, and disjoint file-bridge vs callable UI wording
  (slice ADMISSIBLE_RUN_036).
- RUN_044 runtime-orchestration tests (see the Run 044 section below):
  `tests/test_admissible_runtime_orchestrator.py`,
  `tests/test_admissible_runtime_controller_integration.py`,
  `tests/test_admissible_runtime_single_flight.py`,
  `tests/test_admissible_runtime_exactly_once_evidence.py`,
  `tests/test_admissible_runtime_persistence_recovery.py`,
  `tests/test_admissible_runtime_async_tick_flow.py`,
  `tests/test_admissible_runtime_repair_orchestration.py`,
  `tests/test_admissible_runtime_human_observation.py`,
  `tests/test_admissible_runtime_control_surface_api.py`,
  `tests/test_admissible_runtime_control_surface_ui.py`,
  `tests/test_admissible_neon_runtime_end_to_end.py`,
  `tests/test_admissible_runtime_live_controller_smoke.py` (opt-in, `-m browser_runtime`).

## Run 038 closure and governance contract

`ADMISSIBLE_RUN_038_LIVE_RUN_EFFICIENCY_CLOSURE_AND_GOVERNANCE_HARDENING` makes
`pixel-wanderer-cli-006` the canonical long-run regression without claiming that the
source run completed. The governed loop now uses these durable rules:

- The agent proposes the next smallest **coherent bounded batch**, not the smallest
  individual operation. The default response bound is eight structured operations and
  256 KiB of proposed UTF-8 write content. Every path remains workspace-relative and the
  bounded executor still rejects shell, package-manager, network, deploy, destructive,
  external-resource, executable-command, and secret-reference content.
- Every continuation carries a concise current-state progress ledger: acceptance criteria,
  satisfied/open criteria, latest final file hashes, pending useful operations,
  stale/superseded actions, remaining work budget, closure phase, and batch limits. It does
  not replay the historical transcript.
- Canonical fingerprints are `write_file + normalized path + sha256(content)`,
  `read_file + normalized path + observed/expected sha256`, and `list_files + normalized
  path`. Repeated executed work closes as `duplicate_noop`; a write already matching disk
  closes as `already_satisfied_noop`.
- Safe overwrite remains low-risk only for a non-sensitive path under the submitted goal
  when this run created the file and current disk sha256 matches latest execution evidence.
  A pre-run file, changed sha256, sensitive/executable path, ambiguous scope, destructive
  operation, external resource, secret, or authority escalation requires human review or
  stronger evidence.
- Model text is never admission authority. A “Human decision required” sentence that merely
  restates approval for a separately extracted `ALLOW` operation is suppressed. Equivalent
  gates merge, and already-covered gates are superseded with `superseded_by_action_id`,
  reason, and timestamp. Supersession is queue cleanup, not approval.
- Only open, non-superseded, genuinely human-critical actions pause the loop. `REFUSE`,
  `REQUEST_MORE_EVIDENCE`, sensitive overwrite, destructive/irreversible work, external
  authority, and actual unresolved user choices retain their hard gates.

### Acceptance, verification, and outcomes

Each high-autonomy run persists criteria with `criterion_id`, source text, mandatory flag,
status (`open`, `evidence_available`, `verified_pass`, `verified_fail`, `waived`), evidence
references, verification notes, and generic allowlisted verification requests. A model may
emit `ADMISSIBLE_COMPLETION_CANDIDATE`, but the record is advisory and cannot waive or
self-authorize a criterion.

A run reaches `completed` only when all mandatory criteria are `verified_pass` or explicitly
human-waived, deterministic verification is final, no active human-critical blocker remains,
and no useful admitted operation is pending. Other final states are `incomplete`, `failed`,
`stopped_by_budget`, and `stopped_by_operator`, each with an exact reason and unmet/pending
state.

The model-invocation budget is split into work and closure capacity. With the default 12-turn
budget and two-turn closure reserve, turn 10 enters completion-first mode. Pending response
ingest, admitted bounded execution, and deterministic local verification finish even at the
turn boundary because they require no additional model call. Budget exhaustion is reported
as `stopped_by_budget`, never generic “Stopped”.

Canonical metrics separate backend invocation/retry/empty-success usage; useful writes,
unique file states, duplicate no-ops, and overwrites; reads/lists; verification checks; genuine
human interventions, suppressed pseudo-gates, superseded gates, and active blockers; and
work/verification/closure budget usage. `active_blocked_count` is the one definition used by
the persisted run, export, summary, governed overview, and UI.

## Run 040 verification repair, pseudo-gates, and portable export

`ADMISSIBLE_RUN_040_VERIFICATION_REPAIR_CLOSURE_PSEUDO_GATE_AND_EXPORT_FIX` closes the
`pixel-wanderer-cli-010` regression without broadening executor authority.

- **Proposal coverage:** after extraction, compare mandatory goal paths against proposed and
  already-satisfied paths. Safe partial batches may execute; missing mandatory paths trigger
  `repair_needed` rather than rejecting the whole batch. README does not satisfy LOCAL_DEV.md.
- **Repair-needed state machine:** `verification_failed_repairable → repair_needed →
  writing_repair_instruction → awaiting_repair_response → repair_executing → repair_verifying`.
  Repair packets contain only failed mandatory criteria, diagnostics, satisfied hashes, exact
  missing paths, boundaries, and remaining budget. Default `max_repair_rounds=2`.
- **Verification fail ≠ internal mismatch:** ordinary failed acceptance criteria must not become
  `internal_livelock`. Livelock is reserved for contradictory execution state.
- **Aggregate pseudo-gate suppression:** prose such as “Approve bounded execution of the four
  structured write_file operations below” is suppressed when concrete sibling operations exist.
  Stale persisted gates are repaired on session load. Metrics distinguish
  `raw_human_decision_count`, `genuine_human_intervention_count`, and
  `retrospectively_suppressed_pseudo_gate_decision_count`.
- **Non-null projections:** `outcome` defaults to `in_progress`; counts default to `0`;
  `blocking_reason` defaults to empty string. Legacy null session fields migrate on load/export.
- **Portable JSON:** environment diagnostic keys are canonicalized case-insensitively before
  export; source aliases are recorded separately, never as duplicate object keys.
- **Browser-runtime verification state (Run 043):** `admissible/browser_runtime/state_machine.py`
  adds `runtime_verification_pending → preparing_runtime_plan → runtime_capability_check →
  runtime_verifying → {runtime_verification_pass, runtime_verification_fail,
  runtime_observability_gap, awaiting_human_observation, runtime_verification_capability_gap}`,
  reusing the existing `repair_needed` phase so a runtime repair composes with the pre-existing
  repair loop. A runtime capability gap or failure never becomes `internal_livelock`,
  `human_authority_blocker`, or `completed`. A dedicated `browser_runtime_verification`
  admission class keeps a runtime-verification action from ever being represented as a shell
  action. See
  [admissible-bounded-browser-runtime-verification.md](admissible-bounded-browser-runtime-verification.md).

## Run 044: runtime-verification orchestration

`ADMISSIBLE_RUN_044_HIGH_AUTONOMY_RUNTIME_ORCHESTRATION_AND_END_TO_END_CLOSURE`
wires RUN_043's bounded browser-runtime verifier into this controller's own
tick loop, without turning `high_autonomy_controller.py` into a bigger
monolith and without embedding any browser-provider logic in it.

**Orchestration boundary.** Two new modules, both peers of
`high_autonomy_controller.py` (not inside `browser_runtime/`):
`admissible/runtime_orchestration_models.py` (the durable
`RuntimeVerificationAttempt` attempt schema and the
`RuntimeOrchestrationTransition` the orchestrator hands back) and
`admissible/runtime_verification_orchestrator.py` (the narrow
`assess_runtime_need` / `prepare_runtime_attempt` / `start_runtime_attempt`
/ `poll_runtime_attempt` / `apply_runtime_evidence` /
`cancel_runtime_attempt` / `reconcile_runtime_state_on_load` /
`record_human_observation` API, plus the single-flight background-worker
registry). The controller only calls these five/six functions and persists
what comes back — it never imports anything from
`admissible/browser_runtime/` except the read-only vocabulary in
`state_machine.py`/`terminal_ui.py`. See
[admissible-bounded-browser-runtime-verification.md](admissible-bounded-browser-runtime-verification.md#run_044-wiring-into-the-high-autonomy-governed-run)
for the full detail, including two RUN_043 integration-defect fixes this
wiring surfaced (a criterion-status-aggregation bug and a
`policy_violations` deserialization gap) and a plan_builder re-attempt fix
needed for retries/repairs to regenerate real steps.

**New `HighAutonomyRunState` fields:** `runtime_verification_required`,
`runtime_verification_status`, `active_runtime_attempt_id`,
`active_runtime_attempt`, `active_runtime_plan`, `runtime_attempt_history`,
`last_runtime_plan_sha256`, `last_runtime_evidence_id`,
`runtime_criterion_ids`, `runtime_pending_criterion_ids`,
`runtime_failed_criterion_ids`, `runtime_gap_criterion_ids`,
`runtime_coverage_report`, `runtime_repair_kind`,
`human_observation_pending_criterion_ids`, `human_observation_records`.

**New tick next-actions:** `start_runtime_verification` (Tick A: validate +
persist + capability-check + start the worker, returns promptly),
`poll_runtime_verification` (non-blocking check, never starts a second
attempt), `apply_runtime_evidence` (persists evidence, applies it exactly
once, re-evaluates completion in the same tick),
`await_human_observation` (a stable wait state, distinct from
`human_approval_required`). None of these is a model/provider turn.

**New modes:** `runtime_verifying` (added to the auto-tick-safe set — a
frontend polling loop may keep calling tick while a runtime worker is
active, the same as it already could during `verifying`) and
`awaiting_human_observation` (deliberately *not* auto-tick-safe: only an
explicit `record_human_observation` call resumes it, and it is excluded
from the no-progress-tick counter so it never degrades into
`internal_livelock`).

**New Control Surface API** (thin delegation, no arbitrary plan/selector/
JavaScript/URL/entrypoint ever accepted):
`GET /api/session/high_autonomy/runtime_status`,
`POST /api/session/high_autonomy/runtime/retry`,
`POST /api/session/high_autonomy/runtime/cancel`,
`POST /api/session/high_autonomy/runtime/human_observation` (accepts only
`criterion_id`/`actor`/`disposition`/`note`/`evidence_refs`).

**Canonical metrics added:** `runtime_plan_count`, `runtime_attempt_count`,
`runtime_retry_count`, `runtime_pass_count`, `runtime_fail_count`,
`runtime_capability_gap_count`, `runtime_observability_gap_count`,
`runtime_policy_violation_count`, `runtime_assertion_count`,
`runtime_assertion_pass_count`, `runtime_assertion_fail_count`,
`runtime_duration_ms_total`, `runtime_input_event_count`,
`runtime_snapshot_count`, `runtime_screenshot_count`,
`runtime_external_request_attempt_count`, `runtime_cleanup_failure_count`,
`human_observation_count`, `human_observation_pass_count`,
`human_observation_fail_count`, `human_observation_waiver_count`. These are
recomputed both by `_sync_counters` (every tick) and by
`ControlSurfaceController.session_dict()` (every state read, including
outside a tick — otherwise `session_dict()`'s own base-metrics recompute
would silently drop them between ticks).

**Completion eligibility is unchanged in authority:**
`evaluate_completion_eligibility()` is still the only place `completed` is
decided; the orchestrator only ever mutates the ledger and asks
`_try_finalize_outcome` to look again. A runtime pass, a runtime failure
entering repair, a capability gap, an observability gap, and a pending
human observation are all distinguishable outcomes/modes — none of them is
ever silently reported as `completed`, `internal_livelock`, or
`human_authority_blocker`.

## Run 045: post-repair verification liveness, wait invariants, and run identity

`ADMISSIBLE_RUN_045_POST_REPAIR_VERIFICATION_LIVENESS_WAIT_INVARIANTS_AND_RUN_IDENTITY`
fixes a real livelock observed in an exported live session
(`control_session_89d4376c8c43`, minimized as
[`tests/fixtures/admissible/pixel_wanderer_cli_002_regression.json`](../tests/fixtures/admissible/pixel_wanderer_cli_002_regression.json)):
after a successful targeted repair (the repair write had already executed),
the run got stuck at `mode=waiting_for_agent`, `repair_phase=repair_verifying`,
`next_action=none` — every subsequent auto-run tick returned a reasonless
wait forever instead of scheduling the re-verification that was due. This is
a general state-machine/liveness defect in the post-repair transition, not
specific to Pixel Wanderer, game controls, or the browser runtime.

**Root cause.** In `_plan_next_action`'s `mode == HA_MODE_WAITING_FOR_AGENT`
branch, once a callable-backend response had been consumed
(`backend_step=response_consumed`, `pending_invocation_status=consumed`) with
no retry/reinvoke pending, the branch unconditionally returned
`HA_NEXT_NONE`. It never checked whether `repair_phase` had just finished a
post-write phase (`repair_executing`/`repair_verifying`) that requires
scheduling a static or runtime re-verification — so the pre-existing
repair-phase check further down in the same function could never run; the
callable-backend fallback had already returned first. The file-bridge
fallback had the identical shape of bug.

**Fix.** `_plan_next_action` now computes
`repair_needs_post_write_verification(ha_state.repair_phase)` once up front
and gates both the callable-backend and file-bridge `waiting_for_agent`
fallbacks on it: when a repair-verification is due, the function falls
through instead of returning early, and the existing repair-phase branch
schedules `run_bounded_verification` or `start_runtime_verification` via the
new `plan_post_repair_verification()` helper.

**New module `admissible/high_autonomy_state_invariants.py`** — pure and
standalone, like `admissible.browser_runtime.state_machine` (RUN_043) and
`admissible.runtime_verification_orchestrator` (RUN_044); it never mutates
`HighAutonomyRunState` directly, only classifies already-gathered signals:

- `classify_waiting_for_agent_condition` / `waiting_for_agent_is_valid` — the
  one closed, typed vocabulary of legitimate reasons `waiting_for_agent` may
  still hold (`backend_invocation_running`, `runtime_worker_running`,
  `evidence_file_pending`, `human_authority_decision`, `human_observation`,
  `explicit_operator_retry`). Anything outside this vocabulary is an
  invariant violation, never a silent indefinite wait.
- `repair_needs_post_write_verification` / `plan_post_repair_verification` —
  the canonical post-repair-write routing decision (PART C), used both by
  the controller's normal planner and by session-load reconciliation so
  there is exactly one place this logic lives.
- `reconcile_contradictory_state` — detects and deterministically repairs
  the exact contradictory combination above on session load and before
  every tick (`_reconcile_high_autonomy_state`, called at the top of
  `tick_high_autonomy_run` before `_sync_counters`). Recovery is a pure
  relabeling of already-persisted state: it consumes no model turn, no
  repair round, and no human-intervention metric, and it always leaves a
  `state_invariant_reconciliation` governance record for audit.
- `check_state_invariants` — the full invariant sweep (waiting-for-agent
  validity, repair-verifying-without-scheduled-verification,
  next_action=none-without-justification) used by diagnostics/tests.

**New durable `HighAutonomyRunState` fields:** `wait_reason`,
`wait_condition_type`, `wait_condition_id`, `wait_started_at`,
`wait_timeout_at`, `expected_state_change`, `wait_poll_count`,
`technical_pause_active`, `technical_pause_reason`,
`state_invariant_violations`, `last_reconciliation`.

**Bounded wait/livelock semantics.** A `waiting_for_agent` state with no
legitimate typed wait condition is fingerprinted; if it recurs on a second
consecutive tick with the same fingerprint (reasonless wait, not a
documented runtime-worker/backend-invocation wait), the run enters a new
`technical_pause` mode via `_pause_for_technical_state_invariant` — distinct
from the pre-existing `internal_livelock` no-progress pause, and distinct
from any genuine human-authority pause. Legitimate waits (a real callable
invocation in flight, a real runtime worker running) are exempt and remain
safe indefinitely.

**Auto-run frontend correctness.** The harness previously showed "Backend
invocation in progress" during any in-flight tick HTTP request, even when
no backend invocation existed — misleading during an ordinary tick or a
runtime-verification poll. `computeProgressBanner(ha)` now derives one of
six mutually exclusive labels (`TECHNICAL PAUSE`, `RUNTIME VERIFICATION
RUNNING`, `BACKEND INVOCATION RUNNING` only when
`ha.backend_step === "invoking_agent"`, `ADVANCING STATE` for a plain tick,
`AUTO-RUN ACTIVE`, `AUTO-RUN PAUSED`). A generation-token counter
(`autoRunGeneration`) is incremented on every `stopAutoRun()`; the async
`autoRunLoop(generation)` checks the token at entry and after every await,
so a stale in-flight request from a previous auto-run cannot resume the
loop after Pause — Pause is authoritative.

**Run Identity UX.** Workspace names are not mission authority (this
session's workspace was named `neon-serpents-cli-002` while the actual goal
was Pixel Wanderer, with no on-screen signal of the mismatch). A new
server-computed `run_identity` projection (`_run_identity()` in
`control_surface.py`) and a new "Run Identity" panel in the harness surface
the authoritative goal's first line, the raw-goal SHA-256, the Mission
Contract SHA-256, the target workspace, the backend, and the created
timestamp — sourced only from the raw goal and Mission Contract, never
inferred from the workspace folder name — plus a non-blocking diagnostic
warning when the workspace folder name shares no token with a project name
mentioned in the goal. The panel is visible as soon as a goal is submitted,
before the first backend invocation.

**Unbulleted acceptance-section parsing.** A line under an "Acceptance
criteria:" heading with no `-`/`*`/numeric prefix is no longer silently
dropped by `build_mission_contract()`; it is recorded as an explicit,
mandatory requirement (`mandatory_requirements`, trailing `;`/`,`/`.`
stripped). It is intentionally routed to `mandatory_requirements` rather
than `explicit_acceptance_criteria` — promoting it to a criterion would
have discarded the generic 8-criteria `derive_acceptance_criteria_from_goal`
inference (and its verification-check wiring) that cli_011-shaped goals
already depend on. `ledger_coverage_report()` gained
`inferred_acceptance_criterion_count`, `total_ledger_criterion_count`, and
`criteria_are_inferred` so the UI can show "N/M inferred criteria
represented" instead of a misleading "0/0" when no explicit
acceptance-criteria section was matched.
