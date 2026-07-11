# Admissible bounded browser-runtime verification (slice RUN_043)

Static file inspection cannot honestly prove many mandatory browser
behaviors: continuous pointer steering, live bot movement, collision and
respawn, pause/resume, restart without duplicate animation loops, a
read-only debug interface, a `?debug=1` overlay. RUN_043 adds a real,
strictly bounded local-browser runtime verifier so Admissible can observe
those behaviors instead of guessing at them from source text.

See [admissible-mission-contract.md](admissible-mission-contract.md) for
the contract/ledger this layer plugs into, and
[admissible-bounded-verification.md](admissible-bounded-verification.md)
for the pre-existing static verification layer this one complements
without replacing.

## What this is

A dedicated, read-only runtime verifier (`admissible/browser_runtime/`)
that can:

- serve an authorized local workspace through an isolated loopback-only
  HTTP server;
- launch an already-installed allowlisted Chromium-family browser
  (Chrome, Edge, or Chromium) with fixed, verifier-owned arguments;
- prevent page-originated external network access via CDP request
  interception;
- load the local application and dispatch a bounded set of keyboard,
  pointer, and click inputs;
- collect console, page-error, request, DOM, screenshot, and debug-snapshot
  evidence;
- evaluate only a declarative, allowlisted verification plan;
- map runtime assertions back to Mission Contract criteria;
- report a `verification_capability_gap` when the required behavior cannot
  yet be observed, and never a false pass.

## What this is not

- Not a general process or shell executor.
- Not an arbitrary JavaScript execution API — there is no "evaluate
  expression" step anywhere in the declarative DSL.
- Not a package installer or browser downloader — it only launches an
  already-installed binary from a fixed allowlist.
- Not a public server — the loopback HTTP server is bound to `127.0.0.1`,
  keyed by an unguessable per-session route token, and torn down at the
  end of the session.
- Not authority over subjective/visual claims — "smooth", "polished", and
  similar requirements route to `human_observation_required`, never to an
  invented passing assertion.

## Architecture

| Module | Responsibility |
|---|---|
| `models.py` | Durable schemas: `BrowserRuntimeCapabilityReport`, `BrowserRuntimeVerificationPlan`, `BrowserRuntimeCriterionPlan`, `BrowserRuntimeEvidence`. Kept separate from proposal, admission, write, static, and human evidence. |
| `limits.py` | Every hard ceiling and allowlist (step types, browser basenames, JSON grammar) in one place. |
| `dsl.py` | Validates one declarative step or plan; the only place a CDP evaluation expression is synthesized (`build_snapshot_expression`), always from a regex-validated `window.__NAME__` path. |
| `assertions.py` | Pure JSON-path resolution/comparison and snapshot-diff logic shared by every provider. |
| `provider.py` | `BrowserRuntimeProvider` (5-operation ABC: detect/create/execute/collect/close) and `BaseBrowserRuntimeProvider`, which implements the declarative-step interpreter once against small per-provider primitives. |
| `fixture_provider.py` | `FixtureBrowserRuntimeProvider` — deterministic, in-memory, no real browser; used by the entire unit test suite. |
| `discovery.py` | Allowlisted browser discovery (`ADMISSIBLE_BROWSER_EXECUTABLE` or known install locations) and side-effect-free version detection. |
| `process_cleanup.py` | Windows Job Object / POSIX process-group launch and bounded termination of the whole browser process tree. |
| `server.py` | `LoopbackWorkspaceServer` — the locked, read-only, loopback-only workspace server. |
| `cdp_client.py` | A minimal, dependency-free WebSocket + CDP JSON-RPC client (stdlib only: `socket`, `struct`, `threading`). |
| `chromium_provider.py` | `ChromiumCdpRuntimeProvider` — the real installed-browser provider. |
| `runner.py` | Executes a validated plan against a provider and aggregates `BrowserRuntimeEvidence` + per-criterion results. |
| `plan_builder.py` | Mission Contract → `BrowserRuntimeVerificationPlan`, generically, from pattern-matched contract text. |
| `ledger_integration.py` | Writes plan/evidence results back onto the *same* Mission Contract acceptance ledger `evaluate_completion_eligibility()` already gates on. |
| `state_machine.py` | Runtime-verification state names, transition rules, and the L4 auto-run safety-invariant gate. |
| `repair.py` | Bounded runtime and instrumentation repair packets. |
| `evidence_store.py` | Writes evidence JSON + bounded screenshots under `.admissible/runtime-evidence/<id>/`, with sha256 + byte length recorded for each file. |
| `terminal_ui.py` | Banner selection and coverage/safety-status summaries. |
| `diagnostics.py` | `python -m admissible.browser_runtime.diagnostics` — reports browser capability without launching a target app. |

## Provider abstraction

```python
class BrowserRuntimeProvider(abc.ABC):
    def detect_capability(self) -> BrowserRuntimeCapabilityReport: ...
    def create_session(self, plan) -> RuntimeSession: ...
    def execute_step(self, session, step) -> dict: ...
    def collect_evidence(self, session) -> dict: ...
    def close_session(self, session) -> dict: ...
```

`BaseBrowserRuntimeProvider` implements `execute_step` once, generically,
against small primitives (`_do_navigate`, `_do_query_selector`,
`_do_click`, `_do_key_event`, `_do_pointer_event`, `_do_debug_snapshot`,
`_do_screenshot`, ...). `FixtureBrowserRuntimeProvider` and
`ChromiumCdpRuntimeProvider` each implement only those primitives; every
step-interpretation and assertion rule lives in exactly one place.

## Declarative DSL — no arbitrary JavaScript

Every step is a plain-data dict with an allowlisted `type`:

`navigate_local`, `wait_for_load`, `wait_bounded`,
`assert_selector_present`, `assert_selector_visible`,
`assert_selector_count`, `assert_text_contains`, `read_dom_attribute`,
`debug_snapshot`, `assert_json_path_present`, `assert_json_path_type`,
`assert_json_path_equals`, `assert_json_path_gte`, `assert_json_path_lte`,
`assert_json_path_between`, `compare_snapshot_path_changed`,
`compare_snapshot_path_unchanged`, `compare_snapshot_path_increased`,
`compare_snapshot_path_decreased`, `key_press`, `key_down`, `key_up`,
`pointer_move`, `pointer_down`, `pointer_up`, `click_selector`,
`capture_screenshot`, `assert_console_clean`, `assert_no_page_exceptions`,
`assert_no_external_requests`, `assert_no_downloads`,
`assert_no_unexpected_dialogs`.

Unknown step types are rejected outright. There is no `evaluate`,
`execute_script`, or equivalent step. Selectors and JSON paths are
treated as opaque, length-bounded strings and are never concatenated into
a JavaScript expression a caller controls — the provider builds one fixed
query template internally and passes the selector in as a JSON-encoded
string literal.

Debug snapshots are the one place a JS expression is evaluated, and it is
always synthesized by the verifier itself from a regex-validated
`window.__NAME__` path (`NAME` = a bounded identifier):

```python
build_snapshot_expression("window.__NEON__")
# "(() => { const iface = window.__NEON__; if (!iface || typeof iface.snapshot !== 'function') "
# "{ return { __admissible_error: 'missing_snapshot_method' }; } const result = iface.snapshot(); "
# "return result === undefined ? null : result; })()"
```

No method name, argument, operator, or property path beyond the validated
interface is ever accepted. Snapshot results are validated as JSON
(rejecting functions, cycles, `NaN`/`Infinity`, excessive depth, and
oversized payloads) before they can be compared against.

### Hard limits

| Limit | Default | Absolute ceiling |
|---|---|---|
| Total duration | 30 s | 60 s |
| Steps | 48 | 96 |
| Input events | — | 100 |
| Snapshots | — | 32 |
| Screenshots | — | 8 |
| Wait per step | — | 5 s |
| Debug snapshot size | — | 256 KiB |

## Locked local loopback server

`LoopbackWorkspaceServer` binds only to `127.0.0.1` on an OS-assigned
port, serves `GET`/`HEAD` only, requires an unguessable per-session route
token, and refuses to leave the authorized workspace root: absolute
paths, `..` segments (encoded or not), backslash separators, `.git`/
`.admissible`/hidden state, and symlink/junction escapes are all rejected.
It sends a restrictive CSP (`default-src 'self' data: blob:`,
`connect-src 'self'`, `object-src 'none'`, `frame-src 'none'`,
`base-uri 'none'`, `form-action 'none'`) plus `X-Content-Type-Options`,
`Referrer-Policy`, and cache-control headers. It is threaded
(`http.server.ThreadingHTTPServer`) because a browser opens several
concurrent HTTP/1.1 keep-alive connections per origin; an earlier
single-threaded version intermittently stalled loading a page's second or
third resource behind the first connection's keep-alive wait — a real bug
this slice fixed and now regression-tests directly.

## Network containment

Before the target page loads, the Chromium provider enables the CDP
`Fetch` domain with a catch-all pattern. Every paused request is checked
against exactly the verifier's own loopback origin (plus `data:`/`blob:`
URLs); everything else is failed with `BlockedByClient` and recorded as
both a `network_events` entry and a `policy_violations` entry with a
redacted URL. Popups (`Target.attachedToTarget`) are closed immediately;
downloads are denied via `Page.setDownloadBehavior`; JavaScript dialogs
are auto-dismissed via `Page.handleJavaScriptDialog`. Any of these events
is a runtime policy violation that taints the whole session's results —
even criteria the aggregator would otherwise call `verified_pass` are
withheld from completion (see `ledger_integration.py`).

Browser flags (`--disable-background-networking`, etc.) are
defense-in-depth only; the CDP interception layer is the authoritative
containment mechanism. **Known limitation:** interception is enforced per
attached target; a page that manages to spawn a target our auto-attach
does not observe before it makes a request would not be contained by this
layer alone. No such gap was observed in testing, but it is called out
here rather than implied to be impossible.

## CDP client — dependency-free

`cdp_client.py` implements a small RFC 6455 WebSocket client and a
synchronous JSON-RPC layer over it, using only the standard library.
Event handlers (e.g. `Fetch.requestPaused`) commonly need to issue their
own CDP command and block on the response; running them on the same
thread that reads incoming frames would deadlock (the thread would be
waiting on a response only it can deliver). Handlers are therefore
dispatched onto a small worker pool, keeping the reader thread always free
to receive responses.

## Browser discovery and launch

`ADMISSIBLE_BROWSER_EXECUTABLE` is accepted only when absolute, existing,
and its basename is in a fixed allowlist (`chrome(.exe)`, `msedge(.exe)`,
`chromium(.exe)`, `chromium-browser`, plus the real macOS/Linux package
names). No additional arguments are ever taken from the environment.
Otherwise, known install locations for Chrome/Edge/Chromium are checked
on Windows, macOS, and Linux.

The browser is launched with `shell=False` and a fixed, verifier-owned
argument list: a fresh isolated temporary profile, `--remote-debugging-port=0`
bound to loopback (the assigned port is read from the profile's
`DevToolsActivePort` file), no extensions, no first-run UI, disabled
background networking/sync/update/translation, headless by default.
**Never** `--no-sandbox`. **Never** `--disable-web-security`. A
defense-in-depth check (`_assert_arguments_are_safe`) refuses to launch if
either ever appeared.

Cleanup: Windows uses a Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` so closing the job handle terminates
the whole process tree (including any renderer/utility children); POSIX
launches into a new session and terminates the whole process group.
Verified directly against a real, already-installed Chrome and Edge on
this machine: zero orphaned processes after repeated runs.

## Mission Contract → runtime plan

`extract_runtime_observability_intent()` (in `admissible.mission_contract`)
deterministically parses structurally-recognizable phrases out of the
raw goal and requirement/criterion text — never a specific game or field
name:

- `window.__NAME__` debug interface mentions;
- `snapshot returning at least: ...` field lists;
- `enabled with ?debug=1` query flags;
- `at least/at most/exactly N ...` numeric thresholds;
- `press X to Y` / `pause and resume with X` named controls;
- `must not create duplicate animation loops` /
  `remain playable after repeated restart cycles` temporal requirements;
- `no uncaught errors` stability requirements;
- `#id` / `.class` DOM tokens.

`plan_builder.build_runtime_verification_plan(contract, ledger, ...)` then
classifies every mandatory ledger criterion:

- criteria already `deterministic_structural` / `human_observation_required`
  / `ambiguous_requirement` pass through unchanged;
- criteria marked `unsupported_verifier` (RUN_042's "needs dynamic
  behavior, can't check statically" marker), plus `evidence_required`
  criteria matching a high-confidence runtime hint, are attempted;
- a successful match becomes `deterministic_runtime` with real generated
  steps (a numeric threshold becomes an `assert_json_path_gte/lte/equals`
  against a mapped snapshot field; a `press R to restart` +
  "no duplicate loops" pair becomes a bounded 3x restart/snapshot sequence
  asserting the loop counter stays bounded; a debug-interface mention
  becomes a snapshot + field-presence assertion);
- anything that cannot be safely mapped stays `unsupported_verifier`,
  **represented**, with an honest `unsupported_reason` — never dropped,
  never silently passed.

`RuntimeObservabilityCoverageReport` (`plan_builder.runtime_observability_coverage_report`)
summarizes: how many mandatory criteria are runtime-relevant, how many are
observable/executable, which are partially observable, which remain
unobservable, missing debug fields/DOM observables/control mappings, and
which are pending human observation.

## Verification dispositions

`admissible.mission_contract.VERIFICATION_DISPOSITIONS` now covers:

`deterministic_static`, `deterministic_structural`, `deterministic_runtime`,
`human_observation_required`, `evidence_required`, `unsupported_verifier`,
`ambiguous_requirement`.

## Completion eligibility — reuse, not a new gate

`ledger_integration.apply_runtime_evidence_to_ledger()` writes a runtime
run's plan/evidence back onto the *same* acceptance-ledger entries
`evaluate_completion_eligibility()` already reads — it does not change
that function's signature or logic at all:

- `verified_pass` only when the runtime aggregator itself reported
  `verified_pass` for that criterion (a static proxy can never terminally
  satisfy a `deterministic_runtime` criterion);
- a `runtime_observability_gap` / capability-gap / error / not-executed
  result forces `verification_disposition = "unsupported_verifier"`,
  which the existing evaluator already treats as a capability gap;
- `awaiting_human_observation` sets `human_observation_required`;
- any policy violation in the run withholds a pass from every criterion
  that run touched, even ones that would otherwise read `verified_pass`.

Browser unavailability short-circuits before any session, server, or
process is created and always reports `verification_capability_gap` —
never a false pass (`runner.build_capability_gap_evidence`).

## State machine (PART I)

`state_machine.py` adds, additively, the RUN_043 state vocabulary:
`runtime_verification_pending`, `preparing_runtime_plan`,
`runtime_capability_check`, `runtime_verifying`,
`runtime_verification_pass`, `runtime_verification_fail`,
`runtime_observability_gap`, `awaiting_human_observation`,
`runtime_verification_capability_gap`, and reuses the existing
`repair_needed` phase so a runtime repair composes with the pre-existing
repair loop instead of inventing a parallel one.
`next_runtime_state()` implements the PART I.46 transitions and never
returns `internal_livelock`, `human_authority_blocker`, or `completed`
for a runtime failure or gap. `evaluate_l4_auto_run_safety_invariants()`
is the final, defense-in-depth gate for whether L4 high-autonomy mode may
auto-run verification without a human decision.
`admission_class_for_runtime_action()` returns a dedicated
`browser_runtime_verification` admission class — a runtime action is
never represented as a shell action.

This module is intentionally standalone rather than woven into the
2,900-line `high_autonomy_controller.py` state machine in this slice: the
integration surface that matters for correctness —
`evaluate_completion_eligibility()` — is already wired through
`ledger_integration.py`. Deeper controller wiring (auto-triggering a
runtime plan at a specific tick) is a natural next slice.

## Repair packets (PART J)

`repair.build_runtime_repair_packet()` and
`repair.build_instrumentation_repair_packet()` mirror
`governed_run.build_repair_packet()`'s shape: only failed/gap criterion
IDs, exact assertion diagnostics, observed values, console/page
exceptions, blocked external attempts, missing observables, unchanged
passing criteria, repair boundaries, and remaining budget — never a full
transcript replay. An instrumentation repair packet may request only
read-only additions (snapshot fields, DOM status markers, loop counters,
entity counts, lifecycle state); it explicitly forbids state mutation,
cheat controls, filesystem/network access, rule bypasses, and hidden
success flags.

## Evidence storage (PART K)

`evidence_store.write_runtime_evidence()` writes
`.admissible/runtime-evidence/<evidence_id>/evidence.json` (plus
`screenshots/<screenshot_id>.png` for any captured screenshots) and a
`manifest.json` recording each file's sha256 and byte length.
`evidence_id` is validated against a safe-identifier pattern and the
resolved path is checked against the evidence root before any write, so
collisions and traversal are structurally prevented. Browser profile data
is never persisted as evidence; temporary profiles are removed at session
close.

## Terminal UX (PART L)

Six mutually exclusive banners: `RUNTIME VERIFICATION IN PROGRESS`,
`RUNTIME VERIFICATION FAILED`, `RUNTIME OBSERVABILITY GAP`,
`BROWSER VERIFICATION UNAVAILABLE`, `AWAITING HUMAN OBSERVATION`,
`RUN COMPLETED`. `RUN COMPLETED` renders only when the caller also
confirms overall completion eligibility — a runtime pass with an
unrelated pending gap elsewhere never shows green.
`build_contract_and_verification_summary()` shows contract coverage
(criteria/paths represented) and verification outcome (static passed /
runtime passed / runtime unverified / human-observation pending)
separately. `build_runtime_safety_status()` reports provider, external
network attempts, console errors, page exceptions, duration, input event
count, snapshots, screenshots, and cleanup result.

## Fixtures (PART M)

`tests/fixtures/admissible/browser_runtime/` has six general, non-game
apps: `counter` (click/DOM/snapshot/reset), `form` (typing/validation/no
network), `animation_loop` (bounded restart with a duplicate-loop guard),
`canvas_sim` (entity count/movement/`?debug=1` overlay), `policy_violation`
(a deliberate blocked fetch/popup/download), and `unobservable` (a real
dynamic requirement with no declared observable, proving the verifier
reports a gap rather than inventing a pass).

## Installed-browser requirements and honest capability gaps

`python -m admissible.browser_runtime.diagnostics` reports browser
discovery/version without launching a target application. The full unit
suite never depends on an installed browser — every test in
`tests/test_admissible_*` (except the one opt-in module below) uses
`FixtureBrowserRuntimeProvider`. `tests/test_admissible_browser_runtime_live_smoke.py`
is marked `browser_runtime` and skips honestly (with a clear reason) when
no allowlisted browser is detected; it was run against real, already
installed Chrome and Edge on this development machine and passed,
including the policy-violation containment scenario, with verified
zero-orphan-process cleanup.

## RUN_044: wiring into the high-autonomy governed run

RUN_043 (everything above) is a standalone, sealed verifier: it never runs
itself, never decides *when* it should run, and never touches
`admissible.high_autonomy_controller`. RUN_044 adds exactly one thing on
top: **orchestration** — deciding when runtime verification is required,
starting/polling/applying it as a bounded background step of the governed
run, and closing the loop back into completion eligibility. See
[admissible-high-autonomy-governed-loop.md](admissible-high-autonomy-governed-loop.md)
for the full description; this section only records the boundary and why
it is drawn where it is.

**Orchestration boundary.** Two new top-level modules own this, both
*outside* `admissible/browser_runtime/`:

- `admissible/runtime_orchestration_models.py` — the durable
  `RuntimeVerificationAttempt` schema, the `RuntimeOrchestrationTransition`
  object the orchestrator hands back to the controller, and
  `HumanObservationRecord`.
- `admissible/runtime_verification_orchestrator.py` — `assess_runtime_need`,
  `prepare_runtime_attempt`, `start_runtime_attempt`, `poll_runtime_attempt`,
  `apply_runtime_evidence`, `cancel_runtime_attempt`,
  `reconcile_runtime_state_on_load`, `record_human_observation`, plus the
  single-flight background-worker registry.

Browser discovery, CDP operations, HTTP serving, DSL interpretation,
evidence collection, and provider cleanup all stay inside
`admissible/browser_runtime/`, completely unmodified in shape by RUN_044
(two integration-defect fixes below aside). `high_autonomy_controller.py`
never imports `chromium_provider`, `cdp_client`, `server`, or `dsl`; it only
calls the five orchestrator functions above and persists whatever
`RuntimeOrchestrationTransition`/`RuntimeVerificationAttempt` it gets back.
This is deliberate: a runtime check is not a model turn, and the controller
that already owns the (very large) model-turn state machine must not also
own browser-provider lifecycle — that would make one file responsible for
two unrelated bounded-execution domains.

**Two integration-defect fixes surfaced by actually wiring this up**
(RUN_043's own tests never exercised these paths, since they always call
`execute_runtime_verification_plan` once against a freshly-built ledger and
read the in-memory `evidence` object directly):

1. `_aggregate_criterion_results` (`runner.py`) used to report
   `runtime_observability_gap` for *every* criterion in the plan that had
   no matched assertion — including criteria plan_builder deliberately left
   untouched (still `deterministic_structural`/`evidence_required`, no
   runtime steps ever generated for them). One browser session could
   therefore silently overwrite an unrelated static criterion's status.
   Fixed by only aggregating criteria whose disposition is
   `deterministic_runtime`/`unsupported_verifier`, or which are
   `human_observation_required`.
2. `BrowserRuntimeEvidence.from_dict()` never listed `policy_violations` in
   its bounded-field reconstruction, even though `to_dict()` always
   serialized it — evidence read back from disk (which the orchestrator's
   persistence/recovery and exactly-once-apply paths always do) silently
   lost every recorded policy violation. Fixed by adding it to
   `_BOUNDED_FIELDS` in `models.py`.
3. `plan_builder._classify` never re-attempted a criterion whose
   `verification_disposition` was already `deterministic_runtime` (it only
   re-attempts `unsupported_verifier`/matching `evidence_required` text),
   so rebuilding the plan for a retry or repair rerun against an
   already-touched ledger produced zero steps for that criterion. Fixed by
   adding `deterministic_runtime` to the re-attempt set.

**Single-flight and the async tick lifecycle.** One in-process background
worker per session at most (`_WORKERS: dict[session_id, _RuntimeWorker]` in
the orchestrator module — process-global, not tied to any one
`ControlSurfaceController` instance, so it survives controller
reconstruction within the same process). `HighAutonomyRunState` persists
`active_runtime_attempt`/`active_runtime_plan` (full snapshots, not just an
id) so a fresh tick — or a fresh controller loaded from the same session
file — can resume polling without holding anything only in memory:

- **Tick A** (`HA_NEXT_START_RUNTIME_VERIFICATION`): validate the plan
  (PART D.12: contract sha, authorized workspace, exact entrypoint, DSL
  validation, ceilings, known criterion ids), persist the attempt,
  capability-check (synchronous — a negative result never launches a
  browser and returns immediately), then start the worker thread and
  return. Never blocks on the browser run.
- **Later ticks** (`HA_NEXT_POLL_RUNTIME_VERIFICATION`): non-blocking check
  on the owned worker; `runtime_verifying` stays displayed until the worker
  finishes. No later tick may start a second attempt while one is active —
  enforced both by the controller's existing `_high_autonomy_tick_lock`
  (single-flight per session across HTTP requests) and, independently, by
  the orchestrator's own worker-registry check (so it stays correct even if
  two independent `ControlSurfaceController` objects act on the same
  session).
- **Completion tick** (`HA_NEXT_APPLY_RUNTIME_EVIDENCE`): persist evidence
  via `evidence_store.write_runtime_evidence`, apply it to the ledger
  exactly once (guarded by `attempt.status == evidence_applied`; a repeated
  apply is a stable no-op that touches neither the ledger nor any metric),
  then let the existing `_try_finalize_outcome` re-evaluate completion in
  the same tick.

**Persistence and recovery.** On session load, if a persisted attempt is
`queued`/`running` but no owned worker exists for that session, and no
matching evidence file exists on disk yet, it is marked `interrupted` —
never assumed to have passed — with `cleanup_status:
"unknown_process_state_not_tracked"` (there is no durable PID to
re-attach to and re-verify; RUN_043's evidence schema does not carry one).
If matching evidence *does* already exist on disk (the process crashed
after writing it but before applying it), it is recovered and applied
without relaunching the browser. An interrupted attempt is never
auto-resumed; `retry_runtime_verification_attempt()` starts a fresh attempt
with `retry_of_attempt_id` pointing at the interrupted one, plus the same
plan sha and criterion ids, and the interrupted attempt is archived into
`runtime_attempt_history` before the new one starts.

**Runtime repair.** A `runtime_verification_fail` result builds a packet via
`browser_runtime.repair.build_runtime_repair_packet` (assertion diagnostics,
console/page exceptions, blocked requests); a `runtime_observability_gap`
result builds a packet via `build_instrumentation_repair_packet`, but only
when at least one gap criterion's `unsupported_reason` is one plan_builder
assigns for a *missing declared mapping* (a field/control the contract's
own debug interface could plausibly add) — never for a criterion
plan_builder found no derivable observable for at all (e.g. "collision
causes death"), where more instrumentation would not help and would only
burn a repair round. Either packet reuses the exact same
`REPAIR_PHASE_*`/`repair_round_count`/`max_repair_rounds` bookkeeping the
pre-existing static-verification repair loop already uses; the controller
only picks which text-builder renders the instruction
(`build_runtime_repair_instruction_text` vs. `build_repair_instruction_text`)
based on the packet's `kind`.

**Human observation vs. human authority.** A pending
`human_observation_required` criterion sets `mode =
awaiting_human_observation` — never `human_critical_pending`, never
`HA_MODE_HUMAN_REQUIRED`. It is excluded from `_AUTO_TICK_SAFE_MODES` (a
human must act) but is also excluded from the no-progress-tick counter (it
is a stable wait state, not a livelock).
`ControlSurfaceController.record_human_observation(criterion_id, actor=,
disposition=, note=, evidence_refs=)` accepts `pass`/`fail`/`waive`
(waiving requires a non-empty rationale) and is tracked via
`human_observation_records` and `human_observation_count`/
`_pass_count`/`_fail_count`/`_waiver_count` — never through
`genuine_human_intervention_count` or any other human-authority metric.

**Completion eligibility, capability gaps, observability gaps.**
`evaluate_completion_eligibility()` remains the sole authority for
`completed`; the orchestrator only ever applies evidence and lets the
existing check re-run. Browser unavailability finalizes immediately as
`verification_capability_gap` (no model turn can fix a missing browser, so
there is no reason to wait out the turn budget first). A permanent
observability gap (no instrumentation-fixable criterion, or repair rounds
exhausted) finalizes as `runtime_observability_gap`. Neither is ever
`internal_livelock`, `human_authority_blocker`, or `completed`.

**Cancellation and cleanup.** `cancel_runtime_verification_attempt()` signals
the worker's cooperative cancellation event (checked between DSL steps —
`execute_runtime_verification_plan`'s optional `cancel_event` parameter),
waits briefly for it to unwind, and records `cleanup_status` from the
resulting evidence's `resource_cleanup`. Cleanup failure
(`browser_process_terminated`/`http_server_stopped` false) is recorded on
the attempt and counted in `runtime_cleanup_failure_count`, never hidden.

**Neon fixture expected result (before any human observation).** Running
the RUN_042 Neon Mission Contract through the full controller with
`FixtureBrowserRuntimeProvider` and every declared debug field present:
15/15 criteria and 8/8 exact paths stay represented; exactly one runtime
attempt is created and applied; the 4 objectively-checkable criteria (bot
count, restart/no-duplicate-loop, debug interface, debug overlay) become
`verified_pass`; the 2 subjective criteria (camera smoothness, readable
background) become `human_observation_pending`; the 3 criteria with no
derivable observable at all (collision/respawn, live leaderboard, repeated
restarts) remain `unsupported_verifier` — explicit, visible gaps, never
silently dropped or auto-passed; the run never reaches `completed` on its
own (both the pending human observations and the two remaining static-only
criteria block it honestly); and zero agent instructions are written for
any of this. See `tests/test_admissible_neon_runtime_end_to_end.py`.

## Known limitations

- Windows Chrome's `--version` flag is swallowed by single-instance
  forwarding when another instance is already running; version detection
  falls back to reading the PE file-version resource directly (read-only,
  no execution) on Windows.
- Rapid, back-to-back real-browser launches (as in a tight test loop) can
  occasionally run slower under disk/AV scanning contention; the DSL's
  per-step wait ceiling (5 s) is a hard limit and is not raised to
  compensate — a plan can include an additional bounded `wait_bounded`
  step for extra margin instead.
- CDP request interception is the authoritative containment layer;
  browser command-line flags are defense-in-depth only.
- Fragmented (multi-frame) WebSocket messages are handled minimally in
  `cdp_client.py`; Chrome's DevTools server has not been observed to
  fragment outgoing text frames in practice.

## Tests

- `tests/test_admissible_browser_runtime_models.py`
- `tests/test_admissible_browser_runtime_capability.py`
- `tests/test_admissible_loopback_workspace_server.py`
- `tests/test_admissible_browser_network_containment.py`
- `tests/test_admissible_browser_runtime_dsl.py`
- `tests/test_admissible_runtime_observability_contract.py`
- `tests/test_admissible_runtime_plan_builder.py`
- `tests/test_admissible_runtime_evidence.py`
- `tests/test_admissible_runtime_state_machine.py`
- `tests/test_admissible_runtime_repair_flow.py`
- `tests/test_admissible_runtime_completion_eligibility.py`
- `tests/test_admissible_runtime_terminal_ui.py`
- `tests/test_admissible_neon_runtime_regression.py`
- `tests/test_admissible_browser_runtime_live_smoke.py` (opt-in, `-m browser_runtime`)

RUN_044 orchestration tests (see
[admissible-high-autonomy-governed-loop.md](admissible-high-autonomy-governed-loop.md)
for the full list): `tests/test_admissible_runtime_orchestrator.py`,
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

## Related docs

- `docs/admissible-mission-contract.md`
- `docs/admissible-bounded-verification.md`
- `docs/admissible-high-autonomy-governed-loop.md`
- `docs/admissible-model-agnostic-agent-transport.md`
- `docs/admissible-live-high-autonomy-rehearsal.md`
