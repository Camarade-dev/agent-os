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

## Related docs

- `docs/admissible-mission-contract.md`
- `docs/admissible-bounded-verification.md`
- `docs/admissible-high-autonomy-governed-loop.md`
- `docs/admissible-model-agnostic-agent-transport.md`
- `docs/admissible-live-high-autonomy-rehearsal.md`
