# Admissible Cursor Callable-Backend Transport Forensic Audit

`ADMISSIBLE_RUN_046_CALLABLE_BACKEND_TRANSPORT_FORENSICS_AND_PROTOCOL_DECISION`

**Status: forensic audit only. No production transport code was changed. Not
committed.** This report separates facts (directly observed) from hypotheses
(plausible but unconfirmed) throughout. Where a section states a conclusion,
it names the evidence it rests on.

---

## 0. Executive summary

- The real Cursor CLI transport **worked correctly in all 6 of 6 real
  invocations** run under this audit's controlled minimal-prompt conditions —
  direct-CLI and production-adapter paths produced byte-identical responses
  in every pair. This does **not** prove the transport is reliable in
  general (see §7); it only proves these two code paths behave identically
  when the CLI succeeds.
- The canonical Repair Probe evidence's `empty_success` (1-byte stdout, exit
  0) and 120-second timeout were **not reproduced** in this sample. They
  remain unexplained by CLI/service unavailability — no evidence in this
  audit points at Cursor's remote service being at fault (§7).
- **New confirmed defect, found by this audit, not in the original
  narrative:** on a `subprocess.TimeoutExpired`, Admissible's production
  `CursorCliAgentBackend.invoke()` (via `subprocess.run(timeout=...)`) only
  terminates the *direct* child process. On Windows, `cursor-agent` resolves
  through a `.CMD` → `powershell.exe` → `node.exe` chain; killing only the
  direct child **leaves `powershell.exe` and `node.exe` — the process
  actually holding the model connection — running, orphaned**, after every
  timeout. Empirically verified twice in this audit (§5.2). This is a
  process-lifecycle defect in the adapter, not a Cursor service defect.
- `cursor-agent` ships a real, working, undocumented **ACP (Agent Client
  Protocol) server** (`cursor-agent acp`, hidden from `--help`). A
  handshake-only, non-model probe completed in ~1.1 seconds and returned a
  well-formed `initialize` response with real capabilities (§6). This is
  ~13–16x faster than a one-shot CLI cold start observed in this audit, and
  offers explicit cancellation and progress-event primitives text mode does
  not have.
- Three **non-transport** defects were found and fully root-caused by static
  code reading, independent of live probing (§9): an acceptance-heading
  parser that silently drops "MANDATORY ACCEPTANCE CRITERIA"-style headings,
  the resulting silent substitution of an unrelated generic criteria
  template (explaining the `game_controls`/`local_usage` failures), and a
  frontend key-name typo that makes the Run Identity panel's Backend field
  always show "—" regardless of the active backend.

---

## 1. PART A — Environment and executable identity

### 1.1 Host environment

| Field | Value |
|---|---|
| OS | Windows 11 Home 10.0.26200 (`Windows-11-10.0.26200-SP0`) |
| Architecture | AMD64 |
| Python | 3.12.0 (`MSC v.1935 64 bit (AMD64)`) |
| Admissible commit SHA | `49d02fe9618f9ed8f60121e16dbe09fe59d8ca73` |
| Working tree state at audit start | clean |
| Working tree state at audit end | clean except new, untracked audit artifacts (this report, the diagnostics module, two new test files, one new fixture, the probe-results JSON) — **no production file was modified** |

### 1.2 Cursor Agent CLI identity

| Field | Value |
|---|---|
| `cursor-agent --version` | `2026.07.09-a3815c0` |
| Resolved executable (`shutil.which`) | `C:\Users\stris\AppData\Local\cursor-agent\cursor-agent.CMD` |
| Wrapper type | Windows `.CMD` batch file |
| Wrapper chain | `cursor-agent.CMD` → `powershell.exe -NoProfile -ExecutionPolicy Bypass -File cursor-agent.ps1 %*` → resolves latest `versions\<date>-<hash>\node.exe` → runs `versions\<date>-<hash>\index.js` with forwarded `$args`, `exit $LASTEXITCODE` |
| Resolved node runtime | `versions\2026.07.09-a3815c0\node.exe`, Node **v24.5.0** |
| Installed versions present | `2026.06.15-18-00-12-6f5a2cf` (older), `2026.07.09-a3815c0` (current, auto-selected as latest) |
| `NODE_COMPILE_CACHE` | Set by the wrapper to `%LOCALAPPDATA%\cursor-compile-cache` if unset (startup-speed cache only, not correctness-relevant) |

**Exit-code propagation** (confirmed empirically, §1.4): the `.CMD` → PowerShell
`-File` → `node.exe` chain correctly propagates the real exit code back to
the calling process via `exit $LASTEXITCODE` at each hop. `subprocess.run([...,
"cursor-agent.CMD", ...], shell=False)` on Windows correctly executes the
`.CMD` and receives the true final exit code — Windows' `CreateProcess`
handles the `.CMD`→`cmd.exe` association at the OS level; no `shell=True` is
required. This matches the production adapter's own invocation pattern.

### 1.3 Admissible-side configuration (as of this commit)

| Field | Value | Source |
|---|---|---|
| Command | `cursor-agent` (resolved via `PATH`/`PATHEXT`) | `CURSOR_AGENT_CLI_COMMAND` |
| Safe argv template | `--print --output-format text --mode plan --workspace {agent_workspace} --trust {prompt}` | `CURSOR_AGENT_CLI_SAFE_ARGS` |
| Input mode | `file_pointer_always` (a short adapter prompt pointing at the instruction file; forced for `cursor-agent`, cannot be downgraded by config) | `CursorCliConfig.from_env` |
| Output mode | `stdout` only | `OUTPUT_MODE_STDOUT` |
| Model label | `cursor-agent-default` — **no `--model` flag is configured**; `assess_cursor_cli_safety` already warns "No `--model` configured; Cursor Agent will use its default model" | `CURSOR_AGENT_CLI_MODEL_LABEL` |
| Timeout | **120.0 seconds**, not overridden anywhere in `high_autonomy_controller.py` | `DEFAULT_TIMEOUT_SECONDS` |
| Max output bytes | 512 KiB | `DEFAULT_MAX_OUTPUT_BYTES` |
| Encoding | `text=True, encoding="utf-8", errors="replace"` | `CursorCliAgentBackend.invoke` |
| Environment | Allowlisted OS/profile vars only (`PATH`, `APPDATA`, `TEMP`, etc.); no provider keys, no unrelated app vars forwarded | `build_cursor_agent_safe_environment` |

This matches the canonical evidence's 120-second repair-turn timeout exactly
— confirms the configured timeout, not an ad hoc value, is what fired.

### 1.4 Non-model discovery (`--help`, no model call)

`cursor-agent --help` documents:

- `-p, --print` (script/non-interactive mode; **the CLI's own help text
  warns this "has access to all tools, including write and shell" by
  default** — Admissible's `--mode plan` requirement in
  `assess_cursor_cli_safety` is the load-bearing control that keeps this
  read-only, not `--print` itself).
- `--output-format <format>`: **`text | json | stream-json`** (only Admissible
  uses `text` today).
- `--stream-partial-output`: **streams partial output as individual text
  deltas, but only works with `--print` and `stream-json` format** — direct,
  documented evidence that incremental output exists as a CLI capability and
  is simply not used by the current adapter (§6).
- `--mode plan | ask` (read-only planning/Q&A; Admissible enforces `plan`).
- `--sandbox enabled|disabled`, `--force`/`--yolo` (Admissible's
  `assess_cursor_cli_safety` already blocks the dangerous ones).
- `mcp`, `worker`, `about`, `status|whoami`, `models` subcommands. `worker`
  starts a *private cloud worker that connects outward to Cursor's own
  infrastructure* — this is not a local server Admissible could drive as an
  ACP-style client; it is the opposite direction (Cursor's cloud driving a
  local sandbox).
- **No `acp` command is listed.** It exists but is registered `hidden: true`
  (§6) — this is undocumented-but-real, not fabricated; found by reading the
  installed CLI's own bundled source, then confirmed live.

No flags were assumed from memory; every flag cited above is quoted from the
installed CLI's own `--help`/`--about`-equivalent output or its bundled
source.

---

## 2. PART B — Canonical Repair Probe session: forensic reconstruction

The task brief's "canonical live evidence" is a narrative, not a raw exported
session file (unlike RUN_045's `control_session_89d4376c8c43` export). It has
been minimized into
[`tests/fixtures/admissible/repair_probe_callable_transport_forensic_regression.json`](../../tests/fixtures/admissible/repair_probe_callable_transport_forensic_regression.json),
following the same fixture shape RUN_045 used, and is exercised by
[`tests/test_admissible_callable_transport_forensic_regression.py`](../../tests/test_admissible_callable_transport_forensic_regression.py).
Every field is tagged `data_confidence: reported` (stated explicitly in the
brief) or `unspecified_in_narrative` (not stated; left `null`, never
invented).

### 2.1 Per-invocation reconstruction

| # | Phase | Attempt | Retry of | Exit code | Duration | stdout bytes | Classification | Confidence |
|---|---|---|---|---|---|---|---|---|
| 1 | initial_implementation | 1 | — | 0 | ≈32s | 1 | `empty_success` | reported |
| 2 | initial_implementation | 2 | #1 | unspecified | unspecified | unspecified | `success` | outcome only |
| 3 | repair_turn | 1 | — | unspecified | unspecified | unspecified | unspecified | unspecified |
| 4 | repair_turn | 2 | #3 | unspecified | unspecified | unspecified | unspecified | unspecified |
| 5 | repair_turn | 3 | #4 | unspecified | unspecified | unspecified | unspecified | unspecified |
| 6 | repair_turn | 4 | #5 | unspecified | **120.0s (configured timeout)** | unspecified | `timeout` | reported |

Session totals (reported): **6 total invocations, 4 retries** — consistent
with 1 retry on the initial-implementation turn (#2 retries #1) + 3 retries
on the repair turn (#4/#5/#6 retry #3/#4/#5).

**What the narrative does not tell us, and this audit could not recover**
(no raw log/export exists to inspect): the exit codes, durations, and
stdout/stderr byte counts of repair attempts 1–3, and — critically — whether
attempt 6 (the 120s timeout) had *any* partial stdout before it was killed.
Facts vs. hypotheses on that last point specifically:

- **Fact:** the production `CursorCliAgentBackend.invoke()` only ever
  distinguishes `AGENT_INVOKE_TIMEOUT` as one status; it does not currently
  capture or report partial stdout on `subprocess.TimeoutExpired` (`raw_stdout`
  is never populated in that branch — see `agent_backend.py` lines
  ~1700–1712). So even if partial output existed, today's adapter could not
  have told the operator.
- **Hypothesis, now closed by this audit's own harness:** this exact gap
  (`timeout_before_any_output` vs. `timeout_after_partial_output`) is
  precisely what PART C's incremental-capture harness was built to resolve
  for *future* occurrences (§4). It cannot retroactively recover data that
  was never captured for this specific historical session.

### 2.2 Non-transport findings tied to the same session

Reported in the same narrative, reconstructed and root-caused in §9:
bounded verification failed on `game_controls` and `local_usage` (2
failures against an intended 1), and Run Identity displayed backend `—`
despite the run being governed by `cursor_cli`.

---

## 3. PART C — Diagnostic harness

New module:
[`admissible/diagnostics/callable_backend_probe.py`](../../admissible/diagnostics/callable_backend_probe.py)
(+ `admissible/diagnostics/__init__.py`). **Never imported by any production
module** (verified: `grep` for `diagnostics.callable_backend_probe` outside
the package itself returns nothing).

Capabilities, matching PART C.7–9 exactly:

- `run_direct_probe(...)` — builds the same safe argv template
  (`cursor_agent_cli_safe_args_template()` + `build_cursor_agent_file_pointer_adapter`)
  independently of `admissible.agent_backend`, for a true CLI-only check.
- `run_adapter_probe(...)` — constructs the **real, unmodified**
  `CursorCliAgentBackend` with an injected low-level `runner` matching
  `subprocess.run`'s exact call signature, so production argv/env/validation
  logic executes unchanged while the harness still observes the raw
  subprocess boundary (incremental byte timing, process tree).
- `run_acp_handshake_probe(...)` — non-model; never sends `session/prompt`;
  does not consume the invocation budget.
- Serial-only (`ProbeAlreadyRunning` guard), hard budget
  (`InvocationBudgetExceeded`, default 6, shared by direct+adapter probes),
  per-probe isolated `tempfile.mkdtemp()` workspace (never this repo, never
  an application workspace), bounded/redacted JSON report
  (`_redact_preview`, 400-char cap; environment values never captured, only
  variable names, reusing the existing `build_cursor_agent_safe_environment`
  redaction).
- Classification vocabulary implemented exactly as specified:
  `success` (internal name for "usable response"), `empty_success`,
  `timeout_before_any_output`, `timeout_after_partial_output`,
  `nonzero_exit`, `wrapper_failure`, plus `cancellation_cleanup_failure` as
  an orthogonal boolean and `process_started`/`first_stdout_byte_at`/
  `first_stderr_byte_at`/`process_exit` as explicit fields on every report.
- **`tree_kill()`**: recursive process-tree termination via `psutil` (soft
  dependency — degrades to `observed_via: "unavailable"`, never a hard
  failure, if `psutil` is not importable). Built specifically because plain
  `Popen.kill()` does not kill descendants (§5.2).

### 3.1 Tests (PART K.28)

[`tests/test_admissible_callable_backend_probe_diagnostics.py`](../../tests/test_admissible_callable_backend_probe_diagnostics.py)
— 20 tests, **zero real subprocesses**, `subprocess.Popen` patched with a
deterministic fake process object throughout. Covers: success with output,
exit-zero empty output, partial-output-then-timeout, no-output-then-timeout,
nonzero exit, delayed output, wrapper spawn failure, redaction (short/long/
`None`), process-tree kill full-termination and survivor reporting,
`psutil`-unavailable degradation, invocation-budget enforcement, no
automatic retry (`Popen` call-count assertion), serial re-entrancy guard,
ACP handshake not consuming budget, and both the direct- and adapter-probe
paths end-to-end against fakes. All 20 pass in 0.18s.

---

## 4. PART D — Six-call paired matrix (real invocations)

Executed serially, no automatic retries, exactly 6 real Cursor CLI
invocations consumed (+1 non-model ACP handshake, which does not count
against the budget). Raw results:
[`benchmark/reports/admissible_cursor_callable_transport_forensic_probe_results.json`](admissible_cursor_callable_transport_forensic_probe_results.json).

| Pair | Path | Exit | Total duration | Time to first (only) byte | stdout bytes | Classification |
|---|---|---|---|---|---|---|
| 1 — tiny | direct | 0 | 16200 ms | 15956 ms | 25 | `success` |
| 1 — tiny | adapter | 0 | 13591 ms | 13361 ms | 25 | `success` |
| 2 — medium structured | direct | 0 | 14621 ms | 14400 ms | 138 | `success` |
| 2 — medium structured | adapter | 0 | 15558 ms | 15356 ms | 138 | `success` |
| 3 — repair-shaped | direct | 0 | 16269 ms | 16053 ms | 136 | `success` |
| 3 — repair-shaped | adapter | 0 | 15718 ms | 15505 ms | 136 | `success` |

Every pair's direct and adapter response bytes were **identical in content
and length** (verified via SHA-256 in the raw JSON; both paths use the same
safe-preset argv and the same file-pointer prompt adapter, so this is
expected, not a coincidence). Mode/output-format/model were identical across
all 6 (`--print --output-format text --mode plan`, `cursor-agent-default`
i.e. auto-routed, no `--model` pin available to test against within budget —
see §7's AUTO-vs-PINNED note). Process cleanup: all 6 exited normally via
`proc.wait()`; no timeout, so `tree_kill()` was not invoked for these 6 (by
design — it only engages on timeout). A post-run process scan confirmed zero
leftover `node.exe`/`powershell.exe`/`cursor-agent.CMD` processes.

**This sample did not reproduce `empty_success` or a timeout.** See §7 for
why six successes do not establish reliability.

---

## 5. PART E — Timeout and buffering analysis

### 5.1 Buffering (PART E.11)

**Fact, directly observed in all 6 real invocations:** with
`--output-format text`, stdout is fully buffered — the harness's
incremental-capture reader threads recorded exactly **one** read event per
invocation, arriving 13.3–16.3 seconds after process start, immediately
followed by process exit (200–300 ms later). There is no progressive
output; from Admissible's perspective, a text-mode call is either "silent"
or "done," with nothing observable in between. `--print` + `text` does not
emit incremental output.

This is independently corroborated by static evidence: `--help` documents
`--stream-partial-output` as explicitly gated on `--output-format
stream-json` (§1.4) — the CLI's own documentation says incremental output
requires a different output mode, which the current adapter does not use.

### 5.2 Process/timeout termination behavior (PART E.12–14) — **new confirmed defect**

Distinguishing the four timeout-related concepts PART E.12 asks for:

- **Total execution timeout:** `request.timeout_seconds` (120s, §1.3) passed
  to `subprocess.run(timeout=...)`. This is what fired in the canonical
  repair-turn evidence.
- **Idle/no-output timeout:** **does not exist today.** The adapter has no
  concept of "no bytes for N seconds while the process is still alive" —
  only a single wall-clock deadline for the whole call. Given §5.1's finding
  that a successful call is silent for its *entire* duration until the very
  end, an idle-timeout would need a much longer idle allowance than the
  total-timeout, so it is not obviously more useful as-is (see PART E.14
  reasoning below).
- **Model/provider deadline:** unknown/unobservable from the client side —
  Cursor's backend does not expose one to the CLI in text mode.
- **Child-process termination delay:** **empirically measured and found
  broken.** This was tested twice in this audit, independent of the 6-call
  budget (neither test invoked a model):

  1. Spawned `cursor-agent acp` (a real, non-model-invoking subcommand that
     blocks on stdin) via `subprocess.Popen`, let the process tree fully
     spawn (3 seconds), then called only `Popen.kill()` on the **direct**
     child pid — exactly what `subprocess.run(timeout=...)`'s own internal
     cleanup does on `TimeoutExpired`. Result: the tree was
     `cmd.exe(29400) → powershell.exe(2556) → node.exe(25928)`; after
     killing pid 29400 only, **`powershell.exe` and `node.exe` were both
     still running** 2+ seconds later. `node.exe` is the process that
     actually holds the model/network connection.
  2. Repeated with a proper recursive kill (`psutil`: enumerate
     `parent.children(recursive=True)`, kill each, `wait_procs`) — all 3
     processes terminated cleanly within the grace period. This is exactly
     what the new harness's `tree_kill()` implements, and it was validated
     live a third time during the ACP handshake probe in §6
     (`all_terminated: true, survivor_count: 0`).

  **Conclusion:** every real `subprocess.TimeoutExpired` the production
  `CursorCliAgentBackend.invoke()` has ever hit on Windows has almost
  certainly left the actual Cursor Agent CLI process (`node.exe`) running in
  the background, orphaned — still possibly holding an open connection,
  still possibly about to write a late response, invisible to Admissible,
  and outliving the turn that Admissible has already marked `timeout` and
  moved past. This is a **confirmed adapter/process-lifecycle defect**, not
  a Cursor service defect — it happens regardless of whether the CLI itself
  is behaving correctly.
- **Cross-invocation contamination risk (hypothesis, plausible but not
  directly observed):** because the file-pointer adapter contract points at
  a fixed `next-agent-instruction.md` path in the agent workspace and reads
  from stdout only, an orphaned prior `node.exe` that eventually *does*
  finish and print to its own (already-detached) stdout pipe cannot
  overwrite a later invocation's *response* (each invocation owns its own
  pipes) — but it can still consume real API/session quota unnoticed, and
  if the repeated-timeout pattern in the canonical evidence (4 repair
  retries) each orphaned a `node.exe`, that is up to 3 concurrent orphaned
  model sessions competing for the same Cursor account's concurrency limits
  during the same rehearsal — a plausible, not confirmed, contributor to
  the repeated timeouts themselves.

### 5.3 PART E.13/14 — timeout-value recommendation

**Do not blindly raise the 120s timeout.** Per PART E.13's own criteria:
"the process is alive; useful progress is observable; completion occurs
reliably beyond 120 seconds; process cleanup remains bounded" — this audit
found **zero progress signal** exists in text mode (§5.1: fully silent,
then done), so there is no way to distinguish "about to finish" from "hung
forever" by watching the pipe. Raising the timeout under these conditions
only makes a stuck call slower to detect, while the orphan-process defect
(§5.2) means every raised timeout also means a longer-lived orphaned
`node.exe` if it does eventually time out. **The correct fix is not a bigger
timeout — it is (a) fixing process-tree cleanup so a timeout is actually
bounded and cheap, independent of its length, and (b) getting a real
progress signal (ACP `session/update`, or `stream-json` +
`--stream-partial-output`) so the timeout question becomes less load-bearing
in the first place** (§8).

---

## 6. PART F — Output-format and protocol assessment

### 6.1 Text vs. JSON vs. stream-JSON (documented, not live-tested beyond text)

`--help` documents `--output-format text | json | stream-json` and
`--stream-partial-output` (text-delta streaming, `stream-json`-only). Only
`text` was exercised live in this audit (§4) — testing `json`/`stream-json`
live would have required additional real invocations beyond the 6-call
budget, so per PART F.15's preference for non-model inspection where
possible, this is reported as a **documented-but-unverified** capability, not
a confirmed one. It is the cheapest, lowest-risk next experiment (needs its
own small budget in a follow-up slice, §11).

### 6.2 ACP — confirmed real, working, and fast (PART F.17)

Static evidence (reading the installed CLI's own bundled source, zero
execution): the CLI registers a **hidden** command —
`ge.command("acp",{hidden:!0}).description("Start the Cursor Agent as an ACP
(Agent Client Protocol) server")` — implemented in a dedicated
`./src/acp/*` module set (`acp-storage.ts` and others), using
`process.stdin`/`process.stdout` wired through a JSON-RPC connection helper
with `split("\n")` framing (newline-delimited JSON-RPC 2.0 over stdio — the
standard ACP transport, not LSP-style `Content-Length` framing). The bundled
code contains the canonical ACP method names `session/new`,
`session/prompt`, `session/cancel`, `session/update`, plus
`protocolVersion`, `agentCapabilities`, `jsonrpc`, `notification`, and
`requestId` handling.

**Live confirmation, one handshake-only probe, non-model, does not consume
the 6-call budget** (per PART F.17's explicit carve-out): spawned
`cursor-agent acp`, sent one `initialize` JSON-RPC request, read one
response line, then tore the server down.

- Server started: **yes**, in ~1.1 seconds total round-trip.
- Response: well-formed JSON-RPC 2.0, `id` matched the request, contained
  `result.protocolVersion`, `result.agentCapabilities` (`loadSession: true`,
  `mcpCapabilities: {http: true, sse: true}`, `promptCapabilities: {audio:
  false, embeddedContext: false, image: true}`, `sessionCapabilities:
  {list: {}}`), and `result.authMethods` (`cursor_login`).
- Process tree: the same `cmd.exe → powershell.exe → node.exe` chain as the
  one-shot CLI. This audit's `tree_kill()` cleanly terminated all 3
  processes (`all_terminated: true, survivor_count: 0`) after the handshake.

**Framing:** newline-delimited JSON-RPC 2.0 over stdio — request IDs and
structured `result`/`error` responses are native to the protocol, not
something Admissible would need to invent. **Progress events:**
`session/update` exists in the bundled implementation (not yet exercised
live — no `session/new`/`session/prompt` was sent, by design, to stay
non-model). **Cancellation:** `session/cancel` exists in the bundled
implementation (also not yet exercised live). **Suitability for a custom
Admissible client:** yes in principle — it is a real server process
Admissible would own the lifecycle of, with explicit start/stop instead of
a fresh one-shot spawn per turn, and it responded in ~1.1s vs. the 13–16s
per-call cold start observed for one-shot `--print` calls in §4 (this gap
is most likely one-shot process/CLI startup overhead paid on *every single
turn* in the current architecture — plausible explanation for some of the
canonical evidence's ~32-second first-turn latency, not confirmed against
that specific historical call).

### 6.3 Whether the text parser caused the canonical empty response

**No.** The canonical evidence reports raw stdout length of exactly 1 byte
with exit code 0. A 1-byte stdout is not something Admissible's parser
malformed — there is nothing for a parser to lose from 1 byte. This is a
transport-layer (CLI/process/model) empty response, full stop, consistent
with the task brief's own framing ("Raw zero/one-byte stdout is a transport
failure, not a parser failure"). This audit's 6 real calls all returned
well-formed, correctly-sized stdout that the existing parser handled
correctly in both direct and adapter form — no parser defect was found or
suspected anywhere in this audit.

---

## 7. PART G — Transport responsibility classification

| Pattern | Observed in this audit? | Classification |
|---|---|---|
| Direct CLI fails, adapter fails the same way | No — 0/6 failures either path | N/A this sample |
| Direct CLI succeeds, adapter fails | No — 0/6 divergence | N/A this sample; **when the CLI succeeds, the adapter is provably faithful** (byte-identical output across all 3 pairs) |
| Tiny succeeds, medium/large fail | No — all 3 sizes (25/138/136 bytes out, 229/469/642 bytes in) succeeded uniformly | No output/prompt-size sensitivity detected up to these (still small) sizes |
| Text fails, machine-readable/streaming succeeds | Not tested (text never failed in this sample; json/stream-json not exercised) | Inconclusive — see §6.1 |
| Auto fails while a pinned model succeeds | Not tested — no `--model` pin is authorized/configured, and testing this would require spending real-call budget solely to prove it, which PART G explicitly says not to do without pre-authorization | **Unconfirmed hypothesis only.** Auto-routing instability remains plausible (no `--model` is configured; `assess_cursor_cli_safety` already flags this as a warning) but nothing in this audit confirms or refutes it |
| ACP provides structured progress/terminal events | **Confirmed available** (§6.2) | **Recommend an ACP-backed provider spike** (§8) |
| All probes succeed | **Yes — 6/6** | Per PART G.19: **do not declare the transport reliable from six successes alone.** The one historical session referenced in the task brief reports at least 2 of 6 invocations failing to produce a usable response (33%+, and likely higher — 2 of the repair turn's intermediate attempts have no recorded outcome at all). A 6/6-success controlled sample and a real session with ≥2/6 failures **are not in tension** — they are consistent with an intermittent, low-frequency failure mode this audit's short, simple, isolated-workspace prompts did not happen to trigger. **The live failures are provisionally classified as intermittent**, cause unconfirmed, pending more telemetry (§10 recommends the rolling failure-rate diagnostics that would let future audits quantify this properly instead of guessing from n=6 either way) |

### 7.1 New finding this audit adds to the matrix

**Confirmed adapter-side defect independent of CLI/service behavior:**
process-tree cleanup on timeout (§5.2). This is squarely an Admissible
defect — it exists regardless of whether the CLI/model layer is healthy,
and it would degrade *every* timeout in production today, including ones
this audit did not personally witness.

### 7.2 Confidence levels

| Finding | Confidence | Basis |
|---|---|---|
| Text mode is fully buffered, no incremental signal | **High** | Directly measured, 6/6 real calls, consistent |
| `subprocess.run(timeout=...)` orphans `powershell.exe`/`node.exe` on Windows | **High** | Directly measured twice with a real, representative process tree; mechanism (single-pid kill vs. tree structure) is deterministic, not probabilistic |
| ACP server is real, available, and fast to handshake | **High** | Directly measured; static source evidence corroborates |
| Adapter is faithful to the CLI when the CLI succeeds | **High** for the 3 tested shapes/sizes; **unconfirmed** beyond them | 6/6 byte-identical pairs |
| Auto-model-routing instability contributes to the historical failures | **Low / unconfirmed** | No pinned-model comparison was run (out of authorized budget); only a warning exists in existing code |
| The canonical `empty_success`/timeout were caused by Cursor's remote service specifically | **Unknown / cannot be claimed** | This audit only shows the *local* CLI produced no usable output in the historical session — per PART G.19, that is not evidence about Cursor's remote API specifically, only about what the local process chain delivered to Admissible |
| json/stream-json output modes behave differently from text | **Unknown** | Documented capability, not live-tested (budget) |

---

## 8. PART H — Provider-boundary architecture decision

### Option A — Keep one-shot Cursor CLI stdout (`--print --output-format text`)

- **Required hardening (concrete, scoped, low-risk):** replace the bare
  `subprocess.run(timeout=...)` cleanup with a recursive tree-kill (exactly
  `admissible.diagnostics.callable_backend_probe.tree_kill`, validated live
  in §5.2/§6.2) on every timeout path in `CursorCliAgentBackend.invoke()`.
  This closes the confirmed orphan-process defect without touching anything
  else about the transport.
- **Remaining ambiguity even after that fix:** still zero progress signal
  during a call (§5.1); still one full process cold-start per turn
  (13–16s minimum latency floor observed in this audit, even for a 25-byte
  reply); still cannot distinguish "model is thinking" from "process is
  stuck" without an idle-vs-total timeout split, which itself needs *some*
  progress signal to be worth adding.
- **Expected reliability ceiling:** bounded by the buffering problem — text
  mode structurally cannot report partial progress or accept a targeted
  cancellation; a stuck call can only ever be handled by killing the whole
  process and starting over.

### Option B — Implement a Cursor ACP backend

- **Protocol benefits (confirmed, §6.2):** newline-delimited JSON-RPC 2.0
  over stdio; request IDs; `session/update` progress events; `session/cancel`
  targeted cancellation instead of process-tree guessing; structured
  `result`/`error` completion signaling instead of inferring status from
  exit code + stdout emptiness; a persistent server process avoids paying
  cold-start cost on every turn (handshake alone: ~1.1s vs. ~13–16s per
  one-shot call observed in this audit).
- **Integration effort:** real but bounded — the protocol, method names, and
  capability negotiation already exist and were exercised live; Admissible
  would need a small JSON-RPC client (own the child process lifecycle, frame
  ndjson, correlate request IDs, map `session/update` events onto the
  existing `AgentInvocationResult`/`AgentInvocationRecord` model). No new
  external dependency is required (ndjson JSON-RPC needs nothing beyond the
  stdlib `json`).
- **Process lifecycle:** Admissible would own start/stop explicitly (one
  long-lived server per run, or per session) instead of one spawn+kill per
  turn — directly eliminates both the cold-start cost and the tree-kill
  fragility, by construction, not by patching around it.
- **Compatibility with Admissible's model-agnostic backend interface:**
  clean fit — `AgentBackend.invoke()` already returns a structured
  `AgentInvocationResult`; an ACP-backed implementation would populate the
  same shape with better-sourced fields (a real `error` object instead of an
  inferred "empty success", a real cancel instead of a killed process).
- **Risk/unknowns:** the command is undocumented/hidden — Cursor could
  change or remove it without notice in a future CLI version; the exact
  `protocolVersion` (`1`) and capability set were only confirmed for
  `2026.07.09-a3815c0` and were never cross-checked against the public Zed
  ACP spec version numbering; auth (`authMethods: [cursor_login]`) semantics
  for a headless server were not explored beyond the bare handshake.

### Option C — Add a second independent structured backend (control/fallback)

- **Purpose:** a backend Admissible can invoke identically to Cursor CLI
  (same `AgentBackend` interface) but backed by a different vendor/transport
  — lets a future audit distinguish "this failure is Admissible's adapter"
  from "this failure is specific to Cursor's CLI/service" by running the
  *same* instruction through two independent transports side by side.
  Directly answers the open question in §7.2 ("was the historical
  empty_success Cursor-specific?") that this audit's single-vendor sample
  structurally cannot answer.
- **Not implemented in this slice**, per the task's explicit instruction.

### Recommendation

- **Primary:** spike **Option B (ACP-backed provider)** as the next
  implementation slice. It is the only option that structurally fixes the
  two confirmed defects (no progress signal, fragile process cleanup)
  instead of working around their symptoms, and its core viability
  (server starts, speaks real JSON-RPC, negotiates real capabilities) is
  already confirmed live, not hypothetical.
- **Fallback:** if the ACP spike hits a blocker (undocumented-command
  removal risk, auth/session semantics that don't fit a headless
  batch-style caller, or a protocol-version mismatch), **harden Option A**
  with the tree-kill fix (cheap, already validated, should probably land
  regardless of the ACP timeline given it fixes a real defect on its own)
  and, as a cheaper interim step than full ACP, spend a small dedicated
  budget testing `--output-format stream-json --stream-partial-output`
  live — it may recover partial-progress visibility without a full
  protocol client.

---

## 9. PART J — Non-transport findings (kept separate from the transport conclusion)

All three were root-caused by reading the current code and confirmed with
new, passing characterization tests in
[`tests/test_admissible_callable_transport_forensic_regression.py`](../../tests/test_admissible_callable_transport_forensic_regression.py).
None of them affect, or are affected by, the transport findings above.

### 9.1 `MANDATORY ACCEPTANCE CRITERIA` not recognized as an acceptance section

**Root cause, confirmed:** `admissible/mission_contract.py`'s `_HEADINGS`
dict requires an **exact** (post-lowercasing/stripping) match:
`_HEADINGS["acceptance"] = ("acceptance criteria", "completion criteria",
"critères d'acceptation")`. `"mandatory acceptance criteria"` is not a
member of that tuple — it is a superset (an extra leading word) — so
`_heading()` returns `None` for that line. With no recognized section role,
none of `build_mission_contract()`'s per-line branches match (the
numbered/bulleted acceptance branches require `section == "acceptance"`),
so the eight numbered lines are **silently dropped entirely** — not even
rescued into `mandatory_requirements`. Confirmed reproducible today:
`test_heading_with_extra_leading_word_is_not_recognized_as_acceptance_section`
and `test_dropped_lines_are_not_even_rescued_as_mandatory_requirements`. A
control test using the exact recognized spelling
(`test_a_recognized_heading_spelling_does_work`) confirms the parser
mechanism itself is otherwise sound — the defect is narrowly the exact-match
dictionary, not something broader.

### 9.2 `local_usage` (and `game_controls`) failure — classification: **another deterministic defect**

Not "model failed to follow the controlled prompt," not "instruction packet
omitted the requirement," not "verifier mismatch," not "stale evidence."
**Root cause, confirmed:** because §9.1 leaves `explicit_acceptance_criteria`
empty, `build_mission_contract()` falls back to
`derive_acceptance_criteria_from_goal()`'s **generic, keyword-triggered
template** (`required_files`, `index_assets`, `index_game_ui`,
`style_non_empty`, `game_controls`, `game_collectible_score`,
`game_restart`, `local_usage` — see `admissible/governed_run.py:497-651`).
`game_controls` and `local_usage` are literal `criterion_id` values in that
generic template, triggered by keyword sniffing (`arrow`/`wasd`/`movement`
in the goal text; `usage`/`local`/`run` plus a doc-like filename) — **not**
values traceable to, or chosen by, the operator's actual 8-item
"MANDATORY ACCEPTANCE CRITERIA" list. The bounded verifier was silently
checking a different, generic contract than the one the operator wrote.
Confirmed reproducible:
`test_game_controls_and_local_usage_are_generic_template_ids_not_operator_authored`.
This fully explains "the controlled model instruction intended one failure,
but two criteria failed" — the two observed failures are not necessarily
related to the one *intended* failure at all; they come from an unrelated
substituted contract.

### 9.3 Run Identity backend field shows `—`

**Root cause, confirmed:** `admissible/harness/control_surface.html`'s
`renderRunIdentity(state)` reads `state.high_autonomy` and `state.control` —
but `control_surface.py`'s `session_dict()`/`state_view()` **never sets
top-level keys with those names**; it only ever sets
`view["high_autonomy_summary"]` and `view["agent_backend_control"]` (used
correctly, under their real names, by `renderWorkspaceFirst` elsewhere in
the same file). Both lookups in `renderRunIdentity` are therefore always
`undefined`, so `const backendLabel = ha.backend_id || (control.backends &&
selectedBackendId()) || "—"` always falls through to the `"—"` literal,
**independent of which backend actually governed the run** — this is not
intermittent, not state-dependent, not specific to `cursor_cli`; it would
show `—` for `file_bridge` and `fixture` too. Confirmed reproducible:
`test_run_identity_reads_a_top_level_key_the_server_never_sets` and
`test_the_keys_the_server_actually_sets_are_named_differently` (the latter
also proves this is an isolated typo in one function, not a systemic
server-side omission — the correct keys exist and are used correctly one
function away).

### 9.4 Follow-up slices (kept separate from any ACP work)

1. **`ADMISSIBLE_RUN_047_ACCEPTANCE_HEADING_MATCH_HARDENING`** — broaden
   `_heading()`'s acceptance-role matching (e.g. tolerate a leading
   qualifier word/prefix match instead of requiring an exact tuple member)
   and add a regression test using the exact `"MANDATORY ACCEPTANCE
   CRITERIA"` wording from this audit's fixture. Should also decide whether
   a near-miss heading should surface a diagnostic warning (`contract
   completeness`/`extraction_diagnostics`) rather than silently falling
   back to the generic template, so a future operator gets an on-screen
   signal instead of a silent substitution.
2. **`ADMISSIBLE_RUN_048_RUN_IDENTITY_BACKEND_KEY_FIX`** — trivial, isolated
   one-line-per-lookup fix in `renderRunIdentity` (`state.high_autonomy` →
   `state.high_autonomy_summary`, `state.control` → `state.agent_backend_control`),
   plus a UI-level regression test if the harness gains any JS test
   coverage; otherwise the static test added in §9.3 is sufficient
   guardrail until then.

---

## 10. PART I — Retry and circuit-breaker policy (design only, not implemented)

Provider-neutral, sits above any specific backend (`AgentBackend` interface
already provides the seam):

- **Instruction idempotency key:** already exists in spirit
  (`instruction_id` + `instruction_sha256` on every `AgentInvocationRequest`/
  `AgentInvocationRecord`) — formalize it as the key a retry or a circuit
  breaker keys off, so a retry of the *same* instruction is always
  distinguishable from a *new* instruction.
- **States:** `accepted` (process spawned, wrapper did not fail) →
  `started` (first byte observed, for transports that can tell) →
  `progress` (ACP `session/update`, or a future streaming signal — no
  equivalent exists for text mode today, §5.1) → `completed` (usable
  response) / `error` (structured failure). Today's text-mode transport can
  only ever report `accepted` → `completed`/`error`; ACP is what would make
  `started`/`progress` real (§8).
- **Automatic retry: at most one, and only for provably unaccepted
  requests** — i.e., `wrapper_failure` (the process never started at all,
  §3's classification) is the *only* status safe to auto-retry, because
  nothing was accepted by anything. `empty_success` and `timeout` are
  explicitly **not** auto-retryable — matching the canonical evidence's own
  behavior ("Admissible correctly entered a technical pause and required an
  explicit retry" / "Admissible correctly paused rather than looping"),
  which this policy should keep, not relax.
- **Explicit operator retry for uncertain completion:** unchanged from
  today's `retry_callable_backend_invocation` pattern — a human decides,
  the system never guesses.
- **Per-backend circuit breaker:** rolling window of the last N invocation
  outcomes per `backend_id`; a consecutive-failure threshold (e.g. 3) trips
  a `transport_health: degraded` status surfaced to the operator (this is
  new — no such status exists today; the closest is the per-invocation
  `AGENT_INVOKE_TERMINAL_STATUSES` pause, which is per-turn, not
  session/rolling); a cooldown before the breaker resets automatically;
  never auto-retries through an open breaker.
- **Rolling failure-rate diagnostics:** directly answers §7.2's "unknown"
  cell — persist enough per-invocation metadata (already captured by
  `AgentInvocationRecord`) to compute, e.g., "empty_success rate over the
  last 20 invocations" and surface it, so a future audit is not limited to
  an n=6 sample the way this one was.
- **Hard separation to preserve (already true today, keep it true):** a
  transport-layer failure (`timeout`, `empty_success`, `wrapper_failure`)
  must never consume the *semantic* repair-round budget
  (`repair_round_count`) — those are different budgets today
  (`operator_retry_count` on `AgentInvocationRecord` vs. `repair_round_count`
  on `HighAutonomyRunState`) and this policy should keep them distinct,
  never merge "the CLI didn't answer" with "the model's fix was wrong."

---

## 11. PART K — Tests and validation

| Check | Result |
|---|---|
| New diagnostic-harness tests (`test_admissible_callable_backend_probe_diagnostics.py`) | **20/20 passed**, 0.18s, zero real subprocesses |
| Fixture consistency + non-transport characterization tests (`test_admissible_callable_transport_forensic_regression.py`) | **13/13 passed**, 0.09s |
| Existing callable-backend adapter / retry / timeout tests (unchanged, part of the full run below) | passed |
| Full `python -m pytest tests/ -k admissible -q` | **1454 passed, 1 skipped, 206 subtests passed** in 67.84s — no regressions from RUN_038–045 or the RUN_043/044 browser-runtime work |
| `py_compile` on all new files | clean |
| Trailing-whitespace scan on all new files | clean |
| Production files modified | **none** (`git status` shows only new, untracked files: the diagnostics package, two test files, one fixture, this report, and the probe-results JSON) |

---

## 12. Final report

- **Installed Cursor CLI:** `2026.07.09-a3815c0`, resolved via
  `cursor-agent.CMD` → `powershell.exe -File` → `node.exe v24.5.0` running
  `index.js` (§1).
- **Six-call matrix:** 6/6 real invocations succeeded; direct and adapter
  paths byte-identical in all 3 pairs (§4).
- **Direct-vs-adapter comparison:** no divergence observed; the adapter is a
  faithful pass-through when the CLI succeeds (§4, §7).
- **Raw empty-success evidence:** from the task brief only (1-byte stdout,
  exit 0, ~32s); not reproduced live in this audit's sample (§2, §7).
- **Timeout/buffering behavior:** text mode is fully buffered end-to-end, no
  progress signal (§5.1); `subprocess.run(timeout=...)`'s cleanup only kills
  the direct child and **orphans `powershell.exe`/`node.exe` on every
  timeout** — new confirmed defect (§5.2).
- **Partial progress observable?** No, not in text mode as currently
  configured (§5.1). Yes, in principle, via ACP `session/update` or
  `stream-json --stream-partial-output` — neither exercised live beyond the
  ACP handshake (§6).
- **Do failures reproduce outside Admissible?** Cannot be determined from
  this audit — the direct-CLI path is "outside Admissible" in the sense of
  bypassing the adapter's logic, but it still goes through the identical
  local process chain; nothing here isolates Cursor's *remote* service as a
  variable (§7.2).
- **ACP availability/suitability:** confirmed available, hidden, real,
  fast, and protocol-appropriate (§6, §8).
- **Responsibility classification:** see the full matrix in §7; headline —
  one confirmed adapter-side defect (orphaned processes on timeout), zero
  confirmed CLI/service defects, historical failures provisionally
  intermittent pending more telemetry.
- **Recommended architecture:** ACP-backed provider spike as the primary
  next slice; hardened one-shot text mode (tree-kill fix) as the immediate
  low-risk fallback/interim (§8).
- **Retry/circuit-breaker recommendation:** design in §10, not implemented
  this slice.
- **Acceptance-heading finding:** confirmed, root-caused, reproducible;
  follow-up slice proposed (§9.1, §9.4).
- **`local_usage` finding:** confirmed "another deterministic defect" —
  silent generic-template substitution, not a model or verifier failure
  (§9.2).
- **Run Identity backend-projection finding:** confirmed, root-caused,
  reproducible, isolated one-function typo; follow-up slice proposed (§9.3,
  §9.4).
- **Test results:** all new and existing tests green, no regressions (§11).
- **Committed status: not committed**, per instruction. Working tree
  contains only new, untracked files.
- **Exact next implementation slice:**
  `ADMISSIBLE_RUN_047_CURSOR_ACP_PROVIDER_SPIKE` (§8 primary recommendation)
  — scoped to a bounded ACP client spike behind the existing `AgentBackend`
  interface, with `ADMISSIBLE_RUN_047_ACCEPTANCE_HEADING_MATCH_HARDENING`
  and a Run-Identity backend-key fix (§9.4) tracked as separate,
  non-transport slices so they are never bundled into the ACP work.
