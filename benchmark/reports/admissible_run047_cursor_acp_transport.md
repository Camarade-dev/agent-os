# Admissible RUN_047 — Cursor ACP Transport & Managed Process Lifecycle

`ADMISSIBLE_RUN_047_CURSOR_ACP_TRANSPORT_AND_MANAGED_PROCESS_LIFECYCLE`

**Status: implementation spike. Not committed.** ACP is used only when explicitly
selected; the one-shot transport remains the compatibility default. Neon Serpents
was not run. Companion design doc: `docs/admissible-cursor-acp-transport.md`.

---

## 1. Managed-process architecture (PART A)

New module `admissible/managed_process.py` — provider-neutral, used by **both**
the ACP server and the hardened one-shot adapter.

- `ManagedProcess` owns one external process tree. `spawn` (`shell=False`, fixed
  argv) and `ContainmentStrategy` are injectable seams, so the whole lifecycle is
  driven deterministically in tests with zero real subprocesses.
- Containment strategies: `WindowsJobContainment` (Job Object), `PosixSessionContainment`
  (process group), `PsutilTreeContainment` (portable fallback). `default_containment_strategy()`
  picks the narrowest reliable one per platform.
- `terminate()` = close stdin (graceful) → wait grace → verify the **whole owned
  set** (not just the root) → escalate to a force tree kill if anything survives →
  re-verify liveness. `run_managed_oneshot(...)` is the `subprocess.run`-shaped
  convenience the one-shot adapter uses.
- Durable `ManagedProcessResult` carries every PART A.4 field, including
  `cleanup_complete` + `remaining_process_ids` (the circuit-breaker input) and
  `platform_strategy`.
- Circuit breaker: if cleanup cannot be proven complete, the result exposes the
  remaining pids and transport health latches `unhealthy` (see §9).

## 2. Windows Job Object / process-tree result (PART A.2)

- On Windows the spawned process is assigned to a Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` immediately after spawn (via `ctypes`), so
  descendants inherit containment and one `TerminateJobObject` kills the whole
  `.CMD → powershell.exe → node.exe` chain. If the Job Object API is unavailable
  it falls back to a `psutil` recursive tree kill; cleanup is verified either way.
- **Live proof** (opt-in real, non-model handshake, PART K.41): against the real
  `cursor-agent acp` on this Windows 11 host, `platform_strategy = windows_job_object`,
  handshake matched protocol version **1**, `cleanup_complete = True`,
  `remaining_process_ids = []`, and a post-terminate liveness re-check found
  **zero lingering owned pids**. Graceful stdin-close alone shut the server down
  (force not needed).

## 3. Proof the one-shot timeout no longer orphans PowerShell/Node (PART A.5)

- `CursorCliAgentBackend` now routes **production** one-shot runs (no injected
  `runner`) through `run_managed_oneshot(...)`. On timeout the whole tree is
  terminated and cleanup verified; the result carries `managed_process_result`
  and an error message stating "cleanup verified" or "CLEANUP UNPROVEN".
- The legacy injected-`runner` test seam is unchanged (no real process spawned),
  so all 72 existing one-shot backend tests remain green (PART K.20).
- Deterministic proof: `test_admissible_managed_process_lifecycle.py::TestManagedOneshot::test_oneshot_timeout_terminates_tree`
  models the `.CMD → powershell → node` tree; after a one-shot timeout all three
  pids are dead and `cleanup_proven` is True. `TestOneshotAdapterUsesManagedCleanup`
  proves the adapter surfaces the cleanup proof (and the unproven case).

## 4. Locally observed ACP protocol (PART B)

- Framing: newline-delimited JSON-RPC 2.0 over stdio. **Confirmed live**:
  `initialize` (protocolVersion 1, agentCapabilities, authMethods `[cursor_login]`).
- **Spec-derived, method names confirmed in bundled source, layouts not confirmed
  live**: `session/new`, `session/prompt`, `session/update`, `session/cancel`.
  Parsing is deliberately tolerant; unknowns are documented, not invented.
- Sanitized transcript fixture: `tests/fixtures/admissible/cursor_acp_transport_transcript.json`
  (confirmed-live vs spec-derived vs unknowns tagged per message).

## 5. ACP provider lifecycle (PART C)

- `admissible/cursor_acp_transport.py::CursorAcpBackend` satisfies the existing
  `AgentBackend` boundary. One `invoke()` = detect → start managed server →
  handshake → `session/new` → `session/prompt` (unique request id) → progress →
  terminal → **one canonical `AgentInvocationResult`** → cancel/shutdown/verified
  cleanup.
- Provider identity distinguishes `cursor_cli_oneshot` from `cursor_acp`.
- Fixed executable chain (`cursor-agent acp`); no session/model/UI input supplies
  the executable, command, flags, or a cwd outside the isolated agent workspace.
- **Server lifecycle: per invocation** — the narrowest reliable choice for a
  spike. Admissible reconstructs a fresh controller/transport per HTTP tick, so a
  long-lived server would need new cross-tick persistence (a new failure surface).
  Per-invocation fits the existing tick machine unchanged and shuts down cleanly
  every turn; trade-off is re-paying the ~1–2.6s handshake per turn (still far
  under the 13–16s one-shot cold start). Documented in the module + companion doc.

## 6. Structured invocation states, progress, terminal semantics (PART D/F)

- 19 structured states from `created` … `uncertain_completion` … `cleanup_failed`.
- `AcpInvocationTelemetry` records request id, session id, protocol version,
  handshake duration, accepted/first-progress/last-progress/completed timestamps,
  bounded progress events, terminal event, response bytes, and the managed-process
  result. Separate transport-vs-semantic counters (`transport_attempt_count`,
  `acp_request_count`, `progress_events_total`, `usable_responses`, `model_turns`,
  `semantic_repair_rounds`).
- Progress is bounded (timestamp, event type, ≤200-char summary, request id,
  sequence). `agent_message_chunk` text is accumulated into the canonical response;
  thoughts/tool/plan updates store only a bounded summary — never raw token or
  reasoning streams.

## 7. Timeout / cancellation semantics (PART E)

- Seven timeout dimensions: server-start, handshake, request-acceptance,
  idle/no-progress, absolute-request, cancellation, cleanup.
- A progress event refreshes **only** the idle timeout, never the absolute maximum
  (`test_07`/`test_08` prove idle liveness refresh *and* a bounded absolute
  timeout despite continuous progress).
- On timeout: `session/cancel` → bounded wait → managed tree termination →
  classify. **Uncertain completion is never auto-retried.** The one bounded
  automatic retry is permitted only on *provable* non-acceptance (disconnect during
  setup / explicit rejection — `test_11`); disconnect after submit → uncertain
  (`test_12`, `test_13`).
- Transport failures never consume the semantic repair budget: `semantic_repair_rounds`
  stays 0 on every outcome (`test_17`).

## 8. Exactly-once behavior (PART G)

- Terminal ACP response → the same canonical `AgentInvocationResult` the existing
  extraction/admission pipeline consumes; `ADMISSIBLE_STRUCTURED_OPERATION` blocks
  still extract (`test_16`).
- Exactly-once ingest keyed by backend id + ACP request id + response hash
  (`acp_request_id` + `response_sha256` on the durable record). A replayed terminal
  event is ignored — the first terminal for a request id is authoritative
  (`test_10`: duplicate terminal → single un-doubled response, one usable response).

## 9. Transport selector + circuit breaker (PART H/I)

- `ADMISSIBLE_CURSOR_TRANSPORT=acp|oneshot` (default `oneshot`). Unrecognized →
  compatibility default, never a silent ACP upgrade (`test_18`). Applied only at
  run start; the concrete transport id is persisted, so a reconstructed controller
  never silently switches mid-run. ACP-selected-but-unavailable raises a technical
  capability gap, never a silent one-shot downgrade (`test_18b`). The UI names the
  exact transport ("Cursor Agent ACP" / "Cursor Agent one-shot", `test_19`).
- `admissible/transport_health.py::TransportHealth`: states `healthy/degraded/
  unhealthy/cooldown/unknown`; bounded rolling counters; rules — any cleanup
  failure → latched `unhealthy` + operator recovery required; any uncertain
  completion → `degraded` + no auto-retry; repeated failures ≥ threshold →
  `cooldown`; handshakes alone never mark the model transport healthy. Technical
  state only, never a human-authority gate.

## 10. Fake-server results & four-call matrix (PART J / K.42-44)

- Deterministic in-memory fake ACP server (`tests/fixtures/admissible/fake_acp_server.py`)
  implements all 14 PART J.39 scenarios (handshake success/reject, unsupported
  protocol, accepted+progress+terminal, provider error, malformed, duplicate,
  disconnect before/after acceptance, idle timeout, total timeout despite progress,
  cancel ack/ignored, delayed/leaked cleanup).
- **Real model-bearing four-call comparison matrix: NOT run.** Only the single
  opt-in *non-model* handshake was executed (below). The two paired semantic probes
  (PART K.42) were intentionally skipped this slice — they consume real model
  budget and are gated behind the acceptance decision (§12); the fake-server suite
  covers the semantic paths deterministically. Running the four real calls is the
  first task of the follow-up decision, not of this spike.

| Probe | Type | Result |
|---|---|---|
| Real ACP handshake (managed process, non-model) | 1 real spawn, 0 model calls | **PASS** — Job Object strategy, protocolVersion 1, cleanup_complete, 0 lingering pids |
| Pair A / Pair B semantic probes (ACP vs one-shot) | — | **Not run** (deferred to acceptance decision) |

## 11. Cleanup results

- Real handshake: `cleanup_complete=True`, `remaining_process_ids=[]`, zero
  lingering owned pids after terminate. Graceful shutdown sufficed.
- Deterministic tests prove: full tree kill on ignored cancellation (`test_15`),
  cleanup-failure detection + circuit-breaker trip (`test_03`, both managed and
  ACP levels), and no force when graceful suffices.
- Known limitation: the immediate post-spawn descendant snapshot can be empty when
  `powershell.exe`/`node.exe` have not yet been created; the Job Object still
  contains them and termination still proves clean. A later-sampled snapshot would
  list them — a candidate refinement, not a correctness gap.

## 12. Default-transport acceptance gate (PART L)

**ACP is NOT made the default in this slice.** Gate status:

| Criterion | Status |
|---|---|
| Real handshake reliable | ✅ (1 real non-model handshake PASS; n=1) |
| Both real ACP model probes usable | ❌ **not run** (deferred) |
| No orphan process | ✅ (real handshake + deterministic tree-kill tests) |
| Cancellation + cleanup via managed lifecycle | ✅ |
| Canonical extraction works | ✅ (`test_16`) |
| No exactly-once regression | ✅ (`test_10`, full suite green) |
| Full Admissible suite passes | ✅ (1493 passed) |

**Recommendation:** do **not** switch the default yet. The blocker is the two
real ACP model probes (and confirming the spec-derived `session/prompt`/`session/update`
layouts against a live model turn). Run those (≤4 real calls, serial, no
auto-retry) as an explicit, separately-committed decision.

## 13. Remaining unknowns

- Exact live `session/new` / `session/prompt` / `session/update` field layouts
  (only `initialize` confirmed live).
- Whether the prompt is explicitly acknowledged before progress, or acceptance is
  implicit in the first `session/update`.
- Whether `session/cancel` is a request or notification.
- Headless-server `cursor_login` auth semantics beyond the bare handshake.
- Removal/behaviour-change risk of the hidden `acp` command across CLI versions.

## 14. Full regression results (PART N)

- New: `test_admissible_managed_process_lifecycle.py` (12), `test_admissible_cursor_acp_transport.py`
  (20 incl. transcript), `test_admissible_transport_health.py` (7) — 39 new tests, all pass.
- `py_compile`: clean on all new/changed files. `git diff --check`: clean. No
  trailing whitespace in new files.
- **Full `python -m pytest tests/ -k admissible -q`: 1493 passed, 1 skipped, 209
  subtests passed** (RUN_038–046, callable-backend, retry/liveness/exactly-once,
  and browser-runtime/orchestration suites all green). One transient regression I
  introduced (extra executable-discovery latency in the hot `describe_available_backends`
  path tipped a 0.15s timing-sensitive runtime-verification test) was root-caused
  and fixed by keeping that display function cheap.
- Embedded UI harness: covered indirectly by `test_admissible_workspace_first_ui`
  and the control-surface state-view tests (green); the backend-id set is unchanged
  (`file_bridge`, `cursor_cli`, `fixture`), with the exact transport surfaced on
  the `cursor_cli` entry.

## 15. Committed status

**Not committed.** Working tree contains new untracked files (`admissible/managed_process.py`,
`admissible/transport_health.py`, `admissible/cursor_acp_transport.py`, three test
files, the fake server, the transcript fixture, this report, the companion doc)
and two modified tracked files (`admissible/agent_backend.py`,
`admissible/high_autonomy_controller.py`).

## 16. PART M — separate follow-up registry (recorded, NOT fixed here)

Confirmed RUN_046 non-transport findings, kept out of this slice's production code:

1. **`ADMISSIBLE_RUN_048_ACCEPTANCE_HEADING_MATCH_HARDENING`** — `mission_contract.py`
   `_HEADINGS["acceptance"]` requires an exact match, so "MANDATORY ACCEPTANCE
   CRITERIA" is silently dropped.
2. **`ADMISSIBLE_RUN_049_GENERIC_CRITERIA_SUBSTITUTION_GUARD`** — the direct
   consequence: empty explicit criteria silently fall back to
   `derive_acceptance_criteria_from_goal()`'s generic template (`game_controls`/
   `local_usage`), so the verifier checks a substituted contract. Should surface a
   diagnostic instead of silently substituting.
3. **`ADMISSIBLE_RUN_050_RUN_IDENTITY_BACKEND_KEY_FIX`** — `control_surface.html`
   `renderRunIdentity()` reads `state.high_autonomy`/`state.control`, but the server
   only sets `state.high_autonomy_summary`/`state.agent_backend_control`, so the
   Run Identity Backend field always shows "—".

(Numbers are candidates; renumber when picked up.)

## 17. Exact next slice

**`ADMISSIBLE_RUN_048_CURSOR_ACP_REAL_MODEL_PROBES_AND_DEFAULT_DECISION`** — run
the ≤4 real, serial, no-auto-retry model probes (Pair A tiny response, Pair B one
structured write proposal; ACP vs one-shot), confirm the spec-derived
`session/prompt`/`session/update` layouts against a live turn, fill the four-call
comparison matrix, and make the default-transport switch an explicit, separate
decision/commit. Keep the three PART M findings as their own non-transport slices.
