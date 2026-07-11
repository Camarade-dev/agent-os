# Admissible RUN_048 — Cursor ACP Real Model Probes & Default Decision

`ADMISSIBLE_RUN_048_CURSOR_ACP_REAL_MODEL_PROBES_AND_DEFAULT_DECISION`

**Status: diagnostic + decision slice. Not committed. Default transport unchanged.**
Neon Serpents not run. This report separates *confirmed-live* facts from
*inferred* and *unknown*. Companion: RUN_047 report + `docs/admissible-cursor-acp-transport.md`.

**Verdict: `KEEP_CURSOR_ONESHOT_DEFAULT_ACP_EXPERIMENTAL`** (see §G).

---

## 0. Executive summary

- All four real model-bearing probes **succeeded** (2 ACP, 2 one-shot), serially,
  no retries, budget 4/4. Zero orphaned processes after any probe.
- The **entire spec-derived ACP request sequence is now confirmed live**:
  `initialize` → `session/new` → `session/set_mode` → `session/prompt` →
  `session/update`* → terminal `result{stopReason}`. My RUN_047 layout was
  correct on the first real call.
- **New proven defect found + fixed this slice:** `session/new` returns
  `modes.currentModeId: "agent"` — *"Full agent capabilities with tool access."*
  The RUN_047 ACP backend ran in **write-capable agent mode**, violating
  Admissible's proposal-only invariant. Fixed by forcing read-only **plan mode**
  via `session/set_mode` (confirmed live: server returns `result{}` +
  `current_mode_update`). The structured probe under plan mode **proposed** a
  `write_file` operation and did **not** execute it (no `probe.txt` on disk, no
  tool-call events).
- Because A1 (the first ACP call) ran in agent mode *before* the fix, only **one**
  real ACP call (B1) exercised the promotable (plan-mode) configuration.
  Combined with n=2 not being reliability (§H), ACP stays **experimental**:
  strongly viable, promote after a dedicated rehearsal slice (§I).

---

## A. Preflight (frozen environment)

| Field | Value |
|---|---|
| Repo SHA | `91038af2…` (RUN_047 committed as `feat: add managed Cursor ACP transport`) |
| Working tree | dirty (RUN_048 diagnostic files only) |
| Python | 3.12.0 |
| OS / arch | Windows-11-10.0.26200-SP0 / AMD64 |
| Cursor Agent CLI | `2026.07.09-a3815c0` |
| Resolved executable | `…\cursor-agent\cursor-agent.CMD` → PowerShell → Node |
| Auth | Logged in (confirmed via `cursor-agent status`) |
| Model selector | cursor-agent **default / "Auto"** (`default[]`), unpinned, same for both transports |
| ACP protocol version | **1** |
| Default transport | `oneshot` (unchanged) |
| Managed-process strategy | `windows_job_object` |

**Non-model handshake gate (free, budget not consumed):** PASS — `initialize`
matched, protocolVersion 1, `platform_strategy=windows_job_object`,
`cleanup_complete=true`, `remaining_process_ids=[]`, zero lingering owned pids,
process exited. Model probes were authorized to begin.

---

## B. Four-call matrix (real, serial, no retries)

| # | Transport | Result | Response | Struct ops | Total | Handshake | Progress events | Cleanup | Health |
|---|---|---|---|---|---|---|---|---|---|
| A1 | Cursor **ACP** (tiny) | success / `completed` | exact `ADMISSIBLE_ACP_TINY_PROBE_OK` (28 B) | 0 | 11.1 s | 754 ms | **7** (streamed) | clean | healthy |
| A2 | Cursor **one-shot** (tiny) | success / exit 0 | `ADMISSIBLE_ACP_TINY_PROBE_OK\n` (29 B) | 0 | 16.6 s | — | 0 (buffered) | clean | n/a |
| B1 | Cursor **ACP** (structured) | success / `completed` | 1 valid `ADMISSIBLE_STRUCTURED_OPERATION` block (128 B) | **1** | 12.9 s | 837 ms | **16** (streamed) | clean | healthy |
| B2 | Cursor **one-shot** (structured) | success / exit 0 | 1 valid block (129 B) | **1** | 15.8 s | — | 0 (buffered) | clean | n/a |

Both transports: same model selector (Auto), equivalent isolated temp
workspaces, equivalent semantic instruction, no retry, no fallback, no
concurrency. Sanitized fixture:
`tests/fixtures/admissible/run048_four_call_matrix.json`.

- **A1 caveat:** ran in **agent** mode (before the plan-mode fix). Harmless here
  (read-only text task) but it is why only B1 exercised the promotable config.
- **A2 vs A1 text:** one-shot appended a trailing `\n`; both are semantically
  exact — a *formatting deviation*, not a protocol failure (§D).

---

## C. Live ACP protocol confirmation

Confidence labels: **[L]** confirmed live (model probe), **[H]** confirmed by
non-model handshake only, **[I]** inferred from installed schema, **[U]** unknown.

| Element | Shape observed | Confidence |
|---|---|---|
| initialize / handshake | `initialize {protocolVersion:1, clientCapabilities:{}}` → `result{protocolVersion, agentCapabilities, authMethods}` | **[L]** |
| protocol version | `1` | **[L]** |
| capability response | `agentCapabilities{loadSession, mcpCapabilities{http,sse}, promptCapabilities{audio,embeddedContext,image}, sessionCapabilities{list}}` | **[L]** |
| session creation | `session/new {cwd, mcpServers:[]}` → `result{sessionId, modes, models, configOptions}` | **[L]** |
| session identifier | `result.sessionId` (uuid) | **[L]** |
| **session mode control** | `session/set_mode {sessionId, modeId:"plan"}` → `result{}` + `current_mode_update` notification | **[L]** (new this slice) |
| available modes | `agent` (default, tool access), `plan` (read-only), `ask` (Q&A) | **[L]** |
| available models | `default[]`="Auto" + full list (claude-opus-4-8, gpt-5.x, gemini-3.x, …) | **[L]** |
| prompt / request | `session/prompt {sessionId, prompt:[{type:"text", text}]}`, id = unique string | **[L]** |
| model selection field | `configOptions[id=model]` / `session/set_mode`-style; not exercised for model pinning | **[I]** |
| progress / update | `session/update {sessionId, update{sessionUpdate, content?}}` | **[L]** |
| update kinds seen | `available_commands_update`, `session_info_update`, `current_mode_update`, `agent_thought_chunk`, `agent_message_chunk` | **[L]** |
| content payload | `content{type:"text", text}` | **[L]** |
| terminal success | `{id:<reqid>, result:{stopReason:"end_turn"}}` | **[L]** |
| terminal error | JSON-RPC `error{code,message}` on the request id | **[I]** (fake-server only; not hit live) |
| cancellation | `session/cancel {sessionId}` | **[I]** (fake + non-model lifecycle) |
| shutdown | close stdin → server exits; managed tree termination verifies cleanup | **[L]** |

**No protocol-layout correction was needed** — the spec-derived request shapes
worked live. The only backend change this slice was the **plan-mode enforcement**
(`session/set_mode`), a proven-defect fix, validated live in B1 and
deterministically in the unit suite.

---

## D. Response canonicalization, extraction, exactly-once

- **Progress vs response:** the backend accumulates only `agent_message_chunk`
  text into the canonical response; `agent_thought_chunk` and the
  commands/info/mode updates are bounded progress only. A1's response
  reassembled exactly from 3 message chunks (`ADMISSIBLE_AC`+`P_TINY_PROBE`+`_OK`).
- **Tiny probe (A1):** provider followed the exact-text request; terminal
  structurally usable; canonicalization exact. Classified `exact_match`.
- **Structured probe (B1):** one canonical response; **one** valid structured
  operation extracted; `operation=write_file`, `path=probe.txt`,
  `content="ACP structured probe"`; **no operation executed** (no `probe.txt` on
  disk; no tool-call updates in the stream — plan mode held); no duplicate
  extraction.
- **Exactly-once:** identity = backend id + ACP request id + response hash.
  Offline deterministic test confirms a replayed terminal yields the *same*
  identity (no second ingest) and distinct request ids stay distinct; the
  duplicate-terminal fake scenario (`test_10`) confirms the client ignores a
  replayed terminal.

---

## E. One-shot comparison (control, not the promotion target)

| Dimension | Cursor ACP | Cursor one-shot |
|---|---|---|
| Startup overhead | ~0.8 s handshake, then persistent for the turn | ~13–16 s cold start every turn |
| First observable progress | real `session/update` deltas (7 / 16 events) | **none** — fully buffered until done |
| Terminal clarity | explicit `stopReason` + request id | exit code + stdout emptiness heuristic |
| Raw output | structured events | one buffered stdout blob |
| Usable completion | 2/2 | 2/2 |
| Parse / extraction | 1 op (B1) | 1 op (B2) |
| Process cleanup | verified clean (Job Object) | verified clean (RUN_047 managed one-shot) |
| Failure ambiguity | low (typed states + progress) | higher (silent-then-done) |

Notes (PART E.15): one-shot still fully buffers output; two one-shot successes
here do **not** erase the historical `empty_success`/timeout rate from RUN_046;
the RUN_047 tree-cleanup fix solved orphaning (confirmed: A2/B2 left zero
orphans) but not observability.

---

## F. Timeout / cancellation / progress

Observable ACP states (live): server ready, request submitted, request accepted
(first `session/update`), model running (`agent_thought_chunk`), progress
(`agent_message_chunk`), terminal success. ACP therefore satisfies the PART F.17
minimum (explicit request identity, running state, unambiguous terminal, bounded
cancellation, managed cleanup) **and** emits real intermediate progress — not an
elapsed-time proxy. No model timeout was forced (PART F.19); idle/absolute/
cancellation semantics rest on the fake-server suite + the non-model lifecycle.

---

## G. Default-transport decision

**Verdict: `KEEP_CURSOR_ONESHOT_DEFAULT_ACP_EXPERIMENTAL`.**

Promotion gate (PART G.21), computed from evidence
(`compute_default_transport_verdict`):

| Condition | Met? |
|---|---|
| real non-model handshake passes | ✅ |
| both real ACP calls reach unambiguous terminal | ✅ |
| both produce usable canonical responses | ✅ |
| structured-operation extraction succeeds | ✅ |
| request/session identities stable | ✅ |
| no duplicate ingest | ✅ |
| no uncertain completion | ✅ |
| no orphan / cleanup failure | ✅ |
| no silent fallback | ✅ |
| transport-health healthy | ✅ |
| full Admissible suite passes | ✅ |
| **both ACP calls in the promotable (plan-mode) config** | ❌ (A1 ran agent mode, pre-fix) |

Eleven of twelve conditions hold; the failing one is that the **proposal-only
guarantee (plan mode) was only just added and has exactly one real-call
validation (B1)**. Promoting a transport whose core safety enforcement has n=1
real validation is premature. Hence KEEP — ACP is protocol-viable and
proposal-safe *by construction now*, and should be promoted in a dedicated
rehearsal slice (§I). The production default is **unchanged** in this slice.

---

## H. Reliability interpretation

Two ACP successes prove: live protocol compatibility for the exercised request
types (tiny text + structured proposal); terminal-response usability;
plan-mode enforcement; and clean cleanup for those calls. They do **not** prove:
a low long-run failure rate; stability over dozens of turns; stability under
large prompts; or stability under repair/cancellation. n=2 is viability, not
reliability.

---

## I. Follow-up decision

Because the verdict is KEEP (not PROMOTE), the next slice is a **promotion
rehearsal** that also lands the deferred non-transport fixes:

**`ADMISSIBLE_RUN_049_PROMOTE_CURSOR_ACP_FIX_DETERMINISTIC_FOLLOWUPS_AND_REHEARSE_REPAIR`**
— should: (1) fix the three confirmed non-transport issues (acceptance-heading
exact-match; generic-criteria substitution; Run Identity backend-key typo);
(2) accumulate additional real **plan-mode-enforced** ACP calls (incl. a large
prompt); (3) perform one small real **repair rehearsal** over ACP; (4) verify no
orphan, no duplicate request, no ambiguous wait; (5) only then make ACP the
explicit production default with one-shot as explicit fallback — and only then
return to Neon.

---

## J. Fixtures, tests, reports

- `tests/fixtures/admissible/run048_four_call_matrix.json` — sanitized 4-call
  matrix (transcripts reduced to method/update sequences; sensitive data redacted).
- `admissible/diagnostics/acp_real_probe.py` — budgeted (≤4), serial, no-retry
  real-probe harness + sanitizer + verdict gate + deviation classifier. **Never
  imported by production.**
- `tests/test_admissible_run048_acp_probe_harness.py` (19 tests): budget ≤4,
  serial guard, no auto-retry, failed-probe-recorded, no silent fallback, default
  unchanged, verdict-from-evidence (incl. the actual RUN_048 → KEEP), redaction,
  formatting-vs-protocol, exactly-once offline replay, fixture integrity.
- Plan-mode regression tests added to `test_admissible_cursor_acp_transport.py`
  (3): agent→plan forced, unsupported set_mode graceful, already-plan skips.

## K. Validation

- New RUN_048 harness tests: 19/19. ACP transport tests (incl. plan-mode): 23/23.
- Full `python -m pytest tests/ -k admissible -q`: **1515 passed, 1 skipped, 210
  subtests passed** (RUN_047 baseline 1493 + 22 new; RUN_038–047 all green, no
  regressions from the plan-mode change).
- `py_compile`: clean. `git diff --check`: clean. Embedded UI harness: unchanged
  (no UI surface touched this slice).

---

## Final report

- **Cursor CLI / protocol:** `2026.07.09-a3815c0`, ACP protocolVersion **1**.
- **Handshake:** PASS (non-model), cleanup verified, 0 orphans.
- **Four-call matrix:** 4/4 success; ACP faster (~11–13 s) with real streaming;
  one-shot slower (~16 s) buffered; both usable; both structured probes → 1 op.
- **Confirmed live methods/payloads:** initialize, session/new, **session/set_mode**,
  session/prompt, session/update (multiple kinds), terminal `result{stopReason}`.
- **Progress:** real `agent_message_chunk` deltas (not elapsed-time proxy).
- **Terminal:** explicit `stopReason:end_turn`, request-id-matched.
- **Canonicalization / extraction:** exact; 1 structured op; no execution.
- **Exactly-once:** backend id + request id + response hash; replay-safe.
- **Cleanup / orphans:** all clean; final sweep found zero cursor-agent orphans.
- **Transport health:** ACP `healthy` on both calls.
- **Decision:** **KEEP_CURSOR_ONESHOT_DEFAULT_ACP_EXPERIMENTAL** — ACP viable +
  now proposal-safe; promote in RUN_049 after the rehearsal.
- **Confidence / limitations:** protocol viability HIGH; long-run reliability
  UNPROVEN (n=2); plan-mode path real-validated n=1.
- **Committed status:** not committed.
- **Exact next slice:** `ADMISSIBLE_RUN_049_PROMOTE_CURSOR_ACP_FIX_DETERMINISTIC_FOLLOWUPS_AND_REHEARSE_REPAIR`.
