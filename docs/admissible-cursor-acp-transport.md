# Admissible Cursor ACP Transport (RUN_047)

Slice `ADMISSIBLE_RUN_047_CURSOR_ACP_TRANSPORT_AND_MANAGED_PROCESS_LIFECYCLE`.

This documents the **locally observed** Cursor Agent Client Protocol (ACP)
transport that Admissible drives, the managed-process lifecycle that owns every
external backend process, and — explicitly — the parts of the protocol that are
**not yet confirmed live**. It deliberately separates *confirmed live* facts
from *spec-derived* assumptions and *unknowns*, per the RUN_047 constraint "do
not invent protocol fields from memory".

Status: **experimental spike.** ACP is only used when explicitly selected
(`ADMISSIBLE_CURSOR_TRANSPORT=acp`); the legacy one-shot stdout transport
remains the compatibility default. See "Default-transport acceptance gate".

---

## 1. Why ACP

RUN_046 established (see
`benchmark/reports/admissible_cursor_callable_transport_forensic_audit.md`):

- The one-shot `cursor-agent --print --output-format text` transport is **fully
  buffered** — no progress signal exists during a call; it is "silent, then
  done."
- On Windows, `cursor-agent` resolves through `.CMD -> powershell.exe ->
  node.exe`. `subprocess.run(timeout=...)` cleanup on timeout kills only the
  **direct** child, orphaning `powershell.exe`/`node.exe` (the process holding
  the model connection) on **every** timeout.
- `cursor-agent` ships a real, hidden, working ACP server (`cursor-agent acp`).
  A non-model `initialize` handshake completed in ~1.1s vs. the 13–16s one-shot
  cold start paid on every turn.

ACP structurally fixes both problems: it exposes request IDs, `session/update`
progress events, a targeted `session/cancel`, and structured terminal
`result`/`error` — and Admissible owns the server's lifecycle explicitly.

---

## 2. Managed-process lifecycle (`admissible/managed_process.py`)

Provider-neutral, used by **both** the ACP server and the hardened one-shot
adapter.

- **Spawn**: `shell=False`, fixed/backend-owned argv, never session/UI-supplied.
- **Windows**: the spawned process is assigned to a **Job Object** with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` immediately after spawn, so descendants
  inherit containment and one `TerminateJobObject` kills the whole `.CMD` chain.
  A `psutil` recursive tree-kill is the deterministic fallback if the Job Object
  API is unavailable.
- **POSIX**: the child starts a new session (`start_new_session=True`); the whole
  process group is terminated `SIGTERM` then `SIGKILL`.
- **Graceful → force**: `terminate()` first closes stdin (EOF/shutdown signal),
  waits a bounded grace, then — verifying the **whole owned set**, not just the
  root — escalates to a force tree termination if anything survives.
- **Cleanup verification**: every owned pid is re-checked for liveness. The
  durable `ManagedProcessResult` records `cleanup_complete` + `remaining_process_ids`
  so an operator gets *proof* a timeout was actually bounded, and a breakaway
  descendant is surfaced rather than hidden.
- **Circuit breaker**: if cleanup cannot be proven complete, transport health is
  latched `unhealthy`, automatic retry is prohibited, and explicit operator
  recovery is required.

`ManagedProcessResult` fields: `process_id`, `observed_descendant_ids`,
`started_at`, `first_stdout_at`, `first_stderr_at`, `exited_at`, `exit_code`,
`termination_reason`, `graceful_termination_attempted`,
`force_termination_attempted`, `cleanup_complete`, `remaining_process_ids`,
`stdout_bytes`, `stderr_bytes`, `output_truncated`, `platform_strategy`.

The one-shot adapter (`CursorCliAgentBackend`) now routes production runs through
`run_managed_oneshot(...)` instead of `subprocess.run(timeout=...)`, so a one-shot
timeout terminates the whole tree and **cannot orphan PowerShell/Node**. The
injected-`runner` unit-test seam is unchanged (no real process, no managed
cleanup needed there), so all existing one-shot fixtures remain compatible.

---

## 3. Observed ACP protocol

Framing: **newline-delimited JSON-RPC 2.0 over stdio** (one JSON object per
line). Not LSP-style `Content-Length` framing.

### 3.1 Confirmed live (RUN_046, cursor-agent `2026.07.09-a3815c0`)

- **Startup command**: `cursor-agent acp` (hidden from `--help`; registered
  `hidden: true` in the bundled source).
- **`initialize`** request `{protocolVersion: 1, clientCapabilities: {}}` →
  response with `result.protocolVersion` (**1**), `result.agentCapabilities`
  (`loadSession: true`, `mcpCapabilities: {http, sse}`, `promptCapabilities:
  {audio, embeddedContext, image}`, `sessionCapabilities: {list: {}}`), and
  `result.authMethods` (`["cursor_login"]`). Round-trip ~1.1s.
- Process tree is the same `cmd.exe -> powershell.exe -> node.exe` chain; the
  managed lifecycle terminates it cleanly (`all_terminated: true`).

A sanitized transcript is in
`tests/fixtures/admissible/cursor_acp_transport_transcript.json`.

### 3.2 Spec-derived, method names confirmed in bundled source, **layouts not confirmed live**

- **`session/new`** `{cwd, mcpServers}` → `{sessionId}`.
- **`session/prompt`** `{sessionId, prompt: [{type:"text", text}]}` with a
  client-assigned **unique request id** → terminal `{stopReason}` on success or
  a JSON-RPC `error` on failure.
- **`session/update`** notification `{sessionId, update: {sessionUpdate, content}}`
  carries progress. Admissible accumulates `agent_message_chunk` text into the
  canonical response and stores only a **bounded summary** for every other kind
  (thoughts, tool calls, plans) — never raw token/reasoning streams.
- **`session/cancel`** `{sessionId}` — targeted cancellation.

Parsing is deliberately **tolerant** (multiple field-name fallbacks, malformed
lines skipped with a bounded note) because these layouts are unverified.

### 3.3 Unknowns (documented, not invented)

- Exact `session/new` / `session/prompt` field layouts.
- Whether the prompt is explicitly acknowledged before progress, or acceptance
  is implicit in the first `session/update`.
- Whether `session/cancel` is a request or a notification.
- Headless-server auth semantics beyond the bare handshake.
- Removal/behavior-change risk of the hidden `acp` command in future versions.

---

## 4. ACP provider lifecycle (`admissible/cursor_acp_transport.py`)

`CursorAcpBackend` satisfies the existing model-agnostic `AgentBackend`
boundary. One `invoke()` runs one complete, bounded, cancellable lifecycle:

1. detect executable/capability;
2. start the managed ACP server;
3. `initialize` handshake (reject unsupported `protocolVersion`);
4. `session/new`;
5. `session/prompt` with a unique request id;
6. consume `session/update` progress;
7. terminal `result`/`error` → **one canonical `AgentInvocationResult`**;
8. cancel (on timeout) + graceful shutdown + verified cleanup.

### Server lifecycle: **per invocation** (spike choice)

Admissible reconstructs a fresh controller/transport per HTTP tick, so a
long-lived (process/control-surface/session-scoped) ACP server would need new
cross-tick persistence to survive reconstruction — a new failure surface out of
scope for a spike. A **per-invocation** server (spawn → handshake → one prompt →
shutdown) is the narrowest lifecycle that fits the existing tick machine
unchanged, with a trivially clean shutdown every turn. Trade-off: it re-pays the
~1.1s handshake per turn — still far cheaper than the 13–16s one-shot cold
start, and it eliminates cross-turn server state entirely.

### Structured invocation states

`created`, `server_starting`, `handshake_pending`, `ready`, `request_submitted`,
`accepted`, `running`, `progress`, `response_ready`, `completed`,
`provider_error`, `protocol_error`, `disconnected`, `cancellation_requested`,
`cancelled`, `timed_out_idle`, `timed_out_total`, `uncertain_completion`,
`cleanup_failed`.

### Response canonicalization + exactly-once

The terminal ACP response becomes the same `AgentInvocationResult` the existing
extraction/admission pipeline consumes, so governed textual responses and
`ADMISSIBLE_STRUCTURED_OPERATION` blocks still parse. Exactly-once ingest is
keyed by **backend id + ACP request id + response hash**; a replayed terminal
event or reconnect artifact is ignored (the first terminal for a request id is
authoritative).

---

## 5. Timeout semantics

The one-dimensional one-shot timeout is replaced (for ACP) with:
`server_start`, `handshake`, `request_acceptance`, `idle_no_progress`,
`absolute_request`, `cancellation`, `cleanup`.

- A `session/update` refreshes **only** the idle timeout, never the absolute
  maximum — so a stream that keeps dripping progress still ends at the absolute
  deadline.
- On timeout: request `session/cancel`, wait a bounded interval, terminate the
  owned tree if needed, and classify completion as **known** or **uncertain**.
- **Uncertain completion is never auto-retried.** Automatic retry may occur at
  most once, and only when evidence proves the request was **not accepted**
  (a disconnect during setup, before the prompt was submitted, or an explicit
  rejection).
- Transport failures never consume the semantic repair-round budget
  (`semantic_repair_rounds` stays 0; transport counters are tracked separately).

---

## 6. Transport selection + health

- `ADMISSIBLE_CURSOR_TRANSPORT=acp|oneshot` (default `oneshot`). An unrecognized
  value falls back to the compatibility default — it never silently upgrades to
  ACP.
- Selection is applied **only at run start**; the concrete transport id
  (`cursor_cli` one-shot vs `cursor_acp`) is persisted, so a reconstructed
  controller rebuilds the same transport and never silently switches mid-run.
- If ACP is selected but unavailable, run start raises a **technical capability
  gap** rather than silently invoking one-shot.
- Run Identity / the backend selector name the exact transport ("Cursor Agent
  ACP" vs "Cursor Agent one-shot").
- `TransportHealth` is a bounded, provider-neutral circuit breaker: any cleanup
  failure → `unhealthy` (latched); any uncertain completion → `degraded` + no
  auto-retry; repeated failures above a threshold → `cooldown`; successful
  handshakes alone never mark the model transport healthy. It is a *technical*
  transport state, never a human-authority gate.

---

## 7. Default-transport acceptance gate

ACP does **not** become the default in this slice. Flipping the default requires
all of: reliable real handshake; both real ACP model probes returning usable
terminal responses; no orphan process; cancellation + cleanup through the managed
lifecycle; canonical extraction working; no exactly-once regression; full
Admissible suite green — and even then, a separate explicit decision/commit.
