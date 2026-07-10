# Admissible Model-Agnostic Agent Transport (v0)

Slice: `ADMISSIBLE_RUN_032_MODEL_AGNOSTIC_AGENT_TRANSPORT_AND_WORKSPACE_FIRST_UI`

Builds on [the high-autonomy governed loop](admissible-high-autonomy-governed-loop.md) and
[the live high-autonomy rehearsal](admissible-live-high-autonomy-rehearsal.md).

## Why this slice exists

The high-autonomy governed loop could already run without a human clicking through each
turn — but only because a human kept **Cursor's GUI** pointed at the file bridge. The loop
wrote `.admissible/next-agent-instruction.md` and then *waited for Cursor to voluntarily
notice it* and write `.admissible/agent-response.md` back. That is **semi-autonomous**: there
is no agent-side loop Admissible actually drives.

This slice introduces a **model-agnostic agent transport** so the controller can call an
agent backend through one common interface. Cursor CLI / headless is the first concrete
callable target; the Cursor GUI file bridge is preserved as an honest *external / manual*
backend; and a deterministic fixture backend powers the tests.

## The two invocation shapes

| Shape | Interface | Backends | Progress model |
|---|---|---|---|
| **Pull / external** | `AgentTransport` (unchanged) | `FileBridgeAgentTransport`, `FixtureAgentTransport` | Write instruction, poll for a response file that a human-driven editor produces |
| **Callable** | `AgentBackend.invoke(request)` | `FixtureAgentBackend`, `CursorCliAgentBackend` | One `invoke` per turn returns a structured proposal synchronously — no manual waiting |

Callable backends are adapted onto the existing tick machine by
`CallableBackendTransport`: `write_instruction` invokes the backend once (one safe tick
step, no hidden loop) and stashes the proposal; `read_response_if_changed` hands that text
back for ingest. The high-autonomy state machine is therefore reused unchanged for both
shapes.

## The abstraction

`admissible/agent_backend.py`:

- **`AgentInvocationRequest`** — `instruction_text`, `session_id`, `turn_number`,
  `instruction_id`, `target_workspace_path`, `agent_workspace_path`, `constraints`,
  `max_output_bytes`, `timeout_seconds`.
- **`AgentInvocationResult`** — `status` (`success` / `unavailable` / `timeout` / `failed` /
  `malformed` / `blocked_by_configuration`), `response_text`, `raw_stdout` / `raw_stderr`,
  `exit_code`, `model_label`, `transport_label`, `started_at` / `completed_at`,
  `error_message`.
- **`AgentBackend`** — `backend_id`, `label`, `availability()`, `invoke(request)`,
  `status_snapshot()`.

### Backends

- **`FixtureAgentBackend`** — deterministic scripted responses for tests. No subprocess, no
  provider. Exhaustion reports `unavailable` (never crashes); `set_next_status` forces a
  status to exercise retry / pause paths.
- **`FileBridgeAgentBackend`** — compatibility wrapper over the legacy file bridge. Its
  `availability()` says **external / manual / semi-autonomous** honestly; `invoke` writes the
  instruction and reads any response already present, but never blocks for or drives an
  agent. The existing `FileBridgeAgentTransport` is untouched and still the default pull
  transport.
- **`CursorCliAgentBackend`** — the callable Cursor CLI / headless backend, **disabled unless
  explicitly configured**.

## Cursor CLI discovery / configuration

Nothing hard-codes Cursor CLI syntax. The command and its argument template are
operator-supplied via the environment, so the backend never *guesses* an unverified command
shape.

| Env var | Meaning |
|---|---|
| `ADMISSIBLE_CURSOR_CLI_COMMAND` | Path to the Cursor CLI executable |
| `ADMISSIBLE_CURSOR_CLI_ARGS` | argv template (JSON list, e.g. `["agent","--instructions","{instruction_file}"]`) |
| `ADMISSIBLE_CURSOR_CLI_VERSION_ARGS` | version/help probe args (default `["--version"]`) |
| `ADMISSIBLE_CURSOR_CLI_INPUT_MODE` | `instruction_file` (default) or `stdin` |
| `ADMISSIBLE_CURSOR_CLI_OUTPUT_MODE` | `stdout` (default) or `response_file` |
| `ADMISSIBLE_CURSOR_CLI_MODEL_LABEL` | display label for the model |

Placeholders substituted in the argv template — always with paths **inside the agent
workspace**: `{instruction_file}`, `{response_file}`, `{agent_workspace}`.

This is distinct from `ADMISSIBLE_CURSOR_LAUNCHER` (used by `cursor_bridge` to open the
Cursor *GUI*): those open a window; these drive a headless CLI.

No provider credentials are hard-coded anywhere. To configure a backend you set the command
path + argv template for a CLI you have already authenticated separately; Admissible passes
the child process only a small OS-essential environment allowlist (PATH, HOME/USERPROFILE,
SYSTEMROOT, TEMP, …), so API keys and unrelated secrets in the parent environment are **not**
leaked to the spawned agent.

### Safe configuration ladder

`CursorCliConfig` reports exactly why it is not usable instead of guessing:

1. `ADMISSIBLE_CURSOR_CLI_COMMAND` unset → `not_configured` → `invoke` returns
   `blocked_by_configuration`.
2. Configured command not found on disk / PATH → `unavailable`.
3. No argv template, or a template that does not reference `{instruction_file}` in
   instruction-file mode → `unsupported` → `blocked_by_configuration` (refuses to guess).
4. All present → `available`.

### Invocation safety

`CursorCliAgentBackend.invoke` always runs:

```python
subprocess.run(argv, shell=False, timeout=..., cwd=agent_workspace_path,
               capture_output=True, text=True, env=<sanitized>)
```

- `shell=False`, fixed argv list — no shell string, no arbitrary shell execution of model
  proposals.
- `timeout` enforced; timeouts are reported as `timeout`, not raised.
- stdout/stderr capped to `max_output_bytes`.
- `cwd` is the **agent** workspace, never the target workspace — and the backend refuses to
  run when the agent workspace resolves to the target workspace.
- Unit tests inject `runner` or patch `subprocess.run`; a real Cursor CLI is never spawned in
  tests.

## Target workspace vs agent workspace

- **Target workspace** (`target_workspace_path`) — where admitted writes are applied, and
  **only** by Admissible's bounded executor.
- **Agent workspace** (`agent_workspace_path`) — an isolated location used only to hand the
  instruction to the agent and receive its structured proposal. Default:
  `<target>/.admissible/agent_workspace`.

The agent proposes; Admissible decides what may be admitted; only the bounded executor
writes to the target workspace. A backend never receives direct write authority over the
target workspace. `assess_workspace_safety(...)` enforces the pairing:

- **Blocking** — no target workspace; target does not exist; target looks like the agent-os
  repo (unless explicitly allowed); agent workspace equals target workspace in high-autonomy
  mode.
- **Warning** — agent workspace equals target workspace outside high-autonomy mode.

## Workspace-first Control Surface

The target workspace and agent backend are now first-class fields in the primary
high-autonomy panel (`state_view()["agent_backend_control"]`), not an Advanced setting:

- Target workspace input (top-level), with live status (missing / looks-like-repo / ready).
- Agent backend selector — File bridge (external), Cursor CLI (only when configured),
  Fixture (test-only, not offered as a start default).
- Agent workspace path + backend status.
- A start gate that lists the blocking reasons / warnings before **Start** is enabled.

The high-autonomy panel surfaces: Target workspace, Agent backend, Agent workspace, Backend
status, Current step, Blocking reason, Human action required, Evidence count, Verification
readiness. Everything verbose stays under Advanced / Debug.

## Truth-boundary wording

Because low-risk local writes may now be auto-executed by Admissible in high-autonomy mode,
the header no longer claims "No executor" / "No side effect by Admissible". The truthful
wording is:

- **No arbitrary executor**
- **No shell/npm/network/deploy**
- **Only admitted low-risk local writes may be auto-executed in high-autonomy mode**
- **Human-critical actions still stop**

## Safety around model output (unchanged guarantees)

Regardless of backend, response text goes through the existing
ingest → extraction → admission path; there is no direct workspace mutation; low-risk writes
run only through the bounded executor; human-critical actions pause and are never
auto-approved; malformed output triggers a bounded retry then failure; and file-bridge
stale/duplicate handling is preserved. When a callable backend cannot make progress
(`blocked_by_configuration` / `unavailable` / `timeout` / `failed`) the loop **pauses with a
clear reason** rather than spinning.

## What remains before a fully live Cursor CLI high-autonomy run

1. A verified Cursor CLI (or headless) command + argv template on the operator's machine,
   set via the environment variables above — Admissible does not ship one.
2. Confirmation of the CLI's proposal-only / read-only contract so the agent cannot mutate
   the target workspace even in principle (the abstraction already withholds target write
   authority; a reliable CLI-side read-only mode makes that defense-in-depth).
3. Real-run latency/robustness tuning (timeouts, output caps) for the specific CLI.

Until then, Cursor CLI is a configured-but-unshipped target; the file bridge remains the
semi-autonomous default and the fixture backend covers the loop in tests.

## Tests

- `tests/test_admissible_model_agnostic_agent_transport.py` — fixture backend determinism;
  Cursor CLI unavailable/blocked when unconfigured; subprocess `shell=False` + timeout + cwd
  = agent workspace + sanitized env; output ingested-not-executed; agent workspace isolation;
  two-turn callable loop with no manual waiting; low-risk writes executed only by the bounded
  executor; npm/deploy recovery; human-critical pause; backend-block pause.
- `tests/test_admissible_workspace_first_ui.py` — `agent_backend_control` state view, Start
  gating (missing target, agent-os repo target), top-level workspace/backend markup, and the
  truthful truth-boundary wording.
