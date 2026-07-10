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
  `error_message`, plus prompt/file/hash/length/duration diagnostics for callable CLI runs.
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
| `ADMISSIBLE_CURSOR_CLI_INPUT_MODE` | Generic backends: `instruction_file`, `stdin`, or `prompt_arg`; Cursor Agent is normalized to `file_pointer_always` |
| `ADMISSIBLE_CURSOR_CLI_OUTPUT_MODE` | `stdout` (default) or `response_file` |
| `ADMISSIBLE_CURSOR_CLI_MODEL_LABEL` | display label for the model |

Placeholders substituted in the argv template — always with paths **inside the agent
workspace**: `{instruction_file}`, `{response_file}`, `{agent_workspace}`.

This is distinct from `ADMISSIBLE_CURSOR_LAUNCHER` (used by `cursor_bridge` to open the
Cursor *GUI*): those open a window; these drive a headless CLI.

### Cursor Agent CLI safe preset (slice ADMISSIBLE_RUN_033)

The real local Cursor Agent CLI is **`cursor-agent`** — *not* `cursor agent` (the `cursor`
command is the IDE wrapper and does not expose the real Agent CLI). Admissible drives it only
in **read-only planning mode**: it analyzes and proposes plans; it does not edit files. The
model proposes; only Admissible's bounded executor writes to the target workspace.

Safe preset (`cursor_agent_cli_preset_env()` / `CursorCliConfig.cursor_agent_preset()`):

- command: `cursor-agent`
- args: `--print --output-format text --mode plan --workspace {agent_workspace} --trust {prompt}`
- input mode: `file_pointer_always`. The complete governed instruction is always written to
  `<agent_workspace>/.admissible/next-agent-instruction.md`. `{prompt}` is always **one
  single-line** adapter argv element containing the absolute instruction path. It requires the
  complete proposal on stdout, forbids all file writes (including `.admissible/agent-response.md`),
  and requires every `ADMISSIBLE_STRUCTURED_OPERATION` block directly on stdout. The adapter must
  contain no CR, LF, TAB, or NUL — multiline adapters are rejected before invocation.
- Cursor Agent does **not** use `PROMPT_ARG_MAX_CHARS`. Medium and long instructions follow
  the same pointer contract. Threshold-based inline support remains available only to generic
  headless backends.
- output: `--output-format text` → stdout is captured verbatim as `response_text` and ingested
  through the unchanged extraction/admission path; stdout is never treated as executed.

PowerShell configuration:

```powershell
$env:ADMISSIBLE_CURSOR_CLI_COMMAND = "cursor-agent"
$env:ADMISSIBLE_CURSOR_CLI_ARGS = "--print --output-format text --mode plan --workspace {agent_workspace} --trust {prompt}"
$env:ADMISSIBLE_CURSOR_CLI_MODEL_LABEL = "cursor-agent-default"
```

### Cursor CLI safety validation

`assess_cursor_cli_safety(command_path, args_template)` is defense-in-depth on top of the
workspace separation and the ingest/admission path. It **blocks** configuration when the argv:

- contains `--force` or `--yolo`;
- contains `--sandbox disabled`;
- is `cursor` with an `agent` subcommand (use `cursor-agent`);
- has a `--workspace` value that is not the `{agent_workspace}` placeholder;
- (for `cursor-agent`) is missing `--print`, or missing `--mode plan` / `--plan`.

It **warns** (visible, still allowed) when `--output-format` is not text/json, or `--model` is
absent (the CLI uses its default model). A blocked config makes the backend report
`unsupported` / `blocked_by_configuration` and it is **never invoked**.

No provider credentials are hard-coded anywhere. To configure a backend you set the command
path + argv template for a CLI you have already authenticated separately; Admissible passes
the child process only a **Windows-aware safe environment allowlist** (PATH, PATHEXT, COMSPEC,
SystemRoot/WINDIR, SystemDrive, USERPROFILE/HOME, APPDATA, LOCALAPPDATA, ProgramData,
ALLUSERSPROFILE, PUBLIC, TEMP/TMP, locale/TERM vars), so API keys and unrelated secrets in
the parent environment are **not** leaked to the spawned agent.

### Windows-safe Cursor Agent environment (slice ADMISSIBLE_RUN_036)

Live evidence showed that Admissible's earlier minimal allowlist omitted Windows profile
variables (`SystemDrive`, `APPDATA`, `LOCALAPPDATA`, `ProgramData`, …). When Cursor Agent
inherited that sanitized environment, nested references such as
`%SystemDrive%\ProgramData\Microsoft\Windows\Caches` were **not expanded**, producing invalid
literal paths. That was a real Windows hardening defect and is fixed below — but subsequent
live A/B evidence (slice `ADMISSIBLE_RUN_037`) showed it was **not** the sole cause of empty
stdout when the governed instruction file itself was valid.

`build_cursor_agent_safe_environment()` now:

- preserves the allowlisted variables using **case-insensitive** parent lookup with stable
  canonical output names;
- expands nested `%NAME%` references recursively (bounded, no shell, no `cmd /c`);
- **blocks** invocation when a path-like value still contains an unresolved `%NAME%` token;
- validates path-like variables after expansion;
- persists safe diagnostics (`environment_status`, `environment_variable_names`,
  `unresolved_environment_variables`, `cursor_profile_environment_present`,
  `program_data_path_present`, scoped `environment_paths`) — never the full environment or
  secret values;
- does **not** forward `CURSOR_API_KEY` or other unrelated application secrets.

`probe_cursor_agent_cli_environment()` runs `cursor-agent --version` with the **same** safe
env and `cwd` as a real invocation (`shell=False`, no model call). Use it for operator smoke
tests and unit diagnostics — it is not run automatically on every tick.

Why manual PowerShell worked but Admissible did not (environment slice): PowerShell inherits
the full Windows profile environment; Admissible deliberately strips secrets and only forwards
the allowlist. Without `SystemDrive` / profile paths present and expanded, Cursor Agent could not
resolve its local profile/cache locations.

### Single-line Cursor Agent file-pointer adapter (slice ADMISSIBLE_RUN_037)

Further live A/B evidence on Windows isolated the remaining empty-stdout failure:

1. Python resolves `cursor-agent` to `cursor-agent.CMD`.
2. The wrapper chain is `cursor-agent.cmd` → `powershell.exe -NoProfile -ExecutionPolicy Bypass -File cursor-agent.ps1 %*` → `node.exe index.js $args`.
3. Through that exact `.CMD`, a short inline smoke prompt succeeds; a **strictly one-line**
   file-pointer adapter succeeds and returns a complete structured proposal; Admissible's
   earlier **multiline** file-pointer adapter returned exit code 0, empty stderr, and stdout
   containing only a newline — even when the instruction file was valid and readable.

The final root cause is **command-line argument serialization** of a multiline `{prompt}` adapter
across the `.cmd → PowerShell -File → Node` forwarding boundary. Direct Node invocation is **not**
required: the current `.CMD` works when `{prompt}` is one argv line.

Contract:

- `{prompt}` is built by `build_cursor_agent_file_pointer_adapter()` as fixed application text
  plus the absolute instruction path in double quotes — no heredoc, no embedded governed
  instruction body.
- `validate_cursor_agent_file_pointer_adapter()` blocks invocation when the adapter contains
  CR, LF, TAB, or NUL, or when `adapter_line_count != 1`.
- Durable diagnostics persist `adapter_prompt_length`, `adapter_line_count` (expected `1`),
  `adapter_contains_crlf` (expected `false`), and `adapter_sha256` — never secrets or the full
  environment.

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
- Durable diagnostics record `prompt_mode=file_pointer`, the absolute instruction path,
  instruction sha256, adapter/full-instruction/stdout lengths, adapter line count,
  `adapter_contains_crlf`, optional `adapter_sha256`, exit code, and invocation duration.
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

## Durable callable-response handoff across ticks (slice ADMISSIBLE_RUN_034)

A callable backend is invoked *synchronously* during the write step, so the
response exists at the end of tick N. But the Control Surface reconstructs the
controller / backend / transport between HTTP ticks (a fresh controller per
request, or after a server restart). If the pending response lived only on the
in-memory transport, it was lost on reconstruction and the loop waited forever
(`ingest_response` → `noop_waiting`, indefinitely).

The fix persists the response in durable run state, not on the transport:

- **`AgentInvocationRecord`** (in the run state, serialized with the session):
  `invocation_id`, `instruction_id`, `backend_id`, `session_id`, `turn_number`,
  `status` (`invoking` / `response_ready` / `consumed` / `timeout` / `failed` /
  `malformed`), `response_text`, `response_sha256`, stdout/stderr summaries,
  timestamps, `consumed_at`, and the callable transport diagnostics listed above.

State transitions per turn (callable backend):

```
tick N     : build instruction → invoke backend once → persist record
             (status=response_ready, sha256) → end tick in "response_ready"
             (NOT the file-bridge "waiting for a response file")
tick N+1   : load persisted record after reconstruction → ingest exactly once
             through the existing extraction/admission path → mark "consumed"
             → continue to admission / auto-execution
```

**Exactly-once guarantees:**

- one backend invocation per instruction (the planner ingests a `response_ready`
  record instead of re-planning a write, so it never re-invokes);
- one ingestion per `invocation_id` + `response_sha256` (a `consumed` record is
  never re-ingested);
- repeated ticks after `response_ready` do not re-invoke; repeated ticks after
  consumption do not re-ingest.

**Reconstruction:** a fresh controller has no in-memory transport. The transport
is rebuilt best-effort from `backend_id` + workspace when a *new* invocation is
needed; ingesting an already-persisted response needs no live transport at all,
so a reconstructed controller ingests the pending response without re-invoking.

**Callable vs file bridge:** only the file bridge is
`waiting_for_external_response`. Callable backends move through
`invoking_agent` → `response_ready` → `ingesting_response` → `response_consumed`
and never display "waiting for a response file".

**Failure behavior:** terminal callable statuses (`malformed`, `failed`, `timeout`,
`blocked_by_configuration`, `unavailable`, empty stdout / no usable response) pause
immediately with `last_tick_step=backend_error`, `backend_retry_required=true`, and
`auto_tick_safe=false`. The UI shows backend diagnostics (invocation id, exit code,
duration, stdout bytes, stderr summary, environment status) and **never** uses file-bridge
wording such as "Agent must write `.admissible/agent-response.md`". **Resume alone does not
re-invoke** — the operator must click **Retry backend invocation**, then **Step once** to
dispatch a new instruction. Ordinary ticks never alternate between `wait_for_agent_response`
and `ingest_response` after a terminal failure. A response that parses into no admissible
operations still takes the existing bounded malformed retry during *ingest*, then fails.

## Safety around model output (unchanged guarantees)

Regardless of backend, response text goes through the existing
ingest → extraction → admission path; there is no direct workspace mutation; low-risk writes
run only through the bounded executor; human-critical actions pause and are never
auto-approved; malformed output triggers a bounded retry then failure; and file-bridge
stale/duplicate handling is preserved. When a callable backend cannot make progress
(`blocked_by_configuration` / `unavailable` / `timeout` / `failed`) the loop **pauses with a
clear reason** rather than spinning.

## Live Cursor Agent contract and operator retry

Slice `ADMISSIBLE_RUN_035_CURSOR_AGENT_FILE_POINTER_AND_EXPLICIT_GOAL_SCOPE_FIX` incorporates
the first live-run transport evidence: a short smoke prompt returned normally; a 4,495-character
raw positional instruction exited 0 with newline-only stdout; a short prompt pointing to that
same instruction file returned the complete structured proposal. The supported contract is
therefore file-pointer input plus stdout output.

For a paused empty-stdout invocation, retry is operator-driven:

1. Confirm the persisted invocation diagnostics show `prompt_mode=file_pointer`, the expected
   instruction path/hash, `adapter_line_count=1`, `adapter_contains_crlf=false`, exit code,
   stdout length, and duration.
2. Confirm the safe preset still reports available and the instruction file contains the full
   governed packet.
3. In the Control Surface, click **Resume**, then **Step once** (or re-enable auto-run). Resume
   is the explicit operator retry authority; ordinary ticks while paused never re-invoke.
4. Verify the new invocation reaches `response_ready`, then `response_consumed`, exactly once.

### Optional manual operator smoke (do not run from tests)

```
cursor-agent --print --output-format text --mode plan --workspace <agent_workspace> --trust "Reply with exactly: ADMISSIBLE_CURSOR_AGENT_SMOKE_OK"
```

If it prints `ADMISSIBLE_CURSOR_AGENT_SMOKE_OK`, the local CLI is wired correctly for
Admissible's read-only proposal path. This only checks CLI availability; governed instructions
still use the file-pointer adapter. The fixture and mocked-subprocess backends cover the loop
in tests and never invoke the real CLI/provider.

## Tests

- `tests/test_admissible_model_agnostic_agent_transport.py` — fixture backend determinism;
  Cursor CLI unavailable/blocked when unconfigured; subprocess `shell=False` + timeout + cwd
  = agent workspace + sanitized env; output ingested-not-executed; agent workspace isolation;
  two-turn callable loop with no manual waiting; low-risk writes executed only by the bounded
  executor; npm/deploy recovery; human-critical pause; backend-block pause.
- `tests/test_admissible_cursor_agent_cli_backend.py` — the `cursor-agent` safe preset,
  safety validation (rejects `--force`/`--yolo`/`--sandbox disabled`, requires
  `--print` + plan mode, `cursor-agent` not `cursor agent`, `{agent_workspace}` workspace),
  subprocess mechanics, stable file-pointer prompt, stdout→ingest, and a two-turn
  high-autonomy loop driven by a mocked Cursor Agent CLI.
- `tests/test_admissible_cursor_agent_file_pointer_contract.py` — medium/long stable pointer
  transport, paths with spaces as one argv element under `shell=False`, adapter write bans,
  persisted diagnostics, stdout ingest, and empty-stdout pause without automatic reinvocation.
- `tests/test_admissible_cursor_agent_single_line_adapter.py` — single-line adapter generation,
  forbidden-character rejection, one argv element with spaced paths, multiline adapter blocked
  before subprocess, and adapter diagnostics persistence.
- `tests/test_admissible_workspace_first_ui.py` — `agent_backend_control` state view, Start
  gating (missing target, agent-os repo target), top-level workspace/backend markup, and the
  truthful truth-boundary wording.
- `tests/test_admissible_callable_backend_response_persistence.py` — durable handoff: a real
  controller reconstructed between dispatch and ingest still ingests the persisted response
  exactly once; no re-invoke / no re-ingest across repeated ticks; export/import retains the
  pending response; invocation record turn/instruction/sha alignment; callable UI never says
  "waiting for a response file"; file-bridge semantics unchanged.

## Run 038 empty-success, UTF-8, and single-flight guarantees

Callable results distinguish `empty_success` from malformed agent content. `empty_success`
means exit code 0, empty/whitespace-only response text, and empty or non-fatal stderr. The
invocation record persists attempt number, retry lineage, instruction id and sha256, an
explicit `estimated_cost: unknown` marker, and the operator retry count.

The default is `automatic_empty_success_retries = 0`: the run pauses and does not incur a
hidden second invocation. An operator retry reuses the exact instruction packet/id/text and
creates one new invocation id linked through `retry_of_invocation_id`; the empty attempt has
no response to ingest, and the successful attempt is still consumed exactly once. Operators
may explicitly configure one visible automatic empty-success retry; values above one are
rejected.

Cursor CLI stdout/stderr capture specifies `encoding="utf-8"` and `errors="replace"` while
remaining `shell=False`. Instruction/response files, persisted session JSON, HTTP JSON, and
browser exports are UTF-8; HTTP and HTML declare UTF-8 explicitly.

`ControlSurfaceController.tick_high_autonomy_run()` has a non-blocking per-session lock.
Concurrent Step/auto-run requests return `tick_already_in_progress` and never invoke the
backend twice. The browser disables Start, Step, Retry, and Auto-run while a request is in
flight, prevents Step and auto-run overlap, and displays “Backend invocation in progress.”

## Portable environment diagnostics (Run 040)

Invocation records expose canonical environment path keys (`SystemRoot`, `SystemDrive`,
`ProgramData`, `USERPROFILE`, …) with case-insensitive deduplication before persistence and
export. When multiple spellings observed the same value, aliases are stored in
`environment_path_aliases` rather than duplicate JSON object keys — keeping exports parseable
by PowerShell as well as Python.
