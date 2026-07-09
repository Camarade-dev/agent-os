# Admissible Cursor File Bridge v0

## Purpose

The Supervised Run Loop (`docs/admissible-supervised-run-loop.md`) can
generate a "Next Agent Instruction Packet," but until now a human had to
manually select and copy that packet out of the Control Surface browser tab,
paste it into Cursor, wait for a reply, then copy Cursor's response back
into the Control Surface's paste textarea. `ADMISSIBLE_CURSOR_BRIDGE_V0`
removes that copy/paste step by routing the same packet/response text
through two stable files in the target workspace instead:

```
<workspace>/.admissible/next-agent-instruction.md   Admissible writes this; Cursor reads it.
<workspace>/.admissible/agent-response.md           Cursor writes this; Admissible reads it.
```

A human still has to tell Cursor to read the instruction file and write its
reply to the response file, and still has to click "Ingest response file"
(or run `--ingest-response`) once Cursor is done. Nothing about the
underlying trust model changes: the response file is still
`unverified_agent_output`, and it still only becomes queue items through the
same offline builder/evaluator (`long_run_envelope_builder.build_from_raw_output`
+ `evaluator.rules_only.evaluate_envelope`) the manual paste path has always
used.

## What v0 is

- A **file bridge**: write the next instruction packet to a file, read an
  agent response back from a file.
- A **clipboard helper**: copy the next instruction packet to the OS
  clipboard (via stdlib Tk, no subprocess), with a stdout fallback.
- An **open-workspace helper**: launch Cursor on a workspace path, only if a
  Cursor executable is explicitly configured or discoverable at a
  well-known location -- never a shell command, never guessed.

## What v0 is not

- **Not a provider integration.** It never calls Cursor's API, Claude Code,
  Codex, Gemini, OpenAI, or any network provider. There is no HTTP client to
  any of those in `admissible/runner/cursor_bridge.py`.
- **Not a command executor.** It never runs a project command (build, test,
  lint, install) and never runs a command proposed inside an ingested agent
  response. The only process this module ever starts is an already-installed
  Cursor editor binary, launched with a fixed argv and `shell=False` --  the
  workspace path is validated to be an existing directory before it is ever
  passed as an argument.
- **Not automatic agent control.** Writing the instruction file and reading
  the response file are two separate, explicit, user-triggered actions (CLI
  flags or UI buttons). Nothing polls, watches a directory, or loops.
- **Not a weaker admission gate.** `--ingest-response` calls
  `ControlSurfaceController.ingest_agent_response` unmodified -- the exact
  same code path the browser's "Ingest response" button already uses.
  `REFUSE` / `REQUIRE_HUMAN_APPROVAL` / `REQUEST_MORE_EVIDENCE` are exactly
  as blocking as before.
- **Not a mutation of prior decisions.** The bridge produces no admission
  decisions of its own; it only moves packet/response text through files and
  delegates to the existing run loop.

A future direct Cursor adapter (driving Cursor's own agent/automation APIs,
if any) is explicitly out of scope for v0 and would need its own separate,
explicitly-gated design -- it is not an incremental extension of this file
bridge.

## CLI

```
python -m admissible.runner.cursor_bridge --write-instruction <workspace-path>
python -m admissible.runner.cursor_bridge --ingest-response <workspace-path>
python -m admissible.runner.cursor_bridge --copy-next-instruction
python -m admissible.runner.cursor_bridge --open-workspace <workspace-path>
```

`--write-instruction <workspace-path>`

- Loads the persisted Control Surface session (if one exists at the default
  `.admissible/control_surface_sessions/session.json`, or `--session-dir`),
  so it continues the same goal/plan/queue/turn state a running Control
  Surface server or a previous bridge invocation already built up.
- Calls `generate_next_instruction_packet()` unmodified (advances the turn).
- Writes `<workspace-path>/.admissible/next-agent-instruction.md`: the
  packet text, plus a short block telling Cursor exactly where to write its
  response (`<workspace-path>/.admissible/agent-response.md`) and reminding
  it that Admissible does not execute anything on its behalf.
- Executes nothing.

`--ingest-response <workspace-path>`

- Requires `<workspace-path>/.admissible/agent-response.md` to exist and be
  non-empty; raises a clear, specific error otherwise (it never silently
  no-ops).
- Reads the file and calls `ingest_agent_response(raw_text)` unmodified.
- Prints a JSON ingestion summary: turn number, response record id, how many
  action candidates were extracted, their action ids, and their decisions.
- Executes nothing proposed inside the response file.

`--copy-next-instruction`

- Generates the next instruction packet and copies it to the clipboard using
  stdlib `tkinter` only (no subprocess, no `pyperclip`, no shell tool).
- If no clipboard is available (e.g. a headless environment), prints the
  packet text to stdout instead so the operation still succeeds.

`--open-workspace <workspace-path>`

- Validates the workspace path exists.
- Looks for a Cursor launcher in this order: the `ADMISSIBLE_CURSOR_LAUNCHER`
  environment variable (an explicit full path to a Cursor executable), then
  a small set of well-known per-OS install locations, then `cursor` on
  `PATH`.
- If found: launches it as `[launcher, workspace_path]` with `shell=False`.
  No shell string is ever built; no part of the command is derived from an
  agent response or workspace content.
- If not found: prints a clear fallback message (open Cursor manually, or
  set `ADMISSIBLE_CURSOR_LAUNCHER`) and does not raise.

Both `--write-instruction` and `--ingest-response` accept `--session-dir`
and `--repo-root` to point at a non-default Admissible session location
(mainly for tests and multi-session setups).

## UI integration

`admissible/harness/control_surface.html`'s Run Loop panel gained a "Cursor
file bridge (optional)" section, below the existing manual paste textarea
(which is unchanged and still works on its own):

- A **workspace path** text input, shared by the three buttons below it.
- **Write packet file** -- `POST /api/session/run_loop/bridge/write_instruction`.
- **Ingest response file** -- `POST /api/session/run_loop/bridge/ingest_response`.
- **Open workspace in Cursor** -- `POST /api/session/run_loop/bridge/open_workspace`.
- A status line reporting the last bridge operation's result.

These three routes, added to `admissible/runner/control_surface.py`, call
the same `admissible.runner.cursor_bridge` functions as the CLI, but against
the server's already-running, in-memory `ControlSurfaceController` (so the
browser session and the file bridge always agree on the current turn/queue,
with no separate session file to go stale).

## Architecture

```
admissible/runner/cursor_bridge.py       file/clipboard/open-workspace bridge (CLI + reusable functions)
admissible/runner/control_surface.py     3 new POST routes delegating to cursor_bridge
admissible/control_surface.py            ControlSurfaceController.session_file (new, read-only) -- lets the
                                          CLI load the same on-disk session the running server persists
admissible/harness/control_surface.html  "Cursor file bridge (optional)" section in the Run Loop panel
```

## Acceptance boundary

- A human no longer has to manually select/copy the packet out of the
  browser to get it to Cursor, or manually paste Cursor's reply back in --
  the file bridge (or the UI buttons backed by it) does that instead.
- Cursor is told, in the instruction file itself, exactly where to write its
  response.
- Admissible ingests that response file through the unmodified supervised
  run loop / extraction builder.
- Nothing is executed by Admissible at any point in this flow -- not a
  project command, not a command proposed by Cursor, not a call to Cursor's,
  Claude Code's, Codex's, Gemini's, or OpenAI's API.
