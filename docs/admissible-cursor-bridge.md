# Admissible Cursor File Bridge v0

## Purpose

The Supervised Run Loop (`docs/admissible-supervised-run-loop.md`) can
generate a "Next Agent Instruction Packet," but manually selecting/copying
that packet out of the Control Surface browser tab, pasting it into Cursor,
waiting for a reply, then copying Cursor's response back into a paste
textarea is slow and easy to get wrong. `ADMISSIBLE_CURSOR_BRIDGE_V0`
removes that copy/paste step by routing the same packet/response text
through two stable files in the target workspace instead:

```
<workspace>/.admissible/next-agent-instruction.md   Admissible writes this; Cursor reads it.
<workspace>/.admissible/agent-response.md           Cursor writes this; Admissible reads it.
<workspace>/.admissible/bridge-state.json           Bridge diagnostics only -- turn/session/hash bookkeeping.
```

This file bridge is the **canonical, single visible workflow** in the
Control Surface UI. Manual copy/paste still exists, but only inside a
collapsed "Advanced manual paste fallback" section, for debugging or when a
file bridge isn't usable.

A human still has to tell Cursor to read the instruction file and write its
reply to the response file, and still has to click "Ingest Cursor response
file" (or run `--ingest-response`) once Cursor is done. Nothing about the
underlying trust model changes: the response file is still
`unverified_agent_output`, and it still only becomes queue items through the
same offline builder/evaluator (`long_run_envelope_builder.build_from_raw_output`
+ `evaluator.rules_only.evaluate_envelope`) the manual paste path has always
used.

## What v0 is

- A **file bridge**: write the next instruction packet to a file, read an
  agent response back from a file. Every write/read is independently
  verified after the fact (re-read off disk, not assumed) and reported as
  an absolute path, an exists flag, a byte count, a SHA256 digest, and a
  modified timestamp.
- A **read-only workspace check**: report whether a workspace path exists
  and what its `.admissible/` directory looks like, without writing
  anything -- backs the UI's live workspace status.
- A **clipboard helper** (advanced fallback only): copy the next
  instruction packet to the OS clipboard (via stdlib Tk, no subprocess),
  with a stdout fallback.
- An **open-workspace helper**: launch Cursor on a workspace path, only if a
  Cursor executable is explicitly configured or discoverable at a
  well-known location -- never a shell command, never guessed, and it never
  runs a project command.

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
  same code path the browser's ingest button already uses.
  `REFUSE` / `REQUIRE_HUMAN_APPROVAL` / `REQUEST_MORE_EVIDENCE` are exactly
  as blocking as before. `bridge-state.json` is diagnostics only: it can
  only ever produce a non-blocking *warning*, never a gate, and it is never
  consulted by an admission decision.
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
- Writes/updates `<workspace-path>/.admissible/bridge-state.json` with the
  session id, turn, instruction path, instruction SHA256, `written_at`, and
  the expected response path.
- Prints the written path, byte count, SHA256, modified time, and turn
  number. Executes nothing.

`--ingest-response <workspace-path>`

- Requires `<workspace-path>/.admissible/agent-response.md` to exist and be
  non-empty; exits non-zero with a clear message otherwise (it never
  silently no-ops).
- Reads the file and calls `ingest_agent_response(raw_text)` unmodified.
- Prints the read path, byte count, SHA256, modified time, how many action
  candidates were extracted, their decision summary, any staleness
  warnings, and "Nothing was executed by Admissible." -- then a full JSON
  dump of the same facts.
- Updates `bridge-state.json`'s `last_ingested_turn` /
  `last_ingested_response_sha256` / `last_ingested_at` (diagnostics only).
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

**Exit codes:** every CLI operation returns 0 on success and 1 with a clear
stderr message on: a missing/non-directory workspace, a missing response
file, an empty response file, or a persisted session file that cannot be
parsed/loaded (`InvalidSessionFileError`).

## UI integration

`admissible/harness/control_surface.html` has one top-level workflow card,
**"Cursor supervised file bridge"** -- this is the canonical, single visible
path:

1. **Workspace** -- a path input with a live status (workspace exists?,
   expected `.admissible/` directory, whether it already exists), backed by
   the read-only `check_workspace` route (debounced on input, and on blur).
2. **Write instruction file** -- `POST .../bridge/write_instruction`. Status
   shows success/failure, the absolute path written, exists, bytes, SHA256,
   modified time, turn number, a preview of the first 5 lines, and the next
   step: "Now ask Cursor to read `.admissible/next-agent-instruction.md`
   and write its response to `.admissible/agent-response.md`."
3. **Open workspace in Cursor** -- `POST .../bridge/open_workspace`. Only
   launches Cursor; runs no project command.
4. **Ingest Cursor response file** -- `POST .../bridge/ingest_response`. If
   the response file is missing, shows "No response file found." and the
   expected path. If present, shows the absolute path read, exists, bytes,
   SHA256, modified time, turn, extracted candidate count, added action
   ids, decision summary, any staleness warnings, and "Nothing was executed
   by Admissible."

Manual copy/paste (generate a packet as text, copy it, paste Cursor's reply
back into a textarea) lives inside a collapsed **"Advanced manual paste
fallback"** `<details>` in the same panel -- functional, but never the
default visible path.

These four routes, in `admissible/runner/control_surface.py`, call the same
`admissible.runner.cursor_bridge` functions as the CLI, but against the
server's already-running, in-memory `ControlSurfaceController` (so the
browser session and the file bridge always agree on the current turn/queue,
with no separate session file to go stale). `check_workspace` never touches
the controller -- it is a pure filesystem read.

Error responses from `write_instruction` / `ingest_response` are HTTP 400
JSON bodies with an `"error"` message plus whatever structured `detail`
fields the underlying `CursorBridgeError` carries (e.g. `expected_path`,
`exists`, `bytes`), so the UI can render a specific, verifiable status
instead of a generic failure banner.

## Architecture

```
admissible/runner/cursor_bridge.py       file/clipboard/open-workspace bridge (CLI + reusable functions)
admissible/runner/control_surface.py     4 POST routes delegating to cursor_bridge (check_workspace, write_instruction,
                                          ingest_response, open_workspace); merges CursorBridgeError.detail into 400 bodies
admissible/control_surface.py            ControlSurfaceController.session_file (read-only) -- lets the
                                          CLI load the same on-disk session the running server persists
admissible/harness/control_surface.html  "Cursor supervised file bridge" panel (canonical) + collapsed
                                          "Advanced manual paste fallback" <details>
```

## Acceptance boundary

- A human no longer has to manually select/copy the packet out of the
  browser to get it to Cursor, or manually paste Cursor's reply back in --
  the file bridge (or the UI buttons backed by it) does that instead, and
  that is the one workflow the UI shows by default.
- Cursor is told, in the instruction file itself, exactly where to write its
  response.
- Every bridge write/read is independently verifiable: absolute path,
  exists, byte count, SHA256 digest, modified timestamp -- re-derived from
  disk after the operation, not assumed from what was requested.
- Admissible ingests the response file through the unmodified supervised
  run loop / extraction builder, and always states "Nothing was executed by
  Admissible."
- `bridge-state.json` is bridge diagnostics only -- it can add a warning
  (e.g. a response that looks stale or already-ingested) but can never
  gate, weaken, or otherwise influence an admission decision.
- Nothing is executed by Admissible at any point in this flow -- not a
  project command, not a command proposed by Cursor, not a call to Cursor's,
  Claude Code's, Codex's, Gemini's, or OpenAI's API.
