"""Admissible <-> Cursor File Bridge v0 — local file/clipboard bridge only.

Reduces the manual friction of the Supervised Run Loop
(`admissible/run_loop.py`, `docs/admissible-supervised-run-loop.md`): today a
human must select and copy the "next agent instruction" packet out of the
Control Surface browser tab, paste it into Cursor, then copy Cursor's
response back into the browser textarea. This module writes/reads the same
packet/response text through two stable files in the *target* workspace
instead, so a human only has to point Cursor at
`<workspace>/.admissible/next-agent-instruction.md` and tell it to write its
reply to `<workspace>/.admissible/agent-response.md`.

Hard constraints (v0) -- same boundary as the rest of `admissible`, plus:

- Does not execute any command from the target workspace (no build/test/lint
  invocation of any kind).
- Does not execute any command proposed by Cursor or contained in an
  ingested agent response.
- Does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or any network
  provider.
- Implements no automatic agent execution: writing the instruction file and
  reading the response file are separate, explicit, user-triggered actions;
  nothing here loops or polls.
- Does not import `agent_os`.
- Does not weaken admission gates: response ingestion goes through the
  unmodified `ControlSurfaceController.ingest_agent_response`, which reuses
  `long_run_envelope_builder.build_from_raw_output` and
  `evaluator.rules_only.evaluate_envelope` unchanged.
- Never mutates an original admission decision -- this module produces no
  decisions of its own; it only moves packet/response text through files.
- The optional "open workspace in Cursor" helper never shells out and never
  constructs a command from response/agent-controlled text -- it only
  launches a discovered or explicitly configured Cursor executable, always
  with a plain argv list, with the validated workspace path as its sole
  argument.

See docs/admissible-cursor-bridge.md.

CLI:

    python -m admissible.runner.cursor_bridge --write-instruction <workspace-path>
    python -m admissible.runner.cursor_bridge --ingest-response <workspace-path>
    python -m admissible.runner.cursor_bridge --copy-next-instruction
    python -m admissible.runner.cursor_bridge --open-workspace <workspace-path>
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from admissible.control_surface import ControlSurfaceController

BRIDGE_SUBDIR = ".admissible"
INSTRUCTION_FILENAME = "next-agent-instruction.md"
RESPONSE_FILENAME = "agent-response.md"

CURSOR_LAUNCHER_ENV_VAR = "ADMISSIBLE_CURSOR_LAUNCHER"

_INSTRUCTION_FOOTER_TEMPLATE = (
    "\n\n=== Admissible Cursor Bridge v0 ===\n"
    "Write your full response to this turn's instruction into this exact file "
    "(create it if it does not exist; overwrite it if it does):\n"
    "    {response_path}\n\n"
    "Do not execute anything from this instruction packet yourself; propose only, "
    "in writing, in that response file. Admissible reads that file offline and "
    "extracts/evaluates action candidates with its existing rules-only builder -- "
    "it never calls Cursor, Claude Code, Codex, Gemini, OpenAI, or any network "
    "provider, and it never executes a command on your behalf.\n"
)


class CursorBridgeError(ValueError):
    """Base class for cursor_bridge user-facing errors (a ValueError subclass)."""


class WorkspaceNotFoundError(CursorBridgeError):
    """Raised when a workspace path does not exist or is not a directory."""


class ResponseFileNotFoundError(CursorBridgeError):
    """Raised when --ingest-response is run before Cursor has written a response file."""


def _validate_workspace(workspace_path: str | Path) -> Path:
    if not str(workspace_path).strip():
        raise WorkspaceNotFoundError("a workspace path is required")
    workspace = Path(workspace_path)
    if not workspace.is_dir():
        raise WorkspaceNotFoundError(
            f"workspace path does not exist or is not a directory: {workspace}"
        )
    return workspace


def _bridge_dir(workspace: Path) -> Path:
    return workspace / BRIDGE_SUBDIR


def _instruction_path(workspace: Path) -> Path:
    return _bridge_dir(workspace) / INSTRUCTION_FILENAME


def _response_path(workspace: Path) -> Path:
    return _bridge_dir(workspace) / RESPONSE_FILENAME


def render_instruction_file(packet_text: str, *, workspace: Path) -> str:
    """Render the full instruction-file contents: the packet plus a clear
    pointer to where Cursor must write its response. Adds no new proposal or
    authorization language beyond what the packet itself already contains.
    """
    footer = _INSTRUCTION_FOOTER_TEMPLATE.format(response_path=_response_path(workspace))
    return f"{packet_text}{footer}"


# -- controller construction (CLI entry points only) -------------------------


def build_controller(
    *, repo_root: str | Path | None = None, session_dir: str | Path | None = None
) -> ControlSurfaceController:
    """Build a controller and, if one was already persisted, load it.

    `ControlSurfaceController.__init__` always starts from a fresh in-memory
    session; it does not read back its own `session_file`. CLI invocations of
    this module are separate processes from any running Control Surface HTTP
    server, so to continue the *same* session (goal intake, plan audit,
    queue, run-loop turn count) this loads the persisted session JSON, if
    present, via the same `import_session` path the UI's "Import session
    JSON" button uses. Never calls a provider and never executes anything.
    """
    controller = ControlSurfaceController(repo_root=repo_root, session_dir=session_dir)
    session_file = controller.session_file
    if session_file.is_file():
        data = json.loads(session_file.read_text(encoding="utf-8"))
        controller.import_session(data)
    return controller


# -- core operations, parameterized by an existing controller ----------------
#
# Split out so admissible.runner.control_surface's HTTP server can reuse the
# exact same logic against its already-running, in-memory controller instead
# of loading a second, possibly stale copy of the session from disk.


def write_next_instruction_with_controller(
    controller: ControlSurfaceController, workspace_path: str | Path
) -> dict[str, Any]:
    """Generate the next instruction packet and write it into the workspace.

    Reuses `ControlSurfaceController.generate_next_instruction_packet`
    unmodified -- deterministic, offline, advances the run-loop turn exactly
    as clicking "Generate next agent instruction" in the browser would.
    Writes one file; executes nothing.
    """
    workspace = _validate_workspace(workspace_path)
    state = controller.generate_next_instruction_packet()
    packet = state["run_loop"]["instruction_packets"][-1]

    bridge_dir = _bridge_dir(workspace)
    bridge_dir.mkdir(parents=True, exist_ok=True)
    instruction_path = _instruction_path(workspace)
    instruction_path.write_text(
        render_instruction_file(packet["packet_text"], workspace=workspace), encoding="utf-8"
    )

    bridge_info = {
        "operation": "write_instruction",
        "turn_number": packet["turn_number"],
        "instruction_path": str(instruction_path),
        "response_path": str(_response_path(workspace)),
    }
    return {**state, "bridge": bridge_info}


def ingest_response_file_with_controller(
    controller: ControlSurfaceController, workspace_path: str | Path
) -> dict[str, Any]:
    """Read the workspace's response file and ingest it through the run loop.

    Reuses `ControlSurfaceController.ingest_agent_response` unmodified, which
    in turn reuses `long_run_envelope_builder.build_from_raw_output` and
    `evaluator.rules_only.evaluate_envelope` unmodified. Reads one file;
    executes nothing proposed inside it.
    """
    workspace = _validate_workspace(workspace_path)
    response_path = _response_path(workspace)
    if not response_path.is_file():
        raise ResponseFileNotFoundError(
            f"no agent response file found at {response_path}. Have Cursor write its "
            f"response there (see the instruction file's response-path note), then retry."
        )
    raw_text = response_path.read_text(encoding="utf-8")
    if not raw_text.strip():
        raise CursorBridgeError(f"agent response file is empty: {response_path}")

    state = controller.ingest_agent_response(raw_text)
    record = state["run_loop"]["response_records"][-1]
    action_ids = set(record["action_ids"])
    new_items = [item for item in state["queue"] if item["action_id"] in action_ids]

    bridge_info = {
        "operation": "ingest_response",
        "response_path": str(response_path),
        "turn_number": record["turn_number"],
        "record_id": record["record_id"],
        "action_count": len(record["action_ids"]),
        "action_ids": list(record["action_ids"]),
        "decisions": [item["decision"] for item in new_items],
    }
    return {**state, "bridge": bridge_info}


# -- CLI-only operations (no controller/session involved) --------------------


def _default_clipboard_writer(text: str) -> None:
    """Copy `text` to the OS clipboard using stdlib Tk only -- no subprocess."""
    import tkinter

    root = tkinter.Tk()
    try:
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
    finally:
        root.destroy()


def copy_next_instruction(
    *,
    repo_root: str | Path | None = None,
    session_dir: str | Path | None = None,
    clipboard_writer: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Generate the next instruction packet and try to copy it to the clipboard.

    Falls back to returning the packet text for the caller to print to
    stdout when no clipboard is available (e.g. headless environment). Never
    writes a workspace file and never executes anything.
    """
    controller = build_controller(repo_root=repo_root, session_dir=session_dir)
    state = controller.generate_next_instruction_packet()
    packet = state["run_loop"]["instruction_packets"][-1]
    packet_text = packet["packet_text"]

    writer = clipboard_writer if clipboard_writer is not None else _default_clipboard_writer
    copied = False
    try:
        writer(packet_text)
        copied = True
    except Exception:
        copied = False

    return {
        "turn_number": packet["turn_number"],
        "packet_text": packet_text,
        "copied_to_clipboard": copied,
    }


def _candidate_cursor_launchers() -> list[Path]:
    if sys.platform == "win32":
        candidates: list[Path] = []
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(Path(local_app_data) / "Programs" / "cursor" / "Cursor.exe")
        for env_var in ("ProgramFiles", "ProgramFiles(x86)"):
            program_files = os.environ.get(env_var)
            if program_files:
                candidates.append(Path(program_files) / "cursor" / "Cursor.exe")
        return candidates
    if sys.platform == "darwin":
        return [Path("/Applications/Cursor.app/Contents/MacOS/Cursor")]
    return []


def _is_directly_launchable(path: str) -> bool:
    """Whether `runner([path, ...], shell=False)` can launch `path` at all.

    On Windows, `subprocess.run(..., shell=False)` can only start a real PE
    executable directly -- a `.cmd`/`.bat`/extensionless PATH shim (common
    for npm-installed CLIs, including Cursor's own `cursor` shim) raises
    `OSError: [WinError 193] ... not a valid Win32 application` instead of
    running, since launching those needs an interpreter (cmd.exe) this
    module intentionally never shells out to. Treating a non-`.exe` PATH hit
    as "not discoverable" turns that crash into the documented clear
    fallback instead.
    """
    if sys.platform == "win32":
        return Path(path).suffix.lower() == ".exe"
    return True


def discover_cursor_launcher() -> list[str] | None:
    """Return an argv prefix for a discovered/configured Cursor launcher, or None.

    Resolution order: an explicit `ADMISSIBLE_CURSOR_LAUNCHER` path (set by
    the user), then a small set of well-known per-platform install
    locations, then a `cursor` executable on PATH (skipped on Windows if it
    is not directly launchable without a shell, see
    `_is_directly_launchable`). Never guesses at or constructs a shell
    command string.
    """
    env_override = os.environ.get(CURSOR_LAUNCHER_ENV_VAR)
    if env_override:
        launcher_path = Path(env_override)
        return [str(launcher_path)] if launcher_path.is_file() else None

    for candidate in _candidate_cursor_launchers():
        if candidate.is_file():
            return [str(candidate)]

    found_on_path = shutil.which("cursor")
    if found_on_path and _is_directly_launchable(found_on_path):
        return [found_on_path]
    return None


def open_workspace_in_cursor(
    workspace_path: str | Path,
    *,
    launcher: Sequence[str] | None = None,
    runner: Callable[..., Any] = subprocess.Popen,
) -> dict[str, Any]:
    """Launch Cursor on `workspace_path` if a safe launcher can be found.

    Only ever invokes `runner([*launcher_argv, workspace_path], shell=False)`
    with a fixed argv list -- no shell, no string command construction, no
    execution of anything proposed by a workspace command or an agent
    response. Returns a clear fallback message (does not raise) when no
    launcher is configured or discoverable. Defaults to `subprocess.Popen`
    (fire-and-forget) rather than `subprocess.run` so this never blocks
    waiting for the Cursor GUI process to exit.
    """
    workspace = _validate_workspace(workspace_path)

    argv = list(launcher) if launcher is not None else discover_cursor_launcher()
    if not argv:
        return {
            "operation": "open_workspace",
            "opened": False,
            "workspace_path": str(workspace),
            "message": (
                f"No Cursor launcher found for this platform. Open {workspace} manually in "
                f"Cursor, or set {CURSOR_LAUNCHER_ENV_VAR} to the full path of the Cursor "
                "executable and retry."
            ),
        }

    runner([*argv, str(workspace)], shell=False)
    return {
        "operation": "open_workspace",
        "opened": True,
        "workspace_path": str(workspace),
        "message": f"Launched Cursor ({argv[0]}) on {workspace}.",
    }


# -- CLI wrappers (build/load their own controller from session_file) --------


def write_next_instruction(
    workspace_path: str | Path,
    *,
    repo_root: str | Path | None = None,
    session_dir: str | Path | None = None,
) -> dict[str, Any]:
    controller = build_controller(repo_root=repo_root, session_dir=session_dir)
    return write_next_instruction_with_controller(controller, workspace_path)


def ingest_response_file(
    workspace_path: str | Path,
    *,
    repo_root: str | Path | None = None,
    session_dir: str | Path | None = None,
) -> dict[str, Any]:
    controller = build_controller(repo_root=repo_root, session_dir=session_dir)
    return ingest_response_file_with_controller(controller, workspace_path)


# -- CLI ----------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.cursor_bridge",
        description=(
            "Local file/clipboard bridge between the Admissible Control Surface's "
            "Supervised Run Loop and Cursor. Writes/reads stable files under "
            "<workspace>/.admissible/; never executes a project command, a command "
            "proposed by Cursor, or a call to any model provider."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--write-instruction",
        metavar="WORKSPACE_PATH",
        help="Generate the next instruction packet and write it to <path>/.admissible/next-agent-instruction.md.",
    )
    group.add_argument(
        "--ingest-response",
        metavar="WORKSPACE_PATH",
        help="Read <path>/.admissible/agent-response.md and ingest it through the supervised run loop.",
    )
    group.add_argument(
        "--copy-next-instruction",
        action="store_true",
        help="Generate the next instruction packet and copy it to the clipboard (prints to stdout as a fallback).",
    )
    group.add_argument(
        "--open-workspace",
        metavar="WORKSPACE_PATH",
        help="Open <path> in Cursor using a discovered or configured launcher only, if one is available.",
    )
    parser.add_argument(
        "--session-dir",
        default=None,
        help="Directory for local session JSON artifacts (default: .admissible/control_surface_sessions).",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Admissible repo root used to resolve the default session directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.write_instruction:
            result = write_next_instruction(
                args.write_instruction, repo_root=args.repo_root, session_dir=args.session_dir
            )
            bridge = result["bridge"]
            print(f"Wrote turn {bridge['turn_number']} instruction packet to {bridge['instruction_path']}")
            print(f"Have Cursor write its response to {bridge['response_path']}")
        elif args.ingest_response:
            result = ingest_response_file(
                args.ingest_response, repo_root=args.repo_root, session_dir=args.session_dir
            )
            print(json.dumps(result["bridge"], indent=2, sort_keys=True))
        elif args.copy_next_instruction:
            result = copy_next_instruction(repo_root=args.repo_root, session_dir=args.session_dir)
            if result["copied_to_clipboard"]:
                print(f"Copied turn {result['turn_number']} instruction packet to the clipboard.")
            else:
                print("Clipboard unavailable; printing instruction packet to stdout instead:\n")
                print(result["packet_text"])
        elif args.open_workspace:
            result = open_workspace_in_cursor(args.open_workspace)
            print(result["message"])
        else:  # pragma: no cover - unreachable, mutually exclusive group is required
            raise CursorBridgeError("no bridge operation selected")
    except ValueError as exc:
        print(f"admissible.runner.cursor_bridge error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
