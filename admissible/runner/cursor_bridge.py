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

This is the **canonical** Admissible <-> Cursor workflow; manual copy/paste
(`ControlSurfaceController.generate_next_instruction_packet` /
`ingest_agent_response` called directly, without going through a file) is
kept only as an advanced/debug fallback in the UI.

Every bridge operation is verifiable: writing or reading a file returns its
absolute path, whether it exists, its byte count, its SHA256 digest, and its
modified timestamp, so a human (or a test) never has to take "it worked" on
faith.

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
- `bridge-state.json` (see `write_bridge_state`) is bridge diagnostics only
  -- it is never consulted by, and never an authority for, an admission
  decision. It only ever produces non-blocking *warnings* (e.g. "this looks
  stale"), never a gate.
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
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from admissible.control_surface import ControlSurfaceController

BRIDGE_SUBDIR = ".admissible"
INSTRUCTION_FILENAME = "next-agent-instruction.md"
RESPONSE_FILENAME = "agent-response.md"
BRIDGE_STATE_FILENAME = "bridge-state.json"

CURSOR_LAUNCHER_ENV_VAR = "ADMISSIBLE_CURSOR_LAUNCHER"

NEXT_INSTRUCTION_NOTE = (
    "Now ask Cursor to read `.admissible/next-agent-instruction.md` and write its "
    "response to `.admissible/agent-response.md`."
)

_PREVIEW_LINE_COUNT = 5

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
    """Base class for cursor_bridge user-facing errors (a ValueError subclass).

    Carries an optional `detail` dict of extra, machine-readable fields (e.g.
    `expected_path`, `exists`) so callers -- the HTTP JSON error body in
    particular -- can surface a verifiable, structured error instead of only
    a human-readable message.
    """

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail: dict[str, Any] = dict(detail) if detail else {}


class WorkspaceNotFoundError(CursorBridgeError):
    """Raised when a workspace path does not exist or is not a directory."""


class ResponseFileNotFoundError(CursorBridgeError):
    """Raised when --ingest-response is run before Cursor has written a response file."""


class InvalidSessionFileError(CursorBridgeError):
    """Raised when a persisted Control Surface session file cannot be loaded."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_workspace(workspace_path: str | Path) -> Path:
    raw = str(workspace_path).strip()
    if not raw:
        raise WorkspaceNotFoundError("a workspace path is required", detail={"workspace_path": "", "exists": False})
    workspace = Path(raw)
    if not workspace.is_dir():
        raise WorkspaceNotFoundError(
            f"workspace path does not exist or is not a directory: {workspace}",
            detail={"workspace_path": str(workspace), "exists": workspace.exists()},
        )
    return workspace


def _bridge_dir(workspace: Path) -> Path:
    return workspace / BRIDGE_SUBDIR


def _instruction_path(workspace: Path) -> Path:
    return _bridge_dir(workspace) / INSTRUCTION_FILENAME


def _response_path(workspace: Path) -> Path:
    return _bridge_dir(workspace) / RESPONSE_FILENAME


def _bridge_state_path(workspace: Path) -> Path:
    return _bridge_dir(workspace) / BRIDGE_STATE_FILENAME


def render_instruction_file(packet_text: str, *, workspace: Path) -> str:
    """Render the full instruction-file contents: the packet plus a clear
    pointer to where Cursor must write its response. Adds no new proposal or
    authorization language beyond what the packet itself already contains.
    """
    footer = _INSTRUCTION_FOOTER_TEMPLATE.format(response_path=_response_path(workspace))
    return f"{packet_text}{footer}"


def _file_metadata(path: Path) -> dict[str, Any]:
    """Read `path` off disk and report exactly what is actually there.

    Always re-derives from the file on disk (never from an in-memory string
    the caller intended to write) so a caller can treat this as independent
    verification, not an echo of what it asked for.
    """
    if not path.is_file():
        return {"path": str(path), "exists": False, "bytes": None, "sha256": None, "modified_at": None}
    data = path.read_bytes()
    stat = path.stat()
    modified_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "path": str(path),
        "exists": True,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "modified_at": modified_at,
    }


def _preview_lines(text: str, count: int = _PREVIEW_LINE_COUNT) -> list[str]:
    return text.splitlines()[:count]


# -- bridge-state.json (diagnostics only; never an admission authority) ------


def read_bridge_state(workspace: Path) -> dict[str, Any] | None:
    """Read `<workspace>/.admissible/bridge-state.json` if present and valid.

    Returns None if the file is missing or unreadable/invalid JSON -- this
    is diagnostics-only, so a missing/corrupt bridge-state file must never
    raise; callers treat None as "no turn metadata available".
    """
    path = _bridge_state_path(workspace)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def write_bridge_state(workspace: Path, updates: dict[str, Any]) -> Path:
    """Merge `updates` into `<workspace>/.admissible/bridge-state.json` and persist it.

    Pure bridge diagnostics -- session id, turn, instruction path/sha256,
    written_at, expected response path, plus (best-effort) the most recent
    ingestion's turn/sha256 so a later ingest can flag a likely-stale
    response. Never consulted for, and never able to affect, an admission
    decision.
    """
    path = _bridge_state_path(workspace)
    state = read_bridge_state(workspace) or {}
    state.update(updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


# -- read-only workspace check (no writes, no execution) ----------------------


def check_workspace(workspace_path: str | Path) -> dict[str, Any]:
    """Report whether a workspace path exists and what the bridge dir looks like.

    Read-only: never creates or modifies anything on disk. Backs the UI's
    live "Workspace" status (exists / expected `.admissible/` dir) before any
    write/ingest button has been clicked.
    """
    raw = str(workspace_path).strip()
    result: dict[str, Any] = {"operation": "check_workspace", "workspace_path": raw, "workspace_exists": False}
    if not raw:
        return result

    workspace = Path(raw)
    result["workspace_exists"] = workspace.is_dir()
    bridge_dir = _bridge_dir(workspace)
    result["bridge_dir_path"] = str(bridge_dir)
    result["bridge_dir_exists"] = bridge_dir.is_dir()
    result["instruction_path"] = str(_instruction_path(workspace))
    result["instruction_exists"] = _instruction_path(workspace).is_file()
    result["response_path"] = str(_response_path(workspace))
    result["response_exists"] = _response_path(workspace).is_file()
    return result


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

    Raises `InvalidSessionFileError` (a ValueError) with a clear message if
    the persisted session file exists but cannot be parsed/loaded, instead
    of letting a raw JSONDecodeError/KeyError escape.
    """
    controller = ControlSurfaceController(repo_root=repo_root, session_dir=session_dir)
    session_file = controller.session_file
    if session_file.is_file():
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
            controller.import_session(data)
        except Exception as exc:  # noqa: BLE001 - convert any corrupt-file shape into one clear error
            raise InvalidSessionFileError(
                f"invalid session file at {session_file}: {exc}",
                detail={"session_file": str(session_file)},
            ) from exc
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
    Writes one file (plus the bridge-state.json diagnostics record);
    executes nothing. The returned `bridge` dict re-reads the file off disk
    after writing it, so every field is independently verifiable rather than
    an echo of what was requested.
    """
    workspace = _validate_workspace(workspace_path)
    state = controller.generate_next_instruction_packet()
    packet = state["run_loop"]["instruction_packets"][-1]

    bridge_dir = _bridge_dir(workspace)
    bridge_dir.mkdir(parents=True, exist_ok=True)
    instruction_path = _instruction_path(workspace)
    response_path = _response_path(workspace)
    rendered = render_instruction_file(packet["packet_text"], workspace=workspace)
    instruction_path.write_text(rendered, encoding="utf-8")

    file_meta = _file_metadata(instruction_path)
    bridge_state_path = write_bridge_state(
        workspace,
        {
            "session_id": state.get("session_id"),
            "turn": packet["turn_number"],
            "instruction_path": file_meta["path"],
            "instruction_sha256": file_meta["sha256"],
            "written_at": _now_iso(),
            "expected_response_path": str(response_path),
        },
    )

    bridge_info = {
        "operation": "write_instruction",
        "success": True,
        "workspace_path": str(workspace),
        "turn_number": packet["turn_number"],
        "instruction_path": file_meta["path"],
        "response_path": str(response_path),
        "exists": file_meta["exists"],
        "bytes": file_meta["bytes"],
        "sha256": file_meta["sha256"],
        "modified_at": file_meta["modified_at"],
        "preview_lines": _preview_lines(rendered),
        "next_instruction": NEXT_INSTRUCTION_NOTE,
        "bridge_state_path": str(bridge_state_path),
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

    Raises `ResponseFileNotFoundError` (missing file, with the expected path
    in `.detail`) or `CursorBridgeError` (empty file) -- both ValueError
    subclasses -- rather than silently no-oping. On success, `bridge`
    carries the same independently-re-read file metadata as the write path,
    plus non-blocking `warnings` (e.g. the response file looking older than
    the instruction file, or matching a response already ingested for an
    earlier turn) and the explicit reminder that ingestion never executes
    anything.
    """
    workspace = _validate_workspace(workspace_path)
    response_path = _response_path(workspace)
    instruction_path = _instruction_path(workspace)

    if not response_path.is_file():
        raise ResponseFileNotFoundError(
            "No response file found.",
            detail={"expected_path": str(response_path), "exists": False},
        )

    response_meta = _file_metadata(response_path)
    raw_text = response_path.read_bytes().decode("utf-8")
    if not raw_text.strip():
        raise CursorBridgeError(
            f"agent response file is empty: {response_path}",
            detail={"path": str(response_path), "exists": True, "bytes": response_meta["bytes"]},
        )

    warnings: list[str] = []
    if instruction_path.is_file():
        instruction_meta = _file_metadata(instruction_path)
        if (
            response_meta["modified_at"] is not None
            and instruction_meta["modified_at"] is not None
            and response_meta["modified_at"] < instruction_meta["modified_at"]
        ):
            warnings.append(
                "Response file's modified time is older than the instruction file's -- "
                "this response may be stale (written before the current instruction)."
            )

    bridge_state = read_bridge_state(workspace)
    if bridge_state and bridge_state.get("last_ingested_response_sha256") == response_meta["sha256"]:
        warnings.append(
            "This response file's content is identical to one already ingested "
            f"(turn {bridge_state.get('last_ingested_turn')}) -- it may be stale from a previous turn."
        )

    state = controller.ingest_agent_response(raw_text)
    record = state["run_loop"]["response_records"][-1]
    action_ids = set(record["action_ids"])
    new_items = [item for item in state["queue"] if item["action_id"] in action_ids]
    decisions = [item["decision"] for item in new_items]

    write_bridge_state(
        workspace,
        {
            "last_ingested_turn": record["turn_number"],
            "last_ingested_response_sha256": response_meta["sha256"],
            "last_ingested_at": _now_iso(),
        },
    )

    bridge_info = {
        "operation": "ingest_response",
        "success": True,
        "workspace_path": str(workspace),
        "response_path": response_meta["path"],
        "exists": response_meta["exists"],
        "bytes": response_meta["bytes"],
        "sha256": response_meta["sha256"],
        "modified_at": response_meta["modified_at"],
        "turn_number": record["turn_number"],
        "record_id": record["record_id"],
        "action_count": len(record["action_ids"]),
        "action_ids": list(record["action_ids"]),
        "decisions": decisions,
        "decision_summary": dict(Counter(decisions)),
        "warnings": warnings,
        "note": "Nothing was executed by Admissible.",
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
            print(f"  bytes={bridge['bytes']} sha256={bridge['sha256']} modified_at={bridge['modified_at']}")
            print(f"Have Cursor write its response to {bridge['response_path']}")
        elif args.ingest_response:
            result = ingest_response_file(
                args.ingest_response, repo_root=args.repo_root, session_dir=args.session_dir
            )
            bridge = result["bridge"]
            print(f"Read turn {bridge['turn_number']} response from {bridge['response_path']}")
            print(f"  bytes={bridge['bytes']} sha256={bridge['sha256']} modified_at={bridge['modified_at']}")
            print(f"  extracted {bridge['action_count']} action candidate(s): {bridge['decision_summary']}")
            for warning in bridge["warnings"]:
                print(f"  warning: {warning}")
            print(f"  {bridge['note']}")
            print(json.dumps(bridge, indent=2, sort_keys=True))
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
