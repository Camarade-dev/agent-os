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
- `bridge-state.json` (see `write_bridge_state`) tracks instruction/response
  turn metadata and enforces bridge hygiene only: stale or duplicate response
  files are blocked from ingestion. This is not an admission gate -- it
  never changes a rules-only decision on an already-ingested action.
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

from admissible.control_surface import (
    ControlSurfaceController,
    InvalidSessionFileError as ControlSurfaceInvalidSessionFileError,
    load_persisted_session,
)

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


class StaleResponseError(CursorBridgeError):
    """Raised when a response file predates the current instruction turn."""


class DuplicateResponseError(CursorBridgeError):
    """Raised when an identical response was already ingested for this turn."""


class NoAwaitingInstructionError(CursorBridgeError):
    """Raised when no instruction is awaiting a response for the current turn."""


class BridgeSessionMismatchError(CursorBridgeError):
    """Raised when bridge-state was written for a different Control Surface session."""


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

    Bridge turn metadata -- session id, turn, instruction path/sha256,
    written_at, expected response path, awaiting-response flag, and the most
    recent ingestion's turn/sha256. Used to block stale or duplicate response
    ingestion. Never consulted for, and never able to affect, a rules-only
    admission decision on an already-ingested action.
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
    try:
        load_persisted_session(controller)
    except ControlSurfaceInvalidSessionFileError as exc:
        raise InvalidSessionFileError(str(exc), detail=exc.detail) from exc
    return controller


# -- response freshness / duplicate hygiene (bridge-only; not admission) -----


def _archived_response_path(workspace: Path, *, turn: int) -> Path:
    return _bridge_dir(workspace) / f"agent-response.turn{turn}.archived.md"


def _archive_stale_response_file(workspace: Path, *, turn: int) -> str | None:
    """Move a leftover `agent-response.md` into a turn-labelled archive file.

    Preserves audit trail on disk; the live response path must be empty before
    a new instruction turn awaits a fresh reply.
    """
    response_path = _response_path(workspace)
    if not response_path.is_file():
        return None
    archive_path = _archived_response_path(workspace, turn=turn)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(response_path), str(archive_path))
    return str(archive_path)


def invalidate_bridge_state_for_session_reset(workspace: Path) -> Path | None:
    """Mark workspace bridge-state as invalid after a Control Surface session reset.

    Clears the active awaiting flag so stale on-disk responses cannot be mistaken
    for a current-session instruction. A fresh ``write_instruction`` re-binds
    ``session_id`` and turn metadata for the new session.
    """
    bridge_state = read_bridge_state(workspace)
    if bridge_state is None:
        return None
    return write_bridge_state(
        workspace,
        {
            "awaiting_response": False,
            "session_reset_invalidated_at": _now_iso(),
        },
    )


def _validate_response_for_ingest(
    controller: ControlSurfaceController,
    workspace: Path,
    *,
    response_meta: dict[str, Any],
) -> None:
    """Raise a clear `CursorBridgeError` when a response must not be ingested."""
    instruction_path = _instruction_path(workspace)
    bridge_state = read_bridge_state(workspace) or {}
    state_view = controller.state_view()
    session_id = state_view.get("session_id")
    bridge_session_id = bridge_state.get("session_id")
    raw_session_turn = state_view["run_loop"]["current_turn"]
    session_turn = raw_session_turn if raw_session_turn is not None else 0
    bridge_turn = bridge_state.get("turn")
    response_sha256 = response_meta["sha256"]

    if bridge_session_id is not None and bridge_session_id != session_id:
        raise BridgeSessionMismatchError(
            "Response file was written for a different Control Surface session.",
            detail={
                "reason": "bridge_session_mismatch",
                "bridge_session_id": bridge_session_id,
                "session_id": session_id,
                "bridge_turn": bridge_turn,
            },
        )

    if not instruction_path.is_file():
        raise NoAwaitingInstructionError(
            "No current instruction file found. Write a new instruction before ingesting a response.",
            detail={
                "reason": "no_instruction",
                "instruction_path": str(instruction_path),
                "exists": False,
            },
        )

    if bridge_state.get("awaiting_response") is not True:
        ingested_turn = bridge_state.get("response_ingested_for_turn")
        ingested_sha = bridge_state.get("ingested_response_sha256")
        if ingested_sha == response_sha256 and ingested_turn == bridge_turn:
            raise DuplicateResponseError(
                "This response was already ingested for the current instruction turn.",
                detail={
                    "reason": "duplicate_response",
                    "turn_number": ingested_turn,
                    "response_sha256": response_sha256,
                    "last_ingested_at": bridge_state.get("last_ingested_at"),
                },
            )
        raise NoAwaitingInstructionError(
            "No instruction is currently awaiting a response for this turn.",
            detail={
                "reason": "no_awaiting_instruction",
                "bridge_turn": bridge_turn,
                "response_ingested_for_turn": ingested_turn,
            },
        )

    if bridge_turn is not None and bridge_turn != session_turn:
        raise StaleResponseError(
            "Response does not match the latest instruction turn.",
            detail={
                "reason": "instruction_turn_mismatch",
                "bridge_turn": bridge_turn,
                "session_turn": session_turn,
            },
        )

    instruction_meta = _file_metadata(instruction_path)
    if (
        response_meta["modified_at"] is not None
        and instruction_meta["modified_at"] is not None
        and response_meta["modified_at"] < instruction_meta["modified_at"]
    ):
        raise StaleResponseError(
            "Response file is older than the current instruction file and is not fresh for this turn.",
            detail={
                "reason": "stale_response",
                "response_modified_at": response_meta["modified_at"],
                "instruction_modified_at": instruction_meta["modified_at"],
            },
        )

    ingested_sha = bridge_state.get("ingested_response_sha256")
    if ingested_sha == response_sha256 and bridge_state.get("response_ingested_for_turn") == bridge_turn:
        raise DuplicateResponseError(
            "This response file's content is identical to one already ingested for this instruction turn.",
            detail={
                "reason": "duplicate_response",
                "turn_number": bridge_turn,
                "response_sha256": response_sha256,
                "last_ingested_at": bridge_state.get("last_ingested_at"),
            },
        )


def _record_blocked_ingest(
    controller: ControlSurfaceController,
    workspace: Path,
    exc: CursorBridgeError,
    *,
    response_meta: dict[str, Any],
) -> None:
    reason = str(exc.detail.get("reason") or "blocked")
    controller.record_bridge_ingest_blocked(
        reason,
        workspace_path=str(workspace),
        response_sha256=response_meta.get("sha256"),
        turn_number=exc.detail.get("turn_number") or exc.detail.get("bridge_turn"),
        detail=dict(exc.detail),
    )


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

    prior_bridge_state = read_bridge_state(workspace) or {}
    archive_turn = prior_bridge_state.get("turn") or max(packet["turn_number"] - 1, 1)
    archived_response_path = _archive_stale_response_file(workspace, turn=archive_turn)

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
            "awaiting_response": True,
            "response_ingested_for_turn": None,
            "ingested_response_sha256": None,
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
        "archived_response_path": archived_response_path,
        "prior_response_invalidated": archived_response_path is not None,
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
    plus the explicit reminder that ingestion never executes anything.
    Stale or duplicate responses are blocked before `ingest_agent_response`
    is called.
    """
    workspace = _validate_workspace(workspace_path)
    response_path = _response_path(workspace)

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

    try:
        _validate_response_for_ingest(controller, workspace, response_meta=response_meta)
    except CursorBridgeError as exc:
        _record_blocked_ingest(controller, workspace, exc, response_meta=response_meta)
        raise

    state = controller.ingest_agent_response(raw_text)
    record = state["run_loop"]["response_records"][-1]
    action_ids = set(record["action_ids"])
    new_items = [item for item in state["queue"] if item["action_id"] in action_ids]
    decisions = [item["decision"] for item in new_items]

    ingested_at = _now_iso()
    write_bridge_state(
        workspace,
        {
            "last_ingested_turn": record["turn_number"],
            "last_ingested_response_sha256": response_meta["sha256"],
            "last_ingested_at": ingested_at,
            "awaiting_response": False,
            "response_ingested_for_turn": record["turn_number"],
            "ingested_response_sha256": response_meta["sha256"],
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
        "ingested_response_sha256": response_meta["sha256"],
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
