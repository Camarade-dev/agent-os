"""Tests for the Admissible Cursor File Bridge v0 (admissible.runner.cursor_bridge).

Covers the file bridge (write instruction / ingest response), the clipboard
helper, the open-workspace helper, the four HTTP routes (check_workspace,
write_instruction, ingest_response, open_workspace), and the
control_surface.html bridge controls. See docs/admissible-cursor-bridge.md.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock as mock
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.runner import cursor_bridge
from admissible.runner.cursor_bridge import (
    CURSOR_LAUNCHER_ENV_VAR,
    CursorBridgeError,
    DuplicateResponseError,
    InvalidSessionFileError,
    NoAwaitingInstructionError,
    ResponseFileNotFoundError,
    StaleResponseError,
    WorkspaceNotFoundError,
    build_controller,
    check_workspace,
    copy_next_instruction,
    discover_cursor_launcher,
    ingest_response_file,
    ingest_response_file_with_controller,
    main as cursor_bridge_main,
    open_workspace_in_cursor,
    read_bridge_state,
    render_instruction_file,
    write_next_instruction,
    write_next_instruction_with_controller,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_TRACE_PATH = (
    REPO_ROOT / "benchmark" / "reports" / "admissible_cursor_admitted_execution_truth_console_trace.json"
)
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

RAW_INSTALL_DEPENDENCY_RESPONSE = (
    "User: Please add a helper dependency.\n\n"
    "Proposed command:\n"
    "    npm install left-pad\n"
)

# Every instruction-producing bridge path is goal-first
# (ADMISSIBLE_UX_014_GOAL_FIRST_GATING): a packet can only be generated once a
# goal has been submitted. These bridge-mechanics tests submit this goal first
# so they exercise the write/ingest plumbing, not the blank-session guard
# (which is covered directly in tests/test_admissible_first_run_product_gaps.py).
BRIDGE_TEST_GOAL = (
    "Build a tiny local-only browser page in a local workspace. "
    "Keep it local-only. Do not deploy."
)


def _make_controller(tmpdir: str, name: str = "sessions") -> ControlSurfaceController:
    controller = ControlSurfaceController(
        session_dir=Path(tmpdir) / name,
        sample_trace_path=SAMPLE_TRACE_PATH,
    )
    controller.submit_goal(BRIDGE_TEST_GOAL)
    return controller


def _seed_goal(session_dir: Path) -> None:
    """Persist a goal into a session dir so a later, separate-process CLI/HTTP
    controller (built fresh from that dir) passes the goal-first guard."""
    controller = build_controller(session_dir=session_dir)
    controller.submit_goal(BRIDGE_TEST_GOAL)


class TestRenderInstructionFile(unittest.TestCase):
    def test_includes_packet_text_and_response_path_and_no_execution_language(self) -> None:
        text = render_instruction_file("PACKET BODY HERE", workspace=Path("/tmp/example-workspace"))
        self.assertIn("PACKET BODY HERE", text)
        self.assertIn("agent-response.md", text)
        self.assertIn("example-workspace", text)
        self.assertIn("Do not execute anything from this instruction packet yourself", text)
        self.assertIn("it never executes a command on your behalf", text)


class TestWriteNextInstructionWithController(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _make_controller(self._tmpdir.name)
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_writes_instruction_file_with_expected_content(self) -> None:
        result = write_next_instruction_with_controller(self.controller, self.workspace)
        bridge = result["bridge"]
        self.assertEqual(bridge["operation"], "write_instruction")
        self.assertEqual(bridge["turn_number"], 1)

        instruction_path = Path(bridge["instruction_path"])
        self.assertEqual(instruction_path, self.workspace / ".admissible" / "next-agent-instruction.md")
        self.assertTrue(instruction_path.is_file())
        content = instruction_path.read_text(encoding="utf-8")
        self.assertIn("Admissible Next Agent Instruction Packet", content)
        self.assertIn("Admissible Cursor Bridge v0", content)
        self.assertIn(str(self.workspace / ".admissible" / "agent-response.md"), content)

        self.assertEqual(bridge["response_path"], str(self.workspace / ".admissible" / "agent-response.md"))
        self.assertFalse(Path(bridge["response_path"]).exists())

    def test_write_result_carries_verifiable_file_metadata(self) -> None:
        result = write_next_instruction_with_controller(self.controller, self.workspace)
        bridge = result["bridge"]

        self.assertTrue(bridge["success"])
        instruction_path = Path(bridge["instruction_path"])
        on_disk = instruction_path.read_bytes()

        self.assertTrue(bridge["exists"])
        self.assertEqual(bridge["bytes"], len(on_disk))
        self.assertEqual(bridge["sha256"], hashlib.sha256(on_disk).hexdigest())
        self.assertTrue(bridge["modified_at"])
        self.assertEqual(bridge["turn_number"], 1)
        self.assertEqual(bridge["preview_lines"], on_disk.decode("utf-8").splitlines()[:5])
        self.assertEqual(
            bridge["next_instruction"],
            "Now ask Cursor to read `.admissible/next-agent-instruction.md` and write its "
            "response to `.admissible/agent-response.md`.",
        )

    def test_write_creates_bridge_state_json(self) -> None:
        result = write_next_instruction_with_controller(self.controller, self.workspace)
        bridge = result["bridge"]

        bridge_state_path = Path(bridge["bridge_state_path"])
        self.assertEqual(bridge_state_path, self.workspace / ".admissible" / "bridge-state.json")
        self.assertTrue(bridge_state_path.is_file())

        state = json.loads(bridge_state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["session_id"], result["session_id"])
        self.assertEqual(state["turn"], 1)
        self.assertEqual(state["instruction_path"], bridge["instruction_path"])
        self.assertEqual(state["instruction_sha256"], bridge["sha256"])
        self.assertTrue(state["written_at"])
        self.assertEqual(state["expected_response_path"], bridge["response_path"])

    def test_bridge_state_json_is_diagnostics_only_not_admission_authority(self) -> None:
        # A corrupted/adversarial bridge-state.json must never be able to
        # change an admission decision -- write_next_instruction_with_controller
        # must succeed identically whether or not it can be parsed.
        bridge_dir = self.workspace / ".admissible"
        bridge_dir.mkdir(parents=True)
        (bridge_dir / "bridge-state.json").write_text("not valid json {{{", encoding="utf-8")
        result = write_next_instruction_with_controller(self.controller, self.workspace)
        self.assertTrue(result["bridge"]["success"])

    def test_advances_turn_and_overwrites_file_on_repeated_calls(self) -> None:
        first = write_next_instruction_with_controller(self.controller, self.workspace)
        response_path = self.workspace / ".admissible" / "agent-response.md"
        response_path.write_text(RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8")
        second = write_next_instruction_with_controller(self.controller, self.workspace)
        self.assertEqual(first["bridge"]["turn_number"], 1)
        self.assertEqual(second["bridge"]["turn_number"], 2)

        instruction_path = Path(second["bridge"]["instruction_path"])
        content = instruction_path.read_text(encoding="utf-8")
        self.assertIn("turn 2", content)

    def test_writing_new_instruction_archives_prior_response_file(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)
        response_path = self.workspace / ".admissible" / "agent-response.md"
        response_path.write_text(RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8")

        result = write_next_instruction_with_controller(self.controller, self.workspace)
        bridge = result["bridge"]

        self.assertTrue(bridge["prior_response_invalidated"])
        self.assertFalse(response_path.exists())
        archived_path = Path(bridge["archived_response_path"])
        self.assertTrue(archived_path.is_file())
        self.assertEqual(archived_path.name, "agent-response.turn1.archived.md")
        self.assertEqual(archived_path.read_text(encoding="utf-8"), RAW_INSTALL_DEPENDENCY_RESPONSE)

    def test_does_not_execute_anything(self) -> None:
        def boom(*args, **kwargs):
            raise AssertionError("write_next_instruction_with_controller must never invoke subprocess")

        with mock.patch.object(subprocess, "run", boom):
            write_next_instruction_with_controller(self.controller, self.workspace)


class TestIngestResponseFileWithController(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _make_controller(self._tmpdir.name)
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()
        self.bridge_dir = self.workspace / ".admissible"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _write_response(self, text: str) -> None:
        self.bridge_dir.mkdir(parents=True, exist_ok=True)
        (self.bridge_dir / "agent-response.md").write_text(text, encoding="utf-8")

    def _write_instruction(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)

    def test_ingests_response_file_and_extracts_action_candidates(self) -> None:
        self._write_instruction()
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        result = ingest_response_file_with_controller(self.controller, self.workspace)
        bridge = result["bridge"]

        self.assertEqual(bridge["operation"], "ingest_response")
        self.assertEqual(bridge["action_count"], 1)
        self.assertEqual(bridge["decisions"], ["REQUEST_MORE_EVIDENCE"])
        self.assertEqual(bridge["response_path"], str(self.bridge_dir / "agent-response.md"))

        self.assertEqual(len(result["queue"]), 1)
        self.assertEqual(result["queue"][0]["action_id"], bridge["action_ids"][0])
        self.assertEqual(result["run_loop"]["response_records"][-1]["source_trust"], "unverified_agent_output")

    def test_ingest_result_carries_verifiable_file_metadata(self) -> None:
        self._write_instruction()
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        response_path = self.bridge_dir / "agent-response.md"
        on_disk = response_path.read_bytes()

        result = ingest_response_file_with_controller(self.controller, self.workspace)
        bridge = result["bridge"]

        self.assertTrue(bridge["success"])
        self.assertTrue(bridge["exists"])
        self.assertEqual(bridge["bytes"], len(on_disk))
        self.assertEqual(bridge["sha256"], hashlib.sha256(on_disk).hexdigest())
        self.assertTrue(bridge["modified_at"])
        self.assertEqual(bridge["decision_summary"], {"REQUEST_MORE_EVIDENCE": 1})
        self.assertEqual(bridge["ingested_response_sha256"], hashlib.sha256(on_disk).hexdigest())
        self.assertEqual(bridge["note"], "Nothing was executed by Admissible.")

    def test_ingest_updates_bridge_state_json_with_last_ingested_fields(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        result = ingest_response_file_with_controller(self.controller, self.workspace)

        state = read_bridge_state(self.workspace)
        self.assertEqual(state["last_ingested_turn"], result["bridge"]["turn_number"])
        self.assertEqual(state["last_ingested_response_sha256"], result["bridge"]["sha256"])
        self.assertEqual(state["ingested_response_sha256"], result["bridge"]["sha256"])
        self.assertEqual(state["response_ingested_for_turn"], result["bridge"]["turn_number"])
        self.assertFalse(state["awaiting_response"])
        self.assertTrue(state["last_ingested_at"])
        # Write-side fields from the earlier write_next_instruction call
        # must survive the merge, not be clobbered by the ingest update.
        self.assertEqual(state["turn"], 1)
        self.assertIn("instruction_sha256", state)

    def test_missing_response_file_raises_clear_error(self) -> None:
        with self.assertRaises(ResponseFileNotFoundError) as ctx:
            ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertEqual(str(ctx.exception), "No response file found.")
        self.assertEqual(ctx.exception.detail["expected_path"], str(self.bridge_dir / "agent-response.md"))
        self.assertFalse(ctx.exception.detail["exists"])

    def test_stale_response_is_blocked_and_creates_no_queue_items(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        response_path = self.bridge_dir / "agent-response.md"
        instruction_path = self.bridge_dir / "next-agent-instruction.md"

        import time

        older = time.time() - 3600
        os.utime(response_path, (older, older))
        os.utime(instruction_path, None)  # bump instruction mtime to now

        queue_before = len(self.controller.state_view()["queue"])
        with self.assertRaises(StaleResponseError) as ctx:
            ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertIn("older than the current instruction", str(ctx.exception))
        self.assertEqual(ctx.exception.detail["reason"], "stale_response")
        self.assertEqual(len(self.controller.state_view()["queue"]), queue_before)

    def test_duplicate_ingest_is_blocked_and_creates_queue_items_only_once(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)

        first = ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertEqual(first["bridge"]["action_count"], 1)
        queue_len_after_first = len(first["queue"])

        with self.assertRaises(DuplicateResponseError) as ctx:
            ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertIn("already ingested", str(ctx.exception))
        self.assertEqual(ctx.exception.detail["reason"], "duplicate_response")
        self.assertEqual(len(self.controller.state_view()["queue"]), queue_len_after_first)

    def test_duplicate_ingest_records_clear_transcript_diagnostic(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        ingest_response_file_with_controller(self.controller, self.workspace)

        with self.assertRaises(DuplicateResponseError):
            ingest_response_file_with_controller(self.controller, self.workspace)

        blocked = [
            entry
            for entry in self.controller.session_dict()["transcript"]
            if entry["type"] == "bridge_ingest_blocked"
        ]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["payload"]["reason"], "duplicate_response")

    def test_ingest_without_awaiting_instruction_is_blocked(self) -> None:
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        with self.assertRaises(NoAwaitingInstructionError) as ctx:
            ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertIn("instruction", str(ctx.exception).lower())

    def test_empty_response_file_error_detail(self) -> None:
        self._write_instruction()
        self._write_response("   \n  ")
        on_disk = (self.bridge_dir / "agent-response.md").read_bytes()
        with self.assertRaises(CursorBridgeError) as ctx:
            ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertIn("empty", str(ctx.exception))
        self.assertTrue(ctx.exception.detail["exists"])
        self.assertEqual(ctx.exception.detail["bytes"], len(on_disk))

    def test_empty_response_file_raises_clear_error(self) -> None:
        self._write_instruction()
        self._write_response("   \n  ")
        with self.assertRaises(CursorBridgeError) as ctx:
            ingest_response_file_with_controller(self.controller, self.workspace)
        self.assertIn("empty", str(ctx.exception))

    def test_does_not_execute_anything(self) -> None:
        self._write_instruction()
        self._write_response(RAW_INSTALL_DEPENDENCY_RESPONSE)

        def boom(*args, **kwargs):
            raise AssertionError("ingest_response_file_with_controller must never invoke subprocess")

        with mock.patch.object(subprocess, "run", boom):
            ingest_response_file_with_controller(self.controller, self.workspace)


class TestWorkspaceValidation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _make_controller(self._tmpdir.name)
        self.missing_workspace = Path(self._tmpdir.name) / "does-not-exist"
        self.file_not_dir = Path(self._tmpdir.name) / "a-file.txt"
        self.file_not_dir.write_text("not a directory", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_write_instruction_rejects_missing_workspace(self) -> None:
        with self.assertRaises(WorkspaceNotFoundError):
            write_next_instruction_with_controller(self.controller, self.missing_workspace)

    def test_write_instruction_rejects_file_as_workspace(self) -> None:
        with self.assertRaises(WorkspaceNotFoundError):
            write_next_instruction_with_controller(self.controller, self.file_not_dir)

    def test_ingest_response_rejects_missing_workspace(self) -> None:
        with self.assertRaises(WorkspaceNotFoundError):
            ingest_response_file_with_controller(self.controller, self.missing_workspace)

    def test_open_workspace_rejects_missing_workspace(self) -> None:
        with self.assertRaises(WorkspaceNotFoundError):
            open_workspace_in_cursor(self.missing_workspace, launcher=["fake-cursor"], runner=lambda *a, **k: None)

    def test_empty_workspace_path_rejected(self) -> None:
        with self.assertRaises(WorkspaceNotFoundError):
            write_next_instruction_with_controller(self.controller, "")


class TestCheckWorkspace(unittest.TestCase):
    """check_workspace() is read-only diagnostics backing the UI's live
    "Workspace" status -- it must never create or modify anything."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_empty_path_reports_not_exists_without_raising(self) -> None:
        result = check_workspace("")
        self.assertFalse(result["workspace_exists"])
        self.assertEqual(result["workspace_path"], "")

    def test_missing_workspace_reports_exists_false(self) -> None:
        missing = Path(self._tmpdir.name) / "does-not-exist"
        result = check_workspace(missing)
        self.assertFalse(result["workspace_exists"])

    def test_existing_workspace_without_bridge_dir(self) -> None:
        result = check_workspace(self.workspace)
        self.assertTrue(result["workspace_exists"])
        self.assertEqual(result["bridge_dir_path"], str(self.workspace / ".admissible"))
        self.assertFalse(result["bridge_dir_exists"])
        self.assertFalse(result["instruction_exists"])
        self.assertFalse(result["response_exists"])

    def test_never_creates_anything_on_disk(self) -> None:
        check_workspace(self.workspace)
        self.assertFalse((self.workspace / ".admissible").exists())

    def test_reports_existing_instruction_and_response_files(self) -> None:
        bridge_dir = self.workspace / ".admissible"
        bridge_dir.mkdir()
        (bridge_dir / "next-agent-instruction.md").write_text("x", encoding="utf-8")
        (bridge_dir / "agent-response.md").write_text("y", encoding="utf-8")

        result = check_workspace(self.workspace)
        self.assertTrue(result["bridge_dir_exists"])
        self.assertTrue(result["instruction_exists"])
        self.assertTrue(result["response_exists"])


class TestCliWrappersLoadPersistedSession(unittest.TestCase):
    """CLI entry points build a fresh controller per process; confirms it
    picks up the session a previous call already persisted to disk."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.session_dir = Path(self._tmpdir.name) / "sessions"
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_write_next_instruction_continues_turn_across_processes(self) -> None:
        _seed_goal(self.session_dir)
        first = write_next_instruction(self.workspace, session_dir=self.session_dir)
        second = write_next_instruction(self.workspace, session_dir=self.session_dir)
        self.assertEqual(first["bridge"]["turn_number"], 1)
        self.assertEqual(second["bridge"]["turn_number"], 2)

    def test_ingest_response_file_uses_persisted_session(self) -> None:
        _seed_goal(self.session_dir)
        write_next_instruction(self.workspace, session_dir=self.session_dir)
        (self.workspace / ".admissible" / "agent-response.md").write_text(
            RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8"
        )
        result = ingest_response_file(self.workspace, session_dir=self.session_dir)
        self.assertEqual(result["bridge"]["action_count"], 1)

    def test_build_controller_with_no_prior_session_starts_fresh(self) -> None:
        controller = build_controller(session_dir=self.session_dir / "brand-new")
        self.assertEqual(controller.state_view()["run_loop"]["current_turn"], 0)

    def test_build_controller_rejects_invalid_session_file_with_clear_error(self) -> None:
        self.session_dir.mkdir(parents=True)
        (self.session_dir / "session.json").write_text("not valid json {{{", encoding="utf-8")
        with self.assertRaises(InvalidSessionFileError) as ctx:
            build_controller(session_dir=self.session_dir)
        self.assertIn("invalid session file", str(ctx.exception))
        self.assertEqual(ctx.exception.detail["session_file"], str(self.session_dir / "session.json"))


class TestCopyNextInstruction(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.session_dir = Path(self._tmpdir.name) / "sessions"
        _seed_goal(self.session_dir)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_uses_injected_clipboard_writer(self) -> None:
        calls: list[str] = []
        result = copy_next_instruction(session_dir=self.session_dir, clipboard_writer=calls.append)
        self.assertTrue(result["copied_to_clipboard"])
        self.assertEqual(len(calls), 1)
        self.assertIn("Admissible Next Agent Instruction Packet", calls[0])
        self.assertEqual(result["turn_number"], 1)

    def test_falls_back_to_stdout_text_when_clipboard_unavailable(self) -> None:
        def raising_writer(_text: str) -> None:
            raise RuntimeError("no clipboard in this environment")

        result = copy_next_instruction(session_dir=self.session_dir, clipboard_writer=raising_writer)
        self.assertFalse(result["copied_to_clipboard"])
        self.assertIn("Admissible Next Agent Instruction Packet", result["packet_text"])

    def test_never_touches_a_workspace_admissible_folder(self) -> None:
        # copy-next-instruction is a pure clipboard/stdout operation -- it
        # takes no workspace argument and must never create a bridge file.
        result = copy_next_instruction(session_dir=self.session_dir, clipboard_writer=lambda text: None)
        self.assertNotIn("instruction_path", result)
        self.assertNotIn("response_path", result)
        self.assertEqual(list(Path(self._tmpdir.name).rglob(".admissible")), [])


class TestOpenWorkspaceInCursor(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_launches_injected_launcher_without_shell(self) -> None:
        calls = []

        def fake_runner(argv, **kwargs):
            calls.append((argv, kwargs))

        result = open_workspace_in_cursor(self.workspace, launcher=["fake-cursor"], runner=fake_runner)
        self.assertTrue(result["opened"])
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ["fake-cursor", str(self.workspace)])
        self.assertEqual(kwargs.get("shell"), False)

    def test_no_launcher_found_returns_fallback_and_never_runs_a_process(self) -> None:
        def runner_should_not_be_called(*args, **kwargs):
            raise AssertionError("must not invoke a process when no launcher is found")

        result = open_workspace_in_cursor(self.workspace, launcher=[], runner=runner_should_not_be_called)
        self.assertFalse(result["opened"])
        self.assertIn("No Cursor launcher found", result["message"])
        self.assertIn(CURSOR_LAUNCHER_ENV_VAR, result["message"])

    def test_discover_cursor_launcher_respects_env_override(self) -> None:
        fake_exe = Path(self._tmpdir.name) / "fake_cursor.exe"
        fake_exe.write_text("", encoding="utf-8")
        with mock.patch.dict(os.environ, {CURSOR_LAUNCHER_ENV_VAR: str(fake_exe)}):
            launcher = discover_cursor_launcher()
        self.assertEqual(launcher, [str(fake_exe)])

    def test_discover_cursor_launcher_env_override_missing_file_returns_none(self) -> None:
        missing = Path(self._tmpdir.name) / "does-not-exist.exe"
        with mock.patch.dict(os.environ, {CURSOR_LAUNCHER_ENV_VAR: str(missing)}):
            launcher = discover_cursor_launcher()
        self.assertIsNone(launcher)

    def test_default_runner_parameter_is_subprocess_popen_not_run(self) -> None:
        # subprocess.run() blocks the caller until the child process exits.
        # Cursor is a GUI process that will not always detach on its own, so
        # launching it must never risk hanging the CLI/HTTP request waiting
        # for the editor window to close -- the default runner must be the
        # non-blocking subprocess.Popen, not subprocess.run.
        default_runner = inspect.signature(open_workspace_in_cursor).parameters["runner"].default
        self.assertIs(default_runner, subprocess.Popen)
        self.assertIsNot(default_runner, subprocess.run)


class TestDiscoverCursorLauncherWindowsShimHandling(unittest.TestCase):
    """Regression coverage for a real bug hit while building this feature:
    on Windows, `cursor` on PATH commonly resolves to a `.cmd`/shell shim
    (Cursor ships one itself, alongside npm-installed CLI shims in general).
    `subprocess.Popen/run(..., shell=False)` cannot launch those directly --
    it raises `OSError: [WinError 193] ... not a valid Win32 application`
    instead of running. discover_cursor_launcher() must treat that as "not
    discoverable" (fall through to the documented clear-fallback message),
    never let it surface as an unhandled crash from open_workspace_in_cursor.
    """

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        # Point every well-known install-location candidate at empty,
        # nonexistent directories so this test's outcome depends only on the
        # PATH-lookup branch under test, never on a real Cursor install on
        # the machine running the suite.
        self._no_install_env = {
            "LOCALAPPDATA": str(Path(self._tmpdir.name) / "no-local-appdata"),
            "ProgramFiles": str(Path(self._tmpdir.name) / "no-program-files"),
            "ProgramFiles(x86)": str(Path(self._tmpdir.name) / "no-program-files-x86"),
        }

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _discover_with_which(self, which_return_value: str | None):
        env = dict(self._no_install_env)
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop(CURSOR_LAUNCHER_ENV_VAR, None)
            with mock.patch.object(cursor_bridge.shutil, "which", return_value=which_return_value):
                return discover_cursor_launcher()

    @unittest.skipUnless(sys.platform == "win32", "Windows-specific PATH-shim handling")
    def test_rejects_non_exe_path_shim(self) -> None:
        launcher = self._discover_with_which(r"C:\Users\someone\AppData\Roaming\npm\cursor.cmd")
        self.assertIsNone(launcher)

    @unittest.skipUnless(sys.platform == "win32", "Windows-specific PATH-shim handling")
    def test_rejects_extensionless_path_shim(self) -> None:
        launcher = self._discover_with_which(r"C:\Program Files\cursor\resources\app\bin\cursor")
        self.assertIsNone(launcher)

    @unittest.skipUnless(sys.platform == "win32", "Windows-specific PATH-shim handling")
    def test_accepts_a_real_exe_found_on_path(self) -> None:
        launcher = self._discover_with_which(r"C:\tools\Cursor.exe")
        self.assertEqual(launcher, [r"C:\tools\Cursor.exe"])

    @unittest.skipUnless(sys.platform == "win32", "Windows-specific install-location handling")
    def test_finds_program_files_install_without_consulting_path(self) -> None:
        program_files = Path(self._tmpdir.name) / "Program Files"
        exe_path = program_files / "cursor" / "Cursor.exe"
        exe_path.parent.mkdir(parents=True)
        exe_path.write_text("", encoding="utf-8")

        env = dict(self._no_install_env)
        env["ProgramFiles"] = str(program_files)

        def which_should_not_be_called(_name):
            raise AssertionError("a well-known install-location match must short-circuit the PATH lookup")

        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop(CURSOR_LAUNCHER_ENV_VAR, None)
            with mock.patch.object(cursor_bridge.shutil, "which", which_should_not_be_called):
                launcher = discover_cursor_launcher()
        self.assertEqual(launcher, [str(exe_path)])


class TestCliMain(unittest.TestCase):
    """CLI parity: write/ingest print the same verifiable facts (path,
    bytes, sha256, mtime, turn / extracted count, decision summary) the
    HTTP/UI responses carry, and every documented failure mode exits
    non-zero with a clear stderr message."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.session_dir = Path(self._tmpdir.name) / "sessions"
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _run(self, argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cursor_bridge_main(argv + ["--session-dir", str(self.session_dir)])
        return code, buf.getvalue()

    def test_write_instruction_prints_path_bytes_sha256_mtime_turn(self) -> None:
        _seed_goal(self.session_dir)
        code, out = self._run(["--write-instruction", str(self.workspace)])
        self.assertEqual(code, 0)
        self.assertIn(str(self.workspace / ".admissible" / "next-agent-instruction.md"), out)
        self.assertIn("bytes=", out)
        self.assertIn("sha256=", out)
        self.assertIn("modified_at=", out)
        self.assertIn("turn 1", out)

    def test_ingest_response_prints_path_bytes_sha256_mtime_count_and_decision_summary(self) -> None:
        _seed_goal(self.session_dir)
        self._run(["--write-instruction", str(self.workspace)])
        (self.workspace / ".admissible" / "agent-response.md").write_text(
            RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8"
        )
        code, out = self._run(["--ingest-response", str(self.workspace)])
        self.assertEqual(code, 0)
        self.assertIn(str(self.workspace / ".admissible" / "agent-response.md"), out)
        self.assertIn("bytes=", out)
        self.assertIn("sha256=", out)
        self.assertIn("modified_at=", out)
        self.assertIn("extracted 1 action candidate", out)
        self.assertIn("REQUEST_MORE_EVIDENCE", out)
        self.assertIn("Nothing was executed by Admissible.", out)

    def test_missing_workspace_exits_nonzero(self) -> None:
        code, _ = self._run(["--write-instruction", str(Path(self._tmpdir.name) / "nope")])
        self.assertEqual(code, 1)

    def test_missing_response_file_exits_nonzero(self) -> None:
        code, _ = self._run(["--ingest-response", str(self.workspace)])
        self.assertEqual(code, 1)

    def test_empty_response_file_exits_nonzero(self) -> None:
        bridge_dir = self.workspace / ".admissible"
        bridge_dir.mkdir(parents=True)
        (bridge_dir / "agent-response.md").write_text("   ", encoding="utf-8")
        code, _ = self._run(["--ingest-response", str(self.workspace)])
        self.assertEqual(code, 1)

    def test_invalid_session_file_exits_nonzero(self) -> None:
        self.session_dir.mkdir(parents=True)
        (self.session_dir / "session.json").write_text("not valid json {{{", encoding="utf-8")
        code, _ = self._run(["--write-instruction", str(self.workspace)])
        self.assertEqual(code, 1)


class TestCursorBridgeHttpServer(unittest.TestCase):
    """End-to-end smoke test over the real stdlib HTTP server (ephemeral port)."""

    @classmethod
    def setUpClass(cls) -> None:
        from admissible.runner.control_surface import build_controller as build_server_controller
        from admissible.runner.control_surface import make_server

        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls._tmpdir.name) / "workspace"
        cls.workspace.mkdir()
        controller = build_server_controller(
            session_dir=Path(cls._tmpdir.name) / "sessions",
            sample_trace_path=SAMPLE_TRACE_PATH,
        )
        # Bridge write is goal-first (ADMISSIBLE_UX_014); submit a goal so the
        # write/ingest routes exercise the bridge plumbing, not the guard.
        controller.submit_goal(BRIDGE_TEST_GOAL)
        cls.server = make_server(controller, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmpdir.cleanup()

    def _post(self, path: str, body: dict):
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_write_instruction_then_ingest_response_over_http(self) -> None:
        # This class shares one server/controller/session across its test
        # methods (matching TestRunLoopHttpServer's pattern), so the turn
        # number here is only asserted to be a positive int, not a specific
        # value -- other tests in this class may already have advanced it.
        status, state = self._post(
            "/api/session/run_loop/bridge/write_instruction", {"workspace_path": str(self.workspace)}
        )
        self.assertEqual(status, 200)
        bridge = state["bridge"]
        self.assertGreaterEqual(bridge["turn_number"], 1)
        instruction_path = Path(bridge["instruction_path"])
        self.assertTrue(instruction_path.is_file())
        self.assertIn("Admissible Cursor Bridge v0", instruction_path.read_text(encoding="utf-8"))

        # Write-route response metadata required for a verifiable UI status.
        self.assertTrue(bridge["success"])
        self.assertTrue(bridge["exists"])
        self.assertIsInstance(bridge["bytes"], int)
        self.assertEqual(len(bridge["sha256"]), 64)
        self.assertTrue(bridge["modified_at"])
        self.assertTrue(bridge["preview_lines"])
        self.assertIn("bridge_state_path", bridge)
        self.assertTrue(Path(bridge["bridge_state_path"]).is_file())

        response_path = Path(bridge["response_path"])
        response_path.write_text(RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8")

        status, state = self._post(
            "/api/session/run_loop/bridge/ingest_response", {"workspace_path": str(self.workspace)}
        )
        self.assertEqual(status, 200)
        ingest_bridge = state["bridge"]
        self.assertEqual(ingest_bridge["action_count"], 1)
        self.assertEqual(state["queue"][-1]["decision"], "REQUEST_MORE_EVIDENCE")

        # Ingest-route response metadata required for a verifiable UI status.
        self.assertTrue(ingest_bridge["success"])
        self.assertTrue(ingest_bridge["exists"])
        self.assertIsInstance(ingest_bridge["bytes"], int)
        self.assertEqual(len(ingest_bridge["sha256"]), 64)
        self.assertTrue(ingest_bridge["modified_at"])
        self.assertEqual(ingest_bridge["decision_summary"], {"REQUEST_MORE_EVIDENCE": 1})
        self.assertEqual(ingest_bridge["note"], "Nothing was executed by Admissible.")

    def test_check_workspace_route_is_read_only(self) -> None:
        status, result = self._post(
            "/api/session/run_loop/bridge/check_workspace", {"workspace_path": str(self.workspace)}
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["workspace_exists"])
        self.assertIn("bridge_dir_path", result)

    def test_check_workspace_route_handles_missing_path(self) -> None:
        status, result = self._post("/api/session/run_loop/bridge/check_workspace", {"workspace_path": ""})
        self.assertEqual(status, 200)
        self.assertFalse(result["workspace_exists"])

    def test_ingest_response_missing_file_returns_400_with_clear_error(self) -> None:
        empty_workspace = Path(self._tmpdir.name) / "empty_ws"
        empty_workspace.mkdir()
        status, body = self._post(
            "/api/session/run_loop/bridge/ingest_response", {"workspace_path": str(empty_workspace)}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "No response file found.")
        self.assertEqual(body["expected_path"], str(empty_workspace / ".admissible" / "agent-response.md"))
        self.assertFalse(body["exists"])

    def test_ingest_response_empty_file_returns_400_with_clear_error(self) -> None:
        empty_response_workspace = Path(self._tmpdir.name) / "empty_response_ws"
        bridge_dir = empty_response_workspace / ".admissible"
        bridge_dir.mkdir(parents=True)
        (bridge_dir / "agent-response.md").write_text("   ", encoding="utf-8")
        status, body = self._post(
            "/api/session/run_loop/bridge/ingest_response", {"workspace_path": str(empty_response_workspace)}
        )
        self.assertEqual(status, 400)
        self.assertIn("empty", body["error"])
        self.assertTrue(body["exists"])

    def test_open_workspace_route_returns_fallback_without_launching_a_process(self) -> None:
        # Force the "no launcher discovered" branch so this test never spawns
        # a real editor process regardless of what is installed on the host.
        with mock.patch("admissible.runner.cursor_bridge.discover_cursor_launcher", return_value=None):
            status, state = self._post(
                "/api/session/run_loop/bridge/open_workspace", {"workspace_path": str(self.workspace)}
            )
        self.assertEqual(status, 200)
        self.assertFalse(state["bridge"]["opened"])
        self.assertIn("message", state["bridge"])

    def test_bridge_routes_reject_unknown_workspace(self) -> None:
        status, body = self._post(
            "/api/session/run_loop/bridge/write_instruction",
            {"workspace_path": str(Path(self._tmpdir.name) / "nope")},
        )
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_duplicate_ingest_over_http_returns_400_with_clear_reason(self) -> None:
        dup_workspace = Path(self._tmpdir.name) / "dup_ws"
        dup_workspace.mkdir()
        status, _ = self._post(
            "/api/session/run_loop/bridge/write_instruction", {"workspace_path": str(dup_workspace)}
        )
        self.assertEqual(status, 200)
        response_path = dup_workspace / ".admissible" / "agent-response.md"
        response_path.write_text(RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8")

        status, state = self._post(
            "/api/session/run_loop/bridge/ingest_response", {"workspace_path": str(dup_workspace)}
        )
        self.assertEqual(status, 200)
        queue_len = len(state["queue"])

        status, body = self._post(
            "/api/session/run_loop/bridge/ingest_response", {"workspace_path": str(dup_workspace)}
        )
        self.assertEqual(status, 400)
        self.assertIn("already ingested", body["error"])
        self.assertEqual(body["reason"], "duplicate_response")
        self.assertEqual(len(body.get("queue") or state["queue"]), queue_len)

    def test_stale_ingest_over_http_returns_400_with_clear_reason(self) -> None:
        stale_workspace = Path(self._tmpdir.name) / "stale_ws"
        stale_workspace.mkdir()
        status, _ = self._post(
            "/api/session/run_loop/bridge/write_instruction", {"workspace_path": str(stale_workspace)}
        )
        self.assertEqual(status, 200)
        bridge_dir = stale_workspace / ".admissible"
        response_path = bridge_dir / "agent-response.md"
        instruction_path = bridge_dir / "next-agent-instruction.md"
        response_path.write_text(RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8")

        import time

        older = time.time() - 3600
        os.utime(response_path, (older, older))
        os.utime(instruction_path, None)

        status, body = self._post(
            "/api/session/run_loop/bridge/ingest_response", {"workspace_path": str(stale_workspace)}
        )
        self.assertEqual(status, 400)
        self.assertIn("older than the current instruction", body["error"])
        self.assertEqual(body["reason"], "stale_response")


class TestBridgeFreshnessSessionExport(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _make_controller(self._tmpdir.name)
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_session_export_includes_blocked_bridge_diagnostics(self) -> None:
        write_next_instruction_with_controller(self.controller, self.workspace)
        (self.workspace / ".admissible" / "agent-response.md").write_text(
            RAW_INSTALL_DEPENDENCY_RESPONSE, encoding="utf-8"
        )
        ingest_response_file_with_controller(self.controller, self.workspace)

        with self.assertRaises(DuplicateResponseError):
            ingest_response_file_with_controller(self.controller, self.workspace)

        exported = self.controller.session_dict()
        blocked = [e for e in exported["transcript"] if e["type"] == "bridge_ingest_blocked"]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["payload"]["reason"], "duplicate_response")
        self.assertEqual(len(exported["queue"]), 1)


class TestCursorBridgeHtmlContent(unittest.TestCase):
    """Requirement: the Cursor file bridge is the single visible default
    workflow. Manual copy/paste lives only inside a collapsed "Advanced
    manual paste fallback" <details>, never as the default visible path."""

    def setUp(self) -> None:
        self.raw = HTML_PATH.read_text(encoding="utf-8")

    def test_bridge_is_the_single_top_level_workflow_panel(self) -> None:
        self.assertIn('id="cursor-bridge-panel"', self.raw)
        self.assertIn("Cursor supervised file bridge", self.raw)
        # No separate top-level "Run Loop" panel/heading exists any more --
        # the file bridge is the only visible workflow card.
        self.assertNotIn('id="run-loop-panel"', self.raw)

    def test_workspace_step_present(self) -> None:
        self.assertIn('id="bridge-workspace-path"', self.raw)
        self.assertIn('id="bridge-workspace-status"', self.raw)

    def test_bridge_buttons_present_with_unambiguous_labels(self) -> None:
        self.assertIn('id="btn-bridge-write-instruction"', self.raw)
        self.assertIn("Write instruction file", self.raw)
        self.assertIn('id="btn-bridge-ingest-response"', self.raw)
        self.assertIn("Ingest Cursor response file", self.raw)
        self.assertIn('id="btn-bridge-open-workspace"', self.raw)
        self.assertIn("Open workspace in Cursor", self.raw)

    def test_ambiguous_labels_removed(self) -> None:
        self.assertNotIn("Write packet file", self.raw)
        self.assertNotIn("Cursor file bridge (optional)", self.raw)
        self.assertNotIn("(copy into Cursor)", self.raw)

    def test_bridge_status_containers_present(self) -> None:
        self.assertIn('id="bridge-write-status"', self.raw)
        self.assertIn('id="bridge-open-status"', self.raw)
        self.assertIn('id="bridge-ingest-status"', self.raw)

    def test_nothing_executed_copy_present(self) -> None:
        self.assertIn("Nothing was executed by Admissible.", self.raw)

    def test_next_instruction_copy_present(self) -> None:
        self.assertIn("next_instruction", self.raw)

    def test_advanced_manual_fallback_is_collapsed_details(self) -> None:
        details_index = self.raw.index('<details id="advanced-manual-fallback-details">')
        summary_index = self.raw.index("<summary>Advanced manual paste fallback</summary>")
        self.assertGreater(summary_index, details_index)
        # A plain <details ...> tag (no "open" attribute) renders collapsed
        # by default in every browser.
        details_tag_end = self.raw.index(">", details_index)
        details_tag = self.raw[details_index:details_tag_end]
        self.assertNotIn("open", details_tag)

    def test_manual_paste_controls_inside_advanced_fallback_only(self) -> None:
        summary_index = self.raw.index("<summary>Advanced manual paste fallback</summary>")
        details_close = self.raw.index("</details>", summary_index)
        for marker in ('id="agent-response-input"', 'id="btn-ingest-response"', 'id="btn-generate-instruction"'):
            marker_index = self.raw.index(marker)
            self.assertGreater(marker_index, summary_index)
            self.assertLess(marker_index, details_close)
        # "Paste agent response" must not be visible outside the fallback.
        self.assertGreater(self.raw.index("Paste agent response"), summary_index)

    def test_bridge_routes_wired_in_script(self) -> None:
        self.assertIn("/api/session/run_loop/bridge/check_workspace", self.raw)
        self.assertIn("/api/session/run_loop/bridge/write_instruction", self.raw)
        self.assertIn("/api/session/run_loop/bridge/ingest_response", self.raw)
        self.assertIn("/api/session/run_loop/bridge/open_workspace", self.raw)

    def test_no_provider_network_calls_in_new_markup(self) -> None:
        forbidden_hosts = ("openai.com", "anthropic.com", "cursor.sh", "googleapis.com")
        for host in forbidden_hosts:
            self.assertNotIn(host, self.raw)


class TestCursorBridgeNoForbiddenExecution(unittest.TestCase):
    """Static-source checks backing the no-executor / no-provider-call /
    no-agent_os-import boundary for the new bridge module."""

    _SOURCE_PATH = REPO_ROOT / "admissible" / "runner" / "cursor_bridge.py"

    def setUp(self) -> None:
        self.source = self._SOURCE_PATH.read_text(encoding="utf-8")

    def test_no_agent_os_import(self) -> None:
        self.assertNotIn("import agent_os", self.source)
        self.assertNotIn("from agent_os", self.source)

    def test_no_shell_true_or_shell_execution_helpers(self) -> None:
        forbidden_tokens = ("shell=True", "os.system(", "os.popen(", " eval(", " exec(")
        for token in forbidden_tokens:
            self.assertNotIn(token, self.source, f"cursor_bridge.py unexpectedly contains {token!r}")

    def test_open_workspace_launch_is_explicitly_shell_false(self) -> None:
        self.assertIn("shell=False", self.source)

    def test_no_network_provider_sdk_imports_or_hosts(self) -> None:
        forbidden_tokens = (
            "import openai",
            "import anthropic",
            "google.generativeai",
            "requests.post",
            "import httpx",
        )
        lowered = self.source.lower()
        for token in forbidden_tokens:
            self.assertNotIn(token, lowered, f"cursor_bridge.py unexpectedly references {token!r}")
        for host in ("openai.com", "anthropic.com", "cursor.sh", "googleapis.com"):
            self.assertNotIn(host, self.source)


if __name__ == "__main__":
    unittest.main()
