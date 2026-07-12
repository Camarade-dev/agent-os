"""Slice ADMISSIBLE_RUN_034 tests — durable callable-backend response handoff.

Reproduces the live bug: a callable Cursor Agent CLI response was stored only on
the in-memory transport, so when the Control Surface reconstructs the controller/
backend/transport between HTTP ticks the pending response was lost and the loop
waited forever. These tests reconstruct a real controller between dispatch and
ingest and assert the response survives and is ingested exactly once.

Constraints exercised: no real Cursor Agent invocation (subprocess injected), no
provider calls, no direct target-workspace writes by the backend, admission
guards unchanged, no auto-approval.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.agent_backend import (
    INVOCATION_STATUS_CONSUMED,
    INVOCATION_STATUS_RESPONSE_READY,
    AgentInvocationRecord,
    CursorCliAgentBackend,
    CursorCliConfig,
    FixtureAgentBackend,
)
from admissible.control_surface import ControlSurfaceController
from admissible.runner.control_surface import build_controller as build_runner_controller
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"
TURN_1_FILES = ("index.html", "style.css", "game.js")

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _no_real_subprocess(*args, **kwargs):
    raise AssertionError("callable backend must never spawn a real subprocess in tests")


def _make_fake_cursor_agent(tmp: Path) -> Path:
    fake = tmp / "cursor-agent"
    fake.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    fake.chmod(0o755)
    return fake


def _ndjson_success(text: str) -> str:
    """Wrap ``text`` as a minimal one-line NDJSON terminal success event."""
    return json.dumps(
        {"type": "result", "subtype": "success", "is_error": False, "result": text}
    )


def _counting_runner(responses: list[str], counter: dict) -> "callable":
    queue = list(responses)

    def runner(argv, **kwargs):
        counter["n"] = counter.get("n", 0) + 1
        text = queue.pop(0) if queue else ""
        return _FakeCompleted(stdout=_ndjson_success(text), returncode=0)

    return runner


class TestReconstructionAcrossTicks(unittest.TestCase):
    """The mandatory test: a fresh controller between dispatch and ingest still works."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake = _make_fake_cursor_agent(self.tmp)
        self.sessions = self.tmp / "sessions"
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        self.counter: dict = {}

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _dispatch_on_controller_a(self) -> None:
        config = CursorCliConfig.cursor_agent_preset(command=str(self.fake))
        backend = CursorCliAgentBackend(
            config=config,
            runner=_counting_runner(
                [load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)], self.counter
            ),
        )
        controller_a = ControlSurfaceController(session_dir=self.sessions)
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            controller_a.submit_goal(CANONICAL_GOAL_PROMPT)
            controller_a.start_high_autonomy_run(
                workspace_path=str(self.workspace), backend=backend, max_turns=8
            )
            controller_a.tick_high_autonomy_run()  # write + invoke, persist response_ready

    def test_response_persisted_after_dispatch(self) -> None:
        self._dispatch_on_controller_a()
        controller_b = build_runner_controller(session_dir=self.sessions)
        pending = controller_b._session.high_autonomy_run.get("pending_agent_invocation")
        record = AgentInvocationRecord.from_dict(pending)
        self.assertIsNotNone(record)
        self.assertEqual(record.status, INVOCATION_STATUS_RESPONSE_READY)
        self.assertTrue((record.response_text or "").strip())
        self.assertTrue(record.response_sha256)

    def test_reconstructed_controller_ingests_pending_response(self) -> None:
        self._dispatch_on_controller_a()
        # Brand-new controller/transport instance B (transport is None after rebuild).
        controller_b = build_runner_controller(session_dir=self.sessions)
        self.assertIsNone(controller_b._high_autonomy_transport)
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            state = controller_b.tick_high_autonomy_run()
        tick = state.get("high_autonomy_tick") or {}
        self.assertEqual(tick.get("planned"), "ingest_response")
        self.assertTrue(tick.get("ingested"))
        self.assertEqual(len(controller_b._session.run_loop.response_records), 1)
        # The agent was invoked exactly once (on A) — never on the reconstructed B.
        self.assertEqual(self.counter.get("n"), 1)

    def test_repeated_ticks_do_not_reinvoke_or_reingest(self) -> None:
        self._dispatch_on_controller_a()
        controller_b = build_runner_controller(session_dir=self.sessions)
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            controller_b.tick_high_autonomy_run()  # ingest
            for _ in range(4):
                controller_b.tick_high_autonomy_run()  # auto-execute etc.
        # Exactly one response record and one invocation, regardless of extra ticks.
        self.assertEqual(len(controller_b._session.run_loop.response_records), 1)
        self.assertEqual(self.counter.get("n"), 1)
        pending = controller_b._session.high_autonomy_run.get("pending_agent_invocation")
        record = AgentInvocationRecord.from_dict(pending)
        self.assertEqual(record.status, INVOCATION_STATUS_CONSUMED)

    def test_consumed_response_ingested_exactly_once_writes_files_via_executor(self) -> None:
        self._dispatch_on_controller_a()
        controller_b = build_runner_controller(session_dir=self.sessions)
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            controller_b.tick_high_autonomy_run()  # ingest
            for _ in range(6):
                controller_b.tick_high_autonomy_run()
        # Files exist only because Admissible's bounded executor wrote them.
        for name in TURN_1_FILES:
            self.assertTrue((self.workspace / name).is_file())
        view = controller_b.state_view()
        executed = [
            item
            for item in view["queue"]
            if item["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertGreaterEqual(len(executed), 3)


class TestExactlyOnceAlignment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.tmp / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _start(self, backend) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace), backend=backend, max_turns=8
        )

    def test_invocation_record_aligns_turn_instruction_and_sha(self) -> None:
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            self._start(backend)
            self.controller.tick_high_autonomy_run()  # invoke + persist
        pending = self.controller._session.high_autonomy_run.get("pending_agent_invocation")
        record = AgentInvocationRecord.from_dict(pending)
        self.assertEqual(record.status, INVOCATION_STATUS_RESPONSE_READY)
        self.assertEqual(record.turn_number, self.controller._session.run_loop.current_turn)
        self.assertIsNotNone(record.instruction_id)
        self.assertIsNotNone(record.response_sha256)
        summary = self.controller.state_view()["high_autonomy_summary"]
        self.assertEqual(summary["last_invocation_id"], record.invocation_id)
        self.assertTrue(summary["is_callable_backend"])

    def test_export_import_retains_pending_response(self) -> None:
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            self._start(backend)
            self.controller.tick_high_autonomy_run()  # invoke + persist
        exported = self.controller.session_dict()
        self.assertIsNotNone(
            exported["high_autonomy_run"].get("pending_agent_invocation")
        )
        # Import into a brand-new controller (no transport) and ingest.
        fresh = ControlSurfaceController(session_dir=self.tmp / "fresh")
        fresh.import_session(exported)
        self.assertIsNone(fresh._high_autonomy_transport)
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            state = fresh.tick_high_autonomy_run()
        self.assertTrue((state.get("high_autonomy_tick") or {}).get("ingested"))
        self.assertEqual(len(fresh._session.run_loop.response_records), 1)

    def test_callable_backend_summary_not_waiting_for_response_file(self) -> None:
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            self._start(backend)
            state = self.controller.tick_high_autonomy_run()  # invoke -> response_ready
        summary = state["high_autonomy_summary"]
        # A callable backend never "waits for a response file".
        self.assertFalse(summary["waiting_for_agent"])
        self.assertTrue(summary["is_callable_backend"])
        self.assertEqual(summary["backend_step"], "response_ready")
        self.assertNotIn("agent-response.md", summary["needed_now"])


class TestFileBridgeSemanticsUnchanged(unittest.TestCase):
    def test_file_bridge_still_waits_for_external_response(self) -> None:
        from admissible.agent_transport import FileBridgeAgentTransport

        tmp = Path(tempfile.mkdtemp())
        workspace = tmp / "ws"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=tmp / "sessions")
        transport = FileBridgeAgentTransport(workspace)
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            controller.submit_goal(CANONICAL_GOAL_PROMPT)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), transport=transport, max_turns=8
            )
            controller.tick_high_autonomy_run()  # write instruction file
            state = controller.tick_high_autonomy_run()  # no response file yet
        summary = state["high_autonomy_summary"]
        # File bridge is genuinely waiting for an external response file.
        self.assertEqual(summary["transport_kind"], "file_bridge")
        self.assertFalse(summary["is_callable_backend"])
        self.assertTrue(summary["waiting_for_agent"])
        self.assertIsNone(summary["pending_invocation_status"])


class TestCallableUiWording(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    def test_ui_shows_callable_backend_step_not_response_file(self) -> None:
        self.assertIn("is_callable_backend", self.html)
        self.assertIn("Last invocation id", self.html)
        self.assertIn("Invoking agent CLI", self.html)
        self.assertIn("Response ready", self.html)
        # The callable branch must not tell the operator to wait for a file.
        self.assertIn("Waiting for external agent response file", self.html)


if __name__ == "__main__":
    unittest.main()
