"""Slice ADMISSIBLE_RUN_036 — terminal callable-backend pause semantics.

Verifies malformed/failed/timeout callable invocations pause immediately, never
oscillate into file-bridge waiting, never re-invoke on ordinary ticks, and require
an explicit retry before re-billing.

No real model/provider invocation; fixture backend only.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.agent_backend import (
    AGENT_INVOKE_FAILED,
    AGENT_INVOKE_MALFORMED,
    AGENT_INVOKE_TIMEOUT,
    FixtureAgentBackend,
    INVOCATION_STATUS_MALFORMED,
)
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import (
    HA_MODE_PAUSED,
    HA_NEXT_NONE,
    retry_callable_backend_invocation,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

CANONICAL_GOAL = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


def _no_subprocess(*args, **kwargs):
    raise AssertionError("no subprocess in terminal-pause tests")


class TestTerminalCallablePause(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.tmp / "sessions")
        self.invoke_count = 0

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _malformed_backend(self) -> FixtureAgentBackend:
        backend = FixtureAgentBackend([])
        backend.set_next_status(AGENT_INVOKE_MALFORMED)
        original = backend.invoke

        def counting_invoke(request):
            self.invoke_count += 1
            return original(request)

        backend.invoke = counting_invoke  # type: ignore[method-assign]
        return backend

    def _start(self, backend: FixtureAgentBackend) -> None:
        self.controller.submit_goal(CANONICAL_GOAL)
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace), backend=backend, max_turns=8
        )

    def test_malformed_callable_pauses_immediately(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            self._start(self._malformed_backend())
            state = self.controller.tick_high_autonomy_run()
        ha = state["high_autonomy_summary"]
        self.assertEqual(ha["mode"], HA_MODE_PAUSED)
        self.assertTrue(ha["backend_retry_required"])
        self.assertEqual(
            self.controller._session.high_autonomy_run.get("last_tick_step"),
            "backend_error",
        )
        record = self.controller._session.high_autonomy_run.get("pending_agent_invocation")
        self.assertEqual(record["status"], INVOCATION_STATUS_MALFORMED)
        self.assertIn(
            "Cursor Agent invocation stopped",
            ha["doing_now"],
        )
        self.assertNotIn("agent-response.md", ha["needed_now"])
        self.assertFalse(ha["auto_tick_safe"])

    def test_repeated_ticks_do_not_reinvoke(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            self._start(self._malformed_backend())
            self.controller.tick_high_autonomy_run()
            for _ in range(6):
                tick = self.controller.tick_high_autonomy_run()
                self.assertEqual(tick.get("high_autonomy_tick", {}).get("step"), "noop")
        self.assertEqual(self.invoke_count, 1)

    def test_repeated_ticks_do_not_plan_ingest_or_wait_oscillation(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            self._start(self._malformed_backend())
            self.controller.tick_high_autonomy_run()
            planned = []
            for _ in range(5):
                state = self.controller.tick_high_autonomy_run()
                planned.append(state["high_autonomy_summary"]["next_action"])
        self.assertEqual(planned, [HA_NEXT_NONE] * 5)

    def test_resume_alone_does_not_unpause_or_reinvoke(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            self._start(self._malformed_backend())
            self.controller.tick_high_autonomy_run()
            resume_state = self.controller.resume_high_autonomy_run()
        self.assertIn("high_autonomy_resume_blocked", resume_state)
        ha = resume_state["high_autonomy_summary"]
        self.assertTrue(ha["paused"])
        self.assertEqual(self.invoke_count, 1)

    def test_explicit_retry_allows_reinvoke_once(self) -> None:
        backend = self._malformed_backend()
        backend.enqueue_response(load_fixture(FIXTURES_DIR / "tiny_game_turn_1_agent_response.md"))
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            self._start(backend)
            self.controller.tick_high_autonomy_run()
            retry_callable_backend_invocation(self.controller)
            self.controller.tick_high_autonomy_run()
        self.assertEqual(self.invoke_count, 2)

    def test_timeout_and_failed_also_pause(self) -> None:
        for status in (AGENT_INVOKE_TIMEOUT, AGENT_INVOKE_FAILED):
            with self.subTest(status=status):
                ctrl = ControlSurfaceController(session_dir=self.tmp / f"s-{status}")
                backend = FixtureAgentBackend([])
                backend.set_next_status(status)
                with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
                    ctrl.submit_goal(CANONICAL_GOAL)
                    ctrl.start_high_autonomy_run(
                        workspace_path=str(self.workspace), backend=backend, max_turns=8
                    )
                    state = ctrl.tick_high_autonomy_run()
                ha = state["high_autonomy_summary"]
                self.assertEqual(ha["mode"], HA_MODE_PAUSED)
                self.assertTrue(ha["backend_retry_required"])


class TestCallableVsFileBridgeWording(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    def test_callable_summary_never_mentions_response_file(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        workspace = tmp / "ws"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=tmp / "sessions")
        backend = FixtureAgentBackend([])
        backend.set_next_status(AGENT_INVOKE_MALFORMED)
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            controller.submit_goal(CANONICAL_GOAL)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=8
            )
            state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]
        self.assertTrue(summary["is_callable_backend"])
        self.assertNotIn("agent-response.md", summary["doing_now"])
        self.assertNotIn("agent-response.md", summary["needed_now"])
        self.assertFalse(summary["waiting_for_agent"])

    def test_file_bridge_still_uses_response_file_wording(self) -> None:
        from admissible.agent_transport import FileBridgeAgentTransport

        tmp = Path(tempfile.mkdtemp())
        workspace = tmp / "ws"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=tmp / "sessions")
        transport = FileBridgeAgentTransport(workspace)
        with mock.patch.object(subprocess, "run", side_effect=_no_subprocess):
            controller.submit_goal(CANONICAL_GOAL)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), transport=transport, max_turns=8
            )
            controller.tick_high_autonomy_run()
            state = controller.state_view()
        summary = state["high_autonomy_summary"]
        self.assertFalse(summary["is_callable_backend"])
        self.assertTrue(summary["waiting_for_agent"])
        self.assertIn("response file", summary["doing_now"].lower())

    def test_ui_has_retry_backend_and_backend_error_panel(self) -> None:
        self.assertIn("btn-ha-retry-backend", self.html)
        self.assertIn("Backend retry required", self.html)
        self.assertIn("Environment status", self.html)


if __name__ == "__main__":
    unittest.main()
