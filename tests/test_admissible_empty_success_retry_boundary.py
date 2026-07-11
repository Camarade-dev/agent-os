"""RUN_045 PART J / PART G — bounded empty-success retry boundary.

An ``empty_success`` callable-backend invocation (process exit 0, no usable
response text) gets at most one *automatic* same-instruction retry when the
run opts in (``automatic_empty_success_retries=1``); a second consecutive
empty_success always requires an explicit operator retry (technical pause),
never a second automatic re-bill. The default (``automatic_empty_success_retries=0``,
matching RUN_038-044 behavior) still pauses immediately with zero automatic
retries, so existing callers are unaffected.

No real model/Cursor CLI calls -- FixtureAgentBackend only.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import AGENT_INVOKE_EMPTY_SUCCESS, AGENT_INVOKE_SUCCESS, FixtureAgentBackend
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import HA_MODE_PAUSED, HA_MODE_RUNNING


class TestEmptySuccessRetryBoundary(unittest.TestCase):
    def _controller(self) -> tuple[ControlSurfaceController, Path]:
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal("Create result.txt locally.")
        return controller, workspace

    def test_default_zero_automatic_retries_pauses_immediately(self) -> None:
        controller, workspace = self._controller()
        backend = FixtureAgentBackend()
        backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
        controller.start_high_autonomy_run(workspace_path=str(workspace), backend=backend, max_turns=6)
        state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]
        self.assertTrue(summary["backend_retry_required"])
        self.assertFalse(summary["backend_error"]["automatic_empty_success_retry_used"])
        self.assertEqual(len(backend.invocations), 1)
        # An ordinary tick while paused is a no-op -- never a silent re-bill.
        controller.tick_high_autonomy_run()
        self.assertEqual(len(backend.invocations), 1)

    def test_one_automatic_retry_then_success_never_pauses(self) -> None:
        controller, workspace = self._controller()
        backend = FixtureAgentBackend()
        backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
        controller.start_high_autonomy_run(
            workspace_path=str(workspace),
            backend=backend,
            max_turns=6,
            automatic_empty_success_retries=1,
        )
        state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]
        self.assertFalse(summary["backend_retry_required"], "must not require an operator retry yet")
        self.assertTrue(summary["backend_error"]["automatic_empty_success_retry_used"])
        self.assertEqual(summary["mode"], HA_MODE_RUNNING)
        self.assertEqual(len(backend.invocations), 1)
        # The queued automatic retry consumes the *same* instruction on the next tick.
        state = controller.tick_high_autonomy_run()
        self.assertEqual(len(backend.invocations), 2)

    def test_second_consecutive_empty_success_requires_explicit_retry(self) -> None:
        controller, workspace = self._controller()
        backend = FixtureAgentBackend()
        backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
        controller.start_high_autonomy_run(
            workspace_path=str(workspace),
            backend=backend,
            max_turns=6,
            automatic_empty_success_retries=1,
        )
        controller.tick_high_autonomy_run()  # first empty_success -> automatic retry queued
        backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
        state = controller.tick_high_autonomy_run()  # automatic retry invoked -> empty_success again
        summary = state["high_autonomy_summary"]
        self.assertTrue(summary["backend_retry_required"], "second empty_success must require an explicit operator retry")
        self.assertEqual(summary["mode"], HA_MODE_PAUSED)
        self.assertTrue(summary["backend_error"]["automatic_empty_success_retry_used"])
        self.assertEqual(len(backend.invocations), 2)
        # A normal tick never silently re-invokes a third time.
        controller.tick_high_autonomy_run()
        self.assertEqual(len(backend.invocations), 2)

    def test_diagnostics_fields_present_on_terminal_failure(self) -> None:
        controller, workspace = self._controller()
        backend = FixtureAgentBackend()
        backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
        controller.start_high_autonomy_run(workspace_path=str(workspace), backend=backend, max_turns=6)
        state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]
        for field in (
            "backend_error",
        ):
            self.assertIn(field, summary)
        backend_error = summary["backend_error"]
        for field in (
            "exit_code",
            "stdout_length",
            "stderr_summary",
            "automatic_empty_success_retry_used",
            "manual_retry_count",
            "latest_usable_response_invocation_id",
        ):
            self.assertIn(field, backend_error, msg=f"missing diagnostics field: {field}")
        self.assertEqual(backend_error["manual_retry_count"], 0)
        self.assertIsNone(backend_error["latest_usable_response_invocation_id"])

    def test_explicit_operator_retry_increments_manual_retry_count(self) -> None:
        controller, workspace = self._controller()
        backend = FixtureAgentBackend()
        backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
        controller.start_high_autonomy_run(workspace_path=str(workspace), backend=backend, max_turns=6)
        controller.tick_high_autonomy_run()
        controller.retry_callable_backend_invocation()
        backend.set_responses(
            [
                "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
                '{"operation": "write_file", "path": "result.txt", "content": "done\\n"}'
                "\n```\n"
            ]
        )
        controller.tick_high_autonomy_run()  # invoke retry -> response_ready
        state = controller.tick_high_autonomy_run()  # ingest the retried response
        summary = state["high_autonomy_summary"]
        self.assertEqual(summary["backend_error"].get("operator_retry_count"), 1)
        self.assertEqual(
            summary["backend_error"]["latest_usable_response_invocation_id"],
            summary["last_invocation_id"],
        )


if __name__ == "__main__":
    unittest.main()
