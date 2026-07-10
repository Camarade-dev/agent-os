from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import AGENT_INVOKE_EMPTY_SUCCESS, FixtureAgentBackend
from admissible.control_surface import ControlSurfaceController


def _write_response() -> str:
    return "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n" + json.dumps(
        {"operation": "write_file", "path": "result.txt", "content": "done\n"}
    ) + "\n```\n"


class TestAdmissibleEmptySuccessRetry(unittest.TestCase):
    def test_empty_success_pauses_and_does_not_rebill_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            backend = FixtureAgentBackend()
            backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create result.txt locally.")
            state = controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=6
            )
            del state
            stopped = controller.tick_high_autonomy_run()
            summary = stopped["high_autonomy_summary"]
            self.assertTrue(summary["backend_retry_required"])
            self.assertEqual(summary["pending_invocation_status"], "empty_success")
            self.assertEqual(len(backend.invocations), 1)
            self.assertEqual(summary["metrics"]["empty_success_count"], 1)

            # A normal tick while paused is a no-op and never invokes again.
            controller.tick_high_autonomy_run()
            self.assertEqual(len(backend.invocations), 1)

    def test_explicit_retry_preserves_instruction_and_creates_one_new_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            backend = FixtureAgentBackend()
            backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create result.txt locally.")
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=6
            )
            controller.tick_high_autonomy_run()
            first_record = controller.session_dict()["high_autonomy_run"]["invocation_history"][0]
            backend.enqueue_response(_write_response())
            controller.retry_callable_backend_invocation()
            retried = controller.tick_high_autonomy_run()
            history = retried["high_autonomy_summary"]["metrics"]
            records = controller.session_dict()["high_autonomy_run"]["invocation_history"]
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1]["retry_of_invocation_id"], first_record["invocation_id"])
            self.assertEqual(records[1]["attempt_number"], 2)
            self.assertEqual(records[1]["instruction_id"], first_record["instruction_id"])
            self.assertEqual(
                records[1]["instruction_sha256"], first_record["instruction_sha256"]
            )
            self.assertEqual(backend.invocations[1].instruction_text, backend.invocations[0].instruction_text)
            self.assertEqual(history["backend_retry_count"], 1)

            controller.tick_high_autonomy_run()  # ingest only the successful attempt
            controller.tick_high_autonomy_run()  # bounded execution
            self.assertEqual(
                sum(1 for record in controller._session.run_loop.response_records), 1
            )
            self.assertEqual(
                controller.state_view()["canonical_run_metrics"]["useful_write_count"], 1
            )

    def test_one_automatic_retry_requires_explicit_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            backend = FixtureAgentBackend([_write_response()])
            backend.set_next_status(AGENT_INVOKE_EMPTY_SUCCESS)
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create result.txt locally.")
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                backend=backend,
                max_turns=6,
                automatic_empty_success_retries=1,
            )
            first = controller.tick_high_autonomy_run()
            self.assertEqual(
                first["high_autonomy_tick"]["last_tick_step"],
                "empty_success_retry_queued",
            )
            second = controller.tick_high_autonomy_run()
            self.assertEqual(len(backend.invocations), 2)
            self.assertEqual(
                second["high_autonomy_summary"]["metrics"]["backend_retry_count"], 1
            )
            self.assertFalse(second["high_autonomy_summary"]["backend_retry_required"])


if __name__ == "__main__":
    unittest.main()
