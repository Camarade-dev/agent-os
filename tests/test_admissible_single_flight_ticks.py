from __future__ import annotations

import threading
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import (
    AGENT_AVAILABILITY_AVAILABLE,
    AGENT_INVOKE_SUCCESS,
    AgentBackend,
    AgentBackendAvailability,
    AgentInvocationRequest,
    AgentInvocationResult,
)
from admissible.control_surface import ControlSurfaceController


class _BlockingBackend(AgentBackend):
    backend_id = "blocking_fixture"

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.call_count = 0

    def availability(self) -> AgentBackendAvailability:
        return AgentBackendAvailability(
            status=AGENT_AVAILABILITY_AVAILABLE,
            configured=True,
            message="blocking test backend",
        )

    def invoke(self, request: AgentInvocationRequest) -> AgentInvocationResult:
        del request
        self.call_count += 1
        self.entered.set()
        self.release.wait(timeout=5)
        return AgentInvocationResult(
            status=AGENT_INVOKE_SUCCESS,
            response_text=(
                "ADMISSIBLE_STRUCTURED_OPERATION:\n"
                "{\"operation\":\"write_file\",\"path\":\"one.txt\",\"content\":\"1\"}"
            ),
            raw_stdout="proposal",
            exit_code=0,
        )


class TestAdmissibleSingleFlightTicks(unittest.TestCase):
    def test_concurrent_tick_does_not_invoke_backend_twice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            backend = _BlockingBackend()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create one.txt locally.")
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=6
            )
            first_result: list[dict] = []
            thread = threading.Thread(
                target=lambda: first_result.append(controller.tick_high_autonomy_run())
            )
            thread.start()
            self.assertTrue(backend.entered.wait(timeout=2))
            concurrent = controller.tick_high_autonomy_run()
            self.assertTrue(concurrent["tick_already_in_progress"])
            self.assertEqual(
                concurrent["high_autonomy_tick"]["step"], "tick_already_in_progress"
            )
            self.assertEqual(backend.call_count, 1)
            backend.release.set()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(backend.call_count, 1)


if __name__ == "__main__":
    unittest.main()
