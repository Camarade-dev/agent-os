from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import repair_inconsistent_executable_lifecycle
from admissible.high_autonomy_controller import (
    HA_STEP_INTERNAL_LIVELOCK,
    HA_STEP_INTERNAL_EXECUTION_MISMATCH,
    HighAutonomyPolicy,
    tick_high_autonomy_run,
)
from admissible.high_autonomy_policy import HighAutonomyPolicy as Policy
from admissible.run_loop import LIFECYCLE_READY_TO_EXECUTE

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_007_regression.json"
)


def _response(operations: list[dict]) -> str:
    return "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )


class TestNoProgressLivelock(unittest.TestCase):
    def test_zero_executor_selection_with_pending_executable_pauses_immediately(self) -> None:
        operations = [
            {
                "operation": "write_file",
                "path": "index.html",
                "content": "<!doctype html><canvas></canvas>\n",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "ws"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Local task")
            controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=6)
            controller.ingest_agent_response(_response(operations))
            with mock.patch.object(
                controller,
                "execute_bounded_local",
                side_effect=RuntimeError("bounded execution blocked for test"),
            ):
                state = tick_high_autonomy_run(controller, policy=Policy())
            summary = state["high_autonomy_summary"]
            self.assertTrue(summary["paused"])
            self.assertEqual(summary["current_step"], HA_STEP_INTERNAL_EXECUTION_MISMATCH)

    def test_repeated_no_progress_ticks_never_exceed_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "ws"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Local task")
            controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=6)
            ha = controller._high_autonomy_state()
            ha.auto_tick_safe = True
            ha.last_progress_fingerprint = '{"mode":"reviewing"}'
            controller._set_high_autonomy_state(ha)
            for _ in range(3):
                tick_high_autonomy_run(controller, policy=Policy())
            ha = controller._high_autonomy_state()
            self.assertLessEqual(ha.no_progress_tick_count, 2)
            if ha.paused:
                self.assertEqual(ha.current_step, HA_STEP_INTERNAL_LIVELOCK)

    def test_transcript_repetitions_are_coalesced(self) -> None:
        controller = ControlSurfaceController()
        controller._session.transcript = []
        from admissible.high_autonomy_controller import _append_coalesced_transcript

        payload = {"action_ids": []}
        for _ in range(5):
            _append_coalesced_transcript(controller, "high_autonomy_auto_executed", payload)
        self.assertEqual(len(controller._session.transcript), 1)
        coalesced = controller._session.transcript[0]["coalesced"]
        self.assertEqual(coalesced["repetition_count"], 5)

    def test_stranded_allow_action_repaired_to_ready_to_execute(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        stranded = fixture["stranded_action"]
        queue_item = {
            "action_id": stranded["action_id"],
            "action_type": "create_file",
            "tool_or_command": "write_file LOCAL_DEV.md",
            "decision": stranded["decision"],
            "operational_admissibility_action": "execute",
            "execution_status": stranded["execution_status"],
            "lifecycle_status": stranded["lifecycle_status"],
            "required_approval": "none",
        }
        ws = Path(tempfile.mkdtemp()) / "ws"
        ws.mkdir()
        repairs = repair_inconsistent_executable_lifecycle(
            [queue_item],
            run_envelopes={
                stranded["action_id"]: {
                    "candidate": {
                        "structured_operations": [
                            {"operation": "write_file", "path": "LOCAL_DEV.md", "content": "Open index.html locally\n"}
                        ],
                        "action_type": "create_file",
                    },
                    "decision": {"decision": "ALLOW", "operational_admissibility_action": "execute"},
                }
            },
            workspace_path=str(ws),
            governance_records=[],
        )
        self.assertEqual(queue_item["lifecycle_status"], "ready_to_execute")
        self.assertEqual(repairs, 1)


if __name__ == "__main__":
    unittest.main()
