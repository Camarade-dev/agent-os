from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_policy import HighAutonomyPolicy

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


class TestPartialBatchDrain(unittest.TestCase):
    def test_four_action_batch_drains_three_then_one_without_model_calls(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        operations = [
            {"operation": "write_file", "path": "index.html", "content": "<!doctype html><canvas id=\"game\"></canvas><span id=\"score\">0</span>\n"},
            {"operation": "write_file", "path": "style.css", "content": "body{margin:0;}\n"},
            {"operation": "write_file", "path": "game.js", "content": "let score=0; const keys={}; function restart(){score=0;} addEventListener('keydown',e=>{if(e.key==='r'||e.key==='R')restart(); if('ArrowUp' in keys||'w' in keys){}});\n"},
            {"operation": "write_file", "path": "LOCAL_DEV.md", "content": "Open index.html locally — no server required.\n"},
        ]
        policy = HighAutonomyPolicy(max_auto_executions_per_turn=3)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([_response(operations)])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(fixture["goal_text"])
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=transport,
                max_turns=8,
                closure_reserve_turns=2,
            )
            controller.ingest_agent_response(_response(operations))
            first = controller.tick_high_autonomy_run(policy=policy)
            first_executed = first.get("high_autonomy_tick", {}).get("executed_action_ids") or []
            self.assertEqual(len(first_executed), 3)
            second = controller.tick_high_autonomy_run(policy=policy)
            second_executed = second["high_autonomy_tick"].get("executed_action_ids") or []
            self.assertEqual(len(second_executed), 1)
            self.assertEqual(len(transport.written_instructions), 0)
            metrics = second["high_autonomy_summary"]["metrics"]
            self.assertEqual(metrics["useful_write_count"], 4)


if __name__ == "__main__":
    unittest.main()
