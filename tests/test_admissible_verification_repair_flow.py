from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import FINAL_OUTCOMES, build_repair_packet
from admissible.high_autonomy_controller import REPAIR_PHASE_REPAIR_NEEDED


def _response(operations: list[dict]) -> str:
    return "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )


class TestAdmissibleVerificationRepairFlow(unittest.TestCase):
    GOAL = (
        "Build Pixel Wanderer with mandatory deliverables:\n"
        "- index.html\n- style.css\n- game.js\n- LOCAL_DEV.md\n"
        "Arrow-key and WASD movement; collectible score; restart with R; local usage instructions."
    )

    def _game_js(self) -> str:
        return (
            "const keys={}; addEventListener('keydown',e=>keys[e.key]=true);"
            "if(keys.ArrowUp||keys.w){} if(keys.ArrowDown||keys.s){}"
            "if(keys.ArrowLeft||keys.a){} if(keys.ArrowRight||keys.d){}"
            "let score=0; const collectibles=[]; function restart(){score=0;}"
            "addEventListener('keydown',e=>{if(e.key==='R')restart();});"
        )

    def test_verification_fail_transitions_to_repair_not_livelock(self) -> None:
        initial = [
            {"operation": "write_file", "path": "index.html", "content": '<html><canvas id="game"></canvas><span id="score">0</span><script src="game.js"></script></html>\n'},
            {"operation": "write_file", "path": "style.css", "content": "body{}\n"},
            {"operation": "write_file", "path": "game.js", "content": self._game_js()},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([
                _response([{"operation": "write_file", "path": "LOCAL_DEV.md", "content": "open index.html locally\n"}])
            ])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(self.GOAL)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), transport=transport, max_turns=8, closure_reserve_turns=2
            )
            controller.ingest_agent_response(_response(initial))
            saw_repair = False
            for _ in range(20):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                if summary.get("repair_phase") == REPAIR_PHASE_REPAIR_NEEDED:
                    saw_repair = True
                self.assertNotEqual(summary.get("current_step"), "internal_livelock")
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            self.assertTrue(saw_repair)

    def test_repair_packet_contains_only_failed_criteria_and_paths(self) -> None:
        criteria = [
            {"criterion_id": "required_files", "mandatory": True, "status": "verified_fail"},
            {"criterion_id": "index_assets", "mandatory": True, "status": "verified_pass"},
        ]
        packet = build_repair_packet(
            criteria=criteria,
            verification_record={
                "results": [
                    {
                        "criterion_id": "required_files",
                        "status": "fail",
                        "message": "Missing LOCAL_DEV.md",
                        "evidence_payload": {"missing_paths": ["LOCAL_DEV.md"]},
                    }
                ]
            },
            satisfied_file_hashes={"index.html": "abc"},
            goal_text=self.GOAL,
            remaining_turn_budget=3,
            repair_round=1,
        )
        self.assertEqual(packet["failed_criteria"], ["required_files"])
        self.assertIn("LOCAL_DEV.md", packet["missing_mandatory_paths"])
        self.assertNotIn("index_assets", packet["failed_criteria"])

    def test_zero_budget_yields_incomplete_not_livelock(self) -> None:
        initial = [
            {"operation": "write_file", "path": "index.html", "content": "<html></html>\n"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(self.GOAL)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=FixtureAgentTransport(),
                max_turns=1,
                closure_reserve_turns=0,
            )
            controller.ingest_agent_response(_response(initial))
            for _ in range(30):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                if not summary.get("active"):
                    break
            self.assertIn(summary["outcome"], {"incomplete", "stopped_by_budget", "in_progress"})
            self.assertNotEqual(summary.get("current_step"), "internal_livelock")

    def test_max_repair_rounds_prevent_infinite_loops(self) -> None:
        initial = [
            {"operation": "write_file", "path": "index.html", "content": "<html></html>\n"},
            {"operation": "write_file", "path": "style.css", "content": "body{}\n"},
            {"operation": "write_file", "path": "game.js", "content": "let score=0;\n"},
        ]
        useless_repair = _response([{"operation": "write_file", "path": "README.md", "content": "nope\n"}])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([useless_repair, useless_repair, useless_repair])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(self.GOAL)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), transport=transport, max_turns=10, closure_reserve_turns=2
            )
            ha = controller._high_autonomy_state()
            assert ha is not None
            ha.max_repair_rounds = 2
            controller._set_high_autonomy_state(ha)
            controller.ingest_agent_response(_response(initial))
            for _ in range(40):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            self.assertEqual(summary["outcome"], "incomplete")
            self.assertGreaterEqual(summary["metrics"].get("repair_round_count", 0), 1)


if __name__ == "__main__":
    unittest.main()
