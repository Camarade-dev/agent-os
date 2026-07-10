from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import derive_acceptance_criteria_from_goal

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_007_regression.json"
)
CLI_006 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_006_regression.json"
)


def _response(operations: list[dict]) -> str:
    return "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )


def _passing_four_operations() -> list[dict]:
    return [
        {
            "operation": "write_file",
            "path": "index.html",
            "content": (
                '<!doctype html><html><head><link rel="stylesheet" href="style.css">'
                '</head><body><canvas id="game"></canvas><span id="score">0</span>'
                '<script src="game.js"></script></body></html>\n'
            ),
        },
        {"operation": "write_file", "path": "style.css", "content": "body{margin:0;}\n"},
        {
            "operation": "write_file",
            "path": "game.js",
            "content": (
                "let score=0; const collectibles=[]; function restart(){score=0;}\n"
                "document.addEventListener('keydown',e=>{"
                "if(e.key==='r'||e.key==='R')restart();"
                "if(e.key==='ArrowUp'||e.key==='w'||e.key==='a'||e.key==='s'||e.key==='d'){}});\n"
            ),
        },
        {
            "operation": "write_file",
            "path": "LOCAL_DEV.md",
            "content": "To run locally, open index.html in your browser.\n",
        },
    ]


class TestLiveAcceptanceInitialization(unittest.TestCase):
    def test_control_surface_start_run_derives_eight_granular_criteria(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            workspace.mkdir(parents=True)
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            controller.submit_goal(fixture["goal_text"])
            view = controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                max_turns=8,
                closure_reserve_turns=2,
            )
            criteria = view["high_autonomy_summary"]["acceptance_criteria"]
            self.assertEqual(len(criteria), 8)
            self.assertNotEqual(criteria[0]["criterion_id"], "goal_deliverable")
            self.assertTrue(all(item.get("verification") for item in criteria))

    def test_derive_acceptance_criteria_from_goal_matches_canonical_templates(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        derived = derive_acceptance_criteria_from_goal(fixture["goal_text"])
        self.assertEqual(len(derived), 8)
        ids = {item["criterion_id"] for item in derived}
        self.assertEqual(
            ids,
            {
                "required_files",
                "index_assets",
                "index_game_ui",
                "style_non_empty",
                "game_controls",
                "game_collectible_score",
                "game_restart",
                "local_usage",
            },
        )

    def test_four_writes_verify_and_complete_without_extra_model_call(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        operations = _passing_four_operations()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir(parents=True)
            transport = FixtureAgentTransport()
            transport.set_responses([])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(fixture["goal_text"])
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=transport,
                max_turns=8,
                closure_reserve_turns=2,
            )
            controller.ingest_agent_response(_response(operations))
            for _ in range(8):
                ha = controller._high_autonomy_state()
                if ha is None or not ha.active:
                    break
                state = controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"].get("outcome") == "completed":
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_verified_count"], 8)
            self.assertEqual(len(transport.written_instructions), 0)


if __name__ == "__main__":
    unittest.main()
