from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.execution.bounded_local_verification import (
    VerificationRequest,
    run_single_verification_check,
)
from admissible.governed_run import FINAL_OUTCOMES, build_proposal_coverage_report

FIXTURE_010 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_010_regression.json"
)
FIXTURE_007 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_007_regression.json"
)
FIXTURE_006 = (
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


def _cli010_game_js() -> str:
    return (
        "(function(){'use strict'; var keys={};"
        "window.addEventListener('keydown',function(e){keys[e.key]=true;});"
        "window.addEventListener('keyup',function(e){keys[e.key]=false;});"
        "function update(){"
        "if(keys.ArrowUp||keys.w||keys.W){}"
        "if(keys.ArrowDown||keys.s||keys.S){}"
        "if(keys.ArrowLeft||keys.a||keys.A){}"
        "if(keys.ArrowRight||keys.d||keys.D){}"
        "}"
        "let score=0; const collectibles=[]; function collect(item){score+=1;collectibles.push(item);}"
        "function restart(){score=0;}"
        "document.addEventListener('keydown',e=>{if(e.key==='r'||e.key==='R')restart();});"
        "update();})();"
    )


class TestAdmissibleLiveRun010Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_010.read_text(encoding="utf-8"))

    def test_fixture_documents_cli010_defect_surface(self) -> None:
        self.assertEqual(self.fixture["source_session"], "pixel-wanderer-cli-010")
        self.assertEqual(self.fixture["missing_mandatory_path"], "LOCAL_DEV.md")
        self.assertEqual(self.fixture["final_state_before_fix"]["current_step"], "internal_livelock")

    def test_cli010_game_js_wasd_present_under_property_access_matcher(self) -> None:
        workspace = Path(tempfile.mkdtemp())
        game_path = workspace / "game.js"
        game_path.write_text(_cli010_game_js(), encoding="utf-8")
        result = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="game_controls_check",
                target_paths=["game.js"],
                criterion_id="game_controls",
            ),
        )
        self.assertEqual(result.status, "pass")
        payload = result.evidence_payload
        self.assertEqual(payload["subchecks"]["w"], "pass")
        self.assertEqual(payload["failed_subchecks"], {})

    def test_cli010_partial_batch_replay_closes_with_repair(self) -> None:
        goal = self.fixture["goal_text"]
        initial_ops = [
            {
                "operation": "write_file",
                "path": "index.html",
                "content": '<!doctype html><link rel="stylesheet" href="style.css"><canvas id="game"></canvas><span id="score">0</span><script src="game.js"></script>\n',
            },
            {"operation": "write_file", "path": "style.css", "content": "body{margin:0;}\n"},
            {"operation": "write_file", "path": "game.js", "content": _cli010_game_js()},
            {
                "operation": "write_file",
                "path": "README.md",
                "content": "# Pixel Wanderer\nOptional readme.\n",
            },
        ]
        repair_ops = [
            {
                "operation": "write_file",
                "path": "LOCAL_DEV.md",
                "content": "To run locally, open index.html in your browser.\n",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([_response(repair_ops)])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=transport,
                max_turns=8,
                closure_reserve_turns=2,
            )
            controller.ingest_agent_response(_response(initial_ops))
            coverage = build_proposal_coverage_report(
                goal_text=goal,
                structured_operations=initial_ops,
            )
            self.assertFalse(coverage["coverage_complete"])
            self.assertEqual(coverage["missing_required_paths"], ["LOCAL_DEV.md"])
            self.assertEqual(coverage["additional_paths"], ["README.md"])
            for _ in range(20):
                ha = controller._high_autonomy_state()
                if ha is None or not ha.active:
                    break
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_verified_count"], 8)
            self.assertEqual(len(transport.written_instructions), 1)

    def test_cli006_and_cli007_fixtures_still_supported(self) -> None:
        self.assertTrue(FIXTURE_006.exists())
        self.assertTrue(FIXTURE_007.exists())


if __name__ == "__main__":
    unittest.main()
