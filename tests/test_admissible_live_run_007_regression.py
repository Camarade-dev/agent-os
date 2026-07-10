from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController, ResponseExtractionFailed
from admissible.governed_run import build_agent_response_extraction_report
from admissible.long_run_envelope_builder import build_from_raw_output
from admissible.run_loop import build_candidates_from_agent_response

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


class TestAdmissibleLiveRun007Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_007.read_text(encoding="utf-8"))

    def test_old_misroute_table_row_produced_zero_candidates(self) -> None:
        """Document the historical defect path without reintroducing it in production."""

        from admissible.long_run_envelope_builder import (
            _build_from_production_readiness_report,
            _is_production_readiness_report,
        )

        raw = self.fixture["turn_responses"]["1"]
        self.assertTrue(_is_production_readiness_report(raw) is False)
        built = build_from_raw_output(raw)
        self.assertGreaterEqual(len(built["action_candidates"]), 4)

    def test_turn1_through_turn4_exact_shapes_extract_four_operations(self) -> None:
        for turn in ("1", "2", "3", "4", "5"):
            with self.subTest(turn=turn):
                raw = self.fixture["turn_responses"][turn]
                built = build_candidates_from_agent_response(raw, turn_number=int(turn))
                structured = [
                    entry
                    for entry in built
                    if entry["candidate"].get("structured_operations")
                ]
                self.assertEqual(len(structured), 4)

    def test_reextract_after_code_fix_ingests_turn1_without_provider(self) -> None:
        controller = ControlSurfaceController()
        controller.submit_goal(self.fixture["goal_text"])
        broken = (
            "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n{not valid}\n```\n"
        )
        with self.assertRaises(ResponseExtractionFailed):
            controller.ingest_agent_response(broken)
        controller._session.run_loop.response_records[-1].raw_text = self.fixture["turn_responses"]["1"]
        view = controller.reextract_last_agent_response()
        self.assertGreaterEqual(len(view["queue"]), 4)

    def test_turn5_batch_executes_all_four_and_can_close(self) -> None:
        operations = _passing_four_operations()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(self.fixture["goal_text"])
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
                if state["high_autonomy_summary"].get("outcome"):
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_verified_count"], 8)
            self.assertEqual(len(transport.written_instructions), 0)

    def test_cli_006_regression_fixture_still_closes(self) -> None:
        fixture = json.loads(FIXTURE_006.read_text(encoding="utf-8"))
        states = fixture["file_states"]
        operations = [
            {"operation": "write_file", "path": "index.html", "content": "<!doctype html><canvas></canvas>\n"},
            {"operation": "write_file", "path": "style.css", "content": states["style"]["content"]},
            {"operation": "write_file", "path": "game.js", "content": "let score=0;\n"},
            {"operation": "write_file", "path": "LOCAL_DEV.md", "content": states["local_dev"]["content"]},
            {"operation": "write_file", "path": "index.html", "content": states["index_v2"]["content"]},
            {"operation": "write_file", "path": "game.js", "content": states["game_v2"]["content"]},
            {"operation": "write_file", "path": "LOCAL_DEV.md", "content": states["local_dev"]["content"]},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([_response(operations)])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(
                "Build the final Pixel Wanderer local files: index.html, style.css, game.js, and LOCAL_DEV.md."
            )
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=transport,
                max_turns=fixture["budget"]["max_turns"],
                closure_reserve_turns=fixture["budget"]["closure_reserve_turns_post_038"],
                acceptance_criteria=fixture["acceptance_criteria"],
            )
            for _ in range(8):
                state = controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["outcome"]:
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_verified_count"], 8)


if __name__ == "__main__":
    unittest.main()
