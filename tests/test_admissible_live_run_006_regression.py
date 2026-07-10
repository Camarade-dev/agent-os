from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController


FIXTURE = (
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


class TestAdmissibleLiveRun006Regression(unittest.TestCase):
    def test_minimized_cli_006_fixture_closes_without_original_defects(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        states = fixture["file_states"]
        operations = [
            {"operation": "write_file", "path": "index.html", "content": "<!doctype html><canvas></canvas>\n"},
            {"operation": "write_file", "path": "style.css", "content": states["style"]["content"]},
            {"operation": "write_file", "path": "game.js", "content": "let score=0;\n"},
            {"operation": "write_file", "path": "LOCAL_DEV.md", "content": states["local_dev"]["content"]},
            {"operation": "write_file", "path": "index.html", "content": states["index_v2"]["content"]},
            {"operation": "write_file", "path": "game.js", "content": states["game_v2"]["content"]},
            # Same canonical operation as the earlier LOCAL_DEV.md write.
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
            state = controller.state_view()
            for _ in range(8):
                state = controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["outcome"]:
                    break

            summary = state["high_autonomy_summary"]
            metrics = summary["metrics"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_verified_count"], 8)
            self.assertEqual(metrics["useful_write_count"], 6)
            self.assertEqual(metrics["duplicate_noop_count"], 1)
            self.assertEqual(metrics["overwrite_count"], 2)
            self.assertEqual(metrics["genuine_human_intervention_count"], 0)
            self.assertEqual(metrics["active_blocked_count"], 0)
            self.assertEqual(summary["blocked_action_count"], metrics["active_blocked_count"])
            self.assertEqual(metrics["work_turns_used"], 1)
            self.assertLess(controller._session.run_loop.current_turn, 12)
            self.assertEqual(summary["verification_readiness"], "pass")
            self.assertTrue(all((workspace / name).is_file() for name in ("index.html", "style.css", "game.js", "LOCAL_DEV.md")))


if __name__ == "__main__":
    unittest.main()
