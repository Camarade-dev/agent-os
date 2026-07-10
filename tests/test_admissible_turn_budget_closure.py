from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController


class TestAdmissibleTurnBudgetClosure(unittest.TestCase):
    def _controller(self, root: Path, *, max_turns: int, criteria=None):
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal("Create final.txt locally.")
        controller.start_high_autonomy_run(
            workspace_path=str(workspace),
            transport=FixtureAgentTransport(),
            max_turns=max_turns,
            closure_reserve_turns=1,
            acceptance_criteria=criteria,
        )
        return controller, workspace

    def test_closure_phase_starts_before_max_and_verifies_without_model_call(self) -> None:
        criteria = [
            {
                "criterion_id": "final_exists",
                "source_text": "final.txt exists.",
                "verification": [{"check_id": "file_exists", "target_paths": ["final.txt"]}],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            controller, workspace = self._controller(Path(tmp), max_turns=4, criteria=criteria)
            (workspace / "final.txt").write_text("done", encoding="utf-8", newline="")
            controller._session.run_loop.current_turn = 3
            controller._session.high_autonomy_run["mode"] = "reviewing"
            controller._session.high_autonomy_run["awaiting_instruction_after_review"] = True
            state = controller.tick_high_autonomy_run()
            self.assertTrue(state["high_autonomy_tick"]["verified"])
            self.assertEqual(state["high_autonomy_summary"]["phase"], "closure")
            self.assertEqual(state["high_autonomy_summary"]["outcome"], "completed")
            self.assertEqual(
                state["high_autonomy_summary"]["metrics"]["model_invocation_count"], 0
            )

    def test_budget_exhaustion_is_explicit_with_unmet_criteria(self) -> None:
        criteria = [
            {
                "criterion_id": "missing_file",
                "source_text": "missing.txt exists.",
                "verification": [{"check_id": "file_exists", "target_paths": ["missing.txt"]}],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            controller, _workspace = self._controller(Path(tmp), max_turns=2, criteria=criteria)
            controller._session.run_loop.current_turn = 2
            controller._session.high_autonomy_run["mode"] = "reviewing"
            first = controller.tick_high_autonomy_run()
            self.assertTrue(first["high_autonomy_tick"]["verified"])
            summary = first["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "stopped_by_budget")
            self.assertIn("missing_file", summary["unmet_criteria"])
            self.assertIn("Model invocation budget exhausted", summary["outcome_reason"])


if __name__ == "__main__":
    unittest.main()
