"""Executable documentation of the P0 first-run / product-UX gaps found by
slice ADMISSIBLE_AUDIT_013_PRODUCT_UX_GENERALIZATION_AND_LIVE_RUN_FLOW.

Each test in the `*DesiredBehavior*` classes asserts the behavior the product
SHOULD have and is marked ``@unittest.expectedFailure`` because the current
implementation does not have it yet. The suite therefore stays green today;
when a fix lands, the fixed test reports an unexpected success so the
decorator must be removed in the same change. The `*RefactorGuard*` class
pins behavior that already works and must not regress during the UI refactor.

See benchmark/reports/admissible_product_ux_generalization_audit.md.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.runner import cursor_bridge

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"


class _ControllerCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.workspace = base / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(
            session_dir=base / "sessions", repo_root=REPO_ROOT
        )
        self.addCleanup(self._tmp.cleanup)


class TestInstructionRequiresGoalDesiredBehavior(_ControllerCase):
    """P0: an instruction packet must not exist before a goal exists.

    Today `generate_next_instruction_packet()` succeeds on a blank session,
    advances the run-loop turn, and produces a packet whose TASK section is
    literally "No goal has been submitted to Admissible yet."; the bridge
    then writes that packet to the workspace and marks the turn
    awaiting-response (an impossible state: awaiting a Cursor response to a
    run that has no goal).
    """

    @unittest.expectedFailure
    def test_generate_instruction_without_goal_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.controller.generate_next_instruction_packet()
        # And the failed attempt must not have advanced the turn counter.
        self.assertEqual(self.controller.state_view()["run_loop"]["current_turn"], 0)

    @unittest.expectedFailure
    def test_bridge_write_instruction_without_goal_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            cursor_bridge.write_next_instruction_with_controller(
                self.controller, self.workspace
            )
        instruction = self.workspace / ".admissible" / "next-agent-instruction.md"
        self.assertFalse(instruction.exists())
        diag = self.controller.state_view()["session_diagnostics"]
        self.assertFalse(diag["bridge_awaiting_response"])

    @unittest.expectedFailure
    def test_no_goal_placeholder_task_never_reaches_a_packet(self) -> None:
        # Even if generation is allowed some day for a preview, the literal
        # "No goal has been submitted" task text must never be produced as a
        # real instruction packet for an external agent.
        try:
            state = self.controller.generate_next_instruction_packet()
        except ValueError:
            return  # rejection is the preferred behavior
        packets = state["run_loop"]["instruction_packets"]
        self.assertTrue(all("No goal has been submitted" not in p["task"] for p in packets))


class TestBlankSessionGoalFirstDesiredBehavior(unittest.TestCase):
    """P0: the blank-session UI must lead with goal submission, not with
    diagnostics, the bridge, or the Slither sample."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    @unittest.expectedFailure
    def test_goal_form_appears_before_bridge_and_queue_panels(self) -> None:
        goal = self.html.index('id="goal-form-panel"')
        bridge = self.html.index('id="cursor-bridge-panel"')
        queue = self.html.index('id="admissible-queue-panel"')
        diagnostics = self.html.index('id="session-diagnostics-panel"')
        self.assertLess(goal, bridge, "goal form must come before the bridge panel")
        self.assertLess(goal, queue, "goal form must come before the queue panel")
        self.assertLess(goal, diagnostics, "goal form must come before diagnostics")

    @unittest.expectedFailure
    def test_sample_session_is_not_the_primary_default_action(self) -> None:
        # The sample loader must be a demoted/secondary affordance (secondary
        # style or inside an advanced/sample drawer), not the only
        # primary-styled button in the header, and not named after one demo.
        self.assertNotIn("Load sample Slither session", self.html)
        sample_btn_start = self.html.index('id="btn-load-sample"')
        button_tag = self.html[self.html.rindex("<button", 0, sample_btn_start) : sample_btn_start + 60]
        self.assertIn("secondary", button_tag, "sample loader must not be primary-styled")

    @unittest.expectedFailure
    def test_session_diagnostics_are_collapsed_by_default(self) -> None:
        # Diagnostics (session file path, sha/turn bookkeeping) belong in a
        # collapsed advanced/debug drawer, not an always-open first panel.
        panel_start = self.html.index('id="session-diagnostics-panel"')
        preceding = self.html[max(0, panel_start - 400) : panel_start]
        self.assertIn("<details", preceding, "diagnostics panel must sit inside a collapsed <details>")

    @unittest.expectedFailure
    def test_goal_placeholder_is_not_slither_specific(self) -> None:
        goal_input = self.html.index('id="goal-input"')
        placeholder_region = self.html[goal_input : goal_input + 200]
        self.assertNotIn("Slither", placeholder_region)


class TestBridgeRefactorGuards(_ControllerCase):
    """Already-correct behavior the UI refactor must not regress."""

    def test_bridge_ingest_writes_nothing_outside_admissible_dir(self) -> None:
        self.controller.submit_goal("Build a tiny local game page. Local only. Do not deploy.")
        cursor_bridge.write_next_instruction_with_controller(self.controller, self.workspace)
        (self.workspace / ".admissible" / "agent-response.md").write_text(
            "=== PROPOSED OPERATION ===\n"
            "operation: write_file\n"
            "path: game.html\n"
            "content:\n<canvas></canvas>\n"
            "=== END PROPOSED OPERATION ===\n",
            encoding="utf-8",
        )
        cursor_bridge.ingest_response_file_with_controller(self.controller, self.workspace)
        outside = [
            str(p.relative_to(self.workspace))
            for p in self.workspace.rglob("*")
            if p.is_file() and ".admissible" not in p.parts
        ]
        self.assertEqual(outside, [], "ingest must never create files outside .admissible/")

    def test_bounded_execution_still_requires_admission(self) -> None:
        self.controller.submit_goal("Build a tiny local game page. Local only. Do not deploy.")
        cursor_bridge.write_next_instruction_with_controller(self.controller, self.workspace)
        (self.workspace / ".admissible" / "agent-response.md").write_text(
            "I plan to deploy the app to production and install packages.\n",
            encoding="utf-8",
        )
        state = cursor_bridge.ingest_response_file_with_controller(self.controller, self.workspace)
        for item in state["queue"]:
            if item["decision"] == "ALLOW":
                continue
            with self.assertRaises(ValueError):
                self.controller.execute_bounded_local(
                    item["action_id"], {"workspace_path": str(self.workspace)}
                )

    def test_session_export_declares_no_admissible_side_effect(self) -> None:
        view = self.controller.state_view()
        self.assertFalse(view["mission_summary"]["side_effect_executed_by_admissible"])


if __name__ == "__main__":
    unittest.main()
