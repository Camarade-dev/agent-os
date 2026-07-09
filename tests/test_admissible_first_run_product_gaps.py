"""Executable documentation of the P0 first-run / product-UX gaps found by
slice ADMISSIBLE_AUDIT_013_PRODUCT_UX_GENERALIZATION_AND_LIVE_RUN_FLOW, now
fixed by slice ADMISSIBLE_UX_014_GOAL_FIRST_GATING.

The GAP-001 first-run gaps ("Generate next agent instruction" / bridge "Write
instruction file" succeeding on a blank session, a placeholder
"No goal has been submitted" packet reaching an external agent, the goal form
buried below the bridge/queue, the Slither-specific sample being the primary
default action) are now closed, so the `*GoalFirst*` classes assert the
implemented behavior directly -- no longer `@unittest.expectedFailure`. The
`*RefactorGuard*` class pins behavior that already worked and must not regress.

See benchmark/reports/admissible_product_ux_generalization_audit.md and
docs/admissible-control-surface.md.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import (
    GOAL_REQUIRED_REASON,
    ControlSurfaceController,
    NoGoalSubmittedError,
)
from admissible.runner import cursor_bridge

REPO_ROOT = Path(__file__).resolve().parent.parent
ADMISSIBLE_ROOT = REPO_ROOT / "admissible"
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

_LOCAL_GAME_GOAL = "Build a tiny local game page. Local only. Do not deploy."


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

    def _instruction_path(self) -> Path:
        return self.workspace / ".admissible" / "next-agent-instruction.md"


class TestInstructionRequiresGoalGoalFirst(_ControllerCase):
    """P0 fixed: an instruction packet must not exist before a goal exists.

    Previously `generate_next_instruction_packet()` succeeded on a blank
    session, advanced the run-loop turn, and produced a packet whose TASK
    section was literally "No goal has been submitted to Admissible yet.";
    the bridge then wrote that packet to the workspace and marked the turn
    awaiting-response. Slice ADMISSIBLE_UX_014 guards every instruction-
    producing path server-side (reason: ``goal_required``).
    """

    # 1 + 5. Manual "Generate next agent instruction" is blocked with no goal.
    def test_generate_instruction_without_goal_is_rejected(self) -> None:
        with self.assertRaises(NoGoalSubmittedError) as ctx:
            self.controller.generate_next_instruction_packet()
        self.assertEqual(ctx.exception.detail.get("reason"), GOAL_REQUIRED_REASON)
        # NoGoalSubmittedError is a ValueError so the HTTP layer 400s cleanly.
        self.assertIsInstance(ctx.exception, ValueError)
        # And the failed attempt must not have advanced the turn counter.
        self.assertEqual(self.controller.state_view()["run_loop"]["current_turn"], 0)

    # 1-4. Bridge write is blocked; no file, no turn advance, not awaiting.
    def test_bridge_write_instruction_without_goal_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            cursor_bridge.write_next_instruction_with_controller(
                self.controller, self.workspace
            )
        # 2. No instruction file was written.
        self.assertFalse(self._instruction_path().exists())
        view = self.controller.state_view()
        # 3. The run-loop turn did not advance.
        self.assertEqual(view["run_loop"]["current_turn"], 0)
        # 4. The bridge is not marked awaiting a response.
        self.assertFalse(view["session_diagnostics"]["bridge_awaiting_response"])

    def test_no_goal_placeholder_task_never_reaches_a_packet(self) -> None:
        # The literal "No goal has been submitted" task text must never be
        # produced as a real instruction packet for an external agent.
        try:
            state = self.controller.generate_next_instruction_packet()
        except ValueError:
            return  # rejection is the preferred behavior
        packets = state["run_loop"]["instruction_packets"]
        self.assertTrue(all("No goal has been submitted" not in p["task"] for p in packets))

    # 9. After a goal is submitted, the write path works exactly as before.
    def test_write_instruction_works_after_goal(self) -> None:
        self.controller.submit_goal(_LOCAL_GAME_GOAL)
        result = cursor_bridge.write_next_instruction_with_controller(
            self.controller, self.workspace
        )
        instruction = self._instruction_path()
        self.assertTrue(instruction.exists())
        self.assertEqual(result["run_loop"]["current_turn"], 1)
        text = instruction.read_text(encoding="utf-8")
        self.assertNotIn("No goal has been submitted", text)
        self.assertIn("Admissible Next Agent Instruction Packet", text)
        view = self.controller.state_view()
        self.assertTrue(view["session_diagnostics"]["bridge_awaiting_response"])
        self.assertEqual(view["run_phase"], "awaiting_agent_response")
        self.assertEqual(view["next_expected_action"], "ingest_agent_response")


class TestStateViewProductFields(_ControllerCase):
    """6 + 8. state_view exposes goal-first display/control fields."""

    def test_blank_session_state_view_is_goal_first(self) -> None:
        view = self.controller.state_view()
        self.assertFalse(view["has_goal"])
        self.assertEqual(view["run_phase"], "needs_goal")
        self.assertEqual(view["next_expected_action"], "submit_goal")

    def test_blank_session_disables_instruction_and_ingest_with_reason(self) -> None:
        view = self.controller.state_view()
        self.assertFalse(view["can_write_instruction"])
        self.assertEqual(view["write_instruction_disabled_reason"], GOAL_REQUIRED_REASON)
        self.assertFalse(view["can_ingest_response"])
        self.assertEqual(view["ingest_disabled_reason"], GOAL_REQUIRED_REASON)

    def test_after_goal_write_is_enabled_and_phase_advances(self) -> None:
        self.controller.submit_goal(_LOCAL_GAME_GOAL)
        view = self.controller.state_view()
        self.assertTrue(view["has_goal"])
        self.assertTrue(view["can_write_instruction"])
        self.assertIsNone(view["write_instruction_disabled_reason"])
        self.assertEqual(view["run_phase"], "ready_to_instruct")
        self.assertEqual(view["next_expected_action"], "write_instruction")
        # Ingest is still gated until an instruction packet exists.
        self.assertFalse(view["can_ingest_response"])
        self.assertEqual(view["ingest_disabled_reason"], "no_instruction")


class TestBlankSessionGoalFirstHtml(unittest.TestCase):
    """P0 fixed: the blank-session UI leads with goal submission, not with the
    bridge, the queue, diagnostics, or the Slither sample."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    # 7. Goal form comes before the bridge, queue, and diagnostics panels.
    def test_goal_form_appears_before_bridge_and_queue_panels(self) -> None:
        goal = self.html.index('id="goal-form-panel"')
        bridge = self.html.index('id="cursor-bridge-panel"')
        queue = self.html.index('id="admissible-queue-panel"')
        diagnostics = self.html.index('id="session-diagnostics-panel"')
        self.assertLess(goal, bridge, "goal form must come before the bridge panel")
        self.assertLess(goal, queue, "goal form must come before the queue panel")
        self.assertLess(goal, diagnostics, "goal form must come before diagnostics")

    # 8. Bridge controls are disabled/hidden with a goal_required reason.
    def test_bridge_controls_gated_on_goal_required(self) -> None:
        # A visible "submit a goal first" note lives inside the bridge panel.
        self.assertIn('id="bridge-goal-required-note"', self.html)
        self.assertIn("Submit a goal first.", self.html)
        # The gating JS keys off the server's product-state fields.
        self.assertIn("can_write_instruction", self.html)
        self.assertIn("goal_required", self.html)

    def test_sample_session_is_not_the_primary_default_action(self) -> None:
        # The sample loader must be a demoted/secondary affordance, not the
        # only primary-styled button in the header, and not named after one demo.
        self.assertNotIn("Load sample Slither session", self.html)
        sample_btn_start = self.html.index('id="btn-load-sample"')
        button_tag = self.html[self.html.rindex("<button", 0, sample_btn_start) : sample_btn_start + 60]
        self.assertIn("secondary", button_tag, "sample loader must not be primary-styled")

    def test_session_diagnostics_are_collapsed_by_default(self) -> None:
        # Diagnostics (session file path, sha/turn bookkeeping) belong in a
        # collapsed advanced/debug drawer, not an always-open first panel.
        panel_start = self.html.index('id="session-diagnostics-panel"')
        preceding = self.html[max(0, panel_start - 400) : panel_start]
        self.assertIn("<details", preceding, "diagnostics panel must sit inside a collapsed <details>")

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


class TestAdmissibleBoundary(unittest.TestCase):
    """12. No `agent_os` import leaks into any Admissible module."""

    def test_no_agent_os_imports_in_admissible_modules(self) -> None:
        violations: list[str] = []
        for path in sorted(ADMISSIBLE_ROOT.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "agent_os" or alias.name.startswith("agent_os."):
                            violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module
                    if module and (module == "agent_os" or module.startswith("agent_os.")):
                        violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
