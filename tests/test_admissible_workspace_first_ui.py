"""Slice ADMISSIBLE_RUN_032 tests — workspace-first UI + truth-boundary wording.

Verifies the target workspace and agent backend are first-class Control Surface
fields (not hidden under Advanced), that Start is blocked/warned for unsafe
targets, and that the truth-boundary wording is truthful about high-autonomy
auto-execution.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"


class TestAgentBackendControlStateView(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_state_view_exposes_agent_backend_control(self) -> None:
        control = self.controller.state_view()["agent_backend_control"]
        for key in (
            "target_workspace_path",
            "target_workspace_exists",
            "target_is_agent_os_repo",
            "agent_workspace_path",
            "backends",
            "can_start_high_autonomy",
            "start_blocking_reasons",
            "start_warnings",
        ):
            self.assertIn(key, control)
        ids = {b["backend_id"] for b in control["backends"]}
        self.assertEqual(ids, {"file_bridge", "cursor_cli", "fixture"})

    def test_start_blocked_when_no_target_workspace(self) -> None:
        control = self.controller.state_view()["agent_backend_control"]
        self.assertFalse(control["can_start_high_autonomy"])
        self.assertIn("No target workspace configured.", control["start_blocking_reasons"])

    def test_start_ready_with_valid_target_and_isolated_agent_workspace(self) -> None:
        target = self.root / "project"
        target.mkdir()
        self.controller.set_bounded_executor_workspace(target)
        control = self.controller.state_view()["agent_backend_control"]
        self.assertTrue(control["can_start_high_autonomy"])
        self.assertEqual(control["start_blocking_reasons"], [])
        self.assertTrue(control["target_workspace_exists"])
        self.assertNotEqual(control["agent_workspace_path"], control["target_workspace_path"])

    def test_start_blocked_when_target_is_agent_os_repo(self) -> None:
        controller = ControlSurfaceController(
            session_dir=self.root / "s2", repo_root=REPO_ROOT
        )
        controller.set_bounded_executor_workspace(REPO_ROOT)
        control = controller.state_view()["agent_backend_control"]
        self.assertTrue(control["target_is_agent_os_repo"])
        self.assertFalse(control["can_start_high_autonomy"])
        self.assertTrue(
            any("agent-os repository" in r for r in control["start_blocking_reasons"])
        )

    def test_cursor_cli_reported_not_configured_by_default(self) -> None:
        control = self.controller.state_view()["agent_backend_control"]
        cursor = next(b for b in control["backends"] if b["backend_id"] == "cursor_cli")
        self.assertFalse(cursor["availability"]["available"])
        self.assertFalse(control["cursor_cli_configured"])


class TestWorkspaceFirstHtml(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    def test_target_workspace_input_is_top_level_not_in_advanced(self) -> None:
        self.assertIn('id="ha-target-workspace"', self.html)
        # The top-level target workspace input appears before the Advanced/Debug
        # drawer — i.e. workspace configuration is no longer an advanced setting.
        target_idx = self.html.index('id="ha-target-workspace"')
        advanced_idx = self.html.index('id="advanced-debug-details"')
        self.assertLess(target_idx, advanced_idx)
        # And it lives inside the primary high-autonomy panel.
        panel_idx = self.html.index('id="high-autonomy-panel"')
        self.assertLess(panel_idx, target_idx)

    def test_backend_selector_and_status_present(self) -> None:
        self.assertIn('id="ha-backend-select"', self.html)
        self.assertIn('id="ha-agent-workspace"', self.html)
        self.assertIn('id="ha-backend-status"', self.html)
        self.assertIn('id="ha-start-gate"', self.html)
        self.assertIn("renderWorkspaceFirst", self.html)
        self.assertIn("agent_backend_control", self.html)

    def test_start_sends_selected_backend_id(self) -> None:
        self.assertIn("selectedBackendId", self.html)
        self.assertIn("backend_id: backendId", self.html)

    def test_panel_shows_required_high_autonomy_fields(self) -> None:
        for label in (
            "Target workspace",
            "Agent backend",
            "Agent workspace",
            "Backend status",
            "Current step",
            "Blocking reason",
            "Human action required",
        ):
            self.assertIn(label, self.html)

    def test_truth_boundary_wording_is_truthful_about_high_autonomy(self) -> None:
        # New truthful pills / banner.
        self.assertIn("No arbitrary executor", self.html)
        self.assertIn("No shell/npm/network/deploy", self.html)
        self.assertIn("Human-critical actions still stop", self.html)
        self.assertIn(
            "only admitted low-risk local file writes may be", self.html
        )
        # The misleading absolute claims are gone.
        self.assertNotIn("No side effect executed by Admissible.", self.html)
        self.assertNotIn(">No executor<", self.html)


if __name__ == "__main__":
    unittest.main()
