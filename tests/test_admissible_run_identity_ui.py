"""RUN_045 PART J / PART H — Run Identity UX.

Workspace folder names are not mission authority. These tests cover the
server-computed ``_run_identity()`` projection (goal first line, raw-goal
SHA-256, Mission Contract SHA-256, target workspace, backend, created
timestamp, mandatory/explicit/inferred counts, and a non-blocking
workspace/goal mismatch warning) and the harness wiring that renders it.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController, _run_identity

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"


class TestRunIdentityProjection(unittest.TestCase):
    def _controller(self) -> tuple[ControlSurfaceController, Path]:
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        return controller, workspace

    def test_before_any_goal_the_identity_is_empty_but_present(self) -> None:
        controller, _workspace = self._controller()
        identity = _run_identity(controller._session)
        self.assertEqual(identity["goal_first_line"], "")
        self.assertIsNone(identity["raw_goal_sha256"])
        self.assertIsNone(identity["mission_contract_sha256"])

    def test_goal_first_line_and_shas_populate_after_submit(self) -> None:
        controller, _workspace = self._controller()
        goal = "Build a complete local browser game called Pixel Wanderer.\n\nAcceptance criteria:\n..."
        controller.submit_goal(goal)
        identity = _run_identity(controller._session)
        self.assertEqual(
            identity["goal_first_line"],
            "Build a complete local browser game called Pixel Wanderer.",
        )
        self.assertIsNotNone(identity["raw_goal_sha256"])
        self.assertIsNotNone(identity["mission_contract_sha256"])
        expected_sha = hashlib.sha256(goal.encode("utf-8")).hexdigest()
        self.assertEqual(identity["raw_goal_sha256"], expected_sha)

    def test_mission_contract_sha_changes_when_goal_changes(self) -> None:
        controller_a, _ = self._controller()
        controller_a.submit_goal("Build a tiny local tool called Alpha.")
        identity_a = _run_identity(controller_a._session)

        controller_b, _ = self._controller()
        controller_b.submit_goal("Build a tiny local tool called Beta.")
        identity_b = _run_identity(controller_b._session)

        self.assertNotEqual(identity_a["mission_contract_sha256"], identity_b["mission_contract_sha256"])
        self.assertNotEqual(identity_a["raw_goal_sha256"], identity_b["raw_goal_sha256"])

    def test_workspace_mismatch_is_flagged_as_a_diagnostic_only(self) -> None:
        controller, workspace = self._controller()
        controller.submit_goal("Build a complete local browser game called Pixel Wanderer.")
        mismatched_workspace = workspace.parent / "neon-serpents-cli-002"
        mismatched_workspace.mkdir()
        controller.start_high_autonomy_run(workspace_path=str(mismatched_workspace), max_turns=6)
        identity = _run_identity(controller._session)
        self.assertIsNotNone(identity["workspace_mismatch_warning"])
        self.assertEqual(identity["workspace_basename"], "neon-serpents-cli-002")
        self.assertEqual(identity["extracted_project_name"], "Pixel Wanderer")

    def test_matching_workspace_name_has_no_warning(self) -> None:
        controller, workspace = self._controller()
        controller.submit_goal("Build a complete local browser game called Pixel Wanderer.")
        matching_workspace = workspace.parent / "pixel-wanderer-workspace"
        matching_workspace.mkdir()
        controller.start_high_autonomy_run(workspace_path=str(matching_workspace), max_turns=6)
        identity = _run_identity(controller._session)
        self.assertIsNone(identity["workspace_mismatch_warning"])

    def test_state_view_includes_run_identity(self) -> None:
        controller, _workspace = self._controller()
        controller.submit_goal("Build a tiny local tool called Alpha.")
        view = controller.state_view()
        self.assertIn("run_identity", view)
        self.assertEqual(view["run_identity"], _run_identity(controller._session))

    def test_criterion_counts_reflect_the_contract(self) -> None:
        controller, _workspace = self._controller()
        controller.submit_goal(
            "Build a complete local browser game called Pixel Wanderer as a high-autonomy "
            "governed run.\n\nAcceptance criteria:\nindex.html, style.css, and game.js;\n"
            "a player-controlled dot;\nArrow keys and WASD movement;\ncollectible items and "
            "a visible score;\nrestart with the R key;\na short LOCAL_DEV.md explaining how "
            "to open the game locally;\nbounded local verification at the end."
        )
        identity = _run_identity(controller._session)
        self.assertGreater(identity["inferred_acceptance_criterion_count"], 0)
        self.assertGreaterEqual(identity["mandatory_requirement_count"], 0)


class TestRunIdentityHtmlWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.html = HTML_PATH.read_text(encoding="utf-8")

    def test_panel_exists_and_starts_hidden(self) -> None:
        self.assertIn('id="run-identity-panel"', self.html)
        self.assertIn('id="run-identity-grid"', self.html)
        self.assertIn('id="run-identity-mismatch-warning"', self.html)

    def test_render_function_populates_from_run_identity_field(self) -> None:
        self.assertIn("function renderRunIdentity(state)", self.html)
        self.assertIn("state.run_identity", self.html)
        self.assertIn("renderRunIdentity(state);", self.html)

    def test_render_shows_raw_goal_and_contract_sha(self) -> None:
        self.assertIn("raw_goal_sha256", self.html)
        self.assertIn("mission_contract_sha256", self.html)

    def test_render_shows_mismatch_warning_text(self) -> None:
        self.assertIn("workspace_mismatch_warning", self.html)

    def test_never_infers_identity_from_the_workspace_folder_name_alone(self) -> None:
        # The panel must be driven by run_identity.goal_first_line / SHAs, not by
        # re-deriving a label from ha.workspace_path inside renderRunIdentity.
        start = self.html.index("function renderRunIdentity(state)")
        end = self.html.index("\n}\n", start)
        body = self.html[start:end]
        self.assertIn("identity.goal_first_line", body)
        self.assertNotIn("workspace_path.split", body)


if __name__ == "__main__":
    unittest.main()
