"""Slice ADMISSIBLE_UX_026_PRODUCT_GRADE_RUN_TIMELINE tests.

Asserts demo-readiness UX markers and derived state projections for the
governed-run narrative: overview, timeline, continuation, bounded verification.
Does not test visual perfection — only HTML/state wiring and no auto-execution.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("product-grade UX tests must not spawn a subprocess")


class TestGovernedRunOverviewState(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = ControlSurfaceController(session_dir=Path(self._tmpdir.name))

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_overview_absent_meaningfully_before_goal(self) -> None:
        view = self.controller.state_view()
        overview = view["governed_run_overview"]
        self.assertIsNone(overview["goal"])
        self.assertEqual(overview["verification_readiness"], "not_run")
        self.assertFalse(overview["continuation_available"])

    def test_state_view_exposes_verification_summary(self) -> None:
        summary = self.controller.state_view()["verification_summary"]
        self.assertEqual(summary["readiness"], "not_run")
        self.assertEqual(summary["verification_count"], 0)
        self.assertIn("failed_check_messages", summary)

    def test_overview_populates_after_goal(self) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        overview = self.controller.state_view()["governed_run_overview"]
        self.assertIn("tiny local-only browser game", overview["goal"])
        self.assertEqual(overview["turn_count"], 0)
        self.assertEqual(overview["write_evidence_count"], 0)
        self.assertEqual(overview["verification_readiness"], "not_run")

    def test_governed_run_overview_not_persisted(self) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        self.assertNotIn("governed_run_overview", self.controller.session_dict())
        self.assertNotIn("verification_summary", self.controller.session_dict())


class TestProductGradeRunTimelineUxHtml(unittest.TestCase):
    def test_html_contains_governed_run_panel(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Governed Run",
            'id="governed-run-panel"',
            'id="governed-run-body"',
            "renderGovernedRun",
            "governed_run_overview",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")

    def test_html_contains_improved_run_timeline_markers(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Run Timeline",
            'id="run-timeline-panel"',
            "timeline-ops-table",
            "renderRunTimeline",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")

    def test_html_contains_continuation_markers(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Evidence-Grounded Continuation",
            "continuation-not-auto",
            "pending_local_execution",
            'id="btn-copy-continuation"',
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")

    def test_html_contains_bounded_verification_panel_and_button(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Bounded Verification",
            'id="bounded-verification-panel"',
            'id="bounded-verification-body"',
            'id="btn-verify-bounded-local"',
            "renderBoundedVerification",
            "verification_summary",
            "/api/queue/verify_bounded_local_workspace",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")

    def test_html_does_not_auto_run_verification(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        self.assertNotIn("verify_bounded_local_workspace", html.split("refresh();")[0])
        self.assertIn('if (!window.confirm(message)) return;', html)


class TestBoundedVerificationUiTrigger(unittest.TestCase):
    """Verification can be triggered via controller route; UI uses same path."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.turn_1_raw = load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_verification_summary_updates_after_explicit_run(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_1_raw)
            self.controller.set_bounded_executor_workspace(self.workspace)
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
            verify_state = self.controller.verify_bounded_local_workspace(
                {"workspace_path": str(self.workspace)}
            )

        summary = verify_state["verification_summary"]
        self.assertEqual(summary["verification_count"], 1)
        self.assertIn(summary["readiness"], ("pass", "fail"))
        overview = verify_state["governed_run_overview"]
        self.assertEqual(overview["verification_readiness"], summary["readiness"])


if __name__ == "__main__":
    unittest.main()
