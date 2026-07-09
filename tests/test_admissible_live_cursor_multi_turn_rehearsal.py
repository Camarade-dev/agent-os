"""Slice ADMISSIBLE_DEMO_027_LIVE_CURSOR_MULTI_TURN_REHEARSAL tests.

Asserts display-only rehearsal packet projection and UI markers for the live
Cursor multi-turn operator protocol. Does not call providers or execute shell.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import (
    REHEARSAL_PACKET_SCHEMA_VERSION,
    ControlSurfaceController,
    NEXT_ACTION_SUBMIT_GOAL,
    NEXT_ACTION_WRITE_INSTRUCTION,
    RUN_PHASE_NEEDS_GOAL,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


class TestRehearsalPacketProjection(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = ControlSurfaceController(session_dir=Path(self._tmpdir.name))

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_rehearsal_packet_before_goal(self) -> None:
        packet = self.controller.state_view()["rehearsal_packet"]
        self.assertEqual(packet["schema_version"], REHEARSAL_PACKET_SCHEMA_VERSION)
        self.assertEqual(packet["run_phase"], RUN_PHASE_NEEDS_GOAL)
        self.assertEqual(packet["next_expected_action"], NEXT_ACTION_SUBMIT_GOAL)
        self.assertFalse(packet["latest_instruction_written"])
        self.assertIn("Submit the canonical tiny-game goal", packet["operator_next_steps"][0])
        self.assertIn("ADMISSIBLE LIVE CURSOR MULTI-TURN REHEARSAL CHECKLIST", packet["checklist_text"])

    def test_rehearsal_packet_after_goal(self) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        packet = self.controller.state_view()["rehearsal_packet"]
        self.assertIn("tiny local-only browser game", packet["goal"])
        self.assertEqual(packet["next_expected_action"], NEXT_ACTION_WRITE_INSTRUCTION)
        self.assertIn("Write instruction file", packet["checklist_text"])

    def test_rehearsal_packet_not_persisted(self) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        self.assertNotIn("rehearsal_packet", self.controller.session_dict())


class TestLiveRehearsalUiMarkers(unittest.TestCase):
    def test_html_contains_rehearsal_checklist_button(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Copy live rehearsal checklist",
            'id="btn-copy-rehearsal-checklist"',
            "rehearsal_packet",
            "checklist_text",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")


if __name__ == "__main__":
    unittest.main()
