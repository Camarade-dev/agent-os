from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController


CRITERIA = [
    {
        "criterion_id": "index_exists",
        "source_text": "index.html exists.",
        "verification": [{"check_id": "file_exists", "target_paths": ["index.html"]}],
    },
    {
        "criterion_id": "index_canvas",
        "source_text": "index.html contains a canvas.",
        "verification": [
            {"check_id": "file_contains", "target_paths": ["index.html"], "contains": ["<canvas"]}
        ],
    },
]


class TestAdmissibleAcceptanceLedgerAndCompletion(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=root / "sessions")
        self.controller.submit_goal("Create a local index.html with a canvas.")
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace),
            transport=FixtureAgentTransport(),
            max_turns=6,
            acceptance_criteria=CRITERIA,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_completion_requires_verified_evidence(self) -> None:
        candidate = {
            "claimed_status": "complete",
            "criteria": [
                {"criterion_id": "index_exists", "claimed_status": "satisfied", "evidence_refs": []},
                {"criterion_id": "index_canvas", "claimed_status": "satisfied", "evidence_refs": []},
            ],
            "remaining_work": [],
        }
        self.controller.ingest_agent_response(
            "ADMISSIBLE_COMPLETION_CANDIDATE:\n```json\n"
            + json.dumps(candidate)
            + "\n```\n"
        )
        state = self.controller.state_view()
        self.assertIsNone(state["high_autonomy_summary"]["outcome"])
        self.assertTrue(state["high_autonomy_summary"]["completion_candidate"]["advisory_only"])
        self.assertTrue(
            all(item["status"] == "open" for item in state["high_autonomy_summary"]["acceptance_criteria"])
        )

    def test_deterministic_verification_authorizes_completed_outcome(self) -> None:
        (self.workspace / "index.html").write_text(
            "<!doctype html><canvas id=\"game\"></canvas>\n",
            encoding="utf-8",
            newline="",
        )
        verified = self.controller.verify_bounded_local_workspace(
            {"workspace_path": str(self.workspace), "profile": "acceptance_ledger"}
        )
        self.assertEqual(
            verified["bounded_local_verification_result"]["overall_status"], "pass"
        )
        final = self.controller.tick_high_autonomy_run()
        summary = final["high_autonomy_summary"]
        self.assertEqual(summary["outcome"], "completed")
        self.assertEqual(summary["acceptance_verified_count"], 2)
        self.assertFalse(summary["active"])


if __name__ == "__main__":
    unittest.main()
