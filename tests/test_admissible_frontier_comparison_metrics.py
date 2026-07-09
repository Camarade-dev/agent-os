"""Tests for admissible.runner.frontier_comparison_metrics (Slice DEMO_028)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.runner.frontier_comparison_metrics import (
    CLAIM_BOUNDARY,
    METRICS_SCHEMA_VERSION,
    summarize_comparison_pair,
    summarize_governed_session,
    summarize_ungoverned_observation_log,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LIVE_SESSION_PATH = REPO_ROOT / ".admissible" / "live_rehearsal_027b_session" / "session.json"


class TestFrontierComparisonMetrics(unittest.TestCase):
    def test_governed_session_metrics_shape(self) -> None:
        if not LIVE_SESSION_PATH.is_file():
            self.skipTest("live rehearsal session export not present in workspace")
        session_data = json.loads(LIVE_SESSION_PATH.read_text(encoding="utf-8"))
        metrics = summarize_governed_session(session_data)

        self.assertEqual(metrics["schema_version"], METRICS_SCHEMA_VERSION)
        self.assertEqual(metrics["condition"], "B_admissible_governed")
        self.assertIn(CLAIM_BOUNDARY, metrics["claim_boundary"])
        self.assertEqual(metrics["turn_count"], 4)
        self.assertEqual(metrics["write_evidence_count"], 8)
        self.assertEqual(metrics["verification_readiness"], "pass")
        self.assertEqual(metrics["verification_profile"], "tiny_game_demo")
        self.assertFalse(metrics["ingest_auto_executed"])
        self.assertEqual(metrics["gated_not_executed_count"], 2)
        self.assertGreaterEqual(metrics["executed_local_file_ops"], 8)

    def test_governed_turn_three_gated_ops(self) -> None:
        if not LIVE_SESSION_PATH.is_file():
            self.skipTest("live rehearsal session export not present in workspace")
        session_data = json.loads(LIVE_SESSION_PATH.read_text(encoding="utf-8"))
        metrics = summarize_governed_session(session_data)
        gated = {item["action_id"]: item["decision"] for item in metrics["gated_not_executed"]}
        self.assertEqual(gated.get("resp_t03_001_149bca96"), "REQUEST_MORE_EVIDENCE")
        self.assertEqual(gated.get("resp_t03_002_2f328681"), "REQUIRE_HUMAN_APPROVAL")

    def test_ungoverned_observation_log_normalization(self) -> None:
        log = {
            "schema_version": "admissible_frontier_ungoverned_observation_log_v0",
            "model_label": "Example Model",
            "workspace_path": "/tmp/scratch",
            "turns_observed": 2,
            "files_written_directly": ["index.html"],
            "shell_or_npm_executed": True,
            "deploy_proposed_or_executed": False,
            "completion_claimed_by_agent": True,
            "audit_trail_present": False,
            "recovery_after_blocker": "stuck",
            "operator_manual_steps_approx": 5,
        }
        metrics = summarize_ungoverned_observation_log(log)
        self.assertEqual(metrics["condition"], "A_ungoverned_frontier_agent")
        self.assertEqual(metrics["turns_observed"], 2)
        self.assertTrue(metrics["shell_or_npm_executed"])
        self.assertIsNone(metrics["write_evidence_count"])

    def test_comparison_pair_marks_pending_a(self) -> None:
        if not LIVE_SESSION_PATH.is_file():
            self.skipTest("live rehearsal session export not present in workspace")
        session_data = json.loads(LIVE_SESSION_PATH.read_text(encoding="utf-8"))
        pair = summarize_comparison_pair(governed_session=session_data, ungoverned_log=None)
        self.assertTrue(pair["condition_a_pending"])
        self.assertIn("B_admissible_governed", pair["conditions"])
        self.assertNotIn("A_ungoverned_frontier_agent", pair["conditions"])

    def test_cli_stdout_json(self) -> None:
        if not LIVE_SESSION_PATH.is_file():
            self.skipTest("live rehearsal session export not present in workspace")
        from admissible.runner import frontier_comparison_metrics as module

        exit_code = module.main(["--session", str(LIVE_SESSION_PATH)])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
