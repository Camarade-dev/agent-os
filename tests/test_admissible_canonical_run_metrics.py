from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController, DecisionQueueItem


class TestAdmissibleCanonicalRunMetrics(unittest.TestCase):
    def test_blocked_definition_matches_export_summary_and_ui_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Prepare a local file; do not deploy.")
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=FixtureAgentTransport(),
                max_turns=6,
            )
            controller._session.queue.append(
                DecisionQueueItem(
                    action_id="blocked_1",
                    tool_or_command="deploy production",
                    action_type="deploy_code",
                    decision="REQUEST_MORE_EVIDENCE",
                    operational_admissibility_action="request_more_evidence",
                    risk_level="high",
                    required_approval="operator",
                    missing_evidence=["deployment authority"],
                    execution_status="proposed_only",
                    attestation_eligible=False,
                )
            )
            view = controller.state_view()
            canonical = view["canonical_run_metrics"]["active_blocked_count"]
            self.assertEqual(canonical, 1)
            self.assertEqual(view["high_autonomy_summary"]["blocked_action_count"], canonical)
            self.assertEqual(view["high_autonomy_summary"]["blocked_count"], canonical)
            self.assertEqual(view["governed_run_overview"]["blocked_count"], canonical)
            self.assertEqual(
                controller.session_dict()["high_autonomy_run"]["blocked_action_count"],
                canonical,
            )

            item = controller._session.queue[-1]
            item.lifecycle_status = "superseded"
            item.superseded_at = "2026-07-10T00:00:00Z"
            view2 = controller.state_view()
            self.assertEqual(view2["canonical_run_metrics"]["active_blocked_count"], 0)
            self.assertEqual(view2["high_autonomy_summary"]["blocked_action_count"], 0)

    def test_metric_names_and_final_ui_labels_are_canonical(self) -> None:
        html = (Path(__file__).resolve().parents[1] / "admissible/harness/control_surface.html").read_text(
            encoding="utf-8"
        )
        for label in ("Outcome:", "Progress:", "Usage:", "Execution:", "Remaining:"):
            self.assertIn(label, html)
        for field in (
            "model_invocation_count",
            "backend_retry_count",
            "useful_write_count",
            "duplicate_noop_count",
            "verification_check_count",
            "genuine_human_intervention_count",
            "active_blocked_count",
        ):
            self.assertIn(field, html)


if __name__ == "__main__":
    unittest.main()
