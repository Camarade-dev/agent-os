from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import (
    ControlSurfaceController,
    DecisionQueueItem,
    HumanDecisionRecord,
    RunEnvelope,
    _repair_stale_negated_non_actions,
)
from admissible.governed_run import active_blocking_action_ids

FIXTURE_011 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_011_regression.json"
)


class TestAdmissibleRepairGenuineBlockersOnly(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_011.read_text(encoding="utf-8"))

    def _seed_cli011_false_blocker_session(self, controller: ControlSurfaceController) -> None:
        session = controller._session
        gate = self.fixture["false_git_push_candidate"]
        for path in ("index.html", "style.css", "game.js", "LOCAL_DEV.md"):
            action_id = f"allow_{path}"
            session.queue.append(
                DecisionQueueItem(
                    action_id=action_id,
                    tool_or_command=path,
                    action_type="create_file",
                    decision="ALLOW",
                    operational_admissibility_action=None,
                    risk_level="low",
                    required_approval=None,
                    missing_evidence=[],
                    execution_status="executed_by_bounded_executor",
                    attestation_eligible=False,
                    lifecycle_status="closed",
                )
            )
        gate_id = "false_git_push"
        session.queue.append(
            DecisionQueueItem(
                action_id=gate_id,
                tool_or_command=gate["prose"],
                action_type=gate["action_type"],
                decision=gate["decision"],
                operational_admissibility_action=None,
                risk_level="high",
                required_approval=None,
                missing_evidence=[],
                execution_status=gate["execution_status"],
                attestation_eligible=False,
                lifecycle_status=gate["lifecycle_status"],
            )
        )
        session.human_decisions.append(
            HumanDecisionRecord(
                record_id="hd_1",
                action_id=gate_id,
                actor="operator",
                timestamp="2026-01-01T00:00:00Z",
                decision_type="approve",
                scope="high_autonomy_human_approved_local_only",
                rationale="approved false constraint",
                linked_decision_id=None,
                linked_envelope_id=None,
            )
        )

    def test_suppressed_non_action_excluded_from_active_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            self._seed_cli011_false_blocker_session(controller)
            session = controller._session
            self.assertEqual(active_blocking_action_ids(session.queue), [])
            _repair_stale_negated_non_actions(session)
            item = next(row for row in session.queue if row.action_id == "false_git_push")
            self.assertTrue(item.suppressed_non_action)
            self.assertEqual(active_blocking_action_ids(session.queue), [])

    def test_verification_failure_not_blocked_by_suppressed_non_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            self._seed_cli011_false_blocker_session(controller)
            _repair_stale_negated_non_actions(controller._session)
            ha = controller._high_autonomy_state()
            assert ha is not None
            from admissible.high_autonomy_controller import _can_start_repair

            ha.acceptance_criteria = [
                {
                    "criterion_id": "game_restart",
                    "mandatory": True,
                    "status": "verified_fail",
                    "verification": [{"check_id": "game_restart_check", "target_paths": ["game.js"]}],
                }
            ]
            ha.human_critical_pending = False
            ha.repair_round_count = 0
            ha.max_repair_rounds = 2
            ha.metrics = {"active_blocked_count": 0}
            controller._set_high_autonomy_state(ha)
            controller._session.run_loop.verification_records.append(
                {"overall_status": "fail", "results": []}
            )
            self.assertTrue(_can_start_repair(controller, controller._high_autonomy_state()))


if __name__ == "__main__":
    unittest.main()
