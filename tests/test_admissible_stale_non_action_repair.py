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
from admissible.governed_run import count_genuine_human_interventions

FIXTURE_011 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_011_regression.json"
)


def _queue_item(**overrides: object) -> DecisionQueueItem:
    defaults = {
        "action_id": "action_1",
        "tool_or_command": "",
        "action_type": "write_file",
        "decision": "ALLOW",
        "operational_admissibility_action": None,
        "risk_level": "low",
        "required_approval": None,
        "missing_evidence": [],
        "execution_status": "proposed_only",
        "attestation_eligible": False,
        "lifecycle_status": "ready_to_execute",
    }
    defaults.update(overrides)
    return DecisionQueueItem(**defaults)


class TestAdmissibleStaleNonActionRepair(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_011.read_text(encoding="utf-8"))

    def test_cli011_false_git_push_suppressed_on_load(self) -> None:
        gate = self.fixture["false_git_push_candidate"]
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            session = controller._session
            for path in ("index.html", "style.css", "game.js", "LOCAL_DEV.md"):
                action_id = f"allow_{path}"
                session.queue.append(_queue_item(action_id=action_id, tool_or_command=path))
                session.run_envelopes[action_id] = RunEnvelope(
                    action_id=action_id,
                    envelope_id=f"env_{action_id}",
                    decision_id=f"dec_{action_id}",
                    candidate={
                        "action_type": "write_file",
                        "structured_operations": [
                            {"operation": "write_file", "path": path, "content": "x\n"}
                        ],
                    },
                    decision={"decision": "ALLOW"},
                )
            gate_id = "false_git_push"
            session.queue.append(
                _queue_item(
                    action_id=gate_id,
                    action_type=gate["action_type"],
                    decision=gate["decision"],
                    tool_or_command=gate["prose"],
                    lifecycle_status=gate["lifecycle_status"],
                    execution_status=gate["execution_status"],
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
            repaired = _repair_stale_negated_non_actions(session)
            item = next(row for row in session.queue if row.action_id == gate_id)
            self.assertGreaterEqual(repaired, 1)
            self.assertTrue(item.suppressed_non_action)

    def test_raw_human_approval_preserved_genuine_intervention_zero(self) -> None:
        human_decisions = [{"action_id": "false_1"}]
        governance = [
            {
                "event_type": "retrospective_non_action_suppressed",
                "action_id": "false_1",
            }
        ]
        self.assertEqual(count_genuine_human_interventions(human_decisions, governance), 0)
        self.assertEqual(len(human_decisions), 1)

    def test_fixture_documents_cli011_human_metrics(self) -> None:
        metrics = self.fixture["human_decisions"]
        self.assertEqual(metrics["raw_human_decision_count"], 1)
        self.assertEqual(metrics["genuine_human_intervention_count_after_fix"], 0)
        self.assertEqual(metrics["retrospectively_suppressed_non_action_decision_count"], 1)


if __name__ == "__main__":
    unittest.main()
