from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import (
    ControlSurfaceController,
    DecisionQueueItem,
    RunEnvelope,
    HumanDecisionRecord,
    _repair_stale_aggregate_pseudo_gates,
)
from admissible.governed_run import count_genuine_human_interventions

FIXTURE_010 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_010_regression.json"
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


class TestAdmissibleAggregatePseudoGateSuppression(unittest.TestCase):
    AGGREGATE_PROSE = "Approve bounded execution of the four structured write_file operations below"

    def test_stale_aggregate_gate_suppressed_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            session = controller._session
            for index, path in enumerate(("index.html", "style.css", "game.js", "README.md")):
                action_id = f"allow_{index}"
                session.queue.append(
                    _queue_item(action_id=action_id, tool_or_command=path)
                )
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
            gate_id = "gate_aggregate"
            session.queue.append(
                _queue_item(
                    action_id=gate_id,
                    action_type="plan_gate_resolution",
                    decision="REQUIRE_HUMAN_APPROVAL",
                    tool_or_command=self.AGGREGATE_PROSE,
                    lifecycle_status="admitted_not_executed",
                )
            )
            session.human_decisions.clear()
            session.human_decisions.append(
                HumanDecisionRecord(
                    record_id="hd_1",
                    action_id=gate_id,
                    actor="operator",
                    timestamp="2026-01-01T00:00:00Z",
                    decision_type="approve",
                    scope="action",
                    rationale="approved aggregate prose",
                    linked_decision_id=None,
                    linked_envelope_id=None,
                )
            )
            repaired = _repair_stale_aggregate_pseudo_gates(session)
            gate = next(item for item in session.queue if item.action_id == gate_id)
            self.assertGreaterEqual(repaired, 1)
            self.assertTrue(gate.suppressed_pseudo_gate)
            self.assertEqual(
                count_genuine_human_interventions(session.human_decisions, session.governance_records),
                0,
            )

    def test_cli010_fixture_documents_suppressed_pseudo_gate(self) -> None:
        fixture = json.loads(FIXTURE_010.read_text(encoding="utf-8"))
        gate = fixture["aggregate_pseudo_gate"]
        self.assertIn("four structured write", gate["prose"].lower())
        self.assertTrue(gate["human_decision_recorded"])
        self.assertEqual(fixture["human_decisions"]["genuine_human_intervention_count_after_fix"], 0)

    def test_genuine_human_intervention_count_excludes_suppressed_gates(self) -> None:
        human_decisions = [{"action_id": "gate_1"}, {"action_id": "real_1"}]
        governance = [
            {
                "event_type": "retrospective_pseudo_gate_suppressed",
                "action_id": "gate_1",
            }
        ]
        self.assertEqual(count_genuine_human_interventions(human_decisions, governance), 1)


if __name__ == "__main__":
    unittest.main()
