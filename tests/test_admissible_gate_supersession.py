from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController


def _gate(*, closes: str = "none", label: str = "Approve index.html local write") -> str:
    return (
        f"action_gate_index — {label}\n"
        "Verdict class: REQUIRE_HUMAN_APPROVAL\n"
        f"Closes gates: {closes}\n"
        "Side effects if approved: None\n"
        "Proposal: approve the bounded index.html local write\n"
        "Human decision required: approve this local write\n"
    )


def _write(path: str, content: str) -> str:
    return "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n" + json.dumps(
        {"operation": "write_file", "path": path, "content": content}
    ) + "\n```\n"


class TestAdmissibleGateSupersession(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=root / "sessions")
        self.controller.submit_goal("Create the final index.html in a local workspace.")
        self.controller.set_bounded_executor_workspace(self.workspace)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_model_approval_prose_does_not_override_allow_policy(self) -> None:
        state = self.controller.ingest_agent_response(
            _gate() + "\n" + _write("index.html", "<!doctype html>\n")
        )
        self.assertEqual([row["action_type"] for row in state["queue"]], ["create_file"])
        self.assertEqual(state["queue"][0]["decision"], "ALLOW")
        events = [row["event_type"] for row in state["governance_records"]]
        self.assertIn("pseudo_gate_suppressed", events)

    def test_repeated_equivalent_gates_merge(self) -> None:
        self.controller.ingest_agent_response(_gate(closes="index_choice"))
        state = self.controller.ingest_agent_response(_gate(closes="index_choice"))
        gates = [row for row in state["queue"] if row["action_type"] == "plan_gate_resolution"]
        self.assertEqual(len(gates), 1)
        self.assertTrue(
            any(
                row["event_type"] == "equivalent_gate_merged"
                for row in state["governance_records"]
            )
        )

    def test_stale_index_gate_auto_supersedes_after_newer_write(self) -> None:
        gate_state = self.controller.ingest_agent_response(_gate(closes="index_choice"))
        gate_id = gate_state["run_loop"]["response_records"][-1]["action_ids"][0]
        write_state = self.controller.ingest_agent_response(
            _write("index.html", "<!doctype html><canvas></canvas>\n")
        )
        write_id = write_state["run_loop"]["response_records"][-1]["action_ids"][0]
        final = self.controller.execute_bounded_local(write_id, {})
        gate = next(row for row in final["queue"] if row["action_id"] == gate_id)
        self.assertEqual(gate["lifecycle_status"], "superseded")
        self.assertEqual(gate["superseded_by_action_id"], write_id)
        self.assertEqual(len(final["human_decisions"]), 0)


if __name__ == "__main__":
    unittest.main()
