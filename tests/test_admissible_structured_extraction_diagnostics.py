from __future__ import annotations

import json
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController, ResponseExtractionFailed
from admissible.governed_run import build_agent_response_extraction_report
from admissible.long_run_envelope_builder import build_from_raw_output
from admissible.run_loop import build_candidates_from_agent_response

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_007_regression.json"
)


class TestStructuredExtractionDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.turn_responses = cls.fixture["turn_responses"]

    def test_turn1_exact_response_yields_four_structured_actions(self) -> None:
        raw = self.turn_responses["1"]
        built = build_candidates_from_agent_response(raw, turn_number=1)
        structured = [
            entry
            for entry in built
            if entry["candidate"].get("structured_operations")
        ]
        self.assertEqual(len(structured), 4)

    def test_turn2_through_turn4_exact_shapes_do_not_silently_yield_zero(self) -> None:
        for turn in ("2", "3", "4"):
            with self.subTest(turn=turn):
                raw = self.turn_responses[turn]
                report = build_agent_response_extraction_report(
                    raw,
                    built=build_candidates_from_agent_response(raw, turn_number=int(turn)),
                )
                self.assertEqual(report["structured_marker_count"], 4)
                self.assertGreaterEqual(report["surviving_action_count"], 4)
                self.assertFalse(report["extraction_failed"])

    def test_malformed_block_reports_reason_without_discarding_valid_siblings(self) -> None:
        raw = (
            self.turn_responses["5"]
            + "\nADMISSIBLE_STRUCTURED_OPERATION:\n```json\n{not valid}\n```\n"
            + "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
            '{"operation": "write_file", "path": "extra.txt", "content": "ok"}\n```\n'
        )
        built = build_candidates_from_agent_response(raw, turn_number=5)
        report = build_agent_response_extraction_report(raw, built=built)
        self.assertGreaterEqual(report["surviving_action_count"], 4)
        malformed = [
            block
            for block in report["blocks"]
            if block["outcome"] == "malformed_with_reason"
        ]
        self.assertEqual(len(malformed), 1)

    def test_marker_only_zero_survivors_raises_response_extraction_failed(self) -> None:
        controller = ControlSurfaceController()
        controller.submit_goal("Local task")
        broken = (
            "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n{not valid json}\n```\n"
            "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n{bad again}\n```\n"
        )
        with self.assertRaises(ResponseExtractionFailed):
            controller.ingest_agent_response(broken)

    def test_extraction_report_persisted_on_success(self) -> None:
        controller = ControlSurfaceController()
        controller.submit_goal(self.fixture["goal_text"])
        controller.ingest_agent_response(self.turn_responses["5"])
        record = controller._session.run_loop.response_records[-1]
        self.assertIsNotNone(record.extraction_report)
        self.assertEqual(record.extraction_report["structured_marker_count"], 4)
        self.assertEqual(len(record.action_ids), 4)


if __name__ == "__main__":
    unittest.main()
