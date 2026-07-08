"""Tests for Admitted Execution Protocol v0."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.admitted_execution import (
    EXECUTION_STATUS_ADMITTED_NOT_EXECUTED,
    EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
    EXECUTION_STATUS_PROPOSED_ONLY,
    AdmittedExecutionValidationError,
    apply_execution_attestations,
    load_execution_attestation,
    validate_attestation_fixture,
    validate_executed_after_admission_record,
    validate_execution_evidence_traceability,
)
from admissible.harness.truth_console import render_truth_console_html
from admissible.long_run_truth import build_truth_trace_from_raw_output_fixtures
from admissible.runner.long_run_truth_console import write_long_run_builder_truth_console

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_CAPTURE_FIXTURES_DIR = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "fixtures"
    / "real_captures"
)
EXECUTION_LOG_FIXTURE = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "execution_logs"
    / "admitted_local_actions_v0.json"
)

EXPECTED_EXECUTED_ACTION_IDS = (
    "action_001",
    "action_002",
    "action_013",
    "action_017",
    "action_018",
)

MISMATCHED_LEGACY_ACTION_IDS = ("action_003", "action_004", "action_005")


class TestAdmittedExecutionValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = build_truth_trace_from_raw_output_fixtures(
            fixtures_dir=str(REAL_CAPTURE_FIXTURES_DIR),
            repo_root=str(REPO_ROOT),
        )
        self.attestation = load_execution_attestation(EXECUTION_LOG_FIXTURE)

    def test_fixture_loads(self) -> None:
        self.assertEqual(len(self.attestation["records"]), 5)

    def test_fixture_consistency_against_trace(self) -> None:
        validate_attestation_fixture(self.attestation, self.trace)
        decisions = {d["action_id"]: d for d in self.trace["decisions"]}
        candidates = {c["action_id"]: c for c in self.trace["action_candidates"]}

        for record in self.attestation["records"]:
            action_id = record["action_id"]
            self.assertIn(action_id, decisions, f"{action_id} missing from trace decisions")
            self.assertIn(
                action_id, candidates, f"{action_id} missing from trace action_candidates"
            )
            decision = decisions[action_id]
            basis = record.get("execution_basis") or {}
            self.assertEqual(basis.get("decision_id"), decision["decision_id"])
            self.assertEqual(basis.get("envelope_id"), decision["envelope_id"])
            if record.get("execution_status") == EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION:
                validate_execution_evidence_traceability(record, candidates[action_id])

    def test_apply_marks_selected_actions_executed(self) -> None:
        updated = apply_execution_attestations(self.trace, self.attestation)
        statuses = {
            c["action_id"]: c["execution_status"] for c in updated["action_candidates"]
        }
        for action_id in EXPECTED_EXECUTED_ACTION_IDS:
            self.assertEqual(
                statuses[action_id],
                EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
            )
            candidate = next(
                c for c in updated["action_candidates"] if c["action_id"] == action_id
            )
            self.assertIn("execution_record", candidate)
            self.assertIn("decision_id", candidate["execution_record"]["execution_basis"])

        for action_id in MISMATCHED_LEGACY_ACTION_IDS:
            self.assertEqual(
                statuses[action_id],
                EXECUTION_STATUS_ADMITTED_NOT_EXECUTED,
            )

        # Remaining ALLOW local actions become admitted_not_executed
        self.assertEqual(
            statuses["action_006"],
            EXECUTION_STATUS_ADMITTED_NOT_EXECUTED,
        )

        # Non-ALLOW stays proposed_only
        evidence_actions = [
            c["action_id"]
            for c in updated["action_candidates"]
            if any(
                d["action_id"] == c["action_id"]
                and d["decision"] == "REQUEST_MORE_EVIDENCE"
                for d in updated["decisions"]
            )
        ]
        self.assertTrue(evidence_actions)
        for action_id in evidence_actions[:3]:
            self.assertEqual(statuses[action_id], EXECUTION_STATUS_PROPOSED_ONLY)

    def test_trace_side_effect_executed_remains_false(self) -> None:
        updated = apply_execution_attestations(self.trace, self.attestation)
        self.assertFalse(updated["side_effect_executed"])

    def test_execution_log_references_admission_basis(self) -> None:
        updated = apply_execution_attestations(self.trace, self.attestation)
        executed_events = [
            e
            for e in updated["execution_log"]
            if e.get("event") == "executed_after_admission"
        ]
        self.assertEqual(len(executed_events), 5)
        for event in executed_events:
            basis = event.get("execution_basis") or {}
            self.assertTrue(basis.get("decision_id") or basis.get("envelope_id"))
            self.assertFalse(event["side_effect_executed"])
            self.assertTrue(event["attested_external_execution"])

    def test_request_more_evidence_cannot_be_executed(self) -> None:
        evidence_action = next(
            d for d in self.trace["decisions"] if d["decision"] == "REQUEST_MORE_EVIDENCE"
        )
        bad_record = {
            "action_id": evidence_action["action_id"],
            "execution_status": EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
            "execution_basis": {
                "decision_id": evidence_action["decision_id"],
                "envelope_id": evidence_action["envelope_id"],
            },
            "execution_actor": "human_operator",
            "execution_scope": "local_workspace_only",
            "execution_timestamp": "2026-07-08T20:00:00Z",
        }
        with self.assertRaises(AdmittedExecutionValidationError):
            validate_executed_after_admission_record(bad_record, self.trace)

    def test_allow_with_limits_cannot_be_executed(self) -> None:
        limits_action = next(
            d for d in self.trace["decisions"] if d["decision"] == "ALLOW_WITH_LIMITS"
        )
        bad_record = {
            "action_id": limits_action["action_id"],
            "execution_status": EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
            "execution_basis": {
                "decision_id": limits_action["decision_id"],
                "envelope_id": limits_action["envelope_id"],
            },
            "execution_actor": "human_operator",
            "execution_scope": "local_workspace_only",
            "execution_timestamp": "2026-07-08T20:00:00Z",
        }
        with self.assertRaises(AdmittedExecutionValidationError):
            validate_executed_after_admission_record(bad_record, self.trace)

    def test_wrong_decision_id_in_basis_rejected(self) -> None:
        record = dict(self.attestation["records"][0])
        record["execution_basis"] = {
            "decision_id": "decision_wrong_id",
            "envelope_id": record["execution_basis"]["envelope_id"],
        }
        with self.assertRaises(AdmittedExecutionValidationError):
            validate_executed_after_admission_record(record, self.trace)

    def test_mismatched_evidence_rejected(self) -> None:
        candidate = next(
            c for c in self.trace["action_candidates"] if c["action_id"] == "action_003"
        )
        bad_record = {
            "action_id": "action_003",
            "execution_status": EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
            "execution_basis": {
                "decision_id": next(
                    d["decision_id"]
                    for d in self.trace["decisions"]
                    if d["action_id"] == "action_003"
                ),
                "envelope_id": next(
                    d["envelope_id"]
                    for d in self.trace["decisions"]
                    if d["action_id"] == "action_003"
                ),
            },
            "execution_actor": "human_operator",
            "execution_scope": "local_workspace_only",
            "execution_timestamp": "2026-07-08T20:00:00Z",
            "execution_evidence": {
                "notes": "Resize canvas using container client dimensions and devicePixelRatio.",
                "verification": "Manual test: resize browser window; canvas scales crisply.",
            },
        }
        with self.assertRaises(AdmittedExecutionValidationError):
            validate_execution_evidence_traceability(bad_record, candidate)

    def test_no_agent_os_import_in_admitted_execution_module(self) -> None:
        source = (REPO_ROOT / "admissible" / "admitted_execution.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("import agent_os", source)
        self.assertNotIn("from agent_os", source)


class TestAdmittedExecutionTruthConsole(unittest.TestCase):
    def setUp(self) -> None:
        trace = build_truth_trace_from_raw_output_fixtures(
            fixtures_dir=str(REAL_CAPTURE_FIXTURES_DIR),
            repo_root=str(REPO_ROOT),
        )
        attestation = load_execution_attestation(EXECUTION_LOG_FIXTURE)
        self.trace = apply_execution_attestations(trace, attestation)
        self.html = render_truth_console_html(self.trace)

    def test_console_shows_executed_after_admission_distinctly(self) -> None:
        self.assertIn("executed_after_admission", self.html)
        self.assertIn("badge-executed-after-admission", self.html)
        self.assertIn("admitted_not_executed", self.html)
        self.assertIn("badge-admitted-not-executed", self.html)

    def test_console_preserves_no_automatic_execution_disclaimer(self) -> None:
        self.assertIn(
            "Execution records are fixture-backed/manual attestations in this v0.",
            self.html,
        )
        self.assertIn("Admissible did not execute commands.", self.html)
        self.assertIn("No side effect executed by Admissible.", self.html)

    def test_proposed_only_still_visible_for_non_executed(self) -> None:
        self.assertIn("proposed_only", self.html)
        self.assertIn("badge-proposed-only", self.html)
        self.assertIn("Execution Log (attestations)", self.html)

    def test_writer_with_execution_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            html_out = Path(tmpdir) / "console.html"
            trace_out = Path(tmpdir) / "trace.json"
            trace = write_long_run_builder_truth_console(
                fixtures_dir=REAL_CAPTURE_FIXTURES_DIR,
                html_out=html_out,
                trace_out=trace_out,
                execution_log=EXECUTION_LOG_FIXTURE,
            )
            self.assertTrue(html_out.is_file())
            loaded = json.loads(trace_out.read_text(encoding="utf-8"))
            executed = [
                c
                for c in loaded["action_candidates"]
                if c["execution_status"] == EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION
            ]
            self.assertEqual(len(executed), 5)
            self.assertEqual(
                trace["execution_attestation"]["executed_after_admission_count"],
                5,
            )


if __name__ == "__main__":
    unittest.main()
