"""Tests for admissible.evaluator.rules_only (Tier 1 enriched reference evaluator)."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from admissible.decision import AdmissionDecision
from admissible.evaluator.rules_only import evaluate_envelope

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "benchmark" / "schemas"
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _load_all_envelopes() -> list:
    return [_load_json(path) for path in sorted(CASES_DIR.glob("**/*.envelope.json"))]


def _load_gold_by_envelope_id() -> dict:
    gold_by_id = {}
    with GOLD_LABELS_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            gold_by_id[record["envelope_id"]] = record
    return gold_by_id


def _decision_output_schema() -> dict:
    return _load_json(SCHEMAS_DIR / "decision_output.schema.json")


class TestEvaluateEnvelopeBasics(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = _load_json(
            CASES_DIR / "customer_communication" / "customer_refund_send_requires_finance_approval.envelope.json"
        )

    def test_returns_a_dict(self) -> None:
        result = evaluate_envelope(self.envelope)
        self.assertIsInstance(result, dict)

    def test_does_not_mutate_input_envelope(self) -> None:
        before = copy.deepcopy(self.envelope)
        evaluate_envelope(self.envelope)
        self.assertEqual(self.envelope, before)

    def test_invalid_non_dict_input_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_envelope("not a dict")
        with self.assertRaises(ValueError):
            evaluate_envelope(None)
        with self.assertRaises(ValueError):
            evaluate_envelope(["envelope"])

    def test_missing_minimal_fields_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_envelope({})
        with self.assertRaises(ValueError):
            evaluate_envelope({"envelope_id": "env_x"})
        incomplete = {k: v for k, v in self.envelope.items() if k != "authority_context"}
        with self.assertRaises(ValueError):
            evaluate_envelope(incomplete)
        no_action_type = copy.deepcopy(self.envelope)
        no_action_type["proposed_action"] = {"tool": "gmail.send"}
        with self.assertRaises(ValueError):
            evaluate_envelope(no_action_type)

    def test_decision_is_one_of_five_canonical_labels(self) -> None:
        result = evaluate_envelope(self.envelope)
        self.assertIn(result["decision"], {member.value for member in AdmissionDecision})

    def test_output_contains_required_schema_fields(self) -> None:
        schema = _decision_output_schema()
        result = evaluate_envelope(self.envelope)
        for field in schema["required"]:
            self.assertIn(field, result)

    def test_envelope_id_matches_input(self) -> None:
        result = evaluate_envelope(self.envelope)
        self.assertEqual(result["envelope_id"], self.envelope["envelope_id"])

    def test_system_id_uses_provided_value(self) -> None:
        result = evaluate_envelope(self.envelope, system_id="my_custom_system")
        self.assertEqual(result["system_id"], "my_custom_system")

    def test_default_system_id(self) -> None:
        result = evaluate_envelope(self.envelope)
        self.assertEqual(result["system_id"], "admissible_rules_only_v0")


class TestRepresentativeCasesCoverAllFiveLabels(unittest.TestCase):
    """One representative seed case per canonical label, spot-checked directly."""

    def test_allow(self) -> None:
        envelope = _load_json(CASES_DIR / "file_deletion" / "file_deletion_list_candidates_allowed.envelope.json")
        result = evaluate_envelope(envelope)
        self.assertEqual(result["decision"], AdmissionDecision.ALLOW.value)

    def test_allow_with_limits(self) -> None:
        envelope = _load_json(
            CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"
        )
        result = evaluate_envelope(envelope)
        self.assertEqual(result["decision"], AdmissionDecision.ALLOW_WITH_LIMITS.value)

    def test_request_more_evidence(self) -> None:
        envelope = _load_json(
            CASES_DIR / "crm_record_mutation" / "crm_billing_status_change_inference_more_evidence.envelope.json"
        )
        result = evaluate_envelope(envelope)
        self.assertEqual(result["decision"], AdmissionDecision.REQUEST_MORE_EVIDENCE.value)

    def test_require_human_approval(self) -> None:
        envelope = _load_json(
            CASES_DIR / "customer_communication" / "customer_refund_send_requires_finance_approval.envelope.json"
        )
        result = evaluate_envelope(envelope)
        self.assertEqual(result["decision"], AdmissionDecision.REQUIRE_HUMAN_APPROVAL.value)

    def test_refuse(self) -> None:
        envelope = _load_json(CASES_DIR / "file_deletion" / "file_deletion_audit_logs_refused.envelope.json")
        result = evaluate_envelope(envelope)
        self.assertEqual(result["decision"], AdmissionDecision.REFUSE.value)


class TestAllTier1SeedCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.envelopes = _load_all_envelopes()
        cls.schema = _decision_output_schema()
        cls.allowed_keys = set(cls.schema["properties"].keys())
        cls.required_keys = set(cls.schema["required"])

    def test_seed_case_count_is_twenty_five(self) -> None:
        self.assertEqual(len(self.envelopes), 25)

    def test_all_cases_evaluate_without_crashing(self) -> None:
        for envelope in self.envelopes:
            with self.subTest(envelope_id=envelope["envelope_id"]):
                result = evaluate_envelope(envelope)
                self.assertIsInstance(result, dict)

    def test_all_outputs_have_no_keys_outside_schema_properties(self) -> None:
        for envelope in self.envelopes:
            result = evaluate_envelope(envelope)
            with self.subTest(envelope_id=envelope["envelope_id"]):
                extra_keys = set(result.keys()) - self.allowed_keys
                self.assertEqual(extra_keys, set())

    def test_all_outputs_have_all_required_keys(self) -> None:
        for envelope in self.envelopes:
            result = evaluate_envelope(envelope)
            with self.subTest(envelope_id=envelope["envelope_id"]):
                missing_keys = self.required_keys - set(result.keys())
                self.assertEqual(missing_keys, set())

    def test_all_outputs_have_valid_decision_enum(self) -> None:
        valid_labels = {member.value for member in AdmissionDecision}
        for envelope in self.envelopes:
            result = evaluate_envelope(envelope)
            with self.subTest(envelope_id=envelope["envelope_id"]):
                self.assertIn(result["decision"], valid_labels)


class TestRawLabelComparisonAgainstGold(unittest.TestCase):
    """Internal smoke signal only. This is not a benchmark result.

    Raw match rate against a 25-case hand-authored Tier 1 seed says
    nothing about generalization; see docs/Admissible_BENCHMARK_SPEC.md
    claim-boundary guidance. This test only guards against the evaluator
    being obviously broken, not against imperfect accuracy.
    """

    def test_report_raw_accuracy_against_gold_labels(self) -> None:
        envelopes = _load_all_envelopes()
        gold_by_id = _load_gold_by_envelope_id()

        matches = 0
        mismatches = []
        for envelope in envelopes:
            envelope_id = envelope["envelope_id"]
            gold = gold_by_id[envelope_id]
            result = evaluate_envelope(envelope)
            if result["decision"] == gold["gold_decision"]:
                matches += 1
            else:
                mismatches.append((envelope_id, result["decision"], gold["gold_decision"]))

        total = len(envelopes)
        accuracy = matches / total

        print(f"\n[rules_only smoke signal - NOT a benchmark result] raw match {matches}/{total} = {accuracy:.2%}")
        if mismatches:
            print("Mismatches (envelope_id, predicted, gold):")
            for envelope_id, predicted, gold_decision in mismatches:
                print(f"  {envelope_id}: predicted={predicted} gold={gold_decision}")

        self.assertGreaterEqual(
            accuracy,
            0.2,
            "Raw match rate against the Tier 1 seed is extremely low; "
            "the rules-only evaluator likely has a broken heuristic, not just imperfect accuracy.",
        )


if __name__ == "__main__":
    unittest.main()
