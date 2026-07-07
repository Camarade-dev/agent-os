"""Tests for admissible.decision (labels and precedence only)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from admissible.decision import (
    AdmissionDecision,
    is_valid_decision_label,
    resolve_precedence,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "benchmark" / "schemas"


class TestAdmissionDecisionEnum(unittest.TestCase):
    def test_all_five_enum_values(self) -> None:
        self.assertEqual(
            {member.value for member in AdmissionDecision},
            {
                "ALLOW",
                "ALLOW_WITH_LIMITS",
                "REQUEST_MORE_EVIDENCE",
                "REQUIRE_HUMAN_APPROVAL",
                "REFUSE",
            },
        )
        self.assertEqual(len(list(AdmissionDecision)), 5)


class TestIsValidDecisionLabel(unittest.TestCase):
    def test_valid_string(self) -> None:
        self.assertTrue(is_valid_decision_label("ALLOW"))
        self.assertTrue(is_valid_decision_label("REFUSE"))

    def test_valid_enum(self) -> None:
        self.assertTrue(is_valid_decision_label(AdmissionDecision.ALLOW_WITH_LIMITS))

    def test_invalid_string(self) -> None:
        self.assertFalse(is_valid_decision_label("MAYBE"))
        self.assertFalse(is_valid_decision_label(""))

    def test_invalid_type(self) -> None:
        self.assertFalse(is_valid_decision_label(123))
        self.assertFalse(is_valid_decision_label(None))
        self.assertFalse(is_valid_decision_label(["ALLOW"]))


class TestResolvePrecedenceInputHandling(unittest.TestCase):
    def test_single_valid_string_input(self) -> None:
        self.assertEqual(resolve_precedence(["ALLOW"]), AdmissionDecision.ALLOW)

    def test_single_valid_enum_input(self) -> None:
        self.assertEqual(
            resolve_precedence([AdmissionDecision.REQUIRE_HUMAN_APPROVAL]),
            AdmissionDecision.REQUIRE_HUMAN_APPROVAL,
        )

    def test_mixed_string_and_enum_input(self) -> None:
        result = resolve_precedence(["ALLOW", AdmissionDecision.REFUSE])
        self.assertEqual(result, AdmissionDecision.REFUSE)

    def test_empty_input_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            resolve_precedence([])

    def test_empty_generator_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            resolve_precedence(x for x in [])

    def test_unknown_string_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            resolve_precedence(["MAYBE"])

    def test_unknown_string_among_valid_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            resolve_precedence(["ALLOW", "NOT_A_REAL_LABEL"])

    def test_non_string_non_enum_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            resolve_precedence([123])
        with self.assertRaises(ValueError):
            resolve_precedence([None])
        with self.assertRaises(ValueError):
            resolve_precedence([["ALLOW"]])

    def test_duplicate_labels_do_not_affect_result(self) -> None:
        self.assertEqual(
            resolve_precedence(["ALLOW", "ALLOW", "ALLOW"]),
            AdmissionDecision.ALLOW,
        )
        self.assertEqual(
            resolve_precedence(["REFUSE", "REFUSE", "ALLOW", "ALLOW"]),
            AdmissionDecision.REFUSE,
        )

    def test_deterministic_regardless_of_order(self) -> None:
        labels = ["ALLOW", "REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL", "REFUSE"]
        first = resolve_precedence(labels)
        for _ in range(5):
            labels = labels[1:] + labels[:1]  # rotate
            self.assertEqual(resolve_precedence(labels), first)


class TestPrecedenceRelations(unittest.TestCase):
    def test_refuse_beats_require_human_approval(self) -> None:
        self.assertEqual(
            resolve_precedence(["REFUSE", "REQUIRE_HUMAN_APPROVAL"]),
            AdmissionDecision.REFUSE,
        )

    def test_refuse_beats_request_more_evidence(self) -> None:
        self.assertEqual(
            resolve_precedence(["REFUSE", "REQUEST_MORE_EVIDENCE"]),
            AdmissionDecision.REFUSE,
        )

    def test_refuse_beats_allow_with_limits(self) -> None:
        self.assertEqual(
            resolve_precedence(["REFUSE", "ALLOW_WITH_LIMITS"]),
            AdmissionDecision.REFUSE,
        )

    def test_refuse_beats_allow(self) -> None:
        self.assertEqual(
            resolve_precedence(["REFUSE", "ALLOW"]),
            AdmissionDecision.REFUSE,
        )

    def test_require_human_approval_beats_request_more_evidence(self) -> None:
        self.assertEqual(
            resolve_precedence(["REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL"]),
            AdmissionDecision.REQUIRE_HUMAN_APPROVAL,
        )

    def test_require_human_approval_beats_allow_with_limits(self) -> None:
        self.assertEqual(
            resolve_precedence(["ALLOW_WITH_LIMITS", "REQUIRE_HUMAN_APPROVAL"]),
            AdmissionDecision.REQUIRE_HUMAN_APPROVAL,
        )

    def test_require_human_approval_beats_allow(self) -> None:
        self.assertEqual(
            resolve_precedence(["ALLOW", "REQUIRE_HUMAN_APPROVAL"]),
            AdmissionDecision.REQUIRE_HUMAN_APPROVAL,
        )

    def test_request_more_evidence_beats_allow_with_limits(self) -> None:
        self.assertEqual(
            resolve_precedence(["ALLOW_WITH_LIMITS", "REQUEST_MORE_EVIDENCE"]),
            AdmissionDecision.REQUEST_MORE_EVIDENCE,
        )

    def test_request_more_evidence_beats_allow(self) -> None:
        self.assertEqual(
            resolve_precedence(["ALLOW", "REQUEST_MORE_EVIDENCE"]),
            AdmissionDecision.REQUEST_MORE_EVIDENCE,
        )

    def test_allow_with_limits_beats_allow(self) -> None:
        self.assertEqual(
            resolve_precedence(["ALLOW_WITH_LIMITS", "ALLOW"]),
            AdmissionDecision.ALLOW_WITH_LIMITS,
        )

    def test_full_five_way_mix_resolves_to_refuse(self) -> None:
        self.assertEqual(
            resolve_precedence(
                ["ALLOW", "ALLOW_WITH_LIMITS", "REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL", "REFUSE"]
            ),
            AdmissionDecision.REFUSE,
        )


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


class TestSchemaDecisionEnumConsistency(unittest.TestCase):
    """Schema-only consistency check: no jsonschema dependency, stdlib json only."""

    def test_decision_output_schema_enum_matches_python_enum(self) -> None:
        schema = _load_json(SCHEMAS_DIR / "decision_output.schema.json")
        schema_enum = set(schema["$defs"]["decisionLabel"]["enum"])
        python_enum = {member.value for member in AdmissionDecision}
        self.assertEqual(schema_enum, python_enum)

    def test_gold_annotation_schema_enum_matches_python_enum(self) -> None:
        schema = _load_json(SCHEMAS_DIR / "gold_annotation.schema.json")
        schema_enum = set(schema["properties"]["gold_decision"]["enum"])
        python_enum = {member.value for member in AdmissionDecision}
        self.assertEqual(schema_enum, python_enum)


if __name__ == "__main__":
    unittest.main()
