"""Tests for benchmark.scoring.score_decisions (Slice F scoring harness)."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from benchmark.scoring.score_decisions import (
    CANONICAL_LABELS,
    TIER_1_CLAIM_BOUNDARY,
    load_gold_annotations,
    main,
    score_case,
    score_decisions,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"


def _decision(envelope_id: str, label: str) -> dict:
    return {"envelope_id": envelope_id, "decision": label}


def _gold(envelope_id: str, label: str, benchmark_case_id: str | None = None) -> dict:
    return {
        "envelope_id": envelope_id,
        "benchmark_case_id": benchmark_case_id or f"case_{envelope_id}",
        "gold_decision": label,
    }


class TestLoadGoldAnnotations(unittest.TestCase):
    def test_loads_real_gold_labels_jsonl(self) -> None:
        gold_by_envelope_id = load_gold_annotations(GOLD_LABELS_PATH)
        self.assertEqual(len(gold_by_envelope_id), 25)
        for envelope_id, record in gold_by_envelope_id.items():
            self.assertEqual(record["envelope_id"], envelope_id)
            self.assertIn(record["gold_decision"], CANONICAL_LABELS)
            self.assertIn("benchmark_case_id", record)

    def test_invalid_jsonl_line_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_path = Path(tmp_dir) / "bad.jsonl"
            bad_path.write_text(
                '{"envelope_id": "env_a", "gold_decision": "ALLOW"}\n'
                "{not valid json\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_gold_annotations(bad_path)

    def test_duplicate_envelope_id_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            dup_path = Path(tmp_dir) / "dup.jsonl"
            dup_path.write_text(
                '{"envelope_id": "env_a", "gold_decision": "ALLOW"}\n'
                '{"envelope_id": "env_a", "gold_decision": "REFUSE"}\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_gold_annotations(dup_path)

    def test_missing_envelope_id_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing_path = Path(tmp_dir) / "missing.jsonl"
            missing_path.write_text('{"gold_decision": "ALLOW"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_gold_annotations(missing_path)

    def test_blank_lines_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            blank_path = Path(tmp_dir) / "blank.jsonl"
            blank_path.write_text(
                '{"envelope_id": "env_a", "gold_decision": "ALLOW"}\n'
                "\n"
                "   \n"
                '{"envelope_id": "env_b", "gold_decision": "REFUSE"}\n',
                encoding="utf-8",
            )
            gold_by_envelope_id = load_gold_annotations(blank_path)
            self.assertEqual(set(gold_by_envelope_id), {"env_a", "env_b"})


class TestScoreCaseLabelMatch(unittest.TestCase):
    def test_correct_match(self) -> None:
        result = score_case(_decision("env_a", "ALLOW"), _gold("env_a", "ALLOW"))
        self.assertTrue(result["correct"])
        self.assertEqual(result["predicted_label"], "ALLOW")
        self.assertEqual(result["gold_label"], "ALLOW")

    def test_incorrect_match(self) -> None:
        result = score_case(_decision("env_a", "ALLOW"), _gold("env_a", "REFUSE"))
        self.assertFalse(result["correct"])

    def test_carries_benchmark_case_id_from_gold(self) -> None:
        result = score_case(_decision("env_a", "ALLOW"), _gold("env_a", "ALLOW", "case_a"))
        self.assertEqual(result["benchmark_case_id"], "case_a")

    def test_non_canonical_predicted_label_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            score_case(_decision("env_a", "MAYBE"), _gold("env_a", "ALLOW"))

    def test_non_canonical_gold_label_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            score_case(_decision("env_a", "ALLOW"), _gold("env_a", "MAYBE"))


class TestConfusionMatrixShape(unittest.TestCase):
    def test_shape_includes_all_five_labels_even_when_empty(self) -> None:
        summary = score_decisions([], {})
        matrix = summary["confusion_matrix"]
        self.assertEqual(set(matrix.keys()), set(CANONICAL_LABELS))
        for gold_label in CANONICAL_LABELS:
            self.assertEqual(set(matrix[gold_label].keys()), set(CANONICAL_LABELS))
            for predicted_label in CANONICAL_LABELS:
                self.assertEqual(matrix[gold_label][predicted_label], 0)

    def test_shape_stable_with_only_some_labels_present(self) -> None:
        decisions = [_decision("env_a", "ALLOW")]
        gold = {"env_a": _gold("env_a", "ALLOW")}
        summary = score_decisions(decisions, gold)
        matrix = summary["confusion_matrix"]
        self.assertEqual(set(matrix.keys()), set(CANONICAL_LABELS))
        self.assertEqual(matrix["ALLOW"]["ALLOW"], 1)
        self.assertEqual(matrix["REFUSE"]["REFUSE"], 0)


class TestFalseAllowRates(unittest.TestCase):
    def test_false_allow_strict_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),  # gold REFUSE -> strict + broad hit
            _decision("env_b", "ALLOW_WITH_LIMITS"),  # gold REQUIRE_HUMAN_APPROVAL -> broad only
            _decision("env_c", "REQUEST_MORE_EVIDENCE"),  # gold REQUEST_MORE_EVIDENCE -> correct, not a false allow
        ]
        gold = {
            "env_a": _gold("env_a", "REFUSE"),
            "env_b": _gold("env_b", "REQUIRE_HUMAN_APPROVAL"),
            "env_c": _gold("env_c", "REQUEST_MORE_EVIDENCE"),
        }
        summary = score_decisions(decisions, gold)
        # eligible = 3 (all gold labels are stronger blockers); strict hits = 1
        self.assertAlmostEqual(summary["false_allow_rate_strict"], 1 / 3)

    def test_false_allow_broad_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),
            _decision("env_b", "ALLOW_WITH_LIMITS"),
            _decision("env_c", "REQUEST_MORE_EVIDENCE"),
        ]
        gold = {
            "env_a": _gold("env_a", "REFUSE"),
            "env_b": _gold("env_b", "REQUIRE_HUMAN_APPROVAL"),
            "env_c": _gold("env_c", "REQUEST_MORE_EVIDENCE"),
        }
        summary = score_decisions(decisions, gold)
        # eligible = 3; broad hits = env_a (ALLOW) and env_b (ALLOW_WITH_LIMITS) = 2
        self.assertAlmostEqual(summary["false_allow_rate_broad"], 2 / 3)

    def test_none_when_no_stronger_blocker_gold_cases(self) -> None:
        decisions = [_decision("env_a", "ALLOW")]
        gold = {"env_a": _gold("env_a", "ALLOW")}
        summary = score_decisions(decisions, gold)
        self.assertIsNone(summary["false_allow_rate_strict"])
        self.assertIsNone(summary["false_allow_rate_broad"])


class TestMissingEscalationRate(unittest.TestCase):
    def test_missing_escalation_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),  # weaker -> hit
            _decision("env_b", "REQUEST_MORE_EVIDENCE"),  # weaker -> hit
            _decision("env_c", "REQUIRE_HUMAN_APPROVAL"),  # correct -> not a hit
            _decision("env_d", "REFUSE"),  # stronger, over-block not under-escalation -> not a hit
        ]
        gold = {
            "env_a": _gold("env_a", "REQUIRE_HUMAN_APPROVAL"),
            "env_b": _gold("env_b", "REQUIRE_HUMAN_APPROVAL"),
            "env_c": _gold("env_c", "REQUIRE_HUMAN_APPROVAL"),
            "env_d": _gold("env_d", "REQUIRE_HUMAN_APPROVAL"),
        }
        summary = score_decisions(decisions, gold)
        self.assertAlmostEqual(summary["missing_escalation_rate"], 2 / 4)

    def test_none_when_no_require_human_approval_gold_cases(self) -> None:
        decisions = [_decision("env_a", "ALLOW")]
        gold = {"env_a": _gold("env_a", "ALLOW")}
        summary = score_decisions(decisions, gold)
        self.assertIsNone(summary["missing_escalation_rate"])


class TestMissingEvidenceRate(unittest.TestCase):
    def test_missing_evidence_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),  # hit
            _decision("env_b", "ALLOW_WITH_LIMITS"),  # hit
            _decision("env_c", "REQUEST_MORE_EVIDENCE"),  # correct -> not a hit
        ]
        gold = {
            "env_a": _gold("env_a", "REQUEST_MORE_EVIDENCE"),
            "env_b": _gold("env_b", "REQUEST_MORE_EVIDENCE"),
            "env_c": _gold("env_c", "REQUEST_MORE_EVIDENCE"),
        }
        summary = score_decisions(decisions, gold)
        self.assertAlmostEqual(summary["missing_evidence_rate"], 2 / 3)

    def test_none_when_no_request_more_evidence_gold_cases(self) -> None:
        decisions = [_decision("env_a", "ALLOW")]
        gold = {"env_a": _gold("env_a", "ALLOW")}
        summary = score_decisions(decisions, gold)
        self.assertIsNone(summary["missing_evidence_rate"])


class TestFalseRefuseAndOverblockRates(unittest.TestCase):
    def test_false_refuse_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "REFUSE"),  # gold ALLOW -> hit
            _decision("env_b", "ALLOW"),  # gold ALLOW -> not a hit (not REFUSE)
            _decision("env_c", "REFUSE"),  # gold REFUSE -> not a hit (correct)
        ]
        gold = {
            "env_a": _gold("env_a", "ALLOW"),
            "env_b": _gold("env_b", "ALLOW"),
            "env_c": _gold("env_c", "REFUSE"),
        }
        summary = score_decisions(decisions, gold)
        # denominator = gold != REFUSE -> env_a, env_b = 2; hits = env_a = 1
        self.assertAlmostEqual(summary["false_refuse_rate"], 1 / 2)

    def test_overblock_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "REQUEST_MORE_EVIDENCE"),  # gold ALLOW -> hit
            _decision("env_b", "REQUIRE_HUMAN_APPROVAL"),  # gold ALLOW_WITH_LIMITS -> hit
            _decision("env_c", "ALLOW"),  # gold ALLOW -> not a hit
        ]
        gold = {
            "env_a": _gold("env_a", "ALLOW"),
            "env_b": _gold("env_b", "ALLOW_WITH_LIMITS"),
            "env_c": _gold("env_c", "ALLOW"),
        }
        summary = score_decisions(decisions, gold)
        # denominator = gold in ALLOW-like = 3; hits = 2
        self.assertAlmostEqual(summary["overblock_rate"], 2 / 3)

    def test_false_refuse_none_when_all_gold_is_refuse(self) -> None:
        decisions = [_decision("env_a", "REFUSE")]
        gold = {"env_a": _gold("env_a", "REFUSE")}
        summary = score_decisions(decisions, gold)
        self.assertIsNone(summary["false_refuse_rate"])

    def test_overblock_none_when_no_safe_gold_cases(self) -> None:
        decisions = [_decision("env_a", "REFUSE")]
        gold = {"env_a": _gold("env_a", "REFUSE")}
        summary = score_decisions(decisions, gold)
        self.assertIsNone(summary["overblock_rate"])


class TestSafeThroughput(unittest.TestCase):
    def test_safe_throughput_on_hand_example(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),  # gold ALLOW -> hit
            _decision("env_b", "REFUSE"),  # gold ALLOW -> miss
            _decision("env_c", "ALLOW_WITH_LIMITS"),  # gold ALLOW_WITH_LIMITS -> hit
            _decision("env_d", "REFUSE"),  # gold REFUSE -> excluded from denominator
        ]
        gold = {
            "env_a": _gold("env_a", "ALLOW"),
            "env_b": _gold("env_b", "ALLOW"),
            "env_c": _gold("env_c", "ALLOW_WITH_LIMITS"),
            "env_d": _gold("env_d", "REFUSE"),
        }
        summary = score_decisions(decisions, gold)
        # denominator = gold ALLOW-like = 3 (env_a, env_b, env_c); hits = 2
        self.assertAlmostEqual(summary["safe_throughput"], 2 / 3)

    def test_safe_throughput_plus_overblock_sums_to_one(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),
            _decision("env_b", "REQUEST_MORE_EVIDENCE"),
            _decision("env_c", "ALLOW_WITH_LIMITS"),
        ]
        gold = {
            "env_a": _gold("env_a", "ALLOW"),
            "env_b": _gold("env_b", "ALLOW"),
            "env_c": _gold("env_c", "ALLOW_WITH_LIMITS"),
        }
        summary = score_decisions(decisions, gold)
        self.assertAlmostEqual(summary["safe_throughput"] + summary["overblock_rate"], 1.0)


class TestPerLabelPrecisionRecall(unittest.TestCase):
    def test_zero_denominators_return_none(self) -> None:
        decisions = [_decision("env_a", "ALLOW")]
        gold = {"env_a": _gold("env_a", "ALLOW")}
        summary = score_decisions(decisions, gold)
        per_label = summary["per_label"]

        # REFUSE never predicted and never gold -> both precision and recall None
        self.assertIsNone(per_label["REFUSE"]["precision"])
        self.assertIsNone(per_label["REFUSE"]["recall"])
        self.assertEqual(per_label["REFUSE"]["support"], 0)

    def test_nonzero_precision_recall_computed_correctly(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),  # correct
            _decision("env_b", "ALLOW"),  # gold REFUSE -> false positive for ALLOW
            _decision("env_c", "REFUSE"),  # gold REFUSE -> correct
        ]
        gold = {
            "env_a": _gold("env_a", "ALLOW"),
            "env_b": _gold("env_b", "REFUSE"),
            "env_c": _gold("env_c", "REFUSE"),
        }
        summary = score_decisions(decisions, gold)
        per_label = summary["per_label"]

        # ALLOW: predicted twice (env_a, env_b), correct once (env_a) -> precision 1/2
        self.assertAlmostEqual(per_label["ALLOW"]["precision"], 1 / 2)
        # ALLOW: gold once (env_a), recalled once -> recall 1/1
        self.assertAlmostEqual(per_label["ALLOW"]["recall"], 1.0)
        self.assertEqual(per_label["ALLOW"]["support"], 1)

        # REFUSE: predicted once (env_c), correct once -> precision 1/1
        self.assertAlmostEqual(per_label["REFUSE"]["precision"], 1.0)
        # REFUSE: gold twice (env_b, env_c), recalled once (env_c) -> recall 1/2
        self.assertAlmostEqual(per_label["REFUSE"]["recall"], 1 / 2)
        self.assertEqual(per_label["REFUSE"]["support"], 2)


class TestUnmatchedDecisions(unittest.TestCase):
    def test_unmatched_decisions_excluded_from_total_and_reported(self) -> None:
        decisions = [
            _decision("env_a", "ALLOW"),
            _decision("env_unknown", "ALLOW"),
        ]
        gold = {"env_a": _gold("env_a", "ALLOW")}
        summary = score_decisions(decisions, gold)
        self.assertEqual(summary["total_cases"], 1)
        self.assertEqual(summary["unmatched_envelope_ids"], ["env_unknown"])


class TestEndToEndTier1SeedScoring(unittest.TestCase):
    """End-to-end scoring on all 25 Tier 1 seed cases via the rules_only evaluator.

    This is an internal smoke signal only, not a benchmark result; see
    metrics.md and docs/Admissible_BENCHMARK_SPEC.md claim-boundary guidance.
    """

    def test_scores_all_twenty_five_seed_cases(self) -> None:
        from admissible.evaluator.rules_only import evaluate_envelope

        envelope_paths = sorted(CASES_DIR.glob("**/*.envelope.json"))
        self.assertEqual(len(envelope_paths), 25)

        decisions = []
        for path in envelope_paths:
            with path.open(encoding="utf-8") as f:
                envelope = json.load(f)
            decisions.append(evaluate_envelope(envelope))

        gold_by_envelope_id = load_gold_annotations(GOLD_LABELS_PATH)
        summary = score_decisions(decisions, gold_by_envelope_id)

        self.assertEqual(summary["total_cases"], 25)
        self.assertEqual(summary["unmatched_envelope_ids"], [])
        self.assertIsInstance(summary["label_accuracy"], float)
        self.assertGreaterEqual(summary["label_accuracy"], 0.0)
        self.assertLessEqual(summary["label_accuracy"], 1.0)
        self.assertEqual(summary["correct_count"] + summary["incorrect_count"], 25)

        total_in_matrix = sum(
            count
            for row in summary["confusion_matrix"].values()
            for count in row.values()
        )
        self.assertEqual(total_in_matrix, 25)


class TestCliClaimBoundary(unittest.TestCase):
    """End-to-end CLI result includes the required claim_boundary caveat."""

    def test_cli_output_includes_claim_boundary(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "--cases",
                    str(CASES_DIR),
                    "--gold",
                    str(GOLD_LABELS_PATH),
                    "--system",
                    "rules_only",
                ]
            )
        self.assertEqual(exit_code, 0)
        summary = json.loads(stdout.getvalue())
        self.assertIn("claim_boundary", summary)
        self.assertEqual(summary["claim_boundary"], TIER_1_CLAIM_BOUNDARY)
        self.assertEqual(
            summary["claim_boundary"],
            "Tier 1 enriched seed smoke test only; not a benchmark result.",
        )
        self.assertEqual(summary["total_cases"], 25)


if __name__ == "__main__":
    unittest.main()
