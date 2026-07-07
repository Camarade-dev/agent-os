"""Tests for admissible.runner.compare_runner (Slice H baseline scoring comparison)."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path
from unittest import mock

from admissible.runner.baseline_runner import build_frontier_direct_prompt
from admissible.runner.compare_runner import (
    FRONTIER_MOCK_NOTE,
    SUPPORTED_SYSTEMS,
    compare_systems,
    load_envelopes,
    main,
    run_system_on_envelopes,
)
from benchmark.scoring.score_decisions import TIER_1_CLAIM_BOUNDARY, load_gold_annotations

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"

_REQUIRED_METRIC_FIELDS = (
    "total_cases",
    "label_accuracy",
    "correct_count",
    "incorrect_count",
    "confusion_matrix",
    "false_allow_rate_strict",
    "false_allow_rate_broad",
    "missing_escalation_rate",
    "missing_evidence_rate",
    "false_refuse_rate",
    "overblock_rate",
    "safe_throughput",
    "per_label",
    "unmatched_envelope_ids",
    "claim_boundary",
)


def _case_sort_key(envelope: dict) -> str:
    metadata = envelope.get("metadata") or {}
    benchmark_case_id = metadata.get("benchmark_case_id")
    if isinstance(benchmark_case_id, str) and benchmark_case_id:
        return benchmark_case_id
    return envelope.get("envelope_id") or ""


class TestLoadEnvelopes(unittest.TestCase):
    def test_loads_all_25_seed_cases(self) -> None:
        envelopes = load_envelopes(CASES_DIR)
        self.assertEqual(len(envelopes), 25)
        for envelope in envelopes:
            self.assertIsInstance(envelope, dict)
            self.assertIn("envelope_id", envelope)

    def test_sorted_deterministically_by_benchmark_case_id_or_envelope_id(self) -> None:
        envelopes = load_envelopes(CASES_DIR)
        keys = [_case_sort_key(envelope) for envelope in envelopes]
        self.assertEqual(keys, sorted(keys))

    def test_loading_twice_yields_identical_order(self) -> None:
        first = load_envelopes(CASES_DIR)
        second = load_envelopes(CASES_DIR)
        self.assertEqual(
            [e["envelope_id"] for e in first],
            [e["envelope_id"] for e in second],
        )


class TestRunSystemOnEnvelopes(unittest.TestCase):
    def setUp(self) -> None:
        self.envelopes = load_envelopes(CASES_DIR)
        self.mock_response = json.loads(MOCK_RESPONSE_PATH.read_text(encoding="utf-8"))

    def test_rules_only_returns_25_decisions(self) -> None:
        decisions = run_system_on_envelopes("rules_only", self.envelopes)
        self.assertEqual(len(decisions), 25)
        for decision in decisions:
            self.assertIn(decision["decision"], (
                "ALLOW", "ALLOW_WITH_LIMITS", "REQUEST_MORE_EVIDENCE",
                "REQUIRE_HUMAN_APPROVAL", "REFUSE",
            ))

    def test_frontier_direct_mock_returns_25_decisions(self) -> None:
        decisions = run_system_on_envelopes(
            "frontier_direct_mock", self.envelopes, mock_response=self.mock_response
        )
        self.assertEqual(len(decisions), 25)
        for decision in decisions:
            self.assertIn(decision["decision"], (
                "ALLOW", "ALLOW_WITH_LIMITS", "REQUEST_MORE_EVIDENCE",
                "REQUIRE_HUMAN_APPROVAL", "REFUSE",
            ))

    def test_unknown_system_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            run_system_on_envelopes("not_a_real_system", self.envelopes)

    def test_missing_mock_response_for_frontier_direct_mock_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            run_system_on_envelopes("frontier_direct_mock", self.envelopes)


class TestCompareSystems(unittest.TestCase):
    def _compare(self, systems: list[str]) -> dict:
        return compare_systems(
            CASES_DIR,
            GOLD_LABELS_PATH,
            systems,
            mock_response_path=MOCK_RESPONSE_PATH,
        )

    def test_returns_a_dict(self) -> None:
        comparison = self._compare(["rules_only"])
        self.assertIsInstance(comparison, dict)

    def test_includes_both_requested_systems(self) -> None:
        comparison = self._compare(["rules_only", "frontier_direct_mock"])
        self.assertEqual(set(comparison["systems"]), {"rules_only", "frontier_direct_mock"})
        self.assertEqual(set(comparison["results"].keys()), {"rules_only", "frontier_direct_mock"})

    def test_top_level_claim_boundary_present_and_exact(self) -> None:
        comparison = self._compare(["rules_only", "frontier_direct_mock"])
        self.assertIn("claim_boundary", comparison)
        self.assertEqual(
            comparison["claim_boundary"],
            "Tier 1 enriched seed smoke test only; not a benchmark result.",
        )
        self.assertEqual(comparison["claim_boundary"], TIER_1_CLAIM_BOUNDARY)

    def test_top_level_case_count(self) -> None:
        comparison = self._compare(["rules_only"])
        self.assertEqual(comparison["case_count"], 25)

    def test_each_system_result_includes_scoring_claim_boundary(self) -> None:
        comparison = self._compare(["rules_only", "frontier_direct_mock"])
        for system in ("rules_only", "frontier_direct_mock"):
            self.assertEqual(comparison["results"][system]["claim_boundary"], TIER_1_CLAIM_BOUNDARY)

    def test_each_system_result_has_all_required_metric_fields(self) -> None:
        comparison = self._compare(["rules_only", "frontier_direct_mock"])
        for system in ("rules_only", "frontier_direct_mock"):
            result = comparison["results"][system]
            for field in _REQUIRED_METRIC_FIELDS:
                self.assertIn(field, result, f"missing {field!r} in {system} result")

    def test_rules_only_matches_known_25_of_25_smoke_score(self) -> None:
        comparison = self._compare(["rules_only"])
        rules_only_result = comparison["results"]["rules_only"]
        self.assertEqual(rules_only_result["total_cases"], 25)
        self.assertEqual(rules_only_result["correct_count"], 25)
        self.assertEqual(rules_only_result["incorrect_count"], 0)
        self.assertEqual(rules_only_result["label_accuracy"], 1.0)
        self.assertEqual(rules_only_result["unmatched_envelope_ids"], [])

    def test_frontier_direct_mock_is_scored_but_not_framed_as_model_performance(self) -> None:
        comparison = self._compare(["frontier_direct_mock"])
        result = comparison["results"]["frontier_direct_mock"]
        # It is still scored like any other system:
        self.assertEqual(result["total_cases"], 25)
        self.assertIsInstance(result["label_accuracy"], float)
        # ...but explicitly flagged as not a model-performance measurement.
        self.assertEqual(result["notes"], FRONTIER_MOCK_NOTE)
        self.assertEqual(
            result["notes"],
            "frontier_direct_mock is a plumbing/mock baseline, not a model-performance result.",
        )
        self.assertEqual(comparison["notes"], FRONTIER_MOCK_NOTE)


class TestNoGoldOrRulesOnlyLeakageIntoBaselinePrompt(unittest.TestCase):
    """No gold annotations or rules-only outputs are passed into the baseline prompt.

    Mirrors the leakage checks in tests/test_admissible_baseline_runner.py
    (TestBuildFrontierDirectPrompt), but exercised through compare_runner's
    own frontier_direct_mock code path via a prompt-recording spy client,
    to confirm compare_runner does not add anything beyond the bare
    envelope before calling the baseline runner.
    """

    def test_prompts_built_by_compare_runner_contain_no_gold_or_rules_only_fields(self) -> None:
        envelopes = load_envelopes(CASES_DIR)[:5]
        mock_response = json.loads(MOCK_RESPONSE_PATH.read_text(encoding="utf-8"))
        gold_by_envelope_id = load_gold_annotations(GOLD_LABELS_PATH)

        recorded_prompts: list[str] = []

        class _SpyModelClient:
            def __init__(self, response_text: str):
                self._response_text = response_text

            def complete(self, prompt: str) -> str:
                recorded_prompts.append(prompt)
                return self._response_text

        with mock.patch(
            "admissible.runner.compare_runner.FixedResponseModelClient", _SpyModelClient
        ):
            run_system_on_envelopes(
                "frontier_direct_mock", envelopes, mock_response=mock_response
            )

        self.assertEqual(len(recorded_prompts), 5)
        for envelope, prompt in zip(envelopes, recorded_prompts):
            for leaky_field in (
                "gold_decision", "rubric", "correct_label",
                "gold_safer_next_step", "gold_risk_level",
            ):
                self.assertNotIn(leaky_field, prompt)
            self.assertNotIn("rules_only", prompt)

            gold = gold_by_envelope_id[envelope["envelope_id"]]
            self.assertNotIn(gold["gold_decision"] + '"', prompt.replace(envelope["envelope_id"], ""))

            # The prompt is exactly what build_frontier_direct_prompt would
            # build from the bare envelope alone -- nothing extra injected.
            self.assertEqual(prompt, build_frontier_direct_prompt(envelope))


class TestCli(unittest.TestCase):
    def _run_cli(self, systems: list[str]) -> tuple[int, str]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main([
                "--cases", str(CASES_DIR),
                "--gold", str(GOLD_LABELS_PATH),
                "--systems", *systems,
                "--mock-response", str(MOCK_RESPONSE_PATH),
            ])
        return exit_code, stdout.getvalue()

    def test_cli_prints_valid_json(self) -> None:
        exit_code, output = self._run_cli(["rules_only", "frontier_direct_mock"])
        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertIsInstance(parsed, dict)

    def test_cli_output_includes_both_systems_and_claim_boundary(self) -> None:
        _, output = self._run_cli(["rules_only", "frontier_direct_mock"])
        comparison = json.loads(output)
        self.assertEqual(set(comparison["systems"]), {"rules_only", "frontier_direct_mock"})
        self.assertEqual(set(comparison["results"].keys()), {"rules_only", "frontier_direct_mock"})
        self.assertEqual(
            comparison["claim_boundary"],
            "Tier 1 enriched seed smoke test only; not a benchmark result.",
        )


class TestSupportedSystemsConstant(unittest.TestCase):
    def test_supported_systems_includes_required_two(self) -> None:
        self.assertIn("rules_only", SUPPORTED_SYSTEMS)
        self.assertIn("frontier_direct_mock", SUPPORTED_SYSTEMS)


if __name__ == "__main__":
    unittest.main()
