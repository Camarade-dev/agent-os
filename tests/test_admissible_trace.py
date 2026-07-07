"""Tests for admissible.trace and run_trace.schema.json (Slice I)."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible.runner.baseline_runner import build_frontier_direct_prompt
from admissible.runner.compare_runner import (
    gather_comparison_data,
    main as compare_main,
    run_system_on_envelopes,
)
from admissible.trace import (
    TRACE_GENERATED_BY,
    build_run_trace,
    derive_final_verdict,
    make_trace_id,
)
from benchmark.scoring.score_decisions import TIER_1_CLAIM_BOUNDARY as SCORING_CLAIM_BOUNDARY

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
RUN_TRACE_SCHEMA_PATH = REPO_ROOT / "benchmark" / "schemas" / "run_trace.schema.json"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "trace_id",
    "schema_version",
    "created_at",
    "claim_boundary",
    "case_set",
    "systems",
    "case_traces",
    "aggregate_results",
    "final_verdict",
    "metadata",
)

_EXACT_CLAIM_BOUNDARY = "Tier 1 enriched seed smoke test only; not a benchmark result."


def _full_comparison() -> tuple[dict, list[dict], dict[str, dict], dict[str, list[dict]]]:
    return gather_comparison_data(
        CASES_DIR,
        GOLD_LABELS_PATH,
        ["rules_only", "frontier_direct_mock"],
        mock_response_path=MOCK_RESPONSE_PATH,
    )


def _build_trace() -> dict:
    comparison, envelopes, gold_by_envelope_id, decisions_by_system = _full_comparison()
    return build_run_trace(
        cases_path=CASES_DIR,
        gold_path=GOLD_LABELS_PATH,
        systems=["rules_only", "frontier_direct_mock"],
        comparison=comparison,
        envelopes=envelopes,
        gold_by_envelope_id=gold_by_envelope_id,
        decisions_by_system=decisions_by_system,
    )


class TestBuildRunTraceBasics(unittest.TestCase):
    def test_returns_a_dict(self) -> None:
        trace = _build_trace()
        self.assertIsInstance(trace, dict)

    def test_has_all_required_top_level_fields(self) -> None:
        trace = _build_trace()
        for field in _REQUIRED_TOP_LEVEL_FIELDS:
            self.assertIn(field, trace, f"missing top-level field {field!r}")

    def test_includes_exact_claim_boundary(self) -> None:
        trace = _build_trace()
        self.assertEqual(trace["claim_boundary"], _EXACT_CLAIM_BOUNDARY)
        self.assertEqual(trace["claim_boundary"], SCORING_CLAIM_BOUNDARY)


class TestMetadataOverrides(unittest.TestCase):
    def test_defaults_are_unchanged_when_overrides_omitted(self) -> None:
        trace = _build_trace()
        self.assertEqual(trace["metadata"]["generated_by"], TRACE_GENERATED_BY)
        self.assertEqual(trace["metadata"]["notes"], [])

    def test_metadata_generated_by_and_notes_can_be_overridden(self) -> None:
        comparison, envelopes, gold_by_envelope_id, decisions_by_system = _full_comparison()
        trace = build_run_trace(
            cases_path=CASES_DIR,
            gold_path=GOLD_LABELS_PATH,
            systems=["rules_only", "frontier_direct_mock"],
            comparison=comparison,
            envelopes=envelopes,
            gold_by_envelope_id=gold_by_envelope_id,
            decisions_by_system=decisions_by_system,
            metadata_generated_by="admissible.runner.demo_trace",
            metadata_notes=["note one", "note two"],
        )
        self.assertEqual(trace["metadata"]["generated_by"], "admissible.runner.demo_trace")
        self.assertEqual(trace["metadata"]["notes"], ["note one", "note two"])


class TestCaseSet(unittest.TestCase):
    def test_distinguishes_benchmark_tier_and_envelope_tier(self) -> None:
        trace = _build_trace()
        case_set = trace["case_set"]
        self.assertEqual(case_set["benchmark_tier"], "tier_1_enriched")
        self.assertEqual(case_set["envelope_tier"], "fully_enriched")
        self.assertNotEqual(case_set["benchmark_tier"], case_set["envelope_tier"])

    def test_case_set_paths_and_count(self) -> None:
        trace = _build_trace()
        case_set = trace["case_set"]
        self.assertIn("tier_1_enriched", case_set["cases_path"])
        self.assertIn("gold_labels.jsonl", case_set["gold_path"])
        self.assertEqual(case_set["case_count"], 25)


class TestSystemsDescriptors(unittest.TestCase):
    def test_systems_are_descriptors_with_required_fields(self) -> None:
        trace = _build_trace()
        self.assertEqual(len(trace["systems"]), 2)
        for descriptor in trace["systems"]:
            self.assertIn("system_id", descriptor)
            self.assertIn("system_type", descriptor)
            self.assertIn("description", descriptor)
            self.assertIn("claim_boundary", descriptor)
            self.assertEqual(descriptor["claim_boundary"], _EXACT_CLAIM_BOUNDARY)

    def test_system_types_match_known_systems(self) -> None:
        trace = _build_trace()
        types = {d["system_type"] for d in trace["systems"]}
        self.assertEqual(types, {"rules_only", "frontier_direct_mock"})


class TestCaseTraces(unittest.TestCase):
    def test_case_traces_include_envelope_gold_decisions_scores(self) -> None:
        trace = _build_trace()
        self.assertEqual(len(trace["case_traces"]), 25)
        for case_trace in trace["case_traces"]:
            self.assertIn("benchmark_case_id", case_trace)
            self.assertIn("envelope_id", case_trace)
            self.assertIsInstance(case_trace["envelope"], dict)
            self.assertIsInstance(case_trace["gold_annotation"], dict)
            self.assertIsInstance(case_trace["decisions"], dict)
            self.assertIsInstance(case_trace["scores"], dict)
            self.assertGreater(len(case_trace["decisions"]), 0)
            self.assertGreater(len(case_trace["scores"]), 0)

    def test_scores_keys_match_decisions_keys(self) -> None:
        trace = _build_trace()
        for case_trace in trace["case_traces"]:
            self.assertEqual(
                set(case_trace["decisions"].keys()),
                set(case_trace["scores"].keys()),
            )


class TestGoldNotInPrompts(unittest.TestCase):
    def test_gold_annotation_not_in_baseline_prompts(self) -> None:
        comparison, envelopes, gold_by_envelope_id, _ = _full_comparison()
        mock_response = json.loads(MOCK_RESPONSE_PATH.read_text(encoding="utf-8"))
        recorded_prompts: list[str] = []

        class _SpyModelClient:
            def __init__(self, response_text: str):
                self._response_text = response_text

            def complete(self, prompt: str) -> str:
                recorded_prompts.append(prompt)
                return self._response_text

        with mock.patch(
            "admissible.runner.compare_runner._FixedResponseModelClient", _SpyModelClient
        ):
            run_system_on_envelopes(
                "frontier_direct_mock", envelopes[:5], mock_response=mock_response
            )

        trace = build_run_trace(
            cases_path=CASES_DIR,
            gold_path=GOLD_LABELS_PATH,
            systems=["rules_only", "frontier_direct_mock"],
            comparison=comparison,
            envelopes=envelopes,
            gold_by_envelope_id=gold_by_envelope_id,
            decisions_by_system={"rules_only": [], "frontier_direct_mock": []},
        )

        self.assertEqual(len(trace["case_traces"]), 25)
        for case_trace in trace["case_traces"]:
            self.assertIsNotNone(case_trace["gold_annotation"])

        for envelope, prompt in zip(envelopes[:5], recorded_prompts):
            for leaky_field in (
                "gold_decision", "rubric", "correct_label",
                "gold_safer_next_step", "gold_risk_level",
            ):
                self.assertNotIn(leaky_field, prompt)
            gold = gold_by_envelope_id[envelope["envelope_id"]]
            self.assertNotIn(
                gold["gold_decision"] + '"',
                prompt.replace(envelope["envelope_id"], ""),
            )
            self.assertEqual(prompt, build_frontier_direct_prompt(envelope))


class TestFinalVerdict(unittest.TestCase):
    def test_smoke_pass_for_complete_tier1_mock_comparison(self) -> None:
        trace = _build_trace()
        verdict = trace["final_verdict"]
        self.assertEqual(verdict["status"], "SMOKE_PASS")

    def test_final_verdict_is_not_a_benchmark_claim(self) -> None:
        trace = _build_trace()
        verdict = trace["final_verdict"]
        limitations_text = " ".join(verdict["limitations"])
        self.assertIn("not", limitations_text.lower())
        self.assertIn("benchmark validity", limitations_text.lower())
        self.assertNotIn("benchmark result", verdict["summary"].lower())

    def test_missing_system_results_produces_smoke_fail(self) -> None:
        comparison = {
            "systems": ["rules_only"],
            "case_count": 25,
            "claim_boundary": _EXACT_CLAIM_BOUNDARY,
            "results": {},
        }
        verdict = derive_final_verdict(comparison)
        self.assertIn(verdict["status"], ("SMOKE_FAIL", "INCONCLUSIVE"))
        self.assertNotEqual(verdict["status"], "SMOKE_PASS")

    def test_unmatched_envelope_ids_produce_not_smoke_pass(self) -> None:
        comparison = {
            "systems": ["rules_only"],
            "case_count": 25,
            "claim_boundary": _EXACT_CLAIM_BOUNDARY,
            "results": {
                "rules_only": {
                    "total_cases": 24,
                    "unmatched_envelope_ids": ["env_missing"],
                },
            },
        }
        verdict = derive_final_verdict(comparison)
        self.assertNotEqual(verdict["status"], "SMOKE_PASS")

    def test_missing_claim_boundary_produces_smoke_fail(self) -> None:
        comparison = {
            "systems": ["rules_only"],
            "case_count": 25,
            "claim_boundary": "wrong boundary",
            "results": {
                "rules_only": {"total_cases": 25, "unmatched_envelope_ids": []},
            },
        }
        verdict = derive_final_verdict(comparison)
        self.assertEqual(verdict["status"], "SMOKE_FAIL")


class TestJsonSerialization(unittest.TestCase):
    def test_trace_is_json_serializable(self) -> None:
        trace = _build_trace()
        serialized = json.dumps(trace)
        round_trip = json.loads(serialized)
        self.assertEqual(round_trip["trace_id"], trace["trace_id"])


class TestRunTraceSchema(unittest.TestCase):
    def test_schema_file_is_valid_json(self) -> None:
        with RUN_TRACE_SCHEMA_PATH.open(encoding="utf-8") as f:
            schema = json.load(f)
        self.assertEqual(schema["title"], "Admissible Run Trace")

    def test_trace_top_level_keys_match_schema_required(self) -> None:
        with RUN_TRACE_SCHEMA_PATH.open(encoding="utf-8") as f:
            schema = json.load(f)
        required = set(schema["required"])
        properties = set(schema["properties"].keys())
        self.assertTrue(required.issubset(properties))

        trace = _build_trace()
        for key in required:
            self.assertIn(key, trace, f"trace missing schema-required key {key!r}")


class TestMakeTraceId(unittest.TestCase):
    def test_deterministic_for_same_inputs(self) -> None:
        kwargs = {
            "cases_path": str(CASES_DIR),
            "created_at": "2026-07-07T12:00:00Z",
            "systems": ["rules_only", "frontier_direct_mock"],
        }
        self.assertEqual(make_trace_id(**kwargs), make_trace_id(**kwargs))
        self.assertTrue(make_trace_id(**kwargs).startswith("trace_"))


class TestCliTraceOut(unittest.TestCase):
    def test_cli_writes_valid_json_trace_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "latest_trace.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = compare_main([
                    "--cases", str(CASES_DIR),
                    "--gold", str(GOLD_LABELS_PATH),
                    "--systems", "rules_only", "frontier_direct_mock",
                    "--mock-response", str(MOCK_RESPONSE_PATH),
                    "--trace-out", str(trace_path),
                ])
            self.assertEqual(exit_code, 0)
            self.assertTrue(trace_path.is_file())
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            self.assertIn("trace_id", trace)
            self.assertEqual(trace["final_verdict"]["status"], "SMOKE_PASS")
            comparison = json.loads(stdout.getvalue())
            self.assertIn("results", comparison)


if __name__ == "__main__":
    unittest.main()
