"""Tests for admissible.runner.demo_trace (Slice L demo trace generation)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible.runner.baseline_runner import build_frontier_direct_prompt
from admissible.runner.demo_trace import (
    DEMO_PACK_CLAIM_BOUNDARY,
    DEMO_TRACE_DISCLAIMER_NOTE,
    DEMO_TRACE_LIVE_DISCLAIMER_NOTE,
    OWNER_CONFIG_REQUIRED_STATUS,
    OwnerConfigRequired,
    build_demo_trace,
    load_demo_envelopes,
    load_demo_pack,
    main,
    write_demo_trace_and_html,
)
from admissible.runner.model_clients import FixedResponseModelClient
from benchmark.scoring.score_decisions import TIER_1_CLAIM_BOUNDARY, load_gold_annotations

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_PACK_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-pack.json"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
DEMO_TRACE_MODULE_PATH = REPO_ROOT / "admissible" / "runner" / "demo_trace.py"

_EXACT_CLAIM_BOUNDARY = "Tier 1 enriched seed smoke test only; not a benchmark result."

VALID_LIVE_RESPONSE = json.dumps({
    "decision": "REQUIRE_HUMAN_APPROVAL",
    "risk_level": "high",
    "reasons": [{"dimension": "authority", "summary": "test", "severity": "high"}],
})


def _write_json(tmpdir: str, name: str, payload: dict) -> Path:
    path = Path(tmpdir) / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestLoadDemoPack(unittest.TestCase):
    def test_loads_valid_demo_pack_json(self) -> None:
        demo_pack = load_demo_pack(DEMO_PACK_PATH)
        self.assertIsInstance(demo_pack, dict)
        self.assertEqual(demo_pack["claim_boundary"], DEMO_PACK_CLAIM_BOUNDARY)
        self.assertGreaterEqual(len(demo_pack["selected_cases"]), 5)

    def test_invalid_json_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "bad.json"
            bad_path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_demo_pack(bad_path)

    def test_missing_claim_boundary_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_json(
                tmpdir,
                "demo-pack.json",
                {
                    "claim_boundary": "wrong boundary",
                    "selected_cases": [{}] * 5,
                },
            )
            with self.assertRaises(ValueError):
                load_demo_pack(path)

    def test_selected_case_count_outside_5_to_8_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            too_few_path = _write_json(
                tmpdir,
                "too_few.json",
                {
                    "claim_boundary": DEMO_PACK_CLAIM_BOUNDARY,
                    "selected_cases": [{}] * 3,
                },
            )
            with self.assertRaises(ValueError):
                load_demo_pack(too_few_path)

            too_many_path = _write_json(
                tmpdir,
                "too_many.json",
                {
                    "claim_boundary": DEMO_PACK_CLAIM_BOUNDARY,
                    "selected_cases": [{}] * 9,
                },
            )
            with self.assertRaises(ValueError):
                load_demo_pack(too_many_path)


class TestLoadDemoEnvelopes(unittest.TestCase):
    def test_case_path_outside_tier_1_enriched_raises_value_error(self) -> None:
        demo_pack = {
            "claim_boundary": DEMO_PACK_CLAIM_BOUNDARY,
            "selected_cases": [
                {
                    "benchmark_case_id": "case_outside_tier",
                    "case_path": "benchmark/cases/other_tier/some_case.envelope.json",
                }
            ],
        }
        with self.assertRaises(ValueError):
            load_demo_envelopes(demo_pack)

    def test_missing_selected_case_file_raises_value_error(self) -> None:
        demo_pack = {
            "claim_boundary": DEMO_PACK_CLAIM_BOUNDARY,
            "selected_cases": [
                {
                    "benchmark_case_id": "case_does_not_exist",
                    "case_path": (
                        "benchmark/cases/tier_1_enriched/customer_communication/"
                        "does_not_exist.envelope.json"
                    ),
                }
            ],
        }
        with self.assertRaises(ValueError):
            load_demo_envelopes(demo_pack)

    def test_loaded_envelopes_count_equals_selected_cases_count(self) -> None:
        demo_pack = load_demo_pack(DEMO_PACK_PATH)
        envelopes = load_demo_envelopes(demo_pack)
        self.assertEqual(len(envelopes), len(demo_pack["selected_cases"]))

    def test_loaded_envelope_ids_match_selected_benchmark_case_ids(self) -> None:
        demo_pack = load_demo_pack(DEMO_PACK_PATH)
        envelopes = load_demo_envelopes(demo_pack)
        for case, envelope in zip(demo_pack["selected_cases"], envelopes):
            self.assertEqual(
                envelope["metadata"]["benchmark_case_id"], case["benchmark_case_id"]
            )


class TestBuildDemoTrace(unittest.TestCase):
    def setUp(self) -> None:
        self.demo_pack = load_demo_pack(DEMO_PACK_PATH)
        self.trace = build_demo_trace(
            demo_pack_path=DEMO_PACK_PATH,
            gold_path=GOLD_LABELS_PATH,
            mock_response_path=MOCK_RESPONSE_PATH,
        )

    def test_returns_a_dict(self) -> None:
        self.assertIsInstance(self.trace, dict)

    def test_contains_exactly_the_selected_cases(self) -> None:
        selected_ids = {case["benchmark_case_id"] for case in self.demo_pack["selected_cases"]}
        traced_ids = {
            case_trace["benchmark_case_id"] for case_trace in self.trace["case_traces"]
        }
        self.assertEqual(traced_ids, selected_ids)
        self.assertEqual(len(self.trace["case_traces"]), len(self.demo_pack["selected_cases"]))

    def test_includes_both_rules_only_and_frontier_direct_mock(self) -> None:
        system_types = {descriptor["system_type"] for descriptor in self.trace["systems"]}
        self.assertIn("rules_only", system_types)
        self.assertIn("frontier_direct_mock", system_types)

    def test_includes_standard_claim_boundary(self) -> None:
        self.assertEqual(self.trace["claim_boundary"], _EXACT_CLAIM_BOUNDARY)
        self.assertEqual(self.trace["claim_boundary"], TIER_1_CLAIM_BOUNDARY)

    def test_includes_mock_baseline_disclaimer_note(self) -> None:
        self.assertIn(DEMO_TRACE_DISCLAIMER_NOTE, self.trace["metadata"]["notes"])

    def test_final_verdict_is_smoke_pass(self) -> None:
        self.assertEqual(self.trace["final_verdict"]["status"], "SMOKE_PASS")

    def test_missing_gold_annotation_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_gold_path = Path(tmpdir) / "empty_gold.jsonl"
            empty_gold_path.write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_demo_trace(
                    demo_pack_path=DEMO_PACK_PATH,
                    gold_path=empty_gold_path,
                    mock_response_path=MOCK_RESPONSE_PATH,
                )


class TestWriteDemoTraceAndHtml(unittest.TestCase):
    def setUp(self) -> None:
        self.demo_pack = load_demo_pack(DEMO_PACK_PATH)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.trace_out = Path(self.tmpdir.name) / "demo_trace.json"
        self.html_out = Path(self.tmpdir.name) / "demo_trace.html"
        self.trace = write_demo_trace_and_html(
            demo_pack_path=DEMO_PACK_PATH,
            gold_path=GOLD_LABELS_PATH,
            mock_response_path=MOCK_RESPONSE_PATH,
            trace_out=self.trace_out,
            html_out=self.html_out,
        )

    def test_writes_both_files(self) -> None:
        self.assertTrue(self.trace_out.is_file())
        self.assertTrue(self.html_out.is_file())
        written_trace = json.loads(self.trace_out.read_text(encoding="utf-8"))
        self.assertEqual(written_trace["trace_id"], self.trace["trace_id"])

    def test_written_html_contains_all_selected_benchmark_case_ids(self) -> None:
        html_content = self.html_out.read_text(encoding="utf-8")
        for case in self.demo_pack["selected_cases"]:
            self.assertIn(case["benchmark_case_id"], html_content)

    def test_written_html_contains_claim_boundary(self) -> None:
        html_content = self.html_out.read_text(encoding="utf-8")
        self.assertIn(_EXACT_CLAIM_BOUNDARY, html_content)


class TestNoLiveModelOrNetworkCode(unittest.TestCase):
    def test_source_does_not_use_live_model_provider_or_network_code(self) -> None:
        source = DEMO_TRACE_MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "urllib.request",
            "urllib3",
            "http.client",
            "import socket",
            "openai",
            "anthropic",
        ):
            self.assertNotIn(forbidden, source)


class TestNoAgentOsImport(unittest.TestCase):
    def test_source_does_not_import_agent_os(self) -> None:
        source = DEMO_TRACE_MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in ("import agent_os", "from agent_os"):
            self.assertNotIn(forbidden, source)


class TestLiveDemoTraceMode(unittest.TestCase):
    def _build_live_trace(self) -> dict:
        fake_client = FixedResponseModelClient(VALID_LIVE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_model_client_from_env",
            return_value=fake_client,
        ):
            return build_demo_trace(
                demo_pack_path=DEMO_PACK_PATH,
                gold_path=GOLD_LABELS_PATH,
                provider="env-http",
            )

    def test_mock_mode_still_works_exactly_as_before(self) -> None:
        trace = build_demo_trace(
            demo_pack_path=DEMO_PACK_PATH,
            gold_path=GOLD_LABELS_PATH,
            mock_response_path=MOCK_RESPONSE_PATH,
        )
        system_types = {descriptor["system_type"] for descriptor in trace["systems"]}
        self.assertEqual(system_types, {"rules_only", "frontier_direct_mock"})
        self.assertIn(DEMO_TRACE_DISCLAIMER_NOTE, trace["metadata"]["notes"])

    def test_live_mode_selects_frontier_direct_live(self) -> None:
        trace = self._build_live_trace()
        system_types = {descriptor["system_type"] for descriptor in trace["systems"]}
        self.assertIn("rules_only", system_types)
        self.assertIn("frontier_direct_live", system_types)
        self.assertNotIn("frontier_direct_mock", system_types)

    def test_live_mode_requires_explicit_provider(self) -> None:
        with self.assertRaises(ValueError):
            build_demo_trace(
                demo_pack_path=DEMO_PACK_PATH,
                gold_path=GOLD_LABELS_PATH,
            )

    def test_mock_response_and_provider_together_fail(self) -> None:
        with self.assertRaises(ValueError):
            build_demo_trace(
                demo_pack_path=DEMO_PACK_PATH,
                gold_path=GOLD_LABELS_PATH,
                mock_response_path=MOCK_RESPONSE_PATH,
                provider="env-http",
            )

    def test_missing_live_env_config_fails_without_leaking_secrets(self) -> None:
        secret_key = "super-secret-demo-key"
        env = {
            "ADMISSIBLE_MODEL_API_URL": "https://example.com/v1/complete",
            "ADMISSIBLE_MODEL_API_KEY": secret_key,
        }
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(OwnerConfigRequired) as ctx:
                build_demo_trace(
                    demo_pack_path=DEMO_PACK_PATH,
                    gold_path=GOLD_LABELS_PATH,
                    provider="env-http",
                )
        message = str(ctx.exception)
        self.assertIn(OWNER_CONFIG_REQUIRED_STATUS, message)
        self.assertNotIn(secret_key, message)

    def test_live_mode_cli_missing_env_reports_owner_config_required(self) -> None:
        secret_key = "super-secret-demo-key"
        env = {
            "ADMISSIBLE_MODEL_API_URL": "https://example.com/v1/complete",
            "ADMISSIBLE_MODEL_API_KEY": secret_key,
        }
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_out = Path(tmpdir) / "live_demo_trace.json"
            html_out = Path(tmpdir) / "live_demo_trace.html"
            with mock.patch.dict(os.environ, env, clear=True):
                with contextlib.redirect_stderr(stderr):
                    exit_code = main([
                        "--demo-pack", str(DEMO_PACK_PATH),
                        "--gold", str(GOLD_LABELS_PATH),
                        "--provider", "env-http",
                        "--trace-out", str(trace_out),
                        "--html-out", str(html_out),
                    ])
        self.assertEqual(exit_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], OWNER_CONFIG_REQUIRED_STATUS)
        self.assertNotIn(secret_key, stderr.getvalue())

    def test_live_mode_trace_includes_claim_boundary(self) -> None:
        trace = self._build_live_trace()
        self.assertEqual(trace["claim_boundary"], _EXACT_CLAIM_BOUNDARY)
        self.assertEqual(trace["claim_boundary"], TIER_1_CLAIM_BOUNDARY)

    def test_live_mode_trace_includes_live_provider_disclaimer_note(self) -> None:
        trace = self._build_live_trace()
        self.assertIn(DEMO_TRACE_LIVE_DISCLAIMER_NOTE, trace["metadata"]["notes"])

    def test_live_mode_output_is_json_serializable(self) -> None:
        trace = self._build_live_trace()
        serialized = json.dumps(trace)
        self.assertIsInstance(json.loads(serialized), dict)

    def test_live_prompts_do_not_contain_gold_annotations(self) -> None:
        demo_pack = load_demo_pack(DEMO_PACK_PATH)
        envelopes = load_demo_envelopes(demo_pack)[:3]
        gold_by_envelope_id = load_gold_annotations(GOLD_LABELS_PATH)
        fake_client = FixedResponseModelClient(VALID_LIVE_RESPONSE)

        with mock.patch(
            "admissible.runner.compare_runner.build_model_client_from_env",
            return_value=fake_client,
        ):
            with mock.patch(
                "admissible.runner.demo_trace.load_demo_envelopes",
                return_value=envelopes,
            ):
                build_demo_trace(
                    demo_pack_path=DEMO_PACK_PATH,
                    gold_path=GOLD_LABELS_PATH,
                    provider="env-http",
                )

        self.assertEqual(len(fake_client.prompts), len(envelopes))
        for envelope, prompt in zip(envelopes, fake_client.prompts):
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

    def test_live_prompts_do_not_contain_rules_only_outputs(self) -> None:
        demo_pack = load_demo_pack(DEMO_PACK_PATH)
        envelopes = load_demo_envelopes(demo_pack)[:2]
        fake_client = FixedResponseModelClient(VALID_LIVE_RESPONSE)

        with mock.patch(
            "admissible.runner.compare_runner.build_model_client_from_env",
            return_value=fake_client,
        ):
            with mock.patch(
                "admissible.runner.demo_trace.load_demo_envelopes",
                return_value=envelopes,
            ):
                build_demo_trace(
                    demo_pack_path=DEMO_PACK_PATH,
                    gold_path=GOLD_LABELS_PATH,
                    provider="env-http",
                )

        for envelope, prompt in zip(envelopes, fake_client.prompts):
            self.assertNotIn("rules_only", prompt)
            self.assertEqual(prompt, build_frontier_direct_prompt(envelope))


if __name__ == "__main__":
    unittest.main()
