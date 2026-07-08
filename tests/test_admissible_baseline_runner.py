"""Tests for admissible.runner.baseline_runner (Slice G frontier-direct baseline)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import unittest
from pathlib import Path

from admissible.runner.baseline_runner import (
    CANONICAL_LABELS,
    build_frontier_direct_prompt,
    main,
    parse_frontier_response,
    run_frontier_direct_baseline,
)
from benchmark.scoring.score_decisions import load_gold_annotations, score_case

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "benchmark" / "schemas"
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
SAMPLE_CASE_PATH = CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _decision_output_schema() -> dict:
    return _load_json(SCHEMAS_DIR / "decision_output.schema.json")


class FakeModelClient:
    """Deterministic stand-in for a real model client. No network access."""

    def __init__(self, response: str):
        self.response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.response


VALID_RESPONSE_JSON = json.dumps({
    "decision": "REQUIRE_HUMAN_APPROVAL",
    "risk_level": "high",
    "reasons": [
        {"dimension": "authority", "summary": "No confirmed approval on record.", "severity": "high"}
    ],
    "missing_evidence": ["finance_approval"],
    "required_approval": "finance",
    "safer_next_step": {
        "description": "Draft only; request finance approval before sending.",
        "limits": ["draft_only"],
        "requires_human": True,
    },
    "confidence": 0.75,
})


class TestBuildFrontierDirectPrompt(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = _load_json(SAMPLE_CASE_PATH)

    def test_prompt_includes_action_envelope_json(self) -> None:
        prompt = build_frontier_direct_prompt(self.envelope)
        self.assertIn(self.envelope["envelope_id"], prompt)
        # The prompt template itself has an illustrative ```json format
        # block; the real envelope is appended as the *last* fenced block.
        fence_start = prompt.rindex("```json") + len("```json")
        fence_end = prompt.index("```", fence_start)
        embedded = json.loads(prompt[fence_start:fence_end])
        self.assertEqual(embedded, self.envelope)

    def test_prompt_includes_all_five_decision_labels(self) -> None:
        prompt = build_frontier_direct_prompt(self.envelope)
        for label in CANONICAL_LABELS:
            self.assertIn(label, prompt)

    def test_prompt_does_not_include_gold_annotation_fields(self) -> None:
        prompt = build_frontier_direct_prompt(self.envelope)
        for leaky_field in ("gold_decision", "rubric", "correct_label", "gold_safer_next_step", "gold_risk_level"):
            self.assertNotIn(leaky_field, prompt)

    def test_prompt_does_not_mention_rules_only_evaluator(self) -> None:
        prompt = build_frontier_direct_prompt(self.envelope)
        self.assertNotIn("rules_only", prompt)


class TestFakeModelClientCalledOnce(unittest.TestCase):
    def test_fake_client_called_exactly_once(self) -> None:
        envelope = _load_json(SAMPLE_CASE_PATH)
        client = FakeModelClient(VALID_RESPONSE_JSON)
        run_frontier_direct_baseline(envelope, model_client=client)
        self.assertEqual(len(client.prompts), 1)


class TestParseFrontierResponse(unittest.TestCase):
    def test_accepts_valid_json_response(self) -> None:
        result = parse_frontier_response(VALID_RESPONSE_JSON, envelope_id="env_x", system_id="sys_x")
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")
        self.assertEqual(result["envelope_id"], "env_x")
        self.assertEqual(result["system_id"], "sys_x")
        self.assertEqual(result["required_approval"], "finance")
        self.assertEqual(result["missing_evidence"], ["finance_approval"])
        self.assertAlmostEqual(result["confidence"], 0.75)

    def test_accepts_fenced_markdown_json_block(self) -> None:
        fenced = f"```json\n{VALID_RESPONSE_JSON}\n```"
        result = parse_frontier_response(fenced, envelope_id="env_x", system_id="sys_x")
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")

    def test_accepts_text_containing_one_json_object(self) -> None:
        wrapped = f"Here is my decision:\n{VALID_RESPONSE_JSON}\nThanks."
        result = parse_frontier_response(wrapped, envelope_id="env_x", system_id="sys_x")
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")

    def test_rejects_non_json_response(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            parse_frontier_response("this is not json at all", envelope_id="env_x", system_id="sys_x")
        message = str(ctx.exception)
        self.assertIn("envelope_id=", message)
        self.assertIn("system_id=", message)
        self.assertIn("response_length=", message)
        self.assertIn("first_preview=", message)
        self.assertIn("last_preview=", message)

    def test_error_diagnostics_include_context_and_exclude_secrets(self) -> None:
        secret = "hf_super-secret-token-do-not-leak"
        long_garbage = "x" * 500 + secret + "y" * 500
        with self.assertRaises(ValueError) as ctx:
            parse_frontier_response(long_garbage, envelope_id="env_x", system_id="sys_x")
        message = str(ctx.exception)
        self.assertIn("envelope_id='env_x'", message)
        self.assertIn("system_id='sys_x'", message)
        self.assertIn("response_length=", message)
        self.assertIn("first_preview=", message)
        self.assertIn("last_preview=", message)
        self.assertNotIn(secret, message)

    def test_rejects_non_object_json_response(self) -> None:
        with self.assertRaises(ValueError):
            parse_frontier_response('["ALLOW"]', envelope_id="env_x", system_id="sys_x")

    def test_rejects_unknown_decision_label(self) -> None:
        bad = json.dumps({"decision": "MAYBE_ALLOW"})
        with self.assertRaises(ValueError):
            parse_frontier_response(bad, envelope_id="env_x", system_id="sys_x")

    def test_rejects_missing_decision(self) -> None:
        bad = json.dumps({"risk_level": "low"})
        with self.assertRaises(ValueError):
            parse_frontier_response(bad, envelope_id="env_x", system_id="sys_x")

    def test_rejects_empty_decision(self) -> None:
        bad = json.dumps({"decision": ""})
        with self.assertRaises(ValueError):
            parse_frontier_response(bad, envelope_id="env_x", system_id="sys_x")

    def test_does_not_silently_coerce_unknown_label(self) -> None:
        for bad_label in ("allow", "Allow", "MAYBE", "BLOCK"):
            bad = json.dumps({"decision": bad_label})
            with self.assertRaises(ValueError):
                parse_frontier_response(bad, envelope_id="env_x", system_id="sys_x")

    def test_normalizes_missing_optional_fields_to_schema_defaults(self) -> None:
        minimal = json.dumps({"decision": "ALLOW"})
        result = parse_frontier_response(minimal, envelope_id="env_x", system_id="sys_x")
        self.assertEqual(result["risk_level"], "unknown")
        self.assertEqual(result["required_approval"], "unknown")
        self.assertEqual(result["missing_evidence"], [])
        self.assertIsNone(result["safer_next_step"])
        self.assertIsNone(result["confidence"])
        self.assertEqual(len(result["reasons"]), 1)

    def test_invalid_confidence_normalized_to_none(self) -> None:
        bad_confidence = json.dumps({"decision": "ALLOW", "confidence": 1.5})
        result = parse_frontier_response(bad_confidence, envelope_id="env_x", system_id="sys_x")
        self.assertIsNone(result["confidence"])

    def test_preserves_model_reasons_where_possible(self) -> None:
        result = parse_frontier_response(VALID_RESPONSE_JSON, envelope_id="env_x", system_id="sys_x")
        self.assertEqual(result["reasons"][0]["summary"], "No confirmed approval on record.")
        self.assertEqual(result["reasons"][0]["dimension"], "authority")
        self.assertEqual(result["reasons"][0]["severity"], "high")


class TestRunFrontierDirectBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = _load_json(SAMPLE_CASE_PATH)
        self.schema = _decision_output_schema()

    def test_returns_a_dict(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client)
        self.assertIsInstance(result, dict)

    def test_output_includes_all_required_schema_fields(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client)
        for field in self.schema["required"]:
            self.assertIn(field, result)

    def test_output_has_no_keys_outside_schema_properties(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client)
        allowed_keys = set(self.schema["properties"].keys())
        extra_keys = set(result.keys()) - allowed_keys
        self.assertEqual(extra_keys, set())

    def test_preserves_envelope_id(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client)
        self.assertEqual(result["envelope_id"], self.envelope["envelope_id"])

    def test_uses_provided_system_id(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client, system_id="my_custom_baseline")
        self.assertEqual(result["system_id"], "my_custom_baseline")

    def test_default_system_id(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client)
        self.assertEqual(result["system_id"], "frontier_direct_baseline_v0")

    def test_decision_is_one_of_five_canonical_labels(self) -> None:
        client = FakeModelClient(VALID_RESPONSE_JSON)
        result = run_frontier_direct_baseline(self.envelope, model_client=client)
        self.assertIn(result["decision"], set(CANONICAL_LABELS))

    def test_does_not_mutate_input_envelope(self) -> None:
        before = copy.deepcopy(self.envelope)
        client = FakeModelClient(VALID_RESPONSE_JSON)
        run_frontier_direct_baseline(self.envelope, model_client=client)
        self.assertEqual(self.envelope, before)

    def test_raises_value_error_when_model_returns_garbage(self) -> None:
        client = FakeModelClient("not json")
        with self.assertRaises(ValueError):
            run_frontier_direct_baseline(self.envelope, model_client=client)


class TestAllTier1SeedCasesRunCleanly(unittest.TestCase):
    def test_all_25_envelopes_run_through_baseline_with_fake_client(self) -> None:
        schema = _decision_output_schema()
        required_keys = set(schema["required"])
        envelope_paths = sorted(CASES_DIR.glob("**/*.envelope.json"))
        self.assertEqual(len(envelope_paths), 25)
        for path in envelope_paths:
            envelope = _load_json(path)
            client = FakeModelClient(VALID_RESPONSE_JSON)
            with self.subTest(envelope_id=envelope["envelope_id"]):
                result = run_frontier_direct_baseline(envelope, model_client=client)
                self.assertEqual(required_keys - set(result.keys()), set())
                self.assertEqual(result["envelope_id"], envelope["envelope_id"])


class TestCliMockResponsePath(unittest.TestCase):
    def test_cli_prints_valid_decision_output_json(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main([
                "--case", str(SAMPLE_CASE_PATH),
                "--mock-response", str(MOCK_RESPONSE_PATH),
            ])
        self.assertEqual(exit_code, 0)
        result = json.loads(stdout.getvalue())

        schema = _decision_output_schema()
        for field in schema["required"]:
            self.assertIn(field, result)
        self.assertIn(result["decision"], set(CANONICAL_LABELS))

        envelope = _load_json(SAMPLE_CASE_PATH)
        self.assertEqual(result["envelope_id"], envelope["envelope_id"])
        self.assertEqual(result["system_id"], "frontier_direct_baseline_v0")

    def test_cli_respects_custom_system_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            main([
                "--case", str(SAMPLE_CASE_PATH),
                "--mock-response", str(MOCK_RESPONSE_PATH),
                "--system-id", "cli_test_system",
            ])
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["system_id"], "cli_test_system")


class TestIntegrationSmokeWithScoring(unittest.TestCase):
    """Internal smoke only: baseline output flows into score_case without crashing.

    This does not measure or claim baseline performance; it only checks
    that run_frontier_direct_baseline's output is shape-compatible with
    benchmark.scoring.score_decisions.score_case.
    """

    def test_baseline_decision_scores_cleanly_against_gold(self) -> None:
        envelope = _load_json(SAMPLE_CASE_PATH)
        gold_by_envelope_id = load_gold_annotations(GOLD_LABELS_PATH)
        gold = gold_by_envelope_id[envelope["envelope_id"]]

        client = FakeModelClient(VALID_RESPONSE_JSON)
        decision = run_frontier_direct_baseline(envelope, model_client=client)

        result = score_case(decision, gold)
        self.assertIn("correct", result)
        self.assertIsInstance(result["correct"], bool)
        self.assertEqual(result["predicted_label"], decision["decision"])
        self.assertEqual(result["gold_label"], gold["gold_decision"])


if __name__ == "__main__":
    unittest.main()
