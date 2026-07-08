"""Tests for admissible.harness.clean_trace (offline trace sanitization)."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import html
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible.harness.clean_trace import (
    clean_trace,
    main as clean_trace_main,
    sanitize_provider_metadata,
    write_cleaned_trace,
)
from admissible.harness.viewer import render_trace_html
from admissible.runner.baseline_runner import run_frontier_direct_baseline
from admissible.runner.compare_runner import gather_comparison_data
from admissible.trace import build_run_trace

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
SAMPLE_CASE_PATH = CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"
CLEAN_TRACE_MODULE_PATH = REPO_ROOT / "admissible" / "harness" / "clean_trace.py"
HF_DEMO_TRACE_PATH = REPO_ROOT / "benchmark" / "reports" / "hf_demo_trace.json"

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

_PROVIDER_METADATA_KEYS = (
    "raw_provider_response_text",
    "provider_output_sanitized",
    "provider_output_original_length",
    "provider_output_clean_length",
    "provider_output_trailing_text_preview",
    "provider_output_sha256",
)


def _build_trace() -> dict:
    comparison, envelopes, gold_by_envelope_id, decisions_by_system = gather_comparison_data(
        CASES_DIR,
        GOLD_LABELS_PATH,
        ["rules_only", "frontier_direct_mock"],
        mock_response_path=MOCK_RESPONSE_PATH,
    )
    return build_run_trace(
        cases_path=CASES_DIR,
        gold_path=GOLD_LABELS_PATH,
        systems=["rules_only", "frontier_direct_mock"],
        comparison=comparison,
        envelopes=envelopes,
        gold_by_envelope_id=gold_by_envelope_id,
        decisions_by_system=decisions_by_system,
    )


def _decision_without_provider_metadata(decision: dict) -> dict:
    stripped = copy.deepcopy(decision)
    metadata = stripped.get("metadata")
    if isinstance(metadata, dict):
        for key in _PROVIDER_METADATA_KEYS:
            metadata.pop(key, None)
    return stripped


def _inject_dirty_provider_text(trace: dict, dirty_text: str, system_id: str = "frontier_direct_mock_v0") -> dict:
    dirty_trace = copy.deepcopy(trace)
    for case_trace in dirty_trace["case_traces"]:
        decision = case_trace["decisions"].get(system_id)
        if decision is None:
            continue
        metadata = decision.setdefault("metadata", {})
        metadata["raw_provider_response_text"] = dirty_text
        break
    return dirty_trace


class TestSanitizeProviderMetadata(unittest.TestCase):
    def test_nul_padding_is_cleaned(self) -> None:
        dirty = VALID_RESPONSE_JSON + "\x00\x00\n\x00"
        metadata = {"raw_provider_response_text": dirty}
        cleaned = sanitize_provider_metadata(metadata)
        self.assertEqual(cleaned["raw_provider_response_text"], VALID_RESPONSE_JSON)
        self.assertNotIn("\x00", cleaned["raw_provider_response_text"])
        self.assertTrue(cleaned["provider_output_sanitized"])

    def test_provider_note_spam_is_cleaned(self) -> None:
        note = "(Note: The assistant output is final.)"
        dirty = VALID_RESPONSE_JSON + "\n" + note
        metadata = {"raw_provider_response_text": dirty}
        cleaned = sanitize_provider_metadata(metadata)
        self.assertEqual(cleaned["raw_provider_response_text"], VALID_RESPONSE_JSON)
        self.assertTrue(cleaned["provider_output_sanitized"])
        self.assertIn(note, cleaned["provider_output_trailing_text_preview"])

    def test_clean_json_adds_sha256_without_changing_text(self) -> None:
        metadata = {"raw_provider_response_text": VALID_RESPONSE_JSON}
        cleaned = sanitize_provider_metadata(metadata)
        self.assertEqual(cleaned["raw_provider_response_text"], VALID_RESPONSE_JSON)
        self.assertFalse(cleaned["provider_output_sanitized"])
        expected = hashlib.sha256(VALID_RESPONSE_JSON.encode("utf-8")).hexdigest()
        self.assertEqual(cleaned["provider_output_sha256"], expected)


class TestCleanTrace(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = _build_trace()

    def test_dirty_trace_with_nul_padding_is_cleaned(self) -> None:
        dirty_trace = _inject_dirty_provider_text(
            self.trace,
            VALID_RESPONSE_JSON + "\x00" * 50,
        )
        cleaned = clean_trace(dirty_trace)
        metadata = cleaned["case_traces"][0]["decisions"]["frontier_direct_mock_v0"]["metadata"]
        self.assertEqual(metadata["raw_provider_response_text"], VALID_RESPONSE_JSON)
        self.assertTrue(metadata["provider_output_sanitized"])

    def test_dirty_trace_with_provider_note_spam_is_cleaned(self) -> None:
        note = "(Note: The assistant output is final.)"
        dirty_trace = _inject_dirty_provider_text(
            self.trace,
            VALID_RESPONSE_JSON + "\n" + note,
        )
        cleaned = clean_trace(dirty_trace)
        metadata = cleaned["case_traces"][0]["decisions"]["frontier_direct_mock_v0"]["metadata"]
        self.assertEqual(metadata["raw_provider_response_text"], VALID_RESPONSE_JSON)
        self.assertIn(note, metadata["provider_output_trailing_text_preview"])

    def test_clean_trace_decisions_unchanged_except_provider_metadata(self) -> None:
        dirty_trace = _inject_dirty_provider_text(
            self.trace,
            VALID_RESPONSE_JSON + "\x00garbage",
        )
        cleaned = clean_trace(dirty_trace)
        for case_trace, dirty_case in zip(cleaned["case_traces"], dirty_trace["case_traces"]):
            for system_id, decision in case_trace["decisions"].items():
                self.assertEqual(
                    _decision_without_provider_metadata(decision),
                    _decision_without_provider_metadata(dirty_case["decisions"][system_id]),
                )

    def test_clean_trace_aggregate_results_unchanged(self) -> None:
        dirty_trace = _inject_dirty_provider_text(
            self.trace,
            VALID_RESPONSE_JSON + "\x00garbage",
        )
        cleaned = clean_trace(dirty_trace)
        self.assertEqual(cleaned["aggregate_results"], dirty_trace["aggregate_results"])

    def test_clean_trace_preserves_trace_id_and_claim_boundary(self) -> None:
        dirty_trace = _inject_dirty_provider_text(
            self.trace,
            VALID_RESPONSE_JSON + "\x00garbage",
        )
        cleaned = clean_trace(dirty_trace)
        self.assertEqual(cleaned["trace_id"], dirty_trace["trace_id"])
        self.assertEqual(cleaned["claim_boundary"], dirty_trace["claim_boundary"])

    def test_clean_trace_does_not_mutate_input(self) -> None:
        dirty_trace = _inject_dirty_provider_text(
            self.trace,
            VALID_RESPONSE_JSON + "\x00garbage",
        )
        before = copy.deepcopy(dirty_trace)
        clean_trace(dirty_trace)
        self.assertEqual(dirty_trace, before)


class TestWriteCleanedTrace(unittest.TestCase):
    def test_writes_json_and_optional_html(self) -> None:
        trace = _build_trace()
        dirty_trace = _inject_dirty_provider_text(trace, VALID_RESPONSE_JSON + "\x00" * 20)
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "dirty.json"
            out_path = Path(tmpdir) / "cleaned.json"
            html_path = Path(tmpdir) / "cleaned.html"
            trace_path.write_text(json.dumps(dirty_trace), encoding="utf-8")

            result_path = write_cleaned_trace(trace_path, out_path, html_out=html_path)
            self.assertEqual(result_path, out_path)
            self.assertTrue(out_path.is_file())
            self.assertTrue(html_path.is_file())

            cleaned = json.loads(out_path.read_text(encoding="utf-8"))
            metadata = cleaned["case_traces"][0]["decisions"]["frontier_direct_mock_v0"]["metadata"]
            self.assertNotIn("\x00", metadata["raw_provider_response_text"])

            rendered = html_path.read_text(encoding="utf-8")
            self.assertNotIn("\x00", rendered)
            self.assertNotIn("\\u0000", rendered)

    def test_cli_writes_outputs(self) -> None:
        trace = _build_trace()
        dirty_trace = _inject_dirty_provider_text(trace, VALID_RESPONSE_JSON + "\x00garbage")
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "dirty.json"
            out_path = Path(tmpdir) / "cleaned.json"
            html_path = Path(tmpdir) / "cleaned.html"
            trace_path.write_text(json.dumps(dirty_trace), encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = clean_trace_main([
                    "--trace", str(trace_path),
                    "--out", str(out_path),
                    "--html-out", str(html_path),
                ])
            self.assertEqual(exit_code, 0)
            self.assertTrue(out_path.is_file())
            self.assertTrue(html_path.is_file())


class TestHtmlDoesNotLeakDirtyProviderOutput(unittest.TestCase):
    def _build_trace_with_dirty_frontier_decision(self) -> dict:
        mock_response_text = MOCK_RESPONSE_PATH.read_text(encoding="utf-8")
        clean_json = json.dumps(json.loads(mock_response_text))
        note = "(Note: The assistant output is final.)"
        dirty_response = clean_json + "\x00\x00\n" + note

        class DirtyMockClient:
            def complete(self, prompt: str) -> str:
                return dirty_response

        envelope = json.loads(SAMPLE_CASE_PATH.read_text(encoding="utf-8"))
        frontier_decision = run_frontier_direct_baseline(
            envelope,
            model_client=DirtyMockClient(),
            system_id="frontier_direct_mock_v0",
        )
        # Simulate a pre-sanitization trace by restoring dirty stored text.
        frontier_decision["metadata"]["raw_provider_response_text"] = dirty_response
        for key in _PROVIDER_METADATA_KEYS:
            if key != "raw_provider_response_text":
                frontier_decision["metadata"].pop(key, None)

        trace = _build_trace()
        for case_trace in trace["case_traces"]:
            if case_trace.get("envelope", {}).get("envelope_id") == envelope.get("envelope_id"):
                case_trace["decisions"]["frontier_direct_mock_v0"] = frontier_decision
                break
        return trace

    def test_generated_html_does_not_include_nul_padding_or_provider_note_spam(self) -> None:
        dirty_trace = self._build_trace_with_dirty_frontier_decision()
        cleaned = clean_trace(dirty_trace)
        rendered = render_trace_html(cleaned)
        self.assertNotIn("\x00", rendered)
        self.assertNotIn("\\u0000", rendered)
        self.assertNotIn("(Note: The assistant output is final.)" * 2, rendered)
        self.assertIn("Provider output sanitized", rendered)
        clean_json = json.dumps(json.loads(MOCK_RESPONSE_PATH.read_text(encoding="utf-8")))
        self.assertIn(html.escape(clean_json[:40]), rendered)


class TestNoNetworkOrAgentOsImports(unittest.TestCase):
    def test_module_source_does_not_import_network_modules(self) -> None:
        source = CLEAN_TRACE_MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "urllib.request",
            "urllib3",
            "http.client",
            "import socket",
        ):
            self.assertNotIn(forbidden, source)

    def test_module_does_not_import_agent_os(self) -> None:
        source = CLEAN_TRACE_MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in ("import agent_os", "from agent_os"):
            self.assertNotIn(forbidden, source)

    @mock.patch("socket.socket")
    def test_clean_trace_makes_no_network_calls(self, mock_socket) -> None:
        trace = _build_trace()
        dirty_trace = _inject_dirty_provider_text(trace, VALID_RESPONSE_JSON + "\x00garbage")
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "dirty.json"
            out_path = Path(tmpdir) / "cleaned.json"
            trace_path.write_text(json.dumps(dirty_trace), encoding="utf-8")
            write_cleaned_trace(trace_path, out_path)
        mock_socket.assert_not_called()


class TestHfDemoTraceCleanup(unittest.TestCase):
    @unittest.skipUnless(HF_DEMO_TRACE_PATH.is_file(), "hf_demo_trace.json not present locally")
    def test_offline_cleanup_of_local_hf_demo_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "hf_demo_trace.cleaned.json"
            html_path = Path(tmpdir) / "hf_demo_trace.cleaned.html"
            write_cleaned_trace(HF_DEMO_TRACE_PATH, out_path, html_out=html_path)

            cleaned = json.loads(out_path.read_text(encoding="utf-8"))
            original = json.loads(HF_DEMO_TRACE_PATH.read_text(encoding="utf-8"))
            self.assertEqual(cleaned["aggregate_results"], original["aggregate_results"])
            self.assertEqual(cleaned["trace_id"], original["trace_id"])

            for case_trace in cleaned["case_traces"]:
                for decision in case_trace.get("decisions", {}).values():
                    metadata = decision.get("metadata", {})
                    raw_text = metadata.get("raw_provider_response_text")
                    if isinstance(raw_text, str):
                        self.assertNotIn("\x00", raw_text)

            rendered = html_path.read_text(encoding="utf-8")
            self.assertNotIn("\x00", rendered)
            self.assertNotIn("\\u0000", rendered)


if __name__ == "__main__":
    unittest.main()
