"""Tests for admissible.harness.viewer (Slice J visual trace viewer)."""

from __future__ import annotations

import contextlib
import html
import io
import json
import tempfile
import unittest
from pathlib import Path

from admissible.harness.viewer import (
    load_trace,
    main as viewer_main,
    render_trace_html,
    write_trace_html,
)
from admissible.runner.baseline_runner import run_frontier_direct_baseline
from admissible.runner.compare_runner import gather_comparison_data
from admissible.trace import build_run_trace

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
SAMPLE_CASE_PATH = CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"
VIEWER_MODULE_PATH = REPO_ROOT / "admissible" / "harness" / "viewer.py"
VIEWER_INIT_PATH = REPO_ROOT / "admissible" / "harness" / "__init__.py"

_EXACT_CLAIM_BOUNDARY = "Tier 1 enriched seed smoke test only; not a benchmark result."


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


class TestLoadTrace(unittest.TestCase):
    def test_loads_a_valid_json_trace(self) -> None:
        trace = _build_trace()
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "trace.json"
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            loaded = load_trace(trace_path)
        self.assertEqual(loaded["trace_id"], trace["trace_id"])
        self.assertIsInstance(loaded, dict)

    def test_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "bad.json"
            bad_path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_trace(bad_path)

    def test_rejects_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            list_path = Path(tmpdir) / "list.json"
            list_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_trace(list_path)

    def test_rejects_json_missing_required_top_level_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            incomplete_path = Path(tmpdir) / "incomplete.json"
            incomplete_path.write_text(json.dumps({"trace_id": "x"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_trace(incomplete_path)


class TestRenderTraceHtml(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = _build_trace()
        self.html = render_trace_html(self.trace)

    def test_returns_a_string(self) -> None:
        self.assertIsInstance(self.html, str)

    def test_contains_claim_boundary(self) -> None:
        self.assertIn(_EXACT_CLAIM_BOUNDARY, self.html)
        self.assertEqual(self.trace["claim_boundary"], _EXACT_CLAIM_BOUNDARY)

    def test_contains_final_verdict_status(self) -> None:
        self.assertIn(self.trace["final_verdict"]["status"], self.html)

    def test_contains_system_names(self) -> None:
        for descriptor in self.trace["systems"]:
            self.assertIn(descriptor["system_id"], self.html)
            self.assertIn(descriptor["system_type"], self.html)

    def test_contains_aggregate_metrics(self) -> None:
        for label in (
            "Label accuracy",
            "Safe throughput",
            "Overblock",
            "Missing escalation",
            "Missing evidence",
            "False allow",
        ):
            self.assertIn(label, self.html)

    def test_contains_at_least_one_benchmark_case_id(self) -> None:
        first_case_id = self.trace["case_traces"][0]["benchmark_case_id"]
        self.assertIn(first_case_id, self.html)

    def test_contains_gold_decision_labels(self) -> None:
        gold_labels = {
            case_trace["gold_annotation"]["gold_decision"]
            for case_trace in self.trace["case_traces"]
            if case_trace.get("gold_annotation")
        }
        self.assertTrue(gold_labels)
        for label in gold_labels:
            self.assertIn(label, self.html)

    def test_escapes_unsafe_html_in_trace_derived_fields(self) -> None:
        unsafe_trace = json.loads(json.dumps(self.trace))
        unsafe_trace["case_traces"][0]["envelope"]["user_request"]["raw"] = (
            "<script>alert('xss')</script>"
        )
        rendered = render_trace_html(unsafe_trace)
        self.assertNotIn("<script>alert('xss')</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)


class TestWriteTraceHtml(unittest.TestCase):
    def test_writes_a_file(self) -> None:
        trace = _build_trace()
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "trace.json"
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            out_path = Path(tmpdir) / "trace.html"

            result_path = write_trace_html(trace_path, out_path)

            self.assertEqual(result_path, out_path)
            self.assertTrue(out_path.is_file())
            content = out_path.read_text(encoding="utf-8")
            self.assertIn(trace["trace_id"], content)

    def test_does_not_mutate_source_trace_file(self) -> None:
        trace = _build_trace()
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "trace.json"
            original_text = json.dumps(trace, indent=2, sort_keys=True)
            trace_path.write_text(original_text, encoding="utf-8")
            out_path = Path(tmpdir) / "trace.html"

            write_trace_html(trace_path, out_path)

            self.assertEqual(trace_path.read_text(encoding="utf-8"), original_text)


class TestCli(unittest.TestCase):
    def test_cli_writes_html_file_from_generated_trace(self) -> None:
        trace = _build_trace()
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "trace.json"
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            out_path = Path(tmpdir) / "trace.html"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = viewer_main(
                    ["--trace", str(trace_path), "--out", str(out_path)]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue(out_path.is_file())
            self.assertIn(str(out_path), stdout.getvalue())


class TestNoNetworkDependencies(unittest.TestCase):
    def test_viewer_source_does_not_import_network_modules(self) -> None:
        source = VIEWER_MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "urllib.request",
            "urllib3",
            "http.client",
            "import socket",
        ):
            self.assertNotIn(forbidden, source)

    def test_viewer_html_template_has_no_external_assets(self) -> None:
        template = (VIEWER_MODULE_PATH.parent / "viewer.html").read_text(encoding="utf-8")
        for forbidden in ("http://", "https://", "<script"):
            self.assertNotIn(forbidden, template)


class TestProviderOutputViewerCleanup(unittest.TestCase):
    def _build_trace_with_sanitized_frontier_decision(self) -> dict:
        import json as json_mod

        mock_response_text = MOCK_RESPONSE_PATH.read_text(encoding="utf-8")
        clean_json = json_mod.dumps(json_mod.loads(mock_response_text))
        note = "(Note: The assistant output is final.)"
        dirty_response = clean_json + "\x00\x00\n" + note

        class DirtyMockClient:
            def complete(self, prompt: str) -> str:
                return dirty_response

        envelope = json_mod.loads(SAMPLE_CASE_PATH.read_text(encoding="utf-8"))
        frontier_decision = run_frontier_direct_baseline(
            envelope,
            model_client=DirtyMockClient(),
            system_id="frontier_direct_mock_v0",
        )

        trace = _build_trace()
        for case_trace in trace["case_traces"]:
            if case_trace.get("envelope", {}).get("envelope_id") == envelope.get("envelope_id"):
                case_trace["decisions"]["frontier_direct_mock_v0"] = frontier_decision
                break
        return trace

    def test_viewer_does_not_render_nul_padding_or_provider_note_spam(self) -> None:
        trace = self._build_trace_with_sanitized_frontier_decision()
        html = render_trace_html(trace)
        self.assertNotIn("\x00", html)
        self.assertNotIn("\\u0000", html)
        self.assertNotIn("(Note: The assistant output is final.)" * 2, html)
        self.assertIn("Provider output sanitized", html)
        self.assertIn("Provider response (parsed JSON)", html)

    def test_viewer_shows_clean_parsed_json_without_trailing_garbage(self) -> None:
        trace = self._build_trace_with_sanitized_frontier_decision()
        rendered_html = render_trace_html(trace)
        clean_json = json.dumps(json.loads(MOCK_RESPONSE_PATH.read_text(encoding="utf-8")))
        self.assertIn(html.escape(clean_json[:40]), rendered_html)


class TestNoAgentOsImport(unittest.TestCase):
    """Docstrings may name agent_os to document the boundary (see
    admissible.decision), but neither file may import from it."""

    def _assert_no_agent_os_import(self, path: Path) -> None:
        source = path.read_text(encoding="utf-8")
        for forbidden in ("import agent_os", "from agent_os"):
            self.assertNotIn(forbidden, source)

    def test_viewer_module_does_not_import_agent_os(self) -> None:
        self._assert_no_agent_os_import(VIEWER_MODULE_PATH)

    def test_viewer_init_does_not_import_agent_os(self) -> None:
        self._assert_no_agent_os_import(VIEWER_INIT_PATH)


if __name__ == "__main__":
    unittest.main()
