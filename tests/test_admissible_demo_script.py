"""Tests for the Slice M demo script (benchmark/reports/demo-script.*)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_SCRIPT_JSON_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-script.json"
DEMO_SCRIPT_MD_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-script.md"
DEMO_PACK_JSON_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-pack.json"

_EXACT_CLAIM_BOUNDARY = "Narrative guide for curated Tier 1 demo trace; not a benchmark result."

_PROHIBITED_PHRASES = (
    "beats frontier models",
    "proves safety",
    "production-ready",
)


def _load_demo_script() -> dict:
    with DEMO_SCRIPT_JSON_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_demo_pack() -> dict:
    with DEMO_PACK_JSON_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_markdown() -> str:
    return DEMO_SCRIPT_MD_PATH.read_text(encoding="utf-8")


def _unsafe_benchmark_result_occurrences(text: str) -> list[str]:
    """Return excerpts around any 'benchmark result' not preceded by 'not a '."""
    lower = text.lower()
    violations: list[str] = []
    start = 0
    needle = "benchmark result"
    while True:
        idx = lower.find(needle, start)
        if idx == -1:
            break
        preceding = lower[max(0, idx - 6):idx]
        if preceding != "not a ":
            violations.append(text[max(0, idx - 30):idx + len(needle) + 10])
        start = idx + len(needle)
    return violations


class TestDemoScriptJsonIsValid(unittest.TestCase):
    def test_demo_script_json_is_valid_json(self) -> None:
        demo_script = _load_demo_script()
        self.assertIsInstance(demo_script, dict)


class TestJsonClaimBoundary(unittest.TestCase):
    def test_json_claim_boundary_is_exact(self) -> None:
        demo_script = _load_demo_script()
        self.assertEqual(demo_script.get("claim_boundary"), _EXACT_CLAIM_BOUNDARY)


class TestMarkdownClaimBoundary(unittest.TestCase):
    def test_markdown_contains_claim_boundary(self) -> None:
        self.assertIn(_EXACT_CLAIM_BOUNDARY, _load_markdown())


class TestJsonReferencesSources(unittest.TestCase):
    def test_json_references_demo_pack(self) -> None:
        demo_script = _load_demo_script()
        self.assertIn("demo-pack.json", demo_script.get("source_demo_pack", ""))

    def test_json_references_demo_trace_json(self) -> None:
        demo_script = _load_demo_script()
        self.assertIn("demo_trace.json", demo_script.get("source_trace", ""))

    def test_json_references_demo_trace_html(self) -> None:
        demo_script = _load_demo_script()
        self.assertIn("demo_trace.html", demo_script.get("source_viewer", ""))


class TestSequenceMatchesDemoPack(unittest.TestCase):
    def test_sequence_contains_exactly_the_selected_cases(self) -> None:
        demo_script = _load_demo_script()
        demo_pack = _load_demo_pack()
        sequence_ids = {step["benchmark_case_id"] for step in demo_script["sequence"]}
        selected_ids = {case["benchmark_case_id"] for case in demo_pack["selected_cases"]}
        self.assertEqual(sequence_ids, selected_ids)

    def test_sequence_preserves_demo_pack_order(self) -> None:
        demo_script = _load_demo_script()
        demo_pack = _load_demo_pack()
        sequence_ids = [step["benchmark_case_id"] for step in demo_script["sequence"]]
        selected_ids = [case["benchmark_case_id"] for case in demo_pack["selected_cases"]]
        self.assertEqual(sequence_ids, selected_ids)


class TestSequenceStepFieldsNonEmpty(unittest.TestCase):
    def test_every_step_has_non_empty_spoken_script(self) -> None:
        demo_script = _load_demo_script()
        for step in demo_script["sequence"]:
            self.assertTrue(step["spoken_script"].strip())

    def test_every_step_has_non_empty_viewer_action(self) -> None:
        demo_script = _load_demo_script()
        for step in demo_script["sequence"]:
            self.assertTrue(step["viewer_action"].strip())

    def test_every_step_has_non_empty_point_illustrated(self) -> None:
        demo_script = _load_demo_script()
        for step in demo_script["sequence"]:
            self.assertTrue(step["point_illustrated"].strip())

    def test_every_step_has_non_empty_expected_takeaway(self) -> None:
        demo_script = _load_demo_script()
        for step in demo_script["sequence"]:
            self.assertTrue(step["expected_takeaway"].strip())


class TestMarkdownContainsCaseIds(unittest.TestCase):
    def test_markdown_contains_all_selected_benchmark_case_ids(self) -> None:
        demo_pack = _load_demo_pack()
        markdown = _load_markdown()
        for case in demo_pack["selected_cases"]:
            self.assertIn(case["benchmark_case_id"], markdown)


class TestMarkdownDisclaimers(unittest.TestCase):
    def setUp(self) -> None:
        self.markdown_lower = _load_markdown().lower()

    def test_markdown_states_frontier_baseline_is_mock_not_live(self) -> None:
        self.assertIn("mock", self.markdown_lower)
        self.assertIn("not a live frontier model", self.markdown_lower)

    def test_markdown_states_not_a_benchmark_result(self) -> None:
        self.assertIn("not a benchmark result", self.markdown_lower)

    def test_markdown_states_rules_only_is_tier_1_enriched_only(self) -> None:
        self.assertIn("tier 1 enriched envelopes", self.markdown_lower)


class TestMarkdownProhibitedClaims(unittest.TestCase):
    def test_markdown_does_not_contain_hype_phrases(self) -> None:
        markdown_lower = _load_markdown().lower()
        for phrase in _PROHIBITED_PHRASES:
            self.assertNotIn(phrase, markdown_lower)

    def test_benchmark_result_only_appears_in_explicit_denial_phrasing(self) -> None:
        violations = _unsafe_benchmark_result_occurrences(_load_markdown())
        self.assertEqual(violations, [])


class TestMarkdownSections(unittest.TestCase):
    def test_markdown_includes_if_challenged_section(self) -> None:
        self.assertIn("## If challenged", _load_markdown())

    def test_markdown_includes_next_steps_section(self) -> None:
        self.assertIn("## Next steps", _load_markdown())


if __name__ == "__main__":
    unittest.main()
