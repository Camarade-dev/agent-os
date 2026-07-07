"""Tests for the Slice K demo scenario pack (benchmark/reports/demo-pack.*)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
DEMO_PACK_JSON_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-pack.json"
DEMO_PACK_MD_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-pack.md"

_EXACT_CLAIM_BOUNDARY = "Curated Tier 1 enriched demo pack; not a benchmark result."


def _load_demo_pack() -> dict:
    with DEMO_PACK_JSON_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_seed_case_ids() -> set:
    case_ids = set()
    for envelope_path in CASES_DIR.glob("**/*.envelope.json"):
        with envelope_path.open(encoding="utf-8") as handle:
            envelope = json.load(handle)
        case_ids.add(envelope["metadata"]["benchmark_case_id"])
    return case_ids


def _load_gold_by_case_id() -> dict:
    gold_by_case_id = {}
    with GOLD_LABELS_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            gold_by_case_id[record["benchmark_case_id"]] = record
    return gold_by_case_id


class TestDemoPackJsonIsValid(unittest.TestCase):
    def test_demo_pack_json_is_valid_json(self) -> None:
        demo_pack = _load_demo_pack()
        self.assertIsInstance(demo_pack, dict)


class TestClaimBoundary(unittest.TestCase):
    def test_claim_boundary_present_and_exact(self) -> None:
        demo_pack = _load_demo_pack()
        self.assertEqual(demo_pack.get("claim_boundary"), _EXACT_CLAIM_BOUNDARY)


class TestSelectedCaseCount(unittest.TestCase):
    def test_selects_between_5_and_8_cases(self) -> None:
        demo_pack = _load_demo_pack()
        selected_cases = demo_pack["selected_cases"]
        self.assertGreaterEqual(len(selected_cases), 5)
        self.assertLessEqual(len(selected_cases), 8)


class TestSelectedCasesExistInSeedSet(unittest.TestCase):
    def test_every_benchmark_case_id_exists_in_25_seed_envelopes(self) -> None:
        seed_case_ids = _load_seed_case_ids()
        self.assertEqual(len(seed_case_ids), 25)
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertIn(case["benchmark_case_id"], seed_case_ids)


class TestSelectedCasesHaveGoldAnnotations(unittest.TestCase):
    def test_every_selected_case_has_matching_gold_annotation(self) -> None:
        gold_by_case_id = _load_gold_by_case_id()
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertIn(case["benchmark_case_id"], gold_by_case_id)

    def test_every_selected_gold_decision_matches_gold_annotation(self) -> None:
        gold_by_case_id = _load_gold_by_case_id()
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            gold_record = gold_by_case_id[case["benchmark_case_id"]]
            self.assertEqual(case["gold_decision"], gold_record["gold_decision"])


class TestCasePathsStayWithinTier1Enriched(unittest.TestCase):
    def test_no_selected_case_path_points_outside_tier_1_enriched(self) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            case_path = case["case_path"]
            self.assertTrue(
                case_path.replace("\\", "/").startswith(
                    "benchmark/cases/tier_1_enriched/"
                )
            )
            self.assertNotIn("..", case_path)
            resolved = (REPO_ROOT / case_path).resolve()
            self.assertTrue(resolved.is_file())
            self.assertIn(CASES_DIR.resolve(), resolved.parents)


class TestSelectedCaseNarrativeFieldsNonEmpty(unittest.TestCase):
    def test_every_selected_case_has_non_empty_demo_angle(self) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertTrue(case["demo_angle"].strip())

    def test_every_selected_case_has_non_empty_why_selected(self) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertTrue(case["why_selected"].strip())

    def test_every_selected_case_has_non_empty_expected_frontier_failure_mode(
        self,
    ) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertTrue(case["expected_frontier_failure_mode"].strip())

    def test_every_selected_case_has_non_empty_admissible_expected_behavior(
        self,
    ) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertTrue(case["admissible_expected_behavior"].strip())

    def test_every_selected_case_has_at_least_one_viewer_talking_point(self) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            talking_points = case["viewer_talking_points"]
            self.assertGreaterEqual(len(talking_points), 1)
            for point in talking_points:
                self.assertTrue(point.strip())


class TestDemoPackMarkdown(unittest.TestCase):
    def setUp(self) -> None:
        self.markdown = DEMO_PACK_MD_PATH.read_text(encoding="utf-8")

    def test_markdown_contains_claim_boundary(self) -> None:
        self.assertIn(_EXACT_CLAIM_BOUNDARY, self.markdown)

    def test_markdown_contains_all_selected_benchmark_case_ids(self) -> None:
        demo_pack = _load_demo_pack()
        for case in demo_pack["selected_cases"]:
            self.assertIn(case["benchmark_case_id"], self.markdown)

    def test_markdown_explicitly_says_it_is_not_a_benchmark_result(self) -> None:
        self.assertIn("not a benchmark result", self.markdown.lower())


if __name__ == "__main__":
    unittest.main()
