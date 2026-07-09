"""Tests for the Admissible Agent Response Extraction Lab v0.

Covers the hardened multi-action freeform extraction in
`admissible.long_run_envelope_builder` (via its pasted-agent-response
fixtures), the `admissible.runner.extraction_lab` regression harness itself,
and the run-loop-level guarantee that ingesting one pasted response with
several proposed actions surfaces all of them in the queue without
mutating any existing decision.

Hard constraints exercised here: no provider is called, nothing proposed in
a fixture is executed, `admissible` never imports `agent_os`, and no
executor/subprocess is introduced by this harness.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.evaluator.rules_only import evaluate_envelope
from admissible.long_run_envelope_builder import build_from_raw_output
from admissible.runner.extraction_lab import (
    evaluate_fixture,
    load_expected_spec,
    load_fixture,
    render_markdown_report,
    run_extraction_lab,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "fixtures"
    / "pasted_agent_responses"
)
EXPECTED_SPEC_PATH = FIXTURES_DIR / "expected_extractions.json"

SAMPLE_TRACE_PATH = (
    REPO_ROOT / "benchmark" / "reports" / "admissible_cursor_admitted_execution_truth_console_trace.json"
)


def _load(name: str) -> str:
    return load_fixture(FIXTURES_DIR / name)


def _build(name: str) -> dict:
    raw = _load(name)
    return build_from_raw_output(raw, source_metadata={"fixture_path": str((FIXTURES_DIR / name).as_posix())})


class TestMultiActionExtraction(unittest.TestCase):
    """The originally-reported bug: a mixed install+push+edit+claim paste
    used to collapse into one `unknown (unknown)` candidate."""

    def setUp(self) -> None:
        self.built = _build("multi_action_install_push_local_claim.txt")
        self.candidates = self.built["action_candidates"]
        self.by_type = {c["action_type"]: c for c in self.candidates}
        self.decisions_by_type = {
            c["action_type"]: evaluate_envelope(e)
            for c, e in zip(self.candidates, self.built["envelopes"])
        }

    def test_extracts_at_least_four_candidates(self) -> None:
        self.assertGreaterEqual(len(self.candidates), 4)
        self.assertNotIn("unknown", self.by_type)

    def test_install_dependency_is_not_allow(self) -> None:
        self.assertIn("install_dependency", self.by_type)
        self.assertIn("npm install", self.by_type["install_dependency"]["tool_or_command"])
        self.assertNotEqual(self.decisions_by_type["install_dependency"]["decision"], "ALLOW")

    def test_git_push_requires_human_approval(self) -> None:
        self.assertIn("git_push", self.by_type)
        self.assertEqual(self.decisions_by_type["git_push"]["decision"], "REQUIRE_HUMAN_APPROVAL")

    def test_local_edit_distinguishable_from_install_push(self) -> None:
        self.assertIn("edit_file", self.by_type)
        self.assertNotEqual(self.by_type["edit_file"]["action_type"], "install_dependency")
        self.assertNotEqual(self.by_type["edit_file"]["action_type"], "git_push")
        self.assertEqual(self.decisions_by_type["edit_file"]["decision"], "ALLOW")

    def test_production_readiness_claim_requests_evidence(self) -> None:
        self.assertIn("claim_status", self.by_type)
        self.assertEqual(self.decisions_by_type["claim_status"]["decision"], "REQUEST_MORE_EVIDENCE")

    def test_explicit_non_execution_statement_does_not_relax_gating(self) -> None:
        # The fixture explicitly states "Nothing was executed." -- that
        # truthful non-execution note must not be read as evidence that
        # gated actions are safe to allow.
        for action_type in ("install_dependency", "git_push", "claim_status"):
            self.assertNotEqual(self.decisions_by_type[action_type]["decision"], "ALLOW")


class TestNumberedOperationsExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.built = _build("cursor_numbered_operations.txt")
        self.candidates = self.built["action_candidates"]
        self.action_types = [c["action_type"] for c in self.candidates]

    def test_local_edit_and_checklist_and_tooling_extracted(self) -> None:
        self.assertIn("local_code_change", self.action_types)
        self.assertIn("verification_plan", self.action_types)
        self.assertIn("install_dependency", self.action_types)

    def test_do_not_deploy_yet_does_not_become_deploy_action(self) -> None:
        self.assertNotIn("deploy_code", self.action_types)
        self.assertNotIn("prepare_deploy", self.action_types)


class TestNegativeOnlyBoundaries(unittest.TestCase):
    def setUp(self) -> None:
        self.built = _build("negative_only_boundaries.txt")
        self.candidates = self.built["action_candidates"]
        self.action_types = {c["action_type"] for c in self.candidates}
        self.decisions = [evaluate_envelope(e) for e in self.built["envelopes"]]

    def test_no_positive_install_push_deploy_candidates(self) -> None:
        for forbidden in ("install_dependency", "git_push", "deploy_code", "prepare_deploy"):
            self.assertNotIn(forbidden, self.action_types)

    def test_any_fallback_candidate_is_not_allow(self) -> None:
        for decision in self.decisions:
            self.assertNotEqual(decision["decision"], "ALLOW")


class TestUnknownFreeformRemainsConservative(unittest.TestCase):
    def setUp(self) -> None:
        self.built = _build("unknown_freeform_response.txt")

    def test_single_conservative_candidate_not_allow(self) -> None:
        candidates = self.built["action_candidates"]
        self.assertGreaterEqual(len(candidates), 1)
        decisions = [evaluate_envelope(e) for e in self.built["envelopes"]]
        for decision in decisions:
            self.assertNotEqual(decision["decision"], "ALLOW")


class TestEvidenceResponseNotTreatedAsExecution(unittest.TestCase):
    def setUp(self) -> None:
        self.built = _build("evidence_response_for_request_more_evidence.txt")

    def test_requests_more_evidence_not_execution(self) -> None:
        candidates = self.built["action_candidates"]
        self.assertGreaterEqual(len(candidates), 1)
        for candidate in candidates:
            self.assertEqual(candidate["execution_status"], "proposed_only")
        decisions = [evaluate_envelope(e) for e in self.built["envelopes"]]
        self.assertTrue(all(d["decision"] != "ALLOW" for d in decisions))
        self.assertIn("REQUEST_MORE_EVIDENCE", [d["decision"] for d in decisions])


class TestRunLoopIngestsMultipleCandidatesFromOneResponse(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = ControlSurfaceController(
            session_dir=Path(self._tmpdir.name) / "sessions",
            sample_trace_path=SAMPLE_TRACE_PATH,
        )

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_ingest_adds_all_candidates_and_none_are_executed(self) -> None:
        raw_text = _load("multi_action_install_push_local_claim.txt")
        state = self.controller.ingest_agent_response(raw_text)

        record = state["run_loop"]["response_records"][-1]
        self.assertGreaterEqual(len(record["action_ids"]), 4)
        self.assertEqual(state["transcript"][-1]["type"], "agent_response_ingested")
        self.assertEqual(state["transcript"][-1]["payload"]["action_count"], len(record["action_ids"]))

        queue_action_ids = {item["action_id"] for item in state["queue"]}
        for action_id in record["action_ids"]:
            self.assertIn(action_id, queue_action_ids)
            action_id_prefix = action_id.rsplit("_", 1)[0]
            self.assertTrue(action_id_prefix.startswith(f"resp_t{record['turn_number']:02d}_"))

        action_types = {item["action_type"] for item in state["queue"]}
        self.assertIn("install_dependency", action_types)
        self.assertIn("git_push", action_types)
        self.assertIn("edit_file", action_types)
        self.assertIn("claim_status", action_types)

    def test_ingesting_a_second_response_does_not_mutate_first_batch_decisions(self) -> None:
        raw_text = _load("multi_action_install_push_local_claim.txt")
        state = self.controller.ingest_agent_response(raw_text)
        first_batch_action_ids = list(state["run_loop"]["response_records"][-1]["action_ids"])
        original_decisions = {
            action_id: dict(state["run_envelopes"][action_id]["decision"])
            for action_id in first_batch_action_ids
        }

        state2 = self.controller.ingest_agent_response(
            _load("cursor_numbered_operations.txt")
        )

        for action_id, original_decision in original_decisions.items():
            self.assertEqual(state2["run_envelopes"][action_id]["decision"], original_decision)


class TestExtractionLabHarness(unittest.TestCase):
    def test_load_fixture_and_expected_spec(self) -> None:
        raw = load_fixture(FIXTURES_DIR / "unknown_freeform_response.txt")
        self.assertIn("User:", raw)
        spec = load_expected_spec(EXPECTED_SPEC_PATH)
        self.assertIn("fixtures", spec)
        self.assertGreaterEqual(len(spec["fixtures"]), 5)

    def test_evaluate_fixture_detects_missing_expected_action_type(self) -> None:
        raw = load_fixture(FIXTURES_DIR / "negative_only_boundaries.txt")
        result = evaluate_fixture(
            "negative_only_boundaries.txt",
            raw,
            {"expected_action_types": ["git_push"]},
        )
        self.assertFalse(result["passed"])
        self.assertTrue(any("git_push" in f for f in result["failures"]))

    def test_evaluate_fixture_detects_forbidden_action_type(self) -> None:
        raw = load_fixture(FIXTURES_DIR / "multi_action_install_push_local_claim.txt")
        result = evaluate_fixture(
            "multi_action_install_push_local_claim.txt",
            raw,
            {"forbidden_action_types": ["git_push"]},
        )
        self.assertFalse(result["passed"])
        self.assertTrue(any("forbidden action type 'git_push'" in f for f in result["failures"]))

    def test_evaluate_fixture_detects_forbidden_decision(self) -> None:
        raw = load_fixture(FIXTURES_DIR / "multi_action_install_push_local_claim.txt")
        result = evaluate_fixture(
            "multi_action_install_push_local_claim.txt",
            raw,
            {"forbidden_decisions": ["ALLOW"]},
        )
        self.assertFalse(result["passed"])

    def test_evaluate_fixture_detects_below_minimum_count(self) -> None:
        raw = load_fixture(FIXTURES_DIR / "unknown_freeform_response.txt")
        result = evaluate_fixture(
            "unknown_freeform_response.txt",
            raw,
            {"min_candidate_count": 5},
        )
        self.assertFalse(result["passed"])

    def test_full_lab_run_passes_against_committed_fixtures(self) -> None:
        summary = run_extraction_lab(FIXTURES_DIR, EXPECTED_SPEC_PATH)
        self.assertTrue(summary["overall_passed"], summary)
        self.assertEqual(summary["fail_count"], 0)
        self.assertEqual(summary["fixture_count"], len(summary["results"]))
        for result in summary["results"]:
            self.assertEqual(result["failures"], [])

    def test_markdown_report_renders_pass_status(self) -> None:
        summary = run_extraction_lab(FIXTURES_DIR, EXPECTED_SPEC_PATH)
        markdown = render_markdown_report(summary)
        self.assertIn("Admissible Agent Response Extraction Lab", markdown)
        self.assertIn("PASS", markdown)
        for fixture_name in summary["results"]:
            self.assertIn(fixture_name["fixture"], markdown)


class TestExtractionLabModuleBoundaries(unittest.TestCase):
    """Static-source checks backing the NO_EXECUTOR / NO_PROVIDER_CALLS /
    NO_AGENT_OS_IMPORT / SLICE_SCOPE_EXTRACTION_ONLY diagnostics for the new
    extraction lab module."""

    _SOURCE_PATH = REPO_ROOT / "admissible" / "runner" / "extraction_lab.py"

    def setUp(self) -> None:
        self.source = self._SOURCE_PATH.read_text(encoding="utf-8")

    def test_no_agent_os_import(self) -> None:
        tree = ast.parse(self.source)
        hits: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "agent_os" or alias.name.startswith("agent_os."):
                        hits.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module
                if module and (module == "agent_os" or module.startswith("agent_os.")):
                    hits.append(module)
        self.assertEqual(hits, [])

    def test_no_subprocess_or_shell_execution(self) -> None:
        forbidden_tokens = (
            "import subprocess",
            "os.system(",
            "os.popen(",
            " eval(",
            " exec(",
        )
        for token in forbidden_tokens:
            self.assertNotIn(token, self.source, f"extraction_lab.py unexpectedly contains {token!r}")

    def test_no_network_provider_sdk_imports(self) -> None:
        forbidden_tokens = (
            "import openai",
            "import anthropic",
            "google.generativeai",
            "requests.post",
            "import httpx",
        )
        lowered = self.source.lower()
        for token in forbidden_tokens:
            self.assertNotIn(token, lowered, f"extraction_lab.py unexpectedly references {token!r}")


if __name__ == "__main__":
    unittest.main()
