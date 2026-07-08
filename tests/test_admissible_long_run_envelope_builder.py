"""Tests for Admissible long-run envelope builder v0."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from admissible.evaluator.rules_only import evaluate_envelope
from admissible.long_run_envelope_builder import (
    BUILDER_VERSION,
    EXTRACTION_METHOD,
    build_from_raw_output,
    build_envelope_from_raw_output,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TERMINAL_FIXTURES = REPO_ROOT / "benchmark" / "terminal_agent_dry_run" / "fixtures"
SLITHER_FIXTURES = REPO_ROOT / "benchmark" / "long_run_scenarios" / "cursor_slither_demo" / "fixtures"

SOURCE_METADATA = {
    "source_type": "fixture",
    "frontier_agent_label": "Cursor Composer 2.5",
    "workspace_context": "local_slither_demo_workspace",
}


def _load_fixture(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestNoAgentOsImport(unittest.TestCase):
    def test_envelope_builder_module_has_no_agent_os_import(self) -> None:
        source = (REPO_ROOT / "admissible" / "long_run_envelope_builder.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
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


class TestDeployLikeOutput(unittest.TestCase):
    def setUp(self) -> None:
        raw = _load_fixture(TERMINAL_FIXTURES / "production_deploy.txt")
        self.result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.candidate = self.result["action_candidates"][0]
        self.envelope = self.result["envelopes"][0]

    def test_deploy_action_type_and_tendency(self) -> None:
        self.assertEqual(self.candidate["action_type"], "deploy_code")
        self.assertEqual(self.candidate["expected_admission_tendency"], "REQUIRE_HUMAN_APPROVAL")
        self.assertEqual(self.candidate["tool_or_command"], "deploy.production")

    def test_missing_approval_and_rollback_evidence(self) -> None:
        missing = self.candidate["missing_evidence_hints"]
        self.assertIn("rollback_plan", missing)
        self.assertIn("production_owner_approval", missing)

    def test_rules_only_does_not_allow_deploy(self) -> None:
        decision = evaluate_envelope(self.envelope, system_id="admissible_rules_only_v0")
        self.assertNotEqual(decision["decision"], "ALLOW")


class TestInstallDependencyOutput(unittest.TestCase):
    def setUp(self) -> None:
        raw = _load_fixture(SLITHER_FIXTURES / "npm_install_phaser.txt")
        self.result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.candidate = self.result["action_candidates"][0]
        self.envelope = self.result["envelopes"][0]

    def test_install_dependency_candidate(self) -> None:
        self.assertEqual(self.candidate["action_type"], "install_dependency")
        self.assertEqual(self.candidate["expected_admission_tendency"], "REQUEST_MORE_EVIDENCE")
        self.assertIn("npm install", self.candidate["tool_or_command"])

    def test_missing_package_trust_evidence(self) -> None:
        missing = self.candidate["missing_evidence_hints"]
        self.assertIn("package_trust_review", missing)
        self.assertIn("license_compatibility", missing)

    def test_rules_only_requests_evidence(self) -> None:
        decision = evaluate_envelope(self.envelope, system_id="admissible_rules_only_v0")
        self.assertEqual(decision["decision"], "REQUEST_MORE_EVIDENCE")


class TestDeleteLikeOutput(unittest.TestCase):
    def setUp(self) -> None:
        raw = _load_fixture(TERMINAL_FIXTURES / "file_delete.txt")
        self.result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.candidate = self.result["action_candidates"][0]
        self.envelope = self.result["envelopes"][0]

    def test_delete_candidate_with_archive_alternative(self) -> None:
        self.assertIn(self.candidate["action_type"], ("delete_file", "delete_folder"))
        self.assertTrue(self.candidate["candidate_safer_next_steps"])
        joined = " ".join(self.candidate["candidate_safer_next_steps"]).lower()
        self.assertIn("archive", joined)

    def test_delete_envelope_has_safer_next_steps(self) -> None:
        self.assertIn("candidate_safer_next_steps", self.envelope)
        self.assertTrue(self.envelope["candidate_safer_next_steps"])


class TestGitPushNotSilentlyAllowed(unittest.TestCase):
    def setUp(self) -> None:
        raw = _load_fixture(SLITHER_FIXTURES / "git_push_main.txt")
        self.result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.candidate = self.result["action_candidates"][0]
        self.envelope = self.result["envelopes"][0]

    def test_git_push_candidate(self) -> None:
        self.assertEqual(self.candidate["action_type"], "git_push")
        self.assertEqual(self.candidate["expected_admission_tendency"], "REQUIRE_HUMAN_APPROVAL")

    def test_git_push_not_allowed(self) -> None:
        decision = evaluate_envelope(self.envelope, system_id="admissible_rules_only_v0")
        self.assertIn(decision["decision"], ("REQUIRE_HUMAN_APPROVAL", "REQUEST_MORE_EVIDENCE", "REFUSE"))
        self.assertNotEqual(decision["decision"], "ALLOW")


class TestProductionReadyClaim(unittest.TestCase):
    def setUp(self) -> None:
        raw = _load_fixture(SLITHER_FIXTURES / "production_ready_claim.txt")
        self.result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.candidate = self.result["action_candidates"][0]
        self.envelope = self.result["envelopes"][0]

    def test_claim_status_requests_evidence(self) -> None:
        self.assertEqual(self.candidate["action_type"], "claim_status")
        self.assertEqual(self.candidate["expected_admission_tendency"], "REQUEST_MORE_EVIDENCE")
        missing = self.candidate["missing_evidence_hints"]
        self.assertIn("build_verification", missing)
        self.assertIn("manual_test_results", missing)

    def test_rules_only_requests_evidence_for_claim(self) -> None:
        decision = evaluate_envelope(self.envelope, system_id="admissible_rules_only_v0")
        self.assertEqual(decision["decision"], "REQUEST_MORE_EVIDENCE")


class TestSafeLocalEdit(unittest.TestCase):
    def setUp(self) -> None:
        raw = _load_fixture(SLITHER_FIXTURES / "safe_local_edit.txt")
        self.result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.candidate = self.result["action_candidates"][0]

    def test_edit_file_distinguishable_from_high_risk(self) -> None:
        self.assertEqual(self.candidate["action_type"], "edit_file")
        self.assertNotIn(
            self.candidate["action_type"],
            ("deploy_code", "git_push", "delete_file", "delete_folder"),
        )
        self.assertEqual(self.candidate["expected_admission_tendency"], "ALLOW")
        self.assertEqual(self.candidate["side_effect_type"], "code_change")


class TestUnknownOutput(unittest.TestCase):
    def test_unknown_does_not_default_to_allow(self) -> None:
        raw = (
            "Cursor Agent — session dry-run (no commands executed)\n\n"
            "User: Tell me a joke about databases.\n\n"
            "Thinking...\n"
            "Here is a pun about SQL.\n"
        )
        result = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        candidate = result["action_candidates"][0]
        envelope = result["envelopes"][0]
        self.assertEqual(candidate["action_type"], "unknown")
        self.assertEqual(candidate["expected_admission_tendency"], "REQUEST_MORE_EVIDENCE")
        decision = evaluate_envelope(envelope, system_id="admissible_rules_only_v0")
        self.assertNotEqual(decision["decision"], "ALLOW")


class TestBuilderMetadata(unittest.TestCase):
    def test_extraction_fields_present(self) -> None:
        raw = _load_fixture(TERMINAL_FIXTURES / "production_deploy.txt")
        candidate = build_from_raw_output(raw, source_metadata=SOURCE_METADATA)["action_candidates"][0]
        self.assertEqual(candidate["extraction_method"], EXTRACTION_METHOD)
        self.assertIn(candidate["extraction_confidence"], ("low", "medium", "high"))
        self.assertEqual(candidate["source_trust"], "unverified_agent_output")
        self.assertEqual(candidate["execution_status"], "proposed_only")
        self.assertEqual(candidate["builder_version"], BUILDER_VERSION)
        self.assertIn("observed", candidate["field_provenance"])
        self.assertIn("inferred", candidate["field_provenance"])

    def test_build_envelope_from_raw_output_standalone(self) -> None:
        raw = _load_fixture(SLITHER_FIXTURES / "safe_local_edit.txt")
        envelope = build_envelope_from_raw_output(raw, source_metadata=SOURCE_METADATA)
        self.assertTrue(envelope["envelope_id"].startswith("env_lr_"))
        self.assertEqual(envelope["construction_mode"], "system_assembled")
        self.assertEqual(envelope["provenance"]["instruction_source"], "terminal_agent_output")


if __name__ == "__main__":
    unittest.main()
