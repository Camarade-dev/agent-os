"""Milestone 2 repository artifacts must be canonical and match the code.

The Milestone 1 artifacts are historical and are asserted here to be unchanged
by Milestone 2.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_admissible_paired_runner_m2_crash import CORRUPTION_TARGETS, CRASH_MATRIX  # noqa: E402
from admissible.paired_runner.canonical import canonical_bytes, parse_canonical_json  # noqa: E402
from admissible.paired_runner.durable_store import FAULT_POINTS  # noqa: E402
from admissible.paired_runner.effect_ledger import M2_LEDGER_SCHEMAS  # noqa: E402
from admissible.paired_runner.observation import M2_OBSERVATION_SCHEMAS  # noqa: E402
from admissible.paired_runner.reconciliation import M2_RECONCILIATION_SCHEMAS  # noqa: E402
from admissible.paired_runner.capsule_identity import M2_CAPSULE_IDENTITY_SCHEMAS  # noqa: E402
from admissible.paired_runner.private_workspace import M2_PRIVATE_WORKSPACE_SCHEMAS  # noqa: E402
from admissible.paired_runner.run_index import M2_RUN_INDEX_SCHEMAS  # noqa: E402
from admissible.paired_runner.schemas import SCHEMA_CATALOG  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = ROOT / "implementation"
M1_STARTING_COMMIT = "5b5c3874f1929e77dbc3e2f71aa7f26d675a2705"
M2_STARTING_COMMIT = "096dfbeb8845aaeda4c24f19e13fd144ceea4bfb"
M2_SECOND_STARTING_COMMIT = "6383f765520e3d98c7359118704d063b6aa39b52"
M2_THIRD_STARTING_COMMIT = "68dd7c9a6be66319dc93eeedcec2e994a6119585"
M2_FOURTH_STARTING_COMMIT = "1133d131c75ed07e79d949b6b3f2f40847a3218b"
M2_FINAL_LIFECYCLE_STARTING_COMMIT = "fbadaeec4205c9b24aeaeaac6c73ca1e6e69a4ff"
M2_FINAL_LIFECYCLE_BRANCH = "paired-runner/m2-final-protocol-lifecycle-repair"
M2_SUBREAPER_DEADLINE_STARTING_COMMIT = "c30bf3d38445f59271b61ad4db8520ed053af281"
M2_SUBREAPER_DEADLINE_BRANCH = "paired-runner/m2-subreaper-deadline-closure"
M2_OWNERSHIP_DEBT_REAP_STARTING_COMMIT = "2f7eaac796e6f4b3d93419ac3087183302b2a54e"
M2_OWNERSHIP_DEBT_REAP_BRANCH = "paired-runner/m2-ownership-debt-reap-closure"
M2_PROCESS_OWNER_CLEANUP_STARTING_COMMIT = "4a451c859bc528d6281bfd1368ab3ca74fd3933c"
M2_PROCESS_OWNER_CLEANUP_BRANCH = "paired-runner/m2-process-owner-cleanup-propagation-closure"
M2_CGROUP_IDENTITY_STARTING_COMMIT = "fd4e9fb409f648da356f90b9ca2c211183267354"
M2_CGROUP_IDENTITY_BRANCH = (
    "paired-runner/m2-cgroup-identity-reap-registry-serialization-closure"
)
M2_SECOND_BRANCH = "paired-runner/m2-causal-index-and-ipc-repairs"
M2_THIRD_BRANCH = "paired-runner/m2-private-workspace-and-bound-runtime"
M2_FOURTH_BRANCH = "paired-runner/m2-fourth-critical-repair-retry"
M2_ARTIFACTS = (
    "M2_CUMULATIVE_SCHEMA_CATALOG.json",
    "M2_CRASH_MATRIX.json",
    "M2_OUTPUT_SOAK_REPORT.json",
    "M2_VALIDATION_REPORT.json",
    "M2_VALIDATION_REPORT_HISTORICAL_FOURTH_REPAIR.json",
    "M2_CRITICAL_REPAIR_REPORT.json",
    "M2_SECOND_CRITICAL_REPAIR_REPORT.json",
    "M2_THIRD_CRITICAL_REPAIR_REPORT.json",
    "M2_FOURTH_CRITICAL_REPAIR_REPORT.json",
    "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json",
    "M2_SUBREAPER_DEADLINE_CLOSURE_REPORT.json",
    "M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
    "M2_PROCESS_OWNER_CLEANUP_PROPAGATION_CLOSURE_REPORT.json",
    "M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_CLOSURE_REPORT.json",
)
#: Historical reports of earlier passes.  A later pass may not rewrite them: the
#: record of what an earlier closure claimed is itself evidence.
PRESERVED_HISTORICAL_ARTIFACTS = (
    "M2_CRITICAL_REPAIR_REPORT.json",
    "M2_SECOND_CRITICAL_REPAIR_REPORT.json",
    "M2_THIRD_CRITICAL_REPAIR_REPORT.json",
    "M2_FOURTH_CRITICAL_REPAIR_REPORT.json",
    "M2_B25_CGROUP_TOPOLOGY_REPAIR_REPORT.json",
    "M2_B25_FINAL_FAILCLOSED_REPAIR_REPORT.json",
    "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json",
    "M2_SUBREAPER_DEADLINE_CLOSURE_REPORT.json",
    # This pass supersedes the ownership-debt/reap closure, so that closure's
    # report is historical from here on and may not be rewritten.
    "M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
    # ...and this pass supersedes the process-owner/cleanup-propagation closure,
    # so its report is historical from here on for the same reason.
    "M2_PROCESS_OWNER_CLEANUP_PROPAGATION_CLOSURE_REPORT.json",
)
PRESERVED_M1_ARTIFACTS = (
    "M1_SCHEMA_CATALOG.json",
    "M1_ALLOWED_CONDITION_DIFFERENCES.json",
    "M1_VALIDATION_REPORT.json",
    "M1_BOUNDED_REPAIR_REPORT.json",
    "M1_SECOND_BOUNDED_REPAIR_REPORT.json",
    "M1_EXECUTABLE_ARCHITECTURE_SPEC.md",
)
FORBIDDEN_MODULES = (
    "transport.py",
    "direct_mode.py",
    "governed_mode.py",
    "policy.py",
    "authority.py",
    "evaluator.py",
    "archive.py",
)


class M2ArtifactTests(unittest.TestCase):
    def test_every_m2_json_artifact_is_canonically_encoded(self) -> None:
        for name in M2_ARTIFACTS:
            with self.subTest(artifact=name):
                path = IMPLEMENTATION / name
                raw = path.read_bytes()
                value = parse_canonical_json(raw, label=name)
                self.assertEqual(canonical_bytes(value), raw)

    def test_the_cumulative_catalog_matches_the_code_catalogs(self) -> None:
        catalog = parse_canonical_json((IMPLEMENTATION / "M2_CUMULATIVE_SCHEMA_CATALOG.json").read_bytes())
        self.assertEqual(catalog["milestone_1_schemas"], [item.to_dict() for item in SCHEMA_CATALOG.values()])
        expected_m2 = (
            [item.to_dict() for item in M2_OBSERVATION_SCHEMAS.values()]
            + [item.to_dict() for item in M2_LEDGER_SCHEMAS.values()]
            + [item.to_dict() for item in M2_RECONCILIATION_SCHEMAS.values()]
            + [item.to_dict() for item in M2_RUN_INDEX_SCHEMAS.values()]
            + [item.to_dict() for item in M2_CAPSULE_IDENTITY_SCHEMAS.values()]
            + [item.to_dict() for item in M2_PRIVATE_WORKSPACE_SCHEMAS.values()]
        )
        self.assertEqual(catalog["milestone_2_schemas"], expected_m2)
        self.assertEqual(catalog["milestone_1_schema_count"], 29)
        self.assertEqual(catalog["milestone_2_schema_count"], 19)
        self.assertEqual(catalog["cumulative_schema_count"], 48)
        self.assertEqual(catalog["milestone_2_schema_version"], 2)
        self.assertIn("preserved unchanged", catalog["migration_note"])

    def test_the_crash_matrix_artifact_matches_the_declared_test_table(self) -> None:
        matrix = parse_canonical_json((IMPLEMENTATION / "M2_CRASH_MATRIX.json").read_bytes())
        self.assertEqual(matrix["fault_point_count"], 25)
        self.assertEqual(len(matrix["rows"]), len(CRASH_MATRIX))
        self.assertEqual(
            [row["fault_point"] for row in matrix["rows"]],
            [expectation.point for expectation in CRASH_MATRIX],
        )
        self.assertEqual(set(row["fault_point"] for row in matrix["rows"]), set(FAULT_POINTS))
        for row, expectation in zip(matrix["rows"], CRASH_MATRIX):
            self.assertEqual(row["reconciliation_classification"], expectation.classification)
            self.assertEqual(row["effect_invocations"], expectation.effect_invocations)
            self.assertEqual(row["effect_may_have_occurred"], expectation.effect_may_have_occurred)
            self.assertFalse(row["replay_permitted"])
            self.assertFalse(row["duplicate_effect"])
            self.assertFalse(row["false_completed_state"])
            self.assertEqual(row["run_index_state"], expectation.index_state)
        self.assertEqual(matrix["corruption_fixture_count"], len(CORRUPTION_TARGETS) * 2)
        self.assertEqual(matrix["corruption_fixture_count"], 24)

    def test_the_validation_report_records_the_exact_counts_and_verdict(self) -> None:
        report = parse_canonical_json((IMPLEMENTATION / "M2_VALIDATION_REPORT.json").read_bytes())
        # M2-M36: the canonical filename is the single *current* report, and the
        # superseded fourth-repair bytes live under a historical filename.
        self.assertTrue(report["is_current_validation_report"])
        self.assertEqual(report["starting_commit"], M2_CGROUP_IDENTITY_STARTING_COMMIT)
        self.assertEqual(report["starting_commit_parent"], M2_PROCESS_OWNER_CLEANUP_STARTING_COMMIT)
        self.assertEqual(report["branch"], M2_CGROUP_IDENTITY_BRANCH)
        self.assertIn(
            report["terminal_verdict"],
            {
                "M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_CLOSURE_VERIFIED",
                "M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_OPERATOR_QUALIFICATION_REQUIRED",
            },
        )
        self.assertFalse(report["boundary_audit"]["milestone_3_started"])
        for boundary, crossed in report["boundary_audit"].items():
            self.assertFalse(crossed, boundary)
        for record in report["requirement_dispositions"]:
            self.assertNotEqual(record["status"], "VERIFIED_INSTALLED_PATH")
        # Totals must match live discovery, not a hand-maintained stale number.
        self.assertEqual(
            report["test_counts"]["total"],
            report["test_counts"]["discovered_total"],
        )
        self.assertGreaterEqual(report["test_counts"]["total"], 305)
        self.assertTrue(report["known_limitations"])
        self.assertEqual(
            report["final_repair_report"],
            "implementation/M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_CLOSURE_REPORT.json",
        )
        # The pointer resolves, and the report it names agrees about the pass.
        closure = parse_canonical_json(
            (ROOT / report["final_repair_report"]).read_bytes()
        )
        self.assertEqual(closure["starting_commit"], report["starting_commit"])
        self.assertEqual(closure["branch"], report["branch"])
        self.assertEqual(closure["terminal_verdict"], report["terminal_verdict"])
        # M2-M55: one canonical current run object, byte-identical in both.
        self.assertEqual(closure["canonical_current_run"], report["canonical_current_run"])

    def test_the_repair_report_closes_every_audit_finding(self) -> None:
        report = parse_canonical_json((IMPLEMENTATION / "M2_CRITICAL_REPAIR_REPORT.json").read_bytes())
        self.assertEqual(report["starting_commit"], M2_STARTING_COMMIT)
        self.assertEqual(report["branch"], "paired-runner/m2-critical-repairs")
        self.assertEqual(report["terminal_verdict"], "M2_CRITICAL_REPAIRS_VERIFIED")
        findings = {row["finding"]: row for row in report["findings"]}
        self.assertEqual(
            sorted(findings), [f"M2-R{index:02d}" for index in range(1, 12)]
        )
        for name, row in findings.items():
            with self.subTest(finding=name):
                self.assertEqual(row["status"], "CLOSED")
                self.assertTrue(row["closure"])
                self.assertTrue(row["evidence"])
        self.assertFalse(report["boundary_audit"]["milestone_3_started"])
        for boundary, crossed in report["boundary_audit"].items():
            self.assertFalse(crossed, boundary)
        self.assertEqual(report["sandbox"]["mechanism"], "bubblewrap")
        self.assertFalse(report["sandbox"]["evidence_root_exposed"])
        self.assertTrue(report["known_limitations"])

    def test_the_second_repair_report_closes_every_remaining_finding(self) -> None:
        report = parse_canonical_json(
            (IMPLEMENTATION / "M2_SECOND_CRITICAL_REPAIR_REPORT.json").read_bytes()
        )
        self.assertEqual(report["starting_commit"], M2_SECOND_STARTING_COMMIT)
        self.assertEqual(report["branch"], M2_SECOND_BRANCH)
        self.assertEqual(report["terminal_verdict"], "M2_SECOND_CRITICAL_REPAIRS_VERIFIED")
        findings = {row["finding"]: row for row in report["findings"]}
        self.assertEqual(
            sorted(findings),
            ["M2-B12", "M2-B13", "M2-B14", "M2-B15", "M2-B16", "M2-M17", "M2-M18", "M2-M19", "M2-M20"],
        )
        for name, row in findings.items():
            with self.subTest(finding=name):
                self.assertEqual(row["status"], "CLOSED")
                self.assertTrue(row["reproduction"])
                self.assertTrue(row["closure"])
                self.assertTrue(row["evidence"])
        self.assertFalse(report["boundary_audit"]["milestone_3_started"])
        for boundary, crossed in report["boundary_audit"].items():
            self.assertFalse(crossed, boundary)
        for record in report["requirement_dispositions"]:
            self.assertNotEqual(record["status"], "VERIFIED_INSTALLED_PATH")
        self.assertTrue(report["known_limitations"])

    def test_the_third_repair_report_closes_every_remaining_finding(self) -> None:
        report = parse_canonical_json(
            (IMPLEMENTATION / "M2_THIRD_CRITICAL_REPAIR_REPORT.json").read_bytes()
        )
        self.assertEqual(report["starting_commit"], M2_THIRD_STARTING_COMMIT)
        self.assertEqual(report["branch"], M2_THIRD_BRANCH)
        self.assertEqual(report["terminal_verdict"], "M2_THIRD_CRITICAL_REPAIRS_VERIFIED")
        findings = {row["finding"]: row for row in report["findings"]}
        self.assertEqual(sorted(findings), ["M2-B21", "M2-M22", "M2-M23", "M2-M24"])
        for name, row in findings.items():
            with self.subTest(finding=name):
                self.assertEqual(row["status"], "CLOSED")
                self.assertTrue(row["reproduction"])
                self.assertTrue(row["closure"])
                self.assertTrue(row["evidence"])
        self.assertFalse(report["boundary_audit"]["milestone_3_started"])
        for boundary, crossed in report["boundary_audit"].items():
            self.assertFalse(crossed, boundary)
        for record in report["requirement_dispositions"]:
            self.assertNotEqual(record["status"], "VERIFIED_INSTALLED_PATH")
        self.assertTrue(report.get("withdrawn_claims"))

    def test_the_historical_repair_report_is_preserved_byte_for_byte(self) -> None:
        for name in PRESERVED_HISTORICAL_ARTIFACTS:
            with self.subTest(artifact=name):
                committed = subprocess.run(
                    ["git", "show", f"HEAD:implementation/{name}"],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), committed)

    def test_the_milestone_1_artifacts_are_preserved_byte_for_byte(self) -> None:
        for name in PRESERVED_M1_ARTIFACTS:
            with self.subTest(artifact=name):
                committed = subprocess.run(
                    ["git", "show", f"{M1_STARTING_COMMIT}:implementation/{name}"],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), committed)

    def test_no_forbidden_module_was_introduced(self) -> None:
        package = ROOT / "admissible" / "paired_runner"
        present = {path.name for path in package.glob("*.py")}
        for name in FORBIDDEN_MODULES:
            self.assertNotIn(name, present)
        self.assertEqual(
            present,
            {
                "__init__.py",
                "_capsule_init.py",
                "canonical.py",
                "capsule_identity.py",
                "capsule_seccomp.py",
                "cgroup_launch.py",
                "comparison.py",
                "durable_store.py",
                "git_observer.py",
                "effect_ledger.py",
                "effects.py",
                "identities.py",
                "observation.py",
                "private_workspace.py",
                "process_ownership.py",
                "process_supervision.py",
                "reconciliation.py",
                "resource_limits.py",
                "run_index.py",
                "runtime_binding.py",
                "sandbox.py",
                "schemas.py",
                "specification.py",
                "tool_schemas.py",
            },
        )

    def test_the_package_imports_no_historical_or_provider_path(self) -> None:
        forbidden = (
            "admissible.runner",
            "long_run",
            "high_autonomy",
            "historical_pairing",
            "delegated_gate",
            "capsule",
            "owner_authority",
            "requests",
            "urllib",
            "http",
        )
        # ``socket`` is permitted only in private_workspace.py for SCM_RIGHTS FD
        # passing of the private mount-namespace view — not as network transport.
        for path in (ROOT / "admissible" / "paired_runner").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            tokens = forbidden + (("socket",) if path.name != "private_workspace.py" else ())
            for token in tokens:
                with self.subTest(module=path.name, forbidden=token):
                    self.assertNotIn(f"import {token}", text)
                    self.assertNotIn(f"from {token}", text)


if __name__ == "__main__":
    unittest.main()
