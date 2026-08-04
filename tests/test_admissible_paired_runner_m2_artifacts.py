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
from admissible.paired_runner.schemas import SCHEMA_CATALOG  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = ROOT / "implementation"
M1_STARTING_COMMIT = "5b5c3874f1929e77dbc3e2f71aa7f26d675a2705"
M2_ARTIFACTS = (
    "M2_CUMULATIVE_SCHEMA_CATALOG.json",
    "M2_CRASH_MATRIX.json",
    "M2_OUTPUT_SOAK_REPORT.json",
    "M2_VALIDATION_REPORT.json",
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
        expected_m2 = [item.to_dict() for item in M2_OBSERVATION_SCHEMAS.values()] + [
            item.to_dict() for item in M2_LEDGER_SCHEMAS.values()
        ]
        self.assertEqual(catalog["milestone_2_schemas"], expected_m2)
        self.assertEqual(catalog["milestone_1_schema_count"], 29)
        self.assertEqual(catalog["milestone_2_schema_count"], 9)
        self.assertEqual(catalog["cumulative_schema_count"], 38)
        self.assertIn("preserved unchanged", catalog["migration_note"])

    def test_the_crash_matrix_artifact_matches_the_declared_test_table(self) -> None:
        matrix = parse_canonical_json((IMPLEMENTATION / "M2_CRASH_MATRIX.json").read_bytes())
        self.assertEqual(matrix["fault_point_count"], 13)
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
        self.assertEqual(matrix["corruption_fixture_count"], len(CORRUPTION_TARGETS) * 2)
        self.assertEqual(matrix["corruption_fixture_count"], 24)

    def test_the_validation_report_records_the_exact_counts_and_verdict(self) -> None:
        report = parse_canonical_json((IMPLEMENTATION / "M2_VALIDATION_REPORT.json").read_bytes())
        self.assertEqual(report["starting_commit"], M1_STARTING_COMMIT)
        self.assertEqual(report["branch"], "paired-runner/m2-shared-effect-substrate")
        self.assertEqual(report["terminal_verdict"], "SHARED_EFFECT_SUBSTRATE_VERIFIED")
        self.assertEqual(report["crash_point_count"], 13)
        self.assertEqual(report["corruption_fixture_count"], 24)
        self.assertFalse(report["boundary_audit"]["milestone_3_started"])
        for boundary, crossed in report["boundary_audit"].items():
            self.assertFalse(crossed, boundary)
        for record in report["requirement_dispositions"]:
            self.assertNotEqual(record["status"], "VERIFIED_INSTALLED_PATH")
        self.assertTrue(report["known_limitations"])

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
                "canonical.py",
                "comparison.py",
                "durable_store.py",
                "effect_ledger.py",
                "effects.py",
                "identities.py",
                "observation.py",
                "process_supervision.py",
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
            "socket",
            "http",
        )
        for path in (ROOT / "admissible" / "paired_runner").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                with self.subTest(module=path.name, forbidden=token):
                    self.assertNotIn(f"import {token}", text)
                    self.assertNotIn(f"from {token}", text)


if __name__ == "__main__":
    unittest.main()
