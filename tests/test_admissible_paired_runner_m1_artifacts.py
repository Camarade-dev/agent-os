from __future__ import annotations

from pathlib import Path
import unittest

from admissible.paired_runner.canonical import canonical_bytes, parse_canonical_json
from admissible.paired_runner.schemas import SCHEMA_CATALOG
from admissible.paired_runner.specification import AllowedConditionDifferences


ROOT = Path(__file__).resolve().parents[1]


class M1ArtifactTests(unittest.TestCase):
    def test_m1_json_artifacts_are_canonical_and_match_code_catalog(self) -> None:
        catalog_path = ROOT / "implementation" / "M1_SCHEMA_CATALOG.json"
        allowlist_path = ROOT / "implementation" / "M1_ALLOWED_CONDITION_DIFFERENCES.json"
        report_path = ROOT / "implementation" / "M1_VALIDATION_REPORT.json"
        repair_report_path = ROOT / "implementation" / "M1_BOUNDED_REPAIR_REPORT.json"
        matrix_path = ROOT / "implementation" / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
        catalog = parse_canonical_json(catalog_path.read_bytes(), label=str(catalog_path))
        allowlist = parse_canonical_json(allowlist_path.read_bytes(), label=str(allowlist_path))
        report = parse_canonical_json(report_path.read_bytes(), label=str(report_path))
        repair_report = parse_canonical_json(repair_report_path.read_bytes(), label=str(repair_report_path))
        matrix = parse_canonical_json(matrix_path.read_bytes(), label=str(matrix_path))
        expected_catalog = {
            "package_namespace": "admissible.paired_runner",
            "schema_version": 1,
            "schemas": [descriptor.to_dict() for descriptor in SCHEMA_CATALOG.values()],
        }
        self.assertEqual(catalog, expected_catalog)
        self.assertEqual(canonical_bytes(catalog), catalog_path.read_bytes())
        self.assertEqual(canonical_bytes(allowlist), allowlist_path.read_bytes())
        self.assertEqual(canonical_bytes(report), report_path.read_bytes())
        self.assertEqual(canonical_bytes(repair_report), repair_report_path.read_bytes())
        self.assertEqual(canonical_bytes(matrix), matrix_path.read_bytes())
        self.assertEqual(AllowedConditionDifferences.from_dict(allowlist).to_dict(), allowlist)
        self.assertEqual(len(catalog["schemas"]), 27)
        self.assertEqual(report["schema_count"], 27)
        self.assertEqual(repair_report["schema_count"], 27)
        self.assertEqual(repair_report["new_schema_count"], 8)
        self.assertEqual(
            [finding["id"] for finding in repair_report["repair_findings"]],
            ["M1-R01", "M1-R02", "M1-R03", "M1-R04", "M1-R05"],
        )
        tool_schemas = [item for item in catalog["schemas"] if ".tool." in item["schema_id"]]
        self.assertEqual(len(tool_schemas), 8)
        for descriptor in tool_schemas:
            self.assertTrue(descriptor["field_specs"])
            self.assertIn("effect_classification", descriptor)
            self.assertIn("path_representation", descriptor)
            self.assertIn("bounds", descriptor)
            self.assertIn("result_representation", descriptor)


if __name__ == "__main__":
    unittest.main()
