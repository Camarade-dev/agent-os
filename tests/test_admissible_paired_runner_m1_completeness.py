from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "implementation" / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
STARTING_COMMIT = "41942a3ed3a85d4f47b38a29b9d86368523555cd"
SCOPE = {
    "ARCH-02",
    "ARCH-04",
    "ARCH-05",
    "EXEC-01",
    "EXEC-02",
    "EXEC-03",
    "EXEC-04",
    "EXEC-05",
    "BASE-01",
    "BASE-02",
    "FAIR-01",
    "FAIR-02",
    "FAIR-03",
    "FAIR-04",
    "FAIR-05",
    "FAIR-06",
    "FAIR-07",
}
ALLOWED_STATUSES = {
    "UNASSESSED",
    "DESIGNED",
    "IMPLEMENTED",
    "VERIFIED_UNIT",
    "VERIFIED_INTEGRATION",
    "VERIFIED_INSTALLED_PATH",
    "BLOCKED",
    "DEFERRED_EXPLICITLY",
    "NOT_APPLICABLE_WITH_RATIONALE",
}
# Declared here, not read from the matrix: the second bounded repair restores
# EXEC-02 and EXEC-05 to DESIGNED and keeps every requirement whose subject does
# not exist yet no stronger than DESIGNED.
EXPECTED_STATUS = {
    "ARCH-02": "DESIGNED",
    "ARCH-04": "DESIGNED",
    "ARCH-05": "VERIFIED_UNIT",
    "EXEC-01": "VERIFIED_UNIT",
    "EXEC-02": "DESIGNED",
    "EXEC-03": "DESIGNED",
    "EXEC-04": "DESIGNED",
    "EXEC-05": "DESIGNED",
    "BASE-01": "DESIGNED",
    "BASE-02": "VERIFIED_UNIT",
    "FAIR-01": "VERIFIED_UNIT",
    "FAIR-02": "VERIFIED_UNIT",
    "FAIR-03": "VERIFIED_UNIT",
    "FAIR-04": "VERIFIED_UNIT",
    "FAIR-05": "VERIFIED_UNIT",
    "FAIR-06": "VERIFIED_UNIT",
    "FAIR-07": "VERIFIED_UNIT",
}
FORBIDDEN_STATUSES = {"VERIFIED_INTEGRATION", "VERIFIED_INSTALLED_PATH"}


class RequirementCompletenessTests(unittest.TestCase):
    def test_all_83_ids_remain_unique_and_only_scope_records_changed(self) -> None:
        current = json.loads(MATRIX.read_text(encoding="utf-8"))
        baseline_raw = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/PAIRED_RUNNER_REQUIREMENT_MATRIX.json"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        baseline = json.loads(baseline_raw)
        current_records = current["requirements"]
        baseline_records = baseline["requirements"]
        current_ids = [item["requirement_id"] for item in current_records]
        baseline_ids = [item["requirement_id"] for item in baseline_records]
        self.assertEqual(len(current_records), 83)
        self.assertEqual(len(set(current_ids)), 83)
        self.assertEqual(current_ids, baseline_ids)
        self.assertEqual(set(current_ids) & SCOPE, SCOPE)
        self.assertEqual(set(current_ids) - SCOPE, set(baseline_ids) - SCOPE)
        for record in current_records:
            self.assertIn(record["current_status"], ALLOWED_STATUSES, record["requirement_id"])
            self.assertNotIn(record["current_status"], FORBIDDEN_STATUSES, record["requirement_id"])
            if record["requirement_id"] in SCOPE:
                self.assertEqual(
                    record["current_status"],
                    EXPECTED_STATUS[record["requirement_id"]],
                    record["requirement_id"],
                )
                self.assertNotEqual(record["current_status"], "UNASSESSED")
                self.assertTrue(record["implementation_evidence"], record["requirement_id"])
                self.assertTrue(record["validation_evidence"], record["requirement_id"])
                evidence = " ".join(record["implementation_evidence"] + record["validation_evidence"])
                self.assertTrue("M1" in evidence or "test" in evidence.lower(), record["requirement_id"])
            else:
                baseline_record = next(item for item in baseline_records if item["requirement_id"] == record["requirement_id"])
                self.assertEqual(record, baseline_record, record["requirement_id"])


if __name__ == "__main__":
    unittest.main()
