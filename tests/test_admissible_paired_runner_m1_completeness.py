from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "implementation" / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
STARTING_COMMIT = "148f12cfa349243e81e180257b359f97cef63218"
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
            if record["requirement_id"] in SCOPE:
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
