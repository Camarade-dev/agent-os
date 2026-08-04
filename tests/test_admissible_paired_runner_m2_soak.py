"""Output soak regression tests for the Milestone 2 shared effect substrate.

The regression soak below runs in the ordinary automated suite.  It is large
enough that an unbounded queue or an unbounded retention buffer would show up
immediately, but small enough to run everywhere.  The governing 1,000,000-line /
1 GiB target belongs to the explicit heavy soak command, which is exercised here
only through its recorded report artifact.
"""

from __future__ import annotations

from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from paired_runner_m2_heavy_soak import (  # noqa: E402
    CONTROLLER_RSS_GROWTH_LIMIT_BYTES,
    regression_soak,
)
from admissible.paired_runner.process_supervision import (  # noqa: E402
    CONTROLLER_FIXED_OVERHEAD_BYTES,
    controller_memory_bound,
)


REPORT = Path(__file__).resolve().parents[1] / "implementation" / "M2_OUTPUT_SOAK_REPORT.json"


class RegressionSoakTests(unittest.TestCase):
    def test_a_large_flood_stays_inside_the_declared_retention_bound(self) -> None:
        measurement = regression_soak()
        self.assertEqual(measurement["receipt_status"], "COMPLETED")
        self.assertEqual(measurement["exit_code"], 0)
        self.assertEqual(measurement["total_output_bytes"], 200_000 * 128)
        self.assertEqual(measurement["stdout_retained_bytes"], 65_536)
        self.assertEqual(measurement["stderr_retained_bytes"], 65_536)
        self.assertTrue(measurement["stdout_truncated"])
        self.assertTrue(measurement["stderr_truncated"])
        self.assertLessEqual(
            measurement["controller_peak_retained_output_bytes"], 2 * 65_536
        )
        self.assertEqual(measurement["controller_retention_bound_bytes"], controller_memory_bound(65_536))
        growth = measurement["controller_rss_growth_bytes"]
        if growth is not None:
            self.assertLessEqual(growth, CONTROLLER_RSS_GROWTH_LIMIT_BYTES)
        self.assertTrue(measurement["child_cleanup"]["descendants_reaped"])
        self.assertEqual(measurement["reconciliation_classification"], "RECONCILED_COMPLETE")

    def test_the_documented_controller_bound_is_a_function_of_the_cap_only(self) -> None:
        self.assertEqual(controller_memory_bound(1024), 2 * 1024 + CONTROLLER_FIXED_OVERHEAD_BYTES)
        self.assertEqual(
            controller_memory_bound(1 << 20) - controller_memory_bound(1 << 19), 2 * (1 << 19)
        )


class HeavySoakReportTests(unittest.TestCase):
    """The recorded heavy soak must actually meet the governing target."""

    def test_the_recorded_heavy_soak_meets_the_governing_target(self) -> None:
        measurement = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(measurement["level"], "heavy")
        self.assertEqual(measurement["receipt_status"], "COMPLETED")
        self.assertTrue(measurement["governing_target_met"])
        self.assertGreaterEqual(measurement["total_output_lines"], 1_000_000)
        self.assertGreaterEqual(measurement["total_output_bytes"], 1 << 30)
        self.assertTrue(measurement["controller_memory_within_threshold"])
        self.assertLessEqual(
            measurement["controller_rss_growth_bytes"], CONTROLLER_RSS_GROWTH_LIMIT_BYTES
        )
        self.assertLessEqual(
            measurement["controller_peak_retained_output_bytes"],
            measurement["controller_retention_bound_bytes"],
        )
        self.assertTrue(measurement["child_cleanup"]["descendants_reaped"])
        self.assertEqual(measurement["child_cleanup"]["termination_escalation"], [])


if __name__ == "__main__":
    unittest.main()
