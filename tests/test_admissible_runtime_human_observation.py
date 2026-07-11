"""RUN_044 human-observation controller-level tests (PART J).

Unit-level coverage of admissible.runtime_verification_orchestrator.record_human_observation
lives in test_admissible_runtime_orchestrator.py; this file drives the same
feature through ControlSurfaceController.record_human_observation end to end.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.high_autonomy_controller import HA_MODE_AWAITING_HUMAN_OBSERVATION

from tests._run044_helpers import force_static_verification_final, make_controller, start_run, tick_until

DASHBOARD_GOAL = """Build a widget dashboard.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount.
2. The animation must look smooth and polished.
"""


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class TestHumanObservationControllerFlow(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _reach_awaiting_observation(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, DASHBOARD_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"widgetCount": 3}}))
            force_static_verification_final(self.controller, self.workspace)
            return tick_until(
                self.controller, max_ticks=10, stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed")
            )

    def test_recorded_pass_resolves_and_completes_the_run(self):
        state = self._reach_awaiting_observation()
        self.assertEqual(state["high_autonomy_summary"]["mode"], HA_MODE_AWAITING_HUMAN_OBSERVATION)
        pending = state["high_autonomy_summary"]["human_observation_pending_criterion_ids"]
        self.assertEqual(len(pending), 1)

        result = self.controller.record_human_observation(
            pending[0], actor="qa@example.com", disposition="pass", note="Confirmed smooth in Chrome + Firefox."
        )
        criterion = next(c for c in result["high_autonomy_summary"]["acceptance_criteria"] if c["criterion_id"] == pending[0])
        self.assertEqual(criterion["status"], "verified_pass")
        self.assertTrue(any("qa@example.com" in note for note in criterion["verification_notes"]))

        final = tick_until(self.controller, max_ticks=5)
        summary = final["high_autonomy_summary"]
        self.assertEqual(summary["outcome"], "completed")
        self.assertEqual(summary["metrics"]["human_observation_count"], 1)
        self.assertEqual(summary["metrics"]["human_observation_pass_count"], 1)

    def test_recorded_fail_does_not_complete_the_run(self):
        state = self._reach_awaiting_observation()
        pending = state["high_autonomy_summary"]["human_observation_pending_criterion_ids"]
        self.controller.record_human_observation(pending[0], actor="qa", disposition="fail", note="Stutters on restart.")
        final = self.controller.state_view()
        criterion = next(c for c in final["high_autonomy_summary"]["acceptance_criteria"] if c["criterion_id"] == pending[0])
        self.assertEqual(criterion["status"], "verified_fail")
        self.assertEqual(final["high_autonomy_summary"]["metrics"]["human_observation_fail_count"], 1)

    def test_waive_requires_explicit_rationale_and_is_tracked_distinctly(self):
        state = self._reach_awaiting_observation()
        pending = state["high_autonomy_summary"]["human_observation_pending_criterion_ids"]
        with self.assertRaises(ValueError):
            self.controller.record_human_observation(pending[0], actor="qa", disposition="waive", note="")
        result = self.controller.record_human_observation(
            pending[0], actor="qa", disposition="waive", note="Subjective polish check waived for this milestone."
        )
        criterion = next(c for c in result["high_autonomy_summary"]["acceptance_criteria"] if c["criterion_id"] == pending[0])
        self.assertEqual(criterion["status"], "waived")
        summary = result["high_autonomy_summary"]
        self.assertEqual(summary["metrics"]["human_observation_waiver_count"], 1)
        # A human-observation waiver must never be counted as a genuine
        # human-authority interruption (PART J.51).
        self.assertEqual(summary["metrics"].get("genuine_human_intervention_count", 0), 0)

    def test_human_observation_records_are_stored_separately_from_authority_decisions(self):
        state = self._reach_awaiting_observation()
        pending = state["high_autonomy_summary"]["human_observation_pending_criterion_ids"]
        result = self.controller.record_human_observation(pending[0], actor="qa", disposition="pass", note="ok")
        summary = result["high_autonomy_summary"]
        self.assertEqual(len(summary["human_observation_records"]), 1)
        record = summary["human_observation_records"][0]
        self.assertEqual(record["criterion_id"], pending[0])
        self.assertEqual(record["actor"], "qa")
        self.assertEqual(record["disposition"], "pass")
        self.assertIn("timestamp", record)
        # Distinct storage from human-authority decisions (approve/refuse).
        self.assertEqual(self.controller._session.human_decisions, [])


if __name__ == "__main__":
    unittest.main()
