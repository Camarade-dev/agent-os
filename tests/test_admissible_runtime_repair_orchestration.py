"""RUN_044 runtime repair orchestration tests.

Covers required tests 20-23. A "repair response" is simulated the same way
the existing static-repair loop's own auto-execute step already leaves
things (mode=auto_executing/reviewing, repair_phase=repair_executing then
repair_verifying) rather than hand-authoring a full fake agent response file
-- the RUN_044-owned pieces under test are: packet construction/kind,
routing re-verification through the runtime pipeline instead of the static
one, and preserving unrelated passing evidence.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.high_autonomy_controller import (
    HA_MODE_AUTO_EXECUTING,
    HA_NEXT_START_RUNTIME_VERIFICATION,
    HA_NEXT_WRITE_REPAIR,
    REPAIR_PHASE_REPAIR_VERIFYING,
)

from tests._run044_helpers import TWO_CRITERIA_GOAL, force_static_verification_final, make_controller, start_run


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class TestRuntimeRepairRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_runtime_failure_enters_targeted_repair_with_diagnostics(self):
        """Required test 20."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, TWO_CRITERIA_GOAL, self.workspace)
            # Missing "count" field -> the debug-overlay-fields assertion fails.
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {}}))
            force_static_verification_final(self.controller, self.workspace)

            for _ in range(4):
                state = self.controller.tick_high_autonomy_run()
                if state["high_autonomy_tick"]["planned"] == HA_NEXT_WRITE_REPAIR:
                    break

            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["repair_round_count"], 1)
            packet = summary["repair_packet"]
            self.assertEqual(packet["kind"], "runtime_verification_failure")
            self.assertIn("explicit_ac_001", packet["failed_criteria"])
            self.assertTrue(packet["assertion_diagnostics"])

    def test_repair_preserves_unrelated_passing_evidence_and_reruns_only_affected(self):
        """Required tests 21-23: repair invalidates only the affected runtime
        evidence, preserves passing criteria, and completes on rerun without
        an extra unnecessary provider turn (repair text is written once, and
        re-verification never touches the agent transport again)."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, TWO_CRITERIA_GOAL, self.workspace)
            provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {}})
            self.controller.set_runtime_provider(provider)
            force_static_verification_final(self.controller, self.workspace)

            for _ in range(4):
                state = self.controller.tick_high_autonomy_run()
                if state["high_autonomy_tick"]["planned"] == HA_NEXT_WRITE_REPAIR:
                    break
            summary = state["high_autonomy_summary"]
            criteria_by_id = {c["criterion_id"]: c for c in summary["acceptance_criteria"]}
            # The "no external requests" criterion never failed; it must not
            # have been touched by the repair packet.
            passing_id = next(cid for cid, c in criteria_by_id.items() if cid != "explicit_ac_001")
            self.assertNotIn(passing_id, summary["repair_packet"]["failed_criteria"])

            transport = self.controller._high_autonomy_transport
            instructions_before_repair_simulation = len(transport.written_instructions)

            # Simulate the repair response having already been ingested and
            # auto-executed (existing RUN_029 machinery, untouched by RUN_044).
            ha_state = self.controller._high_autonomy_state()
            ha_state.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
            ha_state.mode = HA_MODE_AUTO_EXECUTING
            self.controller._set_high_autonomy_state(ha_state)
            self.controller._persist()
            provider.scenario["initial_snapshot"] = {"count": 5}

            for _ in range(6):
                state = self.controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break

            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["repair_round_count"], 1, "must not need a second repair round")
            self.assertEqual(
                len(transport.written_instructions),
                instructions_before_repair_simulation,
                "the runtime rerun after repair must not write any further agent instruction",
            )
            history = summary["runtime_attempt_history"]
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["semantic_status"], "runtime_verification_fail")
            self.assertEqual(history[1]["semantic_status"], "runtime_verification_pass")

    def test_runtime_policy_violation_prevents_completion(self):
        """Required test 24."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, TWO_CRITERIA_GOAL, self.workspace)
            self.controller.set_runtime_provider(
                FixtureBrowserRuntimeProvider(
                    {
                        "initial_snapshot": {"count": 5},
                        "external_request_attempts": [{"url": "https://example.invalid/x", "resource_type": "fetch"}],
                    }
                )
            )
            force_static_verification_final(self.controller, self.workspace)

            for _ in range(10):
                state = self.controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break

            summary = state["high_autonomy_summary"]
            self.assertNotEqual(summary["outcome"], "completed")
            criterion = next(c for c in summary["acceptance_criteria"] if c["criterion_id"] == "explicit_ac_001")
            self.assertNotEqual(criterion["status"], "verified_pass")


if __name__ == "__main__":
    unittest.main()
