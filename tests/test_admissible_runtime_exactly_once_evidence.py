"""RUN_044 exactly-once evidence application tests.

Covers required tests 9-12.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.high_autonomy_controller import HA_NEXT_APPLY_RUNTIME_EVIDENCE

from tests._run044_helpers import COUNTER_GOAL, force_static_verification_final, make_controller, start_run, tick_until

# One deterministic-runtime criterion plus one human-observation criterion:
# the run stays *active* (awaiting human observation) after the runtime
# attempt's evidence is applied, so repeated ticks afterward are a real,
# reachable scenario rather than an already-finalized/inactive run.
STAYS_ACTIVE_GOAL = """Build a widget dashboard.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount.
2. The animation must look smooth and polished.
"""


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class TestExactlyOnceEvidence(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _run_to_completion(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)
            return tick_until(self.controller, max_ticks=10)

    def _run_to_awaiting_human_observation(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, STAYS_ACTIVE_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"widgetCount": 3}}))
            force_static_verification_final(self.controller, self.workspace)
            return tick_until(
                self.controller,
                max_ticks=10,
                stop_modes=("awaiting_human_observation", "stopped", "failed"),
            )

    def test_evidence_applies_exactly_once(self):
        """Required test 9."""
        state = self._run_to_completion()
        summary = state["high_autonomy_summary"]
        self.assertEqual(summary["outcome"], "completed")
        self.assertEqual(len(summary["runtime_attempt_history"]), 1)
        self.assertEqual(summary["metrics"]["runtime_pass_count"], 1)

    def test_repeated_evidence_ready_ticks_are_stable_noops(self):
        """Required test 10: once applied, further ticks must not re-apply or
        re-count anything. Uses a goal that stays active afterward (awaiting
        human observation on an unrelated criterion) so the repeated ticks
        are a real, reachable in-run scenario rather than a finalized run."""
        state = self._run_to_awaiting_human_observation()
        summary_before = state["high_autonomy_summary"]
        self.assertEqual(summary_before["mode"], "awaiting_human_observation")
        for _ in range(3):
            state = self.controller.tick_high_autonomy_run()
        summary_after = state["high_autonomy_summary"]
        self.assertEqual(summary_after["mode"], "awaiting_human_observation")
        self.assertEqual(summary_after["runtime_attempt_history"], summary_before["runtime_attempt_history"])
        self.assertEqual(summary_after["metrics"]["runtime_pass_count"], summary_before["metrics"]["runtime_pass_count"])

    def test_metrics_increment_exactly_once(self):
        """Required test 11."""
        state = self._run_to_completion()
        metrics = state["high_autonomy_summary"]["metrics"]
        self.assertEqual(metrics["runtime_attempt_count"], 1)
        self.assertEqual(metrics["runtime_pass_count"], 1)
        self.assertEqual(metrics["runtime_fail_count"], 0)
        self.assertGreater(metrics["runtime_assertion_count"], 0)

    def test_evidence_refs_are_not_duplicated(self):
        """Required test 12."""
        state = self._run_to_awaiting_human_observation()
        criteria_by_id = {c["criterion_id"]: c for c in state["high_autonomy_summary"]["acceptance_criteria"]}
        runtime_criterion = next(c for c in criteria_by_id.values() if c["verification_disposition"] == "deterministic_runtime")
        refs = list(runtime_criterion["evidence_refs"])
        self.assertEqual(len(refs), len(set(refs)), "evidence_refs must not contain duplicates")
        # Re-tick a few more times; refs must remain stable.
        for _ in range(3):
            state = self.controller.tick_high_autonomy_run()
        criteria_after = {c["criterion_id"]: c for c in state["high_autonomy_summary"]["acceptance_criteria"]}
        self.assertEqual(criteria_after[runtime_criterion["criterion_id"]]["evidence_refs"], refs)

    def test_orchestrator_apply_call_directly_is_idempotent(self):
        """Direct unit-level corroboration of the exactly-once guard, using the
        orchestrator's own attempt-status check (attempt.status ==
        evidence_applied short-circuits the second call)."""
        import time

        import admissible.runtime_verification_orchestrator as rvo
        from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger

        contract = build_mission_contract(COUNTER_GOAL).to_dict()
        ledger = contract_acceptance_ledger(contract)
        with tempfile.TemporaryDirectory() as ws:
            assessment = rvo.assess_runtime_need(contract, ledger, workspace_root=ws)
            provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
            attempt, _ = rvo.prepare_runtime_attempt(
                session_id="idem", mission_contract=contract, ledger=ledger, plan=assessment.plan, provider=provider
            )
            rvo.start_runtime_attempt(attempt=attempt, plan=assessment.plan, provider=provider, control_root=ws)
            for _ in range(50):
                poll = rvo.poll_runtime_attempt(attempt=attempt, control_root=ws)
                if poll.transition_type != "poll_wait":
                    break
                time.sleep(0.02)
            evidence = rvo.find_persisted_evidence(ws, attempt.evidence_id)
            t1 = rvo.apply_runtime_evidence(
                ledger=ledger, plan=assessment.plan, evidence=evidence, mission_contract=contract, attempt=attempt
            )
            t2 = rvo.apply_runtime_evidence(
                ledger=ledger, plan=assessment.plan, evidence=evidence, mission_contract=contract, attempt=attempt
            )
            self.assertTrue(t1.changed)
            self.assertFalse(t2.changed)
            self.assertEqual(t1.semantic_status, t2.semantic_status)


if __name__ == "__main__":
    unittest.main()
