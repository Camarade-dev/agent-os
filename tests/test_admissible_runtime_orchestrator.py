"""RUN_044 unit tests for admissible.runtime_verification_orchestrator.

Exercises the narrow orchestration API directly (no ControlSurfaceController):
assess/prepare/start/poll/apply/cancel/reconcile, plus human observation and
canonical metrics. Controller-level integration is covered by
tests/test_admissible_runtime_controller_integration.py and friends.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger
from admissible.runtime_orchestration_models import (
    STATUS_EVIDENCE_APPLIED,
    STATUS_EVIDENCE_READY,
    STATUS_INTERRUPTED,
    STATUS_PREPARED,
    STATUS_RUNNING,
    STATUS_UNAVAILABLE,
)
import admissible.runtime_verification_orchestrator as rvo

GOAL = """Build a tiny counter app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__APP__ with a snapshot returning at least: count.
"""


def _contract_and_ledger():
    contract = build_mission_contract(GOAL).to_dict()
    ledger = contract_acceptance_ledger(contract)
    return contract, ledger


class TestAssessRuntimeNeed(unittest.TestCase):
    def test_required_when_deterministic_runtime_criterion_unresolved(self):
        contract, ledger = _contract_and_ledger()
        with tempfile.TemporaryDirectory() as ws:
            assessment = rvo.assess_runtime_need(contract, ledger, workspace_root=ws)
            self.assertTrue(assessment.required)
            self.assertEqual(assessment.executable_now_criterion_ids, ["explicit_ac_001"])

    def test_not_required_once_criterion_is_verified_pass(self):
        contract, ledger = _contract_and_ledger()
        ledger[0]["status"] = "verified_pass"
        with tempfile.TemporaryDirectory() as ws:
            assessment = rvo.assess_runtime_need(contract, ledger, workspace_root=ws)
            self.assertFalse(assessment.required)

    def test_not_required_without_contract_or_workspace(self):
        _, ledger = _contract_and_ledger()
        self.assertFalse(rvo.assess_runtime_need(None, ledger, workspace_root="/tmp").required)
        self.assertFalse(rvo.assess_runtime_need({"a": 1}, ledger, workspace_root=None).required)


class TestPrepareValidateStart(unittest.TestCase):
    def setUp(self):
        self.contract, self.ledger = _contract_and_ledger()
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _plan(self):
        assessment = rvo.assess_runtime_need(self.contract, self.ledger, workspace_root=self.workspace)
        self.assertIsNotNone(assessment.plan)
        return assessment.plan

    def test_prepare_rejects_plan_referencing_unknown_criterion(self):
        plan = self._plan()
        bad_ledger = [c for c in self.ledger if c["criterion_id"] != "explicit_ac_001"]
        provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 1}})
        attempt, transition = rvo.prepare_runtime_attempt(
            session_id="s1",
            mission_contract=self.contract,
            ledger=bad_ledger,
            plan=plan,
            provider=provider,
        )
        self.assertIsNone(attempt)
        self.assertEqual(transition.semantic_status, "verification_plan_incomplete")

    def test_prepare_rejects_plan_workspace_mismatch(self):
        plan = self._plan()
        provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 1}})
        attempt, transition = rvo.prepare_runtime_attempt(
            session_id="s1",
            mission_contract=self.contract,
            ledger=self.ledger,
            plan=plan,
            provider=provider,
        )
        self.assertIsNotNone(attempt)  # sanity: same workspace, should pass
        # Now corrupt the plan's workspace_root and confirm validate_runtime_plan catches it.
        errors = rvo.validate_runtime_plan(
            plan, mission_contract=self.contract, ledger=self.ledger, authorized_workspace_root=self.workspace + "_other"
        )
        self.assertTrue(errors)

    def test_prepare_records_affected_artifact_hashes(self):
        plan = self._plan()
        provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 1}})
        operation_records = [
            {"outcome": "executed_mutation", "path": "index.html", "result_sha256": "abc123"}
        ]
        attempt, _ = rvo.prepare_runtime_attempt(
            session_id="s1",
            mission_contract=self.contract,
            ledger=self.ledger,
            plan=plan,
            provider=provider,
            operation_records=operation_records,
        )
        self.assertEqual(attempt.affected_artifact_hashes, {"index.html": "abc123"})
        self.assertEqual(attempt.status, STATUS_PREPARED)
        self.assertEqual(attempt.criterion_ids, ["explicit_ac_001"])

    def test_start_capability_gap_is_synchronous_and_writes_evidence(self):
        plan = self._plan()
        provider = FixtureBrowserRuntimeProvider({"available": False, "unavailable_reason": "no_browser"})
        attempt, _ = rvo.prepare_runtime_attempt(
            session_id="s1", mission_contract=self.contract, ledger=self.ledger, plan=plan, provider=provider
        )
        transition = rvo.start_runtime_attempt(attempt=attempt, plan=plan, provider=provider, control_root=self.workspace)
        self.assertEqual(transition.transition_type, "capability_gap")
        self.assertEqual(attempt.status, STATUS_UNAVAILABLE)
        self.assertIsNotNone(attempt.evidence_id)
        evidence = rvo.find_persisted_evidence(self.workspace, attempt.evidence_id)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.status, "verification_capability_gap")

    def test_start_available_spawns_worker_and_returns_promptly(self):
        plan = self._plan()
        provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
        attempt, _ = rvo.prepare_runtime_attempt(
            session_id="s2", mission_contract=self.contract, ledger=self.ledger, plan=plan, provider=provider
        )
        started_at = time.perf_counter()
        transition = rvo.start_runtime_attempt(attempt=attempt, plan=plan, provider=provider, control_root=self.workspace)
        elapsed = time.perf_counter() - started_at
        self.assertLess(elapsed, 1.0, "start_runtime_attempt must return promptly, never block on the browser run")
        self.assertEqual(transition.transition_type, "started")
        self.assertIn(attempt.status, (STATUS_RUNNING, "queued"))

        for _ in range(50):
            poll = rvo.poll_runtime_attempt(attempt=attempt, control_root=self.workspace)
            if poll.transition_type != "poll_wait":
                break
            time.sleep(0.02)
        self.assertEqual(attempt.status, STATUS_EVIDENCE_READY)

    def test_single_flight_second_start_is_a_noop_for_same_session(self):
        # The fixture provider resolves near-instantly, so relying on real
        # thread timing here would be flaky; instead forge a still-alive
        # worker directly in the registry (the same state a real slow
        # browser attempt would leave it in) and confirm start_runtime_attempt
        # refuses to start a second one for the same session.
        plan = self._plan()
        provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
        session_id = "same-session"

        class _NeverDoneWorker:
            attempt_id = "forced-alive-worker"

            def is_alive(self):
                return True

        with rvo._REGISTRY_LOCK:
            rvo._WORKERS[session_id] = _NeverDoneWorker()
        try:
            attempt2, _ = rvo.prepare_runtime_attempt(
                session_id=session_id, mission_contract=self.contract, ledger=self.ledger, plan=plan, provider=provider
            )
            transition2 = rvo.start_runtime_attempt(attempt=attempt2, plan=plan, provider=provider, control_root=self.workspace)
            self.assertEqual(transition2.transition_type, "start_single_flight_noop")
            self.assertFalse(transition2.changed)
        finally:
            with rvo._REGISTRY_LOCK:
                rvo._WORKERS.pop(session_id, None)


class TestApplyEvidenceExactlyOnce(unittest.TestCase):
    def setUp(self):
        self.contract, self.ledger = _contract_and_ledger()
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = self._tmp.name
        assessment = rvo.assess_runtime_need(self.contract, self.ledger, workspace_root=self.workspace)
        self.plan = assessment.plan
        self.provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
        self.attempt, _ = rvo.prepare_runtime_attempt(
            session_id="apply-test", mission_contract=self.contract, ledger=self.ledger, plan=self.plan, provider=self.provider
        )
        rvo.start_runtime_attempt(attempt=self.attempt, plan=self.plan, provider=self.provider, control_root=self.workspace)
        for _ in range(50):
            poll = rvo.poll_runtime_attempt(attempt=self.attempt, control_root=self.workspace)
            if poll.transition_type != "poll_wait":
                break
            time.sleep(0.02)
        self.evidence = rvo.find_persisted_evidence(self.workspace, self.attempt.evidence_id)

    def tearDown(self):
        self._tmp.cleanup()

    def test_apply_marks_criterion_verified_pass_exactly_once(self):
        t1 = rvo.apply_runtime_evidence(
            ledger=self.ledger, plan=self.plan, evidence=self.evidence, mission_contract=self.contract, attempt=self.attempt
        )
        self.assertTrue(t1.changed)
        self.assertEqual(t1.semantic_status, "runtime_verification_pass")
        self.assertEqual(self.ledger[0]["status"], "verified_pass")
        refs_after_first = list(self.ledger[0]["evidence_refs"])

        t2 = rvo.apply_runtime_evidence(
            ledger=self.ledger, plan=self.plan, evidence=self.evidence, mission_contract=self.contract, attempt=self.attempt
        )
        self.assertFalse(t2.changed)
        self.assertEqual(self.ledger[0]["evidence_refs"], refs_after_first, "evidence refs must not duplicate on a repeated apply")

    def test_apply_extra_carries_coverage_reports_and_assertion_counts(self):
        t1 = rvo.apply_runtime_evidence(
            ledger=self.ledger, plan=self.plan, evidence=self.evidence, mission_contract=self.contract, attempt=self.attempt
        )
        self.assertIn("contract_ledger_coverage_report", t1.extra)
        self.assertIn("verification_plan_coverage_report", t1.extra)
        self.assertGreater(t1.extra["assertion_count"], 0)
        self.assertEqual(t1.extra["assertion_fail_count"], 0)


class TestReconcileOnLoad(unittest.TestCase):
    def setUp(self):
        self.contract, self.ledger = _contract_and_ledger()
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = self._tmp.name
        assessment = rvo.assess_runtime_need(self.contract, self.ledger, workspace_root=self.workspace)
        self.plan = assessment.plan
        self.provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})

    def tearDown(self):
        self._tmp.cleanup()

    def test_running_attempt_with_no_owned_worker_is_marked_interrupted(self):
        attempt, _ = rvo.prepare_runtime_attempt(
            session_id="reconcile-1", mission_contract=self.contract, ledger=self.ledger, plan=self.plan, provider=self.provider
        )
        attempt.status = STATUS_RUNNING  # forge: never actually started, no owned worker
        transition = rvo.reconcile_runtime_state_on_load(attempt=attempt, control_root=self.workspace)
        self.assertEqual(transition.transition_type, "reconcile_interrupted")
        self.assertEqual(attempt.status, STATUS_INTERRUPTED)
        self.assertEqual(attempt.cleanup_status, "unknown_process_state_not_tracked")
        self.assertIsNotNone(attempt.failure_message)

    def test_running_attempt_with_matching_persisted_evidence_recovers_without_relaunch(self):
        attempt, _ = rvo.prepare_runtime_attempt(
            session_id="reconcile-2", mission_contract=self.contract, ledger=self.ledger, plan=self.plan, provider=self.provider
        )
        rvo.start_runtime_attempt(attempt=attempt, plan=self.plan, provider=self.provider, control_root=self.workspace)
        for _ in range(50):
            poll = rvo.poll_runtime_attempt(attempt=attempt, control_root=self.workspace)
            if poll.transition_type != "poll_wait":
                break
            time.sleep(0.02)
        self.assertEqual(attempt.status, STATUS_EVIDENCE_READY)
        # Forge: pretend it was still "running" when the session reloaded.
        attempt.status = STATUS_RUNNING
        call_count = {"n": 0}
        real_provider_detect = self.provider.detect_capability

        def _spy(*args, **kwargs):
            call_count["n"] += 1
            return real_provider_detect(*args, **kwargs)

        self.provider.detect_capability = _spy
        transition = rvo.reconcile_runtime_state_on_load(attempt=attempt, control_root=self.workspace)
        self.assertEqual(transition.transition_type, "reconcile_recovered_evidence")
        self.assertEqual(attempt.status, STATUS_EVIDENCE_READY)
        self.assertEqual(call_count["n"], 0, "recovery must not touch the provider / relaunch a browser")


class TestCancel(unittest.TestCase):
    def test_cancel_active_attempt_marks_cancelled_and_cleans_up(self):
        contract, ledger = _contract_and_ledger()
        with tempfile.TemporaryDirectory() as workspace:
            assessment = rvo.assess_runtime_need(contract, ledger, workspace_root=workspace)
            provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
            attempt, _ = rvo.prepare_runtime_attempt(
                session_id="cancel-1", mission_contract=contract, ledger=ledger, plan=assessment.plan, provider=provider
            )
            rvo.start_runtime_attempt(attempt=attempt, plan=assessment.plan, provider=provider, control_root=workspace)
            transition = rvo.cancel_runtime_attempt(attempt=attempt)
            self.assertEqual(transition.semantic_status, "cancelled")
            self.assertEqual(attempt.status, "cancelled")
            self.assertFalse(rvo.has_active_worker("cancel-1"))


class TestHumanObservation(unittest.TestCase):
    def test_pass_marks_verified_pass_and_records_actor_note(self):
        _, ledger = _contract_and_ledger()
        ledger[0]["verification_disposition"] = "human_observation_required"
        record, transition = rvo.record_human_observation(
            ledger=ledger, criterion_id=ledger[0]["criterion_id"], actor="alice", disposition="pass", note="Looks smooth."
        )
        self.assertEqual(ledger[0]["status"], "verified_pass")
        self.assertEqual(record.actor, "alice")
        self.assertIn(record.observation_id, ledger[0]["evidence_refs"])
        self.assertEqual(transition.semantic_status, "human_observation_pass")

    def test_waive_requires_rationale(self):
        _, ledger = _contract_and_ledger()
        with self.assertRaises(ValueError):
            rvo.record_human_observation(
                ledger=ledger, criterion_id=ledger[0]["criterion_id"], actor="alice", disposition="waive", note="   "
            )

    def test_unknown_criterion_id_raises(self):
        _, ledger = _contract_and_ledger()
        with self.assertRaises(ValueError):
            rvo.record_human_observation(
                ledger=ledger, criterion_id="does_not_exist", actor="alice", disposition="pass", note="x"
            )

    def test_invalid_disposition_raises(self):
        _, ledger = _contract_and_ledger()
        with self.assertRaises(ValueError):
            rvo.record_human_observation(
                ledger=ledger, criterion_id=ledger[0]["criterion_id"], actor="alice", disposition="maybe", note="x"
            )


class TestBuildRuntimeMetrics(unittest.TestCase):
    def test_counts_are_derived_from_history_entries(self):
        history = [
            {"runtime_plan_sha256": "a", "semantic_status": "runtime_verification_pass", "assertion_count": 3, "assertion_pass_count": 3},
            {"runtime_plan_sha256": "a", "retry_of_attempt_id": "x", "semantic_status": "runtime_verification_fail", "assertion_count": 1, "assertion_fail_count": 1},
            {"runtime_plan_sha256": "b", "semantic_status": "runtime_verification_capability_gap"},
        ]
        metrics = rvo.build_runtime_metrics(history)
        self.assertEqual(metrics["runtime_attempt_count"], 3)
        self.assertEqual(metrics["runtime_plan_count"], 2)
        self.assertEqual(metrics["runtime_retry_count"], 1)
        self.assertEqual(metrics["runtime_pass_count"], 1)
        self.assertEqual(metrics["runtime_fail_count"], 1)
        self.assertEqual(metrics["runtime_capability_gap_count"], 1)
        self.assertEqual(metrics["runtime_assertion_count"], 4)

    def test_empty_history_is_all_zero(self):
        metrics = rvo.build_runtime_metrics([])
        self.assertTrue(all(v == 0 for v in metrics.values()))


if __name__ == "__main__":
    unittest.main()
