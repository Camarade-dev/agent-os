"""RUN_045 PART J — unit tests for admissible/high_autonomy_state_invariants.py.

Pure, standalone module (like RUN_043's state_machine.py and RUN_044's
runtime_verification_orchestrator.py): no controller, no transport, no real
model/browser/subprocess calls. These tests exercise the typed wait-condition
vocabulary and the post-repair-verification routing decision directly.
"""

from __future__ import annotations

import unittest

from admissible.high_autonomy_state_invariants import (
    SUPPORTED_WAIT_CONDITIONS,
    WAIT_EVIDENCE_FILE_PENDING,
    WAIT_EXPLICIT_OPERATOR_RETRY,
    WAIT_RUNTIME_WORKER_RUNNING,
    WaitingForAgentSignals,
    check_state_invariants,
    classify_waiting_for_agent_condition,
    plan_post_repair_verification,
    repair_needs_post_write_verification,
    waiting_for_agent_is_valid,
)


def _signals(**overrides) -> WaitingForAgentSignals:
    base = dict(
        is_callable_backend=False,
        backend_step=None,
        pending_invocation_status=None,
        backend_retry_required=False,
        backend_reinvoke_pending=False,
        transport_has_pending_response=False,
        runtime_worker_active=False,
    )
    base.update(overrides)
    return WaitingForAgentSignals(**base)


class TestClassifyWaitingForAgentCondition(unittest.TestCase):
    def test_the_cli002_combination_is_invalid(self) -> None:
        # backend_step=response_consumed, pending_invocation_status=consumed,
        # no retry/reinvoke pending -- the exact reported combination.
        signals = _signals(
            is_callable_backend=True,
            backend_step="response_consumed",
            pending_invocation_status="consumed",
            backend_retry_required=False,
            backend_reinvoke_pending=False,
        )
        self.assertIsNone(classify_waiting_for_agent_condition(signals))
        self.assertFalse(waiting_for_agent_is_valid(signals))

    def test_runtime_worker_active_always_wins_first(self) -> None:
        signals = _signals(runtime_worker_active=True, is_callable_backend=True)
        condition = classify_waiting_for_agent_condition(signals)
        self.assertEqual(condition, (WAIT_RUNTIME_WORKER_RUNNING, "runtime_attempt"))

    def test_callable_backend_with_response_ready_is_valid(self) -> None:
        signals = _signals(is_callable_backend=True, pending_invocation_status="response_ready")
        condition = classify_waiting_for_agent_condition(signals)
        self.assertEqual(condition, (WAIT_EVIDENCE_FILE_PENDING, "response_ready"))

    def test_callable_backend_awaiting_retry_is_valid(self) -> None:
        signals = _signals(is_callable_backend=True, backend_retry_required=True)
        condition = classify_waiting_for_agent_condition(signals)
        self.assertEqual(condition, (WAIT_EXPLICIT_OPERATOR_RETRY, "backend_retry"))

    def test_callable_backend_with_nothing_pending_is_invalid(self) -> None:
        signals = _signals(is_callable_backend=True, pending_invocation_status=None)
        self.assertIsNone(classify_waiting_for_agent_condition(signals))

    def test_file_bridge_with_pending_response_is_valid(self) -> None:
        signals = _signals(transport_has_pending_response=True)
        condition = classify_waiting_for_agent_condition(signals)
        self.assertEqual(condition, (WAIT_EVIDENCE_FILE_PENDING, "response_file"))

    def test_file_bridge_with_reinvoke_pending_is_valid(self) -> None:
        signals = _signals(backend_reinvoke_pending=True)
        condition = classify_waiting_for_agent_condition(signals)
        self.assertEqual(condition, (WAIT_EXPLICIT_OPERATOR_RETRY, "backend_retry"))

    def test_file_bridge_with_nothing_pending_is_invalid(self) -> None:
        signals = _signals()
        self.assertIsNone(classify_waiting_for_agent_condition(signals))

    def test_every_returned_condition_type_is_in_the_closed_vocabulary(self) -> None:
        scenarios = [
            _signals(runtime_worker_active=True),
            _signals(is_callable_backend=True, pending_invocation_status="queued"),
            _signals(is_callable_backend=True, backend_retry_required=True),
            _signals(transport_has_pending_response=True),
            _signals(backend_reinvoke_pending=True),
        ]
        for signals in scenarios:
            condition = classify_waiting_for_agent_condition(signals)
            self.assertIsNotNone(condition)
            condition_type, condition_id = condition
            self.assertIn(condition_type, SUPPORTED_WAIT_CONDITIONS)
            self.assertTrue(condition_id)


class TestPostRepairVerificationRouting(unittest.TestCase):
    def test_repair_needs_post_write_verification_only_for_post_write_phases(self) -> None:
        self.assertTrue(repair_needs_post_write_verification("repair_executing"))
        self.assertTrue(repair_needs_post_write_verification("repair_verifying"))
        for phase in ("none", "repair_needed", "writing_repair_instruction", "awaiting_repair_response"):
            self.assertFalse(repair_needs_post_write_verification(phase))

    def test_static_repair_routes_to_bounded_verification(self) -> None:
        decision = plan_post_repair_verification(
            repair_phase="repair_verifying", runtime_repair_kind=None
        )
        self.assertEqual(decision, "run_bounded_verification")

    def test_runtime_sourced_repair_routes_to_runtime_verification(self) -> None:
        decision = plan_post_repair_verification(
            repair_phase="repair_executing",
            runtime_repair_kind="runtime_verification_failure",
        )
        self.assertEqual(decision, "start_runtime_verification")

        decision2 = plan_post_repair_verification(
            repair_phase="repair_verifying",
            runtime_repair_kind="runtime_instrumentation_gap",
        )
        self.assertEqual(decision2, "start_runtime_verification")

    def test_no_post_write_phase_returns_none(self) -> None:
        decision = plan_post_repair_verification(repair_phase="none", runtime_repair_kind=None)
        self.assertIsNone(decision)


class TestCheckStateInvariants(unittest.TestCase):
    def _base_kwargs(self, **overrides) -> dict:
        base = dict(
            active=True,
            mode="running",
            next_action="write_instruction",
            repair_phase="none",
            runtime_repair_kind=None,
            human_critical_pending=False,
            runtime_worker_active=False,
            human_observation_pending=False,
            technical_pause_active=False,
            pending_terminal_eligibility=False,
            waiting_for_agent_signals=_signals(),
        )
        base.update(overrides)
        return base

    def test_clean_state_has_no_violations(self) -> None:
        violations = check_state_invariants(**self._base_kwargs())
        self.assertEqual(violations, [])

    def test_inactive_run_is_never_checked(self) -> None:
        violations = check_state_invariants(**self._base_kwargs(active=False, mode="waiting_for_agent"))
        self.assertEqual(violations, [])

    def test_reasonless_waiting_for_agent_is_flagged(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(mode="waiting_for_agent", next_action="none")
        )
        codes = [v.code for v in violations]
        self.assertIn("waiting_for_agent_without_pending_condition", codes)

    def test_legitimate_waiting_for_agent_is_not_flagged(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(
                mode="waiting_for_agent",
                next_action="wait_for_agent_response",
                waiting_for_agent_signals=_signals(
                    is_callable_backend=True, pending_invocation_status="response_ready"
                ),
            )
        )
        codes = [v.code for v in violations]
        self.assertNotIn("waiting_for_agent_without_pending_condition", codes)

    def test_repair_verifying_without_scheduled_verification_is_flagged(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(
                mode="waiting_for_agent",
                next_action="none",
                repair_phase="repair_verifying",
                waiting_for_agent_signals=_signals(
                    is_callable_backend=True,
                    backend_step="response_consumed",
                    pending_invocation_status="consumed",
                ),
            )
        )
        codes = [v.code for v in violations]
        self.assertIn("repair_verifying_without_verification_scheduled", codes)

    def test_repair_verifying_with_scheduled_verification_is_not_flagged(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(
                mode="verifying",
                next_action="run_bounded_verification",
                repair_phase="repair_verifying",
            )
        )
        codes = [v.code for v in violations]
        self.assertNotIn("repair_verifying_without_verification_scheduled", codes)

    def test_next_action_none_without_justification_is_flagged(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(mode="running", next_action="none")
        )
        codes = [v.code for v in violations]
        self.assertIn("next_action_none_without_justification", codes)

    def test_next_action_none_is_fine_during_technical_pause(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(mode="technical_pause", next_action="none", technical_pause_active=True)
        )
        codes = [v.code for v in violations]
        self.assertNotIn("next_action_none_without_justification", codes)

    def test_next_action_none_is_fine_during_runtime_worker_activity(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(mode="runtime_verifying", next_action="none", runtime_worker_active=True)
        )
        codes = [v.code for v in violations]
        self.assertNotIn("next_action_none_without_justification", codes)

    def test_next_action_none_is_fine_during_human_observation(self) -> None:
        violations = check_state_invariants(
            **self._base_kwargs(
                mode="awaiting_human_observation", next_action="none", human_observation_pending=True
            )
        )
        codes = [v.code for v in violations]
        self.assertNotIn("next_action_none_without_justification", codes)


if __name__ == "__main__":
    unittest.main()
