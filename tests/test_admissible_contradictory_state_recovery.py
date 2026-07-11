"""RUN_045 PART J — session-load / pre-tick contradictory-state reconciliation.

Covers PART D: a persisted, internally-contradictory
``mode=waiting_for_agent`` combination (the cli-002 livelock shape) is
detected and repaired before planning/ticking, as a pure relabeling of
already-persisted state -- never a new model turn, repair round, or
human-intervention metric.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import (
    HA_MODE_VERIFYING,
    HA_MODE_WAITING_FOR_AGENT,
    HA_NEXT_VERIFY,
    REPAIR_PHASE_REPAIR_VERIFYING,
    _reconcile_high_autonomy_state,
    tick_high_autonomy_run,
)
from admissible.high_autonomy_state_invariants import (
    ReconciliationSignals,
    WaitingForAgentSignals,
    reconcile_contradictory_state,
)


def _stuck_signals() -> WaitingForAgentSignals:
    return WaitingForAgentSignals(
        is_callable_backend=True,
        backend_step="response_consumed",
        pending_invocation_status="consumed",
        backend_retry_required=False,
        backend_reinvoke_pending=False,
        transport_has_pending_response=False,
        runtime_worker_active=False,
    )


class TestReconcileContradictoryStatePure(unittest.TestCase):
    def test_cli002_combination_recovers_to_verifying(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="repair_verifying",
            runtime_repair_kind=None,
            pending_useful_operation_count=0,
            active_blocked_count=0,
            waiting_for_agent_signals=_stuck_signals(),
        )
        result = reconcile_contradictory_state(signals)
        self.assertTrue(result.changed)
        self.assertEqual(result.new_mode, "verifying")
        self.assertEqual(result.new_next_action, "run_bounded_verification")
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(
            result.violations[0].code, "waiting_for_agent_without_pending_condition"
        )

    def test_runtime_sourced_repair_recovers_to_runtime_verifying(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="repair_executing",
            runtime_repair_kind="runtime_verification_failure",
            pending_useful_operation_count=0,
            active_blocked_count=0,
            waiting_for_agent_signals=_stuck_signals(),
        )
        result = reconcile_contradictory_state(signals)
        self.assertTrue(result.changed)
        self.assertEqual(result.new_mode, "runtime_verifying")
        self.assertEqual(result.new_next_action, "start_runtime_verification")

    def test_legitimate_wait_is_never_touched(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="repair_verifying",
            runtime_repair_kind=None,
            pending_useful_operation_count=0,
            active_blocked_count=0,
            waiting_for_agent_signals=WaitingForAgentSignals(
                is_callable_backend=True,
                backend_step="response_ready",
                pending_invocation_status="response_ready",
                backend_retry_required=False,
                backend_reinvoke_pending=False,
                transport_has_pending_response=False,
                runtime_worker_active=False,
            ),
        )
        result = reconcile_contradictory_state(signals)
        self.assertFalse(result.changed)

    def test_pending_useful_operation_blocks_reconciliation(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="repair_verifying",
            runtime_repair_kind=None,
            pending_useful_operation_count=1,
            active_blocked_count=0,
            waiting_for_agent_signals=_stuck_signals(),
        )
        result = reconcile_contradictory_state(signals)
        self.assertFalse(result.changed)

    def test_active_blocker_blocks_reconciliation(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="repair_verifying",
            runtime_repair_kind=None,
            pending_useful_operation_count=0,
            active_blocked_count=1,
            waiting_for_agent_signals=_stuck_signals(),
        )
        result = reconcile_contradictory_state(signals)
        self.assertFalse(result.changed)

    def test_non_waiting_mode_is_never_touched(self) -> None:
        signals = ReconciliationSignals(
            mode="running",
            repair_phase="repair_verifying",
            runtime_repair_kind=None,
            pending_useful_operation_count=0,
            active_blocked_count=0,
            waiting_for_agent_signals=_stuck_signals(),
        )
        result = reconcile_contradictory_state(signals)
        self.assertFalse(result.changed)

    def test_no_repair_pending_still_flags_and_neutralizes_next_action(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="none",
            runtime_repair_kind=None,
            pending_useful_operation_count=0,
            active_blocked_count=0,
            waiting_for_agent_signals=_stuck_signals(),
        )
        result = reconcile_contradictory_state(signals)
        self.assertTrue(result.changed)
        self.assertIsNone(result.new_mode)
        self.assertEqual(result.new_next_action, "none")
        self.assertEqual(len(result.violations), 1)


class TestReconciliationIntegration(unittest.TestCase):
    def _build_stuck_controller(self) -> ControlSurfaceController:
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal("Create result.txt locally.")
        controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
        ha = controller._high_autonomy_state()
        ha.mode = HA_MODE_WAITING_FOR_AGENT
        ha.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
        ha.repair_round_count = 1
        ha.transport_kind = "callable_backend"
        ha.backend_step = "response_consumed"
        ha.pending_agent_invocation = {
            "invocation_id": "invoke_stuck",
            "instruction_id": "instr_1",
            "backend_id": "fixture",
            "session_id": "sess_1",
            "turn_number": 1,
            "status": "consumed",
        }
        ha.backend_retry_required = False
        ha.backend_reinvoke_pending = False
        ha.next_action = "none"
        controller._set_high_autonomy_state(ha)
        return controller

    def test_reconcile_helper_repairs_stuck_state_directly(self) -> None:
        controller = self._build_stuck_controller()
        ha = controller._high_autonomy_state()
        changed = _reconcile_high_autonomy_state(controller, ha, transport=None)
        self.assertTrue(changed)
        self.assertEqual(ha.mode, HA_MODE_VERIFYING)
        self.assertEqual(ha.next_action, HA_NEXT_VERIFY)
        self.assertEqual(ha.repair_round_count, 1, "reconciliation must never consume a repair round")
        records = [
            r for r in controller._session.governance_records
            if r.get("event_type") == "state_invariant_reconciliation"
        ]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["old_mode"], HA_MODE_WAITING_FOR_AGENT)
        self.assertEqual(records[0]["new_mode"], HA_MODE_VERIFYING)

    def test_tick_reconciles_before_planning_and_never_relies_on_ordinary_livelock(self) -> None:
        controller = self._build_stuck_controller()
        ha = controller._high_autonomy_state()
        ha.auto_tick_safe = True
        controller._set_high_autonomy_state(ha)
        state = tick_high_autonomy_run(controller)
        summary = state["high_autonomy_summary"]
        # A single tick must already have escaped the reasonless wait -- this
        # is exactly the livelock reported against control_session_89d4376c8c43.
        self.assertNotEqual(summary["mode"], HA_MODE_WAITING_FOR_AGENT)
        self.assertNotEqual(summary["current_step"], "internal_livelock")
        governance_records = controller._session.governance_records
        self.assertTrue(
            any(r.get("event_type") == "state_invariant_reconciliation" for r in governance_records)
        )

    def test_reconciliation_does_not_fire_on_a_healthy_state(self) -> None:
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal("Create result.txt locally.")
        controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
        ha = controller._high_autonomy_state()
        changed = _reconcile_high_autonomy_state(controller, ha, transport=None)
        self.assertFalse(changed)
        self.assertEqual(
            [
                r for r in controller._session.governance_records
                if r.get("event_type") == "state_invariant_reconciliation"
            ],
            [],
        )


if __name__ == "__main__":
    unittest.main()
