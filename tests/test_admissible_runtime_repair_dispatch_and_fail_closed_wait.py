"""RUN_054 — runtime_instrumentation_gap repair dispatch + fail-closed wait.

Fixes a real class of bug: a persisted session had ``repair_phase ==
"repair_needed"``, ``runtime_repair_kind == "runtime_instrumentation_gap"``,
and a non-empty ``repair_packet.gap_criteria`` (four criterion ids) with
repair budget remaining, but ``mode == "waiting_for_agent"``,
``next_action == "none"``, and ``pending_agent_invocation == None`` -- no
pending condition of any kind.

Root cause: ``_can_start_repair`` only ever consulted the STATIC acceptance
ledger's ``verified_fail`` criteria (via ``_repairable_verification_failures``/
``runtime_failed_criterion_ids``). A ``runtime_instrumentation_gap``
criterion's ledger status is ``open``, never ``verified_fail`` (see
``admissible.browser_runtime.ledger_integration``'s
``CRITERION_STATUS_GAP -> "open"`` mapping), so that list is legitimately
always empty for this repair kind -- ``_can_start_repair`` returned False,
``_plan_next_action`` fell through every branch to its final
``wait_for_agent_response`` default, and reconciliation
(``high_autonomy_state_invariants.reconcile_contradictory_state``) detected
the same invalid combination and re-persisted it, unchanged, forever --
producing an infinite loop of ``state_invariant_reconciliation`` governance
records instead of ever pausing.

No real model/Cursor CLI/browser-provider calls -- fixture doubles only.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import FixtureAgentBackend
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import (
    HA_MODE_TECHNICAL_PAUSE,
    HA_MODE_WAITING_FOR_AGENT,
    HA_NEXT_NONE,
    REPAIR_PHASE_REPAIR_NEEDED,
    HighAutonomyRunState,
    _can_start_repair,
    _reconcile_high_autonomy_state,
    _repair_packet_target_ids,
    build_high_autonomy_summary,
)
from admissible.high_autonomy_state_invariants import (
    ReconciliationSignals,
    WaitingForAgentSignals,
    check_state_invariants,
    classify_waiting_for_agent_condition,
    reconcile_contradictory_state,
    waiting_for_agent_is_valid,
)

from tests._run044_helpers import force_static_verification_final

GAP_CRITERION_IDS = ["explicit_ac_003", "explicit_ac_005", "explicit_ac_007", "explicit_ac_011"]


def _gap_packet(*, repair_round: int, max_repair_rounds: int) -> dict:
    return {
        "kind": "runtime_instrumentation_gap",
        "gap_criteria": list(GAP_CRITERION_IDS),
        "failed_criteria": [],
        "repair_round": repair_round,
        "max_repair_rounds": max_repair_rounds,
        "remaining_repair_budget": max(0, max_repair_rounds - repair_round),
    }


def _scripted_response(content: str) -> str:
    return (
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        '{"operation": "write_file", "path": "repair_note.txt", "content": "' + content + '"}\n'
        "```"
    )


class TestRuntimeInstrumentationGapDispatch(unittest.TestCase):
    """Fix #1/#2: gap_criteria is authoritative and the packet actually dispatches."""

    def _stuck_controller(self, backend: FixtureAgentBackend) -> ControlSurfaceController:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal("Create result.txt locally.")
        controller.start_high_autonomy_run(
            workspace_path=str(workspace), backend=backend, max_turns=8, closure_reserve_turns=2
        )
        force_static_verification_final(controller, workspace)

        ha = controller._high_autonomy_state()
        ha.repair_phase = REPAIR_PHASE_REPAIR_NEEDED
        ha.runtime_repair_kind = "runtime_instrumentation_gap"
        ha.repair_packet = _gap_packet(repair_round=1, max_repair_rounds=2)
        ha.repair_round_count = 1  # one round used; one round of budget remains
        ha.max_repair_rounds = 2
        # Proven-state: the static ledger never marks a gap criterion
        # verified_fail, so this stays empty -- must not gate dispatch.
        ha.runtime_failed_criterion_ids = []
        ha.mode = HA_MODE_WAITING_FOR_AGENT
        ha.next_action = HA_NEXT_NONE
        ha.pending_agent_invocation = None
        controller._set_high_autonomy_state(ha)
        return controller

    def test_can_start_repair_true_with_empty_failed_criterion_ids(self) -> None:
        controller = self._stuck_controller(FixtureAgentBackend([_scripted_response("noted")]))
        ha = controller._high_autonomy_state()
        self.assertEqual(ha.runtime_failed_criterion_ids, [])
        self.assertEqual(_repair_packet_target_ids(ha.repair_packet), GAP_CRITERION_IDS)
        self.assertTrue(_can_start_repair(controller, ha))

    def test_non_empty_runtime_repair_packet_dispatches_invoke_agent(self) -> None:
        backend = FixtureAgentBackend([_scripted_response("noted")])
        controller = self._stuck_controller(backend)

        state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]

        self.assertEqual(
            len(backend.invocations), 1, "the existing callable-agent invocation path must run"
        )
        self.assertEqual(state["high_autonomy_tick"].get("last_tick_step"), "invoke_agent")
        self.assertIsNotNone(summary["pending_invocation_status"])
        # Never left with neither a real next action nor a pending invocation.
        self.assertFalse(
            summary["next_action"] == "none" and summary["pending_invocation_status"] is None
        )


class TestWaitingForAgentInvariant(unittest.TestCase):
    """Fix #3: repair_phase=repair_needed alone is never a legitimate wait condition."""

    def test_repair_needed_alone_is_not_a_pending_condition(self) -> None:
        signals = WaitingForAgentSignals(
            is_callable_backend=True,
            backend_step=None,
            pending_invocation_status=None,
            backend_retry_required=False,
            backend_reinvoke_pending=False,
            transport_has_pending_response=False,
            runtime_worker_active=False,
        )
        self.assertIsNone(classify_waiting_for_agent_condition(signals))
        self.assertFalse(waiting_for_agent_is_valid(signals))

        violations = check_state_invariants(
            active=True,
            mode="waiting_for_agent",
            next_action="none",
            repair_phase="repair_needed",
            runtime_repair_kind="runtime_instrumentation_gap",
            human_critical_pending=False,
            runtime_worker_active=False,
            human_observation_pending=False,
            technical_pause_active=False,
            pending_terminal_eligibility=False,
            waiting_for_agent_signals=signals,
        )
        self.assertIn("waiting_for_agent_without_pending_condition", [v.code for v in violations])

    def test_dispatchable_repair_is_left_for_the_planner_not_reconciled(self) -> None:
        signals = ReconciliationSignals(
            mode="waiting_for_agent",
            repair_phase="repair_needed",
            runtime_repair_kind="runtime_instrumentation_gap",
            pending_useful_operation_count=0,
            active_blocked_count=0,
            waiting_for_agent_signals=WaitingForAgentSignals(
                is_callable_backend=True,
                backend_step=None,
                pending_invocation_status=None,
                backend_retry_required=False,
                backend_reinvoke_pending=False,
                transport_has_pending_response=False,
                runtime_worker_active=False,
            ),
            repair_dispatchable=True,
        )
        result = reconcile_contradictory_state(signals)
        self.assertFalse(result.changed)
        self.assertFalse(result.fail_closed)


class TestFailClosedReconciliation(unittest.TestCase):
    """Fix #4: an irreconcilable wait pauses technically in one pass, idempotently."""

    def _irreconcilable_controller(self) -> ControlSurfaceController:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal("Create result.txt locally.")
        controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
        ha = controller._high_autonomy_state()
        ha.mode = HA_MODE_WAITING_FOR_AGENT
        ha.repair_phase = REPAIR_PHASE_REPAIR_NEEDED
        ha.runtime_repair_kind = "runtime_instrumentation_gap"
        # Repair budget already exhausted -- genuinely nothing left to dispatch,
        # no callable/runtime/human signal either: irreconcilable.
        ha.repair_packet = _gap_packet(repair_round=2, max_repair_rounds=2)
        ha.repair_round_count = 2
        ha.max_repair_rounds = 2
        ha.runtime_failed_criterion_ids = []
        ha.next_action = HA_NEXT_NONE
        ha.pending_agent_invocation = None
        controller._set_high_autonomy_state(ha)
        return controller

    def _pause_records(self, controller: ControlSurfaceController) -> list[dict]:
        return [
            r
            for r in controller._session.governance_records
            if r.get("event_type") == "state_invariant_reconciliation_paused"
        ]

    def test_irreconcilable_state_pauses_technically_in_one_tick(self) -> None:
        controller = self._irreconcilable_controller()
        ha = controller._high_autonomy_state()
        changed = _reconcile_high_autonomy_state(controller, ha, transport=None)
        self.assertTrue(changed)
        self.assertEqual(ha.mode, HA_MODE_TECHNICAL_PAUSE)
        self.assertNotEqual(ha.mode, HA_MODE_WAITING_FOR_AGENT)
        self.assertTrue(ha.paused)
        self.assertTrue(ha.technical_pause_active)
        self.assertTrue(ha.technical_pause_reason)
        self.assertEqual(len(self._pause_records(controller)), 1)

    def test_repeated_paused_ticks_append_no_duplicate_governance_records(self) -> None:
        controller = self._irreconcilable_controller()
        ha = controller._high_autonomy_state()
        _reconcile_high_autonomy_state(controller, ha, transport=None)
        self.assertEqual(len(self._pause_records(controller)), 1)

        for _ in range(3):
            state = controller.tick_high_autonomy_run()
            self.assertEqual(state["high_autonomy_summary"]["mode"], HA_MODE_TECHNICAL_PAUSE)
        self.assertEqual(
            len(self._pause_records(controller)),
            1,
            "must not re-emit the same violation every tick",
        )


class TestRepairTargetProjection(unittest.TestCase):
    """Fix #5: the UI must report the repair kind's own authoritative target list."""

    def test_ui_reports_four_repair_targets_for_instrumentation_gap(self) -> None:
        ha_state = HighAutonomyRunState()
        ha_state.active = True
        ha_state.repair_phase = REPAIR_PHASE_REPAIR_NEEDED
        ha_state.runtime_repair_kind = "runtime_instrumentation_gap"
        ha_state.repair_packet = _gap_packet(repair_round=2, max_repair_rounds=2)
        summary = build_high_autonomy_summary(ha_state=ha_state, state_view={})
        self.assertEqual(summary["doing_now"], "Preparing a targeted repair for 4 criteria")


if __name__ == "__main__":
    unittest.main()
