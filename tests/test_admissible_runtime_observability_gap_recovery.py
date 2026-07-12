"""ADMISSIBLE_NARROW_FIX_RUNTIME_GAP_RECOVERY_AND_INTERACTION_COVERAGE (RUN_053).

Focused coverage for the real cli-006 forensic defect: a runtime
observability gap finalizing as "unavailable or exhausted" while repair
budget remained and no repair/recovery was ever attempted, plus the new
bounded boost/pause-resume runtime interaction coverage that fixes it.

Never invokes a real Cursor/ACP/provider or a real browser -- every runtime
attempt below uses ``FixtureBrowserRuntimeProvider``.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime import dsl
from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.plan_builder import build_runtime_verification_plan
from admissible.browser_runtime.runner import execute_runtime_verification_plan
from admissible.browser_runtime.ledger_integration import apply_runtime_evidence_to_ledger
from admissible.high_autonomy_controller import (
    HA_MODE_AWAITING_HUMAN_OBSERVATION,
    HA_MODE_RUNNING,
    HighAutonomyRunState,
    reconcile_premature_runtime_observability_gap,
)
from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger
from admissible.runtime_verification_orchestrator import classify_runtime_observability_gap_disposition

from tests._run044_helpers import force_static_verification_final, make_controller, start_run

FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "admissible" / "neon_serpents_cli_003_contract_regression.json"
)

NEON_SNAPSHOT = {
    "phase": "running",
    "player": {"x": 10, "y": 10, "length": 5, "alive": True, "boosting": False},
    "botCount": 12,
    "pelletCount": 3,
    "leaderboard": [],
    "respawnCount": 0,
    "loopCount": 1,
    "debugVisible": False,
}


def _goal() -> str:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["goal_text"]


def _contract_and_ledger():
    contract = build_mission_contract(_goal()).to_dict()
    ledger = contract_acceptance_ledger(contract)
    return contract, ledger


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class TestGapDispositionDecision(unittest.TestCase):
    """Tests 1-2: no premature finalization; distinct "unavailable" vs
    "exhausted" reasons."""

    def test_repair_available_when_budget_remains_and_nothing_attempted(self):
        decision = classify_runtime_observability_gap_disposition(
            gap_results=[
                {"criterion_id": "explicit_ac_011", "unsupported_reason": "loop_counter_field_or_restart_control_not_declared"}
            ],
            debug_interface="window.__NEON__",
            repair_round_count=0,
            max_repair_rounds=2,
        )
        self.assertEqual(decision.action, "repair_available")
        self.assertNotIn("exhausted", decision.reason)
        self.assertNotIn("unavailable", decision.reason)
        self.assertEqual(list(decision.evaluated_alternatives), [
            "safe_debug_observables_checked",
            "safe_input_controls_checked",
            "bounded_runtime_plan_repair_considered",
            "bounded_instrumentation_repair_considered",
            "human_observation_considered",
        ])

    def test_a_gap_with_repair_budget_and_no_attempt_does_not_finalize(self):
        """Required test 1, driven through the real controller branch."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, _goal(), workspace, max_turns=8)
                controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": dict(NEON_SNAPSHOT)}))
                force_static_verification_final(controller, workspace)
                from tests._run044_helpers import tick_until

                final = tick_until(
                    controller, max_ticks=20, stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed")
                )
        summary = final["high_autonomy_summary"]
        # Never finalizes as runtime_observability_gap while repair budget
        # was never even touched -- either it resolves (human observation
        # pending) or, if some criterion is genuinely unfixable, a repair
        # round must show up in the history before any finalization.
        self.assertNotEqual(summary["outcome"], "runtime_observability_gap")

    def test_repair_exhausted_reason_is_distinct_from_no_safe_observable(self):
        gap_results = [{"criterion_id": "c1", "unsupported_reason": "no_debug_interface_declared"}]
        exhausted = classify_runtime_observability_gap_disposition(
            gap_results=gap_results, debug_interface="window.__X__", repair_round_count=2, max_repair_rounds=2
        )
        unobservable = classify_runtime_observability_gap_disposition(
            gap_results=[{"criterion_id": "c2", "unsupported_reason": "no_safe_observable_derivable"}],
            debug_interface="window.__X__",
            repair_round_count=0,
            max_repair_rounds=2,
        )
        no_debug_iface = classify_runtime_observability_gap_disposition(
            gap_results=gap_results, debug_interface=None, repair_round_count=0, max_repair_rounds=2
        )
        self.assertEqual(exhausted.action, "finalize_repair_exhausted")
        self.assertEqual(unobservable.action, "finalize_no_safe_observable")
        self.assertEqual(no_debug_iface.action, "finalize_no_safe_observable")
        self.assertNotEqual(exhausted.reason, unobservable.reason)
        self.assertIn("exhausted", exhausted.reason)
        self.assertNotIn("exhausted", unobservable.reason)
        self.assertNotIn("exhausted", no_debug_iface.reason)

    def test_repair_attempted_and_failed_reason_differs_from_first_attempt(self):
        gap_results = [{"criterion_id": "c1", "unsupported_reason": "no_debug_interface_declared"}]
        first = classify_runtime_observability_gap_disposition(
            gap_results=gap_results, debug_interface="window.__X__", repair_round_count=0, max_repair_rounds=2
        )
        retried = classify_runtime_observability_gap_disposition(
            gap_results=gap_results, debug_interface="window.__X__", repair_round_count=1, max_repair_rounds=2
        )
        self.assertEqual(first.action, "repair_available")
        self.assertEqual(retried.action, "repair_available")
        self.assertNotEqual(first.reason, retried.reason)
        self.assertIn("previous repair round did not fully resolve", retried.reason)


class TestBoostAndPauseResumePlanning(unittest.TestCase):
    """Tests 3-4: bounded keyboard interaction plans for boost/pause-resume."""

    def setUp(self):
        self.contract, self.ledger = _contract_and_ledger()
        self.workspace = Path(tempfile.mkdtemp())
        (self.workspace / "LOCAL_DEV.md").write_text(
            "# Neon Serpents\n\n"
            "## Controls\n\n"
            "| Action | Input |\n"
            "|--------|-------|\n"
            "| Steer | Move mouse/pointer over the canvas |\n"
            "| Boost | Hold **Space** or **left mouse button** |\n"
            "| Pause / Resume | **P** or **Esc** |\n"
            "| Restart after death | **R** |\n",
            encoding="utf-8",
        )

    def _plan(self):
        plan, coverage = build_runtime_verification_plan(
            self.contract, self.ledger, workspace_root=str(self.workspace), entrypoint_path="index.html"
        )
        return plan, coverage

    def test_space_key_down_up_is_planned_for_boost_criterion(self):
        """Required test 3."""
        plan, coverage = self._plan()
        boost_id = self.ledger[6]["criterion_id"]  # criterion 7
        boost_steps = [s for s in plan.steps if s.get("criterion_id") == boost_id]
        self.assertTrue(any(s["type"] == "key_down" and s["key"] == "Space" for s in boost_steps))
        self.assertTrue(any(s["type"] == "key_up" and s["key"] == "Space" for s in boost_steps))
        by_id = {c.criterion_id: c for c in plan.criteria}
        self.assertEqual(by_id[boost_id].disposition, "deterministic_runtime")
        self.assertTrue(by_id[boost_id].assertion_ids)
        # Boolean toggle checked; speed/cost is not silently claimed as passing.
        self.assertEqual(by_id[boost_id].unsupported_reason, "threshold_subject_not_mapped_to_declared_snapshot_field")
        self.assertIn(boost_id, coverage["partially_observable_criterion_ids"])

    def test_p_or_escape_pause_and_resume_is_planned_for_lifecycle_criterion(self):
        """Required test 4."""
        plan, _coverage = self._plan()
        lifecycle_id = self.ledger[10]["criterion_id"]  # criterion 11
        steps = [s for s in plan.steps if s.get("criterion_id") == lifecycle_id]
        key_presses = [s for s in steps if s["type"] == "key_press"]
        self.assertEqual(len(key_presses), 2)
        self.assertTrue(all(s["key"] in ("P", "Escape") for s in key_presses))
        by_id = {c.criterion_id: c for c in plan.criteria}
        self.assertEqual(by_id[lifecycle_id].disposition, "deterministic_runtime")
        self.assertGreaterEqual(len(by_id[lifecycle_id].assertion_ids), 3)

    def test_unsafe_forced_death_action_is_never_generated(self):
        """Required test 6: the lifecycle criterion's restart sub-aspect is
        never triggered (no key_press for the discovered restart key "R"),
        and no DSL step type outside the fixed allowlist can be requested."""
        plan, _coverage = self._plan()
        lifecycle_id = self.ledger[10]["criterion_id"]
        steps = [s for s in plan.steps if s.get("criterion_id") == lifecycle_id]
        self.assertFalse(any(s.get("key") == "R" for s in steps))
        for forbidden in ("force_death", "set_state", "force_respawn", "teleport", "eval_js"):
            with self.assertRaises(dsl.BrowserRuntimeDSLError):
                dsl.validate_step({"type": forbidden}, index=0)

    def test_boost_and_pause_resume_steps_are_dsl_valid(self):
        plan, _coverage = self._plan()
        dsl.validate_steps(plan.steps, max_steps=plan.max_steps)  # must not raise


class TestMixedRuntimeAndHumanEvidence(unittest.TestCase):
    """Test 5: runtime and human evidence coexist on one criterion."""

    def test_pause_resume_criterion_keeps_runtime_evidence_and_routes_to_human(self):
        """Required test 5, plus PART 2.B/PART 3: ac_011 keeps its passed
        pause/resume/loop-alive runtime assertions while still routing the
        restart-after-death sub-aspect to human observation."""
        contract, ledger = _contract_and_ledger()
        workspace = Path(tempfile.mkdtemp())
        (workspace / "LOCAL_DEV.md").write_text(
            "| Action | Input |\n|---|---|\n| Pause / Resume | **P** or **Esc** |\n| Restart after death | **R** |\n",
            encoding="utf-8",
        )
        plan, _coverage = build_runtime_verification_plan(
            contract, ledger, workspace_root=str(workspace), entrypoint_path="index.html"
        )
        lifecycle_id = ledger[10]["criterion_id"]
        by_id = {c.criterion_id: c for c in plan.criteria}
        self.assertTrue(by_id[lifecycle_id].human_observation_required)
        self.assertTrue(by_id[lifecycle_id].assertion_ids)

        provider = FixtureBrowserRuntimeProvider(
            {
                "initial_snapshot": dict(NEON_SNAPSHOT),
                "key_rules": {"P": {"snapshot": {"phase": "paused"}}},
            }
        )
        result = execute_runtime_verification_plan(provider, plan)
        criterion_result = next(r for r in result.evidence.criterion_results if r["criterion_id"] == lifecycle_id)
        # Routed to human (restart-after-death is never safely triggerable)...
        self.assertEqual(criterion_result["status"], "awaiting_human_observation")
        # ...but the real pause/resume assertions are still present as evidence.
        self.assertTrue(criterion_result["assertions"])
        self.assertTrue(any(a.get("status") == "pass" for a in criterion_result["assertions"]))

        apply_runtime_evidence_to_ledger(ledger, plan, result.evidence)
        item = next(c for c in ledger if c["criterion_id"] == lifecycle_id)
        self.assertEqual(item["verification_disposition"], "human_observation_required")
        self.assertIn(result.evidence.evidence_id, item["evidence_refs"])


class TestPointerSteeringHonestFailure(unittest.TestCase):
    def test_failed_pointer_assertion_is_preserved_not_converted_to_pass(self):
        """PART 2.C / PART 3: explicit_ac_004's failed compare_snapshot_path_changed
        stays honest evidence and the criterion routes to human observation."""
        contract, ledger = _contract_and_ledger()
        with tempfile.TemporaryDirectory() as workspace:
            plan, _coverage = build_runtime_verification_plan(
                contract, ledger, workspace_root=workspace, entrypoint_path="index.html"
            )
        pointer_id = ledger[3]["criterion_id"]  # criterion 4
        # No key/pointer rule patches "player" on pointer_move -> the
        # compare_snapshot_path_changed assertion genuinely fails.
        provider = FixtureBrowserRuntimeProvider({"initial_snapshot": dict(NEON_SNAPSHOT)})
        result = execute_runtime_verification_plan(provider, plan)
        criterion_result = next(r for r in result.evidence.criterion_results if r["criterion_id"] == pointer_id)
        self.assertEqual(criterion_result["status"], "awaiting_human_observation")
        self.assertTrue(any(a.get("status") == "fail" for a in criterion_result["assertions"]))


class TestNestedSnapshotFieldsCompatibility(unittest.TestCase):
    """Test 7: exact-eight-top-level snapshot permits additional safe nested
    player observables."""

    def test_extra_nested_player_fields_do_not_break_exact_eight_top_level_check(self):
        contract, ledger = _contract_and_ledger()
        with tempfile.TemporaryDirectory() as workspace:
            plan, _coverage = build_runtime_verification_plan(
                contract, ledger, workspace_root=workspace, entrypoint_path="index.html"
            )
        debug_iface_id = ledger[12]["criterion_id"]  # criterion 13
        presence_steps = [
            s for s in plan.steps if s.get("criterion_id") == debug_iface_id and s.get("type") == "assert_json_path_present"
        ]
        # Exactly the eight top-level fields are asserted present -- nested
        # sub-fields (player.x, player.boosting, ...) are never counted as
        # extra top-level fields.
        self.assertEqual(
            {s["path"] for s in presence_steps},
            {"phase", "player", "botCount", "pelletCount", "leaderboard", "respawnCount", "loopCount", "debugVisible"},
        )

        richer_snapshot = dict(NEON_SNAPSHOT)
        richer_snapshot["player"] = {
            **richer_snapshot["player"],
            "heading": 1.2,
            "segmentCount": 5,
            "currentSpeed": 4.0,
            "cumulativeBoostCost": 0.5,
        }
        validated = dsl.validate_json_serializable_snapshot(richer_snapshot)
        self.assertEqual(set(validated.keys()), set(NEON_SNAPSHOT.keys()))
        self.assertIn("segmentCount", validated["player"])


class TestNoSilentGenericEvidenceRequired(unittest.TestCase):
    """Test 8: a criterion cannot be silently left generic evidence_required
    after runtime planning."""

    def test_no_unsupported_verifier_criterion_has_a_missing_reason(self):
        contract, ledger = _contract_and_ledger()
        with tempfile.TemporaryDirectory() as workspace:
            plan, _coverage = build_runtime_verification_plan(
                contract, ledger, workspace_root=workspace, entrypoint_path="index.html"
            )
        for criterion in plan.criteria:
            if criterion.disposition == "unsupported_verifier":
                self.assertIsNotNone(
                    criterion.unsupported_reason,
                    f"{criterion.criterion_id} is unsupported_verifier with no recorded reason",
                )

    def test_boost_and_multi_segment_criteria_are_not_silently_generic(self):
        contract, ledger = _contract_and_ledger()
        with tempfile.TemporaryDirectory() as workspace:
            plan, _coverage = build_runtime_verification_plan(
                contract, ledger, workspace_root=workspace, entrypoint_path="index.html"
            )
        by_id = {c.criterion_id: c for c in plan.criteria}
        boost_id = ledger[6]["criterion_id"]
        body_id = ledger[4]["criterion_id"]
        # No LOCAL_DEV.md written in this temp workspace -> boost has no
        # discoverable control, but it must still be an EXPLICIT gap, not a
        # silently-passed-through "evidence_required" with zero assertions.
        self.assertEqual(by_id[boost_id].disposition, "unsupported_verifier")
        self.assertIsNotNone(by_id[boost_id].unsupported_reason)
        self.assertEqual(by_id[body_id].disposition, "human_observation_required")
        self.assertTrue(by_id[body_id].human_observation_required)


REPLAY_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "neon_serpents_cli_006_runtime_observability_gap_replay.json"
)


def _load_replay_fixture() -> dict:
    return json.loads(REPLAY_FIXTURE.read_text(encoding="utf-8"))


def _build_stopped_gap_ha_state() -> HighAutonomyRunState:
    """Sanitized compact replay of the real cli-006 final state (RUN_053
    PART 5): the real ledger (28/29 assertions passed, explicit_ac_004's
    pointer assertion failed, explicit_ac_005/explicit_ac_007 stuck on the
    stale pre-fix "evidence_required" disposition, explicit_ac_011
    unsupported with no recorded reason) plus the real 8 write operation
    records, with outcome=runtime_observability_gap, closure finalized,
    runtime_repair_kind null, recovery_attempted false, repair round 1 of 2
    -- the exact premature-finalization defect RUN_053 fixes."""

    fixture = _load_replay_fixture()
    ha_state = HighAutonomyRunState()
    ha_state.acceptance_criteria = [dict(item) for item in fixture["acceptance_criteria"]]
    for key, value in fixture["ha_state_overrides"].items():
        setattr(ha_state, key, value)
    return ha_state


class TestStoppedCli006Reconciliation(unittest.TestCase):
    """Tests 9-11: the stopped cli-006 fixture reopens without a provider
    call or write; reconciliation is idempotent; existing passed evidence
    and hashes are untouched."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.controller = make_controller(self.root)
        # submit_goal (not a hand-built contract) so goal_intake/plan_candidate
        # exist too -- a finalized real session always has these; without them
        # `_plan_next_action`'s continuation-instruction lookup has nothing to
        # continue from and the reopened run stalls on an unrelated, unrealistic
        # "no goal intake" edge rather than proceeding to runtime verification.
        self.controller.submit_goal(_goal())
        self.contract = self.controller._session.mission_contract
        self.ledger = contract_acceptance_ledger(self.contract)
        self.controller._session.bounded_executor_workspace = str(self.root / "workspace")
        fixture = _load_replay_fixture()
        self.controller._session.operation_records = [dict(r) for r in fixture["operation_records"]]
        # The real session had already run static verification to completion
        # (all 8 mandatory files present) before ever reaching runtime
        # verification; `_plan_next_action` only delegates to the runtime
        # orchestrator once `_verification_is_final` sees a landed static pass.
        self.controller._session.run_loop.verification_records.append({"overall_status": "pass"})
        self.ha_state = _build_stopped_gap_ha_state()
        self.controller._set_high_autonomy_state(self.ha_state)
        self.controller._persist()

    def test_stopped_fixture_reopens_without_provider_call_or_write(self):
        """Required test 9."""
        original_history = json.dumps(self.ha_state.runtime_attempt_history, sort_keys=True)
        original_op_count = len(self.controller._session.operation_records)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            view = self.controller.reconcile_premature_runtime_observability_gap()
        result = view["runtime_observability_gap_reconciliation"]
        self.assertTrue(result["reopened"])
        reopened = self.controller._high_autonomy_state()
        self.assertEqual(reopened.outcome, "in_progress")
        self.assertNotEqual(reopened.closure_phase_status, "finalized")
        self.assertTrue(reopened.active)
        self.assertEqual(reopened.mode, HA_MODE_RUNNING)
        # No new write/operation record was produced by reconciliation itself.
        self.assertEqual(len(self.controller._session.operation_records), original_op_count)
        # Existing runtime evidence is untouched (test 11, part 1).
        self.assertEqual(json.dumps(reopened.runtime_attempt_history, sort_keys=True), original_history)

    def test_reconciliation_is_idempotent(self):
        """Required test 10."""
        first = self.controller.reconcile_premature_runtime_observability_gap()
        self.assertTrue(first["runtime_observability_gap_reconciliation"]["reopened"])
        second = self.controller.reconcile_premature_runtime_observability_gap()
        self.assertFalse(second["reopened"])
        reopened = self.controller._high_autonomy_state()
        self.assertEqual(reopened.outcome, "in_progress")
        self.assertTrue(reopened.active)

    def test_existing_runtime_evidence_and_hashes_remain_unchanged(self):
        """Required test 11."""
        before = self.controller._high_autonomy_state().runtime_attempt_history[0]
        self.controller.reconcile_premature_runtime_observability_gap()
        after = self.controller._high_autonomy_state().runtime_attempt_history[0]
        self.assertEqual(before, after)
        self.assertEqual(after["evidence_id"], "runtime_evidence_993d26183dc6")
        self.assertEqual(after["assertion_pass_count"], 28)
        self.assertEqual(after["assertion_fail_count"], 1)

    def test_stale_boost_disposition_is_migrated_on_reopen(self):
        """The pre-fix ledger snapshot pinned explicit_ac_007 to the generic
        stale "evidence_required" disposition; reopening must re-derive it
        (via the now-fixed mission_contract classification) so the next
        runtime plan actually attempts it, rather than reopening into the
        exact same silent gap."""
        self.controller.reconcile_premature_runtime_observability_gap()
        reopened = self.controller._high_autonomy_state()
        item = next(c for c in reopened.acceptance_criteria if c["criterion_id"] == "explicit_ac_007")
        self.assertEqual(item["verification_disposition"], "unsupported_verifier")
        body_item = next(c for c in reopened.acceptance_criteria if c["criterion_id"] == "explicit_ac_005")
        self.assertEqual(body_item["verification_disposition"], "human_observation_required")

    def test_reopen_selects_a_repaired_plan_not_an_immediate_repeat_gap(self):
        """PART 5/6: after reopening, the controller's runtime-verification
        orchestration selects a repaired plan (attempting boost/pause with
        the now-discoverable controls) and does not immediately reproduce
        the exact same unresolved gap. Driven directly through the runtime
        orchestration sequence (start/poll/apply), which is the specific
        machinery this task's fix touches -- the separate, already-covered
        agent-turn/proposal-coverage bookkeeping is out of scope here.
        """
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.reconcile_premature_runtime_observability_gap()
            provider = FixtureBrowserRuntimeProvider(
                {
                    "initial_snapshot": dict(NEON_SNAPSHOT),
                    "key_rules": {
                        "P": {"snapshot": {"phase": "paused"}},
                        "Space": {"snapshot": {"player": {**NEON_SNAPSHOT["player"], "boosting": True}}},
                    },
                    "key_up_rules": {"Space": {"snapshot": {"player": dict(NEON_SNAPSHOT["player"])}}},
                }
            )
            self.controller.set_runtime_provider(provider)
            workspace = Path(self.controller._session.bounded_executor_workspace)
            workspace.mkdir(parents=True, exist_ok=True)
            (workspace / "LOCAL_DEV.md").write_text(
                "| Action | Input |\n|---|---|\n"
                "| Boost | Hold **Space** or **left mouse button** |\n"
                "| Pause / Resume | **P** or **Esc** |\n"
                "| Restart after death | **R** |\n",
                encoding="utf-8",
            )
            reopened_state = self.controller._high_autonomy_state()
            self.assertEqual(reopened_state.outcome, "in_progress")
            reopened_state.workspace_path = str(workspace)
            self.controller._set_high_autonomy_state(reopened_state)
            self.controller._persist()

            # `_plan_next_action`'s general agent-turn/proposal-coverage
            # bookkeeping (already covered elsewhere) is orthogonal to this
            # task's fix and isn't reconstructed by this compact fixture;
            # force exactly the first decision to the runtime-verification
            # entry point this task's PART 5/6 is actually about, then let
            # every later tick use the real planner so poll/apply/repair
            # routing is genuine, unmodified production behavior.
            import admissible.high_autonomy_controller as hac

            real_plan_next_action = hac._plan_next_action
            forced = {"used": False}

            def _forced_plan_next_action(*args, **kwargs):
                if not forced["used"]:
                    forced["used"] = True
                    return hac.HA_NEXT_START_RUNTIME_VERIFICATION
                return real_plan_next_action(*args, **kwargs)

            with mock.patch.object(hac, "_plan_next_action", side_effect=_forced_plan_next_action):
                for _ in range(6):
                    state = self.controller.tick_high_autonomy_run()
                    summary = state["high_autonomy_summary"]
                    if summary["mode"] in (HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed"):
                        break

        self.assertEqual(len(summary["runtime_attempt_history"]), 2, "a second, real runtime attempt ran")
        # explicit_ac_011 (previously the sole unobservable criterion) is now
        # genuinely resolved with real pause/resume/loop-alive evidence, kept
        # even though it still routes to human for restart-after-death.
        criteria_by_id = {c["criterion_id"]: c for c in summary["acceptance_criteria"]}
        self.assertEqual(criteria_by_id["explicit_ac_011"]["verification_disposition"], "human_observation_required")
        self.assertTrue(criteria_by_id["explicit_ac_011"]["evidence_refs"])
        # explicit_ac_007's boolean toggle is real evidence now too, but the
        # boost-speed/cost sub-aspect still has no declared field -- a
        # genuine, DIFFERENT, narrower instrumentation gap than before, never
        # a repeat of the identical prior finalization message.
        self.assertNotEqual(summary["outcome"], "runtime_observability_gap")
        gap_eval = summary.get("runtime_gap_evaluation") or {}
        if gap_eval:
            self.assertNotIn("unavailable or exhausted", gap_eval.get("reason", ""))


if __name__ == "__main__":
    unittest.main()
