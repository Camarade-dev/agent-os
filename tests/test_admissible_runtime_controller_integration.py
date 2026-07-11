"""RUN_044 controller-integration tests.

Exercises admissible.high_autonomy_controller's delegation to
admissible.runtime_verification_orchestrator through a real
ControlSurfaceController + tick_high_autonomy_run loop, using
FixtureBrowserRuntimeProvider (never a real browser, never a real model
provider).

Covers required tests 1-3, 16, 17, 19, 20, 24, 25, 26, 27, 28.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.high_autonomy_controller import (
    HA_MODE_AWAITING_HUMAN_OBSERVATION,
    HA_MODE_RUNTIME_VERIFYING,
    HA_NEXT_APPLY_RUNTIME_EVIDENCE,
    HA_NEXT_POLL_RUNTIME_VERIFICATION,
    HA_NEXT_START_RUNTIME_VERIFICATION,
    HA_NEXT_WRITE_INSTRUCTION,
)

from tests._run044_helpers import (
    COUNTER_GOAL,
    TWO_CRITERIA_GOAL,
    force_static_verification_final,
    make_controller,
    start_run,
    tick_until,
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("RUN_044 runtime orchestration must never spawn a real subprocess in tests")


class TestRuntimeAutoTriggerAndNoModelTurn(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_static_verification_cannot_complete_while_runtime_criteria_remain(self):
        """Required test 1."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            force_static_verification_final(self.controller, self.workspace)
            # Static verification alone (zero static checks for this criterion)
            # must never mark the run complete.
            ha = self.controller.state_view()["high_autonomy_summary"]
            self.assertNotEqual(ha["outcome"], "completed")

    def test_runtime_plan_auto_triggers_after_static_verification(self):
        """Required test 2."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)
            state = self.controller.tick_high_autonomy_run()
            self.assertEqual(state["high_autonomy_tick"]["planned"], HA_NEXT_START_RUNTIME_VERIFICATION)

    def test_runtime_verification_never_writes_a_model_instruction(self):
        """Required test 3: no model/provider turn is consumed by the runtime pipeline."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)
            state = tick_until(self.controller, max_ticks=10)
            self.assertEqual(state["high_autonomy_summary"]["outcome"], "completed")
            planned_steps = []
            s = self.controller.state_view()
            self.assertEqual(s["run_loop"]["current_turn"], 0, "no agent turn should have been consumed")
            self.assertEqual(len(s["run_loop"].get("instruction_packets") or []), 0)

    def test_runtime_pass_reevaluates_completion_eligibility(self):
        """Required test 19."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)
            state = tick_until(self.controller, max_ticks=10)
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_criteria"][0]["status"], "verified_pass")


class TestCapabilityAndObservabilityGaps(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_browser_unavailable_is_terminally_honest_capability_gap(self):
        """Required test 16."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(
                FixtureBrowserRuntimeProvider({"available": False, "unavailable_reason": "no_browser_installed"})
            )
            force_static_verification_final(self.controller, self.workspace)
            state = tick_until(self.controller, max_ticks=10)
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["mode"], "stopped")
            self.assertEqual(summary["outcome"], "verification_capability_gap")
            self.assertNotEqual(summary["outcome"], "completed")
            self.assertNotIn(summary["outcome"], ("internal_livelock",))
            self.assertFalse(summary["human_action_required"], "browser unavailability is not a human-authority gate")

    def test_no_safe_observable_yields_runtime_observability_gap(self):
        """Required test 17: a criterion whose text hints at a runtime check but
        has no derivable observable stays a gap; runtime never invents a check."""
        goal = """Build a tiny mystery app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. The active entity count must update live during play.
"""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, goal, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({}))
            force_static_verification_final(self.controller, self.workspace)
            state = tick_until(self.controller, max_ticks=10)
            summary = state["high_autonomy_summary"]
            self.assertNotEqual(summary["outcome"], "completed")
            criterion = summary["acceptance_criteria"][0]
            self.assertEqual(criterion["verification_disposition"], "unsupported_verifier")


class TestHumanObservationDistinctFromAuthority(unittest.TestCase):
    def test_human_observation_never_sets_human_critical_pending(self):
        """Required test 18."""
        goal = """Build a widget dashboard.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount.
2. The animation must look smooth and polished.
"""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, goal, workspace)
                controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"widgetCount": 3}}))
                force_static_verification_final(controller, workspace)
                state = tick_until(controller, max_ticks=10, stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed"))
                summary = state["high_autonomy_summary"]
                self.assertEqual(summary["mode"], HA_MODE_AWAITING_HUMAN_OBSERVATION)
                self.assertFalse(summary["human_action_required"])
                self.assertEqual(summary["human_required_action_count"], 0)
                pending = summary["human_observation_pending_criterion_ids"]
                self.assertEqual(len(pending), 1)


class TestRuntimeWaitStatesNeverLivelock(unittest.TestCase):
    def test_repeated_polling_never_triggers_internal_livelock(self):
        """Required test 25."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
                force_static_verification_final(controller, workspace)
                for _ in range(10):
                    state = controller.tick_high_autonomy_run()
                    self.assertNotEqual(state["high_autonomy_summary"].get("current_step"), "internal_livelock")
                    if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                        break
                self.assertEqual(state["high_autonomy_summary"]["outcome"], "completed")


class TestCleanupVisibility(unittest.TestCase):
    def test_cleanup_failure_is_recorded_and_visible(self):
        """Required test 26."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
                real_close = provider.close_session

                def _bad_close(session):
                    result = real_close(session)
                    result["browser_process_terminated"] = False
                    return result

                provider.close_session = _bad_close
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)
                state = tick_until(controller, max_ticks=10)
                summary = state["high_autonomy_summary"]
                history = summary["runtime_attempt_history"]
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0]["cleanup_status"], "cleanup_incomplete")
                self.assertEqual(summary["metrics"]["runtime_cleanup_failure_count"], 1)


class TestCancelAttempt(unittest.TestCase):
    def test_cancel_active_attempt_cleans_up_and_is_visible(self):
        """Required test 27."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
                force_static_verification_final(controller, workspace)
                controller.tick_high_autonomy_run()  # starts the attempt
                self.assertIsNotNone(controller.runtime_verification_status()["active_runtime_attempt"])
                result = controller.cancel_runtime_verification_attempt()
                self.assertIsNone(controller.runtime_verification_status()["active_runtime_attempt"])
                history = controller.runtime_verification_status()["runtime_attempt_history"]
                self.assertEqual(history[-1]["semantic_status"], "cancelled")


class TestNoArbitraryRuntimeApiExposed(unittest.TestCase):
    def test_control_surface_controller_has_no_generic_runtime_plan_submission_method(self):
        """Required test 28."""
        from admissible.control_surface import ControlSurfaceController

        public_methods = {name for name in dir(ControlSurfaceController) if not name.startswith("_")}
        forbidden_substrings = ("submit_runtime_plan", "run_arbitrary", "execute_script", "run_javascript", "eval_js")
        for method_name in public_methods:
            for forbidden in forbidden_substrings:
                self.assertNotIn(forbidden, method_name.lower())

    def test_record_human_observation_rejects_unknown_disposition(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                with self.assertRaises(ValueError):
                    controller.record_human_observation(
                        "explicit_ac_001", actor="op", disposition="run_js", note="x"
                    )


if __name__ == "__main__":
    unittest.main()
