"""RUN_044 async tick lifecycle tests (PART E.17).

Tick A: validate+persist attempt, mark queued/running, start the worker,
return promptly. Later ticks: poll, show in-progress, never start a second
attempt. Completion tick: persist evidence, apply it exactly once, continue
closure or repair.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.high_autonomy_controller import (
    HA_MODE_RUNTIME_VERIFYING,
    HA_NEXT_APPLY_RUNTIME_EVIDENCE,
    HA_NEXT_POLL_RUNTIME_VERIFICATION,
    HA_NEXT_START_RUNTIME_VERIFICATION,
)

from tests._run044_helpers import COUNTER_GOAL, force_static_verification_final, make_controller, start_run


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class _SlowFixtureProvider(FixtureBrowserRuntimeProvider):
    def __init__(self, scenario, *, delay_seconds: float = 0.15):
        super().__init__(scenario)
        self._delay_seconds = delay_seconds

    def _do_debug_snapshot(self, session):
        time.sleep(self._delay_seconds)
        return super()._do_debug_snapshot(session)


class TestAsyncTickLifecycle(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_tick_a_prepares_and_starts_then_returns(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)

            state = self.controller.tick_high_autonomy_run()
            self.assertEqual(state["high_autonomy_tick"]["planned"], HA_NEXT_START_RUNTIME_VERIFICATION)
            attempt = self.controller.runtime_verification_status()["active_runtime_attempt"]
            self.assertIn(attempt["status"], ("queued", "running"))
            self.assertEqual(state["high_autonomy_summary"]["mode"], HA_MODE_RUNTIME_VERIFYING)

    def test_later_ticks_poll_and_show_in_progress_without_starting_again(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)

            self.controller.tick_high_autonomy_run()
            first_attempt_id = self.controller.runtime_verification_status()["active_runtime_attempt_id"]

            seen_planned = []
            for _ in range(20):
                state = self.controller.tick_high_autonomy_run()
                seen_planned.append(state["high_autonomy_tick"]["planned"])
                if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break
                time.sleep(0.02)

            self.assertNotIn(
                HA_NEXT_START_RUNTIME_VERIFICATION,
                seen_planned,
                "no later tick may start a second attempt while the first is in flight",
            )
            self.assertIn(HA_NEXT_POLL_RUNTIME_VERIFICATION, seen_planned)
            self.assertIn(HA_NEXT_APPLY_RUNTIME_EVIDENCE, seen_planned)
            history = state["high_autonomy_summary"]["runtime_attempt_history"]
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["attempt_id"], first_attempt_id)

    def test_completion_tick_applies_evidence_and_continues_closure(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)

            start_state = self.controller.tick_high_autonomy_run()
            self.assertEqual(start_state["high_autonomy_tick"]["planned"], HA_NEXT_START_RUNTIME_VERIFICATION)
            poll_state = self.controller.tick_high_autonomy_run()
            self.assertEqual(poll_state["high_autonomy_tick"]["planned"], HA_NEXT_POLL_RUNTIME_VERIFICATION)
            self.assertEqual(poll_state["high_autonomy_summary"]["runtime_verification_status"], "evidence_ready")
            apply_state = self.controller.tick_high_autonomy_run()
            self.assertEqual(apply_state["high_autonomy_tick"]["planned"], HA_NEXT_APPLY_RUNTIME_EVIDENCE)
            summary = apply_state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(len(summary["runtime_attempt_history"]), 1)


if __name__ == "__main__":
    unittest.main()
