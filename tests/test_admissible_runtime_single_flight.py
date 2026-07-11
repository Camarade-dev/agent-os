"""RUN_044 single-flight tests: one session, one runtime worker, ever.

Covers required tests 4-8.
"""

from __future__ import annotations

import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.high_autonomy_controller import HA_NEXT_POLL_RUNTIME_VERIFICATION, HA_NEXT_START_RUNTIME_VERIFICATION
import admissible.runtime_verification_orchestrator as rvo

from tests._run044_helpers import COUNTER_GOAL, force_static_verification_final, make_controller, start_run


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class _SlowFixtureProvider(FixtureBrowserRuntimeProvider):
    """A FixtureBrowserRuntimeProvider whose session stays open briefly.

    Lets tests deterministically observe "worker still running" without
    depending on true browser I/O timing.
    """

    def __init__(self, scenario, *, delay_seconds: float = 0.15):
        super().__init__(scenario)
        self._delay_seconds = delay_seconds

    def _do_debug_snapshot(self, session):
        time.sleep(self._delay_seconds)
        return super()._do_debug_snapshot(session)


class TestSingleWorkerPerSession(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_one_session_cannot_start_two_runtime_workers(self):
        """Required test 4."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)

            state1 = self.controller.tick_high_autonomy_run()
            self.assertEqual(state1["high_autonomy_tick"]["planned"], HA_NEXT_START_RUNTIME_VERIFICATION)
            attempt_id_1 = self.controller.runtime_verification_status()["active_runtime_attempt_id"]
            self.assertIsNotNone(attempt_id_1)
            self.assertTrue(rvo.has_active_worker(self.controller._session.session_id))

            # A second tick while the worker is still (slowly) running must
            # poll the SAME attempt, never start a second one.
            state2 = self.controller.tick_high_autonomy_run()
            self.assertEqual(state2["high_autonomy_tick"]["planned"], HA_NEXT_POLL_RUNTIME_VERIFICATION)
            attempt_id_2 = self.controller.runtime_verification_status()["active_runtime_attempt_id"]
            self.assertEqual(attempt_id_1, attempt_id_2)

            # Drain.
            for _ in range(50):
                s = self.controller.tick_high_autonomy_run()
                if s["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break
                time.sleep(0.02)

    def test_concurrent_ticks_do_not_duplicate_attempts(self):
        """Required test 5: two threads calling tick_high_autonomy_run concurrently."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}, delay_seconds=0.1))
            force_static_verification_final(self.controller, self.workspace)

            results = []

            def _tick():
                results.append(self.controller.tick_high_autonomy_run())

            threads = [threading.Thread(target=_tick) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            # The controller-level tick lock guarantees at most one real tick
            # executes at a time; the rest observe "tick_already_in_progress".
            real_ticks = [r for r in results if not r.get("tick_already_in_progress")]
            self.assertGreaterEqual(len(real_ticks), 1)
            attempt_ids = {
                r["high_autonomy_summary"].get("active_runtime_attempt_id")
                for r in real_ticks
                if r["high_autonomy_summary"].get("active_runtime_attempt_id")
            }
            self.assertLessEqual(len(attempt_ids), 1, "concurrent ticks must never produce two distinct active attempts")

            for _ in range(50):
                s = self.controller.tick_high_autonomy_run()
                if s["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break
                time.sleep(0.02)

    def test_manual_step_and_auto_poll_do_not_duplicate_attempts(self):
        """Required test 6: repeated manual `tick_high_autonomy_run` Step calls
        (there is no separate "auto-run" code path server-side -- the browser
        auto-run loop is just repeated Step calls) never start a second attempt
        while one is active."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}))
            force_static_verification_final(self.controller, self.workspace)

            self.controller.tick_high_autonomy_run()
            attempt_id = self.controller.runtime_verification_status()["active_runtime_attempt_id"]
            for _ in range(3):
                self.controller.tick_high_autonomy_run()
                self.assertEqual(
                    self.controller.runtime_verification_status()["active_runtime_attempt_id"], attempt_id
                )
            for _ in range(50):
                s = self.controller.tick_high_autonomy_run()
                if s["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break
                time.sleep(0.02)

    def test_worker_returns_promptly_from_initiating_tick(self):
        """Required test 7."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}, delay_seconds=2.0))
            force_static_verification_final(self.controller, self.workspace)

            started_at = time.perf_counter()
            state = self.controller.tick_high_autonomy_run()
            elapsed = time.perf_counter() - started_at
            self.assertLess(elapsed, 1.0, "the initiating tick must not block on the full (2s) browser run")
            self.assertEqual(state["high_autonomy_tick"]["planned"], HA_NEXT_START_RUNTIME_VERIFICATION)
            # Cancel so the slow worker doesn't outlive the test.
            self.controller.cancel_runtime_verification_attempt()

    def test_poll_ticks_report_bounded_progress_without_blocking(self):
        """Required test 8."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            self.controller.set_runtime_provider(_SlowFixtureProvider({"initial_snapshot": {"count": 5}}, delay_seconds=0.2))
            force_static_verification_final(self.controller, self.workspace)

            self.controller.tick_high_autonomy_run()
            started_at = time.perf_counter()
            poll_state = self.controller.tick_high_autonomy_run()
            elapsed = time.perf_counter() - started_at
            self.assertLess(elapsed, 1.0)
            self.assertEqual(poll_state["high_autonomy_tick"]["planned"], HA_NEXT_POLL_RUNTIME_VERIFICATION)
            self.assertEqual(poll_state["high_autonomy_summary"]["mode"], "runtime_verifying")

            for _ in range(50):
                s = self.controller.tick_high_autonomy_run()
                if s["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break
                time.sleep(0.02)
            self.assertEqual(s["high_autonomy_summary"]["outcome"], "completed")


if __name__ == "__main__":
    unittest.main()
