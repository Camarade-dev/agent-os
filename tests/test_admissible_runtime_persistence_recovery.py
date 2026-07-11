"""RUN_044 persistence and crash-recovery tests.

Covers required tests 13-15.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.control_surface import load_persisted_session
import admissible.runtime_verification_orchestrator as rvo

from tests._run044_helpers import COUNTER_GOAL, force_static_verification_final, make_controller, start_run


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


def _simulate_crash(controller, provider):
    """Forge: mark the active attempt "running" and drop the in-process
    worker registry entry for this session, as a real process crash would."""
    ha_state = controller._high_autonomy_state()
    session_id = controller._session.session_id
    with rvo._REGISTRY_LOCK:
        rvo._WORKERS.pop(session_id, None)
    ha_state.active_runtime_attempt["status"] = "running"
    controller._set_high_autonomy_state(ha_state)
    controller._persist()


class TestPersistedEvidenceRecovery(unittest.TestCase):
    def test_persisted_evidence_is_recovered_without_browser_relaunch(self):
        """Required test 13."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)

                controller.tick_high_autonomy_run()  # start
                controller.tick_high_autonomy_run()  # poll -> evidence_ready

                # Forge: the ledger update never landed (process crashed right
                # after evidence was written but before it was applied), and
                # the attempt is still marked "running".
                ha_state = controller._high_autonomy_state()
                session_id = controller._session.session_id
                with rvo._REGISTRY_LOCK:
                    rvo._WORKERS.pop(session_id, None)
                self.assertEqual(ha_state.active_runtime_attempt["status"], "evidence_ready")
                ha_state.active_runtime_attempt["status"] = "running"
                controller._set_high_autonomy_state(ha_state)
                controller._persist()

                detect_calls = {"n": 0}
                real_detect = provider.detect_capability

                def _spy_detect(*a, **kw):
                    detect_calls["n"] += 1
                    return real_detect(*a, **kw)

                provider.detect_capability = _spy_detect

                controller2 = make_controller(root)
                load_persisted_session(controller2)
                controller2.set_runtime_provider(provider)
                state = controller2.tick_high_autonomy_run()

                self.assertEqual(detect_calls["n"], 0, "recovery must never re-launch the browser")
                summary = state["high_autonomy_summary"]
                self.assertIn(summary["runtime_verification_status"], ("evidence_ready", "runtime_verification_pass"))


class TestInterruptedNeverBecomesPass(unittest.TestCase):
    def test_interrupted_attempt_is_never_treated_as_a_pass(self):
        """Required test 14."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)

                controller.tick_high_autonomy_run()
                _simulate_crash(controller, provider)

                controller2 = make_controller(root)
                load_persisted_session(controller2)
                controller2.set_runtime_provider(provider)
                state = controller2.tick_high_autonomy_run()

                summary = state["high_autonomy_summary"]
                self.assertEqual(summary["runtime_verification_status"], "interrupted")
                self.assertNotEqual(summary["outcome"], "completed")
                criterion = summary["acceptance_criteria"][0]
                self.assertNotEqual(criterion["status"], "verified_pass")
                attempt = controller2.runtime_verification_status()["active_runtime_attempt"]
                self.assertEqual(attempt["cleanup_status"], "unknown_process_state_not_tracked")


class TestInterruptedRetryPreservesLineage(unittest.TestCase):
    def test_explicit_retry_preserves_lineage_and_completes(self):
        """Required test 15."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, COUNTER_GOAL, workspace)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"count": 5}})
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)

                controller.tick_high_autonomy_run()
                original_attempt_id = controller.runtime_verification_status()["active_runtime_attempt_id"]
                original_plan_sha = controller.runtime_verification_status()["last_runtime_plan_sha256"]
                original_criteria = list(controller.runtime_verification_status()["active_runtime_attempt"]["criterion_ids"])
                _simulate_crash(controller, provider)

                controller2 = make_controller(root)
                load_persisted_session(controller2)
                controller2.set_runtime_provider(provider)
                controller2.tick_high_autonomy_run()
                self.assertEqual(
                    controller2.runtime_verification_status()["active_runtime_attempt"]["status"], "interrupted"
                )

                # Cannot retry without explicit operator action, even across many ticks.
                for _ in range(3):
                    controller2.tick_high_autonomy_run()
                self.assertEqual(
                    controller2.runtime_verification_status()["active_runtime_attempt"]["status"], "interrupted"
                )

                retried = controller2.retry_runtime_verification_attempt()
                new_status = controller2.runtime_verification_status()
                new_attempt = new_status["active_runtime_attempt"]
                self.assertNotEqual(new_attempt["attempt_id"], original_attempt_id)
                self.assertEqual(new_attempt["retry_of_attempt_id"], original_attempt_id)
                self.assertEqual(new_attempt["runtime_plan_sha256"], original_plan_sha)
                self.assertEqual(new_attempt["criterion_ids"], original_criteria)
                self.assertEqual(new_attempt["attempt_number"], 2)

                for _ in range(10):
                    state = controller2.tick_high_autonomy_run()
                    if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                        break
                summary = state["high_autonomy_summary"]
                self.assertEqual(summary["outcome"], "completed")
                history = summary["runtime_attempt_history"]
                self.assertEqual(len(history), 2)
                self.assertEqual(history[0]["semantic_status"], "interrupted")
                self.assertEqual(history[0]["attempt_id"], original_attempt_id)
                self.assertEqual(history[1]["retry_of_attempt_id"], original_attempt_id)
                self.assertEqual(history[1]["semantic_status"], "runtime_verification_pass")


if __name__ == "__main__":
    unittest.main()
