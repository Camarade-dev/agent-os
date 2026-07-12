"""RUN_044 PART M/N: canonical Neon end-to-end orchestration fixture,
plus cross-domain fixtures, driven through the real
ControlSurfaceController + tick_high_autonomy_run loop (never the raw
browser_runtime functions directly -- that is what
tests/test_admissible_neon_runtime_regression.py already covers for
RUN_043's plan/evidence layer in isolation).

Covers required tests 29-37, plus PART M.62-65 variants.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.control_surface import load_persisted_session
from admissible.high_autonomy_controller import HA_MODE_AWAITING_HUMAN_OBSERVATION, HA_MODE_RECOVERING
import admissible.runtime_verification_orchestrator as rvo

from tests._run044_helpers import (
    ANIMATION_LOOP_GOAL,
    FORM_GOAL,
    POLICY_VIOLATION_GOAL,
    UNOBSERVABLE_GOAL,
    force_static_verification_final,
    make_controller,
    start_run,
    tick_until,
)

NEON_GOAL = """Build a complete polished new browser game called Neon Serpents.

Architecture:
- Use plain HTML, CSS, and JavaScript, Canvas 2D, zero dependencies, and no framework.

Mandatory deliverables:
- index.html
- style.css
- src/main.js
- src/game.js
- src/entities.js
- src/bots.js
- src/render.js
- LOCAL_DEV.md

Acceptance criteria:
1. The game opens locally from index.html with no install or network access.
2. The implementation uses Canvas 2D and the required source-module architecture.
3. The arena is large, bounded, and uses a readable motion background.
4. The camera follows the player smoothly through the large world.
5. Pointer steering controls the player serpent.
6. Boost changes speed and has a visible resource tradeoff.
7. At least 12 active bots navigate the arena.
8. Collision causes death and a bounded respawn lifecycle.
9. Collectibles and growth update during play.
10. A live leaderboard updates from active entities.
11. Press R to restart; the game must not create duplicate animation loops.
12. Repeated restarts remain stable.
13. Expose a read-only debugging interface: window.__NEON__ with a snapshot returning at least: playerX, playerY, botCount, cameraX, cameraY, frameRate, paused, loopStarts.
14. The debug overlay is enabled with ?debug=1 and renders the named debug fields.
15. LOCAL_DEV.md documents local opening, controls, architecture, and debugging.

Constraints:
- Do not use shell commands, installs, package managers, network, deploy, publish, hosting, or git operations.
- Only write inside the configured workspace.
- Prefer the smallest coherent bounded batch, without narrowing the complete mission.
"""

EXPECTED_MANDATORY_PATHS = [
    "index.html",
    "style.css",
    "src/main.js",
    "src/game.js",
    "src/entities.js",
    "src/bots.js",
    "src/render.js",
    "LOCAL_DEV.md",
]

NEON_SNAPSHOT = {
    "playerX": 10,
    "playerY": 10,
    "botCount": 12,
    "cameraX": 0,
    "cameraY": 0,
    "frameRate": 60,
    "paused": False,
    "loopStarts": 1,
}

# A smaller goal with only objectively-checkable + subjective criteria (no
# criterion whose contract text has *no* derivable observable at all, unlike
# Neon's collision/leaderboard/repeated-restart criteria, which RUN_043's own
# regression test already establishes as permanently "unsupported_verifier"
# regardless of scenario/instrumentation). Used where a test's premise is
# "every objective observable is available" or "the fix lands and the run
# fully resolves" -- neither of which the full 15-criterion Neon contract can
# ever reach, by RUN_042/043's own design.
INSTRUMENTED_GOAL = """Build a small arena demo.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. At least 12 active bots navigate the arena.
2. The camera follows the player smoothly through the large world.
3. Expose a read-only debugging interface: window.__ARENA__ with a snapshot returning at least: botCount.
"""


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class TestNeonCanonicalFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_neon_end_to_end_objective_pass_subjective_awaits_observation(self):
        """Required tests 29-32."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = start_run(self.controller, NEON_GOAL, self.workspace, max_turns=8)
            contract = self.controller._session.mission_contract
            self.assertEqual(contract["mandatory_paths"], EXPECTED_MANDATORY_PATHS)  # 8/8 paths (test 29)
            ha_state = self.controller._high_autonomy_state()
            self.assertEqual(len(ha_state.acceptance_criteria), 15)  # 15/15 criteria (test 29)

            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": dict(NEON_SNAPSHOT)}))
            force_static_verification_final(self.controller, self.workspace)  # static verification runs first

            # RUN_053: boost has no discoverable documented key binding in
            # this fixture (no real LOCAL_DEV.md is written by this test), so
            # it now correctly surfaces as an explicit, visible, EXPLICITLY
            # instrumentation-fixable gap (PART 1) instead of the pre-fix
            # behavior of silently vanishing from every bucket -- which
            # legitimately opens one bounded repair round requesting a
            # control-key mapping, so the stop condition must include the
            # repair-write state too, not just human observation.
            final = tick_until(
                self.controller,
                max_ticks=15,
                stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, HA_MODE_RECOVERING, "stopped", "failed"),
            )
            summary = final["high_autonomy_summary"]

            # One runtime attempt was created (test 30).
            self.assertEqual(len(summary["runtime_attempt_history"]), 1)
            self.assertEqual(self.controller._session.run_loop.current_turn, 0)

            criteria_by_id = {c["criterion_id"]: c for c in summary["acceptance_criteria"]}
            runtime_ids = [cid for cid, c in criteria_by_id.items() if c["verification_disposition"] == "deterministic_runtime"]
            self.assertEqual(len(runtime_ids), 4)
            self.assertTrue(all(criteria_by_id[cid]["status"] == "verified_pass" for cid in runtime_ids))  # test 30

            human_ids = [cid for cid, c in criteria_by_id.items() if c["verification_disposition"] == "human_observation_required"]
            self.assertEqual(len(human_ids), 2)

            gap_ids = [cid for cid, c in criteria_by_id.items() if c["verification_disposition"] == "unsupported_verifier"]
            # test 32: unsupported criteria remain explicit, not dropped. 4, not 3.
            self.assertEqual(len(gap_ids), 4)
            self.assertEqual(len(criteria_by_id), 15)

            # PART 1: the boost gap is instrumentation-fixable, so the run
            # opened exactly one bounded repair round for it (never
            # "unavailable or exhausted" while budget remained and nothing
            # had been attempted) instead of silently ignoring it forever.
            self.assertEqual(summary["mode"], HA_MODE_RECOVERING)
            packet = summary["repair_packet"]
            self.assertEqual(packet["kind"], "runtime_instrumentation_gap")
            self.assertNotEqual(summary["outcome"], "runtime_observability_gap")

            # Never falsely completes.
            self.assertNotEqual(summary["outcome"], "completed")

    def test_neon_instrumented_variant_all_objective_observables_available(self):
        """PART M.62: with every objective observable available, only
        genuinely subjective criteria remain human-observation pending.

        Uses INSTRUMENTED_GOAL rather than the full Neon contract: Neon's
        collision/leaderboard/repeated-restart criteria have no derivable
        observable at all (RUN_043's own classification, independent of
        scenario/instrumentation), so the full contract can never resolve to
        "only subjective criteria remain" -- see
        test_neon_end_to_end_objective_pass_subjective_awaits_observation for
        that (accurate) expectation on the full 15-criterion fixture.
        """
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, INSTRUMENTED_GOAL, self.workspace, max_turns=8)
            self.controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {"botCount": 12}}))
            force_static_verification_final(self.controller, self.workspace)
            final = tick_until(
                self.controller, max_ticks=15, stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed")
            )
            summary = final["high_autonomy_summary"]
            criteria_by_id = {c["criterion_id"]: c for c in summary["acceptance_criteria"]}
            runtime_ids = [cid for cid, c in criteria_by_id.items() if c["verification_disposition"] == "deterministic_runtime"]
            self.assertGreaterEqual(len(runtime_ids), 1)
            self.assertTrue(all(criteria_by_id[cid]["status"] == "verified_pass" for cid in runtime_ids))
            self.assertEqual(summary["mode"], HA_MODE_AWAITING_HUMAN_OBSERVATION)
            human_ids = [cid for cid, c in criteria_by_id.items() if c["verification_disposition"] == "human_observation_required"]
            self.assertEqual(set(summary["human_observation_pending_criterion_ids"]), set(human_ids))


class TestNeonRuntimeFailureVariant(unittest.TestCase):
    def test_runtime_failure_repairs_and_reruns_without_third_model_turn(self):
        """PART M.63. Uses INSTRUMENTED_GOAL (see its docstring) so the run
        can actually reach a full pass after the fix lands, rather than the
        full Neon contract's permanently-unsupported criteria masking the
        aggregate outcome forever."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, INSTRUMENTED_GOAL, workspace, max_turns=8)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {"botCount": 3}})  # fails "at least 12"
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)
                transport = controller._high_autonomy_transport

                for _ in range(6):
                    state = controller.tick_high_autonomy_run()
                    if state["high_autonomy_tick"].get("planned") == "write_repair_instruction":
                        break
                self.assertEqual(len(transport.written_instructions), 1, "exactly one repair instruction (one model turn)")
                packet = state["high_autonomy_summary"]["repair_packet"]
                self.assertEqual(packet["kind"], "runtime_verification_failure")

                # Simulate the repair response landing (existing RUN_029 machinery).
                from admissible.high_autonomy_controller import HA_MODE_AUTO_EXECUTING, REPAIR_PHASE_REPAIR_VERIFYING

                ha_state = controller._high_autonomy_state()
                ha_state.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
                ha_state.mode = HA_MODE_AUTO_EXECUTING
                controller._set_high_autonomy_state(ha_state)
                controller._persist()
                provider.scenario["initial_snapshot"]["botCount"] = 12  # the "changed file" landing

                for _ in range(8):
                    state = controller.tick_high_autonomy_run()
                    if state["high_autonomy_summary"]["mode"] in (HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed"):
                        break

                summary = state["high_autonomy_summary"]
                self.assertEqual(len(transport.written_instructions), 1, "no third unnecessary model turn")
                history = summary["runtime_attempt_history"]
                self.assertEqual(len(history), 2)
                self.assertEqual(history[0]["semantic_status"], "runtime_verification_fail")
                self.assertEqual(history[1]["semantic_status"], "awaiting_human_observation")
                bots_criterion = next(c for c in summary["acceptance_criteria"] if "12" in c["source_text"])
                self.assertEqual(bots_criterion["status"], "verified_pass")


class TestNeonBrowserUnavailableVariant(unittest.TestCase):
    def test_browser_unavailable_no_model_or_human_authority_gate(self):
        """PART M.64."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, NEON_GOAL, workspace, max_turns=8)
                controller.set_runtime_provider(
                    FixtureBrowserRuntimeProvider({"available": False, "unavailable_reason": "no_browser"})
                )
                force_static_verification_final(controller, workspace)
                transport = controller._high_autonomy_transport
                final = tick_until(controller, max_ticks=10)
                summary = final["high_autonomy_summary"]
                self.assertEqual(summary["outcome"], "verification_capability_gap")
                self.assertEqual(len(transport.written_instructions), 0, "no model/provider invocation")
                self.assertFalse(summary["human_action_required"], "not a human-authority gate")
                self.assertNotEqual(summary.get("current_step"), "internal_livelock")


class TestNeonRecoveryVariant(unittest.TestCase):
    def test_persisted_evidence_survives_restart_and_applies_exactly_once(self):
        """PART M.65."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, NEON_GOAL, workspace, max_turns=8)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": dict(NEON_SNAPSHOT)})
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)

                controller.tick_high_autonomy_run()  # start
                controller.tick_high_autonomy_run()  # poll -> evidence_ready

                ha_state = controller._high_autonomy_state()
                session_id = controller._session.session_id
                with rvo._REGISTRY_LOCK:
                    rvo._WORKERS.pop(session_id, None)
                self.assertEqual(ha_state.active_runtime_attempt["status"], "evidence_ready")
                # Persisted as "running" (process restarts before evidence is applied).
                ha_state.active_runtime_attempt["status"] = "running"
                controller._set_high_autonomy_state(ha_state)
                controller._persist()

                controller2 = make_controller(root)
                load_persisted_session(controller2)
                controller2.set_runtime_provider(provider)

                detect_calls = {"n": 0}
                real_detect = provider.detect_capability

                def _spy(*a, **kw):
                    detect_calls["n"] += 1
                    return real_detect(*a, **kw)

                provider.detect_capability = _spy

                final = tick_until(
                    controller2, max_ticks=10, stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed")
                )
                self.assertEqual(detect_calls["n"], 0, "the browser must not be relaunched during recovery")
                summary = final["high_autonomy_summary"]
                self.assertEqual(len(summary["runtime_attempt_history"]), 1, "evidence applied exactly once")


class TestCrossDomainFixtures(unittest.TestCase):
    """PART N. Minimal RUN_044-authored goal texts (RUN_043 ships static demo
    apps for these scenarios under tests/fixtures/admissible/browser_runtime/,
    but no automated test reads them by path -- see the module docstring)."""

    def _run(self, goal, scenario, *, workspace_name="workspace"):
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            workspace = root / workspace_name
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, goal, workspace, max_turns=8)
                controller.set_runtime_provider(FixtureBrowserRuntimeProvider(scenario))
                force_static_verification_final(controller, workspace)
                final = tick_until(
                    controller, max_ticks=15, stop_modes=(HA_MODE_AWAITING_HUMAN_OBSERVATION, "stopped", "failed")
                )
            return controller, final
        finally:
            tmp.cleanup()

    def test_counter_fixture_completes_end_to_end(self):
        """Required test 33."""
        from tests._run044_helpers import COUNTER_GOAL

        _, final = self._run(COUNTER_GOAL, {"initial_snapshot": {"count": 5}})
        summary = final["high_autonomy_summary"]
        self.assertEqual(summary["outcome"], "completed")

    def test_form_fixture_completes_end_to_end(self):
        """Required test 34."""
        _, final = self._run(FORM_GOAL, {"initial_snapshot": {"valid": True}})
        summary = final["high_autonomy_summary"]
        self.assertEqual(summary["outcome"], "completed")

    def test_animation_loop_fixture_repairs_and_completes(self):
        """Required test 35: a duplicate-loop failure (loopStarts > 1 after
        restart) is detected, repaired, and completes."""
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            workspace = root / "workspace"
            controller = make_controller(root)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, ANIMATION_LOOP_GOAL, workspace, max_turns=8)
                provider = FixtureBrowserRuntimeProvider(
                    {"initial_snapshot": {"loopStarts": 1}, "key_rules": {"R": {"snapshot": {"loopStarts": 2}}}}
                )
                controller.set_runtime_provider(provider)
                force_static_verification_final(controller, workspace)

                for _ in range(6):
                    state = controller.tick_high_autonomy_run()
                    if state["high_autonomy_tick"].get("planned") == "write_repair_instruction":
                        break
                self.assertEqual(state["high_autonomy_summary"]["repair_packet"]["kind"], "runtime_verification_failure")

                from admissible.high_autonomy_controller import HA_MODE_AUTO_EXECUTING, REPAIR_PHASE_REPAIR_VERIFYING

                ha_state = controller._high_autonomy_state()
                ha_state.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
                ha_state.mode = HA_MODE_AUTO_EXECUTING
                controller._set_high_autonomy_state(ha_state)
                controller._persist()
                # The fix: restarting no longer bumps the loop counter.
                provider.scenario["key_rules"] = {"R": {"snapshot": {"loopStarts": 1}}}

                for _ in range(8):
                    state = controller.tick_high_autonomy_run()
                    if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                        break
                summary = state["high_autonomy_summary"]
                self.assertEqual(summary["outcome"], "completed")
                history = summary["runtime_attempt_history"]
                self.assertEqual(history[0]["semantic_status"], "runtime_verification_fail")
                self.assertEqual(history[1]["semantic_status"], "runtime_verification_pass")
        finally:
            tmp.cleanup()

    def test_policy_violation_fixture_cannot_falsely_complete(self):
        """Required test 36."""
        _, final = self._run(
            POLICY_VIOLATION_GOAL,
            {
                "initial_snapshot": {"count": 5},
                "external_request_attempts": [{"url": "https://example.invalid/x", "resource_type": "fetch"}],
            },
        )
        summary = final["high_autonomy_summary"]
        self.assertNotEqual(summary["outcome"], "completed")

    def test_unobservable_fixture_stops_at_observability_gap(self):
        """Required test 37."""
        _, final = self._run(UNOBSERVABLE_GOAL, {})
        summary = final["high_autonomy_summary"]
        self.assertNotEqual(summary["outcome"], "completed")
        criterion = summary["acceptance_criteria"][0]
        self.assertEqual(criterion["verification_disposition"], "unsupported_verifier")


if __name__ == "__main__":
    unittest.main()
