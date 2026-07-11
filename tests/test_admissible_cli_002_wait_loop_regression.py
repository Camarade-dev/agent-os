"""RUN_045 PART J — the cli-002 exported-session regression.

Replays the exact reported livelock from ``control_session_89d4376c8c43``
(minimized as ``tests/fixtures/admissible/pixel_wanderer_cli_002_regression.json``):
after a targeted repair write executed, the run was stuck at
``mode=waiting_for_agent``, ``repair_phase=repair_verifying``,
``next_action=none``, with every tick returning a reasonless wait forever.
Also covers PART H's run-identity angle documented in the same fixture: the
workspace was named ``neon-serpents-cli-002`` while the actual goal was
Pixel Wanderer.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import AgentInvocationRecord, FixtureAgentBackend
from admissible.control_surface import ControlSurfaceController, _run_identity
from admissible.governed_run import FINAL_OUTCOMES
from admissible.high_autonomy_controller import (
    HA_MODE_VERIFYING,
    HA_MODE_WAITING_FOR_AGENT,
    HA_NEXT_VERIFY,
    REPAIR_PHASE_REPAIR_VERIFYING,
    _reconcile_high_autonomy_state,
)

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_002_regression.json"
)


class TestCli002WaitLoopRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_documents_the_reported_defect_surface(self) -> None:
        self.assertEqual(self.fixture["source_session"], "control_session_89d4376c8c43")
        stuck = self.fixture["stuck_state_before_fix"]
        self.assertEqual(stuck["mode"], "waiting_for_agent")
        self.assertEqual(stuck["next_action"], "none")
        self.assertEqual(stuck["repair_phase"], "repair_verifying")
        self.assertEqual(stuck["backend_step"], "response_consumed")
        self.assertEqual(stuck["pending_invocation_status"], "consumed")
        self.assertFalse(stuck["backend_retry_required"])
        self.assertFalse(stuck["backend_reinvoke_pending"])

    def test_exact_reported_state_combination_recovers_via_reconciliation(self) -> None:
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=root / "sessions")
        controller.submit_goal(self.fixture["goal_text"])
        controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=12)
        ha = controller._high_autonomy_state()
        stuck = self.fixture["stuck_state_before_fix"]
        ha.mode = stuck["mode"]
        ha.repair_phase = stuck["repair_phase"]
        ha.repair_round_count = self.fixture["repair_that_executed"]["repair_round_count"]
        ha.transport_kind = "callable_backend"
        ha.backend_step = stuck["backend_step"]
        ha.backend_retry_required = stuck["backend_retry_required"]
        ha.backend_reinvoke_pending = stuck["backend_reinvoke_pending"]
        ha.pending_agent_invocation = AgentInvocationRecord(
            invocation_id="invoke_repair_fix",
            instruction_id="instr_repair",
            backend_id="fixture",
            session_id=controller._session.session_id,
            turn_number=2,
            status=stuck["pending_invocation_status"],
        ).to_dict()
        ha.next_action = "none"
        controller._set_high_autonomy_state(ha)

        changed = _reconcile_high_autonomy_state(controller, ha, transport=None)

        self.assertTrue(changed, "the exact reported combination must be detected and repaired")
        expected = self.fixture["expected_state_after_fix"]
        self.assertEqual(ha.mode, HA_MODE_VERIFYING)
        self.assertEqual(expected["mode"], "verifying")
        self.assertEqual(ha.next_action, HA_NEXT_VERIFY)
        self.assertEqual(expected["next_action"], "run_bounded_verification")
        self.assertEqual(ha.repair_round_count, self.fixture["repair_that_executed"]["repair_round_count"])
        self.assertTrue(expected["repair_round_count_unchanged"])
        records = [
            r for r in controller._session.governance_records
            if r.get("event_type") == expected["governance_record_type"]
        ]
        self.assertEqual(len(records), 1)

    def test_full_callable_backend_replay_completes_without_livelock(self) -> None:
        goal = self.fixture["goal_text"]
        missing_restart_js = self.fixture["game_js_cli002_missing_restart_content"]
        patch = self.fixture["game_js_cli002_repair_patch"]
        fixed_js = missing_restart_js.replace(
            "  window.addEventListener('keydown', (e) => {\n    keys[e.key] = true;\n  });",
            f"  window.addEventListener('keydown', (e) => {{\n    keys[e.key] = true;\n    {patch}\n  }});",
        )
        self.assertNotEqual(fixed_js, missing_restart_js)

        def _response(operations: list[dict]) -> str:
            return "\n".join(
                "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
                + json.dumps(op, ensure_ascii=False)
                + "\n```"
                for op in operations
            )

        initial_ops = [
            {
                "operation": "write_file",
                "path": "index.html",
                "content": '<!doctype html><link rel="stylesheet" href="style.css"><canvas id="game"></canvas><span id="score">0</span><script src="game.js"></script>\n',
            },
            {"operation": "write_file", "path": "style.css", "content": "body{margin:0;}\n"},
            {"operation": "write_file", "path": "game.js", "content": missing_restart_js},
            {
                "operation": "write_file",
                "path": "LOCAL_DEV.md",
                "content": "To run locally, open index.html in your browser.\n",
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Mirror the reported session: a workspace folder name unrelated to
            # the actual (Pixel Wanderer) goal.
            workspace = root / "neon-serpents-cli-002"
            workspace.mkdir()
            backend = FixtureAgentBackend(
                [
                    _response(initial_ops),
                    _response([{"operation": "write_file", "path": "game.js", "content": fixed_js}]),
                ]
            )
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=12, closure_reserve_turns=2
            )
            reasonless_wait_ticks = 0
            outcome = None
            for _ in range(40):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                self.assertNotEqual(summary.get("current_step"), "internal_livelock")
                if (
                    summary.get("mode") == HA_MODE_WAITING_FOR_AGENT
                    and summary.get("next_action") in ("none", "wait_for_agent_response")
                    and summary.get("repair_phase") == REPAIR_PHASE_REPAIR_VERIFYING
                ):
                    reasonless_wait_ticks += 1
                self.assertLess(
                    reasonless_wait_ticks, 3,
                    "must never spin on the reported reasonless post-repair wait",
                )
                outcome = summary.get("outcome")
                if outcome in FINAL_OUTCOMES:
                    break
            self.assertEqual(outcome, "completed")

    def test_run_identity_reveals_the_workspace_goal_mismatch_from_the_report(self) -> None:
        defect = self.fixture["run_identity_defect"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / defect["workspace_basename"]
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(self.fixture["goal_text"])
            controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
            identity = _run_identity(controller._session)
            self.assertEqual(identity["workspace_basename"], defect["workspace_basename"])
            self.assertIn("Pixel Wanderer", identity["goal_first_line"])
            self.assertIsNotNone(
                identity["workspace_mismatch_warning"],
                "workspace name and goal share no token -- must surface a diagnostic warning",
            )


if __name__ == "__main__":
    unittest.main()
