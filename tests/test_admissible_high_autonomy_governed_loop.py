"""Slice ADMISSIBLE_RUN_029_HIGH_AUTONOMY_GOVERNED_LOOP_V0 tests.

Deterministic tick-driven high-autonomy governed loop using FixtureAgentTransport.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import (
    HA_MODE_HUMAN_REQUIRED,
    HA_MODE_STOPPED,
    HA_MODE_WAITING_FOR_AGENT,
    HA_NEXT_WRITE_INSTRUCTION,
)
from admissible.high_autonomy_policy import HighAutonomyPolicy
from admissible.run_loop import (
    CONTINUATION_STATUS_EVIDENCE_GROUNDED,
    CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"
TURN_3_FIXTURE = "tiny_game_turn_3_blocked_agent_response.md"
TURN_4_FIXTURE = "tiny_game_turn_4_recovery_agent_response.md"

TURN_1_FILES = ("index.html", "style.css", "game.js")
TURN_2_NEW_FILE = "README.md"
TURN_4_NEW_FILE = "LOCAL_DEV.md"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("high-autonomy loop must never spawn a subprocess")


def _tick_until(controller, transport, *, max_ticks: int = 40, target_mode: str | None = None):
    """Drive ticks until mode matches or no progress."""
    for _ in range(max_ticks):
        state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]
        if target_mode and summary["mode"] == target_mode:
            return state
        tick = state.get("high_autonomy_tick") or {}
        if tick.get("planned") == "wait_for_agent_response" and tick.get("step") == "wait":
            break
    return controller.state_view()


class TestHighAutonomyPolicy(unittest.TestCase):
    def test_refuses_npm_and_deploy_auto_execution(self) -> None:
        policy = HighAutonomyPolicy()

        class _Item:
            action_id = "a1"
            decision = "REQUEST_MORE_EVIDENCE"
            action_type = "install_dependency"
            tool_or_command = "npm install left-pad"
            execution_status = "proposed_only"

        result = policy.classify_action(item=_Item(), envelope=None, workspace_path="/tmp/ws")
        self.assertEqual(result.category, "recoverable_blocker")

        class _Deploy:
            action_id = "a2"
            decision = "REQUIRE_HUMAN_APPROVAL"
            action_type = "deploy_code"
            tool_or_command = "deploy to production"
            execution_status = "proposed_only"

        result2 = policy.classify_action(item=_Deploy(), envelope=None, workspace_path="/tmp/ws")
        self.assertEqual(result2.category, "recoverable_blocker")


class TestHighAutonomyGovernedLoop(unittest.TestCase):
    """End-to-end tick-driven four-turn high-autonomy governed loop."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.transport = FixtureAgentTransport()
        self.transport.set_responses(
            [
                load_fixture(FIXTURES_DIR / TURN_1_FIXTURE),
                load_fixture(FIXTURES_DIR / TURN_2_FIXTURE),
                load_fixture(FIXTURES_DIR / TURN_3_FIXTURE),
                load_fixture(FIXTURES_DIR / TURN_4_FIXTURE),
            ]
        )
        self.turn_3_raw = load_fixture(FIXTURES_DIR / TURN_3_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _drive_loop(self) -> dict:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            manual_view = self.controller.state_view()
            self.assertNotIn("high_autonomy_summary", manual_view.get("session_dict", {}))

            start_state = self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace),
                transport=self.transport,
                max_turns=8,
            )
            self.assertTrue(start_state["high_autonomy_summary"]["active"])
            self.assertEqual(self.controller._session.autonomy_level, "L4_HIGH_AUTONOMY_HARD_GATES")

            # Tick 1: write turn 1 instruction automatically
            t1 = self.controller.tick_high_autonomy_run()
            self.assertEqual(len(self.transport.written_instructions), 1)
            self.assertEqual(
                t1["high_autonomy_summary"]["mode"],
                HA_MODE_WAITING_FOR_AGENT,
            )

            # Tick 2: ingest turn 1
            t2 = self.controller.tick_high_autonomy_run()
            self.assertTrue((t2.get("high_autonomy_tick") or {}).get("ingested"))
            self.assertEqual(t2["run_loop"]["current_turn"], 1)
            self.assertEqual(
                {p.name for p in self.workspace.iterdir() if p.is_file()},
                set(),
                "ingest must not write workspace files",
            )

            # Tick 3: auto-execute turn 1 writes
            t3 = self.controller.tick_high_autonomy_run()
            executed_ids = (t3.get("high_autonomy_tick") or {}).get("executed_action_ids") or []
            self.assertEqual(len(executed_ids), 3)
            for name in TURN_1_FILES:
                self.assertTrue((self.workspace / name).is_file())

            # Tick 4: write evidence-grounded continuation for turn 2
            t4 = self.controller.tick_high_autonomy_run()
            self.assertEqual(len(self.transport.written_instructions), 2)
            cont_text = self.transport.written_instructions[-1]
            self.assertIn("sha256", cont_text.lower())

            # Tick 5: ingest turn 2
            t5 = self.controller.tick_high_autonomy_run()
            self.assertTrue((t5.get("high_autonomy_tick") or {}).get("ingested"))
            self.assertEqual(t5["run_loop"]["current_turn"], 2)

            # Tick 6: auto-execute turn 2
            t6 = self.controller.tick_high_autonomy_run()
            self.assertTrue((self.workspace / TURN_2_NEW_FILE).is_file())

            # Tick 7: write continuation for turn 3
            self.controller.tick_high_autonomy_run()

            # Tick 8: ingest turn 3 blocker
            t8 = self.controller.tick_high_autonomy_run()
            self.assertEqual(t8["run_loop"]["current_turn"], 3)
            workspace_files_before_recovery = {
                p.name for p in self.workspace.iterdir() if p.is_file()
            }
            self.assertEqual(
                workspace_files_before_recovery,
                set(TURN_1_FILES) | {TURN_2_NEW_FILE},
            )

            turn_3_ids = set()
            for record in t8["run_loop"]["response_records"]:
                if record["turn_number"] == 3:
                    turn_3_ids = set(record["action_ids"])
            turn_3_items = [i for i in t8["queue"] if i["action_id"] in turn_3_ids]
            self.assertEqual({i["action_type"] for i in turn_3_items}, {"install_dependency", "deploy_code"})
            for item in turn_3_items:
                self.assertFalse(item["bounded_execution_eligible"])
                self.assertNotEqual(item["decision"], "ALLOW")

            # Tick 9: should not auto-execute blockers; write recovery instruction
            t9 = self.controller.tick_high_autonomy_run()
            tick9 = t9.get("high_autonomy_tick") or {}
            if tick9.get("planned") == "auto_execute_low_risk":
                t9 = self.controller.tick_high_autonomy_run()
                tick9 = t9.get("high_autonomy_tick") or {}
            self.assertIn("RECOVERY REQUEST", self.transport.written_instructions[-1])

            # Tick 10: ingest turn 4 recovery
            t10 = self.controller.tick_high_autonomy_run()
            if (t10.get("high_autonomy_tick") or {}).get("planned") == HA_NEXT_WRITE_INSTRUCTION:
                t10 = self.controller.tick_high_autonomy_run()
            self.assertTrue((t10.get("high_autonomy_tick") or {}).get("ingested") or t10["run_loop"]["current_turn"] == 4)

            # Tick 11+: auto-execute recovery writes
            state = t10
            for _ in range(6):
                state = self.controller.tick_high_autonomy_run()
                tick = state.get("high_autonomy_tick") or {}
                if tick.get("executed_action_ids"):
                    break
            self.assertTrue((self.workspace / TURN_4_NEW_FILE).is_file())

            # Verification step when policy allows
            for _ in range(4):
                state = self.controller.tick_high_autonomy_run()
                if (state.get("high_autonomy_tick") or {}).get("verified"):
                    break

            return state

    def test_high_autonomy_four_turn_governed_loop(self) -> None:
        final_state = self._drive_loop()
        timeline = final_state["run_timeline"]
        self.assertEqual(len(timeline["turns"]), 4)
        self.assertGreaterEqual(timeline["evidence_count"], 8)

        turn_3_ops = timeline["turns"][2]["operations"]
        self.assertTrue(all(not op["executed"] for op in turn_3_ops))

        executed_turn_4 = [
            op
            for op in timeline["turns"][3]["operations"]
            if op["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertEqual(len(executed_turn_4), 2)

        summary = final_state["high_autonomy_summary"]
        self.assertGreater(summary["auto_executed_action_count"], 0)
        self.assertIn(summary["mode"], (HA_MODE_STOPPED, HA_MODE_WAITING_FOR_AGENT, "verifying"))

        cont = final_state["continuation_instruction"]
        self.assertIn("must NOT be treated as done", cont.get("instruction_text") or "")

    def test_manual_mode_unchanged_without_high_autonomy(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.generate_next_instruction_packet()
            before = {p.name for p in self.workspace.iterdir() if p.is_file()}
            self.controller.ingest_agent_response(load_fixture(FIXTURES_DIR / TURN_1_FIXTURE))
            after = {p.name for p in self.workspace.iterdir() if p.is_file()}
            self.assertEqual(before, after)
            ready = self.controller.state_view()["ready_to_execute_locally"]
            self.controller.set_bounded_executor_workspace(self.workspace)
            ready = self.controller.state_view()["ready_to_execute_locally"]
            self.assertGreater(len(ready), 0)
            # Without high-autonomy start, files remain until explicit batch execute
            self.assertEqual(len(list(self.workspace.iterdir())), 0)

    def test_high_autonomy_opt_in(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            view = self.controller.state_view()
            self.assertFalse(view["high_autonomy_summary"]["active"])
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace),
                transport=self.transport,
            )
            self.assertTrue(self.controller.state_view()["high_autonomy_summary"]["active"])

    def test_state_view_exposes_minimal_high_autonomy_summary(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace),
                transport=self.transport,
            )
            summary = self.controller.state_view()["high_autonomy_summary"]
            for key in (
                "mode",
                "doing_now",
                "needed_now",
                "last_event",
                "evidence_count",
                "verification_readiness",
                "primary_button",
            ):
                self.assertIn(key, summary)

    def test_html_high_autonomy_panel_is_primary(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        self.assertIn('id="high-autonomy-panel"', html)
        self.assertIn("renderHighAutonomy", html)
        self.assertIn("high_autonomy_summary", html)
        self.assertIn("/api/session/high_autonomy/start", html)
        self.assertIn('id="advanced-debug-details"', html)


if __name__ == "__main__":
    unittest.main()
