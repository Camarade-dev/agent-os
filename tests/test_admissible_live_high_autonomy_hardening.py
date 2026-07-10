"""Slice ADMISSIBLE_RUN_030_LIVE_HIGH_AUTONOMY_REHEARSAL_HARDENING tests.

Hardens the high-autonomy governed loop for a live Cursor/file-bridge rehearsal:
robust FileBridge transport, turn-metadata alignment, safe browser auto-tick
markers, a human-critical pause path, and a minimal live status surface.

Constraints exercised: no provider/Cursor API, no shell/npm/network/deploy
execution, admission/content guards never weakened, human-critical actions
never auto-approved, manual/supervised mode unchanged.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import (
    EXECUTION_STATUS_ADMITTED_NOT_EXECUTED,
    EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
)
from admissible.agent_transport import (
    TRANSPORT_STATUS_INSTRUCTION_WRITTEN,
    TRANSPORT_STATUS_RESPONSE_CONSUMED,
    TRANSPORT_STATUS_RESPONSE_DETECTED,
    TRANSPORT_STATUS_STALE_BLOCKED,
    FileBridgeAgentTransport,
    FixtureAgentTransport,
)
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import (
    HA_MODE_HUMAN_REQUIRED,
    HA_MODE_STOPPED,
    HA_MODE_WAITING_FOR_AGENT,
)
from admissible.high_autonomy_policy import HighAutonomyPolicy
from admissible.runner import cursor_bridge
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"
TURN_3_FIXTURE = "tiny_game_turn_3_blocked_agent_response.md"

TURN_1_FILES = ("index.html", "style.css", "game.js")

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)

# Nothing in the header line mentions git so only the explicit command segment
# is extracted as a genuinely human-critical proposal.
GIT_PUSH_RESPONSE = (
    "Cursor Agent — publish request (nothing executed)\n\n"
    "User: Publish the game so others can play it.\n\n"
    "Thinking...\n"
    "I will send the local commits to the remote so it is visible online.\n\n"
    "Proposed command:\n"
    "    git push origin main\n\n"
    "Status: PROPOSED — awaiting the admission gate.\n"
    "Note: Nothing was executed.\n"
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("high-autonomy loop must never spawn a subprocess")


def _workspace_files(workspace: Path) -> set[str]:
    return {p.name for p in workspace.iterdir() if p.is_file()}


class TestFileBridgeTransportHardening(unittest.TestCase):
    """FileBridgeAgentTransport writes instructions and detects only fresh responses."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name) / "ws"
        self.workspace.mkdir()
        self.transport = FileBridgeAgentTransport(self.workspace)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _response_path(self) -> Path:
        return self.workspace / cursor_bridge.BRIDGE_SUBDIR / cursor_bridge.RESPONSE_FILENAME

    def test_writes_instruction_and_bridge_metadata(self) -> None:
        result = self.transport.write_instruction(
            "Turn 1 instruction.", turn_number=1, session_id="sess_a", instruction_id="pkt_1"
        )
        instruction_path = Path(result["instruction_path"])
        self.assertTrue(instruction_path.is_file())
        self.assertEqual(instruction_path.name, cursor_bridge.INSTRUCTION_FILENAME)

        bridge_state = cursor_bridge.read_bridge_state(self.workspace)
        self.assertEqual(bridge_state["turn"], 1)
        self.assertEqual(bridge_state["session_id"], "sess_a")
        self.assertTrue(bridge_state["awaiting_response"])

        snap = self.transport.status_snapshot()
        self.assertEqual(snap["status"], TRANSPORT_STATUS_INSTRUCTION_WRITTEN)
        self.assertEqual(snap["current_turn"], 1)
        self.assertEqual(snap["session_id"], "sess_a")

    def test_same_response_is_not_ingested_twice(self) -> None:
        self.transport.write_instruction("Turn 1.", turn_number=1, session_id="sess_a")
        self._response_path().write_text("first reply", encoding="utf-8")

        first = self.transport.read_response_if_changed()
        self.assertTrue(first.changed)
        self.assertEqual(first.status, TRANSPORT_STATUS_RESPONSE_DETECTED)

        # Controller confirms ingest; the identical file must not be re-detected.
        self.transport.mark_response_consumed(turn_number=1, response_sha256=first.cursor)
        self.assertEqual(
            self.transport.status_snapshot()["status"], TRANSPORT_STATUS_RESPONSE_CONSUMED
        )

        second = self.transport.read_response_if_changed()
        self.assertFalse(second.changed)
        self.assertEqual(second.status, TRANSPORT_STATUS_STALE_BLOCKED)

    def test_stale_response_predating_instruction_is_blocked(self) -> None:
        # A leftover response written before the current instruction is stale.
        response_path = self._response_path()
        response_path.parent.mkdir(parents=True, exist_ok=True)
        response_path.write_text("old leftover reply", encoding="utf-8")
        old = time.time() - 600
        os.utime(response_path, (old, old))

        self.transport.write_instruction("Turn 5.", turn_number=5, session_id="sess_a")
        # write_instruction archived the leftover; recreate an old one to prove
        # the mtime guard independently blocks a pre-instruction response.
        response_path.write_text("still an old reply", encoding="utf-8")
        os.utime(response_path, (old, old))

        result = self.transport.read_response_if_changed()
        self.assertFalse(result.changed)
        self.assertEqual(result.status, TRANSPORT_STATUS_STALE_BLOCKED)

    def test_new_response_after_new_instruction_is_accepted(self) -> None:
        self.transport.write_instruction("Turn 1.", turn_number=1, session_id="sess_a")
        self._response_path().write_text("reply one", encoding="utf-8")
        r1 = self.transport.read_response_if_changed()
        self.assertTrue(r1.changed)
        self.transport.mark_response_consumed(turn_number=1, response_sha256=r1.cursor)

        # New instruction archives the old response; a fresh reply is accepted.
        self.transport.write_instruction("Turn 2.", turn_number=2, session_id="sess_a")
        self.assertFalse(self._response_path().is_file(), "prior response should be archived")
        self._response_path().write_text("reply two", encoding="utf-8")
        r2 = self.transport.read_response_if_changed()
        self.assertTrue(r2.changed)
        self.assertNotEqual(r1.cursor, r2.cursor)


class TestHighAutonomyLiveFileBridge(unittest.TestCase):
    """Controller drives a live file-bridge loop with aligned turn metadata."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.transport = FileBridgeAgentTransport(self.workspace)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _response_path(self) -> Path:
        return self.workspace / cursor_bridge.BRIDGE_SUBDIR / cursor_bridge.RESPONSE_FILENAME

    def _cursor_writes(self, text: str) -> None:
        """Simulate Cursor writing its reply, guaranteeing a post-instruction mtime."""
        path = self._response_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        future = time.time() + 5
        os.utime(path, (future, future))

    def test_live_bridge_auto_writes_and_metadata_aligns(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=self.transport, max_turns=8
            )

            # Tick 1: instruction is written to the workspace automatically.
            self.controller.tick_high_autonomy_run()
            instruction_path = (
                self.workspace / cursor_bridge.BRIDGE_SUBDIR / cursor_bridge.INSTRUCTION_FILENAME
            )
            self.assertTrue(instruction_path.is_file())

            bridge_state = cursor_bridge.read_bridge_state(self.workspace)
            self.assertEqual(bridge_state["turn"], self.controller._session.run_loop.current_turn)
            self.assertEqual(bridge_state["session_id"], self.controller._session.session_id)
            self.assertEqual(self.transport._current_turn, 1)
            self.assertEqual(self.transport._session_id, self.controller._session.session_id)

            # Cursor replies with the turn-1 scaffold.
            self._cursor_writes(load_fixture(FIXTURES_DIR / TURN_1_FIXTURE))

            # Tick 2: response detected + ingested (no workspace writes yet).
            t2 = self.controller.tick_high_autonomy_run()
            self.assertTrue((t2.get("high_autonomy_tick") or {}).get("ingested"))
            self.assertEqual(t2["run_loop"]["current_turn"], 1)
            self.assertEqual(_workspace_files(self.workspace), set())

            # Tick 3: auto-execute the admitted local writes.
            self.controller.tick_high_autonomy_run()
            for name in TURN_1_FILES:
                self.assertTrue((self.workspace / name).is_file())

            summary = self.controller.state_view()["high_autonomy_summary"]
            self.assertEqual(summary["transport_kind"], "file_bridge")
            self.assertEqual(summary["workspace_path"], str(self.workspace))
            self.assertTrue(str(summary["instruction_path"]).endswith(cursor_bridge.INSTRUCTION_FILENAME))

    def test_consumed_response_not_ingested_twice_via_controller(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=self.transport, max_turns=8
            )
            self.controller.tick_high_autonomy_run()  # write instruction
            self._cursor_writes(load_fixture(FIXTURES_DIR / TURN_1_FIXTURE))
            self.controller.tick_high_autonomy_run()  # ingest
            self.assertEqual(len(self.controller._session.run_loop.response_records), 1)

            # Re-reading the same file without a new instruction yields nothing new.
            read = self.transport.read_response_if_changed()
            self.assertFalse(read.changed)
            self.assertEqual(read.status, TRANSPORT_STATUS_STALE_BLOCKED)


class TestFixtureTurnMetadataAlignment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.transport = FixtureAgentTransport()
        self.transport.set_responses([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_transport_records_controller_turn_and_session(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=self.transport, max_turns=8
            )
            self.controller.tick_high_autonomy_run()  # write turn-1 instruction
            self.assertEqual(len(self.transport.written_instruction_meta), 1)
            meta = self.transport.written_instruction_meta[-1]
            self.assertEqual(meta["turn_number"], self.controller._session.run_loop.current_turn)
            self.assertEqual(meta["session_id"], self.controller._session.session_id)
            self.assertIsNotNone(meta["instruction_id"])


class TestHighAutonomyHumanCriticalPause(unittest.TestCase):
    """A genuinely human-critical proposal pauses; approval never invents execution."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.transport = FixtureAgentTransport()
        self.transport.set_responses([GIT_PUSH_RESPONSE])

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _drive_to_human_required(self) -> dict:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace), transport=self.transport, max_turns=8
        )
        state = self.controller.state_view()
        for _ in range(8):
            state = self.controller.tick_high_autonomy_run()
            if state["high_autonomy_summary"]["mode"] == HA_MODE_HUMAN_REQUIRED:
                return state
        return state

    def test_human_critical_git_push_pauses_with_reason(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self._drive_to_human_required()
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["mode"], HA_MODE_HUMAN_REQUIRED)
            self.assertTrue(summary["human_action_required"])
            self.assertTrue(summary["human_required_reason"])
            self.assertTrue(summary["pending_human_action_id"])
            self.assertFalse(summary["auto_tick_safe"])
            # Nothing was auto-executed and nothing hit the workspace.
            self.assertEqual(summary["auto_executed_action_count"], 0)
            self.assertEqual(_workspace_files(self.workspace), set())

    def test_approval_records_decision_without_execution(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self._drive_to_human_required()
            action_id = state["high_autonomy_summary"]["pending_human_action_id"]
            self.assertTrue(action_id)

            approved = self.controller.approve_high_autonomy_human_action(action_id)
            summary = approved["high_autonomy_summary"]
            self.assertFalse(summary["human_action_required"])

            item = next(i for i in approved["queue"] if i["action_id"] == action_id)
            # Recorded as admitted-not-executed — no shell/network executor exists.
            self.assertEqual(item["execution_status"], EXECUTION_STATUS_ADMITTED_NOT_EXECUTED)
            self.assertTrue(item["human_decision_ids"])
            self.assertEqual(_workspace_files(self.workspace), set())

    def test_refusal_records_decision_and_reopens_loop(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self._drive_to_human_required()
            action_id = state["high_autonomy_summary"]["pending_human_action_id"]
            refused = self.controller.refuse_high_autonomy_human_action(action_id)
            summary = refused["high_autonomy_summary"]
            self.assertNotEqual(summary["mode"], HA_MODE_HUMAN_REQUIRED)
            item = next(i for i in refused["queue"] if i["action_id"] == action_id)
            self.assertTrue(item["human_decision_ids"])
            self.assertEqual(_workspace_files(self.workspace), set())


class TestHighAutonomyAutoExecutionBounds(unittest.TestCase):
    """Auto-execution stays inside the admitted, local, in-workspace envelope."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_auto_executes_low_risk_local_writes(self) -> None:
        transport = FixtureAgentTransport()
        transport.set_responses([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=transport, max_turns=8
            )
            for _ in range(6):
                state = self.controller.tick_high_autonomy_run()
                executed = (state.get("high_autonomy_tick") or {}).get("executed_action_ids")
                if executed:
                    break
            for name in TURN_1_FILES:
                self.assertTrue((self.workspace / name).is_file())

    def test_does_not_auto_execute_npm_or_deploy(self) -> None:
        transport = FixtureAgentTransport()
        transport.set_responses([load_fixture(FIXTURES_DIR / TURN_3_FIXTURE)])
        policy = HighAutonomyPolicy()
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=transport, max_turns=8
            )
            self.controller.tick_high_autonomy_run()  # write instruction
            self.controller.tick_high_autonomy_run()  # ingest turn-3 blocker

            queue = self.controller._session.queue
            self.assertTrue(queue)
            for item in queue:
                env = self.controller._session.run_envelopes.get(item.action_id)
                self.assertFalse(
                    policy.is_auto_executable(
                        item=item, envelope=env, workspace_path=str(self.workspace)
                    )
                )

            for _ in range(6):
                state = self.controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["mode"] == HA_MODE_STOPPED:
                    break
            summary = self.controller.state_view()["high_autonomy_summary"]
            self.assertEqual(summary["auto_executed_action_count"], 0)
            # No npm/deploy side effects: workspace stays free of executed writes.
            executed = [
                op
                for turn in self.controller.state_view()["run_timeline"]["turns"]
                for op in turn["operations"]
                if op.get("execution_status") == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
            ]
            self.assertEqual(executed, [])

    def test_outside_workspace_write_is_not_auto_executed(self) -> None:
        op = json.dumps({"operation": "write_file", "path": "../escape.txt", "content": "x"})
        response = (
            "Turn 1 — proposing a write.\n\n"
            "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n" + op + "\n```\n\nStatus: PROPOSED\n"
        )
        transport = FixtureAgentTransport()
        transport.set_responses([response])
        policy = HighAutonomyPolicy()
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=transport, max_turns=8
            )
            self.controller.tick_high_autonomy_run()  # write instruction
            self.controller.tick_high_autonomy_run()  # ingest
            for item in self.controller._session.queue:
                env = self.controller._session.run_envelopes.get(item.action_id)
                classification = policy.classify_action(
                    item=item, envelope=env, workspace_path=str(self.workspace)
                )
                self.assertEqual(classification.category, "human_critical")
            self.assertFalse((self.root / "escape.txt").exists())
            self.assertFalse((self.workspace.parent / "escape.txt").exists())


class TestHighAutonomyMinimalStatusAndHtml(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_summary_exposes_live_transport_state_and_stays_minimal(self) -> None:
        transport = FixtureAgentTransport()
        transport.set_responses([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace), transport=transport
        )
        view = self.controller.state_view()
        summary = view["high_autonomy_summary"]
        for key in (
            "doing_now",
            "needed_now",
            "transport_status",
            "workspace_path",
            "waiting_for_agent",
            "human_action_required",
            "verification_readiness",
            "auto_tick_safe",
            "live_rehearsal_status",
        ):
            self.assertIn(key, summary)
        # Minimal: the primary summary must not embed raw queue/transcript logs.
        self.assertNotIn("queue", summary)
        self.assertNotIn("transcript", summary)

        live = view["live_high_autonomy_rehearsal_status"]
        for key in (
            "workspace_path",
            "transport_status",
            "instruction_path",
            "response_path",
            "current_turn",
            "waiting_for_cursor",
            "stale_response_blocked",
            "human_action_required",
            "verification_passed",
        ):
            self.assertIn(key, live)

    def test_html_has_auto_run_markers(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        self.assertIn("Auto-run while safe", html)
        self.assertIn("Pause auto-run", html)
        self.assertIn("Step once", html)
        self.assertIn("auto_tick_safe", html)
        self.assertIn("renderAutoRunStatusLine", html)
        # Raw logs/queues remain under the Advanced/Debug drawer.
        self.assertIn('id="advanced-debug-details"', html)


class TestManualModeUnchanged(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_manual_ingest_writes_nothing_without_high_autonomy(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(load_fixture(FIXTURES_DIR / TURN_1_FIXTURE))
            self.assertEqual(_workspace_files(self.workspace), set())
            summary = self.controller.state_view()["high_autonomy_summary"]
            self.assertFalse(summary["active"])
            self.assertFalse(summary["auto_tick_safe"])


if __name__ == "__main__":
    unittest.main()
