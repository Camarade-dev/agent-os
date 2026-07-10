"""Slice ADMISSIBLE_RUN_031_HUMAN_REQUIRED_REFUSAL_RECOVERY_FIX tests.

Fixes the high-autonomy governed loop so a human-critical action can be refused
and the run continues safely with a local-only recovery instruction.

Root cause covered here:

- Refusing only the single surfaced ``pending_human_action_id`` left other open
  human-critical proposals undecided, so the next tick re-entered
  ``human_required`` — the UI stayed stuck. Refusal now clears *every* open
  human-critical action and hands off to a bounded local-only recovery step.
- A capability that the rules-only evaluator already ``REFUSE``d is
  human-critical but offers no human action, so it must not pin the loop in
  ``human_required`` nor make ``decide(refuse)`` raise.

Constraints exercised: no provider/Cursor API, no shell/npm/network/deploy
execution, admission/content guards never weakened, human-critical actions
never auto-approved, manual/supervised mode unchanged.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
from admissible.agent_transport import FileBridgeAgentTransport, FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController, available_human_actions
from admissible.high_autonomy_controller import (
    HA_MODE_HUMAN_REQUIRED,
    HA_MODE_RECOVERING,
    HA_MODE_WAITING_FOR_AGENT,
    HA_NEXT_WRITE_RECOVERY,
)
from admissible.runner import cursor_bridge

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)

# One response proposing TWO genuinely human-critical actions (git commit + push).
# This is the multi-action case that used to leave the loop stuck in
# human_required after refusing only the first one.
MULTI_HUMAN_CRITICAL_RESPONSE = (
    "Cursor Agent — publish request (nothing executed)\n\n"
    "User: Publish the game so others can play it.\n\n"
    "Thinking...\n"
    "I will commit and push the local commits to the remote so it is visible online.\n\n"
    "Proposed command:\n"
    "    git commit -m 'ship game'\n\n"
    "Proposed command:\n"
    "    git push origin main\n\n"
    "Status: PROPOSED — awaiting the admission gate.\n"
    "Note: Nothing was executed.\n"
)

# Single human-critical publish action (admission REQUIRE_HUMAN_APPROVAL).
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
    raise AssertionError("high-autonomy refusal recovery must never spawn a subprocess")


def _workspace_files(workspace: Path) -> set[str]:
    return {p.name for p in workspace.iterdir() if p.is_file()}


class _HumanRequiredCase(unittest.TestCase):
    """Shared harness driving a fixture response to the human_required pause."""

    response_text = MULTI_HUMAN_CRITICAL_RESPONSE

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.transport = FixtureAgentTransport()
        self.transport.set_responses([self.response_text])

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
        self.fail("run never reached human_required")


class TestHumanRequiredIsActionSpecific(_HumanRequiredCase):
    def test_state_view_exposes_all_blocking_action_ids_and_reasons(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self._drive_to_human_required()
        summary = state["high_autonomy_summary"]
        self.assertTrue(summary["human_action_required"])
        self.assertEqual(summary["human_required_action_count"], 2)
        self.assertEqual(len(summary["human_required_action_ids"]), 2)
        # Every blocking action carries a concise label + reason (not a generic
        # message), and the surfaced pending id is one of them.
        actions = summary["human_required_actions"]
        self.assertEqual(len(actions), 2)
        for entry in actions:
            self.assertIn(entry["action_id"], summary["human_required_action_ids"])
            self.assertTrue(entry["reason"])
            self.assertTrue(entry["action_type"])
        self.assertIn(summary["pending_human_action_id"], summary["human_required_action_ids"])
        # The live rehearsal status mirrors the same blocking detail.
        live = state["live_high_autonomy_rehearsal_status"]
        self.assertEqual(live["human_required_action_count"], 2)


class TestRefusalClearsAllAndRecovers(_HumanRequiredCase):
    def test_refusing_records_decisions_for_all_open_human_critical_ids(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self._drive_to_human_required()
            blocking_ids = list(state["high_autonomy_summary"]["human_required_action_ids"])
            self.assertEqual(len(blocking_ids), 2)

            refused = self.controller.refuse_high_autonomy_human_action(None)

        summary = refused["high_autonomy_summary"]
        # Exits human_required immediately and heads into recovery.
        self.assertEqual(summary["mode"], HA_MODE_RECOVERING)
        self.assertFalse(summary["human_action_required"])
        self.assertEqual(summary["human_required_action_count"], 0)
        self.assertEqual(summary["next_action"], HA_NEXT_WRITE_RECOVERY)
        # A refusal decision was recorded for EVERY previously-open action.
        by_id = {i["action_id"]: i for i in refused["queue"]}
        for aid in blocking_ids:
            self.assertTrue(by_id[aid]["human_decision_ids"], aid)
            self.assertEqual(by_id[aid]["lifecycle_status"], "refused_closed")

    def test_next_tick_exits_human_required_and_writes_recovery(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self._drive_to_human_required()
            self.controller.refuse_high_autonomy_human_action(None)
            # The next safe tick composes the recovery instruction automatically.
            state = self.controller.tick_high_autonomy_run()

        summary = state["high_autonomy_summary"]
        self.assertNotEqual(summary["mode"], HA_MODE_HUMAN_REQUIRED)
        self.assertEqual(summary["mode"], HA_MODE_WAITING_FOR_AGENT)
        tick = state["high_autonomy_tick"]
        self.assertEqual(tick["planned"], HA_NEXT_WRITE_RECOVERY)
        self.assertTrue(tick.get("refusal_recovery"))
        # The recovery instruction is bounded + local-only and names the refused
        # forms so the agent does not retry them.
        recovery = self.transport.written_instructions[-1]
        self.assertIn("RECOVERY REQUEST (human refusal)", recovery)
        self.assertIn("git push origin main", recovery)
        self.assertIn(".admissible/agent-response.md", recovery)
        for forbidden in ("npm", "deploy", "network"):
            self.assertIn(forbidden, recovery.lower())

    def test_refused_actions_remain_not_completed_and_not_executed(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self._drive_to_human_required()
            self.controller.refuse_high_autonomy_human_action(None)
            self.controller.tick_high_autonomy_run()

        for item in self.controller._session.queue:
            # Refused actions are never marked executed and never auto-approved.
            self.assertEqual(item.execution_status, "proposed_only")
            self.assertNotIn(item.execution_status, ("executed_by_bounded_executor",))
            self.assertEqual(item.lifecycle_status, "refused_closed")
        # Nothing was executed into the workspace.
        self.assertEqual(_workspace_files(self.workspace), set())

    def test_same_response_not_ingested_twice_after_refusal(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self._drive_to_human_required()
            self.assertEqual(len(self.controller._session.run_loop.response_records), 1)
            self.controller.refuse_high_autonomy_human_action(None)
            # Several recovery/idle ticks must not re-ingest the consumed response.
            for _ in range(4):
                self.controller.tick_high_autonomy_run()
        self.assertEqual(len(self.controller._session.run_loop.response_records), 1)


class TestDuplicateResponseDoesNotBlockRecovery(_HumanRequiredCase):
    def test_duplicate_response_warning_does_not_prevent_refusal_recovery(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self._drive_to_human_required()
            # Simulate the noisy bridge "duplicate response already ingested"
            # warning being recorded while paused; it must not block recovery.
            self.controller.record_bridge_ingest_blocked(
                "duplicate_response",
                workspace_path=str(self.workspace),
                response_sha256="deadbeef",
                turn_number=1,
            )
            refused = self.controller.refuse_high_autonomy_human_action(None)
            self.assertEqual(refused["high_autonomy_summary"]["mode"], HA_MODE_RECOVERING)
            state = self.controller.tick_high_autonomy_run()

        # Recovery proceeded despite the recorded duplicate-response warning.
        self.assertEqual(state["high_autonomy_summary"]["mode"], HA_MODE_WAITING_FOR_AGENT)
        self.assertIn(
            "RECOVERY REQUEST (human refusal)", self.transport.written_instructions[-1]
        )
        # The warning is still visible (stale-response protection intact), just
        # non-fatal.
        diagnostics = state["session_diagnostics"]
        self.assertEqual(diagnostics["latest_bridge_blocked_ingest"]["reason"], "duplicate_response")


class TestApprovalRecordsIntentWithoutExecution(unittest.TestCase):
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
        self.fail("run never reached human_required")

    def test_approval_records_admitted_not_executed_no_shell(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self._drive_to_human_required()
            action_id = state["high_autonomy_summary"]["pending_human_action_id"]
            approved = self.controller.approve_high_autonomy_human_action(action_id)

        summary = approved["high_autonomy_summary"]
        self.assertFalse(summary["human_action_required"])
        item = next(i for i in approved["queue"] if i["action_id"] == action_id)
        # Recorded as admitted-not-executed — no shell/network executor exists.
        self.assertEqual(item["execution_status"], EXECUTION_STATUS_ADMITTED_NOT_EXECUTED)
        self.assertTrue(item["human_decision_ids"])
        self.assertEqual(_workspace_files(self.workspace), set())

    def test_approve_rejects_non_approvable_action_clearly(self) -> None:
        # A REQUEST_MORE_EVIDENCE proposal cannot be approved; the loop must not
        # invent approval authority for it.
        multi = FixtureAgentTransport()
        multi.set_responses([MULTI_HUMAN_CRITICAL_RESPONSE])
        controller = ControlSurfaceController(session_dir=self.root / "sessions2")
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            controller.submit_goal(CANONICAL_GOAL_PROMPT)
            controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=multi, max_turns=8
            )
            for _ in range(8):
                state = controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["mode"] == HA_MODE_HUMAN_REQUIRED:
                    break
            pending = state["high_autonomy_summary"]["pending_human_action_id"]
            item = controller._find_queue_item(pending)
            # Confirm the surfaced pending action is genuinely not approvable.
            self.assertNotIn("approve", available_human_actions(item, controller._session.autonomy_level))
            with self.assertRaises(ValueError):
                controller.approve_high_autonomy_human_action(pending)


class TestRefusedRefuseOnlyDecisionDoesNotPin(unittest.TestCase):
    """A capability the rules already REFUSE must not pin the loop in human_required."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_refuse_admission_shell_action_is_not_an_open_human_decision(self) -> None:
        from admissible.control_surface import DecisionQueueItem
        from admissible.high_autonomy_controller import _open_human_critical_actions
        from admissible.high_autonomy_policy import HighAutonomyPolicy

        # A run_shell_command the evaluator already REFUSEd: human-critical by
        # capability, but no human action is available for it.
        item = DecisionQueueItem(
            action_id="a1",
            tool_or_command="rm -rf /",
            action_type="run_shell_command",
            decision="REFUSE",
            operational_admissibility_action=None,
            risk_level="high",
            required_approval=None,
            missing_evidence=[],
            execution_status="proposed_only",
            attestation_eligible=False,
        )
        self.controller._session.queue.append(item)
        self.controller._session.bounded_executor_workspace = str(self.workspace)
        self.assertEqual(
            available_human_actions(item, self.controller._session.autonomy_level), []
        )
        # It must NOT be reported as an open human-critical decision.
        open_actions = _open_human_critical_actions(self.controller, HighAutonomyPolicy())
        self.assertEqual(open_actions, [])


class TestLiveFileBridgeRefusalRecoveryWritesInstruction(unittest.TestCase):
    """End-to-end over the real file bridge: recovery instruction hits the file."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.transport = FileBridgeAgentTransport(self.workspace)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cursor_writes(self, text: str) -> None:
        path = self.workspace / cursor_bridge.BRIDGE_SUBDIR / cursor_bridge.RESPONSE_FILENAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        future = time.time() + 5
        os.utime(path, (future, future))

    def test_refusal_recovery_instruction_written_to_bridge_file(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), transport=self.transport, max_turns=8
            )
            self.controller.tick_high_autonomy_run()  # write turn-1 instruction
            self._cursor_writes(MULTI_HUMAN_CRITICAL_RESPONSE)
            for _ in range(6):
                state = self.controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["mode"] == HA_MODE_HUMAN_REQUIRED:
                    break
            self.controller.refuse_high_autonomy_human_action(None)
            self.controller.tick_high_autonomy_run()  # write recovery instruction

        instruction_path = (
            self.workspace / cursor_bridge.BRIDGE_SUBDIR / cursor_bridge.INSTRUCTION_FILENAME
        )
        self.assertTrue(instruction_path.is_file())
        text = instruction_path.read_text(encoding="utf-8")
        self.assertIn("RECOVERY REQUEST (human refusal)", text)
        # No forbidden executor side effects reached the workspace.
        self.assertEqual(_workspace_files(self.workspace), set())


class TestHtmlSurfacesBlockingActions(unittest.TestCase):
    def test_html_renders_blocking_actions_and_uses_new_fields(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        self.assertIn("human_required_actions", html)
        self.assertIn("human_required_action_ids", html)
        self.assertIn("ha-blocking-actions", html)
        self.assertIn("Blocking human-critical action(s)", html)


if __name__ == "__main__":
    unittest.main()
