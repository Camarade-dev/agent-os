"""Slice ADMISSIBLE_RUN_022_EVIDENCE_GROUNDED_CONTINUATION tests.

The evidence-grounded continuation composes the next bounded Cursor instruction
from the current run timeline + executed evidence:

    goal -> turn -> proposal -> admission -> local execution -> evidence
         -> next bounded instruction grounded in that evidence

These tests assert it: refuses to continue without a goal; refuses to continue
while admitted local operations are still pending execution; grounds the next
instruction in executed file paths + sha256 evidence once execution has run;
carries blocked/refused actions forward as explicitly *not completed*; preserves
the strict bridge constraints (structured operations only, no direct file
writes, no shell/npm/network/deploy, write only to `.admissible/agent-response.md`);
and preserves the existing first-turn instruction behavior. It re-decides
nothing, executes nothing, and calls no provider.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.control_surface import ControlSurfaceController
from admissible.run_loop import (
    CONTINUATION_NOT_COMPLETED_REFUSED,
    CONTINUATION_STATUS_EVIDENCE_GROUNDED,
    CONTINUATION_STATUS_FIRST_TURN,
    CONTINUATION_STATUS_NO_GOAL,
    CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
    AgentResponseRecord,
    EvidenceRecord,
    RunLoopState,
    build_continuation_instruction,
    build_run_timeline,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"
FIXTURES_DIR = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "fixtures"
    / "pasted_agent_responses"
)
TINY_GAME_FIXTURE = "tiny_local_game_structured_scaffold.txt"
GAME_FILES = ("index.html", "style.css", "game.js")

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)
GOAL_INTAKE = {
    "prompt": CANONICAL_GOAL_PROMPT,
    "deliverable": "tiny local-only browser game",
    "task_type": "build",
    "risk_scope": "local",
}

_STRICT_BRIDGE_MARKERS = (
    ".admissible/agent-response.md",
    "Do not write files directly",
    "shell",
    "npm",
    "network",
    "deploy",
    "structured operations",
    "next smallest admissible step",
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("continuation tests must never spawn a subprocess")


def _response_record(turn_number: int, action_ids: list[str]) -> AgentResponseRecord:
    return AgentResponseRecord(
        record_id=f"resp_{turn_number}",
        turn_number=turn_number,
        created_at="2026-07-09T00:00:00Z",
        raw_text="pasted, unverified agent output",
        source_trust="unverified_agent_output",
        actor="external_frontier_agent",
        action_ids=list(action_ids),
    )


def _continuation(
    goal_intake,
    queue,
    run_loop,
    *,
    operation_context=None,
    turn_number=2,
):
    timeline = build_run_timeline(
        session_id="session_x",
        created_at="2026-07-09T00:00:00Z",
        goal_intake=goal_intake,
        queue=queue,
        run_loop=run_loop,
        operation_context=operation_context or {},
    )
    return build_continuation_instruction(
        turn_number=turn_number,
        autonomy_level="L1_PROPOSE_ONLY",
        goal_intake=goal_intake,
        plan_audit={},
        queue=queue,
        run_loop=run_loop,
        run_timeline=timeline,
    )


class TestContinuationPureFunction(unittest.TestCase):
    def test_no_continuation_without_goal(self) -> None:
        cont = _continuation(None, [], RunLoopState(), turn_number=1)
        self.assertFalse(cont.available)
        self.assertEqual(cont.status, CONTINUATION_STATUS_NO_GOAL)
        self.assertIsNone(cont.instruction_text)

    def test_first_turn_preserved_when_no_response_ingested(self) -> None:
        cont = _continuation(GOAL_INTAKE, [], RunLoopState(), turn_number=1)
        self.assertTrue(cont.available)
        self.assertEqual(cont.status, CONTINUATION_STATUS_FIRST_TURN)
        # The first-turn text is the standard instruction packet, unchanged --
        # it is not the evidence-grounded continuation document.
        self.assertIn("Admissible Next Agent Instruction Packet", cont.instruction_text)
        self.assertNotIn("Evidence-Grounded Continuation", cont.instruction_text)
        self.assertEqual(cont.executed_operations, [])

    def test_no_continuation_while_local_ops_pending_execution(self) -> None:
        run_loop = RunLoopState(current_turn=1)
        run_loop.response_records.append(_response_record(1, ["act_1"]))
        queue = [
            {
                "action_id": "act_1",
                "tool_or_command": "write index.html",
                "action_type": "create_file",
                "decision": "ALLOW",
                "execution_status": "proposed_only",
                "lifecycle_status": "ready_for_next_agent_instruction",
            }
        ]
        op_ctx = {
            "act_1": {
                "operation_types": ["write_file"],
                "target_paths": ["index.html"],
                "structured_operation_count": 1,
            }
        }
        cont = _continuation(GOAL_INTAKE, queue, run_loop, operation_context=op_ctx)
        self.assertFalse(cont.available)
        self.assertEqual(cont.status, CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION)
        self.assertIsNone(cont.instruction_text)
        self.assertEqual(
            [op["action_id"] for op in cont.pending_execution_operations], ["act_1"]
        )
        self.assertIn("not executed yet", cont.reason)

    def test_continuation_after_execution_includes_paths_and_evidence(self) -> None:
        run_loop = RunLoopState(current_turn=1)
        run_loop.response_records.append(_response_record(1, ["act_1"]))
        run_loop.evidence_records.append(
            EvidenceRecord(
                record_id="ev_1",
                action_id="act_1",
                decision_id=None,
                envelope_id=None,
                actor="bounded_executor",
                timestamp="2026-07-09T00:00:00Z",
                evidence_type="bounded_local_write",
                evidence_text="Wrote file index.html (42 chars)",
                file_path_or_note="index.html",
                rationale="",
                source="bounded_executor",
                sha256="deadbeefcafe",
            )
        )
        queue = [
            {
                "action_id": "act_1",
                "tool_or_command": "write index.html",
                "action_type": "create_file",
                "decision": "ALLOW",
                "execution_status": EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
                "lifecycle_status": "closed",
            }
        ]
        op_ctx = {
            "act_1": {
                "operation_types": ["write_file"],
                "target_paths": ["index.html"],
                "structured_operation_count": 1,
            }
        }
        cont = _continuation(GOAL_INTAKE, queue, run_loop, operation_context=op_ctx)
        self.assertTrue(cont.available)
        self.assertEqual(cont.status, CONTINUATION_STATUS_EVIDENCE_GROUNDED)
        self.assertEqual(cont.executed_count, 1)
        executed = cont.executed_operations
        self.assertEqual(len(executed), 1)
        self.assertEqual(executed[0]["action_id"], "act_1")
        self.assertEqual(executed[0]["operation_types"], ["write_file"])
        self.assertEqual(executed[0]["written_paths"], ["index.html"])
        self.assertEqual(executed[0]["sha256"], ["deadbeefcafe"])
        # The grounded facts appear in the copy-ready instruction text.
        self.assertIn("index.html", cont.instruction_text)
        self.assertIn("deadbeefcafe", cont.instruction_text)
        self.assertIn("act_1", cont.instruction_text)

    def test_continuation_includes_blocked_refused_as_not_completed(self) -> None:
        run_loop = RunLoopState(current_turn=1)
        run_loop.response_records.append(_response_record(1, ["act_refuse"]))
        queue = [
            {
                "action_id": "act_refuse",
                "tool_or_command": "deploy to production",
                "action_type": "deploy",
                "decision": "REFUSE",
                "execution_status": "blocked",
                "lifecycle_status": "refused_closed",
            }
        ]
        cont = _continuation(GOAL_INTAKE, queue, run_loop)
        self.assertTrue(cont.available)
        self.assertEqual(cont.status, CONTINUATION_STATUS_EVIDENCE_GROUNDED)
        not_completed = cont.not_completed_operations
        self.assertEqual(len(not_completed), 1)
        self.assertEqual(not_completed[0]["action_id"], "act_refuse")
        self.assertEqual(not_completed[0]["category"], CONTINUATION_NOT_COMPLETED_REFUSED)
        self.assertIn("act_refuse", cont.instruction_text)
        self.assertIn("must NOT be treated as done", cont.instruction_text)

    def test_continuation_reports_missing_evidence_for_request_more_evidence(self) -> None:
        run_loop = RunLoopState(current_turn=1)
        run_loop.response_records.append(_response_record(1, ["act_ev"]))
        queue = [
            {
                "action_id": "act_ev",
                "tool_or_command": "run migration",
                "action_type": "migrate",
                "decision": "REQUEST_MORE_EVIDENCE",
                "execution_status": "proposed_only",
                "lifecycle_status": "needs_human_input",
                "missing_evidence": ["backup_confirmation"],
            }
        ]
        cont = _continuation(GOAL_INTAKE, queue, run_loop)
        self.assertTrue(cont.available)
        self.assertEqual(len(cont.not_completed_operations), 1)
        self.assertIn("backup_confirmation", cont.not_completed_operations[0]["reason"])

    def test_continuation_preserves_strict_bridge_constraints(self) -> None:
        run_loop = RunLoopState(current_turn=1)
        run_loop.response_records.append(_response_record(1, ["act_1"]))
        run_loop.evidence_records.append(
            EvidenceRecord(
                record_id="ev_1",
                action_id="act_1",
                decision_id=None,
                envelope_id=None,
                actor="bounded_executor",
                timestamp="2026-07-09T00:00:00Z",
                evidence_type="bounded_local_write",
                evidence_text="Wrote file game.js",
                file_path_or_note="game.js",
                rationale="",
                source="bounded_executor",
                sha256="0011aabb",
            )
        )
        queue = [
            {
                "action_id": "act_1",
                "decision": "ALLOW",
                "execution_status": EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
                "lifecycle_status": "closed",
            }
        ]
        op_ctx = {
            "act_1": {
                "operation_types": ["write_file"],
                "target_paths": ["game.js"],
                "structured_operation_count": 1,
            }
        }
        cont = _continuation(GOAL_INTAKE, queue, run_loop, operation_context=op_ctx)
        text = cont.instruction_text
        for marker in _STRICT_BRIDGE_MARKERS:
            self.assertIn(marker, text, f"missing strict bridge constraint: {marker}")
        # It carries the base packet's "there is no executor" boundary forward and
        # never declares the overall goal complete.
        self.assertIn("Do not claim an action was executed", text)
        self.assertIn("no explicit completion signal", text)


class TestContinuationControllerFlow(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.raw = load_fixture(FIXTURES_DIR / TINY_GAME_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _continuation_view(self) -> dict:
        return self.controller.state_view()["continuation_instruction"]

    def _ingest_tiny_game(self) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.ingest_agent_response(self.raw)

    def test_controller_exposes_first_turn_continuation(self) -> None:
        # Fresh session: no goal -> no continuation.
        self.assertEqual(self._continuation_view()["status"], CONTINUATION_STATUS_NO_GOAL)
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        view = self._continuation_view()
        self.assertTrue(view["available"])
        self.assertEqual(view["status"], CONTINUATION_STATUS_FIRST_TURN)

    def test_controller_blocks_continuation_until_execution_then_grounds_it(self) -> None:
        self._ingest_tiny_game()
        before = self._continuation_view()
        self.assertFalse(before["available"])
        self.assertEqual(before["status"], CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION)
        self.assertEqual(len(before["pending_execution_operations"]), 3)
        self.assertIsNone(before["instruction_text"])

        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})

        after = self._continuation_view()
        self.assertTrue(after["available"])
        self.assertEqual(after["status"], CONTINUATION_STATUS_EVIDENCE_GROUNDED)
        self.assertEqual(after["executed_count"], 3)
        text = after["instruction_text"]
        for name in GAME_FILES:
            self.assertIn(name, text)
        self.assertIn("sha256", text)
        for marker in _STRICT_BRIDGE_MARKERS:
            self.assertIn(marker, text, f"missing strict bridge constraint: {marker}")

    def test_continuation_is_display_only_and_does_not_execute_or_advance_turn(self) -> None:
        self._ingest_tiny_game()
        turn_before = self.controller.session_dict()["run_loop"]["current_turn"]
        # Reading the continuation view (repeatedly) executes nothing and never
        # advances the persisted run-loop turn; it is a pure projection.
        self._continuation_view()
        self._continuation_view()
        self.assertEqual(
            self.controller.session_dict()["run_loop"]["current_turn"], turn_before
        )
        self.assertEqual(
            [n for n in GAME_FILES if (self.workspace / n).is_file()], []
        )
        # Continuation is a derived view field, not persisted source-of-truth.
        self.assertNotIn("continuation_instruction", self.controller.session_dict())


class TestContinuationHtml(unittest.TestCase):
    def test_html_contains_continuation_panel(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Evidence-Grounded Continuation",
            'id="continuation-panel"',
            'id="continuation-body"',
            'id="continuation-text"',
            'id="btn-copy-continuation"',
            "renderContinuation",
            "continuation_instruction",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")


if __name__ == "__main__":
    unittest.main()
