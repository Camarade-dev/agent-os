"""Slice ADMISSIBLE_RUN_021_MULTI_TURN_RUN_TIMELINE tests.

The run timeline is an additive, display-only projection over existing Control
Surface session state:

    goal -> turn -> agent proposal -> admission -> human-triggered local
    execution -> evidence -> next turn

These tests assert it initializes from a goal/session, tracks
turns/admissions/executions/evidence, represents refused/blocked actions, and
never changes the existing single-turn behavior (ingest never executes;
evidence stays visible after execution). The timeline re-decides nothing and
executes nothing on its own.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.control_surface import (
    ControlSurfaceController,
    RunEnvelope,
    _build_queue_item,
)
from admissible.run_loop import (
    RUN_TIMELINE_SCHEMA_VERSION,
    TIMELINE_STATUS_EXECUTED,
    TIMELINE_STATUS_NEEDS_GOAL,
    TIMELINE_STATUS_PLANNED,
    TIMELINE_STATUS_READY_TO_EXECUTE_LOCAL,
    AgentResponseRecord,
    EvidenceRecord,
    RunLoopState,
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


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("run timeline tests must never spawn a subprocess")


def _inject_queue_item(
    controller: ControlSurfaceController,
    *,
    action_id: str,
    decision_label: str = "ALLOW",
    structured_operations: list | None = None,
    execution_status: str = "proposed_only",
) -> str:
    decision = {
        "action_id": action_id,
        "decision_id": f"decision_{action_id}",
        "envelope_id": f"envelope_{action_id}",
        "decision": decision_label,
        "operational_admissibility_action": "block" if decision_label == "REFUSE" else "execute",
        "risk_level": "local",
        "required_approval": "none",
        "missing_evidence": [],
        "audit_trace": {"blast_radius": "blast_radius=local"},
    }
    candidate = {
        "action_id": action_id,
        "envelope_id": decision["envelope_id"],
        "action_type": "create_file",
        "tool_or_command": f"op {action_id}",
        "execution_status": execution_status,
    }
    if structured_operations:
        candidate["structured_operations"] = structured_operations
    envelope = RunEnvelope(
        action_id=action_id,
        envelope_id=decision["envelope_id"],
        decision_id=decision["decision_id"],
        candidate=candidate,
        decision=decision,
    )
    item = _build_queue_item(envelope)
    item.execution_status = execution_status
    controller._session.run_envelopes[action_id] = envelope
    controller._session.queue.append(item)
    return action_id


class TestBuildRunTimelinePureFunction(unittest.TestCase):
    """`build_run_timeline` is a pure projection over session state."""

    def test_needs_goal_when_no_goal_intake(self) -> None:
        timeline = build_run_timeline(
            session_id="s1",
            created_at="2026-01-01T00:00:00Z",
            goal_intake=None,
            queue=[],
            run_loop=RunLoopState(),
        )
        self.assertEqual(timeline.schema_version, RUN_TIMELINE_SCHEMA_VERSION)
        self.assertEqual(timeline.status, TIMELINE_STATUS_NEEDS_GOAL)
        self.assertIsNone(timeline.goal)
        self.assertEqual(timeline.turns, [])

    def test_planned_after_goal_before_any_turn(self) -> None:
        timeline = build_run_timeline(
            session_id="s1",
            created_at="2026-01-01T00:00:00Z",
            goal_intake={"prompt": "build a tiny thing", "deliverable": "tiny thing"},
            queue=[],
            run_loop=RunLoopState(),
        )
        self.assertEqual(timeline.status, TIMELINE_STATUS_PLANNED)
        self.assertEqual(timeline.goal, "build a tiny thing")
        self.assertEqual(timeline.turn_count, 0)

    def test_operation_is_grouped_under_the_turn_that_proposed_it(self) -> None:
        run_loop = RunLoopState(current_turn=1)
        run_loop.response_records.append(
            AgentResponseRecord(
                record_id="agent_response_1",
                turn_number=1,
                created_at="2026-01-01T00:01:00Z",
                raw_text="proposed write of a file",
                source_trust="unverified_agent_output",
                actor="external_frontier_agent",
                action_ids=["act_1"],
            )
        )
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
        timeline = build_run_timeline(
            session_id="s1",
            created_at="2026-01-01T00:00:00Z",
            goal_intake={"prompt": "goal"},
            queue=queue,
            run_loop=run_loop,
        )
        self.assertEqual(len(timeline.turns), 1)
        turn = timeline.turns[0]
        self.assertEqual(turn.turn_number, 1)
        self.assertEqual([op.action_id for op in turn.operations], ["act_1"])
        self.assertIn("act_1", timeline.admitted_operation_ids)
        self.assertIsNotNone(timeline.latest_agent_proposal)
        self.assertEqual(timeline.latest_agent_proposal["operation_count"], 1)

    def test_refused_operation_is_represented_as_blocked(self) -> None:
        queue = [
            {
                "action_id": "act_refuse",
                "tool_or_command": "rm -rf /",
                "decision": "REFUSE",
                "execution_status": "blocked",
                "lifecycle_status": "closed",
            }
        ]
        timeline = build_run_timeline(
            session_id="s1",
            created_at="2026-01-01T00:00:00Z",
            goal_intake={"prompt": "goal"},
            queue=queue,
            run_loop=RunLoopState(),
        )
        self.assertIn("act_refuse", timeline.blocked_operation_ids)
        self.assertNotIn("act_refuse", timeline.admitted_operation_ids)
        blocked_ops = [op for turn in timeline.turns for op in turn.operations if op.blocked]
        self.assertEqual(len(blocked_ops), 1)

    def test_evidence_records_are_counted_per_action_and_total(self) -> None:
        run_loop = RunLoopState()
        run_loop.evidence_records.append(
            EvidenceRecord(
                record_id="ev_1",
                action_id="act_1",
                decision_id=None,
                envelope_id=None,
                actor="bounded_executor",
                timestamp="2026-01-01T00:02:00Z",
                evidence_type="file_write_sha256",
                evidence_text="wrote index.html",
                file_path_or_note="index.html",
                rationale="",
                source="bounded_executor",
                sha256="abc123",
            )
        )
        queue = [{"action_id": "act_1", "decision": "ALLOW", "execution_status": "executed_by_bounded_executor"}]
        timeline = build_run_timeline(
            session_id="s1",
            created_at="2026-01-01T00:00:00Z",
            goal_intake={"prompt": "goal"},
            queue=queue,
            run_loop=run_loop,
        )
        self.assertEqual(timeline.evidence_count, 1)
        op = timeline.turns[0].operations[0]
        self.assertEqual(op.evidence_count, 1)
        self.assertEqual(timeline.status, TIMELINE_STATUS_EXECUTED)


class TestRunTimelineControllerFlow(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.raw = load_fixture(FIXTURES_DIR / TINY_GAME_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _timeline(self) -> dict:
        return self.controller.state_view()["run_timeline"]

    def _ingest_tiny_game(self) -> dict:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            return self.controller.ingest_agent_response(self.raw)

    def test_timeline_present_and_initializes_from_goal(self) -> None:
        # Fresh session: needs a goal.
        self.assertEqual(self._timeline()["status"], TIMELINE_STATUS_NEEDS_GOAL)
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        timeline = self._timeline()
        self.assertEqual(timeline["status"], TIMELINE_STATUS_PLANNED)
        self.assertIn("browser game", timeline["goal"])

    def test_ingesting_structured_response_creates_a_timeline_turn(self) -> None:
        self._ingest_tiny_game()
        timeline = self._timeline()
        self.assertGreaterEqual(timeline["turn_count"], 1)
        self.assertEqual(len(timeline["turns"]), 1)
        turn = timeline["turns"][0]
        self.assertEqual(turn["turn_number"], 1)
        self.assertEqual(len(turn["operations"]), 3)
        self.assertIsNotNone(timeline["latest_agent_proposal"])
        self.assertEqual(timeline["latest_agent_proposal"]["operation_count"], 3)

    def test_admitted_local_operations_appear_in_timeline(self) -> None:
        self._ingest_tiny_game()
        timeline = self._timeline()
        self.assertEqual(len(timeline["admitted_operation_ids"]), 3)
        ops = timeline["turns"][0]["operations"]
        self.assertTrue(all(op["is_local_file_operation"] for op in ops))
        self.assertEqual(
            sorted(p for op in ops for p in op["target_paths"]),
            sorted(GAME_FILES),
        )

    def test_batch_execution_records_execution_and_evidence_in_timeline(self) -> None:
        self._ingest_tiny_game()
        self.controller.set_bounded_executor_workspace(self.workspace)
        # Before execution: ready to execute locally, nothing executed yet.
        before = self._timeline()
        self.assertEqual(before["status"], TIMELINE_STATUS_READY_TO_EXECUTE_LOCAL)
        self.assertEqual(before["ready_to_execute_local_count"], 3)
        self.assertEqual(before["executed_operation_ids"], [])
        self.assertEqual(before["evidence_count"], 0)

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})

        after = self._timeline()
        self.assertEqual(after["status"], TIMELINE_STATUS_EXECUTED)
        self.assertEqual(len(after["executed_operation_ids"]), 3)
        self.assertEqual(after["evidence_count"], 3)
        self.assertEqual(after["ready_to_execute_local_count"], 0)
        executed_ops = [op for op in after["turns"][0]["operations"] if op["executed"]]
        self.assertEqual(len(executed_ops), 3)
        # Each executed op still carries an evidence record and its op detail.
        for op in executed_ops:
            self.assertEqual(op["execution_status"], EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR)
            self.assertGreaterEqual(op["evidence_count"], 1)
            self.assertEqual(op["operation_types"], ["write_file"])

    def test_refused_action_is_represented_in_timeline(self) -> None:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        _inject_queue_item(
            self.controller,
            action_id="refused_op",
            decision_label="REFUSE",
        )
        timeline = self._timeline()
        self.assertIn("refused_op", timeline["blocked_operation_ids"])

    def test_single_turn_behavior_unchanged_ingest_does_not_execute(self) -> None:
        state = self._ingest_tiny_game()
        # No files written on ingest; nothing executed in the timeline.
        self.assertEqual([n for n in GAME_FILES if (self.workspace / n).is_file()], [])
        timeline = state["run_timeline"]
        self.assertEqual(timeline["executed_operation_ids"], [])
        self.assertFalse(state["mission_summary"]["side_effect_executed_by_admissible"])

    def test_evidence_stays_visible_in_timeline_after_export_import(self) -> None:
        self._ingest_tiny_game()
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
        exported = self.controller.session_dict()
        reloaded = ControlSurfaceController(session_dir=self.root / "reload")
        imported = reloaded.import_session(exported)
        timeline = imported["run_timeline"]
        self.assertEqual(timeline["evidence_count"], 3)
        self.assertEqual(len(timeline["executed_operation_ids"]), 3)


class TestRunTimelineHtml(unittest.TestCase):
    def test_html_contains_run_timeline_panel(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Run Timeline",
            'id="run-timeline-panel"',
            'id="run-timeline-body"',
            "renderRunTimeline",
            "run_timeline",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")


if __name__ == "__main__":
    unittest.main()
