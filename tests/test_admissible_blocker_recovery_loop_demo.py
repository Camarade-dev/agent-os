"""Slice ADMISSIBLE_DEMO_024_BLOCKER_AND_RECOVERY_LOOP tests.

Extends the two-turn local build demo with a deterministic blocker/recovery
sequence:

    Turns 1–2: happy-path scaffold + enhancement (reused flow)
    Turn 3: agent proposes npm install + deploy -> admission gates them;
            ingest writes no files; continuation carries them as not completed
    Turn 4: agent proposes revised local-only writes -> admission + explicit
            batch execution -> evidence accumulates; run continues

Hard constraints: no provider calls, no shell/npm/network/deploy execution,
no auto-execute on ingest, no broadened executor capabilities.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.control_surface import ControlSurfaceController
from admissible.long_run_envelope_builder import (
    STRUCTURED_OPERATION_MARKER,
    extract_structured_operation_blocks,
)
from admissible.run_loop import (
    CONTINUATION_NOT_COMPLETED_AWAITING_DECISION,
    CONTINUATION_STATUS_EVIDENCE_GROUNDED,
    CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
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

_FORBIDDEN_ACTION_TYPES = (
    "install_dependency",
    "git_push",
    "git_commit",
    "deploy_code",
    "prepare_deploy",
    "run_shell_command",
    "run_command",
)

_STRICT_BRIDGE_MARKERS = (
    ".admissible/agent-response.md",
    "Do not write files directly",
    "shell",
    "npm",
    "network",
    "deploy",
    "structured operations",
    "next smallest admissible step",
    "no explicit completion signal",
    "must NOT be treated as done",
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("blocker/recovery demo must never spawn a subprocess")


class TestBlockerRecoveryDemoFixtures(unittest.TestCase):
    """Deterministic blocker/recovery fixtures parse through existing extractors."""

    def test_turn_3_fixture_has_no_structured_writes(self) -> None:
        raw = load_fixture(FIXTURES_DIR / TURN_3_FIXTURE)
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(blocks, [])
        self.assertIn("npm install", raw)
        self.assertIn("deploy to production", raw.lower())

    def test_turn_4_fixture_has_local_recovery_writes(self) -> None:
        raw = load_fixture(FIXTURES_DIR / TURN_4_FIXTURE)
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 2)
        paths = [op["path"] for block in blocks for op in block["operations"]]
        self.assertIn(TURN_4_NEW_FILE, paths)
        self.assertIn("index.html", paths)
        self.assertGreaterEqual(raw.count(STRUCTURED_OPERATION_MARKER), 2)


class TestBlockerRecoveryLoopDemo(unittest.TestCase):
    """End-to-end four-turn governed loop with blocker and local recovery."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.turn_1_raw = load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)
        self.turn_2_raw = load_fixture(FIXTURES_DIR / TURN_2_FIXTURE)
        self.turn_3_raw = load_fixture(FIXTURES_DIR / TURN_3_FIXTURE)
        self.turn_4_raw = load_fixture(FIXTURES_DIR / TURN_4_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _timeline(self) -> dict:
        return self.controller.state_view()["run_timeline"]

    def _continuation(self) -> dict:
        return self.controller.state_view()["continuation_instruction"]

    def _action_ids_for_turn(self, state: dict, turn_number: int) -> list[str]:
        for record in state["run_loop"]["response_records"]:
            if record["turn_number"] == turn_number:
                return list(record["action_ids"])
        return []

    def _assert_no_executable_forbidden_capabilities(self, state: dict) -> None:
        """Blocked proposals may remain on the queue; they must not be locally executable."""
        for entry in state.get("ready_to_execute_locally") or []:
            self.assertNotIn(
                entry.get("action_type"),
                _FORBIDDEN_ACTION_TYPES,
                f"forbidden action type ready to execute: {entry}",
            )
        for item in state["queue"]:
            if not item.get("bounded_execution_eligible"):
                continue
            self.assertNotIn(
                item.get("action_type"),
                _FORBIDDEN_ACTION_TYPES,
                f"forbidden action type marked executable: {item}",
            )
            tool = (item.get("tool_or_command") or "").lower()
            for forbidden in ("npm install", "git push", "deploy", "curl ", "wget "):
                self.assertNotIn(forbidden, tool)

    def _run_two_turn_happy_path(self) -> dict:
        """Replicate turns 1–2 from the multi-turn local build demo."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_1_raw)

        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local_batch(
                {"workspace_path": str(self.workspace)}
            )
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_2_raw)
            return self.controller.execute_bounded_local_batch(
                {"workspace_path": str(self.workspace)}
            )

    def test_four_turn_blocker_recovery_governed_loop(self) -> None:
        turn_2_state = self._run_two_turn_happy_path()
        self.assertEqual(turn_2_state["run_timeline"]["evidence_count"], 6)
        workspace_files_before_blocker = {
            p.name for p in self.workspace.iterdir() if p.is_file()
        }
        self.assertEqual(
            workspace_files_before_blocker,
            set(TURN_1_FILES) | {TURN_2_NEW_FILE},
        )

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.generate_next_instruction_packet()
            turn_3_state = self.controller.ingest_agent_response(self.turn_3_raw)

        self.assertEqual(turn_3_state["run_loop"]["current_turn"], 3)
        self.assertEqual(
            {p.name for p in self.workspace.iterdir() if p.is_file()},
            workspace_files_before_blocker,
            "blocker ingest must not write workspace files",
        )
        self.assertFalse(turn_3_state["mission_summary"]["side_effect_executed_by_admissible"])

        turn_3_ids = set(self._action_ids_for_turn(turn_3_state, 3))
        self.assertEqual(len(turn_3_ids), 2)
        turn_3_items = [
            i for i in turn_3_state["queue"] if i["action_id"] in turn_3_ids
        ]
        decisions = {item["decision"] for item in turn_3_items}
        self.assertEqual(decisions, {"REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL"})
        action_types = {item["action_type"] for item in turn_3_items}
        self.assertEqual(action_types, {"install_dependency", "deploy_code"})

        for item in turn_3_items:
            self.assertFalse(item["bounded_execution_eligible"])
            self.assertEqual(item["execution_status"], "proposed_only")
            self.assertNotEqual(item["decision"], "ALLOW")

        ready_after_blocker = self.controller.state_view()["ready_to_execute_locally"]
        ready_ids = {entry["action_id"] for entry in ready_after_blocker}
        self.assertFalse(turn_3_ids & ready_ids)

        timeline_after_blocker = self._timeline()
        self.assertEqual(len(timeline_after_blocker["turns"]), 3)
        turn_3_ops = timeline_after_blocker["turns"][2]["operations"]
        self.assertEqual(len(turn_3_ops), 2)
        self.assertTrue(all(not op["executed"] for op in turn_3_ops))
        self.assertTrue(all(not op["is_local_file_operation"] for op in turn_3_ops))

        cont_after_blocker = self._continuation()
        self.assertTrue(cont_after_blocker["available"])
        self.assertEqual(cont_after_blocker["status"], CONTINUATION_STATUS_EVIDENCE_GROUNDED)
        not_completed = cont_after_blocker["not_completed_operations"]
        self.assertEqual(len(not_completed), 2)
        not_completed_ids = {op["action_id"] for op in not_completed}
        self.assertEqual(not_completed_ids, set(turn_3_ids))
        for op in not_completed:
            self.assertEqual(op["category"], CONTINUATION_NOT_COMPLETED_AWAITING_DECISION)
        cont_text = cont_after_blocker["instruction_text"]
        for action_id in turn_3_ids:
            self.assertIn(action_id, cont_text)
        self.assertIn("must NOT be treated as done", cont_text)
        for marker in _STRICT_BRIDGE_MARKERS:
            self.assertIn(marker, cont_text, f"missing bridge marker: {marker}")

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.generate_next_instruction_packet()
            turn_4_state = self.controller.ingest_agent_response(self.turn_4_raw)

        self.assertEqual(turn_4_state["run_loop"]["current_turn"], 4)
        self.assertNotIn(TURN_4_NEW_FILE, {p.name for p in self.workspace.iterdir()})

        turn_4_ids = set(self._action_ids_for_turn(turn_4_state, 4))
        turn_4_items = [
            i
            for i in turn_4_state["queue"]
            if i.get("action_type") == "create_file" and i["action_id"] in turn_4_ids
        ]
        self.assertEqual(len(turn_4_items), 2)
        for item in turn_4_items:
            self.assertEqual(item["decision"], "ALLOW")
            self.assertTrue(item["bounded_execution_eligible"])
            self.assertEqual(item["execution_status"], "proposed_only")

        turn_4_ready = self.controller.state_view()["ready_to_execute_locally"]
        turn_4_ready_ids = {e["action_id"] for e in turn_4_ready}
        self.assertEqual(len([aid for aid in turn_4_ids if aid in turn_4_ready_ids]), 2)

        timeline_before_recovery_exec = self._timeline()
        self.assertEqual(timeline_before_recovery_exec["ready_to_execute_local_count"], 2)
        self.assertGreater(timeline_before_recovery_exec["pending_human_decision_count"], 0)

        cont_before_recovery_exec = self._continuation()
        self.assertFalse(cont_before_recovery_exec["available"])
        self.assertEqual(
            cont_before_recovery_exec["status"],
            CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
        )
        self.assertEqual(len(cont_before_recovery_exec["pending_execution_operations"]), 2)

        evidence_count_before_recovery = timeline_before_recovery_exec["evidence_count"]

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            turn_4_exec_state = self.controller.execute_bounded_local_batch(
                {"workspace_path": str(self.workspace)}
            )

        self.assertTrue((self.workspace / TURN_4_NEW_FILE).is_file())
        index_html = (self.workspace / "index.html").read_text(encoding="utf-8")
        self.assertIn("local-only", index_html.lower())
        local_dev = (self.workspace / TURN_4_NEW_FILE).read_text(encoding="utf-8")
        self.assertIn("package manager", local_dev)
        self.assertIn("local-only", local_dev.lower())

        final_timeline = turn_4_exec_state["run_timeline"]
        self.assertEqual(len(final_timeline["turns"]), 4)
        self.assertEqual(
            [t["turn_number"] for t in final_timeline["turns"]],
            [1, 2, 3, 4],
        )
        self.assertGreater(final_timeline["evidence_count"], evidence_count_before_recovery)
        self.assertEqual(final_timeline["evidence_count"], 8)

        executed_turn_4 = [
            op
            for op in final_timeline["turns"][3]["operations"]
            if op["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertEqual(len(executed_turn_4), 2)

        turn_3_timeline_ops = final_timeline["turns"][2]["operations"]
        self.assertEqual(len(turn_3_timeline_ops), 2)
        self.assertTrue(all(not op["executed"] for op in turn_3_timeline_ops))

        final_cont = turn_4_exec_state["continuation_instruction"]
        self.assertTrue(final_cont["available"])
        self.assertIn(TURN_4_NEW_FILE, final_cont["instruction_text"])
        self.assertIn("must NOT be treated as done", final_cont["instruction_text"])
        for action_id in turn_3_ids:
            self.assertIn(action_id, final_cont["instruction_text"])

        self._assert_no_executable_forbidden_capabilities(turn_4_exec_state)
        self.assertFalse((self.workspace / "package.json").exists())


if __name__ == "__main__":
    unittest.main()
