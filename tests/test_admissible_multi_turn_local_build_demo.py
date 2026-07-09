"""Slice ADMISSIBLE_DEMO_023_MULTI_TURN_LOCAL_BUILD tests.

Proves a two-turn governed local build loop using deterministic fixtures:

    Turn 1: propose scaffold -> ingest (no writes) -> explicit batch execution
            -> sha256 evidence -> evidence-grounded continuation available
    Turn 2: advance turn -> ingest enhancement -> explicit batch execution
            -> accumulated evidence -> timeline shows both turns

Hard constraints: no provider calls, no shell/npm/network/deploy, no auto-execute
on ingest, no broadened executor capabilities.
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
    CONTINUATION_STATUS_EVIDENCE_GROUNDED,
    CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
    TIMELINE_STATUS_EXECUTED,
    TIMELINE_STATUS_READY_TO_EXECUTE_LOCAL,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"

TURN_1_FILES = ("index.html", "style.css", "game.js")
TURN_2_NEW_FILE = "README.md"

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
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("multi-turn local build demo must never spawn a subprocess")


class TestMultiTurnLocalBuildDemoFixtures(unittest.TestCase):
    """Deterministic fixtures parse through the structured-operation contract."""

    def test_turn_1_fixture_has_three_scaffold_writes(self) -> None:
        raw = load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 3)
        paths = [op["path"] for block in blocks for op in block["operations"]]
        self.assertEqual(paths, list(TURN_1_FILES))
        self.assertGreaterEqual(raw.count(STRUCTURED_OPERATION_MARKER), 3)

    def test_turn_2_fixture_has_enhancement_writes(self) -> None:
        raw = load_fixture(FIXTURES_DIR / TURN_2_FIXTURE)
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 3)
        paths = [op["path"] for block in blocks for op in block["operations"]]
        self.assertIn("index.html", paths)
        self.assertIn("game.js", paths)
        self.assertIn(TURN_2_NEW_FILE, paths)
        self.assertIn("WASD", raw)
        self.assertIn("restart", raw.lower())


class TestMultiTurnLocalBuildDemo(unittest.TestCase):
    """End-to-end two-turn governed local build loop."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.turn_1_raw = load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)
        self.turn_2_raw = load_fixture(FIXTURES_DIR / TURN_2_FIXTURE)

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

    def _assert_no_forbidden_capabilities(self, state: dict) -> None:
        for item in state["queue"]:
            self.assertNotIn(
                item.get("action_type"),
                _FORBIDDEN_ACTION_TYPES,
                f"forbidden action type in queue: {item}",
            )
            tool = (item.get("tool_or_command") or "").lower()
            for forbidden in ("npm install", "git push", "deploy", "curl ", "wget "):
                self.assertNotIn(forbidden, tool)

    def test_two_turn_governed_local_build_loop(self) -> None:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.assertEqual(self._timeline()["status"], "needs_goal")
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.generate_next_instruction_packet()
            turn_1_state = self.controller.ingest_agent_response(self.turn_1_raw)

        self.assertEqual(turn_1_state["run_loop"]["current_turn"], 1)
        self.assertEqual(
            [n for n in TURN_1_FILES if (self.workspace / n).is_file()],
            [],
        )
        self.assertFalse(turn_1_state["mission_summary"]["side_effect_executed_by_admissible"])

        turn_1_game_items = [
            i for i in turn_1_state["queue"] if i.get("action_type") == "create_file"
        ]
        self.assertEqual(len(turn_1_game_items), 3)
        for item in turn_1_game_items:
            self.assertEqual(item["decision"], "ALLOW")
            self.assertTrue(item["bounded_execution_eligible"])
            self.assertEqual(item["structured_operation_count"], 1)
            self.assertEqual(item["execution_status"], "proposed_only")

        self.controller.set_bounded_executor_workspace(self.workspace)
        turn_1_ready = self.controller.state_view()["ready_to_execute_locally"]
        self.assertEqual(len(turn_1_ready), 3)
        for entry in turn_1_ready:
            self.assertEqual(entry["structured_operation_count"], 1)

        timeline_after_turn_1_ingest = self._timeline()
        self.assertEqual(timeline_after_turn_1_ingest["turn_count"], 1)
        self.assertEqual(
            timeline_after_turn_1_ingest["status"],
            TIMELINE_STATUS_READY_TO_EXECUTE_LOCAL,
        )

        cont_before_turn_1_exec = self._continuation()
        self.assertFalse(cont_before_turn_1_exec["available"])
        self.assertEqual(
            cont_before_turn_1_exec["status"],
            CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
        )
        self.assertEqual(len(cont_before_turn_1_exec["pending_execution_operations"]), 3)

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            turn_1_exec_state = self.controller.execute_bounded_local_batch(
                {"workspace_path": str(self.workspace)}
            )

        self.assertEqual(
            [n for n in TURN_1_FILES if (self.workspace / n).is_file()],
            list(TURN_1_FILES),
        )
        evidence = turn_1_exec_state["run_loop"]["evidence_records"]
        write_records = [r for r in evidence if r["source"] == "bounded_executor"]
        self.assertEqual(len(write_records), 3)
        self.assertEqual({r["file_path_or_note"] for r in write_records}, set(TURN_1_FILES))
        for record in write_records:
            self.assertTrue(record["sha256"])

        cont_after_turn_1 = self._continuation()
        self.assertTrue(cont_after_turn_1["available"])
        self.assertEqual(cont_after_turn_1["status"], CONTINUATION_STATUS_EVIDENCE_GROUNDED)
        self.assertEqual(cont_after_turn_1["executed_count"], 3)
        cont_text = cont_after_turn_1["instruction_text"]
        for name in TURN_1_FILES:
            self.assertIn(name, cont_text)
        self.assertIn("sha256", cont_text)
        for marker in _STRICT_BRIDGE_MARKERS:
            self.assertIn(marker, cont_text, f"missing bridge marker: {marker}")

        timeline_after_turn_1_exec = self._timeline()
        self.assertEqual(timeline_after_turn_1_exec["status"], TIMELINE_STATUS_EXECUTED)
        self.assertEqual(timeline_after_turn_1_exec["evidence_count"], 3)
        turn_1_ops = timeline_after_turn_1_exec["turns"][0]["operations"]
        self.assertEqual(len(turn_1_ops), 3)
        self.assertTrue(all(op["executed"] for op in turn_1_ops))

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.generate_next_instruction_packet()
            turn_2_state = self.controller.ingest_agent_response(self.turn_2_raw)

        self.assertEqual(turn_2_state["run_loop"]["current_turn"], 2)
        self.assertEqual(
            [n for n in (TURN_2_NEW_FILE,) if (self.workspace / n).is_file()],
            [],
        )

        turn_2_ids = set(self._action_ids_for_turn(turn_2_state, 2))
        turn_2_game_items = [
            i
            for i in turn_2_state["queue"]
            if i.get("action_type") == "create_file" and i["action_id"] in turn_2_ids
        ]
        self.assertEqual(len(turn_2_game_items), 3)
        for item in turn_2_game_items:
            self.assertEqual(item["decision"], "ALLOW")
            self.assertTrue(item["bounded_execution_eligible"])
            self.assertEqual(item["execution_status"], "proposed_only")

        turn_2_ready = self.controller.state_view()["ready_to_execute_locally"]
        turn_2_ready_ids = {e["action_id"] for e in turn_2_ready}
        self.assertEqual(
            len([aid for aid in turn_2_ids if aid in turn_2_ready_ids]),
            3,
        )

        timeline_after_turn_2_ingest = self._timeline()
        self.assertGreaterEqual(timeline_after_turn_2_ingest["turn_count"], 2)
        self.assertEqual(len(timeline_after_turn_2_ingest["turns"]), 2)
        turn_numbers = [t["turn_number"] for t in timeline_after_turn_2_ingest["turns"]]
        self.assertEqual(turn_numbers, [1, 2])
        turn_2_timeline_ops = timeline_after_turn_2_ingest["turns"][1]["operations"]
        self.assertEqual(len(turn_2_timeline_ops), 3)
        self.assertTrue(all(not op["executed"] for op in turn_2_timeline_ops))

        cont_before_turn_2_exec = self._continuation()
        self.assertFalse(cont_before_turn_2_exec["available"])
        self.assertEqual(
            cont_before_turn_2_exec["status"],
            CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
        )

        evidence_count_before_turn_2 = timeline_after_turn_2_ingest["evidence_count"]

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            turn_2_exec_state = self.controller.execute_bounded_local_batch(
                {"workspace_path": str(self.workspace)}
            )

        self.assertTrue((self.workspace / TURN_2_NEW_FILE).is_file())
        game_js = (self.workspace / "game.js").read_text(encoding="utf-8")
        self.assertIn("score", game_js.lower())
        self.assertIn("reset", game_js.lower())
        readme = (self.workspace / TURN_2_NEW_FILE).read_text(encoding="utf-8")
        self.assertIn("WASD", readme)

        final_timeline = turn_2_exec_state["run_timeline"]
        self.assertGreaterEqual(final_timeline["turn_count"], 2)
        self.assertGreater(final_timeline["evidence_count"], evidence_count_before_turn_2)
        self.assertEqual(final_timeline["evidence_count"], 6)

        executed_turn_1 = [
            op
            for op in final_timeline["turns"][0]["operations"]
            if op["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        executed_turn_2 = [
            op
            for op in final_timeline["turns"][1]["operations"]
            if op["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertEqual(len(executed_turn_1), 3)
        self.assertEqual(len(executed_turn_2), 3)

        final_cont = turn_2_exec_state["continuation_instruction"]
        self.assertTrue(final_cont["available"])
        self.assertIn("no explicit completion signal", final_cont["instruction_text"])
        self.assertIn(TURN_2_NEW_FILE, final_cont["instruction_text"])

        self._assert_no_forbidden_capabilities(turn_2_exec_state)


if __name__ == "__main__":
    unittest.main()
