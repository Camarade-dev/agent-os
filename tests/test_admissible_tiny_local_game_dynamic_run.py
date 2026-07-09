"""Slice ADMISSIBLE_DEMO_011_TINY_LOCAL_GAME_DYNAMIC_RUN tests.

First dynamic local-only Admissible demo: a simulated agent response proposes
a tiny browser-game scaffold purely through the structured-operation contract
(`ADMISSIBLE_STRUCTURED_OPERATION:` write_file blocks for index.html,
style.css, game.js). The demo proves the flow from structured proposal ->
admission -> *explicit* bounded local execution in a temp workspace, with
sha256 attestation evidence, export/reload durability, and immutable original
decisions.

Hard constraints exercised: no provider calls, no shell/subprocess (guarded
with a raising mock), no npm/pip/git/deploy/network, no `agent_os` import,
decisions never mutated, nothing executed until an explicit execution call,
fixtures/offline only.
"""

from __future__ import annotations

import ast
import copy
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.control_surface import ControlSurfaceController
from admissible.evaluator.rules_only import evaluate_envelope
from admissible.execution.bounded_local_executor import (
    DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION,
)
from admissible.long_run_envelope_builder import (
    STRUCTURED_OPERATION_MARKER,
    build_from_raw_output,
    extract_structured_operation_blocks,
)
from admissible.runner.extraction_lab import (
    load_expected_spec,
    load_fixture,
    run_extraction_lab,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ADMISSIBLE_ROOT = REPO_ROOT / "admissible"
FIXTURES_DIR = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "fixtures"
    / "pasted_agent_responses"
)
EXPECTED_SPEC_PATH = FIXTURES_DIR / "expected_extractions.json"
TINY_GAME_FIXTURE = "tiny_local_game_structured_scaffold.txt"
GAME_FILES = ("index.html", "style.css", "game.js")

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("tiny local game demo must never spawn a subprocess")


class TestTinyLocalGameDynamicRun(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.raw = load_fixture(FIXTURES_DIR / TINY_GAME_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _ingest(self) -> dict:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            return self.controller.ingest_agent_response(self.raw)

    def _game_files_present(self) -> list[str]:
        return [name for name in GAME_FILES if (self.workspace / name).is_file()]

    # 1. Extraction of the three structured write operations.
    def test_fixture_extracts_three_write_file_operations(self) -> None:
        blocks = extract_structured_operation_blocks(self.raw)
        self.assertEqual(len(blocks), 3)
        ops = [op for block in blocks for op in block["operations"]]
        self.assertEqual([op["operation"] for op in ops], ["write_file"] * 3)
        self.assertEqual([op["path"] for op in ops], list(GAME_FILES))
        for op in ops:
            self.assertIsInstance(op["content"], str)
            self.assertTrue(op["content"].strip())

        built = build_from_raw_output(
            self.raw, source_metadata={"fixture_path": TINY_GAME_FIXTURE}
        )
        candidates = built["action_candidates"]
        self.assertEqual(len(candidates), 3)
        for candidate, envelope in zip(candidates, built["envelopes"]):
            self.assertEqual(candidate["action_type"], "create_file")
            self.assertEqual(len(candidate["structured_operations"]), 1)
            self.assertEqual(evaluate_envelope(envelope)["decision"], "ALLOW")

    # 2. Ingesting the fixture creates executable structured local candidates.
    def test_ingest_creates_executable_structured_candidates(self) -> None:
        state = self._ingest()
        game_items = [i for i in state["queue"] if i["action_type"] == "create_file"]
        self.assertEqual(len(game_items), 3)
        for item in game_items:
            self.assertEqual(item["decision"], "ALLOW")
            self.assertTrue(item["bounded_execution_eligible"])
            self.assertIsNone(item["bounded_execution_diagnostic"])
            self.assertEqual(item["structured_operation_count"], 1)
            self.assertEqual(item["execution_status"], "proposed_only")

    # 3. No files are written before bounded execution.
    def test_no_files_written_before_bounded_execution(self) -> None:
        state = self._ingest()
        self.assertEqual(self._game_files_present(), [])
        self.assertFalse(
            state["mission_summary"]["side_effect_executed_by_admissible"]
        )

    # 4. Bounded execution writes index.html, style.css, and game.js.
    def test_bounded_execution_writes_all_three_files(self) -> None:
        self._ingest()
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            for action_id in self._game_action_ids():
                self.controller.execute_bounded_local(
                    action_id, {"workspace_path": str(self.workspace)}
                )
        self.assertEqual(self._game_files_present(), list(GAME_FILES))
        self.assertIn("<!doctype html>", (self.workspace / "index.html").read_text(encoding="utf-8").lower())
        self.assertIn("canvas", (self.workspace / "style.css").read_text(encoding="utf-8").lower())
        self.assertIn("requestanimationframe", (self.workspace / "game.js").read_text(encoding="utf-8").lower())

    # 5. Each write emits sha256 attestation evidence.
    def test_each_write_emits_sha256_attestation_evidence(self) -> None:
        self._ingest()
        for action_id in self._game_action_ids():
            self.controller.execute_bounded_local(
                action_id, {"workspace_path": str(self.workspace)}
            )
        evidence = self.controller.session_dict()["run_loop"]["evidence_records"]
        write_records = [r for r in evidence if r["source"] == "bounded_executor"]
        self.assertEqual(len(write_records), 3)
        paths_attested = {r["file_path_or_note"] for r in write_records}
        self.assertEqual(paths_attested, set(GAME_FILES))
        for record in write_records:
            self.assertIn("local_file_written", record["satisfies"])
            self.assertIn("workspace_scope_attested", record["satisfies"])
            self.assertTrue(record["sha256"])

    # 6. Export/import preserves execution and evidence records.
    def test_export_import_preserves_execution_and_evidence(self) -> None:
        self._ingest()
        for action_id in self._game_action_ids():
            self.controller.execute_bounded_local(
                action_id, {"workspace_path": str(self.workspace)}
            )
        exported = self.controller.session_dict()
        self.assertEqual(len(exported["run_loop"]["evidence_records"]), 3)

        reloaded = ControlSurfaceController(session_dir=self.root / "reload")
        imported = reloaded.import_session(exported)
        self.assertEqual(
            len(imported["run_loop"]["evidence_records"]),
            len(exported["run_loop"]["evidence_records"]),
        )
        executed = [
            i
            for i in imported["queue"]
            if i["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertEqual(len(executed), 3)
        self.assertEqual(
            exported["run_loop"]["evidence_records"][0]["sha256"],
            imported["run_loop"]["evidence_records"][0]["sha256"],
        )

    # 7. Original admission decisions remain immutable through execution.
    def test_original_decisions_remain_immutable(self) -> None:
        state = self._ingest()
        action_ids = self._game_action_ids()
        original = {
            aid: copy.deepcopy(state["run_envelopes"][aid]["decision"])
            for aid in action_ids
        }
        for action_id in action_ids:
            self.controller.execute_bounded_local(
                action_id, {"workspace_path": str(self.workspace)}
            )
        after = self.controller.state_view()
        for action_id in action_ids:
            self.assertEqual(after["run_envelopes"][action_id]["decision"], original[action_id])

    # 8. A prose-only version of the same proposal stays non-executable.
    def test_prose_only_variant_is_not_executable(self) -> None:
        prose_only = (
            "Cursor Agent — session dry-run (no commands executed)\n\n"
            "User: Scaffold a tiny local-only browser game.\n\n"
            "I will edit index.html, style.css, and game.js to add a tiny canvas game.\n"
            "Note: Nothing was executed.\n"
        )
        self.assertNotIn(STRUCTURED_OPERATION_MARKER, prose_only)
        controller = ControlSurfaceController(session_dir=self.root / "prose")
        state = controller.ingest_agent_response(prose_only)
        self.assertTrue(state["queue"])
        for item in state["queue"]:
            self.assertFalse(item["bounded_execution_eligible"])
            self.assertEqual(item["structured_operation_count"], 0)
        self.assertNotEqual(self._game_files_present(), list(GAME_FILES))
        self.assertIn(
            DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION,
            {i["bounded_execution_diagnostic"] for i in state["queue"]},
        )
        for envelope in state["run_envelopes"].values():
            self.assertNotIn("structured_operations", envelope["candidate"])

    def _game_action_ids(self) -> list[str]:
        return [
            i["action_id"]
            for i in self.controller.state_view()["queue"]
            if i["action_type"] == "create_file"
        ]


class TestTinyLocalGameFixtureSpec(unittest.TestCase):
    # 9. The new fixture is spec-consistent and the whole extraction lab
    #    (all committed fixtures) still passes -- extraction did not regress.
    def test_extraction_lab_passes_with_tiny_game_fixture(self) -> None:
        spec = load_expected_spec(EXPECTED_SPEC_PATH)
        self.assertIn(TINY_GAME_FIXTURE, spec["fixtures"])
        summary = run_extraction_lab(FIXTURES_DIR, EXPECTED_SPEC_PATH)
        self.assertTrue(summary["overall_passed"], summary)
        self.assertEqual(summary["fail_count"], 0)
        tiny = next(r for r in summary["results"] if r["fixture"] == TINY_GAME_FIXTURE)
        self.assertTrue(tiny["passed"], tiny)
        self.assertEqual(tiny["candidate_count"], 3)

    def test_fixture_file_exists_and_is_structured(self) -> None:
        path = FIXTURES_DIR / TINY_GAME_FIXTURE
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(STRUCTURED_OPERATION_MARKER), 3)
        for name in GAME_FILES:
            self.assertIn(name, text)


class TestTinyLocalGameBoundary(unittest.TestCase):
    # 10. No `agent_os` import leaks into any Admissible module.
    def test_no_agent_os_imports_in_admissible_modules(self) -> None:
        violations: list[str] = []
        for path in sorted(ADMISSIBLE_ROOT.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "agent_os" or alias.name.startswith("agent_os."):
                            violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module
                    if module and (module == "agent_os" or module.startswith("agent_os.")):
                        violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
