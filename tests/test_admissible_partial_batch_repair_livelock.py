"""Regressions for ADMISSIBLE_NARROW_FIX_PARTIAL_BATCH_VERIFICATION_AND_REPAIR_LIVELOCK.

Covers, using a small synthetic "Tiny Arcade" goal (mirrors the real cli-006
Neon Serpents contract shape -- a rejected root-level substitute, an explicit
per-response operation limit, mandatory deliverables split across two
governed batches -- but with 4 files/1 repairable criterion instead of 8/15
so the flow is fast and fully content-controlled):

1. A partial governed batch does not trigger premature verification or a
   repair round (PART 1).
2. Canonical Mission Contract paths (never rejected root-level substitutes)
   drive proposal-coverage/repair-packet computations (PART 2).
3. A repair round whose targeted criterion passes closes exactly once, even
   though other mandatory criteria remain open pending non-static
   verification (PART 3).
4. Identical verification against unchanged state is deduplicated: no new
   verification record, no duplicate evidence_refs/verification_notes
   (PART 4).
5. The real cli-006 forensic livelock (stuck at repair_phase=repair_verifying,
   next_action=run_bounded_verification, many duplicate verification
   records) is resumable from a sanitized replay fixture with zero new
   provider calls, zero new writes, zero new static checks, and a projected
   next action of start_runtime_verification (PART 5/6).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import (
    build_proposal_coverage_report,
    build_repair_packet,
)
from admissible.high_autonomy_controller import (
    REPAIR_PHASE_NONE,
    REPAIR_PHASE_REPAIR_VERIFYING,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "neon_serpents_cli_006_repair_livelock_replay.json"
)

GOAL = (
    "Build Tiny Arcade.\n\n"
    "Mandatory files:\n"
    "- index.html\n- style.css\n- src/game.js\n- LOCAL_DEV.md\n\n"
    "A root-level game.js does not satisfy the src/game.js requirement.\n\n"
    "Acceptance criteria:\n"
    "1. Arrow-key movement moves the player.\n"
    "2. Collecting items increases the score.\n"
    "3. Press R to restart the game.\n"
    "4. LOCAL_DEV.md documents how to run the app locally.\n\n"
    "Use no more than two write operations in one response.\n"
)

REJECTED_ROOT_LEVEL_PATHS = ["game.js"]
CANONICAL_MANDATORY_PATHS = ["index.html", "style.css", "src/game.js", "LOCAL_DEV.md"]

GOOD_GAME_JS = (
    "const keys={}; addEventListener('keydown',e=>keys[e.key]=true);"
    "if(keys.ArrowUp||keys.w){} if(keys.ArrowDown||keys.s){}"
    "if(keys.ArrowLeft||keys.a){} if(keys.ArrowRight||keys.d){}"
    "let score=0; const collectibles=[]; function restart(){score=0;}"
    "addEventListener('keydown',e=>{if(e.key==='R')restart();});"
)
# Same control wiring, but never mentions "score" -- fails only
# explicit_ac_002 (file_contains "score"), a genuine, deserved failure since
# every mandatory path already exists by the time this content lands.
GAME_JS_MISSING_SCORE = GOOD_GAME_JS.replace("score", "points")

GOOD_LOCAL_DEV_MD = "open index.html locally\n"

TURN1_FILES = ["index.html", "style.css"]
TURN2_FILES = ["src/game.js", "LOCAL_DEV.md"]


def _response(paths: list[str], content: dict[str, str]) -> str:
    blocks = []
    for path in paths:
        op = {"operation": "write_file", "path": path, "content": content[path]}
        blocks.append("ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n" + json.dumps(op) + "\n```")
    return "\n".join(blocks)


def _make_controller(tmp_path: Path) -> tuple[ControlSurfaceController, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    controller = ControlSurfaceController(session_dir=tmp_path / "sessions")
    return controller, workspace


class TestPartialBatchDefersVerification(unittest.TestCase):
    """PART 1 / PART 7 item 1: turn 1 with half the mandatory files."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.controller, self.workspace = _make_controller(self.root)
        self.transport = FixtureAgentTransport()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _content(self, good_game_js: bool = True) -> dict[str, str]:
        return {
            "index.html": "<html><body><canvas></canvas></body></html>\n",
            "style.css": "body{margin:0}\n",
            "src/game.js": GOOD_GAME_JS if good_game_js else GAME_JS_MISSING_SCORE,
            "LOCAL_DEV.md": GOOD_LOCAL_DEV_MD,
        }

    def test_turn1_partial_batch_no_repair_no_premature_failure(self) -> None:
        content = self._content()
        self.transport.set_responses(
            [_response(TURN1_FILES, content), _response(TURN2_FILES, content)]
        )
        self.controller.submit_goal(GOAL)
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace),
            transport=self.transport,
            max_turns=8,
            closure_reserve_turns=2,
            max_structured_operations_per_response=2,
        )
        saw_verify_or_repair = False
        for _ in range(6):
            state = self.controller.tick_high_autonomy_run()
            ha = self.controller._session.high_autonomy_run
            if ha.get("repair_phase") != REPAIR_PHASE_NONE:
                saw_verify_or_repair = True
            if self.controller._session.run_loop.verification_records:
                saw_verify_or_repair = True
            if len(self.controller._session.operation_records) >= 2:
                break

        self.assertFalse(
            saw_verify_or_repair,
            "a partial governed batch must not trigger verification or a repair round",
        )
        self.assertEqual(len(self.controller._session.operation_records), 2)
        ha = self.controller._session.high_autonomy_run
        self.assertEqual(ha.get("repair_phase"), REPAIR_PHASE_NONE)

        # Proposal coverage was recorded honestly (not silently dropped) and
        # only the still-pending *canonical* src/... paths are reported --
        # never the rejected root-level substitute (PART 2).
        coverage = ha.get("last_proposal_coverage_report") or {}
        self.assertFalse(coverage.get("coverage_complete"))
        self.assertTrue(coverage.get("governed_partial_batch"))
        self.assertCountEqual(
            coverage.get("missing_required_paths"), ["src/game.js", "LOCAL_DEV.md"]
        )
        for rejected in REJECTED_ROOT_LEVEL_PATHS:
            self.assertNotIn(rejected, coverage.get("missing_required_paths") or [])
        governance_events = [
            r.get("event_type") for r in self.controller._session.governance_records
        ]
        self.assertIn("proposal_coverage_incomplete", governance_events)

        # The controller continues implementation (next action is a normal
        # continuation invocation), never run_bounded_verification.
        for _ in range(4):
            if ha.get("next_action") in ("write_instruction", "invoke_agent", "ingest_response"):
                break
            state = self.controller.tick_high_autonomy_run()
            ha = self.controller._session.high_autonomy_run
        self.assertIn(ha.get("next_action"), ("write_instruction", "invoke_agent", "ingest_response"))
        self.assertNotEqual(ha.get("next_action"), "run_bounded_verification")


class TestStaticVerificationAndRepairLifecycle(unittest.TestCase):
    """PART 3 / PART 4 / PART 7 items 2-4: full 2-batch flow through repair."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.controller, self.workspace = _make_controller(self.root)
        self.transport = FixtureAgentTransport()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _drive_to_verification(self, *, good_game_js: bool) -> None:
        content = {
            "index.html": "<html><body><canvas></canvas></body></html>\n",
            "style.css": "body{margin:0}\n",
            "src/game.js": GOOD_GAME_JS if good_game_js else GAME_JS_MISSING_SCORE,
            "LOCAL_DEV.md": GOOD_LOCAL_DEV_MD,
        }
        self.transport.set_responses(
            [_response(TURN1_FILES, content), _response(TURN2_FILES, content)]
        )
        self.controller.submit_goal(GOAL)
        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace),
            transport=self.transport,
            max_turns=10,
            closure_reserve_turns=2,
            max_structured_operations_per_response=2,
        )
        for _ in range(20):
            self.controller.tick_high_autonomy_run()
            if self.controller._session.run_loop.verification_records:
                break

    def test_static_verification_runs_once_when_all_files_present_and_clean(self) -> None:
        self._drive_to_verification(good_game_js=True)
        self.assertEqual(len(self.controller._session.operation_records), 4)
        self.assertEqual(len(self.controller._session.run_loop.verification_records), 1)

        # Repeated ticks against the now-settled state never append another
        # verification record (PART 4 dedup / no perpetual re-verification).
        for _ in range(6):
            self.controller.tick_high_autonomy_run()
        self.assertEqual(len(self.controller._session.run_loop.verification_records), 1)

    def test_repair_round_closes_exactly_once_and_deduplicates(self) -> None:
        self._drive_to_verification(good_game_js=False)
        ha = self.controller._session.high_autonomy_run
        criteria_by_id = {c["criterion_id"]: c for c in ha["acceptance_criteria"]}
        failing = [cid for cid, c in criteria_by_id.items() if c["status"] == "verified_fail"]
        self.assertEqual(len(failing), 1, ha["acceptance_criteria"])
        target_id = failing[0]
        self.assertEqual(ha.get("repair_phase"), "repair_needed")
        self.assertEqual(len(self.controller._session.run_loop.verification_records), 1)

        # Repair-packet paths are canonical only (PART 2), never the
        # rejected root-level substitute.
        packet = ha.get("repair_packet") or {}
        for rejected in REJECTED_ROOT_LEVEL_PATHS:
            self.assertNotIn(rejected, packet.get("missing_mandatory_paths") or [])
            self.assertNotIn(
                rejected, (packet.get("repair_boundaries") or {}).get("exact_mandatory_paths") or []
            )

        # Supply the repair fix (adds "score") and drive to resolution.
        fixed_content = {"src/game.js": GOOD_GAME_JS}
        self.transport.enqueue_response(
            _response(["src/game.js"], fixed_content)
        )
        repair_closed = False
        for _ in range(20):
            self.controller.tick_high_autonomy_run()
            ha = self.controller._session.high_autonomy_run
            if ha.get("repair_phase") == REPAIR_PHASE_NONE and len(
                self.controller._session.run_loop.verification_records
            ) > 1:
                repair_closed = True
                break
        self.assertTrue(repair_closed, ha)

        criteria_by_id = {c["criterion_id"]: c for c in ha["acceptance_criteria"]}
        self.assertEqual(criteria_by_id[target_id]["status"], "verified_pass")
        record_count_after_close = len(self.controller._session.run_loop.verification_records)
        evidence_refs_after_close = len(criteria_by_id[target_id]["evidence_refs"])
        notes_after_close = len(criteria_by_id[target_id]["verification_notes"])
        repair_history = ha.get("repair_history") or []
        self.assertTrue(repair_history)
        self.assertIn("resolved_at", repair_history[-1])

        # Repeated ticks against the now-resolved, unchanged state must not
        # create unlimited evidence (PART 4): no new verification record, no
        # duplicate evidence_refs/verification_notes on the resolved
        # criterion, and repair_phase never reopens to repair_verifying.
        for _ in range(8):
            self.controller.tick_high_autonomy_run()
        ha = self.controller._session.high_autonomy_run
        criteria_by_id = {c["criterion_id"]: c for c in ha["acceptance_criteria"]}
        self.assertEqual(
            len(self.controller._session.run_loop.verification_records),
            record_count_after_close,
        )
        self.assertEqual(
            len(criteria_by_id[target_id]["evidence_refs"]), evidence_refs_after_close
        )
        self.assertEqual(
            len(criteria_by_id[target_id]["verification_notes"]), notes_after_close
        )
        self.assertNotEqual(ha.get("repair_phase"), REPAIR_PHASE_REPAIR_VERIFYING)


class TestCanonicalPathHelpers(unittest.TestCase):
    """PART 2 / PART 7 items 5-6: unit-level canonical-path enforcement."""

    def test_proposal_coverage_uses_canonical_mandatory_paths_not_goal_regex(self) -> None:
        report = build_proposal_coverage_report(
            goal_text=GOAL,
            structured_operations=[
                {"operation": "write_file", "path": "index.html", "content": "x"},
                {"operation": "write_file", "path": "style.css", "content": "x"},
            ],
            mandatory_paths=CANONICAL_MANDATORY_PATHS,
            operation_limit=2,
        )
        self.assertEqual(report["required_paths"], CANONICAL_MANDATORY_PATHS)
        self.assertCountEqual(report["missing_required_paths"], ["src/game.js", "LOCAL_DEV.md"])
        for rejected in REJECTED_ROOT_LEVEL_PATHS:
            self.assertNotIn(rejected, report["missing_required_paths"])
        self.assertTrue(report["governed_partial_batch"])

    def test_repair_packet_uses_canonical_mandatory_paths_not_goal_regex(self) -> None:
        packet = build_repair_packet(
            criteria=[
                {"criterion_id": "c1", "mandatory": True, "status": "verified_fail"},
            ],
            verification_record={
                "results": [
                    {
                        "criterion_id": "c1",
                        "status": "fail",
                        "message": "Missing src/game.js",
                        "evidence_payload": {"missing_paths": ["src/game.js"]},
                    }
                ]
            },
            satisfied_file_hashes={"index.html": "abc", "style.css": "def"},
            goal_text=GOAL,
            remaining_turn_budget=3,
            repair_round=1,
            mandatory_paths=CANONICAL_MANDATORY_PATHS,
        )
        self.assertCountEqual(
            packet["missing_mandatory_paths"], ["src/game.js", "LOCAL_DEV.md"]
        )
        for rejected in REJECTED_ROOT_LEVEL_PATHS:
            self.assertNotIn(rejected, packet["missing_mandatory_paths"])
            self.assertNotIn(rejected, packet["repair_boundaries"]["exact_mandatory_paths"])


class TestCli006RepairLivelockReplay(unittest.TestCase):
    """PART 5 / PART 6 / PART 7 item 7: resume the real forensic livelock."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.session_data = fixture["session"]
        for rel_path, content in fixture["file_content"].items():
            target = self.workspace / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="")
        self.session_data["bounded_executor_workspace"] = str(self.workspace)
        self.session_data["high_autonomy_run"]["workspace_path"] = str(self.workspace)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fixture_matches_documented_stuck_state(self) -> None:
        ha = self.session_data["high_autonomy_run"]
        self.assertEqual(ha["repair_phase"], "repair_verifying")
        self.assertEqual(ha["next_action"], "run_bounded_verification")
        self.assertEqual(ha["repair_round_count"], 1)
        self.assertFalse(ha["runtime_verification_required"])
        self.assertEqual(len(self.session_data["operation_records"]), 8)
        self.assertGreater(len(self.session_data["run_loop"]["verification_records"]), 1)
        checkable = [c for c in ha["acceptance_criteria"] if c.get("verification")]
        self.assertGreaterEqual(len(checkable), 2)
        self.assertTrue(all(len(c["evidence_refs"]) > 1 for c in checkable))

    def test_reconciliation_closes_repair_and_projects_runtime_verification(self) -> None:
        self.controller.import_session(self.session_data)
        pre_ops = len(self.controller._session.operation_records)
        pre_records = len(self.controller._session.run_loop.verification_records)

        state = self.controller.tick_high_autonomy_run()
        ha = self.controller._session.high_autonomy_run

        # No provider invocation, no new write, no additional static check.
        self.assertEqual(len(self.controller._session.operation_records), pre_ops)
        self.assertEqual(
            len(self.controller._session.run_loop.verification_records), pre_records
        )
        transport = self.controller._high_autonomy_transport
        if transport is not None:
            self.assertEqual(len(getattr(transport, "written_instructions", [])), 0)

        # The stale repair state is closed exactly once.
        self.assertEqual(ha.get("repair_phase"), REPAIR_PHASE_NONE)
        repair_history = ha.get("repair_history") or []
        self.assertTrue(repair_history)
        self.assertIn("resolved_at", repair_history[-1])

        self.assertTrue(ha.get("runtime_verification_required"))
        self.assertEqual(ha.get("next_action"), "start_runtime_verification")

        # Ticking again with a real (fixture) runtime provider prepares the
        # existing RUN_043 runtime plan successfully -- never a new model or
        # browser invocation, never a real subprocess.
        self.controller.set_runtime_provider(
            FixtureBrowserRuntimeProvider({"initial_snapshot": {"botCount": 12}})
        )
        state = self.controller.tick_high_autonomy_run()
        ha = self.controller._session.high_autonomy_run
        self.assertIsNotNone(ha.get("active_runtime_attempt"))
        self.assertIsNotNone(ha.get("active_runtime_plan"))
        self.assertIn(
            ha.get("runtime_verification_status"),
            ("runtime_verifying", "runtime_verified", "runtime_failed"),
        )
        self.assertEqual(len(self.controller._session.operation_records), pre_ops)
        transport = self.controller._high_autonomy_transport
        if transport is not None:
            self.assertEqual(len(getattr(transport, "written_instructions", [])), 0)

    def test_repeated_ticks_after_reconciliation_stay_flat(self) -> None:
        self.controller.import_session(self.session_data)
        self.controller.tick_high_autonomy_run()
        self.controller.set_runtime_provider(
            FixtureBrowserRuntimeProvider({"initial_snapshot": {"botCount": 12}})
        )
        self.controller.tick_high_autonomy_run()
        record_count = len(self.controller._session.run_loop.verification_records)
        op_count = len(self.controller._session.operation_records)

        for _ in range(5):
            self.controller.tick_high_autonomy_run()

        self.assertEqual(
            len(self.controller._session.run_loop.verification_records), record_count
        )
        self.assertEqual(len(self.controller._session.operation_records), op_count)
        ha = self.controller._session.high_autonomy_run
        self.assertNotEqual(ha.get("repair_phase"), REPAIR_PHASE_REPAIR_VERIFYING)
        self.assertLess(ha.get("no_progress_tick_count", 0), 20)


if __name__ == "__main__":
    unittest.main()
