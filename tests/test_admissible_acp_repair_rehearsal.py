"""RUN_049 PART F/L -- deterministic repair-session construction and rehearsal.

Fake backends only (no real Cursor/model process). Proves the mechanism this
slice's real repair rehearsal depends on: a fixture-built legitimate
pre-repair state (repair_needed, 7/8 criteria pass, exactly one fails), then a
deliberate mid-run backend swap that drives one further callable-backend turn
through the *actual* production lifecycle (invoke -> ingest -> admission ->
bounded write -> post-repair verification -> completion re-evaluation).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import FixtureAgentBackend
from admissible.diagnostics.acp_repair_rehearsal import (
    INITIAL_GAME_JS_MISSING_RESTART,
    build_deterministic_pre_repair_session,
    drive_repair_round,
)

REPAIRED_GAME_JS = (
    INITIAL_GAME_JS_MISSING_RESTART
    + "\nfunction resetGame() { score = 0; player = { x: 0, y: 0 }; }\n"
    "window.addEventListener('keydown', e => { if (e.key === 'r' || e.key === 'R') resetGame(); });\n"
)


def _response(operations: list[dict]) -> str:
    return "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )


class DeterministicPreRepairSessionTests(unittest.TestCase):
    def test_pre_repair_state_is_seven_of_eight_pass_one_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            statuses = session.acceptance_statuses()
            self.assertEqual(len(statuses), 8)
            failing = [cid for cid, status in statuses.items() if status != "verified_pass"]
            self.assertEqual(failing, ["explicit_ac_007"])

    def test_pre_repair_state_has_no_blocker_and_repair_budget_remains(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            ha = session.controller._high_autonomy_state()
            self.assertEqual(ha.blocked_action_count, 0)
            self.assertGreater(ha.max_repair_rounds - ha.repair_round_count, 0)
            self.assertEqual(ha.backend_id, "fixture")

    def test_four_application_files_exist_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            for name in ("index.html", "style.css", "game.js", "LOCAL_DEV.md"):
                self.assertTrue((session.workspace / name).is_file())


class RepairRoundMechanismTests(unittest.TestCase):
    def _repair_backend(self, game_js: str, *, backend_id: str = "test_repair_backend") -> FixtureAgentBackend:
        backend = FixtureAgentBackend(
            responses=[_response([{"operation": "write_file", "path": "game.js", "content": game_js}])]
        )
        backend.backend_id = backend_id
        return backend

    def test_correct_repair_reaches_completed_with_all_eight_passing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            result = drive_repair_round(session, self._repair_backend(REPAIRED_GAME_JS))
            self.assertEqual(result.final_outcome, "completed")
            self.assertTrue(result.all_eight_pass)
            self.assertEqual(result.model_turn_count, 1)
            self.assertEqual(result.final_acceptance_statuses["explicit_ac_007"], "verified_pass")
            # Every criterion that already passed keeps passing (repair preserved them).
            for cid in (
                "explicit_ac_001", "explicit_ac_002", "explicit_ac_003", "explicit_ac_004",
                "explicit_ac_005", "explicit_ac_006", "explicit_ac_008",
            ):
                self.assertEqual(result.final_acceptance_statuses[cid], "verified_pass")

    def test_backend_swap_is_an_explicit_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            result = drive_repair_round(session, self._repair_backend(REPAIRED_GAME_JS))
            self.assertEqual(result.pre_swap_backend_id, "fixture")
            self.assertEqual(result.backend_id, "test_repair_backend")

    def test_model_turn_itself_causes_zero_workspace_mutation(self) -> None:
        # The model's response is a *proposal*; the file only changes once
        # Admissible's own bounded executor runs on a later tick.
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            result = drive_repair_round(session, self._repair_backend(REPAIRED_GAME_JS))
            self.assertTrue(result.workspace_mutation_before_execution["clean"])
            self.assertEqual(result.workspace_paths_added, [])
            self.assertEqual(result.workspace_paths_removed, [])
            self.assertEqual(result.workspace_paths_modified, [])

    def test_wrong_repair_does_not_falsely_complete(self) -> None:
        # An irrelevant repair (touches an unrelated file) must never be
        # admitted as satisfying the one failing criterion.
        with tempfile.TemporaryDirectory() as tmp:
            session = build_deterministic_pre_repair_session(tmp)
            useless_backend = FixtureAgentBackend(
                responses=[_response([{"operation": "write_file", "path": "README.md", "content": "nope\n"}])]
            )
            useless_backend.backend_id = "test_repair_backend"
            result = drive_repair_round(session, useless_backend, max_ticks=6)
            self.assertNotEqual(result.final_acceptance_statuses.get("explicit_ac_007"), "verified_pass")
            self.assertFalse(result.all_eight_pass)


if __name__ == "__main__":
    unittest.main()
