"""RUN_046 PART B/J — the canonical Repair Probe transport-forensic regression.

Loads the minimized fixture reconstructed from the RUN_046 task brief's
canonical Repair Probe rehearsal narrative
(``tests/fixtures/admissible/repair_probe_callable_transport_forensic_regression.json``)
and checks two things:

1. The fixture's own bookkeeping is internally consistent (invocation/retry
   counts, phase structure) -- a forensic fixture that cannot even add up its
   own numbers is worse than useless.
2. The three *non-transport* findings the fixture documents are still live,
   confirmed defects in the current code, characterized precisely enough for
   a dedicated follow-up slice to fix without re-deriving root cause. These
   are intentionally characterization tests of *current* behavior, not
   regression tests of a fix -- RUN_046 is a forensic audit slice and PART J
   explicitly defers the fix to a separate slice.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.governed_run import derive_acceptance_criteria_from_goal
from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "repair_probe_callable_transport_forensic_regression.json"
)
CONTROL_SURFACE_HTML = (
    Path(__file__).resolve().parent.parent / "admissible" / "harness" / "control_surface.html"
)


class RepairProbeFixtureConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_invocation_count_matches_session_metrics(self) -> None:
        invocations = self.fixture["invocations"]
        self.assertEqual(len(invocations), self.fixture["session_metrics"]["total_invocations"])

    def test_retry_count_matches_session_metrics(self) -> None:
        invocations = self.fixture["invocations"]
        retries = sum(1 for item in invocations if item["retry_of_invocation_id"])
        self.assertEqual(retries, self.fixture["session_metrics"]["total_retries"])

    def test_first_turn_first_attempt_is_the_reported_empty_success(self) -> None:
        first = self.fixture["invocations"][0]
        self.assertEqual(first["process_exit_code"], 0)
        self.assertEqual(first["stdout_byte_count"], 1)
        self.assertEqual(first["classification"], "empty_success")
        self.assertEqual(first["controller_action"], "technical_pause_required_explicit_retry")

    def test_final_repair_attempt_is_the_reported_120s_timeout(self) -> None:
        last = self.fixture["invocations"][-1]
        self.assertEqual(last["status"], "timeout")
        self.assertEqual(last["duration_seconds"], 120.0)
        self.assertFalse(last["usable_response"])

    def test_every_invocation_has_retry_lineage_fields(self) -> None:
        for item in self.fixture["invocations"]:
            self.assertIn("invocation_id", item)
            self.assertIn("attempt_number", item)
            self.assertIn("retry_of_invocation_id", item)
            self.assertIn("instruction_id", item)
            self.assertIn("data_confidence", item)

    def test_bounded_verification_result_matches_narrative(self) -> None:
        result = self.fixture["bounded_verification_result"]
        self.assertEqual(sorted(result["failed_criteria"]), ["game_controls", "local_usage"])
        self.assertEqual(result["controlled_instruction_intended_failure_count"], 1)
        self.assertEqual(result["observed_failure_count"], 2)


class MandatoryAcceptanceCriteriaHeadingDefectTests(unittest.TestCase):
    """PART J.24 -- confirmed defect, not conflated with the transport conclusion."""

    GOAL = (
        "Build a small local tool.\n\n"
        "MANDATORY ACCEPTANCE CRITERIA\n"
        "1. index.html exists.\n"
        "2. style.css exists.\n"
        "3. game.js exists.\n"
        "4. Arrow keys move the player.\n"
        "5. WASD keys move the player.\n"
        "6. Collecting an item increases the score.\n"
        "7. The R key restarts the game.\n"
        "8. LOCAL_DEV.md explains how to run it locally.\n"
    )

    def test_heading_with_extra_leading_word_is_now_recognized_as_acceptance_section(self) -> None:
        # RUN_049 PART A fix: acceptance-heading recognition is structural
        # (qualifier words mandatory/required/final/minimum/functional/
        # technical are stripped, case/colon/markdown-marker/whitespace are
        # normalized), so "MANDATORY ACCEPTANCE CRITERIA" now recognizes as
        # section=="acceptance" and the eight numbered lines become explicit
        # acceptance criteria instead of being silently dropped.
        contract = build_mission_contract(self.GOAL)
        self.assertEqual(len(contract.explicit_acceptance_criteria), 8)
        self.assertEqual(
            [item["id"] for item in contract.explicit_acceptance_criteria],
            [f"explicit_ac_{i:03d}" for i in range(1, 9)],
        )

    def test_no_lines_need_rescue_as_mandatory_requirements(self) -> None:
        contract = build_mission_contract(self.GOAL)
        # All eight numbered lines are now correctly routed to
        # explicit_acceptance_criteria; none are needed in (or leak into)
        # mandatory_requirements.
        self.assertEqual(contract.mandatory_requirements, [])

    def test_generic_inferred_template_is_no_longer_substituted(self) -> None:
        # RUN_049 PART A/B fix: because explicit_acceptance_criteria is now
        # correctly populated, build_mission_contract() never falls back to
        # derive_acceptance_criteria_from_goal()'s generic, keyword-triggered
        # template -- the operator's own 8-item contract is used verbatim.
        contract = build_mission_contract(self.GOAL)
        self.assertEqual(contract.inferred_acceptance_criteria, [])

    def test_a_recognized_heading_spelling_does_work(self) -> None:
        # Control case: proves the parser mechanism itself is sound and the
        # defect is specifically the exact-match dictionary, not something
        # else entirely broken in build_mission_contract().
        goal = self.GOAL.replace("MANDATORY ACCEPTANCE CRITERIA", "Acceptance criteria:")
        contract = build_mission_contract(goal)
        self.assertEqual(len(contract.explicit_acceptance_criteria), 8)


class LocalUsageGameControlsDefectTests(unittest.TestCase):
    """PART J.25 -- classified as "another deterministic defect", not a model failure."""

    def test_game_controls_and_local_usage_are_generic_template_ids_not_operator_authored(
        self,
    ) -> None:
        # game_controls and local_usage are literal criterion_id values baked
        # into derive_acceptance_criteria_from_goal's generic Pixel-Wanderer-
        # shaped template, keyed off keyword sniffing (canvas/score/game,
        # arrow/wasd/movement, usage/local/run) -- not values chosen by, or
        # traceable to, the operator's real "MANDATORY ACCEPTANCE CRITERIA"
        # text. When that heading fails to match (see the class above), the
        # verifier silently checks THIS template's two most keyword-fragile
        # criteria instead of whatever the operator actually wrote.
        goal_text = (
            "Build my-game.html, style.css, and game.js for a small canvas game with a score.\n"
            "Movement uses WASD and Arrow keys.\n"
            "See usage.md to run it locally.\n"
        )
        criteria = derive_acceptance_criteria_from_goal(goal_text)
        ids = {item["criterion_id"] for item in criteria}
        self.assertIn("game_controls", ids)
        self.assertIn("local_usage", ids)


class ExplicitCriterionEndToEndVerificationTests(unittest.TestCase):
    """RUN_049 PART B.13 -- reproduces the fixed Repair Probe result end-to-end.

    Drives real per-criterion verification (mirroring how control_surface.py's
    ``profile="acceptance_ledger"`` assembles requests from the ledger) against
    a real workspace, using the exact 8-item MANDATORY ACCEPTANCE CRITERIA goal.
    Confirms failures are now attributed to the operator's own explicit
    criterion IDs (never the bogus "game_controls"/"local_usage" substituted
    IDs) and that exactly the one deliberately-broken criterion fails.
    """

    GOAL = MandatoryAcceptanceCriteriaHeadingDefectTests.GOAL

    PASSING_GAME_JS = (
        "const keys = {};\n"
        "window.addEventListener('keydown', e => { keys[e.key] = true; });\n"
        "window.addEventListener('keyup', e => { keys[e.key] = false; });\n"
        "let player = { x: 0, y: 0 };\n"
        "let score = 0;\n"
        "function update() {\n"
        "  if (keys['ArrowUp'] || keys['w'] || keys['W']) player.y -= 1;\n"
        "  if (keys['ArrowDown'] || keys['s'] || keys['S']) player.y += 1;\n"
        "  if (keys['ArrowLeft'] || keys['a'] || keys['A']) player.x -= 1;\n"
        "  if (keys['ArrowRight'] || keys['d'] || keys['D']) player.x += 1;\n"
        "}\n"
        "function collectItem() {\n"
        "  score += 10;\n"
        "}\n"
    )

    def _write_workspace(self, tmp_path: Path, *, game_js: str) -> Path:
        (tmp_path / "index.html").write_text("<!doctype html><html></html>", encoding="utf-8")
        (tmp_path / "style.css").write_text("body { margin: 0; }", encoding="utf-8")
        (tmp_path / "game.js").write_text(game_js, encoding="utf-8")
        (tmp_path / "LOCAL_DEV.md").write_text(
            "To run locally, open index.html directly in your browser.", encoding="utf-8"
        )
        return tmp_path

    def _verify(self, workspace: Path) -> dict[str, str]:
        from admissible.execution.bounded_local_verification import (
            VerificationRequest,
            run_single_verification_check,
        )

        contract = build_mission_contract(self.GOAL)
        ledger = contract_acceptance_ledger(contract.to_dict())
        status_by_criterion: dict[str, str] = {}
        for criterion in ledger:
            for raw_request in criterion["verification"]:
                data = dict(raw_request)
                data.setdefault("criterion_id", criterion["criterion_id"])
                request = VerificationRequest.from_dict(data)
                result = run_single_verification_check(workspace_path=workspace, request=request)
                status_by_criterion[criterion["criterion_id"]] = result.status
        return status_by_criterion

    def test_fully_compliant_workspace_passes_all_eight_explicit_criteria(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = self._write_workspace(Path(tmp), game_js=self.PASSING_GAME_JS + "\nfunction resetGame() { score = 0; player = { x: 0, y: 0 }; }\nwindow.addEventListener('keydown', e => { if (e.key === 'r' || e.key === 'R') resetGame(); });\n")
            statuses = self._verify(workspace)
            self.assertEqual(len(statuses), 8)
            self.assertTrue(all(status == "pass" for status in statuses.values()), statuses)

    def test_missing_restart_handling_fails_exactly_one_correctly_attributed_criterion(self) -> None:
        # The historical narrative reported "controlled_instruction_intended_
        # failure_count: 1" but "observed_failure_count: 2" against bogus IDs
        # (see repair_probe_callable_transport_forensic_regression.json). With
        # the PART A/B fix, one deliberately-missing behavior (restart) now
        # fails exactly one criterion, under the operator's own criterion ID.
        with tempfile.TemporaryDirectory() as tmp:
            workspace = self._write_workspace(Path(tmp), game_js=self.PASSING_GAME_JS)
            statuses = self._verify(workspace)
            failed = [criterion_id for criterion_id, status in statuses.items() if status == "fail"]
            self.assertEqual(failed, ["explicit_ac_007"])
            self.assertNotIn("game_controls", statuses)
            self.assertNotIn("local_usage", statuses)


class RunIdentityBackendDashDefectTests(unittest.TestCase):
    """RUN_049 PART C -- confirmed frontend key-name mismatch, now fixed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = CONTROL_SURFACE_HTML.read_text(encoding="utf-8")

    def test_run_identity_no_longer_reads_the_keys_the_server_never_set(self) -> None:
        # RUN_049 fix: renderRunIdentity() used to read state.high_autonomy
        # and state.control, which session_dict()/state_view() never set
        # (only state.high_autonomy_summary / state.agent_backend_control).
        self.assertNotIn("const ha = state.high_autonomy ||", self.html)
        self.assertNotIn("const control = state.control ||", self.html)

    def test_run_identity_now_reads_the_real_server_keys(self) -> None:
        self.assertIn('view["high_autonomy_summary"]', self._python_source())
        self.assertIn('view["agent_backend_control"]', self._python_source())
        # renderWorkspaceFirst already used the real key names correctly;
        # renderRunIdentity now matches it instead of drifting from it.
        self.assertIn("state.high_autonomy_summary", self.html)
        self.assertIn("state.agent_backend_control", self.html)
        self.assertIn("identityBackend.transport_label", self.html)
        self.assertIn("identityBackend.model_label", self.html)

    @staticmethod
    def _python_source() -> str:
        path = (
            Path(__file__).resolve().parent.parent / "admissible" / "control_surface.py"
        )
        return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
