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
import unittest
from pathlib import Path

from admissible.governed_run import derive_acceptance_criteria_from_goal
from admissible.mission_contract import build_mission_contract

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

    def test_heading_with_extra_leading_word_is_not_recognized_as_acceptance_section(self) -> None:
        contract = build_mission_contract(self.GOAL)
        # Confirmed root cause: mission_contract._HEADINGS["acceptance"] only
        # exact-matches "acceptance criteria" / "completion criteria" / the
        # French variant. "mandatory acceptance criteria" is a superset, not a
        # member, of that tuple, so _heading() returns None for it and the
        # eight numbered lines are never routed to section == "acceptance".
        self.assertEqual(contract.explicit_acceptance_criteria, [])

    def test_dropped_lines_are_not_even_rescued_as_mandatory_requirements(self) -> None:
        contract = build_mission_contract(self.GOAL)
        # They are not silently promoted anywhere else either -- with no
        # recognized section role, build_mission_contract's per-line dispatch
        # has no branch that matches role=None, so the eight lines vanish
        # from the contract entirely.
        self.assertEqual(contract.mandatory_requirements, [])

    def test_generic_inferred_template_is_silently_substituted_instead(self) -> None:
        contract = build_mission_contract(self.GOAL)
        # Because explicit_acceptance_criteria ends up empty,
        # build_mission_contract() falls back to
        # derive_acceptance_criteria_from_goal()'s generic, keyword-triggered
        # template -- a *different* contract than the operator actually wrote.
        inferred_ids = {item["id"] for item in contract.inferred_acceptance_criteria}
        self.assertTrue(inferred_ids)
        self.assertNotEqual(
            inferred_ids, {f"explicit_ac_{i:03d}" for i in range(1, 9)}
        )

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


class RunIdentityBackendDashDefectTests(unittest.TestCase):
    """PART J.26 -- confirmed frontend key-name mismatch, static evidence only."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = CONTROL_SURFACE_HTML.read_text(encoding="utf-8")

    def test_run_identity_reads_a_top_level_key_the_server_never_sets(self) -> None:
        # Confirmed root cause: renderRunIdentity() reads state.high_autonomy
        # and state.control, but session_dict()/state_view() in
        # control_surface.py only ever populates state.high_autonomy_summary
        # and state.agent_backend_control. Both lookups are therefore always
        # undefined, independent of which backend actually governed the run,
        # which is why the panel always shows the em dash placeholder.
        self.assertIn("const ha = state.high_autonomy ||", self.html)
        self.assertIn("const control = state.control ||", self.html)

    def test_the_keys_the_server_actually_sets_are_named_differently(self) -> None:
        self.assertIn('view["high_autonomy_summary"]', self._python_source())
        self.assertIn('view["agent_backend_control"]', self._python_source())
        # And renderWorkspaceFirst -- elsewhere in the same file -- correctly
        # uses the real key names, proving this is an isolated typo/drift in
        # renderRunIdentity specifically, not a server-side omission.
        self.assertIn("state.high_autonomy_summary", self.html)
        self.assertIn("state.agent_backend_control", self.html)

    @staticmethod
    def _python_source() -> str:
        path = (
            Path(__file__).resolve().parent.parent / "admissible" / "control_surface.py"
        )
        return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
