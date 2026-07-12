"""RUN_050 — Neon cli-003 Mission Contract parsing regression.

Canonical fixture: the EXACT raw goal of the cli-003 first-stop session
(tests/fixtures/admissible/neon_serpents_cli_003_contract_regression.json).
Before RUN_050 it parsed to 47 explicit acceptance criteria, 46 mandatory
requirements, and 13 mandatory paths because:

1. a numbered acceptance item was cut at its first physical line, its wrapped
   continuation lines becoming dangling pseudo-requirements;
2. bullets nested inside criterion 13 (the eight debug snapshot fields) were
   promoted to sibling top-level criteria;
3. unrecognized section headings (IMPLEMENTATION PROCESS, VERIFICATION AND
   REPAIR, FINAL REPORT) never terminated acceptance parsing, so every later
   section's bullets were absorbed as acceptance criteria;
4. root-level file names inside a negated sentence ("... does not satisfy the
   required src/ path.") were promoted to mandatory paths.

The correct canonical shape asserted here: exactly 15 explicit numbered
criteria (1..15) each carrying its complete wrapped text, criterion 13 owning
exactly eight nested subrequirements, exactly 8 mandatory paths, the five
root-level names recorded as rejected substitutes, zero pseudo-requirements,
and an initial projection that never claims human observation is currently
awaited. All of it is deterministic local parsing -- no provider call.
"""

from __future__ import annotations

import json
import socket
import unittest
from pathlib import Path

from admissible.mission_contract import (
    build_mission_contract,
    contract_acceptance_ledger,
    instruction_fidelity_report,
    ledger_coverage_report,
)

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "neon_serpents_cli_003_contract_regression.json"
)

EXPECTED_MANDATORY_PATHS = [
    "index.html",
    "style.css",
    "src/main.js",
    "src/game.js",
    "src/entities.js",
    "src/bots.js",
    "src/render.js",
    "LOCAL_DEV.md",
]

FORBIDDEN_ROOT_SUBSTITUTES = ["game.js", "main.js", "bots.js", "entities.js", "render.js"]

EXPECTED_DEBUG_SUBREQUIREMENTS = [
    "phase: string",
    "player: object containing x, y, length, alive, and boosting",
    "botCount: number",
    "pelletCount: number",
    "leaderboard: array",
    "respawnCount: number",
    "loopCount: number",
    "debugVisible: boolean",
]

# Pseudo-requirements the defective parse manufactured out of wrapped
# continuation lines and unrecognized section headings.
FORBIDDEN_PSEUDO_REQUIREMENTS = {
    "file",
    "change",
    "inspection",
    "IMPLEMENTATION PROCESS",
    "VERIFICATION AND REPAIR",
    "FINAL REPORT",
}

LATER_SECTION_BULLET_FRAGMENTS = [
    # IMPLEMENTATION PROCESS bullets
    "Propose structured local file operations only",
    "Use no more than four write operations",
    "Preserve every already-passing criterion during repairs",
    # VERIFICATION AND REPAIR bullets
    "allow Admissible to run deterministic structural verification",
    "treat runtime failures as repair evidence",
    "do not add a second animation loop during repair",
    # FINAL REPORT bullets
    "files produced",
    "architecture used",
    "repairs performed",
]


def _goal() -> str:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["goal_text"]


def _contract() -> dict:
    return build_mission_contract(_goal()).to_dict()


class TestNeonCli003CanonicalContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _contract()
        cls.criteria = cls.contract["explicit_acceptance_criteria"]
        cls.by_number = {c.get("source_number"): c for c in cls.criteria}
        cls.ledger = contract_acceptance_ledger(cls.contract)

    def test_exactly_fifteen_numbered_criteria(self) -> None:
        # Canonical assertions 1-3.
        self.assertEqual(
            self.contract["extraction_diagnostics"]["explicit_numbered_criterion_count"], 15
        )
        self.assertEqual(len(self.criteria), 15)
        self.assertEqual([c.get("source_number") for c in self.criteria], list(range(1, 16)))

    def test_each_criterion_contains_its_complete_wrapped_text(self) -> None:
        # Canonical assertion 4: wrapped continuation lines are retained in
        # the complete source text of their parent criterion.
        self.assertTrue(self.by_number[1]["source_text"].endswith("through src/main.js."))
        self.assertTrue(self.by_number[15]["source_text"].endswith("direct human observation."))
        # Mid-goal wrapped continuations, previously lost after line one:
        self.assertIn("material console errors", self.by_number[2]["source_text"])
        self.assertIn("one small screen", self.by_number[3]["source_text"])
        self.assertIn("four grid directions", self.by_number[4]["source_text"])
        self.assertIn("without reloading the page", self.by_number[8]["source_text"])
        self.assertIn("updates during play", self.by_number[10]["source_text"])
        self.assertIn("duplicate animation loops", self.by_number[11]["source_text"])
        self.assertIn("must not reveal duplicate loops", self.by_number[13]["source_text"])

    def test_criterion_13_owns_exactly_eight_debug_subrequirements(self) -> None:
        # Canonical assertions 5-6.
        subs = self.by_number[13].get("subrequirements") or []
        self.assertEqual([s["source_text"] for s in subs], EXPECTED_DEBUG_SUBREQUIREMENTS)
        self.assertEqual(len(subs), 8)
        for sub in subs:
            self.assertTrue(sub["mandatory"])
            self.assertTrue(sub["id"].startswith(self.by_number[13]["id"]))
        # The debug fields never appear as top-level criteria.
        for field_text in EXPECTED_DEBUG_SUBREQUIREMENTS:
            for criterion in self.criteria:
                self.assertFalse(criterion["source_text"].startswith(field_text.split(":")[0] + ":"))

    def test_later_sections_terminate_acceptance_parsing(self) -> None:
        # Canonical assertions 7-10: IMPLEMENTATION PROCESS terminates the
        # acceptance section, and no later section's bullets become
        # acceptance criteria.
        criterion_texts = [c["source_text"] for c in self.criteria]
        for fragment in LATER_SECTION_BULLET_FRAGMENTS:
            for text in criterion_texts:
                self.assertNotIn(fragment, text)

    def test_mandatory_paths_are_exactly_the_eight_scoped_paths(self) -> None:
        # Canonical assertion 11.
        self.assertEqual(self.contract["mandatory_paths"], EXPECTED_MANDATORY_PATHS)

    def test_negated_root_level_names_are_rejected_substitutes_not_mandatory(self) -> None:
        # Canonical assertion 12.
        for name in FORBIDDEN_ROOT_SUBSTITUTES:
            self.assertNotIn(name, self.contract["mandatory_paths"])
        rejected = [
            entry
            for entry in self.contract["explicit_non_goals"]
            if entry.get("kind") == "rejected_path_substitute"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["rejected_paths"], FORBIDDEN_ROOT_SUBSTITUTES)
        self.assertIn("does not", rejected[0]["source_text"])

    def test_no_dangling_continuation_word_requirements(self) -> None:
        # Canonical assertion 13: the defective parse manufactured 46
        # pseudo-requirements from continuation lines and headings; the
        # corrected contract has none at all for this goal.
        requirement_texts = {r["source_text"] for r in self.contract["mandatory_requirements"]}
        self.assertEqual(requirement_texts & FORBIDDEN_PSEUDO_REQUIREMENTS, set())
        self.assertEqual(self.contract["mandatory_requirements"], [])

    def test_ledger_coverage_is_complete(self) -> None:
        # Canonical assertion 14.
        coverage = ledger_coverage_report(self.contract, self.ledger)
        self.assertTrue(coverage["coverage_complete"])
        self.assertEqual(coverage["explicit_acceptance_criterion_count"], 15)
        self.assertEqual(coverage["represented_acceptance_criterion_count"], 15)
        self.assertEqual(coverage["mandatory_path_count"], 8)
        self.assertEqual(coverage["represented_path_count"], 8)

    def test_instruction_fidelity_includes_all_criteria_and_paths(self) -> None:
        # Canonical assertion 15.
        packet = f".admissible/mission-contract.json raw {self.contract['raw_goal_sha256']}"
        report = instruction_fidelity_report(self.contract, packet)
        self.assertTrue(report["fidelity_complete"])
        self.assertEqual(len(report["criterion_ids_included"]), 15)
        self.assertEqual(len(report["mandatory_paths_included"]), 8)

    def test_initial_ui_summary_reports_fifteen_criteria_and_eight_paths(self) -> None:
        # Canonical assertions 16-17: the UI contract line renders the
        # coverage report; the "Awaiting human observation" panel keys on the
        # RUN_050 state-priority flag which must be False before any
        # implementation artifact or verification exists -- even though the
        # human-observation DISPOSITIONS legitimately already exist.
        from admissible.high_autonomy_controller import (
            HA_MODE_RUNNING,
            HighAutonomyRunState,
            build_high_autonomy_summary,
            refresh_runtime_projection_and_metrics,
        )

        state = HighAutonomyRunState()
        state.mode = HA_MODE_RUNNING
        state.acceptance_criteria = contract_acceptance_ledger(self.contract)
        state.contract_ledger_coverage_report = ledger_coverage_report(
            self.contract, state.acceptance_criteria
        )
        refresh_runtime_projection_and_metrics(state)
        summary = build_high_autonomy_summary(ha_state=state, state_view={})
        coverage = summary["contract_ledger_coverage_report"]
        self.assertEqual(coverage["explicit_acceptance_criterion_count"], 15)
        self.assertEqual(coverage["mandatory_path_count"], 8)
        # Dispositions may exist...
        self.assertTrue(
            any(
                item["verification_disposition"] == "human_observation_required"
                for item in state.acceptance_criteria
            )
        )
        self.assertTrue(summary["human_observation_pending_criterion_ids"])
        # ...but the initial state never claims observation is awaited NOW.
        self.assertFalse(summary["human_observation_currently_awaited"])
        self.assertNotIn("Awaiting human observation", summary["doing_now"])

    def test_no_provider_call_is_needed_to_build_or_validate_the_contract(self) -> None:
        # Canonical assertion 18: contract construction and validation are
        # purely local -- any socket connect attempt fails this test.
        original_connect = socket.socket.connect

        def _blocked(self, *args, **kwargs):  # pragma: no cover - guard only
            raise AssertionError("mission contract construction attempted a network call")

        socket.socket.connect = _blocked
        try:
            contract = build_mission_contract(_goal()).to_dict()
            ledger = contract_acceptance_ledger(contract)
            self.assertEqual(len(ledger), 15)
            self.assertTrue(ledger_coverage_report(contract, ledger)["coverage_complete"])
        finally:
            socket.socket.connect = original_connect


class TestCrossDomainStructuralParsing(unittest.TestCase):
    """Small focused cross-domain cases proving the fixes are structural,
    not Neon-specific."""

    def test_multiline_numbered_cli_criteria_are_reconstructed(self) -> None:
        goal = (
            "Build a CLI archiver.\n\n"
            "Acceptance criteria:\n"
            "1. The tool accepts an input directory argument and writes a\n"
            "   deterministic archive next to it.\n"
            "2. Invalid arguments exit with status two and print usage\n"
            "   information to stderr.\n"
        )
        contract = build_mission_contract(goal).to_dict()
        criteria = contract["explicit_acceptance_criteria"]
        self.assertEqual(len(criteria), 2)
        self.assertTrue(criteria[0]["source_text"].endswith("deterministic archive next to it."))
        self.assertTrue(criteria[1]["source_text"].endswith("information to stderr."))
        self.assertEqual(contract["mandatory_requirements"], [])

    def test_nested_bullets_inside_a_documentation_criterion(self) -> None:
        goal = (
            "Write an operations guide.\n\n"
            "Acceptance criteria:\n"
            "1. The guide documents every deployment stage:\n"
            "   - build: compile and bundle\n"
            "   - release: tag and publish notes\n"
            "   - rollback: restore the previous tag\n"
            "2. The guide has a troubleshooting section.\n"
        )
        contract = build_mission_contract(goal).to_dict()
        criteria = contract["explicit_acceptance_criteria"]
        self.assertEqual(len(criteria), 2)
        subs = criteria[0].get("subrequirements") or []
        self.assertEqual(
            [s["source_text"] for s in subs],
            [
                "build: compile and bundle",
                "release: tag and publish notes",
                "rollback: restore the previous tag",
            ],
        )
        self.assertEqual(criteria[1].get("subrequirements"), None)

    def test_later_working_method_section_terminates_acceptance(self) -> None:
        goal = (
            "Build a data pipeline.\n\n"
            "Acceptance criteria:\n"
            "1. Input rows are validated against the schema.\n"
            "2. Rejected rows are written to a quarantine file.\n\n"
            "WORKING METHOD\n\n"
            "- Work in small reviewable batches.\n"
            "- Never rewrite passing stages without evidence.\n"
        )
        contract = build_mission_contract(goal).to_dict()
        criteria = contract["explicit_acceptance_criteria"]
        self.assertEqual(len(criteria), 2)
        texts = [c["source_text"] for c in criteria] + [
            r["source_text"] for r in contract["mandatory_requirements"]
        ]
        for text in texts:
            self.assertNotIn("reviewable batches", text)
            self.assertNotIn("WORKING METHOD", text)

    def test_positive_mandatory_paths_with_forbidden_alternatives(self) -> None:
        goal = (
            "Build a reporting service.\n\n"
            "Mandatory files:\n"
            "- app/report.py\n"
            "- app/config.yaml\n\n"
            "A root-level report.py or config.yaml does not satisfy the required app/ layout.\n"
        )
        contract = build_mission_contract(goal).to_dict()
        self.assertEqual(contract["mandatory_paths"], ["app/report.py", "app/config.yaml"])
        rejected = [
            entry
            for entry in contract["explicit_non_goals"]
            if entry.get("kind") == "rejected_path_substitute"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["rejected_paths"], ["report.py", "config.yaml"])


if __name__ == "__main__":
    unittest.main()
