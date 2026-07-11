"""RUN_045 PART J / PART I — unbulleted "Acceptance criteria:" line parsing.

A heading-scoped line under "Acceptance criteria:" with no ``-``/``*``/numeric
prefix must never be silently dropped by ``build_mission_contract`` -- it is
recorded as an explicit, mandatory requirement (never promoted to
``explicit_acceptance_criteria``, which would have displaced the generic
inferred-criteria verification wiring cli_011-shaped goals already depend
on). Exercised across four unrelated domains (CLI, data, docs, browser app)
to confirm this is a general parser fix, not something Pixel-Wanderer- or
browser-game-specific.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from admissible.mission_contract import (
    build_mission_contract,
    contract_acceptance_ledger,
    ledger_coverage_report,
)

FIXTURE_011 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_011_regression.json"
)

DOMAIN_GOALS = {
    "cli": (
        "Build a small CLI tool called linecount.\n\n"
        "Acceptance criteria:\n"
        "Accepts a file path argument;\n"
        "Counts lines, words, and characters;\n"
        "Prints a formatted summary to stdout;\n"
        "Exits non-zero on a missing file."
    ),
    "data": (
        "Build a data processing script called sales_report.\n\n"
        "Mandatory deliverables:\n- transform.py\n- report.csv\n\n"
        "Acceptance criteria:\n"
        "Reads input.csv and writes report.csv;\n"
        "Aggregates totals by region;\n"
        "Handles missing values without crashing;\n"
        "Logs a summary row count."
    ),
    "docs": (
        "Write project documentation called API_GUIDE.\n\n"
        "Acceptance criteria:\n"
        "Explains every public endpoint;\n"
        "Includes a quickstart example;\n"
        "Lists authentication requirements;\n"
        "Has a changelog section."
    ),
    "browser_app": (
        "Build a complete local browser game called Tiny Runner.\n\n"
        "Mandatory deliverables:\n- index.html\n- style.css\n- game.js\n\n"
        "Acceptance criteria:\n"
        "The game opens locally from index.html;\n"
        "Arrow keys move the character;\n"
        "Collisions end the run;\n"
        "A restart control resets the game."
    ),
}


class TestUnbulletedAcceptanceSectionsCrossDomain(unittest.TestCase):
    def test_each_domain_captures_every_line_as_a_mandatory_requirement(self) -> None:
        for domain, goal in DOMAIN_GOALS.items():
            with self.subTest(domain=domain):
                contract = build_mission_contract(goal).to_dict()
                self.assertEqual(
                    contract["explicit_acceptance_criteria"],
                    [],
                    "unbulleted lines must never be promoted to explicit criteria",
                )
                requirements = contract["mandatory_requirements"]
                self.assertEqual(len(requirements), 4, domain)
                for item in requirements:
                    self.assertEqual(item["source"], "explicit")
                    self.assertTrue(item["mandatory"])
                    # Trailing separator punctuation stripped, interior text untouched.
                    self.assertFalse(item["source_text"].endswith(";"))
                    self.assertFalse(item["source_text"].endswith("."))

    def test_cli_domain_exact_requirement_text(self) -> None:
        contract = build_mission_contract(DOMAIN_GOALS["cli"]).to_dict()
        texts = [item["source_text"] for item in contract["mandatory_requirements"]]
        self.assertEqual(
            texts,
            [
                "Accepts a file path argument",
                "Counts lines, words, and characters",
                "Prints a formatted summary to stdout",
                "Exits non-zero on a missing file",
            ],
        )

    def test_data_domain_exact_requirement_text(self) -> None:
        contract = build_mission_contract(DOMAIN_GOALS["data"]).to_dict()
        texts = [item["source_text"] for item in contract["mandatory_requirements"]]
        self.assertEqual(
            texts,
            [
                "Reads input.csv and writes report.csv",
                "Aggregates totals by region",
                "Handles missing values without crashing",
                "Logs a summary row count",
            ],
        )

    def test_docs_domain_exact_requirement_text(self) -> None:
        contract = build_mission_contract(DOMAIN_GOALS["docs"]).to_dict()
        texts = [item["source_text"] for item in contract["mandatory_requirements"]]
        self.assertEqual(
            texts,
            [
                "Explains every public endpoint",
                "Includes a quickstart example",
                "Lists authentication requirements",
                "Has a changelog section",
            ],
        )

    def test_ledger_falls_back_to_requirements_when_no_criteria_exist(self) -> None:
        # cli/data/docs goals have no bulleted acceptance criteria and no
        # deliverable-driven inference (fewer than 2 named deliverable
        # files), so the ledger's only honest source is the requirements.
        for domain in ("cli", "data", "docs"):
            with self.subTest(domain=domain):
                contract = build_mission_contract(DOMAIN_GOALS[domain]).to_dict()
                self.assertEqual(contract["inferred_acceptance_criteria"], [])
                ledger = contract_acceptance_ledger(contract)
                self.assertEqual(len(ledger), 4)
                coverage = ledger_coverage_report(contract, ledger)
                self.assertFalse(coverage["criteria_are_inferred"])
                self.assertEqual(coverage["total_ledger_criterion_count"], 4)
                self.assertEqual(coverage["inferred_acceptance_criterion_count"], 0)

    def test_browser_app_domain_uses_inferred_criteria_not_requirements(self) -> None:
        # With >=2 named deliverable files, derive_acceptance_criteria_from_goal
        # still produces the generic inferred criteria the ledger prefers over
        # the newly-captured requirements -- unbulleted-line capture must never
        # displace that pre-existing, verification-wired path.
        contract = build_mission_contract(DOMAIN_GOALS["browser_app"]).to_dict()
        self.assertGreater(len(contract["inferred_acceptance_criteria"]), 0)
        self.assertEqual(len(contract["mandatory_requirements"]), 4)
        ledger = contract_acceptance_ledger(contract)
        coverage = ledger_coverage_report(contract, ledger)
        self.assertTrue(coverage["criteria_are_inferred"])
        self.assertEqual(coverage["total_ledger_criterion_count"], len(contract["inferred_acceptance_criteria"]))

    def test_cli011_fixture_regression_still_uses_inferred_eight_criteria(self) -> None:
        # The exact pre-existing regression this change must never break: an
        # unbulleted "Acceptance criteria:" section must keep routing through
        # the inferred, verification-wired ledger, not bare explicit criteria.
        fixture = json.loads(FIXTURE_011.read_text(encoding="utf-8"))
        contract = build_mission_contract(fixture["goal_text"]).to_dict()
        self.assertEqual(contract["explicit_acceptance_criteria"], [])
        self.assertEqual(len(contract["inferred_acceptance_criteria"]), 8)
        ledger = contract_acceptance_ledger(contract)
        self.assertEqual(len(ledger), 8)
        coverage = ledger_coverage_report(contract, ledger)
        self.assertTrue(coverage["criteria_are_inferred"])
        self.assertEqual(coverage["inferred_acceptance_criterion_count"], 8)
        self.assertEqual(coverage["total_ledger_criterion_count"], 8)

    def test_bulleted_acceptance_lines_are_unaffected(self) -> None:
        goal = (
            "Build a small CLI tool called linecount.\n\n"
            "Acceptance criteria:\n"
            "- Accepts a file path argument\n"
            "- Counts lines, words, and characters\n"
        )
        contract = build_mission_contract(goal).to_dict()
        self.assertEqual(len(contract["explicit_acceptance_criteria"]), 2)
        self.assertEqual(contract["mandatory_requirements"], [])

    def test_numbered_acceptance_lines_are_unaffected(self) -> None:
        goal = (
            "Build a small CLI tool called linecount.\n\n"
            "Acceptance criteria:\n"
            "1. Accepts a file path argument\n"
            "2. Counts lines, words, and characters\n"
        )
        contract = build_mission_contract(goal).to_dict()
        self.assertEqual(len(contract["explicit_acceptance_criteria"]), 2)
        self.assertEqual(contract["mandatory_requirements"], [])


if __name__ == "__main__":
    unittest.main()
