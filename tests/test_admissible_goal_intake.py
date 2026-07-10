"""Tests for Goal Intake v0 (admissible.goal_intake)."""

from __future__ import annotations

import unittest

from admissible.goal_intake import (
    AUTONOMY_CEILING_L1,
    AUTONOMY_CEILING_L2,
    AUTONOMY_CEILING_L3,
    GoalIntake,
    analyze_goal,
)

SLITHER_PROMPT = (
    "Build a small browser-based Slither-like game with a moving snake, "
    "collectible food, growth, collision handling, score display, restart "
    "behavior, and simple visual polish. Keep it local-only. Do not deploy. "
    "Ask before installing dependencies or deleting existing files."
)


class TestGoalIntakeSlitherExample(unittest.TestCase):
    """The Slither example from docs/admissible-goal-intake-and-plan-audit.md."""

    def setUp(self) -> None:
        self.intake = analyze_goal(SLITHER_PROMPT)

    def test_returns_goal_intake(self) -> None:
        self.assertIsInstance(self.intake, GoalIntake)
        self.assertEqual(self.intake.prompt, SLITHER_PROMPT)

    def test_task_type_and_deliverable(self) -> None:
        self.assertEqual(self.intake.task_type, "software_build")
        self.assertIn("game", self.intake.deliverable)
        self.assertIn("browser", self.intake.deliverable)

    def test_project_maturity_new_project(self) -> None:
        self.assertEqual(self.intake.project_maturity, "new_project")

    def test_architecture_choice_burden_medium(self) -> None:
        self.assertEqual(self.intake.architecture_choice_burden, "medium")

    def test_global_complexity_medium(self) -> None:
        self.assertEqual(self.intake.global_complexity, "medium")

    def test_global_risk_is_bounded_not_high(self) -> None:
        self.assertIn(self.intake.global_risk, ("low", "medium"))
        self.assertEqual(self.intake.risk_scope, "local")

    def test_likely_side_effects_match_expected_classes(self) -> None:
        self.assertEqual(
            self.intake.likely_side_effect_classes,
            ["file_create", "file_edit", "possible_dependency_install", "possible_server_run"],
        )

    def test_deploy_not_listed_because_explicitly_negated(self) -> None:
        self.assertNotIn("possible_deploy", self.intake.likely_side_effect_classes)

    def test_destructive_file_op_not_listed_for_new_project(self) -> None:
        self.assertNotIn("possible_destructive_file_op", self.intake.likely_side_effect_classes)

    def test_missing_context_and_clarifying_questions_present(self) -> None:
        self.assertTrue(self.intake.missing_context)
        self.assertTrue(self.intake.clarifying_questions)
        joined = " ".join(self.intake.missing_context).lower()
        self.assertIn("dependency", joined)
        self.assertNotIn("deployment", joined)
        self.assertEqual(self.intake.explicit_deployment_boundary, "local_only_no_deploy")

    def test_recommended_autonomy_ceiling_is_l2_or_l3_never_l4(self) -> None:
        self.assertIn(self.intake.recommended_autonomy_ceiling, (AUTONOMY_CEILING_L2, AUTONOMY_CEILING_L3))
        self.assertNotEqual(self.intake.recommended_autonomy_ceiling, "L4_HIGH_AUTONOMY_HARD_GATES")

    def test_non_execution_boundary_names_gated_side_effects(self) -> None:
        boundary = self.intake.initial_non_execution_boundary.lower()
        self.assertIn("dependency install", boundary)
        self.assertIn("authorization", boundary)

    def test_signals_are_auditable(self) -> None:
        # Every derived classification should be traceable to at least one
        # recorded signal (auditability requirement).
        for key in ("task_type", "deliverable", "architecture_choice_burden", "global_risk"):
            self.assertIn(key, self.intake.signals)

    def test_to_dict_round_trips_as_plain_json_types(self) -> None:
        import json

        data = self.intake.to_dict()
        # Must be JSON-serializable without a custom encoder.
        json.dumps(data)
        self.assertEqual(data["task_type"], "software_build")


class TestGoalIntakeOtherPrompts(unittest.TestCase):
    def test_bug_fix_prompt_is_low_complexity(self) -> None:
        intake = analyze_goal("Fix a typo in the README file of this repository.")
        self.assertEqual(intake.task_type, "bug_fix")
        self.assertEqual(intake.global_complexity, "low")
        self.assertNotIn("file_create", intake.likely_side_effect_classes)

    def test_high_risk_production_prompt_recommends_l1(self) -> None:
        intake = analyze_goal(
            "Deploy this application to production and wire up live payment processing "
            "with real customer credentials."
        )
        self.assertEqual(intake.global_risk, "high")
        self.assertEqual(intake.recommended_autonomy_ceiling, AUTONOMY_CEILING_L1)

    def test_existing_project_low_ambiguity_prompt_allows_l3(self) -> None:
        intake = analyze_goal(
            "In this existing codebase, using the existing Flask app and existing "
            "test suite, fix the small bug in the login route."
        )
        self.assertEqual(intake.project_maturity, "existing_project")
        self.assertIn(
            intake.recommended_autonomy_ceiling,
            (AUTONOMY_CEILING_L2, AUTONOMY_CEILING_L3),
        )

    def test_empty_prompt_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            analyze_goal("")
        with self.assertRaises(ValueError):
            analyze_goal("   ")

    def test_no_agent_os_import(self) -> None:
        from pathlib import Path

        source = (Path(__file__).resolve().parent.parent / "admissible" / "goal_intake.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("import agent_os", source)
        self.assertNotIn("from agent_os", source)


if __name__ == "__main__":
    unittest.main()
