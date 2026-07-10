"""Explicit goal authority closes matching plan gates without auto-approval."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.goal_intake import analyze_goal
from admissible.plan_audit import PLAN_VERDICT_OK, audit_plan, generate_plan_candidate
from admissible.run_loop import generate_instruction_packet


PIXEL_WANDERER_GOAL = (
    "Build a browser game called Pixel Wanderer using plain HTML/CSS/JavaScript only. "
    "Use zero dependencies, no npm, and no package manager. Keep it local-only. "
    "Do not deploy, publish, host, or push. Do not use network or shell commands."
)


def _plan_and_audit(goal: str):
    intake = analyze_goal(goal)
    plan = generate_plan_candidate(intake)
    return intake, plan, audit_plan(plan, intake)


class TestExplicitGoalScopeResolution(unittest.TestCase):
    def test_pixel_wanderer_goal_closes_architecture_dependency_and_deployment_gates(self) -> None:
        intake, plan, audit = _plan_and_audit(PIXEL_WANDERER_GOAL)
        steps = {step.step_type: step for step in plan.steps}

        self.assertEqual(intake.task_type, "software_build")
        self.assertEqual(intake.explicit_architecture_choice, "explicit_stack_or_plain_web")
        self.assertEqual(intake.explicit_dependency_preference, "zero_dependencies")
        self.assertEqual(intake.explicit_deployment_boundary, "local_only_no_deploy")
        self.assertFalse(steps["choose_architecture"].requires_gate)
        self.assertNotIn("install_dependencies", steps)
        self.assertFalse(steps["deployment_gate"].requires_gate)
        self.assertEqual(audit.verdict, PLAN_VERDICT_OK)
        self.assertEqual(audit.required_gates, [])
        self.assertEqual(intake.missing_context, [])
        self.assertEqual(intake.clarifying_questions, [])

    def test_first_instruction_requests_the_next_structured_local_file_proposal(self) -> None:
        intake, _plan, audit = _plan_and_audit(PIXEL_WANDERER_GOAL)
        packet = generate_instruction_packet(
            turn_number=1,
            autonomy_level="L4_HIGH_AUTONOMY_HARD_GATES",
            goal_intake=intake.to_dict(),
            plan_audit=audit.to_dict(),
            queue=[],
        )

        self.assertIn("TASK\nsoftware_build: browser local game", packet.packet_text)
        self.assertNotIn("Unresolved plan gate", packet.packet_text)
        self.assertIn("next smallest structured local file operation", packet.packet_text)
        self.assertIn("ADMISSIBLE_STRUCTURED_OPERATION", packet.packet_text)

    def test_each_explicit_constraint_resolves_only_its_matching_gate(self) -> None:
        architecture, architecture_plan, architecture_audit = _plan_and_audit(
            "Build a browser game using plain HTML/CSS/JavaScript."
        )
        self.assertEqual(architecture.architecture_choice_burden, "low")
        self.assertFalse(
            next(s for s in architecture_plan.steps if s.step_type == "choose_architecture").requires_gate
        )
        self.assertIn("step_2b_install_dependencies", architecture_audit.required_gates)
        self.assertIn("step_7_no_deploy_without_authorization", architecture_audit.required_gates)

        dependencies, _dependency_plan, dependency_audit = _plan_and_audit(
            "Build a browser game with zero dependencies and no package manager."
        )
        self.assertEqual(dependencies.explicit_dependency_preference, "zero_dependencies")
        self.assertNotIn("step_2b_install_dependencies", dependency_audit.required_gates)
        self.assertIn("step_2_choose_architecture", dependency_audit.required_gates)

        deployment, _deployment_plan, deployment_audit = _plan_and_audit(
            "Build a browser game. Keep it local-only and do not deploy or publish it."
        )
        self.assertEqual(deployment.explicit_deployment_boundary, "local_only_no_deploy")
        self.assertNotIn("step_7_no_deploy_without_authorization", deployment_audit.required_gates)
        self.assertIn("step_2_choose_architecture", deployment_audit.required_gates)

    def test_ambiguous_build_goal_still_produces_all_three_gates(self) -> None:
        intake, _plan, audit = _plan_and_audit("Build a browser game.")
        self.assertEqual(intake.task_type, "software_build")
        self.assertEqual(
            set(audit.required_gates),
            {
                "step_2_choose_architecture",
                "step_2b_install_dependencies",
                "step_7_no_deploy_without_authorization",
            },
        )

    def test_hedged_constraint_language_remains_ambiguous(self) -> None:
        intake, _plan, audit = _plan_and_audit(
            "Build a browser game, perhaps with vanilla JavaScript. Preferably use zero "
            "dependencies. It might stay local-only."
        )
        self.assertIsNone(intake.explicit_architecture_choice)
        self.assertIsNone(intake.explicit_dependency_preference)
        self.assertIsNone(intake.explicit_deployment_boundary)
        self.assertEqual(
            set(audit.required_gates),
            {
                "step_2_choose_architecture",
                "step_2b_install_dependencies",
                "step_7_no_deploy_without_authorization",
            },
        )

    def test_build_directive_wins_over_incidental_explanation_language(self) -> None:
        intake = analyze_goal(
            "Build a browser game with application files and a help panel that explains controls."
        )
        self.assertEqual(intake.task_type, "software_build")
        explanation = analyze_goal(
            "Explain how to build a browser game. Do not create or write application files."
        )
        self.assertEqual(explanation.task_type, "explanation")

    def test_control_surface_does_not_request_human_confirmation_of_explicit_constraints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            state = controller.submit_goal(PIXEL_WANDERER_GOAL)

        self.assertEqual(state["plan_audit"]["verdict"], PLAN_VERDICT_OK)
        self.assertEqual(state["needs_attention"]["unresolved_plan_gates"], [])
        self.assertEqual(state["needs_attention"]["clarifying_questions"], [])
        self.assertEqual(state["needs_attention"]["approval_needed"], [])


if __name__ == "__main__":
    unittest.main()
