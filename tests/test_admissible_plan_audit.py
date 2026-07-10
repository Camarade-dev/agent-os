"""Tests for Plan Candidate + Plan Audit v0 (admissible.plan_audit)."""

from __future__ import annotations

import copy
import unittest

from admissible.goal_intake import GoalIntake, analyze_goal
from admissible.plan_audit import (
    PLAN_VERDICT_BLOCKED,
    PLAN_VERDICT_NEEDS_CLARIFICATION,
    PLAN_VERDICT_NEEDS_HUMAN_APPROVAL,
    PLAN_VERDICT_OK,
    PlanAudit,
    PlanCandidate,
    PlanStep,
    audit_plan,
    generate_plan_candidate,
)

SLITHER_PROMPT = (
    "Build a small browser-based Slither-like game with a moving snake, "
    "collectible food, growth, collision handling, score display, restart "
    "behavior, and simple visual polish. Keep it local-only. Do not deploy. "
    "Ask before installing dependencies or deleting existing files."
)


def _make_intake(**overrides: object) -> GoalIntake:
    base = dict(
        prompt="prompt",
        task_type="software_build",
        deliverable="a tool",
        project_maturity="existing_project",
        architecture_choice_burden="low",
        global_complexity="low",
        global_risk="low",
        risk_scope="local",
        likely_side_effect_classes=["file_edit"],
        missing_context=[],
        clarifying_questions=[],
        recommended_autonomy_ceiling="L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS",
        initial_non_execution_boundary="Do nothing destructive without authorization.",
        signals={},
    )
    base.update(overrides)
    return GoalIntake(**base)  # type: ignore[arg-type]


class TestGeneratePlanCandidate(unittest.TestCase):
    def test_slither_plan_includes_expected_step_types(self) -> None:
        intake = analyze_goal(SLITHER_PROMPT)
        plan = generate_plan_candidate(intake)
        step_types = [step.step_type for step in plan.steps]
        self.assertEqual(
            step_types,
            [
                "inspect_workspace",
                "choose_architecture",
                "install_dependencies",
                "create_minimal_files",
                "implement_core_behavior",
                "verify_locally",
                "assess_production_readiness",
                "deployment_gate",
            ],
        )

    def test_architecture_step_gated_when_burden_not_low(self) -> None:
        intake = _make_intake(architecture_choice_burden="medium")
        plan = generate_plan_candidate(intake)
        arch_step = next(s for s in plan.steps if s.step_type == "choose_architecture")
        self.assertTrue(arch_step.requires_gate)
        self.assertIsNotNone(arch_step.gate_reason)

    def test_architecture_step_not_gated_when_burden_low(self) -> None:
        intake = _make_intake(architecture_choice_burden="low")
        plan = generate_plan_candidate(intake)
        arch_step = next(s for s in plan.steps if s.step_type == "choose_architecture")
        self.assertFalse(arch_step.requires_gate)

    def test_deployment_gate_always_present_and_gated(self) -> None:
        intake = _make_intake()
        plan = generate_plan_candidate(intake)
        deploy_step = next(s for s in plan.steps if s.step_type == "deployment_gate")
        self.assertTrue(deploy_step.requires_gate)

    def test_dependency_step_omitted_when_not_a_likely_side_effect(self) -> None:
        intake = _make_intake(likely_side_effect_classes=["file_edit"])
        plan = generate_plan_candidate(intake)
        step_types = [s.step_type for s in plan.steps]
        self.assertNotIn("install_dependencies", step_types)


class TestAuditPlan(unittest.TestCase):
    def test_slither_plan_needs_clarification(self) -> None:
        intake = analyze_goal(SLITHER_PROMPT)
        plan = generate_plan_candidate(intake)
        audit = audit_plan(plan, intake)
        self.assertIsInstance(audit, PlanAudit)
        self.assertEqual(audit.verdict, PLAN_VERDICT_NEEDS_CLARIFICATION)
        self.assertTrue(audit.reasons)
        self.assertNotIn("step_7_no_deploy_without_authorization", audit.required_gates)
        self.assertIn("step_2_choose_architecture", audit.required_gates)

    def test_well_specified_plan_is_ok_for_local_prototype(self) -> None:
        intake = _make_intake(
            architecture_choice_burden="low",
            likely_side_effect_classes=["file_edit"],
            missing_context=[],
        )
        plan = generate_plan_candidate(intake)
        audit = audit_plan(plan, intake)
        self.assertEqual(audit.verdict, PLAN_VERDICT_OK)

    def test_missing_deployment_gate_is_blocked(self) -> None:
        intake = _make_intake()
        plan = generate_plan_candidate(intake)
        # Simulate an unsafe plan generator output: deployment step exists
        # but isn't gated.
        deploy_step = next(s for s in plan.steps if s.step_type == "deployment_gate")
        deploy_step.requires_gate = False
        audit = audit_plan(plan, intake)
        self.assertEqual(audit.verdict, PLAN_VERDICT_BLOCKED)
        self.assertTrue(any("deployment" in reason.lower() for reason in audit.reasons))

    def test_missing_dependency_gate_is_blocked(self) -> None:
        intake = _make_intake(likely_side_effect_classes=["file_edit", "possible_dependency_install"])
        plan = generate_plan_candidate(intake)
        # Remove the dependency-install step entirely even though the goal
        # intake says dependency installation is a likely side effect.
        plan.steps = [s for s in plan.steps if s.step_type != "install_dependencies"]
        audit = audit_plan(plan, intake)
        self.assertEqual(audit.verdict, PLAN_VERDICT_BLOCKED)
        self.assertTrue(any("dependency" in reason.lower() for reason in audit.reasons))

    def test_missing_verification_step_needs_human_approval(self) -> None:
        intake = _make_intake(architecture_choice_burden="low", likely_side_effect_classes=["file_edit"])
        plan = generate_plan_candidate(intake)
        plan.steps = [s for s in plan.steps if s.step_type != "verify_locally"]
        audit = audit_plan(plan, intake)
        self.assertEqual(audit.verdict, PLAN_VERDICT_NEEDS_HUMAN_APPROVAL)
        self.assertTrue(any("verification" in reason.lower() for reason in audit.reasons))

    def test_missing_context_forces_clarification_even_if_gates_present(self) -> None:
        intake = _make_intake(
            architecture_choice_burden="low",
            likely_side_effect_classes=["file_edit"],
            missing_context=["target deliverable format"],
        )
        plan = generate_plan_candidate(intake)
        audit = audit_plan(plan, intake)
        self.assertEqual(audit.verdict, PLAN_VERDICT_NEEDS_CLARIFICATION)

    def test_audit_does_not_mutate_the_plan(self) -> None:
        intake = analyze_goal(SLITHER_PROMPT)
        plan = generate_plan_candidate(intake)
        before = plan.to_dict()
        audit_plan(plan, intake)
        after = plan.to_dict()
        self.assertEqual(before, after)

    def test_generate_and_audit_are_independent_functions(self) -> None:
        self.assertIsNot(generate_plan_candidate, audit_plan)
        self.assertNotEqual(generate_plan_candidate.__name__, audit_plan.__name__)

    def test_no_agent_os_import(self) -> None:
        from pathlib import Path

        source = (Path(__file__).resolve().parent.parent / "admissible" / "plan_audit.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("import agent_os", source)
        self.assertNotIn("from agent_os", source)


if __name__ == "__main__":
    unittest.main()
