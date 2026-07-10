"""Plan Candidate + Plan Audit v0 — deterministic, offline, and separate.

Two independent deterministic functions live in this module:

- `generate_plan_candidate(goal_intake)` — proposes a fixed v0 plan
  skeleton from a `GoalIntake`. It only *proposes*; it does not judge.
- `audit_plan(plan, goal_intake)` — independently audits a `PlanCandidate`
  and produces a `PlanAudit` verdict. It does not generate or rewrite the
  plan; it can only observe it.

These two functions are deliberately kept separate (not merged, not one
calling the other to "fix itself") so a plan audit failure can never be
silently smoothed over by regenerating a plan until it passes. See
docs/admissible-goal-intake-and-plan-audit.md.

Does not call Cursor, Claude Code, Codex, Gemini, or any network
provider. Does not execute anything.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from admissible.goal_intake import GoalIntake

PLAN_VERDICT_OK = "PLAN_OK_FOR_LOCAL_PROTOTYPE"
PLAN_VERDICT_NEEDS_CLARIFICATION = "PLAN_NEEDS_CLARIFICATION"
PLAN_VERDICT_NEEDS_HUMAN_APPROVAL = "PLAN_NEEDS_HUMAN_APPROVAL"
PLAN_VERDICT_BLOCKED = "PLAN_BLOCKED"

# Highest severity first, mirroring admissible.decision's precedence style:
# the strongest blocker found anywhere in the audit wins.
_VERDICT_PRECEDENCE: tuple[str, ...] = (
    PLAN_VERDICT_BLOCKED,
    PLAN_VERDICT_NEEDS_HUMAN_APPROVAL,
    PLAN_VERDICT_NEEDS_CLARIFICATION,
    PLAN_VERDICT_OK,
)


@dataclass
class PlanStep:
    """One step of a deterministic v0 plan skeleton."""

    step_id: str
    step_type: str
    description: str
    requires_gate: bool
    gate_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlanCandidate:
    """A deterministically generated, ungated proposal. Not yet audited."""

    goal_summary: str
    steps: list[PlanStep]
    assumptions: list[str]
    non_goals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_summary": self.goal_summary,
            "steps": [step.to_dict() for step in self.steps],
            "assumptions": list(self.assumptions),
            "non_goals": list(self.non_goals),
        }


@dataclass
class PlanAudit:
    """Independent audit verdict over a PlanCandidate."""

    verdict: str
    reasons: list[str]
    required_gates: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def generate_plan_candidate(goal_intake: GoalIntake) -> PlanCandidate:
    """Generate a fixed, deterministic v0 plan skeleton from a GoalIntake.

    This function only proposes a plan. It does not decide whether the
    plan is acceptable — see `audit_plan` for the independent audit.
    """
    steps: list[PlanStep] = [
        PlanStep(
            step_id="step_1_inspect_workspace",
            step_type="inspect_workspace",
            description="Inspect the current workspace/repo state before proposing changes.",
            requires_gate=False,
        )
    ]

    architecture_gate = goal_intake.architecture_choice_burden != "low"
    architecture_description = (
        f"Use the architecture explicitly selected by the goal for: {goal_intake.deliverable}."
        if goal_intake.explicit_architecture_choice
        else f"Choose an architecture/approach for: {goal_intake.deliverable}."
    )
    steps.append(
        PlanStep(
            step_id="step_2_choose_architecture",
            step_type="choose_architecture",
            description=architecture_description,
            requires_gate=architecture_gate,
            gate_reason=(
                "Architecture choice is ambiguous (no explicit framework/stack named); "
                "requires an explicit decision or human clarification before implementation."
                if architecture_gate
                else None
            ),
        )
    )

    if "possible_dependency_install" in goal_intake.likely_side_effect_classes:
        steps.append(
            PlanStep(
                step_id="step_2b_install_dependencies",
                step_type="install_dependencies",
                description="Install any dependencies required by the chosen architecture, if any.",
                requires_gate=True,
                gate_reason="Dependency installation requires explicit human approval before execution.",
            )
        )

    steps.append(
        PlanStep(
            step_id="step_3_create_minimal_files",
            step_type="create_minimal_files",
            description=f"Create the minimal files needed for {goal_intake.deliverable}.",
            requires_gate=False,
        )
    )
    steps.append(
        PlanStep(
            step_id="step_4_implement_core_behavior",
            step_type="implement_core_behavior",
            description="Implement the core behavior described in the prompt.",
            requires_gate=False,
        )
    )
    steps.append(
        PlanStep(
            step_id="step_5_verify_locally",
            step_type="verify_locally",
            description="Verify the implementation locally (manual check or local test run).",
            requires_gate=False,
        )
    )
    steps.append(
        PlanStep(
            step_id="step_6_assess_production_readiness",
            step_type="assess_production_readiness",
            description="Assess whether the result is production-ready (never assumed by default).",
            requires_gate=False,
        )
    )
    if goal_intake.explicit_deployment_boundary == "local_only_no_deploy":
        steps.append(
            PlanStep(
                step_id="step_7_local_only_boundary",
                step_type="deployment_gate",
                description=(
                    "Honor the user's explicit local-only boundary; do not deploy, publish, "
                    "host, or push."
                ),
                requires_gate=False,
            )
        )
    else:
        steps.append(
            PlanStep(
                step_id="step_7_no_deploy_without_authorization",
                step_type="deployment_gate",
                description="Do not deploy, publish, or push beyond the local workspace unless authorized.",
                requires_gate=True,
                gate_reason="Deployment/publish/push requires explicit human authorization.",
            )
        )

    assumptions = [
        "The raw prompt is treated as the full scope; unstated requirements are not assumed.",
        "No side-effecting action (dependency install, deploy, delete) proceeds without a gate.",
    ]
    if goal_intake.explicit_dependency_preference == "zero_dependencies":
        assumptions.append("The user explicitly requires zero dependencies and no package manager.")
    if goal_intake.explicit_deployment_boundary == "local_only_no_deploy":
        assumptions.append("The user explicitly requires local-only work with no deployment.")
    non_goals = [
        "This plan does not deploy, publish, or push outside the local workspace.",
        (
            "This plan does not install dependencies."
            if goal_intake.explicit_dependency_preference == "zero_dependencies"
            else "This plan does not install dependencies without explicit human approval."
        ),
    ]

    return PlanCandidate(
        goal_summary=f"{goal_intake.task_type}: {goal_intake.deliverable}",
        steps=steps,
        assumptions=assumptions,
        non_goals=non_goals,
    )


def _resolve_verdict(candidates: list[str]) -> str:
    for verdict in _VERDICT_PRECEDENCE:
        if verdict in candidates:
            return verdict
    return PLAN_VERDICT_OK


def audit_plan(plan: PlanCandidate, goal_intake: GoalIntake) -> PlanAudit:
    """Independently audit a PlanCandidate against its GoalIntake.

    Does not generate or mutate the plan; only observes it. Checks:
    architecture choices explicit/gated, dependency/install decisions
    gated, deployment/push/commit gated, verification exists, and
    whether ambiguous project constraints still require clarification.
    """
    reasons: list[str] = []
    required_gates: list[str] = []
    verdict_candidates: list[str] = []

    steps_by_type = {step.step_type: step for step in plan.steps}

    arch_step = steps_by_type.get("choose_architecture")
    if goal_intake.architecture_choice_burden in ("medium", "high"):
        if arch_step is None or not arch_step.requires_gate:
            reasons.append(
                "Architecture-choice burden is "
                f"{goal_intake.architecture_choice_burden!r} but the plan does not gate "
                "the architecture-choice step."
            )
            verdict_candidates.append(PLAN_VERDICT_BLOCKED)
        else:
            required_gates.append(arch_step.step_id)
            verdict_candidates.append(PLAN_VERDICT_NEEDS_CLARIFICATION)

    needs_dependency_gate = "possible_dependency_install" in goal_intake.likely_side_effect_classes
    dependency_step = steps_by_type.get("install_dependencies")
    if needs_dependency_gate:
        if dependency_step is None or not dependency_step.requires_gate:
            reasons.append(
                "Prompt implies possible dependency installation but the plan has no "
                "gated dependency-install step."
            )
            verdict_candidates.append(PLAN_VERDICT_BLOCKED)
        else:
            required_gates.append(dependency_step.step_id)

    deploy_step = steps_by_type.get("deployment_gate")
    deployment_is_explicitly_local = (
        goal_intake.explicit_deployment_boundary == "local_only_no_deploy"
    )
    if deployment_is_explicitly_local:
        if deploy_step is None:
            reasons.append(
                "Goal explicitly requires local-only/no-deploy behavior but the plan does not "
                "preserve that boundary."
            )
            verdict_candidates.append(PLAN_VERDICT_BLOCKED)
        elif deploy_step.requires_gate:
            reasons.append(
                "Goal already explicitly resolves the deployment boundary as local-only; the "
                "plan must not request a redundant human approval."
            )
            verdict_candidates.append(PLAN_VERDICT_BLOCKED)
    elif deploy_step is None or not deploy_step.requires_gate:
        reasons.append(
            "Plan has no explicit, gated deployment/publish/push boundary. A plan that "
            "can reach production without a human gate is unsafe by default."
        )
        verdict_candidates.append(PLAN_VERDICT_BLOCKED)
    else:
        required_gates.append(deploy_step.step_id)

    verify_step = steps_by_type.get("verify_locally")
    if verify_step is None:
        reasons.append("Plan has no local verification step before assessing readiness.")
        verdict_candidates.append(PLAN_VERDICT_NEEDS_HUMAN_APPROVAL)

    if goal_intake.missing_context:
        reasons.append(
            "Goal intake identified missing context that has not been resolved: "
            f"{goal_intake.missing_context}"
        )
        verdict_candidates.append(PLAN_VERDICT_NEEDS_CLARIFICATION)

    if not reasons:
        reasons.append(
            "Plan honors explicit goal constraints, gates any remaining ambiguous decisions, "
            "and includes local verification."
        )

    return PlanAudit(
        verdict=_resolve_verdict(verdict_candidates),
        reasons=reasons,
        required_gates=required_gates,
    )
