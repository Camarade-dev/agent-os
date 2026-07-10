from admissible.goal_intake import analyze_goal
from admissible.plan_audit import audit_plan, generate_plan_candidate


def test_zero_dependency_choice_closes_gate_without_human():
    intake = analyze_goal("Build a new CLI with zero dependencies, no framework, and no package manager.")
    audit = audit_plan(generate_plan_candidate(intake), intake)
    assert "step_2b_install_dependencies" not in audit.required_gates
    assert intake.explicit_dependency_preference == "zero_dependencies"
