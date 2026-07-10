import json
from pathlib import Path
from admissible.goal_intake import analyze_goal


def test_debug_is_not_bug_and_structural_complexity_wins():
    path = Path(__file__).parent / "fixtures/admissible/neon_serpents_cli_001_contract_regression.json"
    intake = analyze_goal(json.loads(path.read_text(encoding="utf-8"))["goal_text"])
    assert intake.task_type == "software_build"
    assert intake.global_complexity == "high"
    assert intake.project_maturity == "new_project"
    assert intake.explicit_dependency_preference == "zero_dependencies"


def test_real_repair_is_bug_fix():
    assert analyze_goal("Fix the crash in this existing project.").task_type == "bug_fix"
