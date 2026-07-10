from admissible.mission_contract import build_mission_contract


def test_raw_goal_is_immutable_authority_and_hashes_are_stable():
    goal = "Build a tool.\n\nAcceptance criteria:\n1. It works."
    contract = build_mission_contract(goal, created_at="2026-01-01T00:00:00Z")
    assert contract.raw_goal == goal
    assert len(contract.raw_goal_sha256) == 64
    assert contract.contract_completeness


def test_ambiguous_requirement_is_retained():
    contract = build_mission_contract("Build a tool.\n\nRequirements:\n- Output format is TBD.")
    assert contract.mandatory_requirements[0]["source_text"] == "Output format is TBD."
    assert contract.ambiguities
    assert not contract.contract_completeness
