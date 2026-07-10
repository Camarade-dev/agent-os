from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger, verification_plan_coverage_report


def test_unsupported_runtime_criteria_remain_visible():
    contract = build_mission_contract("Build an app.\n\nAcceptance criteria:\n1. Collision causes respawn.\n2. Camera motion is smooth.")
    ledger = contract_acceptance_ledger(contract)
    report = verification_plan_coverage_report(ledger)
    assert report["coverage_complete"]
    assert report["unsupported_criterion_ids"] == ["explicit_ac_001"]
    assert report["human_observation_criterion_ids"] == ["explicit_ac_002"]
