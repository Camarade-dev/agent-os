from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger, evaluate_completion_eligibility, canonical_outcome_for_report


def test_static_passes_cannot_complete_unsupported_contract():
    contract = build_mission_contract("Build it.\n\nAcceptance criteria:\n1. Collision causes respawn.").to_dict()
    ledger = contract_acceptance_ledger(contract)
    ledger[0]["status"] = "verified_pass"
    report = evaluate_completion_eligibility({"acceptance_criteria": ledger}, contract)
    assert not report["eligible"]
    assert canonical_outcome_for_report(report) == "verification_capability_gap"


def test_every_failed_invariant_is_reported():
    contract = build_mission_contract("Build it.\n\nRequirements:\n- Output is TBD.").to_dict()
    report = evaluate_completion_eligibility({"acceptance_criteria": [], "active_blockers": ["x"], "pending_useful_operations": ["y"]}, contract)
    assert {"contract_incomplete", "acceptance_ledger_incomplete", "active_blocker", "pending_useful_operation"} <= set(report["failed_invariants"])
