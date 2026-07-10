from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger, ledger_coverage_report


def test_explicit_criteria_cannot_collapse():
    contract = build_mission_contract("Build a CLI.\n\nAcceptance criteria:\n1. A.\n2. B.\n3. C.")
    ledger = contract_acceptance_ledger(contract)
    report = ledger_coverage_report(contract.to_dict(), ledger)
    assert len(ledger) == 3
    assert report["coverage_complete"]
    assert report["represented_acceptance_criterion_count"] == 3
