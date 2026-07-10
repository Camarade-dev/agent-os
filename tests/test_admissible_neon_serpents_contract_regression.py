import json
from pathlib import Path
from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger, evaluate_completion_eligibility, canonical_outcome_for_report, migrate_legacy_false_completion


def test_false_completed_history_repairs_to_verification_gap():
    fixture = json.loads((Path(__file__).parent / "fixtures/admissible/neon_serpents_cli_001_contract_regression.json").read_text(encoding="utf-8"))
    contract = build_mission_contract(fixture["goal_text"]).to_dict()
    ledger = contract_acceptance_ledger(contract)
    for item in ledger[:4]:
        item["status"] = "verified_pass"
    report = evaluate_completion_eligibility({"acceptance_criteria": ledger}, contract)
    assert fixture["historical_outcome"] == "completed"
    assert fixture["historical_raw_human_decisions"] == 3
    assert canonical_outcome_for_report(report) == fixture["expected_canonical_outcome"]
    assert len(report["unverified_criteria"]) == 11


def test_import_migration_preserves_history_and_repairs_outcome():
    fixture = json.loads((Path(__file__).parent / "fixtures/admissible/neon_serpents_cli_001_contract_regression.json").read_text(encoding="utf-8"))
    legacy = {"goal_intake": {"prompt": fixture["goal_text"]}, "human_decisions": [{}, {}, {}], "high_autonomy_run": {"outcome": "completed", "acceptance_criteria": [{"criterion_id": x, "status": "verified_pass"} for x in fixture["historical_derived_ledger"]]}}
    repaired = migrate_legacy_false_completion(legacy)["high_autonomy_run"]
    assert repaired["historical_outcome"] == "completed"
    assert repaired["outcome"] == "verification_capability_gap"
    assert repaired["metrics"]["raw_human_decision_count"] == 3
    assert repaired["metrics"]["genuine_human_intervention_count"] == 0
