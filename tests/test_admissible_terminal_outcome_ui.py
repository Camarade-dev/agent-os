from admissible.mission_contract import canonical_outcome_for_report


def test_verification_gap_is_not_success():
    outcome = canonical_outcome_for_report({"eligible": False, "failed_invariants": ["verification_capability_gap"]})
    assert outcome == "verification_capability_gap"
    assert outcome != "completed"
