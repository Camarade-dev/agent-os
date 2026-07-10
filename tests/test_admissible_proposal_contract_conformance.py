from admissible.mission_contract import build_mission_contract, proposal_contract_conformance


def test_flat_substitute_is_misplaced_not_satisfied():
    contract = build_mission_contract("Build it.\n\nMandatory deliverables:\n- src/game.js")
    report = proposal_contract_conformance(contract.to_dict(), ["game.js"])
    assert report["missing_required_paths"] == ["src/game.js"]
    assert report["additional_paths"] == ["game.js"]
    assert report["likely_misplaced_substitutes"][0]["required_path"] == "src/game.js"
    assert not report["conformance_complete"]
