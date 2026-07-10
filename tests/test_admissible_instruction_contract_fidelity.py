from admissible.mission_contract import build_mission_contract, instruction_fidelity_report


def test_immutable_reference_exposes_full_contract():
    contract = build_mission_contract("Build it.\n\nAcceptance criteria:\n1. Works.").to_dict()
    packet = f".admissible/mission-contract.json raw {contract['raw_goal_sha256']}"
    assert instruction_fidelity_report(contract, packet)["fidelity_complete"]
