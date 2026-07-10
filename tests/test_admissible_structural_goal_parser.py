import json
from pathlib import Path
from admissible.mission_contract import build_mission_contract

FIXTURE = Path(__file__).parent / "fixtures/admissible/neon_serpents_cli_001_contract_regression.json"


def test_neon_structure_is_preserved_one_to_one():
    goal = json.loads(FIXTURE.read_text(encoding="utf-8"))["goal_text"]
    contract = build_mission_contract(goal)
    assert len(contract.explicit_acceptance_criteria) == 15
    assert contract.mandatory_paths == ["index.html", "style.css", "src/main.js", "src/game.js", "src/entities.js", "src/bots.js", "src/render.js", "LOCAL_DEV.md"]
    assert "At least 12" in contract.explicit_acceptance_criteria[6]["source_text"]


def test_cross_domain_structures_and_pixel_regression():
    root = Path(__file__).parent / "fixtures/admissible"
    domains = json.loads((root / "cross_domain_contract_regressions.json").read_text(encoding="utf-8"))
    assert len(build_mission_contract(domains["cli"]).explicit_acceptance_criteria) == 6
    assert len(build_mission_contract(domains["data"]).explicit_acceptance_criteria) == 4
    assert build_mission_contract(domains["data"]).mandatory_paths == []
    assert len(build_mission_contract(domains["docs"]).explicit_acceptance_criteria) == 3
    assert build_mission_contract(domains["repair"]).task_intent == "general_task"
    pixel = json.loads((root / "pixel_wanderer_cli_007_regression.json").read_text(encoding="utf-8"))["goal_text"]
    assert len(build_mission_contract(pixel).inferred_acceptance_criteria) == 8
