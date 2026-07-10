"""RUN_043 Neon Serpents runtime-plan regression.

The goal text below is a minimized RUN_043 variant of the preserved RUN_042
Neon Serpents Mission Contract (see
tests/fixtures/admissible/neon_serpents_cli_001_contract_regression.json):
the same 15 acceptance criteria and 8 mandatory paths, with the debug
interface / overlay criteria (13-14) restated using the structural phrasing
Part F.27 calls out ("window.__NAME__", "snapshot returning at least: ...",
"?debug=1") and a restart control ("Press R to restart") added to the
existing no-duplicate-loops criterion (11), so the generic, non-game-specific
runtime pipeline has real contract-declared observables to work with. No
production code in admissible/browser_runtime names "Neon", "bot", or any
other game-specific field; this file is the only place those names appear.
"""

from admissible.mission_contract import (
    build_mission_contract,
    canonical_outcome_for_report,
    contract_acceptance_ledger,
    evaluate_completion_eligibility,
    ledger_coverage_report,
    verification_plan_coverage_report,
)
from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.ledger_integration import apply_runtime_evidence_to_ledger
from admissible.browser_runtime.plan_builder import build_runtime_verification_plan
from admissible.browser_runtime.runner import execute_runtime_verification_plan
from admissible.browser_runtime.state_machine import FORBIDDEN_MISCLASSIFICATIONS

NEON_RUN_043_GOAL = """Build a complete polished new browser game called Neon Serpents.

Architecture:
- Use plain HTML, CSS, and JavaScript, Canvas 2D, zero dependencies, and no framework.

Mandatory deliverables:
- index.html
- style.css
- src/main.js
- src/game.js
- src/entities.js
- src/bots.js
- src/render.js
- LOCAL_DEV.md

Acceptance criteria:
1. The game opens locally from index.html with no install or network access.
2. The implementation uses Canvas 2D and the required source-module architecture.
3. The arena is large, bounded, and uses a readable motion background.
4. The camera follows the player smoothly through the large world.
5. Pointer steering controls the player serpent.
6. Boost changes speed and has a visible resource tradeoff.
7. At least 12 active bots navigate the arena.
8. Collision causes death and a bounded respawn lifecycle.
9. Collectibles and growth update during play.
10. A live leaderboard updates from active entities.
11. Press R to restart; the game must not create duplicate animation loops.
12. Repeated restarts remain stable.
13. Expose a read-only debugging interface: window.__NEON__ with a snapshot returning at least: playerX, playerY, botCount, cameraX, cameraY, frameRate, paused, loopStarts.
14. The debug overlay is enabled with ?debug=1 and renders the named debug fields.
15. LOCAL_DEV.md documents local opening, controls, architecture, and debugging.

Constraints:
- Do not use shell commands, installs, package managers, network, deploy, publish, hosting, or git operations.
- Only write inside the configured workspace.
- Prefer the smallest coherent bounded batch, without narrowing the complete mission.
"""

EXPECTED_MANDATORY_PATHS = [
    "index.html",
    "style.css",
    "src/main.js",
    "src/game.js",
    "src/entities.js",
    "src/bots.js",
    "src/render.js",
    "LOCAL_DEV.md",
]


def _contract_and_ledger():
    contract = build_mission_contract(NEON_RUN_043_GOAL).to_dict()
    ledger = contract_acceptance_ledger(contract)
    return contract, ledger


def test_neon_retains_all_fifteen_criteria():
    _, ledger = _contract_and_ledger()
    assert len(ledger) == 15


def test_neon_retains_all_eight_exact_mandatory_paths():
    contract, _ = _contract_and_ledger()
    assert contract["mandatory_paths"] == EXPECTED_MANDATORY_PATHS


def test_neon_runtime_plan_uses_only_contract_derived_observables():
    contract, ledger = _contract_and_ledger()
    plan, coverage = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    assert len(plan.criteria) == 15
    # Every generated step is either untagged (run-wide health/network) or
    # tagged to one of the contract's own 15 criterion IDs -- nothing invented.
    ledger_ids = {item["criterion_id"] for item in ledger}
    for step in plan.steps:
        if "criterion_id" in step:
            assert step["criterion_id"] in ledger_ids


def test_at_least_twelve_threshold_remains_exact():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    threshold_steps = [s for s in plan.steps if s.get("type", "").startswith("assert_json_path") and s.get("expected") is not None]
    bot_threshold_steps = [s for s in threshold_steps if s.get("expected") == 12]
    assert bot_threshold_steps, "the at-least-12 bot threshold must survive into a concrete runtime assertion"


def test_debug_interface_and_overlay_criteria_are_deterministic_runtime():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    by_id = {c.criterion_id: c for c in plan.criteria}
    debug_iface_id = ledger[12]["criterion_id"]  # criterion 13
    debug_overlay_id = ledger[13]["criterion_id"]  # criterion 14
    assert by_id[debug_iface_id].disposition == "deterministic_runtime"
    assert by_id[debug_overlay_id].disposition == "deterministic_runtime"
    assert plan.debug_interface == "window.__NEON__"


def test_restart_no_duplicate_loops_criterion_is_deterministic_runtime():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    by_id = {c.criterion_id: c for c in plan.criteria}
    restart_id = ledger[10]["criterion_id"]  # criterion 11
    assert by_id[restart_id].disposition == "deterministic_runtime"


def test_subjective_polish_is_not_falsely_auto_verified():
    contract, ledger = _contract_and_ledger()
    plan, coverage = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    by_id = {c.criterion_id: c for c in plan.criteria}
    camera_id = ledger[3]["criterion_id"]  # "camera follows the player smoothly"
    background_id = ledger[2]["criterion_id"]  # "readable motion background"
    assert by_id[camera_id].human_observation_required is True
    assert by_id[background_id].human_observation_required is True
    assert coverage["human_observation_criterion_ids"]


def test_unsupported_dynamic_requirements_remain_visible_not_dropped():
    contract, ledger = _contract_and_ledger()
    plan, coverage = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    by_id = {c.criterion_id: c for c in plan.criteria}
    collision_id = ledger[7]["criterion_id"]  # collision/death/respawn
    leaderboard_id = ledger[9]["criterion_id"]  # leaderboard/active entities
    repeated_restart_id = ledger[11]["criterion_id"]  # repeated restarts remain stable
    for cid in (collision_id, leaderboard_id, repeated_restart_id):
        assert by_id[cid].disposition == "unsupported_verifier"
        assert by_id[cid].supported is False
    assert {collision_id, leaderboard_id, repeated_restart_id} <= set(coverage["unobservable_criterion_ids"])


def test_local_dev_md_documentation_criterion_stays_deterministic_structural():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    by_id = {c.criterion_id: c for c in plan.criteria}
    docs_id = ledger[14]["criterion_id"]
    assert by_id[docs_id].disposition == "deterministic_structural"


def test_external_operation_prohibition_is_present_as_a_run_wide_check():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    assert any(s["type"] == "assert_no_external_requests" for s in plan.steps)


def test_neon_replay_reaches_one_honest_result_never_false_completed():
    """The full RUN_043 replay must land on exactly one honest outcome:
    runtime pass on every objectively observable criterion while subjective
    criteria await human observation -- never a collapsed four-check pass."""

    contract, ledger = _contract_and_ledger()
    plan, coverage = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")

    scenario = {
        "initial_snapshot": {
            "playerX": 10, "playerY": 10, "botCount": 12,
            "cameraX": 0, "cameraY": 0, "frameRate": 60, "paused": False, "loopStarts": 1,
        },
    }
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    apply_runtime_evidence_to_ledger(ledger, plan, result.evidence)

    coverage_report = ledger_coverage_report(contract, ledger)
    verification_report = verification_plan_coverage_report(ledger)
    state = {"acceptance_criteria": ledger, "contract_ledger_coverage_report": coverage_report, "verification_plan_coverage_report": verification_report}
    report = evaluate_completion_eligibility(state, contract)
    outcome = canonical_outcome_for_report(report)

    # Never false-completes and never collapses into an unrelated failure
    # domain: it must land on exactly one of the two honest terminal shapes.
    assert outcome != "completed"
    assert outcome not in FORBIDDEN_MISCLASSIFICATIONS
    assert report["eligible"] is False
    # The four objectively-checkable runtime criteria (bots, restart/loop,
    # debug interface, debug overlay) must have real runtime evidence...
    executed_runtime = [item for item in ledger if item["verification_disposition"] == "deterministic_runtime"]
    assert len(executed_runtime) == 4
    assert all(item["status"] == "verified_pass" for item in executed_runtime)
    # ...while the contract is not collapsed to those four checks: all 15
    # criteria remain represented, and the subjective/gap criteria remain
    # pending rather than silently passing.
    assert len(ledger) == 15
    assert any(item["verification_disposition"] == "human_observation_required" for item in ledger)
    assert any(item["verification_disposition"] == "unsupported_verifier" for item in ledger)


def test_cli_style_regressions_are_unaffected_by_browser_runtime_import():
    # Sanity: building the RUN_043 contract and importing admissible.browser_runtime
    # must not perturb the plain RUN_042 contract-ledger/verification pipeline.
    contract, ledger = _contract_and_ledger()
    coverage = ledger_coverage_report(contract, ledger)
    assert coverage["mandatory_path_count"] == 8
    assert coverage["explicit_acceptance_criterion_count"] == 15
