from admissible.mission_contract import (
    build_mission_contract,
    canonical_outcome_for_report,
    contract_acceptance_ledger,
    evaluate_completion_eligibility,
    ledger_coverage_report,
)
from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.ledger_integration import apply_runtime_evidence_to_ledger
from admissible.browser_runtime.plan_builder import build_runtime_verification_plan
from admissible.browser_runtime.runner import execute_runtime_verification_plan
from admissible.browser_runtime.state_machine import FORBIDDEN_MISCLASSIFICATIONS

GOAL = """Build a widget dashboard.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. At least 3 widgets are active on the dashboard.
2. The animation must look smooth and polished.
3. Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount.
"""

GOAL_NO_HUMAN_OBSERVATION = """Build a widget dashboard.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. At least 3 widgets are active on the dashboard.
2. Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount.
"""


def _contract_and_ledger():
    contract = build_mission_contract(GOAL).to_dict()
    ledger = contract_acceptance_ledger(contract)
    return contract, ledger


def _eligibility(contract, ledger):
    state = {"acceptance_criteria": ledger, "contract_ledger_coverage_report": ledger_coverage_report(contract, ledger)}
    return evaluate_completion_eligibility(state, contract)


def test_browser_unavailable_never_yields_completed():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({"available": False}), plan)
    apply_runtime_evidence_to_ledger(ledger, plan, result.evidence)
    report = _eligibility(contract, ledger)
    assert report["eligible"] is False
    outcome = canonical_outcome_for_report(report)
    assert outcome not in ({"completed"} | FORBIDDEN_MISCLASSIFICATIONS)
    assert outcome == "verification_capability_gap"


def test_human_observation_criterion_prevents_automatic_completion():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    scenario = {"initial_snapshot": {"widgetCount": 3}}
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    apply_runtime_evidence_to_ledger(ledger, plan, result.evidence)
    report = _eligibility(contract, ledger)
    assert report["eligible"] is False
    human_criterion = next(c for c in ledger if "smooth" in c["source_text"])
    assert human_criterion["status"] != "verified_pass"


def test_policy_violation_prevents_completion_even_if_criteria_otherwise_pass():
    contract = build_mission_contract(GOAL_NO_HUMAN_OBSERVATION).to_dict()
    ledger = contract_acceptance_ledger(contract)
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    scenario = {
        "initial_snapshot": {"widgetCount": 3},
        "external_request_attempts": [{"url": "https://example.invalid/x", "resource_type": "fetch"}],
    }
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert result.evidence.policy_violations
    apply_runtime_evidence_to_ledger(ledger, plan, result.evidence)
    assert all(item["status"] != "verified_pass" for item in ledger if item.get("runtime_policy_violation_count"))
    report = _eligibility(contract, ledger)
    assert report["eligible"] is False


def test_runtime_pass_with_no_gaps_is_eligible():
    contract = build_mission_contract(GOAL_NO_HUMAN_OBSERVATION).to_dict()
    ledger = contract_acceptance_ledger(contract)
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    scenario = {"initial_snapshot": {"widgetCount": 3}}
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    apply_runtime_evidence_to_ledger(ledger, plan, result.evidence)
    report = _eligibility(contract, ledger)
    assert report["eligible"] is True
    assert canonical_outcome_for_report(report) == "completed"


def test_existing_completion_eligibility_still_rejects_plain_contract_gaps():
    # Regression: importing admissible.browser_runtime must not change the
    # core evaluator's behavior for goals that never touch runtime at all.
    contract = build_mission_contract("Build a thing.\n\nRequirements:\n- Do something ambiguous, tbd.\n").to_dict()
    ledger = contract_acceptance_ledger(contract)
    report = _eligibility(contract, ledger)
    assert report["eligible"] is False


def test_static_disposition_criterion_cannot_be_terminally_satisfied_by_runtime_alone():
    contract, ledger = _contract_and_ledger()
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    # Without ever running the browser (no evidence applied), no runtime
    # criterion may have silently become verified_pass.
    assert all(item["status"] != "verified_pass" for item in ledger if item["verification_disposition"] == "deterministic_runtime")
