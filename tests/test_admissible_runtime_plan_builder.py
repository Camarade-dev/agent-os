from admissible.mission_contract import build_mission_contract, contract_acceptance_ledger
from admissible.browser_runtime.plan_builder import build_runtime_verification_plan

GOAL = """Build a widget dashboard.

Mandatory deliverables:
- index.html
- app.js

Acceptance criteria:
1. At least 5 widgets are active on the dashboard at all times.
2. Press Z to restart; the app must not create duplicate animation loops.
3. No uncaught errors may occur.
4. Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount, loopStarts.
5. The overlay is enabled with ?debug=1.
6. The dashboard must remain playable after repeated restart cycles.
7. The animation must look smooth and polished.
8. Widgets restart and respawn after a collision-like reset event.
"""


def _build():
    contract = build_mission_contract(GOAL).to_dict()
    ledger = contract_acceptance_ledger(contract)
    return build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")


def test_every_mandatory_criterion_is_represented_never_dropped():
    plan, coverage = _build()
    ledger = contract_acceptance_ledger(build_mission_contract(GOAL).to_dict())
    assert len(plan.criteria) == len(ledger)
    represented_ids = {c.criterion_id for c in plan.criteria}
    assert represented_ids == {item["criterion_id"] for item in ledger}


def test_numeric_threshold_criterion_becomes_deterministic_runtime_with_exact_value():
    plan, _ = _build()
    by_id = {c.criterion_id: c for c in plan.criteria}
    threshold_criterion = next(c for c in plan.criteria if c.disposition == "deterministic_runtime" and any(s.get("expected") == 5 for s in plan.steps if s.get("criterion_id") == c.criterion_id))
    assert threshold_criterion.supported is True
    threshold_steps = [s for s in plan.steps if s.get("criterion_id") == threshold_criterion.criterion_id and s["type"].startswith("assert_json_path")]
    assert threshold_steps
    assert threshold_steps[0]["expected"] == 5  # the contract's exact quantity is preserved, never rounded


def test_debug_interface_and_overlay_criteria_become_deterministic_runtime():
    plan, _ = _build()
    debug_criteria = [c for c in plan.criteria if any("debug" in (s.get("assertion_id") or "") for s in plan.steps if s.get("criterion_id") == c.criterion_id)]
    assert debug_criteria
    assert all(c.disposition == "deterministic_runtime" for c in debug_criteria)


def test_restart_control_with_loop_field_becomes_bounded_repeated_sequence():
    plan, _ = _build()
    key_presses = [s for s in plan.steps if s["type"] == "key_press" and s.get("key") == "Z"]
    assert 1 <= len(key_presses) <= 3
    assert len(plan.steps) <= plan.max_steps


def test_human_observation_criterion_remains_represented_and_never_auto_passes():
    plan, coverage = _build()
    human = [c for c in plan.criteria if c.human_observation_required]
    assert human
    assert all(not c.assertion_ids for c in human)
    assert coverage["human_observation_criterion_ids"]


def test_unsupported_runtime_criteria_remain_represented_not_dropped():
    plan, coverage = _build()
    # "repeated restart cycles" (criterion 6) and "collision-like reset" (criterion 8)
    # have no declared snapshot field mapping and must remain honest gaps.
    gaps = [c for c in plan.criteria if c.disposition == "unsupported_verifier"]
    assert gaps
    assert coverage["unobservable_criterion_ids"]
    assert coverage["coverage_complete"] is False


def test_static_proxy_cannot_satisfy_a_deterministic_runtime_criterion():
    # A criterion whose disposition is already settled (e.g. deterministic_structural
    # from an explicit file-path mention) must not be reclassified as
    # deterministic_runtime just because its text also contains a runtime hint.
    goal = """Build a thing.

Mandatory deliverables:
- LOCAL_DEV.md

Acceptance criteria:
1. LOCAL_DEV.md documents the debugging interface and usage instructions.
"""
    contract = build_mission_contract(goal).to_dict()
    ledger = contract_acceptance_ledger(contract)
    assert ledger[0]["verification_disposition"] == "deterministic_structural"
    plan, _ = build_runtime_verification_plan(contract, ledger, workspace_root=".", entrypoint_path="index.html")
    assert plan.criteria[0].disposition == "deterministic_structural"
    assert plan.criteria[0].assertion_ids == []


def test_plan_generation_never_exceeds_absolute_step_ceiling():
    plan, _ = _build()
    from admissible.browser_runtime import limits

    assert plan.max_steps <= limits.ABSOLUTE_MAX_STEPS
    assert len(plan.steps) <= plan.max_steps


def test_runtime_observability_coverage_report_shape():
    _, coverage = _build()
    required_keys = {
        "runtime_criterion_count",
        "observable_criterion_count",
        "executable_runtime_criterion_count",
        "partially_observable_criterion_ids",
        "unobservable_criterion_ids",
        "missing_debug_fields",
        "missing_dom_observables",
        "missing_control_mappings",
        "human_observation_criterion_ids",
        "coverage_complete",
    }
    assert required_keys <= coverage.keys()
