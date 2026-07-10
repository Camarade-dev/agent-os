import pytest

from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.state_machine import (
    FORBIDDEN_MISCLASSIFICATIONS,
    RUNTIME_ADMISSION_CLASS,
    RUNTIME_OBSERVABILITY_GAP,
    RUNTIME_VERIFICATION_CAPABILITY_GAP,
    RUNTIME_VERIFICATION_FAIL,
    RUNTIME_VERIFICATION_PASS,
    admission_class_for_runtime_action,
    evaluate_l4_auto_run_safety_invariants,
    next_runtime_state,
)


def _plan(**overrides):
    defaults = dict(
        plan_version="v1",
        mission_contract_sha256="abc",
        workspace_root=".",
        entrypoint_path="index.html",
        entrypoint_query="",
        target_origin_policy="loopback_only",
        debug_interface=None,
        max_duration_ms=30000,
        max_steps=10,
        max_input_events=10,
        max_snapshots=5,
        max_screenshots=2,
        max_console_entries=50,
        max_network_events=50,
        criteria=[BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)],
        steps=[{"type": "navigate_local"}],
    )
    defaults.update(overrides)
    return BrowserRuntimeVerificationPlan(**defaults)


def test_capability_gap_maps_to_capability_gap_state_never_forbidden_labels():
    state = next_runtime_state("verification_capability_gap", repair_budget_remaining=True)
    assert state == RUNTIME_VERIFICATION_CAPABILITY_GAP
    assert state not in FORBIDDEN_MISCLASSIFICATIONS


def test_runtime_capability_gap_never_becomes_internal_livelock_or_human_authority_blocker():
    for repair_budget in (True, False):
        state = next_runtime_state("verification_capability_gap", repair_budget_remaining=repair_budget)
        assert state not in ("internal_livelock", "human_authority_blocker", "completed")


def test_failure_enters_repair_needed_when_budget_remains():
    state = next_runtime_state("runtime_verification_fail", repair_budget_remaining=True)
    assert state == "repair_needed"


def test_failure_stays_failed_when_budget_exhausted():
    state = next_runtime_state("runtime_verification_fail", repair_budget_remaining=False)
    assert state == RUNTIME_VERIFICATION_FAIL


def test_observability_gap_enters_repair_only_when_instrumentation_authorized():
    assert next_runtime_state("runtime_observability_gap", repair_budget_remaining=True, instrumentation_repair_authorized=False) == RUNTIME_OBSERVABILITY_GAP
    assert next_runtime_state("runtime_observability_gap", repair_budget_remaining=True, instrumentation_repair_authorized=True) == "repair_needed"


def test_human_observation_never_auto_completes():
    state = next_runtime_state("awaiting_human_observation", repair_budget_remaining=True)
    assert state == "awaiting_human_observation"
    assert state not in FORBIDDEN_MISCLASSIFICATIONS


def test_pass_maps_to_pass_state():
    assert next_runtime_state("runtime_verification_pass", repair_budget_remaining=False) == RUNTIME_VERIFICATION_PASS


def test_unknown_status_raises_rather_than_silently_passing():
    with pytest.raises(ValueError):
        next_runtime_state("some_unmodeled_status", repair_budget_remaining=True)


def test_runtime_verification_is_not_a_shell_action_admission_class():
    assert admission_class_for_runtime_action() == RUNTIME_ADMISSION_CLASS
    assert RUNTIME_ADMISSION_CLASS != "shell"
    assert "shell" not in RUNTIME_ADMISSION_CLASS


def test_l4_safety_invariants_pass_for_a_valid_bounded_plan():
    plan = _plan()
    report = evaluate_l4_auto_run_safety_invariants(plan, {"available": True})
    assert report["safe_to_auto_run"] is True
    assert not report["violated"]


def test_l4_safety_invariants_fail_when_browser_unavailable():
    plan = _plan()
    report = evaluate_l4_auto_run_safety_invariants(plan, {"available": False})
    assert report["safe_to_auto_run"] is False
    assert "allowlisted_browser" in report["violated"]


def test_l4_safety_invariants_fail_when_entrypoint_escapes_workspace():
    plan = _plan(entrypoint_path="../outside.html")
    report = evaluate_l4_auto_run_safety_invariants(plan, {"available": True})
    assert report["safe_to_auto_run"] is False
    assert "exact_local_entrypoint" in report["violated"]


def test_l4_safety_invariants_fail_when_limits_exceed_hard_maximums():
    plan = _plan(max_duration_ms=999_999)
    report = evaluate_l4_auto_run_safety_invariants(plan, {"available": True})
    assert report["safe_to_auto_run"] is False
    assert "limits_within_hard_maximums" in report["violated"]
