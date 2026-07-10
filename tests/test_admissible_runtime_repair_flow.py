from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.repair import (
    build_instrumentation_repair_packet,
    build_runtime_repair_instruction_text,
    build_runtime_repair_packet,
)
from admissible.browser_runtime.runner import execute_runtime_verification_plan
from admissible.browser_runtime.state_machine import next_runtime_state


def _plan(steps, criteria):
    return BrowserRuntimeVerificationPlan(
        plan_version="v1",
        mission_contract_sha256="abc",
        workspace_root=".",
        entrypoint_path="index.html",
        entrypoint_query="",
        target_origin_policy="loopback_only",
        debug_interface=None,
        max_duration_ms=30000,
        max_steps=48,
        max_input_events=100,
        max_snapshots=32,
        max_screenshots=8,
        max_console_entries=200,
        max_network_events=200,
        criteria=criteria,
        steps=steps,
    )


def test_runtime_failure_enters_repair_needed_when_budget_remains():
    steps = [
        {"type": "navigate_local"},
        {"type": "assert_selector_present", "selector": "#missing", "criterion_id": "c1", "assertion_id": "a1"},
    ]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({}), plan)
    assert result.evidence.status == "runtime_verification_fail"
    next_state = next_runtime_state(result.evidence.status, repair_budget_remaining=True)
    assert next_state == "repair_needed"

    packet = build_runtime_repair_packet(evidence=result.evidence, repair_round=1, max_repair_rounds=2)
    assert packet["failed_criteria"] == ["c1"]
    assert packet["remaining_repair_budget"] == 1
    assert packet["repair_boundaries"]["preserve_passing_artifacts"] is True
    text = build_runtime_repair_instruction_text(packet)
    assert "c1" in text


def test_runtime_pass_after_repair_completes_without_extra_repair_round():
    steps = [
        {"type": "navigate_local"},
        {"type": "assert_selector_present", "selector": "#fixed", "criterion_id": "c1", "assertion_id": "a1"},
    ]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])

    # Round 1: selector missing -> fail -> repair_needed.
    round1 = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({}), plan)
    assert next_runtime_state(round1.evidence.status, repair_budget_remaining=True) == "repair_needed"

    # Round 2: the "repair" added the missing element -> pass, no further repair.
    round2 = execute_runtime_verification_plan(
        FixtureBrowserRuntimeProvider({"initial_dom": {"#fixed": {"present": True, "visible": True, "count": 1}}}),
        plan,
    )
    assert round2.evidence.status == "runtime_verification_pass"
    assert next_runtime_state(round2.evidence.status, repair_budget_remaining=True) == "runtime_verification_pass"


def test_instrumentation_repair_is_targeted_and_read_only():
    steps = [{"type": "navigate_local"}]
    plan = _plan(
        steps,
        [BrowserRuntimeCriterionPlan("c1", "unsupported_verifier", [], ["botCount"], False, "no_safe_observable_derivable", False)],
    )
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({}), plan)
    assert result.evidence.status == "runtime_observability_gap"

    packet = build_instrumentation_repair_packet(evidence=result.evidence, debug_interface="window.__NEON__", repair_round=1, max_repair_rounds=2)
    assert packet["gap_criteria"] == ["c1"]
    assert "botCount" in packet["missing_observables"]
    forbidden_blob = " ".join(packet["forbidden_requests"])
    assert "state mutation" in forbidden_blob
    assert "cheat controls" in forbidden_blob
    assert "network access" in forbidden_blob
    assert "hidden success flags" in forbidden_blob
    text = build_runtime_repair_instruction_text(packet)
    assert "read-only" in text.lower()


def test_repair_packet_never_replays_the_full_transcript():
    steps = [{"type": "navigate_local"}] + [
        {"type": "assert_selector_present", "selector": f"#s{i}", "criterion_id": "c1", "assertion_id": f"a{i}"} for i in range(10)
    ]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", [f"a{i}" for i in range(10)], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({}), plan)
    packet = build_runtime_repair_packet(evidence=result.evidence, repair_round=1, max_repair_rounds=2)
    assert "steps" not in packet
    assert "full_transcript" not in packet
    assert len(packet["assertion_diagnostics"]) <= 10  # bounded to the actual failures, not a full log replay
