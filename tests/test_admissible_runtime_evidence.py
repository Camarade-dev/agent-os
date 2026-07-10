import hashlib

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.runner import execute_runtime_verification_plan


def _plan(steps, criteria=None, **overrides):
    defaults = dict(
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
        criteria=criteria or [],
        steps=steps,
    )
    defaults.update(overrides)
    return BrowserRuntimeVerificationPlan(**defaults)


def test_fixture_provider_produces_deterministic_evidence_across_runs():
    scenario = {"initial_snapshot": {"count": 1}}
    steps = [{"type": "navigate_local"}, {"type": "debug_snapshot", "name": "s1", "criterion_id": "c1", "assertion_id": "a1"}]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    r1 = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    r2 = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert r1.evidence.debug_snapshots[0]["value"] == r2.evidence.debug_snapshots[0]["value"] == {"count": 1}
    assert r1.evidence.status == r2.evidence.status == "runtime_verification_pass"


def test_runtime_evidence_schema_is_separate_from_other_evidence_families():
    plan = _plan([{"type": "navigate_local"}])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({}), plan)
    data = result.evidence.to_dict()
    assert data["schema_version"] == "admissible_browser_runtime_evidence_v1"
    # write/static evidence records use `evidence_type`/`actor`/`source`; runtime
    # evidence deliberately does not share that shape.
    assert "evidence_type" not in data
    assert "actor" not in data


def test_evidence_truncation_is_deterministic():
    steps = [{"type": "navigate_local"}]
    plan = _plan(steps, max_console_entries=2)
    scenario = {"console_entries": [{"level": "log", "text": str(i)} for i in range(5)]}
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert len(result.evidence.console_entries) == 2
    assert result.evidence.truncation["console_entries"] == {"original_count": 5, "retained_count": 2, "truncated": True}


def test_screenshots_are_bounded_and_hashed():
    steps = [{"type": "navigate_local"}, {"type": "capture_screenshot", "criterion_id": "c1", "assertion_id": "a1"}]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    blob = b"\x89PNG\r\n\x1a\nfakepngbytes"
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({"screenshot": {"bytes": blob, "width": 4, "height": 4}}), plan)
    shot = result.evidence.screenshots[0]
    assert shot["sha256"] == hashlib.sha256(blob).hexdigest()
    assert shot["byte_length"] == len(blob)
    assert result.screenshot_blobs[shot["screenshot_id"]] == blob


def test_screenshot_over_max_bytes_is_rejected_as_a_step_error(monkeypatch):
    from admissible.browser_runtime import limits

    steps = [{"type": "navigate_local"}, {"type": "capture_screenshot", "criterion_id": "c1", "assertion_id": "a1"}]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    oversized = b"x" * (limits.MAX_SCREENSHOT_ENCODED_BYTES + 1)
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({"screenshot": {"bytes": oversized}}), plan)
    assert result.evidence.criterion_results[0]["status"] == "runtime_error"


def test_temporal_comparison_uses_named_bounded_snapshots():
    scenario = {"initial_snapshot": {"count": 0}, "click_rules": {"#inc": {"snapshot": {"count": 1}}}}
    steps = [
        {"type": "navigate_local"},
        {"type": "debug_snapshot", "name": "before"},
        {"type": "click_selector", "selector": "#inc"},
        {"type": "debug_snapshot", "name": "after"},
        {"type": "compare_snapshot_path_increased", "before_snapshot": "before", "after_snapshot": "after", "path": "count", "criterion_id": "c1", "assertion_id": "a1"},
    ]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert result.evidence.criterion_results[0]["status"] == "verified_pass"


def test_repeated_restart_sequence_is_bounded_by_max_steps():
    steps = [{"type": "navigate_local"}]
    for i in range(3):
        steps.append({"type": "key_press", "key": "R"})
        steps.append({"type": "wait_bounded", "duration_ms": 10})
        steps.append({"type": "debug_snapshot", "name": f"restart_{i}"})
    plan = _plan(steps, max_steps=len(steps))
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider({}), plan)
    assert result.evidence.termination_reason == "completed"
    assert len(result.evidence.debug_snapshots) == 3


def test_animation_loop_growth_is_detected_as_a_failure():
    # A buggy fixture where every restart increments loopStarts (a duplicate
    # loop bug); the bounded assertion must fail, proving detection works.
    scenario = {"initial_snapshot": {"loopStarts": 1}, "key_rules": {"R": {"snapshot": {"loopStarts": 2}}}}
    steps = [
        {"type": "navigate_local"},
        {"type": "key_press", "key": "R"},
        {"type": "debug_snapshot", "name": "after_restart"},
        {"type": "assert_json_path_lte", "snapshot": "after_restart", "path": "loopStarts", "expected": 1, "criterion_id": "c1", "assertion_id": "a1"},
    ]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert result.evidence.criterion_results[0]["status"] == "verified_fail"


def test_animation_loop_stability_passes_when_bounded():
    scenario = {"initial_snapshot": {"loopStarts": 1}}  # restart never increments it (correct behavior)
    steps = [
        {"type": "navigate_local"},
        {"type": "key_press", "key": "R"},
        {"type": "debug_snapshot", "name": "after_restart"},
        {"type": "assert_json_path_lte", "snapshot": "after_restart", "path": "loopStarts", "expected": 1, "criterion_id": "c1", "assertion_id": "a1"},
    ]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert result.evidence.criterion_results[0]["status"] == "verified_pass"


def test_runtime_checks_map_back_to_exact_criterion_ids():
    steps = [
        {"type": "navigate_local"},
        {"type": "assert_selector_present", "selector": "#a", "criterion_id": "c1", "assertion_id": "a1"},
        {"type": "assert_selector_present", "selector": "#b", "criterion_id": "c2", "assertion_id": "a2"},
    ]
    plan = _plan(
        steps,
        [
            BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False),
            BrowserRuntimeCriterionPlan("c2", "deterministic_runtime", ["a2"], [], True, None, False),
        ],
    )
    scenario = {"initial_dom": {"#a": {"present": True}, "#b": {"present": False}}}
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    by_id = {r["criterion_id"]: r for r in result.evidence.criterion_results}
    assert by_id["c1"]["status"] == "verified_pass"
    assert by_id["c2"]["status"] == "verified_fail"


def test_console_errors_fail_affected_criteria():
    scenario = {"console_entries": [{"level": "error", "text": "boom"}]}
    steps = [{"type": "navigate_local"}, {"type": "assert_console_clean", "criterion_id": "c1", "assertion_id": "a1"}]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert result.evidence.criterion_results[0]["status"] == "verified_fail"


def test_page_exceptions_fail_affected_criteria():
    scenario = {"page_exceptions": [{"text": "TypeError: boom"}]}
    steps = [{"type": "navigate_local"}, {"type": "assert_no_page_exceptions", "criterion_id": "c1", "assertion_id": "a1"}]
    plan = _plan(steps, [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)])
    result = execute_runtime_verification_plan(FixtureBrowserRuntimeProvider(scenario), plan)
    assert result.evidence.criterion_results[0]["status"] == "verified_fail"
