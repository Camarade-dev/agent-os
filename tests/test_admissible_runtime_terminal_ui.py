from admissible.browser_runtime.models import BrowserRuntimeEvidence
from admissible.browser_runtime.terminal_ui import (
    BANNER_AWAITING_HUMAN_OBSERVATION,
    BANNER_BROWSER_UNAVAILABLE,
    BANNER_FAILED,
    BANNER_IN_PROGRESS,
    BANNER_OBSERVABILITY_GAP,
    BANNER_RUN_COMPLETED,
    build_contract_and_verification_summary,
    build_runtime_safety_status,
    mode_stopped_is_secondary,
    select_runtime_banner,
)

ALL_BANNERS = {
    BANNER_IN_PROGRESS,
    BANNER_FAILED,
    BANNER_OBSERVABILITY_GAP,
    BANNER_BROWSER_UNAVAILABLE,
    BANNER_AWAITING_HUMAN_OBSERVATION,
    BANNER_RUN_COMPLETED,
}


def test_banners_are_mutually_exclusive_and_status_specific():
    assert select_runtime_banner("runtime_verification_fail") == BANNER_FAILED
    assert select_runtime_banner("runtime_observability_gap") == BANNER_OBSERVABILITY_GAP
    assert select_runtime_banner("verification_capability_gap") == BANNER_BROWSER_UNAVAILABLE
    assert select_runtime_banner("awaiting_human_observation") == BANNER_AWAITING_HUMAN_OBSERVATION
    assert select_runtime_banner("runtime_verifying") == BANNER_IN_PROGRESS
    assert len({select_runtime_banner(s) for s in ("runtime_verification_fail", "runtime_observability_gap", "verification_capability_gap", "awaiting_human_observation")}) == 4


def test_run_completed_banner_withheld_unless_completion_eligible():
    assert select_runtime_banner("runtime_verification_pass", completion_eligible=False) == BANNER_IN_PROGRESS
    assert select_runtime_banner("runtime_verification_pass", completion_eligible=True) == BANNER_RUN_COMPLETED


def test_no_green_completion_ui_when_a_gap_remains():
    # Even a "pass" status must never render the completed banner without
    # explicit confirmation that nothing else is pending.
    banner = select_runtime_banner("runtime_verification_pass", completion_eligible=False)
    assert banner != BANNER_RUN_COMPLETED


def test_all_banners_are_distinct_strings():
    assert len(ALL_BANNERS) == 6


def test_contract_and_verification_summary_separates_the_two_concerns():
    coverage = {
        "explicit_acceptance_criterion_count": 15,
        "represented_acceptance_criterion_count": 15,
        "mandatory_path_count": 8,
        "represented_path_count": 8,
    }
    criterion_results = (
        [{"disposition": "deterministic_structural", "status": "verified_pass"}] * 5
        + [{"disposition": "deterministic_runtime", "status": "verified_pass"}] * 7
        + [{"disposition": "deterministic_runtime", "status": "verified_fail"}] * 2
        + [{"disposition": "human_observation_required", "status": "awaiting_human_observation"}]
    )
    summary = build_contract_and_verification_summary(coverage_report=coverage, criterion_results=criterion_results)
    assert summary["contract"] == {
        "criteria_represented": 15,
        "criteria_total": 15,
        "exact_paths_represented": 8,
        "exact_paths_total": 8,
    }
    assert summary["verification"] == {
        "static_criteria_passed": 5,
        "runtime_criteria_passed": 7,
        "runtime_criteria_unverified": 2,
        "human_observation_criteria_pending": 1,
    }


def test_runtime_safety_status_shape():
    evidence = BrowserRuntimeEvidence(
        evidence_id="e1",
        plan_sha256="a",
        mission_contract_sha256="b",
        workspace_root=".",
        entrypoint_path="index.html",
        provider={"provider_id": "chromium_cdp", "browser_version": "120.0"},
        started_at="t",
        completed_at="t",
        duration_ms=1234,
        termination_reason="completed",
        console_entries=[{"level": "error"}, {"level": "log"}],
        external_request_attempts=[{"url": "x"}],
        page_exceptions=[{"text": "boom"}],
        input_events=[{"kind": "key_press"}],
        debug_snapshots=[{"name": "s1"}],
        screenshots=[{"screenshot_id": "s1"}],
        resource_cleanup={"browser_process_terminated": True},
    )
    status = build_runtime_safety_status(evidence)
    assert status["browser_provider"] == "chromium_cdp"
    assert status["external_network_attempts"] == 1
    assert status["console_errors"] == 1
    assert status["page_exceptions"] == 1
    assert status["runtime_duration_ms"] == 1234
    assert status["input_event_count"] == 1
    assert status["snapshot_count"] == 1
    assert status["screenshot_count"] == 1
    assert status["cleanup"]["browser_process_terminated"] is True


def test_mode_stopped_is_secondary_to_semantic_banner():
    labels = mode_stopped_is_secondary(BANNER_RUN_COMPLETED, "Mode: stopped")
    assert labels["primary"] == BANNER_RUN_COMPLETED
    assert labels["secondary"] == "Mode: stopped"
