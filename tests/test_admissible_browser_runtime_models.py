import json

from admissible.browser_runtime.models import (
    BrowserRuntimeCapabilityReport,
    BrowserRuntimeCriterionPlan,
    BrowserRuntimeEvidence,
    BrowserRuntimeVerificationPlan,
    bounded_collect,
)


def test_capability_report_round_trips():
    report = BrowserRuntimeCapabilityReport(
        provider_id="chromium_cdp",
        provider_version="1",
        available=True,
        executable_path="/usr/bin/chromium",
        executable_basename="chromium",
        browser_version="120.0.0.0",
        supported_features=["navigate"],
        unsupported_features=[],
        discovery_source="known_install_location",
        safety_policy_version="v1",
        unavailable_reason=None,
    )
    restored = BrowserRuntimeCapabilityReport.from_dict(json.loads(json.dumps(report.to_dict())))
    assert restored == report


def test_criterion_plan_round_trips():
    plan = BrowserRuntimeCriterionPlan(
        criterion_id="c1",
        disposition="deterministic_runtime",
        assertion_ids=["a1"],
        required_observables=["botCount"],
        supported=True,
        unsupported_reason=None,
        human_observation_required=False,
    )
    restored = BrowserRuntimeCriterionPlan.from_dict(json.loads(json.dumps(plan.to_dict())))
    assert restored == plan


def test_verification_plan_round_trips():
    plan = BrowserRuntimeVerificationPlan(
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
        criteria=[BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", [], [], True, None, False)],
        steps=[{"type": "navigate_local"}],
    )
    restored = BrowserRuntimeVerificationPlan.from_dict(json.loads(json.dumps(plan.to_dict())))
    assert restored.criteria[0].criterion_id == "c1"
    assert restored.steps == [{"type": "navigate_local"}]


def test_evidence_round_trips_and_is_json_serializable():
    evidence = BrowserRuntimeEvidence(
        evidence_id="e1",
        plan_sha256="abc",
        mission_contract_sha256="def",
        workspace_root=".",
        entrypoint_path="index.html",
        provider={"provider_id": "fixture"},
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        duration_ms=1000,
        termination_reason="completed",
        status="runtime_verification_pass",
    )
    payload = json.dumps(evidence.to_dict())
    restored = BrowserRuntimeEvidence.from_dict(json.loads(payload))
    assert restored.evidence_id == "e1"
    assert restored.status == "runtime_verification_pass"


def test_evidence_is_kept_as_its_own_schema_family():
    evidence = BrowserRuntimeEvidence(
        evidence_id="e1",
        plan_sha256="a",
        mission_contract_sha256="b",
        workspace_root=".",
        entrypoint_path="index.html",
        provider={},
        started_at="t",
        completed_at="t",
        duration_ms=0,
        termination_reason="completed",
    )
    data = evidence.to_dict()
    assert data["schema_version"] == "admissible_browser_runtime_evidence_v1"
    # never confused with a write/static/proposal/human evidence schema
    assert "evidence_type" not in data
    assert "source" not in data


def test_bounded_collect_is_deterministic_and_records_truncation():
    items = list(range(10))
    retained, meta = bounded_collect(items, 4)
    assert retained == [0, 1, 2, 3]
    assert meta == {"original_count": 10, "retained_count": 4, "truncated": True}

    retained_again, meta_again = bounded_collect(items, 4)
    assert retained_again == retained
    assert meta_again == meta


def test_bounded_collect_records_no_truncation_when_within_bound():
    retained, meta = bounded_collect([1, 2], 4)
    assert retained == [1, 2]
    assert meta["truncated"] is False
    assert meta["original_count"] == meta["retained_count"] == 2
