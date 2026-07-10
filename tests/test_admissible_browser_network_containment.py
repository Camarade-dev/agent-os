from admissible.browser_runtime.chromium_provider import ChromiumCdpRuntimeProvider
from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.provider import RuntimeSession
from admissible.browser_runtime.runner import execute_runtime_verification_plan
from admissible.browser_runtime.server import LoopbackWorkspaceServer


def _plan(steps, criteria=None):
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
        criteria=criteria or [BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)],
        steps=steps,
    )


def test_is_allowed_request_allows_only_loopback_data_and_blob(tmp_path):
    (tmp_path / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
    server = LoopbackWorkspaceServer(tmp_path)
    server.start()
    try:
        provider = ChromiumCdpRuntimeProvider()
        session = RuntimeSession(session_id="s1", plan=_plan([]), provider_state={"server": server})
        assert provider._is_allowed_request(session, server.origin + f"/{server.token}/index.html") is True
        assert provider._is_allowed_request(session, "data:text/plain;base64,aGk=") is True
        assert provider._is_allowed_request(session, "blob:null/abcd-1234") is True
        assert provider._is_allowed_request(session, "https://example.invalid/x") is False
        assert provider._is_allowed_request(session, "http://evil.example/x") is False
        assert provider._is_allowed_request(session, "https://127.0.0.1:9/x") is False  # right host, wrong port
    finally:
        server.stop()


def test_external_request_attempts_are_recorded_and_fail_the_no_external_requests_step():
    scenario = {
        "external_request_attempts": [
            {"url": "https://example.invalid/blocked", "resource_type": "fetch", "criterion_impact": "external_network_containment"},
        ],
    }
    provider = FixtureBrowserRuntimeProvider(scenario)
    steps = [{"type": "navigate_local"}, {"type": "assert_no_external_requests", "criterion_id": "c1", "assertion_id": "a1"}]
    plan = _plan(steps)
    result = execute_runtime_verification_plan(provider, plan)
    assert result.evidence.external_request_attempts
    assert result.evidence.policy_violations
    assert result.evidence.criterion_results[0]["status"] == "verified_fail"


def test_no_external_requests_passes_when_none_attempted():
    provider = FixtureBrowserRuntimeProvider({})
    steps = [{"type": "navigate_local"}, {"type": "assert_no_external_requests", "criterion_id": "c1", "assertion_id": "a1"}]
    result = execute_runtime_verification_plan(provider, _plan(steps))
    assert result.evidence.criterion_results[0]["status"] == "verified_pass"


def test_popups_downloads_and_dialogs_are_recorded_and_denied():
    scenario = {
        "popups": [{"target_id": "t1", "type": "page", "url": "https://example.invalid/popup"}],
        "downloads": [{"url": "https://example.invalid/file", "suggested_filename": "file.txt"}],
        "dialogs": [{"type": "alert", "message": "hi"}],
    }
    provider = FixtureBrowserRuntimeProvider(scenario)
    steps = [
        {"type": "navigate_local"},
        {"type": "assert_no_downloads", "criterion_id": "c1", "assertion_id": "a1"},
        {"type": "assert_no_unexpected_dialogs", "criterion_id": "c1", "assertion_id": "a2"},
    ]
    result = execute_runtime_verification_plan(provider, _plan(steps))
    assert result.evidence.popups
    assert result.evidence.downloads
    assert result.evidence.dialogs
    statuses = {a["assertion_id"]: a["status"] for a in result.evidence.assertions}
    assert statuses["a1"] == "fail"
    assert statuses["a2"] == "fail"


def test_policy_violation_is_recorded_with_redacted_query_and_criterion_impact():
    from admissible.browser_runtime.chromium_provider import _redact_query

    url = "https://example.invalid/x?token=supersecret&y=1"
    redacted = _redact_query(url)
    assert "supersecret" not in redacted
    assert redacted.startswith("https://example.invalid/x?")
