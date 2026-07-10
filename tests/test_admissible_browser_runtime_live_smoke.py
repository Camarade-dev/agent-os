"""Opt-in real-browser smoke test (PART P.70-71).

Marked ``browser_runtime``; runs only when an allowlisted installed
Chromium-family browser is actually detected on this machine. Uses only a
local fixture, performs no downloads, and leaves no browser process or
temporary profile behind. The full unit suite never depends on this test --
every other RUN_043 test module uses the deterministic FixtureBrowserRuntimeProvider.
"""

from pathlib import Path

import pytest

from admissible.browser_runtime.chromium_provider import ChromiumCdpRuntimeProvider
from admissible.browser_runtime.dsl import validate_steps
from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.runner import execute_runtime_verification_plan

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "admissible" / "browser_runtime" / "counter"


_CAPABILITY = ChromiumCdpRuntimeProvider().detect_capability()
_SKIP_REASON = None if _CAPABILITY.available else f"no allowlisted browser detected: {_CAPABILITY.unavailable_reason}"

pytestmark = pytest.mark.browser_runtime
_skip = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


@_skip
def test_real_browser_runs_the_counter_fixture_and_cleans_up():
    steps = validate_steps(
        [
            {"type": "navigate_local", "criterion_id": "c1", "assertion_id": "a1"},
            {"type": "wait_for_load", "criterion_id": "c1", "timeout_ms": 5000},
            # A short settle buffer in addition to the load event: on a
            # loaded/scanned CI machine a local script may still be finishing
            # execution just after the load event fires.
            {"type": "wait_bounded", "duration_ms": 1500},
            {"type": "assert_selector_present", "selector": "#count", "criterion_id": "c1", "assertion_id": "a2"},
            {"type": "debug_snapshot", "name": "before"},
            {"type": "click_selector", "selector": "#increment", "criterion_id": "c2", "assertion_id": "a3"},
            {"type": "debug_snapshot", "name": "after"},
            {
                "type": "compare_snapshot_path_increased",
                "before_snapshot": "before",
                "after_snapshot": "after",
                "path": "count",
                "criterion_id": "c2",
                "assertion_id": "a4",
            },
            {"type": "assert_no_external_requests"},
            {"type": "assert_console_clean"},
            {"type": "assert_no_page_exceptions"},
        ],
        max_steps=48,
    )
    plan = BrowserRuntimeVerificationPlan(
        plan_version="v1",
        mission_contract_sha256="abc",
        workspace_root=str(FIXTURE_ROOT),
        entrypoint_path="index.html",
        entrypoint_query="",
        target_origin_policy="loopback_only",
        debug_interface="window.__COUNTER__",
        max_duration_ms=30000,
        max_steps=48,
        max_input_events=100,
        max_snapshots=32,
        max_screenshots=8,
        max_console_entries=200,
        max_network_events=200,
        criteria=[
            BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1", "a2"], [], True, None, False),
            BrowserRuntimeCriterionPlan("c2", "deterministic_runtime", ["a3", "a4"], [], True, None, False),
        ],
        steps=steps,
    )

    provider = ChromiumCdpRuntimeProvider(headless=True)
    result = execute_runtime_verification_plan(provider, plan)
    evidence = result.evidence

    assert evidence.status == "runtime_verification_pass", evidence.to_dict()
    assert all(r["status"] == "verified_pass" for r in evidence.criterion_results)
    assert not evidence.external_request_attempts
    assert not evidence.page_exceptions

    cleanup = evidence.resource_cleanup
    assert cleanup["browser_process_terminated"] is True
    assert cleanup["http_server_stopped"] is True
    assert cleanup["temporary_profile_removed"] is True
    assert cleanup["orphan_processes"] == []


@_skip
def test_real_browser_blocks_policy_violations_before_external_effects():
    policy_root = Path(__file__).parent / "fixtures" / "admissible" / "browser_runtime" / "policy_violation"
    steps = validate_steps(
        [
            {"type": "navigate_local"},
            {"type": "wait_for_load", "timeout_ms": 5000},
            {"type": "click_selector", "selector": "#trigger"},
            {"type": "wait_bounded", "duration_ms": 500},
        ],
        max_steps=10,
    )
    plan = BrowserRuntimeVerificationPlan(
        plan_version="v1",
        mission_contract_sha256="abc",
        workspace_root=str(policy_root),
        entrypoint_path="index.html",
        entrypoint_query="",
        target_origin_policy="loopback_only",
        debug_interface=None,
        max_duration_ms=15000,
        max_steps=10,
        max_input_events=10,
        max_snapshots=4,
        max_screenshots=2,
        max_console_entries=50,
        max_network_events=50,
        criteria=[],
        steps=steps,
    )
    provider = ChromiumCdpRuntimeProvider(headless=True)
    result = execute_runtime_verification_plan(provider, plan)
    evidence = result.evidence

    assert evidence.external_request_attempts, "the blocked fetch/popup/download must be recorded"
    assert evidence.policy_violations
    assert evidence.resource_cleanup["browser_process_terminated"] is True
    assert evidence.resource_cleanup["temporary_profile_removed"] is True
