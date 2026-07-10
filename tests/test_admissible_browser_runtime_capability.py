import os
import stat
import sys

import pytest

from admissible.browser_runtime.chromium_provider import (
    ChromiumCdpRuntimeProvider,
    _assert_arguments_are_safe,
    build_chromium_arguments,
)
from admissible.browser_runtime.discovery import ENV_EXECUTABLE_OVERRIDE, discover_browser_executable
from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.runner import build_capability_gap_evidence, execute_runtime_verification_plan


def _minimal_plan(**overrides):
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
        criteria=[BrowserRuntimeCriterionPlan("c1", "deterministic_runtime", ["a1"], [], True, None, False)],
        steps=[{"type": "navigate_local"}],
    )
    defaults.update(overrides)
    return BrowserRuntimeVerificationPlan(**defaults)


def test_env_override_accepts_absolute_allowlisted_existing_path(tmp_path, monkeypatch):
    exe = tmp_path / "chrome.exe"
    exe.write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(exe))
    found = discover_browser_executable()
    assert found is not None
    assert found.executable_path == str(exe)
    assert found.discovery_source == "explicit_env_override"


def test_env_override_rejects_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "chrome.exe").write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, "chrome.exe")
    assert discover_browser_executable() is None


def test_env_override_rejects_disallowed_basename(tmp_path, monkeypatch):
    exe = tmp_path / "totally-not-a-browser.exe"
    exe.write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(exe))
    assert discover_browser_executable() is None


def test_env_override_rejects_nonexistent_path(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(tmp_path / "chrome.exe"))
    assert discover_browser_executable() is None


def test_fixture_provider_capability_available_and_unavailable():
    assert FixtureBrowserRuntimeProvider({"available": True}).detect_capability().available is True
    report = FixtureBrowserRuntimeProvider({"available": False, "unavailable_reason": "no_browser"}).detect_capability()
    assert report.available is False
    assert report.unavailable_reason == "no_browser"


def test_browser_unavailable_produces_capability_gap_never_a_pass():
    plan = _minimal_plan()
    provider = FixtureBrowserRuntimeProvider({"available": False})
    result = execute_runtime_verification_plan(provider, plan)
    assert result.evidence.status == "verification_capability_gap"
    assert result.evidence.termination_reason == "browser_capability_gap"
    assert all(r["status"] == "verification_capability_gap" for r in result.evidence.criterion_results)
    assert result.evidence.resource_cleanup["browser_process_terminated"] is False


def test_capability_gap_evidence_never_touches_a_session_or_server():
    plan = _minimal_plan()
    evidence = build_capability_gap_evidence(plan, {"available": False, "provider_id": "chromium_cdp"})
    assert evidence.resource_cleanup["reason"] == "browser_never_launched"
    assert evidence.duration_ms == 0


def test_chromium_arguments_never_use_shell_true_or_forbidden_flags(tmp_path):
    args = build_chromium_arguments(str(tmp_path / "chrome.exe"), str(tmp_path / "profile"))
    assert isinstance(args, list)
    assert all(isinstance(a, str) for a in args)
    joined = " ".join(args)
    assert "--no-sandbox" not in joined
    assert "--disable-web-security" not in joined
    _assert_arguments_are_safe(args)  # must not raise


def test_chromium_arguments_reject_forbidden_flags_defensively():
    with pytest.raises(RuntimeError):
        _assert_arguments_are_safe(["chrome", "--no-sandbox"])
    with pytest.raises(RuntimeError):
        _assert_arguments_are_safe(["chrome", "--disable-web-security"])


def test_chromium_provider_reports_unavailable_when_discovery_finds_nothing(monkeypatch):
    provider = ChromiumCdpRuntimeProvider()
    monkeypatch.setattr(
        "admissible.browser_runtime.chromium_provider.discover_browser_executable",
        lambda: None,
    )
    report = provider.detect_capability()
    assert report.available is False
    assert report.unavailable_reason == "no_allowlisted_browser_executable_found"
    assert report.safety_policy_version
