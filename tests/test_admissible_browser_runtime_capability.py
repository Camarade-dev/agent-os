import os
import stat
import subprocess
import sys

import pytest

from admissible.browser_runtime import discovery
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


# --- Windows version-probe regression coverage (ADMISSIBLE_NARROW_FIX_WINDOWS_BROWSER_VERSION_PROBE) ---
#
# Root cause: detect_browser_version() used to try `subprocess.run([exe, "--version"])`
# first on every platform, including Windows, where a Chromium-family executable
# given only --version (no --headless, no isolated --user-data-dir) is not
# guaranteed to print a version and exit -- it can proceed straight to a full
# normal launch of the user's real profile. The fix makes Windows read the
# on-disk PE version resource only, and never exec the binary.


def _raise_if_called(*args, **kwargs):
    raise AssertionError(f"subprocess.run must not be called for version probing: args={args!r} kwargs={kwargs!r}")


def test_detect_browser_version_on_windows_never_calls_subprocess(tmp_path, monkeypatch):
    exe = tmp_path / "chrome.exe"
    exe.write_bytes(b"not-a-real-pe-file")
    monkeypatch.setattr(discovery.platform, "system", lambda: "Windows")
    monkeypatch.setattr(discovery.subprocess, "run", _raise_if_called)
    monkeypatch.setattr(discovery, "_windows_file_version", lambda path: "1.2.3.4")

    version = discovery.detect_browser_version(str(exe))

    assert version == "1.2.3.4"


def test_detect_browser_version_on_windows_missing_metadata_yields_none_not_a_launch(tmp_path, monkeypatch):
    exe = tmp_path / "chrome.exe"
    exe.write_bytes(b"not-a-real-pe-file")
    monkeypatch.setattr(discovery.platform, "system", lambda: "Windows")
    monkeypatch.setattr(discovery.subprocess, "run", _raise_if_called)
    monkeypatch.setattr(discovery, "_windows_file_version", lambda path: None)

    version = discovery.detect_browser_version(str(exe))

    assert version is None


def test_chrome_capability_detected_on_windows_without_executing_chrome(tmp_path, monkeypatch):
    exe = tmp_path / "chrome.exe"
    exe.write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(exe))
    monkeypatch.setattr(discovery.platform, "system", lambda: "Windows")
    monkeypatch.setattr(discovery.subprocess, "run", _raise_if_called)

    provider = ChromiumCdpRuntimeProvider()
    report = provider.detect_capability()

    assert report.available is True
    assert report.executable_basename == "chrome.exe"
    # A stub file has no real PE version resource; missing metadata must not
    # make an otherwise valid installed browser unavailable.
    assert report.browser_version is None


def test_edge_capability_detected_on_windows_without_executing_edge(tmp_path, monkeypatch):
    exe = tmp_path / "msedge.exe"
    exe.write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(exe))
    monkeypatch.setattr(discovery.platform, "system", lambda: "Windows")
    monkeypatch.setattr(discovery.subprocess, "run", _raise_if_called)

    provider = ChromiumCdpRuntimeProvider()
    report = provider.detect_capability()

    assert report.available is True
    assert report.executable_basename == "msedge.exe"
    assert report.browser_version is None


def test_non_allowlisted_executable_rejected_without_executing_it(tmp_path, monkeypatch):
    exe = tmp_path / "totally-not-a-browser.exe"
    exe.write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(exe))
    monkeypatch.setattr(discovery.subprocess, "run", _raise_if_called)

    assert discover_browser_executable() is None


def test_detect_capability_never_starts_a_process_tree(tmp_path, monkeypatch):
    exe = tmp_path / "chrome.exe"
    exe.write_bytes(b"stub")
    monkeypatch.setenv(ENV_EXECUTABLE_OVERRIDE, str(exe))
    monkeypatch.setattr(discovery.platform, "system", lambda: "Windows")
    monkeypatch.setattr(discovery.subprocess, "run", _raise_if_called)

    def _fail_if_started(self):
        raise AssertionError("ProcessTreeHandle.start must not run during capability detection")

    monkeypatch.setattr(
        "admissible.browser_runtime.chromium_provider.ProcessTreeHandle.start",
        _fail_if_started,
    )

    provider = ChromiumCdpRuntimeProvider()
    report = provider.detect_capability()

    assert report.available is True


def test_offline_admissible_suite_command_guard_blocks_version_probe_popen(monkeypatch):
    """Proves the tests/conftest.py session guard actually intercepts the
    exact defect signature (chrome.exe --version via subprocess.Popen),
    so a regression in this suite fails loudly instead of opening a browser."""

    with pytest.raises(AssertionError, match="blocked an attempt to launch a browser"):
        subprocess.Popen(["chrome.exe", "--version"])
