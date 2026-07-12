"""Allowlisted local Chromium-family browser discovery (PART B.6-7).

Never downloads or installs anything. Only ever returns a path that is
absolute, exists on disk, and has a basename in the fixed allowlist. No
additional executable arguments are ever taken from the environment.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

from admissible.browser_runtime.limits import ALLOWED_BROWSER_EXECUTABLE_BASENAMES

ENV_EXECUTABLE_OVERRIDE = "ADMISSIBLE_BROWSER_EXECUTABLE"

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


class DiscoveredBrowser(NamedTuple):
    executable_path: str
    executable_basename: str
    discovery_source: str


def _candidate_locations() -> list[str]:
    system = platform.system()
    candidates: list[str] = []
    if system == "Windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local_app_data = os.environ.get("LocalAppData", "")
        candidates.extend(
            [
                rf"{program_files}\Google\Chrome\Application\chrome.exe",
                rf"{program_files_x86}\Google\Chrome\Application\chrome.exe",
                rf"{local_app_data}\Google\Chrome\Application\chrome.exe" if local_app_data else "",
                rf"{program_files}\Microsoft\Edge\Application\msedge.exe",
                rf"{program_files_x86}\Microsoft\Edge\Application\msedge.exe",
                rf"{program_files}\Chromium\Application\chromium.exe",
            ]
        )
    elif system == "Darwin":
        candidates.extend(
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                str(Path.home() / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]
        )
    else:
        candidates.extend(
            [
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/usr/bin/microsoft-edge",
                "/usr/bin/microsoft-edge-stable",
                "/snap/bin/chromium",
                "/opt/google/chrome/google-chrome",
            ]
        )
    return [c for c in candidates if c]


def _validate_explicit_path(raw_path: str) -> DiscoveredBrowser | None:
    path = Path(raw_path)
    if not path.is_absolute():
        return None
    if not path.is_file():
        return None
    if path.name not in ALLOWED_BROWSER_EXECUTABLE_BASENAMES:
        return None
    return DiscoveredBrowser(str(path), path.name, "explicit_env_override")


def discover_browser_executable() -> DiscoveredBrowser | None:
    """Return the first allowlisted, existing browser executable, if any.

    Precedence: ``ADMISSIBLE_BROWSER_EXECUTABLE`` (validated strictly), then
    known installed locations for Chrome, Edge, or Chromium.
    """

    override = os.environ.get(ENV_EXECUTABLE_OVERRIDE)
    if override:
        found = _validate_explicit_path(override)
        if found is not None:
            return found
        return None  # an invalid override is a hard miss, never silently falls back

    for candidate in _candidate_locations():
        path = Path(candidate)
        if path.is_file() and path.name in ALLOWED_BROWSER_EXECUTABLE_BASENAMES:
            return DiscoveredBrowser(str(path), path.name, "known_install_location")
    return None


def _windows_file_version(executable_path: str) -> str | None:
    """Read FileVersion straight from the PE resource block (no execution).

    Used as the Windows fallback: when a browser instance is already
    running, Chrome/Edge's single-instance forwarding means ``--version``
    activates the existing window instead of printing a version, so the
    subprocess-based path below returns nothing. Reading the on-disk
    version resource is read-only and side-effect free either way.
    """

    try:
        import ctypes

        version_dll = ctypes.windll.version
        size = version_dll.GetFileVersionInfoSizeW(executable_path, None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(executable_path, 0, size, buffer):
            return None
        value = ctypes.c_void_p()
        value_size = ctypes.c_uint()
        if not version_dll.VerQueryValueW(buffer, "\\", ctypes.byref(value), ctypes.byref(value_size)):
            return None
        fixed_info = ctypes.cast(value, ctypes.POINTER(ctypes.c_uint * 13)).contents
        # VS_FIXEDFILEINFO layout: ... dwFileVersionMS at index 2, dwFileVersionLS at index 3.
        ms, ls = fixed_info[2], fixed_info[3]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except (OSError, AttributeError, ValueError):
        return None


def detect_browser_version(executable_path: str, *, timeout: float = 10.0) -> str | None:
    """Determine the allowlisted browser's version without side effects.

    On Windows this never executes the binary: launching a Chromium-family
    executable with ``--version`` there is not reliably side-effect-free (it
    can win single-instance forwarding to an already-running instance, or
    otherwise proceed straight to a full normal launch with the user's real
    profile, GPU/renderer/network/storage processes and all) rather than
    printing a version and exiting. So on Windows, version comes only from
    the on-disk PE version resource, which is a read-only API call and never
    starts the executable; a missing/unreadable resource yields ``None``
    (diagnostic-only -- see callers) rather than falling back to executing
    the binary.

    On other platforms, ``--version`` remains one bounded, verifier-owned
    invocation of the allowlisted binary itself -- no shell, no user-supplied
    arguments; not a general process executor.
    """

    if platform.system() == "Windows":
        return _windows_file_version(executable_path)

    try:
        completed = subprocess.run(
            [executable_path, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        match = _VERSION_RE.search((completed.stdout or "") + (completed.stderr or ""))
        if match:
            return match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return None
