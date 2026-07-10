"""Hard limits and allowlists for bounded browser-runtime verification.

Every number in this module is a ceiling, not a default suggestion pulled
from configuration. Callers may request a smaller bound; nothing may ever
request a larger one. See PART E of
docs/admissible-bounded-browser-runtime-verification.md.
"""

from __future__ import annotations

import re

BROWSER_RUNTIME_SCHEMA_VERSION = "admissible_browser_runtime_v1"
BROWSER_RUNTIME_PLAN_VERSION = "admissible_browser_runtime_plan_v1"
SAFETY_POLICY_VERSION = "admissible_browser_runtime_safety_v1"

# --- Duration / step / event ceilings (PART E.21) ---------------------------
DEFAULT_MAX_DURATION_MS = 30_000
ABSOLUTE_MAX_DURATION_MS = 60_000
DEFAULT_MAX_STEPS = 48
ABSOLUTE_MAX_STEPS = 96
ABSOLUTE_MAX_INPUT_EVENTS = 100
ABSOLUTE_MAX_SNAPSHOTS = 32
ABSOLUTE_MAX_SCREENSHOTS = 8
MAX_SCREENSHOT_WIDTH = 1600
MAX_SCREENSHOT_HEIGHT = 1200
MAX_SCREENSHOT_ENCODED_BYTES = 2_000_000
MAX_WAIT_PER_STEP_MS = 5_000
MAX_DEBUG_SNAPSHOT_BYTES = 256 * 1024
MAX_JSON_PATH_DEPTH = 16
MAX_JSON_PATH_LENGTH = 200
MAX_SELECTOR_LENGTH = 300
MAX_TEXT_ASSERTION_LENGTH = 2_000
DEFAULT_MAX_CONSOLE_ENTRIES = 200
DEFAULT_MAX_NETWORK_EVENTS = 200
MAX_KEY_NAME_LENGTH = 24
MAX_SNAPSHOT_NAME_LENGTH = 64
MAX_COORDINATE = 20_000

# --- Declarative DSL step allowlist (PART E.19) -----------------------------
ALLOWED_STEP_TYPES = frozenset(
    {
        "navigate_local",
        "wait_for_load",
        "wait_bounded",
        "assert_selector_present",
        "assert_selector_visible",
        "assert_selector_count",
        "assert_text_contains",
        "read_dom_attribute",
        "debug_snapshot",
        "assert_json_path_present",
        "assert_json_path_type",
        "assert_json_path_equals",
        "assert_json_path_gte",
        "assert_json_path_lte",
        "assert_json_path_between",
        "compare_snapshot_path_changed",
        "compare_snapshot_path_unchanged",
        "compare_snapshot_path_increased",
        "compare_snapshot_path_decreased",
        "key_press",
        "key_down",
        "key_up",
        "pointer_move",
        "pointer_down",
        "pointer_up",
        "click_selector",
        "capture_screenshot",
        "assert_console_clean",
        "assert_no_page_exceptions",
        "assert_no_external_requests",
        "assert_no_downloads",
        "assert_no_unexpected_dialogs",
    }
)

# Step types that dispatch a real bounded input event (subject to the
# ABSOLUTE_MAX_INPUT_EVENTS ceiling independent of the step ceiling).
INPUT_EVENT_STEP_TYPES = frozenset(
    {
        "key_press",
        "key_down",
        "key_up",
        "pointer_move",
        "pointer_down",
        "pointer_up",
        "click_selector",
    }
)

ASSERTION_STEP_TYPES = frozenset(
    {
        "assert_selector_present",
        "assert_selector_visible",
        "assert_selector_count",
        "assert_text_contains",
        "assert_json_path_present",
        "assert_json_path_type",
        "assert_json_path_equals",
        "assert_json_path_gte",
        "assert_json_path_lte",
        "assert_json_path_between",
        "compare_snapshot_path_changed",
        "compare_snapshot_path_unchanged",
        "compare_snapshot_path_increased",
        "compare_snapshot_path_decreased",
        "assert_console_clean",
        "assert_no_page_exceptions",
        "assert_no_external_requests",
        "assert_no_downloads",
        "assert_no_unexpected_dialogs",
    }
)

JSON_TYPE_NAMES = frozenset({"string", "number", "boolean", "object", "array", "null"})

# --- Browser discovery allowlist (PART B.6) ---------------------------------
# The core cross-platform names called out by spec, plus the real-world
# executable basenames Chrome/Edge/Chromium actually ship under on macOS and
# Linux package managers, so discovery is genuinely useful on all three
# platforms "where practical" while remaining a small, fixed, auditable set.
ALLOWED_BROWSER_EXECUTABLE_BASENAMES = frozenset(
    {
        "chrome.exe",
        "chrome",
        "msedge.exe",
        "msedge",
        "chromium.exe",
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "microsoft-edge",
        "microsoft-edge-stable",
        "Google Chrome",
        "Microsoft Edge",
        "Chromium",
    }
)

# --- Verification disposition vocabulary (PART H.37) ------------------------
# Defined canonically in admissible.mission_contract; re-exported here so
# browser_runtime modules have one obvious place to import it from.
from admissible.mission_contract import VERIFICATION_DISPOSITIONS  # noqa: E402,F401

# --- Grammar patterns --------------------------------------------------------
# A validated debug interface path: window.__NAME__ where NAME is a bounded
# identifier. Nothing else is accepted (PART E.23).
DEBUG_INTERFACE_RE = re.compile(r"^window\.__([A-Za-z_][A-Za-z0-9_]{0,63})__$")

# One JSON-path segment: an identifier optionally followed by one or more
# bounded numeric index accessors. No filters, wildcards, or operators
# (PART E.25).
_JSON_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}(?:\[[0-9]{1,6}\]){0,8}$")

# A bounded selector: CSS selector text, length-limited only. Selectors are
# never used to build arbitrary JavaScript; they are passed as a single
# JSON-encoded string literal into one fixed query template.
_SELECTOR_FORBIDDEN_RE = re.compile(r"[`;{}]")

# A bounded key name: single printable character or a named key such as
# ArrowUp / Enter / Escape / KeyR.
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9]$|^[A-Z][A-Za-z0-9]{0,23}$")

_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def json_path_segments(path: str) -> list[str]:
    """Validate and split a strict JSON path; raise ValueError if invalid.

    Grammar: segment(.segment)* where each segment is a bounded identifier
    optionally followed by bounded numeric index accessors. No JSONPath
    filters, scripts, wildcards, or arbitrary expressions are accepted.
    """

    if not isinstance(path, str) or not path.strip():
        raise ValueError("json path must be a non-empty string")
    if len(path) > MAX_JSON_PATH_LENGTH:
        raise ValueError(f"json path exceeds max length {MAX_JSON_PATH_LENGTH}: {path!r}")
    segments = path.split(".")
    if len(segments) > MAX_JSON_PATH_DEPTH:
        raise ValueError(f"json path exceeds max depth {MAX_JSON_PATH_DEPTH}: {path!r}")
    for segment in segments:
        if not _JSON_PATH_SEGMENT_RE.match(segment):
            raise ValueError(f"json path segment is not allowed: {segment!r} in {path!r}")
    return segments


def validate_debug_interface(value: str) -> str:
    """Validate a ``window.__NAME__`` debug interface path; raise ValueError."""

    if not isinstance(value, str) or not DEBUG_INTERFACE_RE.match(value):
        raise ValueError(
            "debug_interface must match window.__NAME__ with a bounded identifier: "
            f"{value!r}"
        )
    return value


def validate_selector(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("selector must be a non-empty string")
    if len(value) > MAX_SELECTOR_LENGTH:
        raise ValueError(f"selector exceeds max length {MAX_SELECTOR_LENGTH}")
    if _SELECTOR_FORBIDDEN_RE.search(value):
        raise ValueError(f"selector contains forbidden characters: {value!r}")
    return value


def validate_key_name(value: str) -> str:
    if not isinstance(value, str) or not _KEY_NAME_RE.match(value):
        raise ValueError(f"key name is not allowed: {value!r}")
    return value


def validate_snapshot_name(value: str) -> str:
    if not isinstance(value, str) or not _SNAPSHOT_NAME_RE.match(value):
        raise ValueError(f"snapshot name is not allowed: {value!r}")
    return value
