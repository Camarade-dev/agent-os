"""Pure assertion-evaluation helpers shared by every runtime provider.

Kept independent of any browser transport so the same comparison logic
backs both :class:`~admissible.browser_runtime.fixture_provider.FixtureBrowserRuntimeProvider`
and :class:`~admissible.browser_runtime.chromium_provider.ChromiumCdpRuntimeProvider`.
"""

from __future__ import annotations

import re
from typing import Any

from admissible.browser_runtime import limits

_SEGMENT_PARTS_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)((?:\[[0-9]+\])*)$")


class SnapshotPathError(ValueError):
    """Raised when a JSON path cannot be resolved against a snapshot value."""


def resolve_json_path(data: Any, path: str) -> tuple[bool, Any]:
    """Resolve a strict JSON path against ``data``.

    Returns ``(present, value)``. Never raises for a missing path; returns
    ``(False, None)`` instead so callers can distinguish "absent" from
    "present but falsy".
    """

    segments = limits.json_path_segments(path)
    current = data
    for segment in segments:
        match = _SEGMENT_PARTS_RE.match(segment)
        if not match:  # pragma: no cover - already validated by json_path_segments
            return False, None
        name, index_suffix = match.group(1), match.group(2)
        indices = [int(part) for part in re.findall(r"\[([0-9]+)\]", index_suffix)]
        if not isinstance(current, dict) or name not in current:
            return False, None
        current = current[name]
        for index in indices:
            if not isinstance(current, list) or index >= len(current):
                return False, None
            current = current[index]
    return True, current


def json_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def compare_numeric(operator: str, actual: Any, expected: Any, *, low: Any = None, high: Any = None) -> bool:
    if not isinstance(actual, (int, float)) or isinstance(actual, bool):
        return False
    if operator == "gte":
        return actual >= expected
    if operator == "lte":
        return actual <= expected
    if operator == "between":
        return low <= actual <= high
    raise ValueError(f"unsupported numeric comparator: {operator!r}")


def diff_snapshot_path(mode: str, before: Any, after: Any, path: str) -> dict[str, Any]:
    """Compare one JSON path across two named snapshots.

    ``mode`` is one of changed/unchanged/increased/decreased.
    """

    before_present, before_value = resolve_json_path(before, path)
    after_present, after_value = resolve_json_path(after, path)
    result = {
        "path": path,
        "before_present": before_present,
        "after_present": after_present,
        "before_value": before_value,
        "after_value": after_value,
    }
    if not (before_present and after_present):
        result["passed"] = False
        result["reason"] = "path_missing_in_one_or_both_snapshots"
        return result

    if mode == "changed":
        result["passed"] = before_value != after_value
    elif mode == "unchanged":
        result["passed"] = before_value == after_value
    elif mode in ("increased", "decreased"):
        numeric = (
            isinstance(before_value, (int, float))
            and isinstance(after_value, (int, float))
            and not isinstance(before_value, bool)
            and not isinstance(after_value, bool)
        )
        if not numeric:
            result["passed"] = False
            result["reason"] = "path_not_numeric"
        elif mode == "increased":
            result["passed"] = after_value > before_value
        else:
            result["passed"] = after_value < before_value
    else:
        raise ValueError(f"unsupported snapshot comparison mode: {mode!r}")
    return result
