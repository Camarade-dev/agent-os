"""Strict allowlisted declarative step schema (PART E).

There is no arbitrary-JavaScript step. Every step is a plain-data dict with
a known ``type`` and a small set of validated, bounded fields. Selectors and
JSON paths are treated as opaque, length-bounded strings -- they are never
concatenated into a JavaScript expression that a caller controls; the one
place a browser-facing expression is synthesized is
:func:`build_snapshot_expression`, which only ever substitutes a
regex-validated ``window.__NAME__`` interface path into one fixed template.
"""

from __future__ import annotations

import numbers
from typing import Any

from admissible.browser_runtime import limits


class BrowserRuntimeDSLError(ValueError):
    """Raised when a runtime verification step or plan is invalid or refused."""

    def __init__(self, message: str, *, diagnostic: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic
        self.detail: dict[str, Any] = dict(detail) if detail else {"diagnostic": diagnostic}


def _require(condition: bool, message: str, diagnostic: str, **detail: Any) -> None:
    if not condition:
        raise BrowserRuntimeDSLError(message, diagnostic=diagnostic, detail=detail)


def _optional_str(step: dict[str, Any], key: str) -> str | None:
    value = step.get(key)
    if value is None:
        return None
    _require(isinstance(value, str), f"{key} must be a string", "invalid_step_field", field=key)
    return value


def _common_fields(step: dict[str, Any]) -> dict[str, Any]:
    """Fields any step may optionally carry to map back to Mission Contract criteria."""

    out: dict[str, Any] = {}
    for key in ("criterion_id", "assertion_id", "repair_hint", "name"):
        value = _optional_str(step, key)
        if value is not None:
            out[key] = value
    return out


def _validate_selector_field(step: dict[str, Any]) -> str:
    selector = step.get("selector")
    _require(isinstance(selector, str), "selector is required", "missing_selector")
    try:
        return limits.validate_selector(selector)
    except ValueError as exc:
        raise BrowserRuntimeDSLError(str(exc), diagnostic="invalid_selector") from exc


def _validate_json_path_field(step: dict[str, Any]) -> list[str]:
    path = step.get("path")
    _require(isinstance(path, str), "path is required", "missing_json_path")
    try:
        return limits.json_path_segments(path)
    except ValueError as exc:
        raise BrowserRuntimeDSLError(str(exc), diagnostic="invalid_json_path") from exc


def _validate_snapshot_name_field(step: dict[str, Any], key: str) -> str:
    value = step.get(key)
    _require(isinstance(value, str), f"{key} is required", "missing_snapshot_name", field=key)
    try:
        return limits.validate_snapshot_name(value)
    except ValueError as exc:
        raise BrowserRuntimeDSLError(str(exc), diagnostic="invalid_snapshot_name") from exc


def _validate_scalar(value: Any) -> Any:
    """Reject non-JSON-scalar expected values (no nested objects/arrays)."""

    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, numbers.Real) and not isinstance(value, bool):
        return value
    raise BrowserRuntimeDSLError(
        f"expected value must be a JSON scalar: {value!r}",
        diagnostic="invalid_expected_value",
    )


def validate_step(step: dict[str, Any], *, index: int) -> dict[str, Any]:
    """Validate one declarative step; return a normalized copy or raise.

    Unknown step types are rejected outright (PART E.20).
    """

    _require(isinstance(step, dict), "step must be an object", "invalid_step", index=index)
    step_type = step.get("type")
    _require(isinstance(step_type, str) and bool(step_type), "step type is required", "missing_step_type", index=index)
    if step_type not in limits.ALLOWED_STEP_TYPES:
        raise BrowserRuntimeDSLError(
            f"step type is not allowlisted: {step_type!r}",
            diagnostic="unsupported_step_type",
            detail={"index": index, "type": step_type, "allowed_types": sorted(limits.ALLOWED_STEP_TYPES)},
        )

    normalized: dict[str, Any] = {"type": step_type, **_common_fields(step)}

    if step_type == "navigate_local":
        path = step.get("path")
        if path is not None:
            _require(isinstance(path, str) and ".." not in path.replace("\\", "/").split("/"), "navigate_local path must be a safe relative path", "invalid_navigate_path")
            normalized["path"] = path
        query = step.get("query")
        if query is not None:
            _require(isinstance(query, str), "query must be a string", "invalid_navigate_query")
            normalized["query"] = query

    elif step_type == "wait_for_load":
        timeout_ms = step.get("timeout_ms", limits.MAX_WAIT_PER_STEP_MS)
        _require(isinstance(timeout_ms, int) and 0 < timeout_ms <= limits.MAX_WAIT_PER_STEP_MS, "timeout_ms out of bounds", "invalid_wait_bound", max=limits.MAX_WAIT_PER_STEP_MS)
        normalized["timeout_ms"] = timeout_ms

    elif step_type == "wait_bounded":
        duration_ms = step.get("duration_ms")
        _require(isinstance(duration_ms, int) and 0 < duration_ms <= limits.MAX_WAIT_PER_STEP_MS, "duration_ms out of bounds", "invalid_wait_bound", max=limits.MAX_WAIT_PER_STEP_MS)
        normalized["duration_ms"] = duration_ms

    elif step_type in ("assert_selector_present", "assert_selector_visible", "click_selector"):
        normalized["selector"] = _validate_selector_field(step)

    elif step_type == "assert_selector_count":
        normalized["selector"] = _validate_selector_field(step)
        expected = step.get("expected")
        _require(isinstance(expected, int) and not isinstance(expected, bool) and expected >= 0, "expected count must be a non-negative integer", "invalid_expected_count")
        comparator = step.get("comparator", "equals")
        _require(comparator in ("equals", "gte", "lte"), "comparator must be one of equals/gte/lte", "invalid_comparator")
        normalized["expected"] = expected
        normalized["comparator"] = comparator

    elif step_type == "assert_text_contains":
        normalized["selector"] = _validate_selector_field(step)
        text = step.get("text")
        _require(isinstance(text, str) and text, "text is required", "missing_text_assertion")
        _require(len(text) <= limits.MAX_TEXT_ASSERTION_LENGTH, "text assertion exceeds max length", "text_assertion_too_long")
        normalized["text"] = text

    elif step_type == "read_dom_attribute":
        normalized["selector"] = _validate_selector_field(step)
        attribute = step.get("attribute")
        _require(isinstance(attribute, str) and attribute, "attribute is required", "missing_attribute")
        _require(len(attribute) <= 128, "attribute name too long", "attribute_too_long")
        normalized["attribute"] = attribute
        store_as = step.get("store_as")
        if store_as is not None:
            normalized["store_as"] = _validate_snapshot_name_field({"store_as": store_as}, "store_as")

    elif step_type == "debug_snapshot":
        normalized["name"] = _validate_snapshot_name_field(step, "name")

    elif step_type in (
        "assert_json_path_present",
        "assert_json_path_type",
        "assert_json_path_equals",
        "assert_json_path_gte",
        "assert_json_path_lte",
        "assert_json_path_between",
    ):
        normalized["snapshot"] = _validate_snapshot_name_field(step, "snapshot")
        normalized["path"] = ".".join(_validate_json_path_field(step))
        if step_type == "assert_json_path_type":
            expected_type = step.get("expected_type")
            _require(expected_type in limits.JSON_TYPE_NAMES, "expected_type must be a JSON type name", "invalid_json_type")
            normalized["expected_type"] = expected_type
        elif step_type == "assert_json_path_equals":
            normalized["expected"] = _validate_scalar(step.get("expected"))
        elif step_type in ("assert_json_path_gte", "assert_json_path_lte"):
            expected = step.get("expected")
            _require(isinstance(expected, numbers.Real) and not isinstance(expected, bool), "expected must be numeric", "invalid_numeric_expected")
            normalized["expected"] = expected
        elif step_type == "assert_json_path_between":
            low, high = step.get("min"), step.get("max")
            _require(isinstance(low, numbers.Real) and not isinstance(low, bool), "min must be numeric", "invalid_numeric_bound")
            _require(isinstance(high, numbers.Real) and not isinstance(high, bool), "max must be numeric", "invalid_numeric_bound")
            _require(low <= high, "min must be <= max", "invalid_numeric_range")
            normalized["min"] = low
            normalized["max"] = high

    elif step_type in (
        "compare_snapshot_path_changed",
        "compare_snapshot_path_unchanged",
        "compare_snapshot_path_increased",
        "compare_snapshot_path_decreased",
    ):
        normalized["before_snapshot"] = _validate_snapshot_name_field(step, "before_snapshot")
        normalized["after_snapshot"] = _validate_snapshot_name_field(step, "after_snapshot")
        normalized["path"] = ".".join(_validate_json_path_field(step))

    elif step_type in ("key_press", "key_down", "key_up"):
        key = step.get("key")
        _require(isinstance(key, str), "key is required", "missing_key")
        try:
            normalized["key"] = limits.validate_key_name(key)
        except ValueError as exc:
            raise BrowserRuntimeDSLError(str(exc), diagnostic="invalid_key_name") from exc

    elif step_type in ("pointer_move", "pointer_down", "pointer_up"):
        for axis in ("x", "y"):
            value = step.get(axis)
            _require(
                isinstance(value, numbers.Real) and not isinstance(value, bool) and 0 <= value <= limits.MAX_COORDINATE,
                f"{axis} must be a bounded non-negative number",
                "invalid_pointer_coordinate",
                axis=axis,
            )
            normalized[axis] = value
        button = step.get("button", "left")
        _require(button in ("left", "right", "middle"), "button must be left/right/middle", "invalid_pointer_button")
        normalized["button"] = button

    elif step_type == "capture_screenshot":
        pass

    elif step_type in (
        "assert_console_clean",
        "assert_no_page_exceptions",
        "assert_no_external_requests",
        "assert_no_downloads",
        "assert_no_unexpected_dialogs",
    ):
        pass

    else:  # pragma: no cover - guarded by the allowlist check above
        raise BrowserRuntimeDSLError(
            f"step type is not implemented: {step_type!r}",
            diagnostic="unsupported_step_type",
        )

    return normalized


def validate_steps(steps: list[Any], *, max_steps: int) -> list[dict[str, Any]]:
    _require(isinstance(steps, list), "steps must be a list", "invalid_steps")
    _require(len(steps) <= max_steps, f"plan exceeds max_steps={max_steps}", "too_many_steps", count=len(steps), max_steps=max_steps)
    return [validate_step(step, index=index) for index, step in enumerate(steps)]


def validate_plan_limits(
    *,
    max_duration_ms: int,
    max_steps: int,
    max_input_events: int,
    max_snapshots: int,
    max_screenshots: int,
) -> None:
    """Reject plan-level limits that exceed the absolute hard ceilings (PART E.21)."""

    _require(
        0 < max_duration_ms <= limits.ABSOLUTE_MAX_DURATION_MS,
        f"max_duration_ms exceeds absolute ceiling {limits.ABSOLUTE_MAX_DURATION_MS}",
        "duration_ceiling_exceeded",
        max_duration_ms=max_duration_ms,
    )
    _require(
        0 < max_steps <= limits.ABSOLUTE_MAX_STEPS,
        f"max_steps exceeds absolute ceiling {limits.ABSOLUTE_MAX_STEPS}",
        "steps_ceiling_exceeded",
        max_steps=max_steps,
    )
    _require(
        0 <= max_input_events <= limits.ABSOLUTE_MAX_INPUT_EVENTS,
        f"max_input_events exceeds absolute ceiling {limits.ABSOLUTE_MAX_INPUT_EVENTS}",
        "input_events_ceiling_exceeded",
        max_input_events=max_input_events,
    )
    _require(
        0 <= max_snapshots <= limits.ABSOLUTE_MAX_SNAPSHOTS,
        f"max_snapshots exceeds absolute ceiling {limits.ABSOLUTE_MAX_SNAPSHOTS}",
        "snapshots_ceiling_exceeded",
        max_snapshots=max_snapshots,
    )
    _require(
        0 <= max_screenshots <= limits.ABSOLUTE_MAX_SCREENSHOTS,
        f"max_screenshots exceeds absolute ceiling {limits.ABSOLUTE_MAX_SCREENSHOTS}",
        "screenshots_ceiling_exceeded",
        max_screenshots=max_screenshots,
    )


def count_input_events(steps: list[dict[str, Any]]) -> int:
    return sum(1 for step in steps if step.get("type") in limits.INPUT_EVENT_STEP_TYPES)


def count_snapshots(steps: list[dict[str, Any]]) -> int:
    return sum(1 for step in steps if step.get("type") == "debug_snapshot")


def count_screenshots(steps: list[dict[str, Any]]) -> int:
    return sum(1 for step in steps if step.get("type") == "capture_screenshot")


def build_snapshot_expression(debug_interface: str) -> str:
    """Return the one fixed CDP evaluation expression for a validated interface.

    ``debug_interface`` must already be a regex-validated ``window.__NAME__``
    path (PART E.23). The expression is entirely constructed here by the
    verifier; no method name, argument, operator, or property path beyond
    the validated interface is ever accepted from a plan, model, or session.
    """

    limits.validate_debug_interface(debug_interface)
    return (
        "(() => { "
        f"const iface = {debug_interface}; "
        "if (!iface || typeof iface.snapshot !== 'function') { return { __admissible_error: 'missing_snapshot_method' }; } "
        "const result = iface.snapshot(); "
        "return result === undefined ? null : result; "
        "})()"
    )


def _validate_snapshot_structure(value: Any, *, _depth: int = 0, _path: str = "$") -> Any:
    if _depth > limits.MAX_JSON_PATH_DEPTH:
        raise BrowserRuntimeDSLError(
            f"debug snapshot exceeds max depth at {_path}",
            diagnostic="snapshot_too_deep",
        )
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        import math

        if math.isnan(value) or math.isinf(value):
            raise BrowserRuntimeDSLError(
                f"debug snapshot contains NaN/Infinity at {_path}",
                diagnostic="snapshot_non_finite_number",
            )
        return value
    if isinstance(value, list):
        return [
            _validate_snapshot_structure(item, _depth=_depth + 1, _path=f"{_path}[{i}]")
            for i, item in enumerate(value)
        ]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise BrowserRuntimeDSLError(
                    f"debug snapshot has a non-string key at {_path}",
                    diagnostic="snapshot_invalid_key",
                )
            out[key] = _validate_snapshot_structure(item, _depth=_depth + 1, _path=f"{_path}.{key}")
        return out
    raise BrowserRuntimeDSLError(
        f"debug snapshot contains a non-JSON-serializable value at {_path}: {type(value).__name__}",
        diagnostic="snapshot_not_serializable",
    )


def validate_json_serializable_snapshot(value: Any, *, max_bytes: int = limits.MAX_DEBUG_SNAPSHOT_BYTES) -> Any:
    """Reject functions, cycles, NaN/Infinity, excessive depth, and oversized snapshots (PART E.24)."""

    import json

    validated = _validate_snapshot_structure(value)
    encoded_len = len(json.dumps(validated, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    if encoded_len > max_bytes:
        raise BrowserRuntimeDSLError(
            f"debug snapshot exceeds max serialized size {max_bytes} bytes (got {encoded_len})",
            diagnostic="snapshot_too_large",
            detail={"max_bytes": max_bytes, "actual_bytes": encoded_len},
        )
    return validated
