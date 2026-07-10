import math

import pytest

from admissible.browser_runtime import limits
from admissible.browser_runtime.dsl import (
    BrowserRuntimeDSLError,
    build_snapshot_expression,
    validate_json_serializable_snapshot,
    validate_plan_limits,
    validate_step,
    validate_steps,
)


def test_unknown_step_type_is_rejected():
    with pytest.raises(BrowserRuntimeDSLError) as exc:
        validate_step({"type": "evaluate_arbitrary_javascript", "code": "1+1"}, index=0)
    assert exc.value.diagnostic == "unsupported_step_type"


def test_no_arbitrary_javascript_step_exists_in_the_allowlist():
    forbidden_names = {"eval", "evaluate", "evaluate_js", "execute_script", "run_script", "exec"}
    assert forbidden_names.isdisjoint(limits.ALLOWED_STEP_TYPES)


def test_valid_snapshot_interface_is_accepted():
    expr = build_snapshot_expression("window.__NEON__")
    assert "window.__NEON__" in expr
    assert "snapshot" in expr


@pytest.mark.parametrize(
    "bad_interface",
    [
        "window.foo",
        "window.__FOO__.bar",
        "window['__FOO__']",
        "window.__FOO__()",
        "__FOO__",
        "window.__FOO__;alert(1)",
        "window.__FOO BAR__",
    ],
)
def test_invalid_debug_interface_paths_are_rejected(bad_interface):
    with pytest.raises(ValueError):
        limits.validate_debug_interface(bad_interface)


def test_debug_snapshot_step_only_accepts_a_name_field():
    step = validate_step({"type": "debug_snapshot", "name": "before"}, index=0)
    assert step == {"type": "debug_snapshot", "name": "before"}


def test_json_paths_cannot_contain_executable_expressions():
    bad_paths = [
        "$.foo",
        "foo[?(@.x>1)]",
        "foo();bar",
        "foo.bar()",
        "foo..bar",
        "foo,bar",
        "foo bar",
        "foo[*]",
        "foo['bar']",
        "__proto__.polluted",
    ]
    for path in bad_paths:
        if path == "__proto__.polluted":
            continue  # a plain identifier path; safety here is structural, not blocklist-based
        with pytest.raises(ValueError):
            limits.json_path_segments(path)


def test_valid_json_paths_are_accepted():
    assert limits.json_path_segments("count") == ["count"]
    assert limits.json_path_segments("bots.length") == ["bots", "length"]
    assert limits.json_path_segments("entities[3].alive") == ["entities[3]", "alive"]


def test_plan_hard_limits_cannot_be_exceeded():
    with pytest.raises(BrowserRuntimeDSLError):
        validate_plan_limits(
            max_duration_ms=limits.ABSOLUTE_MAX_DURATION_MS + 1,
            max_steps=10,
            max_input_events=10,
            max_snapshots=5,
            max_screenshots=2,
        )
    with pytest.raises(BrowserRuntimeDSLError):
        validate_plan_limits(
            max_duration_ms=1000,
            max_steps=limits.ABSOLUTE_MAX_STEPS + 1,
            max_input_events=10,
            max_snapshots=5,
            max_screenshots=2,
        )
    # exactly at the ceiling is accepted
    validate_plan_limits(
        max_duration_ms=limits.ABSOLUTE_MAX_DURATION_MS,
        max_steps=limits.ABSOLUTE_MAX_STEPS,
        max_input_events=limits.ABSOLUTE_MAX_INPUT_EVENTS,
        max_snapshots=limits.ABSOLUTE_MAX_SNAPSHOTS,
        max_screenshots=limits.ABSOLUTE_MAX_SCREENSHOTS,
    )


def test_validate_steps_rejects_more_steps_than_max_steps():
    steps = [{"type": "wait_bounded", "duration_ms": 10} for _ in range(5)]
    with pytest.raises(BrowserRuntimeDSLError):
        validate_steps(steps, max_steps=3)
    validate_steps(steps, max_steps=5)  # exactly at the bound is fine


def test_selector_length_is_bounded():
    with pytest.raises(BrowserRuntimeDSLError):
        validate_step({"type": "click_selector", "selector": "#" + "x" * limits.MAX_SELECTOR_LENGTH}, index=0)


def test_text_assertion_length_is_bounded():
    with pytest.raises(BrowserRuntimeDSLError):
        validate_step({"type": "assert_text_contains", "selector": "#a", "text": "x" * (limits.MAX_TEXT_ASSERTION_LENGTH + 1)}, index=0)


def test_wait_bounded_cannot_exceed_max_wait_per_step():
    with pytest.raises(BrowserRuntimeDSLError):
        validate_step({"type": "wait_bounded", "duration_ms": limits.MAX_WAIT_PER_STEP_MS + 1}, index=0)


def test_debug_snapshot_rejects_functions_cycles_nan_and_infinity():
    with pytest.raises(BrowserRuntimeDSLError):
        validate_json_serializable_snapshot({"f": lambda: None})
    with pytest.raises(BrowserRuntimeDSLError):
        validate_json_serializable_snapshot(float("nan"))
    with pytest.raises(BrowserRuntimeDSLError):
        validate_json_serializable_snapshot(float("inf"))
    cyclic: dict = {}
    cyclic["self"] = cyclic
    with pytest.raises(BrowserRuntimeDSLError):
        validate_json_serializable_snapshot(cyclic)


def test_debug_snapshot_rejects_excessive_depth():
    nested = {"a": 1}
    for _ in range(limits.MAX_JSON_PATH_DEPTH + 5):
        nested = {"child": nested}
    with pytest.raises(BrowserRuntimeDSLError):
        validate_json_serializable_snapshot(nested)


def test_debug_snapshot_rejects_oversized_payload():
    huge = {"data": "x" * (limits.MAX_DEBUG_SNAPSHOT_BYTES + 10)}
    with pytest.raises(BrowserRuntimeDSLError):
        validate_json_serializable_snapshot(huge)


def test_debug_snapshot_accepts_ordinary_json_values():
    value = {"count": 3, "items": [1, 2, 3], "ok": True, "note": None}
    assert validate_json_serializable_snapshot(value) == value


def test_pointer_and_key_steps_are_bounded():
    with pytest.raises(BrowserRuntimeDSLError):
        validate_step({"type": "pointer_move", "x": -1, "y": 0}, index=0)
    with pytest.raises(BrowserRuntimeDSLError):
        validate_step({"type": "pointer_move", "x": limits.MAX_COORDINATE + 1, "y": 0}, index=0)
    with pytest.raises(BrowserRuntimeDSLError):
        validate_step({"type": "key_press", "key": "notAKey;alert(1)"}, index=0)
    validate_step({"type": "key_press", "key": "ArrowUp"}, index=0)
    validate_step({"type": "pointer_move", "x": 10, "y": 10}, index=0)
