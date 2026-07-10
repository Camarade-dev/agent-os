"""Runtime provider abstraction (PART B.4).

``BrowserRuntimeProvider`` is the narrow, five-operation interface every
concrete provider implements: detect capability, create a session for one
validated plan, execute one validated step, collect bounded evidence, and
close the session. It is not a general executor -- there is no "run
arbitrary command" or "evaluate arbitrary expression" operation anywhere
on this interface.

``BaseBrowserRuntimeProvider`` implements ``execute_step`` once, generically,
against a small set of abstract primitives (navigate/query/click/snapshot/
screenshot/...) so the declarative-step interpretation and assertion logic
is written exactly once and shared by every concrete provider.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any

from admissible.browser_runtime import assertions, dsl, limits
from admissible.browser_runtime.models import BrowserRuntimeVerificationPlan, new_id, now_iso


@dataclass
class RuntimeSession:
    """Bookkeeping shared by every concrete provider's session."""

    session_id: str
    plan: BrowserRuntimeVerificationPlan
    provider_state: Any = None
    started_at: str = field(default_factory=now_iso)
    start_perf: float = field(default_factory=time.perf_counter)
    page_load: dict[str, Any] = field(default_factory=dict)
    console_entries: list[dict[str, Any]] = field(default_factory=list)
    page_exceptions: list[dict[str, Any]] = field(default_factory=list)
    network_events: list[dict[str, Any]] = field(default_factory=list)
    external_request_attempts: list[dict[str, Any]] = field(default_factory=list)
    dialogs: list[dict[str, Any]] = field(default_factory=list)
    popups: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    dom_observations: list[dict[str, Any]] = field(default_factory=list)
    debug_snapshots: list[dict[str, Any]] = field(default_factory=list)
    input_events: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    screenshot_blobs: dict[str, bytes] = field(default_factory=dict)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    policy_violations: list[dict[str, Any]] = field(default_factory=list)
    snapshots: dict[str, Any] = field(default_factory=dict)
    input_event_count: int = 0
    snapshot_count: int = 0
    screenshot_count: int = 0
    step_count: int = 0
    terminated: bool = False
    termination_reason: str = ""
    truncated_categories: set[str] = field(default_factory=set)
    dropped_counts: dict[str, int] = field(default_factory=dict)

    def elapsed_ms(self) -> int:
        return int((time.perf_counter() - self.start_perf) * 1000)

    def remaining_ms(self) -> int:
        return max(0, self.plan.max_duration_ms - self.elapsed_ms())

    def original_count(self, attr: str) -> int:
        """Items actually recorded for ``attr``, including any dropped past its bound."""

        return len(getattr(self, attr)) + self.dropped_counts.get(attr, 0)

    def _append_bounded(self, attr: str, entry: dict[str, Any], max_len: int) -> bool:
        items: list[dict[str, Any]] = getattr(self, attr)
        if len(items) >= max_len:
            self.truncated_categories.add(attr)
            self.dropped_counts[attr] = self.dropped_counts.get(attr, 0) + 1
            return False
        items.append(entry)
        return True

    def record_console(self, entry: dict[str, Any]) -> None:
        self._append_bounded("console_entries", entry, self.plan.max_console_entries)

    def record_network(self, entry: dict[str, Any]) -> None:
        self._append_bounded("network_events", entry, self.plan.max_network_events)

    def record_external_attempt(self, entry: dict[str, Any]) -> None:
        self._append_bounded("external_request_attempts", entry, self.plan.max_network_events)
        self.policy_violations.append(
            {
                "kind": "external_request_blocked",
                "detail": entry,
                "timestamp": entry.get("timestamp") or now_iso(),
            }
        )


class BrowserRuntimeProvider(abc.ABC):
    """The five bounded operations a runtime provider may perform."""

    provider_id: str = "abstract"
    provider_version: str = "0"

    @abc.abstractmethod
    def detect_capability(self):
        """Return a BrowserRuntimeCapabilityReport."""

    @abc.abstractmethod
    def create_session(self, plan: BrowserRuntimeVerificationPlan) -> RuntimeSession:
        """Start one bounded verification session for a validated plan."""

    @abc.abstractmethod
    def execute_step(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        """Execute one validated declarative step; return a step-result dict."""

    @abc.abstractmethod
    def collect_evidence(self, session: RuntimeSession) -> dict[str, Any]:
        """Return the accumulated bounded evidence for this session."""

    @abc.abstractmethod
    def close_session(self, session: RuntimeSession) -> dict[str, Any]:
        """Terminate the session and return a resource_cleanup report."""


def _step_result(
    step: dict[str, Any],
    *,
    status: str,
    observed: Any = None,
    expected: Any = None,
    message: str = "",
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "assertion_id": step.get("assertion_id") or f"{step['type']}_{id(step) & 0xFFFF:04x}",
        "criterion_id": step.get("criterion_id"),
        "step_type": step["type"],
        "status": status,
        "observed_value": observed,
        "expected_relation": expected,
        "message": message,
        "evidence_refs": list(evidence_refs or []),
        "repair_hint": step.get("repair_hint") if status in ("fail", "error", "unsupported") else None,
        "timestamp": now_iso(),
    }


class BaseBrowserRuntimeProvider(BrowserRuntimeProvider):
    """Implements the declarative-step interpreter once for all providers.

    Subclasses implement the small "do the real thing" primitives; this
    class implements the DSL semantics, bounds enforcement, and assertion
    logic identically for every provider.
    """

    # --- primitives concrete providers must implement -----------------
    def _do_navigate(self, session: RuntimeSession, path: str, query: str) -> dict[str, Any]:
        raise NotImplementedError

    def _do_wait(self, session: RuntimeSession, duration_ms: int) -> None:
        raise NotImplementedError

    def _do_wait_for_load(self, session: RuntimeSession, timeout_ms: int) -> bool:
        raise NotImplementedError

    def _do_query_selector(self, session: RuntimeSession, selector: str) -> dict[str, Any]:
        """Return {"present": bool, "visible": bool, "count": int, "text": str|None}."""
        raise NotImplementedError

    def _do_click(self, session: RuntimeSession, selector: str) -> bool:
        raise NotImplementedError

    def _do_key_event(self, session: RuntimeSession, action: str, key: str) -> bool:
        raise NotImplementedError

    def _do_pointer_event(self, session: RuntimeSession, action: str, x: float, y: float, button: str) -> bool:
        raise NotImplementedError

    def _do_read_dom_attribute(self, session: RuntimeSession, selector: str, attribute: str) -> str | None:
        raise NotImplementedError

    def _do_debug_snapshot(self, session: RuntimeSession) -> Any:
        raise NotImplementedError

    def _do_screenshot(self, session: RuntimeSession) -> dict[str, Any]:
        """Return {"bytes": b"...", "width": int, "height": int}."""
        raise NotImplementedError

    def _pump_events(self, session: RuntimeSession) -> None:
        """Drain any pending browser events (console/network/dialogs/...) into the session."""

    # --- generic step interpreter ---------------------------------------
    def execute_step(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        self._pump_events(session)
        session.step_count += 1
        step_type = step["type"]

        if step_type in limits.INPUT_EVENT_STEP_TYPES:
            if session.input_event_count >= session.plan.max_input_events:
                result = _step_result(step, status="error", message="max_input_events exceeded")
                session.assertions.append(result)
                return result

        handler = getattr(self, f"_handle_{step_type}", None)
        if handler is None:  # pragma: no cover - guarded by dsl.validate_step
            result = _step_result(step, status="error", message=f"no handler for {step_type}")
            session.assertions.append(result)
            return result

        try:
            result = handler(session, step)
        except Exception as exc:  # noqa: BLE001 - surfaced as a bounded step error, never raised
            result = _step_result(step, status="error", message=f"{type(exc).__name__}: {exc}")
        self._pump_events(session)
        if step_type in limits.ASSERTION_STEP_TYPES or result.get("status") in ("pass", "fail", "error"):
            session.assertions.append(result)
        return result

    # --- individual step handlers ---------------------------------------
    def _handle_navigate_local(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        path = step.get("path") or session.plan.entrypoint_path
        query = step.get("query", session.plan.entrypoint_query)
        result = self._do_navigate(session, path, query)
        session.page_load = result
        status = "pass" if result.get("ok") else "fail"
        return _step_result(step, status=status, observed=result, message=result.get("message", ""))

    def _handle_wait_for_load(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        timeout_ms = step.get("timeout_ms", limits.MAX_WAIT_PER_STEP_MS)
        ok = self._do_wait_for_load(session, timeout_ms)
        return _step_result(step, status="pass" if ok else "fail", observed={"loaded": ok})

    def _handle_wait_bounded(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        self._do_wait(session, step["duration_ms"])
        return _step_result(step, status="pass", observed={"waited_ms": step["duration_ms"]})

    def _handle_assert_selector_present(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        state = self._do_query_selector(session, step["selector"])
        session.dom_observations.append({"selector": step["selector"], "observation": "present", **state, "timestamp": now_iso()})
        return _step_result(step, status="pass" if state.get("present") else "fail", observed=state, expected={"present": True})

    def _handle_assert_selector_visible(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        state = self._do_query_selector(session, step["selector"])
        session.dom_observations.append({"selector": step["selector"], "observation": "visible", **state, "timestamp": now_iso()})
        return _step_result(step, status="pass" if state.get("visible") else "fail", observed=state, expected={"visible": True})

    def _handle_assert_selector_count(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        state = self._do_query_selector(session, step["selector"])
        count = int(state.get("count") or 0)
        comparator, expected = step["comparator"], step["expected"]
        passed = {"equals": count == expected, "gte": count >= expected, "lte": count <= expected}[comparator]
        session.dom_observations.append({"selector": step["selector"], "observation": "count", "count": count, "timestamp": now_iso()})
        return _step_result(step, status="pass" if passed else "fail", observed={"count": count}, expected={"comparator": comparator, "value": expected})

    def _handle_assert_text_contains(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        state = self._do_query_selector(session, step["selector"])
        text = state.get("text") or ""
        passed = step["text"] in text
        session.dom_observations.append({"selector": step["selector"], "observation": "text", "text": text, "timestamp": now_iso()})
        return _step_result(step, status="pass" if passed else "fail", observed={"text": text}, expected={"contains": step["text"]})

    def _handle_read_dom_attribute(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        value = self._do_read_dom_attribute(session, step["selector"], step["attribute"])
        session.dom_observations.append({"selector": step["selector"], "attribute": step["attribute"], "value": value, "store_as": step.get("store_as"), "timestamp": now_iso()})
        return _step_result(step, status="pass" if value is not None else "fail", observed={"value": value})

    def _handle_debug_snapshot(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        if session.snapshot_count >= session.plan.max_snapshots:
            return _step_result(step, status="error", message="max_snapshots exceeded")
        raw = self._do_debug_snapshot(session)
        try:
            validated = dsl.validate_json_serializable_snapshot(raw)
        except dsl.BrowserRuntimeDSLError as exc:
            return _step_result(step, status="error", message=str(exc))
        name = step["name"]
        session.snapshots[name] = validated
        session.snapshot_count += 1
        import json as _json

        size = len(_json.dumps(validated, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        session.debug_snapshots.append({"name": name, "value": validated, "byte_length": size, "timestamp": now_iso()})
        return _step_result(step, status="pass", observed={"name": name, "byte_length": size})

    def _snapshot_json_assertion(self, session: RuntimeSession, step: dict[str, Any], *, present_only: bool = False) -> tuple[bool, bool, Any]:
        snapshot = session.snapshots.get(step["snapshot"])
        if snapshot is None and step["snapshot"] not in session.snapshots:
            return False, False, None
        present, value = assertions.resolve_json_path(snapshot, step["path"])
        return True, present, value

    def _handle_assert_json_path_present(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        have_snapshot, present, value = self._snapshot_json_assertion(session, step)
        if not have_snapshot:
            return _step_result(step, status="error", message=f"unknown snapshot: {step['snapshot']!r}")
        return _step_result(step, status="pass" if present else "fail", observed={"present": present, "value": value})

    def _handle_assert_json_path_type(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        have_snapshot, present, value = self._snapshot_json_assertion(session, step)
        if not have_snapshot:
            return _step_result(step, status="error", message=f"unknown snapshot: {step['snapshot']!r}")
        if not present:
            return _step_result(step, status="fail", observed={"present": False}, expected={"type": step["expected_type"]})
        actual_type = assertions.json_type_name(value)
        return _step_result(step, status="pass" if actual_type == step["expected_type"] else "fail", observed={"type": actual_type, "value": value}, expected={"type": step["expected_type"]})

    def _handle_assert_json_path_equals(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        have_snapshot, present, value = self._snapshot_json_assertion(session, step)
        if not have_snapshot:
            return _step_result(step, status="error", message=f"unknown snapshot: {step['snapshot']!r}")
        passed = present and value == step["expected"]
        return _step_result(step, status="pass" if passed else "fail", observed={"value": value}, expected={"equals": step["expected"]})

    def _handle_assert_json_path_gte(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        have_snapshot, present, value = self._snapshot_json_assertion(session, step)
        if not have_snapshot:
            return _step_result(step, status="error", message=f"unknown snapshot: {step['snapshot']!r}")
        passed = present and assertions.compare_numeric("gte", value, step["expected"])
        return _step_result(step, status="pass" if passed else "fail", observed={"value": value}, expected={"gte": step["expected"]})

    def _handle_assert_json_path_lte(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        have_snapshot, present, value = self._snapshot_json_assertion(session, step)
        if not have_snapshot:
            return _step_result(step, status="error", message=f"unknown snapshot: {step['snapshot']!r}")
        passed = present and assertions.compare_numeric("lte", value, step["expected"])
        return _step_result(step, status="pass" if passed else "fail", observed={"value": value}, expected={"lte": step["expected"]})

    def _handle_assert_json_path_between(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        have_snapshot, present, value = self._snapshot_json_assertion(session, step)
        if not have_snapshot:
            return _step_result(step, status="error", message=f"unknown snapshot: {step['snapshot']!r}")
        passed = present and assertions.compare_numeric("between", value, None, low=step["min"], high=step["max"])
        return _step_result(step, status="pass" if passed else "fail", observed={"value": value}, expected={"between": [step["min"], step["max"]]})

    def _compare_snapshots(self, session: RuntimeSession, step: dict[str, Any], mode: str) -> dict[str, Any]:
        before_name, after_name = step["before_snapshot"], step["after_snapshot"]
        if before_name not in session.snapshots or after_name not in session.snapshots:
            return _step_result(step, status="error", message="unknown before/after snapshot name")
        diff = assertions.diff_snapshot_path(mode, session.snapshots[before_name], session.snapshots[after_name], step["path"])
        return _step_result(step, status="pass" if diff.get("passed") else "fail", observed=diff)

    def _handle_compare_snapshot_path_changed(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return self._compare_snapshots(session, step, "changed")

    def _handle_compare_snapshot_path_unchanged(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return self._compare_snapshots(session, step, "unchanged")

    def _handle_compare_snapshot_path_increased(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return self._compare_snapshots(session, step, "increased")

    def _handle_compare_snapshot_path_decreased(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return self._compare_snapshots(session, step, "decreased")

    def _record_input_event(self, session: RuntimeSession, kind: str, detail: dict[str, Any]) -> None:
        session.input_event_count += 1
        session.input_events.append({"kind": kind, **detail, "timestamp": now_iso()})

    def _handle_key_press(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok_down = self._do_key_event(session, "down", step["key"])
        ok_up = self._do_key_event(session, "up", step["key"])
        self._record_input_event(session, "key_press", {"key": step["key"]})
        return _step_result(step, status="pass" if (ok_down and ok_up) else "fail", observed={"key": step["key"]})

    def _handle_key_down(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok = self._do_key_event(session, "down", step["key"])
        self._record_input_event(session, "key_down", {"key": step["key"]})
        return _step_result(step, status="pass" if ok else "fail", observed={"key": step["key"]})

    def _handle_key_up(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok = self._do_key_event(session, "up", step["key"])
        self._record_input_event(session, "key_up", {"key": step["key"]})
        return _step_result(step, status="pass" if ok else "fail", observed={"key": step["key"]})

    def _handle_pointer_move(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok = self._do_pointer_event(session, "move", step["x"], step["y"], step.get("button", "left"))
        self._record_input_event(session, "pointer_move", {"x": step["x"], "y": step["y"]})
        return _step_result(step, status="pass" if ok else "fail", observed={"x": step["x"], "y": step["y"]})

    def _handle_pointer_down(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok = self._do_pointer_event(session, "down", step["x"], step["y"], step.get("button", "left"))
        self._record_input_event(session, "pointer_down", {"x": step["x"], "y": step["y"]})
        return _step_result(step, status="pass" if ok else "fail", observed={"x": step["x"], "y": step["y"]})

    def _handle_pointer_up(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok = self._do_pointer_event(session, "up", step["x"], step["y"], step.get("button", "left"))
        self._record_input_event(session, "pointer_up", {"x": step["x"], "y": step["y"]})
        return _step_result(step, status="pass" if ok else "fail", observed={"x": step["x"], "y": step["y"]})

    def _handle_click_selector(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        ok = self._do_click(session, step["selector"])
        self._record_input_event(session, "click_selector", {"selector": step["selector"]})
        return _step_result(step, status="pass" if ok else "fail", observed={"clicked": ok})

    def _handle_capture_screenshot(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        if session.screenshot_count >= session.plan.max_screenshots:
            return _step_result(step, status="error", message="max_screenshots exceeded")
        shot = self._do_screenshot(session)
        blob: bytes = shot["bytes"]
        if len(blob) > limits.MAX_SCREENSHOT_ENCODED_BYTES:
            return _step_result(step, status="error", message="screenshot exceeds max encoded bytes")
        import hashlib

        sha256 = hashlib.sha256(blob).hexdigest()
        screenshot_id = new_id("screenshot")
        session.screenshot_blobs[screenshot_id] = blob
        session.screenshot_count += 1
        record = {
            "screenshot_id": screenshot_id,
            "name": step.get("name"),
            "sha256": sha256,
            "byte_length": len(blob),
            "width": shot.get("width"),
            "height": shot.get("height"),
            "timestamp": now_iso(),
        }
        session.screenshots.append(record)
        return _step_result(step, status="pass", observed={"screenshot_id": screenshot_id, "sha256": sha256, "byte_length": len(blob)})

    def _handle_assert_console_clean(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        errors = [e for e in session.console_entries if e.get("level") == "error"]
        return _step_result(step, status="pass" if not errors else "fail", observed={"error_count": len(errors), "errors": errors[:10]})

    def _handle_assert_no_page_exceptions(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return _step_result(step, status="pass" if not session.page_exceptions else "fail", observed={"count": len(session.page_exceptions)})

    def _handle_assert_no_external_requests(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return _step_result(step, status="pass" if not session.external_request_attempts else "fail", observed={"count": len(session.external_request_attempts)})

    def _handle_assert_no_downloads(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return _step_result(step, status="pass" if not session.downloads else "fail", observed={"count": len(session.downloads)})

    def _handle_assert_no_unexpected_dialogs(self, session: RuntimeSession, step: dict[str, Any]) -> dict[str, Any]:
        return _step_result(step, status="pass" if not session.dialogs else "fail", observed={"count": len(session.dialogs)})

    # --- default collect_evidence -----------------------------------------
    def collect_evidence(self, session: RuntimeSession) -> dict[str, Any]:
        return {
            "page_load": dict(session.page_load),
            "console_entries": list(session.console_entries),
            "page_exceptions": list(session.page_exceptions),
            "network_events": list(session.network_events),
            "external_request_attempts": list(session.external_request_attempts),
            "dialogs": list(session.dialogs),
            "popups": list(session.popups),
            "downloads": list(session.downloads),
            "dom_observations": list(session.dom_observations),
            "debug_snapshots": list(session.debug_snapshots),
            "input_events": list(session.input_events),
            "screenshots": list(session.screenshots),
            "assertions": list(session.assertions),
            "policy_violations": list(session.policy_violations),
            "truncation": {
                category: {
                    "original_count": session.original_count(category),
                    "retained_count": len(getattr(session, category)),
                    "truncated": category in session.truncated_categories,
                }
                for category in (
                    "console_entries",
                    "network_events",
                    "external_request_attempts",
                    "debug_snapshots",
                    "screenshots",
                    "input_events",
                )
            },
        }
