"""Deterministic in-memory runtime provider for tests (PART B.5).

``FixtureBrowserRuntimeProvider`` never launches a browser, opens a socket,
or touches the filesystem beyond what a caller hands it. It simulates DOM
state, a debug snapshot, console/network/dialog/download/popup events, and
input-driven transitions from a small declarative scenario dict, so the
same declarative-DSL interpreter in
:class:`~admissible.browser_runtime.provider.BaseBrowserRuntimeProvider` can
be exercised deterministically without any real browser dependency.
"""

from __future__ import annotations

import copy
from typing import Any

from admissible.browser_runtime.models import BrowserRuntimeCapabilityReport, new_id, now_iso
from admissible.browser_runtime.provider import BaseBrowserRuntimeProvider, RuntimeSession
from admissible.browser_runtime.limits import SAFETY_POLICY_VERSION

FIXTURE_PROVIDER_ID = "fixture"
FIXTURE_PROVIDER_VERSION = "1"


class FixtureBrowserRuntimeProvider(BaseBrowserRuntimeProvider):
    """A scripted, deterministic stand-in for a real browser runtime.

    ``scenario`` keys (all optional):

    - ``available``: whether detect_capability reports a usable browser.
    - ``navigate_ok``: whether navigation succeeds.
    - ``initial_dom``: {selector: {"present","visible","count","text"}}.
    - ``dom_attributes``: {(selector, attribute): value}.
    - ``initial_snapshot``: the debug snapshot value returned on the first
      ``debug_snapshot`` step.
    - ``click_rules`` / ``key_rules``: {trigger: {"dom": patch, "snapshot": patch}}
      shallow-merged into the live DOM/snapshot state when that click
      selector or key is dispatched. ``key_rules`` applies on ``key_down``
      (and the down-half of ``key_press``); ``key_up_rules`` is the
      analogous table applied on ``key_up`` (and the up-half of
      ``key_press``), for scenarios where release matters (e.g. a boost key
      that must patch the snapshot back on release).
    - ``console_entries`` / ``page_exceptions`` / ``dialogs`` / ``popups`` /
      ``downloads`` / ``external_request_attempts``: pre-seeded evidence,
      as if collected during the run.
    - ``screenshot``: {"bytes": b"...", "width": int, "height": int}.
    """

    provider_id = FIXTURE_PROVIDER_ID
    provider_version = FIXTURE_PROVIDER_VERSION

    def __init__(self, scenario: dict[str, Any] | None = None) -> None:
        self.scenario = dict(scenario or {})

    def detect_capability(self) -> BrowserRuntimeCapabilityReport:
        available = bool(self.scenario.get("available", True))
        return BrowserRuntimeCapabilityReport(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            available=available,
            executable_path=None,
            executable_basename=None,
            browser_version="fixture/1",
            supported_features=["dsl_v1"] if available else [],
            unsupported_features=[] if available else ["all"],
            discovery_source="fixture_scenario",
            safety_policy_version=SAFETY_POLICY_VERSION,
            unavailable_reason=None if available else str(self.scenario.get("unavailable_reason") or "fixture_marked_unavailable"),
        )

    def create_session(self, plan) -> RuntimeSession:
        state = {
            "dom": copy.deepcopy(self.scenario.get("initial_dom") or {}),
            "attributes": dict(self.scenario.get("dom_attributes") or {}),
            "snapshot": copy.deepcopy(self.scenario.get("initial_snapshot") or {}),
        }
        session = RuntimeSession(session_id=new_id("fixture_session"), plan=plan, provider_state=state)
        for entry in self.scenario.get("console_entries") or []:
            session.record_console(dict(entry))
        session.page_exceptions.extend(copy.deepcopy(self.scenario.get("page_exceptions") or []))
        session.dialogs.extend(copy.deepcopy(self.scenario.get("dialogs") or []))
        session.popups.extend(copy.deepcopy(self.scenario.get("popups") or []))
        session.downloads.extend(copy.deepcopy(self.scenario.get("downloads") or []))
        for entry in self.scenario.get("external_request_attempts") or []:
            session.record_external_attempt(dict(entry))
        return session

    # --- primitives -------------------------------------------------------
    def _do_navigate(self, session: RuntimeSession, path: str, query: str) -> dict[str, Any]:
        ok = bool(self.scenario.get("navigate_ok", True))
        return {"ok": ok, "path": path, "query": query, "message": "" if ok else "navigation_failed", "timestamp": now_iso()}

    def _do_wait(self, session: RuntimeSession, duration_ms: int) -> None:
        return None

    def _do_wait_for_load(self, session: RuntimeSession, timeout_ms: int) -> bool:
        return bool(self.scenario.get("navigate_ok", True))

    def _do_query_selector(self, session: RuntimeSession, selector: str) -> dict[str, Any]:
        dom = session.provider_state["dom"]
        entry = dom.get(selector, {})
        return {
            "present": bool(entry.get("present", False)),
            "visible": bool(entry.get("visible", False)),
            "count": int(entry.get("count", 0)),
            "text": entry.get("text"),
        }

    def _apply_patch(self, session: RuntimeSession, patch: dict[str, Any]) -> None:
        dom_patch = patch.get("dom") or {}
        for selector, updates in dom_patch.items():
            current = session.provider_state["dom"].setdefault(selector, {})
            current.update(updates)
        snapshot_patch = patch.get("snapshot") or {}
        session.provider_state["snapshot"].update(snapshot_patch)

    def _do_click(self, session: RuntimeSession, selector: str) -> bool:
        rule = (self.scenario.get("click_rules") or {}).get(selector)
        if rule:
            self._apply_patch(session, rule)
        return True

    def _do_key_event(self, session: RuntimeSession, action: str, key: str) -> bool:
        if action == "down":
            rule = (self.scenario.get("key_rules") or {}).get(key)
            if rule:
                self._apply_patch(session, rule)
        elif action == "up":
            rule = (self.scenario.get("key_up_rules") or {}).get(key)
            if rule:
                self._apply_patch(session, rule)
        return True

    def _do_pointer_event(self, session: RuntimeSession, action: str, x: float, y: float, button: str) -> bool:
        return True

    def _do_read_dom_attribute(self, session: RuntimeSession, selector: str, attribute: str) -> str | None:
        return session.provider_state["attributes"].get((selector, attribute))

    def _do_debug_snapshot(self, session: RuntimeSession) -> Any:
        return copy.deepcopy(session.provider_state["snapshot"])

    def _do_screenshot(self, session: RuntimeSession) -> dict[str, Any]:
        shot = self.scenario.get("screenshot") or {}
        return {
            "bytes": shot.get("bytes") or _TRANSPARENT_PIXEL_PNG,
            "width": shot.get("width", 1),
            "height": shot.get("height", 1),
        }

    def close_session(self, session: RuntimeSession) -> dict[str, Any]:
        session.terminated = True
        if not session.termination_reason:
            session.termination_reason = "completed"
        return {
            "browser_process_terminated": True,
            "http_server_stopped": True,
            "temporary_profile_removed": True,
            "orphan_processes": [],
        }


# A minimal valid 1x1 transparent PNG, used as the fixture provider's stand-in
# screenshot payload so screenshot bounding/hashing logic has real bytes to hash.
_TRANSPARENT_PIXEL_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753"
    "de000000017352474200aece1ce90000000467414d410000b18f0bfc61050000"
    "000774494d4507e6090d15243b2c667e380000000d4944415478da6360000002"
    "0001489a6a3b0000000049454e44ae426082"
)
