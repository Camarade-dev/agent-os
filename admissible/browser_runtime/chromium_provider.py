"""Real installed-browser provider over the Chrome DevTools Protocol (PART B.5-9, PART D).

``ChromiumCdpRuntimeProvider`` launches an already-installed, allowlisted
Chromium-family browser with a fixed, verifier-owned argument list, serves
the authorized workspace over :class:`LoopbackWorkspaceServer`, enforces
external-network containment through CDP request interception, and cleans
up the whole process tree, the temporary profile, and the server on close.

Never uses ``--no-sandbox`` or ``--disable-web-security``. Never installs
or downloads anything. Never accepts browser flags from a caller.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from admissible.browser_runtime import dsl
from admissible.browser_runtime.cdp_client import CDPConnection, http_get_json, wait_for_devtools_http
from admissible.browser_runtime.discovery import detect_browser_version, discover_browser_executable
from admissible.browser_runtime.limits import MAX_SCREENSHOT_ENCODED_BYTES, SAFETY_POLICY_VERSION
from admissible.browser_runtime.models import BrowserRuntimeCapabilityReport, new_id, now_iso
from admissible.browser_runtime.process_cleanup import ProcessTreeHandle
from admissible.browser_runtime.provider import BaseBrowserRuntimeProvider, RuntimeSession
from admissible.browser_runtime.server import LoopbackWorkspaceServer

CHROMIUM_PROVIDER_ID = "chromium_cdp"
CHROMIUM_PROVIDER_VERSION = "1"

_SUPPORTED_FEATURES = [
    "navigate",
    "dom_query",
    "input_dispatch",
    "debug_snapshot",
    "screenshot",
    "network_interception",
    "popup_denial",
    "dialog_denial",
    "download_denial",
]


def _redact_query(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    return f"{parts.scheme}://{parts.netloc}{parts.path}?<redacted:{len(parts.query)}b>"


def build_chromium_arguments(executable_path: str, user_data_dir: str, *, headless: bool = True) -> list[str]:
    """Return the fixed, verifier-owned argument list for launching the browser.

    Never includes ``--no-sandbox`` or ``--disable-web-security``, and never
    interpolates any caller- or environment-supplied flag.
    """

    args = [
        executable_path,
        f"--user-data-dir={user_data_dir}",
        "--remote-debugging-port=0",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-component-update",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-translate",
        "--disable-features=Translate,MediaRouter,OptimizationHints",
        "--metrics-recording-only",
        "--disable-client-side-phishing-detection",
        "--disable-default-apps",
        "--disable-prompt-on-repost",
        "--disable-hang-monitor",
        "--disable-domain-reliability",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--disable-ipc-flooding-protection",
        "--disable-search-engine-choice-screen",
        "--mute-audio",
        "--window-size=1280,800",
        "--password-store=basic",
        "--use-mock-keychain",
    ]
    if headless:
        args.append("--headless=new")
    args.append("about:blank")
    return args


_FORBIDDEN_ARGUMENTS = ("--no-sandbox", "--disable-web-security")


def _assert_arguments_are_safe(args: list[str]) -> None:
    for forbidden in _FORBIDDEN_ARGUMENTS:
        if any(arg == forbidden or arg.startswith(forbidden + "=") for arg in args):
            raise RuntimeError(f"refusing to launch browser with forbidden argument: {forbidden}")


def _remove_profile_dir_with_retry(profile_dir: str, *, attempts: int = 5, delay_seconds: float = 0.3) -> bool:
    """Remove the temporary profile directory, tolerating transient Windows file locks.

    A just-terminated browser process's file handles (and, on Windows, real-time
    antivirus scanning of the just-modified directory) are not always released
    the instant the process exits, so a single ``rmtree`` attempt can spuriously
    report the directory as still present immediately after a clean shutdown.
    """

    for attempt in range(attempts):
        shutil.rmtree(profile_dir, ignore_errors=True)
        if not Path(profile_dir).exists():
            return True
        if attempt < attempts - 1:
            time.sleep(delay_seconds)
    return not Path(profile_dir).exists()


class ChromiumCdpRuntimeProvider(BaseBrowserRuntimeProvider):
    """Launches one allowlisted local Chromium-family browser per session."""

    provider_id = CHROMIUM_PROVIDER_ID
    provider_version = CHROMIUM_PROVIDER_VERSION

    def __init__(self, *, headless: bool = True, launch_timeout: float = 20.0) -> None:
        self.headless = headless
        self.launch_timeout = launch_timeout

    def detect_capability(self) -> BrowserRuntimeCapabilityReport:
        found = discover_browser_executable()
        if found is None:
            return BrowserRuntimeCapabilityReport(
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                available=False,
                executable_path=None,
                executable_basename=None,
                browser_version=None,
                supported_features=[],
                unsupported_features=list(_SUPPORTED_FEATURES),
                discovery_source=None,
                safety_policy_version=SAFETY_POLICY_VERSION,
                unavailable_reason="no_allowlisted_browser_executable_found",
            )
        version = detect_browser_version(found.executable_path)
        return BrowserRuntimeCapabilityReport(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            available=True,
            executable_path=found.executable_path,
            executable_basename=found.executable_basename,
            browser_version=version,
            supported_features=list(_SUPPORTED_FEATURES),
            unsupported_features=[],
            discovery_source=found.discovery_source,
            safety_policy_version=SAFETY_POLICY_VERSION,
            unavailable_reason=None,
        )

    # --- session lifecycle --------------------------------------------------
    def create_session(self, plan) -> RuntimeSession:
        capability = self.detect_capability()
        if not capability.available:
            raise RuntimeError(f"no allowlisted browser available: {capability.unavailable_reason}")

        server = LoopbackWorkspaceServer(Path(plan.workspace_root))
        server.start()

        profile_dir = tempfile.mkdtemp(prefix="admissible-browser-profile-")
        args = build_chromium_arguments(capability.executable_path, profile_dir, headless=self.headless)
        _assert_arguments_are_safe(args)

        process = ProcessTreeHandle(args)
        process.start()

        state = {
            "server": server,
            "profile_dir": profile_dir,
            "process": process,
            "connection": None,
            "main_target_id": None,
            "load_event": threading.Event(),
            "screenshot_metrics_ready": True,
        }
        session = RuntimeSession(session_id=new_id("chromium_session"), plan=plan, provider_state=state)

        try:
            port = self._discover_devtools_port(profile_dir, process, timeout=self.launch_timeout)
            version_info = wait_for_devtools_http("127.0.0.1", port, timeout=self.launch_timeout)
            ws_url = version_info.get("webSocketDebuggerUrl")
            targets = http_get_json("127.0.0.1", port, "/json/list", timeout=5.0)
            page_targets = [t for t in targets if t.get("type") == "page"]
            page_ws_url = page_targets[0]["webSocketDebuggerUrl"] if page_targets else ws_url
            state["main_target_id"] = page_targets[0]["id"] if page_targets else None

            connection = CDPConnection(page_ws_url, timeout=self.launch_timeout)
            state["connection"] = connection
            self._install_event_handlers(session, connection)
            connection.send("Page.enable")
            connection.send("Runtime.enable")
            connection.send("DOM.enable")
            connection.send("Network.enable")
            connection.send("Log.enable")
            connection.send("Page.setDownloadBehavior", {"behavior": "deny"})
            connection.send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True})
            connection.send(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
            )
        except Exception:
            self._teardown(session)
            raise
        return session

    def _discover_devtools_port(self, profile_dir: str, process: ProcessTreeHandle, *, timeout: float) -> int:
        active_port_file = Path(profile_dir) / "DevToolsActivePort"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.process is not None and process.process.poll() is not None:
                raise RuntimeError(f"browser process exited early with code {process.process.returncode}")
            if active_port_file.is_file():
                try:
                    first_line = active_port_file.read_text(encoding="utf-8").splitlines()[0].strip()
                    return int(first_line)
                except (OSError, IndexError, ValueError):
                    pass
            time.sleep(0.05)
        raise RuntimeError("timed out waiting for browser DevToolsActivePort file")

    def _install_event_handlers(self, session: RuntimeSession, connection: CDPConnection) -> None:
        state = session.provider_state

        def on_console(params: dict[str, Any]) -> None:
            entry_type = params.get("type", "log")
            level = "error" if entry_type == "error" else ("warning" if entry_type == "warning" else "log")
            args_preview = [a.get("value", a.get("description", "")) for a in params.get("args") or []][:5]
            session.record_console({"level": level, "type": entry_type, "text": " ".join(str(a) for a in args_preview), "timestamp": now_iso()})

        def on_exception(params: dict[str, Any]) -> None:
            detail = params.get("exceptionDetails") or {}
            exception = detail.get("exception") or {}
            session.page_exceptions.append(
                {
                    "text": detail.get("text"),
                    "description": exception.get("description"),
                    "line": detail.get("lineNumber"),
                    "column": detail.get("columnNumber"),
                    "timestamp": now_iso(),
                }
            )

        def on_load(params: dict[str, Any]) -> None:
            state["load_event"].set()

        def on_dialog(params: dict[str, Any]) -> None:
            session.dialogs.append({"type": params.get("type"), "message": params.get("message"), "timestamp": now_iso()})
            try:
                connection.send("Page.handleJavaScriptDialog", {"accept": False})
            except Exception:  # noqa: BLE001 - dialog handling must never crash the session
                pass

        def on_download(params: dict[str, Any]) -> None:
            session.downloads.append({"url": _redact_query(params.get("url", "")), "suggested_filename": params.get("suggestedFilename"), "timestamp": now_iso()})

        def on_attached_target(params: dict[str, Any]) -> None:
            target_info = params.get("targetInfo") or {}
            target_id = target_info.get("targetId")
            if target_id and target_id != state.get("main_target_id"):
                session.popups.append({"target_id": target_id, "type": target_info.get("type"), "url": _redact_query(target_info.get("url", "")), "timestamp": now_iso()})
                try:
                    connection.send("Target.closeTarget", {"targetId": target_id})
                except Exception:  # noqa: BLE001 - closing a popup must never crash the session
                    pass

        def on_request_paused(params: dict[str, Any]) -> None:
            request = params.get("request") or {}
            url = request.get("url", "")
            request_id = params.get("requestId")
            allowed = self._is_allowed_request(session, url)
            entry = {
                "url": _redact_query(url),
                "resource_type": params.get("resourceType"),
                "initiator_category": (params.get("request") or {}).get("initiator", {}).get("type") if isinstance(request.get("initiator"), dict) else None,
                "allowed": allowed,
                "timestamp": now_iso(),
            }
            session.record_network(entry)
            try:
                if allowed:
                    connection.send("Fetch.continueRequest", {"requestId": request_id})
                else:
                    session.record_external_attempt(
                        {
                            "url": _redact_query(url),
                            "resource_type": params.get("resourceType"),
                            "criterion_impact": "external_network_containment",
                            "timestamp": now_iso(),
                        }
                    )
                    connection.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            except Exception:  # noqa: BLE001 - a stray Fetch race must never crash the session
                pass

        connection.on_event("Runtime.consoleAPICalled", on_console)
        connection.on_event("Runtime.exceptionThrown", on_exception)
        connection.on_event("Page.loadEventFired", on_load)
        connection.on_event("Page.javascriptDialogOpening", on_dialog)
        connection.on_event("Page.downloadWillBegin", on_download)
        connection.on_event("Target.attachedToTarget", on_attached_target)
        connection.on_event("Fetch.requestPaused", on_request_paused)

    def _is_allowed_request(self, session: RuntimeSession, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme in ("data", "blob", "about"):
            return True
        if parts.scheme in ("chrome-error", "devtools", "chrome"):
            return True
        server: LoopbackWorkspaceServer = session.provider_state["server"]
        allowed_origin = urlsplit(server.origin)
        return parts.scheme == allowed_origin.scheme and parts.hostname == allowed_origin.hostname and parts.port == allowed_origin.port

    # --- primitives ----------------------------------------------------
    def _connection(self, session: RuntimeSession) -> CDPConnection:
        return session.provider_state["connection"]

    def _do_navigate(self, session: RuntimeSession, path: str, query: str) -> dict[str, Any]:
        server: LoopbackWorkspaceServer = session.provider_state["server"]
        session.provider_state["load_event"].clear()
        url = server.url_for(path, query)
        result = self._connection(session).send("Page.navigate", {"url": url})
        ok = "errorText" not in result
        return {"ok": ok, "url": _redact_query(url), "message": result.get("errorText", ""), "timestamp": now_iso()}

    def _do_wait(self, session: RuntimeSession, duration_ms: int) -> None:
        deadline = time.monotonic() + duration_ms / 1000.0
        while time.monotonic() < deadline:
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def _do_wait_for_load(self, session: RuntimeSession, timeout_ms: int) -> bool:
        return session.provider_state["load_event"].wait(timeout_ms / 1000.0)

    def _evaluate(self, session: RuntimeSession, expression: str) -> Any:
        result = self._connection(session).send(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": False},
        )
        if result.get("exceptionDetails"):
            raise RuntimeError(f"Runtime.evaluate raised: {result['exceptionDetails']}")
        return (result.get("result") or {}).get("value")

    def _do_query_selector(self, session: RuntimeSession, selector: str) -> dict[str, Any]:
        expr = (
            "(() => { try { "
            f"const els = document.querySelectorAll({json.dumps(selector)}); "
            "if (els.length === 0) return {present:false, visible:false, count:0, text:null}; "
            "const el = els[0]; const rect = el.getBoundingClientRect(); const style = window.getComputedStyle(el); "
            "const visible = rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none'; "
            "return {present:true, visible, count: els.length, text: el.textContent, x: rect.x + rect.width/2, y: rect.y + rect.height/2}; "
            "} catch (e) { return {present:false, visible:false, count:0, text:null}; } })()"
        )
        value = self._evaluate(session, expr) or {}
        return {"present": bool(value.get("present")), "visible": bool(value.get("visible")), "count": int(value.get("count") or 0), "text": value.get("text"), "_center": (value.get("x"), value.get("y"))}

    def _do_click(self, session: RuntimeSession, selector: str) -> bool:
        state = self._do_query_selector(session, selector)
        if not state.get("present"):
            return False
        x, y = state.get("_center") or (None, None)
        if x is None or y is None:
            return False
        connection = self._connection(session)
        connection.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        connection.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
        connection.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})
        return True

    _NAMED_KEYS: dict[str, dict[str, Any]] = {
        "Enter": {"key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13},
        "Escape": {"key": "Escape", "code": "Escape", "windowsVirtualKeyCode": 27},
        "ArrowUp": {"key": "ArrowUp", "code": "ArrowUp", "windowsVirtualKeyCode": 38},
        "ArrowDown": {"key": "ArrowDown", "code": "ArrowDown", "windowsVirtualKeyCode": 40},
        "ArrowLeft": {"key": "ArrowLeft", "code": "ArrowLeft", "windowsVirtualKeyCode": 37},
        "ArrowRight": {"key": "ArrowRight", "code": "ArrowRight", "windowsVirtualKeyCode": 39},
        "Space": {"key": " ", "code": "Space", "windowsVirtualKeyCode": 32},
        "Tab": {"key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9},
        "Backspace": {"key": "Backspace", "code": "Backspace", "windowsVirtualKeyCode": 8},
    }

    def _key_params(self, key: str) -> dict[str, Any]:
        if key in self._NAMED_KEYS:
            return dict(self._NAMED_KEYS[key])
        if len(key) == 1:
            return {"key": key, "code": f"Key{key.upper()}" if key.isalpha() else key, "text": key, "unmodifiedText": key}
        return {"key": key, "code": key}

    def _do_key_event(self, session: RuntimeSession, action: str, key: str) -> bool:
        params = self._key_params(key)
        event_type = "keyDown" if action == "down" else "keyUp"
        payload = {"type": event_type, **params}
        self._connection(session).send("Input.dispatchKeyEvent", payload)
        return True

    def _do_pointer_event(self, session: RuntimeSession, action: str, x: float, y: float, button: str) -> bool:
        type_map = {"move": "mouseMoved", "down": "mousePressed", "up": "mouseReleased"}
        self._connection(session).send("Input.dispatchMouseEvent", {"type": type_map[action], "x": x, "y": y, "button": button, "clickCount": 1 if action != "move" else 0})
        return True

    def _do_read_dom_attribute(self, session: RuntimeSession, selector: str, attribute: str) -> str | None:
        expr = (
            "(() => { try { "
            f"const el = document.querySelector({json.dumps(selector)}); "
            f"if (!el) return null; const v = el.getAttribute({json.dumps(attribute)}); return v === null ? null : String(v); "
            "} catch (e) { return null; } })()"
        )
        return self._evaluate(session, expr)

    def _do_debug_snapshot(self, session: RuntimeSession) -> Any:
        if not session.plan.debug_interface:
            raise RuntimeError("plan declares no debug_interface; cannot take a debug snapshot")
        expression = dsl.build_snapshot_expression(session.plan.debug_interface)
        return self._evaluate(session, expression)

    def _do_screenshot(self, session: RuntimeSession) -> dict[str, Any]:
        import base64

        connection = self._connection(session)
        result = connection.send("Page.captureScreenshot", {"format": "png"})
        data = base64.b64decode(result.get("data", ""))
        if len(data) > MAX_SCREENSHOT_ENCODED_BYTES:
            data = data[:MAX_SCREENSHOT_ENCODED_BYTES]
        metrics = connection.send("Page.getLayoutMetrics")
        content_size = metrics.get("cssContentSize") or {}
        return {"bytes": data, "width": int(content_size.get("width") or 0), "height": int(content_size.get("height") or 0)}

    def _pump_events(self, session: RuntimeSession) -> None:
        time.sleep(0.01)

    def close_session(self, session: RuntimeSession) -> dict[str, Any]:
        return self._teardown(session)

    def _teardown(self, session: RuntimeSession) -> dict[str, Any]:
        state = session.provider_state
        connection: CDPConnection | None = state.get("connection")
        if connection is not None:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 - cleanup must always proceed
                pass

        process: ProcessTreeHandle = state["process"]
        process_result = process.terminate_tree()

        server: LoopbackWorkspaceServer = state["server"]
        server_result = server.stop()

        profile_dir = state["profile_dir"]
        profile_removed = _remove_profile_dir_with_retry(profile_dir)

        session.terminated = True
        if not session.termination_reason:
            session.termination_reason = "completed"
        return {
            "browser_process_terminated": process_result.get("terminated", False),
            "termination_method": process_result.get("method"),
            "http_server_stopped": server_result.get("stopped", False),
            "requests_served": server_result.get("requests_served", 0),
            "temporary_profile_removed": profile_removed,
            "temporary_profile_path": profile_dir,
            "orphan_processes": [] if process_result.get("terminated") else [process.pid],
        }
