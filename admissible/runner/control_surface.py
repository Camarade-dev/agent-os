"""Admissible Control Surface v0 — local interactive runner.

Starts a local, stdlib-only HTTP server that serves the Control Surface
UI (`admissible/harness/control_surface.html`) and a small same-origin
JSON API backed by `admissible.control_surface.ControlSurfaceController`.

Also exposes four routes (`/api/session/run_loop/bridge/*`) backed by
`admissible.runner.cursor_bridge` -- a local file bridge that writes/reads
`.admissible/next-agent-instruction.md` and `.admissible/agent-response.md`
in a target workspace so a human does not have to copy/paste the packet and
response by hand. See docs/admissible-cursor-bridge.md.

Hard constraints:

- Does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or any
  network provider.
- Does not execute shell commands from the UI or anywhere in this module
  (no `subprocess`, no `os.system`, no `eval`/`exec` of request data). The
  one narrow exception is the bridge's optional "open workspace in Cursor"
  helper (`cursor_bridge.open_workspace_in_cursor`), which only ever
  launches a discovered/configured Cursor executable with `shell=False` and
  a fixed argv -- never a shell string, never a workspace- or
  agent-response-derived command.
- Implements no automatic executor. "Attest executed" only records that
  an already-admitted local action was executed by a human/external
  actor; see admissible.admitted_execution.
- Does not import `agent_os`.

CLI:

    python -m admissible.runner.control_surface --open
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from admissible.control_surface import (
    ControlSurfaceController,
    InvalidSessionFileError,
    load_persisted_session,
)
from admissible.execution.bounded_local_executor import BoundedExecutionError
from admissible.runner import cursor_bridge

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_HTML_PATH = Path(__file__).resolve().parent.parent / "harness" / "control_surface.html"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


class _ControlSurfaceHTTPServer(ThreadingHTTPServer):
    """Refuses to silently share a listening port with another instance.

    ``http.server`` sets ``allow_reuse_address = True`` (SO_REUSEADDR),
    which on Windows -- unlike POSIX -- lets a second process bind the
    *same* host:port while an earlier instance is still listening, with no
    error. Two control-surface processes then serve the same session
    directory from independent in-memory state, so a browser's GET/POST
    calls route unpredictably between them: a button click can appear to do
    nothing if its response lands on a different process than the one that
    rendered the page. On Windows, request SO_EXCLUSIVEADDRUSE instead so a
    duplicate launch fails loudly with "address already in use"; POSIX
    keeps the normal SO_REUSEADDR fast-restart behavior unchanged.
    """

    def server_bind(self) -> None:
        if sys.platform == "win32":
            # SO_EXCLUSIVEADDRUSE and SO_REUSEADDR are mutually exclusive on
            # Windows -- skip the inherited SO_REUSEADDR call.
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


_STARTUP_BANNER = (
    "Admissible Control Surface v0 -- local only. Does not call Cursor, Claude Code, "
    "Codex, Gemini, OpenAI, or any network provider. Does not execute shell commands. "
    "No automatic executor exists in this v0."
)


class _ControlSurfaceRequestHandler(BaseHTTPRequestHandler):
    """Thin JSON/HTML adapter over a ControlSurfaceController.

    All decision logic lives in admissible.control_surface; this class
    only parses requests, dispatches to controller methods, and encodes
    JSON responses. It never shells out and never calls a provider.
    """

    controller: ControlSurfaceController
    server_version = "AdmissibleControlSurface/0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        # Keep local runs quiet by default; this is not an external logging
        # service and carries no user data beyond what's already local.
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_text: str) -> None:
        body = html_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data

    def do_GET(self) -> None:  # noqa: N802 - required BaseHTTPRequestHandler name
        parsed = urlparse(self.path)
        try:
            if parsed.path in ("/", "/index.html"):
                self._send_html(_HTML_PATH.read_text(encoding="utf-8"))
            elif parsed.path == "/api/session":
                self._send_json(200, self.controller.state_view())
            elif parsed.path == "/api/session/export":
                self._send_json(200, self.controller.session_dict())
            else:
                self._send_json(404, {"error": f"not found: {parsed.path}"})
        except Exception as exc:  # local dev tool: surface the error, keep serving
            self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802 - required BaseHTTPRequestHandler name
        parsed = urlparse(self.path)
        try:
            body = self._read_json_body()
            if parsed.path == "/api/session/reset":
                result = self.controller.reset_session()
            elif parsed.path == "/api/session/import":
                result = self.controller.import_session(body)
            elif parsed.path == "/api/session/autonomy":
                result = self.controller.set_autonomy(body.get("level"))
            elif parsed.path == "/api/session/goal":
                result = self.controller.submit_goal(body.get("prompt", ""))
            elif parsed.path == "/api/session/load_sample":
                result = self.controller.load_sample_session()
            elif parsed.path == "/api/session/load_trace":
                result = self.controller.load_trace(body.get("path"))
            elif parsed.path == "/api/session/run_loop/generate_instruction":
                result = self.controller.generate_next_instruction_packet()
            elif parsed.path == "/api/session/run_loop/ingest_response":
                result = self.controller.ingest_agent_response(body.get("raw_response", ""))
            elif parsed.path == "/api/session/run_loop/bridge/check_workspace":
                result = cursor_bridge.check_workspace(body.get("workspace_path", ""))
            elif parsed.path == "/api/session/run_loop/bridge/write_instruction":
                result = cursor_bridge.write_next_instruction_with_controller(
                    self.controller, body.get("workspace_path", "")
                )
            elif parsed.path == "/api/session/run_loop/bridge/ingest_response":
                result = cursor_bridge.ingest_response_file_with_controller(
                    self.controller, body.get("workspace_path", "")
                )
            elif parsed.path == "/api/session/run_loop/bridge/open_workspace":
                result = {
                    **self.controller.state_view(),
                    "bridge": cursor_bridge.open_workspace_in_cursor(body.get("workspace_path", "")),
                }
            elif parsed.path.startswith("/api/queue/") and parsed.path.endswith("/decide"):
                action_id = unquote(parsed.path.split("/")[3])
                result = self.controller.decide(action_id, body)
            elif parsed.path.startswith("/api/queue/") and parsed.path.endswith("/evidence"):
                action_id = unquote(parsed.path.split("/")[3])
                result = self.controller.provide_evidence(action_id, body)
            elif parsed.path.startswith("/api/queue/") and parsed.path.endswith("/execute_bounded_local"):
                action_id = unquote(parsed.path.split("/")[3])
                result = self.controller.execute_bounded_local(action_id, body)
            else:
                self._send_json(404, {"error": f"not found: {parsed.path}"})
                return
        except ValueError as exc:
            payload: dict[str, Any] = {"error": str(exc)}
            detail = getattr(exc, "detail", None)
            if isinstance(detail, dict):
                payload.update(detail)
            elif isinstance(exc, BoundedExecutionError):
                payload["diagnostic"] = exc.diagnostic
            self._send_json(400, payload)
            return
        except Exception as exc:  # local dev tool: surface the error, keep serving
            self._send_json(500, {"error": str(exc)})
            return
        self._send_json(200, result)


def build_controller(
    *,
    session_dir: str | Path | None = None,
    sample_trace_path: str | Path | None = None,
    repo_root: str | Path | None = None,
    fresh_session: bool = False,
) -> ControlSurfaceController:
    controller = ControlSurfaceController(
        session_dir=session_dir,
        sample_trace_path=sample_trace_path,
        repo_root=repo_root,
    )
    load_persisted_session(controller, fresh_session=fresh_session)
    return controller


def make_server(
    controller: ControlSurfaceController,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> ThreadingHTTPServer:
    """Build (but do not start) a ThreadingHTTPServer bound to `controller`."""
    handler_cls = type(
        "BoundControlSurfaceRequestHandler",
        (_ControlSurfaceRequestHandler,),
        {"controller": controller},
    )
    return _ControlSurfaceHTTPServer((host, port), handler_cls)


def run(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    open_browser: bool = False,
    session_dir: str | Path | None = None,
    sample_trace_path: str | Path | None = None,
    repo_root: str | Path | None = None,
    fresh_session: bool = False,
) -> None:
    """Build a controller, start the HTTP server, and serve until interrupted."""
    try:
        controller = build_controller(
            session_dir=session_dir,
            sample_trace_path=sample_trace_path,
            repo_root=repo_root,
            fresh_session=fresh_session,
        )
    except InvalidSessionFileError as exc:
        print(f"admissible.runner.control_surface error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    server = make_server(controller, host=host, port=port)
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"

    print(_STARTUP_BANNER)
    print(f"Serving at {url} (Ctrl+C to stop)")
    if controller._session_loaded_from_disk:
        print(
            f"Resumed session {controller.session_dict()['session_id']} "
            f"from {controller.session_file}"
        )
    else:
        print(f"Fresh in-memory session (persist path: {controller.session_file})")

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.control_surface",
        description=(
            "Launch the local Admissible Control Surface v0: a stdlib-only HTTP "
            "server exposing a goal-intake, plan-audit, and action-admission-queue "
            "UI. Calls no network provider, executes no shell commands, and "
            "implements no automatic executor."
        ),
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host to bind (default: {DEFAULT_HOST}).")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to bind (default: {DEFAULT_PORT}; use 0 for an ephemeral port).",
    )
    parser.add_argument(
        "--open",
        dest="open_browser",
        action="store_true",
        help="Open the default web browser to the control surface once it starts.",
    )
    parser.add_argument(
        "--session-dir",
        default=None,
        help="Directory for local session JSON artifacts (default: .admissible/control_surface_sessions).",
    )
    parser.add_argument(
        "--fresh-session",
        action="store_true",
        help=(
            "Start from a new empty in-memory session instead of resuming "
            "session.json when it already exists on disk."
        ),
    )
    parser.add_argument(
        "--sample-trace",
        default=None,
        help=(
            "Path to the sample trace JSON used by 'load sample session' "
            "(default: benchmark/reports/admissible_cursor_admitted_execution_truth_console_trace.json)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    run(
        host=args.host,
        port=args.port,
        open_browser=args.open_browser,
        session_dir=args.session_dir,
        sample_trace_path=args.sample_trace,
        fresh_session=args.fresh_session,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
