"""Locked local loopback workspace server (PART C).

A read-only HTTP server dedicated to exactly one verification session: it
binds only to 127.0.0.1 on an OS-assigned port, serves only GET/HEAD,
requires an unguessable per-session route token, refuses to leave the
authorized workspace root (no traversal, no symlink escape, no hidden
Admissible state), never lists directories, and is torn down at the end of
the session. It is not exposed publicly and never kept alive afterward.
"""

from __future__ import annotations

import mimetypes
import os
import secrets
import socket
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

MAX_SERVED_FILE_BYTES = 8 * 1024 * 1024
MAX_REQUESTS_PER_SESSION = 2_000
MAX_REQUEST_LOG_ENTRIES = 500

_DENIED_PATH_PREFIXES = (".git", ".admissible", ".hg", ".svn")

_MIME_OVERRIDES = {
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".wasm": "application/wasm",
    ".map": "application/json; charset=utf-8",
}

_CSP = (
    "default-src 'self' data: blob:; "
    "connect-src 'self'; "
    "img-src 'self' data: blob:; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WorkspaceTraversalError(ValueError):
    """Raised when a request path would escape the authorized workspace root."""


def resolve_workspace_request_path(workspace_root: Path, raw_path: str) -> Path:
    """Resolve one request path inside ``workspace_root`` or raise.

    Rejects absolute paths, ``..`` segments (encoded or not), backslashes
    used as alternate separators, hidden Admissible/VCS state, and any
    symlink/junction whose real target escapes the root.
    """

    if "\\" in raw_path or "%5c" in raw_path.lower():
        raise WorkspaceTraversalError("alternate path separators are not allowed")
    decoded = unquote(raw_path)
    if "\\" in decoded:
        raise WorkspaceTraversalError("alternate path separators are not allowed")
    segments = [seg for seg in decoded.split("/") if seg not in ("", ".")]
    for seg in segments:
        if seg == ".." or seg.startswith(".."):
            raise WorkspaceTraversalError("path traversal is not allowed")
        if seg.lower() in _DENIED_PATH_PREFIXES:
            raise WorkspaceTraversalError(f"hidden or verifier-owned path is not servable: {seg}")

    root_real = Path(os.path.realpath(str(workspace_root)))
    candidate = root_real.joinpath(*segments) if segments else root_real
    if candidate.is_dir():
        candidate = candidate / "index.html"

    real_target = Path(os.path.realpath(str(candidate)))
    try:
        real_target.relative_to(root_real)
    except ValueError:
        raise WorkspaceTraversalError("resolved path escapes the workspace root") from None
    return real_target


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AdmissibleRuntimeVerifier/1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return None  # request logging happens via structured request_log instead

    def _deny_host(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        return host not in ("127.0.0.1", "localhost", "")

    def _log(self, *, status: int, reason: str = "") -> None:
        server: LoopbackWorkspaceServer = self.server  # type: ignore[assignment]
        with server.lock:
            if len(server.request_log) < MAX_REQUEST_LOG_ENTRIES:
                server.request_log.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "status": status,
                        "reason": reason,
                        "timestamp": _now_iso(),
                    }
                )
            server.request_count += 1

    def _reject(self, status: HTTPStatus, reason: str) -> None:
        self._log(status=int(status), reason=reason)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self._send_defensive_headers()
        self.end_headers()

    def _send_defensive_headers(self) -> None:
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")

    def _serve(self, *, send_body: bool) -> None:
        server: LoopbackWorkspaceServer = self.server  # type: ignore[assignment]
        if server.request_count >= MAX_REQUESTS_PER_SESSION:
            self._reject(HTTPStatus.TOO_MANY_REQUESTS, "request_count_exceeded")
            return
        if self._deny_host():
            self._reject(HTTPStatus.FORBIDDEN, "non_loopback_host_rejected")
            return

        parts = urlsplit(self.path)
        path = parts.path
        prefix = f"/{server.token}"
        if not (path == prefix or path.startswith(prefix + "/")):
            self._reject(HTTPStatus.NOT_FOUND, "missing_or_invalid_route_token")
            return
        remainder = path[len(prefix):].lstrip("/")

        try:
            target = resolve_workspace_request_path(server.workspace_root, remainder)
        except WorkspaceTraversalError as exc:
            self._reject(HTTPStatus.FORBIDDEN, str(exc))
            return

        if not target.is_file():
            self._reject(HTTPStatus.NOT_FOUND, "not_found")
            return

        size = target.stat().st_size
        if size > MAX_SERVED_FILE_BYTES:
            self._reject(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "file_exceeds_max_served_bytes")
            return

        content_type = _MIME_OVERRIDES.get(target.suffix.lower())
        if content_type is None:
            guessed, _ = mimetypes.guess_type(str(target))
            content_type = guessed or "application/octet-stream"

        body = target.read_bytes() if send_body else b""
        self._log(status=200)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self._send_defensive_headers()
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        self._serve(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib method name
        self._serve(send_body=False)

    def _reject_method(self) -> None:
        self._reject(HTTPStatus.METHOD_NOT_ALLOWED, "unsupported_http_method")

    do_POST = _reject_method
    do_PUT = _reject_method
    do_DELETE = _reject_method
    do_PATCH = _reject_method
    do_OPTIONS = _reject_method
    do_CONNECT = _reject_method
    do_TRACE = _reject_method


class LoopbackWorkspaceServer(ThreadingHTTPServer):
    """A loopback-only, single-session, read-only workspace HTTP server.

    Threaded (one thread per connection): a browser routinely opens several
    concurrent HTTP/1.1 keep-alive connections per origin (document,
    stylesheet, script, ...). A single-threaded server would block its one
    accept loop inside the first persistent connection's keep-alive read,
    starving the others until they time out.
    """

    allow_reuse_address = False
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A browser dropping a connection mid-response (e.g. navigating away,
        # or the verifier tearing down the session) is expected traffic, not
        # a server fault; do not spam stderr with a traceback for it.
        import sys as _sys

        exc_type = _sys.exc_info()[0]
        if exc_type in (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return
        super().handle_error(request, client_address)

    def __init__(self, workspace_root: Path) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.workspace_root = Path(os.path.realpath(str(workspace_root)))
        self.token = secrets.token_urlsafe(24)
        self.request_log: list[dict[str, Any]] = []
        self.request_count = 0
        self.lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def origin(self) -> str:
        host, port = self.server_address[:2]
        return f"http://127.0.0.1:{port}"

    def url_for(self, relative_path: str = "", query: str = "") -> str:
        rel = relative_path.lstrip("/")
        url = f"{self.origin}/{self.token}"
        if rel:
            url += f"/{rel}"
        if query:
            url += f"?{query}"
        return url

    def start(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    def stop(self) -> dict[str, Any]:
        try:
            self.shutdown()
        except Exception:  # noqa: BLE001 - best-effort shutdown
            pass
        try:
            self.server_close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        return {"stopped": True, "requests_served": self.request_count}
