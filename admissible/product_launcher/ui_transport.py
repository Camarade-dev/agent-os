"""Browser-facing loopback transport for the G2.5 product launcher."""
from __future__ import annotations

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import json
import re
import secrets
import threading
from typing import Any, Callable
from urllib.parse import urlsplit

from admissible.product_launcher.configuration import LOOPBACK_HOST

UI_API_PREFIX = "/ui/api/v1"
CSRF_HEADER = "X-Admissible-UI-CSRF"
OWNER_HEADER = "X-Admissible-Owner-Authorization"
DIGEST_HEADER = "X-Admissible-Owner-Authorization-Digest"
G2_TOKEN_HEADER = "X-Admissible-Control-Token"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_ERROR_BYTES = 4096
# Header values are parsed from wire bytes as Latin-1, so string length equals
# physical wire byte count for the bound below.
MAX_OWNER_PHRASE_BYTES = 4096
_DECIMAL_LENGTH = re.compile(r"[0-9]+")
SERVICE_NAME = "admissible-product-launcher"
SERVICE_VERSION = "g2.5"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate")
        out[key] = value
    return out


SHELL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Admissible Product Launcher</title>
<meta name="admissible-ui-csrf" content="{csrf}">
<meta name="admissible-authorization-mode" content="{mode}">
<script>
window.__ADMISSIBLE_PRODUCT_LAUNCHER__ = {{
  csrf: {csrf_json},
  authorization_mode: {mode_json},
  visual_ui_available: false
}};
</script>
</head>
<body>
<main>
<h1>Admissible Product Launcher</h1>
<p>Visual Compose/Contract/Authorize interface is not installed in G2.5.</p>
</main>
</body>
</html>
"""


class UIRequestContext:
    """Mutable per-launcher API surface consumed by the UI HTTP handler."""

    def __init__(self, launcher: object):
        self.launcher = launcher


class _UIServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], context: UIRequestContext, csrf_nonce: str):
        self.context = context
        self.csrf_nonce = csrf_nonce
        super().__init__(address, _UIHandler)


class _UIHandler(BaseHTTPRequestHandler):
    server: _UIServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        return

    def _send(self, status: int, payload: object, *, content_type: str = "application/json") -> None:
        if content_type == "application/json":
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        else:
            body = payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, **extra: object) -> None:
        payload: dict[str, object] = {"error": code}
        payload.update(extra)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_ERROR_BYTES:
            payload = {"error": code}
        # A rejected request may leave an unread body; never let those bytes be
        # parsed as a follow-up pipelined request.
        self.close_connection = True
        self._send(status, payload)

    def _all_headers(self, name: str) -> list[str]:
        values = self.headers.get_all(name)
        return list(values) if values is not None else []

    def _host_ok(self) -> bool:
        hosts = self._all_headers("Host")
        expected = f"{LOOPBACK_HOST}:{self.server.server_port}"
        if len(hosts) != 1 or hosts[0] != expected:
            self._error(403, "INVALID_HOST")
            return False
        return True

    def _origin_ok(self, *, mutating: bool) -> bool:
        origins = self._all_headers("Origin")
        if not origins:
            return True
        expected = f"http://{LOOPBACK_HOST}:{self.server.server_port}"
        if len(origins) != 1 or origins[0] != expected:
            self._error(403, "INVALID_ORIGIN")
            return False
        return True

    def _csrf_ok(self) -> bool:
        supplied = self._all_headers(CSRF_HEADER)
        if len(supplied) != 1:
            self._error(403, "INVALID_CSRF")
            return False
        if not hmac.compare_digest(
            supplied[0].encode("utf-8"), self.server.csrf_nonce.encode("utf-8")
        ):
            self._error(403, "INVALID_CSRF")
            return False
        return True

    def _framed_length(self) -> int | None:
        if self._all_headers("Transfer-Encoding"):
            self._error(400, "UNBOUNDED_BODY")
            return None
        lengths = self._all_headers("Content-Length")
        if not lengths:
            self._error(411, "CONTENT_LENGTH_REQUIRED")
            return None
        if len(lengths) != 1:
            self._error(400, "CONTENT_LENGTH_INVALID")
            return None
        if not _DECIMAL_LENGTH.fullmatch(lengths[0]):
            self._error(400, "CONTENT_LENGTH_INVALID")
            return None
        length = int(lengths[0])
        if length > MAX_REQUEST_BYTES:
            self._error(413, "BODY_TOO_LARGE")
            return None
        return length

    def _read_body_object(self) -> dict[str, Any] | None:
        if self.headers.get("Content-Type") != "application/json":
            self._error(415, "JSON_REQUIRED")
            return None
        length = self._framed_length()
        if length is None:
            return None
        try:
            obj = json.loads(self.rfile.read(length).decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._error(400, "INVALID_JSON")
            return None
        if not isinstance(obj, dict):
            self._error(400, "JSON_OBJECT_REQUIRED")
            return None
        return obj

    def _json(self, fields: set[str]) -> dict[str, Any] | None:
        obj = self._read_body_object()
        if obj is None:
            return None
        if set(obj) != fields:
            self._error(400, "INVALID_FIELDS")
            return None
        return obj

    def _mutating_guards(self) -> bool:
        return self._host_ok() and self._origin_ok(mutating=True) and self._csrf_ok()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        launcher = self.server.context.launcher
        if path == "/":
            if not self._host_ok() or not self._origin_ok(mutating=False):
                return
            html = SHELL_HTML.format(
                csrf=self.server.csrf_nonce,
                mode=getattr(launcher, "authorization_mode"),
                csrf_json=json.dumps(self.server.csrf_nonce),
                mode_json=json.dumps(getattr(launcher, "authorization_mode")),
            )
            self._send(200, html.encode("utf-8"), content_type="text/html; charset=utf-8")
            return
        if not path.startswith(UI_API_PREFIX + "/") and path != UI_API_PREFIX:
            self._error(404, "NOT_FOUND")
            return
        if not self._host_ok() or not self._origin_ok(mutating=False):
            return
        if path == UI_API_PREFIX + "/bootstrap":
            self._send(200, launcher.bootstrap(self.server.csrf_nonce))
            return
        parts = path.split("/")
        try:
            if len(parts) == 6 and parts[4] == "preparations" and parts[5]:
                self._send(200, launcher.preparation_status(parts[5]))
                return
            if path == UI_API_PREFIX + "/runs":
                status, body = launcher.proxy_g2("GET", "/api/v1/runs")
                self._send(status, body)
                return
            if len(parts) == 6 and parts[4] == "runs" and parts[5]:
                status, body = launcher.proxy_g2("GET", f"/api/v1/runs/{parts[5]}")
                self._send(status, body)
                return
            if len(parts) == 7 and parts[4] == "runs" and parts[5] and parts[6] == "result":
                status, body = launcher.proxy_g2("GET", f"/api/v1/runs/{parts[5]}/result")
                self._send(status, body)
                return
        except KeyError:
            self._error(404, "NOT_FOUND")
            return
        except Exception:
            self._error(500, "READ_UNAVAILABLE")
            return
        self._error(404, "NOT_FOUND")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if not path.startswith(UI_API_PREFIX + "/"):
            self._error(404, "NOT_FOUND")
            return
        if not self._mutating_guards():
            return
        launcher = self.server.context.launcher
        phrase = None
        digest = None
        try:
            if path == UI_API_PREFIX + "/contracts":
                # Authoring accepts a bounded object; field set validated in authoring.
                body = self._read_authoring_body()
                if body is None:
                    return
                status, payload = launcher.author_and_validate(body)
                self._send(status, payload)
                return
            parts = path.split("/")
            if (
                len(parts) == 7
                and parts[4] == "contracts"
                and parts[5]
                and parts[6] == "preparations"
            ):
                body = self._json(set())
                if body is None:
                    return
                status, payload = launcher.enqueue_preparation(parts[5])
                self._send(status, payload)
                return
            if path == UI_API_PREFIX + "/runs":
                body = self._json({"contract_id", "preparation_id"})
                if body is None:
                    return
                phrases = self._all_headers(OWNER_HEADER)
                if not phrases:
                    self._error(400, "OWNER_AUTHORIZATION_REQUIRED")
                    return
                if len(phrases) != 1 or len(phrases[0]) > MAX_OWNER_PHRASE_BYTES:
                    self._error(400, "OWNER_AUTHORIZATION_INVALID")
                    return
                phrase = phrases[0]
                digests = self._all_headers(DIGEST_HEADER)
                if len(digests) > 1:
                    self._error(400, "OWNER_AUTHORIZATION_DIGEST_INVALID")
                    return
                if digests:
                    digest = digests[0]
                status, payload = launcher.launch_run(
                    contract_id=body["contract_id"],
                    preparation_id=body["preparation_id"],
                    owner_authorization=phrase,
                    owner_authorization_digest=digest,
                )
                self._send(status, payload)
                return
        except Exception:
            self._error(500, "WRITE_UNAVAILABLE")
            return
        finally:
            phrase = None
            digest = None
        self._error(404, "NOT_FOUND")

    def _read_authoring_body(self) -> dict[str, Any] | None:
        return self._read_body_object()

    def do_PUT(self) -> None:
        self._error(405, "METHOD_NOT_ALLOWED")

    def do_PATCH(self) -> None:
        self._error(405, "METHOD_NOT_ALLOWED")

    def do_DELETE(self) -> None:
        self._error(405, "METHOD_NOT_ALLOWED")


class UILoopbackServer:
    def __init__(self, server: _UIServer):
        self._server = server
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return LOOPBACK_HOST

    @property
    def port(self) -> int:
        return self._server.server_port

    @property
    def csrf_nonce(self) -> str:
        return self._server.csrf_nonce

    def start(self) -> "UILoopbackServer":
        if self._thread is not None:
            raise RuntimeError("already started")
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="admissible-g2-5-ui-http",
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join()
            self._thread = None
        self._server.server_close()


def create_ui_loopback_server(
    launcher: object,
    *,
    host: str = LOOPBACK_HOST,
    port: int = 0,
    csrf_generator: Callable[[int], str] | None = None,
) -> UILoopbackServer:
    if host != LOOPBACK_HOST:
        raise ValueError("only exact IPv4 loopback is permitted")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("invalid port")
    generator = csrf_generator or (lambda nbytes: secrets.token_hex(max(nbytes, 32)))
    nonce = generator(32)
    if not isinstance(nonce, str) or len(nonce.encode("utf-8")) < 32:
        raise ValueError("csrf nonce too short")
    # Require at least 256 bits of encoded entropy material in the hex form.
    if len(nonce) < 64:
        # token_hex(32) yields 64 hex chars = 256 bits; reject shorter generators.
        raise ValueError("csrf nonce entropy below 256 bits")
    context = UIRequestContext(launcher)
    return UILoopbackServer(_UIServer((host, port), context, nonce))


def proxy_http(
    *,
    host: str,
    port: int,
    method: str,
    path: str,
    token: str,
    body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any]]:
    headers = {
        G2_TOKEN_HEADER: token,
        "Host": f"{host}:{port}",
    }
    data = None
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
    if extra_headers:
        headers.update(extra_headers)
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        try:
            parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            parsed = {"error": "UPSTREAM_INVALID_JSON"}
        if not isinstance(parsed, dict):
            parsed = {"error": "UPSTREAM_INVALID_JSON"}
        return response.status, parsed
    finally:
        connection.close()
        if extra_headers:
            for key in list(extra_headers):
                extra_headers[key] = ""


__all__ = [
    "CSRF_HEADER",
    "DIGEST_HEADER",
    "OWNER_HEADER",
    "SERVICE_NAME",
    "SERVICE_VERSION",
    "UI_API_PREFIX",
    "UILoopbackServer",
    "create_ui_loopback_server",
    "proxy_http",
]
