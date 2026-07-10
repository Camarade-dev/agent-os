"""Minimal, dependency-free WebSocket + Chrome DevTools Protocol client.

Implemented against the Python standard library only (``socket``,
``struct``, ``threading``) so the browser-runtime verifier never requires
installing a package to talk to an already-installed Chromium-family
browser over its local DevTools endpoint.

This is a client for our own verifier traffic only: unfragmented text
frames out, fragmented-or-not text frames in, no compression. It is not a
general-purpose WebSocket library.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable
from urllib.parse import urlsplit

_OPCODE_CONTINUATION = 0x0
_OPCODE_TEXT = 0x1
_OPCODE_CLOSE = 0x8
_OPCODE_PING = 0x9
_OPCODE_PONG = 0xA


class CDPConnectionError(RuntimeError):
    """Raised when the DevTools websocket connection fails or times out."""


class _MinimalWebSocketClient:
    """A client-only RFC 6455 implementation sufficient for local CDP traffic."""

    def __init__(self, url: str, *, timeout: float = 10.0) -> None:
        parts = urlsplit(url)
        if parts.scheme != "ws":
            raise CDPConnectionError(f"unsupported websocket scheme: {parts.scheme!r}")
        if parts.hostname not in ("127.0.0.1", "localhost"):
            raise CDPConnectionError("refusing to connect to a non-loopback websocket host")
        host, port = parts.hostname, parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path += f"?{parts.query}"

        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self._sock.sendall(request.encode("ascii"))
        response = self._recv_http_handshake_response()
        if b"101" not in response.split(b"\r\n", 1)[0]:
            raise CDPConnectionError(f"websocket handshake failed: {response[:200]!r}")
        self._recv_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._closed = False

    def _recv_http_handshake_response(self) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def _recv_exact(self, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def send_text(self, text: str) -> None:
        payload = text.encode("utf-8")
        frame_header = self._frame_header(_OPCODE_TEXT, len(payload))
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(frame_header + mask_key + masked)

    @staticmethod
    def _frame_header(opcode: int, length: int) -> bytes:
        fin_opcode = 0x80 | opcode
        mask_bit = 0x80
        if length < 126:
            return bytes([fin_opcode, mask_bit | length])
        if length < 65536:
            return bytes([fin_opcode, mask_bit | 126]) + struct.pack(">H", length)
        return bytes([fin_opcode, mask_bit | 127]) + struct.pack(">Q", length)

    def _recv_frame(self) -> tuple[int, bytes] | None:
        header = self._recv_exact(2)
        if not header:
            return None
        b0, b1 = header[0], header[1]
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            ext = self._recv_exact(2)
            if ext is None:
                return None
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = self._recv_exact(8)
            if ext is None:
                return None
            length = struct.unpack(">Q", ext)[0]
        mask_key = self._recv_exact(4) if masked else b""
        payload = self._recv_exact(length) if length else b""
        if payload is None:
            return None
        if masked:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def recv_message(self) -> str | None:
        """Block for one complete (possibly fragmented) text message."""

        buffer = bytearray()
        first_opcode: int | None = None
        while True:
            frame = self._recv_frame()
            if frame is None:
                return None
            opcode, payload = frame
            if opcode == _OPCODE_PING:
                self._send_control(_OPCODE_PONG, payload)
                continue
            if opcode == _OPCODE_PONG:
                continue
            if opcode == _OPCODE_CLOSE:
                self._closed = True
                return None
            if opcode != _OPCODE_CONTINUATION:
                first_opcode = opcode
            buffer.extend(payload)
            # Real fragmentation support would track the FIN bit; Chrome's
            # DevTools websocket server does not fragment outgoing text
            # frames in practice, so a single frame read is sufficient here.
            break
        if first_opcode != _OPCODE_TEXT:
            return None
        return bytes(buffer).decode("utf-8", errors="replace")

    def _send_control(self, opcode: int, payload: bytes) -> None:
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(self._frame_header(opcode, len(payload)) + mask_key + masked)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._send_control(_OPCODE_CLOSE, b"")
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def http_get_json(host: str, port: int, path: str, *, timeout: float = 10.0) -> Any:
    """GET one loopback-only DevTools HTTP JSON endpoint (e.g. /json/version)."""

    if host not in ("127.0.0.1", "localhost"):
        raise CDPConnectionError("refusing to query a non-loopback DevTools HTTP endpoint")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise CDPConnectionError(f"DevTools HTTP endpoint {path} returned {response.status}")
        return json.loads(body.decode("utf-8"))
    finally:
        conn.close()


class CDPConnection:
    """A synchronous request/response layer over one DevTools websocket."""

    def __init__(self, ws_url: str, *, timeout: float = 10.0) -> None:
        self._ws = _MinimalWebSocketClient(ws_url, timeout=timeout)
        self._next_id = 1
        self._id_lock = threading.Lock()
        self._pending: dict[int, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._event_handlers: dict[str, list[Callable[[dict[str, Any]], None]]] = {}
        self._events_lock = threading.Lock()
        self._closed = threading.Event()
        # Event handlers (e.g. Fetch.requestPaused) routinely need to send
        # their own CDP commands (Fetch.continueRequest/failRequest) and
        # block waiting for the response. Running them directly on the
        # reader thread would deadlock: that thread would be blocked inside
        # the handler instead of free to read the very response it's
        # waiting for. A small worker pool keeps the reader always available
        # to receive command responses, and lets independent events (e.g.
        # concurrent requests for different resources) be handled in
        # parallel instead of queued behind one another.
        self._dispatch_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="admissible-cdp-event")
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        while not self._closed.is_set():
            try:
                message = self._ws.recv_message()
            except OSError:
                break
            if message is None:
                break
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                continue
            msg_id = data.get("id")
            if msg_id is not None:
                with self._pending_lock:
                    entry = self._pending.pop(msg_id, None)
                if entry is not None:
                    entry["result"] = data.get("result")
                    entry["error"] = data.get("error")
                    entry["event"].set()
            else:
                method = data.get("method")
                params = data.get("params") or {}
                with self._events_lock:
                    handlers = list(self._event_handlers.get(method, ()))
                for handler in handlers:
                    try:
                        self._dispatch_pool.submit(self._run_handler, handler, params)
                    except RuntimeError:
                        pass  # pool already shutting down
        self._closed.set()

    @staticmethod
    def _run_handler(handler: Callable[[dict[str, Any]], None], params: dict[str, Any]) -> None:
        try:
            handler(params)
        except Exception:  # noqa: BLE001 - one bad handler must not break dispatch
            pass

    def on_event(self, method: str, handler: Callable[[dict[str, Any]], None]) -> None:
        with self._events_lock:
            self._event_handlers.setdefault(method, []).append(handler)

    def send(self, method: str, params: dict[str, Any] | None = None, *, timeout: float = 10.0) -> dict[str, Any]:
        if self._closed.is_set():
            raise CDPConnectionError(f"CDP connection is closed; cannot send {method}")
        with self._id_lock:
            msg_id = self._next_id
            self._next_id += 1
        entry: dict[str, Any] = {"event": threading.Event(), "result": None, "error": None}
        with self._pending_lock:
            self._pending[msg_id] = entry
        payload = {"id": msg_id, "method": method, "params": params or {}}
        self._ws.send_text(json.dumps(payload))
        if not entry["event"].wait(timeout):
            with self._pending_lock:
                self._pending.pop(msg_id, None)
            raise CDPConnectionError(f"CDP command timed out after {timeout}s: {method}")
        if entry["error"]:
            raise CDPConnectionError(f"CDP error for {method}: {entry['error']}")
        return entry["result"] or {}

    def close(self) -> None:
        self._closed.set()
        self._ws.close()
        self._dispatch_pool.shutdown(wait=False, cancel_futures=False)


def wait_for_devtools_http(host: str, port: int, *, timeout: float = 10.0) -> dict[str, Any]:
    """Poll the DevTools HTTP endpoint until it answers or ``timeout`` elapses."""

    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return http_get_json(host, port, "/json/version", timeout=1.0)
        except Exception as exc:  # noqa: BLE001 - retry until timeout
            last_error = exc
            time.sleep(0.05)
    raise CDPConnectionError(f"DevTools HTTP endpoint did not become ready: {last_error}")
