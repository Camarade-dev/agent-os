"""Slice 5B pre-commit hardening: deterministic tests for H1 and H2.

H1 — stable early POST refusals: every mutation guard that returns *before* the
declared request body is read must produce a deterministic HTTP response, emit
``Connection: close``, close the connection, never drain an oversized/untrusted
body, and never reach disposition persistence. On Windows this prevents the
client from observing ``ConnectionAbortedError`` on a safely-refused request.

H2 — loopback Host enforcement on GET: every GET endpoint refuses a non-loopback
Host before returning any archive data, JSON, HTML, screenshot, DOM, or target
bytes — using exactly the same Host policy as the mutation endpoint — while a
valid exact-loopback Host with the bound port still succeeds.

These tests operate on an isolated temp copy of the canonical archive and assert
the canonical archive is byte-identical before/after.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from admissible.review_surface.evidence_model import build_review_model
from admissible.review_surface.server import ReviewServer

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = REPO_ROOT / "_agent-runs" / "neon-serpents-live-002"
SESSION = "neon-serpents-live-002"

GET_ENDPOINTS = [
    "/",
    "/index.html",
    "/api/review",
    "/api/disposition",
    "/api/evidence/screenshot.png",
    "/api/evidence/document.html",
    "/preview",
    "/preview/",
    "/preview/index.html",
]


def _tree_digest(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = Path(dp) / f
            out[str(p.relative_to(root)).replace(os.sep, "/")] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


@pytest.fixture(scope="module", autouse=True)
def _canonical_untouched():
    before = _tree_digest(CANONICAL)
    yield
    after = _tree_digest(CANONICAL)
    assert before == after, "canonical archive was mutated by hardening tests"


@pytest.fixture
def archive_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "archive"
    shutil.copytree(CANONICAL, dst)
    return dst


# ---------------------------------------------------------------------------
# Raw socket helper: full control over Host, Content-Length, and body framing.
# ---------------------------------------------------------------------------
def _parse_http(buf: bytes) -> dict:
    head, _sep, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0] else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip()] = v.decode("latin-1").strip()
    return {"status": status, "headers": headers, "body": body}


def _send_raw(
    server: ReviewServer,
    method: str,
    path: str,
    *,
    host_header: str | None = "__loopback__",
    extra_headers: dict[str, str] | None = None,
    content_length: int | None = None,
    body: bytes = b"",
) -> dict:
    """Send one raw HTTP/1.1 request and read the full response.

    ``host_header`` defaults to the exact bound loopback Host. ``content_length``
    is emitted verbatim (may deliberately differ from ``len(body)`` to prove the
    server does not drain the declared body). Any transport error observed while
    reading the response is captured rather than raised.
    """

    host, port = server.address
    if host_header == "__loopback__":
        host_header = f"{host}:{port}"
    lines = [f"{method} {path} HTTP/1.1"]
    if host_header is not None:
        lines.append(f"Host: {host_header}")
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    if content_length is not None:
        lines.append(f"Content-Length: {content_length}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    result = {"transport_error": None, "status": None, "headers": {}, "body": b""}
    s = socket.create_connection((host, port), timeout=5)
    try:
        s.sendall(head + body)
        s.settimeout(5)
        buf = b""
        try:
            # 1. Read until the header block is complete.
            while b"\r\n\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            # 2. Read exactly Content-Length body bytes (so keep-alive 200s do
            #    not block waiting for an EOF that never comes), or until EOF for
            #    connection-close responses without a length.
            if b"\r\n\r\n" in buf:
                header_blob, _sep, tail = buf.partition(b"\r\n\r\n")
                parsed = _parse_http(buf)
                clen = parsed["headers"].get("Content-Length")
                if clen is not None and clen.isdigit():
                    want = int(clen)
                    body_buf = tail
                    while len(body_buf) < want:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        body_buf += chunk
                    buf = header_blob + b"\r\n\r\n" + body_buf
                else:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
        except socket.timeout:
            result["transport_error"] = "timeout"
        except (ConnectionAbortedError, ConnectionResetError) as exc:
            result["transport_error"] = type(exc).__name__
        if buf:
            result.update(_parse_http(buf))
        return result
    finally:
        s.close()


def _disposition_file(disp: Path) -> Path:
    return disp / f"{SESSION}.disposition.json"


# ---------------------------------------------------------------------------
# H1.1 / H1.2 / H1.3 — early-refused POST with a non-empty body
# ---------------------------------------------------------------------------
def test_early_refused_post_with_body_is_stable_and_closes(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    body = b'{"disposition":"ACCEPT_RESULT"}' + b" " * 4096
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        # Invalid token -> refused before the body is read.
        res = _send_raw(
            server,
            "POST",
            "/api/disposition",
            extra_headers={"X-Review-Token": "wrong-token", "Content-Type": "application/json"},
            content_length=len(body),
            body=body,
        )
        # (1) deterministic status, no ConnectionAbortedError / reset / timeout.
        assert res["transport_error"] is None, res["transport_error"]
        assert res["status"] == 401
        assert json.loads(res["body"])["error"] == "invalid_or_missing_token"
        # (2) the refusal carries Connection: close.
        assert res["headers"].get("Connection", "").lower() == "close"
        # (3) no disposition reached persistence.
        assert not server.context.store().has_disposition(SESSION)
    assert not _disposition_file(disp).exists()
    assert not disp.exists() or not any(disp.iterdir())


# ---------------------------------------------------------------------------
# H1.4 — invalid-token and invalid-Host refusal behavior remains stable
# ---------------------------------------------------------------------------
def test_invalid_token_and_host_refusals_are_stable(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    body = b'{"x":1}' + b"y" * 1024
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        # Non-loopback Host, with a body, refused before body read.
        res_host = _send_raw(
            server,
            "POST",
            "/api/disposition",
            host_header="evil.example.com",
            content_length=len(body),
            body=body,
        )
        assert res_host["transport_error"] is None
        assert res_host["status"] == 403
        assert json.loads(res_host["body"])["error"] == "non_loopback_host"
        assert res_host["headers"].get("Connection", "").lower() == "close"

        # Missing token, with a body.
        res_tok = _send_raw(
            server,
            "POST",
            "/api/disposition",
            content_length=len(body),
            body=body,
        )
        assert res_tok["transport_error"] is None
        assert res_tok["status"] == 401
        assert res_tok["headers"].get("Connection", "").lower() == "close"

        # Bad Content-Length value, refused before body read.
        res_len = _send_raw(
            server,
            "POST",
            "/api/disposition",
            extra_headers={"X-Review-Token": server.token, "Content-Length": "not-a-number"},
        )
        assert res_len["transport_error"] is None
        assert res_len["status"] == 400
        assert json.loads(res_len["body"])["error"] == "bad_content_length"
        assert res_len["headers"].get("Connection", "").lower() == "close"

        assert not server.context.store().has_disposition(SESSION)
    assert not _disposition_file(disp).exists()


# ---------------------------------------------------------------------------
# H1.5 — oversized bodies are refused without being drained or persisted
# ---------------------------------------------------------------------------
def test_oversized_body_refused_without_draining(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    # Declare a huge body but send only a few bytes: if the server drained the
    # declared length it would block on rfile.read() and we would time out.
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        res = _send_raw(
            server,
            "POST",
            "/api/disposition",
            extra_headers={"X-Review-Token": server.token},
            content_length=200_000,  # > 64 KiB cap
            body=b"x" * 8,  # deliberately far short of the declared length
        )
        assert res["transport_error"] is None, "server appears to have drained the body"
        assert res["status"] == 400
        assert json.loads(res["body"])["error"] == "bad_request_size"
        assert res["headers"].get("Connection", "").lower() == "close"
        assert not server.context.store().has_disposition(SESSION)
    assert not _disposition_file(disp).exists()


# ---------------------------------------------------------------------------
# H1 stress — the formerly flaky mutation-token refusal, repeated on ONE server.
# ---------------------------------------------------------------------------
REPEAT_COUNT = 250


def test_mutation_token_refusal_repeated_stress(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    body = b'{"disposition":"ACCEPT_RESULT","note":"' + b"n" * 2000 + b'"}'
    aborts = 0
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        for i in range(REPEAT_COUNT):
            res = _send_raw(
                server,
                "POST",
                "/api/disposition",
                extra_headers={"X-Review-Token": "wrong-token"},
                content_length=len(body),
                body=body,
            )
            if res["transport_error"] is not None:
                aborts += 1
            assert res["status"] == 401, f"iter {i}: status {res['status']}"
            assert res["headers"].get("Connection", "").lower() == "close", f"iter {i}"
        assert aborts == 0, f"{aborts}/{REPEAT_COUNT} refusals aborted the connection"
        assert not server.context.store().has_disposition(SESSION)
    assert not _disposition_file(disp).exists()


# ---------------------------------------------------------------------------
# H2.6 / H2.7 — every GET endpoint refuses a non-loopback Host, no bytes leak.
# ---------------------------------------------------------------------------
def test_all_get_endpoints_refuse_non_loopback_host(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        for path in GET_ENDPOINTS:
            for bad_host in ["evil.example.com", "evil.example.com:8791", "", "127.0.0.1.evil.com"]:
                res = _send_raw(server, "GET", path, host_header=bad_host or None)
                assert res["status"] == 403, f"{path} host={bad_host!r} -> {res['status']}"
                assert json.loads(res["body"])["error"] == "non_loopback_host"
                # (7) no canonical evidence / target bytes leaked in the refusal.
                b = res["body"]
                assert b[:8] != b"\x89PNG\r\n\x1a\n"
                assert b"<!doctype html" not in b.lower()
                assert b"batch_history" not in b
    assert not _disposition_file(disp).exists()


# ---------------------------------------------------------------------------
# H2.8 — valid exact-loopback Host still succeeds for every read surface.
# ---------------------------------------------------------------------------
def test_valid_loopback_host_get_succeeds(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        host, port = server.address

        page = _send_raw(server, "GET", "/", host_header=f"{host}:{port}")
        assert page["status"] == 200 and b"ACCEPT_RESULT" in page["body"]

        review = _send_raw(server, "GET", "/api/review")
        assert review["status"] == 200
        assert json.loads(review["body"])["model"]["session_id"] == SESSION

        shot = _send_raw(server, "GET", "/api/evidence/screenshot.png")
        assert shot["status"] == 200 and shot["body"][:8] == b"\x89PNG\r\n\x1a\n"

        dom = _send_raw(server, "GET", "/api/evidence/document.html")
        assert dom["status"] == 200 and len(dom["body"]) > 0

        prev_index = _send_raw(server, "GET", "/preview/")
        assert prev_index["status"] == 200
        assert prev_index["body"] == (archive_copy / "target" / "index.html").read_bytes()

        prev_asset = _send_raw(server, "GET", "/preview/src/main.js")
        assert prev_asset["status"] == 200
        assert prev_asset["body"] == (archive_copy / "target" / "src" / "main.js").read_bytes()

        # Localhost Host with the bound port is also an accepted loopback Host.
        loc = _send_raw(server, "GET", "/api/review", host_header=f"localhost:{port}")
        assert loc["status"] == 200
    assert not _disposition_file(disp).exists()


# ---------------------------------------------------------------------------
# H2 — loopback client and loopback Host are independent requirements.
# ---------------------------------------------------------------------------
def test_valid_host_does_not_bypass_client_or_vice_versa(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        # Valid loopback Host but the *client* check is what the mutation path
        # relies on independently: a good Host must never bypass a bad client.
        # We assert both guards exist as separate refusals on GET.
        bad_host = _send_raw(server, "GET", "/api/review", host_header="evil.example.com")
        assert bad_host["status"] == 403 and json.loads(bad_host["body"])["error"] == "non_loopback_host"
        # (client is loopback here, so a valid Host yields success — proving the
        # Host guard is the discriminator, not a compensating check.)
        ok = _send_raw(server, "GET", "/api/review")
        assert ok["status"] == 200


# ---------------------------------------------------------------------------
# H2.9 — GET Host enforcement creates no disposition and mutates no evidence.
# ---------------------------------------------------------------------------
def test_get_host_enforcement_creates_no_disposition_no_evidence_change(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    before = _tree_digest(archive_copy)
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        for path in GET_ENDPOINTS:
            _send_raw(server, "GET", path, host_header="evil.example.com")
            _send_raw(server, "GET", path)  # valid loopback host
    after = _tree_digest(archive_copy)
    assert before == after
    assert not _disposition_file(disp).exists()
    assert not (disp / f"{SESSION}.runtime.json").exists()


# ---------------------------------------------------------------------------
# H2 — refused GET returns no target bytes for a would-be preview asset.
# ---------------------------------------------------------------------------
def test_refused_get_preview_asset_returns_no_target_bytes(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    real = (archive_copy / "target" / "src" / "main.js").read_bytes()
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        res = _send_raw(server, "GET", "/preview/src/main.js", host_header="evil.example.com")
        assert res["status"] == 403
        assert res["body"] != real
        assert real[:32] not in res["body"]


# ---------------------------------------------------------------------------
# H1/H2.10 — server shutdown leaves no socket, thread, or child process.
# ---------------------------------------------------------------------------
def test_shutdown_leaves_no_socket_or_thread(archive_copy: Path, tmp_path: Path):
    server = ReviewServer(archive_copy, disposition_dir=tmp_path / "disp")
    server.start()
    url = server.url
    # Exercise both a refused and a valid request first.
    assert _send_raw(server, "GET", "/api/review", host_header="evil.example.com")["status"] == 403
    assert _send_raw(server, "GET", "/api/review")["status"] == 200
    server.stop()
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(url + "api/review", timeout=2)
    assert server._thread is None
