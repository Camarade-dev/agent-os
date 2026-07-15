"""Slice 5B interactive-preview extension: deterministic acceptance tests.

These prove the read-only operator preview serves the exact eight archived
target files (hash-verified against FileEvidence), refuses everything else
(traversal, encoded traversal, absolute POSIX/Windows paths, alternate
separators, symlink escape, arbitrary repository files), disables itself when
integrity is uncertain, emits the required CSP / security headers, never mutates
the archive or creates runtime/verification evidence, and never selects a
disposition automatically. A byte-identity guard asserts the canonical archive
is untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import urllib.error
import urllib.request
from http.client import HTTPConnection
from pathlib import Path

import pytest

from admissible.review_surface.evidence_model import build_review_model
from admissible.review_surface.preview import PREVIEW_CSP
from admissible.review_surface.server import ReviewServer

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = REPO_ROOT / "_agent-runs" / "neon-serpents-live-002"

EIGHT_FILES = [
    "index.html",
    "style.css",
    "src/main.js",
    "src/game.js",
    "src/entities.js",
    "src/bots.js",
    "src/render.js",
    "LOCAL_DEV.md",
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
    assert before == after, "canonical archive was mutated by preview tests"


@pytest.fixture
def archive_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "archive"
    shutil.copytree(CANONICAL, dst)
    return dst


def _raw_get(server: ReviewServer, raw_path: str):
    """Send a request with a *raw* (unnormalized) path so encoded traversal and
    odd shapes reach the server exactly as written."""

    host, port = server.address
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.putrequest("GET", raw_path, skip_accept_encoding=True)
        conn.putheader("Host", f"{host}:{port}")
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read(), dict(resp.getheaders())
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1 & 2 & 3. index + all eight files, byte-identical, FileEvidence-verified
# ---------------------------------------------------------------------------
def test_preview_index_is_archived_index_html(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        status, body, headers = _raw_get(server, "/preview/")
        assert status == 200
        assert body == (archive_copy / "target" / "index.html").read_bytes()
        assert headers.get("Content-Type") == "text/html; charset=utf-8"


def test_all_eight_files_served_byte_identical_and_verified(archive_copy: Path):
    model = build_review_model(archive_copy)
    ev_hashes = {e["path"]: e["expected_sha256"] for e in model.facts["target_files"]}
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        for rel in EIGHT_FILES:
            status, body, _ = _raw_get(server, "/preview/" + rel)
            assert status == 200, rel
            disk = (archive_copy / "target" / rel).read_bytes()
            assert body == disk, rel
            # served bytes match the authoritative FileEvidence sha256
            assert hashlib.sha256(body).hexdigest() == ev_hashes[rel], rel


# ---------------------------------------------------------------------------
# 4. Unlisted files refused
# ---------------------------------------------------------------------------
def test_unlisted_files_refused(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        for rel in ["README.md", "manifest.json", "session.v0.json", "MANIFEST.sha256",
                    "agent/instruction.json", "runtime-store/neon-serpents-live-002.runtime.json",
                    "src/does_not_exist.js"]:
            status, _b, _h = _raw_get(server, "/preview/" + rel)
            assert status == 404, rel


# ---------------------------------------------------------------------------
# 5 & 6. traversal / encoded traversal / absolute Windows+POSIX refused
# ---------------------------------------------------------------------------
def test_traversal_and_absolute_paths_refused(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        for evil in [
            "/preview/..%2f..%2fsession.v0.json",
            "/preview/%2e%2e/manifest.json",
            "/preview/%2e%2e%2f%2e%2e%2fMANIFEST.sha256",
            "/preview/src%2f..%2f..%2fsession.v0.json",
            "/preview//etc/passwd",
            "/preview/%2fetc%2fpasswd",
            "/preview/C:%2fWindows%2fwin.ini",
            "/preview/C:\\Windows\\win.ini",
            "/preview/src%5Cmain.js",
            "/preview/..%5C..%5Csession.v0.json",
            "/preview/%00index.html",
        ]:
            status, body, _h = _raw_get(server, evil)
            assert status in (400, 404), f"{evil} -> {status}"  # refused, not served
            # never leaks target/session bytes
            assert b"batch_history" not in body and b"<!DOCTYPE html" not in body[:20]


# ---------------------------------------------------------------------------
# 7. Symlink escape refused
# ---------------------------------------------------------------------------
def test_symlink_escape_refused(archive_copy: Path):
    # Attempt to plant a symlinked target file pointing outside target/.
    secret = archive_copy.parent / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    link = archive_copy / "target" / "src" / "leak.js"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform/run")
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        # leak.js is not an allowlisted FileEvidence path -> refused regardless,
        status, body, _ = _raw_get(server, "/preview/src/leak.js")
        assert status == 404
        assert b"TOP SECRET" not in body


# ---------------------------------------------------------------------------
# 8. Preview disabled when integrity is uncertain
# ---------------------------------------------------------------------------
def test_preview_disabled_on_integrity_failure(archive_copy: Path):
    tgt = archive_copy / "target" / "src" / "game.js"
    tgt.write_bytes(tgt.read_bytes() + b"// tamper")
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        # The tampered file itself: refused as uncertain.
        status, body, headers = _raw_get(server, "/preview/src/game.js")
        assert status == 409
        payload = json.loads(body)
        assert payload["preview_disabled"] is True
        # The whole preview is gated: even a clean file is refused (archive uncertain).
        status2, _b2, _h2 = _raw_get(server, "/preview/index.html")
        assert status2 == 409
        # containment headers present even on refusal
        assert headers.get("X-Content-Type-Options") == "nosniff"


# ---------------------------------------------------------------------------
# 9. Required CSP and security headers present
# ---------------------------------------------------------------------------
def test_csp_and_security_headers_present(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        status, _b, h = _raw_get(server, "/preview/index.html")
        assert status == 200
        csp = h.get("Content-Security-Policy")
        assert csp == PREVIEW_CSP
        for token in ["default-src 'none'", "connect-src 'none'", "form-action 'none'",
                      "object-src 'none'", "frame-src 'none'", "worker-src 'none'",
                      "base-uri 'none'", "frame-ancestors 'none'"]:
            assert token in csp
        assert h.get("X-Content-Type-Options") == "nosniff"
        assert h.get("Cache-Control") == "no-store"


# ---------------------------------------------------------------------------
# 10. Preview cannot fetch arbitrary repository file
# ---------------------------------------------------------------------------
def test_preview_cannot_reach_repo_files(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        for evil in ["/preview/../../../../pyproject.toml",
                     "/preview/..%2f..%2f..%2f..%2fpyproject.toml",
                     "/preview/admissible/review_surface/server.py"]:
            status, body, _ = _raw_get(server, evil)
            assert status == 404
            assert b"build-system" not in body and b"ReviewServer" not in body


# ---------------------------------------------------------------------------
# 11, 12, 13. No mutation, no runtime result, no provider/verifier machinery
# ---------------------------------------------------------------------------
def test_preview_does_not_mutate_or_create_evidence(archive_copy: Path, tmp_path: Path):
    before = _tree_digest(archive_copy)
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        for rel in ["/preview/"] + ["/preview/" + f for f in EIGHT_FILES]:
            _raw_get(server, rel)
    after = _tree_digest(archive_copy)
    assert before == after  # target + all Slice-4/5A evidence unchanged
    # No new runtime-verification result was created anywhere.
    assert not (disp / "neon-serpents-live-002.runtime.json").exists()
    # No disposition recorded automatically.
    assert not (disp / "neon-serpents-live-002.disposition.json").exists()
    # The preview module imports no provider/verifier/executor entry points.
    import admissible.review_surface.preview as pv
    for forbidden in ["run_bounded_runtime_verification", "CursorBackend", "cursor", "execute_bounded_operations"]:
        assert not hasattr(pv, forbidden)


# ---------------------------------------------------------------------------
# 14. Terminal disposition still never selected automatically
# ---------------------------------------------------------------------------
def test_opening_preview_records_no_disposition(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        _raw_get(server, "/preview/")
        _raw_get(server, "/preview/index.html")
        # GET disposition must still report none.
        status, body, _ = _raw_get(server, "/api/disposition")
        assert status == 200
        assert json.loads(body)["disposition"] is None
    assert not server.context.store().has_disposition("neon-serpents-live-002")


def test_review_page_gates_disposition_until_preview(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "d") as server:
        status, body, _ = _raw_get(server, "/")
        page = body.decode("utf-8")
        assert status == 200
        assert "OPEN INTERACTIVE PREVIEW" in page
        assert "__previewOpened" in page  # the client-side gate exists
        assert "before recording a disposition" in page


# ---------------------------------------------------------------------------
# 15. Clean shutdown: no thread / socket / child process
# ---------------------------------------------------------------------------
def test_clean_shutdown_after_preview(archive_copy: Path, tmp_path: Path):
    server = ReviewServer(archive_copy, disposition_dir=tmp_path / "disp")
    server.start()
    url = server.url
    assert _raw_get(server, "/preview/")[0] == 200
    server.stop()
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(url + "preview/", timeout=2)
    assert server._thread is None
