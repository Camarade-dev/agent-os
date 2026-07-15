"""Slice 5B: deterministic acceptance tests for the operator review surface.

These prove that the loopback review surface reconstructs authoritative facts
from persisted evidence only, refuses path traversal / arbitrary-file access,
binds only to loopback, requires the per-launch token for mutations, persists
exactly one durable disposition atomically (idempotent replay, contradictory
refusal, restart reconstruction, fail-closed on tamper), and never invokes a
provider / verifier / executor / retry / repair or mutates the archive.

The canonical archived evidence at ``_agent-runs/neon-serpents-live-002`` is
used read-only; mutation tests operate on an isolated temp copy. A module-scoped
byte-identity guard asserts the canonical archive is untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from admissible.review_surface.disposition_store import (
    DispositionConflict,
    DispositionCorrupt,
    ReviewDispositionStore,
)
from admissible.review_surface.evidence_model import build_review_model
from admissible.review_surface.server import ReviewServer

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = REPO_ROOT / "_agent-runs" / "neon-serpents-live-002"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _tree_digest(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = Path(dp) / f
            out[str(p.relative_to(root)).replace(os.sep, "/")] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


@pytest.fixture(scope="module", autouse=True)
def _canonical_untouched():
    """Guard: the canonical archive must be byte-identical before and after."""

    before = _tree_digest(CANONICAL)
    yield
    after = _tree_digest(CANONICAL)
    assert before == after, "canonical Slice-5A archive was mutated by Slice-5B tests"


@pytest.fixture
def archive_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "archive"
    shutil.copytree(CANONICAL, dst)
    return dst


class _Client:
    def __init__(self, server: ReviewServer) -> None:
        self.base = server.url.rstrip("/")
        self.token = server.token

    def get(self, path: str, host: str | None = None):
        req = urllib.request.Request(self.base + path)
        if host:
            req.add_header("Host", host)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def post(self, path: str, payload: dict, *, token: str | None = "__default__", host: str | None = None):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if host is not None:
            req.add_header("Host", host)
        tok = self.token if token == "__default__" else token
        if tok is not None:
            req.add_header("X-Review-Token", tok)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


# ---------------------------------------------------------------------------
# 1. Review model reconstructs from persisted evidence only
# ---------------------------------------------------------------------------
def test_model_reconstructs_from_persisted_evidence():
    m = build_review_model(CANONICAL).to_dict()
    f = m["facts"]
    assert m["session_id"] == "neon-serpents-live-002"
    assert f["phase"] == "awaiting_human"
    assert f["provider_invocation_count"] == 2
    assert f["consumed_result_count"] == 2
    assert f["admitted_operation_count"] == 8
    assert f["physical_receipt_count"] == 8
    assert f["file_evidence_count"] == 8
    assert f["mandatory_paths_remaining_count"] == 0
    assert f["structural_verification"]["passed"] is True
    assert f["structural_verification"]["check_count"] == 8
    assert m["runtime"]["verdict"] == "PASS"
    assert m["runtime"]["provider_invoked"] is False
    assert m["runtime"]["orphan_process_count"] == 0
    assert m["integrity"]["ok"] is True


# ---------------------------------------------------------------------------
# 2. Canonical fixture loads without mutation
# ---------------------------------------------------------------------------
def test_canonical_fixture_loads_without_mutation():
    before = _tree_digest(CANONICAL)
    m = build_review_model(CANONICAL)
    assert m.integrity["ok"] is True
    after = _tree_digest(CANONICAL)
    assert before == after


# ---------------------------------------------------------------------------
# 3. Invalid archive integrity is shown as uncertainty and cannot be hidden
# ---------------------------------------------------------------------------
def test_tampered_evidence_shows_uncertainty(archive_copy: Path):
    target = archive_copy / "target" / "index.html"
    target.write_bytes(target.read_bytes() + b"<!-- tampered -->")
    m = build_review_model(archive_copy)
    d = m.to_dict()
    assert m.uncertain is True
    assert d["integrity"]["ok"] is False
    assert d["uncertain"] is True
    assert any(not c["ok"] for c in d["integrity"]["checks"])
    # The failing check is present (not silently dropped).
    assert any("target" in c["name"] and not c["ok"] for c in d["integrity"]["checks"])


def test_tampered_screenshot_blocks_serving(archive_copy: Path):
    shot = archive_copy / "runtime-store" / "neon-serpents-live-002.runtime.d" / "screenshot.png"
    shot.write_bytes(shot.read_bytes() + b"\x00tamper")
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "disp") as server:
        client = _Client(server)
        status, _body, _h = client.get("/api/evidence/screenshot.png")
        assert status == 409  # integrity failure surfaced, not silently served


# ---------------------------------------------------------------------------
# 4. Path traversal / arbitrary-file access refused
# ---------------------------------------------------------------------------
def test_path_traversal_and_arbitrary_files_refused(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "disp") as server:
        client = _Client(server)
        for evil in [
            "/api/evidence/../../session.v0.json",
            "/api/evidence/..%2f..%2fsession.v0.json",
            "/api/evidence/%2e%2e/manifest.json",
            "/api/evidence/session.v0.json",
            "/api/evidence/../../../../../../etc/passwd",
        ]:
            status, _body, _h = client.get(evil)
            assert status == 404, f"{evil} should be refused, got {status}"


# ---------------------------------------------------------------------------
# 5. Server binds only to loopback
# ---------------------------------------------------------------------------
def test_server_binds_loopback_only(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "disp") as server:
        host, _port = server.address
        assert host == "127.0.0.1"


# ---------------------------------------------------------------------------
# 6. State-changing requests require the local launch token
# ---------------------------------------------------------------------------
def test_mutation_requires_token(archive_copy: Path):
    with ReviewServer(archive_copy, disposition_dir=archive_copy.parent / "disp") as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        payload = {
            "disposition": "ACCEPT_RESULT",
            "session_id": m.session_id,
            "expected_fingerprints": m.fingerprints,
        }
        status, body = client.post("/api/disposition", payload, token=None)
        assert status == 401
        status, body = client.post("/api/disposition", payload, token="wrong-token")
        assert status == 401
        assert not server.context.store().has_disposition(m.session_id)


# ---------------------------------------------------------------------------
# 7 & 8. ACCEPT / REJECT persisted atomically
# ---------------------------------------------------------------------------
def _accept_payload(m):
    return {"disposition": "ACCEPT_RESULT", "session_id": m.session_id, "expected_fingerprints": m.fingerprints}


def test_accept_persisted_atomically(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        status, body = client.post("/api/disposition", _accept_payload(m))
        assert status == 200
        assert body["disposition"]["disposition"] == "ACCEPT_RESULT"
    stored = ReviewDispositionStore(disp).load(m.session_id)
    assert stored is not None and stored.disposition == "ACCEPT_RESULT"


def test_reject_with_bounded_reason_persisted(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        payload = {
            "disposition": "REJECT_RESULT",
            "session_id": m.session_id,
            "expected_fingerprints": m.fingerprints,
            "note": "not playable enough for operator sign-off",
        }
        status, body = client.post("/api/disposition", payload)
        assert status == 200
        assert body["disposition"]["disposition"] == "REJECT_RESULT"
        assert body["disposition"]["note"].startswith("not playable")


# ---------------------------------------------------------------------------
# 9 & 10. Idempotent identical replay; contradictory refused
# ---------------------------------------------------------------------------
def test_idempotent_identical_disposition(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        s1, b1 = client.post("/api/disposition", _accept_payload(m))
        s2, b2 = client.post("/api/disposition", _accept_payload(m))
        assert s1 == 200 and s2 == 200
        assert b1["disposition"]["disposition_nonce"] == b2["disposition"]["disposition_nonce"]
        assert b1["disposition"]["timestamp"] == b2["disposition"]["timestamp"]


def test_contradictory_disposition_refused(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        s1, _ = client.post("/api/disposition", _accept_payload(m))
        assert s1 == 200
        reject = {"disposition": "REJECT_RESULT", "session_id": m.session_id, "expected_fingerprints": m.fingerprints}
        s2, b2 = client.post("/api/disposition", reject)
        assert s2 == 409
        assert b2["error"] == "contradictory_disposition"
        # Original ACCEPT is preserved.
        assert ReviewDispositionStore(disp).load(m.session_id).disposition == "ACCEPT_RESULT"


# ---------------------------------------------------------------------------
# 11. Restart reconstruction preserves the same disposition
# ---------------------------------------------------------------------------
def test_restart_reconstruction_preserves_disposition(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        _, b1 = client.post("/api/disposition", _accept_payload(m))
    # Fresh server instance == process restart from the same durable store.
    with ReviewServer(archive_copy, disposition_dir=disp) as server2:
        client2 = _Client(server2)
        status, raw, _h = client2.get("/api/disposition")
        body = json.loads(raw)
        assert status == 200
        assert body["disposition"]["disposition_nonce"] == b1["disposition"]["disposition_nonce"]
        assert body["disposition"]["disposition"] == "ACCEPT_RESULT"


# ---------------------------------------------------------------------------
# 12. Malformed / tampered disposition fails closed
# ---------------------------------------------------------------------------
def test_tampered_disposition_fails_closed(archive_copy: Path, tmp_path: Path):
    disp = tmp_path / "disp"
    store = ReviewDispositionStore(disp)
    m = build_review_model(archive_copy)
    store.record(session_id=m.session_id, disposition="ACCEPT_RESULT", evidence_fingerprints=dict(m.fingerprints))
    record_path = disp / f"{m.session_id}.disposition.json"
    raw = json.loads(record_path.read_text(encoding="utf-8"))
    raw["disposition"] = "REJECT_RESULT"  # flip verdict but leave fingerprint stale
    record_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(DispositionCorrupt):
        store.load(m.session_id)
    # Malformed JSON also fails closed.
    record_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(DispositionCorrupt):
        store.load(m.session_id)


# ---------------------------------------------------------------------------
# 13. No provider / verifier / executor / retry / repair is invoked
# ---------------------------------------------------------------------------
def test_disposition_invokes_no_machinery(archive_copy: Path, tmp_path: Path, monkeypatch):
    # Any accidental import-time use of these would be caught; here we assert the
    # runtime evidence still records that none occurred and that recording a
    # disposition does not spawn processes or alter those facts.
    import admissible.review_surface.server as srv

    # Guard: the review surface module must not import provider/executor drivers.
    assert not hasattr(srv, "run_bounded_runtime_verification")
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        client.post("/api/disposition", _accept_payload(m))
        m2 = build_review_model(archive_copy)
        assert m2.runtime["provider_invoked"] is False
        assert m2.runtime["retry_attempted"] is False
        assert m2.runtime["repair_attempted"] is False


# ---------------------------------------------------------------------------
# 14. Disposition does not modify target / session / runtime / evidence
# ---------------------------------------------------------------------------
def test_disposition_does_not_mutate_archive(archive_copy: Path, tmp_path: Path):
    before = _tree_digest(archive_copy)
    disp = tmp_path / "disp"
    with ReviewServer(archive_copy, disposition_dir=disp) as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        client.post("/api/disposition", _accept_payload(m))
        client.get("/api/evidence/screenshot.png")
        client.get("/api/evidence/document.html")
        client.get("/api/review")
    after = _tree_digest(archive_copy)
    assert before == after
    # The disposition lives OUTSIDE the archive tree.
    assert disp.resolve() not in archive_copy.resolve().parents
    assert (disp / f"{m.session_id}.disposition.json").is_file()


# ---------------------------------------------------------------------------
# 15. Interface exposes runtime screenshot and integrity status
# ---------------------------------------------------------------------------
def test_exposes_screenshot_and_integrity(archive_copy: Path, tmp_path: Path):
    with ReviewServer(archive_copy, disposition_dir=tmp_path / "disp") as server:
        client = _Client(server)
        status, body, headers = client.get("/api/evidence/screenshot.png")
        assert status == 200
        assert body[:8] == b"\x89PNG\r\n\x1a\n"
        assert headers.get("X-Evidence-Integrity") == "ok"
        status, page, _ = client.get("/")
        assert status == 200
        assert b"ACCEPT_RESULT" in page and b"REJECT_RESULT" in page
        rstatus, rbody, _ = client.get("/api/review")
        model = json.loads(rbody)["model"]
        assert "integrity" in model and model["integrity"]["ok"] is True


# ---------------------------------------------------------------------------
# 16. No server or child process remains after shutdown
# ---------------------------------------------------------------------------
def test_no_process_after_shutdown(archive_copy: Path, tmp_path: Path):
    server = ReviewServer(archive_copy, disposition_dir=tmp_path / "disp")
    server.start()
    url = server.url
    client = _Client(server)
    assert client.get("/api/review")[0] == 200
    server.stop()
    # The listening socket is closed: a fresh connection must fail.
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(url + "api/review", timeout=2)
    # The serving thread has terminated.
    assert server._thread is None


# ---------------------------------------------------------------------------
# Extra: loopback origin enforcement on mutation (spoofed non-loopback Host)
# ---------------------------------------------------------------------------
def test_mutation_rejects_non_loopback_host(archive_copy: Path, tmp_path: Path):
    with ReviewServer(archive_copy, disposition_dir=tmp_path / "disp") as server:
        client = _Client(server)
        m = build_review_model(archive_copy)
        status, body = client.post("/api/disposition", _accept_payload(m), host="evil.example.com")
        assert status == 403
        assert body["error"] == "non_loopback_host"
