"""Governed backend-drift rerun: reauthorization after a truthful refusal.

Covers the single supported recovery class (authoritative terminal REFUSED with
``post_run_backend_drift``), idempotent recovery creation, fresh child
authority, parent immutability, secret non-leakage, depth-one limits, browser
refresh reconstruction, transport guards, and the browser-side flow.

No real provider is ever invoked; every scenario is deterministic.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import ast
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_PRECOMMITTED,
    GOLDEN_TEMPLATE_ID,
)
from admissible.product_launcher.launcher import ProductLauncher
from admissible.product_launcher.preflight import consume_ready_preflight
from admissible.product_launcher.recovery import (
    CLASSIFICATION_NOT_RECOVERABLE,
    CLASSIFICATION_REAUTHORIZATION_REQUIRED,
    RECOVERY_SCHEMA_VERSION,
    RecoveryPersistenceError,
    RecoveryRecord,
    classify_recovery,
    emit_recovery_record,
)
from admissible.product_launcher.ui_transport import CSRF_HEADER, DIGEST_HEADER, OWNER_HEADER
from admissible.product_read_model import load_run_detail, render_result_json
from admissible.product_service.control import _RESULT_TRANSPORT_REDACTIONS

from test_admissible_product_launcher_g2_5 import (
    DIGEST,
    _cfg,
    _golden_owner_input,
    _hex_ids,
    _raw_request,
    _request,
    _ui,
)
from test_admissible_product_ui_g3 import NODE_HARNESS as G3_NODE_HARNESS
from test_admissible_product_ui_g4 import G4_DOM
from tests.product_read_model.builders import RunRootBuilder

NODE = "node"
JS_PATH = Path(__file__).parents[1] / "admissible" / "product_ui" / "app.js"

DRIFT_REASON = "post_run_backend_drift"
SECRET_KEY_MARKERS = ("phrase", "digest", "token", "nonce", "secret", "cookie", "password")


# ---------------------------------------------------------------------------
# Deterministic authoritative refused parent fixture (transport-shaped result)
# ---------------------------------------------------------------------------


def _refused_result(
    *,
    reasons=(DRIFT_REASON,),
    verdict="REFUSED",
    authoritative=True,
    run_id="run-parent-fixture",
    backend_identity="cursor-agent-native-oneshot",
):
    return {
        "schema_version": "admissible_product_read_model_result_v1",
        "transport_schema_version": "admissible_product_service_transport_v1",
        "transport_redactions": ["diagnostics", "run_root"],
        "non_authority_notice": "Presentation only.",
        "run_id": run_id,
        "presentation_status": "REFUSED" if verdict == "REFUSED" else "ADMITTED",
        "authorization": {
            "present": "PRESENT",
            "run_id": run_id,
            "session_id": "session-parent-fixture",
            "backend_identity": backend_identity,
            "authorized_model": "auto",
            "classification": "package-bin",
        },
        "execution_state": {
            "state": "COMPLETED",
            "provider_exit_code": 0,
            "timed_out": False,
            "termination_reason": None,
        },
        "result_admission_state": {
            "verdict": verdict,
            "verification_mode": "FROZEN_BEHAVIORAL",
            "source": "AUTHORITATIVE_RECONSTRUCTION",
            "truth_status": "AUTHORITATIVE",
            "verdict_is_authoritative": authoritative,
            "consistent": True,
            "claim_present": False,
            "claimed_verdict": "UNKNOWN",
            "claim_is_authoritative": False,
        },
        "failing_boundary": {
            "boundary": "MATERIAL_ELIGIBILITY",
            "failure_category": "POLICY",
            "detail": None,
            "reasons": list(reasons),
        },
        "material_git_result": {
            "git": {"present": "PRESENT"},
            "material": {"present": "PRESENT", "result": "FAILED", "eligible": False},
        },
        "behavioral_verifier_result": {"present": "ABSENT", "result": "ABSENT"},
        "checkpoint_result": {"present": "ABSENT", "result": "ABSENT", "attempted": False},
        "evidence_completeness": {
            "state": "COMPLETE",
            "present_records": [],
            "absent_records": [],
            "inconsistent_records": [],
            "missing_required": [],
        },
        "human_disposition": {"present": "ABSENT", "disposition": "NONE", "reason": None},
        "timeline": [],
        "artifacts": [],
        "read_notes": [],
    }


# ---------------------------------------------------------------------------
# Fake G2 with real loopback GET status/result routes for recovery re-fetching
# ---------------------------------------------------------------------------


class RecoveryG2Server:
    host = "127.0.0.1"

    def __init__(self):
        self.control_token = "f" * 64
        self.run_calls = []
        self.validate_count = 0
        self.launch_counter = itertools.count(1)
        self.statuses: dict[str, dict] = {}
        self.results: dict[str, tuple[int, dict]] = {}
        gate = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                return

            def _reply(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                self.rfile.read(length)
                if self.path == "/api/v1/contracts/validate":
                    gate.validate_count += 1
                    self._reply(200, {"contract_id": f"{gate.validate_count:032x}"})
                    return
                if self.path == "/api/v1/runs":
                    control_run_id = f"{next(gate.launch_counter):030x}cc"
                    gate.run_calls.append(
                        {
                            "control_run_id": control_run_id,
                            "phrase": self.headers.get(OWNER_HEADER),
                            "digest": self.headers.get(DIGEST_HEADER),
                        }
                    )
                    self._reply(202, {"control_run_id": control_run_id, "control_state": "QUEUED"})
                    return
                self._reply(404, {"error": "NOT_FOUND"})

            def do_GET(self):
                parts = self.path.split("/")
                if len(parts) == 5 and parts[3] == "runs" and parts[4]:
                    body = gate.statuses.get(parts[4])
                    if body is None:
                        self._reply(404, {"error": "RUN_NOT_FOUND"})
                    else:
                        self._reply(200, body)
                    return
                if len(parts) == 6 and parts[3] == "runs" and parts[4] and parts[5] == "result":
                    entry = gate.results.get(parts[4])
                    if entry is None:
                        self._reply(404, {"error": "RUN_NOT_FOUND"})
                    else:
                        self._reply(entry[0], entry[1])
                    return
                self._reply(404, {"error": "NOT_FOUND"})

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = None

    @property
    def port(self):
        return self._server.server_port

    def start(self):
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="admissible-test-recovery-g2"
        )
        self._thread.start()
        return self

    def stop(self):
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join()
            self._thread = None
        self._server.server_close()

    def mark_terminal(self, control_run_id, *, result=None, control_state="TERMINAL"):
        self.statuses[control_run_id] = {
            "control_state": control_state,
            "control_run_id": control_run_id,
            "authoritative_session_id": f"session-{control_run_id[:8]}",
            "started_at": "2026-07-20T10:00:00Z",
            "ended_at": "2026-07-20T10:05:00Z",
            "start_error_type": None,
            "application_return_code": 0,
            "terminal_evidence": "EVIDENCE_ROOT_PRESENT",
            "product_summary": None,
        }
        if result is not None:
            self.results[control_run_id] = result


class _RecoveryPayload:
    """Deterministic per-preparation payload with visible backend facts."""

    schema_version = "admissible_native_canary_authorization_payload_v4"
    backend_attestation_class = "package-bin"
    source_head = "b" * 40
    mission_profile = SimpleNamespace(profile_fingerprint="c" * 64)
    run_id = "run"
    session_id = "session"
    selected_model = "auto"
    timeout_seconds = 1800

    def __init__(self, fingerprint, attestation_fingerprint):
        self.payload_fingerprint = fingerprint
        self.backend_attestation_fingerprint = attestation_fingerprint

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "payload_fingerprint": self.payload_fingerprint,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "selected_model": self.selected_model,
            "timeout_seconds": self.timeout_seconds,
            "backend_attestation_class": self.backend_attestation_class,
            "backend_attestation_fingerprint": self.backend_attestation_fingerprint,
            "source_head": self.source_head,
            "executable": "cursor-agent",
            "mission_profile": {"profile_fingerprint": self.mission_profile.profile_fingerprint},
        }


def _prefix_ids(start: int):
    """Hex ids whose first 12 characters are distinct per id.

    Authoring derives generated profile/run/session identities from the first
    12 characters of the document ID, so a realistic generator must vary that
    prefix the way ``secrets.token_hex`` does. The colliding-prefix generator
    is used separately to prove the enforced child-freshness rejection.
    """

    counter = itertools.count(start)
    return lambda: f"{next(counter):012x}" + "0" * 20


def _recovery_stack(tmp_path, monkeypatch, *, id_start=700_000, payloads=None, id_factory=None):
    cfg = _cfg(tmp_path, mode=AUTHORIZATION_MODE_PRECOMMITTED, timeout_maximum=3600)
    payload_list = payloads or [
        _RecoveryPayload("a" * 64, "1" * 64),
        _RecoveryPayload("b" * 64, "2" * 64),
        _RecoveryPayload("d" * 64, "3" * 64),
    ]
    preflight_calls = []
    consume_counter = itertools.count()

    def preflight(**kwargs):
        preflight_calls.append(dict(kwargs))
        return 0, json.dumps({"status": "PREFLIGHT_READY", "authorization_payload": {}}).encode()

    def fake_consume(**kwargs):
        payload = payload_list[min(next(consume_counter), len(payload_list) - 1)]
        return consume_ready_preflight(
            **{**kwargs, "payload_loader": lambda _data, chosen=payload: chosen}
        )

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight", fake_consume
    )
    gate = RecoveryG2Server()
    launcher = ProductLauncher(
        cfg,
        control_plane=SimpleNamespace(),
        g2_server=gate,
        preflight_application=preflight,
        id_generator=(id_factory or _prefix_ids)(id_start),
        browser_opener=lambda _u: None,
    )
    launcher.start()
    return launcher, gate, cfg, preflight_calls


def _make_ready_golden(launcher):
    status, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _golden_owner_input())
    assert status == 200, authored
    cid = authored["contract_id"]
    status, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
    assert status == 202, prep
    pid = prep["preparation_id"]
    for _ in range(400):
        _, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
        if body["state"] == "READY":
            return cid, pid, authored
        time.sleep(0.01)
    raise AssertionError(body)


def _launch(launcher, cid, pid, *, phrase="parent-owner-phrase"):
    status, _, body, raw = _ui(
        launcher,
        "POST",
        "/ui/api/v1/runs",
        {"contract_id": cid, "preparation_id": pid},
        **{OWNER_HEADER: phrase, DIGEST_HEADER: DIGEST},
    )
    assert status == 202, body
    return body["control_run_id"], raw


def _refused_parent(launcher, gate, **result_kwargs):
    cid, pid, authored = _make_ready_golden(launcher)
    parent_id, _ = _launch(launcher, cid, pid)
    gate.mark_terminal(parent_id, result=(200, _refused_result(**result_kwargs)))
    return cid, pid, parent_id, authored


def _wait_recovery_state(launcher, recovery_id, wanted):
    for _ in range(400):
        status, _, view, raw = _ui(launcher, "GET", f"/ui/api/v1/recoveries/{recovery_id}")
        assert status == 200, view
        if view["state"] == wanted:
            return view, raw
        time.sleep(0.01)
    raise AssertionError(view)


def _tree_manifest(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _rejected_exchange(port, method, path, *, headers, body=b""):
    """Bounded rejection probe tolerant of the server's intentional early close.

    Guard rejections respond and close before reading the request body, so a
    strict HTTP client can observe a Windows RST instead of the response. The
    raw-socket reader tolerates that; a bounded retry absorbs the rare race
    where the RST lands before any response byte arrives.
    """

    lines = [f"{method} {path} HTTP/1.1".encode("latin-1")]
    for name, value in headers:
        lines.append(f"{name}: {value}".encode("latin-1"))
    lines.append(f"Content-Length: {len(body)}".encode("latin-1"))
    lines.append(b"Connection: close")
    last = b""
    for _attempt in range(5):
        try:
            status, raw = _raw_request(port, lines, body)
        except (IndexError, ValueError, OSError):
            continue
        match = re.search(rb'"error":"([A-Z_]+)"', raw)
        if match:
            return status, match.group(1).decode("ascii")
        last = raw
    raise AssertionError(last)


def _flatten_keys(value, prefix=""):
    keys = []
    if isinstance(value, dict):
        for key, inner in value.items():
            keys.append(f"{prefix}{key}")
            keys.extend(_flatten_keys(inner, prefix=f"{prefix}{key}."))
    elif isinstance(value, list):
        for inner in value:
            keys.extend(_flatten_keys(inner, prefix=prefix))
    return keys


# ---------------------------------------------------------------------------
# 1-5: classification truth matrix (unit level)
# ---------------------------------------------------------------------------


def test_classify_recovery_truth_matrix():
    eligible = _refused_result()
    assert (
        classify_recovery(eligible, control_state="TERMINAL")
        == CLASSIFICATION_REAUTHORIZATION_REQUIRED
    )
    assert (
        classify_recovery(eligible, control_state="START_FAILED")
        == CLASSIFICATION_REAUTHORIZATION_REQUIRED
    )
    rejected = [
        (eligible, {"control_state": "RUNNING"}),
        (eligible, {"control_state": "QUEUED"}),
        (eligible, {"control_state": None}),
        (eligible, {"control_state": "TERMINAL", "parent_is_recovery_child": True}),
        (_refused_result(reasons=("material_paths_noncompliant",)), {"control_state": "TERMINAL"}),
        (_refused_result(reasons=()), {"control_state": "TERMINAL"}),
        (_refused_result(authoritative=False), {"control_state": "TERMINAL"}),
        (_refused_result(verdict="ADMITTED_VERIFIED"), {"control_state": "TERMINAL"}),
        (_refused_result(verdict="UNKNOWN"), {"control_state": "TERMINAL"}),
        (None, {"control_state": "TERMINAL"}),
        ({}, {"control_state": "TERMINAL"}),
        ({"result_admission_state": [], "failing_boundary": {}}, {"control_state": "TERMINAL"}),
    ]
    for result, kwargs in rejected:
        assert classify_recovery(result, **kwargs) == CLASSIFICATION_NOT_RECOVERABLE, (result, kwargs)
    # A drift reason alongside other reasons still classifies as recoverable.
    both = _refused_result(reasons=("material_paths_noncompliant", DRIFT_REASON))
    assert classify_recovery(both, control_state="TERMINAL") == CLASSIFICATION_REAUTHORIZATION_REQUIRED


# ---------------------------------------------------------------------------
# Durable record unit: exact schema, write-once, secret-free
# ---------------------------------------------------------------------------


def test_durable_record_exact_schema_write_once_and_secret_free(tmp_path):
    record = RecoveryRecord(
        recovery_id="ab" * 16,
        parent_control_run_id="parent-1",
        parent_session_id="session-parent",
        refusal_reason=DRIFT_REASON,
        classification=CLASSIFICATION_REAUTHORIZATION_REQUIRED,
        preparation_id="prep-1",
        created_at="2026-07-20T10:00:00Z",
        owner_decision="OWNER_AUTHORIZED_GOVERNED_RERUN",
        child_control_run_id="child-1",
        authorized_at="2026-07-20T10:10:00Z",
        child_contract_id="contract-child-1",
    )
    directory = (tmp_path / "recoveries").resolve()
    path = emit_recovery_record(record, directory=directory)
    stored = json.loads(Path(path).read_bytes().decode("utf-8"))
    assert set(stored) == {
        "schema_version",
        "recovery_id",
        "parent_control_run_id",
        "parent_session_id",
        "refusal_reason",
        "classification",
        "owner_decision",
        "preparation_id",
        "child_control_run_id",
        "created_at",
        "authorized_at",
    }
    assert stored["schema_version"] == RECOVERY_SCHEMA_VERSION
    assert stored["parent_control_run_id"] == "parent-1"
    assert stored["child_control_run_id"] == "child-1"
    # Internal binding fields never persist.
    assert "child_contract_id" not in stored
    blob = Path(path).read_text(encoding="utf-8").lower()
    for marker in SECRET_KEY_MARKERS:
        assert f'"{marker}' not in blob.replace('"owner_decision"', "")
    # Write-once: a second emission for the same recovery is a hard error.
    with pytest.raises(RecoveryPersistenceError) as exc:
        emit_recovery_record(record, directory=directory)
    assert exc.value.error_code == "DOCUMENT_EXISTS"
    with pytest.raises(RecoveryPersistenceError):
        emit_recovery_record(
            RecoveryRecord(
                recovery_id="../evil",
                parent_control_run_id="p",
                parent_session_id=None,
                refusal_reason=DRIFT_REASON,
                classification=CLASSIFICATION_REAUTHORIZATION_REQUIRED,
                preparation_id="x",
                created_at="t",
            ),
            directory=directory,
        )


# ---------------------------------------------------------------------------
# 1, 8-17, 27-28: full offline end-to-end rehearsal
# ---------------------------------------------------------------------------


def test_recovery_full_cycle_fresh_identities_and_parent_immutability(tmp_path, monkeypatch):
    launcher, gate, cfg, preflight_calls = _recovery_stack(tmp_path, monkeypatch)
    parent_evidence = (tmp_path / "parent-evidence").resolve()
    (parent_evidence / "evidence").mkdir(parents=True)
    (parent_evidence / "evidence" / "final-status.json").write_text(
        '{"classification": "PRECAPTURE_ELIGIBILITY_FAILED"}', encoding="utf-8"
    )
    before = _tree_manifest(parent_evidence)
    try:
        parent_cid, parent_pid, parent_id, parent_authored = _refused_parent(launcher, gate)
        parent_fingerprint = parent_authored["profile_fingerprint"]
        parent_ids = parent_authored["generated_ids"]
        _, _, parent_prep, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{parent_pid}")
        assert preflight_calls and len(preflight_calls) == 1

        status, _, view, raw = _ui(
            launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {}
        )
        assert status == 201, view
        assert view["classification"] == CLASSIFICATION_REAUTHORIZATION_REQUIRED
        assert view["refusal_reason"] == DRIFT_REASON
        assert view["parent_control_run_id"] == parent_id
        assert view["parent_backend_identity"] == "cursor-agent-native-oneshot"
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        recovery_id = view["recovery_id"]
        child_cid = view["child_contract_id"]
        child_pid = view["preparation_id"]

        # Fresh preflight ran for the fresh child preparation.
        for _ in range(400):
            if len(preflight_calls) == 2:
                break
            time.sleep(0.01)
        assert len(preflight_calls) == 2

        view, raw = _wait_recovery_state(launcher, recovery_id, "AWAITING_OWNER_AUTHORIZATION")
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        assert "parent-owner-phrase" not in raw.decode("utf-8", "replace")
        assert DIGEST not in raw.decode("utf-8", "replace")

        # Fresh identities: nothing from the parent contract is reused.
        assert child_cid != parent_cid
        assert child_pid != parent_pid
        child_record = launcher._contracts[child_cid]
        assert child_record.profile_fingerprint != parent_fingerprint
        for key, parent_value in parent_ids.items():
            assert child_record.generated_ids[key] != parent_value, key
        assert child_record.contract_summary["template_id"] == GOLDEN_TEMPLATE_ID
        # Only the allowed owner variables are retained from the parent.
        parent_record = launcher._contracts[parent_cid]
        assert (child_record.model, child_record.timeout_seconds) == (
            parent_record.model,
            parent_record.timeout_seconds,
        )
        _, _, child_prep, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{child_pid}")
        assert child_prep["payload_fingerprint"] != parent_prep["payload_fingerprint"]

        # No silent authorization: exactly the one parent launch reached G2.
        assert len(gate.run_calls) == 1
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": child_cid, "preparation_id": child_pid},
        )
        assert status == 400 and body["error"] == "OWNER_AUTHORIZATION_REQUIRED"
        assert len(gate.run_calls) == 1

        # Explicit owner authorization with a fresh phrase creates the child.
        child_id, _ = _launch(launcher, child_cid, child_pid, phrase="fresh-child-phrase")
        assert child_id != parent_id
        assert gate.run_calls[0]["phrase"] == "parent-owner-phrase"
        assert gate.run_calls[1]["phrase"] == "fresh-child-phrase"

        status, _, view, _ = _ui(launcher, "GET", f"/ui/api/v1/recoveries/{recovery_id}")
        assert status == 200
        assert view["child_control_run_id"] == child_id
        assert view["owner_decision"] == "OWNER_AUTHORIZED_GOVERNED_RERUN"
        assert view["authorized_at"]
        assert view["state"] == "CHILD_RUN_CREATED"
        assert view["durable_record_written"] is True

        # Exactly one durable write-once record binding parent and child.
        recoveries_dir = Path(cfg.contract_documents_directory) / "recoveries"
        records = sorted(recoveries_dir.glob("recovery-*.json"))
        assert len(records) == 1
        stored = json.loads(records[0].read_bytes().decode("utf-8"))
        assert stored["parent_control_run_id"] == parent_id
        assert stored["child_control_run_id"] == child_id
        assert stored["preparation_id"] == child_pid
        blob = records[0].read_text(encoding="utf-8")
        assert "parent-owner-phrase" not in blob
        assert "fresh-child-phrase" not in blob
        assert DIGEST not in blob
        assert launcher._g2_token not in blob
        assert launcher.csrf_nonce not in blob
        for key in _flatten_keys(stored):
            lowered = key.lower()
            assert not any(marker in lowered for marker in SECRET_KEY_MARKERS if marker != "digest"), key
            assert "digest" not in lowered, key

        # Duplicate launch clicks cannot create a second child.
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": child_cid, "preparation_id": child_pid},
            **{OWNER_HEADER: "fresh-child-phrase", DIGEST_HEADER: DIGEST},
        )
        assert status == 409 and body["error"] in {"PREPARATION_CONSUMED", "PREPARATION_IN_USE"}
        assert len(gate.run_calls) == 2

        # The parent result stays REFUSED and byte-identical after child creation.
        status, _, parent_result, _ = _ui(launcher, "GET", f"/ui/api/v1/runs/{parent_id}/result")
        assert status == 200
        assert parent_result == _refused_result()
        assert parent_result["result_admission_state"]["verdict"] == "REFUSED"

        # Child terminal truth is independent of the parent.
        gate.mark_terminal(
            child_id,
            result=(200, _refused_result(run_id="run-child-fixture", reasons=("behavioral",))),
        )
        view, _ = _wait_recovery_state(launcher, recovery_id, "COMPLETED")
        status, _, child_result, _ = _ui(launcher, "GET", f"/ui/api/v1/runs/{child_id}/result")
        assert status == 200
        assert child_result["run_id"] == "run-child-fixture"
        assert child_result != parent_result
    finally:
        launcher.close()
    assert _tree_manifest(parent_evidence) == before


# ---------------------------------------------------------------------------
# 2-5: server-side rejections
# ---------------------------------------------------------------------------


def test_recovery_rejected_by_server_truth(tmp_path, monkeypatch):
    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=710_000)
    try:
        cid, pid, _authored = _make_ready_golden(launcher)
        parent_id, _ = _launch(launcher, cid, pid)

        # Unknown control run.
        status, _, body, _ = _ui(launcher, "POST", "/ui/api/v1/runs/unknown-run/recovery", {})
        assert (status, body["error"]) == (404, "RUN_NOT_FOUND")

        # Non-terminal parent.
        gate.mark_terminal(parent_id, control_state="RUNNING")
        status, _, body, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert (status, body["error"]) == (409, "RECOVERY_PARENT_NOT_TERMINAL")

        # Terminal but missing / unavailable result.
        gate.mark_terminal(parent_id)
        gate.results.pop(parent_id, None)
        status, _, body, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert (status, body["error"]) == (409, "RECOVERY_PARENT_RESULT_UNAVAILABLE")
        gate.results[parent_id] = (
            410,
            {"error": "NO_AUTHORITATIVE_RESULT", "control_state": "TERMINAL"},
        )
        status, _, body, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert (status, body["error"]) == (409, "RECOVERY_PARENT_RESULT_UNAVAILABLE")

        # Other refusal reasons, non-authoritative claims, and admitted runs.
        for result in (
            _refused_result(reasons=("material_paths_noncompliant",)),
            _refused_result(authoritative=False),
            _refused_result(verdict="ADMITTED_VERIFIED"),
            _refused_result(verdict="UNKNOWN", authoritative=False),
        ):
            gate.results[parent_id] = (200, result)
            status, _, body, _ = _ui(
                launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {}
            )
            assert (status, body["error"]) == (409, "RECOVERY_NOT_ELIGIBLE"), result[
                "result_admission_state"
            ]

        # No recovery state was created by any rejected attempt.
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert status == 200 and listing == {"recoveries": []}
        assert gate.validate_count == 1  # parent only; no child contract authored
    finally:
        launcher.close()


def test_recovery_rejects_non_fresh_child_identity(tmp_path, monkeypatch):
    """Colliding generated-identity prefixes are refused, never silently reused.

    Authoring derives run/session identity from the first 12 characters of the
    generated document ID. If a generator ever produced a child whose derived
    identity collides with the parent's, the recovery must fail closed instead
    of authoring a child that shares the parent run identity.
    """

    launcher, gate, _cfg_, _calls = _recovery_stack(
        tmp_path, monkeypatch, id_start=717_000, id_factory=_hex_ids
    )
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        status, _, body, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert (status, body["error"]) == (409, "RECOVERY_CHILD_IDENTITY_NOT_FRESH")
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert listing == {"recoveries": []}
    finally:
        launcher.close()


def test_recovery_requires_launcher_owned_parent_contract(tmp_path, monkeypatch):
    """A terminal refused run this launcher never launched cannot be imported."""

    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=715_000)
    try:
        foreign = "feedfacefeedfacefeedfacefeedface"
        gate.mark_terminal(foreign, result=(200, _refused_result()))
        status, _, body, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{foreign}/recovery", {})
        assert (status, body["error"]) == (409, "RECOVERY_PARENT_CONTRACT_UNKNOWN")
    finally:
        launcher.close()


# ---------------------------------------------------------------------------
# 6-7, 29: idempotent creation, including a true concurrent race
# ---------------------------------------------------------------------------


def test_duplicate_recovery_creation_returns_one_recovery(tmp_path, monkeypatch):
    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=720_000)
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        status, _, first, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 201, first
        status, _, second, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 200, second
        assert second["recovery_id"] == first["recovery_id"]
        assert second["preparation_id"] == first["preparation_id"]
        assert second["child_contract_id"] == first["child_contract_id"]
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert [item["recovery_id"] for item in listing["recoveries"]] == [first["recovery_id"]]
        # Exactly one child contract was authored (parent + one child).
        assert gate.validate_count == 2
    finally:
        launcher.close()


def test_concurrent_recovery_creation_race_yields_one_recovery(tmp_path, monkeypatch):
    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=725_000)
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        barrier = threading.Barrier(6)
        results = []
        results_lock = threading.Lock()

        def attempt():
            barrier.wait()
            status, body = launcher.create_recovery(parent_id)
            with results_lock:
                results.append((status, body.get("recovery_id"), body.get("preparation_id")))

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not any(thread.is_alive() for thread in threads)
        assert len(results) == 6
        assert sorted(status for status, _rid, _pid2 in results) == [200] * 5 + [201]
        assert len({rid for _s, rid, _p in results}) == 1
        assert len({prep for _s, _r, prep in results}) == 1
        assert gate.validate_count == 2
    finally:
        launcher.close()


# ---------------------------------------------------------------------------
# 18-19: depth-one limit
# ---------------------------------------------------------------------------


def test_recovery_depth_is_limited_to_one_child(tmp_path, monkeypatch):
    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=730_000)
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        status, _, view, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 201
        _wait_recovery_state(launcher, view["recovery_id"], "AWAITING_OWNER_AUTHORIZATION")
        child_id, _ = _launch(
            launcher, view["child_contract_id"], view["preparation_id"], phrase="child-phrase"
        )
        # The child itself terminates with the same authoritative drift refusal.
        gate.mark_terminal(child_id, result=(200, _refused_result(run_id="run-child")))
        status, _, body, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{child_id}/recovery", {})
        assert (status, body["error"]) == (409, "RECOVERY_DEPTH_EXCEEDED")
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert len(listing["recoveries"]) == 1
        # The parent cannot gain a second recovery either.
        status, _, again, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 200 and again["recovery_id"] == view["recovery_id"]
    finally:
        launcher.close()


# ---------------------------------------------------------------------------
# 20-21: refresh reconstruction vs. restart durability
# ---------------------------------------------------------------------------


def test_browser_refresh_reconstructs_pending_recovery(tmp_path, monkeypatch):
    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=735_000)
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        status, _, view, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 201
        _wait_recovery_state(launcher, view["recovery_id"], "AWAITING_OWNER_AUTHORIZATION")
        # A fresh browser reconstructs everything it needs from GET routes only.
        status, _, listing, raw = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert status == 200
        assert len(listing["recoveries"]) == 1
        pending = listing["recoveries"][0]
        assert pending["state"] == "AWAITING_OWNER_AUTHORIZATION"
        assert pending["child_contract_id"] == view["child_contract_id"]
        assert pending["preparation_id"] == view["preparation_id"]
        assert pending["parent_control_run_id"] == parent_id
        assert isinstance(pending["preparation"], dict)
        assert pending["preparation"]["state"] == "READY"
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        status, _, single, _ = _ui(
            launcher, "GET", f"/ui/api/v1/recoveries/{view['recovery_id']}"
        )
        assert status == 200 and single["recovery_id"] == view["recovery_id"]
        # Parent lookup resolves the same recovery for reconstruction.
        status, _, by_parent, _ = _ui(launcher, "GET", f"/ui/api/v1/recoveries/{parent_id}")
        assert status == 200 and by_parent["recovery_id"] == view["recovery_id"]
        status, _, body, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries/absent-recovery")
        assert (status, body["error"]) == (404, "NOT_FOUND")
    finally:
        launcher.close()


def test_pending_recovery_is_launcher_resident_not_restart_durable(tmp_path, monkeypatch):
    launcher, gate, cfg, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=740_000)
    recoveries_dir = Path(cfg.contract_documents_directory) / "recoveries"
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        status, _, view, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 201
        _wait_recovery_state(launcher, view["recovery_id"], "AWAITING_OWNER_AUTHORIZATION")
        # Pending lifecycle states never touch the durable recoveries directory.
        assert not recoveries_dir.exists() or list(recoveries_dir.glob("*")) == []
    finally:
        launcher.close()
    # A restarted launcher process starts with no pending recovery state.
    gate2 = RecoveryG2Server()
    launcher2 = ProductLauncher(
        cfg,
        control_plane=SimpleNamespace(),
        g2_server=gate2,
        preflight_application=lambda **_k: (1, b"{}"),
        id_generator=_prefix_ids(745_000),
        browser_opener=lambda _u: None,
    )
    try:
        launcher2.start()
        status, _, listing, _ = _ui(launcher2, "GET", "/ui/api/v1/recoveries")
        assert status == 200 and listing == {"recoveries": []}
    finally:
        launcher2.close()


# ---------------------------------------------------------------------------
# E: recovery termination through the existing preparation error surface
# ---------------------------------------------------------------------------


def test_recovery_states_track_preparation_lifecycle(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, mode=AUTHORIZATION_MODE_PRECOMMITTED, timeout_maximum=3600)
    release = threading.Event()
    behavior = {"mode": "ready"}
    payload = _RecoveryPayload("a" * 64, "1" * 64)
    calls = itertools.count()

    def preflight(**_kwargs):
        index = next(calls)
        if index >= 1:
            # Child preflight: hold while queued/running, then obey behavior.
            release.wait(timeout=30)
            if behavior["mode"] == "blocked":
                return 2, json.dumps(
                    {"status": "PREFLIGHT_BLOCKED", "reason_code": "BACKEND_DRIFT"}
                ).encode()
        return 0, json.dumps({"status": "PREFLIGHT_READY", "authorization_payload": {}}).encode()

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: consume_ready_preflight(
            **{**kwargs, "payload_loader": lambda _d: payload}
        ),
    )
    gate = RecoveryG2Server()
    launcher = ProductLauncher(
        cfg,
        control_plane=SimpleNamespace(),
        g2_server=gate,
        preflight_application=preflight,
        id_generator=_prefix_ids(750_000),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        behavior["mode"] = "blocked"
        status, _, view, _ = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 201
        assert view["state"] in {"PREPARING"}
        release.set()
        # BLOCKED terminates the recovery via the existing preparation surface.
        for _ in range(400):
            _, _, current, _ = _ui(
                launcher, "GET", f"/ui/api/v1/recoveries/{view['recovery_id']}"
            )
            if current["state"] == "BLOCKED":
                break
            time.sleep(0.01)
        assert current["state"] == "BLOCKED"
        assert current["preparation"]["blocked_summary"]["error_type"] == "PREFLIGHT_BLOCKED"
        assert current["child_control_run_id"] is None
    finally:
        release.set()
        launcher.close()


# ---------------------------------------------------------------------------
# 22-24: transport guards and G2 isolation
# ---------------------------------------------------------------------------


def test_recovery_routes_apply_existing_guards(tmp_path, monkeypatch):
    launcher, gate, _cfg_, _calls = _recovery_stack(tmp_path, monkeypatch, id_start=760_000)
    try:
        _cid, _pid, parent_id, _authored = _refused_parent(launcher, gate)
        host = f"127.0.0.1:{launcher.ui_port}"
        recovery_path = f"/ui/api/v1/runs/{parent_id}/recovery"
        empty = b"{}"
        # CSRF required on the recovery POST.
        status, error = _rejected_exchange(
            launcher.ui_port,
            "POST",
            recovery_path,
            headers=[("Host", host), ("Content-Type", "application/json"), (CSRF_HEADER, "0" * 64)],
            body=empty,
        )
        assert (status, error) == (403, "INVALID_CSRF")
        # Host validation on POST and GET.
        status, error = _rejected_exchange(
            launcher.ui_port,
            "POST",
            recovery_path,
            headers=[
                ("Host", "evil.example"),
                ("Content-Type", "application/json"),
                (CSRF_HEADER, launcher.csrf_nonce),
            ],
            body=empty,
        )
        assert (status, error) == (403, "INVALID_HOST")
        status, error = _rejected_exchange(
            launcher.ui_port,
            "GET",
            "/ui/api/v1/recoveries",
            headers=[("Host", "evil.example")],
        )
        assert (status, error) == (403, "INVALID_HOST")
        # Origin validation.
        status, error = _rejected_exchange(
            launcher.ui_port,
            "POST",
            recovery_path,
            headers=[
                ("Host", host),
                ("Origin", "https://evil.example"),
                ("Content-Type", "application/json"),
                (CSRF_HEADER, launcher.csrf_nonce),
            ],
            body=empty,
        )
        assert (status, error) == (403, "INVALID_ORIGIN")
        # Strict field set: no extra fields, JSON only.
        status, _, body, _ = _ui(
            launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {"extra": 1}
        )
        assert (status, body["error"]) == (400, "INVALID_FIELDS")
        status, error = _rejected_exchange(
            launcher.ui_port,
            "POST",
            recovery_path,
            headers=[("Host", host), ("Content-Type", "text/plain"), (CSRF_HEADER, launcher.csrf_nonce)],
            body=b"not-json",
        )
        assert (status, error) == (415, "JSON_REQUIRED")
        # No guard rejection created recovery state.
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert listing == {"recoveries": []}
        # A valid creation leaks no token or nonce in any recovery response.
        status, _, view, raw = _ui(launcher, "POST", f"/ui/api/v1/runs/{parent_id}/recovery", {})
        assert status == 201
        for path in ("/ui/api/v1/recoveries", f"/ui/api/v1/recoveries/{view['recovery_id']}"):
            status, headers, _body, raw = _ui(launcher, "GET", path)
            assert status == 200
            text = raw.decode("utf-8", "replace")
            assert launcher._g2_token not in text
            assert launcher.csrf_nonce not in text
            assert all(launcher._g2_token not in f"{k}:{v}" for k, v in headers.items())
        # The UI transport still exposes no arbitrary G2 proxy route.
        for path in (
            "/ui/api/v1/contracts/validate",
            f"/ui/api/v1/runs/{parent_id}/recovery/extra",
            "/ui/api/v1/recovery",
        ):
            status, _, body, _ = _ui(launcher, "GET", path)
            assert status == 404, path
    finally:
        launcher.close()


def test_direct_g2_routes_remain_blocked_on_real_stack(tmp_path):
    cfg = _cfg(tmp_path)
    launcher = ProductLauncher(
        cfg, id_generator=_hex_ids(770_000), browser_opener=lambda _u: None
    )
    try:
        launcher.start()
        # Direct G2 access without the control token stays unauthorized.
        status, _, body, _ = _request(
            "127.0.0.1",
            launcher.g2_port,
            "GET",
            "/api/v1/runs",
            headers={"Host": f"127.0.0.1:{launcher.g2_port}"},
        )
        assert (status, body["error"]) == (401, "UNAUTHORIZED")
        # Recovery GET routes exist on the UI transport, not on G2.
        status, _, body, _ = _request(
            "127.0.0.1",
            launcher.g2_port,
            "GET",
            "/api/v1/recoveries",
            headers={"Host": f"127.0.0.1:{launcher.g2_port}"},
        )
        assert status in {401, 404}
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/recoveries")
        assert status == 200 and listing == {"recoveries": []}
    finally:
        launcher.close()


# ---------------------------------------------------------------------------
# 25: result authorization JSON stays secret-safe
# ---------------------------------------------------------------------------


def test_result_authorization_json_is_secret_safe(tmp_path):
    b = RunRootBuilder(tmp_path / "run")
    b.preflight(secret=True).delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).result(exit_code=0).eligibility(eligible=True)
    b.behavioral(exit_code=1).terminal().final_status()
    detail = load_run_detail(tmp_path / "run")
    payload = render_result_json(detail)
    assert "authorization" in payload
    authorization = payload["authorization"]
    assert isinstance(authorization, dict)
    # Strict allow-list: no key resembles phrase/digest/token custody.
    for key in _flatten_keys(authorization):
        lowered = key.lower()
        assert not any(marker in lowered for marker in SECRET_KEY_MARKERS), key
    blob = json.dumps(payload)
    for leaked in ("hunter2-secret", "sk-should-not-appear", "owner-authorization-secret"):
        assert leaked not in blob
    # The G2 transport never redacts the authorization view away.
    assert "authorization" not in _RESULT_TRANSPORT_REDACTIONS
    assert set(_RESULT_TRANSPORT_REDACTIONS) == {"diagnostics", "run_root"}
    # Backend identity survives for the truthful parent-versus-child delta.
    assert "backend_identity" in authorization


def test_changed_python_sources_parse_and_recovery_module_is_bounded():
    root = Path(__file__).parents[1]
    for relative in (
        "admissible/product_launcher/recovery.py",
        "admissible/product_launcher/launcher.py",
        "admissible/product_launcher/ui_transport.py",
        "admissible/product_read_model/renderer.py",
    ):
        ast.parse((root / relative).read_text(encoding="utf-8"), filename=relative)
    recovery_source = (root / "admissible/product_launcher/recovery.py").read_text(encoding="utf-8")
    # The recovery module never talks HTTP itself and never stores custody.
    assert "HTTPConnection" not in recovery_source
    assert "owner_authorization" not in recovery_source.replace('"owner_authorization"', "")


# ---------------------------------------------------------------------------
# Browser-level scenarios (Node fake-DOM harness reused from G3/G4)
# ---------------------------------------------------------------------------

G5_SCENARIOS = r'''
function g5RefusedResult(options = {}) {
  const reasons = options.reasons || ["post_run_backend_drift"];
  return {
    schema_version: "admissible_product_read_model_result_v1",
    non_authority_notice: "Presentation only.",
    run_id: options.runId || "run-parent-g5",
    presentation_status: "REFUSED",
    authorization: Object.assign({
      present: "PRESENT",
      backend_identity: "parent-backend-identity-g5",
      authorized_model: "auto"
    }, options.authorization || {}),
    execution_state: { state: "COMPLETED", provider_exit_code: 0, timed_out: false, termination_reason: null },
    result_admission_state: {
      verdict: options.verdict || "REFUSED",
      verification_mode: "FROZEN_BEHAVIORAL",
      source: "AUTHORITATIVE_RECONSTRUCTION",
      truth_status: "AUTHORITATIVE",
      verdict_is_authoritative: options.authoritative === undefined ? true : options.authoritative,
      consistent: true, claim_present: false, claimed_verdict: "UNKNOWN", claim_is_authoritative: false
    },
    failing_boundary: { boundary: "MATERIAL_ELIGIBILITY", failure_category: "POLICY", detail: null, reasons },
    material_git_result: {
      git: { present: "PRESENT", final_git_head: "9".repeat(40), commits_added: 1, source_repository_mutated: false },
      material: { present: "PRESENT", result: "FAILED", eligible: false, material_paths_compliant: true }
    },
    checkpoint_result: { present: "ABSENT", result: "ABSENT", attempted: false },
    behavioral_verifier_result: { present: "ABSENT", result: "ABSENT" },
    evidence_completeness: { state: "COMPLETE", present_records: [], absent_records: [], inconsistent_records: [], missing_required: [] },
    human_disposition: { present: "ABSENT", disposition: "NONE", reason: null },
    timeline: [], artifacts: [], read_notes: [],
    transport_schema_version: "admissible_product_service_transport_v1",
    transport_redactions: ["diagnostics", "run_root"]
  };
}

function g5RecoveryView(options = {}) {
  return Object.assign({
    schema_version: "admissible_product_recovery_v1",
    recovery_id: "abc123abc123",
    parent_control_run_id: "control-g5-parent",
    parent_session_id: "session-parent",
    refusal_reason: "post_run_backend_drift",
    classification: "REAUTHORIZATION_REQUIRED",
    state: "PREPARING",
    owner_decision: null,
    preparation_id: "prep-g5-child",
    child_contract_id: "contract-g5-child",
    child_control_run_id: null,
    child_control_state: null,
    created_at: "2026-07-20T10:00:00Z",
    authorized_at: null,
    parent_backend_identity: "parent-backend-identity-g5",
    durable_record_written: false,
    durable_record_error: null,
    authorization_mode: "PRECOMMITTED_DIGEST"
  }, options);
}

function g5PrepBody(options = {}) {
  return Object.assign({
    preparation_id: "prep-g5-child",
    contract_id: "contract-g5-child",
    state: "READY",
    authorization_mode: "PRECOMMITTED_DIGEST",
    authorization_semantics_notice: "notice",
    consumed: false, created_at: "t", updated_at: "t",
    payload_fingerprint: "f".repeat(64),
    safe_payload_summary: { run_id: "run-child-g5" },
    authorization_payload: {
      payload_fingerprint: "f".repeat(64),
      executable: "cursor-agent",
      backend_attestation_class: "package-bin",
      backend_attestation_fingerprint: "1234abcd".repeat(8),
      selected_model: "auto"
    },
    blocked_summary: null, error_type: null
  }, options);
}

function installG5RunFetch(options) {
  const counts = { recoveryPosts: 0, launchPosts: 0 };
  fetchImpl = async (url, requestOptions = {}) => {
    const method = (requestOptions.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(requestOptions.headers || {}) } });
    if (url === "/ui/api/v1/bootstrap") {
      return jsonResponse(200, {
        service: "admissible-product-launcher", version: "g2.5",
        repository_display_path: "safe-repository", required_source_head: "a".repeat(40),
        authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "notice",
        owner_authorization_encoding: "latin-1", g2_ready: true, g2_api_version: "v1",
        csrf_nonce: "c".repeat(64), supported_authoring_template_ids: ["observed_local_git_v1"],
        visual_ui_available: false
      });
    }
    if (url === "/ui/api/v1/runs" && method === "POST") {
      counts.launchPosts += 1;
      const id = counts.launchPosts === 1 ? "control-g5-parent" : "control-g5-child";
      return jsonResponse(202, { control_run_id: id, control_state: "QUEUED" });
    }
    if (method === "POST" && /\/ui\/api\/v1\/runs\/[^/]+\/recovery$/.test(url)) {
      counts.recoveryPosts += 1;
      if (!options.recoveryView) return jsonResponse(409, { error: "RECOVERY_NOT_ELIGIBLE" });
      return jsonResponse(201, options.recoveryView);
    }
    if (url.startsWith("/ui/api/v1/preparations/") && method === "GET") {
      return jsonResponse(200, options.prepBody);
    }
    if (url === "/ui/api/v1/recoveries" && method === "GET") {
      return jsonResponse(200, { recoveries: options.recoveries || [] });
    }
    if (url.endsWith("/result") && method === "GET") {
      if (url.includes("control-g5-child")) {
        return jsonResponse(200, options.childResult || g5RefusedResult({ runId: "run-child-g5" }));
      }
      return jsonResponse(200, options.parentResult);
    }
    if (/\/ui\/api\/v1\/runs\/[^/]+$/.test(url)) {
      const id = decodeURIComponent(url.split("/").pop());
      return jsonResponse(200, {
        control_run_id: id, control_state: "TERMINAL",
        authoritative_session_id: `session-${id}`,
        terminal_evidence: "EVIDENCE_ROOT_PRESENT"
      });
    }
    return jsonResponse(404, { error: "NOT_FOUND" });
  };
  return counts;
}

async function g5WaitG4(wanted, steps = 80) {
  for (let i = 0; i < steps; i++) {
    await settle(); await flushTimers(5);
    if (windowObj.AdmissibleG4Test.getState() === wanted) return;
  }
  throw new Error(`state ${wanted} not reached, have ${windowObj.AdmissibleG4Test.getState()}`);
}

async function g5ReachParentRefusal(options) {
  await goToReady("happy");
  const counts = installG5RunFetch(options);
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle();
  await g5WaitG4("RUN_RESULT_READY");
  return counts;
}

async function runG5Flow() {
  const counts = await g5ReachParentRefusal({
    parentResult: g5RefusedResult(),
    recoveryView: g5RecoveryView(),
    prepBody: g5PrepBody(),
    childResult: g5RefusedResult({ runId: "run-child-g5" })
  });
  const offerShown = windowObj.AdmissibleG5Test.offerPresent();
  const offerText = windowObj.AdmissibleG5Test.offerText();
  windowObj.AdmissibleG5Test.clickOffer();
  windowObj.AdmissibleG5Test.clickOffer();
  await settle(); await flushTimers(12); await settle();
  const stateAfterPrepare = windowObj.AdmissibleG3Test.getState();
  const factsText = windowObj.AdmissibleG5Test.recoveryFactsText();
  const recovery = windowObj.AdmissibleG5Test.getRecovery();
  const launchPostsBeforeOwner = counts.launchPosts;
  windowObj.AdmissibleG3Test.setField("owner-phrase", "fresh-owner-phrase");
  windowObj.AdmissibleG3Test.setField("owner-digest", "e".repeat(64));
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle();
  const acceptedText = document.getElementById("accepted-facts").textContent;
  const childIsRecovery = windowObj.AdmissibleG5Test.runIsRecoveryChild();
  const launchHeaders = fetchLog
    .filter(x => x.url === "/ui/api/v1/runs" && x.method === "POST")
    .map(x => x.headers["X-Admissible-Owner-Authorization"]);
  await g5WaitG4("RUN_RESULT_READY");
  return {
    offerShown, offerText, recoveryPosts: counts.recoveryPosts, stateAfterPrepare,
    factsText, recovery, launchPostsBeforeOwner, launchPosts: counts.launchPosts,
    launchHeaders, acceptedText, childIsRecovery,
    childOfferShown: windowObj.AdmissibleG5Test.offerPresent(),
    childResultState: windowObj.AdmissibleG4Test.getState(),
    childResultText: document.getElementById("result-view").textContent
  };
}

async function runG5NoOffer(variant) {
  const variants = {
    other_reason: g5RefusedResult({ reasons: ["material_paths_noncompliant"] }),
    unauthoritative: g5RefusedResult({ authoritative: false }),
    admitted: g5RefusedResult({ verdict: "ADMITTED_VERIFIED", reasons: [] })
  };
  await g5ReachParentRefusal({ parentResult: variants[variant], recoveryView: null, prepBody: g5PrepBody() });
  return {
    state: windowObj.AdmissibleG4Test.getState(),
    offerShown: windowObj.AdmissibleG5Test.offerPresent(),
    resultText: document.getElementById("result-view").textContent.includes("Prepare governed rerun")
  };
}

async function runG5Resume() {
  const pending = g5RecoveryView({ state: "AWAITING_OWNER_AUTHORIZATION" });
  const counts = installG5RunFetch({
    parentResult: g5RefusedResult(),
    recoveryView: pending,
    prepBody: g5PrepBody(),
    recoveries: [pending]
  });
  loadApp();
  await settle(); await flushTimers(12); await settle();
  for (let i = 0; i < 40 && windowObj.AdmissibleG3Test.getState() !== "PREPARATION_READY"; i++) {
    await settle(); await flushTimers(5);
  }
  return {
    state: windowObj.AdmissibleG3Test.getState(),
    recovery: windowObj.AdmissibleG5Test.getRecovery(),
    factsText: windowObj.AdmissibleG5Test.recoveryFactsText(),
    launchPosts: counts.launchPosts,
    recoveryPosts: counts.recoveryPosts,
    phraseEmpty: document.getElementById("owner-phrase").value === ""
  };
}

async function runG5Hostile() {
  const hostile = `<img src=x onerror="${MARKER}()"><script>${MARKER}()</script>`;
  const counts = await g5ReachParentRefusal({
    parentResult: g5RefusedResult({ authorization: { backend_identity: hostile } }),
    recoveryView: g5RecoveryView({ recovery_id: hostile, parent_control_run_id: hostile }),
    prepBody: g5PrepBody({
      authorization_payload: {
        payload_fingerprint: hostile, executable: hostile,
        backend_attestation_class: hostile, backend_attestation_fingerprint: hostile,
        selected_model: hostile
      }
    })
  });
  windowObj.AdmissibleG5Test.clickOffer();
  await settle(); await flushTimers(12); await settle();
  return {
    state: windowObj.AdmissibleG3Test.getState(),
    markerInvoked, unsafeHtmlApi,
    createdScriptTags: createdTags.filter(x => x === "script").length,
    factsText: windowObj.AdmissibleG5Test.recoveryFactsText(),
    recoveryPosts: counts.recoveryPosts
  };
}

async function runG5Stale() {
  await g5ReachParentRefusal({
    parentResult: g5RefusedResult(),
    recoveryView: g5RecoveryView(),
    prepBody: g5PrepBody()
  });
  let resolveRecovery = null;
  const baseFetch = fetchImpl;
  fetchImpl = (url, requestOptions = {}) => {
    const method = (requestOptions.method || "GET").toUpperCase();
    if (method === "POST" && /\/recovery$/.test(url)) {
      fetchLog.push({ url, method });
      return new Promise(resolve => { resolveRecovery = resolve; });
    }
    return baseFetch(url, requestOptions);
  };
  windowObj.AdmissibleG5Test.clickOffer(); await settle();
  const inFlight = windowObj.AdmissibleG5Test.recoveryInFlight();
  windowObj.AdmissibleG3Test.reset(); await settle();
  const requestsAtReset = fetchLog.length;
  if (resolveRecovery) resolveRecovery(jsonResponse(201, g5RecoveryView()));
  await settle(); await flushTimers(20); await settle();
  return {
    inFlight,
    stateAfterStale: windowObj.AdmissibleG3Test.getState(),
    recoveryAfterStale: windowObj.AdmissibleG5Test.getRecovery(),
    noNewRequests: fetchLog.length === requestsAtReset
  };
}

(async () => {
  try {
    let out;
    if (scenario === "g5_flow") out = await runG5Flow();
    else if (scenario.startsWith("g5_no_offer:")) out = await runG5NoOffer(scenario.split(":")[1]);
    else if (scenario === "g5_resume") out = await runG5Resume();
    else if (scenario === "g5_hostile") out = await runG5Hostile();
    else if (scenario === "g5_stale") out = await runG5Stale();
    else throw new Error("unknown scenario");
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    process.stdout.write(JSON.stringify({ scenario, error: String(error && error.stack || error) }));
    process.exitCode = 1;
  }
})();
'''


def _build_g5_harness() -> str:
    harness = G3_NODE_HARNESS.replace(
        "\nbuildDom();\n\nconst document =",
        "\n" + G4_DOM + "\nbuildDom();\ninstallG4Dom();\n\nconst document =",
    )
    harness = harness.replace(
        "  buildDom();\n  // trap marker side effects",
        "  buildDom();\n  installG4Dom();\n  // trap marker side effects",
    )
    harness = harness.replace(
        "Object, Array, String, Number, Boolean, JSON, Error, Promise, Math, RegExp, Date,",
        "Object, Array, String, Number, Boolean, JSON, Error, Promise, Math, RegExp, "
        "Date: class FakeDate extends Date { static now() { return nowMs; } },",
    )
    return harness.rsplit("(async () => {", 1)[0] + G5_SCENARIOS


G5_NODE_HARNESS = _build_g5_harness()


def _run_g5(tmp_path: Path, scenario: str, timeout: int = 30) -> dict:
    harness = tmp_path / f"g5_harness_{re.sub(r'[^A-Za-z0-9_]+', '_', scenario)}.js"
    harness.write_text(G5_NODE_HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [NODE, str(harness), scenario, str(JS_PATH)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(tmp_path),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    payload = json.loads(completed.stdout)
    assert "error" not in payload, payload
    return payload


def test_ui_offer_and_full_recovery_flow(tmp_path):
    out = _run_g5(tmp_path, "g5_flow")
    assert out["offerShown"] is True
    for copy in (
        "REFUSED",
        "Backend changed during execution.",
        "The candidate workspace and evidence were preserved.",
        "A new owner authorization is required before rerunning.",
        "Prepare governed rerun",
        "Recovery from run control-g5-parent",
    ):
        assert copy in out["offerText"], copy
    # Duplicate clicks issue exactly one recovery POST.
    assert out["recoveryPosts"] == 1
    assert out["stateAfterPrepare"] == "PREPARATION_READY"
    # Backend delta from persisted parent truth and fresh child preparation truth.
    assert "Recovery from run control-g5-parent" in out["factsText"]
    assert "parent-backend-identity-g5" in out["factsText"]
    assert "1234abcd" * 8 in out["factsText"]
    assert "f" * 64 in out["factsText"]
    assert "The parent refusal proved the backend changed during the parent run." in out["factsText"]
    assert out["recovery"]["parentControlRunId"] == "control-g5-parent"
    assert out["recovery"]["hasParentTruth"] is True
    # No silent launch: the child run requires the explicit owner submission.
    assert out["launchPostsBeforeOwner"] == 1
    assert out["launchPosts"] == 2
    assert out["launchHeaders"][1] == "fresh-owner-phrase"
    assert out["launchHeaders"][0] != out["launchHeaders"][1]
    assert "Recovery from run" in out["acceptedText"]
    assert out["childIsRecovery"] is True
    # The child result is shown through the same G4 path, and even a drifted
    # child refusal exposes no second governed rerun offer.
    assert out["childResultState"] == "RUN_RESULT_READY"
    assert out["childOfferShown"] is False
    assert "Prepare governed rerun" not in out["childResultText"]


@pytest.mark.parametrize("variant", ["other_reason", "unauthoritative", "admitted"])
def test_ui_no_offer_for_ineligible_results(tmp_path, variant):
    out = _run_g5(tmp_path, f"g5_no_offer:{variant}")
    assert out["state"] == "RUN_RESULT_READY"
    assert out["offerShown"] is False
    assert out["resultText"] is False


def test_ui_refresh_reconstructs_pending_recovery(tmp_path):
    out = _run_g5(tmp_path, "g5_resume")
    assert out["state"] == "PREPARATION_READY"
    assert out["recovery"]["parentControlRunId"] == "control-g5-parent"
    assert out["recovery"]["hasParentTruth"] is True
    assert "parent-backend-identity-g5" in out["factsText"]
    # Reconstruction never launches and never re-posts recovery creation.
    assert out["launchPosts"] == 0
    assert out["recoveryPosts"] == 0
    assert out["phraseEmpty"] is True


def test_ui_hostile_recovery_values_are_inert(tmp_path):
    out = _run_g5(tmp_path, "g5_hostile")
    assert out["state"] == "PREPARATION_READY"
    assert out["markerInvoked"] == 0
    assert out["unsafeHtmlApi"] == 0
    assert out["createdScriptTags"] == 0
    assert out["recoveryPosts"] == 1
    assert "onerror" in out["factsText"]  # rendered as inert text, not markup


def test_ui_stale_recovery_response_cannot_override_reset(tmp_path):
    out = _run_g5(tmp_path, "g5_stale")
    assert out["inFlight"] is True
    assert out["stateAfterStale"] == "COMPOSE"
    assert out["recoveryAfterStale"] is None
    assert out["noNewRequests"] is True
