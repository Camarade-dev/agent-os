from __future__ import annotations

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import ast
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import (
    WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT,
    WORKFLOW_RECOVERY_V2_MISSION_TEXT,
    WORKFLOW_RECOVERY_VERIFIER_SOURCE,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.native_canary import NativeCanaryAuthorizationPayloadV4
from admissible.product_launcher.authoring import (
    AuthoringError,
    GOLDEN_TEMPLATE_RECOMMENDED_TIMEOUT_SECONDS,
    GOLDEN_WORKFLOW_COMMIT_MESSAGE,
    GOLDEN_WORKFLOW_COMPLETION_CONDITIONS_TEXT,
    GOLDEN_WORKFLOW_GATE_OBJECTIVE,
    GOLDEN_WORKFLOW_INTEROPERABILITY_DISCLOSURE_TEXT,
    GOLDEN_WORKFLOW_MATERIAL_PATHS,
    GOLDEN_WORKFLOW_MISSION_TEXT,
    GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256,
    _write_once,
    author_runtime_contract,
)
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
    DEFAULT_TEMPLATE_ID,
    GOLDEN_TEMPLATE_ID,
    SUPPORTED_TEMPLATE_IDS,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher
from admissible.product_launcher.preflight import (
    INTERACTIVE_AUTHORIZATION_NOTICE,
    PRECOMMITTED_AUTHORIZATION_NOTICE,
    PREFLIGHT_PROTOCOL_MISMATCH,
    STATE_BLOCKED,
    STATE_FAILED,
    STATE_READY,
    compute_interactive_digest,
    consume_ready_preflight,
    parse_preflight_stdout,
)
from admissible.product_launcher.preflight_runner import ProductionPreflightApplication
from admissible.product_launcher.ui_transport import CSRF_HEADER, DIGEST_HEADER, OWNER_HEADER
from admissible.product_service import create_loopback_server, create_product_control_plane
from admissible.product_service.control import ProductControlPlane
from admissible.product_launcher import child_runner as child_runner_module

DIGEST = "d" * 64


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> tuple[Path, str]:
    src = (tmp_path / "source").resolve()
    src.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=src, check=True, capture_output=True)
    _git(src, "config", "user.email", "g25@test.invalid")
    _git(src, "config", "user.name", "g25")
    (src / "README.md").write_text("marker\n", encoding="utf-8")
    _git(src, "add", "README.md")
    _git(src, "commit", "-m", "chore: init")
    head = subprocess.check_output(["git", "-C", str(src), "rev-parse", "HEAD"], text=True).strip()
    return src, head


def _cfg(tmp_path: Path, *, mode: str = AUTHORIZATION_MODE_PRECOMMITTED, **overrides):
    src, head = _repo(tmp_path)
    values = dict(
        source_repository=src,
        required_source_head=head,
        run_parent=(tmp_path / "runs").resolve(),
        contract_documents_directory=(tmp_path / "docs").resolve(),
        executable="provider",
        executable_prefix_args=(),
        attestation_class="package-bin",
        model_default="auto",
        timeout_default=60,
        timeout_maximum=600,
        stdout_byte_limit=8192,
        stderr_byte_limit=8192,
        product_ui_bind_host="127.0.0.1",
        product_ui_bind_port=0,
        g2_bind_host="127.0.0.1",
        g2_bind_port=0,
        authorization_mode=mode,
        open_browser=False,
    )
    values.update(overrides)
    return LauncherConfiguration(**values).validated()


def _owner_input(**extra):
    body = {
        "mission_text": "Implement the configured local marker mission completely.",
        "gate_objective": "Create the configured marker under the local-only contract.",
        "completion_conditions_text": "Stop after the exact one-commit policy passes.",
        "required_material_paths": ["README.md"],
        "commit_message": "feat: add runtime marker",
        "model": "auto",
        "timeout_seconds": 60,
    }
    body.update(extra)
    return body


def _ids(*values):
    return iter(values).__next__


def _request(host, port, method, path, body=None, headers=None):
    conn = HTTPConnection(host, port, timeout=5)
    data = body
    if isinstance(body, dict):
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    conn.request(method, path, body=data, headers=headers or {})
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    parsed = json.loads(raw.decode("utf-8")) if raw and response.getheader("Content-Type", "").startswith("application/json") else raw
    return response.status, dict(response.getheaders()), parsed, raw


def _ui(launcher, method, path, body=None, **extra):
    headers = {
        "Host": f"127.0.0.1:{launcher.ui_port}",
        "Content-Type": "application/json",
        CSRF_HEADER: launcher.csrf_nonce,
        **extra,
    }
    return _request("127.0.0.1", launcher.ui_port, method, path, body=body, headers=headers)


def _fake_payload_dict(profile) -> dict:
    # Minimal structurally valid-looking object is not enough for from_dict.
    # Tests that need READY use an injected preflight returning a real payload
    # built through the G1 type via a stub loader, or return READY with a patched loader.
    return {"status": "PREFLIGHT_READY", "authorization_payload": {"marker": True}}


class FakePayload:
    schema_version = "admissible_native_canary_authorization_payload_v4"
    payload_fingerprint = "a" * 64
    run_id = "run"
    session_id = "session"
    selected_model = "auto"
    timeout_seconds = 60
    backend_attestation_class = "package-bin"
    source_head = "b" * 40
    mission_profile = SimpleNamespace(profile_fingerprint="c" * 64)

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "payload_fingerprint": self.payload_fingerprint,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "selected_model": self.selected_model,
            "timeout_seconds": self.timeout_seconds,
            "backend_attestation_class": self.backend_attestation_class,
            "source_head": self.source_head,
            "mission_profile": {"profile_fingerprint": self.mission_profile.profile_fingerprint},
            "source_repository": "C:/shown/source",
            "run_root": "C:/shown/run",
        }


def test_import_has_no_side_effects():
    before_threads = {t.name for t in threading.enumerate()}
    before_env = dict(os.environ)
    import importlib
    import admissible.product_launcher as pkg
    importlib.reload(pkg)
    assert {t.name for t in threading.enumerate()} == before_threads
    assert dict(os.environ) == before_env


def test_production_construction_uses_canonical_seams(tmp_path):
    cfg = _cfg(tmp_path)
    opened = []
    launcher = ProductLauncher(
        cfg,
        verify_head=True,
        browser_opener=lambda url: opened.append(url),
        id_generator=_ids(*[f"{i:032x}" for i in range(1, 20)]),
    )
    try:
        assert isinstance(launcher._control_plane, ProductControlPlane)
        defaults = ProductControlPlane.__init__.__kwdefaults__
        assert defaults["profile_validator"] is load_native_mission_profile_document
        launcher.start()
        assert launcher.ui_port > 0 and launcher.g2_port > 0
        assert opened == []
        assert launcher.csrf_nonce != launcher._g2_token
        assert len(launcher.csrf_nonce) >= 64
    finally:
        launcher.close()


def test_authoring_canonical_document_write_once_and_bounds(tmp_path):
    cfg = _cfg(tmp_path)
    authored = author_runtime_contract(
        _owner_input(),
        launcher_configuration=cfg,
        documents_directory=cfg.contract_documents_directory,
        id_generator=lambda: "ab" * 16,
    )
    path = Path(authored.document_path)
    assert path.name == "contract-" + ("ab" * 16) + ".json"
    assert path.parent == cfg.contract_documents_directory
    loaded = load_native_mission_profile_document(path)
    assert loaded.profile_fingerprint == authored.profile_fingerprint
    assert authored.contract_summary["gate_clauses"] == [
        {"clause_id": clause_id, "text": text}
        for clause_id, text in loaded.gate_clauses
    ]
    assert canonical_bytes(loaded.to_dict()) == path.read_bytes()
    assert not (cfg.run_parent / loaded.run_id).exists()
    assert list(cfg.run_parent.glob("**/*")) == [] or not any(cfg.run_parent.rglob("*"))
    with pytest.raises(AuthoringError) as first:
        author_runtime_contract(
            _owner_input(),
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "ab" * 16,
        )
    assert first.value.error_code == "DOCUMENT_EXISTS"
    with pytest.raises(AuthoringError) as unknown:
        author_runtime_contract(
            {**_owner_input(), "profile_fingerprint": "f" * 64},
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "cd" * 16,
        )
    assert unknown.value.error_code in {"UNKNOWN_FIELD", "FORBIDDEN_FIELD"}
    with pytest.raises(AuthoringError):
        author_runtime_contract(
            {**_owner_input(), "budgets": [1, 1, 0, 0, 0]},
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "ef" * 16,
        )
    with pytest.raises(AuthoringError):
        author_runtime_contract(
            {**_owner_input(), "extra": 1},
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "11" * 16,
        )
    with pytest.raises(AuthoringError):
        author_runtime_contract(
            {**_owner_input(), "mission_text": "x" * 70_000},
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "22" * 16,
        )
    assert str(cfg.source_repository) == loaded.effective_workspace_source.local_repository_path


def test_builder_rejection_mapped_safely(tmp_path):
    cfg = _cfg(tmp_path)

    def boom(**_kwargs):
        raise ValueError("secret traceback path C:/secret")

    with pytest.raises(AuthoringError) as exc:
        author_runtime_contract(
            _owner_input(),
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "33" * 16,
            profile_builder=boom,
        )
    assert exc.value.error_code == "BUILDER_REJECTED"
    assert "secret" not in repr(exc.value.to_dict())


def test_g2_validation_transit_and_token_custody(tmp_path):
    cfg = _cfg(tmp_path)
    ids = [f"{i:032x}" for i in range(40, 80)]
    launcher = ProductLauncher(cfg, verify_head=True, id_generator=_ids(*ids), browser_opener=lambda _u: None)
    captures = []
    try:
        launcher.start()
        status, headers, body, raw = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        assert status == 200
        assert body["execution_started"] is False
        assert body["authorization_mode"] == AUTHORIZATION_MODE_PRECOMMITTED
        assert "contract_id" in body and body["profile_fingerprint"]
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        assert launcher._g2_token not in json.dumps(body)
        assert all(launcher._g2_token not in f"{k}:{v}" for k, v in headers.items())
        # Browser cannot validate an arbitrary filesystem path through UI.
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/contracts",
            {**_owner_input(), "profile_document": str(tmp_path / "evil.json")},
        )
        assert status == 400
        assert body["error"] == "AUTHORING_REJECTED"
    finally:
        launcher.close()


def test_preflight_parser_adversarial_battery():
    ready = json.dumps({"status": "PREFLIGHT_READY", "authorization_payload": {"x": 1}}, sort_keys=True).encode()
    assert parse_preflight_stdout(ready)["status"] == "PREFLIGHT_READY"
    with pytest.raises(Exception):
        parse_preflight_stdout(b"\xff")
    with pytest.raises(Exception):
        parse_preflight_stdout(b'{"a":1}{"b":2}')
    with pytest.raises(Exception):
        parse_preflight_stdout(b'{"a":1,"a":2}')
    with pytest.raises(Exception):
        parse_preflight_stdout(b"[1]")
    with pytest.raises(Exception):
        parse_preflight_stdout(b'{"a":1} trailing')


def test_preparation_and_launch_precommitted(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    fake = FakePayload()
    printed = {
        "status": "PREFLIGHT_READY",
        "authorization_payload": fake.to_dict(),
    }
    printed_bytes = json.dumps(printed, indent=2).encode("utf-8")  # non-canonical print shape

    def preflight(**_kwargs):
        return 0, printed_bytes

    def loader(_data):
        return fake

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: __import__("admissible.product_launcher.preflight", fromlist=["consume_ready_preflight"]).consume_ready_preflight(
            **{**kwargs, "payload_loader": loader}
        ),
    )
    seen = []

    def app(**kwargs):
        seen.append(
            {
                "phrase": kwargs["owner_authorization"],
                "digest": kwargs["owner_authorization_digest"],
            }
        )
        Path(kwargs["run_root"]).mkdir(parents=True, exist_ok=True)
        return 0

    ids = [f"{i:032x}" for i in range(100, 160)]
    plane = create_product_control_plane(
        run_parent=cfg.run_parent,
        source_repository=cfg.source_repository,
        required_source_head=cfg.required_source_head,
        executable=cfg.executable,
        application=app,
        profile_validator=load_native_mission_profile_document,
        id_generator=_ids(*ids),
    )
    g2 = create_loopback_server(plane, host="127.0.0.1", port=0)
    launcher = ProductLauncher(
        cfg,
        control_plane=plane,
        g2_server=g2,
        preflight_application=preflight,
        verify_head=True,
        id_generator=_ids(*[f"{i:032x}" for i in range(200, 260)]),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        assert status == 200
        cid = authored["contract_id"]
        status, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
        assert status == 202 and prep["state"] in {"QUEUED", "RUNNING"}
        pid = prep["preparation_id"]
        for _ in range(200):
            status, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
            assert status == 200
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        else:
            raise AssertionError(body)
        assert body["authorization_mode"] == AUTHORIZATION_MODE_PRECOMMITTED
        assert body["payload_fingerprint"] == fake.payload_fingerprint
        assert "owner_authorization" not in json.dumps(body)
        assert DIGEST not in json.dumps(body)
        canonical = canonical_bytes(fake.to_dict())
        assert launcher._preparations.get(pid).canonical_payload_bytes == canonical
        assert canonical != printed_bytes
        phrase = "Unicode é\tphrase "
        status, _, launch_body, raw = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid, "preparation_id": pid},
            **{OWNER_HEADER: phrase, DIGEST_HEADER: DIGEST},
        )
        assert status == 202
        assert "product_verdict" not in launch_body
        assert launch_body["control_state"] in {"QUEUED", "STARTING", "RUNNING", "TERMINAL"}
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        for _ in range(200):
            if seen:
                break
            time.sleep(0.01)
        assert seen and seen[0]["phrase"] == phrase and seen[0]["digest"] == DIGEST
        rid = launch_body["control_run_id"]
        for _ in range(200):
            status, _, proxied, _ = _ui(launcher, "GET", f"/ui/api/v1/runs/{rid}")
            if proxied.get("control_state") in {"TERMINAL", "START_FAILED"}:
                break
            time.sleep(0.01)
        # Direct seam preserves exact owner phrase bytes, including leading spaces.
        status, _, authored2, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        cid2 = authored2["contract_id"]
        status, _, prep2, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid2}/preparations", {})
        pid2 = prep2["preparation_id"]
        for _ in range(200):
            status, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid2}")
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        # Whitespace/Unicode survive the shared G2 header transport (leading LWS
        # is HTTP-header-normalized by the stdlib parser, same as raw G2).
        exact = "inner  spaces\tand Unicode é  "
        seen.clear()
        status, body = launcher.launch_run(
            contract_id=cid2,
            preparation_id=pid2,
            owner_authorization=exact,
            owner_authorization_digest=DIGEST,
        )
        assert status == 202
        for _ in range(200):
            if seen:
                break
            time.sleep(0.01)
        assert seen and seen[0]["phrase"] == exact
        # consumed preparation cannot replay
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid, "preparation_id": pid},
            **{OWNER_HEADER: phrase, DIGEST_HEADER: DIGEST},
        )
        assert status == 409
    finally:
        launcher.close()


def test_interactive_mode_digest_and_notice(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, mode=AUTHORIZATION_MODE_INTERACTIVE)
    fake = FakePayload()
    printed = json.dumps({"status": "PREFLIGHT_READY", "authorization_payload": fake.to_dict()}).encode()

    def preflight(**_kwargs):
        return 0, printed

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: __import__("admissible.product_launcher.preflight", fromlist=["consume_ready_preflight"]).consume_ready_preflight(
            **{**kwargs, "payload_loader": lambda _d: fake}
        ),
    )
    seen = []

    def app(**kwargs):
        seen.append(kwargs["owner_authorization_digest"])
        return 0

    plane = create_product_control_plane(
        run_parent=cfg.run_parent,
        source_repository=cfg.source_repository,
        required_source_head=cfg.required_source_head,
        executable=cfg.executable,
        application=app,
        profile_validator=load_native_mission_profile_document,
        id_generator=_ids(*[f"{i:032x}" for i in range(300, 360)]),
    )
    g2 = create_loopback_server(plane)
    launcher = ProductLauncher(
        cfg,
        control_plane=plane,
        g2_server=g2,
        preflight_application=preflight,
        id_generator=_ids(*[f"{i:032x}" for i in range(400, 460)]),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, _, boot, _ = _ui(launcher, "GET", "/ui/api/v1/bootstrap")
        assert status == 200
        assert boot["authorization_mode"] == AUTHORIZATION_MODE_INTERACTIVE
        assert boot["visual_ui_available"] is False
        assert launcher._g2_token not in json.dumps(boot)
        status, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        cid = authored["contract_id"]
        status, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
        pid = prep["preparation_id"]
        for _ in range(200):
            status, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        assert INTERACTIVE_AUTHORIZATION_NOTICE in body["authorization_semantics_notice"]
        phrase = "interactive-phrase"
        expected = compute_interactive_digest(
            phrase=phrase,
            canonical_payload=canonical_bytes(fake.to_dict()),
        )
        status, _, launch_body, raw = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid, "preparation_id": pid},
            **{OWNER_HEADER: phrase},
        )
        assert status == 202
        assert expected not in raw.decode("utf-8", "replace")
        assert expected not in json.dumps(launch_body)
        for _ in range(200):
            if seen:
                break
            time.sleep(0.01)
        assert seen == [expected]
        # no silent fallback: digest header rejected in interactive mode
        status, _, authored2, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        cid2 = authored2["contract_id"]
        status, _, prep2, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid2}/preparations", {})
        pid2 = prep2["preparation_id"]
        for _ in range(200):
            status, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid2}")
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid2, "preparation_id": pid2},
            **{OWNER_HEADER: phrase, DIGEST_HEADER: DIGEST},
        )
        assert status == 400
    finally:
        launcher.close()


def test_csrf_host_origin_and_no_get_mutation(tmp_path):
    cfg = _cfg(tmp_path)
    launcher = ProductLauncher(
        cfg,
        id_generator=_ids(*[f"{i:032x}" for i in range(500, 520)]),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, _, body, raw = _request(
            "127.0.0.1",
            launcher.ui_port,
            "GET",
            "/",
            headers={"Host": f"127.0.0.1:{launcher.ui_port}"},
        )
        assert status == 200
        text = raw.decode("utf-8")
        assert "Admissible" in text and "The model proposes." in text
        assert "Visual Compose/Contract/Authorize interface is not installed in G2.5." not in text
        assert launcher.csrf_nonce in text
        assert launcher._g2_token not in text
        assert "localStorage" not in text and "sessionStorage" not in text
        assert "http" not in text.lower().split("cdn")[0] or "cdn" not in text.lower()
        assert 'src="http' not in text and 'href="http' not in text
        # wrong csrf
        status, _, body, _ = _request(
            "127.0.0.1",
            launcher.ui_port,
            "POST",
            "/ui/api/v1/contracts",
            body=_owner_input(),
            headers={
                "Host": f"127.0.0.1:{launcher.ui_port}",
                "Content-Type": "application/json",
                CSRF_HEADER: "0" * 64,
            },
        )
        assert status == 403 and body["error"] == "INVALID_CSRF"
        status, _, body, _ = _request(
            "127.0.0.1",
            launcher.ui_port,
            "POST",
            "/ui/api/v1/contracts",
            body=_owner_input(),
            headers={
                "Host": "localhost",
                "Content-Type": "application/json",
                CSRF_HEADER: launcher.csrf_nonce,
            },
        )
        assert status == 403 and body["error"] == "INVALID_HOST"
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/contracts",
            _owner_input(),
            Origin="https://evil.example",
        )
        assert status == 403 and body["error"] == "INVALID_ORIGIN"
        # GET must not mutate / create contracts
        before = len(launcher._contracts)
        status, headers, _, _ = _request(
            "127.0.0.1",
            launcher.ui_port,
            "GET",
            "/ui/api/v1/contracts",
            headers={"Host": f"127.0.0.1:{launcher.ui_port}"},
        )
        assert status == 404
        assert len(launcher._contracts) == before
        assert not any(k.lower() == "access-control-allow-origin" for k in headers)
    finally:
        launcher.close()


def test_authorization_material_not_from_json(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    fake = FakePayload()

    def preflight(**_kwargs):
        return 0, json.dumps({"status": "PREFLIGHT_READY", "authorization_payload": fake.to_dict()}).encode()

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: __import__("admissible.product_launcher.preflight", fromlist=["consume_ready_preflight"]).consume_ready_preflight(
            **{**kwargs, "payload_loader": lambda _d: fake}
        ),
    )
    plane = create_product_control_plane(
        run_parent=cfg.run_parent,
        source_repository=cfg.source_repository,
        required_source_head=cfg.required_source_head,
        executable=cfg.executable,
        application=lambda **_k: 0,
        profile_validator=load_native_mission_profile_document,
        id_generator=_ids(*[f"{i:032x}" for i in range(600, 660)]),
    )
    g2 = create_loopback_server(plane)
    launcher = ProductLauncher(
        cfg,
        control_plane=plane,
        g2_server=g2,
        preflight_application=preflight,
        id_generator=_ids(*[f"{i:032x}" for i in range(700, 760)]),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        cid = authored["contract_id"]
        status, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
        pid = prep["preparation_id"]
        for _ in range(200):
            status, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        status, _, body, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {
                "contract_id": cid,
                "preparation_id": pid,
                "owner_authorization": "from-json",
                "owner_authorization_digest": DIGEST,
            },
        )
        assert status == 400 and body["error"] == "INVALID_FIELDS"
    finally:
        launcher.close()


def test_read_proxy_preserves_g2_semantics(tmp_path):
    cfg = _cfg(tmp_path)
    plane = create_product_control_plane(
        run_parent=cfg.run_parent,
        source_repository=cfg.source_repository,
        required_source_head=cfg.required_source_head,
        executable=cfg.executable,
        application=lambda **_k: 0,
        profile_validator=lambda _p: SimpleNamespace(
            schema_version="v2",
            profile_id="p",
            run_id="run",
            session_id="session",
            gate_id="g",
            mission_id="m",
            profile_fingerprint="a" * 64,
            model="auto",
            timeout_seconds=10,
            stdout_byte_limit=1000,
            stderr_byte_limit=1000,
            effective_workspace_source=SimpleNamespace(kind=SimpleNamespace(value="EXISTING_LOCAL_GIT_REPOSITORY")),
            verification_mode=SimpleNamespace(value="OBSERVED_ONLY"),
        ),
        id_generator=_ids("contract", "control"),
    )
    g2 = create_loopback_server(plane)
    launcher = ProductLauncher(
        cfg,
        control_plane=plane,
        g2_server=g2,
        verify_head=False,
        id_generator=_ids(*[f"{i:032x}" for i in range(800, 820)]),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        # seed a validated contract / run through G2 directly
        doc = tmp_path / "p.json"
        doc.write_text("{}", encoding="utf-8")
        from admissible.product_service.http import TOKEN_HEADER

        status, _, body, _ = _request(
            "127.0.0.1",
            launcher.g2_port,
            "POST",
            "/api/v1/contracts/validate",
            body={"profile_document": str(doc.resolve())},
            headers={
                TOKEN_HEADER: g2.control_token,
                "Content-Type": "application/json",
                "Host": f"127.0.0.1:{launcher.g2_port}",
            },
        )
        assert status == 200
        status, _, launch, _ = _request(
            "127.0.0.1",
            launcher.g2_port,
            "POST",
            "/api/v1/runs",
            body={"contract_id": body["contract_id"]},
            headers={
                TOKEN_HEADER: g2.control_token,
                "Content-Type": "application/json",
                "Host": f"127.0.0.1:{launcher.g2_port}",
                OWNER_HEADER: "x",
                DIGEST_HEADER: DIGEST,
            },
        )
        assert status == 202
        rid = launch["control_run_id"]
        for _ in range(200):
            status, _, proxied, raw = _ui(launcher, "GET", f"/ui/api/v1/runs/{rid}")
            if proxied.get("control_state") in {"TERMINAL", "START_FAILED"}:
                break
            time.sleep(0.01)
        assert status == 200
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        status, _, result, _ = _ui(launcher, "GET", f"/ui/api/v1/runs/{rid}/result")
        assert status in {409, 410}
        status, _, listing, _ = _ui(launcher, "GET", "/ui/api/v1/runs")
        assert status == 200 and "control_runs" in listing
    finally:
        launcher.close()


def test_lifecycle_browser_flag_and_shutdown(tmp_path):
    opened = []
    cfg = _cfg(tmp_path, open_browser=True)
    before_env = dict(os.environ)
    before_threads = {t.name for t in threading.enumerate()}
    launcher = ProductLauncher(
        cfg,
        id_generator=_ids(*[f"{i:032x}" for i in range(900, 920)]),
        browser_opener=lambda url: opened.append(url),
    )
    launcher.start()
    assert opened == [f"http://127.0.0.1:{launcher.ui_port}/"]
    ui_port, g2_port = launcher.ui_port, launcher.g2_port
    launcher.close()
    launcher.close()
    assert dict(os.environ) == before_env
    # ports released: binding again should work
    cfg2 = _cfg(tmp_path / "second", open_browser=False)
    launcher2 = ProductLauncher(
        cfg2,
        id_generator=_ids(*[f"{i:032x}" for i in range(920, 940)]),
        browser_opener=lambda _u: None,
    )
    try:
        launcher2.start()
        assert launcher2.ui_port > 0
    finally:
        launcher2.close()
    leftover = {t.name for t in threading.enumerate()} - before_threads
    assert not any(name.startswith("admissible-g2") for name in leftover)


# The trees that stay frozen against launcher-slice drift. A trailing slash
# matches a whole subtree; a bare filename matches only that exact file.
PROTECTED_PATH_PREFIXES = (
    "admissible/delegated_gate/",
    "admissible/product_service/",
    "admissible/product_read_model/",
    "admissible/checkpoint.py",
)

# Accepted history since the G2.4 base, enumerated file by file. Authorizing a
# whole protected directory would make the guard vacuous, so every entry names
# one reviewed file:
#   - the golden result-presentation repair re-opened the run reconstruction;
#   - the governed backend-drift rerun authorized the renderer (secret-safe
#     authorization exposure in result JSON);
#   - the behavioral backend-authority consistency repair authorized the native
#     canary (behavioral-entry policy) and the native executor (behavioral-lane
#     store binding);
#   - neon-siege-v1 governed native canary preflight (eee9620) introduced the
#     fixture registry, mission profile and neon siege mission;
#   - V0.3 Step 1 authorized gate-clause visibility (4da0b39) surfaced the
#     existing clauses through the read-model view type and the control plane.
#   - V0.3 Step 2A/2A.1 authorized the inert ClaimAuthority schema and its
#     pre-integration hardening in mission_profile.py and native_canary.py.
AUTHORIZED_REPAIR_PATHS = frozenset({
    "admissible/product_read_model/read_model.py",
    "admissible/product_read_model/renderer.py",
    "admissible/delegated_gate/native_canary.py",
    "admissible/delegated_gate/native_executor.py",
    "admissible/delegated_gate/fixture_registry.py",
    "admissible/delegated_gate/mission_profile.py",
    "admissible/delegated_gate/neon_siege_mission.py",
    "admissible/product_read_model/presentation_types.py",
    "admissible/product_service/control.py",
})


def _unauthorized_protected_paths(changed_paths, authorized=AUTHORIZED_REPAIR_PATHS):
    """Return every changed protected path that is not explicitly authorized.

    The complete protected set is evaluated for every candidate path, so a single
    stale authorization can no longer terminate the guard early and hide later
    protected-path violations behind it.
    """

    violations = []
    for raw in changed_paths:
        path = raw.strip()
        if not path or path in authorized:
            continue
        if any(
            path.startswith(prefix) if prefix.endswith("/") else path == prefix
            for prefix in PROTECTED_PATH_PREFIXES
        ):
            violations.append(path)
    return sorted(violations)


def _changed_since_g2_4_base(root):
    return subprocess.check_output(
        ["git", "diff", "--name-only", "1f2949d42fb79e9407035822c65b6f889650d689"],
        cwd=root,
        text=True,
    ).splitlines()


def test_child_runner_unchanged_and_protected_paths_unmodified():
    root = Path(__file__).resolve().parents[1]
    violations = _unauthorized_protected_paths(_changed_since_g2_4_base(root))
    assert violations == [], f"unauthorized protected-path changes: {violations}"
    # child_runner substantive body unchanged vs base unless import-only
    base = subprocess.check_output(
        ["git", "show", "1f2949d42fb79e9407035822c65b6f889650d689:admissible/product_launcher/child_runner.py"],
        cwd=root,
    )
    current = (root / "admissible/product_launcher/child_runner.py").read_bytes()
    assert current.replace(b"\r\n", b"\n") == base.replace(b"\r\n", b"\n")
    assert child_runner_module.ProductionChildApplication is not None


def test_protected_path_guard_still_rejects_unauthorized_changes():
    """The guard must fail on a genuinely unauthorized protected path.

    A guard that passes only because its authorization set swallowed a whole
    directory - or because it stopped at the first stale entry - would be
    vacuous, so each protected tree is probed independently and the real
    repository state is required to stay clean at the same time.
    """

    root = Path(__file__).resolve().parents[1]
    real = _changed_since_g2_4_base(root)
    assert _unauthorized_protected_paths(real) == []

    # One intruder per protected tree, each alongside the real accepted history,
    # proves no protected tree lost its coverage and that later entries are still
    # evaluated after earlier ones match an authorized path.
    for intruder in (
        "admissible/delegated_gate/native_canary_patch.py",
        "admissible/product_service/control_plane_v2.py",
        "admissible/product_read_model/read_model_v2.py",
        "admissible/checkpoint.py",
    ):
        assert _unauthorized_protected_paths(list(real) + [intruder]) == [intruder]

    # Several unauthorized paths at once are all reported, not just the first.
    intruders = [
        "admissible/checkpoint.py",
        "admissible/product_read_model/read_model_v2.py",
        "admissible/product_service/control_plane_v2.py",
    ]
    assert _unauthorized_protected_paths(list(real) + intruders) == sorted(intruders)

    # Authorization is per file, never per directory.
    assert _unauthorized_protected_paths(["admissible/product_service/control.py"]) == []
    assert _unauthorized_protected_paths(["admissible/product_service/other.py"]) == [
        "admissible/product_service/other.py"
    ]
    assert _unauthorized_protected_paths(["admissible/product_read_model/renderer.py"]) == []
    assert _unauthorized_protected_paths(["admissible/product_read_model/renderer_v2.py"]) == [
        "admissible/product_read_model/renderer_v2.py"
    ]

    # A bare protected filename must not match by prefix.
    assert _unauthorized_protected_paths(["admissible/checkpoint_helpers.py"]) == []

    # Unprotected trees stay out of scope.
    assert _unauthorized_protected_paths(["tests/test_admissible_product_launcher_g2_5.py"]) == []
    assert _unauthorized_protected_paths(["admissible/product_ui/app.js"]) == []

    # Every authorized entry must actually live in a protected tree, otherwise the
    # authorization list is silently accumulating dead entries.
    for authorized in AUTHORIZED_REPAIR_PATHS:
        assert _unauthorized_protected_paths([authorized], authorized=frozenset()) == [authorized]


def test_live_rehearsal_end_to_end(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    fake = FakePayload()
    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: __import__("admissible.product_launcher.preflight", fromlist=["consume_ready_preflight"]).consume_ready_preflight(
            **{
                **kwargs,
                "payload_loader": lambda _d: fake,
            }
        ),
    )

    def preflight(**_kwargs):
        return 0, json.dumps({"status": "PREFLIGHT_READY", "authorization_payload": fake.to_dict()}).encode()

    def app(**kwargs):
        Path(kwargs["run_root"]).mkdir(parents=True, exist_ok=True)
        return 0

    plane = create_product_control_plane(
        run_parent=cfg.run_parent,
        source_repository=cfg.source_repository,
        required_source_head=cfg.required_source_head,
        executable=cfg.executable,
        application=app,
        profile_validator=load_native_mission_profile_document,
        id_generator=_ids(*[f"{i:032x}" for i in range(1000, 1060)]),
    )
    g2 = create_loopback_server(plane)
    captured = []
    launcher = ProductLauncher(
        cfg,
        control_plane=plane,
        g2_server=g2,
        preflight_application=preflight,
        id_generator=_ids(*[f"{i:032x}" for i in range(1100, 1160)]),
        browser_opener=lambda url: captured.append(url),
    )
    try:
        launcher.start()
        status, _, _, raw = _request(
            "127.0.0.1",
            launcher.ui_port,
            "GET",
            "/",
            headers={"Host": f"127.0.0.1:{launcher.ui_port}"},
        )
        assert status == 200 and launcher._g2_token not in raw.decode()
        status, _, boot, _ = _ui(launcher, "GET", "/ui/api/v1/bootstrap")
        assert status == 200 and boot["csrf_nonce"] == launcher.csrf_nonce
        status, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
        assert status == 200
        cid = authored["contract_id"]
        status, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
        pid = prep["preparation_id"]
        for _ in range(200):
            status, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        status, _, launch, raw = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid, "preparation_id": pid},
            **{OWNER_HEADER: "owner", DIGEST_HEADER: DIGEST},
        )
        assert status == 202 and "product_verdict" not in launch
        assert launcher._g2_token not in raw.decode()
        rid = launch["control_run_id"]
        for _ in range(200):
            status, _, proxied, _ = _ui(launcher, "GET", f"/ui/api/v1/runs/{rid}")
            if proxied.get("control_state") in {"TERMINAL", "START_FAILED"}:
                break
            time.sleep(0.01)
        assert status == 200
    finally:
        launcher.close()
    assert captured == []


def test_ast_parse_changed_launcher_files():
    root = Path(__file__).resolve().parents[1] / "admissible" / "product_launcher"
    for path in root.glob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


# ---------------------------------------------------------------------------
# G2.5 pre-G3 repair battery (F-001..F-009)
# ---------------------------------------------------------------------------


def _hex_ids(start: int):
    counter = itertools.count(start)
    return lambda: f"{next(counter):032x}"


class _GateG2Server:
    """Real loopback fake G2 endpoint with a gate-controlled /runs route."""

    host = "127.0.0.1"

    def __init__(self):
        self.control_token = "f" * 64
        self.run_calls = []
        self.validate_count = 0
        self.hold = False
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.responses = []
        self.die_once = False
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
                    gate.run_calls.append(
                        {
                            "phrase": self.headers.get(OWNER_HEADER),
                            "digest": self.headers.get(DIGEST_HEADER),
                        }
                    )
                    gate.arrived.set()
                    if gate.hold:
                        gate.release.wait(timeout=30)
                    if gate.die_once:
                        gate.die_once = False
                        self.close_connection = True
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        return
                    if gate.responses:
                        status, payload = gate.responses.pop(0)
                    else:
                        status, payload = 202, {
                            "control_run_id": "control-run",
                            "control_state": "QUEUED",
                        }
                    self._reply(status, payload)
                    return
                self._reply(404, {"error": "NOT_FOUND"})

            def do_GET(self):
                self._reply(404, {"error": "NOT_FOUND"})

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = None

    @property
    def port(self):
        return self._server.server_port

    def start(self):
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="admissible-test-fake-g2"
        )
        self._thread.start()
        return self

    def stop(self):
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join()
            self._thread = None
        self._server.server_close()


def _gate_stack(tmp_path, monkeypatch, *, mode=AUTHORIZATION_MODE_PRECOMMITTED, id_start=30_000):
    cfg = _cfg(tmp_path, mode=mode)
    fake = FakePayload()

    def preflight(**_kwargs):
        return 0, json.dumps(
            {"status": "PREFLIGHT_READY", "authorization_payload": fake.to_dict()}
        ).encode()

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: consume_ready_preflight(
            **{**kwargs, "payload_loader": lambda _d: fake}
        ),
    )
    gate = _GateG2Server()
    launcher = ProductLauncher(
        cfg,
        control_plane=SimpleNamespace(),
        g2_server=gate,
        preflight_application=preflight,
        id_generator=_hex_ids(id_start),
        browser_opener=lambda _u: None,
    )
    launcher.start()
    return launcher, gate, fake


def _make_ready(launcher):
    status, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
    assert status == 200, authored
    cid = authored["contract_id"]
    status, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
    assert status == 202, prep
    pid = prep["preparation_id"]
    for _ in range(400):
        _, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
        if body["state"] == STATE_READY:
            return cid, pid
        time.sleep(0.01)
    raise AssertionError(body)


def _raw_request(port: int, header_lines: list[bytes], body: bytes = b"") -> tuple[int, bytes]:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(b"\r\n".join(header_lines) + b"\r\n\r\n" + body)
        chunks = []
        while True:
            try:
                chunk = conn.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    return int(raw.split(b" ", 2)[1]), raw


def test_raw_socket_header_multiplicity_battery(tmp_path, monkeypatch):
    launcher, gate, _fake = _gate_stack(tmp_path, monkeypatch, id_start=40_000)
    try:
        cid, pid = _make_ready(launcher)
        port = launcher.ui_port
        host = f"127.0.0.1:{port}"
        origin = f"http://127.0.0.1:{port}"
        nonce = launcher.csrf_nonce
        body = json.dumps(
            {"contract_id": cid, "preparation_id": pid},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        def build(*, hosts=None, origins=(), csrfs=None, owners=(), digests=(), lengths=None, transfer=None):
            lines = [b"POST /ui/api/v1/runs HTTP/1.1"]
            for value in (hosts if hosts is not None else [host]):
                lines.append(f"Host: {value}".encode("latin-1"))
            for value in origins:
                lines.append(f"Origin: {value}".encode("latin-1"))
            lines.append(b"Content-Type: application/json")
            for value in (csrfs if csrfs is not None else [nonce]):
                lines.append(f"{CSRF_HEADER}: {value}".encode("latin-1"))
            for value in owners:
                lines.append(f"{OWNER_HEADER}: {value}".encode("latin-1"))
            for value in digests:
                lines.append(f"{DIGEST_HEADER}: {value}".encode("latin-1"))
            for value in (lengths if lengths is not None else [str(len(body))]):
                lines.append(f"Content-Length: {value}".encode("latin-1"))
            if transfer is not None:
                lines.append(f"Transfer-Encoding: {transfer}".encode("latin-1"))
            lines.append(b"Connection: close")
            return lines

        length = str(len(body))
        cases = [
            (build(hosts=[host, host]), 403, "INVALID_HOST"),
            (build(hosts=[host, "127.0.0.1:1"]), 403, "INVALID_HOST"),
            (build(hosts=[f"{host}, {host}"]), 403, "INVALID_HOST"),
            (build(hosts=[]), 403, "INVALID_HOST"),
            (build(hosts=[f"owner@{host}"]), 403, "INVALID_HOST"),
            (build(hosts=["localhost:" + str(port)]), 403, "INVALID_HOST"),
            (build(origins=[origin, origin]), 403, "INVALID_ORIGIN"),
            (build(origins=[origin, "http://evil.example"]), 403, "INVALID_ORIGIN"),
            (build(origins=["null"]), 403, "INVALID_ORIGIN"),
            (build(origins=[f"{origin}, {origin}"]), 403, "INVALID_ORIGIN"),
            (build(origins=[f"https://127.0.0.1:{port}"]), 403, "INVALID_ORIGIN"),
            (build(csrfs=[nonce, nonce]), 403, "INVALID_CSRF"),
            (build(csrfs=[f"{nonce}, {nonce}"]), 403, "INVALID_CSRF"),
            (build(csrfs=[]), 403, "INVALID_CSRF"),
            (build(csrfs=[nonce[:10] + " " + nonce[10:]]), 403, "INVALID_CSRF"),
            (build(owners=["p", "p"], digests=[DIGEST]), 400, "OWNER_AUTHORIZATION_INVALID"),
            (build(owners=["p", "q"], digests=[DIGEST]), 400, "OWNER_AUTHORIZATION_INVALID"),
            (build(owners=["a" * 4097], digests=[DIGEST]), 400, "OWNER_AUTHORIZATION_INVALID"),
            (build(digests=[DIGEST]), 400, "OWNER_AUTHORIZATION_REQUIRED"),
            (build(owners=["p"], digests=[DIGEST, DIGEST]), 400, "OWNER_AUTHORIZATION_DIGEST_INVALID"),
            (build(lengths=[f"+{length}"]), 400, "CONTENT_LENGTH_INVALID"),
            (build(lengths=["-1"]), 400, "CONTENT_LENGTH_INVALID"),
            (build(lengths=[length, length]), 400, "CONTENT_LENGTH_INVALID"),
            (build(lengths=["0x10"]), 400, "CONTENT_LENGTH_INVALID"),
            (build(lengths=[f"{length}.0"]), 400, "CONTENT_LENGTH_INVALID"),
            (build(lengths=[f"{length},{length}"]), 400, "CONTENT_LENGTH_INVALID"),
            (build(lengths=[]), 411, "CONTENT_LENGTH_REQUIRED"),
            (build(lengths=[length], transfer="chunked"), 400, "UNBOUNDED_BODY"),
            (build(lengths=[], transfer="chunked"), 400, "UNBOUNDED_BODY"),
        ]
        for lines, expected_status, expected_error in cases:
            status, raw = _raw_request(port, lines, body)
            assert status == expected_status, raw
            assert f'"error":"{expected_error}"'.encode() in raw
        # Leading zeroes satisfy the decimal-only law; the request proceeds to
        # the owner-authorization stage instead of a framing rejection.
        status, raw = _raw_request(port, build(lengths=["0" + length]), body)
        assert status == 400 and b'"error":"OWNER_AUTHORIZATION_REQUIRED"' in raw
        # No launcher or G2 state was mutated by any rejected request.
        assert gate.run_calls == []
        assert len(launcher._contracts) == 1
        _, _, prep_body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
        assert prep_body["state"] == STATE_READY and prep_body["consumed"] is False
        # The untouched preparation still launches cleanly afterwards.
        status, _, launch, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid, "preparation_id": pid},
            **{OWNER_HEADER: "owner", DIGEST_HEADER: DIGEST},
        )
        assert status == 202, launch
        assert len(gate.run_calls) == 1
    finally:
        launcher.close()


def test_document_write_failure_cleanup_battery(tmp_path):
    directory = (tmp_path / "docs-cleanup").resolve()
    directory.mkdir(parents=True, exist_ok=True)
    payload = b'{"marker":1}'

    def boom(*_args, **_kwargs):
        raise OSError(28, "injected failure")

    target = directory / "contract-aa.json"
    with pytest.raises(AuthoringError) as write_exc:
        _write_once(target, payload, write=boom)
    assert write_exc.value.error_code == "DOCUMENT_WRITE_FAILED"
    assert not target.exists()

    target = directory / "contract-bb.json"
    with pytest.raises(AuthoringError) as fsync_exc:
        _write_once(target, payload, fsync=boom)
    assert fsync_exc.value.error_code == "DOCUMENT_WRITE_FAILED"
    assert not target.exists()

    def close_then_fail(fd):
        os.close(fd)
        raise OSError(5, "injected close failure")

    target = directory / "contract-cc.json"
    with pytest.raises(AuthoringError) as close_exc:
        _write_once(target, payload, close=close_then_fail)
    assert close_exc.value.error_code == "DOCUMENT_WRITE_FAILED"
    assert not target.exists()

    # Cleanup failure is bounded, never echoes OS text or the residual path to
    # the browser payload, and records the residual path internally only.
    target = directory / "contract-dd.json"
    with pytest.raises(AuthoringError) as cleanup_exc:
        _write_once(target, payload, fsync=boom, unlink=boom)
    assert cleanup_exc.value.error_code == "DOCUMENT_CLEANUP_FAILED"
    browser_visible = json.dumps(cleanup_exc.value.to_dict())
    assert "contract-dd" not in browser_visible
    assert "injected" not in browser_visible
    assert cleanup_exc.value.internal_residual_path.endswith("contract-dd.json")
    assert target.exists()
    target.unlink()


def test_author_fsync_failure_leaves_no_document_and_no_registration(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)

    def fsync_boom(_fd):
        raise OSError(28, "injected fsync failure")

    monkeypatch.setattr("admissible.product_launcher.authoring.os.fsync", fsync_boom)
    with pytest.raises(AuthoringError) as exc:
        author_runtime_contract(
            _owner_input(),
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "55" * 16,
        )
    assert exc.value.error_code == "DOCUMENT_WRITE_FAILED"
    assert "injected" not in json.dumps(exc.value.to_dict())
    assert list(Path(cfg.contract_documents_directory).glob("*")) == []


def test_collision_never_deletes_preexisting_document(tmp_path):
    cfg = _cfg(tmp_path)
    directory = Path(cfg.contract_documents_directory)
    directory.mkdir(parents=True, exist_ok=True)
    pre_existing = directory / ("contract-" + "ab" * 16 + ".json")
    pre_existing.write_bytes(b"pre-existing document")
    with pytest.raises(AuthoringError) as exc:
        author_runtime_contract(
            _owner_input(),
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "ab" * 16,
        )
    assert exc.value.error_code == "DOCUMENT_EXISTS"
    assert pre_existing.read_bytes() == b"pre-existing document"


def test_preflight_status_return_pairing_matrix():
    fake = FakePayload()
    loader_calls = []

    def loader(data):
        loader_calls.append(data)
        return fake

    def stdout_for(status_value):
        return json.dumps(
            {
                "status": status_value,
                "authorization_payload": fake.to_dict(),
                "reason_code": "RC",
            }
        ).encode()

    for status_value in ("PREFLIGHT_READY", "PREFLIGHT_BLOCKED", "PREFLIGHT_UNKNOWN"):
        for code in (0, 1, 2, 64):
            loader_calls.clear()
            state, payload, summary = consume_ready_preflight(
                return_code=code,
                stdout=stdout_for(status_value),
                payload_loader=loader,
            )
            if status_value == "PREFLIGHT_READY" and code == 0:
                assert state == STATE_READY
                assert payload is fake and summary is None
                assert loader_calls
            elif status_value == "PREFLIGHT_BLOCKED" and code == 2:
                assert state == STATE_BLOCKED and payload is None
                assert summary["error_type"] == "PREFLIGHT_BLOCKED"
                assert summary["reason_code"] == "RC"
                assert not loader_calls
            else:
                assert state == STATE_FAILED and payload is None
                assert summary == {"error_type": PREFLIGHT_PROTOCOL_MISMATCH}
                assert not loader_calls


def test_preflight_protocol_mismatch_through_launcher(tmp_path):
    cfg = _cfg(tmp_path)
    fake = FakePayload()
    behavior = {"code": 1, "status": "PREFLIGHT_READY"}

    def preflight(**_kwargs):
        printed = json.dumps(
            {
                "status": behavior["status"],
                "authorization_payload": fake.to_dict(),
                "reason_code": "SOURCE_DRIFT",
            }
        ).encode()
        return behavior["code"], printed

    gate = _GateG2Server()
    launcher = ProductLauncher(
        cfg,
        control_plane=SimpleNamespace(),
        g2_server=gate,
        preflight_application=preflight,
        id_generator=_hex_ids(60_000),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()

        def one_preparation():
            _, _, authored, _ = _ui(launcher, "POST", "/ui/api/v1/contracts", _owner_input())
            cid = authored["contract_id"]
            _, _, prep, _ = _ui(launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {})
            pid = prep["preparation_id"]
            for _ in range(400):
                _, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
                if body["state"] not in {"QUEUED", "RUNNING"}:
                    return cid, pid, body
                time.sleep(0.01)
            raise AssertionError(body)

        # READY status paired with wrapper exit code 1 is a protocol mismatch.
        cid, pid, body = one_preparation()
        assert body["state"] == STATE_FAILED
        assert body["error_type"] == PREFLIGHT_PROTOCOL_MISMATCH
        assert body["blocked_summary"] is None
        assert body["payload_fingerprint"] is None
        assert body["authorization_payload"] is None
        assert launcher._preparations.get(pid).canonical_payload_bytes is None
        status, launch = launcher.launch_run(
            contract_id=cid,
            preparation_id=pid,
            owner_authorization="p",
            owner_authorization_digest=DIGEST,
        )
        assert (status, launch["error"]) == (409, "PREPARATION_NOT_READY")
        assert gate.run_calls == []
        # BLOCKED status paired with exit code 0 is a mismatch, never BLOCKED.
        behavior.update(code=0, status="PREFLIGHT_BLOCKED")
        _cid, _pid, body = one_preparation()
        assert body["state"] == STATE_FAILED
        assert body["error_type"] == PREFLIGHT_PROTOCOL_MISMATCH
        assert body["blocked_summary"] is None
        # BLOCKED with exit code 2 remains a true blocked preparation.
        behavior.update(code=2, status="PREFLIGHT_BLOCKED")
        _cid, _pid, body = one_preparation()
        assert body["state"] == STATE_BLOCKED
        assert body["blocked_summary"]["error_type"] == "PREFLIGHT_BLOCKED"
        assert body["blocked_summary"]["reason_code"] == "SOURCE_DRIFT"
    finally:
        launcher.close()


def test_preparation_one_shot_reservation_race(tmp_path, monkeypatch):
    launcher, gate, _fake = _gate_stack(tmp_path, monkeypatch, id_start=50_000)
    try:
        cid, pid = _make_ready(launcher)
        gate.hold = True
        barrier = threading.Barrier(8)
        results = []
        results_lock = threading.Lock()

        def attempt():
            barrier.wait()
            status, body = launcher.launch_run(
                contract_id=cid,
                preparation_id=pid,
                owner_authorization="race-phrase",
                owner_authorization_digest=DIGEST,
            )
            with results_lock:
                results.append((status, body.get("error")))

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        assert gate.arrived.wait(timeout=10)
        # The seven losers must fail locally while the single winner is still
        # held inside the G2 call.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with results_lock:
                if len(results) == 7:
                    break
            time.sleep(0.01)
        with results_lock:
            assert len(results) == 7, results
            assert results.count((409, "PREPARATION_IN_USE")) == 7, results
        gate.release.set()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
        with results_lock:
            outcomes = list(results)
        assert outcomes.count((409, "PREPARATION_IN_USE")) == 7
        assert outcomes.count((202, None)) == 1
        # One-shot is enforced locally: G2 saw exactly one launch request, so
        # a second G2 RUN_CONFLICT was never the mechanism.
        assert len(gate.run_calls) == 1
        status, body = launcher.launch_run(
            contract_id=cid,
            preparation_id=pid,
            owner_authorization="race-phrase",
            owner_authorization_digest=DIGEST,
        )
        assert (status, body["error"]) == (409, "PREPARATION_CONSUMED")
        assert len(gate.run_calls) == 1
        _, _, prep_body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
        assert prep_body["consumed"] is True
        dumped = json.dumps(prep_body)
        assert "race-phrase" not in dumped and DIGEST not in dumped
    finally:
        gate.release.set()
        launcher.close()


def test_reservation_cleared_on_non_202_and_proxy_exception(tmp_path, monkeypatch):
    launcher, gate, _fake = _gate_stack(tmp_path, monkeypatch, id_start=55_000)
    try:
        cid, pid = _make_ready(launcher)
        request_body = {"contract_id": cid, "preparation_id": pid}
        launch_headers = {OWNER_HEADER: "retry-phrase", DIGEST_HEADER: DIGEST}

        def prep_state():
            _, _, body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
            return body["state"], body["consumed"]

        gate.responses = [(400, {"error": "AUTHORIZATION_REJECTED"})]
        status, _, body, _ = _ui(launcher, "POST", "/ui/api/v1/runs", request_body, **launch_headers)
        assert (status, body["error"]) == (400, "AUTHORIZATION_REJECTED")
        assert prep_state() == (STATE_READY, False)

        gate.responses = [(409, {"error": "RUN_CONFLICT"})]
        status, _, body, _ = _ui(launcher, "POST", "/ui/api/v1/runs", request_body, **launch_headers)
        assert (status, body["error"]) == (409, "RUN_CONFLICT")
        assert prep_state() == (STATE_READY, False)

        gate.die_once = True
        status, _, body, _ = _ui(launcher, "POST", "/ui/api/v1/runs", request_body, **launch_headers)
        assert (status, body["error"]) == (500, "WRITE_UNAVAILABLE")
        assert prep_state() == (STATE_READY, False)

        status, _, body, _ = _ui(launcher, "POST", "/ui/api/v1/runs", request_body, **launch_headers)
        assert status == 202, body
        assert prep_state()[1] is True

        status, _, body, _ = _ui(launcher, "POST", "/ui/api/v1/runs", request_body, **launch_headers)
        assert (status, body["error"]) == (409, "PREPARATION_CONSUMED")
        assert len(gate.run_calls) == 4
    finally:
        launcher.close()


def test_owner_phrase_encoding_law_and_independent_digest(tmp_path, monkeypatch):
    launcher, gate, fake = _gate_stack(
        tmp_path, monkeypatch, mode=AUTHORIZATION_MODE_INTERACTIVE, id_start=70_000
    )
    try:
        # Independently captured canonical payload bytes via the G1 canonical
        # encoder; the production digest helper is never used for expectations.
        canonical = canonical_bytes(fake.to_dict())

        def expected_digest(phrase):
            return hashlib.sha256(phrase.encode("utf-8") + b"\0" + canonical).hexdigest()

        for phrase in ("café é", "boundary ÿ end"):
            cid, pid = _make_ready(launcher)
            before = len(gate.run_calls)
            status, _, launch, _ = _ui(
                launcher,
                "POST",
                "/ui/api/v1/runs",
                {"contract_id": cid, "preparation_id": pid},
                **{OWNER_HEADER: phrase},
            )
            assert status == 202, launch
            assert len(gate.run_calls) == before + 1
            assert gate.run_calls[-1]["digest"] == expected_digest(phrase)
            assert gate.run_calls[-1]["phrase"] == phrase
        # Direct-seam phrases pin exact Python-string preservation where HTTP
        # header whitespace normalization would otherwise interfere.
        for phrase in (" padded \t trailing ", "line1\r\n line2"):
            cid, pid = _make_ready(launcher)
            before = len(gate.run_calls)
            status, _launch = launcher.launch_run(
                contract_id=cid,
                preparation_id=pid,
                owner_authorization=phrase,
                owner_authorization_digest=None,
            )
            assert status == 202
            assert len(gate.run_calls) == before + 1
            assert gate.run_calls[-1]["digest"] == expected_digest(phrase)
        # Non-Latin-1 phrase: stable bounded 400 before digest calculation or
        # any G2 proxy call; the preparation remains available.
        cid, pid = _make_ready(launcher)
        before = len(gate.run_calls)
        status, body = launcher.launch_run(
            contract_id=cid,
            preparation_id=pid,
            owner_authorization="rocket \U0001F680",
            owner_authorization_digest=None,
        )
        assert (status, body) == (400, {"error": "OWNER_AUTHORIZATION_ENCODING_UNSUPPORTED"})
        assert len(gate.run_calls) == before
        _, _, prep_body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
        assert prep_body["state"] == STATE_READY and prep_body["consumed"] is False
        status, _body = launcher.launch_run(
            contract_id=cid,
            preparation_id=pid,
            owner_authorization="supported é",
            owner_authorization_digest=None,
        )
        assert status == 202
        assert gate.run_calls[-1]["digest"] == expected_digest("supported é")
    finally:
        launcher.close()


def test_bootstrap_authorization_disclosure_both_modes(tmp_path):
    for mode, notice in (
        (AUTHORIZATION_MODE_PRECOMMITTED, PRECOMMITTED_AUTHORIZATION_NOTICE),
        (AUTHORIZATION_MODE_INTERACTIVE, INTERACTIVE_AUTHORIZATION_NOTICE),
    ):
        cfg = _cfg(tmp_path / mode.lower(), mode=mode)
        launcher = ProductLauncher(
            cfg,
            id_generator=_hex_ids(80_000),
            browser_opener=lambda _u: None,
        )
        try:
            launcher.start()
            status, _, boot, _ = _ui(launcher, "GET", "/ui/api/v1/bootstrap")
            assert status == 200
            assert boot["authorization_mode"] == mode
            assert boot["authorization_semantics_notice"] == notice
            assert boot["owner_authorization_encoding"] == "latin-1"
        finally:
            launcher.close()
    assert "unchanged and never derives it" in PRECOMMITTED_AUTHORIZATION_NOTICE
    assert "interactive bound confirmation" in INTERACTIVE_AUTHORIZATION_NOTICE


def test_rejected_request_closes_connection_before_pipelined_follow_up(tmp_path, monkeypatch):
    """Rejected UI requests must close TCP before unread body can feed a pipelined follow-up."""
    before_threads = {t.name for t in threading.enumerate()}
    launcher, gate, _fake = _gate_stack(tmp_path, monkeypatch, id_start=90_000)
    phrase = "pipeline-owner"
    try:
        cid, pid = _make_ready(launcher)
        preparation = launcher._preparations.get(pid)
        assert preparation is not None
        assert preparation.consumed is False
        assert preparation.launch_reserved is False
        assert len(gate.run_calls) == 0

        port = launcher.ui_port
        host = f"127.0.0.1:{port}"
        nonce = launcher.csrf_nonce
        run_body = json.dumps(
            {"contract_id": cid, "preparation_id": pid},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        assert len(run_body) > 0

        rejected = b"\r\n".join(
            [
                b"POST /ui/api/v1/runs HTTP/1.1",
                f"Host: {host}".encode("latin-1"),
                b"Content-Type: application/json",
                b"X-Admissible-UI-CSRF: not-the-csrf-nonce",
                f"Content-Length: {len(run_body)}".encode("ascii"),
                b"",
                run_body,
            ]
        )
        valid = b"\r\n".join(
            [
                b"POST /ui/api/v1/runs HTTP/1.1",
                f"Host: {host}".encode("latin-1"),
                b"Content-Type: application/json",
                f"{CSRF_HEADER}: {nonce}".encode("latin-1"),
                f"{OWNER_HEADER}: {phrase}".encode("latin-1"),
                f"{DIGEST_HEADER}: {DIGEST}".encode("latin-1"),
                f"Content-Length: {len(run_body)}".encode("ascii"),
                b"",
                run_body,
            ]
        )
        assert b"Connection: close" not in rejected
        assert b"Connection: close" not in valid

        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.settimeout(5)
            # Transmit both requests on one write before reading any response.
            conn.sendall(rejected + valid)
            chunks: list[bytes] = []
            saw_eof = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    saw_eof = True
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)

        assert saw_eof, raw
        # Count every wire status-line token. Pipelined keep-alive responses may
        # be concatenated directly after a prior body with no intervening LF, so
        # a ^/MULTILINE scan would miss the follow-up.
        status_lines = re.findall(rb"HTTP/1\.[01] \d{3} ", raw)
        assert len(status_lines) == 1, raw
        assert status_lines[0] == b"HTTP/1.1 403 "
        assert raw.startswith(b"HTTP/1.1 403 ")
        assert b'"error":"INVALID_CSRF"' in raw
        assert b"HTTP/1.1 202 " not in raw

        assert len(gate.run_calls) == 0
        preparation = launcher._preparations.get(pid)
        assert preparation is not None
        assert preparation.consumed is False
        assert preparation.launch_reserved is False
        assert cid in launcher._contracts
        _, _, prep_body, _ = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
        assert prep_body["state"] == STATE_READY
        assert prep_body["consumed"] is False

        text = raw.decode("utf-8", "replace")
        assert phrase not in text
        assert DIGEST not in text
        assert nonce not in text
    finally:
        launcher.close()

    leftover = {t.name for t in threading.enumerate()} - before_threads
    assert not any(name.startswith("admissible-") for name in leftover), leftover


# ---------------------------------------------------------------------------
# Golden trusted template battery: workflow-recovery-verified-v1
# ---------------------------------------------------------------------------

GOLDEN_PINNED_VERIFIER_SHA256 = (
    "a4e2daf9179129a7929bea5825f95f494ed601eb4a9bbbbaf6a65eb3918149e1"
)


def _golden_owner_input(**extra):
    body = {
        "mission_text": GOLDEN_WORKFLOW_MISSION_TEXT,
        "gate_objective": GOLDEN_WORKFLOW_GATE_OBJECTIVE,
        "completion_conditions_text": GOLDEN_WORKFLOW_COMPLETION_CONDITIONS_TEXT,
        "required_material_paths": list(GOLDEN_WORKFLOW_MATERIAL_PATHS),
        "commit_message": GOLDEN_WORKFLOW_COMMIT_MESSAGE,
        "template_id": GOLDEN_TEMPLATE_ID,
    }
    body.update(extra)
    return body


def test_trusted_template_set_and_bootstrap_expose_exactly_both(tmp_path):
    assert DEFAULT_TEMPLATE_ID == "observed-local-git-v1"
    assert GOLDEN_TEMPLATE_ID == "workflow-recovery-verified-v1"
    assert SUPPORTED_TEMPLATE_IDS == (DEFAULT_TEMPLATE_ID, GOLDEN_TEMPLATE_ID)
    cfg = _cfg(tmp_path)
    launcher = ProductLauncher(
        cfg, id_generator=_hex_ids(110_000), browser_opener=lambda _u: None
    )
    try:
        launcher.start()
        status, _, boot, _ = _ui(launcher, "GET", "/ui/api/v1/bootstrap")
        assert status == 200
        assert boot["supported_authoring_template_ids"] == [
            "observed-local-git-v1",
            "workflow-recovery-verified-v1",
        ]
    finally:
        launcher.close()


def test_observed_template_authority_non_regression(tmp_path):
    cfg = _cfg(tmp_path)
    inputs = _owner_input()
    inputs.pop("model")
    inputs.pop("timeout_seconds")
    authored = author_runtime_contract(
        inputs,
        launcher_configuration=cfg,
        documents_directory=cfg.contract_documents_directory,
        id_generator=lambda: "ba" * 16,
    )
    assert authored.contract_summary["template_id"] == DEFAULT_TEMPLATE_ID
    loaded = load_native_mission_profile_document(authored.document_path)
    source = loaded.effective_workspace_source
    assert source.kind.value == "EXISTING_LOCAL_GIT_REPOSITORY"
    assert source.local_repository_path == str(cfg.source_repository)
    assert source.fixture_id is None and source.fixture_version is None
    assert loaded.verification_mode.value == "OBSERVED_ONLY"
    assert loaded.verification.disclose_complete_source is False
    assert loaded.verifier_source is None and loaded.verifier_source_sha256 is None
    assert [command.to_dict() for command in loaded.checkpoint_commands] == [
        {
            "command_id": "workspace-marker-check",
            "argv": ["git", "status", "--porcelain"],
            "timeout_seconds": 30,
            "max_capture_bytes": 65_536,
        }
    ]
    assert loaded.budgets == (1, 1, 0, 0, 0)
    assert loaded.timeout_seconds == cfg.timeout_default
    assert loaded.model == cfg.model_default
    policy = loaded.effective_git_end_state_policy
    assert policy.required_complete_commit_message == inputs["commit_message"]
    assert policy.required_material_paths == ("README.md",)


def test_golden_template_exact_authoring_and_frozen_authority(tmp_path):
    cfg = _cfg(tmp_path, timeout_maximum=3600)
    authored = author_runtime_contract(
        _golden_owner_input(),
        launcher_configuration=cfg,
        documents_directory=cfg.contract_documents_directory,
        id_generator=lambda: "ca" * 16,
    )
    assert authored.contract_summary["workspace_source_kind"] == "REGISTERED_FIXTURE"
    assert authored.contract_summary["verification_mode"] == "FROZEN_BEHAVIORAL"
    assert authored.contract_summary["template_id"] == GOLDEN_TEMPLATE_ID
    loaded = load_native_mission_profile_document(authored.document_path)
    assert loaded.schema_version == "admissible_native_mission_profile_v2"
    source = loaded.effective_workspace_source
    assert (source.kind.value, source.fixture_id, source.fixture_version) == (
        "REGISTERED_FIXTURE",
        "local-workflow-console",
        1,
    )
    assert source.local_repository_path is None
    verification = loaded.verification
    assert verification.mode.value == "FROZEN_BEHAVIORAL"
    assert verification.disclose_complete_source is True
    assert verification.verifier_source == WORKFLOW_RECOVERY_VERIFIER_SOURCE
    independent = hashlib.sha256(
        verification.verifier_source.encode("utf-8")
    ).hexdigest()
    assert independent == GOLDEN_PINNED_VERIFIER_SHA256
    assert verification.verifier_source_sha256 == GOLDEN_PINNED_VERIFIER_SHA256
    assert GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256 == GOLDEN_PINNED_VERIFIER_SHA256
    assert verification.verifier_timeout_seconds == 120
    assert verification.verifier_output_limit_bytes == 524_288
    assert [command.to_dict() for command in loaded.checkpoint_commands] == [
        {
            "command_id": "npm-test",
            "argv": ["npm.cmd", "test"],
            "timeout_seconds": 300,
            "max_capture_bytes": 1_048_576,
        }
    ]
    assert loaded.budgets == (1, 1, 0, 0, 0)
    policy = loaded.effective_git_end_state_policy
    assert policy.required_commits_added == 1
    assert policy.required_complete_commit_message == "feat: add resumable workflow execution"
    assert policy.final_worktree_clean is True
    assert policy.final_index_clean is True
    assert policy.final_remotes_absent is True
    assert policy.required_material_paths == (
        "README.md",
        "index.html",
        "src/app.js",
        "src/execution/engine.js",
        "src/storage/run-store.js",
        "src/ui/render.js",
    )
    assert loaded.mission_text == GOLDEN_WORKFLOW_MISSION_TEXT
    assert loaded.mission_text.startswith(WORKFLOW_RECOVERY_V2_MISSION_TEXT)
    assert loaded.mission_text.endswith(GOLDEN_WORKFLOW_INTEROPERABILITY_DISCLOSURE_TEXT)
    assert "test/fixtures/legacy-run-state-v0.json" in loaded.mission_text
    assert "createMemoryStorage" in loaded.mission_text
    assert "src/storage/memory-storage.js" in loaded.mission_text
    assert loaded.gate_objective == GOLDEN_WORKFLOW_GATE_OBJECTIVE
    assert "verified" in loaded.gate_objective
    assert loaded.completion_conditions_text == WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT
    assert loaded.timeout_seconds == GOLDEN_TEMPLATE_RECOMMENDED_TIMEOUT_SECONDS == 1800
    assert loaded.model == cfg.model_default
    assert not (cfg.run_parent / loaded.run_id).exists()
    assert canonical_bytes(loaded.to_dict()) == Path(authored.document_path).read_bytes()


def test_golden_owner_variable_law_and_timeout_bounds(tmp_path):
    cfg = _cfg(tmp_path, timeout_maximum=600)
    authored = author_runtime_contract(
        _golden_owner_input(),
        launcher_configuration=cfg,
        documents_directory=cfg.contract_documents_directory,
        id_generator=lambda: "da" * 16,
    )
    defaulted = load_native_mission_profile_document(authored.document_path)
    # The recommended golden timeout stays inside the current safe limits.
    assert defaulted.timeout_seconds == 600
    varied = author_runtime_contract(
        _golden_owner_input(model="cursor-fast", timeout_seconds=300),
        launcher_configuration=cfg,
        documents_directory=cfg.contract_documents_directory,
        id_generator=lambda: "db" * 16,
    )
    loaded = load_native_mission_profile_document(varied.document_path)
    assert (loaded.model, loaded.timeout_seconds) == ("cursor-fast", 300)
    # Owner-variable values never move the frozen authority.
    assert loaded.verification.verifier_source_sha256 == GOLDEN_PINNED_VERIFIER_SHA256
    assert loaded.effective_workspace_source.fixture_id == "local-workflow-console"
    for bad_timeout in (601, 0, -1, True, "300"):
        with pytest.raises(AuthoringError) as exc:
            author_runtime_contract(
                _golden_owner_input(timeout_seconds=bad_timeout),
                launcher_configuration=cfg,
                documents_directory=cfg.contract_documents_directory,
                id_generator=lambda: "dc" * 16,
            )
        assert exc.value.error_code == "INVALID_FIELD"
        assert exc.value.field == "timeout_seconds"
    with pytest.raises(AuthoringError) as model_exc:
        author_runtime_contract(
            _golden_owner_input(model="   "),
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "dd" * 16,
        )
    assert model_exc.value.field == "model"


def test_golden_contract_mismatch_battery(tmp_path):
    cfg = _cfg(tmp_path)
    documents = Path(cfg.contract_documents_directory)
    cases = [
        ("mission_text", GOLDEN_WORKFLOW_MISSION_TEXT + " drifted"),
        ("mission_text", WORKFLOW_RECOVERY_V2_MISSION_TEXT),
        ("gate_objective", GOLDEN_WORKFLOW_GATE_OBJECTIVE.replace("verified ", "")),
        (
            "completion_conditions_text",
            GOLDEN_WORKFLOW_COMPLETION_CONDITIONS_TEXT + "\n- extra owner condition.",
        ),
        ("commit_message", "feat: add resumable workflow executions"),
        ("required_material_paths", list(GOLDEN_WORKFLOW_MATERIAL_PATHS[:-1])),
        (
            "required_material_paths",
            list(GOLDEN_WORKFLOW_MATERIAL_PATHS) + ["src/extra.js"],
        ),
        ("required_material_paths", list(reversed(GOLDEN_WORKFLOW_MATERIAL_PATHS))),
    ]
    for field, value in cases:
        with pytest.raises(AuthoringError) as exc:
            author_runtime_contract(
                _golden_owner_input(**{field: value}),
                launcher_configuration=cfg,
                documents_directory=cfg.contract_documents_directory,
                id_generator=lambda: "ea" * 16,
            )
        assert exc.value.error_code == "GOLDEN_CONTRACT_MISMATCH", field
        assert exc.value.field == field
        assert "drifted" not in json.dumps(exc.value.to_dict())
    # Rejection happens before any document write.
    assert not documents.exists() or list(documents.glob("*")) == []


def test_golden_browser_authority_inputs_rejected(tmp_path):
    cfg = _cfg(tmp_path)
    for field, value in (
        ("fixture_id", "evil-fixture"),
        ("fixture_version", 2),
        ("verifier_source", "process.exit(0);"),
        ("verifier_source_sha256", "0" * 64),
        (
            "checkpoint_commands",
            [{"command_id": "x", "argv": ["cmd"], "timeout_seconds": 1, "max_capture_bytes": 1}],
        ),
        ("workspace_source", {"kind": "REGISTERED_FIXTURE"}),
        ("verification", {"mode": "OBSERVED_ONLY"}),
        ("git_end_state_policy", {}),
        ("runtime_prompt", {}),
        ("budgets", [1, 1, 0, 0, 0]),
        ("disclose_complete_source", True),
        ("profile_document", str(tmp_path / "evil.json")),
    ):
        with pytest.raises(AuthoringError) as exc:
            author_runtime_contract(
                _golden_owner_input(**{field: value}),
                launcher_configuration=cfg,
                documents_directory=cfg.contract_documents_directory,
                id_generator=lambda: "eb" * 16,
            )
        assert exc.value.error_code in {"UNKNOWN_FIELD", "FORBIDDEN_FIELD"}, field
        assert exc.value.field == field
    # An unsupported template identity is rejected before any authority assembly.
    with pytest.raises(AuthoringError) as template_exc:
        author_runtime_contract(
            _golden_owner_input(template_id="workflow-recovery-verified-v2"),
            launcher_configuration=cfg,
            documents_directory=cfg.contract_documents_directory,
            id_generator=lambda: "ec" * 16,
        )
    assert template_exc.value.field == "template_id"


def test_golden_document_validates_through_real_g2_boundary(tmp_path):
    cfg = _cfg(tmp_path, timeout_maximum=3600)
    launcher = ProductLauncher(
        cfg,
        verify_head=True,
        id_generator=_hex_ids(120_000),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, headers, body, raw = _ui(
            launcher, "POST", "/ui/api/v1/contracts", _golden_owner_input()
        )
        assert status == 200
        assert body["execution_started"] is False
        assert body["authorization_mode"] == AUTHORIZATION_MODE_PRECOMMITTED
        summary = body["contract_summary"]
        assert summary["workspace_source_kind"] == "REGISTERED_FIXTURE"
        assert summary["verification_mode"] == "FROZEN_BEHAVIORAL"
        assert summary["template_id"] == GOLDEN_TEMPLATE_ID
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        assert all(launcher._g2_token not in f"{k}:{v}" for k, v in headers.items())
        record = launcher._contracts[body["contract_id"]]
        loaded = load_native_mission_profile_document(record.document_path)
        assert loaded.profile_fingerprint == body["profile_fingerprint"]
        assert not any(Path(cfg.run_parent).rglob("*"))
        # A golden contract mismatch surfaces the one stable bounded error.
        status, _, rejected, _ = _ui(
            launcher,
            "POST",
            "/ui/api/v1/contracts",
            _golden_owner_input(mission_text=WORKFLOW_RECOVERY_V2_MISSION_TEXT),
        )
        assert status == 400
        assert rejected["error"] == "AUTHORING_REJECTED"
        assert rejected["error_code"] == "GOLDEN_CONTRACT_MISMATCH"
        assert rejected["field"] == "mission_text"
    finally:
        launcher.close()


class _GoldenPayload:
    """Test seam payload embedding the complete authored golden profile."""

    schema_version = "admissible_native_canary_authorization_payload_v4"
    payload_fingerprint = "e" * 64
    backend_attestation_class = "package-bin"
    source_head = "b" * 40

    def __init__(self, profile):
        self.mission_profile = profile
        self.run_id = profile.run_id
        self.session_id = profile.session_id
        self.selected_model = profile.model
        self.timeout_seconds = profile.timeout_seconds

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "payload_fingerprint": self.payload_fingerprint,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "selected_model": self.selected_model,
            "timeout_seconds": self.timeout_seconds,
            "backend_attestation_class": self.backend_attestation_class,
            "source_head": self.source_head,
            "mission_profile": self.mission_profile.to_dict(),
        }


@pytest.mark.parametrize(
    "mode", [AUTHORIZATION_MODE_PRECOMMITTED, AUTHORIZATION_MODE_INTERACTIVE]
)
def test_golden_preparation_payload_and_launch_both_modes(tmp_path, monkeypatch, mode):
    cfg = _cfg(tmp_path / mode.lower(), mode=mode, timeout_maximum=3600)
    holder = {}

    def preflight(**_kwargs):
        return 0, json.dumps(
            {
                "status": "PREFLIGHT_READY",
                "authorization_payload": holder["payload"].to_dict(),
            }
        ).encode()

    monkeypatch.setattr(
        "admissible.product_launcher.launcher.consume_ready_preflight",
        lambda **kwargs: consume_ready_preflight(
            **{**kwargs, "payload_loader": lambda _d: holder["payload"]}
        ),
    )
    gate = _GateG2Server()
    launcher = ProductLauncher(
        cfg,
        control_plane=SimpleNamespace(),
        g2_server=gate,
        preflight_application=preflight,
        id_generator=_hex_ids(130_000 if mode == AUTHORIZATION_MODE_PRECOMMITTED else 140_000),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, _, authored, _ = _ui(
            launcher, "POST", "/ui/api/v1/contracts", _golden_owner_input()
        )
        assert status == 200, authored
        cid = authored["contract_id"]
        profile = load_native_mission_profile_document(
            launcher._contracts[cid].document_path
        )
        holder["payload"] = _GoldenPayload(profile)
        status, _, prep, _ = _ui(
            launcher, "POST", f"/ui/api/v1/contracts/{cid}/preparations", {}
        )
        assert status == 202, prep
        pid = prep["preparation_id"]
        for _ in range(400):
            _, _, body, raw = _ui(launcher, "GET", f"/ui/api/v1/preparations/{pid}")
            if body["state"] == STATE_READY:
                break
            time.sleep(0.01)
        assert body["state"] == STATE_READY, body
        # The complete frozen authority is disclosed in the visible payload.
        visible_profile = body["authorization_payload"]["mission_profile"]
        assert visible_profile["verification"]["verifier_source"] == WORKFLOW_RECOVERY_VERIFIER_SOURCE
        assert visible_profile["verification"]["verifier_source_sha256"] == GOLDEN_PINNED_VERIFIER_SHA256
        assert visible_profile["verification"]["disclose_complete_source"] is True
        assert visible_profile["workspace_source"]["kind"] == "REGISTERED_FIXTURE"
        assert visible_profile["workspace_source"]["fixture_id"] == "local-workflow-console"
        assert visible_profile["workspace_source"]["fixture_version"] == 1
        assert visible_profile["checkpoint_commands"] == [
            {
                "command_id": "npm-test",
                "argv": ["npm.cmd", "test"],
                "timeout_seconds": 300,
                "max_capture_bytes": 1_048_576,
            }
        ]
        assert visible_profile["budgets"] == [1, 1, 0, 0, 0]
        canonical = launcher._preparations.get(pid).canonical_payload_bytes
        parsed = json.loads(canonical.decode("utf-8"))
        assert parsed["mission_profile"]["verification"]["verifier_source"] == WORKFLOW_RECOVERY_VERIFIER_SOURCE
        assert launcher._g2_token not in raw.decode("utf-8", "replace")
        headers = {OWNER_HEADER: "golden-owner"}
        if mode == AUTHORIZATION_MODE_PRECOMMITTED:
            headers[DIGEST_HEADER] = DIGEST
        status, _, launch, launch_raw = _ui(
            launcher,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": cid, "preparation_id": pid},
            **headers,
        )
        assert status == 202, launch
        assert launcher._g2_token not in launch_raw.decode("utf-8", "replace")
        assert len(gate.run_calls) == 1
        if mode == AUTHORIZATION_MODE_INTERACTIVE:
            expected = hashlib.sha256(
                b"golden-owner" + b"\x00" + canonical
            ).hexdigest()
            assert gate.run_calls[0]["digest"] == expected
        else:
            assert gate.run_calls[0]["digest"] == DIGEST
    finally:
        launcher.close()


def test_golden_preflight_authority_argv_and_operational_bounds_are_independent(tmp_path):
    cfg = _cfg(
        tmp_path,
        timeout_maximum=3600,
        stdout_byte_limit=333_333,
        stderr_byte_limit=222_222,
        preflight_timeout_seconds=120,
        preflight_stdout_byte_limit=55_555,
        preflight_stderr_byte_limit=44_444,
        executable="cursor-agent",
        attestation_class="wrapper-chain",
    )
    invocation = {}

    def capture_preflight(**kwargs):
        invocation.update(kwargs)
        return 1, json.dumps(
            {
                "status": "PREFLIGHT_BLOCKED",
                "error_type": "test-stop",
                "provider_invocations": 0,
                "native_processes_started": 0,
            }
        ).encode()

    launcher = ProductLauncher(
        cfg,
        preflight_application=capture_preflight,
        id_generator=_hex_ids(150_000),
        browser_opener=lambda _u: None,
    )
    try:
        launcher.start()
        status, _, authored, _ = _ui(
            launcher, "POST", "/ui/api/v1/contracts", _golden_owner_input()
        )
        assert status == 200, authored
        profile = load_native_mission_profile_document(
            launcher._contracts[authored["contract_id"]].document_path
        )
        status, _, _, _ = _ui(
            launcher,
            "POST",
            f"/ui/api/v1/contracts/{authored['contract_id']}/preparations",
            {},
        )
        assert status == 202
        for _ in range(400):
            if invocation:
                break
            time.sleep(0.01)
        assert invocation
    finally:
        launcher.close()

    assert (
        invocation["authority_timeout_seconds"],
        invocation["authority_stdout_byte_limit"],
        invocation["authority_stderr_byte_limit"],
    ) == (
        profile.timeout_seconds,
        profile.stdout_byte_limit,
        profile.stderr_byte_limit,
    ) == (1800, 333_333, 222_222)
    assert (
        invocation["process_timeout_seconds"],
        invocation["process_stdout_capture_limit"],
        invocation["process_stderr_capture_limit"],
    ) == (120, 55_555, 44_444)

    observed = {}

    class FakeProcess:
        def __init__(self, argv, **kwargs):
            observed["argv"] = argv
            observed["constructor"] = kwargs

        def start(self):
            return None

        def wait(self, *, timeout):
            observed["wait_timeout"] = timeout
            return 1

        def poll(self):
            return 1

        def finish(self, *, reason):
            return SimpleNamespace(
                cleanup_proven=True,
                termination_reason=reason,
                exit_code=1,
            )

        def captured_stdout(self):
            return '{"status":"PREFLIGHT_BLOCKED"}'

    ProductionPreflightApplication(process_factory=FakeProcess)(**invocation)
    argv = observed["argv"]
    authority_flags = {
        "--model": profile.model,
        "--timeout-seconds": str(profile.timeout_seconds),
        "--stdout-byte-limit": str(profile.stdout_byte_limit),
        "--stderr-byte-limit": str(profile.stderr_byte_limit),
    }
    for flag, expected in authority_flags.items():
        assert argv[argv.index(flag) + 1] == expected
    assert argv[argv.index("--run-id") + 1] == profile.run_id
    assert argv[argv.index("--session-id") + 1] == profile.session_id
    assert argv[argv.index("--profile-document") + 1] == str(invocation["profile_document"])
    assert observed["wait_timeout"] == 120.0
    assert observed["constructor"]["max_capture_bytes"] == 55_555


def test_real_golden_preflight_ready_and_contradiction_remains_fail_closed(tmp_path):
    standalone = (tmp_path / "standalone-product-source").resolve()
    product_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        ["git", "clone", "--no-local", "--no-checkout", str(product_root), str(standalone)],
        check=True,
        capture_output=True,
    )
    tested_head = subprocess.check_output(
        ["git", "-C", str(product_root), "rev-parse", "HEAD"], text=True
    ).strip()
    _git(standalone, "checkout", "--detach", tested_head)
    _git(standalone, "remote", "remove", "origin")
    _git(standalone, "config", "core.autocrlf", "false")
    _git(standalone, "reset", "--hard", tested_head)
    cfg = _cfg(
        tmp_path,
        source_repository=standalone,
        required_source_head=tested_head,
        timeout_maximum=3600,
        stdout_byte_limit=333_333,
        stderr_byte_limit=222_222,
        preflight_timeout_seconds=120,
        preflight_stdout_byte_limit=55_555,
        preflight_stderr_byte_limit=44_444,
        executable="cursor-agent",
        attestation_class="wrapper-chain",
    )
    authored = author_runtime_contract(
        _golden_owner_input(),
        launcher_configuration=cfg,
        documents_directory=cfg.contract_documents_directory,
        id_generator=lambda: "fa" * 16,
    )
    profile = load_native_mission_profile_document(authored.document_path)
    (cfg.run_parent / "ready").mkdir(parents=True)
    (cfg.run_parent / "contradiction").mkdir()
    application = ProductionPreflightApplication()
    common = dict(
        profile_document=authored.document_path,
        source_repository=cfg.source_repository,
        required_source_head=cfg.required_source_head,
        run_id=profile.run_id,
        session_id=profile.session_id,
        executable=cfg.executable,
        executable_prefix_args=cfg.executable_prefix_args,
        model=profile.model,
        authority_stdout_byte_limit=profile.stdout_byte_limit,
        authority_stderr_byte_limit=profile.stderr_byte_limit,
        process_timeout_seconds=cfg.preflight_timeout_seconds,
        process_stdout_capture_limit=cfg.preflight_stdout_byte_limit,
        process_stderr_capture_limit=cfg.preflight_stderr_byte_limit,
        attestation_class=cfg.attestation_class,
    )
    ready_run_root = cfg.run_parent / "ready" / profile.run_id
    code, stdout = application(
        **common,
        run_root=ready_run_root,
        authority_timeout_seconds=profile.timeout_seconds,
    )
    ready = parse_preflight_stdout(stdout)
    assert code == 0, ready
    assert ready["status"] == "PREFLIGHT_READY"
    # PREPARE_ONLY returns before run-root creation, reservation, or process start.
    assert not ready_run_root.exists()

    code, stdout = application(
        **common,
        run_root=cfg.run_parent / "contradiction" / profile.run_id,
        authority_timeout_seconds=120,
    )
    blocked = parse_preflight_stdout(stdout)
    assert code != 0
    assert blocked["status"] == "PREFLIGHT_BLOCKED"
    assert blocked["provider_invocations"] == 0
    assert blocked["native_processes_started"] == 0
    assert "--timeout-seconds contradicts the selected profile" in json.dumps(blocked)
