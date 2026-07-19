from __future__ import annotations

from http.client import HTTPConnection
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import (
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.native_canary import NativeCanaryAuthorizationPayloadV4
from admissible.product_launcher.authoring import AuthoringError, author_runtime_contract
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher
from admissible.product_launcher.preflight import (
    INTERACTIVE_AUTHORIZATION_NOTICE,
    STATE_READY,
    compute_interactive_digest,
    parse_preflight_stdout,
)
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
        assert "Admissible Product Launcher" in text
        assert "Visual Compose/Contract/Authorize interface is not installed in G2.5." in text
        assert launcher.csrf_nonce in text
        assert launcher._g2_token not in text
        assert "localStorage" not in text and "sessionStorage" not in text
        assert "http" not in text.lower().split("cdn")[0] or "cdn" not in text.lower()
        assert 'src="http' not in text and "<link" not in text
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


def test_child_runner_unchanged_and_protected_paths_unmodified():
    root = Path(__file__).resolve().parents[1]
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", "1f2949d42fb79e9407035822c65b6f889650d689"],
        cwd=root,
        text=True,
    )
    for forbidden in (
        "admissible/delegated_gate/",
        "admissible/product_service/",
        "admissible/product_read_model/",
        "admissible/checkpoint.py",
        "admissible/product_ui/",
    ):
        assert forbidden not in changed
    # child_runner substantive body unchanged vs base unless import-only
    base = subprocess.check_output(
        ["git", "show", "1f2949d42fb79e9407035822c65b6f889650d689:admissible/product_launcher/child_runner.py"],
        cwd=root,
    )
    current = (root / "admissible/product_launcher/child_runner.py").read_bytes()
    assert current.replace(b"\r\n", b"\n") == base.replace(b"\r\n", b"\n")
    assert child_runner_module.ProductionChildApplication is not None


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
