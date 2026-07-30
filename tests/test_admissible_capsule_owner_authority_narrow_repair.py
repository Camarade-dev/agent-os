"""Narrow final-repair regressions for owner-authority audit blockers.

Provider-free.  No public model/API.  No real Codex authentication content.
Privileged socket-identity tests skip outside a disposable user namespace.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import types
from pathlib import Path

import pytest

from admissible.capsule.common import fingerprint, strict_json_loads
from admissible.capsule.owner_authority.broker import OwnerAuthorityBroker
from admissible.capsule.owner_authority.broker_service import (
    EXPECTED_BROKER_SOCKET_MODE,
    _clear_stale_socket,
    _unlink_verified_stale_socket,
    expected_broker_socket_identity,
    require_expected_broker_socket_identity,
    require_stable_socket_identity,
)
from admissible.capsule.owner_authority.installation import (
    attest_synthetic_non_production_installation,
)
from admissible.capsule.owner_authority.installer import perform_installation
from admissible.capsule.owner_authority.layout import (
    BROKER_SOCKET_NAME,
    OwnerAuthorityError,
    synthetic_non_production_layout,
)
from admissible.capsule.owner_authority.provisioner import (
    OwnerAuthorityProvisioningError,
    _load_payload,
    owner_payload_summary,
    provision_authorization,
    validate_closed_world_owner_payload,
)
from admissible.capsule.owner_authorization import (
    OWNER_AUTHORIZATION_PAYLOAD_KEYS,
    zero_retry_policy,
)
from tests._candidate_canary_binding import PRIVILEGED_IDENTITY_REASON

privileged = pytest.mark.skipif(
    os.geteuid() != 0, reason=PRIVILEGED_IDENTITY_REASON
)


def _valid_payload(**overrides) -> dict:
    body = {
        "schema_version": "synthetic_external_owner_authority_payload_v1",
        "repository_head": "a" * 40,
        "repository_canonical_path_sha256": "1" * 64,
        "implementation_head": "b" * 40,
        "run_id": "external-owner-authority-run-1",
        "mission_fingerprint": "c" * 64,
        "model_binding_policy": {
            "configured_model": "gpt-5.3-codex",
            "configured_reasoning_effort": "high",
        },
        "destination_manifest_identity": "d" * 64,
        "tool_authority_identity": "e" * 64,
        "budgets": {"wall_clock_seconds": 600, "capsule_pids": 64},
        "zero_retry_policy": zero_retry_policy(),
    }
    body.update(overrides)
    return body


def _plant_dead_socket(path: Path, *, uid: int, gid: int, mode: int) -> None:
    if path.exists() or path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        sock.bind(os.fspath(path))
    finally:
        os.umask(previous)
        sock.close()
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _install_world(tmp_path: Path, prefix: str = "oa-narrow-"):
    root = Path(tempfile.mkdtemp(prefix=prefix, dir=tmp_path))
    layout = synthetic_non_production_layout(root)
    perform_installation(
        layout=layout,
        installation_id=(prefix.replace("-", "")[:16]).ljust(16, "0"),
        authorized_launcher_uid=os.getuid(),
        authorized_launcher_gid=os.getgid(),
        install_unit=False,
    )
    installation = attest_synthetic_non_production_installation(layout)
    broker = OwnerAuthorityBroker(installation)
    return layout, installation, broker


# ---------------------------------------------------------------------------
# A. stale-socket identity gates
# ---------------------------------------------------------------------------


@privileged
def test_expected_dead_socket_is_removed(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-dead-ok-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    assert path.exists()
    _clear_stale_socket(broker)
    assert not path.exists()


@privileged
def test_live_expected_socket_is_retained(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-live-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        listener.bind(os.fspath(path))
    finally:
        os.umask(previous)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    listener.listen(1)
    try:
        with pytest.raises(OwnerAuthorityError) as failure:
            _clear_stale_socket(broker)
        assert failure.value.classification == "OWNER_AUTHORITY_SOCKET_BUSY"
        assert path.exists()
    finally:
        listener.close()
        if path.exists():
            path.unlink()


@privileged
def test_world_writable_dead_socket_is_refused_and_retained(tmp_path: Path):
    """Independent auditor probe: mode 0777 must not be deleted."""

    layout, installation, broker = _install_world(tmp_path, "oa-777-")
    path = layout.broker_socket_path
    uid, gid, _mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=0o777)
    with pytest.raises(OwnerAuthorityError) as failure:
        _clear_stale_socket(broker)
    assert failure.value.classification == "OWNER_AUTHORITY_SOCKET_REFUSED"
    assert path.exists()
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o777


@privileged
def test_wrong_mode_dead_socket_is_refused(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-mode-")
    path = layout.broker_socket_path
    uid, gid, _mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=0o666)
    with pytest.raises(OwnerAuthorityError):
        _clear_stale_socket(broker)
    assert path.exists()


def test_wrong_owner_identity_gate_refuses():
    info = types.SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=1000,
        st_gid=0,
        st_dev=1,
        st_ino=2,
    )
    with pytest.raises(OwnerAuthorityError, match="ownership"):
        require_expected_broker_socket_identity(
            info,  # type: ignore[arg-type]
            expected_uid=0,
            expected_gid=0,
            expected_mode=EXPECTED_BROKER_SOCKET_MODE,
        )


def test_wrong_group_identity_gate_refuses():
    info = types.SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=0,
        st_gid=999,
        st_dev=1,
        st_ino=2,
    )
    with pytest.raises(OwnerAuthorityError, match="group"):
        require_expected_broker_socket_identity(
            info,  # type: ignore[arg-type]
            expected_uid=0,
            expected_gid=0,
            expected_mode=EXPECTED_BROKER_SOCKET_MODE,
        )


@privileged
def test_mismatched_authorized_launcher_gid_is_refused(tmp_path: Path):
    from dataclasses import replace

    layout, installation, broker = _install_world(tmp_path, "oa-gid-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    # Change the expected launcher gid without being able to chown in this
    # single-uid namespace: the on-disk socket no longer matches authority.
    mutated = dict(installation.record)
    mutated["authorized_launcher_gid"] = gid + 1 if gid < 2**31 - 2 else 0
    broker.installation = replace(installation, record=mutated)
    with pytest.raises(OwnerAuthorityError) as failure:
        _clear_stale_socket(broker)
    assert failure.value.classification == "OWNER_AUTHORITY_SOCKET_REFUSED"
    assert path.exists()


@privileged
def test_symlink_and_non_socket_are_refused(tmp_path: Path):
    layout, _installation, broker = _install_world(tmp_path, "oa-type-")
    path = layout.broker_socket_path
    path.parent.mkdir(parents=True, exist_ok=True)

    target = tmp_path / "elsewhere"
    target.write_text("x", encoding="utf-8")
    os.symlink(target, path)
    with pytest.raises(OwnerAuthorityError):
        _clear_stale_socket(broker)
    assert path.is_symlink()
    path.unlink()

    path.write_text("not-a-socket", encoding="utf-8")
    with pytest.raises(OwnerAuthorityError):
        _clear_stale_socket(broker)
    assert path.is_file()


@privileged
def test_missing_installation_identity_is_refused(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-ident-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    from dataclasses import replace

    broker.installation = replace(
        installation, installation_identity="not-a-sha256-identity-value"
    )
    with pytest.raises(OwnerAuthorityError):
        _clear_stale_socket(broker)
    assert path.exists()


@privileged
def test_inode_replacement_race_is_refused(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-race-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    first = os.lstat(path)
    first_identity = (
        "socket",
        int(first.st_dev),
        int(first.st_ino),
        int(first.st_uid),
        int(first.st_gid),
        int(stat.S_IMODE(first.st_mode)),
    )
    path.unlink()
    # Burn the recycled inode that tmpfs may immediately reuse.
    burned = path.parent / "inode-burn"
    burned.write_text("burn", encoding="utf-8")
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    burned.unlink()
    second = os.lstat(path)
    assert int(second.st_ino) != int(first.st_ino)
    dir_fd = os.open(
        os.fspath(path.parent),
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        with pytest.raises(OwnerAuthorityError, match="identity changed"):
            _unlink_verified_stale_socket(
                dir_fd=dir_fd,
                name=BROKER_SOCKET_NAME,
                expected_identity=first_identity,
            )
        assert path.exists()
    finally:
        os.close(dir_fd)


@privileged
def test_validated_parent_directory_mismatch_is_refused(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-parent-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    os.chmod(path.parent, 0o777)
    with pytest.raises(OwnerAuthorityError) as failure:
        _clear_stale_socket(broker)
    assert failure.value.classification == "OWNER_AUTHORITY_SOCKET_REFUSED"
    assert path.exists()
    os.chmod(path.parent, 0o755)


@privileged
def test_repeated_cleanup_remains_deterministic(tmp_path: Path):
    layout, installation, broker = _install_world(tmp_path, "oa-repeat-")
    path = layout.broker_socket_path
    uid, gid, mode = expected_broker_socket_identity(installation)
    _clear_stale_socket(broker)
    _clear_stale_socket(broker)
    _plant_dead_socket(path, uid=uid, gid=gid, mode=mode)
    _clear_stale_socket(broker)
    assert not path.exists()
    _clear_stale_socket(broker)
    assert not path.exists()
    _plant_dead_socket(path, uid=uid, gid=gid, mode=0o777)
    with pytest.raises(OwnerAuthorityError):
        _clear_stale_socket(broker)
    with pytest.raises(OwnerAuthorityError):
        _clear_stale_socket(broker)
    assert path.exists()


def test_stable_identity_helper_refuses_drift():
    with pytest.raises(OwnerAuthorityError):
        require_stable_socket_identity(
            ("socket", 1, 2, 0, 0, 0o660),
            ("socket", 1, 3, 0, 0, 0o660),
        )


# ---------------------------------------------------------------------------
# B. closed-world owner payload schema
# ---------------------------------------------------------------------------


def test_authoritative_payload_key_set_is_exported():
    assert "repository_head" in OWNER_AUTHORIZATION_PAYLOAD_KEYS
    assert "evil_field" not in OWNER_AUTHORIZATION_PAYLOAD_KEYS


def test_one_unknown_top_level_field_is_refused():
    with pytest.raises(OwnerAuthorityProvisioningError) as failure:
        owner_payload_summary(_valid_payload(unexpected_attacker_field="x"))
    assert failure.value.classification == "OWNER_AUTHORITY_PAYLOAD_REFUSED"
    assert "unexpected_attacker_field" not in str(failure.value)


def test_multiple_unknown_fields_are_refused():
    payload = _valid_payload(alpha="1", beta="2")
    with pytest.raises(OwnerAuthorityProvisioningError) as failure:
        validate_closed_world_owner_payload(payload)
    assert failure.value.classification == "OWNER_AUTHORITY_PAYLOAD_REFUSED"


def test_unknown_nested_fields_in_structured_authorities_are_refused():
    cases = [
        _valid_payload(
            model_binding_policy={
                "configured_model": "gpt-5.3-codex",
                "configured_reasoning_effort": "high",
                "attacker_nested": True,
            }
        ),
        _valid_payload(
            zero_retry_policy={**zero_retry_policy(), "extra_retry_knob": 1}
        ),
        _valid_payload(
            preparation_root_identity={
                "schema_version": "x",
                "canonical_path_sha256": "1" * 64,
                "device": 1,
                "inode": 1,
                "root_mode": 0o755,
                "root_type": "directory",
                "preparation_id": "prep",
                "run_id": "run",
                "evil": 1,
            }
        ),
        _valid_payload(
            destination_manifest_identity={
                "identity": "d" * 64,
                "evil": 1,
            }
        ),
        _valid_payload(
            tool_authority_identity={"identity": "e" * 64, "evil": 1}
        ),
        _valid_payload(budgets={"wall_clock_seconds": {"nested": 1}}),
    ]
    for payload in cases:
        with pytest.raises(OwnerAuthorityProvisioningError) as failure:
            validate_closed_world_owner_payload(payload)
        assert failure.value.classification == "OWNER_AUTHORITY_PAYLOAD_REFUSED"


def test_duplicate_required_and_unknown_keys_are_refused(tmp_path: Path):
    required = (
        '{"schema_version":"synthetic_external_owner_authority_payload_v1",'
        '"schema_version":"dup",'
        '"repository_head":"' + ("a" * 40) + '"}'
    )
    unknown = '{"run_id":"r1","run_id":"r2","evil":1,"evil":2}'
    for raw in (required, unknown):
        path = tmp_path / "dup.json"
        path.write_text(raw, encoding="utf-8")
        with pytest.raises(OwnerAuthorityProvisioningError) as failure:
            _load_payload(path)
        assert failure.value.classification == "OWNER_AUTHORITY_PAYLOAD_REFUSED"
        assert "evil" not in str(failure.value) or "duplicate" in str(
            failure.value
        ).lower() or "unexpected" in str(failure.value).lower()


def test_unicode_confusable_and_whitespace_field_names_are_refused():
    # Cyrillic 'а' looks like Latin 'a' in repository_head.
    confusable = _valid_payload()
    confusable.pop("repository_head")
    confusable["r\u043epository_head"] = "a" * 40
    with pytest.raises(OwnerAuthorityProvisioningError):
        validate_closed_world_owner_payload(confusable)

    spaced = _valid_payload()
    spaced[" repository_head"] = spaced.pop("repository_head")
    with pytest.raises(OwnerAuthorityProvisioningError):
        validate_closed_world_owner_payload(spaced)


def test_bool_as_integer_attempts_are_refused():
    with pytest.raises(OwnerAuthorityProvisioningError):
        validate_closed_world_owner_payload(
            _valid_payload(budgets={"wall_clock_seconds": True})
        )


def test_valid_payload_fingerprint_is_unchanged():
    payload = _valid_payload()
    before = fingerprint(payload)
    summary = owner_payload_summary(payload)
    assert summary["payload_fingerprint"] == before
    assert validate_closed_world_owner_payload(payload) == payload


def test_refusal_occurs_before_phrase_descriptor_consumption(tmp_path: Path):
    path = tmp_path / "payload.json"
    path.write_text(
        json.dumps(_valid_payload(attacker_field="secret-value")),
        encoding="utf-8",
    )
    read_end, write_end = os.pipe()
    os.write(write_end, b"phrase-never-should-be-read-here")
    os.close(write_end)
    try:
        with pytest.raises(OwnerAuthorityProvisioningError) as failure:
            _load_payload(path)
        assert failure.value.classification == "OWNER_AUTHORITY_PAYLOAD_REFUSED"
        # Descriptor still has unread data: refusal happened before phrase read.
        remaining = os.read(read_end, 64)
        assert remaining.startswith(b"phrase-never")
    finally:
        os.close(read_end)


@privileged
def test_refusal_creates_no_authorization_state_or_residue(tmp_path: Path):
    layout, installation, _broker = _install_world(tmp_path, "oa-prov-")
    before = list(layout.authorizations_root.iterdir()) if layout.authorizations_root.exists() else []
    with pytest.raises(OwnerAuthorityProvisioningError):
        provision_authorization(
            installation=installation,
            owner_payload=_valid_payload(attacker_field="x"),
            owner_phrase="synthetic-owner-phrase-value",
        )
    after = list(layout.authorizations_root.iterdir()) if layout.authorizations_root.exists() else []
    assert after == before


def test_strict_json_loads_still_rejects_duplicate_keys():
    with pytest.raises(ValueError, match="duplicate"):
        strict_json_loads(b'{"a":1,"a":2}', label="owner payload")
