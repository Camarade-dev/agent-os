"""Future preflight sealing is separate, durable, and non-self-referential."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from admissible.capsule.preflight_seal import (
    FUTURE_PREFLIGHT_MANIFEST_PATH,
    FUTURE_PREFLIGHT_SEAL_PATH,
    FuturePreflightSealError,
    publish_future_preflight_seal,
    validate_future_preflight_seal,
)
from tests._verified_canary_binding import verified_canary_binding


def _prepared(tmp_path: Path):
    binding = verified_canary_binding()
    root = tmp_path / "future-preflight"
    (root / "evidence").mkdir(parents=True)
    (root / "CANARY.txt").write_bytes(
        b"admissible-chatgpt-codex-canary-v1\n"
    )
    owner = {
        "schema_version": "future_owner_payload_v1",
        "classification": "PREPARED_NOT_CONSUMED",
        "model_binding_policy_fingerprint": (
            binding["policy"].policy_fingerprint
        ),
        "verified_serialization_witness_receipt_identity": (
            binding["receipt"].receipt_identity
        ),
        "verified_serialization_witness_run_identity": (
            binding["receipt"].witness_run_identity
        ),
    }
    (root / "evidence" / "owner-payload.json").write_text(
        json.dumps(owner, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    result = publish_future_preflight_seal(
        root=root,
        covered_paths=("CANARY.txt", "evidence/owner-payload.json"),
        owner_payload_path="evidence/owner-payload.json",
        model_binding_policy=binding["policy"],
        verified_witness_receipt=binding["receipt"],
        trusted_witness_store=binding["store"],
    )
    return root, binding, result


def test_future_manifest_and_seal_are_mutually_consistent_without_self_entry(
    tmp_path: Path,
):
    root, binding, published = _prepared(tmp_path)
    reloaded = validate_future_preflight_seal(
        root=root,
        expected_model_binding_policy=binding["policy"],
        expected_verified_witness_receipt=binding["receipt"],
        trusted_witness_store=binding["store"],
        expected_seal_fingerprint=published["seal_fingerprint"],
    )
    assert reloaded == published
    assert reloaded["self_referential"] is False
    assert FUTURE_PREFLIGHT_MANIFEST_PATH not in reloaded["covered_paths"]
    assert FUTURE_PREFLIGHT_SEAL_PATH not in reloaded["covered_paths"]


def test_future_seal_detects_a_changed_covered_file(tmp_path: Path):
    root, binding, published = _prepared(tmp_path)
    (root / "CANARY.txt").write_bytes(
        b"admissible-chatgpt-codex-canary-v1\nextra\n"
    )
    with pytest.raises(FuturePreflightSealError, match="covered file changed"):
        validate_future_preflight_seal(
            root=root,
            expected_model_binding_policy=binding["policy"],
            expected_verified_witness_receipt=binding["receipt"],
            trusted_witness_store=binding["store"],
            expected_seal_fingerprint=published["seal_fingerprint"],
        )


def test_future_seal_detects_a_changed_manifest(tmp_path: Path):
    root, binding, published = _prepared(tmp_path)
    manifest = root / FUTURE_PREFLIGHT_MANIFEST_PATH
    manifest.chmod(0o600)
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    with pytest.raises(FuturePreflightSealError, match="final seal differs"):
        validate_future_preflight_seal(
            root=root,
            expected_model_binding_policy=binding["policy"],
            expected_verified_witness_receipt=binding["receipt"],
            trusted_witness_store=binding["store"],
            expected_seal_fingerprint=published["seal_fingerprint"],
        )


def test_future_seal_detects_a_changed_final_seal(tmp_path: Path):
    root, binding, published = _prepared(tmp_path)
    seal = root / FUTURE_PREFLIGHT_SEAL_PATH
    seal.chmod(0o600)
    value = json.loads(seal.read_text(encoding="utf-8"))
    value["seal_fingerprint"] = "0" * 64
    seal.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(FuturePreflightSealError, match="final seal differs"):
        validate_future_preflight_seal(
            root=root,
            expected_model_binding_policy=binding["policy"],
            expected_verified_witness_receipt=binding["receipt"],
            trusted_witness_store=binding["store"],
            expected_seal_fingerprint=published["seal_fingerprint"],
        )


@pytest.mark.parametrize(
    "self_path",
    [FUTURE_PREFLIGHT_MANIFEST_PATH, FUTURE_PREFLIGHT_SEAL_PATH],
)
def test_future_manifest_refuses_its_own_publication_files(
    tmp_path: Path, self_path: str
):
    binding = verified_canary_binding()
    root = tmp_path / "future-preflight"
    (root / "evidence").mkdir(parents=True)
    owner = root / "evidence" / "owner-payload.json"
    owner.write_text(
        json.dumps(
            {
                "model_binding_policy_fingerprint": (
                    binding["policy"].policy_fingerprint
                ),
                "verified_serialization_witness_receipt_identity": (
                    binding["receipt"].receipt_identity
                ),
                "verified_serialization_witness_run_identity": (
                    binding["receipt"].witness_run_identity
                ),
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(FuturePreflightSealError, match="outside the covered"):
        publish_future_preflight_seal(
            root=root,
            covered_paths=("evidence/owner-payload.json", self_path),
            owner_payload_path="evidence/owner-payload.json",
            model_binding_policy=binding["policy"],
            verified_witness_receipt=binding["receipt"],
            trusted_witness_store=binding["store"],
        )


def test_future_sealing_does_not_touch_a_historical_v1_preparation(
    tmp_path: Path,
):
    historical = tmp_path / "canary-preflight-v1"
    historical.mkdir()
    old = (
        b'{"classification":"CHATGPT_CODEX_CANARY_MODEL_UNRESOLVED",'
        b'"consumed":false,"schema_version":"historical_v1"}'
    )
    seal = historical / "preflight-seal.json"
    seal.write_bytes(old)
    before = seal.stat(), seal.read_bytes()
    _prepared(tmp_path)
    after = seal.stat(), seal.read_bytes()
    assert after[1] == before[1]
    assert after[0].st_mtime_ns == before[0].st_mtime_ns
    assert b'"consumed":false' in after[1]
