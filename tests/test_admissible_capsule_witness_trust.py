"""Adversarial tests for anchored Codex serialization witness trust."""

from __future__ import annotations

import inspect
import json
import shutil
from pathlib import Path

import pytest

from admissible.capsule.common import canonical_bytes, fingerprint
from admissible.capsule.host_codex_backend import (
    HostCodexAppServerCapsuleBackend,
)
from admissible.capsule.model_authority import (
    CANARY_CONFIGURED_MODEL,
    CANARY_CONFIGURED_REASONING_EFFORT,
    CodexModelAuthority,
    ModelBindingPolicy,
    ModelConfigurationError,
    canary_model_authority,
    canary_model_binding_policy,
)
from admissible.capsule.serialization_witness import (
    SerializationWitnessError,
    SerializationWitnessRecord,
    TrustedSerializationWitnessStore,
    VerifiedSerializationWitnessReceipt,
    evaluate_serialization_witness,
    extract_witness_record,
    serialization_witness_identity,
    validate_verified_receipt_metadata,
)
from tests._verified_canary_binding import verified_canary_binding


def _fresh(tmp_path: Path):
    shared = verified_canary_binding()
    policy = canary_model_binding_policy(
        codex_executable_identity=shared["identity"].to_dict()
    )
    store = TrustedSerializationWitnessStore(tmp_path / "trusted-witness")
    receipt = store.verify_canary(
        policy=policy,
        codex_executable=shared["codex"],
    )
    authority = canary_model_authority(
        model_binding_policy=policy,
        verified_witness_receipt=receipt,
        trusted_witness_store=store,
    )
    return shared, store, policy, receipt, authority


def _pack_path(store: TrustedSerializationWitnessStore, receipt):
    return store.root / receipt.to_dict()["evidence_pack_relative_path"]


def test_caller_created_record_is_only_an_untrusted_observation():
    isolated = CodexModelAuthority.create(
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        codex_executable_identity=verified_canary_binding()["identity"].to_dict(),
    )
    record = extract_witness_record(
        request_path="/v1/responses",
        request_body={
            "model": CANARY_CONFIGURED_MODEL,
            "reasoning": {"effort": CANARY_CONFIGURED_REASONING_EFFORT},
        },
    )
    comparison = evaluate_serialization_witness([record], isolated)
    assert comparison["trust_state"] == "UNTRUSTED_OBSERVATION_ONLY"
    assert comparison["verified_receipt"] is False
    with pytest.raises(ModelConfigurationError, match="opaque verified"):
        CodexModelAuthority.from_verified_receipt(
            policy=isolated.model_binding_policy,
            receipt=record,
            trusted_witness_store=verified_canary_binding()["store"],
        )


def test_arbitrary_witness_fingerprint_has_no_authority():
    with pytest.raises(
        ModelConfigurationError, match="arbitrary serialization witness"
    ):
        CodexModelAuthority.create(
            configured_model=CANARY_CONFIGURED_MODEL,
            configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
            codex_executable_identity=(
                verified_canary_binding()["identity"].to_dict()
            ),
            serialization_witness_identity="0" * 64,
        )


def test_receipt_cannot_be_constructed_from_expected_strings():
    receipt_body = verified_canary_binding()["receipt"].to_dict()
    with pytest.raises(
        SerializationWitnessError, match="only be loaded by the trusted store"
    ):
        VerifiedSerializationWitnessReceipt(receipt_body, object())


def test_structural_receipt_metadata_does_not_restore_live_provenance():
    binding = verified_canary_binding()
    metadata = validate_verified_receipt_metadata(
        binding["receipt"].to_dict(),
        expected_policy=binding["policy"],
        expected_executable_identity=binding["identity"].to_dict(),
    )
    reconstructed = CodexModelAuthority.from_dict(
        binding["authority"].to_dict()
    )
    assert metadata["receipt_identity"] == binding["receipt"].receipt_identity
    assert reconstructed.receipt_revalidated is False
    with pytest.raises(ModelConfigurationError, match="no revalidated durable"):
        reconstructed.require_verified_receipt()


def test_self_consistent_fake_pack_without_external_anchor_is_refused(
    tmp_path: Path,
):
    binding = verified_canary_binding()
    store = TrustedSerializationWitnessStore(tmp_path / "unanchored-fake")
    fake_body = {
        "schema_version": "admissible_codex_verified_serialization_evidence_pack_v1",
        "configured_model": CANARY_CONFIGURED_MODEL,
        "configured_reasoning_effort": CANARY_CONFIGURED_REASONING_EFFORT,
    }
    fake = {**fake_body, "evidence_pack_fingerprint": fingerprint(fake_body)}
    (store.root / "evidence-packs" / "fabricated.json").write_bytes(
        canonical_bytes(fake)
    )
    with pytest.raises(SerializationWitnessError, match="no verified witness"):
        store.load_current_verified_receipt(
            expected_policy=binding["policy"],
            expected_executable_identity=binding["identity"].to_dict(),
        )


def test_copied_evidence_under_an_unauthorized_store_is_refused(tmp_path: Path):
    shared, store, policy, _receipt, _authority = _fresh(tmp_path / "source")
    copied = tmp_path / "copied-store"
    shutil.copytree(store.root, copied)
    unauthorized = TrustedSerializationWitnessStore(copied)
    with pytest.raises(SerializationWitnessError, match="no verified witness"):
        unauthorized.load_current_verified_receipt(
            expected_policy=policy,
            expected_executable_identity=shared["identity"].to_dict(),
        )


def test_substituted_witness_run_nonce_is_refused(tmp_path: Path):
    _shared, store, policy, receipt, _authority = _fresh(tmp_path)
    path = _pack_path(store, receipt)
    pack = json.loads(path.read_text(encoding="utf-8"))
    pack["witness_run_nonce"] = "f" * 64
    body = {
        key: value for key, value in pack.items()
        if key != "evidence_pack_fingerprint"
    }
    pack["evidence_pack_fingerprint"] = fingerprint(body)
    path.write_bytes(canonical_bytes(pack))
    with pytest.raises(SerializationWitnessError, match="evidence bytes changed"):
        store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=receipt.executable_identity,
        )


def test_substituted_executable_identity_is_refused(tmp_path: Path):
    _shared, store, policy, receipt, _authority = _fresh(tmp_path)
    substituted = dict(receipt.executable_identity)
    substituted["sha256"] = "0" * 64
    with pytest.raises(
        SerializationWitnessError, match="run anchor differs"
    ):
        store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=substituted,
        )


def test_substituted_namespace_network_evidence_is_refused(tmp_path: Path):
    _shared, store, policy, receipt, _authority = _fresh(tmp_path)
    path = _pack_path(store, receipt)
    pack = json.loads(path.read_text(encoding="utf-8"))
    pack["namespace_network_evidence"]["observed_network_state"][
        "public_route_available"
    ] = True
    body = {
        key: value for key, value in pack.items()
        if key != "evidence_pack_fingerprint"
    }
    pack["evidence_pack_fingerprint"] = fingerprint(body)
    path.write_bytes(canonical_bytes(pack))
    with pytest.raises(SerializationWitnessError, match="evidence bytes changed"):
        store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=receipt.executable_identity,
        )


@pytest.mark.parametrize(
    ("model", "effort"),
    [
        ("gpt-5.6-sol", "low"),
        ("gpt-5.3-codex", "medium"),
        ("gpt-5.3-codex", "high"),
    ],
)
def test_receipt_for_another_model_policy_is_refused(
    tmp_path: Path, model: str, effort: str
):
    shared, store, _policy, receipt, _authority = _fresh(tmp_path)
    other = ModelBindingPolicy.create(
        policy_kind="another_explicit_mission_policy_v1",
        configured_model=model,
        configured_reasoning_effort=effort,
        allow_provider_model_fallback=False,
        codex_executable_identity=shared["identity"].to_dict(),
    )
    with pytest.raises(SerializationWitnessError, match="run anchor differs"):
        store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=other,
            expected_executable_identity=shared["identity"].to_dict(),
        )


def test_authority_created_before_witness_replacement_is_refused(
    tmp_path: Path,
):
    shared, store, policy, first, first_authority = _fresh(tmp_path)
    second = store.verify_canary(
        policy=policy,
        codex_executable=shared["codex"],
    )
    assert second.receipt_identity != first.receipt_identity
    assert first_authority.receipt_revalidated is True
    with pytest.raises(SerializationWitnessError, match="not the externally"):
        store.load_verified_receipt(
            receipt_identity=first.receipt_identity,
            witness_run_identity=first.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=shared["identity"].to_dict(),
        )


def test_missing_durable_witness_evidence_is_refused(tmp_path: Path):
    _shared, store, policy, receipt, _authority = _fresh(tmp_path)
    _pack_path(store, receipt).unlink()
    with pytest.raises(SerializationWitnessError, match="evidence pack is missing"):
        store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=receipt.executable_identity,
        )


def test_changed_durable_witness_evidence_is_refused(tmp_path: Path):
    _shared, store, policy, receipt, _authority = _fresh(tmp_path)
    path = _pack_path(store, receipt)
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(SerializationWitnessError, match="evidence bytes changed"):
        store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=receipt.executable_identity,
        )


def test_backend_has_no_optional_runtime_model_override():
    signature = inspect.signature(HostCodexAppServerCapsuleBackend)
    assert "model_authority" not in signature.parameters
    assert "model" not in signature.parameters
    assert "reasoning_effort" not in signature.parameters


def test_receipt_excludes_prompt_credentials_headers_and_response_bodies():
    rendered = canonical_bytes(
        verified_canary_binding()["receipt"].to_dict()
    ).lower()
    for denied in (
        b"prompt_text",
        b"synthetic_credential",
        b"authorization_header",
        b"response_body",
    ):
        assert denied not in rendered
