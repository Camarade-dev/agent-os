from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import fields
import inspect
import json
from pathlib import Path
import sys
import threading
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.durability import (
    FileWriteFailure,
    PlatformDurabilityAdapter,
)
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
    create_historical_evaluation_pairing_authority,
    project_v5_runtime_authority_to_v2,
    validate_historical_evaluation_pairing_relation,
)
from admissible.delegated_gate.historical_evaluation_store import (
    AUTHORITY_DIRECTORY_NAME,
    AUTHORITY_FILE_SUFFIX,
    PAYLOAD_DIRECTORY_NAME,
    PAYLOAD_FILE_SUFFIX,
    PROFILE_DIRECTORY_NAME,
    PROFILE_FILE_SUFFIX,
    CommittedHistoricalEvaluationAuthorityNotFound,
    HistoricalEvaluationArchiveConflict,
    HistoricalEvaluationArchiveFingerprintMismatch,
    HistoricalEvaluationPairingBundle,
    MalformedHistoricalAuthorizationPayload,
    MalformedHistoricalEvaluationAuthority,
    MalformedHistoricalEvaluationProfile,
    ReferencedHistoricalAuthorizationPayloadNotFound,
    ReferencedHistoricalEvaluationProfileNotFound,
    load_historical_evaluation_pairing,
    persist_historical_evaluation_pairing,
)
from admissible.delegated_gate.mission_profile import (
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from test_admissible_historical_evaluation_pairing import (
    _payload_for_runtime_profile,
    _refingerprint_payload,
    _refingerprint_profile,
    _runtime_profile_variant,
)
from test_admissible_historical_v5_derivation import (
    _derive,
    _runtime_v2_profile,
)
from test_admissible_workflow_recovery_profile import _payload_harness


class SimulatedCrash(RuntimeError):
    pass


@pytest.fixture(scope="module")
def historical_pairing_documents(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[
    NativeMissionProfile,
    NativeCanaryAuthorizationPayloadV4,
    HistoricalEvaluationPairingAuthority,
]:
    fixture_root = tmp_path_factory.mktemp("historical-evaluation-store-fixture")
    runtime_profile = _runtime_v2_profile()
    live = _payload_harness(fixture_root, runtime_profile).payload.to_dict()
    absent = fixture_root / "absent-original-material"
    live["source_repository"] = str(absent / "source")
    live["executable"] = str(absent / "bin" / "agent.exe")
    live["launcher_prefix"] = [
        str(absent / "bin" / f"launcher-{index}.exe")
        for index, _value in enumerate(live["launcher_prefix"])
    ]
    run_root = absent / runtime_profile.run_id
    live["run_root"] = str(run_root)
    live["workspace_root"] = str(run_root / WORKSPACE_DIRECTORY_NAME)
    live["evidence_root"] = str(run_root / EVIDENCE_DIRECTORY_NAME)
    live["native_sidecar_root"] = str(
        run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME
    )
    payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(live)
    )
    profile = _derive(payload)
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.asserted-actor",
        evaluation_profile=profile,
        target_authorization_payload=payload,
    )
    assert not absent.exists()
    return profile, payload, authority


def _document_paths(
    archive_root: Path,
    profile: NativeMissionProfile,
    payload: NativeCanaryAuthorizationPayloadV4,
    authority: HistoricalEvaluationPairingAuthority,
) -> tuple[Path, Path, Path]:
    return (
        archive_root
        / PROFILE_DIRECTORY_NAME
        / f"{profile.profile_fingerprint}{PROFILE_FILE_SUFFIX}",
        archive_root
        / PAYLOAD_DIRECTORY_NAME
        / f"{payload.payload_fingerprint}{PAYLOAD_FILE_SUFFIX}",
        archive_root
        / AUTHORITY_DIRECTORY_NAME
        / f"{authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}",
    )


def _write_fragment(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _persist(
    archive_root: Path,
    documents: tuple[
        NativeMissionProfile,
        NativeCanaryAuthorizationPayloadV4,
        HistoricalEvaluationPairingAuthority,
    ],
) -> HistoricalEvaluationPairingAuthority:
    profile, payload, authority = documents
    return persist_historical_evaluation_pairing(
        archive_root=archive_root,
        evaluation_profile=profile,
        target_authorization_payload=payload,
        pairing_authority=authority,
    )


def _load(
    archive_root: Path,
    authority: HistoricalEvaluationPairingAuthority,
) -> HistoricalEvaluationPairingBundle:
    return load_historical_evaluation_pairing(
        archive_root=archive_root,
        authority_fingerprint=authority.authority_fingerprint,
    )


def test_persist_load_round_trip_is_exact_ordered_and_relation_validated(
    tmp_path: Path,
    historical_pairing_documents,
    monkeypatch: pytest.MonkeyPatch,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "archive"
    events: list[str] = []
    from admissible.delegated_gate import historical_evaluation_store as store_module

    real_relation = validate_historical_evaluation_pairing_relation
    real_publish = PlatformDurabilityAdapter.publish

    def observed_relation(**kwargs):
        events.append("relation")
        return real_relation(**kwargs)

    def observed_publish(self, final_path, data, **kwargs):
        events.append(Path(final_path).parent.name)
        return real_publish(self, final_path, data, **kwargs)

    monkeypatch.setattr(
        store_module,
        "validate_historical_evaluation_pairing_relation",
        observed_relation,
    )
    monkeypatch.setattr(PlatformDurabilityAdapter, "publish", observed_publish)

    returned = _persist(archive_root, historical_pairing_documents)
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    assert returned == authority
    assert profile_path.read_bytes() == canonical_bytes(profile.to_dict())
    assert payload_path.read_bytes() == canonical_bytes(payload.to_dict())
    assert authority_path.read_bytes() == canonical_bytes(authority.to_dict())
    assert events[:4] == [
        "relation",
        PROFILE_DIRECTORY_NAME,
        PAYLOAD_DIRECTORY_NAME,
        AUTHORITY_DIRECTORY_NAME,
    ]
    # The post-publication load reruns the accepted external relation validator.
    assert events[-1] == "relation"

    loaded = _load(archive_root, authority)
    assert canonical_bytes(loaded.evaluation_profile.to_dict()) == canonical_bytes(
        profile.to_dict()
    )
    assert canonical_bytes(
        loaded.target_authorization_payload.to_dict()
    ) == canonical_bytes(payload.to_dict())
    assert canonical_bytes(loaded.pairing_authority.to_dict()) == canonical_bytes(
        authority.to_dict()
    )
    assert loaded.evaluation_profile.is_launchable_runtime_profile is False


def test_public_api_has_only_explicit_archive_and_three_canonical_documents():
    persist_parameters = inspect.signature(
        persist_historical_evaluation_pairing
    ).parameters
    assert list(persist_parameters) == [
        "archive_root",
        "evaluation_profile",
        "target_authorization_payload",
        "pairing_authority",
    ]
    load_parameters = inspect.signature(
        load_historical_evaluation_pairing
    ).parameters
    assert list(load_parameters) == ["archive_root", "authority_fingerprint"]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in (*persist_parameters.values(), *load_parameters.values())
    )
    assert [field.name for field in fields(HistoricalEvaluationPairingBundle)] == [
        "evaluation_profile",
        "target_authorization_payload",
        "pairing_authority",
    ]
    assert not hasattr(HistoricalEvaluationPairingBundle, "to_dict")


def test_exact_replay_is_idempotent_without_republication(
    tmp_path: Path,
    historical_pairing_documents,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    first = _persist(archive_root, historical_pairing_documents)
    before = tuple(
        path.read_bytes()
        for path in _document_paths(archive_root, *historical_pairing_documents)
    )
    forbidden = AssertionError("exact replay attempted to publish a document")
    monkeypatch.setattr(
        PlatformDurabilityAdapter, "publish", mock.Mock(side_effect=forbidden)
    )
    second = _persist(archive_root, historical_pairing_documents)
    after = tuple(
        path.read_bytes()
        for path in _document_paths(archive_root, *historical_pairing_documents)
    )
    assert second == first
    assert after == before


@pytest.mark.parametrize("conflict_kind", ["profile", "payload", "authority"])
def test_existing_conflicting_bytes_are_never_overwritten_or_committed(
    tmp_path: Path,
    historical_pairing_documents,
    conflict_kind: str,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / conflict_kind
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    selected = {
        "profile": profile_path,
        "payload": payload_path,
        "authority": authority_path,
    }[conflict_kind]
    hostile = b'{"conflicting":"bytes"}'
    _write_fragment(selected, hostile)

    with pytest.raises(HistoricalEvaluationArchiveConflict):
        _persist(archive_root, historical_pairing_documents)

    assert selected.read_bytes() == hostile
    if conflict_kind != "authority":
        assert not authority_path.exists()
    if conflict_kind == "authority":
        assert not profile_path.exists()
        assert not payload_path.exists()


@pytest.mark.parametrize("conflict_kind", ["profile", "payload", "authority"])
def test_conflicting_replay_never_repairs_a_committed_document(
    tmp_path: Path,
    historical_pairing_documents,
    conflict_kind: str,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / f"committed-{conflict_kind}"
    _persist(archive_root, historical_pairing_documents)
    paths = _document_paths(archive_root, profile, payload, authority)
    selected = {
        "profile": paths[0],
        "payload": paths[1],
        "authority": paths[2],
    }[conflict_kind]
    hostile = b'{"post-commit":"conflict"}'
    selected.write_bytes(hostile)

    with pytest.raises(HistoricalEvaluationArchiveConflict):
        _persist(archive_root, historical_pairing_documents)

    assert selected.read_bytes() == hostile


@pytest.mark.parametrize("fragments", [("profile",), ("profile", "payload")])
def test_profile_or_profile_payload_fragments_are_not_committed(
    tmp_path: Path,
    historical_pairing_documents,
    fragments: tuple[str, ...],
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "-".join(fragments)
    profile_path, payload_path, _authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    if "profile" in fragments:
        _write_fragment(profile_path, canonical_bytes(profile.to_dict()))
    if "payload" in fragments:
        _write_fragment(payload_path, canonical_bytes(payload.to_dict()))
    with pytest.raises(CommittedHistoricalEvaluationAuthorityNotFound):
        _load(archive_root, authority)


def test_authority_without_profile_is_rejected(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "missing-profile"
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    _write_fragment(payload_path, canonical_bytes(payload.to_dict()))
    _write_fragment(authority_path, canonical_bytes(authority.to_dict()))
    assert not profile_path.exists()
    with pytest.raises(ReferencedHistoricalEvaluationProfileNotFound):
        _load(archive_root, authority)


def test_authority_without_payload_is_rejected(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "missing-payload"
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    _write_fragment(profile_path, canonical_bytes(profile.to_dict()))
    _write_fragment(authority_path, canonical_bytes(authority.to_dict()))
    assert not payload_path.exists()
    with pytest.raises(ReferencedHistoricalAuthorizationPayloadNotFound):
        _load(archive_root, authority)


def test_malformed_authority_is_rejected_as_a_commit_marker(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "malformed-authority"
    _profile_path, _payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    _write_fragment(authority_path, b'{"partial":')
    with pytest.raises(MalformedHistoricalEvaluationAuthority):
        _load(archive_root, authority)


@pytest.mark.parametrize("malformed_kind", ["profile", "payload"])
def test_malformed_referenced_document_never_returns_a_partial_bundle(
    tmp_path: Path,
    historical_pairing_documents,
    malformed_kind: str,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / malformed_kind
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    _write_fragment(
        profile_path,
        b'{"partial":'
        if malformed_kind == "profile"
        else canonical_bytes(profile.to_dict()),
    )
    _write_fragment(
        payload_path,
        b'{"partial":'
        if malformed_kind == "payload"
        else canonical_bytes(payload.to_dict()),
    )
    _write_fragment(authority_path, canonical_bytes(authority.to_dict()))
    error = (
        MalformedHistoricalEvaluationProfile
        if malformed_kind == "profile"
        else MalformedHistoricalAuthorizationPayload
    )
    with pytest.raises(error):
        _load(archive_root, authority)


def test_pretty_printed_referenced_document_is_not_accepted_as_canonical(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "pretty"
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    _write_fragment(
        profile_path,
        json.dumps(profile.to_dict(), indent=2, sort_keys=True).encode("utf-8"),
    )
    _write_fragment(payload_path, canonical_bytes(payload.to_dict()))
    _write_fragment(authority_path, canonical_bytes(authority.to_dict()))
    with pytest.raises(MalformedHistoricalEvaluationProfile, match="canonical"):
        _load(archive_root, authority)


def test_exact_retry_reuses_valid_orphaned_profile_and_payload(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "orphan-retry"
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    profile_bytes = canonical_bytes(profile.to_dict())
    payload_bytes = canonical_bytes(payload.to_dict())
    _write_fragment(profile_path, profile_bytes)
    _write_fragment(payload_path, payload_bytes)
    assert not authority_path.exists()

    assert _persist(archive_root, historical_pairing_documents) == authority
    assert profile_path.read_bytes() == profile_bytes
    assert payload_path.read_bytes() == payload_bytes
    assert authority_path.read_bytes() == canonical_bytes(authority.to_dict())


@pytest.mark.parametrize(
    ("failure_parent", "expected_visible"),
    [
        (PROFILE_DIRECTORY_NAME, (False, False, False)),
        (PAYLOAD_DIRECTORY_NAME, (True, False, False)),
        (AUTHORITY_DIRECTORY_NAME, (True, True, False)),
    ],
)
def test_crash_before_each_document_publication_preserves_commit_marker_law(
    tmp_path: Path,
    historical_pairing_documents,
    monkeypatch: pytest.MonkeyPatch,
    failure_parent: str,
    expected_visible: tuple[bool, bool, bool],
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / f"crash-{failure_parent}"
    paths = _document_paths(archive_root, profile, payload, authority)
    real_publish = PlatformDurabilityAdapter.publish

    def injected_failure(self, final_path, data, **kwargs):
        path = Path(final_path)
        if path.parent.name == failure_parent:
            raise FileWriteFailure(
                "simulated bounded publication interruption", path=path
            )
        return real_publish(self, final_path, data, **kwargs)

    monkeypatch.setattr(
        PlatformDurabilityAdapter, "publish", injected_failure
    )
    with pytest.raises(Exception, match="publication"):
        _persist(archive_root, historical_pairing_documents)
    assert tuple(path.exists() for path in paths) == expected_visible
    with pytest.raises(CommittedHistoricalEvaluationAuthorityNotFound):
        _load(archive_root, authority)

    monkeypatch.setattr(PlatformDurabilityAdapter, "publish", real_publish)
    assert _persist(archive_root, historical_pairing_documents) == authority
    assert _load(archive_root, authority).pairing_authority == authority


def test_interruption_during_authority_write_leaves_no_accepted_partial_marker(
    tmp_path: Path,
    historical_pairing_documents,
    monkeypatch: pytest.MonkeyPatch,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "during-authority"
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    real_publish = PlatformDurabilityAdapter.publish

    def interrupted(self, final_path, data, **kwargs):
        path = Path(final_path)
        if path.parent.name == AUTHORITY_DIRECTORY_NAME:
            (path.parent / f".{path.name}.interrupted.tmp").write_bytes(
                data[:17]
            )
            raise FileWriteFailure("simulated mid-authority write", path=path)
        return real_publish(self, final_path, data, **kwargs)

    monkeypatch.setattr(PlatformDurabilityAdapter, "publish", interrupted)
    with pytest.raises(Exception, match="publication"):
        _persist(archive_root, historical_pairing_documents)
    assert profile_path.is_file()
    assert payload_path.is_file()
    assert not authority_path.exists()
    with pytest.raises(CommittedHistoricalEvaluationAuthorityNotFound):
        _load(archive_root, authority)

    monkeypatch.setattr(PlatformDurabilityAdapter, "publish", real_publish)
    assert _persist(archive_root, historical_pairing_documents) == authority
    assert _load(archive_root, authority).pairing_authority == authority


def test_crash_after_authority_publication_before_return_is_retryable(
    tmp_path: Path,
    historical_pairing_documents,
    monkeypatch: pytest.MonkeyPatch,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "after-authority"
    _profile_path, _payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    from admissible.delegated_gate import historical_evaluation_store as store_module

    real_load = store_module.load_historical_evaluation_pairing

    def crash_after_marker(**kwargs):
        if authority_path.exists():
            raise SimulatedCrash("after authority write before return")
        return real_load(**kwargs)

    monkeypatch.setattr(
        store_module, "load_historical_evaluation_pairing", crash_after_marker
    )
    with pytest.raises(SimulatedCrash, match="after authority"):
        _persist(archive_root, historical_pairing_documents)
    assert authority_path.read_bytes() == canonical_bytes(authority.to_dict())

    monkeypatch.setattr(
        store_module, "load_historical_evaluation_pairing", real_load
    )
    assert real_load(
        archive_root=archive_root,
        authority_fingerprint=authority.authority_fingerprint,
    ).pairing_authority == authority
    assert _persist(archive_root, historical_pairing_documents) == authority


def test_failed_retry_cannot_make_an_existing_commit_unreadable(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "committed"
    _persist(archive_root, historical_pairing_documents)
    malformed = HistoricalEvaluationPairingAuthority(
        **{**authority.__dict__, "authority_fingerprint": "0" * 64}
    )
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        persist_historical_evaluation_pairing(
            archive_root=archive_root,
            evaluation_profile=profile,
            target_authorization_payload=payload,
            pairing_authority=malformed,
        )
    assert _load(archive_root, authority).pairing_authority == authority


def _changed_profile(
    profile: NativeMissionProfile,
    layer: str,
) -> NativeMissionProfile:
    data = profile.to_dict()
    if layer == "claims":
        data["claim_authority"]["claims"][0]["statement"] += " Updated."
    elif layer == "plan":
        data["claim_verification_plan_authority"]["verification_obligations"][0][
            "declared_coverage"
        ] += " Updated."
    elif layer == "bindings":
        data["verification_evidence_binding_authority"]["bindings"][0][
            "binding_id"
        ] = "binding.updated"
    else:
        raise AssertionError(layer)
    return NativeMissionProfile.from_dict(_refingerprint_profile(data))


@pytest.mark.parametrize("layer", ["claims", "plan", "bindings"])
def test_updated_v5_evaluation_layers_reject_before_any_archive_write(
    tmp_path: Path,
    historical_pairing_documents,
    layer: str,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / layer
    changed = _changed_profile(profile, layer)
    with pytest.raises(ValueError, match="does not reference this v5"):
        persist_historical_evaluation_pairing(
            archive_root=archive_root,
            evaluation_profile=changed,
            target_authorization_payload=payload,
            pairing_authority=authority,
        )
    assert not archive_root.exists()


def test_wrong_non_v5_profile_rejects_before_any_archive_write(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "wrong-v5"
    with pytest.raises(ValueError, match="exact v5 schema"):
        persist_historical_evaluation_pairing(
            archive_root=archive_root,
            evaluation_profile=project_v5_runtime_authority_to_v2(profile),
            target_authorization_payload=payload,
            pairing_authority=authority,
        )
    assert not archive_root.exists()


def _another_payload_same_v2(
    payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeCanaryAuthorizationPayloadV4:
    data = payload.to_dict()
    data["source_head"] = (
        "f" * len(data["source_head"])
        if data["source_head"] != "f" * len(data["source_head"])
        else "e" * len(data["source_head"])
    )
    return load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(data)
    )


def test_copied_self_valid_authority_rejects_another_payload_with_same_v2(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    other_payload = _another_payload_same_v2(payload)
    copied = HistoricalEvaluationPairingAuthority.from_dict(authority.to_dict())
    assert (
        other_payload.mission_profile.profile_fingerprint
        == payload.mission_profile.profile_fingerprint
    )
    assert other_payload.payload_fingerprint != payload.payload_fingerprint
    archive_root = tmp_path / "copied-authority"
    with pytest.raises(ValueError, match="does not reference this v4"):
        persist_historical_evaluation_pairing(
            archive_root=archive_root,
            evaluation_profile=profile,
            target_authorization_payload=other_payload,
            pairing_authority=copied,
        )
    assert not archive_root.exists()


def test_wrong_payload_with_different_embedded_runtime_rejects(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    wrong_runtime = _runtime_profile_variant(
        payload.mission_profile, "mission_text"
    )
    wrong_payload = _payload_for_runtime_profile(payload, wrong_runtime)
    archive_root = tmp_path / "wrong-payload"
    with pytest.raises(ValueError, match="does not reference this v4"):
        persist_historical_evaluation_pairing(
            archive_root=archive_root,
            evaluation_profile=profile,
            target_authorization_payload=wrong_payload,
            pairing_authority=authority,
        )
    assert not archive_root.exists()


@pytest.mark.parametrize(
    "hostile_fingerprint",
    [
        "A" * 64,
        "a" * 63,
        "../" + "a" * 61,
        "..\\" + "a" * 61,
        "C:" + "a" * 62,
        "https://" + "a" * 56,
        "." * 64,
    ],
)
def test_authority_fingerprint_path_traversal_and_noncanonical_forms_reject(
    tmp_path: Path,
    hostile_fingerprint: str,
):
    archive_root = tmp_path / "archive"
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        load_historical_evaluation_pairing(
            archive_root=archive_root,
            authority_fingerprint=hostile_fingerprint,
        )
    assert not archive_root.exists()


def test_loader_does_not_trust_filename_or_embedded_fingerprint_alone(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "fingerprint-mismatch"
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    profile_data = deepcopy(profile.to_dict())
    profile_data["profile_fingerprint"] = "0" * 64
    _write_fragment(profile_path, canonical_bytes(profile_data))
    _write_fragment(payload_path, canonical_bytes(payload.to_dict()))
    _write_fragment(authority_path, canonical_bytes(authority.to_dict()))
    with pytest.raises(HistoricalEvaluationArchiveFingerprintMismatch):
        _load(archive_root, authority)


def test_concurrent_identical_persistence_is_byte_exact(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "identical-concurrency"
    barrier = threading.Barrier(8)

    def writer(_index: int):
        barrier.wait()
        return _persist(archive_root, historical_pairing_documents)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(writer, range(8)))
    assert results == [authority] * 8
    profile_path, payload_path, authority_path = _document_paths(
        archive_root, profile, payload, authority
    )
    assert profile_path.read_bytes() == canonical_bytes(profile.to_dict())
    assert payload_path.read_bytes() == canonical_bytes(payload.to_dict())
    assert authority_path.read_bytes() == canonical_bytes(authority.to_dict())


def test_concurrent_conflicting_create_only_writers_cannot_overwrite(
    tmp_path: Path,
):
    from admissible.delegated_gate.historical_evaluation_store import (
        _persist_exact_document,
    )

    directory = tmp_path / "conflict"
    directory.mkdir()
    path = directory / "same-canonical-key.json"
    barrier = threading.Barrier(2)

    def writer(data: bytes):
        barrier.wait()
        try:
            _persist_exact_document(
                path=path,
                expected=data,
                label="concurrency probe",
                durability_adapter=PlatformDurabilityAdapter(),
            )
            return "committed"
        except HistoricalEvaluationArchiveConflict:
            return "conflict"

    candidates = (b'{"writer":"alpha"}', b'{"writer":"beta"}')
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(writer, candidates))
    assert sorted(outcomes) == ["committed", "conflict"]
    assert path.read_bytes() in candidates


def _byte_manifest(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_only_explicit_archive_root_changes_and_original_material_is_immutable(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    original = tmp_path / "representative-historical-run" / profile.run_id
    evidence = original / EVIDENCE_DIRECTORY_NAME
    sidecar = evidence / NATIVE_SIDECAR_DIRECTORY_NAME
    workspace = original / WORKSPACE_DIRECTORY_NAME
    sidecar.mkdir(parents=True)
    workspace.mkdir()
    (original / "canary-preflight.json").write_bytes(b'{"historical":true}')
    (original / "manifest.json").write_bytes(b'{"immutable":"manifest"}')
    (evidence / "terminal-record.json").write_bytes(b'{"terminal":"record"}')
    (sidecar / "process-observation.json").write_bytes(b'{"process":"record"}')
    (workspace / "material.txt").write_bytes(b"original material")
    target_mapping = payload.to_dict()
    target_mapping["run_root"] = str(original)
    target_mapping["workspace_root"] = str(workspace)
    target_mapping["evidence_root"] = str(evidence)
    target_mapping["native_sidecar_root"] = str(sidecar)
    target_payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(target_mapping)
    )
    target_authority = create_historical_evaluation_pairing_authority(
        actor_id=authority.actor_id,
        evaluation_profile=profile,
        target_authorization_payload=target_payload,
    )
    before = _byte_manifest(original)
    archive_root = tmp_path / "separate-archive"

    persist_historical_evaluation_pairing(
        archive_root=archive_root,
        evaluation_profile=profile,
        target_authorization_payload=target_payload,
        pairing_authority=target_authority,
    )
    _load(archive_root, target_authority)

    assert _byte_manifest(original) == before
    assert archive_root != Path(target_payload.run_root)
    assert archive_root != Path(target_payload.source_repository)
    assert set(path.name for path in archive_root.iterdir()) == {
        PROFILE_DIRECTORY_NAME,
        PAYLOAD_DIRECTORY_NAME,
        AUTHORITY_DIRECTORY_NAME,
    }


def test_persist_and_load_are_evidence_runtime_product_and_provider_blind(
    tmp_path: Path,
    historical_pairing_documents,
    monkeypatch: pytest.MonkeyPatch,
):
    _profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "blind-archive"
    forbidden = AssertionError("historical evaluation store touched forbidden state")
    from admissible.delegated_gate import native_canary

    forbidden_dependencies = (
        mock.patch.object(
            native_canary, "AtomicNativeExecutionStore", side_effect=forbidden
        ),
        mock.patch.object(
            native_canary, "AtomicDelegatedSessionStore", side_effect=forbidden
        ),
        mock.patch.object(
            native_canary, "capture_checkpoint", side_effect=forbidden
        ),
        mock.patch.object(
            native_canary, "run_behavioral_verifier", side_effect=forbidden
        ),
        mock.patch.object(
            native_canary,
            "reconstruct_completed_native_mission",
            side_effect=forbidden,
        ),
        mock.patch.object(
            native_canary, "preflight_native_cursor", side_effect=forbidden
        ),
    )
    forbidden_prefixes = (
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.delegated_gate.native_acceptance",
    )
    modules_before = {
        name for name in sys.modules if name.startswith(forbidden_prefixes)
    }
    real_read_bytes = Path.read_bytes
    accessed: list[Path] = []

    def guarded_read_bytes(path: Path) -> bytes:
        accessed.append(path)
        try:
            path.relative_to(archive_root)
        except ValueError as exc:
            raise forbidden from exc
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    with ExitStack() as stack:
        for dependency in forbidden_dependencies:
            stack.enter_context(dependency)
        _persist(archive_root, historical_pairing_documents)
        loaded = _load(archive_root, authority)
    assert loaded.target_authorization_payload.payload_fingerprint == (
        payload.payload_fingerprint
    )
    assert accessed
    assert {
        name for name in sys.modules if name.startswith(forbidden_prefixes)
    } == modules_before


def test_actor_id_is_only_an_asserted_identifier_and_no_fourth_authority_exists(
    tmp_path: Path,
    historical_pairing_documents,
):
    profile, payload, authority = historical_pairing_documents
    archive_root = tmp_path / "actor"
    _persist(archive_root, historical_pairing_documents)
    loaded = _load(archive_root, authority)
    assert loaded.pairing_authority.actor_id == "owner.asserted-actor"
    bundle_doc = inspect.getdoc(HistoricalEvaluationPairingBundle).lower()
    persist_doc = inspect.getdoc(persist_historical_evaluation_pairing).lower()
    assert "asserted actor identifier" in bundle_doc
    assert "no actor authentication" in persist_doc
    assert "authenticated actor" not in bundle_doc + persist_doc
    forbidden_fields = {
        "authenticated",
        "signature",
        "owner_phrase",
        "availability",
        "resolution",
        "status",
        "success",
        "evidence",
    }
    for document in (
        profile.to_dict(),
        payload.to_dict(),
        authority.to_dict(),
    ):
        assert forbidden_fields.isdisjoint(document)
    assert len(tuple(archive_root.rglob("*.json"))) == 3
