"""Step 5C2B: headless confirmation-gated coordinator for historical pairing.

Every expected confirmation tag in this module is produced by an independent
oracle that re-implements the documented canonical-JSON rule and calls the
standard library directly.  The coordinator under test is never asked to
produce an expectation it is then compared against.
"""

from __future__ import annotations

import ast
import builtins
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
import hashlib
import hmac
import inspect
import itertools
import json
import os
from pathlib import Path
import re
import sys
import threading
from unittest import mock

import pytest

from admissible.delegated_gate import historical_pairing_workflow as workflow
from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.durability import PlatformDurabilityAdapter
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
    create_historical_evaluation_pairing_authority,
    derive_historical_v5_evaluation_profile,
)
from admissible.delegated_gate.historical_evaluation_store import (
    AUTHORITY_DIRECTORY_NAME,
    AUTHORITY_FILE_SUFFIX,
    PAYLOAD_DIRECTORY_NAME,
    PAYLOAD_FILE_SUFFIX,
    PROFILE_DIRECTORY_NAME,
    PROFILE_FILE_SUFFIX,
    HistoricalEvaluationArchiveDurabilityError,
    HistoricalEvaluationPairingBundle,
    load_historical_evaluation_pairing,
    persist_historical_evaluation_pairing,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN,
    MAX_CONFIRMATION_SECRET_BYTES,
    MIN_CONFIRMATION_SECRET_BYTES,
    compute_historical_pairing_confirmation_tag,
)
from admissible.delegated_gate.historical_pairing_workflow import (
    CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE,
    CONFIRMATION_REJECTED_MESSAGE,
    DEFAULT_MAX_PREPARATIONS,
    DEFAULT_PREPARATION_TTL_SECONDS,
    HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS,
    MAX_PREPARATION_CAPACITY,
    MAX_PREPARATION_ID_ATTEMPTS,
    MAX_PREPARATION_TTL_SECONDS,
    HistoricalEvaluationPairingCoordinator,
    HistoricalEvaluationPairingPreparationView,
    HistoricalEvaluationPairingReviewProjection,
    HistoricalEvaluationPairingWorkflowResult,
    HistoricalPairingWorkflowError,
    InvalidPairingCoordinatorConfiguration,
    InvalidPairingPreparationRequest,
    MalformedPairingConfirmationTag,
    PairingArchiveConflict,
    PairingArchiveContentMismatch,
    PairingArchiveDurabilityUncertain,
    PairingArchiveReloadFailed,
    PairingArchiveWriteFailed,
    PairingConfirmationRejected,
    PairingPreparationCapacityExhausted,
    PairingPreparationConsumed,
    PairingPreparationExpired,
    PairingPreparationIdentifierUnavailable,
    PairingPreparationInUse,
    PairingPreparationNotFound,
    StalePairingAuthorityFingerprint,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    OWNER_AUTHORIZATION_DIGEST_ENV,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from test_admissible_historical_evaluation_pairing import _refingerprint_payload
from test_admissible_historical_pairing_confirmation import (
    _disclosures,
    _disclosures_in_text,
    _fragments_of,
    _observed_sinks,
)
from test_admissible_historical_v5_derivation import (
    _derive,
    _owner_bindings,
    _owner_claims,
    _owner_plan,
    _runtime_v2_profile,
)
from test_admissible_workflow_recovery_profile import _payload_harness


# ---------------------------------------------------------------------------
# Fixture material.
#
# The secret is deliberately printable ASCII and deliberately short so the
# derived forbidden-fragment set stays small and fully deterministic.  It is
# fixture material and no real secret.
# ---------------------------------------------------------------------------

# Deliberately structureless printable ASCII: no contiguous eight-character
# window of it can occur accidentally in ordinary source text or in a canonical
# document, so a fragment match is always a real disclosure.
WORKFLOW_SECRET = b"Xq7Zk9Vb3Nm5Pw1Rt4Hj6Ds8Fg2Ly0Cu5Ai8Ne3Ov6"
OTHER_SECRET = b"Bd4Tc8Wr2Zx6Qm0Ls9Ky3Ju7Ng1Ep5Ha4Iv2Fo6Xz"
ACTOR_ID = "owner.asserted-actor"
OTHER_ACTOR_ID = "owner.other-asserted-actor"


@pytest.fixture(scope="module")
def historical_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    """One exact historical V4 payload whose every path is absent on disk."""

    fixture_root = tmp_path_factory.mktemp("s5c2b")
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
    assert not absent.exists()
    return payload


def _owner_material(payload: NativeCanaryAuthorizationPayloadV4) -> dict:
    """Fresh owner-authored member arrays for one preparation request."""

    return {
        "result_claims": _owner_claims(),
        "claim_verification_plan": _owner_plan(),
        "verification_evidence_bindings": _owner_bindings(
            payload.mission_profile.verification.verifier_source_sha256
        ),
    }


@pytest.fixture(scope="module")
def expected_profile(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeMissionProfile:
    return _derive(historical_payload)


@pytest.fixture(scope="module")
def expected_authority(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
) -> HistoricalEvaluationPairingAuthority:
    return create_historical_evaluation_pairing_authority(
        actor_id=ACTOR_ID,
        evaluation_profile=expected_profile,
        target_authorization_payload=historical_payload,
    )


@pytest.fixture(scope="module")
def other_authority(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
) -> HistoricalEvaluationPairingAuthority:
    return create_historical_evaluation_pairing_authority(
        actor_id=OTHER_ACTOR_ID,
        evaluation_profile=expected_profile,
        target_authorization_payload=historical_payload,
    )


def _independent_tag(secret: bytes, authority_document: dict) -> str:
    """Recompute one tag without touching any production helper."""

    body = json.dumps(
        authority_document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(
        key=secret,
        msg=b"admissible_historical_evaluation_pairing_confirmation_v1"
        + b"\x00"
        + body,
        digestmod=hashlib.sha256,
    ).hexdigest()


@pytest.fixture(scope="module")
def expected_tag(
    expected_authority: HistoricalEvaluationPairingAuthority,
) -> str:
    return _independent_tag(WORKFLOW_SECRET, expected_authority.to_dict())


WRONG_TAG = "0" * 64


class _FakeClock:
    """Injectable monotonic clock that only ever moves when a test says so."""

    def __init__(self, start: float = 10_000.0) -> None:
        self.value = float(start)

    def __call__(self) -> float:
        return self.value

    def advance(self, delta: float) -> None:
        self.value += float(delta)


def _sequential_identifiers(prefix: str = "prep"):
    counter = itertools.count(1)
    return lambda: f"{prefix}-{next(counter):06d}"


def _coordinator(archive_root: Path, **overrides):
    kwargs = dict(
        configured_secret=WORKFLOW_SECRET,
        archive_root=archive_root,
        preparation_ttl_seconds=600,
        max_preparations=8,
        clock=_FakeClock(),
        preparation_id_factory=_sequential_identifiers(),
    )
    kwargs.update(overrides)
    return HistoricalEvaluationPairingCoordinator(**kwargs)


def _prepare(coordinator, payload, *, actor_id: str = ACTOR_ID, **overrides):
    kwargs = dict(
        target_authorization_payload=payload,
        actor_id=actor_id,
        **_owner_material(payload),
    )
    kwargs.update(overrides)
    return coordinator.prepare_historical_evaluation_pairing(**kwargs)


def _confirm(coordinator, view, tag: str, **overrides):
    kwargs = dict(
        preparation_id=view.preparation_id,
        expected_authority_fingerprint=view.authority_fingerprint,
        presented_confirmation_tag=tag,
    )
    kwargs.update(overrides)
    return coordinator.confirm_historical_evaluation_pairing(**kwargs)


def _archive_documents(archive_root: Path) -> list[str]:
    if not archive_root.exists():
        return []
    return sorted(
        str(path.relative_to(archive_root)).replace("\\", "/")
        for path in archive_root.rglob("*")
        if path.is_file()
    )


def _expected_document_names(
    profile: NativeMissionProfile,
    payload: NativeCanaryAuthorizationPayloadV4,
    authority: HistoricalEvaluationPairingAuthority,
) -> list[str]:
    return sorted(
        [
            f"{AUTHORITY_DIRECTORY_NAME}/"
            f"{authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}",
            f"{PAYLOAD_DIRECTORY_NAME}/"
            f"{payload.payload_fingerprint}{PAYLOAD_FILE_SUFFIX}",
            f"{PROFILE_DIRECTORY_NAME}/"
            f"{profile.profile_fingerprint}{PROFILE_FILE_SUFFIX}",
        ]
    )


class _SecretAccessRecordingCoordinator(HistoricalEvaluationPairingCoordinator):
    """Coordinator that records every read of the configured secret."""

    def __init__(self, **kwargs) -> None:
        self.secret_reads: list[str] = []
        super().__init__(**kwargs)

    @property
    def _configured_secret(self) -> bytes:
        self.secret_reads.append("read")
        return self._recorded_secret

    @_configured_secret.setter
    def _configured_secret(self, value: bytes) -> None:
        self._recorded_secret = value


# ---------------------------------------------------------------------------
# Bounded filesystem-access observation.
# ---------------------------------------------------------------------------

_OBSERVED_PATH_METHODS = (
    "open",
    "exists",
    "is_file",
    "is_dir",
    "stat",
    "lstat",
    "mkdir",
    "read_bytes",
    "read_text",
    "write_bytes",
    "write_text",
    "iterdir",
    "glob",
    "rglob",
    "touch",
    "unlink",
    "rename",
    "replace",
    "resolve",
    "samefile",
)
_OBSERVED_OS_FUNCTIONS = (
    "stat",
    "lstat",
    "listdir",
    "scandir",
    "mkdir",
    "makedirs",
    "open",
    "replace",
    "rename",
    "remove",
    "unlink",
    "rmdir",
    "walk",
)


@contextmanager
def _observed_filesystem_access():
    """Record every filesystem entry point reached inside one bounded window."""

    seen: list[str] = []
    with ExitStack() as stack:

        def install(owner, name: str) -> None:
            original = getattr(owner, name)

            def wrapper(*args, **kwargs):
                seen.append(f"{name}({args[0] if args else ''})")
                return original(*args, **kwargs)

            stack.enter_context(mock.patch.object(owner, name, wrapper))

        for method in _OBSERVED_PATH_METHODS:
            if hasattr(Path, method):
                install(Path, method)
        for function in _OBSERVED_OS_FUNCTIONS:
            if hasattr(os, function):
                install(os, function)
        install(builtins, "open")
        yield seen


def _payload_paths(payload: NativeCanaryAuthorizationPayloadV4) -> tuple[str, ...]:
    return (
        payload.source_repository,
        payload.executable,
        payload.run_root,
        payload.workspace_root,
        payload.evidence_root,
        payload.native_sidecar_root,
        *payload.launcher_prefix,
    )


# ===========================================================================
# A. Preparation composes the accepted primitives and writes nothing.
# ===========================================================================


def test_preparation_composes_the_accepted_primitives_in_the_pinned_order(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []
    observed = {
        "derive_historical_v5_evaluation_profile": "derive",
        "create_historical_evaluation_pairing_authority": "authority",
        "validate_historical_evaluation_pairing_relation": "relation",
        "build_historical_pairing_confirmation_message": "message",
        "persist_historical_evaluation_pairing": "persist",
        "load_historical_evaluation_pairing": "load",
        "verify_historical_pairing_confirmation_tag": "verify",
    }
    for name, label in observed.items():
        original = getattr(workflow, name)

        def spy(*args, _original=original, _label=label, **kwargs):
            events.append(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(workflow, name, spy)

    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)

    assert events == ["derive", "authority", "relation", "message"]
    assert "persist" not in events and "load" not in events and "verify" not in events
    assert view.preparation_id == "prep-000001"
    assert isinstance(view, HistoricalEvaluationPairingPreparationView)
    assert isinstance(
        view.review_projection, HistoricalEvaluationPairingReviewProjection
    )


def test_preparation_derives_the_exact_step_5b_v5_and_step_5a_authority(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)

    assert view.evaluation_profile_fingerprint == expected_profile.profile_fingerprint
    assert view.target_authorization_payload_fingerprint == (
        historical_payload.payload_fingerprint
    )
    assert view.authority_fingerprint == expected_authority.authority_fingerprint
    assert view.asserted_actor_id == ACTOR_ID


def test_prepared_evaluation_profile_remains_non_launchable(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)

    assert expected_profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert expected_profile.is_launchable_runtime_profile is False
    projection = view.review_projection
    assert projection.evaluation_profile_schema_version == (
        MISSION_PROFILE_SCHEMA_VERSION_V5
    )
    assert projection.evaluation_profile_is_launchable is False


def test_preparation_pins_the_exact_step_5c2a_confirmation_message(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)

    authority_bytes = canonical_bytes(expected_authority.to_dict())
    assert view.confirmation_message == (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN + b"\x00" + authority_bytes
    )
    assert isinstance(view.confirmation_message, bytes)
    assert view.confirmation_message.count(b"\x00") == 1


def test_preparation_view_exposes_only_presentation_safe_fields(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)

    assert [field.name for field in fields(view)] == [
        "preparation_id",
        "asserted_actor_id",
        "authority_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "confirmation_message",
        "review_projection",
        "limitations",
    ]
    assert [field.name for field in fields(view.review_projection)] == [
        "evaluation_profile_schema_version",
        "evaluation_profile_is_launchable",
        "target_authorization_payload_schema_version",
        "pairing_authority_schema_version",
        "profile_id",
        "run_id",
        "session_id",
        "gate_id",
        "mission_id",
        "result_claim_ids",
        "verification_obligation_ids",
        "verification_evidence_binding_ids",
    ]
    # No canonical-document disguise, no store, no lock, no reservation state.
    assert not hasattr(view, "to_dict")
    assert not hasattr(view.review_projection, "to_dict")
    for forbidden in (
        "secret",
        "expected_tag",
        "tag",
        "archive_root",
        "archive_path",
        "confirmation_reserved",
        "consumed",
        "created_at",
        "evaluation_profile",
        "target_authorization_payload",
        "pairing_authority",
    ):
        assert not hasattr(view, forbidden), forbidden
    with pytest.raises(FrozenInstanceError):
        view.asserted_actor_id = "owner.injected"
    with pytest.raises(FrozenInstanceError):
        view.review_projection.run_id = "injected"
    assert isinstance(view.review_projection.result_claim_ids, tuple)


def test_preparation_projection_is_derived_from_the_pinned_canonical_objects(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
):
    coordinator = _coordinator(tmp_path / "archive")
    projection = _prepare(coordinator, historical_payload).review_projection

    assert projection.run_id == expected_profile.run_id
    assert projection.session_id == expected_profile.session_id
    assert projection.gate_id == expected_profile.gate_id
    assert projection.mission_id == expected_profile.mission_id
    assert projection.profile_id == expected_profile.profile_id
    assert projection.result_claim_ids == tuple(
        claim.claim_id for claim in expected_profile.claim_authority.claims
    )
    assert projection.verification_obligation_ids == tuple(
        obligation.obligation_id
        for obligation in (
            expected_profile.claim_verification_plan_authority
            .verification_obligations
        )
    )
    assert projection.verification_evidence_binding_ids == tuple(
        binding.binding_id
        for binding in (
            expected_profile.verification_evidence_binding_authority.bindings
        )
    )
    assert projection.target_authorization_payload_schema_version == (
        historical_payload.schema_version
    )


def test_preparation_performs_no_filesystem_access_at_all(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    with _observed_filesystem_access() as seen:
        view = _prepare(coordinator, historical_payload)
    assert seen == []
    assert view.preparation_id
    assert not archive_root.exists()


def test_preparation_dereferences_no_historical_payload_path(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    coordinator = _coordinator(tmp_path / "archive")
    with _observed_filesystem_access() as seen:
        _prepare(coordinator, historical_payload)
    rendered = "\n".join(seen)
    for path in _payload_paths(historical_payload):
        assert path not in rendered
        assert not Path(path).exists()


def test_coordinator_construction_writes_nothing(
    tmp_path: Path,
):
    archive_root = tmp_path / "never-created"
    with _observed_filesystem_access() as seen:
        coordinator = _coordinator(archive_root)
    assert seen == []
    assert not archive_root.exists()
    assert repr(coordinator) == "<HistoricalEvaluationPairingCoordinator>"
    assert "0x" not in repr(coordinator)


def test_preparation_never_reads_the_configured_secret(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _SecretAccessRecordingCoordinator(
        configured_secret=WORKFLOW_SECRET,
        archive_root=tmp_path / "archive",
        preparation_ttl_seconds=600,
        max_preparations=8,
        clock=_FakeClock(),
        preparation_id_factory=_sequential_identifiers(),
    )
    view = _prepare(coordinator, historical_payload)
    assert coordinator.secret_reads == []
    # The secret is reached exactly once, and only during confirmation.
    _confirm(coordinator, view, expected_tag)
    assert coordinator.secret_reads == ["read"]


_INVALID_PREPARATION_INPUTS = (
    ("payload-not-canonical", {"target_authorization_payload": object()}),
    ("payload-is-mapping", {"target_authorization_payload": {"schema_version": "x"}}),
    ("claims-empty", {"result_claims": []}),
    ("claims-mapping", {"result_claims": {"claims": []}}),
    ("claims-none", {"result_claims": None}),
    ("plan-empty", {"claim_verification_plan": []}),
    ("bindings-empty", {"verification_evidence_bindings": []}),
    ("actor-empty", {"actor_id": ""}),
    ("actor-not-identifier", {"actor_id": "owner actor"}),
    ("actor-not-string", {"actor_id": 17}),
)


@pytest.mark.parametrize(
    ("overrides",),
    [(overrides,) for _label, overrides in _INVALID_PREPARATION_INPUTS],
    ids=[label for label, _overrides in _INVALID_PREPARATION_INPUTS],
)
def test_invalid_preparation_inputs_are_refused_and_leave_no_preparation(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    overrides: dict,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    # A capacity of one proves publicly that the refusal stored nothing.
    coordinator = _coordinator(archive_root, max_preparations=1)
    with pytest.raises(InvalidPairingPreparationRequest):
        _prepare(coordinator, historical_payload, **overrides)
    assert not archive_root.exists()
    view = _prepare(coordinator, historical_payload)
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_owner_material_mutated_after_preparation_cannot_change_the_pinning(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    material = _owner_material(historical_payload)
    view = coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=historical_payload,
        actor_id=ACTOR_ID,
        **material,
    )
    material["result_claims"][0]["statement"] = "injected after preparation"
    material["result_claims"].append({"claim_id": "claim.injected"})
    material["claim_verification_plan"].clear()
    material["verification_evidence_bindings"].clear()

    result = _confirm(coordinator, view, expected_tag)
    assert result.authority_fingerprint == expected_authority.authority_fingerprint
    assert result.asserted_actor_id == ACTOR_ID
    assert canonical_bytes(
        result.archived_pairing.pairing_authority.to_dict()
    ) == canonical_bytes(expected_authority.to_dict())


# ===========================================================================
# B. Preparation lifetime and capacity.
# ===========================================================================


def test_preparation_expires_exactly_at_its_bounded_ttl(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    clock = _FakeClock()
    coordinator = _coordinator(
        archive_root, preparation_ttl_seconds=10, clock=clock
    )
    view = _prepare(coordinator, historical_payload)

    # 9.5 and 0.5 are exactly representable, so the boundary is exact.
    clock.advance(9.5)
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, WRONG_TAG)

    clock.advance(0.5)
    with pytest.raises(PairingPreparationExpired):
        _confirm(coordinator, view, expected_tag)
    assert not archive_root.exists()
    # The expired locator is dropped, so it can never be revived.
    with pytest.raises(PairingPreparationNotFound):
        _confirm(coordinator, view, expected_tag)


def test_backwards_moving_clock_fails_closed(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    clock = _FakeClock()
    coordinator = _coordinator(
        archive_root, preparation_ttl_seconds=600, clock=clock
    )
    view = _prepare(coordinator, historical_payload)
    clock.advance(-1.0)
    with pytest.raises(PairingPreparationExpired):
        _confirm(coordinator, view, expected_tag)
    assert not archive_root.exists()


def test_preparation_capacity_is_bounded_and_reclaimed_after_expiry(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    clock = _FakeClock()
    coordinator = _coordinator(
        tmp_path / "archive",
        max_preparations=2,
        preparation_ttl_seconds=30,
        clock=clock,
    )
    first = _prepare(coordinator, historical_payload)
    second = _prepare(coordinator, historical_payload)
    assert first.preparation_id != second.preparation_id
    with pytest.raises(PairingPreparationCapacityExhausted):
        _prepare(coordinator, historical_payload)
    with pytest.raises(PairingPreparationCapacityExhausted):
        _prepare(coordinator, historical_payload)

    clock.advance(30)
    third = _prepare(coordinator, historical_payload)
    assert third.preparation_id not in {first.preparation_id, second.preparation_id}
    with pytest.raises(PairingPreparationNotFound):
        _confirm(coordinator, first, WRONG_TAG)


def test_consumed_preparations_are_reclaimed_before_a_capacity_refusal(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive", max_preparations=1)
    first = _prepare(coordinator, historical_payload)
    assert _confirm(coordinator, first, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    second = _prepare(coordinator, historical_payload)
    assert second.preparation_id != first.preparation_id
    assert _confirm(coordinator, second, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_preparation_identifier_collisions_retry_a_bounded_number_of_times(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    calls: list[str] = []

    def colliding() -> str:
        calls.append("call")
        return "prep-collision"

    coordinator = _coordinator(
        tmp_path / "archive", preparation_id_factory=colliding
    )
    first = _prepare(coordinator, historical_payload)
    assert first.preparation_id == "prep-collision"
    assert len(calls) == 1
    with pytest.raises(PairingPreparationIdentifierUnavailable):
        _prepare(coordinator, historical_payload)
    assert len(calls) == 1 + MAX_PREPARATION_ID_ATTEMPTS


def test_preparation_identifier_factory_must_return_a_bounded_identifier(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    for produced in ("", "short", "x" * 65, "-leading", "with space", 17):
        coordinator = _coordinator(
            tmp_path / "archive", preparation_id_factory=lambda value=produced: value
        )
        with pytest.raises(InvalidPairingCoordinatorConfiguration):
            _prepare(coordinator, historical_payload)


def test_preparation_identifiers_are_unique_and_opaque_locators(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    coordinator = HistoricalEvaluationPairingCoordinator(
        configured_secret=WORKFLOW_SECRET,
        archive_root=tmp_path / "archive",
    )
    identifiers = {
        _prepare(coordinator, historical_payload).preparation_id for _index in range(8)
    }
    assert len(identifiers) == 8
    for identifier in identifiers:
        assert re.fullmatch(r"[0-9a-f]{32}", identifier)
        # An ephemeral locator is not an authority identity.
        assert identifier != expected_authority.authority_fingerprint
        assert identifier not in expected_authority.to_dict().values()


# ===========================================================================
# C. Confirmation ordering, verification and persistence.
# ===========================================================================


def test_independently_computed_tag_confirms_persists_and_reloads(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    result = _confirm(coordinator, view, expected_tag)

    assert isinstance(result, HistoricalEvaluationPairingWorkflowResult)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert result.preparation_id == view.preparation_id
    assert result.asserted_actor_id == ACTOR_ID
    assert result.authority_fingerprint == expected_authority.authority_fingerprint
    assert result.evaluation_profile_fingerprint == (
        expected_profile.profile_fingerprint
    )
    assert result.target_authorization_payload_fingerprint == (
        historical_payload.payload_fingerprint
    )
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )

    bundle = result.archived_pairing
    assert isinstance(bundle, HistoricalEvaluationPairingBundle)
    # A genuine public reload returns fresh objects, never the pinned ones.
    assert bundle.target_authorization_payload is not historical_payload
    assert bundle.evaluation_profile is not expected_profile
    assert canonical_bytes(bundle.evaluation_profile.to_dict()) == canonical_bytes(
        expected_profile.to_dict()
    )
    assert canonical_bytes(
        bundle.target_authorization_payload.to_dict()
    ) == canonical_bytes(historical_payload.to_dict())
    assert canonical_bytes(bundle.pairing_authority.to_dict()) == canonical_bytes(
        expected_authority.to_dict()
    )
    assert bundle.evaluation_profile.is_launchable_runtime_profile is False
    # The store's own public load agrees with the returned bundle.
    reloaded = load_historical_evaluation_pairing(
        archive_root=archive_root,
        authority_fingerprint=expected_authority.authority_fingerprint,
    )
    assert reloaded == bundle


def test_confirmation_invokes_the_accepted_apis_in_the_required_order(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)

    events: list[str] = []
    for name, label in (
        ("verify_historical_pairing_confirmation_tag", "verify"),
        ("persist_historical_evaluation_pairing", "persist"),
        ("load_historical_evaluation_pairing", "load"),
    ):
        original = getattr(workflow, name)

        def spy(*args, _original=original, _label=label, **kwargs):
            events.append(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(workflow, name, spy)

    _confirm(coordinator, view, expected_tag)
    assert events == ["verify", "persist", "load"]


def test_wrong_valid_format_tag_is_rejected_generically_and_writes_nothing(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    forbidden = AssertionError("persistence was attempted before verification")
    monkeypatch.setattr(
        workflow,
        "persist_historical_evaluation_pairing",
        mock.Mock(side_effect=forbidden),
    )
    with pytest.raises(PairingConfirmationRejected) as caught:
        _confirm(coordinator, view, WRONG_TAG)
    assert str(caught.value) == CONFIRMATION_REJECTED_MESSAGE
    assert not archive_root.exists()
    assert _archive_documents(archive_root) == []


_MALFORMED_TAGS = (
    ("uppercase", "A" * 64),
    ("too-short", "0" * 63),
    ("too-long", "0" * 65),
    ("non-hex", "g" * 64),
    ("padded", " " + "0" * 63),
    ("bytes", b"0" * 64),
    ("none", None),
    ("integer", 0),
)


@pytest.mark.parametrize(
    ("candidate",),
    [(candidate,) for _label, candidate in _MALFORMED_TAGS],
    ids=[label for label, _candidate in _MALFORMED_TAGS],
)
def test_malformed_tag_fails_boundedly_without_writing(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    candidate,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    with pytest.raises(MalformedPairingConfirmationTag):
        _confirm(coordinator, view, candidate)
    assert not archive_root.exists()


def test_presented_secret_is_never_accepted_in_place_of_a_tag(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    for candidate in (
        WORKFLOW_SECRET,
        WORKFLOW_SECRET.hex(),
        WORKFLOW_SECRET.hex()[:64],
        WORKFLOW_SECRET.decode("ascii"),
    ):
        with pytest.raises(HistoricalPairingWorkflowError) as caught:
            _confirm(coordinator, view, candidate)
        assert isinstance(
            caught.value,
            (MalformedPairingConfirmationTag, PairingConfirmationRejected),
        )
    assert not archive_root.exists()


def test_runtime_owner_digest_construction_is_not_a_valid_confirmation(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    # Exactly the committed runtime owner-authorization construction.
    runtime_style = hashlib.sha256(
        WORKFLOW_SECRET + b"\0" + canonical_bytes(expected_authority.to_dict())
    ).hexdigest()
    assert runtime_style != expected_tag
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, runtime_style)
    assert not archive_root.exists()
    # The accepted HMAC construction still confirms on the same preparation.
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_another_authority_tag_does_not_confirm_this_pairing(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_authority: HistoricalEvaluationPairingAuthority,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    other_tag = _independent_tag(WORKFLOW_SECRET, other_authority.to_dict())
    assert other_authority.authority_fingerprint != (
        expected_authority.authority_fingerprint
    )
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, other_tag)
    assert not archive_root.exists()


def test_another_configured_secret_tag_does_not_confirm(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    foreign = _independent_tag(OTHER_SECRET, expected_authority.to_dict())
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, foreign)
    assert not archive_root.exists()


def test_stale_expected_authority_fingerprint_fails_before_secret_access(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _SecretAccessRecordingCoordinator(
        configured_secret=WORKFLOW_SECRET,
        archive_root=archive_root,
        preparation_ttl_seconds=600,
        max_preparations=8,
        clock=_FakeClock(),
        preparation_id_factory=_sequential_identifiers(),
    )
    view = _prepare(coordinator, historical_payload)

    verifications: list[str] = []
    monkeypatch.setattr(
        workflow,
        "verify_historical_pairing_confirmation_tag",
        lambda **kwargs: verifications.append("verify") or True,
    )
    with pytest.raises(StalePairingAuthorityFingerprint):
        _confirm(
            coordinator,
            view,
            expected_tag,
            expected_authority_fingerprint="f" * 64,
        )
    assert verifications == []
    assert coordinator.secret_reads == []
    assert not archive_root.exists()


def test_malformed_expected_authority_fingerprint_is_a_bounded_input_refusal(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    for candidate in ("", "F" * 64, "0" * 63, None, 17):
        with pytest.raises(InvalidPairingPreparationRequest):
            _confirm(
                coordinator, view, expected_tag,
                expected_authority_fingerprint=candidate,
            )


def test_unknown_and_malformed_preparation_identifiers_are_bounded(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    with pytest.raises(PairingPreparationNotFound):
        _confirm(coordinator, view, expected_tag, preparation_id="prep-999999")
    for candidate in ("", "short", "x" * 65, "with space", None, 17):
        with pytest.raises(InvalidPairingPreparationRequest):
            _confirm(coordinator, view, expected_tag, preparation_id=candidate)


def test_preparation_is_consumed_only_after_complete_success(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    with pytest.raises(PairingPreparationConsumed):
        _confirm(coordinator, view, expected_tag)
    with pytest.raises(PairingPreparationConsumed):
        _confirm(coordinator, view, WRONG_TAG)


# ===========================================================================
# D. Configured secret versus presented tag separation.
# ===========================================================================


def test_public_api_separates_configured_secret_from_presented_tag():
    construction = inspect.signature(
        HistoricalEvaluationPairingCoordinator.__init__
    ).parameters
    assert list(construction) == [
        "self",
        "configured_secret",
        "archive_root",
        "preparation_ttl_seconds",
        "max_preparations",
        "clock",
        "preparation_id_factory",
    ]
    preparation = inspect.signature(
        HistoricalEvaluationPairingCoordinator.prepare_historical_evaluation_pairing
    ).parameters
    assert list(preparation) == [
        "self",
        "target_authorization_payload",
        "result_claims",
        "claim_verification_plan",
        "verification_evidence_bindings",
        "actor_id",
    ]
    confirmation = inspect.signature(
        HistoricalEvaluationPairingCoordinator.confirm_historical_evaluation_pairing
    ).parameters
    assert list(confirmation) == [
        "self",
        "preparation_id",
        "expected_authority_fingerprint",
        "presented_confirmation_tag",
    ]
    for parameters in (construction, preparation, confirmation):
        assert all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for name, parameter in parameters.items()
            if name != "self"
        )
    # No request-scoped credential, archive root, fingerprint, identifier, or
    # timestamp may be smuggled in, and no API may take both a secret and a tag.
    request_parameters = set(preparation) | set(confirmation)
    for forbidden in (
        "secret",
        "configured_secret",
        "presented_secret",
        "archive_root",
        "pairing_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "preparation_ttl_seconds",
        "timestamp",
        "created_at",
        "evidence",
        "result",
    ):
        assert forbidden not in request_parameters, forbidden
    assert "presented_confirmation_tag" not in set(preparation)
    assert "configured_secret" not in set(confirmation)


def test_coordinator_passes_the_caller_tag_verbatim_to_the_accepted_verifier(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
    monkeypatch: pytest.MonkeyPatch,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    recorded: dict = {}
    real = workflow.verify_historical_pairing_confirmation_tag

    def spy(*, configured_secret, pairing_authority, presented_tag):
        recorded["secret"] = configured_secret
        recorded["authority"] = pairing_authority
        recorded["tag"] = presented_tag
        return real(
            configured_secret=configured_secret,
            pairing_authority=pairing_authority,
            presented_tag=presented_tag,
        )

    monkeypatch.setattr(
        workflow, "verify_historical_pairing_confirmation_tag", spy
    )
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, WRONG_TAG)

    # The coordinator forwards exactly what the caller presented; it never
    # computes a tag of its own and feeds that into its own verifier.
    assert recorded["tag"] == WRONG_TAG
    assert recorded["secret"] is WORKFLOW_SECRET
    assert recorded["authority"] == expected_authority


def test_verification_is_delegated_to_the_accepted_helper(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    monkeypatch.setattr(
        workflow, "verify_historical_pairing_confirmation_tag", lambda **kwargs: False
    )
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, expected_tag)
    assert not archive_root.exists()

    monkeypatch.setattr(
        workflow, "verify_historical_pairing_confirmation_tag", lambda **kwargs: True
    )
    assert _confirm(coordinator, view, WRONG_TAG).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_non_true_verifier_answers_are_refused(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    for truthy in (1, "yes", [1], object()):
        view = _prepare(coordinator, historical_payload)
        monkeypatch.setattr(
            workflow,
            "verify_historical_pairing_confirmation_tag",
            lambda _value=truthy, **kwargs: _value,
        )
        with pytest.raises(PairingConfirmationRejected):
            _confirm(coordinator, view, expected_tag)
    assert not archive_root.exists()


def test_coordinator_never_references_the_tag_computer(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    source = Path(inspect.getfile(workflow)).read_text(encoding="utf-8")
    assert "compute_historical_pairing_confirmation_tag" not in source
    assert not hasattr(workflow, "compute_historical_pairing_confirmation_tag")
    assert "hmac" not in source and "hashlib" not in source
    # The coordinator never probes the archive before publishing, so it can
    # never build a racy published-now versus already-present distinction.
    assert ".exists(" not in source
    assert ".is_file(" not in source


def test_no_public_surface_returns_an_expected_tag(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    rendered = repr(view) + repr(view.review_projection)
    assert expected_tag not in rendered
    result = _confirm(coordinator, view, expected_tag)
    rendered_result = repr(result)
    assert expected_tag not in rendered_result
    assert WORKFLOW_SECRET.hex() not in rendered_result
    assert [field.name for field in fields(result)] == [
        "outcome",
        "preparation_id",
        "asserted_actor_id",
        "authority_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "archived_pairing",
        "limitations",
    ]
    assert not hasattr(result, "to_dict")
    with pytest.raises(FrozenInstanceError):
        result.outcome = "INJECTED"


# ===========================================================================
# E. Retry and crash behaviour.
# ===========================================================================


def test_wrong_tag_leaves_the_preparation_retryable(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    for _attempt in range(5):
        with pytest.raises(PairingConfirmationRejected):
            _confirm(coordinator, view, WRONG_TAG)
    assert not archive_root.exists()
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_persistence_failure_before_commit_leaves_the_preparation_retryable(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    monkeypatch.setattr(
        workflow,
        "persist_historical_evaluation_pairing",
        mock.Mock(
            side_effect=HistoricalEvaluationArchiveDurabilityError("simulated")
        ),
    )
    with pytest.raises(PairingArchiveDurabilityUncertain):
        _confirm(coordinator, view, expected_tag)
    assert _archive_documents(archive_root) == []

    monkeypatch.undo()
    result = _confirm(coordinator, view, expected_tag)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )


def test_arbitrary_persistence_error_is_bounded_and_retryable(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    monkeypatch.setattr(
        workflow,
        "persist_historical_evaluation_pairing",
        mock.Mock(side_effect=OSError("simulated device failure")),
    )
    with pytest.raises(PairingArchiveWriteFailed):
        _confirm(coordinator, view, expected_tag)
    monkeypatch.undo()
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_interrupted_publication_leaves_an_orphan_prefix_and_retries_exactly(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    real_publish = PlatformDurabilityAdapter.publish

    def interrupted(self, final_path, data, **kwargs):
        if Path(final_path).parent.name == AUTHORITY_DIRECTORY_NAME:
            raise OSError("simulated interruption before the commit marker")
        return real_publish(self, final_path, data, **kwargs)

    monkeypatch.setattr(PlatformDurabilityAdapter, "publish", interrupted)
    with pytest.raises(PairingArchiveWriteFailed):
        _confirm(coordinator, view, expected_tag)

    # Step 5C1 orphan-prefix semantics: the referenced documents exist, the
    # commit marker does not, and the pairing is therefore not loadable.
    documents = _archive_documents(archive_root)
    assert documents == sorted(
        [
            f"{PAYLOAD_DIRECTORY_NAME}/"
            f"{historical_payload.payload_fingerprint}{PAYLOAD_FILE_SUFFIX}",
            f"{PROFILE_DIRECTORY_NAME}/"
            f"{expected_profile.profile_fingerprint}{PROFILE_FILE_SUFFIX}",
        ]
    )

    monkeypatch.undo()
    result = _confirm(coordinator, view, expected_tag)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )


def test_post_persist_load_failure_keeps_the_archive_and_allows_exact_retry(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    monkeypatch.setattr(
        workflow,
        "load_historical_evaluation_pairing",
        mock.Mock(side_effect=OSError("simulated response failure")),
    )
    with pytest.raises(PairingArchiveReloadFailed):
        _confirm(coordinator, view, expected_tag)

    # The archive is the durable truth even though the response failed.
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    monkeypatch.undo()
    result = _confirm(coordinator, view, expected_tag)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )


def test_reloaded_documents_that_differ_from_the_pinned_objects_are_refused(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    other_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    foreign = HistoricalEvaluationPairingBundle(
        evaluation_profile=expected_profile,
        target_authorization_payload=historical_payload,
        pairing_authority=other_authority,
    )
    monkeypatch.setattr(
        workflow, "load_historical_evaluation_pairing", lambda **kwargs: foreign
    )
    with pytest.raises(PairingArchiveContentMismatch):
        _confirm(coordinator, view, expected_tag)

    monkeypatch.setattr(
        workflow, "load_historical_evaluation_pairing", lambda **kwargs: None
    )
    with pytest.raises(PairingArchiveReloadFailed):
        _confirm(coordinator, view, expected_tag)

    monkeypatch.undo()
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


@pytest.mark.parametrize(
    "document", ["profile", "payload", "authority"]
)
def test_conflicting_archive_bytes_are_bounded_and_retryable(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    document: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)

    occupied = {
        "profile": archive_root
        / PROFILE_DIRECTORY_NAME
        / f"{expected_profile.profile_fingerprint}{PROFILE_FILE_SUFFIX}",
        "payload": archive_root
        / PAYLOAD_DIRECTORY_NAME
        / f"{historical_payload.payload_fingerprint}{PAYLOAD_FILE_SUFFIX}",
        "authority": archive_root
        / AUTHORITY_DIRECTORY_NAME
        / f"{expected_authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}",
    }[document]
    occupied.parent.mkdir(parents=True, exist_ok=True)
    occupied.write_bytes(b'{"conflicting":"bytes"}')
    with pytest.raises(PairingArchiveConflict):
        _confirm(coordinator, view, expected_tag)
    assert occupied.read_bytes() == b'{"conflicting":"bytes"}'

    occupied.unlink()
    result = _confirm(coordinator, view, expected_tag)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )


def test_stale_fingerprint_releases_the_reservation_and_stays_retryable(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    for _attempt in range(3):
        with pytest.raises(StalePairingAuthorityFingerprint):
            _confirm(
                coordinator, view, expected_tag,
                expected_authority_fingerprint="b" * 64,
            )
    assert not archive_root.exists()
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


_FAILURE_INJECTIONS = (
    ("wrong-tag", None, WRONG_TAG, PairingConfirmationRejected),
    ("malformed-tag", None, "Z" * 64, MalformedPairingConfirmationTag),
    (
        "persistence",
        ("persist_historical_evaluation_pairing", OSError("simulated")),
        None,
        PairingArchiveWriteFailed,
    ),
    (
        "reload",
        ("load_historical_evaluation_pairing", OSError("simulated")),
        None,
        PairingArchiveReloadFailed,
    ),
)


@pytest.mark.parametrize(
    ("patch", "tag", "expected_error"),
    [(patch, tag, error) for _label, patch, tag, error in _FAILURE_INJECTIONS],
    ids=[label for label, _patch, _tag, _error in _FAILURE_INJECTIONS],
)
def test_reservation_is_released_on_every_failure_path(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
    patch,
    tag,
    expected_error,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    if patch is not None:
        name, error = patch
        monkeypatch.setattr(workflow, name, mock.Mock(side_effect=error))
    with pytest.raises(expected_error):
        _confirm(coordinator, view, tag if tag is not None else expected_tag)
    monkeypatch.undo()
    # A retained reservation would surface here as IN_USE rather than success.
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_a_fresh_preparation_reaches_the_same_archive_state_with_the_same_tag(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    first = _confirm(
        coordinator, _prepare(coordinator, historical_payload), expected_tag
    )
    documents = {
        path: (archive_root / path).read_bytes()
        for path in _archive_documents(archive_root)
    }
    second = _confirm(
        coordinator, _prepare(coordinator, historical_payload), expected_tag
    )

    assert first.preparation_id != second.preparation_id
    for name in (
        "outcome",
        "asserted_actor_id",
        "authority_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "archived_pairing",
        "limitations",
    ):
        assert getattr(first, name) == getattr(second, name), name
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    assert {
        path: (archive_root / path).read_bytes()
        for path in _archive_documents(archive_root)
    } == documents


# ===========================================================================
# F. Concurrency.
# ===========================================================================


def test_second_confirm_during_persistence_receives_a_bounded_in_use_refusal(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    entered = threading.Event()
    proceed = threading.Event()
    real_persist = workflow.persist_historical_evaluation_pairing

    def blocking_persist(**kwargs):
        entered.set()
        assert proceed.wait(timeout=60)
        return real_persist(**kwargs)

    monkeypatch.setattr(
        workflow, "persist_historical_evaluation_pairing", blocking_persist
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_confirm, coordinator, view, expected_tag)
        assert entered.wait(timeout=60)
        with pytest.raises(PairingPreparationInUse):
            _confirm(coordinator, view, expected_tag)
        with pytest.raises(PairingPreparationInUse):
            _confirm(coordinator, view, WRONG_TAG)
        proceed.set()
        result = pending.result(timeout=60)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    with pytest.raises(PairingPreparationConsumed):
        _confirm(coordinator, view, expected_tag)


def test_simultaneous_confirms_admit_exactly_one_verification_and_publication(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    rounds = 12
    entries = {"verify": 0, "persist": 0}
    counter_lock = threading.Lock()
    for name, label in (
        ("verify_historical_pairing_confirmation_tag", "verify"),
        ("persist_historical_evaluation_pairing", "persist"),
    ):
        original = getattr(workflow, name)

        def counting(*args, _original=original, _label=label, **kwargs):
            with counter_lock:
                entries[_label] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(workflow, name, counting)

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for index in range(rounds):
            archive_root = tmp_path / f"archive-{index}"
            coordinator = _coordinator(archive_root)
            view = _prepare(coordinator, historical_payload)
            barrier = threading.Barrier(2)

            def attempt():
                barrier.wait(timeout=60)
                try:
                    return ("ok", _confirm(coordinator, view, expected_tag).outcome)
                except HistoricalPairingWorkflowError as exc:
                    return ("error", type(exc).__name__)

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = [
                    future.result(timeout=60)
                    for future in [pool.submit(attempt), pool.submit(attempt)]
                ]
            successes = [outcome for kind, outcome in outcomes if kind == "ok"]
            refusals = [outcome for kind, outcome in outcomes if kind == "error"]
            assert successes == [CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE]
            assert set(refusals) <= {
                "PairingPreparationInUse",
                "PairingPreparationConsumed",
            }
            assert len(refusals) == 1
            assert _archive_documents(archive_root) == _expected_document_names(
                expected_profile, historical_payload, expected_authority
            )
    finally:
        sys.setswitchinterval(previous_interval)
    assert entries == {"verify": rounds, "persist": rounds}


def test_a_wrong_tag_storm_cannot_permanently_lock_a_preparation(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    barrier = threading.Barrier(4)

    def attempt():
        barrier.wait(timeout=60)
        try:
            _confirm(coordinator, view, WRONG_TAG)
            return "unexpected-success"
        except HistoricalPairingWorkflowError as exc:
            return type(exc).__name__

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = [
            future.result(timeout=60)
            for future in [pool.submit(attempt) for _index in range(4)]
        ]
    assert set(outcomes) <= {"PairingConfirmationRejected", "PairingPreparationInUse"}
    assert not archive_root.exists()
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_simultaneous_wrong_and_correct_tags_never_publish_more_than_one_archive(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    barrier = threading.Barrier(2)

    def attempt(tag: str):
        barrier.wait(timeout=60)
        try:
            return ("ok", _confirm(coordinator, view, tag).outcome)
        except HistoricalPairingWorkflowError as exc:
            return ("error", type(exc).__name__)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            future.result(timeout=60)
            for future in [
                pool.submit(attempt, expected_tag),
                pool.submit(attempt, WRONG_TAG),
            ]
        ]
    successes = [outcome for kind, outcome in outcomes if kind == "ok"]
    assert len(successes) <= 1
    if not successes:
        assert _confirm(coordinator, view, expected_tag).outcome == (
            CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
        )
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )


def test_independent_preparations_for_the_same_authority_stay_independent(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    views = [_prepare(coordinator, historical_payload) for _index in range(4)]
    assert len({view.preparation_id for view in views}) == 4
    assert len({view.authority_fingerprint for view in views}) == 1
    barrier = threading.Barrier(4)

    def attempt(view):
        barrier.wait(timeout=60)
        return _confirm(coordinator, view, expected_tag).outcome

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = [
            future.result(timeout=60)
            for future in [pool.submit(attempt, view) for view in views]
        ]
    assert outcomes == [CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE] * 4
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    for view in views:
        with pytest.raises(PairingPreparationConsumed):
            _confirm(coordinator, view, expected_tag)


# ===========================================================================
# G. Archive-root semantics.
# ===========================================================================


def test_two_configured_roots_share_the_authority_message_and_tag(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    left_root = tmp_path / "left-archive"
    right_root = tmp_path / "right-archive"
    left = _coordinator(left_root)
    right = _coordinator(right_root)

    left_view = _prepare(left, historical_payload)
    right_view = _prepare(right, historical_payload)

    assert left_view.authority_fingerprint == right_view.authority_fingerprint
    assert left_view.evaluation_profile_fingerprint == (
        right_view.evaluation_profile_fingerprint
    )
    assert left_view.confirmation_message == right_view.confirmation_message
    for root in (left_root, right_root):
        assert str(root).encode("utf-8") not in left_view.confirmation_message
        assert root.name.encode("utf-8") not in left_view.confirmation_message

    left_result = _confirm(left, left_view, expected_tag)
    right_result = _confirm(right, right_view, expected_tag)
    assert left_result.authority_fingerprint == right_result.authority_fingerprint
    expected_names = _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    assert _archive_documents(left_root) == expected_names
    assert _archive_documents(right_root) == expected_names
    for name in expected_names:
        assert (left_root / name).read_bytes() == (right_root / name).read_bytes()


def test_the_archive_root_never_reaches_the_tag_or_the_confirmation_request(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    with pytest.raises(TypeError):
        coordinator.confirm_historical_evaluation_pairing(
            preparation_id=view.preparation_id,
            expected_authority_fingerprint=view.authority_fingerprint,
            presented_confirmation_tag=expected_tag,
            archive_root=tmp_path / "attacker-archive",
        )
    with pytest.raises(TypeError):
        coordinator.prepare_historical_evaluation_pairing(
            target_authorization_payload=historical_payload,
            actor_id=ACTOR_ID,
            archive_root=tmp_path / "attacker-archive",
            **_owner_material(historical_payload),
        )
    assert not (tmp_path / "attacker-archive").exists()
    assert not archive_root.exists()


_INVALID_CONFIGURATIONS = (
    ("secret-too-short", {"configured_secret": b"x" * 15}),
    (
        "secret-too-long",
        {"configured_secret": b"x" * (MAX_CONFIRMATION_SECRET_BYTES + 1)},
    ),
    ("secret-empty", {"configured_secret": b""}),
    ("secret-text", {"configured_secret": "x" * 32}),
    ("secret-bytearray", {"configured_secret": bytearray(b"x" * 32)}),
    ("secret-none", {"configured_secret": None}),
    ("root-relative", {"archive_root": Path("relative-archive")}),
    ("root-text", {"archive_root": "C:/absolute/but/text"}),
    ("root-none", {"archive_root": None}),
    ("ttl-zero", {"preparation_ttl_seconds": 0}),
    ("ttl-negative", {"preparation_ttl_seconds": -1}),
    ("ttl-bool", {"preparation_ttl_seconds": True}),
    ("ttl-too-large", {"preparation_ttl_seconds": MAX_PREPARATION_TTL_SECONDS + 1}),
    ("capacity-zero", {"max_preparations": 0}),
    ("capacity-too-large", {"max_preparations": MAX_PREPARATION_CAPACITY + 1}),
    ("clock-not-callable", {"clock": 1.0}),
    ("factory-not-callable", {"preparation_id_factory": "prep"}),
)


@pytest.mark.parametrize(
    ("overrides",),
    [(overrides,) for _label, overrides in _INVALID_CONFIGURATIONS],
    ids=[label for label, _overrides in _INVALID_CONFIGURATIONS],
)
def test_invalid_configuration_is_refused_without_touching_the_filesystem(
    tmp_path: Path,
    overrides: dict,
):
    archive_root = tmp_path / "archive"
    remaining = dict(overrides)
    root = remaining.pop("archive_root", archive_root)
    with _observed_filesystem_access() as seen:
        with pytest.raises(InvalidPairingCoordinatorConfiguration):
            _coordinator(root, **remaining)
    assert seen == []
    assert not archive_root.exists()


def test_configured_secret_bounds_match_the_accepted_step_5c2a_bounds(
    tmp_path: Path,
):
    assert MIN_CONFIRMATION_SECRET_BYTES == 16
    assert MAX_CONFIRMATION_SECRET_BYTES == 4096
    for length in (MIN_CONFIRMATION_SECRET_BYTES, MAX_CONFIRMATION_SECRET_BYTES):
        coordinator = _coordinator(tmp_path / "archive", configured_secret=b"k" * length)
        assert isinstance(coordinator, HistoricalEvaluationPairingCoordinator)


def test_configured_secret_is_retained_exactly_and_never_reencoded(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
    monkeypatch: pytest.MonkeyPatch,
):
    # A secret with a trailing NUL and non-UTF-8 bytes survives untouched.
    hostile = b"\xff\xfe binary-secret with trailing nul\x00"
    assert len(hostile) >= MIN_CONFIRMATION_SECRET_BYTES
    coordinator = _coordinator(tmp_path / "archive", configured_secret=hostile)
    view = _prepare(coordinator, historical_payload)
    recorded: dict = {}
    real = workflow.verify_historical_pairing_confirmation_tag

    def spy(*, configured_secret, pairing_authority, presented_tag):
        recorded["secret"] = configured_secret
        return real(
            configured_secret=configured_secret,
            pairing_authority=pairing_authority,
            presented_tag=presented_tag,
        )

    monkeypatch.setattr(workflow, "verify_historical_pairing_confirmation_tag", spy)
    hostile_tag = _independent_tag(hostile, expected_authority.to_dict())
    assert _confirm(coordinator, view, hostile_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    assert recorded["secret"] is hostile
    assert recorded["secret"] == hostile


# ===========================================================================
# H. No receipt, evidence blindness, environment blindness.
# ===========================================================================


def test_successful_confirmation_creates_exactly_three_documents(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    _confirm(coordinator, _prepare(coordinator, historical_payload), expected_tag)

    documents = _archive_documents(archive_root)
    assert documents == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    assert len(documents) == 3
    assert sorted(
        entry.name for entry in archive_root.iterdir() if entry.is_dir()
    ) == sorted(
        [AUTHORITY_DIRECTORY_NAME, PAYLOAD_DIRECTORY_NAME, PROFILE_DIRECTORY_NAME]
    )
    # Nothing that even looks like a receipt, record, or confirmation document.
    joined = " ".join(documents).lower()
    for forbidden in (
        "receipt",
        "confirmation",
        "record",
        "tag",
        "secret",
        "verifier",
        "hmac",
    ):
        assert forbidden not in joined, forbidden
    for name in documents:
        document = json.loads((archive_root / name).read_text(encoding="utf-8"))
        rendered = json.dumps(document, sort_keys=True).lower()
        for forbidden in ("confirmation_tag", "presented_tag", "confirmed_at"):
            assert forbidden not in rendered, forbidden


def test_confirmation_dereferences_no_historical_payload_path(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    with _observed_filesystem_access() as seen:
        _confirm(coordinator, view, expected_tag)
    rendered = "\n".join(seen)
    assert rendered  # persistence really did reach the filesystem
    for path in _payload_paths(historical_payload):
        assert path not in rendered
        assert not Path(path).exists()


def test_no_execution_evidence_product_or_acceptance_module_is_reached(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    tracked = (
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.product_launcher",
        "admissible.review_surface",
        "admissible.browser_runtime",
        "admissible.delegated_gate.native_executor",
        "admissible.delegated_gate.native_acceptance",
        "admissible.delegated_gate.store",
        "admissible.delegated_gate.state",
        "admissible.delegated_gate.reducer",
        "admissible.delegated_gate.checkpoint",
        "admissible.delegated_gate.events",
    )
    source = Path(inspect.getfile(workflow)).read_text(encoding="utf-8")
    for prefix in tracked:
        assert prefix not in source, prefix
    for forbidden in (
        "canary-preflight",
        "NativeCanaryOutcome",
        "EvidenceOnlyCanaryReconstruction",
        "run_root",
        "evidence_root",
        "workspace_root",
        "source_repository",
        "native_sidecar_root",
        "launcher_prefix",
    ):
        assert forbidden not in source, forbidden

    # The complete import graph, pinned exactly.  A new dependency on any
    # execution, evidence, acceptance, product, or provider module fails here
    # before it can ever be exercised.
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add(node.module)
    assert imported == {
        "__future__",
        "dataclasses",
        "math",
        "os",
        "pathlib",
        "re",
        "secrets",
        "threading",
        "time",
        "typing",
        "admissible.delegated_gate.canonical",
        "admissible.delegated_gate.historical_evaluation",
        "admissible.delegated_gate.historical_evaluation_store",
        "admissible.delegated_gate.historical_pairing_confirmation",
        "admissible.delegated_gate.mission_profile",
        "admissible.delegated_gate.native_canary",
    }

    before = {name for name in sys.modules if name.startswith(tracked)}
    coordinator = _coordinator(tmp_path / "archive")
    _confirm(coordinator, _prepare(coordinator, historical_payload), expected_tag)
    after = {name for name in sys.modules if name.startswith(tracked)}
    assert after == before


def test_no_environment_variable_is_read_or_written(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    source = Path(inspect.getfile(workflow)).read_text(encoding="utf-8")
    for forbidden in ("environ", "getenv", "putenv", OWNER_AUTHORIZATION_DIGEST_ENV):
        assert forbidden not in source, forbidden

    accesses: list[str] = []
    real_environ = os.environ

    class _TripwireEnvironment(dict):
        def __getitem__(self, key):
            accesses.append(str(key))
            return real_environ[key]

        def __contains__(self, key):
            accesses.append(str(key))
            return key in real_environ

        def get(self, key, default=None):
            accesses.append(str(key))
            return real_environ.get(key, default)

    monkeypatch.setattr(os, "environ", _TripwireEnvironment(real_environ))
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    assert accesses == []
    result = _confirm(coordinator, view, expected_tag)
    monkeypatch.undo()
    assert accesses == []
    assert OWNER_AUTHORIZATION_DIGEST_ENV not in accesses
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE


# ===========================================================================
# I. Confidentiality of the configured secret and the presented tag.
# ===========================================================================


@pytest.fixture(scope="module")
def forbidden_fragments(expected_tag: str) -> frozenset[str]:
    return _fragments_of(WORKFLOW_SECRET, expected_tag)


def test_confidentiality_fixture_is_printable_ascii_and_bounded(
    forbidden_fragments: frozenset[str],
    expected_tag: str,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    assert WORKFLOW_SECRET.isascii()
    assert WORKFLOW_SECRET.decode("ascii").isprintable()
    assert (
        MIN_CONFIRMATION_SECRET_BYTES
        <= len(WORKFLOW_SECRET)
        <= MAX_CONFIRMATION_SECRET_BYTES
    )
    assert expected_tag == compute_historical_pairing_confirmation_tag(
        secret=WORKFLOW_SECRET, pairing_authority=expected_authority
    )
    assert 0 < len(forbidden_fragments) < 400
    assert min(len(fragment) for fragment in forbidden_fragments) == 8
    assert {expected_tag, WORKFLOW_SECRET.decode("ascii")} <= forbidden_fragments
    # The guard is armed: a deliberate leak is detected.
    assert _disclosures_in_text(f"leak={expected_tag[:16]}", forbidden_fragments) != []


def test_a_complete_workflow_discloses_nothing_on_any_output_sink(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    forbidden_fragments: frozenset[str],
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    with _observed_sinks() as observation:
        view = _prepare(coordinator, historical_payload)
        result = _confirm(coordinator, view, expected_tag)
    assert _disclosures(observation, forbidden_fragments) == []
    assert observation.is_silent()
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE


def test_every_rejection_path_discloses_nothing_on_any_output_sink(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    forbidden_fragments: frozenset[str],
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    messages: list[str] = []
    with _observed_sinks() as observation:
        for candidate, expected_fingerprint in (
            (WRONG_TAG, view.authority_fingerprint),
            ("A" * 64, view.authority_fingerprint),
            (WORKFLOW_SECRET.hex()[:64], view.authority_fingerprint),
            (expected_tag, "f" * 64),
            (expected_tag[:-1] + ("0" if expected_tag[-1] != "0" else "1"),
             view.authority_fingerprint),
        ):
            try:
                _confirm(
                    coordinator,
                    view,
                    candidate,
                    expected_authority_fingerprint=expected_fingerprint,
                )
            except HistoricalPairingWorkflowError as exc:
                messages.append(f"{type(exc).__name__}: {exc}")
    assert _disclosures(observation, forbidden_fragments) == []
    assert observation.is_silent()
    assert len(messages) == 5
    for message in messages:
        assert _disclosures_in_text(message, forbidden_fragments) == []
        assert "0x" not in message


def test_no_bounded_error_string_carries_forbidden_material(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    forbidden_fragments: frozenset[str],
    monkeypatch: pytest.MonkeyPatch,
):
    # A distinctive directory name that no bounded message may ever contain.
    archive_root = tmp_path / "kv7q2x-root"
    coordinator = _coordinator(archive_root, max_preparations=1)
    view = _prepare(coordinator, historical_payload)
    collected: list[BaseException] = []

    def capture(callable_):
        try:
            callable_()
        except HistoricalPairingWorkflowError as exc:
            collected.append(exc)
            return
        raise AssertionError("a bounded coordinator error was expected")

    capture(lambda: _coordinator(archive_root, configured_secret=b"short"))
    capture(lambda: _prepare(coordinator, historical_payload, result_claims=[]))
    capture(lambda: _prepare(coordinator, historical_payload))
    capture(lambda: _confirm(coordinator, view, expected_tag, preparation_id="nope-1234"))
    capture(lambda: _confirm(coordinator, view, "Z" * 64))
    capture(lambda: _confirm(coordinator, view, WRONG_TAG))
    capture(
        lambda: _confirm(
            coordinator, view, expected_tag, expected_authority_fingerprint="a" * 64
        )
    )
    with monkeypatch.context() as patched:
        patched.setattr(
            workflow,
            "persist_historical_evaluation_pairing",
            mock.Mock(side_effect=OSError("simulated")),
        )
        capture(lambda: _confirm(coordinator, view, expected_tag))
    with monkeypatch.context() as patched:
        patched.setattr(
            workflow,
            "load_historical_evaluation_pairing",
            mock.Mock(side_effect=OSError("simulated")),
        )
        capture(lambda: _confirm(coordinator, view, expected_tag))

    assert len(collected) == 9
    root_text = str(archive_root)
    for error in collected:
        for rendered in (str(error), repr(error)):
            assert _disclosures_in_text(rendered, forbidden_fragments) == []
            assert expected_tag not in rendered
            assert root_text not in rendered
            assert archive_root.name not in rendered
            assert "0x" not in rendered
        message = str(error).lower()
        for forbidden in (
            "evidence",
            "checkpoint",
            "terminal",
            "behavioral",
            "artifact",
            "verdict",
            "reconstruction",
            "workspace",
            "claim.",
            "verify.",
            "binding.",
            "{",
            "}",
        ):
            assert forbidden not in message, (forbidden, message)


def test_no_archive_byte_or_name_carries_forbidden_material(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    forbidden_fragments: frozenset[str],
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    _confirm(coordinator, _prepare(coordinator, historical_payload), expected_tag)
    for name in _archive_documents(archive_root):
        assert _disclosures_in_text(name, forbidden_fragments) == []
        rendered = (archive_root / name).read_bytes().decode("latin-1")
        assert _disclosures_in_text(rendered, forbidden_fragments) == []


def test_no_returned_object_or_module_global_carries_forbidden_material(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    forbidden_fragments: frozenset[str],
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    result = _confirm(coordinator, view, expected_tag)
    for rendered in (
        repr(view),
        repr(view.review_projection),
        repr(result),
        repr(result.archived_pairing),
        repr(coordinator),
        # The live registry itself, including the now-consumed preparation.
        repr(coordinator._preparations),
        "\n".join(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS),
    ):
        assert _disclosures_in_text(rendered, forbidden_fragments) == []
    for name, value in vars(workflow).items():
        if name.startswith("__"):
            continue
        assert _disclosures_in_text(repr(value), forbidden_fragments) == [], name
    source = Path(inspect.getfile(workflow)).read_text(encoding="utf-8")
    assert _disclosures_in_text(source, forbidden_fragments) == []


# ===========================================================================
# J. Semantic limitations and the direct-store bypass.
# ===========================================================================


def test_workflow_limitations_are_exactly_pinned_and_ordered():
    assert HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS == (
        "acceptance means only that a valid deterministic tag for the pinned "
        "pairing authority was presented and that the exact complete archive is "
        "now loadable",
        "actor_id is an asserted identifier and is not authenticated by this "
        "coordinator",
        "the tag is a symmetric shared-secret message authentication code and is "
        "not a digital signature",
        "the construction is deterministic and carries no nonce, so acceptance "
        "does not prove fresh secret possession by the current operator",
        "this coordinator gates only the archive publications routed through it "
        "and enforces nothing about the rest of the process",
        "the accepted lower-level historical evaluation store remains callable "
        "directly by trusted internal code without any confirmation",
        "the three-document archive holds no confirmation receipt, record, "
        "timestamp, tag, tag hash, or other secret-derived material",
        "an existing archive therefore never proves that a tag was presented, and "
        "no read model may infer confirmation from archive existence alone",
        "this result does not state whether the archive was published now or "
        "already held the same exact bytes",
        "the configured secret stays reachable in coordinator memory for the "
        "coordinator lifetime and is not zeroized",
        "this coordinator says nothing about execution, evidence, source "
        "resolution, eligibility, obligation satisfaction, claim support, result "
        "admission, or ProductVerdict",
    )
    assert isinstance(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS, tuple)
    assert len(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS) == 11
    assert len(set(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS)) == 11


def test_the_result_claims_nothing_beyond_the_single_success_meaning():
    assert CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE == (
        "CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE"
    )
    outcomes = {
        value
        for name, value in vars(workflow).items()
        if isinstance(value, str)
        and not name.startswith("_")
        and value.isupper()
        and value.replace("_", "").isalnum()
    }
    assert outcomes == {CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE}
    joined = " ".join(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS).lower()
    for refused in (
        "is not authenticated by this coordinator",
        "is not a digital signature",
        "does not prove fresh secret possession by the current operator",
        "no read model may infer confirmation from archive existence alone",
        "does not state whether the archive was published now or already held "
        "the same exact bytes",
    ):
        assert refused in joined, refused


def test_the_view_and_the_result_carry_the_pinned_limitations(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    result = _confirm(coordinator, view, expected_tag)
    assert view.limitations == HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS
    assert result.limitations == HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS
    # The asserted actor is never renamed into an authenticated one.
    assert view.asserted_actor_id == ACTOR_ID
    assert result.asserted_actor_id == ACTOR_ID
    for holder in (view, result):
        for forbidden in (
            "authenticated_actor_id",
            "authenticated",
            "signature",
            "verified_actor",
            "created",
            "replayed",
            "archive_created",
        ):
            assert not hasattr(holder, forbidden), forbidden


def test_module_documentation_pins_the_direct_store_bypass_limitation():
    documentation = inspect.getdoc(workflow) or ""
    lowered = " ".join(documentation.split()).lower()
    for statement in (
        "confirmation-gated",
        "direct calls to the lower-level step 5c1 store remain possible",
        "no receipt",
        "never proves that a tag was presented",
        "no read model may infer confirmation from archive existence alone",
        "does not universally enforce confirmation across a python process",
        "no memory zeroization is performed and none is claimed",
    ):
        assert statement in lowered, statement
    method_documentation = " ".join(
        (
            inspect.getdoc(
                HistoricalEvaluationPairingCoordinator
                .confirm_historical_evaluation_pairing
            )
            or ""
        ).split()
    ).lower()
    assert "accepts a tag and never a secret" in method_documentation
    assert "never computes the presented tag" in method_documentation
    assert "never returns an expected tag" in method_documentation


def test_a_direct_store_call_still_produces_a_loadable_unconfirmed_archive(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    other_authority: HistoricalEvaluationPairingAuthority,
):
    """The bypass is real and is documented rather than hidden.

    The accepted Step 5C1 store is deliberately left unchanged: no credential
    parameter is added and nothing is renamed.  A trusted direct caller
    therefore still publishes a complete archive without ever presenting a tag,
    and the resulting archive is byte-identical in shape to a confirmed one.
    """

    archive_root = tmp_path / "archive"
    assert inspect.signature(persist_historical_evaluation_pairing).parameters.keys() == {
        "archive_root",
        "evaluation_profile",
        "target_authorization_payload",
        "pairing_authority",
    }
    persist_historical_evaluation_pairing(
        archive_root=archive_root,
        evaluation_profile=expected_profile,
        target_authorization_payload=historical_payload,
        pairing_authority=other_authority,
    )
    bundle = load_historical_evaluation_pairing(
        archive_root=archive_root,
        authority_fingerprint=other_authority.authority_fingerprint,
    )
    assert bundle.pairing_authority == other_authority
    # Exactly three documents, and not one of them records a confirmation.
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, other_authority
    )
    assert set(bundle.pairing_authority.to_dict()) == {
        "schema_version",
        "actor_id",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "authority_fingerprint",
    }


def test_a_confirmed_archive_is_byte_identical_to_an_unconfirmed_one(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
):
    """An archive alone can never prove that a tag was presented."""

    confirmed_root = tmp_path / "confirmed"
    bypassed_root = tmp_path / "bypassed"
    coordinator = _coordinator(confirmed_root)
    _confirm(coordinator, _prepare(coordinator, historical_payload), expected_tag)
    persist_historical_evaluation_pairing(
        archive_root=bypassed_root,
        evaluation_profile=expected_profile,
        target_authorization_payload=historical_payload,
        pairing_authority=expected_authority,
    )
    names = _archive_documents(confirmed_root)
    assert names == _archive_documents(bypassed_root)
    for name in names:
        assert (confirmed_root / name).read_bytes() == (
            bypassed_root / name
        ).read_bytes()


def test_historical_primitives_and_canonical_bytes_are_unchanged(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    """The coordinator composes the accepted primitives without touching them."""

    independent = derive_historical_v5_evaluation_profile(
        target_authorization_payload=historical_payload,
        **_owner_material(historical_payload),
    )
    assert canonical_bytes(independent.to_dict()) == canonical_bytes(
        expected_profile.to_dict()
    )
    assert independent.profile_fingerprint == expected_profile.profile_fingerprint
    assert independent.is_launchable_runtime_profile is False
    assert independent.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    replay = create_historical_evaluation_pairing_authority(
        actor_id=ACTOR_ID,
        evaluation_profile=independent,
        target_authorization_payload=historical_payload,
    )
    assert replay == expected_authority
    assert deepcopy(expected_authority.to_dict()) == expected_authority.to_dict()


def test_coordinator_defaults_are_bounded_and_positive():
    assert DEFAULT_PREPARATION_TTL_SECONDS == 900
    assert 0 < DEFAULT_PREPARATION_TTL_SECONDS <= MAX_PREPARATION_TTL_SECONDS
    assert DEFAULT_MAX_PREPARATIONS == 64
    assert 0 < DEFAULT_MAX_PREPARATIONS <= MAX_PREPARATION_CAPACITY
    assert MAX_PREPARATION_ID_ATTEMPTS == 8
    defaults = inspect.signature(
        HistoricalEvaluationPairingCoordinator.__init__
    ).parameters
    assert defaults["preparation_ttl_seconds"].default == (
        DEFAULT_PREPARATION_TTL_SECONDS
    )
    assert defaults["max_preparations"].default == DEFAULT_MAX_PREPARATIONS
    assert defaults["configured_secret"].default is inspect.Parameter.empty
    assert defaults["archive_root"].default is inspect.Parameter.empty


def test_no_internal_preparation_pretends_to_be_a_canonical_document(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    pinned = coordinator._preparations[view.preparation_id]
    assert not hasattr(pinned, "to_dict")
    assert not hasattr(pinned, "validated")
    assert [field.name for field in fields(pinned)] == [
        "preparation_id",
        "evaluation_profile",
        "target_authorization_payload",
        "pairing_authority",
        "confirmation_message",
        "archive_root",
        "created_at",
        "confirmation_reserved",
        "consumed",
    ]
    assert pinned.archive_root == tmp_path / "archive"
    assert pinned.confirmation_reserved is False
    assert pinned.consumed is False
    assert pinned.target_authorization_payload is historical_payload
    for name in vars(pinned):
        assert "secret" not in name
        assert "tag" not in name
