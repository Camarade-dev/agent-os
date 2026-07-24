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
from dataclasses import FrozenInstanceError, fields, replace
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


# ===========================================================================
# K. Callback and registry-lock discipline.
#
# Every callback reachable from the public constructor may block, raise,
# inspect external state, acquire another lock, or re-enter this coordinator.
# None of them may therefore run while the registry lock is held.  Each probe
# below decides that dynamically with a non-blocking acquisition rather than by
# reading the source, so a future implementation that reintroduces the defect
# fails here even if it is spelled differently.
# ===========================================================================


class _RegistryLockProbe:
    """Record, per labelled call, whether the registry lock was already held."""

    def __init__(self) -> None:
        self.coordinator = None
        self.observations: list[tuple[str, bool]] = []

    def observe(self, label: str) -> None:
        lock = self.coordinator._lock
        acquired = lock.acquire(blocking=False)
        if acquired:
            lock.release()
        self.observations.append((label, acquired))

    @property
    def labels(self) -> list[str]:
        return [label for label, _free in self.observations]

    @property
    def under_lock(self) -> list[str]:
        return [label for label, free in self.observations if not free]


class _ProbingClock:
    """A configured clock that reports whether it ran under the registry lock."""

    def __init__(self, probe: _RegistryLockProbe, start: float = 10_000.0) -> None:
        self._probe = probe
        self.value = float(start)

    def __call__(self) -> float:
        self._probe.observe("clock")
        return self.value

    def advance(self, delta: float) -> None:
        self.value += float(delta)


def test_the_configured_clock_is_never_called_while_the_registry_lock_is_held(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    probe = _RegistryLockProbe()
    clock = _ProbingClock(probe)
    coordinator = _coordinator(tmp_path / "archive", clock=clock)
    probe.coordinator = coordinator

    view = _prepare(coordinator, historical_payload)
    with pytest.raises(PairingConfirmationRejected):
        _confirm(coordinator, view, WRONG_TAG)
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )

    # The clock really was exercised on every path that consults it.
    assert probe.labels == ["clock", "clock", "clock"]
    assert probe.under_lock == []


def test_the_preparation_identifier_factory_runs_outside_the_registry_lock(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    """An injected factory may take the registry lock while it is being called.

    The callback below does exactly what a hostile or merely careless injected
    factory may do: it tries to acquire the coordinator's own registry lock
    without blocking.  That acquisition must succeed, which is only possible if
    the coordinator invoked the factory with the lock released.
    """

    archive_root = tmp_path / "archive"
    holder: dict = {}
    acquisitions: list[bool] = []
    identifiers = _sequential_identifiers()

    def probing_factory() -> str:
        lock = holder["coordinator"]._lock
        acquired = lock.acquire(blocking=False)
        acquisitions.append(acquired)
        if acquired:
            lock.release()
        return identifiers()

    coordinator = _coordinator(archive_root, preparation_id_factory=probing_factory)
    holder["coordinator"] = coordinator
    view = _prepare(coordinator, historical_payload)

    assert acquisitions == [True]
    assert view.preparation_id == "prep-000001"
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    # A second preparation repeats the same discipline, including after the
    # registry already holds an entry.
    second = _prepare(coordinator, historical_payload)
    assert acquisitions == [True, True]
    assert second.preparation_id == "prep-000002"


def test_a_colliding_identifier_factory_still_runs_outside_the_registry_lock(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Every bounded retry re-enters the factory with the lock released."""

    holder: dict = {}
    acquisitions: list[bool] = []

    def colliding_factory() -> str:
        lock = holder["coordinator"]._lock
        acquired = lock.acquire(blocking=False)
        acquisitions.append(acquired)
        if acquired:
            lock.release()
        return "prep-collision"

    coordinator = _coordinator(
        tmp_path / "archive", preparation_id_factory=colliding_factory
    )
    holder["coordinator"] = coordinator
    first = _prepare(coordinator, historical_payload)
    assert first.preparation_id == "prep-collision"
    with pytest.raises(PairingPreparationIdentifierUnavailable):
        _prepare(coordinator, historical_payload)

    assert acquisitions == [True] * (1 + MAX_PREPARATION_ID_ATTEMPTS)
    # The refused preparation left exactly one live entry behind.
    assert list(coordinator._preparations) == ["prep-collision"]


def test_a_raising_identifier_factory_leaves_the_registry_unchanged(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    """A callback that raises must not corrupt or half-populate the registry."""

    failures = itertools.count()
    identifiers = _sequential_identifiers()

    def hostile_factory() -> str:
        index = next(failures)
        if index == 0:
            raise RuntimeError("injected identifier factory failure")
        if index == 1:
            return 17  # an invalid type
        if index == 2:
            return "no"  # malformed syntax
        return identifiers()

    coordinator = _coordinator(
        tmp_path / "archive", preparation_id_factory=hostile_factory
    )
    with pytest.raises(RuntimeError) as caught:
        _prepare(coordinator, historical_payload)
    assert not isinstance(caught.value, HistoricalPairingWorkflowError)
    assert coordinator._preparations == {}
    for _invalid in range(2):
        with pytest.raises(InvalidPairingCoordinatorConfiguration):
            _prepare(coordinator, historical_payload)
        assert coordinator._preparations == {}
    # The lock was released on every failure path, so the coordinator is live.
    view = _prepare(coordinator, historical_payload)
    assert list(coordinator._preparations) == [view.preparation_id]
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_canonical_preparation_callbacks_run_outside_the_registry_lock(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    probe = _RegistryLockProbe()
    for name, label in (
        ("derive_historical_v5_evaluation_profile", "derive"),
        ("create_historical_evaluation_pairing_authority", "authority"),
        ("validate_historical_evaluation_pairing_relation", "relation"),
        ("build_historical_pairing_confirmation_message", "message"),
    ):
        original = getattr(workflow, name)

        def probing(*args, _original=original, _label=label, **kwargs):
            probe.observe(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(workflow, name, probing)

    coordinator = _coordinator(tmp_path / "archive")
    probe.coordinator = coordinator
    view = _prepare(coordinator, historical_payload)

    assert probe.labels == ["derive", "authority", "relation", "message"]
    assert probe.under_lock == []
    assert view.preparation_id == "prep-000001"


def test_verification_persistence_and_reload_run_outside_the_registry_lock(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
):
    probe = _RegistryLockProbe()
    for name, label in (
        ("verify_historical_pairing_confirmation_tag", "verify"),
        ("persist_historical_evaluation_pairing", "persist"),
        ("load_historical_evaluation_pairing", "load"),
    ):
        original = getattr(workflow, name)

        def probing(*args, _original=original, _label=label, **kwargs):
            probe.observe(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(workflow, name, probing)

    coordinator = _coordinator(tmp_path / "archive")
    probe.coordinator = coordinator
    view = _prepare(coordinator, historical_payload)
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )

    assert probe.labels == ["verify", "persist", "load"]
    assert probe.under_lock == []


def test_an_injected_identifier_factory_may_reenter_without_deadlocking(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    """A bounded re-entry probe: one nested preparation from inside the callback.

    The nesting depth is bounded to exactly one, so the probe terminates by
    construction rather than by timing.  The worker thread carries the outer
    preparation only so that a coordinator which invoked the callback under its
    own non-reentrant lock fails this test instead of hanging the session.
    """

    holder: dict = {}
    nested: list = []
    identifiers = _sequential_identifiers()
    depth = itertools.count()

    def reentrant_factory() -> str:
        if next(depth) == 0:
            nested.append(_prepare(holder["coordinator"], historical_payload))
        return identifiers()

    coordinator = _coordinator(
        tmp_path / "archive", preparation_id_factory=reentrant_factory
    )
    holder["coordinator"] = coordinator

    outer: list = []
    worker = threading.Thread(
        target=lambda: outer.append(_prepare(coordinator, historical_payload)),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive(), (
        "an injected preparation identifier factory deadlocked the coordinator"
    )

    assert len(nested) == 1 and len(outer) == 1
    assert nested[0].preparation_id == "prep-000001"
    assert outer[0].preparation_id == "prep-000002"
    assert set(coordinator._preparations) == {"prep-000001", "prep-000002"}
    # Both re-entered preparations are complete and independently confirmable.
    for view in (nested[0], outer[0]):
        assert coordinator._preparations[view.preparation_id].consumed is False
    assert _confirm(coordinator, nested[0], expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    assert _confirm(coordinator, outer[0], expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


class _LockObservingRegistry(dict):
    """A registry that records whether each membership probe held the lock.

    ``__contains__`` is reached only by the identifier-uniqueness decision, so a
    probe that finds the lock free was taken outside it.  A non-blocking
    acquisition decides that without any timing assumption.
    """

    def __init__(self, lock: threading.Lock) -> None:
        super().__init__()
        self._lock = lock
        self.probes: list[bool] = []

    def __contains__(self, key) -> bool:
        acquired = self._lock.acquire(blocking=False)
        if acquired:
            self._lock.release()
        self.probes.append(acquired)
        return super().__contains__(key)


def test_the_identifier_uniqueness_decision_is_made_under_the_registry_lock(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    """Candidate generation left the lock; the uniqueness decision did not.

    A membership probe taken before the lock is acquired would let two
    simultaneous preparations both conclude that the same candidate is free.
    """

    coordinator = _coordinator(tmp_path / "archive", max_preparations=4)
    registry = _LockObservingRegistry(coordinator._lock)
    coordinator._preparations = registry

    first = _prepare(coordinator, historical_payload)
    second = _prepare(coordinator, historical_payload)
    assert first.preparation_id != second.preparation_id
    coordinator._preparation_id_factory = lambda: first.preparation_id
    with pytest.raises(PairingPreparationIdentifierUnavailable):
        _prepare(coordinator, historical_payload)

    # One probe for each accepted candidate plus one for each bounded collision.
    assert len(registry.probes) == 2 + MAX_PREPARATION_ID_ATTEMPTS
    assert registry.probes == [False] * len(registry.probes), registry.probes
    assert _confirm(coordinator, first, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )


def test_two_simultaneous_preparations_never_share_one_identifier(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Candidate generation moved out of the lock; uniqueness did not.

    Both threads are handed exactly the same candidate sequence, so only an
    atomic in-lock uniqueness decision can keep them apart.
    """

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for index in range(8):
            coordinator = _coordinator(
                tmp_path / f"archive-{index}", max_preparations=8
            )
            calls = itertools.count()
            sequence_lock = threading.Lock()

            def shared_factory() -> str:
                # Both threads are handed the very same first candidate; only
                # the loser of the atomic in-lock decision ever sees another.
                with sequence_lock:
                    position = next(calls)
                if position < 2:
                    return "prep-shared-0000"
                return f"prep-shared-{position:04d}"

            coordinator._preparation_id_factory = shared_factory
            barrier = threading.Barrier(2)

            def attempt():
                barrier.wait(timeout=60)
                return _prepare(coordinator, historical_payload).preparation_id

            with ThreadPoolExecutor(max_workers=2) as pool:
                identifiers = [
                    future.result(timeout=60)
                    for future in [pool.submit(attempt), pool.submit(attempt)]
                ]
            assert len(set(identifiers)) == 2, identifiers
            assert "prep-shared-0000" in identifiers, identifiers
            assert set(coordinator._preparations) == set(identifiers)
            assert len(coordinator._preparations) == 2
    finally:
        sys.setswitchinterval(previous_interval)


# ===========================================================================
# L. Public identities are never credentials.
#
# The public preparation view deliberately exposes several lowercase SHA-256
# identities.  Each is syntactically indistinguishable from a confirmation tag
# and none is a credential, so every one of them must be refused exactly like
# any other wrong tag.
# ===========================================================================


def _public_identity_candidate_tags(
    view: HistoricalEvaluationPairingPreparationView,
    expected_authority: HistoricalEvaluationPairingAuthority,
    other_authority: HistoricalEvaluationPairingAuthority,
) -> tuple[tuple[str, str], ...]:
    """Syntactically valid, semantically worthless confirmation-tag candidates."""

    authority_bytes = canonical_bytes(expected_authority.to_dict())
    return (
        ("authority-fingerprint", view.authority_fingerprint),
        ("evaluation-profile-fingerprint", view.evaluation_profile_fingerprint),
        (
            "target-payload-fingerprint",
            view.target_authorization_payload_fingerprint,
        ),
        (
            "preparation-id-digest",
            hashlib.sha256(view.preparation_id.encode("utf-8")).hexdigest(),
        ),
        (
            "confirmation-message-digest",
            hashlib.sha256(view.confirmation_message).hexdigest(),
        ),
        (
            "runtime-owner-authorization-digest",
            hashlib.sha256(WORKFLOW_SECRET + b"\0" + authority_bytes).hexdigest(),
        ),
        ("all-zero", "0" * 64),
        ("all-f", "f" * 64),
        (
            "other-authority-valid-tag",
            _independent_tag(WORKFLOW_SECRET, other_authority.to_dict()),
        ),
        (
            "other-secret-valid-tag",
            _independent_tag(OTHER_SECRET, expected_authority.to_dict()),
        ),
    )


def test_no_public_identity_is_accepted_as_a_confirmation_tag(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    other_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    forbidden_fragments: frozenset[str],
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    pinned = coordinator._preparations[view.preparation_id]
    candidates = _public_identity_candidate_tags(
        view, expected_authority, other_authority
    )
    assert len(candidates) == 10
    assert len({candidate for _label, candidate in candidates}) == 10

    for label, candidate in candidates:
        # Every candidate really is syntactically a well-formed tag, so nothing
        # below can be refused merely as malformed input.
        assert re.fullmatch(r"[0-9a-f]{64}", candidate), label
        assert candidate != expected_tag, label

        accepted = None
        try:
            accepted = _confirm(coordinator, view, candidate)
        except PairingConfirmationRejected as exc:
            rejection = exc
        else:
            rejection = None

        # The load-bearing failure: an archive published without a valid tag.
        assert _archive_documents(archive_root) == [], (
            f"{label} caused an archive to be published without a valid tag"
        )
        assert not archive_root.exists(), label
        assert accepted is None, f"{label} was accepted as a confirmation tag"
        # One generic refusal for every wrong-but-well-formed candidate.
        assert type(rejection) is PairingConfirmationRejected, label
        assert str(rejection) == CONFIRMATION_REJECTED_MESSAGE, label
        # No expected tag is read back, returned, or hinted at.
        for rendered in (str(rejection), repr(rejection)):
            assert expected_tag not in rendered, label
            assert candidate not in rendered, label
            assert _disclosures_in_text(rendered, forbidden_fragments) == [], label
        # The preparation stays retryable and the reservation was released.
        assert pinned.confirmation_reserved is False, label
        assert pinned.consumed is False, label
        assert coordinator._preparations[view.preparation_id] is pinned, label

    # An independently computed Step 5C2A tag still confirms the same pairing.
    result = _confirm(coordinator, view, expected_tag)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )


def test_public_identities_reach_the_accepted_verifier_as_ordinary_tags(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
    other_authority: HistoricalEvaluationPairingAuthority,
    monkeypatch: pytest.MonkeyPatch,
):
    """No candidate is short-circuited into acceptance before verification."""

    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    presented: list[str] = []
    real = workflow.verify_historical_pairing_confirmation_tag

    def spy(*, configured_secret, pairing_authority, presented_tag):
        presented.append(presented_tag)
        return real(
            configured_secret=configured_secret,
            pairing_authority=pairing_authority,
            presented_tag=presented_tag,
        )

    monkeypatch.setattr(workflow, "verify_historical_pairing_confirmation_tag", spy)
    candidates = _public_identity_candidate_tags(
        view, expected_authority, other_authority
    )
    for _label, candidate in candidates:
        with pytest.raises(PairingConfirmationRejected):
            _confirm(coordinator, view, candidate)
    assert presented == [candidate for _label, candidate in candidates]


# ===========================================================================
# M. Confidentiality of the complete exception chain.
#
# A bounded top-level message proves nothing on its own: Python keeps the whole
# ``__cause__``/``__context__`` chain reachable and a trusted caller renders it.
# The dedicated fixture below therefore uses a deliberately short six-character
# fragment threshold, and every chained exception is inspected.
# ===========================================================================


# Fixture material only.  Structureless printable ASCII, so no six-character
# window of it can occur accidentally in ordinary text.
CHAIN_SECRET = b"Wg4Yn7Bq2Kd9Fs5Tj1Vc8Lm3Zx6Ph0Ru4Aw7Eo2"
CHAIN_OTHER_SECRET = b"Nz5Jr9Cw3Hf7Qb1Mk8Sv4Dp0Xt6Ly2Ug9Ia5Te3"
_CHAIN_FRAGMENT_LENGTH = 6
_CHAIN_MAX_DEPTH = 32


def _chain_fragments(secret: bytes, *tags: str) -> frozenset[str]:
    """Meaningful contiguous fragments of one secret and its related tags."""

    text = secret.decode("ascii")
    fragments: set[str] = {text, secret.hex(), repr(secret), *tags}
    for rendered in (text, secret.hex(), *tags):
        for start in range(len(rendered) - _CHAIN_FRAGMENT_LENGTH + 1):
            fragments.add(rendered[start : start + _CHAIN_FRAGMENT_LENGTH])
    return frozenset(fragments)


def _rendered_exception_chain(
    error: BaseException,
    *,
    max_depth: int = _CHAIN_MAX_DEPTH,
) -> list[str]:
    """Every renderable text of one exception and of its complete chain.

    ``__cause__`` and ``__context__`` are both followed, including through a
    ``raise ... from None`` that only suppresses traceback display.  Traversal
    is bounded by ``max_depth`` and by identity, so a self-referential or cyclic
    chain terminates.
    """

    rendered: list[str] = []
    seen: set[int] = set()
    pending: list[tuple[BaseException | None, int]] = [(error, 0)]
    while pending:
        current, depth = pending.pop()
        if current is None or depth > max_depth or id(current) in seen:
            continue
        seen.add(id(current))
        rendered.append(str(current))
        rendered.append(repr(current))
        rendered.extend(repr(argument) for argument in getattr(current, "args", ()))
        rendered.extend(f"{name}={value!r}" for name, value in vars(current).items())
        for attribute in ("filename", "filename2", "strerror", "msg", "reason"):
            value = getattr(current, attribute, None)
            if value is not None:
                rendered.append(repr(value))
        pending.append((current.__cause__, depth + 1))
        pending.append((current.__context__, depth + 1))
    return rendered


def _chain_disclosures(
    error: BaseException,
    fragments: frozenset[str],
) -> list[str]:
    """Every forbidden fragment carried anywhere in one exception chain."""

    found: list[str] = []
    for rendered in _rendered_exception_chain(error):
        found.extend(
            f"{fragment!r} disclosed by {rendered[:120]!r}"
            for fragment in _disclosures_in_text(rendered, fragments)
        )
    return found


@pytest.fixture(scope="module")
def chain_authority(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
) -> HistoricalEvaluationPairingAuthority:
    return create_historical_evaluation_pairing_authority(
        actor_id=ACTOR_ID,
        evaluation_profile=expected_profile,
        target_authorization_payload=historical_payload,
    )


@pytest.fixture(scope="module")
def chain_expected_tag(chain_authority: HistoricalEvaluationPairingAuthority) -> str:
    return _independent_tag(CHAIN_SECRET, chain_authority.to_dict())


@pytest.fixture(scope="module")
def chain_presented_tag(chain_authority: HistoricalEvaluationPairingAuthority) -> str:
    return _independent_tag(CHAIN_OTHER_SECRET, chain_authority.to_dict())


@pytest.fixture(scope="module")
def chain_fragments(
    chain_expected_tag: str,
    chain_presented_tag: str,
) -> frozenset[str]:
    return _chain_fragments(CHAIN_SECRET, chain_expected_tag, chain_presented_tag)


def test_the_exception_chain_scanner_is_armed_and_bounded(
    chain_fragments: frozenset[str],
    chain_expected_tag: str,
):
    assert CHAIN_SECRET.isascii() and CHAIN_SECRET.decode("ascii").isprintable()
    assert MIN_CONFIRMATION_SECRET_BYTES <= len(CHAIN_SECRET)
    assert _CHAIN_FRAGMENT_LENGTH <= 6
    assert min(len(fragment) for fragment in chain_fragments) == (
        _CHAIN_FRAGMENT_LENGTH
    )

    secret_fragment = CHAIN_SECRET.decode("ascii")[7 : 7 + _CHAIN_FRAGMENT_LENGTH]
    tag_fragment = chain_expected_tag[9 : 9 + _CHAIN_FRAGMENT_LENGTH]
    assert {secret_fragment, tag_fragment} <= chain_fragments

    # A leak through __cause__ is caught.
    try:
        raise PairingConfirmationRejected(
            CONFIRMATION_REJECTED_MESSAGE
        ) from ValueError(f"key={secret_fragment}")
    except PairingConfirmationRejected as exc:
        assert _chain_disclosures(exc, chain_fragments) != []

    # A leak through __context__ is caught even when it is suppressed for
    # traceback display by a bare "from None".
    try:
        try:
            raise ValueError(f"expected={tag_fragment}")
        except ValueError:
            raise PairingConfirmationRejected(CONFIRMATION_REJECTED_MESSAGE) from None
    except PairingConfirmationRejected as exc:
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
        assert _chain_disclosures(exc, chain_fragments) != []

    # A leak two links deep, through a mixed cause and context chain, is caught.
    try:
        try:
            raise OSError(f"deep={secret_fragment}")
        except OSError as inner:
            raise ValueError("middle") from inner
    except ValueError as middle:
        outer = PairingArchiveWriteFailed("bounded")
        outer.__cause__ = middle
        assert _chain_disclosures(outer, chain_fragments) != []

    # A structured attribute is caught.
    structured = PairingArchiveWriteFailed("bounded")
    structured.detail = f"secret={secret_fragment}"
    assert _chain_disclosures(structured, chain_fragments) != []

    # A cyclic chain terminates instead of exhausting the interpreter.
    first = RuntimeError("first")
    second = RuntimeError("second")
    first.__cause__ = second
    second.__cause__ = first
    assert len(_rendered_exception_chain(first)) < 100
    assert _chain_disclosures(first, chain_fragments) == []

    # The depth limit really is a bound.
    deepest = RuntimeError(f"deepest={secret_fragment}")
    current: BaseException = deepest
    for _link in range(_CHAIN_MAX_DEPTH + 5):
        wrapper = RuntimeError("link")
        wrapper.__cause__ = current
        current = wrapper
    assert _chain_disclosures(current, chain_fragments) == []
    assert _chain_disclosures(deepest, chain_fragments) != []


def test_no_exception_chain_carries_secret_or_tag_derived_material(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    chain_authority: HistoricalEvaluationPairingAuthority,
    chain_expected_tag: str,
    chain_presented_tag: str,
    chain_fragments: frozenset[str],
    monkeypatch: pytest.MonkeyPatch,
):
    archive_root = tmp_path / "chain-archive"
    coordinator = _coordinator(
        archive_root, configured_secret=CHAIN_SECRET, max_preparations=2
    )
    view = _prepare(coordinator, historical_payload)
    assert view.authority_fingerprint == chain_authority.authority_fingerprint

    collected: list[tuple[str, BaseException]] = []

    def capture(label: str, callable_) -> None:
        try:
            callable_()
        except HistoricalPairingWorkflowError as exc:
            collected.append((label, exc))
            return
        raise AssertionError(f"{label}: a bounded coordinator error was expected")

    capture(
        "invalid-configuration",
        lambda: _coordinator(archive_root, configured_secret=b"short"),
    )
    capture(
        "invalid-preparation",
        lambda: _prepare(coordinator, historical_payload, result_claims=[]),
    )
    capture("wrong-tag", lambda: _confirm(coordinator, view, chain_presented_tag))
    capture("malformed-tag", lambda: _confirm(coordinator, view, "Z" * 64))
    capture(
        "stale-fingerprint",
        lambda: _confirm(
            coordinator,
            view,
            chain_expected_tag,
            expected_authority_fingerprint="a" * 64,
        ),
    )
    capture(
        "unknown-preparation",
        lambda: _confirm(
            coordinator, view, chain_expected_tag, preparation_id="absent-000001"
        ),
    )
    capture(
        "malformed-preparation-identifier",
        lambda: _confirm(coordinator, view, chain_expected_tag, preparation_id="x"),
    )

    with monkeypatch.context() as patched:
        patched.setattr(
            workflow,
            "verify_historical_pairing_confirmation_tag",
            mock.Mock(side_effect=ValueError("simulated verifier refusal")),
        )
        capture("verifier-raised", lambda: _confirm(coordinator, view, chain_expected_tag))

    # A real internal cause: its message names the archive path, which is the
    # one kind of detail the trusted chain is allowed to carry.
    with monkeypatch.context() as patched:
        patched.setattr(
            workflow,
            "persist_historical_evaluation_pairing",
            mock.Mock(side_effect=OSError(f"simulated write failure at {archive_root}")),
        )
        capture(
            "persistence-failed",
            lambda: _confirm(coordinator, view, chain_expected_tag),
        )
    with monkeypatch.context() as patched:
        patched.setattr(
            workflow,
            "load_historical_evaluation_pairing",
            mock.Mock(side_effect=OSError(f"simulated reload failure at {archive_root}")),
        )
        capture("reload-failed", lambda: _confirm(coordinator, view, chain_expected_tag))
    with monkeypatch.context() as patched:
        foreign = HistoricalEvaluationPairingBundle(
            evaluation_profile=expected_profile,
            target_authorization_payload=historical_payload,
            pairing_authority=replace(chain_authority, actor_id=OTHER_ACTOR_ID),
        )
        patched.setattr(
            workflow, "load_historical_evaluation_pairing", lambda **kwargs: foreign
        )
        capture("content-mismatch", lambda: _confirm(coordinator, view, chain_expected_tag))

    conflicting = (
        archive_root
        / AUTHORITY_DIRECTORY_NAME
        / f"{chain_authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}"
    )
    conflicting.parent.mkdir(parents=True, exist_ok=True)
    conflicting.write_bytes(b'{"conflicting":"bytes"}')
    capture("archive-conflict", lambda: _confirm(coordinator, view, chain_expected_tag))
    conflicting.unlink()

    _prepare(coordinator, historical_payload)
    capture("capacity", lambda: _prepare(coordinator, historical_payload))

    # Capacity is checked before uniqueness, so an exhausted identifier needs a
    # coordinator that still has room.
    roomy = _coordinator(
        archive_root, configured_secret=CHAIN_SECRET, max_preparations=4
    )
    taken = _prepare(roomy, historical_payload).preparation_id
    roomy._preparation_id_factory = lambda: taken
    capture("identifier-unavailable", lambda: _prepare(roomy, historical_payload))

    assert len(collected) == 14
    # Every distinct bounded failure class really was exercised, so the scan
    # below covers the complete refusal surface rather than one repeated path.
    assert {label: type(error) for label, error in collected} == {
        "invalid-configuration": InvalidPairingCoordinatorConfiguration,
        "invalid-preparation": InvalidPairingPreparationRequest,
        "wrong-tag": PairingConfirmationRejected,
        "malformed-tag": MalformedPairingConfirmationTag,
        "stale-fingerprint": StalePairingAuthorityFingerprint,
        "unknown-preparation": PairingPreparationNotFound,
        "malformed-preparation-identifier": InvalidPairingPreparationRequest,
        "verifier-raised": PairingConfirmationRejected,
        "persistence-failed": PairingArchiveWriteFailed,
        "reload-failed": PairingArchiveReloadFailed,
        "content-mismatch": PairingArchiveContentMismatch,
        "archive-conflict": PairingArchiveConflict,
        "capacity": PairingPreparationCapacityExhausted,
        "identifier-unavailable": PairingPreparationIdentifierUnavailable,
    }
    for label, error in collected:
        assert _chain_disclosures(error, chain_fragments) == [], label
        for rendered in _rendered_exception_chain(error):
            assert chain_expected_tag not in rendered, label
            assert chain_presented_tag not in rendered, label
            assert CHAIN_SECRET.decode("ascii") not in rendered, label
            assert CHAIN_SECRET.hex() not in rendered, label

    # The scan really did reach chained causes: the tolerated archive path is
    # present inside one internal cause and absent from every bounded message.
    by_label = dict(collected)
    persistence_chain = "\n".join(
        _rendered_exception_chain(by_label["persistence-failed"])
    )
    assert str(archive_root) in persistence_chain
    assert by_label["persistence-failed"].__cause__ is not None
    for _label, error in collected:
        assert str(archive_root) not in str(error)


# ===========================================================================
# N. A reserved preparation is never reclaimed.
#
# Expiry and capacity cleanup both run while another thread may be inside
# verification or persistence holding exactly one pinned preparation.  Evicting
# that record would let a second confirmation republish under a reused
# identifier, so a reservation is an absolute cleanup barrier.
# ===========================================================================


class _BlockedConfirmation:
    """Hold one confirmation inside a chosen accepted call until released.

    The confirmation runs on a worker thread and parks inside the patched call,
    so the preparation stays reserved for the whole ``with`` body while the main
    thread exercises cleanup.
    """

    def __init__(self, coordinator, view, tag: str, *, name: str) -> None:
        self._coordinator = coordinator
        self._view = view
        self._tag = tag
        self._name = name
        self.entered = threading.Event()
        self._proceed = threading.Event()
        self._patch = None
        self._pool = None
        self._pending = None

    def __enter__(self) -> "_BlockedConfirmation":
        original = getattr(workflow, self._name)
        proceed = self._proceed
        entered = self.entered

        def blocking(*args, **kwargs):
            entered.set()
            assert proceed.wait(timeout=60)
            return original(*args, **kwargs)

        self._patch = mock.patch.object(workflow, self._name, blocking)
        self._patch.start()
        self._pool = ThreadPoolExecutor(max_workers=1)
        self._pending = self._pool.submit(
            _confirm, self._coordinator, self._view, self._tag
        )
        assert self.entered.wait(timeout=60)
        return self

    def release(self):
        self._proceed.set()
        return self._pending.result(timeout=60)

    def __exit__(self, *exception) -> bool:
        self._proceed.set()
        try:
            self._pending.exception(timeout=60)
        finally:
            self._pool.shutdown(wait=True)
            self._patch.stop()
        return False


_RESERVATION_STAGES = (
    ("verification", "verify_historical_pairing_confirmation_tag"),
    ("persistence", "persist_historical_evaluation_pairing"),
)


@pytest.mark.parametrize(
    "blocked_call",
    [name for _label, name in _RESERVATION_STAGES],
    ids=[label for label, _name in _RESERVATION_STAGES],
)
def test_cleanup_never_reclaims_a_reserved_preparation(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    blocked_call: str,
):
    archive_root = tmp_path / "archive"
    clock = _FakeClock()
    coordinator = _coordinator(
        archive_root,
        max_preparations=1,
        preparation_ttl_seconds=30,
        clock=clock,
    )
    view = _prepare(coordinator, historical_payload)
    pinned = coordinator._preparations[view.preparation_id]

    with _BlockedConfirmation(
        coordinator, view, expected_tag, name=blocked_call
    ) as blocked:
        assert pinned.confirmation_reserved is True
        assert pinned.consumed is False

        # Reserved and otherwise active: cleanup keeps it and capacity refuses.
        with pytest.raises(PairingPreparationCapacityExhausted):
            _prepare(coordinator, historical_payload)
        assert coordinator._preparations[view.preparation_id] is pinned

        # A concurrent locator resolution cannot reclaim it either.
        with pytest.raises(PairingPreparationInUse):
            _confirm(coordinator, view, expected_tag)
        assert coordinator._preparations[view.preparation_id] is pinned

        # Reserved after crossing the TTL: still not reclaimed, still refusing.
        clock.advance(31)
        assert clock.value - pinned.created_at >= 30
        for _round in range(3):
            with pytest.raises(PairingPreparationCapacityExhausted):
                _prepare(coordinator, historical_payload)
        assert coordinator._preparations[view.preparation_id] is pinned

        # An expired but reserved record is refused as expired and, unlike an
        # unreserved one, is deliberately not dropped by that refusal.
        with pytest.raises(PairingPreparationExpired):
            _confirm(coordinator, view, expected_tag)
        assert coordinator._preparations[view.preparation_id] is pinned

        # The active confirmation still holds exactly its pinned objects.
        assert pinned.evaluation_profile is not None
        assert pinned.target_authorization_payload is historical_payload
        assert pinned.pairing_authority == expected_authority
        assert pinned.confirmation_reserved is True

        result = blocked.release()

    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert result.asserted_actor_id == ACTOR_ID
    assert result.authority_fingerprint == expected_authority.authority_fingerprint
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    # Released and consumed, the record becomes ordinarily reclaimable again.
    assert pinned.confirmation_reserved is False
    assert pinned.consumed is True
    replacement = _prepare(coordinator, historical_payload)
    assert replacement.preparation_id != view.preparation_id


def test_a_reserved_identifier_is_never_reissued(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_tag: str,
):
    """The reserved locator stays taken until its record is truly reclaimable."""

    clock = _FakeClock()
    coordinator = _coordinator(
        tmp_path / "archive",
        max_preparations=4,
        preparation_ttl_seconds=30,
        clock=clock,
        preparation_id_factory=lambda: "prep-reserved-0001",
    )
    view = _prepare(coordinator, historical_payload)
    assert view.preparation_id == "prep-reserved-0001"

    with _BlockedConfirmation(
        coordinator,
        view,
        expected_tag,
        name="persist_historical_evaluation_pairing",
    ) as blocked:
        # Reserved: the identifier cannot be handed out again even though the
        # coordinator has capacity left.
        with pytest.raises(PairingPreparationIdentifierUnavailable):
            _prepare(coordinator, historical_payload)
        # Still reserved after the TTL has passed: still not reissued.
        clock.advance(31)
        with pytest.raises(PairingPreparationIdentifierUnavailable):
            _prepare(coordinator, historical_payload)
        assert "prep-reserved-0001" in coordinator._preparations
        blocked.release()

    # Released and now ordinarily reclaimable, the locator frees up.
    reissued = _prepare(coordinator, historical_payload)
    assert reissued.preparation_id == "prep-reserved-0001"
    assert coordinator._preparations["prep-reserved-0001"].consumed is False
    # A consumed but still live record keeps its locator: only reclamation
    # releases it, and capacity is deliberately not exhausted here.
    assert _confirm(coordinator, reissued, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    assert coordinator._preparations["prep-reserved-0001"].consumed is True
    with pytest.raises(PairingPreparationIdentifierUnavailable):
        _prepare(coordinator, historical_payload)


# ===========================================================================
# O. Interleaved preparations stay attributed and persisted separately.
# ===========================================================================


def _other_owner_material(payload: NativeCanaryAuthorizationPayloadV4) -> dict:
    """Owner material whose claim prose differs from the module fixture."""

    material = _owner_material(payload)
    material["result_claims"][0]["statement"] = (
        "The zulu behavior exists in the second recorded material."
    )
    return material


@pytest.fixture(scope="module")
def other_historical_payload(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeCanaryAuthorizationPayloadV4:
    """A second exact historical payload with its own canonical identity."""

    document = historical_payload.to_dict()
    document["source_head"] = "b" * 40
    assert document["source_head"] != historical_payload.source_head
    payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(document)
    )
    assert payload.payload_fingerprint != historical_payload.payload_fingerprint
    return payload


@pytest.fixture(scope="module")
def other_expected_profile(
    other_historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeMissionProfile:
    return derive_historical_v5_evaluation_profile(
        target_authorization_payload=other_historical_payload,
        **_other_owner_material(other_historical_payload),
    )


@pytest.fixture(scope="module")
def other_pairing_authority(
    other_historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_expected_profile: NativeMissionProfile,
) -> HistoricalEvaluationPairingAuthority:
    return create_historical_evaluation_pairing_authority(
        actor_id=OTHER_ACTOR_ID,
        evaluation_profile=other_expected_profile,
        target_authorization_payload=other_historical_payload,
    )


@pytest.fixture(scope="module")
def other_pairing_tag(
    other_pairing_authority: HistoricalEvaluationPairingAuthority,
) -> str:
    return _independent_tag(WORKFLOW_SECRET, other_pairing_authority.to_dict())


def _prepare_other(coordinator, payload: NativeCanaryAuthorizationPayloadV4):
    return coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=payload,
        actor_id=OTHER_ACTOR_ID,
        **_other_owner_material(payload),
    )


def test_the_two_interleaved_fixtures_really_are_distinct(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    other_expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    other_pairing_authority: HistoricalEvaluationPairingAuthority,
):
    assert expected_authority.actor_id != other_pairing_authority.actor_id
    assert historical_payload.payload_fingerprint != (
        other_historical_payload.payload_fingerprint
    )
    assert expected_profile.profile_fingerprint != (
        other_expected_profile.profile_fingerprint
    )
    assert expected_authority.authority_fingerprint != (
        other_pairing_authority.authority_fingerprint
    )
    assert other_expected_profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert other_expected_profile.is_launchable_runtime_profile is False


def test_interleaved_confirmations_keep_their_own_result_attribution(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    other_expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    other_pairing_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    other_pairing_tag: str,
):
    coordinator = _coordinator(tmp_path / "archive")
    first = _prepare(coordinator, historical_payload)
    second = _prepare_other(coordinator, other_historical_payload)
    assert first.preparation_id != second.preparation_id

    # A is confirmed only after B already exists in the registry.
    first_result = _confirm(coordinator, first, expected_tag)
    second_result = _confirm(coordinator, second, other_pairing_tag)

    for result, actor, profile, payload, authority in (
        (
            first_result,
            ACTOR_ID,
            expected_profile,
            historical_payload,
            expected_authority,
        ),
        (
            second_result,
            OTHER_ACTOR_ID,
            other_expected_profile,
            other_historical_payload,
            other_pairing_authority,
        ),
    ):
        assert result.asserted_actor_id == actor
        assert result.authority_fingerprint == authority.authority_fingerprint
        assert result.evaluation_profile_fingerprint == profile.profile_fingerprint
        assert result.target_authorization_payload_fingerprint == (
            payload.payload_fingerprint
        )
        # Every value is also the one carried by this result's own reloaded
        # bundle, so no coordinator-level "latest" value could have supplied it.
        bundle = result.archived_pairing
        assert bundle.pairing_authority.actor_id == actor
        assert bundle.pairing_authority.authority_fingerprint == (
            result.authority_fingerprint
        )
        assert bundle.evaluation_profile.profile_fingerprint == (
            result.evaluation_profile_fingerprint
        )
        assert bundle.target_authorization_payload.payload_fingerprint == (
            result.target_authorization_payload_fingerprint
        )
        assert canonical_bytes(bundle.evaluation_profile.to_dict()) == (
            canonical_bytes(profile.to_dict())
        )
        assert canonical_bytes(bundle.target_authorization_payload.to_dict()) == (
            canonical_bytes(payload.to_dict())
        )
        assert canonical_bytes(bundle.pairing_authority.to_dict()) == (
            canonical_bytes(authority.to_dict())
        )

    assert first_result.preparation_id == first.preparation_id
    assert second_result.preparation_id == second.preparation_id
    assert first_result.asserted_actor_id != second_result.asserted_actor_id


def test_an_earlier_confirmation_persists_exactly_its_own_documents(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    other_expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    other_pairing_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    other_pairing_tag: str,
):
    """Distinct from result attribution: this pins the published bytes."""

    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    first = _prepare(coordinator, historical_payload)
    second = _prepare_other(coordinator, other_historical_payload)

    # Confirming A must publish exactly A's three documents.  Reporting the
    # archive state on failure keeps the diagnosis semantic: a coordinator that
    # published a later preparation's documents cannot then reload its own.
    try:
        _confirm(coordinator, first, expected_tag)
    except HistoricalPairingWorkflowError as exc:
        raise AssertionError(
            "confirming the earlier preparation did not publish its own "
            f"documents: archive={_archive_documents(archive_root)} "
            f"error={type(exc).__name__}"
        ) from None
    first_names = _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    second_names = _expected_document_names(
        other_expected_profile, other_historical_payload, other_pairing_authority
    )
    assert set(first_names).isdisjoint(second_names)
    # Only A's three documents exist while B is still merely prepared.
    assert _archive_documents(archive_root) == first_names

    _confirm(coordinator, second, other_pairing_tag)
    assert _archive_documents(archive_root) == sorted(first_names + second_names)

    for profile, payload, authority in (
        (expected_profile, historical_payload, expected_authority),
        (other_expected_profile, other_historical_payload, other_pairing_authority),
    ):
        bundle = load_historical_evaluation_pairing(
            archive_root=archive_root,
            authority_fingerprint=authority.authority_fingerprint,
        )
        assert canonical_bytes(bundle.evaluation_profile.to_dict()) == (
            canonical_bytes(profile.to_dict())
        )
        assert canonical_bytes(bundle.target_authorization_payload.to_dict()) == (
            canonical_bytes(payload.to_dict())
        )
        assert canonical_bytes(bundle.pairing_authority.to_dict()) == (
            canonical_bytes(authority.to_dict())
        )


# ===========================================================================
# P. All three reloaded documents are compared as exact canonical bytes.
#
# Each case below replaces exactly one referenced object in an otherwise exact
# reloaded bundle.  Every forgery keeps the expected fingerprint field and
# differs only in canonical body bytes, so neither a fingerprint-only
# comparison nor an authority-only comparison can notice it.
# ===========================================================================


def _forged_documents(
    expected_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
) -> dict:
    """One bypass-loaded variant per document, each fingerprint-preserving."""

    return {
        "profile": replace(
            expected_profile,
            mission_text=expected_profile.mission_text + "\nforged historical body",
        ),
        "payload": replace(historical_payload, source_head="c" * 40),
        "authority": replace(expected_authority, actor_id=OTHER_ACTOR_ID),
    }


def test_the_forged_reload_documents_are_fingerprint_preserving(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
):
    forged = _forged_documents(
        expected_profile, historical_payload, expected_authority
    )
    expected = {
        "profile": expected_profile,
        "payload": historical_payload,
        "authority": expected_authority,
    }
    fingerprint_fields = {
        "profile": "profile_fingerprint",
        "payload": "payload_fingerprint",
        "authority": "authority_fingerprint",
    }
    for document, candidate in forged.items():
        original = expected[document]
        assert type(candidate) is type(original), document
        assert getattr(candidate, fingerprint_fields[document]) == getattr(
            original, fingerprint_fields[document]
        ), document
        assert canonical_bytes(candidate.to_dict()) != canonical_bytes(
            original.to_dict()
        ), document
    # The forgeries are deliberately unreachable through the canonical
    # constructors: only a bypass-loaded object can carry a fingerprint field
    # that does not match its own body, which is exactly why the coordinator
    # must compare bytes rather than trust the field.
    with pytest.raises((TypeError, ValueError)):
        NativeMissionProfile.from_dict(forged["profile"].to_dict())
    with pytest.raises((TypeError, ValueError)):
        load_historical_native_canary_authorization_payload_v4(
            forged["payload"].to_dict()
        )
    with pytest.raises((TypeError, ValueError)):
        HistoricalEvaluationPairingAuthority.from_dict(forged["authority"].to_dict())
    # The forged profile is still non-launchable, so a launchability guard can
    # never be what refuses it.
    assert forged["profile"].is_launchable_runtime_profile is False
    assert forged["profile"].schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5


@pytest.mark.parametrize("document", ["profile", "payload", "authority"])
def test_one_differing_reloaded_document_is_refused_by_byte_comparison(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
    document: str,
):
    archive_root = tmp_path / "archive"
    coordinator = _coordinator(archive_root)
    view = _prepare(coordinator, historical_payload)
    forged = _forged_documents(
        expected_profile, historical_payload, expected_authority
    )[document]

    members = {
        "evaluation_profile": expected_profile,
        "target_authorization_payload": historical_payload,
        "pairing_authority": expected_authority,
    }
    members[
        {
            "profile": "evaluation_profile",
            "payload": "target_authorization_payload",
            "authority": "pairing_authority",
        }[document]
    ] = forged
    bundle = HistoricalEvaluationPairingBundle(**members)
    assert isinstance(bundle, HistoricalEvaluationPairingBundle)
    # Exactly one referenced object differs; the other two are the exact
    # expected objects, by identity.
    differing = [
        name
        for name, member in (
            ("evaluation_profile", bundle.evaluation_profile),
            ("target_authorization_payload", bundle.target_authorization_payload),
            ("pairing_authority", bundle.pairing_authority),
        )
        if member is not {
            "evaluation_profile": expected_profile,
            "target_authorization_payload": historical_payload,
            "pairing_authority": expected_authority,
        }[name]
    ]
    assert len(differing) == 1

    monkeypatch.setattr(
        workflow, "load_historical_evaluation_pairing", lambda **kwargs: bundle
    )
    with pytest.raises(PairingArchiveContentMismatch) as caught:
        _confirm(coordinator, view, expected_tag)
    # The byte-comparison layer refused it, not the reload type gate.
    assert type(caught.value) is PairingArchiveContentMismatch
    assert str(caught.value) == (
        "reloaded historical pairing documents are not the exact pinned "
        "canonical bytes"
    )

    # The preparation was not consumed, so the exact retry still succeeds.
    monkeypatch.undo()
    result = _confirm(coordinator, view, expected_tag)
    assert result.outcome == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert _archive_documents(archive_root) == _expected_document_names(
        expected_profile, historical_payload, expected_authority
    )
    assert canonical_bytes(
        result.archived_pairing.pairing_authority.to_dict()
    ) == canonical_bytes(expected_authority.to_dict())


# ===========================================================================
# Q. Staleness compares the complete fingerprint, never a prefix.
# ===========================================================================


def _prefix_sharing_fingerprint(expected: str, shared: int) -> str:
    """A different valid lowercase SHA-256 sharing ``shared`` leading characters."""

    for counter in itertools.count():
        digest = hashlib.sha256(f"stale-{shared}-{counter}".encode("utf-8")).hexdigest()
        candidate = expected[:shared] + digest[shared:]
        if candidate != expected:
            return candidate
    raise AssertionError("unreachable")


@pytest.mark.parametrize("shared", [8, 16, 32, 63])
def test_a_prefix_sharing_authority_fingerprint_is_still_stale(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_authority: HistoricalEvaluationPairingAuthority,
    expected_tag: str,
    monkeypatch: pytest.MonkeyPatch,
    shared: int,
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
    expected_fingerprint = expected_authority.authority_fingerprint
    candidate = _prefix_sharing_fingerprint(expected_fingerprint, shared)

    assert re.fullmatch(r"[0-9a-f]{64}", candidate)
    assert candidate != expected_fingerprint
    assert candidate[:shared] == expected_fingerprint[:shared]
    assert candidate[shared:] != expected_fingerprint[shared:]

    verifications: list[str] = []
    monkeypatch.setattr(
        workflow,
        "verify_historical_pairing_confirmation_tag",
        lambda **kwargs: verifications.append("verify") or True,
    )
    # The presented tag is the genuinely valid one, so only a complete
    # fingerprint comparison can refuse this call.
    with pytest.raises(StalePairingAuthorityFingerprint):
        _confirm(
            coordinator,
            view,
            expected_tag,
            expected_authority_fingerprint=candidate,
        )
    assert verifications == []
    assert coordinator.secret_reads == []
    assert not archive_root.exists()
    assert _archive_documents(archive_root) == []

    # The exact fingerprint still confirms the same preparation.
    monkeypatch.undo()
    assert _confirm(coordinator, view, expected_tag).outcome == (
        CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    )
    assert coordinator.secret_reads == ["read"]


# ===========================================================================
# R. The review projection is a bounded headless identity summary.
#
# Step 5C2C must build a complete owner-review representation from the pinned
# V5, V4 and authority objects.  This section pins what today's projection
# deliberately is not, so that boundary cannot be crossed silently.
# ===========================================================================


_OMITTED_CANONICAL_KEYS = (
    "statement",
    "non_claims",
    "obligation_level",
    "depends_on",
    "strategy",
    "procedure_reference",
    "acceptance_predicate",
    "declared_coverage",
    "oracle_disclosed_to_subject",
    "independence_requirements",
    "negative_controls",
    "reference_cases",
    "source_authority_type",
    "source_authority_reference",
    "mission_text",
    "gate_objective",
    "gate_clauses",
    "completion_conditions_text",
    "runtime_prompt",
    "attestation_non_claims",
    "canary_non_claims",
)


def _projection_rendering(
    projection: HistoricalEvaluationPairingReviewProjection,
) -> str:
    return "\n".join(
        [repr(projection)]
        + [f"{field.name}={getattr(projection, field.name)!r}" for field in fields(projection)]
    )


def test_the_review_projection_is_a_bounded_identity_summary_only(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    expected_profile: NativeMissionProfile,
):
    coordinator = _coordinator(tmp_path / "archive")
    view = _prepare(coordinator, historical_payload)
    projection = view.review_projection
    rendering = _projection_rendering(projection)
    profile_bytes = canonical_bytes(expected_profile.to_dict()).decode("utf-8")
    payload_bytes = canonical_bytes(historical_payload.to_dict()).decode("utf-8")

    # Every omitted concept really exists in the pinned canonical material, so
    # the omission below is a real boundary rather than a vacuous one.
    for key in _OMITTED_CANONICAL_KEYS:
        assert key in profile_bytes or key in payload_bytes, key
        assert key not in rendering, key
        assert not hasattr(projection, key), key
    assert [field.name for field in fields(projection)] == [
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

    # The owner prose itself never appears.
    claims = expected_profile.claim_authority.claims
    obligations = (
        expected_profile.claim_verification_plan_authority.verification_obligations
    )
    bindings = expected_profile.verification_evidence_binding_authority.bindings
    omitted_prose = [
        *(claim.statement for claim in claims),
        *(text for claim in claims for text in claim.non_claims),
        *(obligation.procedure_reference for obligation in obligations),
        *(obligation.strategy.value for obligation in obligations),
        *(obligation.acceptance_predicate.value for obligation in obligations),
        *(obligation.declared_coverage for obligation in obligations),
        *(text for obligation in obligations for text in obligation.non_claims),
        *(
            control.description
            for obligation in obligations
            for control in obligation.negative_controls
        ),
        *(
            control.control_id
            for obligation in obligations
            for control in obligation.negative_controls
        ),
        *(binding.source_authority_reference for binding in bindings),
        *(binding.source_authority_type.value for binding in bindings),
        *historical_payload.attestation_non_claims,
        *historical_payload.canary_non_claims,
        expected_profile.mission_text,
        expected_profile.gate_objective,
    ]
    assert len(omitted_prose) > 20
    for text in omitted_prose:
        assert text, "an omitted-content probe must not be empty"
        assert text not in rendering, text[:60]
    # Independence requirements are a canonical mapping in the pinned profile
    # and are projected neither as a value nor as a field.
    independence = obligations[0].independence_requirements.to_dict()
    assert json.dumps(independence, sort_keys=True) not in rendering
    for name, value in independence.items():
        assert not hasattr(projection, name), name
        assert f"{name}={value!r}" not in rendering, name

    # Only owner-ordered member identities are projected.
    assert projection.result_claim_ids == tuple(claim.claim_id for claim in claims)
    assert projection.verification_obligation_ids == tuple(
        obligation.obligation_id for obligation in obligations
    )
    assert projection.verification_evidence_binding_ids == tuple(
        binding.binding_id for binding in bindings
    )
    # No coordinator limitation notice is smuggled into the projection either.
    for limitation in HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS:
        assert limitation not in rendering


def test_the_review_projection_is_derived_pinned_and_non_canonical(
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
    projection = view.review_projection
    pinned = coordinator._preparations[view.preparation_id]

    # Derived from the pinned canonical objects, value by value.
    assert projection.evaluation_profile_schema_version == (
        pinned.evaluation_profile.schema_version
    )
    assert projection.evaluation_profile_is_launchable == (
        pinned.evaluation_profile.is_launchable_runtime_profile
    )
    assert projection.target_authorization_payload_schema_version == (
        pinned.target_authorization_payload.schema_version
    )
    assert projection.pairing_authority_schema_version == (
        pinned.pairing_authority.schema_version
    )
    for name in ("profile_id", "run_id", "session_id", "gate_id", "mission_id"):
        assert getattr(projection, name) == getattr(pinned.evaluation_profile, name)

    # Non-canonical: no document interface, no fingerprint, no persistence.
    assert not hasattr(projection, "to_dict")
    assert not hasattr(projection, "identity_fingerprint")
    assert not hasattr(projection, "validated")
    assert not any("fingerprint" in field.name for field in fields(projection))
    with pytest.raises((AttributeError, TypeError, ValueError)):
        canonical_bytes(projection)

    published: list[dict] = []
    real_persist = workflow.persist_historical_evaluation_pairing

    def recording_persist(**kwargs):
        published.append(kwargs)
        return real_persist(**kwargs)

    monkeypatch.setattr(
        workflow, "persist_historical_evaluation_pairing", recording_persist
    )
    authority_bytes = canonical_bytes(expected_authority.to_dict())
    result = _confirm(coordinator, view, expected_tag)
    monkeypatch.undo()

    assert len(published) == 1
    assert set(published[0]) == {
        "archive_root",
        "evaluation_profile",
        "target_authorization_payload",
        "pairing_authority",
    }
    assert projection not in published[0].values()
    # Extending or changing the projection cannot move one authority byte.
    extended = replace(projection, profile_id="mutated-review-identity")
    assert extended != projection
    assert canonical_bytes(expected_authority.to_dict()) == authority_bytes
    assert canonical_bytes(
        result.archived_pairing.pairing_authority.to_dict()
    ) == authority_bytes
    assert (
        archive_root
        / AUTHORITY_DIRECTORY_NAME
        / f"{expected_authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}"
    ).read_bytes() == authority_bytes
    assert _independent_tag(WORKFLOW_SECRET, expected_authority.to_dict()) == (
        expected_tag
    )
    # The result carries no projection at all: review presentation is not a
    # confirmation outcome.
    assert not hasattr(result, "review_projection")
