"""Write-once archive for canonical historical evaluation pairing documents.

The archive stores only one exact V5 evaluation profile, one exact historical
V4 authorization payload, and their existing pairing authority.  The authority
document is published last and is the sole commit marker.  This module does not
inspect execution, evidence, product, reconstruction, or provider state.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Mapping

from admissible.delegated_gate.canonical import (
    canonical_bytes,
    fingerprint,
    require_sha256,
)
from admissible.delegated_gate.durability import (
    DurabilityAdapterError,
    PlatformDurabilityAdapter,
    PostPublicationReloadFailure,
    PublicationConflict,
    PublicationMode,
    PublicationVisibleButMetadataUncertain,
)
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
    require_exact_v5_v2_runtime_authority_compatibility,
    validate_historical_evaluation_pairing_relation,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)


PROFILE_DIRECTORY_NAME = "profiles"
PAYLOAD_DIRECTORY_NAME = "payloads"
AUTHORITY_DIRECTORY_NAME = "authorities"
PROFILE_FILE_SUFFIX = ".native-mission-profile-v5.json"
PAYLOAD_FILE_SUFFIX = ".native-canary-authorization-v4.json"
AUTHORITY_FILE_SUFFIX = ".historical-evaluation-pairing-v1.json"
_MAX_DOCUMENT_BYTES = 32 * 1024 * 1024


class HistoricalEvaluationStoreError(RuntimeError):
    """Base class for bounded historical evaluation archive failures."""


class InvalidHistoricalEvaluationArchiveRoot(HistoricalEvaluationStoreError):
    pass


class CommittedHistoricalEvaluationAuthorityNotFound(HistoricalEvaluationStoreError):
    pass


class ReferencedHistoricalEvaluationProfileNotFound(HistoricalEvaluationStoreError):
    pass


class ReferencedHistoricalAuthorizationPayloadNotFound(
    HistoricalEvaluationStoreError
):
    pass


class MalformedHistoricalEvaluationAuthority(HistoricalEvaluationStoreError):
    pass


class MalformedHistoricalEvaluationProfile(HistoricalEvaluationStoreError):
    pass


class MalformedHistoricalAuthorizationPayload(HistoricalEvaluationStoreError):
    pass


class HistoricalEvaluationArchiveFingerprintMismatch(
    HistoricalEvaluationStoreError
):
    pass


class HistoricalEvaluationArchiveRelationMismatch(HistoricalEvaluationStoreError):
    pass


class HistoricalEvaluationArchiveConflict(HistoricalEvaluationStoreError):
    pass


class HistoricalEvaluationArchiveDurabilityError(HistoricalEvaluationStoreError):
    pass


@dataclass(frozen=True)
class HistoricalEvaluationPairingBundle:
    """One fully validated committed pairing, without a fourth document.

    ``pairing_authority.actor_id`` remains only the asserted actor identifier
    contained in the canonical authority.  Loading this bundle does not
    authenticate that actor.
    """

    evaluation_profile: NativeMissionProfile
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4
    pairing_authority: HistoricalEvaluationPairingAuthority


@dataclass(frozen=True)
class _ArchivePaths:
    root: Path
    profiles: Path
    payloads: Path
    authorities: Path

    def profile(self, profile_fingerprint: str) -> Path:
        require_sha256(
            profile_fingerprint, "historical evaluation profile fingerprint"
        )
        return self.profiles / f"{profile_fingerprint}{PROFILE_FILE_SUFFIX}"

    def payload(self, payload_fingerprint: str) -> Path:
        require_sha256(
            payload_fingerprint,
            "historical target authorization payload fingerprint",
        )
        return self.payloads / f"{payload_fingerprint}{PAYLOAD_FILE_SUFFIX}"

    def authority(self, authority_fingerprint: str) -> Path:
        require_sha256(
            authority_fingerprint,
            "historical evaluation pairing authority fingerprint",
        )
        return (
            self.authorities
            / f"{authority_fingerprint}{AUTHORITY_FILE_SUFFIX}"
        )


def _archive_paths(archive_root: Path) -> _ArchivePaths:
    if not isinstance(archive_root, Path):
        raise InvalidHistoricalEvaluationArchiveRoot(
            "historical evaluation archive root must be an explicit Path"
        )
    raw = os.fspath(archive_root)
    if "\x00" in raw or not archive_root.is_absolute():
        raise InvalidHistoricalEvaluationArchiveRoot(
            "historical evaluation archive root must be canonical and absolute"
        )
    canonical = Path(os.path.abspath(raw))
    if canonical != archive_root:
        raise InvalidHistoricalEvaluationArchiveRoot(
            "historical evaluation archive root must be canonical and absolute"
        )
    return _ArchivePaths(
        root=archive_root,
        profiles=archive_root / PROFILE_DIRECTORY_NAME,
        payloads=archive_root / PAYLOAD_DIRECTORY_NAME,
        authorities=archive_root / AUTHORITY_DIRECTORY_NAME,
    )


def _create_archive_directories(paths: _ArchivePaths) -> None:
    try:
        paths.root.mkdir(parents=True, exist_ok=True)
        for directory in (paths.profiles, paths.payloads, paths.authorities):
            directory.mkdir(exist_ok=True)
    except OSError as exc:
        raise InvalidHistoricalEvaluationArchiveRoot(
            "historical evaluation archive directories cannot be created"
        ) from exc


def _require_document_fingerprint(
    mapping: Mapping[str, Any],
    *,
    field: str,
    expected: str,
    label: str,
) -> None:
    try:
        embedded = require_sha256(mapping.get(field), f"{label} fingerprint")
    except ValueError as exc:
        raise HistoricalEvaluationArchiveFingerprintMismatch(
            f"{label} fingerprint is malformed"
        ) from exc
    if embedded != expected:
        raise HistoricalEvaluationArchiveFingerprintMismatch(
            f"{label} fingerprint differs from its canonical identity"
        )
    body = dict(mapping)
    body.pop(field)
    if fingerprint(body) != expected:
        raise HistoricalEvaluationArchiveFingerprintMismatch(
            f"{label} fingerprint does not match its canonical document"
        )


def _validated_documents(
    *,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
    pairing_authority: HistoricalEvaluationPairingAuthority,
) -> tuple[bytes, bytes, bytes]:
    if not isinstance(evaluation_profile, NativeMissionProfile):
        raise ValueError(
            "post-run evaluation profile must be a canonical NativeMissionProfile"
        )
    evaluation_profile.validated()
    if evaluation_profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V5:
        raise ValueError("post-run evaluation profile must use the exact v5 schema")
    if evaluation_profile.is_launchable_runtime_profile:
        raise ValueError("post-run evaluation profile must remain non-launchable")
    if not isinstance(
        target_authorization_payload, NativeCanaryAuthorizationPayloadV4
    ):
        raise ValueError(
            "target execution authorization must be a canonical historical v4 payload"
        )
    target_authorization_payload.validated_historical_structure()
    if not isinstance(pairing_authority, HistoricalEvaluationPairingAuthority):
        raise ValueError(
            "historical evaluation pairing must be a canonical authority"
        )
    pairing_authority.validated()

    # This accepted external relation validator is deliberately load-bearing.
    validate_historical_evaluation_pairing_relation(
        authority=pairing_authority,
        evaluation_profile=evaluation_profile,
        target_authorization_payload=target_authorization_payload,
    )
    # Retain the exact compatibility postcondition as an independent check.
    require_exact_v5_v2_runtime_authority_compatibility(
        evaluation_profile=evaluation_profile,
        target_authorization_payload=target_authorization_payload,
    )

    profile_mapping = evaluation_profile.to_dict()
    payload_mapping = target_authorization_payload.to_dict()
    authority_mapping = pairing_authority.to_dict()
    _require_document_fingerprint(
        profile_mapping,
        field="profile_fingerprint",
        expected=evaluation_profile.profile_fingerprint,
        label="historical evaluation profile",
    )
    _require_document_fingerprint(
        payload_mapping,
        field="payload_fingerprint",
        expected=target_authorization_payload.payload_fingerprint,
        label="historical authorization payload",
    )
    _require_document_fingerprint(
        authority_mapping,
        field="authority_fingerprint",
        expected=pairing_authority.authority_fingerprint,
        label="historical evaluation pairing authority",
    )
    return (
        canonical_bytes(profile_mapping),
        canonical_bytes(payload_mapping),
        canonical_bytes(authority_mapping),
    )


def _read_existing_bytes(path: Path, *, label: str) -> bytes:
    try:
        if not path.is_file():
            raise HistoricalEvaluationArchiveConflict(
                f"existing {label} identity is not a regular file"
            )
        return path.read_bytes()
    except HistoricalEvaluationArchiveConflict:
        raise
    except OSError as exc:
        raise HistoricalEvaluationArchiveConflict(
            f"existing {label} document cannot be verified"
        ) from exc


def _persist_exact_document(
    *,
    path: Path,
    expected: bytes,
    label: str,
    durability_adapter: PlatformDurabilityAdapter,
) -> None:
    if path.exists():
        if _read_existing_bytes(path, label=label) != expected:
            raise HistoricalEvaluationArchiveConflict(
                f"existing {label} bytes conflict with the canonical document"
            )
        return
    try:
        durability_adapter.publish(
            path,
            expected,
            mode=PublicationMode.CREATE_ONLY,
        )
    except PublicationConflict as exc:
        # Another create-only writer won.  Exact bytes are an idempotent replay;
        # every other result is a bounded conflict and is never overwritten.
        if _read_existing_bytes(path, label=label) != expected:
            raise HistoricalEvaluationArchiveConflict(
                f"concurrent {label} bytes conflict with the canonical document"
            ) from exc
    except PublicationVisibleButMetadataUncertain as exc:
        raise HistoricalEvaluationArchiveDurabilityError(
            f"{label} publication is visible but durability is uncertain"
        ) from exc
    except PostPublicationReloadFailure as exc:
        raise HistoricalEvaluationArchiveDurabilityError(
            f"{label} publication cannot be reloaded exactly"
        ) from exc
    except DurabilityAdapterError as exc:
        raise HistoricalEvaluationArchiveDurabilityError(
            f"{label} publication failed before a durable commit"
        ) from exc


def _json_mapping(
    *,
    path: Path,
    missing_error: type[HistoricalEvaluationStoreError],
    malformed_error: type[HistoricalEvaluationStoreError],
    label: str,
) -> tuple[bytes, Mapping[str, Any]]:
    try:
        if not path.is_file():
            raise missing_error(f"{label} not found")
        raw = path.read_bytes()
    except HistoricalEvaluationStoreError:
        raise
    except FileNotFoundError as exc:
        raise missing_error(f"{label} not found") from exc
    except OSError as exc:
        raise malformed_error(f"{label} cannot be read") from exc
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise malformed_error(f"{label} exceeds its archive byte bound")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise malformed_error(f"{label} is not canonical JSON") from exc
    if not isinstance(document, Mapping):
        raise malformed_error(f"{label} must be one JSON object")
    return raw, document


def _require_canonical_reload(
    *,
    raw: bytes,
    mapping: Mapping[str, Any],
    canonical_mapping: Mapping[str, Any],
    malformed_error: type[HistoricalEvaluationStoreError],
    label: str,
) -> None:
    expected = canonical_bytes(canonical_mapping)
    if raw != expected or canonical_bytes(mapping) != expected:
        raise malformed_error(f"{label} bytes are not the exact canonical mapping")


def _load_authority(
    paths: _ArchivePaths,
    authority_fingerprint: str,
) -> HistoricalEvaluationPairingAuthority:
    path = paths.authority(authority_fingerprint)
    raw, mapping = _json_mapping(
        path=path,
        missing_error=CommittedHistoricalEvaluationAuthorityNotFound,
        malformed_error=MalformedHistoricalEvaluationAuthority,
        label="committed historical evaluation pairing authority",
    )
    embedded = mapping.get("authority_fingerprint")
    if embedded != authority_fingerprint:
        raise HistoricalEvaluationArchiveFingerprintMismatch(
            "authority document identity differs from its requested fingerprint"
        )
    try:
        authority = HistoricalEvaluationPairingAuthority.from_dict(mapping)
    except (TypeError, ValueError) as exc:
        if "fingerprint" in str(exc).lower():
            raise HistoricalEvaluationArchiveFingerprintMismatch(
                "authority document fingerprint is invalid"
            ) from exc
        raise MalformedHistoricalEvaluationAuthority(
            "authority document is structurally invalid"
        ) from exc
    _require_canonical_reload(
        raw=raw,
        mapping=mapping,
        canonical_mapping=authority.to_dict(),
        malformed_error=MalformedHistoricalEvaluationAuthority,
        label="authority document",
    )
    return authority


def _load_profile(
    paths: _ArchivePaths,
    profile_fingerprint: str,
) -> NativeMissionProfile:
    path = paths.profile(profile_fingerprint)
    raw, mapping = _json_mapping(
        path=path,
        missing_error=ReferencedHistoricalEvaluationProfileNotFound,
        malformed_error=MalformedHistoricalEvaluationProfile,
        label="referenced historical evaluation profile",
    )
    if mapping.get("profile_fingerprint") != profile_fingerprint:
        raise HistoricalEvaluationArchiveFingerprintMismatch(
            "profile document identity differs from its authority reference"
        )
    try:
        profile = NativeMissionProfile.from_dict(mapping)
        profile.validated()
    except (TypeError, ValueError) as exc:
        if "fingerprint" in str(exc).lower():
            raise HistoricalEvaluationArchiveFingerprintMismatch(
                "profile document fingerprint is invalid"
            ) from exc
        raise MalformedHistoricalEvaluationProfile(
            "profile document is structurally invalid"
        ) from exc
    if (
        profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V5
        or profile.is_launchable_runtime_profile
    ):
        raise MalformedHistoricalEvaluationProfile(
            "referenced profile must be exact non-launchable V5"
        )
    _require_canonical_reload(
        raw=raw,
        mapping=mapping,
        canonical_mapping=profile.to_dict(),
        malformed_error=MalformedHistoricalEvaluationProfile,
        label="profile document",
    )
    return profile


def _load_payload(
    paths: _ArchivePaths,
    payload_fingerprint: str,
) -> NativeCanaryAuthorizationPayloadV4:
    path = paths.payload(payload_fingerprint)
    raw, mapping = _json_mapping(
        path=path,
        missing_error=ReferencedHistoricalAuthorizationPayloadNotFound,
        malformed_error=MalformedHistoricalAuthorizationPayload,
        label="referenced historical authorization payload",
    )
    if mapping.get("payload_fingerprint") != payload_fingerprint:
        raise HistoricalEvaluationArchiveFingerprintMismatch(
            "payload document identity differs from its authority reference"
        )
    try:
        payload = load_historical_native_canary_authorization_payload_v4(mapping)
    except (TypeError, ValueError) as exc:
        if "fingerprint" in str(exc).lower():
            raise HistoricalEvaluationArchiveFingerprintMismatch(
                "payload document fingerprint is invalid"
            ) from exc
        raise MalformedHistoricalAuthorizationPayload(
            "payload document is structurally invalid"
        ) from exc
    _require_canonical_reload(
        raw=raw,
        mapping=mapping,
        canonical_mapping=payload.to_dict(),
        malformed_error=MalformedHistoricalAuthorizationPayload,
        label="payload document",
    )
    return payload


def load_historical_evaluation_pairing(
    *,
    archive_root: Path,
    authority_fingerprint: str,
) -> HistoricalEvaluationPairingBundle:
    """Load only a complete pairing whose authority commit marker exists."""

    require_sha256(
        authority_fingerprint,
        "historical evaluation pairing authority fingerprint",
    )
    paths = _archive_paths(archive_root)
    authority = _load_authority(paths, authority_fingerprint)
    profile = _load_profile(
        paths, authority.evaluation_profile_fingerprint
    )
    payload = _load_payload(
        paths, authority.target_authorization_payload_fingerprint
    )
    try:
        validate_historical_evaluation_pairing_relation(
            authority=authority,
            evaluation_profile=profile,
            target_authorization_payload=payload,
        )
    except ValueError as exc:
        raise HistoricalEvaluationArchiveRelationMismatch(
            "archived historical evaluation pairing relation is invalid"
        ) from exc
    return HistoricalEvaluationPairingBundle(
        evaluation_profile=profile,
        target_authorization_payload=payload,
        pairing_authority=authority,
    )


def persist_historical_evaluation_pairing(
    *,
    archive_root: Path,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
    pairing_authority: HistoricalEvaluationPairingAuthority,
) -> HistoricalEvaluationPairingAuthority:
    """Durably publish one exact pairing with byte-identical replay idempotence.

    All semantic validation and canonical-byte computation precede directory or
    document writes.  The asserted ``actor_id`` is persisted exactly as carried
    by ``pairing_authority``; no actor authentication is performed or claimed.
    """

    paths = _archive_paths(archive_root)
    profile_bytes, payload_bytes, authority_bytes = _validated_documents(
        evaluation_profile=evaluation_profile,
        target_authorization_payload=target_authorization_payload,
        pairing_authority=pairing_authority,
    )
    profile_path = paths.profile(evaluation_profile.profile_fingerprint)
    payload_path = paths.payload(target_authorization_payload.payload_fingerprint)
    authority_path = paths.authority(pairing_authority.authority_fingerprint)

    _create_archive_directories(paths)

    # A pre-existing marker is idempotent only when the whole committed bundle
    # already exists and all three exact bytes match.  Never repair around an
    # authority that appeared before its referenced documents.
    if authority_path.exists():
        if _read_existing_bytes(
            authority_path, label="pairing authority"
        ) != authority_bytes:
            raise HistoricalEvaluationArchiveConflict(
                "existing pairing authority bytes conflict with the canonical document"
            )
        for path, expected, label in (
            (profile_path, profile_bytes, "evaluation profile"),
            (
                payload_path,
                payload_bytes,
                "historical authorization payload",
            ),
        ):
            if _read_existing_bytes(path, label=label) != expected:
                raise HistoricalEvaluationArchiveConflict(
                    f"existing {label} bytes conflict with the canonical replay"
                )
        existing = load_historical_evaluation_pairing(
            archive_root=archive_root,
            authority_fingerprint=pairing_authority.authority_fingerprint,
        )
        if (
            canonical_bytes(existing.evaluation_profile.to_dict()) != profile_bytes
            or canonical_bytes(
                existing.target_authorization_payload.to_dict()
            )
            != payload_bytes
            or canonical_bytes(existing.pairing_authority.to_dict())
            != authority_bytes
        ):
            raise HistoricalEvaluationArchiveConflict(
                "existing committed pairing differs from the canonical replay"
            )
        return existing.pairing_authority

    adapter = PlatformDurabilityAdapter()
    # The authority is intentionally last: it alone commits the pairing.
    _persist_exact_document(
        path=profile_path,
        expected=profile_bytes,
        label="evaluation profile",
        durability_adapter=adapter,
    )
    _persist_exact_document(
        path=payload_path,
        expected=payload_bytes,
        label="historical authorization payload",
        durability_adapter=adapter,
    )
    _persist_exact_document(
        path=authority_path,
        expected=authority_bytes,
        label="pairing authority",
        durability_adapter=adapter,
    )

    committed = load_historical_evaluation_pairing(
        archive_root=archive_root,
        authority_fingerprint=pairing_authority.authority_fingerprint,
    )
    return committed.pairing_authority


__all__ = [
    "AUTHORITY_DIRECTORY_NAME",
    "AUTHORITY_FILE_SUFFIX",
    "CommittedHistoricalEvaluationAuthorityNotFound",
    "HistoricalEvaluationArchiveConflict",
    "HistoricalEvaluationArchiveDurabilityError",
    "HistoricalEvaluationArchiveFingerprintMismatch",
    "HistoricalEvaluationArchiveRelationMismatch",
    "HistoricalEvaluationPairingBundle",
    "HistoricalEvaluationStoreError",
    "InvalidHistoricalEvaluationArchiveRoot",
    "MalformedHistoricalAuthorizationPayload",
    "MalformedHistoricalEvaluationAuthority",
    "MalformedHistoricalEvaluationProfile",
    "PAYLOAD_DIRECTORY_NAME",
    "PAYLOAD_FILE_SUFFIX",
    "PROFILE_DIRECTORY_NAME",
    "PROFILE_FILE_SUFFIX",
    "ReferencedHistoricalAuthorizationPayloadNotFound",
    "ReferencedHistoricalEvaluationProfileNotFound",
    "load_historical_evaluation_pairing",
    "persist_historical_evaluation_pairing",
]
