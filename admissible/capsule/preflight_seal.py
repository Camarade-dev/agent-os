"""Closed-world, root-bound sealing for future capsule preflight preparations.

Historical V1 preparations are intentionally outside this module.  V2 seals a
*complete* preparation tree: the manifest enumerates every entry beneath the
preparation root recursively, excluding only the manifest file and the final
seal file, and validation refuses any added file, added directory, removed
entry, unexpected empty directory, rename, path/case/Unicode alias, symlink,
hardlink, special file or mutation observed during validation.  An unlisted
extra file is a refusal, not an ignored file.

Two further properties matter for the one-time canary:

* The seal binds the exact preparation root -- canonical absolute path, device,
  inode, root mode and type, preparation ID and run ID -- so a byte-identical
  copy of the directory at another path or inode refuses.  Portability is not a
  goal; a new location requires a new preparation and a new owner
  authorization.
* The expected final-seal fingerprint is *not* retained inside the preparation.
  ``RetainedPreparationSealIdentity`` lives outside the root and is bound into
  the owner payload, so the preparation cannot mint both a replacement seal and
  the expected fingerprint used to validate it.

Neither document contains its own final-byte hash, so the construction stays
non-self-referential.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    atomic_json,
    canonical_bytes,
    fingerprint,
    fsync_directory,
    mode_type,
    portable_path_collision_key,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    sha256_bytes,
    strict_json_loads,
    validate_closed_relative_path,
)
from admissible.capsule.model_authority import ModelBindingPolicy
from admissible.capsule.serialization_witness import (
    CandidateSerializationWitnessReceipt,
    CandidateSerializationWitnessStore,
)


FUTURE_PREFLIGHT_MANIFEST_SCHEMA_VERSION = (
    "admissible_capsule_future_preflight_closed_world_manifest_v2"
)
FUTURE_PREFLIGHT_SEAL_SCHEMA_VERSION = (
    "admissible_capsule_future_preflight_final_seal_v2"
)
RETAINED_SEAL_IDENTITY_SCHEMA_VERSION = (
    "admissible_capsule_retained_preflight_seal_identity_v1"
)
PREPARATION_ROOT_IDENTITY_SCHEMA_VERSION = (
    "admissible_capsule_future_preparation_root_identity_v1"
)
FUTURE_PREFLIGHT_MANIFEST_PATH = "evidence/content-manifest-v2.json"
FUTURE_PREFLIGHT_SEAL_PATH = "evidence/preflight-seal-v2.json"

#: The only entries excluded from coverage.  There is no ignore rule: any other
#: unlisted entry is a refusal.
EXCLUDED_PUBLICATION_PATHS = (
    FUTURE_PREFLIGHT_MANIFEST_PATH,
    FUTURE_PREFLIGHT_SEAL_PATH,
)

#: The preparation classifications.  No earlier state is runnable.
SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION = (
    "SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION"
)
OWNER_BOUND_READY_FOR_SINGLE_LAUNCH = "OWNER_BOUND_READY_FOR_SINGLE_LAUNCH"
OWNER_AUTHORIZATION_CONSUMED = "OWNER_AUTHORIZATION_CONSUMED"

_MAX_ENTRIES = 4096
_MAX_FILE_BYTES = 8 * 1024 * 1024


class FuturePreflightSealError(ValueError):
    pass


def _reject_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise FuturePreflightSealError(f"{label} has a symlinked component")


def _root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise FuturePreflightSealError(
            "future preflight root must be absolute without aliases"
        )
    _reject_symlink_components(path, "future preflight root")
    if not path.is_dir():
        raise FuturePreflightSealError("future preflight root is absent")
    return path


def preparation_root_identity(
    root: Path,
    *,
    preparation_id: str,
    run_id: str,
) -> dict[str, Any]:
    """Bind the exact root this one-time preparation may ever validate at."""

    root = _root(root)
    require_identifier(preparation_id, "future preparation identity")
    require_identifier(run_id, "future preparation run identity")
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode):
        raise FuturePreflightSealError("future preflight root is not a directory")
    return {
        "schema_version": PREPARATION_ROOT_IDENTITY_SCHEMA_VERSION,
        "canonical_path_sha256": sha256_bytes(
            os.fsencode(os.fspath(root.resolve()))
        ),
        "device": info.st_dev,
        "inode": info.st_ino,
        "root_mode": stat.S_IMODE(info.st_mode),
        "root_type": mode_type(info.st_mode),
        "preparation_id": preparation_id,
        "run_id": run_id,
    }


def validate_preparation_root_identity(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FuturePreflightSealError(f"{label} is not an object")
    require_exact_keys(
        value,
        {
            "schema_version",
            "canonical_path_sha256",
            "device",
            "inode",
            "root_mode",
            "root_type",
            "preparation_id",
            "run_id",
        },
        label,
    )
    if (
        value["schema_version"] != PREPARATION_ROOT_IDENTITY_SCHEMA_VERSION
        or value["root_type"] != "directory"
    ):
        raise FuturePreflightSealError(f"{label} is not a supported directory root")
    require_sha256(value["canonical_path_sha256"], f"{label} canonical path")
    require_identifier(value["preparation_id"], f"{label} preparation")
    require_identifier(value["run_id"], f"{label} run")
    for key, maximum in (
        ("device", 2**63 - 1),
        ("inode", 2**63 - 1),
        ("root_mode", 0o7777),
    ):
        require_strict_int(value[key], f"{label} {key}", minimum=0, maximum=maximum)
    return dict(value)


def _observe_file_and_bytes(
    root: Path,
    relative: str,
) -> tuple[dict[str, Any], bytes]:
    relative = validate_closed_relative_path(
        relative,
        label="future preflight covered path",
    )
    path = root / relative
    _reject_symlink_components(path, "future preflight covered path")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise FuturePreflightSealError(
                "future preflight covers only private regular files"
            )
        if before.st_size > _MAX_FILE_BYTES:
            raise FuturePreflightSealError(
                "future preflight covered file exceeds its byte bound"
            )
        content = bytearray()
        while True:
            block = os.read(descriptor, 256 * 1024)
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise FuturePreflightSealError(
                "future preflight file changed while observed"
            )
    finally:
        os.close(descriptor)
    exact = bytes(content)
    return {
        "relative_path": relative,
        "entry_type": "regular",
        "mode": stat.S_IMODE(before.st_mode),
        "size": len(exact),
        "sha256": sha256_bytes(exact),
    }, exact


def _observe_file(root: Path, relative: str) -> dict[str, Any]:
    return _observe_file_and_bytes(root, relative)[0]


def _observe_directory(root: Path, relative: str) -> dict[str, Any]:
    relative = validate_closed_relative_path(
        relative,
        label="future preflight covered directory",
    )
    path = root / relative
    _reject_symlink_components(path, "future preflight covered directory")
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise FuturePreflightSealError(
            f"future preflight expected a directory at {relative}"
        )
    return {
        "relative_path": relative,
        "entry_type": "directory",
        "mode": stat.S_IMODE(info.st_mode),
    }


@dataclass(frozen=True)
class PreparationTreeObservation:
    """One complete recursive observation of the preparation root."""

    files: tuple[str, ...]
    directories: tuple[str, ...]

    @property
    def covered_files(self) -> tuple[str, ...]:
        return tuple(
            item for item in self.files if item not in EXCLUDED_PUBLICATION_PATHS
        )


def observe_preparation_tree(root: Path) -> PreparationTreeObservation:
    """Enumerate every entry beneath the root, refusing anything unexpected.

    The walk refuses symlinks, hardlinks, special files, path/case/Unicode
    aliases and unbounded trees.  Coverage rulings are made by the caller only
    after this complete observation returns.
    """

    root = _root(root)
    files: list[str] = []
    directories: list[str] = []
    collisions: dict[str, str] = {}
    refusals: list[str] = []
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        current, prefix = pending.pop()
        with os.scandir(current) as scan:
            entries = sorted(scan, key=lambda item: item.name)
        for entry in entries:
            relative = validate_closed_relative_path(
                f"{prefix}{entry.name}",
                label="future preflight tree entry",
                forbidden_components=frozenset(),
            )
            if len(files) + len(directories) >= _MAX_ENTRIES:
                raise FuturePreflightSealError(
                    "future preflight tree exceeds its entry bound"
                )
            key = portable_path_collision_key(relative)
            if key in collisions and collisions[key] != relative:
                refusals.append(
                    "contains a path/case/Unicode alias: "
                    f"{relative} aliases {collisions[key]}"
                )
            collisions[key] = relative
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                refusals.append(f"contains a symlink: {relative}")
                continue
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative)
                pending.append((Path(entry.path), f"{relative}/"))
                continue
            if not stat.S_ISREG(info.st_mode):
                refusals.append(
                    "contains a special entry "
                    f"({mode_type(info.st_mode)}): {relative}"
                )
                continue
            if info.st_nlink != 1:
                refusals.append(f"contains a hardlink: {relative}")
                continue
            files.append(relative)
    # Observation is complete before any ruling: the whole tree is walked and
    # every structural refusal is accumulated, then reported together.
    if refusals:
        raise FuturePreflightSealError(
            "future preflight tree " + "; ".join(sorted(refusals))
        )
    return PreparationTreeObservation(
        files=tuple(sorted(files)),
        directories=tuple(sorted(directories)),
    )


def _owner_payload(
    root: Path,
    relative: str,
    *,
    policy: ModelBindingPolicy,
    receipt: CandidateSerializationWitnessReceipt,
) -> Mapping[str, Any]:
    record, payload_bytes = _observe_file_and_bytes(root, relative)
    value = strict_json_loads(
        payload_bytes,
        label="future preflight owner payload",
    )
    if not isinstance(value, Mapping):
        raise FuturePreflightSealError("future owner payload is not an object")
    required = {
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "candidate_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "candidate_serialization_witness_run_identity": (
            receipt.witness_run_identity
        ),
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise FuturePreflightSealError(
                f"future owner payload does not bind {key}"
            )
    return {
        "relative_path": record["relative_path"],
        "payload_fingerprint": fingerprint(value),
        **required,
    }


@dataclass(frozen=True)
class RetainedPreparationSealIdentity:
    """The expected seal fingerprint, retained outside the preparation root.

    The preparation directory never contains this value.  Validation therefore
    cannot be satisfied by replacing the manifest and seal with a mutually
    consistent pair: the replacement's fingerprint will not equal the retained
    one.  A replacement fingerprint sourced from inside the preparation is
    refused outright, because both ``publish`` and ``load`` require a retention
    path outside the root.
    """

    schema_version: str
    retention_path: Path
    preparation_root_identity: Mapping[str, Any]
    expected_manifest_fingerprint: str
    expected_seal_fingerprint: str
    retained_identity: str

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "preparation_root_identity": dict(self.preparation_root_identity),
            "expected_manifest_fingerprint": self.expected_manifest_fingerprint,
            "expected_seal_fingerprint": self.expected_seal_fingerprint,
        }

    def validated(self) -> "RetainedPreparationSealIdentity":
        if self.schema_version != RETAINED_SEAL_IDENTITY_SCHEMA_VERSION:
            raise FuturePreflightSealError("unsupported retained seal identity")
        validate_preparation_root_identity(
            self.preparation_root_identity,
            "retained preparation root identity",
        )
        require_sha256(
            self.expected_manifest_fingerprint,
            "retained expected manifest fingerprint",
        )
        require_sha256(
            self.expected_seal_fingerprint,
            "retained expected seal fingerprint",
        )
        require_sha256(self.retained_identity, "retained seal identity")
        if fingerprint(self._body()) != self.retained_identity:
            raise FuturePreflightSealError("retained seal identity mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "retained_identity": self.retained_identity}

    @staticmethod
    def external_retention_path(retention_path: Path, root: Path) -> Path:
        """Refuse any retention path inside the preparation it validates."""

        if (
            not isinstance(retention_path, Path)
            or not retention_path.is_absolute()
            or ".." in retention_path.parts
        ):
            raise FuturePreflightSealError(
                "retained seal path must be absolute without aliases"
            )
        resolved_root = _root(root).resolve()
        candidate = retention_path.parent.resolve() / retention_path.name
        if candidate == resolved_root or candidate.is_relative_to(resolved_root):
            raise FuturePreflightSealError(
                "the expected seal fingerprint must be retained outside the "
                "preparation directory"
            )
        return candidate

    @classmethod
    def publish(
        cls,
        *,
        retention_path: Path,
        root: Path,
        preparation_root_identity: Mapping[str, Any],
        expected_manifest_fingerprint: str,
        expected_seal_fingerprint: str,
    ) -> "RetainedPreparationSealIdentity":
        path = cls.external_retention_path(retention_path, root)
        body = {
            "schema_version": RETAINED_SEAL_IDENTITY_SCHEMA_VERSION,
            "preparation_root_identity": dict(preparation_root_identity),
            "expected_manifest_fingerprint": expected_manifest_fingerprint,
            "expected_seal_fingerprint": expected_seal_fingerprint,
        }
        record = cls(
            schema_version=body["schema_version"],
            retention_path=path,
            preparation_root_identity=dict(preparation_root_identity),
            expected_manifest_fingerprint=expected_manifest_fingerprint,
            expected_seal_fingerprint=expected_seal_fingerprint,
            retained_identity=fingerprint(body),
        ).validated()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            encoded = canonical_bytes(record.to_dict())
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(path.parent)
        return record

    @classmethod
    def load(
        cls,
        *,
        retention_path: Path,
        root: Path,
    ) -> "RetainedPreparationSealIdentity":
        path = cls.external_retention_path(retention_path, root)
        try:
            value = strict_json_loads(
                path.read_bytes(),
                label="retained preflight seal identity",
            )
        except (FileNotFoundError, ValueError) as error:
            raise FuturePreflightSealError(
                "retained preflight seal identity is missing or invalid"
            ) from error
        require_exact_keys(
            value,
            {
                "schema_version",
                "preparation_root_identity",
                "expected_manifest_fingerprint",
                "expected_seal_fingerprint",
                "retained_identity",
            },
            "retained preflight seal identity",
        )
        return cls(
            schema_version=value["schema_version"],
            retention_path=path,
            preparation_root_identity=dict(value["preparation_root_identity"]),
            expected_manifest_fingerprint=value["expected_manifest_fingerprint"],
            expected_seal_fingerprint=value["expected_seal_fingerprint"],
            retained_identity=value["retained_identity"],
        ).validated()


def publish_future_preflight_seal(
    *,
    root: Path,
    owner_payload_path: str,
    preparation_id: str,
    run_id: str,
    retained_seal_path: Path,
    model_binding_policy: ModelBindingPolicy,
    candidate_witness_receipt: CandidateSerializationWitnessReceipt,
    candidate_witness_store: CandidateSerializationWitnessStore,
) -> Mapping[str, Any]:
    """Publish the closed-world manifest, then a separate root-bound seal.

    Coverage is derived from a complete recursive observation of the root, never
    from a caller-supplied path list, so an operator cannot leave a file out.
    """

    root = _root(root)
    policy = model_binding_policy.validated()
    if not isinstance(
        candidate_witness_receipt, CandidateSerializationWitnessReceipt
    ):
        raise FuturePreflightSealError(
            "future preflight requires an opaque candidate witness receipt"
        )
    if not isinstance(candidate_witness_store, CandidateSerializationWitnessStore):
        raise FuturePreflightSealError(
            "future preflight requires the candidate witness store"
        )
    bundle = candidate_witness_store.load_candidate_evidence(
        receipt_identity=candidate_witness_receipt.receipt_identity,
        witness_run_identity=candidate_witness_receipt.witness_run_identity,
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    receipt = bundle.receipt
    if receipt.to_dict() != candidate_witness_receipt.to_dict():
        raise FuturePreflightSealError(
            "future preflight receipt differs from durable evidence"
        )
    if (
        receipt.model_binding_policy_fingerprint != policy.policy_fingerprint
        or receipt.executable_identity != policy.codex_executable_identity
    ):
        raise FuturePreflightSealError(
            "future preflight receipt belongs to another model policy"
        )
    root_identity = preparation_root_identity(
        root,
        preparation_id=preparation_id,
        run_id=run_id,
    )
    manifest_path = root / FUTURE_PREFLIGHT_MANIFEST_PATH
    seal_path = root / FUTURE_PREFLIGHT_SEAL_PATH
    if manifest_path.exists() or seal_path.exists():
        raise FuturePreflightSealError(
            "future preflight manifest or seal is already published"
        )
    owner_payload_path = validate_closed_relative_path(
        owner_payload_path,
        label="future owner payload path",
    )
    observation = observe_preparation_tree(root)
    covered = observation.covered_files
    if not covered:
        raise FuturePreflightSealError(
            "future preflight preparation contains no covered file"
        )
    if owner_payload_path not in covered:
        raise FuturePreflightSealError(
            "future owner payload must be covered by the content manifest"
        )
    records = [_observe_file(root, item) for item in covered]
    directories = [
        _observe_directory(root, item) for item in observation.directories
    ]
    owner = _owner_payload(
        root,
        owner_payload_path,
        policy=policy,
        receipt=receipt,
    )
    manifest_body = {
        "schema_version": FUTURE_PREFLIGHT_MANIFEST_SCHEMA_VERSION,
        "construction": "closed_world_non_self_referential_tree_v2",
        "coverage": "every_entry_beneath_root_except_manifest_and_seal",
        "extra_entry_policy": "REFUSE_ANY_UNLISTED_ENTRY",
        "excluded_publication_paths": list(EXCLUDED_PUBLICATION_PATHS),
        "preparation_root_identity": dict(root_identity),
        "records": records,
        "expected_directories": directories,
        "owner_payload_binding": dict(owner),
        "model_binding_policy": policy.to_dict(),
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "candidate_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "candidate_serialization_witness_run_identity": (
            receipt.witness_run_identity
        ),
        "candidate_store_anchor_fingerprint": bundle.store_anchor_fingerprint,
        "candidate_evidence_pack_fingerprint": (
            bundle.pack.evidence_pack_fingerprint
        ),
    }
    manifest = {
        **manifest_body,
        "manifest_fingerprint": fingerprint(manifest_body),
    }
    atomic_json(manifest_path, manifest, mode=0o400)
    manifest_bytes = manifest_path.read_bytes()
    seal_body = {
        "schema_version": FUTURE_PREFLIGHT_SEAL_SCHEMA_VERSION,
        "manifest_relative_path": FUTURE_PREFLIGHT_MANIFEST_PATH,
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "manifest_size": len(manifest_bytes),
        "manifest_fingerprint": manifest["manifest_fingerprint"],
        "preparation_root_identity": dict(root_identity),
        "classification": SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION,
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "candidate_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "candidate_serialization_witness_run_identity": (
            receipt.witness_run_identity
        ),
    }
    seal = {**seal_body, "seal_fingerprint": fingerprint(seal_body)}
    atomic_json(seal_path, seal, mode=0o400)
    retained = RetainedPreparationSealIdentity.publish(
        retention_path=retained_seal_path,
        root=root,
        preparation_root_identity=root_identity,
        expected_manifest_fingerprint=manifest["manifest_fingerprint"],
        expected_seal_fingerprint=seal["seal_fingerprint"],
    )
    return validate_future_preflight_seal(
        root=root,
        expected_model_binding_policy=policy,
        expected_candidate_witness_receipt=receipt,
        candidate_witness_store=candidate_witness_store,
        retained_seal_identity=retained,
    )


def validate_future_preflight_seal(
    *,
    root: Path,
    expected_model_binding_policy: ModelBindingPolicy,
    expected_candidate_witness_receipt: CandidateSerializationWitnessReceipt,
    candidate_witness_store: CandidateSerializationWitnessStore,
    retained_seal_identity: RetainedPreparationSealIdentity,
) -> Mapping[str, Any]:
    """Reopen the retained identity, seal, manifest, complete tree and entries."""

    root = _root(root)
    policy = expected_model_binding_policy.validated()
    receipt = expected_candidate_witness_receipt
    if not isinstance(receipt, CandidateSerializationWitnessReceipt):
        raise FuturePreflightSealError(
            "expected witness receipt is not a candidate receipt"
        )
    if not isinstance(candidate_witness_store, CandidateSerializationWitnessStore):
        raise FuturePreflightSealError(
            "future preflight requires the candidate witness store"
        )
    if not isinstance(retained_seal_identity, RetainedPreparationSealIdentity):
        raise FuturePreflightSealError(
            "future preflight requires an externally retained seal identity"
        )
    retained = retained_seal_identity.validated()
    RetainedPreparationSealIdentity.external_retention_path(
        retained.retention_path, root
    )
    bundle = candidate_witness_store.load_candidate_evidence(
        receipt_identity=receipt.receipt_identity,
        witness_run_identity=receipt.witness_run_identity,
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if bundle.receipt.to_dict() != receipt.to_dict():
        raise FuturePreflightSealError(
            "future preflight receipt differs from durable evidence"
        )
    before_tree = observe_preparation_tree(root)
    try:
        _seal_record, seal_bytes = _observe_file_and_bytes(
            root,
            FUTURE_PREFLIGHT_SEAL_PATH,
        )
        _manifest_record, manifest_bytes = _observe_file_and_bytes(
            root,
            FUTURE_PREFLIGHT_MANIFEST_PATH,
        )
        seal = strict_json_loads(seal_bytes, label="future preflight final seal")
        manifest = strict_json_loads(
            manifest_bytes,
            label="future preflight content manifest",
        )
    except (FileNotFoundError, ValueError) as error:
        raise FuturePreflightSealError(
            "future preflight manifest or seal is missing/invalid"
        ) from error
    require_exact_keys(
        seal,
        {
            "schema_version",
            "manifest_relative_path",
            "manifest_sha256",
            "manifest_size",
            "manifest_fingerprint",
            "preparation_root_identity",
            "classification",
            "model_binding_policy_fingerprint",
            "candidate_serialization_witness_receipt_identity",
            "candidate_serialization_witness_run_identity",
            "seal_fingerprint",
        },
        "future preflight final seal",
    )
    seal_body = {
        key: value for key, value in seal.items() if key != "seal_fingerprint"
    }
    if (
        seal["schema_version"] != FUTURE_PREFLIGHT_SEAL_SCHEMA_VERSION
        or seal["seal_fingerprint"] != retained.expected_seal_fingerprint
        or seal["manifest_relative_path"] != FUTURE_PREFLIGHT_MANIFEST_PATH
        or sha256_bytes(manifest_bytes) != seal["manifest_sha256"]
        or len(manifest_bytes) != seal["manifest_size"]
        or fingerprint(seal_body) != seal["seal_fingerprint"]
        or seal["classification"]
        != SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION
        or seal["model_binding_policy_fingerprint"]
        != policy.policy_fingerprint
        or seal["candidate_serialization_witness_receipt_identity"]
        != receipt.receipt_identity
        or seal["candidate_serialization_witness_run_identity"]
        != receipt.witness_run_identity
    ):
        raise FuturePreflightSealError(
            "future preflight final seal differs from manifest or authority"
        )
    sealed_root = validate_preparation_root_identity(
        seal["preparation_root_identity"],
        "sealed preparation root identity",
    )
    observed_root = preparation_root_identity(
        root,
        preparation_id=sealed_root["preparation_id"],
        run_id=sealed_root["run_id"],
    )
    if (
        sealed_root != dict(retained.preparation_root_identity)
        or sealed_root != observed_root
    ):
        raise FuturePreflightSealError(
            "future preflight preparation root was copied, moved or re-created"
        )
    require_exact_keys(
        manifest,
        {
            "schema_version",
            "construction",
            "coverage",
            "extra_entry_policy",
            "excluded_publication_paths",
            "preparation_root_identity",
            "records",
            "expected_directories",
            "owner_payload_binding",
            "model_binding_policy",
            "model_binding_policy_fingerprint",
            "candidate_serialization_witness_receipt_identity",
            "candidate_serialization_witness_run_identity",
            "candidate_store_anchor_fingerprint",
            "candidate_evidence_pack_fingerprint",
            "manifest_fingerprint",
        },
        "future preflight content manifest",
    )
    manifest_body = {
        key: value
        for key, value in manifest.items()
        if key != "manifest_fingerprint"
    }
    if (
        manifest["schema_version"] != FUTURE_PREFLIGHT_MANIFEST_SCHEMA_VERSION
        or manifest["construction"]
        != "closed_world_non_self_referential_tree_v2"
        or manifest["coverage"]
        != "every_entry_beneath_root_except_manifest_and_seal"
        or manifest["extra_entry_policy"] != "REFUSE_ANY_UNLISTED_ENTRY"
        or manifest["excluded_publication_paths"]
        != list(EXCLUDED_PUBLICATION_PATHS)
        or fingerprint(manifest_body) != manifest["manifest_fingerprint"]
        or manifest["manifest_fingerprint"]
        != retained.expected_manifest_fingerprint
        or manifest["manifest_fingerprint"] != seal["manifest_fingerprint"]
        or manifest["preparation_root_identity"] != sealed_root
        or manifest["model_binding_policy"] != policy.to_dict()
        or manifest["model_binding_policy_fingerprint"]
        != policy.policy_fingerprint
        or manifest["candidate_serialization_witness_receipt_identity"]
        != receipt.receipt_identity
        or manifest["candidate_serialization_witness_run_identity"]
        != receipt.witness_run_identity
        or manifest["candidate_store_anchor_fingerprint"]
        != bundle.store_anchor_fingerprint
        or manifest["candidate_evidence_pack_fingerprint"]
        != bundle.pack.evidence_pack_fingerprint
    ):
        raise FuturePreflightSealError(
            "future preflight content manifest changed"
        )
    records = manifest["records"]
    directories = manifest["expected_directories"]
    if not isinstance(records, list) or not records:
        raise FuturePreflightSealError("future manifest has no records")
    if not isinstance(directories, list):
        raise FuturePreflightSealError(
            "future manifest has no explicit expected directory set"
        )
    paths = [item.get("relative_path") for item in records]
    directory_paths = [item.get("relative_path") for item in directories]
    if (
        len(paths) != len(set(paths))
        or len(directory_paths) != len(set(directory_paths))
        or set(paths) & set(directory_paths)
        or set(EXCLUDED_PUBLICATION_PATHS) & set(paths)
        or set(EXCLUDED_PUBLICATION_PATHS) & set(directory_paths)
    ):
        raise FuturePreflightSealError(
            "future manifest is duplicate or self-referential"
        )
    observed_files = set(before_tree.covered_files)
    observed_directories = set(before_tree.directories)
    unlisted = sorted(
        (observed_files - set(paths)) | (observed_directories - set(directory_paths))
    )
    absent = sorted(
        (set(paths) - observed_files) | (set(directory_paths) - observed_directories)
    )
    if unlisted or absent:
        raise FuturePreflightSealError(
            "future preflight tree is not the closed authorized entry set "
            f"(unlisted={unlisted}, removed={absent})"
        )
    for expected in records:
        require_exact_keys(
            expected,
            {"relative_path", "entry_type", "mode", "size", "sha256"},
            "future preflight content record",
        )
        if expected["entry_type"] != "regular":
            raise FuturePreflightSealError(
                "future preflight content record is not a regular file"
            )
        if _observe_file(root, expected["relative_path"]) != expected:
            raise FuturePreflightSealError(
                "future preflight covered file changed: "
                f"{expected['relative_path']}"
            )
    for expected in directories:
        require_exact_keys(
            expected,
            {"relative_path", "entry_type", "mode"},
            "future preflight directory record",
        )
        if expected["entry_type"] != "directory":
            raise FuturePreflightSealError(
                "future preflight directory record is not a directory"
            )
        if _observe_directory(root, expected["relative_path"]) != expected:
            raise FuturePreflightSealError(
                f"future preflight directory changed: {expected['relative_path']}"
            )
    owner = manifest["owner_payload_binding"]
    observed_owner = _owner_payload(
        root,
        owner["relative_path"],
        policy=policy,
        receipt=receipt,
    )
    if observed_owner != owner:
        raise FuturePreflightSealError("future owner payload binding changed")
    if observe_preparation_tree(root) != before_tree:
        raise FuturePreflightSealError(
            "future preflight tree mutated during validation"
        )
    require_sha256(seal["seal_fingerprint"], "future preflight seal")
    return {
        "manifest_fingerprint": manifest["manifest_fingerprint"],
        "seal_fingerprint": seal["seal_fingerprint"],
        "retained_seal_identity": retained.retained_identity,
        "preparation_root_identity": dict(sealed_root),
        "classification": SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION,
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "candidate_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "candidate_store_anchor_fingerprint": bundle.store_anchor_fingerprint,
        "candidate_evidence_pack_fingerprint": (
            bundle.pack.evidence_pack_fingerprint
        ),
        "covered_paths": tuple(sorted(paths)),
        "expected_directories": tuple(sorted(directory_paths)),
        "closed_world": True,
        "self_referential": False,
    }
