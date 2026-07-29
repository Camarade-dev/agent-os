"""Non-self-referential sealing for future capsule preflight preparations.

Historical V1 preparations are intentionally outside this module.  V2 uses an
immutable content manifest that excludes both the manifest and final seal.  A
separate final seal records the exact manifest bytes and model-binding
authority.  No document claims to contain its own final-byte hash.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.common import (
    atomic_json,
    fingerprint,
    require_exact_keys,
    require_sha256,
    sha256_bytes,
    strict_json_loads,
    validate_closed_relative_path,
)
from admissible.capsule.model_authority import ModelBindingPolicy
from admissible.capsule.serialization_witness import (
    TrustedSerializationWitnessStore,
    VerifiedSerializationWitnessReceipt,
)


FUTURE_PREFLIGHT_MANIFEST_SCHEMA_VERSION = (
    "admissible_capsule_future_preflight_content_manifest_v2"
)
FUTURE_PREFLIGHT_SEAL_SCHEMA_VERSION = (
    "admissible_capsule_future_preflight_final_seal_v2"
)
FUTURE_PREFLIGHT_MANIFEST_PATH = "evidence/content-manifest-v2.json"
FUTURE_PREFLIGHT_SEAL_PATH = "evidence/preflight-seal-v2.json"


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
        "mode": stat.S_IMODE(before.st_mode),
        "size": len(exact),
        "sha256": sha256_bytes(exact),
    }, exact


def _observe_file(root: Path, relative: str) -> dict[str, Any]:
    return _observe_file_and_bytes(root, relative)[0]


def _owner_payload(
    root: Path,
    relative: str,
    *,
    policy: ModelBindingPolicy,
    receipt: VerifiedSerializationWitnessReceipt,
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
        "verified_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "verified_serialization_witness_run_identity": (
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


def publish_future_preflight_seal(
    *,
    root: Path,
    covered_paths: Sequence[str],
    owner_payload_path: str,
    model_binding_policy: ModelBindingPolicy,
    verified_witness_receipt: VerifiedSerializationWitnessReceipt,
    trusted_witness_store: TrustedSerializationWitnessStore,
) -> Mapping[str, Any]:
    """Publish immutable manifest, then a separate seal over its exact bytes."""

    root = _root(root)
    policy = model_binding_policy.validated()
    if not isinstance(
        verified_witness_receipt, VerifiedSerializationWitnessReceipt
    ):
        raise FuturePreflightSealError(
            "future preflight requires an opaque verified witness receipt"
        )
    if not isinstance(trusted_witness_store, TrustedSerializationWitnessStore):
        raise FuturePreflightSealError(
            "future preflight requires the trusted witness store"
        )
    receipt = trusted_witness_store.load_verified_receipt(
        receipt_identity=verified_witness_receipt.receipt_identity,
        witness_run_identity=verified_witness_receipt.witness_run_identity,
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if receipt.to_dict() != verified_witness_receipt.to_dict():
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
    normalized = tuple(
        validate_closed_relative_path(
            item,
            label="future preflight covered path",
        )
        for item in covered_paths
    )
    if len(normalized) != len(set(normalized)) or not normalized:
        raise FuturePreflightSealError(
            "future preflight covered paths must be non-empty and unique"
        )
    if {
        FUTURE_PREFLIGHT_MANIFEST_PATH,
        FUTURE_PREFLIGHT_SEAL_PATH,
    } & set(normalized):
        raise FuturePreflightSealError(
            "manifest and seal must remain outside the covered content set"
        )
    owner_payload_path = validate_closed_relative_path(
        owner_payload_path,
        label="future owner payload path",
    )
    if owner_payload_path not in normalized:
        raise FuturePreflightSealError(
            "future owner payload must be covered by the content manifest"
        )
    manifest_path = root / FUTURE_PREFLIGHT_MANIFEST_PATH
    seal_path = root / FUTURE_PREFLIGHT_SEAL_PATH
    if manifest_path.exists() or seal_path.exists():
        raise FuturePreflightSealError(
            "future preflight manifest or seal is already published"
        )
    records = [_observe_file(root, item) for item in sorted(normalized)]
    owner = _owner_payload(
        root,
        owner_payload_path,
        policy=policy,
        receipt=receipt,
    )
    manifest_body = {
        "schema_version": FUTURE_PREFLIGHT_MANIFEST_SCHEMA_VERSION,
        "construction": "non_self_referential_content_set_v2",
        "excluded_publication_paths": [
            FUTURE_PREFLIGHT_MANIFEST_PATH,
            FUTURE_PREFLIGHT_SEAL_PATH,
        ],
        "records": records,
        "owner_payload_binding": dict(owner),
        "model_binding_policy": policy.to_dict(),
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "verified_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "verified_serialization_witness_run_identity": (
            receipt.witness_run_identity
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
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "verified_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "verified_serialization_witness_run_identity": (
            receipt.witness_run_identity
        ),
    }
    seal = {**seal_body, "seal_fingerprint": fingerprint(seal_body)}
    atomic_json(seal_path, seal, mode=0o400)
    return validate_future_preflight_seal(
        root=root,
        expected_model_binding_policy=policy,
        expected_verified_witness_receipt=receipt,
        trusted_witness_store=trusted_witness_store,
        expected_seal_fingerprint=seal["seal_fingerprint"],
    )


def validate_future_preflight_seal(
    *,
    root: Path,
    expected_model_binding_policy: ModelBindingPolicy,
    expected_verified_witness_receipt: VerifiedSerializationWitnessReceipt,
    trusted_witness_store: TrustedSerializationWitnessStore,
    expected_seal_fingerprint: str,
) -> Mapping[str, Any]:
    """Reopen the seal, manifest, owner payload, and every covered file."""

    root = _root(root)
    policy = expected_model_binding_policy.validated()
    receipt = expected_verified_witness_receipt
    if not isinstance(receipt, VerifiedSerializationWitnessReceipt):
        raise FuturePreflightSealError("expected witness receipt is not verified")
    if not isinstance(trusted_witness_store, TrustedSerializationWitnessStore):
        raise FuturePreflightSealError(
            "future preflight requires the trusted witness store"
        )
    durable_receipt = trusted_witness_store.load_verified_receipt(
        receipt_identity=receipt.receipt_identity,
        witness_run_identity=receipt.witness_run_identity,
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if durable_receipt.to_dict() != receipt.to_dict():
        raise FuturePreflightSealError(
            "future preflight receipt differs from durable evidence"
        )
    require_sha256(
        expected_seal_fingerprint,
        "externally retained future preflight seal",
    )
    manifest_path = root / FUTURE_PREFLIGHT_MANIFEST_PATH
    seal_path = root / FUTURE_PREFLIGHT_SEAL_PATH
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
            "model_binding_policy_fingerprint",
            "verified_serialization_witness_receipt_identity",
            "verified_serialization_witness_run_identity",
            "seal_fingerprint",
        },
        "future preflight final seal",
    )
    seal_body = {
        key: value for key, value in seal.items() if key != "seal_fingerprint"
    }
    if (
        seal["schema_version"] != FUTURE_PREFLIGHT_SEAL_SCHEMA_VERSION
        or seal["seal_fingerprint"] != expected_seal_fingerprint
        or seal["manifest_relative_path"] != FUTURE_PREFLIGHT_MANIFEST_PATH
        or sha256_bytes(manifest_bytes) != seal["manifest_sha256"]
        or len(manifest_bytes) != seal["manifest_size"]
        or fingerprint(seal_body) != seal["seal_fingerprint"]
        or seal["model_binding_policy_fingerprint"]
        != policy.policy_fingerprint
        or seal["verified_serialization_witness_receipt_identity"]
        != receipt.receipt_identity
        or seal["verified_serialization_witness_run_identity"]
        != receipt.witness_run_identity
    ):
        raise FuturePreflightSealError(
            "future preflight final seal differs from manifest or authority"
        )
    require_exact_keys(
        manifest,
        {
            "schema_version",
            "construction",
            "excluded_publication_paths",
            "records",
            "owner_payload_binding",
            "model_binding_policy",
            "model_binding_policy_fingerprint",
            "verified_serialization_witness_receipt_identity",
            "verified_serialization_witness_run_identity",
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
        or manifest["construction"] != "non_self_referential_content_set_v2"
        or manifest["excluded_publication_paths"]
        != [FUTURE_PREFLIGHT_MANIFEST_PATH, FUTURE_PREFLIGHT_SEAL_PATH]
        or fingerprint(manifest_body) != manifest["manifest_fingerprint"]
        or manifest["manifest_fingerprint"] != seal["manifest_fingerprint"]
        or manifest["model_binding_policy"] != policy.to_dict()
        or manifest["model_binding_policy_fingerprint"]
        != policy.policy_fingerprint
        or manifest["verified_serialization_witness_receipt_identity"]
        != receipt.receipt_identity
        or manifest["verified_serialization_witness_run_identity"]
        != receipt.witness_run_identity
    ):
        raise FuturePreflightSealError(
            "future preflight content manifest changed"
        )
    records = manifest["records"]
    if not isinstance(records, list) or not records:
        raise FuturePreflightSealError("future manifest has no records")
    paths = [item.get("relative_path") for item in records]
    if (
        len(paths) != len(set(paths))
        or FUTURE_PREFLIGHT_MANIFEST_PATH in paths
        or FUTURE_PREFLIGHT_SEAL_PATH in paths
    ):
        raise FuturePreflightSealError(
            "future manifest is duplicate or self-referential"
        )
    for expected in records:
        require_exact_keys(
            expected,
            {"relative_path", "mode", "size", "sha256"},
            "future preflight content record",
        )
        if _observe_file(root, expected["relative_path"]) != expected:
            raise FuturePreflightSealError(
                f"future preflight covered file changed: {expected['relative_path']}"
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
    require_sha256(seal["seal_fingerprint"], "future preflight seal")
    return {
        "manifest_fingerprint": manifest["manifest_fingerprint"],
        "seal_fingerprint": seal["seal_fingerprint"],
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "verified_serialization_witness_receipt_identity": (
            receipt.receipt_identity
        ),
        "covered_paths": tuple(paths),
        "self_referential": False,
    }
