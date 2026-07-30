"""Owner authorization as the external trust root for candidate witness evidence.

The candidate witness store in ``admissible.capsule.serialization_witness`` is
self-anchoring by construction: it mints its own store anchor, run anchors,
evidence packs, receipts and tail.  An ordinary caller with write access to a
directory can therefore produce a completely fabricated but internally
self-consistent store.  None of that can be production authority, and this
module is where the missing external root lives.

The external root is the owner, not another hash this code generated.  The owner
holds a phrase that is never stored anywhere in the repository, and the expected
authorization digest is retained *outside* the preparation directory.  The
digest construction is a versioned successor to the native-canary construction
already used by ``admissible.delegated_gate.native_canary``:

    sha256(construction || 0x00 || phrase || 0x00 || canonical(payload))

No API key and no other user secret is introduced.  The phrase arrives only on
its dedicated descriptor (:func:`read_owner_phrase_from_descriptor`), is used
for exactly one comparison inside this module, and is never returned, logged,
fingerprinted on its own, persisted, or passed to the general controller, the
witness store or the model backend.

Trust ladder
------------

============================================  =====================
object                                         authority
============================================  =====================
``CandidateSerializationWitnessStore``         none
``CandidateSerializationWitnessPack``          none
``CandidateSerializationWitnessReceipt``       none
``OwnerAuthorizationPayload``                  none (a *request*)
``OwnerBoundVerifiedSerializationReceipt``     production pre-effect
============================================  =====================

Knowing every expected model, executable and network value is not authority
either: the payload binds them, but only the owner phrase can turn a payload
into an owner-bound receipt, and that receipt is consumable exactly once.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    fsync_directory,
    mode_type,
    require_exact_keys,
    require_git_oid,
    require_identifier,
    require_sha256,
    require_strict_int,
    sha256_bytes,
    strict_json_loads,
)
from admissible.capsule.execution_authority import (
    validate_component_identity_metadata,
)
from admissible.capsule.model_authority import ModelBindingPolicy
from admissible.capsule.owner_authority.layout import (
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
)
from admissible.capsule.preflight_seal import (
    OWNER_AUTHORIZATION_CONSUMED,
    OWNER_BOUND_READY_FOR_SINGLE_LAUNCH,
    RetainedPreparationSealIdentity,
    SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION,
    validate_future_preflight_seal,
    validate_preparation_root_identity,
)
from admissible.capsule.serialization_witness import (
    CandidateSerializationWitnessReceipt,
    CandidateSerializationWitnessStore,
    trusted_witness_verifier_identity,
)


OWNER_PAYLOAD_SCHEMA_VERSION = (
    "admissible_capsule_canary_owner_authorization_payload_v1"
)
OWNER_BOUND_RECEIPT_SCHEMA_VERSION = (
    "admissible_capsule_owner_bound_verified_serialization_receipt_v1"
)
OWNER_AUTHORIZATION_STATE_SCHEMA_VERSION = (
    "admissible_capsule_owner_authorization_state_v1"
)

#: Versioned successor to the native-canary owner digest construction.  The
#: construction label is inside the hashed material so a digest computed for one
#: construction can never satisfy another.
#:
#: This construction is **self-rooted** and therefore non-production: the same
#: caller who chooses the phrase can compute the digest.  It survives only for
#: the explicitly named non-production helpers in
#: ``admissible.capsule.owner_authorization_non_production``.  Production
#: payloads carry :data:`EXTERNAL_OWNER_DIGEST_CONSTRUCTION`, whose digest
#: additionally binds a root-generated authorization record identity the caller
#: never chooses.
OWNER_DIGEST_CONSTRUCTION = (
    "admissible_owner_phrase_nul_canonical_payload_sha256_v2"
)

#: The two constructions a payload may declare.  A payload declares which world
#: it belongs to; each world then requires its own construction exactly.
SUPPORTED_DIGEST_CONSTRUCTIONS = frozenset(
    {OWNER_DIGEST_CONSTRUCTION, EXTERNAL_OWNER_DIGEST_CONSTRUCTION}
)

#: The owner phrase may only be delivered on a dedicated descriptor.  This is
#: the environment variable name the future real launcher uses to pass it.
OWNER_PHRASE_DESCRIPTOR_ENV = "ADMISSIBLE_CAPSULE_OWNER_PHRASE_FD"

OWNER_PHRASE_MAX_BYTES = 4096
OWNER_PHRASE_MIN_BYTES = 8

#: Local ChatGPT login classifications.  All are decided from descriptor
#: metadata only; no credential byte is ever read, hashed or displayed.
LOGIN_PRESENT = "LOCAL_CHATGPT_LOGIN_PRESENT_METADATA_ONLY"
LOGIN_ABSENT = "LOCAL_CHATGPT_LOGIN_ABSENT"
LOGIN_REFUSED = "LOCAL_CHATGPT_LOGIN_REFUSED_NOT_PRIVATE_REGULAR_FILE"

_ZERO_RETRY_POLICY = MappingProxyType(
    {
        "schema_version": "admissible_capsule_zero_retry_zero_repair_policy_v1",
        "retries": 0,
        "repairs": 0,
        "launches_per_authorization": 1,
        "after_consumption": "NO_RETRY_NO_REPAIR_TERMINAL",
    }
)


class OwnerAuthorizationError(ValueError):
    """A classified refusal on the owner-authorization trust path."""

    def __init__(self, detail: str, *, classification: str = "OWNER_AUTHORIZATION_REFUSED"):
        self.classification = require_identifier(
            classification, "owner authorization failure classification"
        )
        super().__init__(f"{self.classification}: {detail}")


def zero_retry_policy() -> Mapping[str, Any]:
    """The fixed zero-retry, zero-repair policy bound into every payload."""

    return dict(_ZERO_RETRY_POLICY)


# ---------------------------------------------------------------------------
# Step 2 of the launch order: local login classification, metadata only
# ---------------------------------------------------------------------------


def classify_local_chatgpt_login(path: Path) -> dict[str, Any]:
    """Classify a local ChatGPT login from metadata without reading bytes.

    The file is opened ``O_RDONLY|O_NOFOLLOW`` purely to ``fstat`` it and is
    closed without a single ``read``.  Nothing derived from the contents --- not
    a length-bounded prefix, not a hash --- ever leaves this function.
    """

    if not isinstance(path, Path) or not path.is_absolute():
        raise OwnerAuthorizationError(
            "local login classification requires an absolute path"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return {
            "classification": LOGIN_ABSENT,
            "credential_bytes_read": 0,
            "credential_content_observed": False,
        }
    except OSError as error:
        raise OwnerAuthorizationError(
            "local login path is not an openable regular file",
            classification="OWNER_LOGIN_CLASSIFICATION_REFUSED",
        ) from error
    try:
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    classification = LOGIN_PRESENT
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or not 1 <= info.st_size <= 1024 * 1024
    ):
        classification = LOGIN_REFUSED
    return {
        "classification": classification,
        "file_type": mode_type(info.st_mode),
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": info.st_nlink,
        "owner_uid": info.st_uid,
        "size": info.st_size,
        "credential_bytes_read": 0,
        "credential_content_observed": False,
    }


# ---------------------------------------------------------------------------
# Step 4 of the launch order: the owner phrase, on its dedicated descriptor
# ---------------------------------------------------------------------------


def read_owner_phrase_from_descriptor(descriptor: int) -> str:
    """Read the owner phrase from its dedicated descriptor and nothing else.

    The descriptor must be a pipe, a socket or a regular file (which covers an
    anonymous ``memfd``).  A terminal or a character device is refused so the
    phrase can never be scraped from a shared console.  The caller of this
    function must discard the result immediately after
    :func:`authorize_owner_bound_serialization_receipt` returns; no other module
    ever receives it.
    """

    if isinstance(descriptor, bool) or not isinstance(descriptor, int):
        raise OwnerAuthorizationError("owner phrase descriptor must be an integer")
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise OwnerAuthorizationError(
            "owner phrase descriptor is not open",
            classification="OWNER_PHRASE_CHANNEL_REFUSED",
        ) from error
    if os.isatty(descriptor) or not (
        stat.S_ISFIFO(info.st_mode)
        or stat.S_ISSOCK(info.st_mode)
        or stat.S_ISREG(info.st_mode)
    ):
        raise OwnerAuthorizationError(
            "the owner phrase must arrive on a private pipe, socket or memfd",
            classification="OWNER_PHRASE_CHANNEL_REFUSED",
        )
    collected = bytearray()
    while len(collected) <= OWNER_PHRASE_MAX_BYTES:
        block = os.read(descriptor, OWNER_PHRASE_MAX_BYTES + 1 - len(collected))
        if not block:
            break
        collected.extend(block)
    if len(collected) > OWNER_PHRASE_MAX_BYTES:
        raise OwnerAuthorizationError(
            "owner phrase exceeds its byte bound",
            classification="OWNER_PHRASE_CHANNEL_REFUSED",
        )
    try:
        phrase = bytes(collected).decode("utf-8").strip("\r\n")
    except UnicodeDecodeError as error:
        raise OwnerAuthorizationError(
            "owner phrase is not UTF-8 text",
            classification="OWNER_PHRASE_CHANNEL_REFUSED",
        ) from error
    finally:
        for index in range(len(collected)):
            collected[index] = 0
    if not OWNER_PHRASE_MIN_BYTES <= len(phrase.encode("utf-8")) or "\x00" in phrase:
        raise OwnerAuthorizationError(
            "owner phrase is empty, too short, or contains NUL",
            classification="OWNER_PHRASE_CHANNEL_REFUSED",
        )
    return phrase


def owner_authorization_digest(*, phrase: str, payload_bytes: bytes) -> str:
    """The versioned canonical owner digest over the exact payload bytes."""

    if not isinstance(phrase, str) or not phrase:
        raise OwnerAuthorizationError("owner phrase must be non-empty text")
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise OwnerAuthorizationError("owner payload must be canonical bytes")
    return hashlib.sha256(
        OWNER_DIGEST_CONSTRUCTION.encode("utf-8")
        + b"\0"
        + phrase.encode("utf-8")
        + b"\0"
        + bytes(payload_bytes)
    ).hexdigest()


# ---------------------------------------------------------------------------
# The external owner payload
# ---------------------------------------------------------------------------

_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "digest_construction",
        "repository_canonical_path_sha256",
        "repository_head",
        "implementation_head",
        "run_id",
        "preparation_id",
        "preparation_root_identity",
        "candidate_store_root_identity",
        "candidate_store_anchor_fingerprint",
        "candidate_evidence_pack_fingerprint",
        "candidate_receipt_identity",
        "candidate_witness_run_identity",
        "candidate_witness_run_nonce",
        "candidate_store_tail_identity",
        "model_binding_policy",
        "model_binding_policy_fingerprint",
        "canonical_configuration_fingerprint",
        "codex_executable_identity",
        "codex_executable_sha256",
        "protocol_schema_identity",
        "boundary_launcher_identity",
        "destination_manifest_identity",
        "mission_fingerprint",
        "tool_authority_identity",
        "budgets",
        "preflight_manifest_fingerprint",
        "preflight_seal_fingerprint",
        "retained_seal_identity",
        "zero_retry_policy",
    }
)


@dataclass(frozen=True)
class OwnerAuthorizationPayload:
    """The canonical external payload an owner phrase authorizes.

    A payload is a *request*, never authority.  It exists so the owner signs one
    exact set of identities: change the store, the pack, the receipt, the tail,
    the policy, the preparation root, the run, the mission, the budgets, the
    seal or the retained seal identity and the digest no longer matches.
    """

    body: Mapping[str, Any]
    payload_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        repository_root: Path,
        repository_head: str,
        implementation_head: str,
        run_id: str,
        preparation_id: str,
        preparation_root_identity: Mapping[str, Any],
        candidate_store_root_identity: Mapping[str, Any],
        candidate_store_anchor_fingerprint: str,
        candidate_evidence_pack_fingerprint: str,
        candidate_receipt_identity: str,
        candidate_witness_run_identity: str,
        candidate_witness_run_nonce: str,
        candidate_store_tail_identity: str,
        model_binding_policy: ModelBindingPolicy,
        boundary_launcher_identity: Mapping[str, Any],
        destination_manifest_identity: str,
        mission_fingerprint: str,
        tool_authority_identity: str,
        budgets: Mapping[str, Any],
        preflight_manifest_fingerprint: str,
        preflight_seal_fingerprint: str,
        retained_seal_identity: str,
        digest_construction: str = EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    ) -> "OwnerAuthorizationPayload":
        policy = model_binding_policy.validated_canary()
        if digest_construction not in SUPPORTED_DIGEST_CONSTRUCTIONS:
            raise OwnerAuthorizationError(
                "owner payload digest construction is unsupported",
                classification="OWNER_PAYLOAD_INVALID",
            )
        if not isinstance(repository_root, Path) or not repository_root.is_absolute():
            raise OwnerAuthorizationError(
                "owner payload requires the absolute repository root"
            )
        body = {
            "schema_version": OWNER_PAYLOAD_SCHEMA_VERSION,
            "digest_construction": digest_construction,
            "repository_canonical_path_sha256": sha256_bytes(
                os.fsencode(os.fspath(repository_root.resolve()))
            ),
            "repository_head": repository_head,
            "implementation_head": implementation_head,
            "run_id": run_id,
            "preparation_id": preparation_id,
            "preparation_root_identity": dict(preparation_root_identity),
            "candidate_store_root_identity": dict(candidate_store_root_identity),
            "candidate_store_anchor_fingerprint": (
                candidate_store_anchor_fingerprint
            ),
            "candidate_evidence_pack_fingerprint": (
                candidate_evidence_pack_fingerprint
            ),
            "candidate_receipt_identity": candidate_receipt_identity,
            "candidate_witness_run_identity": candidate_witness_run_identity,
            "candidate_witness_run_nonce": candidate_witness_run_nonce,
            "candidate_store_tail_identity": candidate_store_tail_identity,
            "model_binding_policy": policy.to_dict(),
            "model_binding_policy_fingerprint": policy.policy_fingerprint,
            "canonical_configuration_fingerprint": (
                policy.configuration_fingerprint
            ),
            "codex_executable_identity": dict(policy.codex_executable_identity),
            "codex_executable_sha256": (
                policy.codex_executable_identity["sha256"]
            ),
            "protocol_schema_identity": policy.protocol_schema_identity,
            "boundary_launcher_identity": dict(boundary_launcher_identity),
            "destination_manifest_identity": destination_manifest_identity,
            "mission_fingerprint": mission_fingerprint,
            "tool_authority_identity": tool_authority_identity,
            "budgets": dict(budgets),
            "preflight_manifest_fingerprint": preflight_manifest_fingerprint,
            "preflight_seal_fingerprint": preflight_seal_fingerprint,
            "retained_seal_identity": retained_seal_identity,
            "zero_retry_policy": zero_retry_policy(),
        }
        return cls(
            body=MappingProxyType(body),
            payload_fingerprint=fingerprint(body),
        ).validated()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OwnerAuthorizationPayload":
        """Canonicalize an owner payload document read from outside this process."""

        if not isinstance(value, Mapping):
            raise OwnerAuthorizationError("owner payload is not an object")
        body = {key: item for key, item in value.items() if key != "payload_fingerprint"}
        supplied = value.get("payload_fingerprint")
        if supplied is not None and supplied != fingerprint(body):
            raise OwnerAuthorizationError(
                "owner payload fingerprint does not match its own bytes",
                classification="OWNER_PAYLOAD_INVALID",
            )
        return cls(
            body=MappingProxyType(dict(body)),
            payload_fingerprint=fingerprint(body),
        ).validated()

    def validated(self) -> "OwnerAuthorizationPayload":
        body = dict(self.body)
        require_exact_keys(body, set(_PAYLOAD_KEYS), "owner authorization payload")
        if (
            body["schema_version"] != OWNER_PAYLOAD_SCHEMA_VERSION
            or body["digest_construction"] not in SUPPORTED_DIGEST_CONSTRUCTIONS
        ):
            raise OwnerAuthorizationError(
                "owner payload schema or digest construction is unsupported",
                classification="OWNER_PAYLOAD_INVALID",
            )
        require_git_oid(body["repository_head"], "owner payload repository HEAD")
        require_git_oid(body["implementation_head"], "owner payload implementation HEAD")
        require_identifier(body["run_id"], "owner payload run")
        require_identifier(body["preparation_id"], "owner payload preparation")
        for key in (
            "repository_canonical_path_sha256",
            "candidate_store_anchor_fingerprint",
            "candidate_evidence_pack_fingerprint",
            "candidate_receipt_identity",
            "candidate_witness_run_nonce",
            "candidate_store_tail_identity",
            "model_binding_policy_fingerprint",
            "canonical_configuration_fingerprint",
            "codex_executable_sha256",
            "protocol_schema_identity",
            "destination_manifest_identity",
            "mission_fingerprint",
            "tool_authority_identity",
            "preflight_manifest_fingerprint",
            "preflight_seal_fingerprint",
            "retained_seal_identity",
        ):
            require_sha256(body[key], f"owner payload {key}")
        require_identifier(
            body["candidate_witness_run_identity"],
            "owner payload candidate witness run",
        )
        root_identity = validate_preparation_root_identity(
            body["preparation_root_identity"],
            "owner payload preparation root identity",
        )
        if (
            root_identity["run_id"] != body["run_id"]
            or root_identity["preparation_id"] != body["preparation_id"]
        ):
            raise OwnerAuthorizationError(
                "owner payload run or preparation differs from its root identity",
                classification="OWNER_PAYLOAD_INVALID",
            )
        _validate_store_root_identity(
            body["candidate_store_root_identity"],
            "owner payload candidate store root identity",
        )
        validate_component_identity_metadata(
            body["codex_executable_identity"],
            "owner payload Codex executable",
        )
        validate_component_identity_metadata(
            body["boundary_launcher_identity"],
            "owner payload boundary launcher",
        )
        policy = ModelBindingPolicy.from_dict(
            dict(body["model_binding_policy"])
        ).validated_canary()
        if (
            policy.policy_fingerprint != body["model_binding_policy_fingerprint"]
            or policy.configuration_fingerprint
            != body["canonical_configuration_fingerprint"]
            or dict(policy.codex_executable_identity)
            != dict(body["codex_executable_identity"])
            or policy.protocol_schema_identity != body["protocol_schema_identity"]
        ):
            raise OwnerAuthorizationError(
                "owner payload model policy is internally inconsistent",
                classification="OWNER_PAYLOAD_INVALID",
            )
        budgets = body["budgets"]
        if not isinstance(budgets, Mapping) or not budgets:
            raise OwnerAuthorizationError(
                "owner payload must bind explicit budgets",
                classification="OWNER_PAYLOAD_INVALID",
            )
        for name, limit in budgets.items():
            require_identifier(name, "owner payload budget name")
            require_strict_int(
                limit, f"owner payload budget {name}", minimum=0, maximum=2**62
            )
        if dict(body["zero_retry_policy"]) != zero_retry_policy():
            raise OwnerAuthorizationError(
                "owner payload must bind the zero-retry zero-repair policy",
                classification="OWNER_PAYLOAD_INVALID",
            )
        require_sha256(self.payload_fingerprint, "owner payload fingerprint")
        if fingerprint(body) != self.payload_fingerprint:
            raise OwnerAuthorizationError(
                "owner payload fingerprint mismatch",
                classification="OWNER_PAYLOAD_INVALID",
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            **dict(self.body),
            "payload_fingerprint": self.payload_fingerprint,
        }

    def canonical_payload_bytes(self) -> bytes:
        """The exact bytes the owner phrase authorizes: the body, not the wrapper."""

        return canonical_bytes(dict(self.body))

    @property
    def model_binding_policy(self) -> ModelBindingPolicy:
        return ModelBindingPolicy.from_dict(dict(self.body["model_binding_policy"]))


def _validate_store_root_identity(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerAuthorizationError(f"{label} is not an object")
    require_exact_keys(
        value,
        {"canonical_path_sha256", "device", "inode", "mode"},
        label,
    )
    require_sha256(value["canonical_path_sha256"], f"{label} canonical path")
    for key, maximum in (
        ("device", 2**63 - 1),
        ("inode", 2**63 - 1),
        ("mode", 0o7777),
    ):
        require_strict_int(value[key], f"{label} {key}", minimum=0, maximum=maximum)
    return dict(value)
