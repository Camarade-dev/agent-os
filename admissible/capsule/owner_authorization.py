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
OWNER_DIGEST_CONSTRUCTION = (
    "admissible_owner_phrase_nul_canonical_payload_sha256_v2"
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
    ) -> "OwnerAuthorizationPayload":
        policy = model_binding_policy.validated_canary()
        if not isinstance(repository_root, Path) or not repository_root.is_absolute():
            raise OwnerAuthorizationError(
                "owner payload requires the absolute repository root"
            )
        body = {
            "schema_version": OWNER_PAYLOAD_SCHEMA_VERSION,
            "digest_construction": OWNER_DIGEST_CONSTRUCTION,
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
            or body["digest_construction"] != OWNER_DIGEST_CONSTRUCTION
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


# ---------------------------------------------------------------------------
# One-time authorization state, retained outside the preparation
# ---------------------------------------------------------------------------


class OwnerAuthorizationStateStore:
    """External, one-time authorization state for one canary preparation.

    The state directory must be outside the preparation root, so a preparation
    can never mint its own authorization.  Consumption is a single
    ``O_CREAT|O_EXCL`` create under an exclusive lock: the second attempt with
    the same authorization loses, whatever the caller does.
    """

    def __init__(self, root: Path, *, preparation_root: Path):
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise OwnerAuthorizationError(
                "owner authorization state root must be absolute without aliases"
            )
        resolved_preparation = Path(preparation_root).resolve()
        candidate = root.parent.resolve() / root.name if root.parent.exists() else root
        if candidate == resolved_preparation or candidate.is_relative_to(
            resolved_preparation
        ):
            raise OwnerAuthorizationError(
                "owner authorization state must live outside the preparation root",
                classification="OWNER_AUTHORIZATION_STATE_REFUSED",
            )
        self.root = root
        created = not root.exists()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if created:
            fsync_directory(root.parent)
        self._consumed = root / "consumed"
        consumed_created = not self._consumed.exists()
        self._consumed.mkdir(exist_ok=True, mode=0o700)
        if consumed_created:
            fsync_directory(root)
        self._lock_path = root / "authorization.lock"
        self._state_path = root / "authorization-state.json"

    # -- expected digest retention ---------------------------------------

    def retain_expected_digest(
        self,
        *,
        expected_owner_authorization_digest: str,
        payload_fingerprint: str,
        retained_seal: RetainedPreparationSealIdentity,
    ) -> Mapping[str, Any]:
        """Retain the expected digest and seal identity before authorization."""

        require_sha256(
            expected_owner_authorization_digest,
            "expected owner authorization digest",
        )
        require_sha256(payload_fingerprint, "retained owner payload fingerprint")
        retained_seal.validated()
        body = {
            "schema_version": OWNER_AUTHORIZATION_STATE_SCHEMA_VERSION,
            "classification": SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION,
            "digest_construction": OWNER_DIGEST_CONSTRUCTION,
            "expected_owner_authorization_digest": (
                expected_owner_authorization_digest
            ),
            "payload_fingerprint": payload_fingerprint,
            "expected_seal_fingerprint": retained_seal.expected_seal_fingerprint,
            "expected_manifest_fingerprint": (
                retained_seal.expected_manifest_fingerprint
            ),
            "retained_seal_identity": retained_seal.retained_identity,
            "preparation_root_identity": dict(
                retained_seal.preparation_root_identity
            ),
        }
        record = {**body, "state_identity": fingerprint(body)}
        with self._locked():
            if self._state_path.exists():
                raise OwnerAuthorizationError(
                    "owner authorization state is already retained",
                    classification="OWNER_AUTHORIZATION_STATE_REFUSED",
                )
            descriptor = os.open(
                self._state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
            )
            try:
                encoded = canonical_bytes(record)
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(self.root)
        return record

    def retained_state(self) -> Mapping[str, Any]:
        try:
            value = strict_json_loads(
                self._state_path.read_bytes(),
                label="owner authorization state",
            )
        except (FileNotFoundError, ValueError) as error:
            raise OwnerAuthorizationError(
                "owner authorization state is missing or invalid",
                classification="OWNER_AUTHORIZATION_STATE_REFUSED",
            ) from error
        require_exact_keys(
            value,
            {
                "schema_version",
                "classification",
                "digest_construction",
                "expected_owner_authorization_digest",
                "payload_fingerprint",
                "expected_seal_fingerprint",
                "expected_manifest_fingerprint",
                "retained_seal_identity",
                "preparation_root_identity",
                "state_identity",
            },
            "owner authorization state",
        )
        body = {
            key: item for key, item in value.items() if key != "state_identity"
        }
        if (
            value["schema_version"] != OWNER_AUTHORIZATION_STATE_SCHEMA_VERSION
            or value["digest_construction"] != OWNER_DIGEST_CONSTRUCTION
            or value["classification"]
            != SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION
            or fingerprint(body) != value["state_identity"]
        ):
            raise OwnerAuthorizationError(
                "owner authorization state is not the retained sealed candidate",
                classification="OWNER_AUTHORIZATION_STATE_REFUSED",
            )
        for key in (
            "expected_owner_authorization_digest",
            "payload_fingerprint",
            "expected_seal_fingerprint",
            "expected_manifest_fingerprint",
            "retained_seal_identity",
        ):
            require_sha256(value[key], f"owner authorization state {key}")
        validate_preparation_root_identity(
            value["preparation_root_identity"],
            "owner authorization state preparation root",
        )
        return value

    # -- one-time consumption --------------------------------------------

    def _consumption_path(self, consumption_identity: str) -> Path:
        return self._consumed / f"{require_sha256(consumption_identity, 'consumption identity')}.json"

    def is_consumed(self, consumption_identity: str) -> bool:
        return self._consumption_path(consumption_identity).exists()

    def require_unconsumed(self, consumption_identity: str) -> None:
        if self.is_consumed(consumption_identity):
            raise OwnerAuthorizationError(
                "this owner authorization was already consumed",
                classification="OWNER_AUTHORIZATION_ALREADY_CONSUMED",
            )

    def consume_once(
        self,
        *,
        owner_bound_receipt: "OwnerBoundVerifiedSerializationReceipt",
    ) -> Mapping[str, Any]:
        """Atomically consume this authorization exactly once."""

        if not isinstance(
            owner_bound_receipt, OwnerBoundVerifiedSerializationReceipt
        ):
            raise OwnerAuthorizationError(
                "only an owner-bound receipt can consume an authorization"
            )
        state = self.retained_state()
        if (
            owner_bound_receipt.owner_payload_fingerprint
            != state["payload_fingerprint"]
            or owner_bound_receipt.owner_authorization_digest
            != state["expected_owner_authorization_digest"]
        ):
            raise OwnerAuthorizationError(
                "owner-bound receipt belongs to another retained authorization",
                classification="OWNER_AUTHORIZATION_STATE_REFUSED",
            )
        identity = owner_bound_receipt.authorization_consumption_identity
        record = {
            "schema_version": "admissible_capsule_owner_consumption_record_v1",
            "classification": OWNER_AUTHORIZATION_CONSUMED,
            "authorization_consumption_identity": identity,
            "owner_payload_fingerprint": (
                owner_bound_receipt.owner_payload_fingerprint
            ),
            "owner_bound_receipt_identity": owner_bound_receipt.receipt_identity,
            "run_id": owner_bound_receipt.run_id,
        }
        with self._locked():
            path = self._consumption_path(identity)
            try:
                descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
                )
            except FileExistsError as error:
                raise OwnerAuthorizationError(
                    "this owner authorization was already consumed",
                    classification="OWNER_AUTHORIZATION_ALREADY_CONSUMED",
                ) from error
            try:
                encoded = canonical_bytes(record)
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(self._consumed)
        return record

    def classification(self, consumption_identity: str | None = None) -> str:
        """Classify the preparation: no earlier state than owner-bound may run."""

        if consumption_identity is not None and self.is_consumed(
            consumption_identity
        ):
            return OWNER_AUTHORIZATION_CONSUMED
        if consumption_identity is not None:
            return OWNER_BOUND_READY_FOR_SINGLE_LAUNCH
        return SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION

    def _locked(self):
        return _ExclusiveLock(self._lock_path)


class _ExclusiveLock:
    def __init__(self, path: Path):
        self._path = path
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        self._descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._descriptor, fcntl.LOCK_EX)

    def __exit__(self, *_exc: object) -> None:
        assert self._descriptor is not None
        fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        os.close(self._descriptor)
        self._descriptor = None


# ---------------------------------------------------------------------------
# The one production authority
# ---------------------------------------------------------------------------

_OWNER_BOUND_CONSTRUCTION_TOKEN = object()

_OWNER_BOUND_KEYS = frozenset(
    {
        "schema_version",
        "trust_state",
        "candidate_witness_receipt",
        "candidate_witness_pack",
        "candidate_receipt_identity",
        "candidate_evidence_pack_fingerprint",
        "candidate_store_anchor_fingerprint",
        "candidate_store_tail_identity",
        "owner_payload_fingerprint",
        "owner_authorization_digest",
        "owner_digest_construction",
        "boundary_launcher_identity",
        "preparation_root_identity",
        "preflight_seal_fingerprint",
        "retained_seal_identity",
        "model_binding_policy",
        "model_binding_policy_fingerprint",
        "run_id",
        "authorization_consumption_identity",
    }
)


class OwnerBoundVerifiedSerializationReceipt:
    """The only object that may authorize a production capsule effect.

    It can be created solely by
    :func:`authorize_owner_bound_serialization_receipt`, and only after the
    owner phrase has verified the exact canonical payload that binds this store,
    this pack, this receipt, this tail, this policy, this preparation root and
    this run.  Constructor privacy is *not* the security boundary: the security
    boundary is that every field is re-derived from reopened durable evidence
    and from an external digest this code cannot compute without the phrase.
    """

    __slots__ = ("_body",)

    def __init__(self, body: Mapping[str, Any], token: object):
        if token is not _OWNER_BOUND_CONSTRUCTION_TOKEN:
            raise OwnerAuthorizationError(
                "owner-bound receipts may only be created by the authorization path",
                classification="OWNER_BOUND_RECEIPT_CONSTRUCTION_REFUSED",
            )
        object.__setattr__(self, "_body", MappingProxyType(dict(body)))

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("OwnerBoundVerifiedSerializationReceipt is immutable")

    def __delattr__(self, name: str) -> None:  # pragma: no cover
        raise AttributeError("OwnerBoundVerifiedSerializationReceipt is immutable")

    @property
    def receipt_identity(self) -> str:
        return self._body["owner_bound_receipt_identity"]

    @property
    def trust_state(self) -> str:
        return self._body["trust_state"]

    @property
    def candidate_receipt_identity(self) -> str:
        return self._body["candidate_receipt_identity"]

    @property
    def candidate_witness_run_identity(self) -> str:
        return self._body["candidate_witness_receipt"]["witness_run_identity"]

    @property
    def candidate_evidence_pack_fingerprint(self) -> str:
        return self._body["candidate_evidence_pack_fingerprint"]

    @property
    def candidate_store_anchor_fingerprint(self) -> str:
        return self._body["candidate_store_anchor_fingerprint"]

    @property
    def candidate_store_tail_identity(self) -> str:
        return self._body["candidate_store_tail_identity"]

    @property
    def owner_payload_fingerprint(self) -> str:
        return self._body["owner_payload_fingerprint"]

    @property
    def owner_authorization_digest(self) -> str:
        return self._body["owner_authorization_digest"]

    @property
    def boundary_launcher_identity(self) -> Mapping[str, Any]:
        return dict(self._body["boundary_launcher_identity"])

    @property
    def preparation_root_identity(self) -> Mapping[str, Any]:
        return dict(self._body["preparation_root_identity"])

    @property
    def preflight_seal_fingerprint(self) -> str:
        return self._body["preflight_seal_fingerprint"]

    @property
    def model_binding_policy_fingerprint(self) -> str:
        return self._body["model_binding_policy_fingerprint"]

    @property
    def run_id(self) -> str:
        return self._body["run_id"]

    @property
    def authorization_consumption_identity(self) -> str:
        return self._body["authorization_consumption_identity"]

    def candidate_witness_receipt(self) -> Mapping[str, Any]:
        return dict(self._body["candidate_witness_receipt"])

    def candidate_witness_pack(self) -> Mapping[str, Any]:
        return dict(self._body["candidate_witness_pack"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self._body)

    def validated(self) -> "OwnerBoundVerifiedSerializationReceipt":
        body = dict(self._body)
        require_exact_keys(
            body,
            set(_OWNER_BOUND_KEYS) | {"owner_bound_receipt_identity"},
            "owner-bound serialization receipt",
        )
        if (
            body["schema_version"] != OWNER_BOUND_RECEIPT_SCHEMA_VERSION
            or body["trust_state"] != "OWNER_BOUND_PRODUCTION_AUTHORITY"
            or body["owner_digest_construction"] != OWNER_DIGEST_CONSTRUCTION
        ):
            raise OwnerAuthorizationError(
                "owner-bound receipt schema or trust state is unsupported",
                classification="OWNER_BOUND_RECEIPT_INVALID",
            )
        identity_body = {
            key: item
            for key, item in body.items()
            if key != "owner_bound_receipt_identity"
        }
        if fingerprint(identity_body) != body["owner_bound_receipt_identity"]:
            raise OwnerAuthorizationError(
                "owner-bound receipt fingerprint mismatch",
                classification="OWNER_BOUND_RECEIPT_INVALID",
            )
        return self


def _consumption_identity(
    *,
    payload: OwnerAuthorizationPayload,
    digest: str,
    tail_identity: str,
) -> str:
    return fingerprint(
        {
            "schema_version": "admissible_capsule_owner_consumption_identity_v1",
            "owner_payload_fingerprint": payload.payload_fingerprint,
            "owner_authorization_digest": digest,
            "candidate_store_tail_identity": tail_identity,
            "run_id": payload.body["run_id"],
            "single_use": True,
        }
    )


def authorize_owner_bound_serialization_receipt(
    *,
    owner_payload: OwnerAuthorizationPayload | Mapping[str, Any],
    owner_phrase_descriptor: int,
    authorization_state: OwnerAuthorizationStateStore,
    candidate_witness_store: CandidateSerializationWitnessStore,
    candidate_witness_receipt: CandidateSerializationWitnessReceipt,
    preparation_root: Path,
    retained_seal_identity: RetainedPreparationSealIdentity,
    boundary_launcher_identity: Mapping[str, Any],
) -> OwnerBoundVerifiedSerializationReceipt:
    """Create the one production authority, in the one authorized order.

    1. canonicalize the owner payload;
    2. verify the owner phrase against the exact canonical payload bytes;
    3. reopen the candidate store and its evidence pack;
    4. independently revalidate every real-binary witness claim;
    5. verify the current candidate tail;
    6. verify the fixed canary model policy;
    7. verify the preparation root and its closed-world seal;
    8. verify the authorization is still unconsumed.

    Any deterministic local failure among 1, 3-8 refuses *without* consuming the
    authorization.  Consumption is a separate explicit step performed by the
    production launch path.
    """

    if not isinstance(authorization_state, OwnerAuthorizationStateStore):
        raise OwnerAuthorizationError(
            "owner authorization requires the external state store"
        )
    if not isinstance(candidate_witness_store, CandidateSerializationWitnessStore):
        raise OwnerAuthorizationError(
            "owner authorization requires the candidate witness store"
        )
    if not isinstance(
        candidate_witness_receipt, CandidateSerializationWitnessReceipt
    ):
        raise OwnerAuthorizationError(
            "owner authorization requires an opaque candidate receipt"
        )
    if not isinstance(retained_seal_identity, RetainedPreparationSealIdentity):
        raise OwnerAuthorizationError(
            "owner authorization requires the externally retained seal identity"
        )

    # 1. canonicalize the payload
    payload = (
        owner_payload.validated()
        if isinstance(owner_payload, OwnerAuthorizationPayload)
        else OwnerAuthorizationPayload.from_dict(owner_payload)
    )
    retained = retained_seal_identity.validated()
    state = authorization_state.retained_state()
    if (
        state["payload_fingerprint"] != payload.payload_fingerprint
        or state["retained_seal_identity"] != retained.retained_identity
        or state["expected_seal_fingerprint"]
        != payload.body["preflight_seal_fingerprint"]
        or state["expected_manifest_fingerprint"]
        != payload.body["preflight_manifest_fingerprint"]
        or dict(state["preparation_root_identity"])
        != dict(payload.body["preparation_root_identity"])
    ):
        raise OwnerAuthorizationError(
            "retained authorization state does not bind this owner payload",
            classification="OWNER_PAYLOAD_NOT_RETAINED",
        )
    if payload.body["retained_seal_identity"] != retained.retained_identity:
        raise OwnerAuthorizationError(
            "owner payload does not bind the externally retained seal identity",
            classification="OWNER_PAYLOAD_NOT_RETAINED",
        )

    # 2. the owner phrase verifies the exact payload; it never leaves this scope
    phrase = read_owner_phrase_from_descriptor(owner_phrase_descriptor)
    try:
        observed = owner_authorization_digest(
            phrase=phrase,
            payload_bytes=payload.canonical_payload_bytes(),
        )
    finally:
        del phrase
    if not hmac.compare_digest(
        observed, state["expected_owner_authorization_digest"]
    ):
        raise OwnerAuthorizationError(
            "the owner phrase does not authorize this exact payload",
            classification="OWNER_PHRASE_REFUSED",
        )

    # 3. reopen the candidate store and pack
    policy = payload.model_binding_policy.validated_canary()
    bundle = candidate_witness_store.load_candidate_evidence(
        receipt_identity=candidate_witness_receipt.receipt_identity,
        witness_run_identity=candidate_witness_receipt.witness_run_identity,
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if bundle.receipt.to_dict() != candidate_witness_receipt.to_dict():
        raise OwnerAuthorizationError(
            "candidate receipt differs from reopened durable evidence",
            classification="OWNER_CANDIDATE_EVIDENCE_CHANGED",
        )

    # 4. independently revalidate the real-binary witness evidence
    pack = bundle.pack.revalidated(
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )

    # the owner payload must name this exact store, pack, receipt and run
    if (
        payload.body["candidate_receipt_identity"]
        != bundle.receipt.receipt_identity
        or payload.body["candidate_witness_run_identity"]
        != bundle.receipt.witness_run_identity
        or payload.body["candidate_witness_run_nonce"]
        != bundle.receipt.witness_run_nonce
        or payload.body["candidate_evidence_pack_fingerprint"]
        != pack.evidence_pack_fingerprint
        or payload.body["candidate_store_anchor_fingerprint"]
        != bundle.store_anchor_fingerprint
        or dict(payload.body["candidate_store_root_identity"])
        != dict(bundle.store_root_identity)
    ):
        raise OwnerAuthorizationError(
            "owner payload authorizes another candidate store, pack or run",
            classification="OWNER_PAYLOAD_TARGETS_ANOTHER_WITNESS",
        )

    # 5. the current tail must still be the authorized one
    if payload.body["candidate_store_tail_identity"] != bundle.tail_identity:
        raise OwnerAuthorizationError(
            "candidate store tail advanced after the owner payload was built",
            classification="OWNER_CANDIDATE_TAIL_ADVANCED",
        )

    # 6. the fixed canary policy
    if (
        policy.policy_fingerprint
        != bundle.receipt.model_binding_policy_fingerprint
        or policy.policy_fingerprint
        != payload.body["model_binding_policy_fingerprint"]
        or trusted_witness_verifier_identity()
        != bundle.receipt.to_dict()["trusted_witness_verifier_identity"]
    ):
        raise OwnerAuthorizationError(
            "owner payload model policy differs from the candidate evidence",
            classification="OWNER_PAYLOAD_TARGETS_ANOTHER_POLICY",
        )

    # 7. the preparation root and its closed-world seal
    sealed = validate_future_preflight_seal(
        root=preparation_root,
        expected_model_binding_policy=policy,
        expected_candidate_witness_receipt=bundle.receipt,
        candidate_witness_store=candidate_witness_store,
        retained_seal_identity=retained,
    )
    if (
        sealed["seal_fingerprint"] != payload.body["preflight_seal_fingerprint"]
        or sealed["manifest_fingerprint"]
        != payload.body["preflight_manifest_fingerprint"]
        or dict(sealed["preparation_root_identity"])
        != dict(payload.body["preparation_root_identity"])
    ):
        raise OwnerAuthorizationError(
            "owner payload authorizes another preparation root or seal",
            classification="OWNER_PAYLOAD_TARGETS_ANOTHER_PREPARATION",
        )
    launcher = validate_component_identity_metadata(
        boundary_launcher_identity,
        "owner-bound boundary launcher",
    )
    if dict(launcher) != dict(payload.body["boundary_launcher_identity"]):
        raise OwnerAuthorizationError(
            "owner payload authorizes another boundary launcher",
            classification="OWNER_PAYLOAD_TARGETS_ANOTHER_LAUNCHER",
        )

    # 8. the authorization must still be unconsumed
    consumption_identity = _consumption_identity(
        payload=payload,
        digest=observed,
        tail_identity=bundle.tail_identity,
    )
    authorization_state.require_unconsumed(consumption_identity)

    body = {
        "schema_version": OWNER_BOUND_RECEIPT_SCHEMA_VERSION,
        "trust_state": "OWNER_BOUND_PRODUCTION_AUTHORITY",
        "candidate_witness_receipt": bundle.receipt.to_dict(),
        "candidate_witness_pack": pack.to_dict(),
        "candidate_receipt_identity": bundle.receipt.receipt_identity,
        "candidate_evidence_pack_fingerprint": pack.evidence_pack_fingerprint,
        "candidate_store_anchor_fingerprint": bundle.store_anchor_fingerprint,
        "candidate_store_tail_identity": bundle.tail_identity,
        "owner_payload_fingerprint": payload.payload_fingerprint,
        "owner_authorization_digest": observed,
        "owner_digest_construction": OWNER_DIGEST_CONSTRUCTION,
        "boundary_launcher_identity": dict(launcher),
        "preparation_root_identity": dict(sealed["preparation_root_identity"]),
        "preflight_seal_fingerprint": sealed["seal_fingerprint"],
        "retained_seal_identity": retained.retained_identity,
        "model_binding_policy": policy.to_dict(),
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "run_id": payload.body["run_id"],
        "authorization_consumption_identity": consumption_identity,
    }
    return OwnerBoundVerifiedSerializationReceipt(
        {**body, "owner_bound_receipt_identity": fingerprint(body)},
        _OWNER_BOUND_CONSTRUCTION_TOKEN,
    ).validated()


def revalidate_owner_bound_receipt(
    *,
    owner_bound_receipt: OwnerBoundVerifiedSerializationReceipt,
    candidate_witness_store: CandidateSerializationWitnessStore,
    authorization_state: OwnerAuthorizationStateStore,
    preparation_root: Path,
    retained_seal_identity: RetainedPreparationSealIdentity,
    expected_model_binding_policy: ModelBindingPolicy,
) -> Mapping[str, Any]:
    """Re-check an owner-bound receipt before every effect, refusing drift.

    This is the pre-effect gate.  It refuses when the candidate tail advanced,
    the candidate evidence changed, the preparation root changed, the policy
    differs, a fresh fabricated store was substituted, or the authorization was
    already consumed.
    """

    if not isinstance(
        owner_bound_receipt, OwnerBoundVerifiedSerializationReceipt
    ):
        raise OwnerAuthorizationError(
            "the production pre-effect gate requires an owner-bound receipt",
            classification="OWNER_BINDING_ABSENT",
        )
    receipt = owner_bound_receipt.validated()
    policy = expected_model_binding_policy.validated_canary()
    if policy.policy_fingerprint != receipt.model_binding_policy_fingerprint:
        raise OwnerAuthorizationError(
            "owner-bound receipt targets another model policy",
            classification="OWNER_BINDING_TARGETS_ANOTHER_POLICY",
        )
    retained = retained_seal_identity.validated()
    if retained.retained_identity != receipt.to_dict()["retained_seal_identity"]:
        raise OwnerAuthorizationError(
            "owner-bound receipt targets another retained seal identity",
            classification="OWNER_BINDING_TARGETS_ANOTHER_PREPARATION",
        )
    bundle = candidate_witness_store.load_candidate_evidence(
        receipt_identity=receipt.candidate_receipt_identity,
        witness_run_identity=receipt.candidate_witness_run_identity,
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if bundle.receipt.to_dict() != receipt.candidate_witness_receipt():
        raise OwnerAuthorizationError(
            "candidate witness evidence changed after owner authorization",
            classification="OWNER_CANDIDATE_EVIDENCE_CHANGED",
        )
    pack = bundle.pack.revalidated(
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if pack.to_dict() != receipt.candidate_witness_pack():
        raise OwnerAuthorizationError(
            "candidate witness pack changed after owner authorization",
            classification="OWNER_CANDIDATE_EVIDENCE_CHANGED",
        )
    if bundle.store_anchor_fingerprint != receipt.candidate_store_anchor_fingerprint:
        raise OwnerAuthorizationError(
            "a different candidate store was substituted after authorization",
            classification="OWNER_BINDING_TARGETS_ANOTHER_STORE",
        )
    if bundle.tail_identity != receipt.candidate_store_tail_identity:
        raise OwnerAuthorizationError(
            "candidate store tail advanced after owner authorization",
            classification="OWNER_CANDIDATE_TAIL_ADVANCED",
        )
    sealed = validate_future_preflight_seal(
        root=preparation_root,
        expected_model_binding_policy=policy,
        expected_candidate_witness_receipt=bundle.receipt,
        candidate_witness_store=candidate_witness_store,
        retained_seal_identity=retained,
    )
    if (
        sealed["seal_fingerprint"] != receipt.preflight_seal_fingerprint
        or dict(sealed["preparation_root_identity"])
        != dict(receipt.preparation_root_identity)
    ):
        raise OwnerAuthorizationError(
            "the preparation root or seal changed after owner authorization",
            classification="OWNER_PREPARATION_ROOT_CHANGED",
        )
    state = authorization_state.retained_state()
    if (
        state["payload_fingerprint"] != receipt.owner_payload_fingerprint
        or state["expected_owner_authorization_digest"]
        != receipt.owner_authorization_digest
    ):
        raise OwnerAuthorizationError(
            "owner-bound receipt belongs to another retained authorization",
            classification="OWNER_AUTHORIZATION_STATE_REFUSED",
        )
    return {
        "classification": authorization_state.classification(
            receipt.authorization_consumption_identity
        ),
        "owner_bound_receipt_identity": receipt.receipt_identity,
        "candidate_store_tail_identity": bundle.tail_identity,
        "preflight_seal_fingerprint": sealed["seal_fingerprint"],
    }
