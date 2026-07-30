"""Pending-authorization records, the owner digest, and the signed receipt.

Three facts about this module carry the repair:

1. The owner digest binds a **root-generated** authorization record identity.
   An ordinary caller who knows the phrase and the payload still cannot compute
   the expected digest before the privileged provisioner has chosen that
   identity, and cannot make the broker use a different one.
2. A pending-authorization record is *described* here but only ever *written*
   by the privileged provisioner into root-owned state.  No function in this
   module writes one, and nothing an ordinary process can call does either.
3. A receipt is authority only with a valid Ed25519 signature over its exact
   canonical payload, verified against the public key of an attested
   root-owned installation.  Every field the pre-effect gate needs is inside
   the signed bytes.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    strict_json_loads,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallation,
    validate_file_identity,
)
from admissible.capsule.owner_authority.layout import (
    BROKER_PROTOCOL_VERSION,
    CONSUMED_LAUNCH_COMMITTED,
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    OwnerAuthorityError,
    PENDING_AUTHORIZATION_SCHEMA_VERSION,
    RECEIPT_SIGNATURE_CONSTRUCTION,
    SIGNED_RECEIPT_SCHEMA_VERSION,
)
from admissible.capsule.owner_authority.signing import verify_signature

#: Bytes of root-generated entropy behind every authorization record identity.
AUTHORIZATION_RECORD_ID_BYTES = 32

_PENDING_KEYS = frozenset(
    {
        "schema_version",
        "authorization_record_id",
        "installation_id",
        "installation_identity",
        "digest_construction",
        "expected_owner_authorization_digest",
        "owner_payload",
        "owner_payload_fingerprint",
        "launches_authorized",
        "retries_authorized",
        "repairs_authorized",
        "record_identity",
    }
)

_RECEIPT_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "broker_protocol",
        "signature_construction",
        "digest_construction",
        "installation_id",
        "installation_identity",
        "signing_key_fingerprint",
        "authorization_record_id",
        "authorization_record_identity",
        "owner_payload",
        "owner_payload_fingerprint",
        "authorization_consumption_identity",
        "consumption_state",
        "consumption_record_identity",
        "launches_authorized",
        "retries_authorized",
        "repairs_authorized",
        "broker_terminal_evidence",
    }
)

_TERMINAL_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "commit_rule",
        "observed_state_sequence",
        "consumption_marker_identity",
        "cryptographic_executable_identity",
        "broker_protocol",
        "peer_uid",
    }
)


class OwnerAuthorityRecordError(OwnerAuthorityError):
    """A refusal while reading or validating an owner-authority record."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_RECORD_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def new_authorization_record_id() -> str:
    """Root-generated, unpredictable identity for one pending authorization."""

    return os.urandom(AUTHORIZATION_RECORD_ID_BYTES).hex()


def require_authorization_record_id(value: Any, label: str) -> str:
    identity = require_identifier(value, label)
    if len(identity) != AUTHORIZATION_RECORD_ID_BYTES * 2 or any(
        character not in "0123456789abcdef" for character in identity
    ):
        raise OwnerAuthorityRecordError(
            f"{label} is not a root-generated authorization record identity"
        )
    return identity


def external_owner_authorization_digest(
    *,
    phrase: str,
    payload_bytes: bytes,
    authorization_record_id: str,
) -> str:
    """The externally rooted owner digest.

    Binding ``authorization_record_id`` --- 32 bytes chosen by the privileged
    provisioner --- is what makes a caller-precomputed digest useless: the
    caller does not choose it, cannot predict it, and cannot make the broker
    verify against another one.
    """

    if not isinstance(phrase, str) or not phrase:
        raise OwnerAuthorityRecordError("owner phrase must be non-empty text")
    if not isinstance(payload_bytes, (bytes, bytearray)) or not payload_bytes:
        raise OwnerAuthorityRecordError("owner payload must be canonical bytes")
    record_id = require_authorization_record_id(
        authorization_record_id, "authorization record id"
    )
    return hashlib.sha256(
        EXTERNAL_OWNER_DIGEST_CONSTRUCTION.encode("utf-8")
        + b"\0"
        + phrase.encode("utf-8")
        + b"\0"
        + bytes(payload_bytes)
        + b"\0"
        + record_id.encode("utf-8")
    ).hexdigest()


def authorization_consumption_identity(
    *,
    authorization_record_id: str,
    owner_payload_fingerprint: str,
    installation_identity: str,
) -> str:
    """The one-time consumption identity for exactly one launch."""

    return fingerprint(
        {
            "schema_version": (
                "admissible_owner_authority_consumption_identity_v1"
            ),
            "authorization_record_id": require_authorization_record_id(
                authorization_record_id, "authorization record id"
            ),
            "owner_payload_fingerprint": require_sha256(
                owner_payload_fingerprint, "owner payload fingerprint"
            ),
            "installation_identity": require_sha256(
                installation_identity, "installation identity"
            ),
            "launches_authorized": 1,
        }
    )


def build_pending_authorization_record(
    *,
    authorization_record_id: str,
    installation: OwnerAuthorityInstallation,
    expected_owner_authorization_digest: str,
    owner_payload: Mapping[str, Any],
    owner_payload_fingerprint: str,
) -> dict[str, Any]:
    """Build the pending-authorization body written by the root provisioner."""

    body = {
        "schema_version": PENDING_AUTHORIZATION_SCHEMA_VERSION,
        "authorization_record_id": require_authorization_record_id(
            authorization_record_id, "authorization record id"
        ),
        "installation_id": installation.installation_id,
        "installation_identity": installation.installation_identity,
        "digest_construction": EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
        "expected_owner_authorization_digest": require_sha256(
            expected_owner_authorization_digest,
            "expected owner authorization digest",
        ),
        "owner_payload": dict(owner_payload),
        "owner_payload_fingerprint": require_sha256(
            owner_payload_fingerprint, "owner payload fingerprint"
        ),
        "launches_authorized": 1,
        "retries_authorized": 0,
        "repairs_authorized": 0,
    }
    return {**body, "record_identity": fingerprint(body)}


def validate_pending_authorization_record(
    value: Any, label: str = "pending authorization record"
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerAuthorityRecordError(f"{label} is not an object")
    record = dict(value)
    require_exact_keys(record, set(_PENDING_KEYS), label)
    if record["schema_version"] != PENDING_AUTHORIZATION_SCHEMA_VERSION:
        raise OwnerAuthorityRecordError(f"unsupported {label} schema")
    if record["digest_construction"] != EXTERNAL_OWNER_DIGEST_CONSTRUCTION:
        raise OwnerAuthorityRecordError(
            f"{label} does not use the external owner digest construction"
        )
    require_authorization_record_id(
        record["authorization_record_id"], f"{label} authorization record id"
    )
    require_identifier(record["installation_id"], f"{label} installation id")
    for key in (
        "installation_identity",
        "expected_owner_authorization_digest",
        "owner_payload_fingerprint",
        "record_identity",
    ):
        require_sha256(record[key], f"{label} {key}")
    if not isinstance(record["owner_payload"], Mapping):
        raise OwnerAuthorityRecordError(f"{label} owner payload is not an object")
    for key, expected in (
        ("launches_authorized", 1),
        ("retries_authorized", 0),
        ("repairs_authorized", 0),
    ):
        require_strict_int(record[key], f"{label} {key}", minimum=0, maximum=1)
        if record[key] != expected:
            raise OwnerAuthorityRecordError(
                f"{label} must authorize exactly one launch, zero retries and "
                "zero repairs"
            )
    body = {key: item for key, item in record.items() if key != "record_identity"}
    if fingerprint(body) != record["record_identity"]:
        raise OwnerAuthorityRecordError(
            f"{label} fingerprint mismatch",
            classification="OWNER_AUTHORITY_RECORD_INVALID",
        )
    return record


def read_pending_authorization_record(path: Path) -> dict[str, Any]:
    """Read and validate a pending record from root-owned state."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise OwnerAuthorityRecordError(
            "the pending authorization record is unreadable",
            classification="OWNER_AUTHORITY_AUTHORIZATION_ABSENT",
        ) from error
    record = strict_json_loads(raw, label="pending authorization record")
    if canonical_bytes(record) != raw:
        raise OwnerAuthorityRecordError(
            "the pending authorization record is not in canonical form",
            classification="OWNER_AUTHORITY_RECORD_INVALID",
        )
    return validate_pending_authorization_record(record)


# ---------------------------------------------------------------------------
# The broker-signed production receipt
# ---------------------------------------------------------------------------


def build_receipt_payload(
    *,
    installation: OwnerAuthorityInstallation,
    pending: Mapping[str, Any],
    consumption_identity: str,
    consumption_record_identity: str,
    terminal_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """The exact bytes the broker signs.  Broker use only."""

    record = validate_pending_authorization_record(pending)
    return {
        "schema_version": SIGNED_RECEIPT_SCHEMA_VERSION,
        "broker_protocol": BROKER_PROTOCOL_VERSION,
        "signature_construction": RECEIPT_SIGNATURE_CONSTRUCTION,
        "digest_construction": EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
        "installation_id": installation.installation_id,
        "installation_identity": installation.installation_identity,
        "signing_key_fingerprint": installation.signing_key_fingerprint,
        "authorization_record_id": record["authorization_record_id"],
        "authorization_record_identity": record["record_identity"],
        "owner_payload": dict(record["owner_payload"]),
        "owner_payload_fingerprint": record["owner_payload_fingerprint"],
        "authorization_consumption_identity": require_sha256(
            consumption_identity, "authorization consumption identity"
        ),
        "consumption_state": CONSUMED_LAUNCH_COMMITTED,
        "consumption_record_identity": require_sha256(
            consumption_record_identity, "consumption record identity"
        ),
        "launches_authorized": 1,
        "retries_authorized": 0,
        "repairs_authorized": 0,
        "broker_terminal_evidence": dict(terminal_evidence),
    }


def validate_terminal_evidence(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerAuthorityRecordError(f"{label} is not an object")
    evidence = dict(value)
    require_exact_keys(evidence, set(_TERMINAL_EVIDENCE_KEYS), label)
    if evidence["broker_protocol"] != BROKER_PROTOCOL_VERSION:
        raise OwnerAuthorityRecordError(f"{label} names another broker protocol")
    if evidence["commit_rule"] != (
        "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
    ):
        raise OwnerAuthorityRecordError(
            f"{label} does not attest the fail-closed commit rule"
        )
    sequence = evidence["observed_state_sequence"]
    if not isinstance(sequence, list) or not sequence:
        raise OwnerAuthorityRecordError(f"{label} has no observed state sequence")
    validate_file_identity(
        evidence["consumption_marker_identity"],
        f"{label} consumption marker identity",
    )
    require_strict_int(
        evidence["peer_uid"], f"{label} peer uid", minimum=0, maximum=2**31 - 1
    )
    return evidence


@dataclass(frozen=True)
class SignedOwnerAuthorizationReceipt:
    """A broker-signed, single-launch production authorization.

    Unlike the receipt it replaces, this object carries no authority of its own
    and cannot be forged by reconstructing its fields: authority is the Ed25519
    signature over :meth:`signed_bytes`, verifiable only against the public key
    of an attested root-owned installation.
    """

    payload: Mapping[str, Any]
    signature: bytes
    receipt_identity: str

    @classmethod
    def create(
        cls, *, payload: Mapping[str, Any], signature: bytes
    ) -> "SignedOwnerAuthorizationReceipt":
        body = dict(payload)
        return cls(
            payload=MappingProxyType(body),
            signature=bytes(signature),
            receipt_identity=fingerprint(body),
        ).structurally_validated()

    @classmethod
    def from_dict(cls, value: Any) -> "SignedOwnerAuthorizationReceipt":
        if not isinstance(value, Mapping):
            raise OwnerAuthorityRecordError("signed receipt is not an object")
        require_exact_keys(
            dict(value),
            {"payload", "signature_hex", "receipt_identity"},
            "signed owner authorization receipt",
        )
        signature_hex = value["signature_hex"]
        if not isinstance(signature_hex, str) or len(signature_hex) != 128:
            raise OwnerAuthorityRecordError(
                "signed receipt signature is not an Ed25519 signature"
            )
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError as error:
            raise OwnerAuthorityRecordError(
                "signed receipt signature is not hexadecimal"
            ) from error
        receipt = cls(
            payload=MappingProxyType(dict(value["payload"])),
            signature=signature,
            receipt_identity=value["receipt_identity"],
        ).structurally_validated()
        if fingerprint(dict(receipt.payload)) != receipt.receipt_identity:
            raise OwnerAuthorityRecordError(
                "signed receipt identity does not match its payload",
                classification="OWNER_AUTHORITY_RECEIPT_INVALID",
            )
        return receipt

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": dict(self.payload),
            "signature_hex": self.signature.hex(),
            "receipt_identity": self.receipt_identity,
        }

    def signed_bytes(self) -> bytes:
        """The exact canonical bytes covered by the signature."""

        return canonical_bytes(dict(self.payload))

    # -- accessors used by the production gate ---------------------------

    @property
    def installation_identity(self) -> str:
        return self.payload["installation_identity"]

    @property
    def authorization_record_id(self) -> str:
        return self.payload["authorization_record_id"]

    @property
    def owner_payload(self) -> Mapping[str, Any]:
        return dict(self.payload["owner_payload"])

    @property
    def owner_payload_fingerprint(self) -> str:
        return self.payload["owner_payload_fingerprint"]

    @property
    def authorization_consumption_identity(self) -> str:
        return self.payload["authorization_consumption_identity"]

    @property
    def run_id(self) -> str:
        return self.payload["owner_payload"]["run_id"]

    def structurally_validated(self) -> "SignedOwnerAuthorizationReceipt":
        payload = dict(self.payload)
        require_exact_keys(
            payload, set(_RECEIPT_PAYLOAD_KEYS), "signed receipt payload"
        )
        if (
            payload["schema_version"] != SIGNED_RECEIPT_SCHEMA_VERSION
            or payload["broker_protocol"] != BROKER_PROTOCOL_VERSION
            or payload["signature_construction"] != RECEIPT_SIGNATURE_CONSTRUCTION
            or payload["digest_construction"]
            != EXTERNAL_OWNER_DIGEST_CONSTRUCTION
        ):
            raise OwnerAuthorityRecordError(
                "signed receipt schema, protocol or construction is unsupported",
                classification="OWNER_AUTHORITY_RECEIPT_INVALID",
            )
        if payload["consumption_state"] != CONSUMED_LAUNCH_COMMITTED:
            raise OwnerAuthorityRecordError(
                "a signed receipt may only be issued after the durable "
                "consumption commit",
                classification="OWNER_AUTHORITY_RECEIPT_INVALID",
            )
        for key, expected in (
            ("launches_authorized", 1),
            ("retries_authorized", 0),
            ("repairs_authorized", 0),
        ):
            if payload[key] != expected:
                raise OwnerAuthorityRecordError(
                    "a signed receipt authorizes exactly one launch with zero "
                    "retries and zero repairs",
                    classification="OWNER_AUTHORITY_RECEIPT_INVALID",
                )
        require_authorization_record_id(
            payload["authorization_record_id"], "signed receipt record id"
        )
        require_identifier(payload["installation_id"], "signed receipt installation")
        for key in (
            "installation_identity",
            "signing_key_fingerprint",
            "authorization_record_identity",
            "owner_payload_fingerprint",
            "authorization_consumption_identity",
            "consumption_record_identity",
        ):
            require_sha256(payload[key], f"signed receipt {key}")
        if not isinstance(payload["owner_payload"], Mapping):
            raise OwnerAuthorityRecordError(
                "signed receipt owner payload is not an object"
            )
        validate_terminal_evidence(
            payload["broker_terminal_evidence"], "signed receipt terminal evidence"
        )
        require_sha256(self.receipt_identity, "signed receipt identity")
        if len(self.signature) != 64:
            raise OwnerAuthorityRecordError(
                "signed receipt signature is not an Ed25519 signature"
            )
        return self


def verify_signed_receipt(
    *,
    receipt: SignedOwnerAuthorizationReceipt,
    installation: OwnerAuthorityInstallation,
) -> Mapping[str, Any]:
    """Verify a receipt against exactly one attested installation.

    The public key comes from ``installation`` --- that is, from the root-owned
    record at the fixed path --- and from nowhere else.  A caller-generated key,
    a key at another path, or a receipt signed under another installation all
    fail here.
    """

    if not isinstance(receipt, SignedOwnerAuthorizationReceipt):
        raise OwnerAuthorityRecordError(
            "the production gate requires a broker-signed receipt",
            classification="OWNER_AUTHORITY_RECEIPT_ABSENT",
        )
    if not isinstance(installation, OwnerAuthorityInstallation):
        raise OwnerAuthorityRecordError(
            "receipt verification requires an attested installation",
            classification="OWNER_AUTHORITY_INSTALLATION_ABSENT",
        )
    receipt.structurally_validated()
    attested = installation.validated()
    if receipt.installation_identity != attested.installation_identity:
        raise OwnerAuthorityRecordError(
            "the signed receipt was issued under another installation",
            classification="OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION",
        )
    if (
        receipt.payload["signing_key_fingerprint"]
        != attested.signing_key_fingerprint
        or receipt.payload["installation_id"] != attested.installation_id
    ):
        raise OwnerAuthorityRecordError(
            "the signed receipt names another signing key or installation",
            classification="OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION",
        )
    verified = verify_signature(
        executable=attested.cryptographic_executable_identity,
        public_key_pem=bytes(attested.public_key_pem),
        message=receipt.signed_bytes(),
        signature=receipt.signature,
    )
    if not verified:
        raise OwnerAuthorityRecordError(
            "the owner-authority signature over this receipt is invalid",
            classification="OWNER_AUTHORITY_SIGNATURE_REFUSED",
        )
    expected_consumption = authorization_consumption_identity(
        authorization_record_id=receipt.authorization_record_id,
        owner_payload_fingerprint=receipt.owner_payload_fingerprint,
        installation_identity=attested.installation_identity,
    )
    if receipt.authorization_consumption_identity != expected_consumption:
        raise OwnerAuthorityRecordError(
            "the signed receipt carries a foreign consumption identity",
            classification="OWNER_AUTHORITY_RECEIPT_INVALID",
        )
    if fingerprint(dict(receipt.owner_payload)) != (
        receipt.owner_payload_fingerprint
    ):
        raise OwnerAuthorityRecordError(
            "the signed owner payload does not match its fingerprint",
            classification="OWNER_AUTHORITY_RECEIPT_INVALID",
        )
    return {
        "classification": "OWNER_AUTHORITY_SIGNATURE_VERIFIED",
        "installation_identity": attested.installation_identity,
        "signing_key_fingerprint": attested.signing_key_fingerprint,
        "receipt_identity": receipt.receipt_identity,
        "authorization_record_id": receipt.authorization_record_id,
        "owner_payload_fingerprint": receipt.owner_payload_fingerprint,
        "authorization_consumption_identity": (
            receipt.authorization_consumption_identity
        ),
    }
