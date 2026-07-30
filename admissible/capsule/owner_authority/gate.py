"""The production pre-effect gate over a broker-signed owner authorization.

Every effect revalidates, from scratch, all of:

* the Ed25519 signature over the receipt, against the public key of the fixed
  root-owned installation record --- re-attested from disk on every call, so a
  record replaced or re-owned after construction is caught;
* the exact authorization record and its durable state at the broker;
* the complete owner payload, re-derived rather than trusted;
* the candidate witness evidence, reopened and independently revalidated;
* the fixed canary model policy;
* the preparation root and its closed-world seal, against the externally
  retained seal identity;
* the run identity.

Nothing here trusts a fingerprint the receipt happens to carry: the receipt
says what the owner authorized, and the gate re-derives what is actually on
disk and refuses any difference.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.owner_authority.broker import (
    OwnerAuthorityBrokerClient,
    OwnerAuthorityBrokerError,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallation,
)
from admissible.capsule.owner_authority.layout import (
    LAUNCH_RESULT_RECORDED,
    OwnerAuthorityError,
    RECEIPT_ISSUED,
)
from admissible.capsule.owner_authority.records import (
    OwnerAuthorityRecordError,
    SignedOwnerAuthorizationReceipt,
    verify_signed_receipt,
)

#: The gate's verdict when the receipt is the one issued and not yet spent.
READY_FOR_SINGLE_LAUNCH = "OWNER_AUTHORITY_READY_FOR_SINGLE_LAUNCH"

#: The gate's verdict once *this* backend has recorded its launch.
LAUNCH_COMMITTED_HERE = "OWNER_AUTHORITY_LAUNCH_COMMITTED_HERE"


class OwnerAuthorityGateError(OwnerAuthorityError):
    """A refusal at the production pre-effect gate."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_GATE_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def revalidate_signed_owner_authority(
    *,
    signed_receipt: SignedOwnerAuthorizationReceipt,
    installation: OwnerAuthorityInstallation,
    broker_client: OwnerAuthorityBrokerClient,
    candidate_witness_store: Any,
    preparation_root: Path,
    retained_seal_identity: Any,
    expected_model_binding_policy: Any,
    launch_recorded_here: bool = False,
) -> Mapping[str, Any]:
    """Re-derive the complete owner authority before an effect."""

    from admissible.capsule.owner_authorization import OwnerAuthorizationPayload
    from admissible.capsule.preflight_seal import (
        RetainedPreparationSealIdentity,
        validate_future_preflight_seal,
    )
    from admissible.capsule.serialization_witness import (
        CandidateSerializationWitnessStore,
        trusted_witness_verifier_identity,
    )

    if not isinstance(signed_receipt, SignedOwnerAuthorizationReceipt):
        raise OwnerAuthorityGateError(
            "the production pre-effect gate requires a broker-signed receipt",
            classification="OWNER_AUTHORITY_RECEIPT_ABSENT",
        )
    if not isinstance(broker_client, OwnerAuthorityBrokerClient):
        raise OwnerAuthorityGateError(
            "the production pre-effect gate requires the owner-authority "
            "broker client",
            classification="OWNER_AUTHORITY_BROKER_ABSENT",
        )
    if not isinstance(candidate_witness_store, CandidateSerializationWitnessStore):
        raise OwnerAuthorityGateError(
            "the production pre-effect gate requires the candidate witness store"
        )
    if not isinstance(retained_seal_identity, RetainedPreparationSealIdentity):
        raise OwnerAuthorityGateError(
            "the production pre-effect gate requires the externally retained "
            "seal identity"
        )

    # 1. re-attest the installation from disk and verify the signature against
    #    the key that record names, and only that key.
    attested = installation.reattested()
    verification = verify_signed_receipt(receipt=signed_receipt, installation=attested)

    # 2. the broker's durable state decides eligibility, not the receipt.
    status = broker_client.authorization_status(
        signed_receipt.authorization_record_id
    )
    state = status.get("state")
    if state == RECEIPT_ISSUED:
        classification = READY_FOR_SINGLE_LAUNCH
    elif state == LAUNCH_RESULT_RECORDED and launch_recorded_here:
        classification = LAUNCH_COMMITTED_HERE
    else:
        raise OwnerAuthorityGateError(
            f"this owner authorization is not eligible for a launch: {state}",
            classification="OWNER_AUTHORITY_ALREADY_CONSUMED",
        )
    if status.get("receipt_identity") != signed_receipt.receipt_identity:
        raise OwnerAuthorityGateError(
            "the broker issued another receipt for this authorization",
            classification="OWNER_AUTHORITY_RECEIPT_SUBSTITUTED",
        )
    if status.get("installation_identity") != attested.installation_identity:
        raise OwnerAuthorityGateError(
            "the authorization record belongs to another installation",
            classification="OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION",
        )
    if status.get("owner_payload_fingerprint") != (
        signed_receipt.owner_payload_fingerprint
    ):
        raise OwnerAuthorityGateError(
            "the authorization record binds another owner payload",
            classification="OWNER_AUTHORITY_PAYLOAD_REFUSED",
        )

    # 3. the complete owner payload, structurally revalidated.
    try:
        payload = OwnerAuthorizationPayload.from_dict(
            dict(signed_receipt.owner_payload)
        )
    except ValueError as error:
        raise OwnerAuthorityGateError(
            "the signed owner payload is not a valid authorization payload",
            classification="OWNER_AUTHORITY_PAYLOAD_REFUSED",
        ) from error
    if payload.payload_fingerprint != signed_receipt.owner_payload_fingerprint:
        raise OwnerAuthorityGateError(
            "the signed owner payload does not match its fingerprint",
            classification="OWNER_AUTHORITY_PAYLOAD_REFUSED",
        )
    if payload.body["digest_construction"] != attested.record["digest_construction"]:
        raise OwnerAuthorityGateError(
            "the signed owner payload was not built for this installation's "
            "digest construction",
            classification="OWNER_AUTHORITY_PAYLOAD_REFUSED",
        )

    # 4. the fixed canary model policy.
    policy = expected_model_binding_policy.validated_canary()
    if policy.policy_fingerprint != payload.body["model_binding_policy_fingerprint"]:
        raise OwnerAuthorityGateError(
            "the owner authorization targets another model policy",
            classification="OWNER_AUTHORITY_TARGETS_ANOTHER_POLICY",
        )

    # 5. the externally retained seal identity.
    retained = retained_seal_identity.validated()
    if retained.retained_identity != payload.body["retained_seal_identity"]:
        raise OwnerAuthorityGateError(
            "the owner authorization targets another retained seal identity",
            classification="OWNER_AUTHORITY_TARGETS_ANOTHER_PREPARATION",
        )

    # 6. the candidate witness evidence, reopened and independently revalidated.
    bundle = candidate_witness_store.load_candidate_evidence(
        receipt_identity=payload.body["candidate_receipt_identity"],
        witness_run_identity=payload.body["candidate_witness_run_identity"],
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    pack = bundle.pack.revalidated(
        expected_policy=policy,
        expected_executable_identity=policy.codex_executable_identity,
    )
    if (
        bundle.receipt.receipt_identity != payload.body["candidate_receipt_identity"]
        or bundle.receipt.witness_run_nonce
        != payload.body["candidate_witness_run_nonce"]
        or pack.evidence_pack_fingerprint
        != payload.body["candidate_evidence_pack_fingerprint"]
        or bundle.store_anchor_fingerprint
        != payload.body["candidate_store_anchor_fingerprint"]
        or dict(bundle.store_root_identity)
        != dict(payload.body["candidate_store_root_identity"])
    ):
        raise OwnerAuthorityGateError(
            "candidate witness evidence differs from the owner authorization",
            classification="OWNER_AUTHORITY_CANDIDATE_EVIDENCE_CHANGED",
        )
    if bundle.tail_identity != payload.body["candidate_store_tail_identity"]:
        raise OwnerAuthorityGateError(
            "the candidate store tail advanced after the owner authorized it",
            classification="OWNER_AUTHORITY_CANDIDATE_TAIL_ADVANCED",
        )
    if (
        bundle.receipt.model_binding_policy_fingerprint != policy.policy_fingerprint
        or bundle.receipt.to_dict()["trusted_witness_verifier_identity"]
        != trusted_witness_verifier_identity()
    ):
        raise OwnerAuthorityGateError(
            "candidate witness evidence names another policy or verifier",
            classification="OWNER_AUTHORITY_TARGETS_ANOTHER_POLICY",
        )

    # 7. the preparation root and its closed-world seal.
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
        raise OwnerAuthorityGateError(
            "the preparation root or seal changed after the owner authorized it",
            classification="OWNER_AUTHORITY_PREPARATION_ROOT_CHANGED",
        )

    return {
        "classification": classification,
        "installation_identity": attested.installation_identity,
        "signing_key_fingerprint": attested.signing_key_fingerprint,
        "signature_verification": dict(verification),
        "authorization_record_id": signed_receipt.authorization_record_id,
        "authorization_state": state,
        "receipt_identity": signed_receipt.receipt_identity,
        "owner_payload_fingerprint": payload.payload_fingerprint,
        "candidate_store_tail_identity": bundle.tail_identity,
        "preflight_seal_fingerprint": sealed["seal_fingerprint"],
        "run_id": payload.body["run_id"],
        "authorization_consumption_identity": (
            signed_receipt.authorization_consumption_identity
        ),
    }


__all__ = [
    "LAUNCH_COMMITTED_HERE",
    "OwnerAuthorityGateError",
    "READY_FOR_SINGLE_LAUNCH",
    "revalidate_signed_owner_authority",
]
