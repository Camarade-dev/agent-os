"""Inert authority for pairing post-run evaluation with historical execution.

This module contains canonical data and pure relation checks only.  It does
not locate an execution request, resolve evidence bindings, retrieve evidence,
adjudicate claims, persist authority, or make any profile launchable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from admissible.delegated_gate.canonical import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_sha256,
)
from admissible.delegated_gate.mission_profile import (
    ClaimAuthority,
    ClaimVerificationPlanAuthority,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
    VerificationEvidenceBindingAuthority,
)
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
)


HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION = (
    "admissible_historical_evaluation_pairing_authority_v1"
)


def _validated_v5_evaluation_profile(
    evaluation_profile: NativeMissionProfile,
) -> NativeMissionProfile:
    if not isinstance(evaluation_profile, NativeMissionProfile):
        raise ValueError(
            "post-run evaluation profile must be a canonical NativeMissionProfile"
        )
    if evaluation_profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V5:
        raise ValueError("post-run evaluation profile must use the exact v5 schema")
    evaluation_profile.validated()
    if evaluation_profile.is_launchable_runtime_profile:
        raise ValueError("post-run evaluation profile must remain non-launchable")
    if not isinstance(evaluation_profile.claim_authority, ClaimAuthority):
        raise ValueError("v5 evaluation profile must carry complete claim authority")
    if not isinstance(
        evaluation_profile.claim_verification_plan_authority,
        ClaimVerificationPlanAuthority,
    ):
        raise ValueError(
            "v5 evaluation profile must carry complete claim verification plan authority"
        )
    if not isinstance(
        evaluation_profile.verification_evidence_binding_authority,
        VerificationEvidenceBindingAuthority,
    ):
        raise ValueError(
            "v5 evaluation profile must carry complete verification evidence binding authority"
        )
    return evaluation_profile


def project_v5_runtime_authority_to_v2(
    evaluation_profile: NativeMissionProfile,
) -> NativeMissionProfile:
    """Project one exact V5 evaluation contract to its runtime-authority V2.

    The projection preserves every runtime-authority value and owner-ordered
    collection.  It removes only the three post-run evaluation-authority
    layers and performs the exact schema/fingerprint transition to V2.
    """

    evaluation_profile = _validated_v5_evaluation_profile(evaluation_profile)
    projected = evaluation_profile.to_dict()
    for key in (
        "claim_authority",
        "claim_verification_plan_authority",
        "verification_evidence_binding_authority",
    ):
        projected.pop(key)
    projected["schema_version"] = MISSION_PROFILE_SCHEMA_VERSION_V2
    projected.pop("profile_fingerprint")
    projected["profile_fingerprint"] = fingerprint(projected)
    return NativeMissionProfile.from_dict(projected)


def require_exact_v5_v2_runtime_authority_compatibility(
    *,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeMissionProfile:
    """Require byte-exact runtime authority between V5 and historical V4.

    Canonical byte equality is the primary law.  Fingerprint equality is
    checked again as a redundant invariant.  Passing this check says nothing
    about whether an execution, request, artifact, or evidence record exists.
    """

    if not isinstance(
        target_authorization_payload,
        NativeCanaryAuthorizationPayloadV4,
    ):
        raise ValueError(
            "target execution authorization must be a canonical historical v4 payload"
        )
    target_authorization_payload.validated_historical_structure()
    target_profile = target_authorization_payload.mission_profile
    if (
        target_profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V2
        or not target_profile.is_launchable_runtime_profile
    ):
        raise ValueError(
            "historical v4 authorization must embed an exact launchable runtime-v2 profile"
        )
    projected = project_v5_runtime_authority_to_v2(evaluation_profile)
    if canonical_bytes(projected.to_dict()) != canonical_bytes(target_profile.to_dict()):
        raise ValueError(
            "projected v5 runtime authority does not exactly match the historical v2 profile"
        )
    if projected.profile_fingerprint != target_profile.profile_fingerprint:
        raise ValueError(
            "projected v5 runtime-authority fingerprint does not match the historical v2 profile"
        )
    return projected


@dataclass(frozen=True)
class HistoricalEvaluationPairingAuthority:
    """Owner-asserted post-run evaluation authorization for one exact payload.

    The record means only that, after an execution authorization was created,
    the asserted owner actor authorized one exact V5 profile as the post-run
    evaluation contract for records attributable to that exact V4 payload.
    Actor authentication belongs to the later owner workflow.
    """

    schema_version: str
    actor_id: str
    evaluation_profile_fingerprint: str
    target_authorization_payload_fingerprint: str
    authority_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data.pop("authority_fingerprint")
        return data

    def validated(self) -> "HistoricalEvaluationPairingAuthority":
        if (
            self.schema_version
            != HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION
        ):
            raise ValueError("unsupported historical evaluation pairing schema")
        require_identifier(self.actor_id, "historical evaluation pairing actor_id")
        require_sha256(
            self.evaluation_profile_fingerprint,
            "historical evaluation profile fingerprint",
        )
        require_sha256(
            self.target_authorization_payload_fingerprint,
            "historical target authorization payload fingerprint",
        )
        require_sha256(
            self.authority_fingerprint,
            "historical evaluation pairing authority fingerprint",
        )
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError(
                "historical evaluation pairing authority fingerprint mismatch"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["authority_fingerprint"] = self.authority_fingerprint
        return data

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
    ) -> "HistoricalEvaluationPairingAuthority":
        require_exact_keys(
            data,
            set(cls.__dataclass_fields__),
            "historical evaluation pairing authority",
        )
        return cls(**dict(data)).validated()


def create_historical_evaluation_pairing_authority(
    *,
    actor_id: str,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
) -> HistoricalEvaluationPairingAuthority:
    """Create inert post-run evaluation authorization for one exact payload."""

    require_identifier(actor_id, "historical evaluation pairing actor_id")
    evaluation_profile = _validated_v5_evaluation_profile(evaluation_profile)
    if not isinstance(
        target_authorization_payload,
        NativeCanaryAuthorizationPayloadV4,
    ):
        raise ValueError(
            "target execution authorization must be a canonical historical v4 payload"
        )
    target_authorization_payload.validated_historical_structure()
    require_exact_v5_v2_runtime_authority_compatibility(
        evaluation_profile=evaluation_profile,
        target_authorization_payload=target_authorization_payload,
    )
    provisional = HistoricalEvaluationPairingAuthority(
        schema_version=HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION,
        actor_id=actor_id,
        evaluation_profile_fingerprint=evaluation_profile.profile_fingerprint,
        target_authorization_payload_fingerprint=(
            target_authorization_payload.payload_fingerprint
        ),
        authority_fingerprint="0" * 64,
    )
    return HistoricalEvaluationPairingAuthority(
        **{
            **provisional.__dict__,
            "authority_fingerprint": fingerprint(provisional._body()),
        }
    ).validated()


def validate_historical_evaluation_pairing_relation(
    *,
    authority: HistoricalEvaluationPairingAuthority,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
) -> HistoricalEvaluationPairingAuthority:
    """Validate one authority against its exact external profile and payload.

    A self-valid pairing authority proves only its own canonical bytes.  This
    separate relation check proves the referenced documents and the V5-to-V2
    compatibility law supplied by the caller.
    """

    if not isinstance(authority, HistoricalEvaluationPairingAuthority):
        raise ValueError(
            "historical evaluation pairing relation requires a canonical authority"
        )
    authority.validated()
    evaluation_profile = _validated_v5_evaluation_profile(evaluation_profile)
    if not isinstance(
        target_authorization_payload,
        NativeCanaryAuthorizationPayloadV4,
    ):
        raise ValueError(
            "target execution authorization must be a canonical historical v4 payload"
        )
    target_authorization_payload.validated_historical_structure()
    if (
        authority.evaluation_profile_fingerprint
        != evaluation_profile.profile_fingerprint
    ):
        raise ValueError(
            "historical evaluation pairing does not reference this v5 evaluation profile"
        )
    if (
        authority.target_authorization_payload_fingerprint
        != target_authorization_payload.payload_fingerprint
    ):
        raise ValueError(
            "historical evaluation pairing does not reference this v4 authorization payload"
        )
    require_exact_v5_v2_runtime_authority_compatibility(
        evaluation_profile=evaluation_profile,
        target_authorization_payload=target_authorization_payload,
    )
    return authority


__all__ = [
    "HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION",
    "HistoricalEvaluationPairingAuthority",
    "create_historical_evaluation_pairing_authority",
    "project_v5_runtime_authority_to_v2",
    "require_exact_v5_v2_runtime_authority_compatibility",
    "validate_historical_evaluation_pairing_relation",
]
