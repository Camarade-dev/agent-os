"""Immutable authoritative state for one capsule product session.

This is a new, independent lifecycle for the provider-free capsule
architecture. It does not touch, extend, or reinterpret the historical
`admissible.delegated_gate.state.Phase` enum or any historical run
evidence — the two protocols are structurally unrelated so that existing
historical runtime semantics are preserved exactly as they were.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from admissible.capsule.backend import CapsuleAuthority
from admissible.capsule.common import fingerprint, require_exact_keys, require_identifier, require_strict_int
from admissible.capsule.events import FailureCode, RefusalReason
from admissible.capsule.finalizer import FinalizationOutcome, FinalizationResult
from admissible.capsule.intake import IntakeEvidence
from admissible.capsule.models import ProviderOutput
from admissible.capsule.verification import BehaviorResult, CheckpointResult


SESSION_SCHEMA_VERSION = "admissible_capsule_session_v1"


class Phase(str, Enum):
    CAPSULE_READY = "CAPSULE_READY"
    CAPSULE_EXECUTING = "CAPSULE_EXECUTING"
    PROVIDER_OUTPUT_FROZEN = "PROVIDER_OUTPUT_FROZEN"
    INTAKE_EVALUATING = "INTAKE_EVALUATING"
    INTAKE_ACCEPTED = "INTAKE_ACCEPTED"
    VERIFYING_CHECKPOINT = "VERIFYING_CHECKPOINT"
    VERIFYING_BEHAVIOR = "VERIFYING_BEHAVIOR"
    FINALIZATION_READY = "FINALIZATION_READY"
    FINALIZING = "FINALIZING"
    ACCEPTED = "ACCEPTED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


TERMINAL_PHASES = frozenset({Phase.ACCEPTED, Phase.REFUSED, Phase.FAILED})


@dataclass(frozen=True)
class CapsuleSessionState:
    schema_version: str
    session_id: str
    revision: int
    phase: Phase
    capsule_authority: CapsuleAuthority
    provider_output: ProviderOutput | None
    intake_evidence: IntakeEvidence | None
    checkpoint_result: CheckpointResult | None
    behavior_result: BehaviorResult | None
    finalization_result: FinalizationResult | None
    refusal_reason: RefusalReason | None
    failure_code: FailureCode | None
    failure_detail: str | None
    state_fingerprint: str

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "revision": self.revision,
            "phase": self.phase.value,
            "capsule_authority": self.capsule_authority.to_dict(),
            "provider_output": self.provider_output.to_dict() if self.provider_output is not None else None,
            "intake_evidence": self.intake_evidence.to_dict() if self.intake_evidence is not None else None,
            "checkpoint_result": self.checkpoint_result.to_dict() if self.checkpoint_result is not None else None,
            "behavior_result": self.behavior_result.to_dict() if self.behavior_result is not None else None,
            "finalization_result": (
                self.finalization_result.to_dict() if self.finalization_result is not None else None
            ),
            "refusal_reason": self.refusal_reason.value if self.refusal_reason is not None else None,
            "failure_code": self.failure_code.value if self.failure_code is not None else None,
            "failure_detail": self.failure_detail,
        }

    def canonical_bytes(self) -> bytes:
        from admissible.capsule.common import canonical_bytes

        return canonical_bytes(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["state_fingerprint"] = self.state_fingerprint
        return data

    def validated_structure(self) -> "CapsuleSessionState":
        if self.schema_version != SESSION_SCHEMA_VERSION:
            raise ValueError("unsupported capsule session schema")
        require_identifier(self.session_id, "session_id")
        require_strict_int(self.revision, "revision", minimum=0, maximum=2**63 - 1)
        if not isinstance(self.phase, Phase):
            raise ValueError("unknown capsule session phase")
        self.capsule_authority.validated()
        if self.provider_output is not None:
            self.provider_output.validated()
            if self.provider_output.capsule_authority_fingerprint != self.capsule_authority.authority_fingerprint:
                raise ValueError("provider output is bound to another capsule authority")
        if self.intake_evidence is not None:
            self.intake_evidence.validated()
        if self.checkpoint_result is not None:
            self.checkpoint_result.validated()
        if self.behavior_result is not None:
            self.behavior_result.validated()
            from admissible.capsule.verification import require_independent_copies

            if self.checkpoint_result is None:
                raise ValueError("a behavior result cannot exist without a checkpoint result")
            require_independent_copies(self.checkpoint_result.copy, self.behavior_result.copy)
        if self.finalization_result is not None:
            self.finalization_result.validated()
        if self.refusal_reason is not None and not isinstance(self.refusal_reason, RefusalReason):
            raise ValueError("unknown refusal reason")
        if self.failure_code is not None and not isinstance(self.failure_code, FailureCode):
            raise ValueError("unknown failure code")
        if self.failure_detail is not None and not isinstance(self.failure_detail, str):
            raise ValueError("invalid failure detail")
        from admissible.capsule.common import require_sha256

        require_sha256(self.state_fingerprint, "state_fingerprint")
        if fingerprint(self._body()) != self.state_fingerprint:
            raise ValueError("capsule session state fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CapsuleSessionState":
        require_exact_keys(
            data,
            {
                "schema_version",
                "session_id",
                "revision",
                "phase",
                "capsule_authority",
                "provider_output",
                "intake_evidence",
                "checkpoint_result",
                "behavior_result",
                "finalization_result",
                "refusal_reason",
                "failure_code",
                "failure_detail",
                "state_fingerprint",
            },
            "capsule session",
        )
        state = cls(
            schema_version=data["schema_version"],
            session_id=data["session_id"],
            revision=data["revision"],
            phase=Phase(data["phase"]),
            capsule_authority=CapsuleAuthority.from_dict(data["capsule_authority"]),
            provider_output=(
                ProviderOutput.from_dict(data["provider_output"]) if data["provider_output"] is not None else None
            ),
            intake_evidence=(
                IntakeEvidence.from_dict(data["intake_evidence"]) if data["intake_evidence"] is not None else None
            ),
            checkpoint_result=(
                CheckpointResult.from_dict(data["checkpoint_result"])
                if data["checkpoint_result"] is not None
                else None
            ),
            behavior_result=(
                BehaviorResult.from_dict(data["behavior_result"]) if data["behavior_result"] is not None else None
            ),
            finalization_result=(
                FinalizationResult.from_dict(data["finalization_result"])
                if data["finalization_result"] is not None
                else None
            ),
            refusal_reason=(RefusalReason(data["refusal_reason"]) if data["refusal_reason"] is not None else None),
            failure_code=(FailureCode(data["failure_code"]) if data["failure_code"] is not None else None),
            failure_detail=data["failure_detail"],
            state_fingerprint=data["state_fingerprint"],
        )
        return state.validated_structure()


def mint_state(**values: Any) -> CapsuleSessionState:
    provisional = CapsuleSessionState(**{**values, "state_fingerprint": "0" * 64})
    return CapsuleSessionState(
        **{**values, "state_fingerprint": fingerprint(provisional._body())}
    ).validated_structure()


def new_session_state(*, session_id: str, capsule_authority: CapsuleAuthority) -> CapsuleSessionState:
    return mint_state(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=session_id,
        revision=0,
        phase=Phase.CAPSULE_READY,
        capsule_authority=capsule_authority,
        provider_output=None,
        intake_evidence=None,
        checkpoint_result=None,
        behavior_result=None,
        finalization_result=None,
        refusal_reason=None,
        failure_code=None,
        failure_detail=None,
    )
