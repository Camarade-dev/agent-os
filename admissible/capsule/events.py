"""Closed event vocabulary consumed by the capsule reducer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from admissible.capsule.finalizer import FinalizationResult
from admissible.capsule.intake import IntakeEvidence
from admissible.capsule.models import ProviderOutput
from admissible.capsule.verification import BehaviorResult, CheckpointResult


class FailureCode(str, Enum):
    """Operational/transactional failures — distinct from evidentiary refusal."""

    PROVIDER_FAILED = "PROVIDER_FAILED"
    TRANSPORT_LOST = "TRANSPORT_LOST"
    CLEANUP_UNCONFIRMED = "CLEANUP_UNCONFIRMED"
    FINALIZER_CRASHED_BEFORE_UPDATE_REF = "FINALIZER_CRASHED_BEFORE_UPDATE_REF"
    COMPARE_AND_SWAP_REFUSED = "COMPARE_AND_SWAP_REFUSED"


class RefusalReason(str, Enum):
    """Evidentiary refusals — a deliberate ruling, not an operational failure."""

    INTAKE_REJECTED = "INTAKE_REJECTED"
    CHECKPOINT_REFUSED = "CHECKPOINT_REFUSED"
    BEHAVIOR_REFUSED = "BEHAVIOR_REFUSED"


@dataclass(frozen=True)
class CapsuleExecutionStarted:
    pass


@dataclass(frozen=True)
class ProviderOutputFrozen:
    provider_output: ProviderOutput


@dataclass(frozen=True)
class IntakeStarted:
    pass


@dataclass(frozen=True)
class IntakeEvaluated:
    intake_evidence: IntakeEvidence


@dataclass(frozen=True)
class CheckpointVerificationStarted:
    pass


@dataclass(frozen=True)
class CheckpointVerified:
    checkpoint_result: CheckpointResult


@dataclass(frozen=True)
class BehaviorVerified:
    behavior_result: BehaviorResult


@dataclass(frozen=True)
class FinalizationStarted:
    pass


@dataclass(frozen=True)
class FinalizationCompleted:
    finalization_result: FinalizationResult


@dataclass(frozen=True)
class SessionFailed:
    code: FailureCode
    detail: str


CapsuleEvent = (
    CapsuleExecutionStarted
    | ProviderOutputFrozen
    | IntakeStarted
    | IntakeEvaluated
    | CheckpointVerificationStarted
    | CheckpointVerified
    | BehaviorVerified
    | FinalizationStarted
    | FinalizationCompleted
    | SessionFailed
)
