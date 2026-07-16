"""Independent deterministic protocol core for delegated material work gates.

Act 1 contains no provider, native write-capable executor, or model auditor.
"""

from admissible.delegated_gate.checkpoint import CheckpointCaptureError, capture_checkpoint
from admissible.delegated_gate.events import (
    AuditStarted,
    AuditVerdictRecorded,
    CheckpointRecorded,
    GateAdvanced,
    GateExecutionStarted,
    HumanDispositionRecorded,
    RepairExecutionStarted,
)
from admissible.delegated_gate.fixtures import FixtureAuditor, FixtureChange, FixtureExecutor
from admissible.delegated_gate.invariants import InvariantViolation, validate_state
from admissible.delegated_gate.models import (
    BUILD_WEEK_GATE_COUNT,
    MAX_GATES,
    ArtifactReference,
    AuditFinding,
    AuditVerdict,
    Checkpoint,
    CommandEvidence,
    EvidenceKind,
    EvidenceStatus,
    FindingSeverity,
    GateClause,
    GateContract,
    GatePlan,
    GitEvidence,
    Mission,
    TreeEvidence,
    Verdict,
    VerificationCommand,
)
from admissible.delegated_gate.reducer import IllegalTransition, reduce
from admissible.delegated_gate.state import (
    DelegatedSessionState,
    HumanBoundaryReason,
    HumanDisposition,
    Phase,
    RepairAuthority,
    new_session_state,
)
from admissible.delegated_gate.store import (
    AtomicDelegatedSessionStore,
    CommittedButDurabilityUncertain,
    DelegatedGateStoreError,
    InvalidSuccessorError,
    PersistedStateInvalid,
    StaleRevisionError,
)

__all__ = [
    "ArtifactReference",
    "AtomicDelegatedSessionStore",
    "AuditFinding",
    "AuditStarted",
    "AuditVerdict",
    "AuditVerdictRecorded",
    "BUILD_WEEK_GATE_COUNT",
    "Checkpoint",
    "CheckpointCaptureError",
    "CheckpointRecorded",
    "CommandEvidence",
    "CommittedButDurabilityUncertain",
    "DelegatedGateStoreError",
    "DelegatedSessionState",
    "EvidenceKind",
    "EvidenceStatus",
    "FindingSeverity",
    "FixtureAuditor",
    "FixtureChange",
    "FixtureExecutor",
    "GateAdvanced",
    "GateClause",
    "GateContract",
    "GateExecutionStarted",
    "GatePlan",
    "GitEvidence",
    "HumanBoundaryReason",
    "HumanDisposition",
    "HumanDispositionRecorded",
    "IllegalTransition",
    "InvariantViolation",
    "InvalidSuccessorError",
    "MAX_GATES",
    "Mission",
    "PersistedStateInvalid",
    "Phase",
    "RepairAuthority",
    "RepairExecutionStarted",
    "StaleRevisionError",
    "TreeEvidence",
    "Verdict",
    "VerificationCommand",
    "capture_checkpoint",
    "new_session_state",
    "reduce",
    "validate_state",
]
