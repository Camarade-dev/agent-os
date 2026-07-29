"""Provider-free product architecture for the capsule backend.

A capsule backend produces only an untrusted transient workspace and a
`ProviderOutput`; it owns no Git stage, commit, or publication authority.
Acceptance flows exclusively through `CanonicalIntake` (exact bounded file
bytes), `IndependentVerification` (checkpoint and behavioral verification
kept structurally separate), and `AdmissibleFinalizer` (the sole path to an
accepted Git commit).

Historical Cursor/ACP backend code under `admissible.delegated_gate` and
`admissible.v0_controller` is retained as historical Cursor backend support
and protocol-handling defense in depth. It is not the trusted root authority
for this capsule backend architecture; nothing in this package is coupled to
it, and nothing in this package reinterprets its historical run evidence.
"""

from admissible.capsule.backend import CapsuleAuthority, CapsuleBackend, CapsuleTerminalClassification
from admissible.capsule.intake import (
    NEON_RELAY_AUTHORITY,
    CanonicalIntake,
    IntakeAuthority,
    IntakeEvidence,
    RejectionCode,
    path_policy_reasons,
    validate_and_copy,
)
from admissible.capsule.models import (
    ByteTreeObservation,
    CleanupResult,
    ObservedEntry,
    ProcessResult,
    ProviderCompletionClaim,
    ProviderOutput,
    ProviderTerminalClassification,
    TransportResult,
    WorkspaceReference,
)

__all__ = [
    "ByteTreeObservation",
    "CanonicalIntake",
    "CapsuleAuthority",
    "CapsuleBackend",
    "CapsuleTerminalClassification",
    "CleanupResult",
    "IntakeAuthority",
    "IntakeEvidence",
    "NEON_RELAY_AUTHORITY",
    "ObservedEntry",
    "ProcessResult",
    "ProviderCompletionClaim",
    "ProviderOutput",
    "ProviderTerminalClassification",
    "RejectionCode",
    "TransportResult",
    "WorkspaceReference",
    "path_policy_reasons",
    "validate_and_copy",
]
