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
from admissible.capsule.events import (
    BehaviorVerified,
    CapsuleEvent,
    CapsuleExecutionStarted,
    CheckpointVerificationStarted,
    CheckpointVerified,
    FailureCode,
    FinalizationCompleted,
    FinalizationStarted,
    IntakeEvaluated,
    IntakeStarted,
    ProviderOutputFrozen,
    RefusalReason,
    SessionFailed,
)
from admissible.capsule.finalizer import (
    AcceptedBlob,
    AdmissibleFinalizer,
    FinalizationOutcome,
    FinalizationResult,
    FinalizerPreconditionError,
    FROZEN_IDENTITY,
    initialize_disposable_repository,
)
from admissible.capsule.intake import (
    NEON_RELAY_AUTHORITY,
    CanonicalIntake,
    IntakeAuthority,
    IntakeEvidence,
    RejectionCode,
    path_policy_reasons,
    validate_and_copy,
)
from admissible.capsule.docker_controller import (
    CapsuleExecutionAuthority,
    ControllerCleanupEvidence,
    DockerCapsuleController,
    DockerCapsuleLimits,
    DurableControllerAuthority,
)
from admissible.capsule.host_codex_backend import (
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    DYNAMIC_TOOL_NAMESPACE,
    AppServerConnection,
    AppServerConnectionFactory,
    BwrapCodexConnectionFactory,
    HostCodexAppServerCapsuleBackend,
    ScriptedCodexAppServerConnection,
    ScriptedCodexConnectionFactory,
    dynamic_tools_grammar,
)
from admissible.capsule.host_control import (
    AuthenticatedControlAuthority,
    HostControlBwrapPolicy,
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
from admissible.capsule.reducer import IllegalTransition, reduce
from admissible.capsule.session_store import (
    DurableCapsuleSessionStore,
    DurableToolRequest,
    DurableToolResult,
    ReconstructedCapsuleSession,
    SessionTerminalClassification,
    ToolIdDisposition,
    ToolTerminalClassification,
)
from admissible.capsule.state import TERMINAL_PHASES, CapsuleSessionState, Phase, new_session_state
from admissible.capsule.verification import (
    BehavioralVerifierIdentity,
    BehaviorRefusalCode,
    BehaviorResult,
    ByteHashPair,
    CheckpointIdentity,
    CheckpointRefusalCode,
    CheckpointResult,
    CommandCapture,
    IndependentVerificationResult,
    VerificationCopy,
    require_independent_copies,
)

__all__ = [
    "AcceptedBlob",
    "AdmissibleFinalizer",
    "AppServerConnection",
    "AppServerConnectionFactory",
    "AuthenticatedControlAuthority",
    "BehavioralVerifierIdentity",
    "BehaviorRefusalCode",
    "BehaviorResult",
    "BehaviorVerified",
    "ByteHashPair",
    "ByteTreeObservation",
    "BwrapCodexConnectionFactory",
    "CODEX_APP_SERVER_PROTOCOL_VERSION",
    "CanonicalIntake",
    "CapsuleAuthority",
    "CapsuleBackend",
    "CapsuleEvent",
    "CapsuleExecutionAuthority",
    "CapsuleExecutionStarted",
    "CapsuleSessionState",
    "CapsuleTerminalClassification",
    "CheckpointIdentity",
    "CheckpointRefusalCode",
    "CheckpointResult",
    "CheckpointVerificationStarted",
    "CheckpointVerified",
    "CleanupResult",
    "CommandCapture",
    "ControllerCleanupEvidence",
    "DYNAMIC_TOOL_NAMESPACE",
    "DockerCapsuleController",
    "DockerCapsuleLimits",
    "DurableCapsuleSessionStore",
    "DurableControllerAuthority",
    "DurableToolRequest",
    "DurableToolResult",
    "FailureCode",
    "FinalizationCompleted",
    "FinalizationOutcome",
    "FinalizationResult",
    "FinalizationStarted",
    "FinalizerPreconditionError",
    "FROZEN_IDENTITY",
    "HostCodexAppServerCapsuleBackend",
    "HostControlBwrapPolicy",
    "IllegalTransition",
    "IndependentVerificationResult",
    "IntakeAuthority",
    "IntakeEvaluated",
    "IntakeEvidence",
    "IntakeStarted",
    "NEON_RELAY_AUTHORITY",
    "ObservedEntry",
    "Phase",
    "ProcessResult",
    "ProviderCompletionClaim",
    "ProviderOutput",
    "ProviderOutputFrozen",
    "ProviderTerminalClassification",
    "RefusalReason",
    "RejectionCode",
    "ReconstructedCapsuleSession",
    "SessionFailed",
    "SessionTerminalClassification",
    "ScriptedCodexAppServerConnection",
    "ScriptedCodexConnectionFactory",
    "TERMINAL_PHASES",
    "TransportResult",
    "ToolIdDisposition",
    "ToolTerminalClassification",
    "VerificationCopy",
    "WorkspaceReference",
    "initialize_disposable_repository",
    "new_session_state",
    "path_policy_reasons",
    "reduce",
    "require_independent_copies",
    "validate_and_copy",
    "dynamic_tools_grammar",
]
