"""Isolated, reducer-driven Admissible V0 controller core.

This package intentionally has no dependency on the legacy high-autonomy
controller or the Control Surface.  Slice 1 exposes only pure state handling,
durable command intent, and fixture-dispatcher seams.
"""

from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.engine import V0BoundedExecutorAdapter, V0ControllerEngine
from admissible.v0_controller.events import (
    ActionsAdmitted,
    AgentInvocationFailed,
    AgentResultReceived,
    BoundedExecutionCompleted,
    CommandDispatchStarted,
    ExecutionReceipt,
    ExecutionCapability,
    InvocationRequested,
    NoEvent,
    OperatorResume,
    SessionCreated,
    StructuralCheckCompleted,
    TechnicalFault,
    V0ExecutionResultEnvelope,
)
from admissible.v0_controller.reducer import ReducerResult, reduce
from admissible.v0_controller.state import (
    MissionContract,
    Phase,
    SessionState,
    new_session_state,
)
from admissible.v0_controller.store import (
    AtomicSessionStore,
    CommitResult,
    CommittedButDurabilityUncertain,
    DirectoryDurabilityStatus,
    PreCommitFailure,
)
from admissible.v0_controller.workspace_guard import (
    FilesystemIdentityPolicy,
    ValidatedTarget,
    ValidatedWorkspaceTarget,
    WorkspaceGuard,
    WorkspaceGuardError,
)

__all__ = [
    "ActionsAdmitted",
    "AgentInvocationFailed",
    "AgentResultReceived",
    "AtomicSessionStore",
    "BoundedExecutionCompleted",
    "CommitResult",
    "CommittedButDurabilityUncertain",
    "Command",
    "CommandDispatchStarted",
    "CommandKind",
    "CommandStatus",
    "ExecutionReceipt",
    "ExecutionCapability",
    "FilesystemIdentityPolicy",
    "InvocationRequested",
    "MissionContract",
    "NoEvent",
    "OperatorResume",
    "Phase",
    "PreCommitFailure",
    "ReducerResult",
    "SessionCreated",
    "SessionState",
    "StructuralCheckCompleted",
    "TechnicalFault",
    "DirectoryDurabilityStatus",
    "V0BoundedExecutorAdapter",
    "V0ControllerEngine",
    "V0ExecutionResultEnvelope",
    "ValidatedTarget",
    "ValidatedWorkspaceTarget",
    "WorkspaceGuard",
    "WorkspaceGuardError",
    "new_session_state",
    "reduce",
]
