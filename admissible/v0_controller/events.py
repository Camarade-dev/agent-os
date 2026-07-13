"""Typed facts accepted by the V0 reducer.

All identifiers and timestamps arrive through these immutable events.  The
reducer neither creates random identifiers nor reads a clock.
"""

from __future__ import annotations

from dataclasses import dataclass

from admissible.v0_controller.state import (
    OutcomeReason,
    ProposedOperation,
    StructuralFileCheck,
)
from admissible.v0_controller.workspace_guard import ValidatedTarget


@dataclass(frozen=True)
class NoEvent:
    """A deliberately empty logical tick."""


@dataclass(frozen=True)
class SessionCreated:
    session_id: str
    occurred_at: str


@dataclass(frozen=True)
class InvocationRequested:
    """Engine-created deterministic request to prepare the next invocation."""

    invocation_id: str
    occurred_at: str


@dataclass(frozen=True)
class CommandDispatchStarted:
    command_id: str


@dataclass(frozen=True)
class AgentResultReceived:
    invocation_id: str
    batch_id: str
    response_reference: str
    proposed_operations: tuple[ProposedOperation, ...]
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentInvocationFailed:
    invocation_id: str
    reason: OutcomeReason


@dataclass(frozen=True)
class ActionsAdmitted:
    batch_id: str
    admitted_operation_ids: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionReceipt:
    """Immutable bounded-executor confirmation for one admitted operation.

    These facts cross the executor/engine boundary.  The reducer maps a
    validated successful ``write_file`` receipt to authoritative evidence; an
    agent proposal alone never does so.
    """

    action_id: str
    operation_kind: str
    path: str
    sha256: str | None
    byte_count: int | None
    success: bool
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        text_fields = (
            self.action_id,
            self.operation_kind,
            self.path,
        )
        if any(not isinstance(value, str) or not value for value in text_fields):
            raise ValueError("execution receipt identifiers are required")
        if self.byte_count is not None and (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
        ):
            raise ValueError("execution receipt byte_count is invalid")


@dataclass(frozen=True)
class BoundedExecutionCompleted:
    """Public raw completion shape, deliberately rejected by ``engine.tick``.

    It remains a named type so normal callers receive a precise boundary
    rejection rather than a misleading unsupported-event error.  The reducer
    consumes only the private validated counterpart below.
    """

    execution_command_id: str
    batch_id: str
    invocation_id: str
    success: bool
    receipts: tuple[ExecutionReceipt, ...]
    occurred_at: str
    failure_reason: OutcomeReason | None = None


@dataclass(frozen=True)
class ExecutionCapability:
    """Engine-issued, persisted, single-use in-process execution capability."""

    nonce: str
    session_id: str
    issued_revision: int
    command_id: str
    batch_id: str
    invocation_id: str

    def __post_init__(self) -> None:
        if (
            not self.nonce
            or not self.session_id
            or self.issued_revision < 0
            or not self.command_id
            or not self.batch_id
            or not self.invocation_id
        ):
            raise ValueError("execution capability is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {
            "nonce": self.nonce,
            "session_id": self.session_id,
            "issued_revision": self.issued_revision,
            "command_id": self.command_id,
            "batch_id": self.batch_id,
            "invocation_id": self.invocation_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "ExecutionCapability":
        expected = {"nonce", "session_id", "issued_revision", "command_id", "batch_id", "invocation_id"}
        if set(data) != expected:
            raise ValueError("execution capability fields are invalid")
        return cls(**data)  # type: ignore[arg-type]


@dataclass(frozen=True)
class V0ExecutionResultEnvelope:
    """Trusted-adapter return value; correlations are derived by the engine."""

    capability: ExecutionCapability
    receipts: tuple[ExecutionReceipt, ...]
    success: bool
    occurred_at: str
    adapter_identity: str
    adapter_protocol_version: str
    failure_reason: OutcomeReason | None = None

    def __post_init__(self) -> None:
        if not self.adapter_identity or not self.adapter_protocol_version or not self.occurred_at:
            raise ValueError("trusted executor envelope identity and timestamp are required")


@dataclass(frozen=True)
class _BoundedExecutionCompleted:
    """Internal reducer fact built only by trusted adapter consumption."""

    execution_command_id: str
    batch_id: str
    invocation_id: str
    success: bool
    receipts: tuple[ExecutionReceipt, ...]
    validated_targets: tuple[ValidatedTarget, ...]
    occurred_at: str
    adapter_identity: str
    adapter_protocol_version: str
    failure_reason: OutcomeReason | None = None


@dataclass(frozen=True)
class StructuralCheckCompleted:
    checks: tuple[StructuralFileCheck, ...]
    occurred_at: str
    technical_reason: OutcomeReason | None = None


@dataclass(frozen=True)
class OperatorResume:
    approved: bool
    occurred_at: str


@dataclass(frozen=True)
class TechnicalFault:
    reason: OutcomeReason


Event = (
    NoEvent
    | SessionCreated
    | InvocationRequested
    | CommandDispatchStarted
    | AgentResultReceived
    | AgentInvocationFailed
    | ActionsAdmitted
    | StructuralCheckCompleted
    | OperatorResume
    | TechnicalFault
)
