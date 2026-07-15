"""Typed fail-closed failure classification for the V0 Cursor callable backend.

Every uncertain provider completion becomes one of these kinds.  Nothing here
retries, falls back, or repairs lifecycle state: the backend raises, the
orchestrator turns the carried :class:`OutcomeReason` into a ``TechnicalFault``,
and the session enters ``TECHNICAL_PAUSE`` for explicit operator disposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from admissible.v0_controller.state import OutcomeReason, ReasonCode


class V0BackendFailureKind(str, Enum):
    """The complete Slice 3 failure taxonomy."""

    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    PROCESS_START_FAILED = "process_start_failed"
    TIMEOUT = "timeout"
    NONZERO_EXIT = "nonzero_exit"
    MALFORMED_NDJSON = "malformed_ndjson"
    MISSING_TERMINAL_RESULT = "missing_terminal_result"
    DUPLICATE_TERMINAL_RESULT = "duplicate_terminal_result"
    TERMINAL_FAILURE = "terminal_failure"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    CANONICAL_RESULT_TOO_LARGE = "canonical_result_too_large"
    INVALID_PROPOSAL_SCHEMA = "invalid_proposal_schema"
    INVOCATION_MISMATCH = "invocation_mismatch"
    PROPOSAL_OPERATION_LIMIT_EXCEEDED = "proposal_operation_limit_exceeded"
    PROCESS_CLEANUP_FAILED = "process_cleanup_failed"
    STALE_RESULT = "stale_result"
    DUPLICATE_RESULT_CONSUMPTION = "duplicate_result_consumption"
    TERMINAL_STATE_REJECTED = "terminal_state_rejected"
    DISPATCH_ORDER_VIOLATION = "dispatch_order_violation"
    AGENT_WORKSPACE_UNAVAILABLE = "agent_workspace_unavailable"
    # A real process may start only after the persisted session, reloaded from
    # the authoritative store, proves the dispatch.  These three are the ways
    # that proof can fail *before* any process exists.
    PERSISTED_DISPATCH_REJECTED = "persisted_dispatch_rejected"
    BACKEND_FINGERPRINT_MISMATCH = "backend_fingerprint_mismatch"
    MATERIALIZED_CONTEXT_DRIFT = "materialized_context_drift"
    PERSISTED_CONTEXT_UNAVAILABLE = "persisted_context_unavailable"


_TRANSPORT_KINDS = frozenset(
    {
        V0BackendFailureKind.EXECUTABLE_UNAVAILABLE,
        V0BackendFailureKind.PROCESS_START_FAILED,
        V0BackendFailureKind.TIMEOUT,
        V0BackendFailureKind.NONZERO_EXIT,
        V0BackendFailureKind.AGENT_WORKSPACE_UNAVAILABLE,
    }
)

# An unproven process tree, and a command whose external outcome cannot be
# decided, are both "we do not know what happened out there".
_UNCERTAIN_KINDS = frozenset(
    {
        V0BackendFailureKind.PROCESS_CLEANUP_FAILED,
        V0BackendFailureKind.DISPATCH_ORDER_VIOLATION,
        V0BackendFailureKind.TERMINAL_STATE_REJECTED,
        V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED,
        V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH,
    }
)

# The persisted facts are the authority; a physical target that no longer agrees
# with its durable receipt, or a persisted content that cannot be reconstructed,
# is an attestation failure -- never a reason to build a different instruction.
_ATTESTATION_KINDS = frozenset(
    {
        V0BackendFailureKind.MATERIALIZED_CONTEXT_DRIFT,
        V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
    }
)

_OPERATOR_ACTION = "Inspect the Cursor backend outcome and start a new V0 session; Slice 3 never retries automatically."


def _reason_code(kind: V0BackendFailureKind) -> ReasonCode:
    if kind in _TRANSPORT_KINDS:
        return ReasonCode.INVOCATION_FAILED
    if kind in _UNCERTAIN_KINDS:
        return ReasonCode.COMMAND_OUTCOME_UNCERTAIN
    if kind in _ATTESTATION_KINDS:
        return ReasonCode.PHYSICAL_ATTESTATION_FAILED
    return ReasonCode.INVALID_EXTERNAL_RESULT


@dataclass(frozen=True)
class V0BackendFailure:
    """Typed, bounded description of one fail-closed backend outcome."""

    kind: V0BackendFailureKind
    message: str
    diagnostics: tuple[str, ...] = ()

    def to_reason(self) -> OutcomeReason:
        return OutcomeReason(
            code=_reason_code(self.kind),
            message=f"{self.kind.value}: {self.message}",
            operator_action=_OPERATOR_ACTION,
        )


class V0ProposalBackendFailure(Exception):
    """Raised by a proposal backend; the orchestrator pauses on it, never retries."""

    def __init__(self, kind: V0BackendFailureKind, message: str, *, diagnostics: tuple[str, ...] = ()) -> None:
        super().__init__(f"{kind.value}: {message}")
        self.failure = V0BackendFailure(kind=kind, message=message, diagnostics=diagnostics)

    @property
    def kind(self) -> V0BackendFailureKind:
        return self.failure.kind

    @property
    def diagnostics(self) -> tuple[str, ...]:
        return self.failure.diagnostics

    def to_reason(self) -> OutcomeReason:
        return self.failure.to_reason()


__all__ = [
    "V0BackendFailure",
    "V0BackendFailureKind",
    "V0ProposalBackendFailure",
]
