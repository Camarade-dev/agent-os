"""Store-backed dispatch authority for the V0 Cursor callable backend (Slice 3).

A raw dataclass handed in by a caller is not dispatch authority.  The real
Cursor process may start only after the V0 session has been *reloaded from the
authoritative store* and the persisted lifecycle proves, immediately before the
process starts, that this exact dispatch is live.

The public real-backend invocation path therefore accepts only stable
identifiers (:class:`PersistedCursorDispatchRequest`) and then independently
loads the session.  Nothing here trusts an in-memory ``Command``.

Honest scope: this is an *in-process structural* capability, exactly like the
existing bounded-execution capability.  It prevents normal-path and accidental
synthetic dispatch (a hand-built Command, a stale invocation, a replayed
restart, a differently configured backend).  It is not, and does not claim to
be, a defence against arbitrary malicious Python with filesystem access.
"""

from __future__ import annotations

from dataclasses import dataclass

from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.cursor_failures import (
    V0BackendFailureKind,
    V0ProposalBackendFailure,
)
from admissible.v0_controller.events import DispatchCapability
from admissible.v0_controller.state import (
    InvocationLifecycle,
    Phase,
    SessionState,
    WaitKind,
)
from admissible.v0_controller.store import AtomicSessionStore, StoreError

AGENT_WAIT_EVENT = "agent_terminal_result"

_NONTERMINAL_PHASES = frozenset({Phase.WAITING_FOR_AGENT})


@dataclass(frozen=True)
class PersistedCursorDispatchRequest:
    """Stable identifiers only.  No Command, no state, no instruction."""

    session_id: str
    command_id: str
    invocation_id: str
    batch_id: str
    expected_revision: int
    backend_fingerprint: str

    def __post_init__(self) -> None:
        if (
            not self.session_id
            or not self.command_id
            or not self.invocation_id
            or not self.batch_id
            or not self.backend_fingerprint
            or not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 0
        ):
            raise ValueError("persisted dispatch request is incomplete")


@dataclass(frozen=True)
class AuthorizedCursorDispatch:
    """The proven persisted dispatch.  Only this may reach the process runner."""

    request: PersistedCursorDispatchRequest
    state: SessionState
    command: Command
    capability: DispatchCapability
    dispatch_authority_nonce: str


def _reject(message: str, *, kind: V0BackendFailureKind = V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED) -> "V0ProposalBackendFailure":
    return V0ProposalBackendFailure(kind, message)


@dataclass(frozen=True)
class CursorDispatchAuthority:
    """Reload the session and prove the dispatch, or refuse to start a process."""

    store: AtomicSessionStore
    backend_fingerprint: str

    def authorize(self, request: PersistedCursorDispatchRequest) -> AuthorizedCursorDispatch:
        """Prove one persisted dispatch.  Raises before any process can start."""

        if request.backend_fingerprint != self.backend_fingerprint:
            raise _reject(
                "The dispatch request names a backend configuration that is not the configured backend.",
                kind=V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH,
            )
        try:
            state = self.store.load(request.session_id)
        except StoreError as exc:
            raise _reject(
                f"The V0 session {request.session_id!r} could not be loaded from the authoritative store: "
                f"{type(exc).__name__}."
            ) from exc

        if state.session_id != request.session_id:
            raise _reject("The loaded session identity does not match the dispatch request.")
        if state.phase not in _NONTERMINAL_PHASES:
            raise _reject(
                f"A Cursor process may start only from the persisted {Phase.WAITING_FOR_AGENT.value!r} phase; "
                f"the session is {state.phase.value!r}."
            )
        if state.outcome_reason is not None:
            raise _reject("The persisted session already carries a terminal or paused outcome reason.")
        if state.revision != request.expected_revision:
            raise _reject(
                f"Stale dispatch revision: the request expected {request.expected_revision}, "
                f"the persisted session is at {state.revision}."
            )

        invocation = state.current_invocation
        if invocation is None:
            raise _reject("The persisted session has no active invocation.")
        if invocation.lifecycle != InvocationLifecycle.DISPATCHED:
            raise _reject(
                f"The persisted invocation is {invocation.lifecycle.value!r}, not "
                f"{InvocationLifecycle.DISPATCHED.value!r}."
            )
        if invocation.invocation_id != request.invocation_id:
            raise _reject("The persisted active invocation is not the requested invocation.")
        if any(record.invocation_id == request.invocation_id for record in state.invocation_history):
            raise _reject("The requested invocation is already settled in persisted invocation history.")
        dispatch_authority = invocation.dispatch_authority
        if dispatch_authority is None:
            raise _reject("The persisted active invocation has no independent engine-issued dispatch authority.")

        command = state.pending_command
        if command is None or command.kind != CommandKind.DISPATCH_AGENT:
            raise _reject("The persisted session has no pending dispatch_agent command.")
        if command.status != CommandStatus.IN_FLIGHT:
            raise _reject(
                f"The persisted dispatch command is {command.status.value!r}; a Cursor process may start only "
                "after its dispatch was durably marked in-flight."
            )
        if command.command_id != request.command_id:
            raise _reject("The persisted dispatch command id does not match the requested command id.")
        if command.owner_id != request.invocation_id:
            raise _reject("The persisted dispatch command does not own the requested invocation.")
        if command.command_id in state.completed_command_ids or command.command_id in state.uncertain_command_ids:
            raise _reject("The persisted dispatch command is already completed or uncertain.")

        token = state.wait_token
        if token is None:
            raise _reject("The persisted in-flight dispatch carries no agent wait token.")
        if (
            token.kind != WaitKind.AGENT_RESULT
            or token.owner_id != request.invocation_id
            or token.command_id != request.command_id
            or token.expected_event != AGENT_WAIT_EVENT
        ):
            raise _reject("The persisted agent wait token does not match the requested dispatch.")

        try:
            raw = command.payload.get("dispatch_capability")
        except ValueError as exc:
            raise _reject(f"The persisted dispatch payload is unreadable: {exc}") from exc
        if not isinstance(raw, dict):
            raise _reject(
                "The persisted dispatch command carries no engine-issued dispatch capability; it was not "
                "created by this engine for a configured callable backend."
            )
        try:
            capability = DispatchCapability.from_dict(dict(raw))
        except (TypeError, ValueError) as exc:
            raise _reject(f"The persisted dispatch capability is invalid: {exc}") from exc
        if capability.backend_fingerprint != self.backend_fingerprint:
            raise _reject(
                "The persisted dispatch capability was issued for a different backend configuration.",
                kind=V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH,
            )
        if (
            capability.session_id != state.session_id
            or capability.command_id != command.command_id
            or capability.invocation_id != request.invocation_id
            or capability.batch_id != request.batch_id
            or capability.issued_revision != state.revision - 1
        ):
            raise _reject("The persisted dispatch capability does not bind this session, command, batch, and revision.")

        if (
            dispatch_authority.session_id != state.session_id
            or dispatch_authority.issued_revision != state.revision - 1
            or dispatch_authority.command_id != command.command_id
            or dispatch_authority.invocation_id != invocation.invocation_id
            or dispatch_authority.batch_id != request.batch_id
            or dispatch_authority.wait_owner_id != token.owner_id
            or dispatch_authority.wait_token_id != token.token_id
            or dispatch_authority.backend_fingerprint != self.backend_fingerprint
        ):
            raise _reject("The independent active invocation dispatch authority does not bind this live lifecycle.")
        if (
            capability.nonce != dispatch_authority.nonce
            or capability.session_id != dispatch_authority.session_id
            or capability.issued_revision != dispatch_authority.issued_revision
            or capability.command_id != dispatch_authority.command_id
            or capability.batch_id != dispatch_authority.batch_id
            or capability.invocation_id != dispatch_authority.invocation_id
            or capability.backend_fingerprint != dispatch_authority.backend_fingerprint
            or token.correlation_nonce != dispatch_authority.nonce
        ):
            raise _reject("The dispatch capability, wait token, and independent invocation authority disagree.")

        expected_batch = f"{request.invocation_id}:batch:{state.counters.batches + 1}"
        if request.batch_id != expected_batch:
            raise _reject("The requested turn batch identity is not the persisted next batch of this session.")

        return AuthorizedCursorDispatch(
            request=request,
            state=state,
            command=command,
            capability=capability,
            dispatch_authority_nonce=dispatch_authority.nonce,
        )


__all__ = [
    "AGENT_WAIT_EVENT",
    "AuthorizedCursorDispatch",
    "CursorDispatchAuthority",
    "PersistedCursorDispatchRequest",
]
