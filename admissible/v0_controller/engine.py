"""Single-tick V0 engine with explicit trusted bounded-executor consumption.

The executor boundary is an in-process trust boundary.  It prevents normal
callers from accidentally materializing evidence with a raw event; it is not a
cryptographic defence against arbitrary malicious Python in this process.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import secrets
from typing import Protocol

from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.events import (
    _BoundedExecutionCompleted,
    BoundedExecutionCompleted,
    CommandDispatchStarted,
    Event,
    ExecutionCapability,
    InvocationRequested,
    NoEvent,
    SessionCreated,
    TechnicalFault,
    V0ExecutionResultEnvelope,
)
from admissible.v0_controller.invariants import InvariantViolation, validate_state
from admissible.v0_controller.reducer import IllegalTransition, ReducerResult, reduce
from admissible.v0_controller.state import BatchRecord, OutcomeReason, Phase, ReasonCode, SessionState
from admissible.v0_controller.store import (
    AtomicSessionStore,
    CommittedButDurabilityUncertain,
    StaleRevisionError,
)
from admissible.v0_controller.workspace_guard import (
    FilesystemIdentityPolicy,
    ValidatedWorkspaceTarget,
    WorkspaceGuard,
    WorkspaceGuardError,
)


@dataclass(frozen=True)
class TickResult:
    state: SessionState
    pending_command: Command | None
    diagnostic_facts: tuple[str, ...]


class FixtureCommandDispatcher(Protocol):
    """Slice-1-only command seam; a raw execution-completion event is rejected."""

    def dispatch(self, command: Command) -> Event:
        ...


class V0BoundedExecutorAdapter(Protocol):
    """The one trusted adapter protocol for bounded execution or offline fixtures."""

    identity: str
    protocol_version: str

    def execute(
        self,
        *,
        command: Command,
        batch: BatchRecord,
        workspace_target: ValidatedWorkspaceTarget,
    ) -> V0ExecutionResultEnvelope:
        ...


class V0ControllerEngine:
    """Loads once, reduces once, validates once, and writes only on change."""

    def __init__(
        self,
        store: AtomicSessionStore,
        *,
        bounded_executor_adapter: V0BoundedExecutorAdapter | None = None,
        filesystem_identity_policy: FilesystemIdentityPolicy | None = None,
    ) -> None:
        self.store = store
        self._bounded_executor_adapter = bounded_executor_adapter
        self._filesystem_identity_policy = filesystem_identity_policy

    @staticmethod
    def _invocation_id(state: SessionState) -> str:
        return f"v0inv:{state.session_id}:{state.revision + 1}:{state.counters.invocations + 1}"

    @staticmethod
    def _command_id(state: SessionState, command: Command, ordinal: int) -> str:
        return f"v0cmd:{state.session_id}:{state.revision + 1}:{ordinal}:{command.kind.value}:{command.owner_id}"

    @staticmethod
    def _execution_capability(
        previous: SessionState,
        command: Command,
        batch: BatchRecord,
    ) -> ExecutionCapability:
        if command.command_id is None:
            raise InvariantViolation("execution capability requires a materialized command id")
        return ExecutionCapability(
            nonce=secrets.token_urlsafe(32),
            session_id=previous.session_id,
            issued_revision=previous.revision + 1,
            command_id=command.command_id,
            batch_id=batch.batch_id,
            invocation_id=batch.invocation_id,
        )

    def _materialize_commands(self, previous: SessionState, result: ReducerResult) -> SessionState:
        if len(result.commands) > 1:
            raise InvariantViolation("V0 state permits at most one pending external command")
        next_state = result.next_state
        if not result.commands:
            return next_state
        command = result.commands[0]
        if next_state.pending_command != command or command.command_id is not None:
            raise InvariantViolation("reducer command intent must be the sole unassigned pending command")
        assigned = command.with_id(self._command_id(previous, command, 1))
        if assigned.kind == CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            batch = next_state.current_batch
            if batch is None or assigned.owner_id != batch.batch_id:
                raise InvariantViolation("execution command has no active admitted batch")
            payload = assigned.payload
            payload["execution_capability"] = self._execution_capability(previous, assigned, batch).to_dict()
            assigned = assigned.with_payload(payload)
        return replace(
            next_state,
            pending_command=assigned,
            counters=replace(next_state.counters, commands=next_state.counters.commands + 1),
        )

    def _guard(self, state: SessionState) -> WorkspaceGuard:
        return WorkspaceGuard(
            state.contract.target_workspace,
            state.contract.workspace_policy,
            identity_policy=self._filesystem_identity_policy,
        )

    @staticmethod
    def _expected_execution_capability(state: SessionState, command: Command, batch: BatchRecord) -> ExecutionCapability:
        try:
            raw = command.payload["execution_capability"]
            if not isinstance(raw, dict):
                raise ValueError("execution capability must be an object")
            capability = ExecutionCapability.from_dict(raw)
        except (KeyError, ValueError, TypeError) as exc:
            raise IllegalTransition("active execution command has no valid engine-issued capability") from exc
        expected = ExecutionCapability(
            nonce=capability.nonce,
            session_id=state.session_id,
            issued_revision=state.revision - (1 if command.status == CommandStatus.IN_FLIGHT else 0),
            command_id=command.command_id or "",
            batch_id=batch.batch_id,
            invocation_id=batch.invocation_id,
        )
        if capability != expected:
            raise IllegalTransition("execution capability does not bind the active revision lineage")
        return capability

    @staticmethod
    def _active_execution(state: SessionState) -> tuple[Command, BatchRecord]:
        command = state.pending_command
        batch = state.current_batch
        if (
            state.phase != Phase.READY_TO_EXECUTE
            or command is None
            or command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS
            or command.status != CommandStatus.IN_FLIGHT
            or command.command_id is None
            or batch is None
        ):
            raise IllegalTransition("trusted bounded executor requires an in-flight execution command")
        return command, batch

    def _validated_execution_target(self, state: SessionState, paths: tuple[str, ...]) -> ValidatedWorkspaceTarget:
        target = self._guard(state).validate_workspace_target(paths)
        policy = target.identity_policy
        for validated in target.targets:
            for evidence in state.materialized_evidence:
                prior_key_under_current_policy = policy.key_for_resolved_target(evidence.resolved_target)
                if validated.physical_identity_key in {evidence.physical_identity_key, prior_key_under_current_policy}:
                    raise WorkspaceGuardError(
                        "materialized_evidence_alias",
                        "a bounded execution target aliases already materialized V0 evidence",
                    )
        return target

    def _normalize_event(self, state: SessionState, event: Event | None) -> Event:
        if event is not None:
            return event
        if state.phase == Phase.READY_TO_INVOKE and state.current_invocation is None and state.pending_command is None:
            return InvocationRequested(
                invocation_id=self._invocation_id(state),
                occurred_at=f"revision:{state.revision + 1}",
            )
        return NoEvent()

    def _apply_loaded(self, state: SessionState, event: Event | _BoundedExecutionCompleted) -> TickResult:
        result = reduce(state, event)  # exactly one pure reducer call
        next_state = self._materialize_commands(state, result)
        if next_state.canonical_bytes() == state.canonical_bytes():
            if result.semantic_progress or result.commands:
                raise InvariantViolation("unchanged V0 state cannot claim semantic progress or a command")
            return TickResult(state, state.pending_command, result.diagnostic_facts)
        if not result.semantic_progress:
            raise InvariantViolation("authoritative V0 change requires semantic progress")
        next_state = replace(
            next_state,
            revision=state.revision + 1,
            semantic_state_version=state.semantic_state_version + 1,
        )
        validate_state(next_state)
        self.store.replace(next_state, expected_revision=state.revision)
        return TickResult(next_state, next_state.pending_command, result.diagnostic_facts)

    def _enter_durability_pause(self, session_id: str, outcome: CommittedButDurabilityUncertain) -> TickResult:
        """Persist one distinct fail-closed pause; never retry the prior commit."""

        committed = self.store.load(session_id)
        if (
            not outcome.visibility_confirmed
            or committed.revision != outcome.committed_revision
            or committed.session_id != outcome.session_id
        ):
            raise outcome
        reason = OutcomeReason(
            ReasonCode.DURABILITY_UNCERTAIN,
            "The changed V0 revision is visible but directory durability could not be confirmed. "
            f"Original error: {type(outcome.original_durability_error).__name__}.",
            "Treat this session as paused; inspect storage durability and explicitly decide how to continue.",
        )
        pause_result = reduce(committed, TechnicalFault(reason))
        paused = self._materialize_commands(committed, pause_result)
        if paused.canonical_bytes() == committed.canonical_bytes() or not pause_result.semantic_progress:
            raise InvariantViolation("durability uncertainty must create a technical pause")
        paused = replace(
            paused,
            revision=committed.revision + 1,
            semantic_state_version=committed.semantic_state_version + 1,
        )
        validate_state(paused)
        try:
            self.store.replace(paused, expected_revision=committed.revision)
        except CommittedButDurabilityUncertain as pause_outcome:
            # The pause bytes are visible.  Do not retry or overwrite again.
            visible_pause = self.store.load(session_id)
            if pause_outcome.visibility_confirmed and visible_pause.phase == Phase.TECHNICAL_PAUSE:
                return TickResult(visible_pause, visible_pause.pending_command, ("durability_uncertain_pause_visible",))
            raise
        return TickResult(paused, paused.pending_command, ("committed_but_durability_uncertain",))

    def create_session(self, state: SessionState, *, occurred_at: str) -> TickResult:
        """Reduce creation in memory and persist its created state exactly once."""

        if state.revision != 0 or state.phase != Phase.PLAN:
            raise ValueError("V0 creation requires the revision-zero in-memory plan state")
        result = reduce(state, SessionCreated(session_id=state.session_id, occurred_at=occurred_at))
        created = self._materialize_commands(state, result)
        if not result.semantic_progress:
            raise InvariantViolation("session creation must change authoritative V0 state")
        created = replace(created, revision=0, semantic_state_version=state.semantic_state_version + 1)
        validate_state(created)
        try:
            self.store.create(created)
        except CommittedButDurabilityUncertain as outcome:
            return self._enter_durability_pause(state.session_id, outcome)
        return TickResult(created, created.pending_command, result.diagnostic_facts)

    def tick(self, session_id: str, event: Event | None = None, *, expected_revision: int | None = None) -> TickResult:
        """Submit normal public facts; raw execution completions are prohibited."""

        if isinstance(event, (BoundedExecutionCompleted, _BoundedExecutionCompleted)):
            raise IllegalTransition("raw execution completion is accepted only through trusted adapter consumption")
        state = self.store.load(session_id)
        if expected_revision is not None and expected_revision != state.revision:
            raise StaleRevisionError(f"stale caller revision {expected_revision}; current is {state.revision}")
        effective_event = self._normalize_event(state, event)
        try:
            return self._apply_loaded(state, effective_event)
        except CommittedButDurabilityUncertain as outcome:
            return self._enter_durability_pause(session_id, outcome)

    def execute_bounded_once(self, session_id: str) -> TickResult:
        """Run the configured adapter once, then consume its bounded envelope once."""

        adapter = self._bounded_executor_adapter
        if adapter is None:
            raise IllegalTransition("no trusted bounded executor adapter is configured")
        state = self.store.load(session_id)
        command, batch = self._active_execution(state)
        admitted_paths = tuple(
            item.path for item in batch.proposed_operations if item.operation_id in set(batch.admitted_operation_ids)
        )
        workspace_target = self._validated_execution_target(state, admitted_paths)
        envelope = adapter.execute(command=command, batch=batch, workspace_target=workspace_target)
        return self.consume_trusted_execution_result(session_id, envelope)

    def consume_trusted_execution_result(self, session_id: str, envelope: V0ExecutionResultEnvelope) -> TickResult:
        """The only engine method that converts an adapter envelope to reducer input."""

        adapter = self._bounded_executor_adapter
        if adapter is None:
            raise IllegalTransition("trusted adapter consumption requires a configured adapter")
        if (
            envelope.adapter_identity != adapter.identity
            or envelope.adapter_protocol_version != adapter.protocol_version
        ):
            raise IllegalTransition("executor envelope identity does not match the configured trusted adapter")
        state = self.store.load(session_id)
        command, batch = self._active_execution(state)
        expected = self._expected_execution_capability(state, command, batch)
        if envelope.capability != expected:
            raise IllegalTransition("executor envelope capability is forged, stale, or bound to another lifecycle")
        targets = self._validated_execution_target(state, tuple(receipt.path for receipt in envelope.receipts))
        internal = _BoundedExecutionCompleted(
            execution_command_id=command.command_id or "",
            batch_id=batch.batch_id,
            invocation_id=batch.invocation_id,
            success=envelope.success,
            receipts=envelope.receipts,
            validated_targets=targets.targets,
            occurred_at=envelope.occurred_at,
            adapter_identity=envelope.adapter_identity,
            adapter_protocol_version=envelope.adapter_protocol_version,
            failure_reason=envelope.failure_reason,
        )
        try:
            return self._apply_loaded(state, internal)
        except CommittedButDurabilityUncertain as outcome:
            return self._enter_durability_pause(session_id, outcome)

    def restart_pending_command(self, session_id: str) -> Command | TickResult | None:
        """Return a prepared command; pause rather than replay an in-flight command."""

        state = self.store.load(session_id)
        pending = state.pending_command
        if pending is None:
            return None
        if pending.status == CommandStatus.PREPARED:
            return pending
        return self.tick(
            session_id,
            TechnicalFault(
                OutcomeReason(
                    ReasonCode.COMMAND_OUTCOME_UNCERTAIN,
                    "Restart found an in-flight command without a confirmed result.",
                    "Determine the external outcome manually and start a new V0 session if needed.",
                )
            ),
        )

    def dispatch_fixture_once(self, session_id: str, dispatcher: FixtureCommandDispatcher) -> TickResult:
        """Execute a persisted prepared non-execution command with a fixture dispatcher."""

        pending_or_pause = self.restart_pending_command(session_id)
        if pending_or_pause is None:
            raise ValueError("no pending V0 command")
        if isinstance(pending_or_pause, TickResult):
            return pending_or_pause
        command = pending_or_pause
        if command.kind == CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            raise IllegalTransition("execution commands must run through V0BoundedExecutorAdapter")
        started = self.tick(session_id, CommandDispatchStarted(command.command_id or ""))
        try:
            result_event = dispatcher.dispatch(started.pending_command or command)
        except Exception as exc:
            return self.tick(
                session_id,
                TechnicalFault(
                    OutcomeReason(
                        ReasonCode.DISPATCHER_FAILURE,
                        f"Fixture dispatcher failed: {type(exc).__name__}",
                        "Inspect the dispatcher outcome before starting another V0 session.",
                    )
                ),
            )
        return self.tick(session_id, result_event)
