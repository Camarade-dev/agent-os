"""Single-tick V0 engine with explicit trusted bounded-executor consumption.

The executor boundary is an in-process trust boundary.  It prevents normal
callers from accidentally materializing evidence with a raw event; it is not a
cryptographic defence against arbitrary malicious Python in this process.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import secrets
from typing import Protocol

from admissible.execution.bounded_write import (
    BoundedWriteError,
    PhysicalAttestationError,
    attest_completed_write_against_original_authority,
    attest_physical_file,
)
from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.events import (
    _BoundedExecutionCompleted,
    _BoundedExecutionInterrupted,
    BoundedExecutionCompleted,
    CommandDispatchStarted,
    DispatchCapability,
    Event,
    ExecutionCapability,
    InvocationRequested,
    NoEvent,
    SessionCreated,
    TechnicalFault,
    V0ExecutionInterrupted,
    V0ExecutionResultEnvelope,
)
from admissible.v0_controller.invariants import InvariantViolation, validate_state
from admissible.v0_controller.reducer import IllegalTransition, ReducerResult, reduce
from admissible.v0_controller.state import (
    BatchRecord,
    DispatchAuthorityRecord,
    OutcomeReason,
    Phase,
    ReasonCode,
    SessionState,
)
from admissible.v0_controller.store import (
    AtomicSessionStore,
    CommittedButDurabilityUncertain,
    StaleRevisionError,
)
from admissible.v0_controller.workspace_guard import (
    FilesystemIdentityPolicy,
    ValidatedTarget,
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
    ) -> V0ExecutionResultEnvelope | V0ExecutionInterrupted:
        ...


class V0ControllerEngine:
    """Loads once, reduces once, validates once, and writes only on change."""

    def __init__(
        self,
        store: AtomicSessionStore,
        *,
        bounded_executor_adapter: V0BoundedExecutorAdapter | None = None,
        filesystem_identity_policy: FilesystemIdentityPolicy | None = None,
        dispatch_backend_fingerprint: str | None = None,
    ) -> None:
        self.store = store
        self._bounded_executor_adapter = bounded_executor_adapter
        self._filesystem_identity_policy = filesystem_identity_policy
        # Set only when a real callable proposal backend is configured.  It binds
        # each persisted dispatch command to one exact backend configuration, so
        # a differently configured backend cannot consume that dispatch.
        self._dispatch_backend_fingerprint = dispatch_backend_fingerprint

    @staticmethod
    def _invocation_id(state: SessionState) -> str:
        return f"v0inv:{state.session_id}:{state.revision + 1}:{state.counters.invocations + 1}"

    @staticmethod
    def _command_id(state: SessionState, command: Command, ordinal: int) -> str:
        return f"v0cmd:{state.session_id}:{state.revision + 1}:{ordinal}:{command.kind.value}:{command.owner_id}"

    @staticmethod
    def dispatch_batch_id(state: SessionState, invocation_id: str) -> str:
        """The exact turn-batch identity this dispatch command may propose into."""

        return f"{invocation_id}:batch:{state.counters.batches + 1}"

    @staticmethod
    def dispatch_wait_token_id(command_id: str) -> str:
        """Deterministic identity for the wait token bound to one dispatch."""

        return f"v0wait:{command_id}"

    def _dispatch_capability(self, previous: SessionState, next_state: SessionState, command: Command) -> DispatchCapability:
        if command.command_id is None:
            raise InvariantViolation("dispatch capability requires a materialized command id")
        if not self._dispatch_backend_fingerprint:
            raise InvariantViolation("dispatch capability requires a configured backend fingerprint")
        return DispatchCapability(
            nonce=secrets.token_urlsafe(32),
            session_id=previous.session_id,
            issued_revision=previous.revision + 1,
            command_id=command.command_id,
            batch_id=self.dispatch_batch_id(next_state, command.owner_id),
            invocation_id=command.owner_id,
            backend_fingerprint=self._dispatch_backend_fingerprint,
        )

    @classmethod
    def _dispatch_authority_record(
        cls,
        capability: DispatchCapability,
    ) -> DispatchAuthorityRecord:
        """Persist a second, semantically separate engine-issued nonce binding."""

        return DispatchAuthorityRecord(
            schema_version="admissible_v0_dispatch_authority_v1",
            nonce=capability.nonce,
            session_id=capability.session_id,
            issued_revision=capability.issued_revision,
            command_id=capability.command_id,
            batch_id=capability.batch_id,
            invocation_id=capability.invocation_id,
            wait_token_id=cls.dispatch_wait_token_id(capability.command_id),
            wait_owner_id=capability.invocation_id,
            backend_fingerprint=capability.backend_fingerprint,
        )

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
        if assigned.kind == CommandKind.DISPATCH_AGENT and self._dispatch_backend_fingerprint:
            payload = assigned.payload
            capability = self._dispatch_capability(previous, next_state, assigned)
            payload["dispatch_capability"] = capability.to_dict()
            assigned = assigned.with_payload(payload)
            invocation = next_state.current_invocation
            if (
                invocation is None
                or invocation.invocation_id != assigned.owner_id
                or invocation.dispatch_authority is not None
            ):
                raise InvariantViolation("dispatch capability requires one prepared active invocation")
            next_state = replace(
                next_state,
                current_invocation=replace(
                    invocation,
                    dispatch_authority=self._dispatch_authority_record(capability),
                ),
            )
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
            authority=state.workspace_authority,
        )

    @staticmethod
    def _workspace_authority_reason(error: ValueError) -> OutcomeReason:
        diagnostic = getattr(error, "diagnostic", "workspace_authority_changed")
        return OutcomeReason(
            (
                ReasonCode.WORKSPACE_CONTAINMENT_CHANGED
                if diagnostic == "workspace_containment_changed"
                else ReasonCode.WORKSPACE_AUTHORITY_CHANGED
            ),
            f"{diagnostic}: {error}",
            "Treat this V0 session as technically paused; inspect the workspace binding and start a new session.",
        )

    @staticmethod
    def _physical_attestation_reason(error: ValueError) -> OutcomeReason:
        diagnostic = getattr(error, "diagnostic", "physical_attestation_failed")
        return OutcomeReason(
            ReasonCode.PHYSICAL_ATTESTATION_FAILED,
            f"{diagnostic}: {error}",
            "Treat this V0 session as technically paused; inspect the physical file and start a new session.",
        )

    def ensure_workspace_authority(self, state: SessionState) -> None:
        """Fail closed if the configuration-time workspace binding changed."""

        self._guard(state).revalidate_authority()

    def fail_closed_workspace_authority(self, session_id: str, error: ValueError) -> TickResult:
        return self.tick(session_id, TechnicalFault(self._workspace_authority_reason(error)))

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

    @staticmethod
    def _receipt_id(command_id: str, action_id: str) -> str:
        return f"v0receipt:{command_id}:{action_id}"

    def _validate_complete_execution_receipts(
        self,
        *,
        state: SessionState,
        command: Command,
        batch: BatchRecord,
        capability: ExecutionCapability,
        envelope: V0ExecutionResultEnvelope,
        workspace_target: ValidatedWorkspaceTarget,
    ) -> None:
        """Reject any receipt that is not the exact active V0 write fact."""

        receipts = envelope.receipts
        if not envelope.success:
            if receipts:
                raise IllegalTransition("failed execution envelopes cannot claim successful V0 receipts")
            return
        admitted = {
            operation.operation_id: operation
            for operation in batch.proposed_operations
            if operation.operation_id in set(batch.admitted_operation_ids)
        }
        if not receipts or {receipt.action_id for receipt in receipts} != set(admitted):
            raise IllegalTransition("successful execution envelope must contain exactly one receipt per admitted action")
        if len({receipt.receipt_id for receipt in receipts}) != len(receipts):
            raise IllegalTransition("execution envelope receipt ids must be unique")
        consumed_ids = {receipt.receipt_id for receipt in state.execution_receipt_history}
        if consumed_ids.intersection(receipt.receipt_id for receipt in receipts):
            raise IllegalTransition("execution receipt replay is not permitted")
        targets = {target.relative_path: target for target in workspace_target.targets}
        for receipt in receipts:
            operation = admitted.get(receipt.action_id)
            target = targets.get(receipt.path)
            if operation is None or target is None:
                if state.workspace_authority is not None:
                    raise PhysicalAttestationError(
                        "execution receipt names a target that is not physically authorized for the active batch",
                        diagnostic="physical_attestation_failed",
                    )
                raise IllegalTransition("execution receipt action or path is not part of the active admitted batch")
            if (
                receipt.schema_version != "admissible_v0_execution_receipt_v1"
                or receipt.receipt_id != self._receipt_id(command.command_id or "", receipt.action_id)
                or receipt.session_id != state.session_id
                or receipt.issued_revision != capability.issued_revision
                or receipt.execution_command_id != command.command_id
                or receipt.batch_id != batch.batch_id
                or receipt.invocation_id != batch.invocation_id
                or receipt.operation_kind != operation.operation.get("operation")
                or receipt.operation_kind != "write_file"
                or receipt.path != operation.path
                or receipt.success is not True
            ):
                if state.workspace_authority is not None:
                    raise PhysicalAttestationError(
                        "execution receipt does not exactly correlate to the active V0 lifecycle",
                        diagnostic="physical_attestation_failed",
                    )
                raise IllegalTransition("execution receipt does not exactly correlate to the active V0 lifecycle")
            if (
                receipt.resolved_target != target.resolved_target
                or receipt.physical_identity_key != target.physical_identity_key
            ):
                raise PhysicalAttestationError(
                    "execution receipt physical target does not match the current authorized target",
                    diagnostic="physical_attestation_failed",
                )
            if state.workspace_authority is not None:
                content = operation.operation.get("content")
                if not isinstance(content, str):
                    raise PhysicalAttestationError(
                        "admitted write command has no confirmed string content",
                        diagnostic="physical_attestation_failed",
                    )
                try:
                    facts = attest_physical_file(
                        authority=state.workspace_authority,
                        relative_path=receipt.path,
                        expected_resolved_target=target.resolved_target,
                        expected_physical_identity_key=target.physical_identity_key,
                        expected_content=content.encode("utf-8"),
                    )
                except BoundedWriteError as exc:
                    if exc.diagnostic in {"workspace_authority_changed", "workspace_containment_changed"}:
                        raise WorkspaceGuardError(exc.diagnostic, str(exc)) from exc
                    raise PhysicalAttestationError(str(exc), diagnostic=exc.diagnostic) from exc
                if facts.sha256 != receipt.sha256 or facts.byte_count != receipt.byte_count:
                    raise PhysicalAttestationError(
                        "execution receipt SHA-256 or byte count does not match the final physical file",
                        diagnostic="physical_attestation_failed",
                    )

    def _validate_interrupted_receipts(
        self,
        *,
        state: SessionState,
        command: Command,
        batch: BatchRecord,
        capability: ExecutionCapability,
        interrupted: V0ExecutionInterrupted,
    ) -> tuple[ValidatedTarget, ...]:
        """Attest an accomplished completed prefix against the original authority.

        A rebound logical workspace path is never followed here: every receipt
        is re-attested beneath the immutable canonical workspace captured in the
        persisted ``WorkspaceAuthorityDescriptor``.
        """

        admitted = batch.admitted_operation_ids
        receipts = interrupted.receipts
        completed_ids = tuple(receipt.action_id for receipt in receipts)
        if completed_ids != admitted[: len(completed_ids)]:
            raise IllegalTransition("interrupted execution receipts must be the exact ordered admitted prefix")
        if interrupted.remaining_action_ids != admitted[len(completed_ids):]:
            raise IllegalTransition("interrupted execution must report the exact unexecuted remainder")
        if len({receipt.receipt_id for receipt in receipts}) != len(receipts):
            raise IllegalTransition("execution envelope receipt ids must be unique")
        consumed_ids = {receipt.receipt_id for receipt in state.execution_receipt_history}
        if consumed_ids.intersection(receipt.receipt_id for receipt in receipts):
            raise IllegalTransition("execution receipt replay is not permitted")

        admitted_by_id = {item.operation_id: item for item in batch.proposed_operations if item.operation_id in set(admitted)}
        identity_policy = self._filesystem_identity_policy or FilesystemIdentityPolicy.for_host()
        targets: list[ValidatedTarget] = []
        for receipt in receipts:
            operation = admitted_by_id.get(receipt.action_id)
            if operation is None:
                raise IllegalTransition("interrupted receipt names an action outside the admitted batch")
            if (
                receipt.schema_version != "admissible_v0_execution_receipt_v1"
                or receipt.receipt_id != self._receipt_id(command.command_id or "", receipt.action_id)
                or receipt.session_id != state.session_id
                or receipt.issued_revision != capability.issued_revision
                or receipt.execution_command_id != command.command_id
                or receipt.batch_id != batch.batch_id
                or receipt.invocation_id != batch.invocation_id
                or receipt.operation_kind != operation.operation.get("operation")
                or receipt.operation_kind != "write_file"
                or receipt.path != operation.path
                or receipt.success is not True
            ):
                raise IllegalTransition("interrupted receipt does not exactly correlate to the active V0 lifecycle")
            content = operation.operation.get("content")
            if not isinstance(content, str):
                raise PhysicalAttestationError(
                    "admitted write command has no confirmed string content",
                    diagnostic="physical_attestation_failed",
                )
            if state.workspace_authority is None:
                targets.append(self._guard(state).validate(receipt.path))
                continue
            facts = attest_completed_write_against_original_authority(
                authority=state.workspace_authority,
                relative_path=receipt.path,
                expected_resolved_target=receipt.resolved_target,
                expected_physical_identity_key=receipt.physical_identity_key,
                expected_content=content.encode("utf-8"),
            )
            if (
                facts.sha256 != receipt.sha256
                or facts.byte_count != receipt.byte_count
                or identity_policy.key_for_resolved_target(facts.resolved_target) != receipt.physical_identity_key
            ):
                raise PhysicalAttestationError(
                    "interrupted receipt SHA-256, byte count, or identity does not match the physical file",
                    diagnostic="physical_attestation_failed",
                )
            targets.append(
                ValidatedTarget(
                    relative_path=receipt.path,
                    resolved_target=facts.resolved_target,
                    physical_identity_key=facts.physical_identity_key,
                )
            )
        return tuple(targets)

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

        if isinstance(
            event,
            (BoundedExecutionCompleted, _BoundedExecutionCompleted, V0ExecutionInterrupted, _BoundedExecutionInterrupted),
        ):
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
        try:
            workspace_target = self._validated_execution_target(state, admitted_paths)
            envelope = adapter.execute(command=command, batch=batch, workspace_target=workspace_target)
        except WorkspaceGuardError as exc:
            if state.workspace_authority is None:
                raise
            return self.fail_closed_workspace_authority(session_id, exc)
        except BoundedWriteError as exc:
            if state.workspace_authority is None:
                raise
            if exc.diagnostic in {"workspace_authority_changed", "workspace_containment_changed"}:
                return self.fail_closed_workspace_authority(session_id, exc)
            return self.tick(session_id, TechnicalFault(self._physical_attestation_reason(exc)))
        if isinstance(envelope, V0ExecutionInterrupted):
            return self.consume_trusted_interrupted_result(session_id, envelope)
        return self.consume_trusted_execution_result(session_id, envelope)

    def consume_trusted_interrupted_result(self, session_id: str, interrupted: V0ExecutionInterrupted) -> TickResult:
        """Durably represent an accomplished completed prefix, then pause.

        The remaining operations are never replayed or continued, and no
        structural verification follows an interruption.
        """

        adapter = self._bounded_executor_adapter
        if adapter is None:
            raise IllegalTransition("trusted adapter consumption requires a configured adapter")
        if (
            interrupted.adapter_identity != adapter.identity
            or interrupted.adapter_protocol_version != adapter.protocol_version
        ):
            raise IllegalTransition("executor result identity does not match the configured trusted adapter")
        state = self.store.load(session_id)
        command, batch = self._active_execution(state)
        expected = self._expected_execution_capability(state, command, batch)
        if interrupted.capability != expected:
            raise IllegalTransition("interrupted executor result capability is forged, stale, or bound to another lifecycle")
        try:
            targets = self._validate_interrupted_receipts(
                state=state,
                command=command,
                batch=batch,
                capability=expected,
                interrupted=interrupted,
            )
        except PhysicalAttestationError as exc:
            return self.tick(session_id, TechnicalFault(self._physical_attestation_reason(exc)))
        except (BoundedWriteError, WorkspaceGuardError) as exc:
            if state.workspace_authority is None:
                raise
            return self.fail_closed_workspace_authority(session_id, exc)
        internal = _BoundedExecutionInterrupted(
            execution_command_id=command.command_id or "",
            batch_id=batch.batch_id,
            invocation_id=batch.invocation_id,
            receipts=interrupted.receipts,
            validated_targets=targets,
            remaining_action_ids=interrupted.remaining_action_ids,
            interruption_code=interrupted.interruption_code,
            diagnostic=interrupted.diagnostic,
            occurred_at=interrupted.occurred_at,
            adapter_identity=interrupted.adapter_identity,
            adapter_protocol_version=interrupted.adapter_protocol_version,
            failure_reason=interrupted.failure_reason,
            failed_action_id=interrupted.failed_action_id,
        )
        try:
            return self._apply_loaded(state, internal)
        except CommittedButDurabilityUncertain as outcome:
            return self._enter_durability_pause(session_id, outcome)

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
        admitted_paths = tuple(
            operation.path
            for operation in batch.proposed_operations
            if operation.operation_id in set(batch.admitted_operation_ids)
        )
        try:
            workspace_target = self._validated_execution_target(state, admitted_paths)
            self._validate_complete_execution_receipts(
                state=state,
                command=command,
                batch=batch,
                capability=expected,
                envelope=envelope,
                workspace_target=workspace_target,
            )
            # The envelope is accepted only after a final authority check
            # immediately before reducer consumption.
            self._guard(state).revalidate_authority()
        except WorkspaceGuardError as exc:
            if state.workspace_authority is None:
                raise
            return self.fail_closed_workspace_authority(session_id, exc)
        except PhysicalAttestationError as exc:
            return self.tick(session_id, TechnicalFault(self._physical_attestation_reason(exc)))
        targets = tuple(workspace_target.target_for(receipt.path) for receipt in envelope.receipts)
        internal = _BoundedExecutionCompleted(
            execution_command_id=command.command_id or "",
            batch_id=batch.batch_id,
            invocation_id=batch.invocation_id,
            success=envelope.success,
            receipts=envelope.receipts,
            validated_targets=targets,
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
