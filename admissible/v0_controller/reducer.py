"""Pure, filesystem-free state transitions for the isolated V0 controller."""

from __future__ import annotations

from dataclasses import dataclass, replace

from admissible.v0_controller.commands import Command, CommandKind, CommandStatus, command_intent
from admissible.v0_controller.events import (
    ActionsAdmitted,
    AgentInvocationFailed,
    AgentResultReceived,
    _BoundedExecutionCompleted,
    _BoundedExecutionInterrupted,
    CommandDispatchStarted,
    Event,
    ExecutionReceipt,
    InvocationRequested,
    NoEvent,
    OperatorResume,
    SessionCreated,
    StructuralCheckCompleted,
    TechnicalFault,
)
from admissible.v0_controller.state import (
    BatchRecord,
    BatchStatus,
    FileEvidence,
    InvocationLifecycle,
    InvocationRecord,
    OutcomeReason,
    Phase,
    ReasonCode,
    SessionState,
    StructuralVerification,
    WaitKind,
    WaitToken,
)


class IllegalTransition(ValueError):
    """The supplied fact cannot legally follow the authoritative state."""


@dataclass(frozen=True)
class ReducerResult:
    next_state: SessionState
    commands: tuple[Command, ...] = ()
    semantic_progress: bool = False
    diagnostic_facts: tuple[str, ...] = ()


_WAIT_FOR_COMMAND: dict[CommandKind, tuple[WaitKind, str]] = {
    CommandKind.DISPATCH_AGENT: (WaitKind.AGENT_RESULT, "agent_terminal_result"),
    CommandKind.ADMIT_PROPOSAL: (WaitKind.ADMISSION_RESULT, "actions_admitted"),
    CommandKind.EXECUTE_BOUNDED_OPERATIONS: (WaitKind.EXECUTION_RESULT, "bounded_execution_completed"),
    CommandKind.RUN_STRUCTURAL_CHECK: (WaitKind.STRUCTURAL_CHECK_RESULT, "structural_check_completed"),
}


def _reason(code: ReasonCode, message: str, action: str) -> OutcomeReason:
    return OutcomeReason(code=code, message=message, operator_action=action)


def _replace_counters(state: SessionState, *, invocations: int = 0, batches: int = 0) -> SessionState:
    return replace(
        state,
        counters=replace(
            state.counters,
            invocations=state.counters.invocations + invocations,
            batches=state.counters.batches + batches,
        ),
    )


def _queue(state: SessionState, command: Command) -> ReducerResult:
    if state.pending_command is not None:
        raise IllegalTransition("cannot queue another command while one is durable")
    return ReducerResult(
        next_state=replace(state, pending_command=command),
        commands=(command,),
        semantic_progress=True,
    )


def _settle_pending(state: SessionState) -> SessionState:
    command = state.pending_command
    if command is None or command.command_id is None or command.status != CommandStatus.IN_FLIGHT:
        raise IllegalTransition("a result requires its assigned in-flight pending command")
    if command.command_id in state.completed_command_ids:
        raise IllegalTransition("command result was already consumed")
    return replace(
        state,
        pending_command=None,
        wait_token=None,
        completed_command_ids=(*state.completed_command_ids, command.command_id),
    )


def _finalize_current_invocation(
    state: SessionState,
    lifecycle: InvocationLifecycle,
    *,
    response_reference: str | None = None,
    diagnostics: tuple[str, ...] | None = None,
) -> SessionState:
    current = state.current_invocation
    if current is None:
        raise IllegalTransition("no active invocation to finalize")
    final = replace(
        current,
        lifecycle=lifecycle,
        response_reference=response_reference if response_reference is not None else current.response_reference,
        diagnostics=diagnostics if diagnostics is not None else current.diagnostics,
    )
    return replace(state, current_invocation=None, invocation_history=(*state.invocation_history, final))


def _finalize_current_batch(
    state: SessionState,
    status: BatchStatus,
    *,
    executed_operation_ids: tuple[str, ...] | None = None,
    materialized_evidence: tuple[FileEvidence, ...] | None = None,
    remaining_mandatory_paths: tuple[str, ...] | None = None,
    remaining_action_ids: tuple[str, ...] = (),
    interruption_code: str | None = None,
) -> SessionState:
    batch = state.current_batch
    if batch is None:
        raise IllegalTransition("no active batch to finalize")
    final = replace(
        batch,
        status=status,
        executed_operation_ids=batch.executed_operation_ids if executed_operation_ids is None else executed_operation_ids,
        materialized_evidence=batch.materialized_evidence if materialized_evidence is None else materialized_evidence,
        remaining_mandatory_paths=batch.remaining_mandatory_paths if remaining_mandatory_paths is None else remaining_mandatory_paths,
        remaining_action_ids=remaining_action_ids,
        interruption_code=interruption_code,
    )
    return replace(state, current_batch=None, batch_history=(*state.batch_history, final))


def _pause(state: SessionState, reason: OutcomeReason, *, uncertain_command: bool = False) -> SessionState:
    """Fail closed and move all active lifecycle objects to immutable history."""

    pending = state.pending_command
    uncertain_ids = state.uncertain_command_ids
    if uncertain_command and pending is not None and pending.command_id is not None:
        uncertain_ids = (*uncertain_ids, pending.command_id)
    if state.current_invocation is not None:
        state = _finalize_current_invocation(state, InvocationLifecycle.UNCERTAIN)
    if state.current_batch is not None:
        state = _finalize_current_batch(state, BatchStatus.FAILED)
    return replace(
        state,
        phase=Phase.TECHNICAL_PAUSE,
        pending_command=None,
        wait_token=None,
        uncertain_command_ids=uncertain_ids,
        outcome_reason=reason,
    )


def _matches_in_flight_command(
    state: SessionState,
    *,
    kind: CommandKind,
    owner_id: str,
) -> bool:
    pending = state.pending_command
    if pending is None or pending.kind != kind or pending.status != CommandStatus.IN_FLIGHT or pending.owner_id != owner_id:
        return False
    token = state.wait_token
    expected_kind, expected_event = _WAIT_FOR_COMMAND[kind]
    return (
        token is not None
        and token.kind == expected_kind
        and token.owner_id == owner_id
        and token.command_id == pending.command_id
        and token.expected_event == expected_event
    )


def _merge_evidence(existing: tuple[FileEvidence, ...], incoming: tuple[FileEvidence, ...]) -> tuple[FileEvidence, ...]:
    existing_paths = {item.path for item in existing}
    existing_physical_keys = {item.physical_identity_key for item in existing}
    incoming_paths = [item.path for item in incoming]
    incoming_physical_keys = [item.physical_identity_key for item in incoming]
    if (
        existing_paths.intersection(incoming_paths)
        or len(set(incoming_paths)) != len(incoming_paths)
        or existing_physical_keys.intersection(incoming_physical_keys)
        or len(set(incoming_physical_keys)) != len(incoming_physical_keys)
    ):
        raise IllegalTransition("execution evidence may not overwrite or duplicate a materialized physical target")
    return (*existing, *incoming)


def _structural_passes(state: SessionState, event: StructuralCheckCompleted) -> bool:
    checks = {item.path: item for item in event.checks}
    if len(checks) != len(event.checks):
        return False
    evidence_by_path = {item.path: item for item in state.materialized_evidence}
    for path in state.mandatory_paths:
        check = checks.get(path)
        if check is None or not (check.passed and check.exists and check.non_empty and check.inside_workspace):
            return False
        evidence = evidence_by_path.get(path)
        if evidence is not None and (check.observed_sha256 or check.sha256) != evidence.sha256:
            return False
    return True


def _no_event(state: SessionState) -> ReducerResult:
    """Never invent a clock, id, diagnostic mutation, or revision on a no-event tick."""

    if state.phase == Phase.PLAN:
        return ReducerResult(
            _pause(
                state,
                _reason(
                    ReasonCode.ID_FACTORY_REQUIRED,
                    "Session creation event is required.",
                    "Create a V0 session through the engine.",
                ),
            ),
            semantic_progress=True,
        )
    if state.phase in {Phase.ADMITTING, Phase.READY_TO_EXECUTE, Phase.CHECKING_FILES} and state.pending_command is None:
        return ReducerResult(
            _pause(
                state,
                _reason(
                    ReasonCode.INVARIANT_FAILURE,
                    "Automatic phase has no durable command.",
                    "Inspect the persisted V0 state before resuming.",
                ),
            ),
            semantic_progress=True,
        )
    return ReducerResult(next_state=state, diagnostic_facts=("no_event_stable",))


def _receipt_evidence(
    state: SessionState,
    batch: BatchRecord,
    event: _BoundedExecutionCompleted,
) -> tuple[tuple[str, ...], tuple[FileEvidence, ...]]:
    command = state.pending_command
    if command is None or command.command_id != event.execution_command_id:
        raise IllegalTransition("execution result does not name the active execution command")
    if event.invocation_id != batch.invocation_id:
        raise IllegalTransition("execution result invocation does not match active batch")
    admitted_by_id = {item.operation_id: item for item in batch.proposed_operations if item.operation_id in set(batch.admitted_operation_ids)}
    receipts = event.receipts
    if not receipts and event.success:
        raise IllegalTransition("bounded execution completion requires at least one executor receipt")
    action_ids = [receipt.action_id for receipt in receipts]
    paths = [receipt.path for receipt in receipts]
    targets_by_path = {target.relative_path: target for target in event.validated_targets}
    if (
        len(set(action_ids)) != len(action_ids)
        or len(set(paths)) != len(paths)
        or len(targets_by_path) != len(event.validated_targets)
        or set(targets_by_path) != set(paths)
        or len({target.physical_identity_key for target in event.validated_targets}) != len(event.validated_targets)
    ):
        raise IllegalTransition("execution receipts cannot duplicate an action or path")
    if not set(action_ids).issubset(admitted_by_id):
        raise IllegalTransition("execution receipt has an unknown or unadmitted action")
    for receipt in receipts:
        operation = admitted_by_id[receipt.action_id]
        source = operation.operation
        if receipt.operation_kind != source.get("operation") or receipt.path != operation.path:
            raise IllegalTransition("execution receipt action kind or path does not match admitted operation")

    if not event.success:
        return tuple(action_ids), ()
    if event.failure_reason is not None or set(action_ids) != set(batch.admitted_operation_ids):
        raise IllegalTransition("successful execution must provide one receipt for every admitted operation")
    if not all(receipt.success for receipt in receipts):
        raise IllegalTransition("successful execution cannot contain a failed receipt")

    materialized = _materialize_receipt_evidence(
        state,
        receipts,
        targets_by_path,
        execution_command_id=event.execution_command_id,
        batch_id=event.batch_id,
        invocation_id=event.invocation_id,
    )
    if not materialized:
        raise IllegalTransition("successful execution cannot be empty of materialized V0 work")
    return tuple(action_ids), materialized


def _materialize_receipt_evidence(
    state: SessionState,
    receipts: tuple[ExecutionReceipt, ...],
    targets_by_path: dict[str, object],
    *,
    execution_command_id: str,
    batch_id: str,
    invocation_id: str,
) -> tuple[FileEvidence, ...]:
    materialized: list[FileEvidence] = []
    existing_paths = {item.path for item in state.materialized_evidence}
    existing_physical_keys = {item.physical_identity_key for item in state.materialized_evidence}
    for receipt in receipts:
        if receipt.operation_kind != "write_file":
            raise IllegalTransition("non-materializing receipt cannot claim file evidence")
        if receipt.path not in state.mandatory_paths:
            raise IllegalTransition("V0 may materialize evidence only for mandatory paths")
        target = targets_by_path[receipt.path]
        if receipt.path in existing_paths or target.physical_identity_key in existing_physical_keys:
            raise IllegalTransition("V0 cannot overwrite an already-materialized mandatory physical target")
        try:
            materialized.append(
                FileEvidence(
                    path=receipt.path,
                    resolved_target=target.resolved_target,
                    physical_identity_key=target.physical_identity_key,
                    sha256=receipt.sha256,
                    byte_count=receipt.byte_count,
                    action_id=receipt.action_id,
                    execution_command_id=execution_command_id,
                    batch_id=batch_id,
                    invocation_id=invocation_id,
                    execution_receipt_id=receipt.receipt_id,
                )
            )
        except ValueError as exc:
            raise IllegalTransition("materialized file receipt has an invalid SHA-256") from exc
    return tuple(materialized)


def _interrupted_prefix_evidence(
    state: SessionState,
    batch: BatchRecord,
    event: _BoundedExecutionInterrupted,
) -> tuple[tuple[str, ...], tuple[FileEvidence, ...]]:
    """Accept only an exact ordered completed prefix of the admitted operations."""

    command = state.pending_command
    if command is None or command.command_id != event.execution_command_id:
        raise IllegalTransition("interrupted execution does not name the active execution command")
    if event.invocation_id != batch.invocation_id:
        raise IllegalTransition("interrupted execution invocation does not match active batch")
    if not event.interruption_code or event.failure_reason is None:
        raise IllegalTransition("interrupted execution requires a bounded code and typed reason")

    admitted = batch.admitted_operation_ids
    receipts = event.receipts
    completed_ids = tuple(receipt.action_id for receipt in receipts)
    if completed_ids != admitted[: len(completed_ids)]:
        raise IllegalTransition("interrupted execution receipts must be the exact ordered admitted prefix")
    if event.remaining_action_ids != admitted[len(completed_ids):]:
        raise IllegalTransition("interrupted execution must report the exact unexecuted remainder")
    if event.failed_action_id is not None and event.failed_action_id not in set(event.remaining_action_ids):
        raise IllegalTransition("interrupted execution failed action must be an unexecuted admitted action")

    admitted_by_id = {item.operation_id: item for item in batch.proposed_operations if item.operation_id in set(admitted)}
    paths = [receipt.path for receipt in receipts]
    targets_by_path = {target.relative_path: target for target in event.validated_targets}
    if (
        len(set(paths)) != len(paths)
        or len(targets_by_path) != len(event.validated_targets)
        or set(targets_by_path) != set(paths)
        or len({target.physical_identity_key for target in event.validated_targets}) != len(event.validated_targets)
    ):
        raise IllegalTransition("interrupted execution receipts cannot duplicate an action or path")
    for receipt in receipts:
        operation = admitted_by_id[receipt.action_id]
        if (
            receipt.operation_kind != operation.operation.get("operation")
            or receipt.path != operation.path
            or receipt.success is not True
        ):
            raise IllegalTransition("interrupted receipt does not match its admitted operation")
    evidence = _materialize_receipt_evidence(
        state,
        receipts,
        targets_by_path,
        execution_command_id=event.execution_command_id,
        batch_id=event.batch_id,
        invocation_id=event.invocation_id,
    )
    return completed_ids, evidence


def reduce(state: SessionState, event: Event | _BoundedExecutionCompleted | _BoundedExecutionInterrupted) -> ReducerResult:
    """Reduce one typed fact without I/O, clocks, ids, dispatch, or projection."""

    if state.phase in {Phase.COMPLETED, Phase.FAILED}:
        if isinstance(event, NoEvent):
            return ReducerResult(next_state=state, diagnostic_facts=("terminal_no_event",))
        return ReducerResult(next_state=state, diagnostic_facts=("terminal_event_ignored",))
    if isinstance(event, NoEvent):
        return _no_event(state)
    if isinstance(event, TechnicalFault):
        if state.phase == Phase.TECHNICAL_PAUSE:
            return ReducerResult(next_state=state, diagnostic_facts=("technical_pause_stable",))
        uncertain = state.pending_command is not None and state.pending_command.status == CommandStatus.IN_FLIGHT
        return ReducerResult(next_state=_pause(state, event.reason, uncertain_command=uncertain), semantic_progress=True)
    if state.phase == Phase.TECHNICAL_PAUSE:
        raise IllegalTransition("technical_pause is stable; start a new V0 session after resolving the reason")

    if isinstance(event, SessionCreated):
        if state.phase != Phase.PLAN or event.session_id != state.session_id:
            raise IllegalTransition("session_created is legal only for its bootstrap plan state")
        if state.remaining_paths():
            return ReducerResult(replace(state, phase=Phase.READY_TO_INVOKE), semantic_progress=True)
        command = command_intent(
            CommandKind.RUN_STRUCTURAL_CHECK,
            owner_id=state.session_id,
            payload={"mandatory_paths": list(state.mandatory_paths)},
        )
        return _queue(replace(state, phase=Phase.CHECKING_FILES), command)

    if isinstance(event, InvocationRequested):
        if state.phase != Phase.READY_TO_INVOKE or state.current_invocation is not None or state.pending_command is not None:
            raise IllegalTransition("invocation request is legal only from an idle ready_to_invoke state")
        if state.counters.invocations >= state.contract.max_invocations:
            return ReducerResult(
                _pause(
                    state,
                    _reason(ReasonCode.INVOCATION_LIMIT_REACHED, "Invocation budget is exhausted before all paths materialized.", "Review the partial batches and start a new V0 session."),
                ),
                semantic_progress=True,
            )
        seen = {record.invocation_id for record in state.invocation_history}
        if event.invocation_id in seen or not event.invocation_id:
            raise IllegalTransition("invocation id must be a new deterministic identifier")
        prepared = InvocationRecord(event.invocation_id, InvocationLifecycle.PREPARED, event.occurred_at)
        next_state = _replace_counters(replace(state, current_invocation=prepared), invocations=1)
        return _queue(
            next_state,
            command_intent(
                CommandKind.DISPATCH_AGENT,
                owner_id=event.invocation_id,
                payload={"invocation_id": event.invocation_id, "mandatory_paths": list(state.remaining_paths())},
            ),
        )

    if isinstance(event, CommandDispatchStarted):
        pending = state.pending_command
        if pending is None or pending.status != CommandStatus.PREPARED or pending.command_id != event.command_id:
            raise IllegalTransition("dispatch start requires the matching persisted prepared command")
        wait_kind, expected_event = _WAIT_FOR_COMMAND[pending.kind]
        in_flight = pending.with_status(CommandStatus.IN_FLIGHT)
        dispatch_wait: WaitToken | None = None
        if pending.kind == CommandKind.DISPATCH_AGENT and "dispatch_capability" in pending.payload:
            invocation = state.current_invocation
            authority = None if invocation is None else invocation.dispatch_authority
            if (
                invocation is None
                or invocation.lifecycle != InvocationLifecycle.PREPARED
                or invocation.invocation_id != pending.owner_id
                or authority is None
                or authority.command_id != pending.command_id
                or authority.wait_owner_id != pending.owner_id
            ):
                raise IllegalTransition("dispatch command has no engine-issued invocation authority")
            dispatch_wait = WaitToken(
                kind=wait_kind,
                owner_id=pending.owner_id,
                command_id=pending.command_id,
                expected_event=expected_event,
                token_id=authority.wait_token_id,
                correlation_nonce=authority.nonce,
            )
        next_state = replace(
            state,
            pending_command=in_flight,
            wait_token=(
                dispatch_wait
                if dispatch_wait is not None
                else WaitToken(
                    kind=wait_kind,
                    owner_id=pending.owner_id,
                    command_id=pending.command_id,
                    expected_event=expected_event,
                )
            ),
        )
        if pending.kind == CommandKind.DISPATCH_AGENT:
            invocation = state.current_invocation
            next_state = replace(
                next_state,
                phase=Phase.WAITING_FOR_AGENT,
                current_invocation=replace(invocation, lifecycle=InvocationLifecycle.DISPATCHED),
            )
        return ReducerResult(next_state=next_state, semantic_progress=True)

    if isinstance(event, AgentResultReceived):
        invocation = state.current_invocation
        if (
            state.phase != Phase.WAITING_FOR_AGENT
            or invocation is None
            or invocation.lifecycle != InvocationLifecycle.DISPATCHED
            or invocation.invocation_id != event.invocation_id
            or not _matches_in_flight_command(state, kind=CommandKind.DISPATCH_AGENT, owner_id=event.invocation_id)
        ):
            raise IllegalTransition("agent result does not match an active dispatched invocation")
        if not event.batch_id or event.batch_id in {batch.batch_id for batch in state.batch_history}:
            raise IllegalTransition("agent result requires a new batch id")
        settled = _settle_pending(state)
        settled = _finalize_current_invocation(
            settled,
            InvocationLifecycle.CONSUMED,
            response_reference=event.response_reference,
            diagnostics=event.diagnostics,
        )
        if state.counters.batches >= state.contract.max_batches:
            return ReducerResult(
                _pause(settled, _reason(ReasonCode.INVOCATION_LIMIT_REACHED, "Batch budget is exhausted.", "Review completed batches and start a new V0 session.")),
                semantic_progress=True,
            )
        proposal_ids = [item.operation_id for item in event.proposed_operations]
        proposal_paths = [item.path for item in event.proposed_operations]
        if (
            not proposal_ids
            or len(set(proposal_ids)) != len(proposal_ids)
            or len(set(proposal_paths)) != len(proposal_paths)
            or any(not settled.contract.permits_path(item.path) for item in event.proposed_operations)
        ):
            return ReducerResult(
                _pause(settled, _reason(ReasonCode.INVALID_EXTERNAL_RESULT, "Agent result has no unique bounded proposals.", "Inspect the response and start a new V0 session.")),
                semantic_progress=True,
            )
        batch = BatchRecord(
            batch_id=event.batch_id,
            invocation_id=event.invocation_id,
            proposed_operations=event.proposed_operations,
            admitted_operation_ids=(),
            executed_operation_ids=(),
            materialized_evidence=(),
            remaining_mandatory_paths=settled.remaining_paths(),
            status=BatchStatus.PREPARED,
        )
        next_state = _replace_counters(replace(settled, phase=Phase.ADMITTING, current_batch=batch), batches=1)
        return _queue(
            next_state,
            command_intent(
                CommandKind.ADMIT_PROPOSAL,
                owner_id=batch.batch_id,
                payload={"batch_id": batch.batch_id, "operation_ids": proposal_ids},
            ),
        )

    if isinstance(event, AgentInvocationFailed):
        invocation = state.current_invocation
        if (
            state.phase != Phase.WAITING_FOR_AGENT
            or invocation is None
            or invocation.invocation_id != event.invocation_id
            or not _matches_in_flight_command(state, kind=CommandKind.DISPATCH_AGENT, owner_id=event.invocation_id)
        ):
            raise IllegalTransition("agent failure does not match active invocation")
        settled = _settle_pending(state)
        finalized = _finalize_current_invocation(settled, InvocationLifecycle.FAILED, diagnostics=(event.reason.message,))
        return ReducerResult(_pause(finalized, event.reason), semantic_progress=True)

    if isinstance(event, ActionsAdmitted):
        batch = state.current_batch
        if (
            state.phase != Phase.ADMITTING
            or batch is None
            or batch.batch_id != event.batch_id
            or not _matches_in_flight_command(state, kind=CommandKind.ADMIT_PROPOSAL, owner_id=event.batch_id)
        ):
            raise IllegalTransition("admission result does not match prepared batch")
        proposed_by_id = {item.operation_id: item for item in batch.proposed_operations}
        admitted = event.admitted_operation_ids
        invalid = (
            not admitted
            or len(set(admitted)) != len(admitted)
            or not set(admitted).issubset(proposed_by_id)
            or any(proposed_by_id[action_id].path in {evidence.path for evidence in state.materialized_evidence} for action_id in admitted)
        )
        settled = _settle_pending(state)
        if invalid:
            failed_state = _finalize_current_batch(settled, BatchStatus.FAILED)
            return ReducerResult(
                _pause(failed_state, _reason(ReasonCode.INVALID_EXTERNAL_RESULT, "Admission returned no valid operation set.", "Review the admission fixture and start a new V0 session.")),
                semantic_progress=True,
            )
        admitted_batch = replace(batch, admitted_operation_ids=admitted, status=BatchStatus.ADMITTED)
        settled = replace(settled, current_batch=admitted_batch, phase=Phase.READY_TO_EXECUTE)
        operations = [item.operation for item in admitted_batch.proposed_operations if item.operation_id in set(admitted)]
        return _queue(
            settled,
            command_intent(
                CommandKind.EXECUTE_BOUNDED_OPERATIONS,
                owner_id=admitted_batch.batch_id,
                payload={"batch_id": admitted_batch.batch_id, "operations": operations, "operation_ids": list(admitted)},
            ),
        )

    if isinstance(event, _BoundedExecutionInterrupted):
        batch = state.current_batch
        if (
            state.phase != Phase.READY_TO_EXECUTE
            or batch is None
            or batch.batch_id != event.batch_id
            or not _matches_in_flight_command(state, kind=CommandKind.EXECUTE_BOUNDED_OPERATIONS, owner_id=event.batch_id)
        ):
            raise IllegalTransition("interrupted execution result does not match admitted batch")
        completed_ids, evidence = _interrupted_prefix_evidence(state, batch, event)
        settled = _settle_pending(state)
        known_receipt_ids = {receipt.receipt_id for receipt in settled.execution_receipt_history}
        incoming_receipt_ids = [receipt.receipt_id for receipt in event.receipts]
        if known_receipt_ids.intersection(incoming_receipt_ids) or len(set(incoming_receipt_ids)) != len(incoming_receipt_ids):
            raise IllegalTransition("execution receipt replay is not permitted")
        temporary = replace(
            settled,
            materialized_evidence=_merge_evidence(settled.materialized_evidence, evidence),
            execution_receipt_history=(*settled.execution_receipt_history, *event.receipts),
        )
        interrupted_state = _finalize_current_batch(
            temporary,
            BatchStatus.INTERRUPTED,
            executed_operation_ids=completed_ids,
            materialized_evidence=evidence,
            remaining_mandatory_paths=temporary.remaining_paths(),
            remaining_action_ids=event.remaining_action_ids,
            interruption_code=event.interruption_code,
        )
        # The accomplished prefix is durable; the batch is never continued.
        return ReducerResult(
            _pause(interrupted_state, event.failure_reason),
            semantic_progress=True,
            diagnostic_facts=("execution_interrupted_prefix_persisted", f"completed_effects:{len(completed_ids)}"),
        )

    if isinstance(event, _BoundedExecutionCompleted):
        batch = state.current_batch
        if (
            state.phase != Phase.READY_TO_EXECUTE
            or batch is None
            or batch.batch_id != event.batch_id
            or not _matches_in_flight_command(state, kind=CommandKind.EXECUTE_BOUNDED_OPERATIONS, owner_id=event.batch_id)
        ):
            raise IllegalTransition("bounded execution result does not match admitted batch")
        executed_ids, evidence = _receipt_evidence(state, batch, event)
        settled = _settle_pending(state)
        if not event.success:
            failed_state = _finalize_current_batch(settled, BatchStatus.FAILED, executed_operation_ids=executed_ids)
            return ReducerResult(
                _pause(failed_state, event.failure_reason or _reason(ReasonCode.EXECUTION_FAILED, "Bounded execution failed.", "Inspect executor evidence and start a new V0 session.")),
                semantic_progress=True,
            )
        merged_evidence = _merge_evidence(settled.materialized_evidence, evidence)
        known_receipt_ids = {receipt.receipt_id for receipt in settled.execution_receipt_history}
        incoming_receipt_ids = [receipt.receipt_id for receipt in event.receipts]
        if known_receipt_ids.intersection(incoming_receipt_ids) or len(set(incoming_receipt_ids)) != len(incoming_receipt_ids):
            raise IllegalTransition("execution receipt replay is not permitted")
        temporary = replace(
            settled,
            materialized_evidence=merged_evidence,
            execution_receipt_history=(*settled.execution_receipt_history, *event.receipts),
        )
        remaining = temporary.remaining_paths()
        completed_state = _finalize_current_batch(
            temporary,
            BatchStatus.COMPLETED,
            executed_operation_ids=executed_ids,
            materialized_evidence=evidence,
            remaining_mandatory_paths=remaining,
        )
        if remaining:
            return ReducerResult(
                next_state=replace(completed_state, phase=Phase.READY_TO_INVOKE),
                semantic_progress=True,
                diagnostic_facts=("partial_batch_ready_for_continuation",),
            )
        checking = replace(completed_state, phase=Phase.CHECKING_FILES)
        return _queue(
            checking,
            command_intent(
                CommandKind.RUN_STRUCTURAL_CHECK,
                owner_id=batch.batch_id,
                payload={"mandatory_paths": list(checking.mandatory_paths)},
            ),
        )

    if isinstance(event, StructuralCheckCompleted):
        command = state.pending_command
        if (
            state.phase != Phase.CHECKING_FILES
            or command is None
            or not _matches_in_flight_command(state, kind=CommandKind.RUN_STRUCTURAL_CHECK, owner_id=command.owner_id)
        ):
            raise IllegalTransition("structural result does not match in-flight structural check")
        if any(not state.contract.permits_path(check.path) for check in event.checks):
            raise IllegalTransition("structural check reported a path outside workspace policy")
        settled = _settle_pending(state)
        passed = event.technical_reason is None and _structural_passes(settled, event)
        verification = StructuralVerification(event.checks, passed, event.occurred_at)
        checked = replace(settled, structural_verification=verification)
        if event.technical_reason is not None:
            return ReducerResult(_pause(checked, event.technical_reason), semantic_progress=True)
        if not passed:
            return ReducerResult(
                replace(
                    checked,
                    phase=Phase.FAILED,
                    outcome_reason=_reason(ReasonCode.STRUCTURAL_CHECK_FAILED, "Mandatory structural file check failed.", "Correct the files manually and start a new V0 session."),
                ),
                semantic_progress=True,
            )
        if checked.contract.structural_completion_only:
            return ReducerResult(replace(checked, phase=Phase.COMPLETED), semantic_progress=True)
        return ReducerResult(
            replace(
                checked,
                phase=Phase.AWAITING_HUMAN,
                wait_token=WaitToken(
                    kind=WaitKind.HUMAN_DECISION,
                    owner_id="human_operator",
                    command_id=None,
                    expected_event="operator_resume",
                ),
            ),
            semantic_progress=True,
        )

    if isinstance(event, OperatorResume):
        if state.phase != Phase.AWAITING_HUMAN:
            raise IllegalTransition("operator resume is legal only from awaiting_human")
        if event.approved:
            return ReducerResult(replace(state, phase=Phase.COMPLETED, wait_token=None), semantic_progress=True)
        return ReducerResult(
            replace(
                state,
                phase=Phase.FAILED,
                wait_token=None,
                outcome_reason=_reason(ReasonCode.HUMAN_DECLINED, "Operator declined structural completion.", "Resolve the reported concern and start a new V0 session."),
            ),
            semantic_progress=True,
        )

    raise IllegalTransition(f"unsupported V0 event {type(event).__name__}")
