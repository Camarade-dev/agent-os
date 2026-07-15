"""Fail-closed, exhaustive phase/history validation for V0 authoritative state."""

from __future__ import annotations

from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.events import DispatchCapability, ExecutionCapability
from admissible.v0_controller.state import (
    BatchRecord,
    BatchStatus,
    Counters,
    InvocationLifecycle,
    Phase,
    ReasonCode,
    SessionState,
    V0_SCHEMA_VERSION,
    WaitKind,
)


class InvariantViolation(ValueError):
    """Raised before persistence when a V0 state is not safe to store."""


def _fail(message: str) -> None:
    raise InvariantViolation(message)


_COMMAND_WAIT: dict[CommandKind, tuple[WaitKind, str]] = {
    CommandKind.DISPATCH_AGENT: (WaitKind.AGENT_RESULT, "agent_terminal_result"),
    CommandKind.ADMIT_PROPOSAL: (WaitKind.ADMISSION_RESULT, "actions_admitted"),
    CommandKind.EXECUTE_BOUNDED_OPERATIONS: (WaitKind.EXECUTION_RESULT, "bounded_execution_completed"),
    CommandKind.RUN_STRUCTURAL_CHECK: (WaitKind.STRUCTURAL_CHECK_RESULT, "structural_check_completed"),
}


def _payload(command: Command) -> dict:
    try:
        return command.payload
    except ValueError as exc:
        _fail(f"pending command payload is invalid: {exc}")
    raise AssertionError("unreachable")


def _require_payload(command: Command, expected: set[str]) -> dict:
    value = _payload(command)
    if set(value) != expected:
        _fail(f"{command.kind.value} payload fields are invalid")
    return value


def _require_command(
    state: SessionState,
    *,
    kind: CommandKind,
    owner_id: str | None = None,
) -> Command:
    command = state.pending_command
    if command is None or command.kind != kind:
        _fail(f"{state.phase.value} requires exactly one {kind.value} command")
    if owner_id is not None and command.owner_id != owner_id:
        _fail("command owner does not correlate with its phase object")
    if command.status == CommandStatus.PREPARED:
        if state.wait_token is not None:
            _fail("prepared commands cannot retain an external wait token")
    elif command.status == CommandStatus.IN_FLIGHT:
        expected_kind, expected_event = _COMMAND_WAIT[kind]
        token = state.wait_token
        if token is None:
            _fail("in-flight command requires one typed wait token")
        if (
            token.kind != expected_kind
            or token.owner_id != command.owner_id
            or token.command_id != command.command_id
            or token.expected_event != expected_event
        ):
            _fail("in-flight command wait token does not match command owner/id/event")
    else:
        _fail("active command has an unsupported status")
    return command


def _validate_batch_shape(state: SessionState, batch: BatchRecord, *, current: bool) -> None:
    if not batch.batch_id or not batch.invocation_id:
        _fail("batch identifiers are required")
    proposal_ids = [item.operation_id for item in batch.proposed_operations]
    proposal_paths = [item.path for item in batch.proposed_operations]
    if not proposal_ids or len(set(proposal_ids)) != len(proposal_ids):
        _fail("batch proposal ids must be non-empty and unique")
    if len(set(proposal_paths)) != len(proposal_paths):
        _fail("batch proposal paths must be unique")
    for proposal in batch.proposed_operations:
        operation = proposal.operation
        # Proposed operations are immutable untrusted backend facts.  Their
        # exact (including absent or malformed) kind is retained until the
        # admission boundary rejects it; normalizing it here would be unsafe.
        if operation.get("path") != proposal.path or not state.contract.permits_path(proposal.path):
            _fail("proposed operation path is not authorized")
    admitted = batch.admitted_operation_ids
    executed = batch.executed_operation_ids
    if len(set(admitted)) != len(admitted) or not set(admitted).issubset(proposal_ids):
        _fail("batch admitted operations must be a unique proposal subset")
    if len(set(executed)) != len(executed) or not set(executed).issubset(admitted):
        _fail("batch executed operations must be a unique admitted subset")
    evidence = batch.materialized_evidence
    if len({item.path for item in evidence}) != len(evidence):
        _fail("batch evidence paths must be unique")
    if len({item.physical_identity_key for item in evidence}) != len(evidence):
        _fail("batch evidence physical identities must be unique")
    if any(item.path not in state.mandatory_paths for item in evidence):
        _fail("batch evidence must be for mandatory paths")
    if any(item.action_id not in set(executed) for item in evidence):
        _fail("batch evidence action must have an executed operation")
    if any(
        item.batch_id != batch.batch_id or item.invocation_id != batch.invocation_id
        for item in evidence
    ):
        _fail("batch evidence receipt correlation is invalid")
    if any(path not in state.mandatory_paths for path in batch.remaining_mandatory_paths):
        _fail("batch remaining path is outside mandatory contract")
    if len(set(batch.remaining_mandatory_paths)) != len(batch.remaining_mandatory_paths):
        _fail("batch remaining paths must be unique")

    if batch.status != BatchStatus.INTERRUPTED and (batch.remaining_action_ids or batch.interruption_code is not None):
        _fail("only an interrupted batch may record an unexecuted remainder or interruption code")

    if current:
        if batch.status == BatchStatus.PREPARED:
            if admitted or executed or evidence:
                _fail("prepared batch cannot retain admitted or executed data")
        elif batch.status == BatchStatus.ADMITTED:
            if not admitted:
                _fail("admitted batch requires at least one operation")
            if executed or evidence:
                _fail("admitted batch cannot retain execution evidence")
        else:
            _fail("only prepared or admitted batches may remain active")
    else:
        if batch.status not in {BatchStatus.COMPLETED, BatchStatus.INTERRUPTED, BatchStatus.FAILED}:
            _fail("batch history may contain only completed, interrupted, or failed batches")
        if batch.status == BatchStatus.COMPLETED:
            if set(executed) != set(admitted) or not evidence:
                _fail("completed batch must record all execution and materialized evidence")
        elif batch.status == BatchStatus.INTERRUPTED:
            # An interruption may represent only an exact completed prefix of
            # the persisted admitted order, and every completed effect exactly once.
            if executed != admitted[: len(executed)]:
                _fail("interrupted batch executed operations must be an exact ordered admitted prefix")
            if batch.remaining_action_ids != admitted[len(executed):]:
                _fail("interrupted batch must record the exact unexecuted admitted remainder")
            if not batch.interruption_code:
                _fail("interrupted batch requires a bounded interruption code")
            if len(evidence) != len(executed) or {item.action_id for item in evidence} != set(executed):
                _fail("interrupted batch evidence must represent every completed effect exactly once")
        elif evidence:
            _fail("failed batch cannot claim materialized evidence")


def _validate_command_payload_for_phase(
    state: SessionState,
    command: Command,
    *,
    allow_unassigned_command_id: bool,
) -> None:
    if state.phase in {Phase.READY_TO_INVOKE, Phase.WAITING_FOR_AGENT}:
        invocation = state.current_invocation
        if invocation is None:
            _fail("dispatch phase lacks an invocation")
        payload = _payload(command)
        base_fields = {"invocation_id", "mandatory_paths"}
        if set(payload) not in (base_fields, base_fields | {"dispatch_capability"}):
            _fail("dispatch command payload fields are invalid")
        if payload["invocation_id"] != invocation.invocation_id or payload["mandatory_paths"] != list(state.remaining_paths()):
            _fail("dispatch command payload does not match active invocation")
        if "dispatch_capability" in payload:
            raw = payload["dispatch_capability"]
            if not isinstance(raw, dict):
                _fail("dispatch command capability must be an object")
            try:
                capability = DispatchCapability.from_dict(raw)
            except (TypeError, ValueError) as exc:
                _fail(f"dispatch command capability is invalid: {exc}")
            if (
                capability.session_id != state.session_id
                or capability.issued_revision != state.revision - (1 if command.status == CommandStatus.IN_FLIGHT else 0)
                or capability.command_id != command.command_id
                or capability.invocation_id != invocation.invocation_id
                or capability.batch_id != f"{invocation.invocation_id}:batch:{state.counters.batches + 1}"
            ):
                _fail("dispatch command capability does not bind the active lifecycle")
            authority = invocation.dispatch_authority
            if authority is None:
                _fail("dispatch capability has no independent active invocation authority")
            if (
                authority.nonce != capability.nonce
                or authority.session_id != capability.session_id
                or authority.issued_revision != capability.issued_revision
                or authority.command_id != capability.command_id
                or authority.batch_id != capability.batch_id
                or authority.invocation_id != capability.invocation_id
                or authority.wait_owner_id != invocation.invocation_id
                or authority.backend_fingerprint != capability.backend_fingerprint
            ):
                _fail("dispatch capability does not match independent invocation authority")
            if command.status == CommandStatus.IN_FLIGHT:
                token = state.wait_token
                if (
                    token is None
                    or token.token_id != authority.wait_token_id
                    or token.correlation_nonce != authority.nonce
                ):
                    _fail("dispatch wait token does not match independent invocation authority")
        elif invocation.dispatch_authority is not None:
            _fail("fixture dispatch cannot retain callable-backend authority")
        return
    if state.phase == Phase.ADMITTING:
        batch = state.current_batch
        if batch is None:
            _fail("admission phase lacks a batch")
        payload = _require_payload(command, {"batch_id", "operation_ids"})
        if payload["batch_id"] != batch.batch_id or payload["operation_ids"] != [item.operation_id for item in batch.proposed_operations]:
            _fail("admission command payload does not match prepared batch")
        return
    if state.phase == Phase.READY_TO_EXECUTE:
        batch = state.current_batch
        if batch is None:
            _fail("execution phase lacks a batch")
        payload = _payload(command)
        base_fields = {"batch_id", "operations", "operation_ids"}
        expected_fields = base_fields if command.command_id is None and allow_unassigned_command_id else base_fields | {"execution_capability"}
        if set(payload) != expected_fields:
            _fail("execution command payload fields are invalid")
        admitted = set(batch.admitted_operation_ids)
        expected_operations = [item.operation for item in batch.proposed_operations if item.operation_id in admitted]
        if (
            payload["batch_id"] != batch.batch_id
            or payload["operation_ids"] != list(batch.admitted_operation_ids)
            or payload["operations"] != expected_operations
        ):
            _fail("execution command payload does not match admitted batch")
        if "execution_capability" in payload:
            raw = payload["execution_capability"]
            if not isinstance(raw, dict):
                _fail("execution command capability must be an object")
            try:
                capability = ExecutionCapability.from_dict(raw)
            except (TypeError, ValueError) as exc:
                _fail(f"execution command capability is invalid: {exc}")
            if (
                capability.session_id != state.session_id
                or capability.issued_revision != state.revision - (1 if command.status == CommandStatus.IN_FLIGHT else 0)
                or capability.command_id != command.command_id
                or capability.batch_id != batch.batch_id
                or capability.invocation_id != batch.invocation_id
            ):
                _fail("execution command capability does not bind the active lifecycle")
        return
    if state.phase == Phase.CHECKING_FILES:
        payload = _require_payload(command, {"mandatory_paths"})
        if payload["mandatory_paths"] != list(state.mandatory_paths):
            _fail("structural command payload does not match contract")
        return
    _fail("pending command exists in a phase with no command ownership")


def _evidence_batches(state: SessionState) -> tuple[BatchRecord, ...]:
    """Batches whose physical effects are durably represented: completed or interrupted."""

    return tuple(
        batch
        for batch in state.batch_history
        if batch.status in {BatchStatus.COMPLETED, BatchStatus.INTERRUPTED}
    )


def _validate_materialized_history(state: SessionState) -> None:
    expected = tuple(
        evidence
        for batch in _evidence_batches(state)
        for evidence in batch.materialized_evidence
    )
    if state.materialized_evidence != expected:
        _fail("materialized evidence must exactly equal immutable completed-batch evidence")
    receipts = state.execution_receipt_history
    if len({receipt.receipt_id for receipt in receipts}) != len(receipts):
        _fail("execution receipt history ids must be unique")
    if len(receipts) != len(expected):
        _fail("execution receipt history must exactly cover materialized evidence")
    for evidence, receipt in zip(expected, receipts, strict=True):
        if (
            receipt.session_id != state.session_id
            or receipt.receipt_id != evidence.execution_receipt_id
            or receipt.path != evidence.path
            or receipt.resolved_target != evidence.resolved_target
            or receipt.physical_identity_key != evidence.physical_identity_key
            or receipt.sha256 != evidence.sha256
            or receipt.byte_count != evidence.byte_count
            or receipt.action_id != evidence.action_id
            or receipt.execution_command_id != evidence.execution_command_id
            or receipt.batch_id != evidence.batch_id
            or receipt.invocation_id != evidence.invocation_id
            or receipt.operation_kind != "write_file"
            or receipt.success is not True
        ):
            _fail("execution receipt history does not exactly correlate materialized evidence")


def _validate_nonpause_history(state: SessionState, *, allow_current_batch: bool = False) -> None:
    """Non-paused lifecycles may retain only completed history coherent with phase."""

    if any(batch.status != BatchStatus.COMPLETED for batch in state.batch_history):
        _fail("non-paused phases cannot retain failed batch history")
    _validate_materialized_history(state)
    expected_invocation_ids = [batch.invocation_id for batch in state.batch_history]
    if allow_current_batch and state.current_batch is not None:
        expected_invocation_ids.append(state.current_batch.invocation_id)
    if [item.invocation_id for item in state.invocation_history] != expected_invocation_ids:
        _fail("non-paused invocation history does not match completed/current batch lifecycle")
    if any(item.lifecycle != InvocationLifecycle.CONSUMED for item in state.invocation_history):
        _fail("non-paused invocation history may contain only consumed records")
    if state.uncertain_command_ids:
        _fail("non-paused phases cannot retain uncertain command history")


def _validate_nonpause_command_history(state: SessionState, *, completed_count: int, active_command: bool) -> None:
    if len(state.completed_command_ids) != completed_count:
        _fail("phase command history does not match the possible lifecycle")
    if state.counters.commands != completed_count + (1 if active_command else 0):
        _fail("phase command counter does not match the possible lifecycle")


def validate_state(state: SessionState, *, allow_unassigned_command_id: bool = False) -> None:
    """Validate the complete phase/object/history exclusivity matrix before I/O."""

    if state.schema_version != V0_SCHEMA_VERSION:
        _fail("unsupported schema_version")
    if not state.session_id or state.revision < 0 or state.semantic_state_version < 0:
        _fail("invalid session identity or revision")
    if state.mandatory_paths != state.contract.mandatory_paths:
        _fail("state mandatory paths must exactly match immutable contract")
    if len(set(state.mandatory_paths)) != len(state.mandatory_paths):
        _fail("mandatory paths must remain an exact set")
    if any(not state.contract.permits_path(path) for path in state.mandatory_paths):
        _fail("mandatory path outside configured workspace policy")

    evidence = state.materialized_evidence
    if len({item.path for item in evidence}) != len(evidence):
        _fail("materialized evidence paths must be unique")
    if len({item.physical_identity_key for item in evidence}) != len(evidence):
        _fail("materialized evidence physical identities must be unique")
    if any(item.path not in state.mandatory_paths for item in evidence):
        _fail("materialized evidence must be for mandatory contract paths")
    if any(not state.contract.permits_path(item.path) for item in evidence):
        _fail("evidence path outside configured workspace policy")

    history_by_id = {item.invocation_id: item for item in state.invocation_history}
    if len(history_by_id) != len(state.invocation_history):
        _fail("invocation history ids must be unique")
    if any(item.lifecycle not in {InvocationLifecycle.CONSUMED, InvocationLifecycle.FAILED, InvocationLifecycle.CANCELLED, InvocationLifecycle.UNCERTAIN} for item in state.invocation_history):
        _fail("invocation history may contain only final records")
    if state.current_invocation is not None:
        if state.current_invocation.lifecycle not in {InvocationLifecycle.PREPARED, InvocationLifecycle.DISPATCHED}:
            _fail("completed/failed/cancelled/uncertain invocation cannot remain active")
        if state.current_invocation.invocation_id in history_by_id:
            _fail("active invocation also appears in history")

    batch_ids = [item.batch_id for item in state.batch_history]
    if len(set(batch_ids)) != len(batch_ids):
        _fail("batch history ids must be unique")
    if state.current_batch is not None and state.current_batch.batch_id in batch_ids:
        _fail("current batch also appears in history")
    for batch in state.batch_history:
        _validate_batch_shape(state, batch, current=False)
        invocation = history_by_id.get(batch.invocation_id)
        if invocation is None or invocation.lifecycle != InvocationLifecycle.CONSUMED:
            _fail("batch history must correlate to a consumed invocation")
    if state.current_batch is not None:
        _validate_batch_shape(state, state.current_batch, current=True)
        invocation = history_by_id.get(state.current_batch.invocation_id)
        if invocation is None or invocation.lifecycle != InvocationLifecycle.CONSUMED:
            _fail("active batch must correlate to a consumed invocation")

    completed = state.completed_command_ids
    uncertain = state.uncertain_command_ids
    if any(not isinstance(item, str) or not item for item in (*completed, *uncertain)):
        _fail("command completion records require non-empty ids")
    if len(set(completed)) != len(completed) or len(set(uncertain)) != len(uncertain):
        _fail("command completion records must be unique")
    if set(completed) & set(uncertain):
        _fail("command cannot be both completed and uncertain")
    command = state.pending_command
    if command is not None:
        if command.command_id is None and not allow_unassigned_command_id:
            _fail("persisted pending command requires deterministic id")
        if command.command_id and command.command_id in set(completed) | set(uncertain):
            _fail("completed or uncertain command cannot remain active")
        if command.kind not in _COMMAND_WAIT:
            _fail("pending command kind is not a legal V0 external command")
    elif state.wait_token is not None and state.wait_token.kind != WaitKind.HUMAN_DECISION:
        _fail("external result wait cannot exist without an in-flight command")

    verification = state.structural_verification
    if verification is not None:
        checks = verification.checks
        if not checks or len({item.path for item in checks}) != len(checks):
            _fail("structural verification checks must be non-empty and unique")
        if any(item.path not in state.mandatory_paths for item in checks):
            _fail("structural verification path is outside the contract")

    remaining = state.remaining_paths()
    completed_batches = len(state.batch_history)
    phase = state.phase
    if phase == Phase.PLAN:
        # PLAN is the untouched bootstrap object, never a partially-cleared run.
        if (
            state.revision != 0
            or state.semantic_state_version != 0
            or state.materialized_evidence
            or state.execution_receipt_history
            or state.current_invocation is not None
            or state.invocation_history
            or state.current_batch is not None
            or state.batch_history
            or command is not None
            or completed
            or uncertain
            or state.wait_token is not None
            or verification is not None
            or state.outcome_reason is not None
            or state.counters != Counters()
        ):
            _fail("plan must contain only immutable untouched session configuration and contract")
    elif phase == Phase.READY_TO_INVOKE:
        if not remaining:
            _fail("ready_to_invoke is impossible after every mandatory path materializes")
        if state.current_batch is not None or state.wait_token is not None or verification is not None or state.outcome_reason is not None:
            _fail("ready_to_invoke has a foreign phase object")
        _validate_nonpause_history(state)
        if state.current_invocation is None:
            if command is not None:
                _fail("idle ready_to_invoke cannot retain a command")
            _validate_nonpause_command_history(state, completed_count=3 * completed_batches, active_command=False)
        else:
            if state.current_invocation.lifecycle != InvocationLifecycle.PREPARED:
                _fail("ready_to_invoke may retain only a prepared invocation")
            checked = _require_command(state, kind=CommandKind.DISPATCH_AGENT, owner_id=state.current_invocation.invocation_id)
            if checked.status != CommandStatus.PREPARED:
                _fail("ready_to_invoke dispatch command must be prepared")
            _validate_command_payload_for_phase(state, checked, allow_unassigned_command_id=allow_unassigned_command_id)
            _validate_nonpause_command_history(state, completed_count=3 * completed_batches, active_command=True)
    elif phase == Phase.WAITING_FOR_AGENT:
        if not remaining or state.current_batch is not None or verification is not None or state.outcome_reason is not None:
            _fail("waiting_for_agent has a foreign phase object")
        _validate_nonpause_history(state)
        invocation = state.current_invocation
        if invocation is None or invocation.lifecycle != InvocationLifecycle.DISPATCHED:
            _fail("waiting_for_agent requires exactly one dispatched invocation")
        checked = _require_command(state, kind=CommandKind.DISPATCH_AGENT, owner_id=invocation.invocation_id)
        if checked.status != CommandStatus.IN_FLIGHT:
            _fail("waiting_for_agent dispatch command must be in flight")
        _validate_command_payload_for_phase(state, checked, allow_unassigned_command_id=allow_unassigned_command_id)
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches, active_command=True)
    elif phase == Phase.ADMITTING:
        if not remaining or state.current_invocation is not None or verification is not None or state.outcome_reason is not None:
            _fail("admitting has a foreign phase object")
        _validate_nonpause_history(state, allow_current_batch=True)
        batch = state.current_batch
        if batch is None or batch.status != BatchStatus.PREPARED:
            _fail("admitting requires one prepared current batch")
        checked = _require_command(state, kind=CommandKind.ADMIT_PROPOSAL, owner_id=batch.batch_id)
        _validate_command_payload_for_phase(state, checked, allow_unassigned_command_id=allow_unassigned_command_id)
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches + 1, active_command=True)
    elif phase == Phase.READY_TO_EXECUTE:
        if not remaining or state.current_invocation is not None or verification is not None or state.outcome_reason is not None:
            _fail("ready_to_execute has a foreign phase object")
        _validate_nonpause_history(state, allow_current_batch=True)
        batch = state.current_batch
        if batch is None or batch.status != BatchStatus.ADMITTED:
            _fail("ready_to_execute requires one admitted current batch")
        checked = _require_command(state, kind=CommandKind.EXECUTE_BOUNDED_OPERATIONS, owner_id=batch.batch_id)
        _validate_command_payload_for_phase(state, checked, allow_unassigned_command_id=allow_unassigned_command_id)
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches + 2, active_command=True)
    elif phase == Phase.CHECKING_FILES:
        if remaining or state.current_invocation is not None or state.current_batch is not None or verification is not None or state.outcome_reason is not None:
            _fail("checking_files has a foreign phase object")
        _validate_nonpause_history(state)
        checked = _require_command(state, kind=CommandKind.RUN_STRUCTURAL_CHECK)
        allowed_owners = {state.session_id}
        if state.batch_history:
            allowed_owners.add(state.batch_history[-1].batch_id)
        if checked.owner_id not in allowed_owners:
            _fail("structural command owner does not correlate with session or completed batch")
        _validate_command_payload_for_phase(state, checked, allow_unassigned_command_id=allow_unassigned_command_id)
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches, active_command=True)
    elif phase == Phase.AWAITING_HUMAN:
        token = state.wait_token
        if remaining or state.current_invocation is not None or state.current_batch is not None or command is not None or state.outcome_reason is not None:
            _fail("awaiting_human has a foreign phase object")
        _validate_nonpause_history(state)
        if verification is None or not verification.passed:
            _fail("awaiting_human requires passing structural verification")
        if (
            token is None
            or token.kind != WaitKind.HUMAN_DECISION
            or token.owner_id != "human_operator"
            or token.command_id is not None
            or token.expected_event != "operator_resume"
        ):
            _fail("awaiting_human requires its matching human wait token")
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches + 1, active_command=False)
    elif phase == Phase.COMPLETED:
        if remaining or state.current_invocation is not None or state.current_batch is not None or command is not None or state.wait_token is not None:
            _fail("completed cannot retain active work")
        _validate_nonpause_history(state)
        if verification is None or not verification.passed or state.outcome_reason is not None:
            _fail("completed requires passing verification and no failure reason")
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches + 1, active_command=False)
    elif phase == Phase.FAILED:
        if remaining or state.current_invocation is not None or state.current_batch is not None or command is not None or state.wait_token is not None:
            _fail("failed cannot retain active work")
        _validate_nonpause_history(state)
        reason = state.outcome_reason
        if reason is None:
            _fail("failed requires a typed terminal reason")
        if reason.code == ReasonCode.STRUCTURAL_CHECK_FAILED:
            if verification is None or verification.passed:
                _fail("structural failure must retain a failed structural verification")
        elif reason.code == ReasonCode.HUMAN_DECLINED:
            if verification is None or not verification.passed:
                _fail("human-declined failure requires prior passing verification")
        else:
            _fail("failed reason is not a legal V0 terminal reason")
        _validate_nonpause_command_history(state, completed_count=3 * completed_batches + 1, active_command=False)
    elif phase == Phase.TECHNICAL_PAUSE:
        if state.current_invocation is not None or state.current_batch is not None or command is not None or state.wait_token is not None:
            _fail("technical_pause cannot retain active command, invocation, batch, or wait")
        if state.outcome_reason is None:
            _fail("technical_pause requires an actionable typed reason")
        _validate_materialized_history(state)
    else:
        _fail("unknown phase")

    counters = state.counters
    if counters.invocations != len(state.invocation_history) + (1 if state.current_invocation else 0):
        _fail("invocation counter is not authoritative")
    if counters.batches != len(state.batch_history) + (1 if state.current_batch else 0):
        _fail("batch counter is not authoritative")
    if counters.commands < len(completed) + len(uncertain) + (1 if command else 0):
        _fail("command counter undercounts durable commands")
    if counters.invocations > state.contract.max_invocations or counters.batches > state.contract.max_batches or counters.commands > state.contract.max_commands:
        _fail("bounded counter limit exceeded")
