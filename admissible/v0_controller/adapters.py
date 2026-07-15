"""V0 Slice 2 adapters: fixture proposal backend, admission, bounded executor."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any, Callable, Mapping, Protocol

from admissible.execution.bounded_write import (
    BoundedWriteError,
    BoundedWriteRequest,
    CompletedWriteInterruption,
    PhysicalAttestationError,
    attest_physical_file,
    execute_bounded_write,
    validate_bounded_write_content,
)
from admissible.v0_controller.commands import Command, CommandKind
from admissible.v0_controller.events import (
    ActionsAdmitted,
    AgentResultReceived,
    Event,
    ExecutionCapability,
    ExecutionReceipt,
    TechnicalFault,
    V0ExecutionInterrupted,
    V0ExecutionResultEnvelope,
    bounded_interruption_diagnostic,
)
from admissible.v0_controller.state import (
    BatchRecord,
    OutcomeReason as StateOutcomeReason,
    Phase,
    ProposedOperation,
    ReasonCode,
    SessionState,
)
from admissible.v0_controller.workspace_guard import (
    ValidatedTarget,
    ValidatedWorkspaceTarget,
    WorkspaceGuard,
    WorkspaceGuardError,
)

ALLOWED_V0_PROPOSAL_OPERATIONS = frozenset({"write_file"})
MAX_PROPOSAL_OPERATIONS = 4
DIAGNOSTIC_RETENTION_CAP_BYTES = 1_048_576


def _reason(code: ReasonCode, message: str, action: str) -> StateOutcomeReason:
    return StateOutcomeReason(code=code, message=message, operator_action=action)


@dataclass(frozen=True)
class V0ProposalOperation:
    action_id: str
    path: str
    content: object
    operation_kind: object = "write_file"
    include_operation_kind: bool = True

    def to_operation_dict(self) -> dict[str, Any]:
        operation = {"path": self.path, "content": self.content}
        if self.include_operation_kind:
            operation["operation"] = self.operation_kind
        return operation


@dataclass(frozen=True)
class V0ProposalResult:
    """Typed proposal-only backend result; diagnostics are not lifecycle authority.

    ``output_truncated`` and the identity fields are explicit metadata: a backend
    must never let a truncated stream masquerade as a complete one, and the
    engine must be able to say exactly which backend, model, and transport
    produced a proposal.  Materialized execution evidence is never carried here.
    """

    invocation_id: str
    result_id: str
    batch_id: str
    response_reference: str
    operations: tuple[V0ProposalOperation, ...]
    diagnostics: tuple[str, ...] = ()
    retained_diagnostic_stream: str = ""
    output_truncated: bool = False
    backend_identity: str = ""
    model_identity: str = ""
    transport_identity: str = ""
    # The dispatch/config fingerprint the result was produced under.  Result
    # consumption verifies it, so a result cannot be consumed by a backend whose
    # configuration is not the one that produced it.
    config_fingerprint: str = ""
    # The nonce from the independently persisted dispatch authority.  It is
    # checked by the real backend before a result may be consumed.
    dispatch_nonce: str = ""

    @property
    def retained_diagnostic_bytes(self) -> int:
        return len(self.retained_diagnostic_stream.encode("utf-8"))


class V0ProposalBackend(Protocol):
    """Protocol for any proposal-only callable backend (fixture or real Cursor)."""

    @property
    def invocation_count(self) -> int:
        ...

    @property
    def results_consumed(self) -> int:
        ...

    def invoke(self, *, command: Command, instruction: Mapping[str, Any]) -> V0ProposalResult:
        ...

    def mark_result_consumed(self, result: V0ProposalResult | None = None) -> None:
        ...

    def retain_diagnostic_stream(self, stream: str) -> tuple[str, bool]:
        ...


@dataclass
class FixtureProposalBackend:
    """Offline scripted proposal backend; never writes the target workspace."""

    identity: str = "v0-fixture-proposal-backend"
    protocol_version: str = "fixture-proposal-v1"
    _scripts: dict[str, V0ProposalResult] = field(default_factory=dict)
    _sequence_builders: list[Callable[[str], V0ProposalResult]] = field(default_factory=list)
    _sequence_index: int = 0
    _invocation_count: int = 0
    _results_consumed: int = 0
    retained_diagnostic_total_bytes: int = 0

    @property
    def invocation_count(self) -> int:
        return self._invocation_count

    @property
    def results_consumed(self) -> int:
        return self._results_consumed

    def register_script(self, invocation_id: str, result: V0ProposalResult) -> None:
        self._scripts[invocation_id] = result

    def register_sequence_builder(self, builder: Callable[[str], V0ProposalResult]) -> None:
        self._sequence_builders.append(builder)

    def invoke(self, *, command: Command, instruction: Mapping[str, Any]) -> V0ProposalResult:
        if command.kind != CommandKind.DISPATCH_AGENT:
            raise ValueError("fixture proposal backend accepts dispatch_agent commands only")
        invocation_id = str(instruction.get("invocation_id") or command.owner_id)
        if invocation_id in self._scripts:
            result = self._scripts[invocation_id]
        elif self._sequence_index < len(self._sequence_builders):
            result = self._sequence_builders[self._sequence_index](invocation_id)
            self._sequence_index += 1
        else:
            raise KeyError(f"no fixture script registered for invocation {invocation_id!r}")
        if result.invocation_id != invocation_id:
            raise ValueError("fixture script invocation_id does not match requested invocation")
        self._invocation_count += 1
        return result

    def mark_result_consumed(self, result: V0ProposalResult | None = None) -> None:
        self._results_consumed += 1

    def retain_diagnostic_stream(self, stream: str) -> tuple[str, bool]:
        encoded = stream.encode("utf-8")
        truncated = len(encoded) > DIAGNOSTIC_RETENTION_CAP_BYTES
        if truncated:
            retained = encoded[:DIAGNOSTIC_RETENTION_CAP_BYTES].decode("utf-8", errors="ignore")
            self.retained_diagnostic_total_bytes += DIAGNOSTIC_RETENTION_CAP_BYTES
            return retained, True
        self.retained_diagnostic_total_bytes += len(encoded)
        return stream, False


def build_cli008_turn1_result(*, invocation_id: str, batch_id: str | None = None, large_diagnostic: bool = True) -> V0ProposalResult:
    resolved_batch = batch_id or f"{invocation_id}:batch-1"
    operations = (
        V0ProposalOperation("turn1-index", "index.html", "<!DOCTYPE html><html><head><title>CLI008</title></head><body></body></html>"),
        V0ProposalOperation("turn1-style", "style.css", "body { margin: 0; font-family: sans-serif; }"),
        V0ProposalOperation("turn1-entities", "src/entities.js", "export function createEntity() { return { id: 1 }; }"),
        V0ProposalOperation("turn1-local-dev", "LOCAL_DEV.md", "# Local development\n\nOpen index.html in a browser.\n"),
    )
    diagnostic_stream = ""
    if large_diagnostic:
        diagnostic_stream = "DIAGNOSTIC-PADDING-" + ("x" * (DIAGNOSTIC_RETENTION_CAP_BYTES + 1024))
    return V0ProposalResult(
        invocation_id=invocation_id,
        result_id=f"{invocation_id}:result:1",
        batch_id=resolved_batch,
        response_reference=f"fixture://cli008/{resolved_batch}",
        operations=operations,
        diagnostics=("fixture_turn_1",),
        retained_diagnostic_stream=diagnostic_stream,
    )


def build_cli008_turn2_result(*, invocation_id: str, batch_id: str | None = None) -> V0ProposalResult:
    resolved_batch = batch_id or f"{invocation_id}:batch-2"
    operations = (
        V0ProposalOperation("turn2-render", "src/render.js", "export function render() { return '<div></div>'; }"),
        V0ProposalOperation("turn2-bots", "src/bots.js", "export function createBot() { return { id: 'bot' }; }"),
        V0ProposalOperation("turn2-game", "src/game.js", "export function startGame() { return { running: true }; }"),
        V0ProposalOperation("turn2-main", "src/main.js", "import { startGame } from './game.js';\nstartGame();\n"),
    )
    return V0ProposalResult(
        invocation_id=invocation_id,
        result_id=f"{invocation_id}:result:2",
        batch_id=resolved_batch,
        response_reference=f"fixture://cli008/{resolved_batch}",
        operations=operations,
        diagnostics=("fixture_turn_2",),
    )


def proposal_result_to_operations(result: V0ProposalResult) -> tuple[ProposedOperation, ...]:
    proposed: list[ProposedOperation] = []
    for item in result.operations:
        proposed.append(
            ProposedOperation.from_operation(
                operation_id=item.action_id,
                operation=item.to_operation_dict(),
            )
        )
    return tuple(proposed)


def validate_proposal_operations(
    *,
    state: SessionState,
    operations: tuple[V0ProposalOperation, ...],
    guard: WorkspaceGuard,
    max_operations: int = MAX_PROPOSAL_OPERATIONS,
) -> tuple[str, ...] | StateOutcomeReason:
    if len(operations) > max_operations:
        return _reason(
            ReasonCode.INVALID_EXTERNAL_RESULT,
            f"Proposal contains more than {max_operations} operations.",
            "Inspect the backend response and start a new V0 session.",
        )
    action_ids = [item.action_id for item in operations]
    paths = [item.path for item in operations]
    if not action_ids or len(set(action_ids)) != len(action_ids):
        return _reason(
            ReasonCode.INVALID_EXTERNAL_RESULT,
            "Proposal action IDs must be unique and non-empty.",
            "Inspect the backend response and start a new V0 session.",
        )
    if len(set(paths)) != len(paths):
        return _reason(
            ReasonCode.INVALID_EXTERNAL_RESULT,
            "Proposal paths must be unique within one response.",
            "Inspect the backend response and start a new V0 session.",
        )
    remaining = set(state.remaining_paths())
    materialized = {item.path for item in state.materialized_evidence}
    for item in operations:
        operation = item.to_operation_dict()
        kind = operation.get("operation")
        if not isinstance(kind, str) or kind != "write_file":
            return _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                f"Unsupported proposal operation kind: {kind!r}.",
                "Inspect the backend response and start a new V0 session.",
            )
        if not state.contract.permits_path(item.path):
            return _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                f"Proposal path violates workspace policy: {item.path!r}.",
                "Inspect the backend response and start a new V0 session.",
            )
        if item.path not in state.mandatory_paths:
            return _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                f"Proposal path is outside the mission contract: {item.path!r}.",
                "Inspect the backend response and start a new V0 session.",
            )
        if item.path in materialized:
            return _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                f"Proposal path is already materialized: {item.path!r}.",
                "Inspect the backend response and start a new V0 session.",
            )
        if item.path not in remaining:
            return _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                f"Proposal path is not among remaining mandatory paths: {item.path!r}.",
                "Inspect the backend response and start a new V0 session.",
            )
        try:
            validate_bounded_write_content(item.path, item.content)
            guard.validate(item.path)
        except (BoundedWriteError, WorkspaceGuardError, ValueError) as exc:
            return _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                f"Proposal operation failed validation: {exc}",
                "Inspect the backend response and start a new V0 session.",
            )
    return tuple(action_ids)


def admit_proposal_for_batch(
    *,
    state: SessionState,
    batch: BatchRecord,
    guard: WorkspaceGuard,
) -> Event:
    if state.phase != Phase.ADMITTING or batch.batch_id != (state.current_batch.batch_id if state.current_batch else ""):
        return TechnicalFault(
            _reason(
                ReasonCode.INVALID_EXTERNAL_RESULT,
                "Admission requested without an active admitting batch.",
                "Inspect persisted V0 state before continuing.",
            )
        )
    operations = tuple(
        V0ProposalOperation(
            action_id=item.operation_id,
            path=item.path,
            content=item.operation.get("content"),
            operation_kind=item.operation.get("operation"),
        )
        for item in batch.proposed_operations
    )
    admission = validate_proposal_operations(state=state, operations=operations, guard=guard)
    if isinstance(admission, StateOutcomeReason):
        return TechnicalFault(admission)
    return ActionsAdmitted(batch_id=batch.batch_id, admitted_operation_ids=admission)


def proposal_backend_to_agent_result(
    *,
    backend: V0ProposalBackend,
    command: Command,
    result: V0ProposalResult,
) -> AgentResultReceived:
    """Convert one typed proposal result into the single reducer-facing fact.

    Consumption is exact-once: a backend that already consumed this result, or
    that is bound to another lifecycle, rejects here before any state changes.
    """

    retained, truncated = backend.retain_diagnostic_stream(result.retained_diagnostic_stream)
    diagnostics = (*result.diagnostics, f"result_id:{result.result_id}")
    if truncated or result.output_truncated:
        diagnostics = (*diagnostics, "diagnostic_stream_truncated")
    for label, value in (
        ("backend_identity", result.backend_identity),
        ("model_identity", result.model_identity),
        ("transport_identity", result.transport_identity),
    ):
        if value:
            diagnostics = (*diagnostics, f"{label}:{value}")
    backend.mark_result_consumed(result)
    return AgentResultReceived(
        invocation_id=result.invocation_id,
        batch_id=result.batch_id,
        response_reference=result.response_reference,
        proposed_operations=proposal_result_to_operations(result),
        diagnostics=diagnostics + (f"retained_diagnostic_bytes:{len(retained.encode('utf-8'))}",),
    )


_INTERRUPTION_REASON_CODES: dict[str, ReasonCode] = {
    "workspace_containment_changed": ReasonCode.WORKSPACE_CONTAINMENT_CHANGED,
    "workspace_authority_changed": ReasonCode.WORKSPACE_AUTHORITY_CHANGED,
    "physical_attestation_failed": ReasonCode.PHYSICAL_ATTESTATION_FAILED,
}


@dataclass
class BoundedLocalExecutorV0Adapter:
    """Trusted V0 adapter wrapping the existing bounded local write implementation.

    Operations run in the persisted admitted order.  A batch stopped part-way
    returns ``V0ExecutionInterrupted`` carrying the exact completed prefix, so
    a physical write that really happened is never discarded.
    """

    identity: str = "v0-bounded-local-executor"
    protocol_version: str = "bounded-local-v1"
    write_count: int = 0
    duplicate_write_attempts: int = 0
    envelope_count: int = 0
    interrupted_count: int = 0

    def _interrupted(
        self,
        *,
        command: Command,
        capability: ExecutionCapability,
        admitted_ids: tuple[str, ...],
        receipts: list[ExecutionReceipt],
        failed_action_id: str | None,
        diagnostic: str,
        message: str,
    ) -> V0ExecutionInterrupted:
        self.interrupted_count += 1
        return V0ExecutionInterrupted(
            capability=capability,
            receipts=tuple(receipts),
            remaining_action_ids=admitted_ids[len(receipts):],
            interruption_code=diagnostic,
            diagnostic=bounded_interruption_diagnostic(message),
            occurred_at=f"bounded-local:{command.command_id}",
            adapter_identity=self.identity,
            adapter_protocol_version=self.protocol_version,
            failure_reason=_reason(
                _INTERRUPTION_REASON_CODES.get(diagnostic, ReasonCode.EXECUTION_FAILED),
                bounded_interruption_diagnostic(f"{diagnostic}: {message}"),
                "Treat this V0 session as technically paused and start a new session after inspection.",
            ),
            failed_action_id=failed_action_id,
        )

    def _receipt(
        self,
        *,
        capability: ExecutionCapability,
        command: Command,
        action_id: str,
        path: str,
        target: ValidatedTarget,
        sha256: str,
        byte_count: int,
    ) -> ExecutionReceipt:
        return ExecutionReceipt(
            schema_version="admissible_v0_execution_receipt_v1",
            receipt_id=f"v0receipt:{command.command_id}:{action_id}",
            session_id=capability.session_id,
            issued_revision=capability.issued_revision,
            execution_command_id=capability.command_id,
            batch_id=capability.batch_id,
            invocation_id=capability.invocation_id,
            action_id=action_id,
            operation_kind="write_file",
            path=path,
            resolved_target=target.resolved_target,
            physical_identity_key=target.physical_identity_key,
            sha256=sha256,
            byte_count=byte_count,
            success=True,
        )

    def execute(
        self,
        *,
        command: Command,
        batch: BatchRecord,
        workspace_target: ValidatedWorkspaceTarget,
    ) -> V0ExecutionResultEnvelope | V0ExecutionInterrupted:
        if command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            raise ValueError("bounded executor adapter accepts execute_bounded_operations only")
        raw = command.payload["execution_capability"]
        if not isinstance(raw, dict):
            raise ValueError("execution capability must be an object")
        capability = ExecutionCapability.from_dict(raw)
        admitted_ids = batch.admitted_operation_ids
        by_id = {item.operation_id: item for item in batch.proposed_operations}
        if len(set(admitted_ids)) != len(admitted_ids) or not set(admitted_ids).issubset(by_id):
            raise ValueError("admitted batch operations do not match admitted ids")
        if not admitted_ids:
            raise ValueError("admitted batch is empty")
        admitted_ops = [by_id[action_id] for action_id in admitted_ids]

        receipts: list[ExecutionReceipt] = []
        for operation in admitted_ops:
            structured = operation.operation
            action_id = operation.operation_id
            path = operation.path
            target = workspace_target.target_for(path)
            try:
                if workspace_target.authority is not None:
                    guard = WorkspaceGuard(
                        workspace_target.resolved_workspace,
                        authority=workspace_target.authority,
                        identity_policy=workspace_target.identity_policy,
                    )
                    current_target = guard.validate(path)
                    if (
                        current_target.resolved_target != target.resolved_target
                        or current_target.physical_identity_key != target.physical_identity_key
                    ):
                        raise PhysicalAttestationError(
                            "bounded executor target changed before mutation",
                            diagnostic="workspace_containment_changed",
                        )
                write_result = execute_bounded_write(
                    BoundedWriteRequest(
                        workspace=workspace_target.resolved_workspace,
                        relative_path=path,
                        content=structured.get("content"),
                        workspace_authority=workspace_target.authority,
                    )
                )
                expected_content = structured.get("content")
                if not isinstance(expected_content, str):
                    raise PhysicalAttestationError(
                        "admitted write content is not a string",
                        diagnostic="physical_attestation_failed",
                    )
                if workspace_target.authority is not None:
                    facts = attest_physical_file(
                        authority=workspace_target.authority,
                        relative_path=path,
                        expected_resolved_target=target.resolved_target,
                        expected_physical_identity_key=target.physical_identity_key,
                        expected_content=expected_content.encode("utf-8"),
                    )
                    digest = facts.sha256
                    byte_count = facts.byte_count
                    resolved_after_write = facts.resolved_target
                    physical_identity = facts.physical_identity_key
                else:
                    digest = write_result.sha256
                    byte_count = write_result.byte_count
                    resolved_after_write = write_result.resolved_target
                    physical_identity = target.physical_identity_key
            except CompletedWriteInterruption as exc:
                # The write syscall completed; only the post-write authority
                # check failed.  Represent the accomplished effect, then stop.
                facts = exc.facts
                if (
                    facts.resolved_target != target.resolved_target
                    or facts.physical_identity_key != target.physical_identity_key
                ):
                    return self._interrupted(
                        command=command,
                        capability=capability,
                        admitted_ids=admitted_ids,
                        receipts=receipts,
                        failed_action_id=action_id,
                        diagnostic="physical_attestation_failed",
                        message="completed write cannot be correlated to its validated target",
                    )
                receipts.append(
                    self._receipt(
                        capability=capability,
                        command=command,
                        action_id=action_id,
                        path=path,
                        target=target,
                        sha256=facts.sha256,
                        byte_count=facts.byte_count,
                    )
                )
                self.write_count += 1
                return self._interrupted(
                    command=command,
                    capability=capability,
                    admitted_ids=admitted_ids,
                    receipts=receipts,
                    failed_action_id=None,
                    diagnostic=exc.diagnostic,
                    message=str(exc),
                )
            except (BoundedWriteError, WorkspaceGuardError) as exc:
                return self._interrupted(
                    command=command,
                    capability=capability,
                    admitted_ids=admitted_ids,
                    receipts=receipts,
                    failed_action_id=action_id,
                    diagnostic=getattr(exc, "diagnostic", "execution_failed"),
                    message=str(exc),
                )
            if write_result.overwritten:
                self.duplicate_write_attempts += 1
            if target.resolved_target != resolved_after_write or target.physical_identity_key != physical_identity:
                return self._interrupted(
                    command=command,
                    capability=capability,
                    admitted_ids=admitted_ids,
                    receipts=receipts,
                    failed_action_id=action_id,
                    diagnostic="physical_attestation_failed",
                    message="resolved target does not match validated workspace target",
                )
            receipts.append(
                self._receipt(
                    capability=capability,
                    command=command,
                    action_id=action_id,
                    path=path,
                    target=target,
                    sha256=digest,
                    byte_count=byte_count,
                )
            )
            self.write_count += 1

        if len(receipts) != len(admitted_ids):
            return self._interrupted(
                command=command,
                capability=capability,
                admitted_ids=admitted_ids,
                receipts=receipts,
                failed_action_id=None,
                diagnostic="execution_failed",
                message="executor returned a partial or extra receipt set",
            )
        self.envelope_count += 1
        return V0ExecutionResultEnvelope(
            capability=capability,
            receipts=tuple(receipts),
            success=True,
            occurred_at=f"bounded-local:{command.command_id}",
            adapter_identity=self.identity,
            adapter_protocol_version=self.protocol_version,
        )


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()
