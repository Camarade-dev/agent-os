"""Explicit opt-in offline orchestration for the isolated V0 controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from admissible.execution.bounded_write import WorkspaceAuthorityDescriptor
from admissible.v0_controller.adapters import (
    V0ProposalBackend,
    V0ProposalResult,
    admit_proposal_for_batch,
    proposal_backend_to_agent_result,
)
from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.cursor_dispatch import PersistedCursorDispatchRequest
from admissible.v0_controller.cursor_failures import V0BackendFailureKind, V0ProposalBackendFailure
from admissible.v0_controller.cursor_instruction import build_governed_instruction, expected_batch_id
from admissible.v0_controller.engine import TickResult, V0BoundedExecutorAdapter, V0ControllerEngine
from admissible.v0_controller.events import CommandDispatchStarted, Event, NoEvent, TechnicalFault
from admissible.v0_controller.integration_policy import WorkspaceIntegrationPolicy
from admissible.v0_controller.projection import project_control_surface
from admissible.v0_controller.reducer import IllegalTransition
from admissible.v0_controller.state import MissionContract, OutcomeReason, Phase, ReasonCode, SessionState, new_session_state
from admissible.v0_controller.store import AtomicSessionStore
from admissible.v0_controller.structural_checker import V0StructuralChecker
from admissible.v0_controller.workspace_guard import FilesystemIdentityPolicy, WorkspaceGuardError


CLI008_MANDATORY_PATHS: tuple[str, ...] = (
    "index.html",
    "style.css",
    "src/main.js",
    "src/game.js",
    "src/entities.js",
    "src/bots.js",
    "src/render.js",
    "LOCAL_DEV.md",
)


class OrchestratorStepKind(str, Enum):
    SESSION_CREATED = "session_created"
    INVOCATION_REQUESTED = "invocation_requested"
    COMMAND_DISPATCH_STARTED = "command_dispatch_started"
    PROPOSAL_DISPATCHED = "proposal_dispatched"
    PROPOSAL_ADMITTED = "proposal_admitted"
    BOUNDED_EXECUTION = "bounded_execution"
    STRUCTURAL_CHECK = "structural_check"
    NO_EVENT = "no_event"
    RESTART_PAUSE = "restart_pause"


@dataclass(frozen=True)
class OrchestratorStepResult:
    step_kind: OrchestratorStepKind
    tick: TickResult
    session_bytes: bytes


@dataclass(frozen=True)
class V0OfflineIntegrationConfig:
    """Explicit construction gate for Slice 2 offline integration."""

    store_directory: Path
    session_id: str
    contract: MissionContract
    proposal_backend: V0ProposalBackend
    bounded_executor_adapter: V0BoundedExecutorAdapter
    structural_checker: V0StructuralChecker
    workspace_integration_policy: WorkspaceIntegrationPolicy
    occurred_at: str
    filesystem_identity_policy: FilesystemIdentityPolicy | None = None
    workspace_authority: WorkspaceAuthorityDescriptor = field(init=False)

    def __post_init__(self) -> None:
        authority = self.workspace_integration_policy.capture_workspace_authority(
            self.contract.target_workspace,
            case_sensitive=(
                self.filesystem_identity_policy.case_sensitive
                if self.filesystem_identity_policy is not None
                else None
            ),
        )
        object.__setattr__(self, "workspace_authority", authority)


@dataclass(frozen=True)
class IntegrationRunProjection:
    """Read-only integration totals for inspection and regression assertions."""

    phase: str
    revision: int
    semantic_state_version: int
    backend_invocations: int
    proposal_results_consumed: int
    admitted_operations: int
    bounded_writes: int
    duplicate_writes: int
    partial_batches: int
    completed_batches: int
    interrupted_batches: int
    structural_checks: int
    materialized_paths: tuple[str, ...]
    remaining_paths: tuple[str, ...]
    pending_command_kind: str | None
    control_surface: dict[str, Any]

    @classmethod
    def from_state(
        cls,
        state: SessionState,
        *,
        backend_invocations: int,
        proposal_results_consumed: int,
        bounded_writes: int,
        duplicate_writes: int,
        structural_checks: int,
    ) -> "IntegrationRunProjection":
        partial_batches = sum(
            1
            for batch in state.batch_history
            if batch.status.value == "completed" and batch.remaining_mandatory_paths
        )
        completed_batches = sum(1 for batch in state.batch_history if batch.status.value == "completed")
        interrupted_batches = sum(1 for batch in state.batch_history if batch.status.value == "interrupted")
        admitted_operations = sum(len(batch.admitted_operation_ids) for batch in state.batch_history)
        if state.current_batch is not None:
            admitted_operations += len(state.current_batch.admitted_operation_ids)
        return cls(
            phase=state.phase.value,
            revision=state.revision,
            semantic_state_version=state.semantic_state_version,
            backend_invocations=backend_invocations,
            proposal_results_consumed=proposal_results_consumed,
            admitted_operations=admitted_operations,
            bounded_writes=len(state.execution_receipt_history),
            duplicate_writes=duplicate_writes,
            partial_batches=partial_batches,
            completed_batches=completed_batches,
            interrupted_batches=interrupted_batches,
            structural_checks=structural_checks,
            materialized_paths=tuple(item.path for item in state.materialized_evidence),
            remaining_paths=state.remaining_paths(),
            pending_command_kind=None if state.pending_command is None else state.pending_command.kind.value,
            control_surface=project_control_surface(state),
        )


class V0OfflineOrchestrator:
    """One external effect per persisted command; reconstruct from disk every step."""

    def __init__(self, config: V0OfflineIntegrationConfig) -> None:
        self.config = config
        self.store = AtomicSessionStore(config.store_directory)

    def fresh_engine(self) -> V0ControllerEngine:
        return V0ControllerEngine(
            self.store,
            bounded_executor_adapter=self.config.bounded_executor_adapter,
            filesystem_identity_policy=self.config.filesystem_identity_policy,
            dispatch_backend_fingerprint=self.backend_fingerprint(),
        )

    def backend_fingerprint(self) -> str | None:
        """The configured callable backend's identity, when it has one.

        A fixture backend has none: it never starts a process, so no persisted
        dispatch capability is issued for it.
        """

        fingerprint = getattr(self.config.proposal_backend, "config_fingerprint", None)
        return fingerprint if isinstance(fingerprint, str) and fingerprint else None

    def load_state(self) -> SessionState:
        return self.store.load(self.config.session_id)

    def session_bytes(self) -> bytes:
        return self.store.load(self.config.session_id).canonical_bytes()

    def create_session(self) -> OrchestratorStepResult:
        state = new_session_state(
            session_id=self.config.session_id,
            contract=self.config.contract,
            workspace_authority=self.config.workspace_authority,
        )
        tick = self.fresh_engine().create_session(state, occurred_at=self.config.occurred_at)
        return OrchestratorStepResult(
            step_kind=OrchestratorStepKind.SESSION_CREATED,
            tick=tick,
            session_bytes=self.session_bytes(),
        )

    def run_no_event_tick(self) -> OrchestratorStepResult:
        tick = self.fresh_engine().tick(self.config.session_id, NoEvent())
        return OrchestratorStepResult(
            step_kind=OrchestratorStepKind.NO_EVENT,
            tick=tick,
            session_bytes=self.session_bytes(),
        )

    def run_logical_tick(self) -> OrchestratorStepResult:
        state = self.load_state()
        engine = self.fresh_engine()
        if state.phase in {Phase.COMPLETED, Phase.FAILED, Phase.TECHNICAL_PAUSE}:
            tick = engine.tick(self.config.session_id, NoEvent())
            return OrchestratorStepResult(OrchestratorStepKind.NO_EVENT, tick, self.session_bytes())
        pending = state.pending_command
        if pending is None:
            if state.phase == Phase.READY_TO_INVOKE:
                try:
                    engine.ensure_workspace_authority(state)
                except WorkspaceGuardError as exc:
                    tick = engine.tick(
                        self.config.session_id,
                        TechnicalFault(engine._workspace_authority_reason(exc)),
                    )
                    return OrchestratorStepResult(OrchestratorStepKind.NO_EVENT, tick, self.session_bytes())
                tick = engine.tick(self.config.session_id)
                return OrchestratorStepResult(OrchestratorStepKind.INVOCATION_REQUESTED, tick, self.session_bytes())
            tick = engine.tick(self.config.session_id, NoEvent())
            return OrchestratorStepResult(OrchestratorStepKind.NO_EVENT, tick, self.session_bytes())
        if pending.status == CommandStatus.IN_FLIGHT:
            restart = engine.restart_pending_command(self.config.session_id)
            if isinstance(restart, Command):
                raise IllegalTransition("in-flight command cannot be replayed automatically")
            return OrchestratorStepResult(OrchestratorStepKind.RESTART_PAUSE, restart, self.session_bytes())
        if pending.status != CommandStatus.PREPARED or pending.command_id is None:
            raise IllegalTransition("prepared command must be materialized before dispatch")
        if pending.kind == CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            if pending.status == CommandStatus.PREPARED:
                engine.tick(self.config.session_id, CommandDispatchStarted(pending.command_id))
            tick = self.fresh_engine().execute_bounded_once(self.config.session_id)
            return OrchestratorStepResult(OrchestratorStepKind.BOUNDED_EXECUTION, tick, self.session_bytes())
        started = engine.tick(self.config.session_id, CommandDispatchStarted(pending.command_id))
        event = self._dispatch_prepared_command(started.state, started.pending_command or pending)
        tick = engine.tick(self.config.session_id, event)
        step_kind = self._step_kind_for_command(pending.kind)
        return OrchestratorStepResult(step_kind, tick, self.session_bytes())

    @staticmethod
    def _step_kind_for_command(kind: CommandKind) -> OrchestratorStepKind:
        if kind == CommandKind.DISPATCH_AGENT:
            return OrchestratorStepKind.PROPOSAL_DISPATCHED
        if kind == CommandKind.ADMIT_PROPOSAL:
            return OrchestratorStepKind.PROPOSAL_ADMITTED
        if kind == CommandKind.RUN_STRUCTURAL_CHECK:
            return OrchestratorStepKind.STRUCTURAL_CHECK
        return OrchestratorStepKind.COMMAND_DISPATCH_STARTED

    def _dispatch_prepared_command(self, state: SessionState, command: Command) -> Event:
        engine = self.fresh_engine()
        guard = engine._guard(state)
        try:
            # Every external or mutation-capable stage has its own authority
            # gate; configuration-time validation is never reused as proof.
            engine.ensure_workspace_authority(state)
        except WorkspaceGuardError as exc:
            return TechnicalFault(engine._workspace_authority_reason(exc))
        if command.kind == CommandKind.DISPATCH_AGENT:
            backend = self.config.proposal_backend
            try:
                result = self._invoke_proposal_backend(state, command, backend)
                return proposal_backend_to_agent_result(backend=backend, command=command, result=result)
            except V0ProposalBackendFailure as failure:
                # Fail closed.  Slice 3 never retries and never falls back to the
                # legacy backend: the operator disposes of the paused session.
                return TechnicalFault(failure.to_reason())
        if command.kind == CommandKind.ADMIT_PROPOSAL:
            batch = state.current_batch
            if batch is None:
                return TechnicalFault(
                    OutcomeReason(
                        ReasonCode.INVALID_EXTERNAL_RESULT,
                        "Admission requested without an active admitting batch.",
                        "Inspect persisted V0 state before continuing.",
                    )
                )
            try:
                return admit_proposal_for_batch(state=state, batch=batch, guard=guard)
            except WorkspaceGuardError as exc:
                return TechnicalFault(engine._workspace_authority_reason(exc))
        if command.kind == CommandKind.RUN_STRUCTURAL_CHECK:
            try:
                return self.config.structural_checker.check(command=command, state=state, guard=guard)
            except WorkspaceGuardError as exc:
                return TechnicalFault(engine._workspace_authority_reason(exc))
        raise IllegalTransition(f"unsupported prepared command for offline dispatch: {command.kind.value}")

    def _invoke_proposal_backend(
        self,
        state: SessionState,
        command: Command,
        backend: V0ProposalBackend,
    ) -> V0ProposalResult:
        """Dispatch one persisted agent command to the configured backend.

        A backend with store-backed persisted dispatch authority (the real Cursor
        backend) receives *identifiers only* and reloads the session itself; the
        in-memory ``state``/``command`` here are never its authority.  A fixture
        backend, which starts no process, keeps the pure in-memory seam.
        """

        persisted = getattr(backend, "invoke_persisted", None)
        if callable(persisted):
            fingerprint = self.backend_fingerprint()
            if not fingerprint:
                raise V0ProposalBackendFailure(
                    V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH,
                    "A store-backed callable backend must expose a configuration fingerprint.",
                )
            request = PersistedCursorDispatchRequest(
                session_id=self.config.session_id,
                command_id=command.command_id or "",
                invocation_id=command.owner_id,
                batch_id=expected_batch_id(state, command.owner_id),
                expected_revision=state.revision,
                backend_fingerprint=fingerprint,
            )
            return persisted(request=request)
        instruction = build_governed_instruction(state=state, command=command)
        return backend.invoke(command=command, instruction=instruction)

    def projection(self) -> IntegrationRunProjection:
        state = self.load_state()
        backend = self.config.proposal_backend
        executor = self.config.bounded_executor_adapter
        checker = self.config.structural_checker
        invocations = getattr(backend, "invocation_count", 0)
        consumed = getattr(backend, "results_consumed", 0)
        writes = getattr(executor, "write_count", 0)
        duplicate_writes = getattr(executor, "duplicate_write_attempts", 0)
        structural_checks = getattr(checker, "check_count", 0)
        return IntegrationRunProjection.from_state(
            state,
            backend_invocations=invocations,
            proposal_results_consumed=consumed,
            bounded_writes=writes,
            duplicate_writes=duplicate_writes,
            structural_checks=structural_checks,
        )

    def run_until_awaiting_human(self, *, max_steps: int = 128) -> list[OrchestratorStepResult]:
        steps: list[OrchestratorStepResult] = []
        for _ in range(max_steps):
            if self.load_state().phase == Phase.AWAITING_HUMAN:
                break
            steps.append(self.run_logical_tick())
        return steps

    def run_no_event_stability(self, *, ticks: int = 20) -> list[OrchestratorStepResult]:
        return [self.run_no_event_tick() for _ in range(ticks)]


def cli008_contract(
    *,
    target_workspace: Path,
    contract_id: str = "cli008-offline-two-batch",
    mission_specification: str = "",
) -> MissionContract:
    return MissionContract(
        contract_id=contract_id,
        target_workspace=str(target_workspace),
        mandatory_paths=CLI008_MANDATORY_PATHS,
        structural_completion_only=False,
        max_invocations=8,
        max_batches=8,
        max_commands=32,
        mission_specification=mission_specification,
    )
