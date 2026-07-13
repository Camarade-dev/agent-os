from __future__ import annotations

from dataclasses import replace
import ast
import errno
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from admissible.v0_controller.commands import CommandKind, CommandStatus
from admissible.v0_controller.engine import V0ControllerEngine
from admissible.v0_controller.events import (
    _BoundedExecutionCompleted,
    ActionsAdmitted,
    AgentResultReceived,
    BoundedExecutionCompleted,
    CommandDispatchStarted,
    ExecutionCapability,
    ExecutionReceipt,
    InvocationRequested,
    NoEvent,
    OperatorResume,
    StructuralCheckCompleted,
    TechnicalFault,
    V0ExecutionResultEnvelope,
)
from admissible.v0_controller.invariants import InvariantViolation, validate_state
from admissible.v0_controller.reducer import IllegalTransition, reduce
from admissible.v0_controller.state import (
    Counters,
    MissionContract,
    OutcomeReason,
    Phase,
    ReasonCode,
    StructuralFileCheck,
    WorkspacePolicy,
    new_session_state,
)
from admissible.v0_controller.store import (
    AtomicSessionStore,
    CommittedButDurabilityUncertain,
    DirectoryDurabilityStatus,
    DurabilityError,
    PreCommitFailure,
    StaleRevisionError,
)
from admissible.v0_controller.workspace_guard import (
    FilesystemIdentityPolicy,
    WorkspaceGuard,
    WorkspaceGuardError,
)


NOW = "2026-07-13T10:00:00Z"
SHA_A = "a" * 64
SHA_B = "b" * 64


def contract(root: Path, *, paths: tuple[str, ...] = ("src/main.py", "README.md"), structural_only: bool = False) -> MissionContract:
    return MissionContract(
        contract_id="contract-v0-test",
        target_workspace=str(root),
        mandatory_paths=paths,
        structural_completion_only=structural_only,
        max_invocations=8,
        max_batches=8,
        max_commands=32,
        workspace_policy=WorkspacePolicy(rejected_path_prefixes=(".admissible",)),
    )


def proposal(operation_id: str, path: str):
    from admissible.v0_controller.state import ProposedOperation

    return ProposedOperation.from_operation(
        operation_id=operation_id,
        operation={"operation": "write_file", "path": path, "content": f"content for {path}"},
    )


class CountingStore(AtomicSessionStore):
    def __init__(self, directory: str | Path, **kwargs) -> None:
        super().__init__(directory, **kwargs)
        self.writes = 0
        self.replaces = 0

    def _atomic_write(self, path, state):
        self.writes += 1
        return super()._atomic_write(path, state)

    def replace(self, state, *, expected_revision):
        self.replaces += 1
        return super().replace(state, expected_revision=expected_revision)


class OfflineReceiptAdapter:
    """Fixture-only implementation of the exact trusted executor protocol."""

    identity = "offline-v0-fixture"
    protocol_version = "fixture-v1"

    def __init__(self) -> None:
        self.receipts: tuple[ExecutionReceipt, ...] | None = None
        self.success = True
        self.failure_reason: OutcomeReason | None = None
        self.calls: list[tuple[object, object, object]] = []

    def execute(self, *, command, batch, workspace_target) -> V0ExecutionResultEnvelope:
        self.calls.append((command, batch, workspace_target))
        raw = command.payload["execution_capability"]
        capability = ExecutionCapability.from_dict(raw)
        receipts = self.receipts
        if receipts is None:
            receipts = tuple(
                ExecutionReceipt(
                    action_id=operation.operation_id,
                    operation_kind=operation.operation["operation"],
                    path=operation.path,
                    sha256=SHA_A,
                    byte_count=10,
                    success=True,
                )
                for operation in batch.proposed_operations
                if operation.operation_id in set(batch.admitted_operation_ids)
            )
        return V0ExecutionResultEnvelope(
            capability=capability,
            receipts=receipts,
            success=self.success,
            occurred_at=NOW,
            adapter_identity=self.identity,
            adapter_protocol_version=self.protocol_version,
            failure_reason=self.failure_reason,
        )


class Case:
    """A fixture-only V0 session with temporary physical workspace and adapter."""

    def __init__(
        self,
        testcase: unittest.TestCase,
        *,
        paths=("src/main.py", "README.md"),
        structural_only=False,
        store_type=CountingStore,
        target_workspace: Path | None = None,
        filesystem_identity_policy: FilesystemIdentityPolicy | None = None,
    ) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.store = store_type(self.root / "sessions")
        self.adapter = OfflineReceiptAdapter()
        self.engine = V0ControllerEngine(
            self.store,
            bounded_executor_adapter=self.adapter,
            filesystem_identity_policy=filesystem_identity_policy,
        )
        self.session_id = f"v0-{id(self)}"
        self.created = self.engine.create_session(
            new_session_state(
                session_id=self.session_id,
                contract=contract(target_workspace or self.workspace, paths=paths, structural_only=structural_only),
            ),
            occurred_at=NOW,
        ).state

    def state(self):
        return self.store.load(self.session_id)

    def session_path(self) -> Path:
        return self.store._path(self.session_id)

    def tick(self, event=None):
        return self.engine.tick(self.session_id, event).state

    def start(self):
        command = self.state().pending_command
        assert command is not None and command.command_id is not None
        return self.tick(CommandDispatchStarted(command.command_id))

    def to_waiting(self):
        prepared = self.tick()
        assert prepared.phase == Phase.READY_TO_INVOKE
        return self.start()

    def to_admitting(self, *, paths: tuple[str, ...] | None = None, batch_id="batch-1"):
        waiting = self.to_waiting()
        paths = self.state().mandatory_paths if paths is None else paths
        operations = tuple(proposal(f"op-{index}", path) for index, path in enumerate(paths, start=1))
        invocation = waiting.current_invocation
        assert invocation is not None
        return self.tick(
            AgentResultReceived(
                invocation_id=invocation.invocation_id,
                batch_id=batch_id,
                response_reference="fixture://response",
                proposed_operations=operations,
            )
        )

    def to_ready_execute(self, *, paths: tuple[str, ...] | None = None, batch_id="batch-1"):
        self.to_admitting(paths=paths, batch_id=batch_id)
        self.start()
        batch = self.state().current_batch
        assert batch is not None
        return self.tick(ActionsAdmitted(batch.batch_id, tuple(item.operation_id for item in batch.proposed_operations)))

    def receipt(self, action_id: str, *, sha256: str | None = SHA_A, path: str | None = None, operation_kind: str | None = None) -> ExecutionReceipt:
        batch = self.state().current_batch
        assert batch is not None
        operation = next(item for item in batch.proposed_operations if item.operation_id == action_id)
        return ExecutionReceipt(
            action_id=action_id,
            operation_kind=operation.operation["operation"] if operation_kind is None else operation_kind,
            path=operation.path if path is None else path,
            sha256=sha256,
            byte_count=10 if sha256 is not None else None,
            success=True,
        )

    def envelope(
        self,
        receipts: tuple[ExecutionReceipt, ...] | None = None,
        *,
        capability: ExecutionCapability | None = None,
        success: bool = True,
        failure_reason: OutcomeReason | None = None,
    ) -> V0ExecutionResultEnvelope:
        state = self.state()
        command = state.pending_command
        batch = state.current_batch
        assert command is not None and batch is not None
        if receipts is None:
            receipts = tuple(self.receipt(action_id) for action_id in batch.admitted_operation_ids)
        if capability is None:
            capability = ExecutionCapability.from_dict(command.payload["execution_capability"])
        return V0ExecutionResultEnvelope(
            capability=capability,
            receipts=receipts,
            success=success,
            occurred_at=NOW,
            adapter_identity=self.adapter.identity,
            adapter_protocol_version=self.adapter.protocol_version,
            failure_reason=failure_reason,
        )

    def consume(self, receipts: tuple[ExecutionReceipt, ...] | None = None, **kwargs):
        return self.engine.consume_trusted_execution_result(self.session_id, self.envelope(receipts, **kwargs)).state

    def to_checking(self):
        self.to_ready_execute()
        self.start()
        return self.consume()

    def to_awaiting_human(self):
        checking = self.to_checking()
        assert checking.phase == Phase.CHECKING_FILES
        self.start()
        checks = tuple(StructuralFileCheck(path, True, True, True, SHA_A) for path in self.state().mandatory_paths)
        return self.tick(StructuralCheckCompleted(checks=checks, occurred_at=NOW))

    def to_completed(self):
        awaiting = self.to_awaiting_human()
        assert awaiting.phase == Phase.AWAITING_HUMAN
        return self.tick(OperatorResume(approved=True, occurred_at=NOW))

    def to_failed(self):
        self.to_checking()
        self.start()
        checks = tuple(
            StructuralFileCheck(path, True, True, True, SHA_B if index == 0 else SHA_A)
            for index, path in enumerate(self.state().mandatory_paths)
        )
        return self.tick(StructuralCheckCompleted(checks=checks, occurred_at=NOW))


class TestV0ByteStability(unittest.TestCase):
    def _assert_twenty_no_event_ticks_are_byte_stable(self, case: Case) -> None:
        initial = case.state()
        bytes_before = case.session_path().read_bytes()
        writes_before = case.store.writes
        for _ in range(20):
            result = case.tick(NoEvent())
            self.assertEqual(result.phase, initial.phase)
            self.assertEqual(result.revision, initial.revision)
            self.assertEqual(result.semantic_state_version, initial.semantic_state_version)
            self.assertEqual(result.canonical_bytes(), initial.canonical_bytes())
            self.assertEqual(case.session_path().read_bytes(), bytes_before)
            self.assertEqual(case.store.writes, writes_before)

    def test_new_nonempty_ready_session_and_every_stable_wait_are_byte_stable(self) -> None:
        ready = Case(self)
        self.assertEqual(ready.created.phase, Phase.READY_TO_INVOKE)
        self._assert_twenty_no_event_ticks_are_byte_stable(ready)

        completed = Case(self)
        self.assertEqual(completed.to_completed().phase, Phase.COMPLETED)
        self._assert_twenty_no_event_ticks_are_byte_stable(completed)

        failed = Case(self)
        self.assertEqual(failed.to_failed().phase, Phase.FAILED)
        self._assert_twenty_no_event_ticks_are_byte_stable(failed)

        human = Case(self)
        self.assertEqual(human.to_awaiting_human().phase, Phase.AWAITING_HUMAN)
        self._assert_twenty_no_event_ticks_are_byte_stable(human)

        paused = Case(self)
        paused.tick(TechnicalFault(OutcomeReason(ReasonCode.DISPATCHER_FAILURE, "fixture fault", "inspect fixture")))
        self._assert_twenty_no_event_ticks_are_byte_stable(paused)

        waiting = Case(self)
        waiting.to_waiting()
        self._assert_twenty_no_event_ticks_are_byte_stable(waiting)

        admitting = Case(self)
        admitting.to_admitting()
        admitting.start()
        self._assert_twenty_no_event_ticks_are_byte_stable(admitting)

        executing = Case(self)
        executing.to_ready_execute()
        executing.start()
        self._assert_twenty_no_event_ticks_are_byte_stable(executing)

        checking = Case(self)
        checking.to_checking()
        checking.start()
        self._assert_twenty_no_event_ticks_are_byte_stable(checking)

    def test_unspecified_tick_may_request_deterministic_invocation_but_explicit_no_event_never_does(self) -> None:
        case = Case(self)
        explicit = case.tick(NoEvent())
        self.assertEqual(explicit.phase, Phase.READY_TO_INVOKE)
        self.assertIsNone(explicit.pending_command)
        requested = case.tick()
        self.assertEqual(requested.phase, Phase.READY_TO_INVOKE)
        self.assertEqual(requested.pending_command.kind, CommandKind.DISPATCH_AGENT)


class TestV0StoreOutcomes(unittest.TestCase):
    def _next_state(self, case: Case):
        current = case.state()
        result = reduce(current, InvocationRequested("store-direct", NOW))
        next_state = case.engine._materialize_commands(current, result)
        return replace(next_state, revision=current.revision + 1, semantic_state_version=current.semantic_state_version + 1)

    def test_create_and_changed_tick_write_once_unchanged_tick_writes_zero(self) -> None:
        case = Case(self)
        self.assertEqual(case.store.writes, 1)
        case.tick(NoEvent())
        self.assertEqual(case.store.writes, 1)
        case.tick()
        self.assertEqual(case.store.writes, 2)

    def test_temp_write_file_fsync_and_replace_failures_are_typed_precommit_and_preserve_prior_bytes(self) -> None:
        case = Case(self)
        before = case.state().canonical_bytes()
        with patch.object(case.store, "_write_temp_file", side_effect=DurabilityError("temp_write", "temp write failed")):
            with self.assertRaises(PreCommitFailure) as caught:
                case.store.replace(self._next_state(case), expected_revision=0)
        self.assertEqual(caught.exception.stage, "temp_write")
        self.assertEqual(case.state().canonical_bytes(), before)

        case = Case(self)
        before = case.state().canonical_bytes()
        with patch("admissible.v0_controller.store.os.fsync", side_effect=OSError(errno.EIO, "file fsync failed")):
            with self.assertRaises(PreCommitFailure) as caught:
                case.store.replace(self._next_state(case), expected_revision=0)
        self.assertEqual(caught.exception.stage, "file_fsync")
        self.assertEqual(case.state().canonical_bytes(), before)

        case = Case(self)
        before = case.state().canonical_bytes()
        with patch("admissible.v0_controller.store.os.replace", side_effect=OSError("replace denied")):
            with self.assertRaises(PreCommitFailure) as caught:
                case.store.replace(self._next_state(case), expected_revision=0)
        self.assertEqual(caught.exception.stage, "replace")
        self.assertEqual(case.state().canonical_bytes(), before)

    def test_unsupported_directory_fsync_is_committed_success(self) -> None:
        case = Case(self)
        next_state = self._next_state(case)
        with patch.object(case.store, "_fsync_directory", return_value=DirectoryDurabilityStatus.UNSUPPORTED):
            outcome = case.store.replace(next_state, expected_revision=0)
        self.assertEqual(outcome.directory_durability, DirectoryDurabilityStatus.UNSUPPORTED)
        self.assertEqual(case.state().canonical_bytes(), next_state.canonical_bytes())

    def test_post_replace_fsync_failure_is_visible_typed_commit_uncertainty(self) -> None:
        case = Case(self)
        next_state = self._next_state(case)
        fault = OSError(errno.EIO, "directory fsync failed")
        with patch.object(case.store, "_fsync_directory", side_effect=fault):
            with self.assertRaises(CommittedButDurabilityUncertain) as caught:
                case.store.replace(next_state, expected_revision=0)
        outcome = caught.exception
        self.assertEqual(outcome.session_id, case.session_id)
        self.assertEqual(outcome.committed_revision, next_state.revision)
        self.assertTrue(outcome.visibility_confirmed)
        self.assertIs(outcome.original_durability_error, fault)
        self.assertEqual(case.state().canonical_bytes(), next_state.canonical_bytes())

    def test_engine_pauses_after_visible_commit_without_retrying_that_commit(self) -> None:
        case = Case(self)
        fsync_outcomes = [OSError(errno.EIO, "directory fsync failed"), DirectoryDurabilityStatus.DURABLE]
        with patch.object(case.store, "_fsync_directory", side_effect=fsync_outcomes):
            paused = case.tick(InvocationRequested("durability-pause", NOW))
        self.assertEqual(paused.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(paused.outcome_reason.code, ReasonCode.DURABILITY_UNCERTAIN)
        self.assertEqual(case.store.replaces, 2)  # changed revision, then one distinct pause transition
        writes_after_pause = case.store.writes
        self.assertEqual(case.tick(NoEvent()).canonical_bytes(), paused.canonical_bytes())
        self.assertEqual(case.store.writes, writes_after_pause)

    def test_stale_revision_is_rejected(self) -> None:
        case = Case(self)
        original = case.state()
        case.tick()
        with self.assertRaises(StaleRevisionError):
            case.store.replace(replace(original, revision=1), expected_revision=0)

    def test_two_controllers_cannot_overwrite_same_revision(self) -> None:
        case = Case(self, store_type=AtomicSessionStore)
        barrier = threading.Barrier(2)

        class BarrierStore(AtomicSessionStore):
            def __init__(self, directory, gate) -> None:
                super().__init__(directory)
                self.gate = gate

            def load(self, session_id):
                state = super().load(session_id)
                if self.gate is not None:
                    gate, self.gate = self.gate, None
                    gate.wait(timeout=5)
                return state

        first = V0ControllerEngine(BarrierStore(case.store.directory, barrier))
        second = V0ControllerEngine(BarrierStore(case.store.directory, barrier))
        outcomes: list[object] = []

        def run(engine, invocation_id):
            try:
                outcomes.append(engine.tick(case.session_id, InvocationRequested(invocation_id, NOW)))
            except Exception as exc:
                outcomes.append(exc)

        threads = [
            threading.Thread(target=run, args=(first, "writer-a")),
            threading.Thread(target=run, args=(second, "writer-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sum(not isinstance(item, Exception) for item in outcomes), 1)
        self.assertEqual(sum(isinstance(item, StaleRevisionError) for item in outcomes), 1)


class TestV0PhaseHistoryInvariants(unittest.TestCase):
    def _phase_states(self):
        base = Case(self)
        plan = new_session_state(session_id="plan-only", contract=contract(base.workspace))
        ready = base.state()
        prepared = base.tick()
        waiting = base.start()
        invocation = waiting.current_invocation
        admitting = base.tick(
            AgentResultReceived(invocation.invocation_id, "batch-1", "fixture://result", (proposal("op-1", "src/main.py"),))
        )
        base.start()
        executing = base.tick(ActionsAdmitted("batch-1", ("op-1",)))
        base.start()
        partial = base.consume((base.receipt("op-1"),))
        checking_case = Case(self)
        checking = checking_case.to_checking()
        awaiting_case = Case(self)
        awaiting = awaiting_case.to_awaiting_human()
        completed_case = Case(self)
        completed = completed_case.to_completed()
        failed_case = Case(self)
        failed = failed_case.to_failed()
        paused_case = Case(self)
        paused = paused_case.tick(TechnicalFault(OutcomeReason(ReasonCode.DISPATCHER_FAILURE, "fault", "inspect")))
        return {
            Phase.PLAN: plan,
            Phase.READY_TO_INVOKE: ready,
            Phase.WAITING_FOR_AGENT: waiting,
            Phase.ADMITTING: admitting,
            Phase.READY_TO_EXECUTE: executing,
            Phase.CHECKING_FILES: checking,
            Phase.AWAITING_HUMAN: awaiting,
            Phase.COMPLETED: completed,
            Phase.FAILED: failed,
            Phase.TECHNICAL_PAUSE: paused,
            "prepared": prepared,
            "partial": partial,
        }

    def test_valid_phase_matrix_and_partial_continuation_validate(self) -> None:
        states = self._phase_states()
        for phase in Phase:
            validate_state(states[phase])
        validate_state(states["prepared"])
        validate_state(states["partial"])
        self.assertEqual(states["partial"].phase, Phase.READY_TO_INVOKE)
        self.assertEqual(states["partial"].remaining_paths(), ("README.md",))

    def test_plan_rejects_every_prior_lifecycle_family_before_persistence(self) -> None:
        states = self._phase_states()
        plan = states[Phase.PLAN]
        source = states["partial"]
        waiting = states[Phase.WAITING_FOR_AGENT]
        awaiting = states[Phase.AWAITING_HUMAN]
        paused = states[Phase.TECHNICAL_PAUSE]
        families = {
            "materialized_evidence": lambda state: replace(state, materialized_evidence=source.materialized_evidence),
            "current_invocation": lambda state: replace(state, current_invocation=waiting.current_invocation),
            "invocation_history": lambda state: replace(state, invocation_history=source.invocation_history),
            "current_batch": lambda state: replace(state, current_batch=states[Phase.ADMITTING].current_batch),
            "batch_history": lambda state: replace(state, batch_history=source.batch_history),
            "completed_commands": lambda state: replace(state, completed_command_ids=source.completed_command_ids),
            "uncertain_commands": lambda state: replace(state, uncertain_command_ids=("uncertain",)),
            "wait_token": lambda state: replace(state, wait_token=waiting.wait_token),
            "structural_verification": lambda state: replace(state, structural_verification=awaiting.structural_verification),
            "outcome": lambda state: replace(state, outcome_reason=paused.outcome_reason),
            "counters": lambda state: replace(state, counters=Counters(invocations=1)),
        }
        for family, inject in families.items():
            with self.subTest(family=family):
                with self.assertRaises(InvariantViolation):
                    validate_state(inject(plan))

    def test_table_driven_incompatible_authoritative_object_injections_reject(self) -> None:
        states = self._phase_states()
        source = states["partial"]
        waiting = states[Phase.WAITING_FOR_AGENT]
        awaiting = states[Phase.AWAITING_HUMAN]
        paused = states[Phase.TECHNICAL_PAUSE]
        families = {
            "active_invocation": (lambda state: replace(state, current_invocation=waiting.current_invocation), {Phase.READY_TO_INVOKE, Phase.WAITING_FOR_AGENT}),
            "invocation_history": (lambda state: replace(state, invocation_history=source.invocation_history), {Phase.ADMITTING, Phase.READY_TO_EXECUTE}),
            "active_batch": (lambda state: replace(state, current_batch=states[Phase.ADMITTING].current_batch), {Phase.ADMITTING, Phase.READY_TO_EXECUTE}),
            "batch_history": (lambda state: replace(state, batch_history=source.batch_history), set()),
            "evidence": (lambda state: replace(state, materialized_evidence=source.materialized_evidence), set()),
            "pending_command": (lambda state: replace(state, pending_command=states[Phase.READY_TO_EXECUTE].pending_command), {Phase.READY_TO_EXECUTE}),
            "wait": (lambda state: replace(state, wait_token=awaiting.wait_token), {Phase.AWAITING_HUMAN}),
            "verification": (lambda state: replace(state, structural_verification=awaiting.structural_verification), {Phase.AWAITING_HUMAN, Phase.COMPLETED, Phase.FAILED, Phase.TECHNICAL_PAUSE}),
            "outcome": (lambda state: replace(state, outcome_reason=paused.outcome_reason), {Phase.TECHNICAL_PAUSE}),
            "receipt_history": (lambda state: replace(state, materialized_evidence=source.materialized_evidence), set()),
            "lifecycle_counters": (lambda state: replace(state, counters=replace(state.counters, commands=state.counters.commands + 1)), {Phase.TECHNICAL_PAUSE}),
        }
        for phase in Phase:
            baseline = states[phase]
            for family, (inject, allowed) in families.items():
                if phase in allowed:
                    continue
                with self.subTest(phase=phase.value, family=family):
                    with self.assertRaises(InvariantViolation):
                        validate_state(inject(baseline))

    def test_terminal_and_pause_states_reject_active_objects(self) -> None:
        states = self._phase_states()
        for phase in (Phase.COMPLETED, Phase.FAILED, Phase.TECHNICAL_PAUSE):
            with self.subTest(phase=phase.value):
                with self.assertRaises(InvariantViolation):
                    validate_state(replace(states[phase], current_batch=states[Phase.ADMITTING].current_batch))

    def test_v0_imports_no_legacy_controller_or_control_surface_authority(self) -> None:
        package = Path(__file__).parents[1] / "admissible" / "v0_controller"
        forbidden = ("admissible.high_autonomy_controller", "admissible.control_surface")
        imports: list[str] = []
        for source_path in package.glob("*.py"):
            tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
        self.assertFalse(any(name == item or name.startswith(f"{item}.") for name in imports for item in forbidden))


class TestV0ReducerPurity(unittest.TestCase):
    def _assert_deterministic(self, state, event) -> None:
        before = state.canonical_bytes()
        first = reduce(state, event)
        second = reduce(state, event)
        self.assertEqual(state.canonical_bytes(), before)
        self.assertEqual(first, second)

    def test_mutating_transition_inputs_are_byte_immutable_and_deterministic(self) -> None:
        case = Case(self)
        plan = new_session_state(session_id="pure-plan", contract=contract(case.workspace))
        self._assert_deterministic(plan, __import__("admissible.v0_controller.events", fromlist=["SessionCreated"]).SessionCreated("pure-plan", NOW))

        ready = case.state()
        self._assert_deterministic(ready, InvocationRequested("pure-invocation", NOW))
        prepared = case.tick(InvocationRequested("pure-invocation", NOW))
        self._assert_deterministic(prepared, CommandDispatchStarted(prepared.pending_command.command_id))
        waiting = case.start()
        self._assert_deterministic(
            waiting,
            AgentResultReceived(waiting.current_invocation.invocation_id, "pure-batch", "fixture://pure", (proposal("pure-op", "src/main.py"),)),
        )
        admitting = case.tick(
            AgentResultReceived(waiting.current_invocation.invocation_id, "pure-batch", "fixture://pure", (proposal("pure-op", "src/main.py"),))
        )
        admission_inflight = case.start()
        self._assert_deterministic(admission_inflight, ActionsAdmitted("pure-batch", ("pure-op",)))
        execution = case.tick(ActionsAdmitted("pure-batch", ("pure-op",)))
        execution_inflight = case.start()
        receipt = case.receipt("pure-op")
        targets = WorkspaceGuard(case.workspace, case.state().contract.workspace_policy).validate_distinct((receipt.path,))
        internal = _BoundedExecutionCompleted(
            execution_command_id=execution_inflight.pending_command.command_id,
            batch_id="pure-batch",
            invocation_id=execution_inflight.current_batch.invocation_id,
            success=True,
            receipts=(receipt,),
            validated_targets=targets,
            occurred_at=NOW,
            adapter_identity=case.adapter.identity,
            adapter_protocol_version=case.adapter.protocol_version,
        )
        self._assert_deterministic(execution_inflight, internal)

        completed_execution = case.consume((receipt,))
        self.assertEqual(completed_execution.phase, Phase.READY_TO_INVOKE)

        structural = Case(self)
        structural.to_checking()
        checking_inflight = structural.start()
        checks = tuple(StructuralFileCheck(path, True, True, True, SHA_A) for path in checking_inflight.mandatory_paths)
        self._assert_deterministic(checking_inflight, StructuralCheckCompleted(checks, NOW))

        human = Case(self)
        awaiting = human.to_awaiting_human()
        self._assert_deterministic(awaiting, OperatorResume(True, NOW))


class TestV0TrustedExecutorBoundary(unittest.TestCase):
    def _execution_case(self):
        case = Case(self)
        case.to_ready_execute()
        case.start()
        return case

    def _raw_completion(self, case: Case) -> BoundedExecutionCompleted:
        state = case.state()
        command = state.pending_command
        batch = state.current_batch
        return BoundedExecutionCompleted(
            execution_command_id=command.command_id,
            batch_id=batch.batch_id,
            invocation_id=batch.invocation_id,
            success=True,
            receipts=tuple(case.receipt(action_id) for action_id in batch.admitted_operation_ids),
            occurred_at=NOW,
        )

    def test_raw_public_completion_injection_is_rejected_without_evidence(self) -> None:
        case = self._execution_case()
        before = case.state().canonical_bytes()
        with self.assertRaises(IllegalTransition):
            case.tick(self._raw_completion(case))
        self.assertEqual(case.state().canonical_bytes(), before)

    def test_configured_fixture_adapter_envelope_creates_evidence_exactly_once(self) -> None:
        case = self._execution_case()
        checked = case.engine.execute_bounded_once(case.session_id).state
        self.assertEqual(checked.phase, Phase.CHECKING_FILES)
        self.assertEqual(len(case.adapter.calls), 1)
        self.assertEqual({item.path for item in checked.materialized_evidence}, {"src/main.py", "README.md"})
        self.assertTrue(all(item.execution_command_id for item in checked.materialized_evidence))
        self.assertTrue(all(item.physical_identity_key for item in checked.materialized_evidence))

    def test_forged_replayed_and_cross_lifecycle_capabilities_are_rejected(self) -> None:
        case = self._execution_case()
        envelope = case.envelope()
        capability = envelope.capability
        for field, value in (
            ("nonce", "forged"),
            ("session_id", "other-session"),
            ("command_id", "other-command"),
            ("batch_id", "other-batch"),
            ("invocation_id", "other-invocation"),
            ("issued_revision", capability.issued_revision + 1),
        ):
            with self.subTest(field=field):
                forged = replace(capability, **{field: value})
                with self.assertRaises(IllegalTransition):
                    case.engine.consume_trusted_execution_result(case.session_id, replace(envelope, capability=forged))

        other = self._execution_case()
        with self.assertRaises(IllegalTransition):
            other.engine.consume_trusted_execution_result(other.session_id, envelope)

        case.engine.consume_trusted_execution_result(case.session_id, envelope)
        with self.assertRaises(IllegalTransition):
            case.engine.consume_trusted_execution_result(case.session_id, envelope)

    def test_bad_receipt_shapes_are_rejected_at_internal_semantic_boundary(self) -> None:
        case = self._execution_case()
        with self.assertRaises(IllegalTransition):
            case.engine.consume_trusted_execution_result(case.session_id, case.envelope(()))

        case = self._execution_case()
        batch = case.state().current_batch
        duplicate = case.receipt(batch.admitted_operation_ids[0])
        with self.assertRaises(IllegalTransition):
            case.engine.consume_trusted_execution_result(case.session_id, case.envelope((duplicate, duplicate)))

        case = self._execution_case()
        batch = case.state().current_batch
        receipts = tuple(case.receipt(action_id) for action_id in batch.admitted_operation_ids)
        with self.assertRaises(IllegalTransition):
            case.engine.consume_trusted_execution_result(
                case.session_id,
                case.envelope((replace(receipts[0], action_id="unknown"), receipts[1])),
            )


class TestV0PhysicalIdentity(unittest.TestCase):
    def _case_insensitive_policy(self) -> FilesystemIdentityPolicy:
        return FilesystemIdentityPolicy(case_sensitive=False)

    def test_same_batch_case_alias_is_rejected_before_evidence(self) -> None:
        case = Case(
            self,
            paths=("CaseDir/file.txt", "casedir/file.txt"),
            filesystem_identity_policy=self._case_insensitive_policy(),
        )
        case.to_ready_execute()
        case.start()
        before = case.state().canonical_bytes()
        with self.assertRaises(WorkspaceGuardError):
            case.consume()
        self.assertEqual(case.state().canonical_bytes(), before)

    def test_cross_batch_case_alias_is_rejected_and_prior_evidence_is_unchanged(self) -> None:
        case = Case(
            self,
            paths=("CaseDir/file.txt", "casedir/file.txt"),
            filesystem_identity_policy=self._case_insensitive_policy(),
        )
        case.to_ready_execute(paths=("CaseDir/file.txt",))
        case.start()
        first = case.consume()
        prior_evidence = first.materialized_evidence
        waiting = case.to_waiting()
        case.tick(
            AgentResultReceived(
                waiting.current_invocation.invocation_id,
                "batch-2",
                "fixture://alias",
                (proposal("op-alias", "casedir/file.txt"),),
            )
        )
        case.start()
        case.tick(ActionsAdmitted("batch-2", ("op-alias",)))
        case.start()
        before = case.state().canonical_bytes()
        with self.assertRaises(WorkspaceGuardError):
            case.consume()
        self.assertEqual(case.state().canonical_bytes(), before)
        self.assertEqual(case.state().materialized_evidence, prior_evidence)

    def test_cross_batch_symlink_alias_is_rejected_when_supported(self) -> None:
        case = Case(self, paths=("real/file.txt", "alias/file.txt"))
        (case.workspace / "real").mkdir()
        alias = case.workspace / "alias"
        try:
            alias.symlink_to(case.workspace / "real", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")
        case.to_ready_execute(paths=("real/file.txt",))
        case.start()
        case.consume()
        waiting = case.to_waiting()
        case.tick(AgentResultReceived(waiting.current_invocation.invocation_id, "batch-2", "fixture://alias", (proposal("op-alias", "alias/file.txt"),)))
        case.start()
        case.tick(ActionsAdmitted("batch-2", ("op-alias",)))
        case.start()
        prior = case.state().materialized_evidence
        with self.assertRaises(WorkspaceGuardError):
            case.consume()
        self.assertEqual(case.state().materialized_evidence, prior)

    def test_windows_alias_syntax_rejected_and_distinct_nested_paths_accepted(self) -> None:
        guard = WorkspaceGuard(self._workspace(), WorkspacePolicy())
        for path in ("file.txt.", "file.txt ", "dir /file.txt", "dir/file.txt:stream"):
            with self.subTest(path=path):
                with self.assertRaises(WorkspaceGuardError):
                    guard.validate(path)
        targets = guard.validate_distinct(("nested/one/file.txt", "nested/two/file.txt"))
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0].physical_identity_key, targets[1].physical_identity_key)

    def _workspace(self) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "workspace"
        root.mkdir()
        return root


class TestV0WorkspaceGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "workspace"
        self.root.mkdir()
        self.guard = WorkspaceGuard(self.root, WorkspacePolicy(rejected_path_prefixes=("artifacts",)))

    def test_rejects_noncanonical_traversal_absolute_drive_ads_separator_and_windows_alias_forms(self) -> None:
        invalid = (
            "../escape.txt", "/absolute.txt", "C:drive-relative.txt", "C:/absolute.txt", "dir\\backslash.txt",
            "dir:stream.txt", "dir//double.txt", "./dot.txt", "artifacts/out.txt", "file.", "file ",
        )
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(WorkspaceGuardError):
                    self.guard.validate(path)

    def test_returns_durable_target_identity_and_forceable_case_policy(self) -> None:
        target = self.guard.validate("nested/file.txt")
        self.assertEqual(target.relative_path, "nested/file.txt")
        self.assertEqual(target.resolved_target, str((self.root / "nested" / "file.txt").resolve()))
        insensitive = WorkspaceGuard(self.root, identity_policy=FilesystemIdentityPolicy(case_sensitive=False))
        with self.assertRaises(WorkspaceGuardError):
            insensitive.validate_distinct(("CaseDir/file.txt", "casedir/file.txt"))

    def test_symlink_escape_and_alias_are_rejected_when_supported(self) -> None:
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        escape = self.root / "escape"
        real = self.root / "real"
        real.mkdir()
        alias = self.root / "alias"
        try:
            escape.symlink_to(outside, target_is_directory=True)
            alias.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")
        with self.assertRaises(WorkspaceGuardError):
            self.guard.validate("escape/file.txt")
        with self.assertRaises(WorkspaceGuardError):
            self.guard.validate_distinct(("real/file.txt", "alias/file.txt"))


if __name__ == "__main__":
    unittest.main()
