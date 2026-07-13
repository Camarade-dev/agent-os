from __future__ import annotations

import tempfile
import unittest
import unittest.mock
from dataclasses import replace
from pathlib import Path
import subprocess
import sys

from admissible.execution import bounded_write
import admissible.v0_controller.adapters as adapters_module
from admissible.v0_controller.adapters import (
    BoundedLocalExecutorV0Adapter,
    FixtureProposalBackend,
    V0ProposalOperation,
    V0ProposalResult,
    build_cli008_turn1_result,
    build_cli008_turn2_result,
    proposal_backend_to_agent_result,
    sha256_file,
    validate_proposal_operations,
)
from admissible.v0_controller.commands import CommandKind, CommandStatus
from admissible.v0_controller.engine import TickResult, V0ControllerEngine
from admissible.v0_controller.events import (
    CommandDispatchStarted,
    ExecutionCapability,
    ExecutionReceipt,
    NoEvent,
    TechnicalFault,
    V0ExecutionInterrupted,
    V0ExecutionResultEnvelope,
)
from admissible.v0_controller.integration_policy import WorkspaceIntegrationError, WorkspaceIntegrationPolicy
from admissible.v0_controller.integration_projection import project_integration_run
from admissible.v0_controller.orchestrator import (
    CLI008_MANDATORY_PATHS,
    OrchestratorStepKind,
    V0OfflineIntegrationConfig,
    V0OfflineOrchestrator,
    cli008_contract,
)
from admissible.v0_controller.reducer import IllegalTransition
from admissible.v0_controller.state import OutcomeReason, Phase, ReasonCode, WorkspacePolicy
from admissible.v0_controller.store import AtomicSessionStore
from admissible.v0_controller.structural_checker import V0StructuralChecker
from admissible.v0_controller.workspace_guard import WorkspaceGuard, WorkspaceGuardError


NOW = "2026-07-13T10:00:00Z"


class CLI008IntegrationHarness:
    def __init__(self, testcase: unittest.TestCase) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.artifact_root = root / "artifacts"
        self.artifact_root.mkdir()
        self.workspace = root / "live_workspace"
        self.workspace.mkdir()
        self.store_dir = root / "sessions"
        self.backend = FixtureProposalBackend()
        self.backend.register_sequence_builder(lambda inv_id: build_cli008_turn1_result(invocation_id=inv_id))
        self.backend.register_sequence_builder(lambda inv_id: build_cli008_turn2_result(invocation_id=inv_id))
        self.executor = BoundedLocalExecutorV0Adapter()
        self.checker = V0StructuralChecker()
        self.config = V0OfflineIntegrationConfig(
            store_directory=self.store_dir,
            session_id="cli008-offline-two-batch",
            contract=cli008_contract(target_workspace=self.workspace),
            proposal_backend=self.backend,
            bounded_executor_adapter=self.executor,
            structural_checker=self.checker,
            workspace_integration_policy=WorkspaceIntegrationPolicy(
                allowed_live_workspace_roots=(str(root),),
                rejected_workspace_roots=(str(self.artifact_root),),
            ),
            occurred_at=NOW,
        )
        self.orchestrator = V0OfflineOrchestrator(self.config)

    def fresh_orchestrator(self) -> V0OfflineOrchestrator:
        return V0OfflineOrchestrator(self.config)

    def state(self):
        return self.orchestrator.load_state()

    def session_path(self) -> Path:
        return self.store_dir / f"{self.config.session_id}.v0.json"

    def file_hashes(self) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for path in CLI008_MANDATORY_PATHS:
            target = self.workspace / Path(path)
            if target.is_file():
                hashes[path] = sha256_file(str(target))
        return hashes

    def run_to_awaiting_human(self) -> list:
        self.orchestrator.create_session()
        steps = []
        while self.state().phase != Phase.AWAITING_HUMAN:
            steps.append(self.fresh_orchestrator().run_logical_tick())
        return steps


class TestV0Slice2Adapters(unittest.TestCase):
    def test_proposal_validation_rejects_more_than_four_operations(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        state = harness.state()
        guard = WorkspaceGuard(harness.workspace, state.contract.workspace_policy)
        operations = tuple(
            V0ProposalOperation(action_id=f"op-{index}", path=path, content="content")
            for index, path in enumerate(CLI008_MANDATORY_PATHS, start=1)
        )
        result = validate_proposal_operations(state=state, operations=operations, guard=guard)
        self.assertIsInstance(result, OutcomeReason)

    def test_bounded_executor_adapter_writes_and_correlates_receipts(self) -> None:
        harness = CLI008IntegrationHarness(self)
        steps = harness.run_to_awaiting_human()
        self.assertGreater(len(steps), 0)
        self.assertEqual(harness.executor.write_count, 8)
        self.assertEqual(harness.executor.envelope_count, 2)
        for path in CLI008_MANDATORY_PATHS:
            target = harness.workspace / Path(path)
            self.assertTrue(target.is_file())
            self.assertGreater(target.stat().st_size, 0)

    def test_unsupported_operation_kinds_are_preserved_and_rejected_before_execution(self) -> None:
        cases = (
            ("shell", True), ("command", True), ("network", True), ("browser", True),
            ("deploy", True), ("package_install", True), ("WRITE_FILE", True),
            ("", True), (None, True), ("write_file", False),
        )
        for kind, rejected in cases:
            with self.subTest(kind=kind):
                harness = CLI008IntegrationHarness(self)
                harness.orchestrator.create_session()
                harness.fresh_orchestrator().run_logical_tick()
                dispatch = harness.state().pending_command
                assert dispatch is not None
                operation = V0ProposalOperation(
                    action_id="kind-case",
                    path="index.html",
                    content="safe local content",
                    operation_kind=kind,
                    include_operation_kind=kind is not None,
                )
                harness.backend.register_script(
                    dispatch.owner_id,
                    V0ProposalResult(
                        invocation_id=dispatch.owner_id,
                        result_id="kind-case-result",
                        batch_id="kind-case-batch",
                        response_reference="fixture://kind-case",
                        operations=(operation,),
                    ),
                )
                harness.fresh_orchestrator().run_logical_tick()
                persisted = harness.state().current_batch
                assert persisted is not None
                raw = persisted.proposed_operations[0].operation
                if kind is None:
                    self.assertNotIn("operation", raw)
                else:
                    self.assertEqual(raw["operation"], kind)
                harness.fresh_orchestrator().run_logical_tick()
                state = harness.state()
                if rejected:
                    self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
                    self.assertEqual(state.outcome_reason.code, ReasonCode.INVALID_EXTERNAL_RESULT)
                    self.assertIn(repr(kind), state.outcome_reason.message)
                    self.assertEqual(sum(len(batch.admitted_operation_ids) for batch in state.batch_history), 0)
                    self.assertEqual(state.counters.commands, 2)
                    self.assertEqual(harness.executor.write_count, 0)
                    self.assertEqual(harness.executor.envelope_count, 0)
                    self.assertEqual(harness.file_hashes(), {})
                else:
                    self.assertEqual(state.phase, Phase.READY_TO_EXECUTE)
                    self.assertEqual(state.current_batch.admitted_operation_ids, ("kind-case",))


class TestV0Slice2WorkspacePolicy(unittest.TestCase):
    def test_accepts_live_workspace_and_rejects_artifact_root(self) -> None:
        harness = CLI008IntegrationHarness(self)
        policy = harness.config.workspace_integration_policy
        accepted = policy.validate_target_workspace(harness.workspace)
        self.assertEqual(accepted, harness.workspace.resolve())
        with self.assertRaises(WorkspaceIntegrationError) as rejected:
            policy.validate_target_workspace(harness.artifact_root)
        self.assertEqual(rejected.exception.code, "artifact_root_rejected")

    def test_rejects_missing_workspace(self) -> None:
        policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=(tempfile.gettempdir(),))
        with self.assertRaises(WorkspaceIntegrationError) as missing:
            policy.validate_target_workspace(Path(tempfile.gettempdir()) / "missing-v0-workspace-root")
        self.assertEqual(missing.exception.code, "missing_workspace")

    def test_allowed_live_root_containment_rejects_outside_and_common_prefix_siblings(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        allowed = root / "live"
        nested = allowed / "team" / "app"
        sibling = root / "outside"
        prefix_sibling = root / "live-copy"
        nested.mkdir(parents=True)
        sibling.mkdir()
        prefix_sibling.mkdir()
        policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=(str(allowed),))
        self.assertEqual(policy.validate_target_workspace(nested), nested.resolve())
        for target in (sibling, prefix_sibling):
            with self.subTest(target=target.name), self.assertRaises(WorkspaceIntegrationError) as rejected:
                policy.validate_target_workspace(target)
            self.assertEqual(rejected.exception.code, "outside_allowed_live_root")

    def test_rejected_artifact_root_wins_under_an_allowed_parent(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        allowed = root / "live"
        artifact = allowed / "artifacts"
        artifact.mkdir(parents=True)
        policy = WorkspaceIntegrationPolicy(
            allowed_live_workspace_roots=(str(allowed),),
            rejected_workspace_roots=(str(artifact),),
        )
        with self.assertRaises(WorkspaceIntegrationError) as rejected:
            policy.validate_target_workspace(artifact)
        self.assertEqual(rejected.exception.code, "artifact_root_rejected")

    def test_multiple_allowed_live_roots_accepts_exactly_one_match(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        first = root / "live-a"
        second = root / "live-b"
        target = second / "nested"
        first.mkdir()
        target.mkdir(parents=True)
        policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=(str(first), str(second)))
        self.assertEqual(policy.validate_target_workspace(target), target.resolve())

    def test_overlapping_allowed_live_roots_reject_an_ambiguous_target(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        broad = root / "live"
        narrow = broad / "nested"
        target = narrow / "app"
        target.mkdir(parents=True)
        policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=(str(broad), str(narrow)))
        with self.assertRaises(WorkspaceIntegrationError) as rejected:
            policy.validate_target_workspace(target)
        self.assertEqual(rejected.exception.code, "ambiguous_allowed_live_root")

    def test_rejects_symlinked_target_root_escaping_allowed_root_when_supported(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        allowed = root / "allowed"
        outside = root / "outside"
        allowed.mkdir()
        outside.mkdir()
        link = allowed / "linked-workspace"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")
        policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=(str(allowed),))
        with self.assertRaises(WorkspaceIntegrationError) as rejected:
            policy.validate_target_workspace(link)
        self.assertEqual(rejected.exception.code, "outside_allowed_live_root")

    def test_rejects_symlinked_workspace_escape_when_supported(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "outside"
        outside.mkdir()
        escape = workspace / "escape"
        try:
            escape.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")
        policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=(str(root),))
        resolved = policy.validate_target_workspace(workspace)
        guard = WorkspaceGuard(resolved, WorkspacePolicy())
        (outside / "secret.txt").write_text("outside", encoding="utf-8")
        with self.assertRaises(WorkspaceGuardError):
            guard.validate("escape/secret.txt")


class TestV0Slice2WorkspaceAuthorityMutation(unittest.TestCase):
    @staticmethod
    def _rebind_workspace(harness: CLI008IntegrationHarness, target: Path) -> None:
        if any(harness.workspace.iterdir()):
            original = harness.workspace.parent / "original-workspace-after-rebind"
            harness.workspace.rename(original)
        else:
            harness.workspace.rmdir()
        try:
            harness.workspace.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            raise unittest.SkipTest(f"symlink capability unavailable: {exc}") from exc

    def _assert_authority_pause(
        self,
        harness: CLI008IntegrationHarness,
        *,
        expected_writes: int = 0,
        expected_receipts: int = 0,
    ) -> None:
        state = harness.state()
        assert state.outcome_reason is not None
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertIn(
            state.outcome_reason.code,
            {ReasonCode.WORKSPACE_AUTHORITY_CHANGED, ReasonCode.WORKSPACE_CONTAINMENT_CHANGED},
        )
        self.assertEqual(harness.executor.write_count, expected_writes)
        self.assertEqual(len(state.execution_receipt_history), expected_receipts)
        self.assertEqual(len(state.materialized_evidence), expected_receipts)

    def test_rebind_before_first_driver_step_makes_zero_effects(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        outside = harness.workspace.parent / "outside-sibling"
        outside.mkdir()
        self._rebind_workspace(harness, outside)

        harness.fresh_orchestrator().run_logical_tick()

        self.assertEqual(harness.backend.invocation_count, 0)
        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.checker.check_count, 0)
        self._assert_authority_pause(harness)

    def test_rebind_after_backend_completion_blocks_admission_and_execution(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        harness.fresh_orchestrator().run_logical_tick()
        harness.fresh_orchestrator().run_logical_tick()
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(harness.state().phase, Phase.ADMITTING)
        outside = harness.workspace.parent / "outside-after-backend"
        outside.mkdir()
        self._rebind_workspace(harness, outside)

        harness.fresh_orchestrator().run_logical_tick()

        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.checker.check_count, 0)
        self._assert_authority_pause(harness)

    def test_rebind_after_admission_blocks_executor_dispatch(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.READY_TO_EXECUTE:
            harness.fresh_orchestrator().run_logical_tick()
        outside = harness.workspace.parent / "outside-after-admission"
        outside.mkdir()
        self._rebind_workspace(harness, outside)

        harness.fresh_orchestrator().run_logical_tick()

        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.checker.check_count, 0)
        self._assert_authority_pause(harness)

    def test_rejected_artifact_rebind_wins_before_mutation(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.READY_TO_EXECUTE:
            harness.fresh_orchestrator().run_logical_tick()
        self._rebind_workspace(harness, harness.artifact_root)

        harness.fresh_orchestrator().run_logical_tick()

        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.file_hashes(), {})
        self._assert_authority_pause(harness)

    def test_parent_directory_symlink_escape_is_rejected_before_mutation(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.READY_TO_EXECUTE:
            harness.fresh_orchestrator().run_logical_tick()
        outside = harness.workspace.parent / "outside-parent"
        outside.mkdir()
        parent = harness.workspace / "src"
        try:
            parent.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")

        harness.fresh_orchestrator().run_logical_tick()

        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.file_hashes(), {})
        self._assert_authority_pause(harness)

    def test_structural_stage_revalidates_authority_before_checker(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.CHECKING_FILES:
            harness.fresh_orchestrator().run_logical_tick()
        outside = harness.workspace.parent / "outside-before-structural"
        outside.mkdir()
        self._rebind_workspace(harness, outside)

        harness.fresh_orchestrator().run_logical_tick()

        self.assertEqual(harness.checker.check_count, 0)
        self._assert_authority_pause(harness, expected_writes=8, expected_receipts=8)
        descriptor = harness.state().workspace_authority
        self.assertIsNotNone(descriptor)
        assert descriptor is not None
        self.assertEqual(descriptor.configured_workspace_path, str(harness.workspace))
        self.assertNotEqual(descriptor.canonical_workspace_path, str(harness.workspace.resolve()))


class TestCLI008OfflineTwoBatchIntegration(unittest.TestCase):
    def test_full_two_batch_trajectory_and_totals(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        after_first_batch = None
        checking_state = None
        step_count = 0
        while harness.state().phase != Phase.AWAITING_HUMAN:
            step = harness.fresh_orchestrator().run_logical_tick()
            step_count += 1
            state = harness.state()
            if after_first_batch is None and state.phase == Phase.READY_TO_INVOKE and len(state.materialized_evidence) == 4:
                after_first_batch = state
            if checking_state is None and state.phase == Phase.CHECKING_FILES:
                checking_state = state
            self.assertLess(step_count, 64, "integration run exceeded expected step budget")
        self.assertIsNotNone(after_first_batch)
        assert after_first_batch is not None
        self.assertEqual(len(after_first_batch.remaining_paths()), 4)
        self.assertIsNone(after_first_batch.structural_verification)
        self.assertIsNone(after_first_batch.outcome_reason)
        self.assertEqual(after_first_batch.phase, Phase.READY_TO_INVOKE)
        self.assertIsNotNone(checking_state)
        assert checking_state is not None
        self.assertEqual(harness.backend.invocation_count, 2)
        self.assertEqual(checking_state.pending_command.kind, CommandKind.RUN_STRUCTURAL_CHECK)

        final = harness.state()
        projection = project_integration_run(
            final,
            backend_invocations=harness.backend.invocation_count,
            proposal_results_consumed=harness.backend.results_consumed,
            bounded_writes=harness.executor.write_count,
            duplicate_writes=harness.executor.duplicate_write_attempts,
            structural_checks=harness.checker.check_count,
        )
        self.assertEqual(projection["phase"], Phase.AWAITING_HUMAN.value)
        self.assertEqual(projection["backend_invocations"], 2)
        self.assertEqual(projection["proposal_results_consumed"], 2)
        self.assertEqual(projection["admitted_operations"], 8)
        self.assertEqual(projection["bounded_writes"], 8)
        self.assertEqual(len(final.execution_receipt_history), 8)
        self.assertEqual(len(projection["execution_receipt_ids"]), 8)
        self.assertEqual(projection["duplicate_writes"], 0)
        self.assertEqual(projection["partial_batches"], 1)
        self.assertEqual(projection["completed_batches"], 2)
        self.assertEqual(projection["structural_checks"], 1)
        self.assertEqual(projection["remaining_paths"], [])
        self.assertTrue(projection["structural_verification_present"])
        self.assertEqual(set(projection["materialized_paths"]), set(CLI008_MANDATORY_PATHS))

    def test_large_diagnostic_does_not_alter_structured_result(self) -> None:
        harness = CLI008IntegrationHarness(self)
        turn1 = build_cli008_turn1_result(invocation_id="unused", large_diagnostic=True)
        self.assertGreater(turn1.retained_diagnostic_bytes, 1_048_576)
        self.assertEqual(len(turn1.operations), 4)
        harness.orchestrator.create_session()
        harness.fresh_orchestrator().run_logical_tick()
        state = harness.state()
        command = state.pending_command
        assert command is not None
        result = harness.backend.invoke(command=command, instruction=command.payload)
        agent_event = proposal_backend_to_agent_result(
            backend=harness.backend,
            command=command,
            result=result,
        )
        self.assertEqual(len(agent_event.proposed_operations), 4)
        retained = [value for value in agent_event.diagnostics if value.startswith("retained_diagnostic_bytes:")]
        self.assertEqual(retained, ["retained_diagnostic_bytes:1048576"])
        self.assertIn("diagnostic_stream_truncated", agent_event.diagnostics)
        self.assertIn(f"result_id:{result.result_id}", agent_event.diagnostics)
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(harness.backend.results_consumed, 1)

    def test_twenty_tick_stability_after_awaiting_human(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.run_to_awaiting_human()
        initial_state = harness.state()
        initial_bytes = harness.orchestrator.session_bytes()
        session_file_bytes = harness.session_path().read_bytes()
        initial_revision = initial_state.revision
        initial_semantic = initial_state.semantic_state_version
        initial_hashes = harness.file_hashes()
        for _ in range(20):
            step = harness.fresh_orchestrator().run_no_event_tick()
            self.assertEqual(step.step_kind, OrchestratorStepKind.NO_EVENT)
            self.assertEqual(step.tick.state.phase, Phase.AWAITING_HUMAN)
            self.assertEqual(step.tick.state.revision, initial_revision)
            self.assertEqual(step.tick.state.canonical_bytes(), initial_bytes)
            self.assertEqual(harness.session_path().read_bytes(), session_file_bytes)
        self.assertEqual(harness.backend.invocation_count, 2)
        self.assertEqual(harness.executor.write_count, 8)
        self.assertEqual(harness.checker.check_count, 1)
        self.assertEqual(harness.file_hashes(), initial_hashes)


class TestV0Slice2RestartBoundaries(unittest.TestCase):
    def _engine(self, harness: CLI008IntegrationHarness) -> V0ControllerEngine:
        return harness.fresh_orchestrator().fresh_engine()

    def test_restart_after_prepared_invocation_dispatches_once(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        harness.fresh_orchestrator().run_logical_tick()
        pending = self._engine(harness).restart_pending_command(harness.config.session_id)
        self.assertIsNotNone(pending)
        assert not isinstance(pending, TechnicalFault)
        self.assertEqual(pending.kind, CommandKind.DISPATCH_AGENT)
        self.assertEqual(pending.status, CommandStatus.PREPARED)
        before = harness.backend.invocation_count
        harness.fresh_orchestrator().run_logical_tick()
        self.assertEqual(harness.backend.invocation_count, before + 1)

    def test_restart_after_invocation_in_flight_pauses_without_backend_replay(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        harness.fresh_orchestrator().run_logical_tick()
        engine = self._engine(harness)
        command = harness.state().pending_command
        assert command is not None and command.command_id is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id))
        before = harness.backend.invocation_count
        restarted = engine.restart_pending_command(harness.config.session_id)
        self.assertIsInstance(restarted, TickResult)
        assert isinstance(restarted, TickResult)
        self.assertEqual(restarted.state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(harness.backend.invocation_count, before)

    def test_restart_after_prepared_execution_runs_once(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().pending_command is None or harness.state().pending_command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            harness.fresh_orchestrator().run_logical_tick()
        before = harness.executor.write_count
        harness.fresh_orchestrator().run_logical_tick()
        self.assertEqual(before, 0)
        self.assertEqual(harness.executor.write_count, 4)

    def test_restart_after_execution_in_flight_fails_closed(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().pending_command is None or harness.state().pending_command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            harness.fresh_orchestrator().run_logical_tick()
        engine = self._engine(harness)
        command = harness.state().pending_command
        assert command is not None and command.command_id is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id))
        before_writes = harness.executor.write_count
        restarted = engine.restart_pending_command(harness.config.session_id)
        self.assertIsInstance(restarted, TickResult)
        assert isinstance(restarted, TickResult)
        self.assertEqual(restarted.state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(harness.executor.write_count, before_writes)

    def test_restart_after_structural_prepared_runs_once(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.CHECKING_FILES:
            harness.fresh_orchestrator().run_logical_tick()
        before = harness.checker.check_count
        harness.fresh_orchestrator().run_logical_tick()
        self.assertEqual(harness.checker.check_count, before + 1)
        self.assertEqual(harness.state().phase, Phase.AWAITING_HUMAN)

    def test_restart_after_structural_in_flight_fails_closed(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.CHECKING_FILES:
            harness.fresh_orchestrator().run_logical_tick()
        engine = self._engine(harness)
        command = harness.state().pending_command
        assert command is not None and command.command_id is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id))
        before = harness.checker.check_count
        restarted = engine.restart_pending_command(harness.config.session_id)
        self.assertIsInstance(restarted, TickResult)
        assert isinstance(restarted, TickResult)
        self.assertEqual(restarted.state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(harness.checker.check_count, before)

    def test_duplicate_backend_result_cannot_be_consumed_twice(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        harness.fresh_orchestrator().run_logical_tick()
        engine = self._engine(harness)
        command = harness.state().pending_command
        assert command is not None and command.command_id is not None
        started = engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id))
        result = harness.backend.invoke(command=command, instruction=command.payload)
        event = proposal_backend_to_agent_result(backend=harness.backend, command=command, result=result)
        engine.tick(harness.config.session_id, event)
        with self.assertRaises(IllegalTransition):
            engine.tick(harness.config.session_id, event)

    def test_duplicate_executor_envelope_cannot_create_evidence_twice(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().pending_command is None or harness.state().pending_command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            harness.fresh_orchestrator().run_logical_tick()
        engine = self._engine(harness)
        command = harness.state().pending_command
        assert command is not None and command.command_id is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id))
        in_flight = harness.state()
        batch = in_flight.current_batch
        assert batch is not None
        paths = tuple(
            operation.path
            for operation in batch.proposed_operations
            if operation.operation_id in set(batch.admitted_operation_ids)
        )
        envelope = harness.executor.execute(
            command=command,
            batch=batch,
            workspace_target=engine._validated_execution_target(in_flight, paths),
        )
        hashes_after_write = harness.file_hashes()
        engine.consume_trusted_execution_result(harness.config.session_id, envelope)
        consumed = harness.state()
        receipts_before = consumed.execution_receipt_history
        bytes_before = consumed.canonical_bytes()
        writes_before = harness.executor.write_count
        with self.assertRaises(IllegalTransition):
            engine.consume_trusted_execution_result(harness.config.session_id, envelope)
        self.assertEqual(harness.executor.write_count, writes_before)
        self.assertEqual(harness.state().execution_receipt_history, receipts_before)
        self.assertEqual(harness.file_hashes(), hashes_after_write)
        self.assertEqual(harness.state().canonical_bytes(), bytes_before)


class TestV0Slice2StructuralFailureDurability(unittest.TestCase):
    def _checking_harness(self) -> CLI008IntegrationHarness:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().phase != Phase.CHECKING_FILES:
            harness.fresh_orchestrator().run_logical_tick()
        self.assertEqual(harness.checker.check_count, 0)
        self.assertEqual(harness.executor.write_count, 8)
        return harness

    def test_first_path_structural_failures_are_durable_and_never_retried(self) -> None:
        cases = (
            ("file_missing", lambda target, _outside: target.unlink()),
            ("empty_file", lambda target, _outside: target.write_text("", encoding="utf-8")),
            ("not_regular_file", lambda target, _outside: (target.unlink(), target.mkdir())),
            ("hash_mismatch", lambda target, _outside: target.write_text("tampered", encoding="utf-8")),
            ("containment_failure", self._symlink_escape),
        )
        for expected_code, mutate in cases:
            with self.subTest(failure_code=expected_code):
                harness = self._checking_harness()
                target = harness.workspace / "index.html"
                outside = harness.workspace.parent / "outside-structural"
                outside.mkdir(exist_ok=True)
                mutate(target, outside)
                command = harness.state().pending_command
                assert command is not None and command.command_id is not None
                harness.fresh_orchestrator().run_logical_tick()
                failed = harness.state()
                self.assertIn(failed.phase, {Phase.FAILED, Phase.TECHNICAL_PAUSE})
                self.assertEqual(harness.checker.check_count, 1)
                self.assertIsNone(failed.pending_command)
                self.assertIn(command.command_id, failed.completed_command_ids)
                self.assertIsNotNone(failed.structural_verification)
                check = failed.structural_verification.checks[0]
                self.assertEqual(len(failed.structural_verification.checks), 1)
                self.assertEqual(check.structural_command_id, command.command_id)
                self.assertEqual(check.path, "index.html")
                self.assertEqual(check.check_kind, "mandatory_file")
                self.assertFalse(check.passed)
                self.assertEqual(check.failure_code, expected_code)
                self.assertIn(expected_code, failed.outcome_reason.message)
                bytes_before = failed.canonical_bytes()
                writes_before = harness.executor.write_count
                for _ in range(3):
                    reloaded = harness.fresh_orchestrator().run_no_event_tick()
                    self.assertEqual(reloaded.tick.state.canonical_bytes(), bytes_before)
                self.assertEqual(harness.checker.check_count, 1)
                self.assertEqual(harness.executor.write_count, writes_before)

    @staticmethod
    def _symlink_escape(target: Path, outside: Path) -> None:
        target.unlink()
        try:
            target.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            raise unittest.SkipTest(f"symlink capability unavailable: {exc}") from exc


class TestV0Slice2DurableExecutionReceipts(unittest.TestCase):
    def _in_flight_execution(self) -> tuple[CLI008IntegrationHarness, V0ControllerEngine]:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while harness.state().pending_command is None or harness.state().pending_command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS:
            harness.fresh_orchestrator().run_logical_tick()
        engine = harness.fresh_orchestrator().fresh_engine()
        command = harness.state().pending_command
        assert command is not None and command.command_id is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id))
        return harness, engine

    def _forged_envelope(self, harness: CLI008IntegrationHarness, engine: V0ControllerEngine) -> V0ExecutionResultEnvelope:
        state = harness.state()
        command = state.pending_command
        batch = state.current_batch
        assert command is not None and batch is not None
        capability = ExecutionCapability.from_dict(command.payload["execution_capability"])
        admitted = tuple(item for item in batch.proposed_operations if item.operation_id in set(batch.admitted_operation_ids))
        targets = engine._validated_execution_target(state, tuple(item.path for item in admitted))
        receipts = tuple(
            ExecutionReceipt(
                schema_version="admissible_v0_execution_receipt_v1",
                receipt_id=f"v0receipt:{command.command_id}:{operation.operation_id}",
                session_id=state.session_id,
                issued_revision=capability.issued_revision,
                execution_command_id=command.command_id,
                batch_id=batch.batch_id,
                invocation_id=batch.invocation_id,
                action_id=operation.operation_id,
                operation_kind="write_file",
                path=operation.path,
                resolved_target=targets.target_for(operation.path).resolved_target,
                physical_identity_key=targets.target_for(operation.path).physical_identity_key,
                sha256="a" * 64,
                byte_count=1,
                success=True,
            )
            for operation in admitted
        )
        return V0ExecutionResultEnvelope(
            capability=capability,
            receipts=receipts,
            success=True,
            occurred_at=NOW,
            adapter_identity=harness.executor.identity,
            adapter_protocol_version=harness.executor.protocol_version,
        )

    def _executed_envelope(self) -> tuple[CLI008IntegrationHarness, V0ControllerEngine, V0ExecutionResultEnvelope]:
        harness, engine = self._in_flight_execution()
        state = harness.state()
        command = state.pending_command
        batch = state.current_batch
        assert command is not None and batch is not None
        paths = tuple(
            operation.path
            for operation in batch.proposed_operations
            if operation.operation_id in set(batch.admitted_operation_ids)
        )
        envelope = harness.executor.execute(
            command=command,
            batch=batch,
            workspace_target=engine._validated_execution_target(state, paths),
        )
        return harness, engine, envelope

    def _second_batch_executed_envelope(self) -> tuple[CLI008IntegrationHarness, V0ControllerEngine, V0ExecutionResultEnvelope]:
        harness = CLI008IntegrationHarness(self)
        harness.orchestrator.create_session()
        while not (harness.state().phase == Phase.READY_TO_INVOKE and len(harness.state().materialized_evidence) == 4):
            harness.fresh_orchestrator().run_logical_tick()
        while (
            harness.state().pending_command is None
            or harness.state().pending_command.kind != CommandKind.EXECUTE_BOUNDED_OPERATIONS
        ):
            harness.fresh_orchestrator().run_logical_tick()
        engine = harness.fresh_orchestrator().fresh_engine()
        state = harness.state()
        command = state.pending_command
        batch = state.current_batch
        assert command is not None and batch is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(command.command_id or ""))
        in_flight = harness.state()
        paths = tuple(
            operation.path
            for operation in batch.proposed_operations
            if operation.operation_id in set(batch.admitted_operation_ids)
        )
        envelope = harness.executor.execute(
            command=command,
            batch=batch,
            workspace_target=engine._validated_execution_target(in_flight, paths),
        )
        return harness, engine, envelope

    def _assert_rejected_physical_envelope(
        self,
        harness: CLI008IntegrationHarness,
        engine: V0ControllerEngine,
        envelope: V0ExecutionResultEnvelope,
        *,
        prior_receipts: int = 0,
    ) -> None:
        result = engine.consume_trusted_execution_result(harness.config.session_id, envelope)
        self.assertEqual(result.state.phase, Phase.TECHNICAL_PAUSE)
        state = harness.fresh_orchestrator().load_state()
        self.assertEqual(len(state.execution_receipt_history), prior_receipts)
        self.assertEqual(len(state.materialized_evidence), prior_receipts)
        self.assertIsNotNone(state.outcome_reason)
        assert state.outcome_reason is not None
        self.assertIn(
            state.outcome_reason.code,
            {ReasonCode.PHYSICAL_ATTESTATION_FAILED, ReasonCode.WORKSPACE_AUTHORITY_CHANGED},
        )
        writes_after_rejection = harness.executor.write_count
        stable_bytes = state.canonical_bytes()
        for _ in range(3):
            tick = harness.fresh_orchestrator().run_no_event_tick()
            self.assertEqual(tick.tick.state.canonical_bytes(), stable_bytes)
        self.assertEqual(harness.executor.write_count, writes_after_rejection)
        self.assertEqual(len(harness.state().execution_receipt_history), prior_receipts)

    def test_receipt_history_persists_complete_schema_and_drives_write_projection(self) -> None:
        harness = CLI008IntegrationHarness(self)
        harness.run_to_awaiting_human()
        reloaded = harness.fresh_orchestrator().load_state()
        self.assertEqual(len(reloaded.execution_receipt_history), 8)
        self.assertEqual(len({receipt.receipt_id for receipt in reloaded.execution_receipt_history}), 8)
        for receipt in reloaded.execution_receipt_history:
            self.assertEqual(receipt.schema_version, "admissible_v0_execution_receipt_v1")
            self.assertEqual(receipt.session_id, reloaded.session_id)
            self.assertEqual(receipt.operation_kind, "write_file")
            self.assertTrue(receipt.resolved_target)
            self.assertTrue(receipt.physical_identity_key)
            self.assertTrue(receipt.success)
            physical = Path(receipt.resolved_target)
            self.assertTrue(physical.is_file())
            self.assertEqual(str(physical.resolve()), receipt.resolved_target)
            self.assertEqual(sha256_file(str(physical)), receipt.sha256)
            self.assertEqual(physical.stat().st_size, receipt.byte_count)
        projection = harness.orchestrator.projection()
        self.assertEqual(projection.bounded_writes, 8)
        self.assertEqual(len(reloaded.materialized_evidence), 8)
        self.assertEqual(
            {evidence.execution_receipt_id for evidence in reloaded.materialized_evidence},
            {receipt.receipt_id for receipt in reloaded.execution_receipt_history},
        )

    def test_forged_correlated_receipt_fields_reject_without_history_mutation(self) -> None:
        mutations = {
            "receipt_id": "forged-receipt",
            "session_id": "other-session",
            "issued_revision": 999,
            "execution_command_id": "other-command",
            "batch_id": "other-batch",
            "invocation_id": "other-invocation",
            "action_id": "other-action",
            "operation_kind": "shell",
            "path": "style.css",
            "resolved_target": "C:/forged/target",
            "physical_identity_key": "case_sensitive:C:/forged/target",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                harness, engine = self._in_flight_execution()
                envelope = self._forged_envelope(harness, engine)
                before = harness.state().canonical_bytes()
                original_history = harness.state().execution_receipt_history
                forged = replace(envelope, receipts=(replace(envelope.receipts[0], **{field: value}),))
                with self.assertRaises(IllegalTransition):
                    engine.consume_trusted_execution_result(harness.config.session_id, forged)
                self.assertEqual(harness.state().canonical_bytes(), before)
                self.assertEqual(harness.state().execution_receipt_history, original_history)
                self.assertEqual(harness.executor.write_count, 0)

    def test_correlated_envelope_without_physical_files_is_rejected(self) -> None:
        harness, engine = self._in_flight_execution()
        envelope = self._forged_envelope(harness, engine)
        self._assert_rejected_physical_envelope(harness, engine, envelope)
        self.assertEqual(harness.executor.write_count, 0)

    def test_fabricated_sha256_is_rejected_without_receipt_or_evidence(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        forged = replace(
            envelope,
            receipts=(replace(envelope.receipts[0], sha256="0" * 64), *envelope.receipts[1:]),
        )
        self._assert_rejected_physical_envelope(harness, engine, forged)

    def test_fabricated_byte_count_is_rejected_without_receipt_or_evidence(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        forged = replace(
            envelope,
            receipts=(replace(envelope.receipts[0], byte_count=envelope.receipts[0].byte_count + 1), *envelope.receipts[1:]),
        )
        self._assert_rejected_physical_envelope(harness, engine, forged)

    def test_file_changed_after_adapter_execution_is_rejected(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        target = harness.workspace / envelope.receipts[0].path
        target.write_text("changed after adapter execution", encoding="utf-8")
        self._assert_rejected_physical_envelope(harness, engine, envelope)

    def test_wrong_resolved_target_and_physical_identity_are_rejected(self) -> None:
        for field in ("resolved_target", "physical_identity_key"):
            with self.subTest(field=field):
                harness, engine, envelope = self._executed_envelope()
                replacement = (
                    envelope.receipts[1].resolved_target
                    if field == "resolved_target"
                    else "case_sensitive:forged-physical-target"
                )
                forged = replace(
                    envelope,
                    receipts=(replace(envelope.receipts[0], **{field: replacement}), *envelope.receipts[1:]),
                )
                self._assert_rejected_physical_envelope(harness, engine, forged)

    def test_exact_operation_kind_must_remain_write_file(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        forged = replace(
            envelope,
            receipts=(replace(envelope.receipts[0], operation_kind="shell"), *envelope.receipts[1:]),
        )
        self._assert_rejected_physical_envelope(harness, engine, forged)

    def test_directory_instead_of_file_is_rejected(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        target = harness.workspace / envelope.receipts[0].path
        target.unlink()
        target.mkdir()
        self._assert_rejected_physical_envelope(harness, engine, envelope)

    def test_symlink_escape_before_envelope_consumption_is_rejected(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        target = harness.workspace / envelope.receipts[0].path
        outside = harness.workspace.parent / "outside-envelope"
        outside.mkdir()
        outside_file = outside / "escaped.html"
        outside_file.write_text("outside", encoding="utf-8")
        target.unlink()
        try:
            target.symlink_to(outside_file)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")
        self._assert_rejected_physical_envelope(harness, engine, envelope)

    def test_one_invalid_receipt_among_four_preserves_prior_valid_history(self) -> None:
        harness, engine, envelope = self._second_batch_executed_envelope()
        forged = replace(
            envelope,
            receipts=(envelope.receipts[0], replace(envelope.receipts[1], sha256="f" * 64), *envelope.receipts[2:]),
        )
        self._assert_rejected_physical_envelope(harness, engine, forged, prior_receipts=4)

    def test_exact_replay_of_valid_envelope_does_not_replay_writes(self) -> None:
        harness, engine, envelope = self._executed_envelope()
        engine.consume_trusted_execution_result(harness.config.session_id, envelope)
        state = harness.state()
        history = state.execution_receipt_history
        evidence = state.materialized_evidence
        writes = harness.executor.write_count
        with self.assertRaises(IllegalTransition):
            engine.consume_trusted_execution_result(harness.config.session_id, envelope)
        self.assertEqual(harness.executor.write_count, writes)
        self.assertEqual(harness.state().execution_receipt_history, history)
        self.assertEqual(harness.state().materialized_evidence, evidence)


TURN1_ACTION_IDS = ("turn1-index", "turn1-style", "turn1-entities", "turn1-local-dev")
TURN1_PATHS = ("index.html", "style.css", "src/entities.js", "LOCAL_DEV.md")


class RebindableWorkspaceHarness:
    """A workspace reached through a logical symlink, so it can be rebound in place.

    The physical workspace never moves; only the configured logical path is
    repointed.  This is the exact shape of the observed interruption defect.
    """

    def __init__(self, testcase: unittest.TestCase) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.root = root
        self.artifact_root = root / "artifacts"
        self.artifact_root.mkdir()
        self.real_workspace = root / "real_workspace"
        self.real_workspace.mkdir()
        self.outside = root / "outside"
        self.outside.mkdir()
        self.workspace = root / "live_workspace"
        try:
            self.workspace.symlink_to(self.real_workspace, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            raise unittest.SkipTest(f"symlink capability unavailable: {exc}") from exc
        self.store_dir = root / "sessions"
        self.backend = FixtureProposalBackend()
        self.backend.register_sequence_builder(lambda inv_id: build_cli008_turn1_result(invocation_id=inv_id))
        self.backend.register_sequence_builder(lambda inv_id: build_cli008_turn2_result(invocation_id=inv_id))
        self.executor = BoundedLocalExecutorV0Adapter()
        self.checker = V0StructuralChecker()
        self.config = V0OfflineIntegrationConfig(
            store_directory=self.store_dir,
            session_id="cli008-interrupted-batch",
            contract=cli008_contract(target_workspace=self.workspace),
            proposal_backend=self.backend,
            bounded_executor_adapter=self.executor,
            structural_checker=self.checker,
            workspace_integration_policy=WorkspaceIntegrationPolicy(
                allowed_live_workspace_roots=(str(root),),
                rejected_workspace_roots=(str(self.artifact_root),),
            ),
            occurred_at=NOW,
        )
        self.orchestrator = V0OfflineOrchestrator(self.config)

    def fresh_orchestrator(self) -> V0OfflineOrchestrator:
        return V0OfflineOrchestrator(self.config)

    def state(self):
        return self.orchestrator.load_state()

    def rebind(self) -> None:
        """Repoint only the logical workspace path; the real workspace stays put."""

        self.workspace.unlink()
        self.workspace.symlink_to(self.outside, target_is_directory=True)

    def run_to_ready_to_execute(self) -> None:
        self.orchestrator.create_session()
        while self.state().phase != Phase.READY_TO_EXECUTE:
            self.fresh_orchestrator().run_logical_tick()

    def physical_files(self) -> set[str]:
        return {
            str(path.relative_to(self.real_workspace)).replace("\\", "/")
            for path in self.real_workspace.rglob("*")
            if path.is_file()
        }


class TestV0Slice2InterruptedExecution(unittest.TestCase):
    """Every confirmed physical write is durably represented exactly once."""

    def _rebind_after_write(self, harness: RebindableWorkspaceHarness, completed_writes: int):
        """Rebind the logical path immediately after the Nth completed write syscall."""

        real_attest = bounded_write.attest_completed_write_against_original_authority
        state = {"writes": 0}

        def patched(**kwargs):
            facts = real_attest(**kwargs)
            state["writes"] += 1
            if state["writes"] == completed_writes:
                harness.rebind()
            return facts

        return unittest.mock.patch.object(
            bounded_write,
            "attest_completed_write_against_original_authority",
            patched,
        )

    def _rebind_before_first_write(self, harness: RebindableWorkspaceHarness):
        real_write = adapters_module.execute_bounded_write

        def patched(request):
            harness.rebind()
            return real_write(request)

        return unittest.mock.patch.object(adapters_module, "execute_bounded_write", patched)

    def _assert_durable_prefix(self, harness: RebindableWorkspaceHarness, completed: int) -> None:
        state = harness.fresh_orchestrator().load_state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        assert state.outcome_reason is not None
        self.assertIn(
            state.outcome_reason.code,
            {ReasonCode.WORKSPACE_AUTHORITY_CHANGED, ReasonCode.WORKSPACE_CONTAINMENT_CHANGED},
        )

        # Counters and durable evidence reflect physical truth.
        self.assertEqual(harness.executor.write_count, completed)
        self.assertEqual(harness.executor.duplicate_write_attempts, 0)
        self.assertEqual(harness.executor.envelope_count, 0)
        self.assertEqual(len(state.execution_receipt_history), completed)
        self.assertEqual(len(state.materialized_evidence), completed)

        batch = state.batch_history[-1]
        self.assertEqual(batch.status.value, "interrupted")
        self.assertEqual(batch.executed_operation_ids, TURN1_ACTION_IDS[:completed])
        self.assertEqual(batch.remaining_action_ids, TURN1_ACTION_IDS[completed:])
        self.assertEqual(batch.interruption_code, "workspace_authority_changed")
        self.assertEqual(len(batch.materialized_evidence), completed)
        self.assertEqual([item.status.value for item in state.batch_history].count("completed"), 0)

        # Persisted receipts exactly match the physical files under the
        # originally authorized workspace, and nothing else was written.
        represented = set()
        for receipt in state.execution_receipt_history:
            target = Path(receipt.resolved_target)
            self.assertTrue(target.is_file())
            self.assertTrue(str(target).startswith(str(harness.real_workspace)))
            self.assertEqual(sha256_file(str(target)), receipt.sha256)
            self.assertEqual(target.stat().st_size, receipt.byte_count)
            represented.add(receipt.path)
        self.assertEqual(represented, set(TURN1_PATHS[:completed]))
        self.assertEqual(harness.physical_files(), represented)
        self.assertEqual([path for path in harness.outside.rglob("*")], [])

        # No continuation, structural check, or further backend invocation.
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(harness.checker.check_count, 0)
        self.assertIsNone(state.pending_command)
        self.assertIsNone(state.current_batch)

    def _assert_stable_after_reload(self, harness: RebindableWorkspaceHarness) -> None:
        before = harness.fresh_orchestrator().session_bytes()
        writes = harness.executor.write_count
        hashes = {path: sha256_file(str(harness.real_workspace / path)) for path in harness.physical_files()}
        for _ in range(20):
            step = harness.fresh_orchestrator().run_no_event_tick()
            self.assertEqual(step.tick.state.phase, Phase.TECHNICAL_PAUSE)
            self.assertEqual(step.session_bytes, before)
        self.assertEqual(harness.executor.write_count, writes)
        self.assertEqual(harness.checker.check_count, 0)
        self.assertEqual({path: sha256_file(str(harness.real_workspace / path)) for path in harness.physical_files()}, hashes)

    def test_rebind_before_first_operation_persists_zero_effects(self) -> None:
        harness = RebindableWorkspaceHarness(self)
        harness.run_to_ready_to_execute()
        with self._rebind_before_first_write(harness):
            harness.fresh_orchestrator().run_logical_tick()
        self._assert_durable_prefix(harness, 0)
        self._assert_stable_after_reload(harness)

    def test_rebind_after_each_completed_write_persists_that_exact_prefix(self) -> None:
        for completed in (1, 2, 3):
            with self.subTest(completed_writes=completed):
                harness = RebindableWorkspaceHarness(self)
                harness.run_to_ready_to_execute()
                with self._rebind_after_write(harness, completed):
                    harness.fresh_orchestrator().run_logical_tick()
                self._assert_durable_prefix(harness, completed)
                self._assert_stable_after_reload(harness)

    def test_interrupted_totals_are_projected_as_physical_truth(self) -> None:
        harness = RebindableWorkspaceHarness(self)
        harness.run_to_ready_to_execute()
        with self._rebind_after_write(harness, 2):
            harness.fresh_orchestrator().run_logical_tick()
        projection = harness.fresh_orchestrator().projection()
        self.assertEqual(projection.bounded_writes, 2)
        self.assertEqual(projection.duplicate_writes, 0)
        self.assertEqual(projection.completed_batches, 0)
        self.assertEqual(projection.interrupted_batches, 1)
        self.assertEqual(projection.partial_batches, 0)
        self.assertEqual(projection.structural_checks, 0)
        self.assertEqual(projection.phase, Phase.TECHNICAL_PAUSE.value)

    def _drive_to_interrupted_result(
        self,
        harness: RebindableWorkspaceHarness,
        completed: int,
    ) -> tuple[V0ControllerEngine, V0ExecutionInterrupted]:
        """Run the trusted adapter once without consuming its interrupted result."""

        harness.run_to_ready_to_execute()
        engine = harness.fresh_orchestrator().fresh_engine()
        pending = harness.state().pending_command
        assert pending is not None and pending.command_id is not None
        engine.tick(harness.config.session_id, CommandDispatchStarted(pending.command_id))
        state = harness.state()
        command, batch = engine._active_execution(state)
        paths = tuple(
            item.path for item in batch.proposed_operations if item.operation_id in set(batch.admitted_operation_ids)
        )
        workspace_target = engine._validated_execution_target(state, paths)
        with self._rebind_after_write(harness, completed):
            result = harness.executor.execute(command=command, batch=batch, workspace_target=workspace_target)
        self.assertIsInstance(result, V0ExecutionInterrupted)
        assert isinstance(result, V0ExecutionInterrupted)
        self.assertEqual(len(result.receipts), completed)
        self.assertEqual(result.completed_action_ids, TURN1_ACTION_IDS[:completed])
        self.assertEqual(result.remaining_action_ids, TURN1_ACTION_IDS[completed:])
        # The interruption was detected by the post-write authority check, so no
        # action failed: the last write really completed.
        self.assertIsNone(result.failed_action_id)
        self.assertEqual(result.interruption_code, "workspace_authority_changed")
        return engine, result

    def test_non_prefix_and_forged_interrupted_results_are_rejected(self) -> None:
        harness = RebindableWorkspaceHarness(self)
        engine, result = self._drive_to_interrupted_result(harness, 2)
        session_id = harness.config.session_id
        before = harness.fresh_orchestrator().session_bytes()

        skipped_first = replace(
            result,
            receipts=(result.receipts[1],),
            remaining_action_ids=TURN1_ACTION_IDS[2:],
        )
        reordered = replace(result, receipts=(result.receipts[1], result.receipts[0]))
        duplicated = replace(
            result,
            receipts=(result.receipts[0], result.receipts[0]),
            remaining_action_ids=TURN1_ACTION_IDS[2:],
        )
        wrong_remainder = replace(result, remaining_action_ids=TURN1_ACTION_IDS[3:])
        for name, forged in (
            ("non_prefix", skipped_first),
            ("reordered", reordered),
            ("duplicated", duplicated),
            ("wrong_remainder", wrong_remainder),
        ):
            with self.subTest(case=name), self.assertRaises(IllegalTransition):
                engine.consume_trusted_interrupted_result(session_id, forged)
            self.assertEqual(harness.fresh_orchestrator().session_bytes(), before)

        forged_hash = replace(
            result,
            receipts=(replace(result.receipts[0], sha256="0" * 64), result.receipts[1]),
        )
        tick = engine.consume_trusted_interrupted_result(session_id, forged_hash)
        self.assertEqual(tick.state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(tick.state.outcome_reason.code, ReasonCode.PHYSICAL_ATTESTATION_FAILED)
        self.assertEqual(len(tick.state.execution_receipt_history), 0)
        self.assertEqual(len(tick.state.materialized_evidence), 0)

    def test_exact_interrupted_result_replay_is_rejected_without_any_change(self) -> None:
        harness = RebindableWorkspaceHarness(self)
        engine, result = self._drive_to_interrupted_result(harness, 2)
        session_id = harness.config.session_id
        tick = engine.consume_trusted_interrupted_result(session_id, result)
        self.assertEqual(tick.state.phase, Phase.TECHNICAL_PAUSE)
        self._assert_durable_prefix(harness, 2)

        after = harness.fresh_orchestrator().session_bytes()
        history = harness.state().execution_receipt_history
        evidence = harness.state().materialized_evidence
        hashes = {path: sha256_file(str(harness.real_workspace / path)) for path in harness.physical_files()}
        writes = harness.executor.write_count
        with self.assertRaises(IllegalTransition):
            engine.consume_trusted_interrupted_result(session_id, result)
        self.assertEqual(harness.fresh_orchestrator().session_bytes(), after)
        self.assertEqual(harness.state().execution_receipt_history, history)
        self.assertEqual(harness.state().materialized_evidence, evidence)
        self.assertEqual({path: sha256_file(str(harness.real_workspace / path)) for path in harness.physical_files()}, hashes)
        self.assertEqual(harness.executor.write_count, writes)

    def test_interrupted_result_is_rejected_through_the_public_event_api(self) -> None:
        harness = RebindableWorkspaceHarness(self)
        engine, result = self._drive_to_interrupted_result(harness, 1)
        with self.assertRaises(IllegalTransition):
            engine.tick(harness.config.session_id, result)


class TestV0Slice2ImportIsolation(unittest.TestCase):
    def test_importing_all_v0_slice_modules_does_not_load_legacy_authority(self) -> None:
        source = """
import importlib
import sys
modules = [
    'admissible.v0_controller.commands', 'admissible.v0_controller.state',
    'admissible.v0_controller.events', 'admissible.v0_controller.reducer',
    'admissible.v0_controller.invariants', 'admissible.v0_controller.store',
    'admissible.v0_controller.workspace_guard', 'admissible.v0_controller.engine',
    'admissible.v0_controller.adapters', 'admissible.v0_controller.integration_policy',
    'admissible.v0_controller.integration_projection', 'admissible.v0_controller.structural_checker',
    'admissible.v0_controller.orchestrator',
]
for name in modules:
    importlib.import_module(name)
forbidden = ('admissible.run_loop', 'admissible.high_autonomy_controller', 'admissible.evaluator', 'admissible.long_run')
loaded = sorted(name for name in sys.modules if any(name == prefix or name.startswith(prefix + '.') for prefix in forbidden))
raise SystemExit(0 if not loaded else 'legacy imports loaded: ' + ', '.join(loaded))
"""
        result = subprocess.run(
            [sys.executable, "-c", source],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


class TestV0Slice2ExplicitOptIn(unittest.TestCase):
    def test_orchestrator_requires_explicit_config(self) -> None:
        harness = CLI008IntegrationHarness(self)
        self.assertIsInstance(harness.orchestrator, V0OfflineOrchestrator)
        with self.assertRaises(WorkspaceIntegrationError):
            bad = replace(
                harness.config,
                contract=cli008_contract(target_workspace=harness.artifact_root),
            )
            V0OfflineOrchestrator(bad)

    def test_invalid_live_root_configuration_blocks_before_any_integration_effect(self) -> None:
        harness = CLI008IntegrationHarness(self)
        outside_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(outside_tmp.cleanup)
        outside = Path(outside_tmp.name) / "outside-workspace"
        outside.mkdir()
        with self.assertRaises(WorkspaceIntegrationError) as rejected:
            V0OfflineIntegrationConfig(
                store_directory=harness.store_dir,
                session_id="outside-root",
                contract=cli008_contract(target_workspace=outside),
                proposal_backend=harness.backend,
                bounded_executor_adapter=harness.executor,
                structural_checker=harness.checker,
                workspace_integration_policy=harness.config.workspace_integration_policy,
                occurred_at=NOW,
            )
        self.assertEqual(rejected.exception.code, "outside_allowed_live_root")
        self.assertEqual(harness.backend.invocation_count, 0)
        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.checker.check_count, 0)
        self.assertEqual(harness.file_hashes(), {})


if __name__ == "__main__":
    unittest.main()
