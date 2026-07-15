"""V0 Slice 4: the operator-only first real two-turn Cursor trajectory runner.

Offline by construction.  The process boundary is driven by the same
``FakeCursorProcessRunner`` the Slice 3 backend tests use, so "did it call
Cursor?" is answered by an exact integer, never by a real process.  No browser,
runtime, repair, or retry path is ever imported or exercised.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path
from typing import Any

from admissible.diagnostics import v0_cursor_live_run as live
from admissible.v0_controller.cursor_failures import V0BackendFailureKind, V0ProposalBackendFailure
from admissible.v0_controller.orchestrator import CLI008_MANDATORY_PATHS, V0OfflineOrchestrator
from admissible.v0_controller.state import Phase
from admissible.v0_controller.store import AtomicSessionStore, SessionNotFound

from tests.test_admissible_v0_slice3_cursor_backend import (
    FakeCursorProcessRunner,
    successful_stream,
)

SESSION_ID = "v0-cursor-live-run-test"


class LiveRunHarness:
    def __init__(self, testcase: unittest.TestCase) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "live_workspace"
        self.workspace.mkdir()
        self.agent_workspace = self.root / "agent_workspace"
        self.store_dir = self.root / "sessions"
        # A real native-executable file (not a .cmd/.ps1/.bat wrapper) so
        # resolution succeeds without a real Cursor.
        self.executable = self.root / "cursor-agent.exe"
        self.executable.write_text("", encoding="utf-8")
        self.launcher = self.root / "index.js"
        self.launcher.write_text("// launcher\n", encoding="utf-8")
        self.runner = FakeCursorProcessRunner()

    def argv(self, *flags: str, **overrides: str) -> list[str]:
        values = {
            "--executable": str(self.executable),
            "--executable-prefix-arg": str(self.launcher),
            "--target-workspace": str(self.workspace),
            "--agent-workspace": str(self.agent_workspace),
            "--store-directory": str(self.store_dir),
            "--session-id": SESSION_ID,
            "--allowed-workspace-root": str(self.root),
        }
        values.update(overrides)
        argv: list[str] = []
        for name, value in values.items():
            argv.extend([name, value])
        argv.extend(flags)
        return argv

    def args(self, *flags: str, **overrides: str):
        return live.build_parser().parse_args(self.argv(*flags, **overrides))

    def main(self, *flags: str, runner: Any = "default", **overrides: str) -> int:
        use = self.runner if runner == "default" else runner
        return live.main(self.argv(*flags, **overrides), runner=use)

    def session_exists(self) -> bool:
        try:
            AtomicSessionStore(self.store_dir).load(SESSION_ID)
        except (SessionNotFound, OSError):
            return False
        return True

    def state(self):
        return AtomicSessionStore(self.store_dir).load(SESSION_ID)

    def target_files(self) -> list[str]:
        return sorted(str(p.relative_to(self.workspace)).replace("\\", "/") for p in self.workspace.rglob("*") if p.is_file())


# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------


class TestLiveRunContract(unittest.TestCase):
    def test_contract_constants(self) -> None:
        self.assertEqual(live.MAX_CURSOR_INVOCATIONS, 2)
        self.assertEqual(live.MAX_OPERATIONS_PER_RESULT, 4)
        self.assertEqual(live.MAX_ADMITTED_OPERATIONS, 8)
        self.assertEqual(live.MAX_TARGET_WRITES, 8)
        self.assertEqual(live.MAX_AUTOMATIC_RETRIES, 0)
        self.assertEqual(live.MAX_REPAIR_ROUNDS, 0)
        self.assertEqual(live.MAX_RUNTIME_ATTEMPTS, 0)
        self.assertEqual(live.MAX_STRUCTURAL_CHECKS, 1)
        self.assertEqual(live.POST_TERMINAL_STABILITY_CHECKS, 20)
        self.assertEqual(live.EXPECTED_FINAL_PHASE, Phase.AWAITING_HUMAN)
        self.assertEqual(live.MISSION_MANDATORY_PATHS, CLI008_MANDATORY_PATHS)
        self.assertEqual(len(live.MISSION_MANDATORY_PATHS), 8)

    def test_module_imports_no_browser_runtime_repair_or_retry_paths(self) -> None:
        tree = ast.parse(Path(live.__file__).read_text(encoding="utf-8"))
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
            elif isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
        forbidden_fragments = ("browser_runtime", "runtime_verification", "repair", "run_loop", "chromium", "cdp")
        for module in modules:
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, module, f"forbidden import {module!r} names {fragment!r}")


# ---------------------------------------------------------------------------
# Inert-by-default / double-confirmation gate
# ---------------------------------------------------------------------------


class TestDryRunAndConfirmationGate(unittest.TestCase):
    def _assert_no_effects(self, harness: LiveRunHarness) -> None:
        self.assertFalse(harness.session_exists())
        self.assertEqual(harness.target_files(), [])
        self.assertEqual(harness.runner.started, 0)

    def test_default_is_dry_run(self) -> None:
        harness = LiveRunHarness(self)
        self.assertEqual(harness.main(), 0)
        self._assert_no_effects(harness)

    def test_execute_alone_remains_dry_run(self) -> None:
        harness = LiveRunHarness(self)
        self.assertEqual(harness.main("--execute"), 0)
        self._assert_no_effects(harness)

    def test_confirm_alone_remains_dry_run(self) -> None:
        harness = LiveRunHarness(self)
        self.assertEqual(harness.main("--confirm-real-run"), 0)
        self._assert_no_effects(harness)

    def test_missing_configuration_is_inert(self) -> None:
        code = live.main(["--session-id", "x"], runner=FakeCursorProcessRunner())
        self.assertEqual(code, 2)


# ---------------------------------------------------------------------------
# Preflight isolation and budget configuration
# ---------------------------------------------------------------------------


class TestPreflightIsolation(unittest.TestCase):
    def test_agent_inside_target_is_rejected(self) -> None:
        harness = LiveRunHarness(self)
        args = harness.args(**{"--agent-workspace": str(harness.workspace / "agent")})
        with self.assertRaises(live.LiveRunPreflightError) as exc:
            live.preflight(args)
        self.assertEqual(exc.exception.code, "workspace_overlap")

    def test_store_inside_target_is_rejected(self) -> None:
        harness = LiveRunHarness(self)
        args = harness.args(**{"--store-directory": str(harness.workspace / "sessions")})
        with self.assertRaises(live.LiveRunPreflightError) as exc:
            live.preflight(args)
        self.assertEqual(exc.exception.code, "store_overlap")

    def test_unclean_target_is_rejected(self) -> None:
        harness = LiveRunHarness(self)
        (harness.workspace / "leftover.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(live.LiveRunPreflightError) as exc:
            live.preflight(harness.args())
        self.assertEqual(exc.exception.code, "unclean_target_workspace")

    def test_shell_wrapper_executable_rejected_on_windows(self) -> None:
        import os

        if os.name != "nt":
            self.skipTest("windows-only shell wrapper guard")
        harness = LiveRunHarness(self)
        wrapper = harness.root / "cursor-agent.cmd"
        wrapper.write_text("", encoding="utf-8")
        with self.assertRaises(live.LiveRunPreflightError) as exc:
            live.preflight(harness.args(**{"--executable": str(wrapper)}))
        self.assertEqual(exc.exception.code, "shell_wrapper_executable")

    def test_wrong_invocation_limit_rejected(self) -> None:
        harness = LiveRunHarness(self)
        with self.assertRaises(live.LiveRunPreflightError) as exc:
            live.preflight(harness.args(**{"--invocation-limit": "3"}))
        self.assertEqual(exc.exception.code, "invalid_invocation_limit")

    def test_backend_invocation_budget_is_two(self) -> None:
        harness = LiveRunHarness(self)
        pre = live.preflight(harness.args())
        _config, backend, _executor, _checker = live.build_integration_config(pre, runner=harness.runner)
        self.assertEqual(backend.max_invocations, live.MAX_CURSOR_INVOCATIONS)


# ---------------------------------------------------------------------------
# The successful two-turn / eight-write path
# ---------------------------------------------------------------------------


class TestSuccessfulTwoTurnPath(unittest.TestCase):
    def _run(self, harness: LiveRunHarness) -> live.LiveRunOutcome:
        pre = live.preflight(harness.args())
        return live.run_live_trajectory(pre, runner=harness.runner)

    def test_full_trajectory_totals(self) -> None:
        harness = LiveRunHarness(self)
        outcome = self._run(harness)
        self.assertEqual(outcome.final_phase, Phase.AWAITING_HUMAN.value)
        self.assertEqual(outcome.invocation_count, 2)
        self.assertEqual(outcome.result_count, 2)
        self.assertEqual(outcome.admitted_operations, 8)
        self.assertEqual(outcome.physical_writes, 8)
        self.assertEqual(outcome.durable_receipts, 8)
        self.assertEqual(outcome.evidence_count, 8)
        self.assertEqual(outcome.structural_checks, 1)
        self.assertEqual(outcome.remaining_mandatory_paths, ())
        self.assertEqual(outcome.technical_failure, "")
        self.assertEqual(outcome.budget_breach, "")
        self.assertEqual(harness.runner.started, 2)

    def test_every_mandatory_file_is_present_with_bytes(self) -> None:
        harness = LiveRunHarness(self)
        outcome = self._run(harness)
        self.assertEqual({item.path for item in outcome.target_manifest}, set(CLI008_MANDATORY_PATHS))
        for item in outcome.target_manifest:
            self.assertTrue(item.present, item.path)
            self.assertIsNotNone(item.sha256)
            self.assertGreater(item.byte_count, 0)
        self.assertEqual(harness.target_files(), sorted(CLI008_MANDATORY_PATHS))

    def test_first_result_four_ops_second_result_four_remaining(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)
        self.assertEqual(len(harness.runner.instructions), 2)
        first, second = harness.runner.instructions
        self.assertEqual(first["remaining_mandatory_paths"], list(CLI008_MANDATORY_PATHS))
        self.assertEqual(second["remaining_mandatory_paths"], list(CLI008_MANDATORY_PATHS[4:]))
        state = harness.state()
        completed = [batch for batch in state.batch_history if batch.status.value == "completed"]
        self.assertEqual(len(completed), 2)
        for batch in completed:
            self.assertEqual(len(batch.admitted_operation_ids), 4)

    def test_structural_check_happens_once_and_only_after_all_paths_exist(self) -> None:
        harness = LiveRunHarness(self)
        outcome = self._run(harness)
        structural_transitions = [t for t in outcome.transitions if t.step_kind == "structural_check"]
        self.assertEqual(len(structural_transitions), 1)
        # Before the structural check transition, both batches are already
        # executed: the checking phase is only reachable with zero remaining paths.
        checking = [t for t in outcome.transitions if t.phase == Phase.CHECKING_FILES.value]
        self.assertTrue(checking)
        self.assertEqual(outcome.structural_checks, 1)

    def test_main_real_run_returns_zero(self) -> None:
        harness = LiveRunHarness(self)
        self.assertEqual(harness.main("--execute", "--confirm-real-run"), 0)
        self.assertEqual(harness.state().phase, Phase.AWAITING_HUMAN)


# ---------------------------------------------------------------------------
# Budget impossibilities
# ---------------------------------------------------------------------------


class TestBudgetImpossibilities(unittest.TestCase):
    def _run(self, harness: LiveRunHarness) -> live.LiveRunOutcome:
        pre = live.preflight(harness.args())
        self._pre = pre
        return live.run_live_trajectory(pre, runner=harness.runner)

    def test_third_invocation_is_structurally_impossible(self) -> None:
        harness = LiveRunHarness(self)
        pre = live.preflight(harness.args())
        config, backend, _executor, _checker = live.build_integration_config(pre, runner=harness.runner)
        orchestrator = V0OfflineOrchestrator(config)
        orchestrator.create_session()
        for _ in range(live.MAX_LOGICAL_STEPS):
            if orchestrator.load_state().phase == Phase.AWAITING_HUMAN:
                break
            V0OfflineOrchestrator(config).run_logical_tick()
        self.assertEqual(backend.invocation_count, 2)
        # Any further logical tick after the terminal state is a NoEvent: it can
        # never start a third Cursor invocation.
        V0OfflineOrchestrator(config).run_logical_tick()
        self.assertEqual(backend.invocation_count, 2)
        self.assertEqual(harness.runner.started, 2)

    def test_ninth_write_is_impossible(self) -> None:
        harness = LiveRunHarness(self)
        outcome = self._run(harness)
        writes = outcome.physical_writes
        self.assertEqual(writes, 8)
        config, _b, executor, _c = live.build_integration_config(self._pre, runner=harness.runner)
        # Re-driving the already-terminal persisted session performs no new write.
        for _ in range(3):
            V0OfflineOrchestrator(config).run_no_event_tick()
        self.assertEqual(executor.write_count, 0)  # a fresh executor never ran
        self.assertEqual(len(harness.state().execution_receipt_history), 8)

    def test_enforce_budget_flags_premature_structural_check_and_overruns(self) -> None:
        # Direct unit checks of the independent budget layer.
        harness = LiveRunHarness(self)
        pre = live.preflight(harness.args())
        config, backend, executor, checker = live.build_integration_config(pre, runner=harness.runner)
        orchestrator = V0OfflineOrchestrator(config)
        orchestrator.create_session()
        state = orchestrator.load_state()
        # A clean early state passes the budget layer.
        live._enforce_budget(state, backend=backend, executor=executor, checker=checker)
        # Simulated overruns fail closed.
        executor.write_count = 9
        with self.assertRaises(live.LiveRunBudgetExceeded) as exc:
            live._enforce_budget(state, backend=backend, executor=executor, checker=checker)
        self.assertEqual(exc.exception.code, "write_budget")


# ---------------------------------------------------------------------------
# Fail-closed paths: technical pause, provider uncertainty, no retry
# ---------------------------------------------------------------------------


class TestFailClosedPaths(unittest.TestCase):
    def _run(self, harness: LiveRunHarness, runner: FakeCursorProcessRunner) -> live.LiveRunOutcome:
        pre = live.preflight(harness.args())
        return live.run_live_trajectory(pre, runner=runner)

    def test_terminal_provider_failure_pauses_and_stops(self) -> None:
        harness = LiveRunHarness(self)
        runner = FakeCursorProcessRunner(returncode=3)
        outcome = self._run(harness, runner)
        self.assertEqual(outcome.final_phase, Phase.TECHNICAL_PAUSE.value)
        self.assertNotEqual(outcome.technical_failure, "")
        self.assertEqual(outcome.physical_writes, 0)
        self.assertEqual(outcome.structural_checks, 0)
        self.assertEqual(runner.started, 1)
        self.assertTrue(outcome.stability_byte_stable)

    def test_provider_uncertainty_never_retries(self) -> None:
        harness = LiveRunHarness(self)
        # Unproven process cleanup is the canonical uncertain completion.
        runner = FakeCursorProcessRunner(cleanup_proven=False, remaining_process_ids=(4321,))
        outcome = self._run(harness, runner)
        self.assertEqual(outcome.final_phase, Phase.TECHNICAL_PAUSE.value)
        self.assertEqual(runner.started, 1)  # exactly one attempt: no retry
        self.assertEqual(outcome.physical_writes, 0)
        self.assertTrue(outcome.stability_byte_stable)

    def test_the_fake_uncertain_failure_kind_is_cleanup(self) -> None:
        # Sanity: the fake really models an uncertain completion the backend rejects.
        harness = LiveRunHarness(self)
        pre = live.preflight(harness.args())
        config, backend, _e, _c = live.build_integration_config(
            pre, runner=FakeCursorProcessRunner(cleanup_proven=False, remaining_process_ids=(1,))
        )
        orchestrator = V0OfflineOrchestrator(config)
        orchestrator.create_session()
        V0OfflineOrchestrator(config).run_logical_tick()  # prepared dispatch
        command = orchestrator.load_state().pending_command
        assert command is not None
        from admissible.v0_controller.cursor_dispatch import PersistedCursorDispatchRequest
        from admissible.v0_controller.cursor_instruction import expected_batch_id
        from admissible.v0_controller.events import CommandDispatchStarted

        orchestrator.fresh_engine().tick(SESSION_ID, CommandDispatchStarted(command.command_id or ""))
        state = orchestrator.load_state()
        with self.assertRaises(V0ProposalBackendFailure) as exc:
            backend.invoke_persisted(
                request=PersistedCursorDispatchRequest(
                    session_id=SESSION_ID,
                    command_id=command.command_id or "",
                    invocation_id=command.owner_id,
                    batch_id=expected_batch_id(state, command.owner_id),
                    expected_revision=state.revision,
                    backend_fingerprint=backend.config_fingerprint,
                )
            )
        self.assertEqual(exc.exception.kind, V0BackendFailureKind.PROCESS_CLEANUP_FAILED)


# ---------------------------------------------------------------------------
# Reconstruction and stability
# ---------------------------------------------------------------------------


class TestReconstructionAndStability(unittest.TestCase):
    def _run(self, harness: LiveRunHarness) -> live.LiveRunOutcome:
        pre = live.preflight(harness.args())
        self._pre = pre
        return live.run_live_trajectory(pre, runner=harness.runner)

    def test_restart_reconstructs_terminal_state_from_disk(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)
        # A brand-new orchestrator built only from the store reconstructs the
        # terminal state; nothing lived in memory.
        config, _b, _e, _c = live.build_integration_config(self._pre, runner=FakeCursorProcessRunner())
        reloaded = V0OfflineOrchestrator(config).load_state()
        self.assertEqual(reloaded.phase, Phase.AWAITING_HUMAN)
        self.assertEqual(len(reloaded.execution_receipt_history), 8)
        self.assertEqual(reloaded.remaining_paths(), ())

    def test_twenty_final_no_event_ticks_are_byte_stable(self) -> None:
        harness = LiveRunHarness(self)
        outcome = self._run(harness)
        self.assertEqual(len(outcome.stability_ticks), 20)
        self.assertTrue(outcome.stability_byte_stable)
        revisions = {tick.revision for tick in outcome.stability_ticks}
        phases = {tick.phase for tick in outcome.stability_ticks}
        self.assertEqual(len(revisions), 1)
        self.assertEqual(phases, {Phase.AWAITING_HUMAN.value})

    def test_target_and_store_remain_isolated(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)
        # No session artifacts leaked into the target; no target files leaked
        # into the store.
        store_files = {p.name for p in harness.store_dir.rglob("*") if p.is_file()}
        self.assertTrue(any(name.endswith(".v0.json") for name in store_files))
        for path in CLI008_MANDATORY_PATHS:
            self.assertFalse((harness.store_dir / path).exists())
        self.assertEqual(harness.target_files(), sorted(CLI008_MANDATORY_PATHS))


class TestMissionBinding(unittest.TestCase):
    """The operator mission is persisted and reaches the governed instruction."""

    def _run(self, harness: LiveRunHarness, **overrides: str) -> live.LiveRunOutcome:
        pre = live.preflight(harness.args(**overrides))
        self._pre = pre
        return live.run_live_trajectory(pre, runner=harness.runner)

    def _instruction_prompt(self, instruction: dict) -> str:
        from admissible.v0_controller.cursor_instruction import render_governed_prompt

        return render_governed_prompt(instruction)

    def test_first_instruction_contains_the_exact_neon_mission(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)
        instruction = harness.runner.instructions[0]
        normalized = live.normalize_mission(live.DEFAULT_MISSION_SUMMARY)
        self.assertEqual(instruction["mission"]["specification"], normalized)
        self.assertIn("Neon Serpents", instruction["mission"]["specification"])
        self.assertEqual(instruction["mission"]["mandatory_paths"], list(CLI008_MANDATORY_PATHS))
        self.assertEqual(instruction["remaining_mandatory_paths"], list(CLI008_MANDATORY_PATHS))
        self.assertEqual(instruction["operation_limit"], 4)
        self.assertTrue(instruction["proposal_only"])
        prompt = self._instruction_prompt(instruction)
        self.assertIn("Neon Serpents", prompt)
        self.assertIn("MISSION SPECIFICATION", prompt)
        self.assertIn("COMPLETE final content", prompt)
        for boundary in ("shell", "network", "browser", "package_install", "deploy", "git"):
            self.assertIn(boundary, prompt)
        # direct workspace writes are forbidden by the explicit proposal-only clause.
        self.assertIn("MUST NOT write, create, edit, or delete any file", prompt)
        self.assertIn("direct_workspace_write", instruction["prohibited_capabilities"])

    def test_second_turn_instruction_carries_the_same_immutable_mission(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)
        first, second = harness.runner.instructions
        self.assertEqual(first["mission"]["specification"], second["mission"]["specification"])
        self.assertEqual(second["remaining_mandatory_paths"], list(CLI008_MANDATORY_PATHS[4:]))
        self.assertEqual([item["path"] for item in second["materialized_paths"]], list(CLI008_MANDATORY_PATHS[:4]))

    def test_mission_survives_disk_reconstruction(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)
        reloaded = harness.state()
        self.assertEqual(
            reloaded.contract.mission_specification, live.normalize_mission(live.DEFAULT_MISSION_SUMMARY)
        )

    def test_changing_cli_mission_after_creation_does_not_change_instruction(self) -> None:
        from admissible.v0_controller.cursor_instruction import build_governed_instruction

        harness = LiveRunHarness(self)
        # Create a session (mission A) and drive to a persisted dispatch command.
        pre_a = live.preflight(harness.args())
        config, _b, _e, _c = live.build_integration_config(pre_a, runner=harness.runner)
        V0OfflineOrchestrator(config).create_session()
        V0OfflineOrchestrator(config).run_logical_tick()  # -> prepared dispatch
        state = V0OfflineOrchestrator(config).load_state()
        command = state.pending_command
        assert command is not None
        mission_a = live.normalize_mission(live.DEFAULT_MISSION_SUMMARY)
        # A brand-new CLI object naming a DIFFERENT mission is discarded: the
        # instruction is built only from persisted state.
        _pre_b = live.preflight(harness.args(**{"--mission-summary": "an entirely different mission"}))
        instruction = build_governed_instruction(state=state, command=command)
        self.assertEqual(instruction["mission"]["specification"], mission_a)
        self.assertNotIn("different mission", instruction["mission"]["specification"])

    def test_resuming_with_a_different_mission_rejects_with_zero_runner_calls(self) -> None:
        harness = LiveRunHarness(self)
        self._run(harness)  # persist a session under the default (Neon) mission
        fresh_runner = FakeCursorProcessRunner()
        pre_b = live.preflight(harness.args(**{"--mission-summary": "a conflicting mission for the same session id"}))
        with self.assertRaises(live.LiveRunMissionMismatch):
            live.run_live_trajectory(pre_b, runner=fresh_runner)
        self.assertEqual(fresh_runner.started, 0)

    def test_invalid_missions_reject_before_session_creation(self) -> None:
        cases = {
            "": "empty_mission",
            "   \n  \t ": "empty_mission",
            "hello\x00world": "nul_in_mission",
            "x" * (live.MAX_MISSION_BYTES + 1): "oversized_mission",
        }
        for raw, code in cases.items():
            with self.subTest(code=code):
                harness = LiveRunHarness(self)
                with self.assertRaises(live.LiveRunPreflightError) as exc:
                    live.preflight(harness.args(**{"--mission-summary": raw}))
                self.assertEqual(exc.exception.code, code)
                self.assertFalse(harness.session_exists())
                self.assertEqual(harness.runner.started, 0)

    def test_equivalent_normalized_input_yields_byte_identical_instructions(self) -> None:
        base = live.normalize_mission(live.DEFAULT_MISSION_SUMMARY)
        noisy = "\r\n\r\n" + base.replace("\n", "  \r\n") + "\n\n   \n"
        self.assertEqual(live.normalize_mission(noisy), base)

        harness_a = LiveRunHarness(self)
        self._run(harness_a)
        harness_b = LiveRunHarness(self)
        pre_b = live.preflight(harness_b.args(**{"--mission-summary": noisy}))
        live.run_live_trajectory(pre_b, runner=harness_b.runner)
        self.assertEqual(
            harness_a.runner.instructions[0]["mission"]["specification"],
            harness_b.runner.instructions[0]["mission"]["specification"],
        )
        self.assertEqual(
            self._instruction_prompt(harness_a.runner.instructions[0]),
            self._instruction_prompt(harness_b.runner.instructions[0]),
        )

    def test_two_turn_totals_are_unchanged_by_mission_binding(self) -> None:
        harness = LiveRunHarness(self)
        outcome = self._run(harness)
        self.assertEqual(outcome.invocation_count, 2)
        self.assertEqual(outcome.admitted_operations, 8)
        self.assertEqual(outcome.physical_writes, 8)
        self.assertEqual(outcome.durable_receipts, 8)
        self.assertEqual(outcome.structural_checks, 1)
        self.assertEqual(outcome.final_phase, Phase.AWAITING_HUMAN.value)
        self.assertEqual(len(outcome.stability_ticks), 20)
        self.assertTrue(outcome.stability_byte_stable)

    def test_mission_file_overrides_summary(self) -> None:
        harness = LiveRunHarness(self)
        mission_file = harness.root / "mission.txt"
        mission_file.write_text("Build Neon Serpents from a file mission.\n- local only\n", encoding="utf-8")
        pre = live.preflight(harness.args(**{"--mission-file": str(mission_file)}))
        self.assertEqual(pre.mission_specification, "Build Neon Serpents from a file mission.\n- local only")

    def test_runner_module_does_not_touch_control_surface(self) -> None:
        source = Path(live.__file__).read_text(encoding="utf-8")
        self.assertNotIn("control_surface", source)
        self.assertNotIn("high_autonomy", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
