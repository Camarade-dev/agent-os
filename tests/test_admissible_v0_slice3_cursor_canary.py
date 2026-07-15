"""V0 Slice 3: the one-call, zero-write Cursor canary.

Offline by construction.  The canary's process boundary is driven by the same
``FakeCursorProcessRunner`` the backend tests use, so "did it call Cursor?" is
answered by an exact integer, never by a real process.
"""

from __future__ import annotations

import ast
import os
import tempfile
import unittest
from pathlib import Path

from admissible.diagnostics import v0_cursor_canary as canary
from admissible.v0_controller.state import Phase
from admissible.v0_controller.store import AtomicSessionStore, SessionNotFound

from tests.test_admissible_v0_slice3_cursor_backend import FakeCursorProcessRunner, result_line

SESSION_ID = "v0-cursor-canary-test"


class CanaryHarness:
    def __init__(self, testcase: unittest.TestCase) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "live_workspace"
        self.workspace.mkdir()
        self.agent_workspace = self.root / "agent_workspace"
        self.store_dir = self.root / "sessions"
        # A real native-executable file so resolution succeeds without a real
        # Cursor.  A ``.exe`` (not a ``.cmd``/``.ps1``/``.bat`` wrapper) is used
        # so the Windows shell-wrapper preflight guard does not reject it.
        self.executable = self.root / "cursor-agent.exe"
        self.executable.write_text("", encoding="utf-8")
        self.runner = FakeCursorProcessRunner()

    def argv(self, *flags: str, **overrides: str) -> list[str]:
        values = {
            "--executable": str(self.executable),
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

    def main(self, *flags: str, **overrides: str) -> int:
        return canary.main(self.argv(*flags, **overrides), runner=self.runner)

    def session_exists(self) -> bool:
        try:
            AtomicSessionStore(self.store_dir).load(SESSION_ID)
        except (SessionNotFound, OSError):
            return False
        return True

    def state(self):
        return AtomicSessionStore(self.store_dir).load(SESSION_ID)

    def target_snapshot(self) -> list[str]:
        return sorted(str(p) for p in self.workspace.rglob("*"))


class TestCanaryContract(unittest.TestCase):
    def test_the_canary_contract_is_one_call_and_no_execution(self) -> None:
        self.assertEqual(canary.MAX_INVOCATIONS, 1)
        self.assertEqual(canary.MAX_OPERATIONS, 4)
        self.assertEqual(canary.MAX_TARGET_WRITES, 0)
        self.assertEqual(canary.MAX_EXECUTOR_CALLS, 0)
        self.assertEqual(canary.MAX_STRUCTURAL_CHECKS, 0)
        self.assertEqual(canary.MAX_AUTOMATIC_RETRIES, 0)

    def test_the_canary_names_no_executor_checker_or_driver_loop(self) -> None:
        """Only comments may mention them; no code may name them."""

        tree = ast.parse(Path(canary.__file__).read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.alias):
                names.add(node.name.split(".")[-1])
        for forbidden in (
            "BoundedLocalExecutorV0Adapter",
            "V0StructuralChecker",
            "V0OfflineOrchestrator",
            "V0OfflineIntegrationConfig",
            "run_logical_tick",
            "run_until_awaiting_human",
            "execute_bounded_once",
            "admit_proposal_for_batch",
            "proposal_backend_to_agent_result",
            "AgentResultReceived",
        ):
            self.assertNotIn(forbidden, names)


class TestCanaryFlagGate(unittest.TestCase):
    def test_no_flags_is_a_dry_run_with_zero_runner_calls(self) -> None:
        harness = CanaryHarness(self)
        self.assertEqual(harness.main(), 0)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_execute_alone_is_a_dry_run(self) -> None:
        harness = CanaryHarness(self)
        self.assertEqual(harness.main("--execute"), 0)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_confirm_alone_is_a_dry_run(self) -> None:
        harness = CanaryHarness(self)
        self.assertEqual(harness.main("--confirm-real-invocation"), 0)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_missing_configuration_is_inert(self) -> None:
        harness = CanaryHarness(self)
        argv = [item for item in harness.argv("--execute", "--confirm-real-invocation") if item != str(harness.executable)]
        argv.remove("--executable")
        self.assertEqual(canary.main(argv, runner=harness.runner), 2)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())


class TestCanaryPreflight(unittest.TestCase):
    """Preflight faults must precede any durable, active-looking session."""

    def _preflight_fails(self, harness: CanaryHarness, **overrides: str) -> None:
        code = harness.main("--execute", "--confirm-real-invocation", **overrides)
        self.assertEqual(code, 2)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_a_missing_executable_creates_no_session(self) -> None:
        harness = CanaryHarness(self)
        self._preflight_fails(harness, **{"--executable": "cursor-agent-that-does-not-exist-on-this-host"})

    def test_an_overlapping_agent_workspace_creates_no_session(self) -> None:
        harness = CanaryHarness(self)
        self._preflight_fails(harness, **{"--agent-workspace": str(harness.workspace / "inside")})

    def test_an_invalid_target_policy_creates_no_session(self) -> None:
        harness = CanaryHarness(self)
        outside = self.enterContext(tempfile.TemporaryDirectory()) if hasattr(self, "enterContext") else None
        allowed = outside or str(harness.root / "not-a-root")
        self._preflight_fails(harness, **{"--allowed-workspace-root": allowed})

    def test_a_missing_target_workspace_creates_no_session(self) -> None:
        harness = CanaryHarness(self)
        self._preflight_fails(harness, **{"--target-workspace": str(harness.root / "no-such-dir")})


class TestCanaryOneCall(unittest.TestCase):
    def test_both_flags_perform_exactly_one_invocation_and_no_writes(self) -> None:
        harness = CanaryHarness(self)
        before = harness.target_snapshot()
        code = harness.main("--execute", "--confirm-real-invocation")
        self.assertEqual(code, 0)
        self.assertEqual(harness.runner.started, 1)
        # Four proposals parsed, zero writes, zero executor calls, zero checks.
        self.assertEqual(len(harness.runner.instructions), 1)
        self.assertEqual(harness.target_snapshot(), before)
        self.assertEqual(harness.target_snapshot(), [])

    def test_the_session_settles_where_it_cannot_continue(self) -> None:
        harness = CanaryHarness(self)
        harness.main("--execute", "--confirm-real-invocation")
        state = harness.state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertIn(canary.CANARY_PAUSE_CODE, state.outcome_reason.message)
        # Nothing was admitted, executed, or checked -- and no ADMIT_PROPOSAL
        # command exists for anything to pick up.
        self.assertIsNone(state.current_batch)
        self.assertEqual(state.batch_history, ())
        self.assertEqual(state.execution_receipt_history, ())
        self.assertEqual(state.materialized_evidence, ())
        self.assertIsNone(state.structural_verification)
        self.assertIsNone(state.pending_command)

    def test_a_four_operation_result_is_inspected_but_never_admitted(self) -> None:
        harness = CanaryHarness(self)
        pre = canary.preflight(canary.build_parser().parse_args(harness.argv()))
        outcome = canary.run_one_call_canary(pre, runner=harness.runner)
        self.assertEqual(outcome.invocations, 1)
        self.assertEqual(outcome.operations, 4)
        self.assertEqual(outcome.target_writes, 0)
        self.assertEqual(outcome.executor_calls, 0)
        self.assertEqual(outcome.structural_checks, 0)
        self.assertEqual(outcome.final_phase, Phase.TECHNICAL_PAUSE.value)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.target_snapshot(), [])

    def test_a_result_with_follow_up_work_still_makes_no_second_call(self) -> None:
        # The proposal leaves four mandatory paths unmaterialized: a continuation
        # opportunity the canary must ignore completely.
        harness = CanaryHarness(self)
        pre = canary.preflight(canary.build_parser().parse_args(harness.argv()))
        outcome = canary.run_one_call_canary(pre, runner=harness.runner)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(outcome.invocations, 1)
        state = harness.state()
        self.assertEqual(len(state.remaining_paths()), 8)  # nothing was executed
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)

    def test_the_invocation_maximum_is_one_not_two(self) -> None:
        # Off-by-one regression: a second dispatch attempt must be refused by the
        # backend's own maximum, not merely by the (already terminal) session.
        harness = CanaryHarness(self)
        pre = canary.preflight(canary.build_parser().parse_args(harness.argv()))
        canary.run_one_call_canary(pre, runner=harness.runner)
        self.assertEqual(harness.runner.started, 1)

        second = CanaryHarness(self)
        second.runner = harness.runner
        from admissible.v0_controller.cursor_backend import CursorCallableProposalBackend
        from admissible.v0_controller.cursor_dispatch import PersistedCursorDispatchRequest
        from admissible.v0_controller.cursor_failures import (
            V0BackendFailureKind,
            V0ProposalBackendFailure,
        )

        backend = CursorCallableProposalBackend(
            config=pre.config,
            target_workspace=pre.target_workspace,
            store=AtomicSessionStore(pre.store_directory),
            runner=harness.runner,
            max_invocations=canary.MAX_INVOCATIONS,
        )
        backend._invocation_count = canary.MAX_INVOCATIONS  # already at the cap
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            backend.invoke_persisted(
                request=PersistedCursorDispatchRequest(
                    session_id=SESSION_ID,
                    command_id="v0cmd:anything",
                    invocation_id="v0inv:anything",
                    batch_id="v0inv:anything:batch:1",
                    expected_revision=0,
                    backend_fingerprint=backend.config_fingerprint,
                )
            )
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.DISPATCH_ORDER_VIOLATION)
        self.assertEqual(harness.runner.started, 1)

    def test_a_failing_invocation_still_settles_and_writes_nothing(self) -> None:
        harness = CanaryHarness(self)
        harness.runner = FakeCursorProcessRunner(
            stream_builder=lambda instruction: [result_line("I already wrote all the files.")]
        )
        code = harness.main("--execute", "--confirm-real-invocation")
        self.assertEqual(code, 1)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.state().phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(harness.target_snapshot(), [])


class TestCanaryExecutablePrefix(unittest.TestCase):
    """Native launcher prefix: node.exe + index.js compatibility on the canary."""

    def _index_js(self, harness: CanaryHarness) -> Path:
        launcher = harness.root / "launcher" / "index.js"
        launcher.parent.mkdir(parents=True, exist_ok=True)
        launcher.write_text("// fake launcher\n", encoding="utf-8")
        return launcher

    def test_native_exe_plus_index_js_passes_dry_run_preflight(self) -> None:
        harness = CanaryHarness(self)
        index_js = self._index_js(harness)
        code = harness.main("--executable-prefix-arg", str(index_js))
        self.assertEqual(code, 0)  # dry run
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_dry_run_prints_executable_prefix_and_effective_argv(self) -> None:
        harness = CanaryHarness(self)
        index_js = self._index_js(harness)
        pre = canary.preflight(
            canary.build_parser().parse_args(
                harness.argv("--executable-prefix-arg", str(index_js))
            )
        )
        text = canary.describe(pre, real=False)
        self.assertIn("executable prefix arguments", text)
        self.assertIn(str(index_js.resolve()), text)
        self.assertIn("effective argv template", text)
        # The prefix sits between the executable and the fixed Cursor arguments.
        argv = list(pre.config.fixed_arguments())
        self.assertEqual(argv[0], str(harness.executable))
        self.assertEqual(argv[1], str(index_js.resolve()))
        self.assertEqual(argv[2], "--print")

    def test_a_missing_required_launcher_file_rejects_before_any_session(self) -> None:
        harness = CanaryHarness(self)
        missing = harness.root / "launcher" / "does-not-exist.js"
        code = harness.main(
            "--executable-prefix-arg", str(missing), "--execute", "--confirm-real-invocation"
        )
        self.assertEqual(code, 2)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_a_directory_as_required_launcher_file_rejects(self) -> None:
        harness = CanaryHarness(self)
        directory = harness.root / "launcher-dir"
        directory.mkdir()
        code = harness.main(
            "--executable-prefix-arg", str(directory), "--execute", "--confirm-real-invocation"
        )
        self.assertEqual(code, 2)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    def test_a_launcher_file_inside_the_target_workspace_rejects(self) -> None:
        harness = CanaryHarness(self)
        inside = harness.workspace / "index.js"
        inside.write_text("// inside target\n", encoding="utf-8")
        code = harness.main(
            "--executable-prefix-arg", str(inside), "--execute", "--confirm-real-invocation"
        )
        self.assertEqual(code, 2)
        self.assertEqual(harness.runner.started, 0)
        self.assertFalse(harness.session_exists())

    @unittest.skipUnless(os.name == "nt", "shell-wrapper extension guard is Windows-specific")
    def test_ps1_cmd_bat_executables_reject_on_windows(self) -> None:
        for suffix in (".ps1", ".cmd", ".bat"):
            with self.subTest(suffix=suffix):
                harness = CanaryHarness(self)
                wrapper = harness.root / f"cursor-agent{suffix}"
                wrapper.write_text("", encoding="utf-8")
                code = harness.main(
                    "--execute",
                    "--confirm-real-invocation",
                    **{"--executable": str(wrapper)},
                )
                self.assertEqual(code, 2)
                self.assertEqual(harness.runner.started, 0)
                self.assertFalse(harness.session_exists())

    def test_prefix_canary_performs_exactly_one_call_and_no_writes(self) -> None:
        harness = CanaryHarness(self)
        index_js = self._index_js(harness)
        before = harness.target_snapshot()
        code = harness.main(
            "--executable-prefix-arg", str(index_js), "--execute", "--confirm-real-invocation"
        )
        self.assertEqual(code, 0)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(len(harness.runner.instructions), 1)
        # The real spawned argv carried the resolved prefix between exe and args.
        argv = list(harness.runner.invocations[0].argv)
        self.assertEqual(argv[0], str(harness.executable))
        self.assertEqual(argv[1], str(index_js.resolve()))
        self.assertEqual(argv[2], "--print")
        # Zero target writes.
        self.assertEqual(harness.target_snapshot(), before)
        self.assertEqual(harness.target_snapshot(), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
