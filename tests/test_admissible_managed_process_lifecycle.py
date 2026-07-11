"""Managed-process lifecycle tests (slice ADMISSIBLE_RUN_047, PART A / K 1-4,15).

Drives a deterministic fake process *world* (which pids are alive, whether they
survive a tree kill) through ``ManagedProcess`` — no real subprocess. The real
OS containment (Windows Job Object / POSIX session) is validated only by the
opt-in real integration test; here the orchestration + cleanup verification +
circuit-breaker input are proven deterministically.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from admissible.managed_process import (
    PLATFORM_STRATEGY_POSIX_SESSION,
    PLATFORM_STRATEGY_WINDOWS_JOB,
    TERMINATION_CLEANUP_FAILED,
    ContainmentStrategy,
    ManagedProcess,
    TreeTerminationOutcome,
    pid_alive,
    run_managed_oneshot,
)
from admissible.transport_health import (
    HEALTH_UNHEALTHY,
    OUTCOME_CLEANUP_FAILURE,
    TransportHealth,
)


# ---------------------------------------------------------------------------
# Deterministic fake process world
# ---------------------------------------------------------------------------


class FakeWorld:
    def __init__(self, root: int, descendants, *, leak=()) -> None:
        self.root = root
        self.descendants = list(descendants)
        self.leak = set(leak)
        self.alive = {root: True}
        for d in descendants:
            self.alive[d] = True

    def is_alive(self, pid) -> bool:
        return self.alive.get(pid, False)

    def kill_all(self) -> None:
        for pid in list(self.alive):
            if pid not in self.leak:
                self.alive[pid] = False


class _FakeStdin:
    def __init__(self, proc: "FakeProc") -> None:
        self.proc = proc

    def write(self, text: str) -> None:
        pass

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.proc.graceful_closed = True


class FakeProc:
    """Minimal Popen-like process backed by a FakeWorld."""

    def __init__(self, world: FakeWorld, *, exits_on_graceful: bool) -> None:
        self.world = world
        self.pid = world.root
        self.exits_on_graceful = exits_on_graceful
        self.graceful_closed = False
        self.stdin = _FakeStdin(self)
        self.stdout = None
        self.stderr = None

    def poll(self):
        return None if self.world.is_alive(self.pid) else 0

    def wait(self, timeout=None):
        if self.exits_on_graceful and self.graceful_closed:
            # A well-behaved graceful shutdown exits the whole owned tree.
            self.world.kill_all()
            return 0
        raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

    def kill(self):
        self.world.alive[self.pid] = False


class FakeContainment(ContainmentStrategy):
    def __init__(self, world: FakeWorld, name: str) -> None:
        self.world = world
        self.name = name
        self.assigned = False

    def assign(self, proc) -> None:
        self.assigned = True

    def observed_descendant_ids(self, proc):
        return list(self.world.descendants)

    def terminate_tree(self, proc, *, grace_seconds, force_seconds):
        self.world.kill_all()
        remaining = [
            p for p in [self.world.root, *self.world.descendants] if self.world.is_alive(p)
        ]
        return TreeTerminationOutcome(
            observed_descendant_ids=list(self.world.descendants),
            remaining_process_ids=remaining,
            strategy=self.name,
        )

    def is_alive(self, pid):
        return self.world.is_alive(pid)


def _spawn_of(proc: FakeProc):
    def spawn(argv, *, cwd, env, want_stdin):
        return proc

    return spawn


def _managed(proc: FakeProc, containment: FakeContainment) -> ManagedProcess:
    return ManagedProcess(
        ["cursor-agent.CMD", "acp"],
        cwd=".",
        env={},
        want_stdin=True,
        grace_seconds=0.05,
        force_seconds=0.05,
        spawn=_spawn_of(proc),
        containment=containment,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestManagedProcessTreeCleanup(unittest.TestCase):
    def test_01_windows_owned_tree_cleanup_kills_wrapper_and_descendants(self) -> None:
        # Models the real .CMD -> powershell -> node chain that RUN_046 found
        # orphaned. A process that ignores the graceful stop forces the job/tree
        # termination, which must kill the whole tree.
        world = FakeWorld(1000, [1001, 1002])  # wrapper + powershell + node
        proc = FakeProc(world, exits_on_graceful=False)
        containment = FakeContainment(world, PLATFORM_STRATEGY_WINDOWS_JOB)
        mp = _managed(proc, containment)
        mp.start()
        self.assertTrue(containment.assigned)  # contained from birth
        result = mp.terminate()
        self.assertTrue(result.force_termination_attempted)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(result.remaining_process_ids, [])
        self.assertTrue(result.cleanup_proven)
        self.assertEqual(result.platform_strategy, PLATFORM_STRATEGY_WINDOWS_JOB)
        self.assertEqual(set(result.observed_descendant_ids) & {1001, 1002}, {1001, 1002})
        self.assertFalse(world.is_alive(1000))
        self.assertFalse(world.is_alive(1001))
        self.assertFalse(world.is_alive(1002))

    def test_02_posix_process_group_cleanup_kills_descendants(self) -> None:
        world = FakeWorld(2000, [2001, 2002])
        proc = FakeProc(world, exits_on_graceful=False)
        containment = FakeContainment(world, PLATFORM_STRATEGY_POSIX_SESSION)
        mp = _managed(proc, containment)
        mp.start()
        result = mp.terminate()
        self.assertTrue(result.cleanup_proven)
        self.assertEqual(result.platform_strategy, PLATFORM_STRATEGY_POSIX_SESSION)
        self.assertFalse(any(world.is_alive(p) for p in (2000, 2001, 2002)))

    def test_15_ignored_cancellation_escalates_to_tree_termination(self) -> None:
        # Graceful stop (close stdin) is ignored -> ManagedProcess must escalate
        # to a force tree termination, not give up.
        world = FakeWorld(3000, [3001])
        proc = FakeProc(world, exits_on_graceful=False)
        containment = FakeContainment(world, PLATFORM_STRATEGY_WINDOWS_JOB)
        mp = _managed(proc, containment)
        mp.start()
        result = mp.terminate()
        self.assertTrue(result.graceful_termination_attempted)
        self.assertTrue(result.force_termination_attempted)
        self.assertTrue(result.cleanup_proven)

    def test_graceful_stop_needs_no_force(self) -> None:
        # A well-behaved process that exits on the graceful stop must not be
        # force-killed.
        world = FakeWorld(4000, [4001])
        proc = FakeProc(world, exits_on_graceful=True)
        containment = FakeContainment(world, PLATFORM_STRATEGY_POSIX_SESSION)
        mp = _managed(proc, containment)
        mp.start()
        result = mp.terminate()
        self.assertTrue(result.graceful_termination_attempted)
        self.assertFalse(result.force_termination_attempted)
        self.assertTrue(result.cleanup_proven)

    def test_03_cleanup_failure_trips_circuit_breaker(self) -> None:
        # A descendant that survives termination (breakaway) must be reported as
        # remaining, and must trip the transport circuit breaker.
        world = FakeWorld(5000, [5001], leak={5001})
        proc = FakeProc(world, exits_on_graceful=False)
        containment = FakeContainment(world, PLATFORM_STRATEGY_WINDOWS_JOB)
        mp = _managed(proc, containment)
        mp.start()
        result = mp.terminate()
        self.assertFalse(result.cleanup_complete)
        self.assertIn(5001, result.remaining_process_ids)
        self.assertFalse(result.cleanup_proven)
        self.assertEqual(result.termination_reason, TERMINATION_CLEANUP_FAILED)

        health = TransportHealth(backend_id="cursor_acp")
        if not result.cleanup_proven:
            health.record(OUTCOME_CLEANUP_FAILURE)
        self.assertEqual(health.state, HEALTH_UNHEALTHY)
        self.assertTrue(health.blocks_automatic_retry)
        self.assertTrue(health.requires_operator_recovery)


class TestManagedOneshot(unittest.TestCase):
    def test_oneshot_success_via_managed_process(self) -> None:
        world = FakeWorld(6000, [])
        proc = FakeProc(world, exits_on_graceful=True)
        containment = FakeContainment(world, PLATFORM_STRATEGY_POSIX_SESSION)
        # graceful close makes wait() return 0; the one-shot then finishes clean
        proc.graceful_closed = True
        result = run_managed_oneshot(
            ["echo", "hi"],
            cwd=".",
            env={},
            timeout_seconds=1.0,
            input_text="x",
            spawn=_spawn_of(proc),
            containment=containment,
        )
        self.assertFalse(result.timed_out)
        self.assertTrue(result.cleanup_proven)

    def test_oneshot_timeout_terminates_tree(self) -> None:
        world = FakeWorld(7000, [7001, 7002])
        proc = FakeProc(world, exits_on_graceful=False)  # never exits -> timeout
        containment = FakeContainment(world, PLATFORM_STRATEGY_WINDOWS_JOB)
        result = run_managed_oneshot(
            ["cursor-agent.CMD"],
            cwd=".",
            env={},
            timeout_seconds=0.1,
            spawn=_spawn_of(proc),
            containment=containment,
        )
        self.assertTrue(result.timed_out)
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(any(world.is_alive(p) for p in (7000, 7001, 7002)))


class TestOneshotAdapterUsesManagedCleanup(unittest.TestCase):
    """PART K.4 — the one-shot Cursor adapter routes production runs through the
    managed lifecycle so a timeout no longer orphans PowerShell/Node."""

    def setUp(self) -> None:
        from admissible.agent_backend import CursorCliConfig

        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.agent_ws = root / "agent"
        self.target_ws = root / "target"
        self.agent_ws.mkdir()
        self.target_ws.mkdir()
        # A real file named cursor-agent.cmd so the config is 'ready' (is_file()).
        fake_exe = root / "cursor-agent.cmd"
        fake_exe.write_text("", encoding="utf-8")
        self.config = CursorCliConfig.cursor_agent_preset(command=str(fake_exe))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _request(self):
        from admissible.agent_backend import AgentInvocationRequest

        return AgentInvocationRequest(
            instruction_text="Do it.",
            target_workspace_path=str(self.target_ws),
            agent_workspace_path=str(self.agent_ws),
            timeout_seconds=1.0,
        )

    def _managed_oneshot(self, *, timed_out, cleanup_complete, stdout=""):
        from admissible.managed_process import ManagedOneshotResult, ManagedProcessResult

        def fake(argv, *, cwd, env, timeout_seconds, input_text=None, max_capture_bytes=0):
            mpr = ManagedProcessResult(
                process_id=999,
                observed_descendant_ids=[1000, 1001],
                exit_code=None if timed_out else 0,
                termination_reason=("hard_timeout" if timed_out else "completed"),
                graceful_termination_attempted=timed_out,
                force_termination_attempted=timed_out,
                cleanup_complete=cleanup_complete,
                remaining_process_ids=[] if cleanup_complete else [1001],
                platform_strategy="windows_job_object",
            )
            return ManagedOneshotResult(
                returncode=None if timed_out else 0,
                stdout=stdout,
                stderr="",
                timed_out=timed_out,
                process_result=mpr,
            )

        return fake

    def test_timeout_uses_managed_cleanup_and_is_proven(self) -> None:
        from admissible.agent_backend import (
            AGENT_INVOKE_TIMEOUT,
            BACKEND_ID_CURSOR_ONESHOT,
            CursorCliAgentBackend,
        )

        backend = CursorCliAgentBackend(
            config=self.config,
            managed_oneshot=self._managed_oneshot(timed_out=True, cleanup_complete=True),
        )
        result = backend.invoke(self._request())
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertEqual(result.transport_kind, BACKEND_ID_CURSOR_ONESHOT)
        self.assertIsNotNone(result.managed_process_result)
        self.assertTrue(result.managed_process_result["cleanup_complete"])
        self.assertTrue(result.managed_process_result["force_termination_attempted"])
        self.assertIn("cleanup verified", result.error_message)

    def test_timeout_with_unproven_cleanup_is_surfaced(self) -> None:
        from admissible.agent_backend import AGENT_INVOKE_TIMEOUT, CursorCliAgentBackend

        backend = CursorCliAgentBackend(
            config=self.config,
            managed_oneshot=self._managed_oneshot(timed_out=True, cleanup_complete=False),
        )
        result = backend.invoke(self._request())
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertFalse(result.managed_process_result["cleanup_complete"])
        self.assertIn("CLEANUP UNPROVEN", result.error_message)

    def test_success_via_managed_path_carries_transport_kind(self) -> None:
        from admissible.agent_backend import (
            AGENT_INVOKE_SUCCESS,
            BACKEND_ID_CURSOR_ONESHOT,
            CursorCliAgentBackend,
        )

        backend = CursorCliAgentBackend(
            config=self.config,
            managed_oneshot=self._managed_oneshot(
                timed_out=False, cleanup_complete=True, stdout="the response"
            ),
        )
        result = backend.invoke(self._request())
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertEqual(result.response_text, "the response")
        self.assertEqual(result.transport_kind, BACKEND_ID_CURSOR_ONESHOT)
        self.assertIsNotNone(result.managed_process_result)


class TestPidAlive(unittest.TestCase):
    def test_current_process_is_alive(self) -> None:
        import os

        self.assertTrue(pid_alive(os.getpid()))

    def test_invalid_pids_are_not_alive(self) -> None:
        self.assertFalse(pid_alive(None))
        self.assertFalse(pid_alive(-1))
        self.assertFalse(pid_alive(0))


if __name__ == "__main__":
    unittest.main()
