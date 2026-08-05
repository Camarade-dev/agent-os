"""M2 final protocol and process-lifecycle repair: B32, B33, B34, B35, M36.

Each finding is closed by making an untrue statement impossible to produce.

M2-B32 -- release truth is terminal and monotonic
    A first ``SpawnedLauncher.release()`` could return RELEASE_OUTCOME_UNKNOWN /
    EXECUTION_OUTCOME_UNKNOWN and a second could return NOT_RELEASED /
    NO_INSTRUCTION_EXECUTED, because only a *released* outcome was retained and
    every other answer was rebuilt from ``_awaiting_release``.  That is a
    downgrade of uncertainty into a positive claim that the proposed command
    never ran.  The first terminal outcome is now the only outcome.

M2-B33 -- every external wait is bounded by this controller
    Release acknowledgements, kill, wait, poll, spawn, startup, and shutdown
    were blocking reads with no controller-owned deadline.  A helper that is
    alive but wedged or stopped therefore held the trusted controller open for
    ever, before the local cgroup kill and before any refusal evidence existed.
    Each round trip now carries an absolute monotonic deadline this process
    enforces, a deadline that expires mid-frame poisons the connection so the
    next call refuses instead of blocking again, and the abort path bypasses the
    helper for controller-owned kernel mechanisms.

M2-B34 -- ownership proved, not inferred from an empty cgroup
    The mount-namespace helper is the launcher's parent.  When it dies after the
    gate write, ``cgroup.kill`` still destroys the domain and an empty
    ``cgroup.procs`` still proves no live member -- but neither says who
    observed the exit or who reaped it.  The controller now makes itself a child
    subreaper before forking the helper, so the orphaned launcher is reparented
    to it and ``waitpid`` on that exact PID is a reap it performed and can name.
    A pidfd supplies exit observation only: ``waitid(P_PIDFD, ...)`` on a
    non-child fails with ECHILD, which is asserted here rather than assumed.

M2-B35 -- membership is a typed observation
    ``_members_of`` mapped an unreadable ``cgroup.procs`` to ``set()``, making
    "unreadable" and "observed empty" the same value for bootstrap, cache
    revalidation, probe cleanup, attach verification, kill-domain enumeration,
    quiescence, and removal.  Every one of those decisions is about emptiness.
    Reads are now typed and every security-relevant caller fails closed.

M2-M36 -- one coherent current validation artifact
    The current validation report simultaneously recorded a delegated
    qualification with 125 passing tests and an old terminal refusal saying the
    same work was not physically qualified.  History is preserved byte for byte
    under a versioned filename; the canonical filename is the single current
    report and no current field contradicts another.

Deterministic tests drive real socket pairs, real trusted helpers, real forked
launchers, constructed cgroup trees, and injected kernel failures.  Delegated
physical tests run the production path inside a real ``Delegate=yes`` cgroup v2
subtree and, under ``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than
skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
import errno
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.paired_runner import private_workspace as pw  # noqa: E402
from admissible.paired_runner import process_ownership as po  # noqa: E402
from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner.cgroup_launch import (  # noqa: E402
    RELEASE_NOT_RELEASED,
    RELEASE_OUTCOME_UNKNOWN,
    RELEASE_PHASE_ACCEPTED,
    RELEASE_PHASE_ACCEPT_DEADLINE_EXPIRED,
    RELEASE_PHASE_ACK_LOST,
    RELEASE_PHASE_COMPLETION_DEADLINE_EXPIRED,
    RELEASE_PHASE_NOT_GATED,
    RELEASE_PHASE_NOT_REQUESTED,
    RELEASE_PHASE_WRITE_COMPLETED,
    RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
    RELEASE_PHASES,
    RELEASE_RELEASED,
    GateReleaseOutcome,
    monotonic_release_truth,
    release_truth_is_downgrade,
)
from admissible.paired_runner.private_workspace import (  # noqa: E402
    HelperDeadlineExpired,
    HelperProtocolBroken,
    PrivateMountHelper,
    PrivateWorkspaceError,
    SpawnedLauncher,
    _recv_framed,
    _send_framed,
)
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    REAPER_MOUNT_NAMESPACE_HELPER,
    REAPER_NONE,
    REAPER_TRUSTED_CONTROLLER,
    Deadline,
    ProcessOwnershipEvidence,
)
from admissible.paired_runner.resource_limits import (  # noqa: E402
    CgroupDelegation,
    CgroupMembership,
    CgroupMembershipUnreadable,
    EffectCgroup,
    ResourceBounds,
    probe_cgroup_delegation,
    read_cgroup_members,
    revalidate_cgroup_topology,
)

DELEGATION = probe_cgroup_delegation()
REQUIRE_DELEGATED = os.environ.get("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP") == "1"

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
)
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import SharedEffectSubstrate, WorkspaceBinding  # noqa: E402
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = REPOSITORY_ROOT / "implementation"

#: A deadline small enough to keep the deterministic suite fast, large enough
#: that ordinary scheduling jitter cannot make a bounded call miss it.
FAST_DEADLINE_MS = 400
#: The upper bound a bounded call must respect.  Deliberately generous: the
#: property under test is finiteness, not latency.
BOUND_SLACK_SECONDS = 5.0


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


# --- shared fixtures ----------------------------------------------------------


LAUNCHER_SCRIPT = (
    "import os, sys, time\n"
    "open(sys.argv[1], 'w').write('the gated image executed')\n"
    "time.sleep(120)\n"
)

QUICK_LAUNCHER_SCRIPT = "import sys\nopen(sys.argv[1], 'w').write('done')\n"


class _SilentPeer(threading.Thread):
    """A helper stand-in that receives a request and then says too little.

    ``script`` chooses how much of the two-phase release protocol it performs.
    In every case the peer stays *alive* with the socket open, which is the
    condition the old blocking reads could not survive.
    """

    def __init__(self, sock: socket.socket, script: str) -> None:
        super().__init__(daemon=True)
        self.sock = sock
        self.script = script
        self.requests: list[dict] = []
        self.stop_event = threading.Event()

    def run(self) -> None:
        try:
            while not self.stop_event.is_set():
                request, _fds = _recv_framed(self.sock)
                self.requests.append(request)
                if self.script == "accept_then_silence":
                    _send_framed(self.sock, {"phase": RELEASE_PHASE_ACCEPTED, "ok": True})
                # Every other script answers nothing at all, for ever.
                self.stop_event.wait(30)
        except Exception:
            return

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.sock.close()
        except OSError:
            pass


def _peer_helper(test: unittest.TestCase, script: str) -> PrivateMountHelper:
    """A helper object wired to a live, silent protocol peer."""

    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    peer = _SilentPeer(child, script)
    peer.start()
    helper = PrivateMountHelper(pid=-1, conn=parent, view_fd=-1, staging_path="/nowhere")
    test.addCleanup(peer.stop)
    test.addCleanup(peer.join, 5)
    test.addCleanup(parent.close)
    return helper


class _LiveLauncher:
    """A real trusted helper holding one real gated launcher child.

    This is the production ``PrivateMountHelper`` and the production
    ``SpawnedLauncher``: the helper unshares a user+mount namespace, forks the
    launcher, and holds the trusted pipe gate.  Nothing about the ownership
    topology under test is simulated.
    """

    def __init__(self, *, gated: bool = True, script: str = LAUNCHER_SCRIPT) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="admissible-m2-lifecycle-"))
        self.sentinel = self.directory / "sentinel.txt"
        self.helper = PrivateMountHelper.start()
        try:
            self.launcher = self.helper.spawn(
                [PYTHON, "-c", script, str(self.sentinel)], await_release=gated
            )
        except BaseException:
            self.helper.close()
            raise

    @property
    def executed(self) -> bool:
        return self.sentinel.exists()

    def close(self) -> None:
        try:
            self.launcher.terminate_and_reap(
                deadline=Deadline.after_ms(po.ABORT_TOTAL_DEADLINE_MS, "fixture_close")
            )
        except Exception:
            pass
        for descriptor in (self.launcher.stdout_fd, self.launcher.stderr_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.helper.close()
        import shutil

        shutil.rmtree(self.directory, ignore_errors=True)


def _live(test: unittest.TestCase, **kwargs) -> _LiveLauncher:
    fixture = _LiveLauncher(**kwargs)
    test.addCleanup(fixture.close)
    return fixture


class _FakeCgroupParent:
    """A constructed directory tree shaped like a delegated effect parent.

    It is never kernel evidence: the production magic check refuses it, which
    the B25 modules already assert.  Here it exists so a membership read can be
    made to fail on demand at each caller.
    """

    def __init__(self, *, with_manager_leaf: bool = True) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-m2-b35-"))
        self.parent = self.root / "svc"
        self.parent.mkdir()
        (self.parent / "cgroup.controllers").write_text("memory pids", encoding="utf-8")
        (self.parent / "cgroup.subtree_control").write_text("memory pids", encoding="utf-8")
        (self.parent / "cgroup.procs").write_text("", encoding="utf-8")
        self.manager = self.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        if with_manager_leaf:
            # A tree whose bootstrap already happened.  The bootstrap tests use
            # a tree without one, because creating it is the step under test.
            self.manager.mkdir()
            (self.manager / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="utf-8")

    def delegation(self) -> CgroupDelegation:
        return CgroupDelegation(
            available=True,
            detail="constructed",
            unified_root=str(self.root),
            delegated_path=str(self.parent),
            controllers=("memory", "pids"),
            code=rl.TOPOLOGY_INITIALIZED,
            manager_leaf=str(self.manager),
            enabled_controllers=("memory", "pids"),
        )

    def topology(self, **overrides) -> rl.CgroupTopology:
        fields = {
            "initialized": True,
            "code": rl.TOPOLOGY_INITIALIZED,
            "detail": "constructed",
            "unified_root": str(self.root),
            "unified_cgroup": "/svc",
            "effect_parent": str(self.parent),
            "manager_leaf": str(self.manager),
            "available_controllers": ("memory", "pids"),
            "enabled_controllers": ("memory", "pids"),
            "owner_pid": os.getpid(),
            "effect_parent_identity": rl._directory_identity(self.parent),
            "manager_leaf_identity": rl._directory_identity(self.manager),
            "owner_unified_path": f"/svc/{self.manager.name}",
            "cgroup2_required": False,
        }
        fields.update(overrides)
        return rl.CgroupTopology(**fields)

    def effect(self, label: str = "b35") -> EffectCgroup:
        cgroup = EffectCgroup(self.delegation(), ResourceBounds.for_timeout(1000), label)
        assert cgroup.create(), cgroup.create_error
        (Path(cgroup.path) / "cgroup.procs").write_text("", encoding="utf-8")
        return cgroup

    def close(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)


def _unreadable(path: Path) -> None:
    """Make one ``cgroup.procs`` produce EACCES for this process."""

    os.chmod(path / "cgroup.procs", 0o000)


def _malformed(path: Path) -> None:
    (path / "cgroup.procs").write_text("not-a-pid\n17\n", encoding="utf-8")


# --- M2-B32: terminal, monotonic release truth --------------------------------


class ReleaseTruthMonotonicityTests(unittest.TestCase):
    """A release attempt answers the question once, and that answer stands."""

    def test_the_combinator_keeps_the_first_terminal_answer(self) -> None:
        unknown = GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "lost")
        stronger = GateReleaseOutcome(RELEASE_NOT_RELEASED, RELEASE_PHASE_NOT_GATED, "later")
        self.assertIs(monotonic_release_truth(unknown, stronger), unknown)
        self.assertIs(monotonic_release_truth(None, stronger), stronger)

    def test_any_state_change_after_a_terminal_answer_is_a_downgrade(self) -> None:
        unknown = GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "")
        not_released = GateReleaseOutcome(RELEASE_NOT_RELEASED, RELEASE_PHASE_NOT_GATED, "")
        released = GateReleaseOutcome(RELEASE_RELEASED, RELEASE_PHASE_WRITE_COMPLETED, "")
        self.assertTrue(release_truth_is_downgrade(unknown, not_released))
        self.assertTrue(release_truth_is_downgrade(released, not_released))
        self.assertTrue(release_truth_is_downgrade(not_released, unknown))
        self.assertFalse(release_truth_is_downgrade(unknown, unknown))
        self.assertFalse(release_truth_is_downgrade(None, not_released))

    def _launcher(
        self, helper: PrivateMountHelper, *, gated: bool, pid: int = 4242
    ) -> SpawnedLauncher:
        return SpawnedLauncher(
            pid=pid, stdout_fd=-1, stderr_fd=-1, _helper=helper, _awaiting_release=gated
        )

    def test_a_repeated_not_released_stays_not_released(self) -> None:
        launcher = self._launcher(_peer_helper(self, "silent"), gated=False)
        first = launcher.release()
        self.assertEqual(first.state, RELEASE_NOT_RELEASED)
        self.assertEqual(first.phase, RELEASE_PHASE_NOT_GATED)
        for _ in range(3):
            repeated = launcher.release()
            self.assertIs(repeated, first)
            self.assertEqual(repeated.state, RELEASE_NOT_RELEASED)

    def test_a_repeated_released_stays_released(self) -> None:
        helper = _scripted_helper(self, "released")
        launcher = self._launcher(helper, gated=True)
        first = launcher.release()
        self.assertEqual(first.state, RELEASE_RELEASED)
        for _ in range(3):
            self.assertIs(launcher.release(), first)

    def test_a_repeated_unknown_stays_unknown(self) -> None:
        helper = _scripted_helper(self, "die_after_accept")
        launcher = self._launcher(helper, gated=True)
        first = launcher.release()
        self.assertEqual(first.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(first.phase, RELEASE_PHASE_ACK_LOST)
        for _ in range(3):
            repeated = launcher.release()
            self.assertIs(repeated, first)
            self.assertEqual(repeated.state, RELEASE_OUTCOME_UNKNOWN)

    def test_no_second_call_claims_that_no_instruction_executed(self) -> None:
        """The exact defect: unknown first, NO_INSTRUCTION_EXECUTED second."""

        helper = _scripted_helper(self, "die_after_accept")
        launcher = self._launcher(helper, gated=True)
        first = launcher.release()
        self.assertEqual(first.sentinel_claim, "EXECUTION_OUTCOME_UNKNOWN")
        second = launcher.release()
        self.assertNotEqual(second.sentinel_claim, "NO_INSTRUCTION_EXECUTED")
        self.assertEqual(second.sentinel_claim, "EXECUTION_OUTCOME_UNKNOWN")

    def test_the_unknown_survives_the_helper_socket_closing(self) -> None:
        helper = _scripted_helper(self, "die_after_accept")
        launcher = self._launcher(helper, gated=True)
        first = launcher.release()
        self.assertEqual(first.state, RELEASE_OUTCOME_UNKNOWN)
        helper.conn.close()
        self.assertEqual(launcher.release().state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(launcher.observed_release_outcome().state, RELEASE_OUTCOME_UNKNOWN)

    def test_the_unknown_survives_abort_cleanup(self) -> None:
        helper = _scripted_helper(self, "die_after_accept")
        launcher = self._launcher(helper, gated=True, pid=_owned_victim(self))
        unknown = launcher.release()
        self.assertEqual(unknown.state, RELEASE_OUTCOME_UNKNOWN)
        evidence = ps.abort_gated_effect(
            process=launcher,
            cgroup=None,
            descriptors=(),
            release_outcome=unknown,
            reason="unknown-release",
            deadline=Deadline.after_ms(FAST_DEADLINE_MS, "abort"),
        )
        self.assertEqual(evidence["release"]["release_state"], RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(evidence["release"]["sentinel_claim"], "EXECUTION_OUTCOME_UNKNOWN")
        self.assertEqual(launcher.release().state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(launcher.observed_release_outcome().state, RELEASE_OUTCOME_UNKNOWN)

    def test_the_evidence_layer_never_replaces_a_recorded_unknown(self) -> None:
        helper = _scripted_helper(self, "die_after_accept")
        launcher = self._launcher(helper, gated=True, pid=_owned_victim(self))
        launcher.release()
        # A caller that hands in a *stronger* outcome cannot overwrite what the
        # launcher already established.
        evidence = ps.abort_gated_effect(
            process=launcher,
            cgroup=None,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_NOT_ATTEMPTED, "a later, weaker story"
            ),
            reason="downgrade-attempt",
            deadline=Deadline.after_ms(FAST_DEADLINE_MS, "abort"),
        )
        self.assertEqual(evidence["release"]["release_state"], RELEASE_OUTCOME_UNKNOWN)

    def test_serialization_preserves_the_unknown(self) -> None:
        outcome = GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "lost")
        round_tripped = json.loads(json.dumps(outcome.to_dict()))
        self.assertEqual(round_tripped["release_state"], RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(round_tripped["sentinel_claim"], "EXECUTION_OUTCOME_UNKNOWN")

    def test_the_public_accessor_is_never_stronger_than_the_truth(self) -> None:
        helper = _peer_helper(self, "silent")
        gated = self._launcher(helper, gated=True)
        interim = gated.observed_release_outcome()
        self.assertEqual(interim.phase, RELEASE_PHASE_NOT_REQUESTED)
        self.assertIsNone(gated.release_outcome, "an accessor never records a terminal outcome")
        ungated = self._launcher(helper, gated=False)
        self.assertEqual(ungated.observed_release_outcome().phase, RELEASE_PHASE_NOT_GATED)

    def test_every_phase_this_module_produces_is_declared(self) -> None:
        for phase in (
            RELEASE_PHASE_NOT_REQUESTED,
            RELEASE_PHASE_ACCEPT_DEADLINE_EXPIRED,
            RELEASE_PHASE_COMPLETION_DEADLINE_EXPIRED,
        ):
            self.assertIn(phase, RELEASE_PHASES)


class _ScriptedPeer(threading.Thread):
    """A helper stand-in that completes a scripted release exchange."""

    def __init__(self, sock: socket.socket, script: str) -> None:
        super().__init__(daemon=True)
        self.sock = sock
        self.script = script

    def run(self) -> None:
        try:
            _recv_framed(self.sock)
        except Exception:
            return
        if self.script == "released":
            _send_framed(self.sock, {"phase": RELEASE_PHASE_ACCEPTED, "ok": True})
            _send_framed(
                self.sock, {"phase": RELEASE_PHASE_WRITE_COMPLETED, "ok": True, "released": True}
            )
        elif self.script == "die_after_accept":
            _send_framed(self.sock, {"phase": RELEASE_PHASE_ACCEPTED, "ok": True})
        try:
            self.sock.close()
        except OSError:
            pass


def _scripted_helper(test: unittest.TestCase, script: str) -> PrivateMountHelper:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    peer = _ScriptedPeer(child, script)
    peer.start()
    helper = PrivateMountHelper(pid=-1, conn=parent, view_fd=-1, staging_path="/nowhere")
    test.addCleanup(child.close)
    test.addCleanup(parent.close)
    test.addCleanup(peer.join, 5)
    return helper


# --- M2-B33: controller-owned deadlines ---------------------------------------


class DeadlinePrimitiveTests(unittest.TestCase):
    """The bound is an absolute monotonic instant this process owns."""

    def test_a_deadline_is_absolute_not_renewed_per_step(self) -> None:
        deadline = Deadline.after_ms(120, "test")
        first = deadline.remaining_seconds
        time.sleep(0.05)
        self.assertLess(deadline.remaining_seconds, first)
        time.sleep(0.1)
        self.assertTrue(deadline.expired)
        self.assertEqual(deadline.remaining_seconds, 0.0)

    def test_a_nested_deadline_can_never_outlive_its_whole(self) -> None:
        whole = Deadline.after_ms(100, "whole")
        nested = whole.sub(10_000, "nested")
        self.assertLessEqual(nested.expires_at_ns, whole.expires_at_ns)
        self.assertLessEqual(nested.remaining_seconds, 0.11)

    def test_an_already_expired_deadline_is_expired(self) -> None:
        self.assertTrue(Deadline.already_expired("now").expired)

    def test_every_configured_deadline_is_finite(self) -> None:
        for name in (
            "HELPER_RELEASE_ACCEPT_DEADLINE_MS",
            "HELPER_RELEASE_COMPLETION_DEADLINE_MS",
            "HELPER_CONTROL_RPC_DEADLINE_MS",
            "HELPER_SHUTDOWN_DEADLINE_MS",
            "HELPER_STARTUP_DEADLINE_MS",
            "LAUNCHER_EXIT_OBSERVATION_DEADLINE_MS",
            "LAUNCHER_REAP_DEADLINE_MS",
            "HELPER_REAP_DEADLINE_MS",
            "ABORT_TOTAL_DEADLINE_MS",
        ):
            value = getattr(po, name)
            self.assertIsInstance(value, int, name)
            self.assertGreater(value, 0, name)
            self.assertLess(value, 120_000, name)

    def test_no_production_module_arms_a_process_wide_alarm(self) -> None:
        """A global SIGALRM would corrupt operations this bound never touches."""

        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        for path in sorted(package.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for forbidden in ("signal.alarm(", "setitimer(", "SIGALRM"):
                self.assertNotIn(forbidden, text, f"{path.name} arms a process-wide timer")


class ControllerDeadlineTests(unittest.TestCase):
    """A helper that is alive and silent can never hold the controller open."""

    def setUp(self) -> None:
        self._threads_before = threading.active_count()
        for name in (
            "HELPER_RELEASE_ACCEPT_DEADLINE_MS",
            "HELPER_RELEASE_COMPLETION_DEADLINE_MS",
            "HELPER_CONTROL_RPC_DEADLINE_MS",
            "HELPER_SHUTDOWN_DEADLINE_MS",
        ):
            patcher = mock.patch.object(pw, name, FAST_DEADLINE_MS)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _bounded(self, call):
        started = time.monotonic()
        result = call()
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            FAST_DEADLINE_MS / 1000.0 + BOUND_SLACK_SECONDS,
            "the call outlived the controller-owned deadline",
        )
        return result, elapsed

    def test_a_live_helper_that_never_accepts_reports_unknown(self) -> None:
        helper = _peer_helper(self, "silent")
        outcome, _ = self._bounded(lambda: helper.release(11))
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACCEPT_DEADLINE_EXPIRED)

    def test_a_live_helper_that_accepts_then_stops_reports_unknown(self) -> None:
        helper = _peer_helper(self, "accept_then_silence")
        outcome, _ = self._bounded(lambda: helper.release(11))
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_COMPLETION_DEADLINE_EXPIRED)

    def test_a_timeout_before_acceptance_never_claims_non_execution(self) -> None:
        helper = _peer_helper(self, "silent")
        outcome, _ = self._bounded(lambda: helper.release(11))
        self.assertNotEqual(outcome.sentinel_claim, "NO_INSTRUCTION_EXECUTED")

    def test_a_kill_rpc_that_never_replies_is_bounded(self) -> None:
        helper = _peer_helper(self, "silent")
        with self.assertRaises(HelperDeadlineExpired):
            self._bounded(lambda: helper.kill(11))

    def test_a_wait_rpc_that_never_replies_is_bounded(self) -> None:
        helper = _peer_helper(self, "silent")
        with self.assertRaises(HelperDeadlineExpired):
            self._bounded(lambda: helper.wait(11, timeout=0.05))

    def test_a_poll_rpc_that_never_replies_is_bounded(self) -> None:
        helper = _peer_helper(self, "silent")
        with self.assertRaises(HelperDeadlineExpired):
            self._bounded(lambda: helper.poll(11))

    def test_a_shutdown_that_never_replies_is_bounded(self) -> None:
        helper = _peer_helper(self, "silent")
        _state, _elapsed = self._bounded(helper.close)

    def test_an_expired_deadline_poisons_the_connection_once(self) -> None:
        """A wedged helper costs one deadline in total, not one per call."""

        helper = _peer_helper(self, "silent")
        with self.assertRaises(HelperDeadlineExpired):
            helper.poll(11)
        self.assertFalse(helper.protocol_usable)
        started = time.monotonic()
        for _ in range(5):
            with self.assertRaises(HelperProtocolBroken):
                helper.poll(11)
        self.assertLess(time.monotonic() - started, 1.0, "a broken protocol blocked again")

    def test_a_release_after_a_broken_protocol_proves_non_release(self) -> None:
        """No release request reached the helper, so the gate cannot have opened."""

        helper = _peer_helper(self, "silent")
        with self.assertRaises(HelperDeadlineExpired):
            helper.poll(11)
        outcome = helper.release(11)
        self.assertEqual(outcome.state, RELEASE_NOT_RELEASED)
        self.assertEqual(outcome.phase, RELEASE_PHASE_WRITE_NOT_ATTEMPTED)

    def test_no_unbounded_thread_is_left_behind(self) -> None:
        helper = _peer_helper(self, "silent")
        with self.assertRaises(HelperDeadlineExpired):
            helper.poll(11)
        # Only the test's own peer thread may exist beyond the baseline.
        self.assertLessEqual(threading.active_count(), self._threads_before + 1)

    def test_a_deadline_expiry_appears_in_the_durable_evidence(self) -> None:
        helper = _peer_helper(self, "silent")
        launcher = SpawnedLauncher(
            pid=_owned_victim(self), stdout_fd=-1, stderr_fd=-1, _helper=helper,
            _awaiting_release=True,
        )
        evidence = ps.abort_gated_effect(
            process=launcher,
            cgroup=None,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "lost"
            ),
            reason="wedged-helper",
            deadline=Deadline.after_ms(FAST_DEADLINE_MS, "abort"),
        )
        self.assertTrue(evidence["deadline_expirations"], evidence["process_ownership"])
        self.assertTrue(evidence["process_ownership"]["helper_bypassed"])


class StoppedHelperTests(unittest.TestCase):
    """A helper stopped by SIGSTOP is alive, is silent, and is bypassed."""

    def setUp(self) -> None:
        for name in ("HELPER_CONTROL_RPC_DEADLINE_MS", "HELPER_RELEASE_ACCEPT_DEADLINE_MS"):
            patcher = mock.patch.object(pw, name, FAST_DEADLINE_MS)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_helper_stopped_before_release_cannot_wedge_the_controller(self) -> None:
        fixture = _live(self)
        os.kill(fixture.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, fixture.helper.pid)
        started = time.monotonic()
        outcome = fixture.launcher.release()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, FAST_DEADLINE_MS / 1000.0 + BOUND_SLACK_SECONDS)
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACCEPT_DEADLINE_EXPIRED)
        self.assertFalse(fixture.executed, "a stopped helper never opened the gate")

    def test_a_helper_stopped_after_acceptance_cannot_wedge_the_cleanup(self) -> None:
        fixture = _live(self)
        os.kill(fixture.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, fixture.helper.pid)
        started = time.monotonic()
        evidence = ps.abort_gated_effect(
            process=fixture.launcher,
            cgroup=None,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "stopped after accept"
            ),
            reason="stopped-helper",
            deadline=Deadline.after_ms(po.ABORT_TOTAL_DEADLINE_MS, "abort"),
        )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, po.ABORT_TOTAL_DEADLINE_MS / 1000.0 + BOUND_SLACK_SECONDS)
        self.assertTrue(evidence["launcher_reaped"], evidence["process_ownership"])
        self.assertEqual(evidence["launcher_reaper_role"], REAPER_TRUSTED_CONTROLLER)
        self.assertEqual(evidence["launcher_reaper_pid"], os.getpid())
        self.assertTrue(evidence["helper_reaped"], evidence["process_ownership"])
        self.assertFalse(evidence["process_ownership"]["launcher_zombie_remains"])


def _owned_victim(test: unittest.TestCase) -> int:
    """A real child of this test process, safe to signal and reap.

    A stand-in launcher whose PID is invented would make the abort path signal
    an unrelated process -- or this one.  Every test that drives termination
    therefore owns its target.
    """

    pid = os.fork()
    if pid == 0:  # pragma: no cover - child process
        try:
            time.sleep(120)
        finally:
            os._exit(0)

    def cleanup() -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except (ChildProcessError, OSError):
            pass

    test.addCleanup(cleanup)
    return pid


def _resume(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGCONT)
    except OSError:
        pass


# --- M2-B34: proved process ownership and reap --------------------------------


class KernelOwnershipSemanticsTests(unittest.TestCase):
    """The Linux semantics this design rests on, verified rather than assumed."""

    def test_a_pidfd_alone_does_not_permit_a_non_parent_to_reap(self) -> None:
        read_fd, write_fd = os.pipe()
        middle = os.fork()
        if middle == 0:  # pragma: no cover - child process
            try:
                os.close(read_fd)
                grandchild = os.fork()
                if grandchild == 0:
                    os.close(write_fd)
                    time.sleep(5)
                    os._exit(0)
                os.write(write_fd, str(grandchild).encode())
                os.close(write_fd)
            finally:
                os._exit(0)
        os.close(write_fd)
        grandchild = int(os.read(read_fd, 32))
        os.close(read_fd)
        descriptor, detail = po.open_process_descriptor(grandchild)
        self.assertIsNotNone(descriptor, detail)
        try:
            with self.assertRaises(ChildProcessError):
                os.waitid(os.P_PIDFD, descriptor, os.WEXITED | os.WNOHANG)
        finally:
            os.close(descriptor)
            os.kill(grandchild, signal.SIGKILL)
            os.waitpid(middle, 0)
            # The grandchild is reparented to this subreaper-less test context
            # only if some ancestor claims it; reap it if it is ours.
            try:
                os.waitpid(grandchild, 0)
            except ChildProcessError:
                pass

    def test_the_subreaper_flag_is_acquired_reference_counted_and_restored(self) -> None:
        before, error = po.get_child_subreaper()
        self.assertIsNone(error)
        ownership = po.ChildSubreaperOwnership()
        first = ownership.acquire()
        self.assertEqual(first["code"], po.SUBREAPER_APPLIED)
        self.assertEqual(po.get_child_subreaper()[0], 1)
        second = ownership.acquire()
        self.assertEqual(second["depth"], 2)
        ownership.release()
        self.assertEqual(po.get_child_subreaper()[0], 1, "an outer acquisition still holds it")
        final = ownership.release()
        self.assertEqual(final["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(po.get_child_subreaper()[0], before)

    def test_a_fork_inherited_acquisition_is_discarded_not_trusted(self) -> None:
        ownership = po.ChildSubreaperOwnership()
        ownership.acquire()
        self.addCleanup(ownership.release)
        ownership._owner_pid = os.getpid() + 1_000_000
        state = ownership.state()
        self.assertTrue(state["applied"])
        self.assertFalse(ownership.active, "an inherited acquisition is never reported active")

    def test_no_ownership_primitive_will_address_every_process(self) -> None:
        for pid in (0, -1, -12345):
            with self.subTest(pid=pid):
                self.assertFalse(po.is_addressable_pid(pid))
                self.assertEqual(po.signal_process(pid, signal.SIGKILL)["error"], "NOT_AN_ADDRESSABLE_PID")
                outcome = po.reap_owned_child(pid, Deadline.already_expired("guard"))
                self.assertFalse(outcome.reaped)
                self.assertEqual(outcome.code, po.REAP_NOT_OWNED)
                self.assertEqual(outcome.reaper_role, REAPER_NONE)


class HelperLossOwnershipTests(unittest.TestCase):
    """Helper loss at each point in the launch sequence, with a proved reap."""

    def _abort(self, fixture, *, release_outcome=None) -> dict:
        return ps.abort_gated_effect(
            process=fixture.launcher,
            cgroup=None,
            descriptors=(),
            release_outcome=release_outcome
            or GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "helper lost"),
            reason="helper-loss",
            deadline=Deadline.after_ms(po.ABORT_TOTAL_DEADLINE_MS, "abort"),
        )

    def test_the_helper_dying_before_launcher_creation_is_bounded(self) -> None:
        helper = PrivateMountHelper.start()
        self.addCleanup(helper.close)
        os.kill(helper.pid, signal.SIGKILL)
        started = time.monotonic()
        with self.assertRaises(PrivateWorkspaceError):
            helper.spawn([PYTHON, "-c", "pass"], await_release=True)
        self.assertLess(time.monotonic() - started, po.HELPER_CONTROL_RPC_DEADLINE_MS / 1000.0 + BOUND_SLACK_SECONDS)

    def test_the_helper_dying_before_release_leaves_a_proved_reap(self) -> None:
        fixture = _live(self)
        os.kill(fixture.helper.pid, signal.SIGKILL)
        evidence = self._abort(fixture)
        self.assertTrue(evidence["launcher_exit_observed"])
        self.assertTrue(evidence["launcher_reaped"], evidence["process_ownership"])
        self.assertEqual(evidence["launcher_reaper_role"], REAPER_TRUSTED_CONTROLLER)
        self.assertEqual(evidence["launcher_reaper_pid"], os.getpid())
        self.assertFalse(fixture.executed, "the gate never opened, so no command ran")

    def test_the_helper_dying_after_the_gate_write_leaves_a_proved_reap(self) -> None:
        """The B34 scenario: the gate opened, the helper is gone, who reaped?"""

        fixture = _live(self)
        fixture.helper.release_fault = "die_after_write"
        outcome = fixture.launcher.release()
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        _await(lambda: fixture.executed, 10.0)
        self.assertTrue(fixture.executed, "the gate write did reach the launcher")
        evidence = self._abort(fixture, release_outcome=outcome)
        ownership = evidence["process_ownership"]
        self.assertTrue(evidence["launcher_exit_observed"], ownership)
        self.assertTrue(evidence["launcher_reaped"], ownership)
        self.assertEqual(evidence["launcher_reaper_role"], REAPER_TRUSTED_CONTROLLER)
        self.assertEqual(evidence["launcher_reaper_pid"], os.getpid())
        self.assertTrue(evidence["helper_exit_observed"], ownership)
        self.assertTrue(evidence["helper_reaped"], ownership)
        self.assertEqual(ownership["helper_exit_code"], 71, "the helper's own exit is recorded")
        self.assertFalse(ownership["launcher_zombie_remains"])
        self.assertEqual(evidence["release"]["release_state"], RELEASE_OUTCOME_UNKNOWN)

    def test_a_launcher_that_exited_before_the_helper_loss_is_still_reaped(self) -> None:
        fixture = _live(self, script=QUICK_LAUNCHER_SCRIPT)
        fixture.launcher.release()
        _await(lambda: fixture.executed, 10.0)
        os.kill(fixture.helper.pid, signal.SIGKILL)
        evidence = self._abort(fixture)
        self.assertTrue(evidence["launcher_reaped"], evidence["process_ownership"])
        self.assertFalse(evidence["process_ownership"]["launcher_zombie_remains"])

    def test_a_launcher_alive_after_the_helper_loss_is_killed_and_reaped(self) -> None:
        fixture = _live(self)
        fixture.launcher.release()
        _await(lambda: fixture.executed, 10.0)
        os.kill(fixture.helper.pid, signal.SIGKILL)
        self.assertTrue(po.process_present(fixture.launcher.pid))
        evidence = self._abort(fixture)
        self.assertTrue(evidence["launcher_exit_observed"])
        self.assertTrue(evidence["launcher_reaped"], evidence["process_ownership"])
        self.assertFalse(po.process_is_zombie(fixture.launcher.pid))

    def test_a_concurrent_unrelated_child_is_never_reaped(self) -> None:
        unrelated = subprocess.Popen([PYTHON, "-c", "import time; time.sleep(20)"])
        self.addCleanup(unrelated.wait)
        self.addCleanup(unrelated.kill)
        fixture = _live(self)
        os.kill(fixture.helper.pid, signal.SIGKILL)
        self._abort(fixture)
        self.assertIsNone(unrelated.poll(), "an unrelated child was consumed by the reaper")
        self.assertTrue(po.process_present(unrelated.pid))

    def test_repeated_cleanup_never_reports_a_second_reap(self) -> None:
        fixture = _live(self)
        os.kill(fixture.helper.pid, signal.SIGKILL)
        first = self._abort(fixture)
        self.assertTrue(first["launcher_reaped"])
        second = self._abort(fixture)
        self.assertTrue(second["launcher_reaped"], "the first reap is still the truth")
        self.assertEqual(second["process_ownership"]["launcher_reap_code"], po.REAP_ALREADY_REAPED)
        self.assertIn("reaped nothing", second["process_ownership"]["launcher_reap_detail"])

    def test_helper_and_launcher_lifecycle_states_stay_distinct(self) -> None:
        fixture = _live(self)
        fixture.helper.release_fault = "die_after_write"
        fixture.launcher.release()
        _await(lambda: fixture.executed, 10.0)
        evidence = self._abort(fixture)
        ownership = evidence["process_ownership"]
        self.assertNotEqual(ownership["launcher_pid"], ownership["helper_pid"])
        self.assertEqual(ownership["helper_exit_code"], 71)
        self.assertNotEqual(ownership["launcher_exit_code"], ownership["helper_exit_code"])
        for field in (
            "process_domain_kill_requested",
            "launcher_exit_observed",
            "launcher_reaped",
            "launcher_reaper_pid",
            "helper_exit_observed",
            "helper_reaped",
            "cgroup_quiescent",
            "effect_cgroup_removed",
        ):
            self.assertIn(field, ownership, field)

    def test_the_ownership_architecture_is_declared(self) -> None:
        description = po.ownership_architecture_description()
        self.assertEqual(description["chosen"], "CONTROLLER_CHILD_SUBREAPER_PLUS_PIDFD_OBSERVATION")
        self.assertIn("waitpid(-1)", description["never"])
        self.assertIn("ECHILD", description["verified_kernel_semantics"])
        self.assertTrue(description["residual"])


def _await(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# --- M2-B35: typed cgroup membership reads ------------------------------------


class TypedMembershipReadTests(unittest.TestCase):
    """An unreadable membership is never an observation of emptiness."""

    def setUp(self) -> None:
        self.fake = _FakeCgroupParent()
        self.addCleanup(self.fake.close)

    def test_a_readable_empty_cgroup_is_observed_empty(self) -> None:
        membership = read_cgroup_members(self.fake.parent)
        self.assertTrue(membership.read_ok)
        self.assertTrue(membership.usable)
        self.assertTrue(membership.observed_empty)
        self.assertEqual(membership.pids, ())

    def test_an_unreadable_cgroup_is_not_empty_and_says_why(self) -> None:
        _unreadable(self.fake.parent)
        self.addCleanup(os.chmod, self.fake.parent / "cgroup.procs", 0o644)
        membership = read_cgroup_members(self.fake.parent)
        self.assertFalse(membership.read_ok)
        self.assertFalse(membership.usable)
        self.assertFalse(membership.observed_empty)
        self.assertEqual(membership.error_code, "EACCES")
        self.assertIn("unreadable", membership.refusal_detail())
        self.assertEqual(membership.path, str(self.fake.parent))

    def test_a_malformed_cgroup_is_refused_not_parsed_around(self) -> None:
        _malformed(self.fake.parent)
        membership = read_cgroup_members(self.fake.parent)
        self.assertTrue(membership.read_ok)
        self.assertTrue(membership.malformed)
        self.assertFalse(membership.usable)
        self.assertIn("not-a-pid", membership.malformed_detail)

    def test_a_member_this_namespace_cannot_name_still_populates_the_cgroup(self) -> None:
        (self.fake.parent / "cgroup.procs").write_text("0\n0\n", encoding="utf-8")
        membership = read_cgroup_members(self.fake.parent)
        self.assertTrue(membership.usable)
        self.assertEqual(membership.opaque_member_count, 2)
        self.assertFalse(membership.observed_empty)
        self.assertTrue(membership.observed_populated)
        self.assertFalse(membership.fully_addressable)

    def test_the_typed_result_serializes_every_field(self) -> None:
        payload = read_cgroup_members(self.fake.parent).to_dict()
        for field in (
            "path",
            "read_ok",
            "pids",
            "error_code",
            "malformed",
            "malformed_detail",
            "opaque_member_count",
            "usable",
            "observed_empty",
        ):
            self.assertIn(field, payload, field)

    def test_no_caller_can_receive_a_bare_empty_set_on_a_failed_read(self) -> None:
        cgroup = self.fake.effect("bare")
        self.addCleanup(cgroup.close)
        _unreadable(Path(cgroup.path))
        self.addCleanup(os.chmod, Path(cgroup.path) / "cgroup.procs", 0o644)
        with self.assertRaises(CgroupMembershipUnreadable):
            cgroup.members()


class MembershipFailClosedCallerTests(unittest.TestCase):
    """Every security-relevant caller refuses on an unreadable membership."""

    def setUp(self) -> None:
        self.fake = _FakeCgroupParent()
        self.addCleanup(self.fake.close)

    def _restore(self, path: Path) -> None:
        self.addCleanup(os.chmod, path / "cgroup.procs", 0o644)

    def test_cache_revalidation_refuses_an_eacces_parent(self) -> None:
        """The exact reproduction: parent/cgroup.procs -> EACCES must refuse."""

        topology = self.fake.topology()
        self.assertIsNone(revalidate_cgroup_topology(topology))
        _unreadable(self.fake.parent)
        self._restore(self.fake.parent)
        detail = revalidate_cgroup_topology(topology)
        self.assertIsNotNone(detail, "an unreadable parent passed revalidation")
        self.assertIn("EACCES", detail)
        self.assertIn("cgroup.procs", detail)

    def test_cache_revalidation_refuses_an_unreadable_manager_leaf(self) -> None:
        topology = self.fake.topology()
        _unreadable(self.fake.manager)
        self._restore(self.fake.manager)
        detail = revalidate_cgroup_topology(topology)
        self.assertIsNotNone(detail)
        self.assertIn("EACCES", detail)

    def test_cache_revalidation_refuses_a_malformed_parent(self) -> None:
        topology = self.fake.topology()
        _malformed(self.fake.parent)
        detail = revalidate_cgroup_topology(topology)
        self.assertIsNotNone(detail)
        self.assertIn("unparseable", detail)

    def test_bootstrap_parent_depopulation_refuses_an_unreadable_parent(self) -> None:
        tree = _FakeCgroupParent(with_manager_leaf=False)
        self.addCleanup(tree.close)
        real = rl.read_cgroup_members

        def failing(path):
            if Path(path) == tree.parent:
                return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
            return real(path)

        with mock.patch.object(rl, "read_cgroup_members", failing):
            topology = rl.initialize_cgroup_topology(
                unified_root=tree.root,
                own_cgroup="/svc",
                require_cgroup2=False,
                cache=False,
            )
        self.assertFalse(topology.initialized)
        self.assertIn(
            topology.code, {rl.TOPOLOGY_MEMBERSHIP_UNREADABLE, rl.TOPOLOGY_MEMBERSHIP_MALFORMED}
        )

    def test_bootstrap_manager_verification_refuses_an_unreadable_leaf(self) -> None:
        tree = _FakeCgroupParent(with_manager_leaf=False)
        self.addCleanup(tree.close)
        real = rl.read_cgroup_members

        def failing(path):
            if Path(path).name.startswith(rl.MANAGER_LEAF_PREFIX):
                return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
            return real(path)

        with mock.patch.object(rl, "read_cgroup_members", failing):
            topology = rl.initialize_cgroup_topology(
                unified_root=tree.root,
                own_cgroup="/svc",
                require_cgroup2=False,
                cache=False,
            )
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_MEMBERSHIP_UNREADABLE)

    def test_probe_cleanup_refuses_to_remove_an_unreadable_probe(self) -> None:
        probe = self.fake.parent / f"{rl.PROBE_PREFIX}{os.getpid()}"
        probe.mkdir()
        (probe / "cgroup.procs").write_text("", encoding="utf-8")
        _unreadable(probe)
        self._restore(probe)
        evidence = rl._remove_owned_probe(probe)
        self.assertEqual(evidence["code"], rl.TOPOLOGY_PROBE_MEMBERSHIP_UNREADABLE)
        self.assertFalse(evidence["removed"])
        self.assertFalse(evidence["rmdir_attempted"])
        self.assertTrue(probe.exists(), "an unreadable probe cgroup was removed anyway")

    def test_no_positive_readiness_is_built_over_an_unreadable_probe(self) -> None:
        with mock.patch.object(
            rl, "initialize_cgroup_topology", lambda **_kwargs: self.fake.topology()
        ):
            real = rl.read_cgroup_members

            def failing(path):
                if Path(path).name.startswith(rl.PROBE_PREFIX):
                    return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
                return real(path)

            with mock.patch.object(rl, "read_cgroup_members", failing):
                delegation = rl.probe_cgroup_delegation(force=True)
        self.assertFalse(delegation.available)
        self.assertEqual(delegation.code, rl.TOPOLOGY_PROBE_MEMBERSHIP_UNREADABLE)

    def test_pre_attach_emptiness_refuses_an_unreadable_effect_cgroup(self) -> None:
        cgroup = self.fake.effect("pre-attach")
        self.addCleanup(cgroup.close)
        _unreadable(Path(cgroup.path))
        self._restore(Path(cgroup.path))
        self.assertFalse(cgroup.attach_and_verify(os.getpid()))
        self.assertIn("pre_attach_membership_unreadable", cgroup.attach_error)
        self.assertFalse(cgroup.active)

    def test_pre_attach_refuses_a_cgroup_that_is_not_observed_empty(self) -> None:
        cgroup = self.fake.effect("occupied")
        self.addCleanup(cgroup.close)
        (Path(cgroup.path) / "cgroup.procs").write_text("999999\n", encoding="utf-8")
        self.assertFalse(cgroup.attach_and_verify(os.getpid()))
        self.assertIn("not_empty_before_attach", cgroup.attach_error)

    def test_post_attach_verification_refuses_an_unreadable_read(self) -> None:
        cgroup = self.fake.effect("post-attach")
        self.addCleanup(cgroup.close)
        reads = {"count": 0}
        real = cgroup.read_members

        def failing_second_read():
            reads["count"] += 1
            if reads["count"] >= 2:
                return CgroupMembership(cgroup.path, read_ok=False, error_code="EACCES")
            return real()

        with mock.patch.object(cgroup, "read_members", failing_second_read):
            self.assertFalse(cgroup.attach_and_verify(os.getpid()))
        self.assertIn("post_attach_membership_unreadable", cgroup.attach_error)
        self.assertFalse(cgroup.active)

    def test_the_kill_domain_signals_nothing_it_could_not_observe(self) -> None:
        cgroup = self.fake.effect("kill-domain")
        self.addCleanup(cgroup.close)
        _unreadable(Path(cgroup.path))
        self._restore(Path(cgroup.path))
        evidence = cgroup.kill_domain()
        self.assertFalse(evidence["membership_readable"])
        self.assertEqual(evidence["members_signalled"], [])
        self.assertTrue(any("cgroup.procs" in item for item in evidence["errors"]))

    def test_quiescence_is_never_claimed_over_an_unreadable_membership(self) -> None:
        cgroup = self.fake.effect("quiescence")
        self.addCleanup(cgroup.close)
        _unreadable(Path(cgroup.path))
        self._restore(Path(cgroup.path))
        evidence = cgroup.wait_quiescent(0.05)
        self.assertFalse(evidence["quiescent"])
        self.assertFalse(evidence["membership_readable"])
        self.assertIn("EACCES", evidence["detail"])

    def test_removal_is_refused_over_an_unreadable_membership(self) -> None:
        cgroup = self.fake.effect("removal")
        path = Path(cgroup.path)
        _unreadable(path)
        self.addCleanup(os.chmod, path / "cgroup.procs", 0o644)
        self.assertFalse(cgroup.close())
        evidence = cgroup.removal_evidence()
        self.assertFalse(evidence["removed"])
        self.assertFalse(evidence["absence_verified"])
        self.assertFalse(evidence["membership_readable"])
        self.assertTrue(path.exists(), "an unreadable cgroup was removed anyway")

    def test_a_malformed_membership_fails_closed_in_every_caller(self) -> None:
        cgroup = self.fake.effect("malformed")
        self.addCleanup(cgroup.close)
        _malformed(Path(cgroup.path))
        self.assertFalse(cgroup.attach_and_verify(os.getpid()))
        self.assertFalse(cgroup.wait_quiescent(0.05)["quiescent"])
        self.assertFalse(cgroup.close())
        self.assertEqual(cgroup.kill_domain()["members_signalled"], [])


# --- M2-M36: coherent current validation artifacts ----------------------------


CURRENT_VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
HISTORICAL_VALIDATION_SNAPSHOT = (
    IMPLEMENTATION / "M2_VALIDATION_REPORT_HISTORICAL_FOURTH_REPAIR.json"
)
FINAL_REPAIR_REPORT = IMPLEMENTATION / "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
IMMUTABLE_HISTORICAL_REPORTS = (
    "M2_CRITICAL_REPAIR_REPORT.json",
    "M2_SECOND_CRITICAL_REPAIR_REPORT.json",
    "M2_THIRD_CRITICAL_REPAIR_REPORT.json",
    "M2_FOURTH_CRITICAL_REPAIR_REPORT.json",
    "M2_B25_CGROUP_TOPOLOGY_REPAIR_REPORT.json",
    "M2_B25_FINAL_FAILCLOSED_REPAIR_REPORT.json",
    "M1_BOUNDED_REPAIR_REPORT.json",
    "M1_SECOND_BOUNDED_REPAIR_REPORT.json",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ValidationArtifactCoherenceTests(unittest.TestCase):
    """Third-party interpretation must be unambiguous."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _load(CURRENT_VALIDATION_REPORT)
        cls.repair = _load(FINAL_REPAIR_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)

    def test_exactly_one_validation_report_declares_itself_current(self) -> None:
        self.assertTrue(self.report["is_current_validation_report"])
        self.assertTrue(HISTORICAL_VALIDATION_SNAPSHOT.exists())
        historical = _load(HISTORICAL_VALIDATION_SNAPSHOT)
        self.assertNotIn("is_current_validation_report", historical)
        current = [
            path
            for path in sorted(IMPLEMENTATION.glob("M2_VALIDATION_REPORT*.json"))
            if _load(path).get("is_current_validation_report")
        ]
        self.assertEqual([path.name for path in current], ["M2_VALIDATION_REPORT.json"])

    def test_the_historical_snapshot_is_the_superseded_bytes_and_its_hash(self) -> None:
        import hashlib

        recorded = self.report["supersedes_validation_report"]
        self.assertEqual(recorded["path"], f"implementation/{HISTORICAL_VALIDATION_SNAPSHOT.name}")
        raw = HISTORICAL_VALIDATION_SNAPSHOT.read_bytes()
        self.assertEqual(recorded["sha256"], hashlib.sha256(raw).hexdigest())
        # The snapshot is the superseded report byte for byte, not a re-encoding.
        # The anchor is the starting commit, which is fixed.  HEAD moves the
        # moment this repair is committed -- at which point HEAD carries the
        # *current* report -- so anchoring here to HEAD would make the
        # comparison pass before the commit and fail after it.
        committed = subprocess.run(
            [
                "git",
                "show",
                f"{self.repair['starting_commit']}:implementation/M2_VALIDATION_REPORT.json",
            ],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(raw, committed)
        snapshot = json.loads(raw.decode("utf-8"))
        self.assertEqual(snapshot["terminal_verdict"], "M2_FOURTH_CRITICAL_REPAIRS_REFUSED")
        self.assertNotEqual(snapshot["starting_commit"], self.report["starting_commit"])

    def test_no_current_field_repeats_a_superseded_verdict(self) -> None:
        text = CURRENT_VALIDATION_REPORT.read_text(encoding="utf-8")
        for stale in (
            "M2_FOURTH_CRITICAL_REPAIRS_REFUSED",
            "IMPLEMENTED_NOT_PHYSICALLY_QUALIFIED",
            "M2_B25_CGROUP_TOPOLOGY_REPAIR_VERIFIED",
        ):
            self.assertNotIn(stale, text, f"the current report still asserts {stale}")
        self.assertEqual(self.report["starting_commit"], self.repair["starting_commit"])
        self.assertEqual(self.report["branch"], self.repair["branch"])
        # The independent audit's verdicts are recorded verbatim: they are the
        # governing defect statement, not a superseded self-claim.
        self.assertEqual(
            self.report["independent_audit_verdicts"],
            ["M2_FINAL_INDEPENDENT_CLOSURE_REFUSED", "MILESTONE_3_NOT_PERMITTED"],
        )
        self.assertEqual(
            self.report["independent_audit_sha256"], self.repair["independent_audit_sha256"]
        )

    def test_a_prior_transcript_is_never_offered_as_qualifying_this_code(self) -> None:
        prior = self.report["prior_physical_qualification"]
        self.assertEqual(prior["qualified_commit"], "f702509c06346d4f288a9f8b942d21fc1a38e2cb")
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertIn("does not qualify", prior["scope"])

    def test_the_physical_qualification_state_is_internally_coherent(self) -> None:
        """Either a complete transcript, or an explicit absence.  Never both."""

        run = self.report["m2_final_protocol_lifecycle_closure"]["delegated_run"]
        claimed = self.report["independent_validation"][
            "real_delegated_cgroup_qualification_of_this_repair"
        ]
        self.assertIn(
            run["status"],
            {"OPERATOR_QUALIFICATION_REQUIRED", "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2"},
        )
        if run["status"] == "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
            self.assertTrue(claimed)
            self.assertEqual(run["skipped"], 0, "a delegated skip is never counted as a pass")
            self.assertEqual(run["failures"], 0)
            self.assertEqual(run["errors"], 0)
            self.assertIn(f"Ran {run['executed']} tests", run["exact_result"])
            self.assertIn("OK", run["exact_result"])
            self.assertEqual(
                self.report["terminal_verdict"], "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_VERIFIED"
            )
        else:
            self.assertFalse(claimed, "an unperformed run may not be claimed as qualification")
            self.assertIsNone(run["executed"])
            self.assertEqual(run["exact_result"], "")
            self.assertEqual(
                self.report["terminal_verdict"],
                "M2_FINAL_PROTOCOL_LIFECYCLE_OPERATOR_QUALIFICATION_REQUIRED",
            )
        self.assertEqual(run, self.repair["delegated_physical_qualification"]["run"])
        self.assertEqual(
            run["expected_modules"],
            [
                "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
                "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
                "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
            ],
        )

    def test_the_current_verdict_matches_the_requirement_matrix(self) -> None:
        dispositions = {
            row["requirement_id"]: row for row in self.report["requirement_dispositions"]
        }
        records = {row["requirement_id"]: row for row in self.matrix["requirements"]}
        for requirement_id, row in dispositions.items():
            self.assertEqual(
                row["status"], records[requirement_id]["current_status"], requirement_id
            )
        self.assertEqual(records["EXEC-06"]["current_status"], "VERIFIED_INTEGRATION")
        self.assertEqual(
            records["EVID-08"]["current_status"],
            "IMPLEMENTED",
            "provider retry accounting is Milestone 3 work and is not closed here",
        )

    def test_the_expected_delegated_total_matches_the_three_modules(self) -> None:
        run = self.report["m2_final_protocol_lifecycle_closure"]["delegated_run"]
        expected = sum(
            unittest.defaultTestLoader.loadTestsFromName(module).countTestCases()
            for module in run["expected_modules"]
        )
        self.assertEqual(run["expected_total"], expected)
        if run["executed"] is not None:
            self.assertEqual(run["executed"], expected)

    def test_the_declared_module_counts_match_the_modules_on_disk(self) -> None:
        counts = self.report["m2_test_count_semantics"]
        for module, field in (
            ("tests.test_admissible_paired_runner_m2_b25_cgroup_topology", "m2_b25_topology_module"),
            (
                "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
                "m2_b25_final_failclosed_module",
            ),
            (
                "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
                "m2_final_protocol_lifecycle_module",
            ),
        ):
            loader = unittest.defaultTestLoader.loadTestsFromName(module)
            self.assertEqual(loader.countTestCases(), counts[field], module)
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_legacy_pre_b25"]
            + counts["m2_b25_topology_module"]
            + counts["m2_b25_final_failclosed_module"]
            + counts["m2_final_protocol_lifecycle_module"],
        )
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_skipped"] + counts["m2_non_skipped"],
        )

    def test_the_historical_reports_are_immutable(self) -> None:
        committed = subprocess.run(
            ["git", "show", "--stat", "--format=", "HEAD"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        del committed
        for name in IMMUTABLE_HISTORICAL_REPORTS:
            with self.subTest(artifact=name):
                original = subprocess.run(
                    ["git", "show", f"HEAD:implementation/{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), original)

    def test_independent_acceptance_and_installed_path_remain_unclaimed(self) -> None:
        self.assertFalse(self.report["independent_validation"]["independent_acceptance_claimed"])
        self.assertFalse(
            self.report["independent_validation"]["installed_path_qualification_claimed"]
        )
        self.assertFalse(self.repair["independent_acceptance_claimed"])
        self.assertFalse(self.repair["installed_path_qualification_claimed"])

    def test_the_repair_report_declares_the_bounded_findings_and_architecture(self) -> None:
        self.assertEqual(
            self.repair["bounded_findings"], ["M2-B32", "M2-B33", "M2-B34", "M2-B35", "M2-M36"]
        )
        self.assertEqual(self.repair["starting_commit"], "fbadaeec4205c9b24aeaeaac6c73ca1e6e69a4ff")
        self.assertEqual(self.repair["branch"], "paired-runner/m2-final-protocol-lifecycle-repair")
        self.assertTrue(self.repair["sole_parent_required"])
        architecture = self.repair["process_ownership_architecture"]
        self.assertEqual(
            architecture["chosen"], "CONTROLLER_CHILD_SUBREAPER_PLUS_PIDFD_OBSERVATION"
        )
        self.assertTrue(architecture["rejected_alternatives"])
        self.assertNotIn("ending_commit", self.repair)

    def test_the_repair_report_records_every_required_deadline(self) -> None:
        deadlines = self.repair["controller_deadline_model"]["deadlines_ms"]
        for name, value in deadlines.items():
            self.assertEqual(getattr(po, name), value, name)
        self.assertEqual(
            self.repair["controller_deadline_model"]["enforcement"],
            "absolute monotonic deadline owned by the controller process, applied to each socket "
            "operation and restored afterwards",
        )


class MilestoneBoundaryTests(unittest.TestCase):
    """Milestone 3 is forbidden and was not started."""

    def test_no_milestone_3_module_was_created(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        present = {path.name for path in package.glob("*.py")}
        for forbidden in (
            "transport.py",
            "direct_mode.py",
            "governed_mode.py",
            "policy.py",
            "authority.py",
            "evaluator.py",
            "archive.py",
            "checkpoint.py",
            "state.py",
        ):
            self.assertNotIn(forbidden, present, forbidden)

    def test_this_module_imports_no_network_client(self) -> None:
        # Only the import block is inspected: the assertions themselves have to
        # name the forbidden tokens, and a test may not fail on its own text.
        text = Path(__file__).read_text(encoding="utf-8").split("\nclass ", 1)[0]
        for forbidden in ("requests", "urllib", "http.client", "socketserver"):
            self.assertNotIn(f"import {forbidden}", text, forbidden)
            self.assertNotIn(f"from {forbidden}", text, forbidden)

    def test_the_repository_worktree_is_never_the_effect_workspace(self) -> None:
        with DisposableWorkspace() as disposable:
            self.assertNotEqual(disposable.workspace, REPOSITORY_ROOT)
            self.assertFalse(str(disposable.workspace).startswith(str(REPOSITORY_ROOT)))


# --- delegated physical qualification -----------------------------------------


class _Harness:
    """The production shared effect substrate over a disposable workspace."""

    def __init__(self, *, run_id: str) -> None:
        self.specification = build_specification("DIRECT", run_id=run_id)
        self.grammar = self.specification.tool_grammar.grammar_fingerprint
        self.disposable = DisposableWorkspace()
        self.workspace = self.disposable.workspace
        self.store_root = self.disposable.store_root
        self.store = DurableObjectStore(self.store_root)
        self.binding = WorkspaceBinding.bind(
            self.workspace, self.specification, evidence_root=self.store_root
        )
        self.substrate = SharedEffectSubstrate(
            binding=self.binding, store=self.store, ledger=RunEffectLedger(run_id)
        )
        self._counter = 0

    def command(self, script: str, *, timeout_ms: int = 60_000):
        self._counter += 1
        request = RunCommandRequest.create(
            tool_grammar_fingerprint=self.grammar,
            argv=[PYTHON, "-c", script],
            timeout_ms=timeout_ms,
        )
        proposal = build_proposal(
            self.specification, request, proposal_id=f"proposal-{self._counter}"
        )
        return self.substrate.execute(
            specification=self.specification,
            proposal=proposal,
            decision=decision_for(proposal),
            reservation_id=f"reservation-{self._counter}",
            receipt_id=f"receipt-{self._counter}",
        )

    def close(self) -> None:
        self.binding.close()
        self.disposable.close()


SENTINEL_SCRIPT = "open('sentinel.txt', 'w').write('the command executed')\n"


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _zombies_of(pids: list[int]) -> list[int]:
    return [pid for pid in pids if po.process_is_zombie(pid)]


class DelegatedProtocolLifecycleTests(unittest.TestCase):
    """Physical qualification of the repaired paths on a real cgroup v2 subtree."""

    @classmethod
    def setUpClass(cls) -> None:
        if REQUIRE_DELEGATED and not DELEGATION.available:
            raise AssertionError(
                "ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1 but no delegated cgroup v2 "
                f"topology is available: {DELEGATION.detail}"
            )

    def test_the_no_false_green_variable_forbids_skipping(self) -> None:
        if REQUIRE_DELEGATED:
            self.assertTrue(DELEGATION.available, DELEGATION.detail)
            self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        else:
            self.skipTest("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP is not set")

    @delegated
    def test_a_lost_acknowledgement_stays_unknown_after_cleanup(self) -> None:
        """M2-B32 physically: force a lost ack, then ask again after cleanup."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        observed: dict[str, object] = {}
        real_spawn = pw.PrivateExecutionView.spawn_launcher

        def faulted(view, argv, **kwargs):
            view.helper.release_fault = "die_after_write"
            launcher = real_spawn(view, argv, **kwargs)
            observed["launcher"] = launcher
            return launcher

        harness = _Harness(run_id="run-b32-physical")
        self.addCleanup(harness.close)
        with mock.patch.object(pw.PrivateExecutionView, "spawn_launcher", faulted):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        launcher = observed["launcher"]
        first = launcher.release_outcome
        self.assertEqual(first.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(first.sentinel_claim, "EXECUTION_OUTCOME_UNKNOWN")
        # The public accessor and a repeated call, after the whole abort path.
        self.assertIs(launcher.release(), first)
        self.assertIs(launcher.observed_release_outcome(), first)
        self.assertNotEqual(launcher.release().sentinel_claim, "NO_INSTRUCTION_EXECUTED")

    @delegated
    def test_a_wedged_helper_returns_within_the_controller_bound(self) -> None:
        """M2-B33 physically: a live, stopped helper cannot hold the controller."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        parent = Path(DELEGATION.delegated_path)
        stopped: dict[str, int] = {}
        real_spawn = pw.PrivateExecutionView.spawn_launcher

        def wedge_after_gate_write(view, argv, **kwargs):
            launcher = real_spawn(view, argv, **kwargs)
            os.kill(view.helper.pid, signal.SIGSTOP)
            stopped["pid"] = view.helper.pid
            return launcher

        harness = _Harness(run_id="run-b33-physical")
        self.addCleanup(harness.close)
        started = time.monotonic()
        with mock.patch.object(pw.PrivateExecutionView, "spawn_launcher", wedge_after_gate_write):
            outcome = harness.command(SENTINEL_SCRIPT)
        elapsed = time.monotonic() - started
        if stopped:
            self.addCleanup(_resume, stopped["pid"])
        self.assertLess(
            elapsed,
            (po.ABORT_TOTAL_DEADLINE_MS + po.HELPER_RELEASE_ACCEPT_DEADLINE_MS) / 1000.0
            + 30.0,
            "a wedged helper held the controller beyond its own bound",
        )
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup was left behind")

    @delegated
    def test_helper_loss_after_the_gate_write_proves_the_launcher_reap(self) -> None:
        """M2-B34 physically, with a real cgroup kill domain."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        parent = Path(DELEGATION.delegated_path)
        fixture = _live(self)
        bounds = ResourceBounds.for_timeout(1000)
        cgroup = EffectCgroup(DELEGATION, bounds, f"lifecycle-{os.getpid()}")
        self.assertTrue(cgroup.create(), cgroup.create_error)
        self.addCleanup(cgroup.close)
        self.assertTrue(cgroup.attach_and_verify(fixture.launcher.pid), cgroup.attach_error)

        fixture.helper.release_fault = "die_after_write"
        outcome = fixture.launcher.release()
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertTrue(_await(lambda: fixture.executed, 15.0), "the gated image never ran")
        self.assertTrue(_await(lambda: not po.process_present(fixture.helper.pid) or po.process_is_zombie(fixture.helper.pid), 10.0))

        evidence = ps.abort_gated_effect(
            process=fixture.launcher,
            cgroup=cgroup,
            descriptors=(),
            release_outcome=outcome,
            reason="physical-helper-loss",
            deadline=Deadline.after_ms(po.ABORT_TOTAL_DEADLINE_MS, "abort"),
        )
        ownership = evidence["process_ownership"]
        self.assertTrue(evidence["process_domain_kill_requested"], ownership)
        self.assertTrue(evidence["launcher_exit_observed"], ownership)
        self.assertTrue(evidence["launcher_reaped"], ownership)
        self.assertEqual(evidence["launcher_reaper_role"], REAPER_TRUSTED_CONTROLLER)
        self.assertEqual(evidence["launcher_reaper_pid"], os.getpid())
        self.assertTrue(evidence["helper_exit_observed"], ownership)
        self.assertTrue(evidence["helper_reaped"], ownership)
        self.assertTrue(evidence["cgroup_quiescent"], evidence["quiescence"])
        self.assertTrue(evidence["effect_cgroup_removed"], evidence["cgroup_removal"])
        self.assertEqual(_zombies_of([fixture.launcher.pid, fixture.helper.pid]), [])
        self.assertEqual(_effect_cgroups(parent), [])

    @delegated
    def test_an_unreadable_membership_refuses_release_quiescence_and_removal(self) -> None:
        """M2-B35 physically, through the production membership-read function."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)

        for stage in ("revalidation", "pre_attach", "post_attach", "cleanup"):
            with self.subTest(stage=stage):
                harness = _Harness(run_id=f"run-b35-{stage}")
                self.addCleanup(harness.close)
                real = rl.read_cgroup_members
                seen = {"effect_reads": 0}

                def failing(path, stage=stage, seen=seen):
                    name = Path(path).name
                    if stage == "revalidation" and name.startswith(rl.MANAGER_LEAF_PREFIX):
                        return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
                    if name.startswith(rl.EFFECT_PREFIX):
                        seen["effect_reads"] += 1
                        if stage == "pre_attach":
                            return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
                        if stage == "post_attach" and seen["effect_reads"] >= 2:
                            return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
                        if stage == "cleanup" and seen["effect_reads"] >= 3:
                            return CgroupMembership(str(path), read_ok=False, error_code="EACCES")
                    return real(path)

                with mock.patch.object(rl, "read_cgroup_members", failing):
                    outcome = harness.command(SENTINEL_SCRIPT)
                self.assertNotEqual(
                    outcome.receipt.status,
                    "COMPLETED",
                    f"a {stage} membership refusal still completed the effect",
                )
                if stage in {"revalidation", "pre_attach", "post_attach"}:
                    self.assertFalse(
                        (harness.workspace / "sentinel.txt").exists(),
                        "the command ran after an unreadable pre-release membership",
                    )
                self.assertEqual(
                    _effect_cgroups(parent), [], "a cgroup survived an unreadable-membership refusal"
                )

    @delegated
    def test_a_nominal_effect_still_completes_and_cleans_up(self) -> None:
        """The accepted nominal path is unchanged by all four repairs."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-nominal-lifecycle")
        self.addCleanup(harness.close)
        started = time.monotonic()
        outcome = harness.command(SENTINEL_SCRIPT)
        elapsed = time.monotonic() - started
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(_effect_cgroups(parent), [])
        self.assertLess(elapsed, 60.0, "nominal latency was materially degraded")

    @delegated
    def test_the_controller_leaves_no_owned_process_or_subreaper_state(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        before, error = po.get_child_subreaper()
        self.assertIsNone(error)
        fixture = _LiveLauncher()
        self.assertTrue(CHILD_SUBREAPER.active, "the helper did not take subreaper ownership")
        launcher_pid = fixture.launcher.pid
        helper_pid = fixture.helper.pid
        fixture.close()
        self.assertEqual(po.get_child_subreaper()[0], before, "the process-wide flag was left set")
        self.assertEqual(_zombies_of([launcher_pid, helper_pid]), [])


if __name__ == "__main__":
    unittest.main()
