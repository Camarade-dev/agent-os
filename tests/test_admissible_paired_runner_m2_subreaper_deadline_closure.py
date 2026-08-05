"""M2 subreaper and global-deadline closure: B37, B38, B39, B40.

Each finding is closed by making an untrue statement impossible to produce.

M2-B37 -- an ownership guarantee is a precondition, not a preference
    ``ChildSubreaperOwnership.acquire`` reported that the process-wide flag
    could not be read, could not be set, or did not read back as set -- and
    still returned a state holding a reference, after which
    ``PrivateMountHelper.start`` forked anyway.  The controller therefore
    created a helper whose orphaned launcher it had no established right to
    reap, while every later evidence field spoke as though it had one.
    Acquisition now either returns kernel-confirmed state or raises, and the
    fork primitive is a single named call site a test can prove was never
    reached.

M2-B38 -- acquisition around a fork is failure-atomic
    An acquisition taken before ``fork()`` survived a ``fork()`` that failed, so
    a process-wide flag stayed set for a helper that was never created and a
    controller that had nothing to reap.  Every exit path between acquisition
    and successful ownership transfer now destroys and reaps the partially
    created child, closes every descriptor, and releases the acquisition exactly
    once through a handle that cannot double-release.

M2-B39 -- a restoration is a readback, not a request
    ``release`` performed the readback and then ignored it: it decided RESTORED
    from the *write's* error code, so requesting 0 and reading back 1 reported a
    restored flag while this process was still a child subreaper.  Restoration
    is now claimed only when the kernel reads back exactly the intended value;
    RESTORE_SET_FAILED, RESTORE_READBACK_FAILED and RESTORE_MISMATCH are
    truthful residual states that keep both values and mark the cleanup
    incomplete.

M2-B40 -- one deadline for one bounded cleanup
    The abort path declared a 30-second total and then handed later stages fresh
    fixed durations: ``wait_quiescent`` received a new five seconds even when the
    global deadline was already exhausted, so the stated bound was the total
    *plus* whatever the tail asked for.  One :class:`CleanupBudget` is now
    created at entry and every stage receives a capped view of what is left of
    it, with what each stage was granted, completed, or left incomplete recorded
    in the durable cleanup evidence.

Deterministic tests drive real ``prctl`` calls, real socket pairs, real trusted
helpers, real forked launchers, real constructed cgroup trees, and injected
kernel failures.  Delegated physical tests run the production path inside a real
``Delegate=yes`` cgroup v2 subtree and, under
``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than skip.

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
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.paired_runner import private_workspace as pw  # noqa: E402
from admissible.paired_runner import process_ownership as po  # noqa: E402
from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner.cgroup_launch import (  # noqa: E402
    RELEASE_OUTCOME_UNKNOWN,
    RELEASE_PHASE_ACK_LOST,
    GateReleaseOutcome,
)
from admissible.paired_runner.private_workspace import (  # noqa: E402
    PrivateMountHelper,
    PrivateWorkspaceError,
)
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    REAPER_TRUSTED_CONTROLLER,
    ChildSubreaperOwnership,
    ChildSubreaperUnavailable,
    CleanupBudget,
    Deadline,
)
from admissible.paired_runner.resource_limits import (  # noqa: E402
    CgroupDelegation,
    EffectCgroup,
    ResourceBounds,
    probe_cgroup_delegation,
)

DELEGATION = probe_cgroup_delegation()
REQUIRE_DELEGATED = os.environ.get("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP") == "1"

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
    guard_process_wide_cgroup_caches,
)
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import SharedEffectSubstrate, WorkspaceBinding  # noqa: E402
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = REPOSITORY_ROOT / "implementation"

#: The upper bound a bounded call must respect.  Deliberately generous: the
#: property under test is finiteness, not latency.
BOUND_SLACK_SECONDS = 10.0
#: A whole-cleanup budget short enough to keep the deterministic suite fast and
#: long enough that ordinary scheduling jitter cannot make a stage miss it.
SHORT_ABORT_MS = 1_500


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


LAUNCHER_SCRIPT = (
    "import sys, time\n"
    "open(sys.argv[1], 'w').write('the gated image executed')\n"
    "time.sleep(120)\n"
)
SENTINEL_SCRIPT = "open('sentinel.txt', 'w').write('the command executed')\n"


# --- shared fixtures ----------------------------------------------------------


class _FlagGuard:
    """Restore the process-wide subreaper flag whatever a test did to it.

    The flag is genuinely process-wide, so a test that leaves it set changes the
    conditions of every test that runs after it.  Each test that touches it
    therefore records the value it found and puts that value back.
    """

    @staticmethod
    def install(test: unittest.TestCase) -> int:
        before, error = po.get_child_subreaper()
        test.assertIsNone(error, "this kernel does not expose PR_GET_CHILD_SUBREAPER")

        def restore() -> None:
            po.set_child_subreaper(int(before or 0))

        test.addCleanup(restore)
        return int(before or 0)


class _LiveLauncher:
    """A real trusted helper holding one real gated launcher child.

    This is the production ``PrivateMountHelper`` and the production
    ``SpawnedLauncher``: the helper unshares a user+mount namespace, forks the
    launcher, and holds the trusted pipe gate.  Nothing about the ownership
    topology under test is simulated.
    """

    def __init__(self, *, gated: bool = True, script: str = LAUNCHER_SCRIPT) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="admissible-m2-closure-"))
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
    the B25 modules already assert.  Here it exists so the abort path has a real
    directory to read membership from, wait for quiescence on, and remove.
    """

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-m2-b40-"))
        self.parent = self.root / "svc"
        self.parent.mkdir()
        (self.parent / "cgroup.controllers").write_text("memory pids", encoding="utf-8")
        (self.parent / "cgroup.subtree_control").write_text("memory pids", encoding="utf-8")
        (self.parent / "cgroup.procs").write_text("", encoding="utf-8")
        self.manager = self.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
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

    def effect(self, label: str = "b40") -> EffectCgroup:
        cgroup = EffectCgroup(self.delegation(), ResourceBounds.for_timeout(1000), label)
        assert cgroup.create(), cgroup.create_error
        (Path(cgroup.path) / "cgroup.procs").write_text("", encoding="utf-8")
        return cgroup

    def close(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)


class _RecordingCgroup:
    """A real effect cgroup that records what the abort path granted each stage.

    The audited defect is exactly a *duration handed to a stage*, so the
    duration is captured at the boundary rather than inferred from timings.
    """

    def __init__(self, inner: EffectCgroup, *, burn_until: Deadline | None = None) -> None:
        self._inner = inner
        self.quiescence_timeouts: list[float] = []
        self.kill_domain_calls = 0
        self._burn_until = burn_until

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def kill_domain(self):
        self.kill_domain_calls += 1
        if self._burn_until is not None:
            # Spend the whole remaining budget inside an early stage, so the
            # later stages meet a genuinely exhausted deadline rather than a
            # simulated one.
            while not self._burn_until.expired:
                time.sleep(0.01)
        return self._inner.kill_domain()

    def wait_quiescent(self, timeout_seconds: float):
        self.quiescence_timeouts.append(float(timeout_seconds))
        return self._inner.wait_quiescent(timeout_seconds)


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _receipt_diagnosis(outcome) -> str:
    """The classification and causal evidence behind a receipt status.

    A physical assertion that reports only "was FAILED, expected COMPLETED"
    forces the next diagnosis to guess.  Every field a receipt failure is
    actually decided from is rendered here, so the assertion that fails also
    says *why* it failed.
    """

    receipt = outcome.receipt
    result = getattr(outcome, "result", None)
    process = getattr(outcome, "process_observation", None)
    lines = [
        f"receipt.status={receipt.status!r}",
        f"result.outcome={getattr(result, 'outcome', None)!r}",
        f"result.error_code={getattr(result, 'error_code', None)!r}",
    ]
    if process is not None:
        for field in (
            "process_started",
            "start_failure_class",
            "exit_code",
            "timed_out",
            "cancelled",
            "status_document_present",
            "namespace_quiescent",
            "descendants_alive_at_direct_exit",
            "descendants_reaped",
            "capsule_mechanism",
            "launcher_exit_code",
        ):
            if hasattr(process, field):
                lines.append(f"process.{field}={getattr(process, field)!r}")
    delegation = ps.cgroup_delegation()
    lines.append(f"delegation.available={delegation.available!r}")
    lines.append(f"delegation.code={delegation.code!r}")
    lines.append(f"delegation.detail={delegation.detail!r}")
    lines.append(f"topology_cache_initialized={getattr(rl._TOPOLOGY, 'initialized', None)!r}")
    lines.append(f"child_subreaper={CHILD_SUBREAPER.state()!r}")
    return "\n  ".join([""] + lines)


def _open_descriptor_count() -> int:
    try:
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))
    except OSError:  # pragma: no cover - /proc is part of the platform contract
        return -1


def _await(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# --- M2-B37: acquisition failure must stop before fork ------------------------


class SubreaperAcquisitionGateTests(unittest.TestCase):
    """An ownership guarantee the launch path may proceed without is not one."""

    def setUp(self) -> None:
        self.before = _FlagGuard.install(self)

    def test_a_set_failure_is_a_refusal_and_not_a_held_reference(self) -> None:
        ownership = ChildSubreaperOwnership()
        with mock.patch.object(po, "set_child_subreaper", return_value="EINVAL"):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_SET_FAILED)
        state = ownership.state()
        self.assertEqual(state["depth"], 0, "a failed acquisition still counted a reference")
        self.assertFalse(state["applied"])
        self.assertIsNone(state["owner_pid"])
        self.assertFalse(ownership.active)

    def test_a_readback_failure_is_a_refusal(self) -> None:
        ownership = ChildSubreaperOwnership()
        reads = {"count": 0}

        def failing_read():
            reads["count"] += 1
            return (self.before, None) if reads["count"] == 1 else (None, "EPERM")

        with mock.patch.object(po, "get_child_subreaper", failing_read):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_READBACK_FAILED)
        self.assertEqual(ownership.state()["depth"], 0)

    def test_a_readback_mismatch_is_a_refusal(self) -> None:
        ownership = ChildSubreaperOwnership()
        reads = {"count": 0}

        def lying_read():
            reads["count"] += 1
            # First read is the baseline; the read after the write disagrees
            # with the write that reported success.
            return (0, None) if reads["count"] == 1 else (0, None)

        with mock.patch.object(po, "get_child_subreaper", lying_read):
            with mock.patch.object(po, "set_child_subreaper", return_value=None):
                with self.assertRaises(ChildSubreaperUnavailable) as raised:
                    ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_READBACK_MISMATCH)
        self.assertEqual(ownership.state()["depth"], 0)

    def test_an_unreadable_flag_is_a_refusal(self) -> None:
        ownership = ChildSubreaperOwnership()
        with mock.patch.object(po, "get_child_subreaper", return_value=(None, "ENOSYS")):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_UNAVAILABLE)
        self.assertEqual(ownership.state()["depth"], 0)

    def test_every_acquisition_refusal_is_declared(self) -> None:
        self.assertEqual(
            sorted(po.SUBREAPER_ACQUISITION_REFUSALS),
            sorted(
                [
                    po.SUBREAPER_UNAVAILABLE,
                    po.SUBREAPER_SET_FAILED,
                    po.SUBREAPER_READBACK_FAILED,
                    po.SUBREAPER_READBACK_MISMATCH,
                ]
            ),
        )
        self.assertNotIn(po.SUBREAPER_APPLIED, po.SUBREAPER_ACQUISITION_REFUSALS)

    def test_a_refused_acquisition_preserves_the_previous_process_wide_state(self) -> None:
        ownership = ChildSubreaperOwnership()
        writes: list[int] = []
        real_set = po.set_child_subreaper

        def recording_set(value):
            writes.append(int(value))
            return real_set(value)

        reads = {"count": 0}

        def read_after_write():
            reads["count"] += 1
            if reads["count"] == 1:
                return self.before, None
            # The write reported success and the kernel says otherwise.
            return 0 if reads["count"] == 2 else self.before, None

        with mock.patch.object(po, "set_child_subreaper", recording_set):
            with mock.patch.object(po, "get_child_subreaper", read_after_write):
                with self.assertRaises(ChildSubreaperUnavailable):
                    ownership.acquire()
        self.assertEqual(writes[0], 1, "the acquisition wrote 1")
        self.assertEqual(writes[-1], self.before, "the previous value was not written back")
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_an_acquisition_reference_must_be_valid_and_owned_by_this_pid(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
        self.addCleanup(reference.release)
        self.assertTrue(reference.valid)
        self.assertEqual(reference.holder_pid, os.getpid())
        self.assertEqual(reference.state["owner_pid"], os.getpid())
        reference.release()
        self.assertFalse(reference.valid, "a released reference is not a valid ownership")

    def test_an_acquisition_object_that_does_not_describe_ownership_is_refused(self) -> None:
        ownership = ChildSubreaperOwnership()
        forged = dict(ownership.state())
        forged.update({"code": po.SUBREAPER_APPLIED, "applied": True, "depth": 1})
        forged["owner_pid"] = os.getpid() + 1_000_000
        with mock.patch.object(ChildSubreaperOwnership, "acquire", return_value=forged):
            with self.assertRaises(ChildSubreaperUnavailable):
                ownership.acquire_reference()

    # --- the production launch path -------------------------------------------

    def test_an_acquisition_failure_never_reaches_the_fork_primitive(self) -> None:
        """The production path, with the kernel write injected to fail."""

        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(po, "set_child_subreaper", return_value="EPERM"):
            with mock.patch.object(pw, "_fork", forked):
                with self.assertRaises(PrivateWorkspaceError) as raised:
                    PrivateMountHelper.start()
        self.assertFalse(forked.called, "the launch path forked without proved ownership")
        self.assertEqual(raised.exception.code, "private_mountns_subreaper_unavailable")
        self.assertIn(po.SUBREAPER_SET_FAILED, str(raised.exception))

    def test_a_readback_mismatch_never_reaches_the_fork_primitive(self) -> None:
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(po, "get_child_subreaper", return_value=(0, None)):
            with mock.patch.object(po, "set_child_subreaper", return_value=None):
                with mock.patch.object(pw, "_fork", forked):
                    with self.assertRaises(PrivateWorkspaceError):
                        PrivateMountHelper.start()
        self.assertFalse(forked.called)

    def test_a_refused_start_creates_no_helper_launcher_or_descriptor(self) -> None:
        before_descriptors = _open_descriptor_count()
        before_children = _child_pids()
        with mock.patch.object(po, "set_child_subreaper", return_value="EPERM"):
            with self.assertRaises(PrivateWorkspaceError):
                PrivateMountHelper.start()
        self.assertEqual(_open_descriptor_count(), before_descriptors, "a descriptor leaked")
        self.assertEqual(_child_pids(), before_children, "a process was created")
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0, "an ownership reference was retained")
        self.assertFalse(CHILD_SUBREAPER.active)

    def test_a_refused_start_returns_no_helper_object_at_all(self) -> None:
        with mock.patch.object(po, "set_child_subreaper", return_value="EPERM"):
            with self.assertRaises(PrivateWorkspaceError):
                helper = PrivateMountHelper.start()
                self.fail(f"a helper was started without ownership: {helper}")

    def test_the_controller_forks_only_through_the_gated_primitive(self) -> None:
        """One named call site, so the gate above cannot be bypassed elsewhere."""

        import inspect

        launch = inspect.getsource(PrivateMountHelper.start)
        self.assertIn("_fork()", launch)
        self.assertNotIn(
            "os.fork(", launch, "the controller forks around its own gated primitive"
        )
        self.assertIn("acquire_reference", launch)
        self.assertLess(
            launch.index("acquire_reference"),
            launch.index("_fork()"),
            "the acquisition is not established before the fork",
        )
        # The helper's own fork of the launcher runs *inside* the helper
        # process, which holds no acquisition -- the flag is not inherited --
        # and is not the trusted controller.
        self.assertIn("os.fork()", inspect.getsource(pw._helper_main))


def _child_pids() -> list[int]:
    """Live children of this process, from the kernel rather than bookkeeping."""

    try:
        raw = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text(encoding="ascii")
    except OSError:  # pragma: no cover - CONFIG_PROC_CHILDREN absent
        return []
    return sorted(int(value) for value in raw.split())


# --- M2-B38: fork failure must roll back ownership state ----------------------


class ForkFailureRollbackTests(unittest.TestCase):
    """Acquisition around helper creation is failure-atomic."""

    def setUp(self) -> None:
        self.before = _FlagGuard.install(self)
        self.baseline_depth = CHILD_SUBREAPER.state()["depth"]

    def _assert_no_ownership_leak(self) -> None:
        state = CHILD_SUBREAPER.state()
        self.assertEqual(
            state["depth"], self.baseline_depth, "a failed launch leaked an ownership reference"
        )
        if self.baseline_depth == 0:
            self.assertFalse(CHILD_SUBREAPER.active)
            self.assertEqual(
                po.get_child_subreaper()[0], self.before, "the process-wide flag was left set"
            )

    def test_a_fork_failing_with_eagain_rolls_the_acquisition_back(self) -> None:
        with mock.patch.object(pw, "_fork", side_effect=OSError(errno.EAGAIN, "EAGAIN")):
            with self.assertRaises(PrivateWorkspaceError) as raised:
                PrivateMountHelper.start()
        self.assertEqual(raised.exception.code, "private_mountns_helper_start_failed")
        self.assertIn("EAGAIN", str(raised.exception))
        self._assert_no_ownership_leak()

    def test_a_fork_failing_with_enomem_rolls_the_acquisition_back(self) -> None:
        with mock.patch.object(pw, "_fork", side_effect=OSError(errno.ENOMEM, "ENOMEM")):
            with self.assertRaises(PrivateWorkspaceError):
                PrivateMountHelper.start()
        self._assert_no_ownership_leak()

    def test_a_descriptor_failure_before_fork_rolls_the_acquisition_back(self) -> None:
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw.socket, "socketpair", side_effect=OSError(errno.EMFILE, "EMFILE")):
            with mock.patch.object(pw, "_fork", forked):
                with self.assertRaises(PrivateWorkspaceError):
                    PrivateMountHelper.start()
        self.assertFalse(forked.called, "the descriptor failure still reached fork()")
        self._assert_no_ownership_leak()

    def test_a_failure_in_the_parent_setup_path_rolls_the_acquisition_back(self) -> None:
        """A real fork, then a real failure in the parent's handshake."""

        before_descriptors = _open_descriptor_count()
        with mock.patch.object(
            pw.Path, "write_text", side_effect=OSError(errno.EPERM, "uid_map refused")
        ):
            with self.assertRaises(PrivateWorkspaceError):
                PrivateMountHelper.start()
        self._assert_no_ownership_leak()
        self.assertEqual(_open_descriptor_count(), before_descriptors, "a descriptor leaked")

    def test_the_rolled_back_child_is_destroyed_and_reaped(self) -> None:
        before_children = _child_pids()
        with mock.patch.object(
            pw.Path, "write_text", side_effect=OSError(errno.EPERM, "uid_map refused")
        ):
            with self.assertRaises(PrivateWorkspaceError):
                PrivateMountHelper.start()
        self.assertTrue(
            _await(lambda: _child_pids() == before_children, 5.0),
            "the partially created helper survived the rollback",
        )
        self._assert_no_ownership_leak()

    def test_a_repeated_rollback_releases_nothing_a_second_time(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
        first = pw._roll_back_failed_start(
            pid=None, sockets=(), descriptors=(), subreaper=reference
        )
        second = pw._roll_back_failed_start(
            pid=None, sockets=(), descriptors=(), subreaper=reference
        )
        self.assertEqual(first["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(
            second["subreaper"],
            first["subreaper"],
            "the repeated rollback reported a different release",
        )
        self.assertEqual(ownership.state()["depth"], 0)

    def test_a_failed_launch_never_clears_a_still_required_acquisition(self) -> None:
        """A concurrent effect's ownership survives another effect's rollback."""

        ownership = ChildSubreaperOwnership()
        held = ownership.acquire_reference()
        self.addCleanup(held.release)
        doomed = ownership.acquire_reference()
        self.assertEqual(ownership.state()["depth"], 2)
        rollback = pw._roll_back_failed_start(
            pid=None, sockets=(), descriptors=(), subreaper=doomed
        )
        self.assertEqual(rollback["subreaper"]["code"], po.SUBREAPER_REFERENCE_RETAINED)
        self.assertEqual(ownership.state()["depth"], 1)
        self.assertTrue(ownership.active, "the surviving effect lost its subreaper ownership")
        self.assertEqual(po.get_child_subreaper()[0], 1)
        final = held.release()
        self.assertEqual(final["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_the_previous_state_is_restored_when_the_final_reference_is_released(self) -> None:
        ownership = ChildSubreaperOwnership()
        first = ownership.acquire_reference()
        second = ownership.acquire_reference()
        self.assertEqual(second.release()["code"], po.SUBREAPER_REFERENCE_RETAINED)
        self.assertEqual(po.get_child_subreaper()[0], 1)
        final = first.release()
        self.assertEqual(final["code"], po.SUBREAPER_RESTORED)
        self.assertTrue(final["restoration_verified"])
        self.assertEqual(final["restore_observed"], self.before)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_rollback_closes_every_partially_created_descriptor(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        read_fd, write_fd = os.pipe()
        before = _open_descriptor_count()
        evidence = pw._roll_back_failed_start(
            pid=None, sockets=(parent, child), descriptors=(read_fd, write_fd), subreaper=reference
        )
        self.assertEqual(evidence["sockets_closed"], 2)
        self.assertEqual(evidence["descriptors_closed"], 2)
        self.assertEqual(_open_descriptor_count(), before - 4)
        self.assertEqual(ownership.state()["depth"], 0)

    def test_a_rollback_never_addresses_a_process_it_does_not_own(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
        for pid in (0, -1):
            with self.subTest(pid=pid):
                evidence = pw._roll_back_failed_start(
                    pid=pid, sockets=(), descriptors=(), subreaper=reference
                )
                self.assertFalse(evidence["helper_reaped"])
        self.assertEqual(ownership.state()["depth"], 0)

    def test_a_successful_start_transfers_ownership_rather_than_rolling_back(self) -> None:
        fixture = _live(self, script="import sys, time\ntime.sleep(30)\n")
        self.assertTrue(CHILD_SUBREAPER.active, "a started helper holds no ownership")
        self.assertEqual(fixture.helper.subreaper_state["code"], po.SUBREAPER_APPLIED)
        self.assertGreaterEqual(CHILD_SUBREAPER.state()["depth"], 1)


# --- M2-B39: restoration must verify the claimed kernel state -----------------


class SubreaperRestorationStateMachineTests(unittest.TestCase):
    """A restoration claim is a readback, never a request."""

    def setUp(self) -> None:
        self.before = _FlagGuard.install(self)

    def _acquired(self) -> ChildSubreaperOwnership:
        ownership = ChildSubreaperOwnership()
        ownership.acquire()
        return ownership

    def test_a_restore_set_failure_is_never_reported_restored(self) -> None:
        ownership = self._acquired()
        with mock.patch.object(po, "set_child_subreaper", return_value="EPERM"):
            result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_SET_FAILED)
        self.assertFalse(result["restoration_verified"])
        self.assertFalse(result["cleanup_complete"])
        self.assertNotEqual(result["code"], po.SUBREAPER_RESTORED)

    def test_a_restore_readback_failure_is_never_reported_restored(self) -> None:
        ownership = self._acquired()
        with mock.patch.object(po, "get_child_subreaper", return_value=(None, "EPERM")):
            result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_READBACK_FAILED)
        self.assertFalse(result["restoration_verified"])
        self.assertIsNone(result["restore_observed"])

    def test_a_restore_mismatch_of_requested_zero_observed_one_is_refused(self) -> None:
        """The exact audited defect: request 0, read back 1, report RESTORED."""

        ownership = ChildSubreaperOwnership()
        with mock.patch.object(po, "get_child_subreaper", return_value=(0, None)):
            with mock.patch.object(po, "set_child_subreaper", return_value=None):
                # Acquire against a baseline of 0 without touching the kernel.
                with mock.patch.object(
                    po, "get_child_subreaper", side_effect=[(0, None), (1, None)]
                ):
                    ownership.acquire()
        self.assertEqual(ownership.state()["previous_value"], 0)
        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", return_value=(1, None)):
                result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertEqual(result["restore_intended"], 0)
        self.assertEqual(result["restore_observed"], 1)
        self.assertFalse(result["restoration_verified"])
        self.assertFalse(result["cleanup_complete"])
        self.assertIn("still a child subreaper", result["detail"])

    def test_a_restore_mismatch_of_requested_one_observed_zero_is_refused(self) -> None:
        """A controller nested inside an outer subreaper: the baseline is 1."""

        ownership = ChildSubreaperOwnership()
        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", side_effect=[(1, None), (1, None)]):
                ownership.acquire()
        self.assertEqual(ownership.state()["previous_value"], 1)
        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", return_value=(0, None)):
                result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertEqual(result["restore_intended"], 1)
        self.assertEqual(result["restore_observed"], 0)

    def test_a_mismatch_keeps_the_evidence_of_what_is_still_owed(self) -> None:
        ownership = ChildSubreaperOwnership()
        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", side_effect=[(0, None), (1, None)]):
                ownership.acquire()
        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", return_value=(1, None)):
                ownership.release()
        state = ownership.state()
        self.assertEqual(state["previous_value"], 0, "the last evidence of ownership was discarded")
        self.assertFalse(state["cleanup_complete"])
        self.assertFalse(ownership.cleanup_complete)

    def test_a_nested_release_restores_nothing_and_claims_nothing(self) -> None:
        ownership = self._acquired()
        ownership.acquire()
        writes: list[int] = []
        real_set = po.set_child_subreaper

        def recording(value):
            writes.append(int(value))
            return real_set(value)

        with mock.patch.object(po, "set_child_subreaper", recording):
            inner = ownership.release()
        self.assertEqual(inner["code"], po.SUBREAPER_REFERENCE_RETAINED)
        self.assertEqual(writes, [], "an inner release wrote the process-wide flag")
        self.assertEqual(po.get_child_subreaper()[0], 1)
        self.assertEqual(ownership.release()["code"], po.SUBREAPER_RESTORED)

    def test_an_inherited_acquisition_is_discarded_and_never_restored(self) -> None:
        ownership = self._acquired()
        self.addCleanup(ownership.release)
        ownership._owner_pid = os.getpid() + 1_000_000
        writes: list[int] = []
        real_set = po.set_child_subreaper

        def recording(value):
            writes.append(int(value))
            return real_set(value)

        with mock.patch.object(po, "set_child_subreaper", recording):
            result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_INHERITED_DISCARDED)
        self.assertEqual(writes, [], "the child restored a flag it never set")
        self.assertFalse(ownership.active)

    def test_an_inherited_reference_handle_restores_nothing(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
        self.addCleanup(ownership.release)
        reference._holder_pid = os.getpid() + 1_000_000
        writes: list[int] = []
        with mock.patch.object(po, "set_child_subreaper", lambda value: writes.append(int(value))):
            result = reference.release()
        self.assertEqual(result["code"], po.SUBREAPER_INHERITED_DISCARDED)
        self.assertEqual(writes, [])
        self.assertFalse(reference.valid)

    def test_a_repeated_release_returns_the_original_terminal_result(self) -> None:
        for injected, expected in (
            (None, po.SUBREAPER_RESTORED),
            ("EPERM", po.SUBREAPER_RESTORE_SET_FAILED),
        ):
            with self.subTest(result=expected):
                ownership = self._acquired()
                if injected is None:
                    first = ownership.release()
                else:
                    with mock.patch.object(po, "set_child_subreaper", return_value=injected):
                        first = ownership.release()
                self.assertEqual(first["code"], expected)
                second = ownership.release()
                self.assertEqual(second["code"], expected, "the terminal result was overwritten")
                self.assertTrue(second["released_nothing"])
                po.set_child_subreaper(self.before)

    def test_a_release_with_nothing_held_is_already_released(self) -> None:
        ownership = ChildSubreaperOwnership()
        result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_ALREADY_RELEASED)
        self.assertTrue(result["released_nothing"])
        self.assertEqual(result["depth"], 0)

    def test_every_release_result_is_declared(self) -> None:
        self.assertEqual(
            sorted(po.SUBREAPER_RELEASE_RESULTS),
            sorted(
                [
                    po.SUBREAPER_RESTORED,
                    po.SUBREAPER_RESTORE_SET_FAILED,
                    po.SUBREAPER_RESTORE_READBACK_FAILED,
                    po.SUBREAPER_RESTORE_MISMATCH,
                    po.SUBREAPER_REFERENCE_RETAINED,
                    po.SUBREAPER_ALREADY_RELEASED,
                    po.SUBREAPER_INHERITED_DISCARDED,
                ]
            ),
        )

    def test_no_injected_failure_can_produce_a_false_restored_claim(self) -> None:
        """Exhaustive over the failure matrix: RESTORED requires the readback."""

        # The intended restored value is whatever this process's baseline was,
        # so the mismatch injection reads back the value that is never it.
        matrix = (
            ("set_failed", "EPERM", (self.before, None)),
            ("readback_failed", None, (None, "EPERM")),
            ("mismatch", None, (1 - self.before, None)),
        )
        for name, set_result, read_result in matrix:
            with self.subTest(injection=name):
                ownership = self._acquired()
                with mock.patch.object(po, "set_child_subreaper", return_value=set_result):
                    with mock.patch.object(po, "get_child_subreaper", return_value=read_result):
                        result = ownership.release()
                self.assertNotEqual(result["code"], po.SUBREAPER_RESTORED, name)
                self.assertFalse(result["restoration_verified"], name)
                self.assertFalse(result["cleanup_complete"], name)
                po.set_child_subreaper(self.before)


class KernelSubreaperRestorationTests(unittest.TestCase):
    """The real kernel flag, read before and after, with nothing mocked."""

    def test_the_process_state_is_verified_before_and_after_a_real_cycle(self) -> None:
        before, error = po.get_child_subreaper()
        self.assertIsNone(error, "this kernel does not expose PR_GET_CHILD_SUBREAPER")
        ownership = ChildSubreaperOwnership()
        acquired = ownership.acquire()
        try:
            self.assertEqual(acquired["code"], po.SUBREAPER_APPLIED)
            self.assertEqual(acquired["previous_value"], before)
            observed_while_held, held_error = po.get_child_subreaper()
            self.assertIsNone(held_error)
            self.assertEqual(observed_while_held, 1, "the kernel does not agree the flag is set")
            self.assertTrue(ownership.active)
        finally:
            released = ownership.release()
        self.assertEqual(released["code"], po.SUBREAPER_RESTORED)
        self.assertTrue(released["restoration_verified"])
        self.assertEqual(released["restore_intended"], before)
        self.assertEqual(released["restore_observed"], before)
        observed_after, after_error = po.get_child_subreaper()
        self.assertIsNone(after_error)
        self.assertEqual(observed_after, before, "the process-wide flag was not put back")
        self.assertFalse(ownership.active)
        self.assertTrue(ownership.cleanup_complete)

    def test_a_real_helper_leaves_the_flag_exactly_as_it_found_it(self) -> None:
        before, _ = po.get_child_subreaper()
        helper = PrivateMountHelper.start()
        self.assertEqual(po.get_child_subreaper()[0], 1)
        closure = helper.close()
        self.assertEqual(closure["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertTrue(closure["subreaper"]["restoration_verified"])
        self.assertEqual(po.get_child_subreaper()[0], before)

    def test_a_forked_child_does_not_inherit_the_flag(self) -> None:
        """The kernel semantic the discard rule rests on, asserted not assumed."""

        ownership = ChildSubreaperOwnership()
        ownership.acquire()
        try:
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:  # pragma: no cover - child process
                try:
                    os.close(read_fd)
                    value, _ = po.get_child_subreaper()
                    os.write(write_fd, str(value).encode("ascii"))
                    os.close(write_fd)
                finally:
                    os._exit(0)
            os.close(write_fd)
            observed = int(os.read(read_fd, 16))
            os.close(read_fd)
            os.waitpid(pid, 0)
        finally:
            ownership.release()
        self.assertEqual(observed, 0, "PR_SET_CHILD_SUBREAPER was inherited across fork()")


# --- M2-B40: one true global abort deadline -----------------------------------


class CleanupBudgetTests(unittest.TestCase):
    """The primitive that makes a renewal inexpressible."""

    def test_a_grant_can_never_outlive_the_whole(self) -> None:
        budget = CleanupBudget.open(None, total_ms=200, label="whole")
        granted = budget.grant("stage", 10_000)
        self.assertLessEqual(granted.expires_at_ns, budget.deadline.expires_at_ns)

    def test_a_grant_after_exhaustion_is_zero_not_a_new_budget(self) -> None:
        budget = CleanupBudget.open(Deadline.already_expired("whole"), total_ms=30_000, label="w")
        self.assertEqual(budget.grant_seconds("quiescence", 5.0), 0.0)
        self.assertTrue(budget.grant("reap", 5_000).expired)
        self.assertTrue(budget.exhausted)

    def test_the_budget_is_never_renewed_between_stages(self) -> None:
        budget = CleanupBudget.open(None, total_ms=400, label="whole")
        first = budget.grant("a", 10_000)
        time.sleep(0.05)
        second = budget.grant("b", 10_000)
        self.assertLessEqual(second.expires_at_ns, first.expires_at_ns)
        remaining = [entry["budget_remaining_ms"] for entry in budget.grants]
        self.assertEqual(remaining, sorted(remaining, reverse=True))

    def test_the_ledger_records_the_configured_total_and_the_outcome(self) -> None:
        budget = CleanupBudget.open(None, total_ms=1_000, label="whole")
        budget.grant_seconds("quiescence", 5.0)
        budget.note("quiescence", completed=True)
        budget.observe("removal")
        budget.note("removal", completed=False)
        recorded = budget.to_dict()
        self.assertEqual(recorded["configured_total_ms"], 1_000)
        self.assertEqual(recorded["completed_steps"], ["quiescence"])
        self.assertEqual(recorded["incomplete_steps"], ["removal"])
        self.assertFalse(recorded["renewed_after_a_step"])
        self.assertEqual(recorded["clock"], "time.monotonic_ns")
        self.assertIsInstance(recorded["elapsed_ms"], int)

    def test_a_completed_step_can_be_downgraded_but_never_duplicated(self) -> None:
        budget = CleanupBudget.open(None, total_ms=1_000, label="whole")
        budget.note("reap", completed=True)
        budget.note("reap", completed=False)
        recorded = budget.to_dict()
        self.assertEqual(recorded["completed_steps"], [])
        self.assertEqual(recorded["incomplete_steps"], ["reap"])

    def test_the_configured_total_is_the_exact_configured_input(self) -> None:
        """The delegated regression: a 30 000 ms deadline is not 29 999 ms.

        The configured total is the input the caller chose.  Re-deriving it from
        the remaining time reports one millisecond less as soon as any time at
        all has passed between constructing the deadline and opening the budget,
        which is always.
        """

        deadline = Deadline.after_ms(po.ABORT_TOTAL_DEADLINE_MS, "abort")
        time.sleep(0.05)
        budget = CleanupBudget.open(
            deadline, total_ms=po.ABORT_TOTAL_DEADLINE_MS, label="abort_gated_effect"
        )
        recorded = budget.to_dict()
        self.assertEqual(recorded["configured_total_ms"], 30_000)
        self.assertEqual(recorded["default_total_ms"], po.ABORT_TOTAL_DEADLINE_MS)
        self.assertTrue(recorded["caller_supplied_deadline"])
        # How much of that total was already gone is a separate, truthful fact.
        self.assertLess(recorded["remaining_at_entry_ms"], recorded["configured_total_ms"])
        self.assertGreater(recorded["remaining_at_entry_ms"], 0)

    def test_a_deadline_carries_the_duration_it_was_configured_with(self) -> None:
        for milliseconds in (0, 1, 1_500, 30_000):
            with self.subTest(configured_ms=milliseconds):
                self.assertEqual(
                    Deadline.after_ms(milliseconds, "d").configured_ms, milliseconds
                )
        self.assertEqual(Deadline.already_expired("d").configured_ms, 0)
        self.assertEqual(Deadline.after(2.9, "d").configured_ms, 2_900)
        # A capped view keeps the cap the step asked for; what it was granted is
        # recorded separately by the budget.
        whole = Deadline.after_ms(400, "whole")
        self.assertEqual(whole.sub(30_000, "step").configured_ms, 30_000)
        self.assertLessEqual(whole.sub(30_000, "step").expires_at_ns, whole.expires_at_ns)

    def test_a_budget_without_a_caller_deadline_reports_the_module_default(self) -> None:
        budget = CleanupBudget.open(None, total_ms=po.ABORT_TOTAL_DEADLINE_MS, label="whole")
        recorded = budget.to_dict()
        self.assertEqual(recorded["configured_total_ms"], po.ABORT_TOTAL_DEADLINE_MS)
        self.assertFalse(recorded["caller_supplied_deadline"])

    def test_no_recorded_value_is_a_floating_point_number(self) -> None:
        """The durable evidence encoding forbids floats."""

        budget = CleanupBudget.open(None, total_ms=1_000, label="whole")
        budget.grant_seconds("quiescence", 5.0)
        for value in _scalars(budget.to_dict()):
            self.assertNotIsInstance(value, float, budget.to_dict())


def _scalars(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _scalars(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _scalars(item)
    else:
        yield value


class GlobalAbortDeadlineTests(unittest.TestCase):
    """The whole abort operation is bounded by one absolute monotonic instant."""

    def setUp(self) -> None:
        _FlagGuard.install(self)
        self.parent = _FakeCgroupParent()
        self.addCleanup(self.parent.close)

    def _cgroup(self, *, burn_until: Deadline | None = None) -> _RecordingCgroup:
        cgroup = _RecordingCgroup(self.parent.effect(), burn_until=burn_until)
        self.addCleanup(cgroup.close)
        return cgroup

    def _abort(self, fixture, cgroup, deadline: Deadline) -> dict:
        return ps.abort_gated_effect(
            process=fixture.launcher,
            cgroup=cgroup,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "helper lost"
            ),
            reason="deadline-closure",
            deadline=deadline,
        )

    def test_an_already_expired_deadline_at_entry_blocks_on_nothing(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        started = time.monotonic()
        evidence = self._abort(fixture, cgroup, Deadline.already_expired("abort"))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, BOUND_SLACK_SECONDS, "an exhausted budget still blocked")
        self.assertTrue(evidence["deadline_exhausted"])
        self.assertEqual(cgroup.quiescence_timeouts, [0.0], "quiescence got a fresh interval")

    def test_the_deadline_expiring_before_the_helper_rpc_bypasses_it(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        evidence = self._abort(fixture, cgroup, Deadline.already_expired("abort"))
        ownership = evidence["process_ownership"]
        self.assertTrue(ownership["helper_bypassed"], ownership)
        self.assertIn("helper_kill_rpc", ownership["deadline_expirations"])

    def test_the_deadline_expiring_before_the_launcher_reap_claims_no_reap(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        evidence = self._abort(fixture, cgroup, Deadline.already_expired("abort"))
        ownership = evidence["process_ownership"]
        if not evidence["launcher_reaped"]:
            self.assertIn("launcher_reap", ownership["deadline_expirations"])
            self.assertEqual(ownership["launcher_reaper_role"], po.REAPER_NONE)
            self.assertIsNone(ownership["launcher_exit_code"])
            self.assertIn("launcher_reap", evidence["cleanup_budget"]["incomplete_steps"])
        else:
            # A reap that did happen was positively observed, and is attributed.
            self.assertEqual(ownership["launcher_reaper_pid"], os.getpid())

    def test_wait_quiescent_never_receives_a_new_fixed_five_seconds(self) -> None:
        """The exact audited defect, observed at the boundary it crosses."""

        fixture = _live(self)
        whole = Deadline.after_ms(SHORT_ABORT_MS, "abort")
        cgroup = self._cgroup(burn_until=whole)
        self._abort(fixture, cgroup, whole)
        self.assertEqual(len(cgroup.quiescence_timeouts), 1)
        self.assertEqual(
            cgroup.quiescence_timeouts[0],
            0.0,
            "the quiescence stage started a fresh interval after the whole deadline expired",
        )
        self.assertNotEqual(cgroup.quiescence_timeouts[0], ps.ABORT_QUIESCENCE_TIMEOUT_SECONDS)

    def test_wait_quiescent_receives_the_remaining_duration_when_time_is_left(self) -> None:
        fixture = _live(self)
        whole = Deadline.after_ms(30_000, "abort")
        cgroup = self._cgroup()
        self._abort(fixture, cgroup, whole)
        granted = cgroup.quiescence_timeouts[0]
        self.assertGreater(granted, 0.0)
        self.assertLessEqual(granted, ps.ABORT_QUIESCENCE_TIMEOUT_SECONDS)
        self.assertLessEqual(granted, whole.remaining_seconds + ps.ABORT_QUIESCENCE_TIMEOUT_SECONDS)

    def test_the_deadline_expiring_before_removal_still_verifies_what_it_claims(self) -> None:
        fixture = _live(self)
        whole = Deadline.after_ms(SHORT_ABORT_MS, "abort")
        cgroup = self._cgroup(burn_until=whole)
        evidence = self._abort(fixture, cgroup, whole)
        removal = evidence["cgroup_removal"]
        self.assertTrue(evidence["deadline_exhausted"])
        if evidence["effect_cgroup_removed"]:
            self.assertTrue(removal["absence_verified"], "removal was claimed without observation")
            self.assertFalse(removal["residual_path_exists"])
        else:
            self.assertIn("cgroup_removal", evidence["cleanup_budget"]["incomplete_steps"])

    def test_the_deadline_expiring_before_the_subreaper_release_is_recorded(self) -> None:
        fixture = _live(self)
        whole = Deadline.after_ms(SHORT_ABORT_MS, "abort")
        cgroup = self._cgroup(burn_until=whole)
        evidence = self._abort(fixture, cgroup, whole)
        grants = {entry["stage"]: entry for entry in evidence["cleanup_budget"]["stage_grants"]}
        self.assertIn("subreaper_release", grants)
        self.assertTrue(grants["subreaper_release"]["deadline_expired_at_entry"])
        self.assertEqual(grants["subreaper_release"]["granted_ms"], 0)
        release = evidence["subreaper_release"]
        self.assertIsNotNone(release)
        if release["performed"]:
            result = release["result"]
            self.assertIn(result["code"], po.SUBREAPER_RELEASE_RESULTS)
            if result["code"] == po.SUBREAPER_RESTORED:
                self.assertTrue(result["restoration_verified"])

    def test_every_stage_receives_only_the_remaining_time(self) -> None:
        fixture = _live(self)
        whole = Deadline.after_ms(2_000, "abort")
        cgroup = self._cgroup()
        evidence = self._abort(fixture, cgroup, whole)
        grants = evidence["cleanup_budget"]["stage_grants"]
        self.assertTrue(grants)
        for entry in grants:
            self.assertLessEqual(
                entry["granted_ms"],
                max(entry["budget_remaining_ms"], 0) + 50,
                f"stage {entry['stage']} received more than the budget had left",
            )
            self.assertLessEqual(entry["granted_ms"], 2_000 + 50)
        remaining = [entry["budget_remaining_ms"] for entry in grants]
        self.assertEqual(remaining, sorted(remaining, reverse=True), "the budget was renewed")

    def test_the_declared_stages_are_all_present_in_the_ledger(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        evidence = self._abort(fixture, cgroup, Deadline.after_ms(5_000, "abort"))
        stages = {entry["stage"] for entry in evidence["cleanup_budget"]["stage_grants"]}
        for stage in (
            "release_state",
            "process_domain_kill",
            "launcher_terminate_and_reap",
            "descriptor_closure",
            "cgroup_quiescence",
            "cgroup_removal",
            "subreaper_release",
        ):
            self.assertIn(stage, stages, stage)

    def test_the_total_elapsed_time_stays_inside_the_configured_total(self) -> None:
        fixture = _live(self)
        os.kill(fixture.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, fixture.helper.pid)
        cgroup = self._cgroup()
        started = time.monotonic()
        evidence = self._abort(fixture, cgroup, Deadline.after_ms(SHORT_ABORT_MS, "abort"))
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            SHORT_ABORT_MS / 1000.0 + BOUND_SLACK_SECONDS,
            "the whole abort outlived its configured total",
        )
        budget = evidence["cleanup_budget"]
        self.assertTrue(budget["caller_supplied_deadline"])
        self.assertEqual(budget["default_total_ms"], po.ABORT_TOTAL_DEADLINE_MS)
        self.assertEqual(
            budget["configured_total_ms"],
            SHORT_ABORT_MS,
            "the evidence did not report the exact total the caller configured",
        )
        self.assertLessEqual(budget["remaining_at_entry_ms"], SHORT_ABORT_MS)
        self.assertLessEqual(
            budget["elapsed_ms"], SHORT_ABORT_MS + int(BOUND_SLACK_SECONDS * 1000)
        )

    def test_no_successful_field_is_claimed_after_unobserved_exhaustion(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        evidence = self._abort(fixture, cgroup, Deadline.already_expired("abort"))
        self.assertTrue(evidence["deadline_exhausted"])
        ownership = evidence["process_ownership"]
        if not ownership["cgroup_quiescent"]:
            self.assertIn("cgroup_quiescence", evidence["cleanup_budget"]["incomplete_steps"])
        if evidence["cgroup_quiescent"]:
            self.assertTrue(evidence["quiescence"]["membership_readable"])
            self.assertEqual(evidence["quiescence"]["residual_members"], [])
        if evidence["launcher_reaped"]:
            self.assertEqual(ownership["launcher_reaper_pid"], os.getpid())
            self.assertIsNotNone(ownership["launcher_exit_code"])
        self.assertFalse(evidence["cleanup_complete"] and evidence["cleanup_budget"]["incomplete_steps"])

    def test_a_repeated_bounded_cleanup_stays_idempotent(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        first = self._abort(fixture, cgroup, Deadline.after_ms(10_000, "abort"))
        second = self._abort(fixture, cgroup, Deadline.after_ms(10_000, "abort"))
        self.assertTrue(first["launcher_reaped"], first["process_ownership"])
        self.assertTrue(second["launcher_reaped"], "the first reap is still the truth")
        self.assertEqual(
            second["process_ownership"]["launcher_reap_code"], po.REAP_ALREADY_REAPED
        )
        self.assertFalse(second["cgroup_removal"]["removed"], "a second removal was claimed")
        self.assertEqual(
            second["cgroup_removal"]["absence_verified"],
            first["cgroup_removal"]["absence_verified"],
            "the repeated cleanup reported a different disposition",
        )
        self.assertFalse(second["subreaper_release"]["performed"])

    def test_a_repeated_cleanup_with_an_expired_deadline_stays_idempotent(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        self._abort(fixture, cgroup, Deadline.after_ms(10_000, "abort"))
        started = time.monotonic()
        second = self._abort(fixture, cgroup, Deadline.already_expired("abort"))
        self.assertLess(time.monotonic() - started, BOUND_SLACK_SECONDS)
        self.assertTrue(second["launcher_reaped"])
        self.assertEqual(cgroup.quiescence_timeouts[-1], 0.0)

    def test_the_release_truth_survives_a_deadline_exhausted_cleanup(self) -> None:
        fixture = _live(self)
        cgroup = self._cgroup()
        evidence = self._abort(fixture, cgroup, Deadline.already_expired("abort"))
        self.assertEqual(evidence["release"]["release_state"], RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(evidence["release"]["sentinel_claim"], "EXECUTION_OUTCOME_UNKNOWN")

    def test_a_legacy_launcher_wait_is_bounded_by_the_same_budget(self) -> None:
        """A launcher object with no ownership interface is still bounded."""

        class _LegacyLauncher:
            def __init__(self) -> None:
                self.waits: list[float] = []

            def kill(self) -> None:
                return None

            def wait(self, timeout=None):
                self.waits.append(float(timeout))
                raise TimeoutError("never exits")

            def poll(self):
                return None

        legacy = _LegacyLauncher()
        evidence = ps.abort_gated_effect(
            process=legacy,
            cgroup=None,
            descriptors=(),
            release_outcome=None,
            reason="legacy",
            deadline=Deadline.after_ms(300, "abort"),
        )
        self.assertTrue(legacy.waits, "the legacy path never waited")
        self.assertLessEqual(legacy.waits[0], 0.35)
        self.assertLess(legacy.waits[0], ps.CAPSULE_TEARDOWN_TIMEOUT_SECONDS)
        self.assertFalse(evidence["launcher_reaped"])

    def test_a_legacy_launcher_wait_is_skipped_once_nothing_remains(self) -> None:
        class _LegacyLauncher:
            def __init__(self) -> None:
                self.waits: list[float] = []

            def kill(self) -> None:
                return None

            def wait(self, timeout=None):  # pragma: no cover - must not be reached
                self.waits.append(float(timeout))
                raise TimeoutError("never exits")

            def poll(self):
                return None

        legacy = _LegacyLauncher()
        started = time.monotonic()
        ps.abort_gated_effect(
            process=legacy,
            cgroup=None,
            descriptors=(),
            release_outcome=None,
            reason="legacy-expired",
            deadline=Deadline.already_expired("abort"),
        )
        self.assertLess(time.monotonic() - started, BOUND_SLACK_SECONDS)
        self.assertEqual(legacy.waits, [], "a blocking wait started with nothing left")


class BoundedHelperShutdownTests(unittest.TestCase):
    """Helper shutdown spends one instant, not one per step."""

    def setUp(self) -> None:
        _FlagGuard.install(self)

    def test_a_shutdown_is_bounded_by_a_caller_supplied_deadline(self) -> None:
        """A helper that is alive, stopped and silent still costs one bound."""

        helper = PrivateMountHelper.start()
        os.kill(helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, helper.pid)
        whole_ms = po.HELPER_COOPERATIVE_EXIT_DEADLINE_MS + 1_000
        started = time.monotonic()
        closure = helper.close(deadline=Deadline.after_ms(whole_ms, "bounded_shutdown"))
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            whole_ms / 1000.0 + BOUND_SLACK_SECONDS,
            "a stopped helper's shutdown outlived the caller's deadline",
        )
        self.assertFalse(closure["graceful_shutdown"], "a stopped helper answered")
        self.assertTrue(closure["reaped"], "the stopped helper was not killed and reaped")
        self.assertEqual(closure["subreaper"]["code"], po.SUBREAPER_RESTORED)

    def test_the_cooperative_steps_cannot_spend_the_forced_reaps_share(self) -> None:
        """The guarantee is the kill-and-reap; the cooperative steps are not it."""

        import inspect

        self.assertLess(
            po.HELPER_COOPERATIVE_EXIT_DEADLINE_MS,
            po.HELPER_SHUTDOWN_DEADLINE_MS,
            "the cooperative prefix can consume the whole shutdown deadline",
        )
        source = inspect.getsource(PrivateMountHelper.close)
        self.assertEqual(
            source.count("Deadline.after_ms"), 1, "a shutdown step started a fresh deadline"
        )
        self.assertIn('whole.sub(HELPER_REAP_DEADLINE_MS, "helper_forced_reap")', source)

    def test_a_repeated_close_reports_the_first_one(self) -> None:
        helper = PrivateMountHelper.start()
        first = helper.close()
        second = helper.close()
        self.assertFalse(first["already_closed"])
        self.assertTrue(second["already_closed"])
        self.assertEqual(first["subreaper"]["code"], po.SUBREAPER_RESTORED)

    def test_a_helper_reaped_by_the_controller_releases_its_ownership(self) -> None:
        before, _ = po.get_child_subreaper()
        fixture = _LiveLauncher()
        self.addCleanup(fixture.close)
        self.assertTrue(CHILD_SUBREAPER.active)
        fixture.helper.terminate_and_reap(
            deadline=Deadline.after_ms(po.HELPER_REAP_DEADLINE_MS, "reap")
        )
        release = fixture.launcher.release_owned_subreaper(Deadline.after_ms(1_000, "release"))
        self.assertTrue(release["performed"], release)
        self.assertEqual(release["result"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(po.get_child_subreaper()[0], before)
        repeated = fixture.launcher.release_owned_subreaper()
        self.assertFalse(repeated["performed"], "a second release was performed")

    def test_a_live_helper_keeps_its_ownership(self) -> None:
        fixture = _live(self)
        release = fixture.launcher.release_owned_subreaper(Deadline.after_ms(1_000, "release"))
        self.assertFalse(release["performed"], release)
        self.assertIn("alive", release["reason"])
        self.assertTrue(CHILD_SUBREAPER.active)


def _resume(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGCONT)
    except OSError:
        pass


# --- closure artifacts --------------------------------------------------------


CURRENT_VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
CLOSURE_REPORT = IMPLEMENTATION / "M2_SUBREAPER_DEADLINE_CLOSURE_REPORT.json"
LIFECYCLE_REPAIR_REPORT = IMPLEMENTATION / "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
STARTING_COMMIT = "c30bf3d38445f59271b61ad4db8520ed053af281"
BRANCH = "paired-runner/m2-subreaper-deadline-closure"
QUALIFICATION_MODULES = (
    "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
    "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
    "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
    "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ClosureArtifactCoherenceTests(unittest.TestCase):
    """The closure report, the current validation report and the matrix agree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _load(CURRENT_VALIDATION_REPORT)
        cls.closure = _load(CLOSURE_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)

    def test_the_closure_report_declares_the_bounded_findings(self) -> None:
        self.assertEqual(
            self.closure["bounded_findings"], ["M2-B37", "M2-B38", "M2-B39", "M2-B40"]
        )
        self.assertEqual(self.closure["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.closure["branch"], BRANCH)
        self.assertTrue(self.closure["sole_parent_required"])
        self.assertNotIn("ending_commit", self.closure)
        self.assertEqual(self.closure["schema_version"], 1)
        self.assertEqual(
            self.closure["schema_id"], "admissible.paired_runner.m2.subreaper_deadline_closure_report"
        )

    def test_the_current_validation_report_points_at_this_closure(self) -> None:
        self.assertTrue(self.report["is_current_validation_report"])
        self.assertEqual(self.report["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.report["branch"], BRANCH)
        self.assertEqual(
            self.report["final_repair_report"],
            "implementation/M2_SUBREAPER_DEADLINE_CLOSURE_REPORT.json",
        )
        self.assertEqual(self.report["current_closure_key"], "m2_subreaper_deadline_closure")

    def test_the_independent_audit_is_recorded_verbatim(self) -> None:
        self.assertEqual(
            self.closure["independent_audit_sha256"],
            "198afbec4543c06a43d8a7edf79cb4fa83d69a622f7e798b64fa74b54dec0f3e",
        )
        self.assertEqual(
            self.closure["independent_audit_verdicts"],
            ["M2_PROTOCOL_LIFECYCLE_INDEPENDENT_CLOSURE_REFUSED", "MILESTONE_3_NOT_PERMITTED"],
        )
        self.assertEqual(
            self.report["independent_audit_sha256"], self.closure["independent_audit_sha256"]
        )
        self.assertEqual(
            self.report["independent_audit_verdicts"], self.closure["independent_audit_verdicts"]
        )

    def test_the_prior_transcript_is_never_offered_as_qualifying_this_code(self) -> None:
        prior = self.report["prior_physical_qualification"]
        self.assertEqual(prior["qualified_commit"], STARTING_COMMIT)
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertIn("does not qualify", prior["scope"])
        self.assertEqual(prior["transcript"], "Ran 210 tests in 92.979s\n\nOK")
        self.assertTrue(self.closure["delegated_physical_qualification"][
            "prior_transcripts_do_not_qualify_modified_code"
        ])

    def test_the_physical_qualification_state_is_internally_coherent(self) -> None:
        """Either a complete transcript, or an explicit absence.  Never both."""

        closure = self.report[self.report["current_closure_key"]]
        run = closure["delegated_run"]
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
            self.assertEqual(self.report["terminal_verdict"], "M2_SUBREAPER_DEADLINE_CLOSURE_VERIFIED")
        else:
            self.assertFalse(claimed, "an unperformed run may not be claimed as qualification")
            self.assertIsNone(run["executed"])
            self.assertEqual(run["exact_result"], "")
            self.assertEqual(
                self.report["terminal_verdict"],
                "M2_SUBREAPER_DEADLINE_OPERATOR_QUALIFICATION_REQUIRED",
            )
        self.assertEqual(run, self.closure["delegated_physical_qualification"]["run"])
        self.assertEqual(run["expected_modules"], list(QUALIFICATION_MODULES))

    def test_the_expected_delegated_total_matches_the_four_modules(self) -> None:
        run = self.report[self.report["current_closure_key"]]["delegated_run"]
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
            (
                "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
                "m2_subreaper_deadline_closure_module",
            ),
        ):
            loader = unittest.defaultTestLoader.loadTestsFromName(module)
            self.assertEqual(loader.countTestCases(), counts[field], module)
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_legacy_pre_b25"]
            + counts["m2_b25_topology_module"]
            + counts["m2_b25_final_failclosed_module"]
            + counts["m2_final_protocol_lifecycle_module"]
            + counts["m2_subreaper_deadline_closure_module"],
        )

    def test_the_closure_report_records_every_declared_deadline(self) -> None:
        deadlines = self.closure["global_abort_deadline_model"]["deadlines_ms"]
        for name, value in deadlines.items():
            self.assertEqual(getattr(po, name), value, name)
        self.assertEqual(deadlines["ABORT_TOTAL_DEADLINE_MS"], 30_000)

    def test_the_closure_report_declares_the_restoration_state_machine(self) -> None:
        machine = self.closure["restoration_state_machine"]
        self.assertEqual(sorted(machine["results"]), sorted(po.SUBREAPER_RELEASE_RESULTS))
        self.assertEqual(sorted(machine["acquisition_refusals"]), sorted(po.SUBREAPER_ACQUISITION_REFUSALS))
        self.assertFalse(machine["restored_without_readback_possible"])

    def test_the_closure_report_declares_the_acquisition_gate_and_rollback(self) -> None:
        gate = self.closure["acquisition_gate"]
        self.assertEqual(gate["fork_primitive"], "admissible.paired_runner.private_workspace._fork")
        self.assertTrue(gate["fork_unreachable_without_proved_ownership"])
        rollback = self.closure["fork_failure_rollback"]
        self.assertTrue(rollback["idempotent"])
        self.assertEqual(
            rollback["order"],
            ["DESTROY_AND_REAP_THE_CHILD", "CLOSE_EVERY_DESCRIPTOR", "RELEASE_THE_ACQUISITION_ONCE"],
        )

    def test_the_verdicts_match_the_requirement_matrix(self) -> None:
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

    def test_no_milestone_3_requirement_was_closed(self) -> None:
        for row in self.matrix["requirements"]:
            if row.get("milestone") in {3, "3"}:
                self.assertNotIn(
                    row["current_status"],
                    {"VERIFIED_INTEGRATION", "VERIFIED_INSTALLED_PATH"},
                    row["requirement_id"],
                )
        for row in self.report["requirement_dispositions"]:
            self.assertNotEqual(row["status"], "VERIFIED_INSTALLED_PATH")

    def test_independent_acceptance_and_installed_path_remain_unclaimed(self) -> None:
        self.assertFalse(self.closure["independent_acceptance_claimed"])
        self.assertFalse(self.closure["installed_path_qualification_claimed"])
        self.assertFalse(self.report["independent_validation"]["independent_acceptance_claimed"])
        self.assertFalse(
            self.report["independent_validation"]["installed_path_qualification_claimed"]
        )

    def test_the_historical_reports_are_untouched(self) -> None:
        for name in (
            "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json",
            "M2_B25_FINAL_FAILCLOSED_REPAIR_REPORT.json",
            "M2_B25_CGROUP_TOPOLOGY_REPAIR_REPORT.json",
            "M2_FOURTH_CRITICAL_REPAIR_REPORT.json",
            "M2_VALIDATION_REPORT_HISTORICAL_FOURTH_REPAIR.json",
        ):
            with self.subTest(artifact=name):
                original = subprocess.run(
                    ["git", "show", f"{STARTING_COMMIT}:implementation/{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), original)

    def test_the_superseded_current_report_is_preserved_in_git(self) -> None:
        """The bytes this closure replaces are recoverable, and it says where."""

        superseded = self.report["supersedes_prior_current_report"]
        self.assertEqual(superseded["commit"], STARTING_COMMIT)
        self.assertEqual(superseded["path"], "implementation/M2_VALIDATION_REPORT.json")
        committed = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/M2_VALIDATION_REPORT.json"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        import hashlib

        self.assertEqual(superseded["sha256"], hashlib.sha256(committed).hexdigest())
        self.assertEqual(
            json.loads(committed.decode("utf-8"))["terminal_verdict"],
            "M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_VERIFIED",
        )

    def test_the_b26_and_b27_closures_are_preserved_not_reopened(self) -> None:
        self.assertIn("PRESERVED_NOT_REOPENED", self.closure["b26_disposition"])
        self.assertIn("PRESERVED_NOT_REOPENED", self.closure["b27_disposition"])

    def test_the_accepted_behaviour_is_declared_preserved(self) -> None:
        preserved = self.closure["accepted_behaviour_preserved"]
        for statement in (
            "manager-leaf/sibling-effect cgroup-v2 topology",
            "finite pids.max=64 and memory.max=2147483648",
            "child membership verification before normal release",
            "controller-owned per-RPC deadlines",
            "PR_SET_CHILD_SUBREAPER + pidfd observation architecture",
            "typed cgroup.procs reads",
        ):
            self.assertIn(statement, preserved, statement)


class InjectedTopologyFailureIsolationTests(unittest.TestCase):
    """A cached topology contradiction must not outlive the test that made it.

    The delegated regression this closes: a nominal effect that had always
    completed began returning a FAILED receipt once a fourth qualification
    module put a nominal delegated effect *after* the lifecycle module's
    injected-membership-failure test.  M2-B29 makes such a contradiction fail
    closed and cache the failure process-wide, permanently and by design -- so
    the injection followed every later effect in the same interpreter and
    refused it before exec with ``cgroup_membership_unverified``.

    The production behaviour is correct and is not weakened.  What is repaired
    is the leak: the test that injects a contradiction restores the caches it
    poisoned.
    """

    def _healthy_topology(self) -> rl.CgroupTopology:
        return rl.CgroupTopology(
            initialized=True,
            code=rl.TOPOLOGY_INITIALIZED,
            detail="healthy",
            unified_root="/sys/fs/cgroup",
            unified_cgroup="/svc",
            effect_parent="/sys/fs/cgroup/svc",
            manager_leaf="/sys/fs/cgroup/svc/mgr",
            available_controllers=("memory", "pids"),
            enabled_controllers=("memory", "pids"),
            owner_pid=os.getpid(),
            effect_parent_identity=None,
            manager_leaf_identity=None,
            owner_unified_path="/svc/mgr",
            cgroup2_required=False,
        )

    def _broken_topology(self) -> rl.CgroupTopology:
        return rl.CgroupTopology(
            initialized=False,
            code="MANAGER_MEMBERSHIP_UNREADABLE",
            detail="injected",
            unified_root="/sys/fs/cgroup",
            unified_cgroup="/svc",
            effect_parent=None,
            manager_leaf=None,
            available_controllers=(),
            enabled_controllers=(),
            owner_pid=os.getpid(),
            effect_parent_identity=None,
            manager_leaf_identity=None,
            owner_unified_path=None,
            cgroup2_required=False,
        )

    def _available_delegation(self) -> CgroupDelegation:
        return CgroupDelegation(
            available=True,
            detail="a delegated host",
            unified_root="/sys/fs/cgroup",
            delegated_path="/sys/fs/cgroup/svc",
            controllers=("memory", "pids"),
            code=rl.TOPOLOGY_INITIALIZED,
            manager_leaf="/sys/fs/cgroup/svc/mgr",
            enabled_controllers=("memory", "pids"),
        )

    def _seed_delegated_host(self) -> None:
        """Stand in for a delegated host, so this runs anywhere.

        The revalidation in ``cgroup_delegation`` is the production one; only
        the kernel-facing topology derivation is stood in for, because an
        undelegated development host cannot produce an initialized topology and
        the property under test is the *cache lifecycle*, not the derivation.
        """

        ps._DELEGATION_CACHE = self._available_delegation()
        ps._DELEGATION_PID = os.getpid()
        rl._TOPOLOGY = self._healthy_topology()

    def _healthy_kernel(self):
        return mock.patch.object(
            ps, "initialize_cgroup_topology", return_value=self._healthy_topology()
        )

    def _contradicting_kernel(self):
        return mock.patch.object(
            ps, "initialize_cgroup_topology", return_value=self._broken_topology()
        )

    def test_an_injected_failure_poisons_the_process_wide_cache_permanently(self) -> None:
        """The mechanism, asserted rather than assumed."""

        guard_process_wide_cgroup_caches(self)
        self._seed_delegated_host()
        with self._healthy_kernel():
            self.assertTrue(ps.cgroup_delegation().available)
        with self._contradicting_kernel():
            poisoned = ps.cgroup_delegation()
        self.assertFalse(poisoned.available, "the contradiction did not fail closed")
        # The injection is gone, the kernel is healthy again -- and the cached
        # refusal is still returned, because it is never re-bootstrapped.
        with self._healthy_kernel():
            after = ps.cgroup_delegation()
        self.assertFalse(
            after.available,
            "the cached failure was silently re-bootstrapped; M2-B29 forbids that",
        )

    def test_the_guard_restores_what_the_injection_poisoned(self) -> None:
        guard_process_wide_cgroup_caches(self)
        self._seed_delegated_host()
        with self._healthy_kernel():
            self.assertTrue(ps.cgroup_delegation().available)

        outer = self

        class _Injecting(unittest.TestCase):
            def runTest(inner) -> None:  # noqa: N805 - unittest fixture protocol
                guard_process_wide_cgroup_caches(inner)
                with outer._contradicting_kernel():
                    inner.assertFalse(ps.cgroup_delegation().available)

        result = _Injecting().run()
        self.assertTrue(result.wasSuccessful(), result.errors or result.failures)
        with self._healthy_kernel():
            restored = ps.cgroup_delegation()
        self.assertTrue(
            restored.available,
            "the injected contradiction outlived the test that injected it: "
            f"code={restored.code!r} detail={restored.detail!r}",
        )
        self.assertTrue(rl._TOPOLOGY.initialized)

    def test_every_delegated_class_that_can_inject_guards_its_caches(self) -> None:
        """The guard is registered where a contradiction can be produced."""

        import inspect

        for module_name, class_name in (
            (
                "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
                "DelegatedProtocolLifecycleTests",
            ),
            (
                "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
                "MembershipFailClosedCallerTests",
            ),
            (
                "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
                "DelegatedSubreaperDeadlineTests",
            ),
        ):
            with self.subTest(cls=f"{module_name}.{class_name}"):
                module = __import__(module_name, fromlist=[class_name])
                setup = inspect.getsource(getattr(module, class_name).setUp)
                self.assertIn("guard_process_wide_cgroup_caches", setup)


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

    def test_the_boundary_audit_declares_every_frontier_uncrossed(self) -> None:
        audit = _load(CLOSURE_REPORT)["milestone_3_boundary_audit"]
        for boundary, crossed in audit.items():
            self.assertFalse(crossed, boundary)
        self.assertIn("milestone_3_permitted", audit)
        self.assertIn("provider_transport_started", audit)
        self.assertIn("owner_authority_started", audit)

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


class DelegatedSubreaperDeadlineTests(unittest.TestCase):
    """Physical qualification of the four closures on a real cgroup v2 subtree."""

    @classmethod
    def setUpClass(cls) -> None:
        if REQUIRE_DELEGATED and not DELEGATION.available:
            raise AssertionError(
                "ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1 but no delegated cgroup v2 "
                f"topology is available: {DELEGATION.detail}"
            )

    def setUp(self) -> None:
        guard_process_wide_cgroup_caches(self)

    def _require_live_delegation(self) -> None:
        """A nominal effect needs a live topology, not merely a delegated host.

        The process-wide delegation cache is permanently poisoned by any
        topology contradiction (M2-B29), including one an earlier test injected.
        Asserting it here separates "this controller has no usable cgroup
        topology right now" from "the nominal effect path is broken", which are
        different defects and were previously reported as the same failure.
        """

        delegation = ps.cgroup_delegation()
        self.assertTrue(
            delegation.available,
            "the process-wide delegation cache is not usable before this effect: "
            f"code={delegation.code!r} detail={delegation.detail!r}; "
            f"topology_initialized={getattr(rl._TOPOLOGY, 'initialized', None)!r}",
        )

    def test_the_no_false_green_variable_forbids_skipping(self) -> None:
        if REQUIRE_DELEGATED:
            self.assertTrue(DELEGATION.available, DELEGATION.detail)
            self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        else:
            self.skipTest("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP is not set")

    @delegated
    def test_an_acquisition_failure_refuses_the_whole_effect_before_any_process(self) -> None:
        """M2-B37 physically: the production effect path refuses, not forks."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        before, _ = po.get_child_subreaper()
        harness = _Harness(run_id="run-b37-physical")
        self.addCleanup(harness.close)
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(po, "set_child_subreaper", return_value="EPERM"):
            with mock.patch.object(pw, "_fork", forked):
                outcome = harness.command(SENTINEL_SCRIPT)
        self.assertFalse(forked.called, "the effect forked without proved ownership")
        self.assertNotEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup was left behind")
        self.assertEqual(po.get_child_subreaper()[0], before)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)

    @delegated
    def test_a_fork_failure_leaves_no_ownership_process_or_cgroup(self) -> None:
        """M2-B38 physically, through the production effect path."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        before, _ = po.get_child_subreaper()
        before_children = _child_pids()
        harness = _Harness(run_id="run-b38-physical")
        self.addCleanup(harness.close)
        with mock.patch.object(pw, "_fork", side_effect=OSError(errno.EAGAIN, "EAGAIN")):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertNotEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertEqual(po.get_child_subreaper()[0], before, "the flag survived a failed fork")
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertTrue(_await(lambda: _child_pids() == before_children, 5.0))
        self.assertEqual(_effect_cgroups(parent), [])

    @delegated
    def test_a_wedged_effect_aborts_inside_the_configured_global_bound(self) -> None:
        """M2-B40 physically: a real wedged helper and a real cgroup kill domain."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        parent = Path(DELEGATION.delegated_path)
        before, _ = po.get_child_subreaper()
        fixture = _LiveLauncher()
        self.addCleanup(fixture.close)
        bounds = ResourceBounds.for_timeout(1000)
        cgroup = EffectCgroup(DELEGATION, bounds, f"closure-{os.getpid()}")
        self.assertTrue(cgroup.create(), cgroup.create_error)
        self.addCleanup(cgroup.close)
        self.assertTrue(cgroup.attach_and_verify(fixture.launcher.pid), cgroup.attach_error)
        recording = _RecordingCgroup(cgroup)

        fixture.launcher.release()
        self.assertTrue(_await(lambda: fixture.executed, 15.0), "the gated image never ran")
        # Deliberately wedged: alive, scheduled out, and silent.
        os.kill(fixture.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, fixture.helper.pid)

        started = time.monotonic()
        evidence = ps.abort_gated_effect(
            process=fixture.launcher,
            cgroup=recording,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "wedged helper"
            ),
            reason="physical-wedged-abort",
            deadline=Deadline.after_ms(po.ABORT_TOTAL_DEADLINE_MS, "abort"),
        )
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            po.ABORT_TOTAL_DEADLINE_MS / 1000.0 + BOUND_SLACK_SECONDS,
            "the whole abort outlived its one configured total",
        )
        budget = evidence["cleanup_budget"]
        self.assertEqual(budget["configured_total_ms"], po.ABORT_TOTAL_DEADLINE_MS)
        self.assertFalse(budget["renewed_after_a_step"])
        self.assertLessEqual(
            recording.quiescence_timeouts[0], ps.ABORT_QUIESCENCE_TIMEOUT_SECONDS
        )
        ownership = evidence["process_ownership"]
        self.assertTrue(ownership["helper_bypassed"], ownership)
        self.assertTrue(evidence["launcher_exit_observed"], ownership)
        self.assertTrue(evidence["launcher_reaped"], ownership)
        self.assertEqual(evidence["launcher_reaper_role"], REAPER_TRUSTED_CONTROLLER)
        self.assertEqual(evidence["launcher_reaper_pid"], os.getpid())
        self.assertTrue(evidence["cgroup_quiescent"], evidence["quiescence"])
        self.assertTrue(evidence["effect_cgroup_removed"], evidence["cgroup_removal"])
        self.assertTrue(evidence["subreaper_release"]["performed"], evidence["subreaper_release"])
        self.assertEqual(
            evidence["subreaper_release"]["result"]["code"], po.SUBREAPER_RESTORED
        )
        self.assertEqual(po.get_child_subreaper()[0], before, "the process-wide flag was left set")
        self.assertFalse(po.process_is_zombie(fixture.launcher.pid))
        self.assertFalse(po.process_is_zombie(fixture.helper.pid))
        self.assertEqual(_effect_cgroups(parent), [])

    @delegated
    def test_a_nominal_effect_still_completes_and_restores_the_flag(self) -> None:
        """The accepted nominal path is unchanged by all four closures."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        before, _ = po.get_child_subreaper()
        self._require_live_delegation()
        harness = _Harness(run_id="run-nominal-closure")
        self.addCleanup(harness.close)
        started = time.monotonic()
        outcome = harness.command(SENTINEL_SCRIPT)
        elapsed = time.monotonic() - started
        self.assertEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(_effect_cgroups(parent), [])
        self.assertEqual(po.get_child_subreaper()[0], before)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertLess(elapsed, 60.0, "nominal latency was materially degraded")

    @delegated
    def test_the_controller_leaves_no_owned_process_descriptor_or_ownership(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        before, error = po.get_child_subreaper()
        self.assertIsNone(error)
        before_descriptors = _open_descriptor_count()
        before_children = _child_pids()
        fixture = _LiveLauncher()
        self.assertTrue(CHILD_SUBREAPER.active, "the helper did not take subreaper ownership")
        launcher_pid = fixture.launcher.pid
        helper_pid = fixture.helper.pid
        fixture.close()
        self.assertEqual(po.get_child_subreaper()[0], before, "the process-wide flag was left set")
        self.assertFalse(CHILD_SUBREAPER.active)
        self.assertTrue(CHILD_SUBREAPER.cleanup_complete)
        self.assertFalse(po.process_is_zombie(launcher_pid))
        self.assertFalse(po.process_is_zombie(helper_pid))
        self.assertTrue(_await(lambda: _child_pids() == before_children, 5.0))
        self.assertLessEqual(_open_descriptor_count(), before_descriptors)


if __name__ == "__main__":
    unittest.main()
