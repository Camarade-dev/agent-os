"""M2 process-owner and cleanup-propagation closure: B45, B46, B47, B48, M49.

Each finding is closed by making an untrue statement impossible to produce.

M2-B45 -- one process owns one flag
    ``PR_SET_CHILD_SUBREAPER`` is a single flag on a single process, but the
    *active* ownership of it -- depth, baseline, owner PID, applied bit, and the
    lock serialising them -- was a field of whichever
    :class:`ChildSubreaperOwnership` happened to be constructed.  Two objects
    could therefore each own the one flag: the second read the first one's
    activation back as its own baseline, and the first one's release put the
    flag underneath an object that went on reporting active ownership, depth 1,
    a valid reference and state APPLIED over a flag the kernel had cleared.
    There is now exactly one active ownership record per process, every object
    is a handle onto it, and a reference is valid only while the activation it
    was cut from is still the live one.

M2-B46 -- a failed start is complete when it is settled, not when it is tried
    ``_UnsettledFailedStart.cleanup_complete`` was ``reaped and released``, so a
    retry that reaped the exact child and received RESTORE_MISMATCH,
    RESTORE_SET_FAILED or RESTORE_READBACK_FAILED from its single release still
    reported the cleanup complete and deleted the only registry entry -- the
    only remaining handle to the settlement that could have ended it.
    Completion now requires the reap, the single release, a positively settled
    restoration, and no outstanding process-wide debt.

M2-B47 -- a retryable cleanup must be able to progress
    After a helper reap and an unsettled release, ``PrivateMountHelper.close``
    reported ``cleanup_retryable=true`` for ever: the reference was spent, the
    reap was done, and no production caller ever invoked the process-wide
    settlement, so every later call performed nothing and returned the same
    unfinished answer.  ``close`` now attempts that settlement, becomes terminal
    only on an exact baseline readback, and names the operation that a retry
    would perform.

M2-B48 -- incomplete cleanup must outlive the frame that detects it
    Every object could return incomplete cleanup evidence and the production
    call chain dropped all of it: ``BoundRuntime.close()`` returned into a
    ``finally`` that ignored it, ``_EffectPreparation.close()`` returned
    ``None``, ``_execute_permitted_effect`` never looked,
    ``EffectExecutionOutcome`` had nowhere to carry it, and
    ``PrivateExecutionView.materialize`` discarded its helper's closure on the
    exception path.  A PID-bound process registry now retains every unresolved
    retry handle under a deterministic id, refuses new effects at capacity, and
    drains boundedly; the evidence travels the whole chain; and a command that
    completed inside a view whose cleanup did not is classified rather than
    reported green.

M2-M49 -- a current report may not overstate its own closure
    The current artifacts claimed process-wide active ownership, retryable
    failed-start cleanup, a helper retry that could settle a restoration, and
    ``_EffectPreparation.close`` propagating incomplete cleanup.  The semantic
    tests here reject each claim unless the live code exhibits it.

Deterministic tests drive real ``prctl`` calls, real forked helpers, real
zombies, real private views, the real shared effect substrate, and injected
kernel failures.  Delegated physical tests run the production path inside a real
``Delegate=yes`` cgroup v2 subtree and, under
``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
import dataclasses
import gc
import inspect
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.paired_runner import effects as ef  # noqa: E402
from admissible.paired_runner import private_workspace as pw  # noqa: E402
from admissible.paired_runner import process_ownership as po  # noqa: E402
from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner import runtime_binding as rb  # noqa: E402
from admissible.paired_runner.private_workspace import (  # noqa: E402
    CleanupRegistrySaturated,
    PrivateExecutionView,
    PrivateMountHelper,
    PrivateWorkspaceError,
)
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    ChildSubreaperOwnership,
    ChildSubreaperUnavailable,
    Deadline,
)
from admissible.paired_runner.resource_limits import probe_cgroup_delegation  # noqa: E402

DELEGATION = probe_cgroup_delegation()
REQUIRE_DELEGATED = os.environ.get("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP") == "1"

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
    guard_process_wide_cgroup_caches,
    guard_process_wide_cleanup_registry,
    guard_process_wide_restoration_debt,
    guard_process_wide_subreaper_ownership,
)
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import SharedEffectSubstrate, WorkspaceBinding  # noqa: E402
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = REPOSITORY_ROOT / "implementation"

#: A retry budget long enough that a real kill, reap and settlement always fit.
RETRY_BUDGET_MS = 5_000
#: Generous on purpose: the property under test is finiteness, not latency.
BOUND_SLACK_SECONDS = 10.0

SENTINEL_SCRIPT = "open('sentinel.txt', 'w').write('the command executed')\n"


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


def capsule(test):
    """A test that launches the real capsule.  Never skipped under the variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        CAPSULE_READY.available, f"no capsule on this host: {CAPSULE_READY.probe_detail}"
    )(test)


# --- shared fixtures ----------------------------------------------------------


class _ProcessGuard:
    """Put back every process-wide fact a test in this module can disturb.

    Four of them are genuinely process-wide: the child-subreaper flag, the
    M2-B42 restoration-debt latch, the M2-B45 active ownership record, and the
    M2-B48 cleanup registry.  Each is recorded on entry and restored on exit,
    including when an assertion fails, because a test that leaves any of them
    changed decides the outcome of every test after it.

    The flag is then *normalised to zero* for the duration of the test.  The
    audited reproduction is stated over a baseline of 0 -- "baseline 0, object A
    acquires, object B acquires, A releases" -- and an injected restoration
    failure has to be able to tell an acquisition's write of 1 apart from a
    restoration's write of the baseline, which it cannot do when the baseline
    happens to be 1.  Another module in this suite deliberately simulates an
    acquisition inherited across fork and therefore restores nothing, so the
    ambient flag genuinely can be 1 here.  Whatever was found is written back on
    exit; normalising decides nothing about the code under test, it only makes
    the baseline a stated fact rather than an inherited one.
    """

    @staticmethod
    def install(test: unittest.TestCase) -> int:
        before, error = po.get_child_subreaper()
        test.assertIsNone(error, "this kernel does not expose PR_GET_CHILD_SUBREAPER")
        guard_process_wide_restoration_debt(test)
        guard_process_wide_subreaper_ownership(test)
        guard_process_wide_cleanup_registry(test)

        def restore() -> None:
            po.set_child_subreaper(int(before or 0))

        test.addCleanup(restore)
        # A leaked *reference* would be a different matter: it would mean an
        # earlier test still holds ownership, and normalising over it would hide
        # that rather than isolate this test from it.
        test.assertEqual(
            po.process_active_ownership()["depth"],
            0,
            "an earlier test left an outstanding process-wide subreaper reference",
        )
        po.restore_process_ownership({"active": po._ActiveOwnership().__dict__, "debt": None})
        test.assertIsNone(po.set_child_subreaper(0), "PR_SET_CHILD_SUBREAPER(0) failed")
        observed, error = po.get_child_subreaper()
        test.assertEqual(observed, 0, f"the baseline could not be normalised: {error}")
        return 0


def _await(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _child_pids() -> list[int]:
    try:
        raw = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text(encoding="ascii")
    except OSError:  # pragma: no cover - CONFIG_PROC_CHILDREN absent
        return []
    return sorted(int(value) for value in raw.split())


def _open_descriptor_count() -> int:
    try:
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))
    except OSError:  # pragma: no cover - /proc is part of the platform contract
        return -1


def _resume(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGCONT)
    except OSError:
        pass


def _reap_quietly(pid: int) -> None:
    if pid <= 0:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass


def _close_quietly(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


class _NoSignal:
    """Suppress exactly the SIGKILL a bounded cleanup would send.

    A stopped helper that is killed dies, and a single non-blocking ``waitpid``
    after the kill would resolve by a race rather than by the property under
    test.  Suppressing the signal makes the outcome a fact -- the helper is
    genuinely still there and genuinely unreaped -- with the reap left real.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def __call__(self, pid: int, signal_number: int) -> dict:
        self.calls.append((int(pid), int(signal_number)))
        return {"pid": pid, "signal": int(signal_number), "delivered": False, "error": "SUPPRESSED"}


class _RestorationInjection:
    """Fail only the *restoration* write, leaving the acquisition real.

    The acquisition writes 1 and must succeed, because the defects under test
    are about what happens after a helper this controller really forked is
    really reaped.  Only the write that puts the baseline back is failed, in
    each of the three ways the kernel can fail to confirm one.
    """

    MISMATCH = "MISMATCH"
    SET_FAILED = "SET_FAILED"
    READBACK_FAILED = "READBACK_FAILED"

    def __init__(self, mode: str, baseline: int) -> None:
        self.mode = mode
        self.baseline = int(baseline)
        self.real_set = po.set_child_subreaper
        self.real_get = po.get_child_subreaper
        self.restore_writes = 0

    def set(self, value: int) -> str | None:
        if int(value) == self.baseline:
            self.restore_writes += 1
            if self.mode == self.SET_FAILED:
                return "EPERM"
            if self.mode == self.MISMATCH:
                # The write reports success and the kernel is left as it was.
                return None
        return self.real_set(value)

    def get(self) -> tuple[int | None, str | None]:
        if self.restore_writes and self.mode == self.READBACK_FAILED:
            return None, "EPERM"
        return self.real_get()


def _injected(mode: str, baseline: int):
    """A context manager failing exactly the restoration, in one stated way."""

    injection = _RestorationInjection(mode, baseline)
    set_patch = mock.patch.object(po, "set_child_subreaper", injection.set)
    get_patch = mock.patch.object(po, "get_child_subreaper", injection.get)

    class _Scope:
        def __enter__(self) -> _RestorationInjection:
            set_patch.start()
            get_patch.start()
            return injection

        def __exit__(self, *exception: object) -> None:
            get_patch.stop()
            set_patch.stop()

    return _Scope()


def _source_tree(test: unittest.TestCase) -> tuple[Path, int]:
    directory = Path(tempfile.mkdtemp(prefix="admissible-m2-b48-source-"))
    test.addCleanup(shutil.rmtree, str(directory), True)
    (directory / "tracked.txt").write_text("source\n", encoding="utf-8")
    handle = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    test.addCleanup(_close_quietly, handle)
    return directory, handle


def _view(test: unittest.TestCase) -> PrivateExecutionView:
    """A real private execution view over a disposable source tree."""

    directory, handle = _source_tree(test)
    view = PrivateExecutionView.materialize(directory, handle)
    test.addCleanup(_close_view, view)
    return view


def _close_view(view: PrivateExecutionView) -> None:
    _resume(view.helper.pid)
    try:
        view.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "fixture_view_close"))
    except Exception:  # pragma: no cover - the fixture never masks a failure
        pass
    _reap_quietly(view.helper.pid)


def _stopped(test: unittest.TestCase, pid: int) -> None:
    os.kill(pid, signal.SIGSTOP)
    test.addCleanup(_resume, pid)


class _StubCleanup:
    """A handle that reports exactly the cleanup evidence a test states.

    Used only where the registry's own bookkeeping is under test: filling it to
    capacity with sixty-four real stopped helpers would test the fixture rather
    than the invariant.  Every test about what a *cleanup* does uses a real
    helper.
    """

    def __init__(self, helper_pid: int = 0, *, complete: bool = False) -> None:
        self._registry_id: str | None = None
        self.helper_pid = helper_pid
        self.complete = complete
        self.closes = 0

    def evidence(self) -> dict:
        return {
            "helper_pid": self.helper_pid,
            "cleanup_complete": self.complete,
            "cleanup_retryable": not self.complete,
            "cleanup_retry_operation": (
                pw.CLEANUP_RETRY_NONE if self.complete else pw.CLEANUP_RETRY_SETTLE
            ),
            "ownership_generation": po.ownership_generation(),
        }

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict:
        self.closes += 1
        evidence = self.evidence()
        evidence["cleanup_registry_id"] = pw._CLEANUP_REGISTRY.record(self, evidence)
        return evidence

    def cleanup_evidence(self) -> dict:
        return self.evidence()

    def close(self, *, deadline: Deadline | None = None) -> dict:
        return self.settle_cleanup(deadline=deadline)


# --- M2-B45: one process-wide active ownership domain -------------------------


class ProcessWideActiveOwnershipTests(unittest.TestCase):
    """Two ownership objects are two handles, never two owners."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def test_two_ownership_objects_share_one_process_wide_depth(self) -> None:
        first = ChildSubreaperOwnership()
        second = ChildSubreaperOwnership()
        first.acquire()
        self.addCleanup(first.release)
        self.assertEqual(second.state()["depth"], 1, "the second object sees its own depth")
        second.acquire()
        self.addCleanup(second.release)
        self.assertEqual(first.state()["depth"], 2)
        self.assertEqual(second.state()["depth"], 2)
        self.assertEqual(po.process_active_ownership()["depth"], 2)

    def test_a_second_object_does_not_create_a_second_baseline(self) -> None:
        first = ChildSubreaperOwnership()
        first.acquire()
        self.addCleanup(first.release)
        self.assertEqual(po.get_child_subreaper()[0], 1)
        second = ChildSubreaperOwnership()
        state = second.acquire()
        self.addCleanup(second.release)
        # The defect: the second acquisition read the *first one's* activation
        # back as its baseline, so the process owed 1 rather than the value it
        # actually found.
        self.assertEqual(state["previous_value"], self.before)
        self.assertEqual(state["original_baseline"], self.before)
        self.assertEqual(po.process_active_ownership()["original_baseline"], self.before)

    def test_releasing_one_object_while_another_holds_keeps_the_flag_set(self) -> None:
        first = ChildSubreaperOwnership()
        second = ChildSubreaperOwnership()
        first_reference = first.acquire_reference()
        second_reference = second.acquire_reference()
        self.addCleanup(second_reference.release)
        result = first_reference.release()
        self.assertEqual(result["code"], po.SUBREAPER_REFERENCE_RETAINED)
        self.assertEqual(po.get_child_subreaper()[0], 1, "the flag was restored under a live holder")
        self.assertEqual(second.state()["depth"], 1)
        self.assertTrue(second_reference.valid)
        self.assertTrue(second.active)

    def test_no_object_can_restore_while_a_process_wide_reference_remains(self) -> None:
        first = ChildSubreaperOwnership().acquire_reference()
        second = ChildSubreaperOwnership().acquire_reference()
        self.addCleanup(second.release)
        writes: list[int] = []
        real_set = po.set_child_subreaper

        def recording(value):
            writes.append(int(value))
            return real_set(value)

        with mock.patch.object(po, "set_child_subreaper", recording):
            first.release()
        self.assertEqual(writes, [], "an inner release wrote the process-wide flag")

    def test_the_final_release_restores_the_original_baseline_exactly_once(self) -> None:
        first = ChildSubreaperOwnership().acquire_reference()
        second = ChildSubreaperOwnership().acquire_reference()
        first.release()
        writes: list[int] = []
        real_set = po.set_child_subreaper

        def recording(value):
            writes.append(int(value))
            return real_set(value)

        with mock.patch.object(po, "set_child_subreaper", recording):
            result = second.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(writes, [self.before], "the baseline was not restored exactly once")
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(po.process_active_ownership()["depth"], 0)

    def test_the_audited_reproduction_cannot_be_produced(self) -> None:
        """The exact independent reproduction, asserted at every step.

        Baseline 0; object A acquires; object B acquires; A releases.  The
        audited behaviour was: the kernel flag reads 0 while B reports active
        ownership, depth 1, a valid reference and state APPLIED.
        """

        first = ChildSubreaperOwnership()
        second = ChildSubreaperOwnership()
        first_reference = first.acquire_reference()
        second_reference = second.acquire_reference()
        first_reference.release()
        observed, error = po.get_child_subreaper()
        self.assertIsNone(error)
        self.assertEqual(observed, 1)
        # Whatever the objects say, no object may say "active" while the kernel
        # says the process is not a child subreaper.
        for owner in (first, second):
            self.assertEqual(owner.active, observed == 1)
        self.assertTrue(second_reference.valid)
        second_reference.release()
        observed, _ = po.get_child_subreaper()
        self.assertEqual(observed, self.before)
        for owner in (first, second):
            self.assertFalse(owner.active, "an object reported active over a restored flag")
            self.assertFalse(owner.state()["applied"])
        self.assertFalse(second_reference.valid)

    def test_a_replacement_ownership_object_addresses_the_same_activation(self) -> None:
        held = ChildSubreaperOwnership().acquire_reference()
        self.addCleanup(held.release)
        generation = po.ownership_generation()
        replacement = ChildSubreaperOwnership()
        self.assertTrue(replacement.active)
        self.assertEqual(replacement.generation, generation)
        self.assertEqual(replacement.state()["owner_pid"], os.getpid())
        self.assertEqual(replacement.state()["depth"], 1)

    def test_a_reference_from_a_replaced_activation_is_stale(self) -> None:
        first = CHILD_SUBREAPER.acquire_reference()
        generation = first.generation
        first.release()
        second = CHILD_SUBREAPER.acquire_reference()
        self.addCleanup(second.release)
        self.assertEqual(second.generation, generation + 1, "a fresh activation reused a generation")
        self.assertFalse(first.valid)
        self.assertTrue(second.valid)

    def test_a_handle_over_a_discarded_activation_is_not_valid(self) -> None:
        reference = CHILD_SUBREAPER.acquire_reference()
        self.assertTrue(reference.valid)
        # An activation this process did not take -- what a fork child inherits.
        CHILD_SUBREAPER._owner_pid = os.getpid() + 1_000_000
        self.assertFalse(CHILD_SUBREAPER.active)
        self.assertFalse(reference.valid, "a handle survived the discard of its activation")
        self.assertNotEqual(reference.generation, po.ownership_generation())

    def test_concurrent_acquisitions_are_serialized_and_cannot_split_ownership(self) -> None:
        outer = CHILD_SUBREAPER.acquire_reference()
        self.addCleanup(outer.release)
        generation = po.ownership_generation()
        baseline = CHILD_SUBREAPER.state()["previous_value"]
        started = threading.Barrier(9)
        acquired: list[po.SubreaperReference] = []
        failures: list[BaseException] = []
        lock = threading.Lock()

        def worker() -> None:
            try:
                started.wait(timeout=BOUND_SLACK_SECONDS)
                reference = ChildSubreaperOwnership().acquire_reference()
                with lock:
                    acquired.append(reference)
            except BaseException as error:  # pragma: no cover - reported below
                with lock:
                    failures.append(error)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        started.wait(timeout=BOUND_SLACK_SECONDS)
        for thread in threads:
            thread.join(timeout=BOUND_SLACK_SECONDS)
        self.assertEqual(failures, [])
        self.assertEqual(len(acquired), 8)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 9, "concurrent acquisitions split")
        self.assertEqual(po.ownership_generation(), generation, "a second activation was created")
        self.assertEqual(CHILD_SUBREAPER.state()["previous_value"], baseline)
        for reference in acquired:
            self.assertEqual(reference.release()["code"], po.SUBREAPER_REFERENCE_RETAINED)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 1)
        self.assertEqual(po.get_child_subreaper()[0], 1)

    def test_every_ownership_handle_takes_the_same_lock(self) -> None:
        self.assertIs(ChildSubreaperOwnership()._lock, ChildSubreaperOwnership()._lock)
        self.assertIs(ChildSubreaperOwnership()._lock, po._OWNERSHIP_LOCK)
        self.assertIs(CHILD_SUBREAPER._lock, po._OWNERSHIP_LOCK)
        self.assertIs(po._DEBT_LOCK, po._OWNERSHIP_LOCK)

    def test_no_ownership_field_is_stored_on_an_instance(self) -> None:
        """An instance attribute is exactly how two owners were created."""

        owner = ChildSubreaperOwnership()
        owner.acquire()
        self.addCleanup(owner.release)
        self.assertEqual(set(owner.__dict__), {"_lock"})
        for field in ("_depth", "_previous", "_owner_pid", "_applied", "_state"):
            with self.subTest(field=field):
                self.assertIsInstance(getattr(type(owner), field), property)

    def test_the_ownership_state_document_names_the_activation(self) -> None:
        owner = ChildSubreaperOwnership()
        state = owner.acquire()
        self.addCleanup(owner.release)
        self.assertTrue(state["process_wide"])
        self.assertEqual(state["generation"], po.ownership_generation())
        snapshot = po.process_active_ownership()
        self.assertEqual(snapshot["owner_pid"], os.getpid())
        self.assertTrue(snapshot["owned_by_this_pid"])
        self.assertEqual(snapshot["reading_pid"], os.getpid())

    def test_the_debt_and_the_activation_are_captured_and_restored_together(self) -> None:
        owner = ChildSubreaperOwnership()
        owner.acquire()
        snapshot = po.capture_process_ownership()
        self.assertEqual(snapshot["active"]["depth"], 1)
        owner.release()
        self.assertEqual(po.process_active_ownership()["depth"], 0)
        po.restore_process_ownership(snapshot)
        self.assertEqual(po.process_active_ownership()["depth"], 1)
        self.addCleanup(po.restore_process_ownership, snapshot)
        owner.release()


class ProcessWideOwnershipForkTests(unittest.TestCase):
    """A child inherits this module's memory and none of its ownership."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def test_an_inherited_active_state_is_discarded_safely_in_the_child(self) -> None:
        reference = CHILD_SUBREAPER.acquire_reference()
        self.addCleanup(reference.release)
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            code = 0
            try:
                checks = [
                    po.get_child_subreaper()[0] == 0,
                    po.process_active_ownership()["owned_by_this_pid"] is False,
                    CHILD_SUBREAPER.active is False,
                    reference.valid is False,
                    reference.release()["code"] == po.SUBREAPER_INHERITED_DISCARDED,
                    po.get_child_subreaper()[0] == 0,
                    po.process_restoration_debt() is None,
                ]
                code = 0 if all(checks) else 1 + checks.index(False)
            except BaseException:
                code = 90
            finally:
                os._exit(code)
        _pid, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, "the child trusted inherited state")
        # And the parent is untouched by anything the child did.
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 1)
        self.assertEqual(po.get_child_subreaper()[0], 1)
        self.assertTrue(reference.valid)

    def test_a_child_neither_owes_nor_can_settle_the_parents_debt(self) -> None:
        owner = ChildSubreaperOwnership()
        owner.acquire()
        with _injected(_RestorationInjection.MISMATCH, self.before):
            result = owner.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertTrue(po.process_restoration_debt())
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            code = 0
            try:
                checks = [
                    po.process_restoration_debt() is None,
                    ChildSubreaperOwnership().settle_restoration_debt()["performed"] is False,
                ]
                code = 0 if all(checks) else 1 + checks.index(False)
            except BaseException:
                code = 90
            finally:
                os._exit(code)
        _pid, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertIsNotNone(po.process_restoration_debt(), "the child settled the parent's debt")
        self.assertTrue(CHILD_SUBREAPER.settle_restoration_debt()["settled"])
        self.assertEqual(po.get_child_subreaper()[0], self.before)


# --- M2-B46: failed-start completion includes restoration settlement ----------


class FailedStartSettlementTests(unittest.TestCase):
    """A failed start is complete when the flag is back, not when it was tried."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        self.addCleanup(self._drain)

    def _drain(self) -> None:
        for pending in pw.unsettled_failed_starts():
            _resume(pending.helper_pid)
            try:
                pending.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))
            except Exception:  # pragma: no cover - the fixture never masks a failure
                pass
            _reap_quietly(pending.helper_pid)
            if pending in pw._UNSETTLED_FAILED_STARTS:
                pw._UNSETTLED_FAILED_STARTS.remove(pending)

    def _unreaped_failed_start(self) -> tuple[int, pw._UnsettledFailedStart]:
        """A real forked child and a real acquisition the rollback could not end."""

        reference = ChildSubreaperOwnership().acquire_reference()
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            try:
                time.sleep(30)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, child)
        with mock.patch.object(
            pw,
            "reap_owned_child",
            return_value=po.ReapOutcome(
                reaped=False,
                exit_code=None,
                reaper_role=po.REAPER_NONE,
                reaper_pid=None,
                detail="injected: the child was not reaped inside the deadline",
                code=po.REAP_DEADLINE_EXPIRED,
            ),
        ):
            pw._roll_back_failed_start(pid=child, sockets=(), descriptors=(), subreaper=reference)
        pending = [entry for entry in pw.unsettled_failed_starts() if entry.helper_pid == child]
        self.assertEqual(len(pending), 1, "the incomplete rollback left nothing to retry")
        return child, pending[0]

    def _retry_with(self, entry: pw._UnsettledFailedStart, mode: str) -> dict:
        with _injected(mode, self.before):
            return entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "injected_retry"))

    def test_a_reap_with_a_restore_mismatch_is_incomplete_and_retained(self) -> None:
        child, entry = self._unreaped_failed_start()
        evidence = self._retry_with(entry, _RestorationInjection.MISMATCH)
        self.assertTrue(evidence["helper_reaped"])
        self.assertEqual(evidence["subreaper_release_result"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertFalse(evidence["restoration_settled"])
        self.assertFalse(evidence["cleanup_complete"], evidence)
        self.assertTrue(evidence["cleanup_retryable"])
        self.assertTrue(evidence["registry_retained"], "the only settlement handle was deleted")
        self.assertIn(entry, pw.unsettled_failed_starts())
        self.assertFalse(po.process_is_zombie(child))

    def test_a_reap_with_a_restore_set_failure_is_incomplete_and_retained(self) -> None:
        _child, entry = self._unreaped_failed_start()
        evidence = self._retry_with(entry, _RestorationInjection.SET_FAILED)
        self.assertEqual(evidence["subreaper_release_result"], po.SUBREAPER_RESTORE_SET_FAILED)
        self.assertFalse(evidence["cleanup_complete"])
        self.assertTrue(evidence["registry_retained"])

    def test_a_reap_with_a_restore_readback_failure_is_incomplete_and_retained(self) -> None:
        _child, entry = self._unreaped_failed_start()
        evidence = self._retry_with(entry, _RestorationInjection.READBACK_FAILED)
        self.assertEqual(evidence["subreaper_release_result"], po.SUBREAPER_RESTORE_READBACK_FAILED)
        self.assertFalse(evidence["cleanup_complete"])
        self.assertTrue(evidence["registry_retained"])

    def test_the_next_retry_settles_the_debt_and_removes_the_entry(self) -> None:
        _child, entry = self._unreaped_failed_start()
        self._retry_with(entry, _RestorationInjection.MISMATCH)
        self.assertIsNotNone(po.process_restoration_debt())
        settled = entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settling_retry"))
        self.assertTrue(settled["restoration_settled"], settled)
        self.assertTrue(settled["cleanup_complete"])
        self.assertFalse(settled["registry_retained"])
        self.assertNotIn(entry, pw.unsettled_failed_starts())
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_failed_settlement_keeps_the_entry_retained(self) -> None:
        _child, entry = self._unreaped_failed_start()
        self._retry_with(entry, _RestorationInjection.MISMATCH)
        again = self._retry_with(entry, _RestorationInjection.MISMATCH)
        self.assertFalse(again["cleanup_complete"], again)
        self.assertTrue(again["registry_retained"])
        self.assertGreaterEqual(again["settlement_attempts"], 2)
        self.assertIsNotNone(po.process_restoration_debt())

    def test_the_release_happens_exactly_once_across_every_retry(self) -> None:
        _child, entry = self._unreaped_failed_start()
        calls: list[int] = []
        real_release = entry.subreaper.release

        def counting():
            calls.append(1)
            return real_release()

        entry.subreaper.release = counting
        self._retry_with(entry, _RestorationInjection.MISMATCH)
        self._retry_with(entry, _RestorationInjection.MISMATCH)
        entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "final"))
        self.assertEqual(len(calls), 1, "the single reference was released more than once")
        self.assertTrue(entry.cleanup_complete)

    def test_the_exact_child_is_reaped_exactly_once(self) -> None:
        child, entry = self._unreaped_failed_start()
        reaped: list[int] = []
        real_reap = pw._kill_and_reap_owned

        def counting(pid, deadline):
            reaped.append(int(pid))
            return real_reap(pid, deadline)

        with mock.patch.object(pw, "_kill_and_reap_owned", counting):
            self._retry_with(entry, _RestorationInjection.MISMATCH)
            entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "second"))
        self.assertEqual(reaped, [child], "the exact child was not reaped exactly once")

    def test_no_unrelated_child_is_reaped_by_a_settlement_retry(self) -> None:
        _child, entry = self._unreaped_failed_start()
        unrelated = os.fork()
        if unrelated == 0:  # pragma: no cover - child process
            try:
                time.sleep(30)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, unrelated)
        self._retry_with(entry, _RestorationInjection.MISMATCH)
        entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "second"))
        self.assertIn(unrelated, _child_pids(), "an unrelated child was consumed")
        self.assertFalse(po.process_is_zombie(unrelated))

    def test_the_original_baseline_survives_every_retry(self) -> None:
        _child, entry = self._unreaped_failed_start()
        self.assertEqual(entry.owed_baseline, self.before)
        self._retry_with(entry, _RestorationInjection.MISMATCH)
        debt = po.process_restoration_debt()
        self.assertEqual(debt["owed_baseline"], self.before)
        self._retry_with(entry, _RestorationInjection.SET_FAILED)
        self.assertEqual(po.process_restoration_debt()["owed_baseline"], self.before)
        entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "final"))
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_rollback_whose_release_owes_a_restoration_stays_retryable(self) -> None:
        """The reap succeeded; the restoration did not.  That is not complete."""

        reference = ChildSubreaperOwnership().acquire_reference()
        with _injected(_RestorationInjection.MISMATCH, self.before):
            evidence = pw._roll_back_failed_start(
                pid=None, sockets=(), descriptors=(), subreaper=reference
            )
        self.assertTrue(evidence["subreaper_released"])
        self.assertFalse(evidence["restoration_settled"])
        self.assertFalse(evidence["cleanup_complete"], evidence)
        self.assertTrue(evidence["cleanup_retryable"])
        pending = pw.unsettled_failed_starts()
        self.assertTrue(pending, "the rollback reported a completion nobody performed")
        results = pw.retry_unsettled_failed_starts(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "sweep")
        )
        self.assertTrue(all(entry["cleanup_complete"] for entry in results), results)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_rollback_that_reaps_and_restores_is_complete(self) -> None:
        """The accepted M2-B38/B43 behaviour, unchanged where nothing is owed."""

        reference = ChildSubreaperOwnership().acquire_reference()
        evidence = pw._roll_back_failed_start(
            pid=None, sockets=(), descriptors=(), subreaper=reference
        )
        self.assertTrue(evidence["subreaper_released"])
        self.assertTrue(evidence["restoration_settled"])
        self.assertTrue(evidence["cleanup_complete"])
        self.assertFalse(evidence["cleanup_retryable"])
        self.assertEqual(evidence["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(pw.unsettled_failed_starts(), ())


# --- M2-B47: a retryable helper cleanup can actually settle -------------------


class HelperDebtRetryTests(unittest.TestCase):
    """A cleanup that advertises a retry must be able to progress."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def _helper(self) -> PrivateMountHelper:
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        return helper

    def _closed_with(self, mode: str) -> tuple[PrivateMountHelper, dict]:
        helper = self._helper()
        with _injected(mode, self.before):
            evidence = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "injected_close"))
        return helper, evidence

    def test_a_close_whose_restoration_mismatches_is_not_terminal(self) -> None:
        helper, evidence = self._closed_with(_RestorationInjection.MISMATCH)
        self.assertTrue(evidence["reaped"], evidence)
        self.assertEqual(evidence["subreaper_release_result"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertFalse(evidence["restoration_settled"])
        self.assertFalse(evidence["cleanup_complete"])
        self.assertTrue(evidence["cleanup_retryable"])
        self.assertEqual(evidence["cleanup_retry_operation"], pw.CLEANUP_RETRY_SETTLE)
        self.assertFalse(helper.cleanup_complete)

    def test_a_retry_after_a_mismatch_settles_the_debt(self) -> None:
        helper, first = self._closed_with(_RestorationInjection.MISMATCH)
        self.assertIsNotNone(po.process_restoration_debt())
        second = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(second["restoration_settled"], second)
        self.assertTrue(second["cleanup_complete"])
        self.assertEqual(second["cleanup_retry_operation"], pw.CLEANUP_RETRY_NONE)
        self.assertGreater(second["settlement_attempts"], first["settlement_attempts"])
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_retry_after_a_set_failure_settles_the_debt(self) -> None:
        helper, _first = self._closed_with(_RestorationInjection.SET_FAILED)
        second = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(second["cleanup_complete"], second)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_retry_after_a_readback_failure_settles_the_debt(self) -> None:
        helper, _first = self._closed_with(_RestorationInjection.READBACK_FAILED)
        second = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(second["cleanup_complete"], second)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_the_release_happens_once_and_the_settlement_may_repeat(self) -> None:
        helper = self._helper()
        releases: list[int] = []
        with _injected(_RestorationInjection.MISMATCH, self.before):
            reference = helper._subreaper
            real_release = reference.release

            def counting():
                releases.append(1)
                return real_release()

            reference.release = counting
            helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "first"))
            helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "second"))
        self.assertEqual(len(releases), 1, "the single reference was released more than once")
        self.assertGreaterEqual(helper.settlement_attempts, 2)
        final = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "third"))
        self.assertEqual(len(releases), 1)
        self.assertTrue(final["cleanup_complete"])

    def test_the_original_baseline_is_the_one_restored(self) -> None:
        helper, _first = self._closed_with(_RestorationInjection.MISMATCH)
        debt = po.process_restoration_debt()
        self.assertEqual(debt["owed_baseline"], self.before)
        helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        observed, error = po.get_child_subreaper()
        self.assertIsNone(error)
        self.assertEqual(observed, self.before, "the settlement restored a value nobody found")

    def test_a_terminal_close_is_idempotent(self) -> None:
        helper, _first = self._closed_with(_RestorationInjection.MISMATCH)
        helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        attempts = helper.settlement_attempts
        third = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "third"))
        self.assertTrue(third["already_closed"])
        self.assertTrue(third["cleanup_complete"])
        self.assertEqual(helper.settlement_attempts, attempts, "a terminal close settled again")
        self.assertFalse(third["subreaper_released_by_this_call"])

    def test_a_failed_settlement_never_claims_completion(self) -> None:
        helper = self._helper()
        with _injected(_RestorationInjection.MISMATCH, self.before):
            first = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "first"))
            second = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "second"))
            third = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "third"))
        for evidence in (first, second, third):
            self.assertFalse(evidence["cleanup_complete"], evidence)
            self.assertTrue(evidence["cleanup_retryable"])
            self.assertTrue(evidence["debt_outstanding"])
        self.assertEqual(third["cleanup_retry_operation"], pw.CLEANUP_RETRY_SETTLE)
        self.assertTrue(helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settling"))[
            "cleanup_complete"
        ])

    def test_an_unreaped_helper_names_the_reap_and_not_the_settlement(self) -> None:
        helper = self._helper()
        _stopped(self, helper.pid)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            evidence = helper.close(deadline=Deadline.already_expired("expired"))
        self.assertFalse(evidence["reaped"])
        self.assertTrue(evidence["ownership_retained"])
        self.assertEqual(evidence["cleanup_retry_operation"], pw.CLEANUP_RETRY_REAP)
        _resume(helper.pid)
        final = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(final["cleanup_complete"], final)
        self.assertEqual(final["cleanup_retry_operation"], pw.CLEANUP_RETRY_NONE)


# --- M2-B48: the process cleanup registry ------------------------------------


class CleanupRegistryTests(unittest.TestCase):
    """The retry handle belongs to the process, not to a local wrapper."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def test_only_an_incomplete_cleanup_is_registered(self) -> None:
        complete = _StubCleanup(helper_pid=11, complete=True)
        self.assertIsNone(pw._CLEANUP_REGISTRY.record(complete, complete.evidence()))
        self.assertEqual(pw.incomplete_cleanups(), ())
        incomplete = _StubCleanup(helper_pid=12)
        entry_id = pw._CLEANUP_REGISTRY.record(incomplete, incomplete.evidence())
        self.assertIsNotNone(entry_id)
        self.assertEqual([entry.entry_id for entry in pw.incomplete_cleanups()], [entry_id])

    def test_a_completed_cleanup_releases_its_entry(self) -> None:
        handle = _StubCleanup(helper_pid=13)
        entry_id = pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        self.assertIn(entry_id, [entry.entry_id for entry in pw.incomplete_cleanups()])
        handle.complete = True
        self.assertIsNone(pw._CLEANUP_REGISTRY.record(handle, handle.evidence()))
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertIsNone(handle._registry_id)

    def test_entry_ids_are_deterministic_and_name_the_owning_pid(self) -> None:
        first = _StubCleanup(helper_pid=21)
        second = _StubCleanup(helper_pid=22)
        first_id = pw._CLEANUP_REGISTRY.record(first, first.evidence())
        second_id = pw._CLEANUP_REGISTRY.record(second, second.evidence())
        self.assertTrue(first_id.startswith(f"cleanup-{os.getpid()}-"))
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(sorted([first_id, second_id]), [first_id, second_id])
        # A repeat records against the same entry rather than creating another.
        self.assertEqual(pw._CLEANUP_REGISTRY.record(first, first.evidence()), first_id)
        self.assertEqual(len(pw.incomplete_cleanups()), 2)

    def test_a_drain_retries_every_entry_and_removes_the_terminal_ones(self) -> None:
        stuck = _StubCleanup(helper_pid=31)
        finishing = _StubCleanup(helper_pid=32)
        pw._CLEANUP_REGISTRY.record(stuck, stuck.evidence())
        pw._CLEANUP_REGISTRY.record(finishing, finishing.evidence())
        finishing.complete = True
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
        self.assertEqual(len(results), 2)
        by_pid = {entry["helper_pid"]: entry for entry in results}
        self.assertTrue(by_pid[32]["cleanup_complete"])
        self.assertTrue(by_pid[32]["removed"])
        self.assertFalse(by_pid[31]["cleanup_complete"])
        self.assertFalse(by_pid[31]["removed"])
        self.assertEqual([entry.helper_pid for entry in pw.incomplete_cleanups()], [31])

    def test_repeated_drains_are_idempotent(self) -> None:
        handle = _StubCleanup(helper_pid=41)
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        handle.complete = True
        first = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
        second = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
        third = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(third, [])
        self.assertEqual(handle.closes, 1, "a drained entry was closed again")

    def test_capacity_exhaustion_refuses_a_new_helper_fail_closed(self) -> None:
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _StubCleanup(helper_pid=1000 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        self.assertTrue(pw._CLEANUP_REGISTRY.saturated())
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            with self.assertRaises(CleanupRegistrySaturated) as raised:
                PrivateMountHelper.start()
        self.assertEqual(raised.exception.code, "cleanup_registry_saturated")
        self.assertFalse(forked.called, "a helper was forked at registry capacity")
        self.assertEqual(po.get_child_subreaper()[0], self.before, "an acquisition was taken")
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)

    def test_capacity_exhaustion_refuses_a_materialisation(self) -> None:
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _StubCleanup(helper_pid=2000 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        directory, source_fd = _source_tree(self)
        with self.assertRaises(PrivateWorkspaceError) as raised:
            PrivateExecutionView.materialize(directory, source_fd)
        self.assertEqual(raised.exception.code, "cleanup_registry_saturated")

    def test_a_forked_child_trusts_no_parent_registry_handle(self) -> None:
        handle = _StubCleanup(helper_pid=51)
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            code = 0
            try:
                checks = [
                    pw.incomplete_cleanups() == (),
                    pw.cleanup_registry_evidence()["retained"] == 0,
                    pw.cleanup_registry_evidence()["owner_pid"] == os.getpid(),
                    pw.drain_incomplete_cleanups() == [],
                ]
                code = 0 if all(checks) else 1 + checks.index(False)
            except BaseException:
                code = 90
            finally:
                os._exit(code)
        _pid, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, "a child trusted a parent handle")
        self.assertEqual(len(pw.incomplete_cleanups()), 1, "the parent lost its own entry")
        self.assertEqual(handle.closes, 0, "a child retried a parent's cleanup")

    def test_the_registry_evidence_names_no_repository_path(self) -> None:
        view = _view(self)
        _stopped(self, view.helper.pid)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            view.close(deadline=Deadline.already_expired("expired"))
        evidence = pw.cleanup_registry_evidence()
        self.assertGreaterEqual(evidence["retained"], 1)
        text = json.dumps(evidence)
        self.assertNotIn(str(REPOSITORY_ROOT), text, "the registry retained a worktree path")
        for entry in evidence["entries"]:
            for key, value in entry.items():
                if isinstance(value, str):
                    self.assertNotIn("/", value, f"{key} retained a filesystem path")
        self.assertEqual(evidence["capacity"], pw.CLEANUP_REGISTRY_CAPACITY)

    def test_the_registry_retains_the_handle_after_the_wrapper_is_destroyed(self) -> None:
        directory, source_fd = _source_tree(self)
        helper_pid: list[int] = []

        def make_and_drop() -> str:
            view = PrivateExecutionView.materialize(directory, source_fd)
            helper_pid.append(view.helper.pid)
            os.kill(view.helper.pid, signal.SIGSTOP)
            with mock.patch.object(pw, "signal_process", _NoSignal()):
                evidence = view.close(deadline=Deadline.already_expired("expired"))
            self.assertFalse(evidence["cleanup_complete"])
            return evidence["cleanup_registry_id"]

        entry_id = make_and_drop()
        gc.collect()
        self.addCleanup(_reap_quietly, helper_pid[0])
        self.addCleanup(_resume, helper_pid[0])
        entry = pw._CLEANUP_REGISTRY.entry(entry_id)
        self.assertIsNotNone(entry, "the only retry handle went out of scope with its wrapper")
        self.assertEqual(entry.helper_pid, helper_pid[0])
        self.assertEqual(entry.kind, pw.CLEANUP_KIND_HELPER)
        _resume(helper_pid[0])
        results = pw.drain_incomplete_cleanups(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain")
        )
        drained = [row for row in results if row["entry_id"] == entry_id]
        self.assertEqual(len(drained), 1, results)
        self.assertTrue(drained[0]["cleanup_complete"], drained)
        self.assertTrue(drained[0]["removed"])
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(entry_id))
        self.assertFalse(po.process_is_zombie(helper_pid[0]))
        self.assertEqual(po.get_child_subreaper()[0], self.before)


# --- M2-B48: the production call chain ---------------------------------------


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

    def request(self, script: str, *, timeout_ms: int = 60_000) -> RunCommandRequest:
        return RunCommandRequest.create(
            tool_grammar_fingerprint=self.grammar,
            argv=[PYTHON, "-c", script],
            timeout_ms=timeout_ms,
        )

    def command(self, script: str, *, timeout_ms: int = 60_000):
        self._counter += 1
        request = self.request(script, timeout_ms=timeout_ms)
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


class ProductionCleanupPropagationTests(unittest.TestCase):
    """The real call chain carries the cleanup truth it detects."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        guard_process_wide_cgroup_caches(self)

    def _harness(self, run_id: str) -> _Harness:
        harness = _Harness(run_id=run_id)
        self.addCleanup(harness.close)
        return harness

    def _prepared(self, harness: _Harness) -> ef._EffectPreparation:
        preparation = ef.prepare_effect(harness.binding, harness.request(SENTINEL_SCRIPT))
        self.assertIsNone(preparation.refusal, preparation.refusal)
        self.assertIsNotNone(preparation.private_view)
        self.addCleanup(_reap_quietly, preparation.private_view.helper.pid)
        return preparation

    @capsule
    def test_the_preparation_close_returns_its_cleanup_evidence(self) -> None:
        harness = self._harness("run-preparation-evidence")
        preparation = self._prepared(harness)
        helper_pid = preparation.private_view.helper.pid
        _stopped(self, helper_pid)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            evidence = preparation.close()
        self.assertIsNotNone(evidence, "_EffectPreparation.close() reported nothing")
        self.assertFalse(evidence["cleanup_complete"], evidence)
        self.assertTrue(evidence["cleanup_retryable"])
        self.assertIsNotNone(evidence["cleanup_registry_id"])
        self.assertEqual(preparation.cleanup_registry_id, evidence["cleanup_registry_id"])
        self.assertFalse(preparation.cleanup_complete)
        self.assertIsNotNone(preparation.private_view, "the only handle was dropped")
        _resume(helper_pid)
        final = preparation.close()
        self.assertTrue(final["cleanup_complete"], final)
        self.assertTrue(preparation.cleanup_complete)
        self.assertIsNone(preparation.private_view)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    @capsule
    def test_run_command_propagates_incomplete_cleanup_evidence(self) -> None:
        harness = self._harness("run-command-evidence")
        preparation = self._prepared(harness)
        helper_pid = preparation.private_view.helper.pid
        _stopped(self, helper_pid)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            with mock.patch.object(
                ef.BoundRuntime, "bind", side_effect=ef.RuntimeBindingRefused("injected")
            ):
                execution = ef._run_command(
                    harness.binding,
                    harness.request(SENTINEL_SCRIPT),
                    preparation=preparation,
                    cancellation=None,
                    start_hook=None,
                )
        self.assertEqual(execution.result.error_code, "runtime_identity_bind_refused")
        self.assertIsNotNone(execution.lifecycle_cleanup, "_run_command discarded the evidence")
        self.assertFalse(execution.lifecycle_cleanup_complete)
        self.assertIsNotNone(execution.cleanup_registry_id)
        self.assertIn(
            execution.cleanup_registry_id,
            [entry.entry_id for entry in pw.incomplete_cleanups()],
        )
        _resume(helper_pid)
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    @capsule
    def test_a_materialisation_exception_retains_a_cleanup_entry(self) -> None:
        directory, source_fd = _source_tree(self)
        with _injected(_RestorationInjection.MISMATCH, self.before):
            with mock.patch.object(pw, "host_can_pathname_reach", return_value=True):
                with self.assertRaises(PrivateWorkspaceError) as raised:
                    PrivateExecutionView.materialize(directory, source_fd)
        self.assertEqual(raised.exception.code, "private_view_host_pathname_reachable")
        evidence = getattr(raised.exception, "cleanup_evidence", None)
        self.assertIsNotNone(evidence, "the materialisation discarded its helper's closure")
        self.assertFalse(evidence["cleanup_complete"])
        entry_id = getattr(raised.exception, "cleanup_registry_id", None)
        self.assertIsNotNone(entry_id)
        self.assertIsNotNone(pw._CLEANUP_REGISTRY.entry(entry_id))
        results = pw.drain_incomplete_cleanups(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain")
        )
        self.assertTrue(all(row["cleanup_complete"] for row in results), results)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_a_completed_command_cannot_hide_an_unresolved_cleanup(self) -> None:
        """The classification itself, on the exact production function."""

        green = ef.RunCommandResult.create(
            request_fingerprint=ef.RunCommandRequest.create(
                tool_grammar_fingerprint=build_specification(
                    "DIRECT", run_id="run-classification"
                ).tool_grammar.grammar_fingerprint,
                argv=[PYTHON, "-c", "pass"],
                timeout_ms=1_000,
            ).request_fingerprint,
            outcome="OK",
            process_started=True,
            stdout="out",
            stderr="err",
            exit_code=0,
        )
        execution = ef._CommandExecution(
            result=green,
            process_observation=None,
            stdout_observation=None,
            stderr_observation=None,
            resource_observation=None,
            timed_out=False,
            cancelled=False,
        )
        incomplete = ef._with_lifecycle_cleanup(
            execution,
            {"cleanup_complete": False, "cleanup_registry_id": "cleanup-1-000001"},
        )
        self.assertEqual(incomplete.result.outcome, "FAILED")
        self.assertEqual(incomplete.result.error_code, ef.LIFECYCLE_CLEANUP_INCOMPLETE)
        # The command's own facts are preserved exactly.
        self.assertTrue(incomplete.result.process_started)
        self.assertEqual(incomplete.result.exit_code, 0)
        self.assertEqual(incomplete.result.stdout, "out")
        self.assertEqual(incomplete.result.stderr, "err")
        self.assertFalse(incomplete.lifecycle_cleanup_complete)
        self.assertEqual(incomplete.cleanup_registry_id, "cleanup-1-000001")
        complete = ef._with_lifecycle_cleanup(execution, {"cleanup_complete": True})
        self.assertEqual(complete.result.outcome, "OK", "a settled cleanup downgraded a completion")
        self.assertTrue(complete.lifecycle_cleanup_complete)

    def test_the_merged_verdict_is_incomplete_when_any_closure_is(self) -> None:
        execution = ef._CommandExecution(
            result=None,
            process_observation=None,
            stdout_observation=None,
            stderr_observation=None,
            resource_observation=None,
            timed_out=False,
            cancelled=False,
            lifecycle_cleanup={"cleanup_complete": True, "cleanup_registry_id": None},
            lifecycle_cleanup_complete=True,
        )
        merged = ef._merge_cleanup_evidence(
            execution, {"cleanup_complete": False, "cleanup_registry_id": "cleanup-1-000009"}
        )
        self.assertFalse(merged["complete"])
        self.assertEqual(merged["registry_ids"], ("cleanup-1-000009",))
        self.assertEqual(ef._merge_cleanup_evidence(None, None)["complete"], True)
        self.assertIsNone(ef._merge_cleanup_evidence(None, None)["evidence"])

    @capsule
    def test_a_positive_effect_carries_a_settled_cleanup_and_registers_nothing(self) -> None:
        harness = self._harness("run-nominal-cleanup")
        outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "COMPLETED", outcome.receipt.outcome_reason)
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertTrue(outcome.lifecycle_cleanup_complete)
        self.assertEqual(outcome.cleanup_registry_ids, ())
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertIsNone(po.process_restoration_debt())

    @capsule
    def test_a_completed_command_with_an_unresolved_cleanup_is_not_green(self) -> None:
        """The whole production chain, with only the restoration write failed."""

        harness = self._harness("run-unresolved-cleanup")
        descriptors = _open_descriptor_count()
        with _injected(_RestorationInjection.SET_FAILED, self.before):
            outcome = harness.command(SENTINEL_SCRIPT)
        # The command really ran and its export really happened: that truth is
        # preserved rather than converted into "nothing started".
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertTrue(outcome.effect_crossed_boundary)
        self.assertTrue(outcome.tool_result.process_started)
        self.assertEqual(outcome.tool_result.exit_code, 0)
        # And it is not reported as an ordinary green completion.
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(outcome.tool_result.error_code, ef.LIFECYCLE_CLEANUP_INCOMPLETE)
        self.assertFalse(outcome.lifecycle_cleanup_complete)
        self.assertTrue(outcome.cleanup_registry_ids, "the outcome named no retry handle")
        self.assertIsNotNone(outcome.lifecycle_cleanup)
        # The wrappers are gone; the process still owns the retry.
        retained = {entry.entry_id for entry in pw.incomplete_cleanups()}
        self.assertTrue(set(outcome.cleanup_registry_ids) <= retained, retained)
        results = pw.drain_incomplete_cleanups(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain")
        )
        self.assertTrue(results, "nothing was retained to drain")
        self.assertTrue(all(row["cleanup_complete"] for row in results), results)
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertTrue(_await(lambda: _open_descriptor_count() <= descriptors + 1, 5.0))

    @capsule
    def test_registry_capacity_refuses_a_new_effect_fail_closed(self) -> None:
        harness = self._harness("run-registry-capacity")
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _StubCleanup(helper_pid=3000 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(
            outcome.tool_result.error_code, "private_workspace_cleanup_registry_saturated"
        )
        self.assertFalse(outcome.effect_crossed_boundary)
        self.assertFalse(forked.called, "a helper was forked at registry capacity")
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(po.get_child_subreaper()[0], self.before)


# --- M2-B48: an unremoved per-effect cgroup is a retained obligation ----------


_REAL_MKDIR = Path.mkdir


def _cgroupfs_mkdir(self_path, *args, **kwargs):
    """Create a fixture cgroup carrying the interface files the kernel creates."""

    _REAL_MKDIR(self_path, *args, **kwargs)
    if (self_path.parent / "cgroup.controllers").exists():
        procs = self_path / "cgroup.procs"
        if not procs.exists():
            procs.write_text("", encoding="utf-8")
        kill = self_path / "cgroup.kill"
        if not kill.exists():
            kill.write_text("0\n", encoding="utf-8")


def _cgroupfs_rmdir(test: unittest.TestCase) -> None:
    """Make an ordinary directory behave like a cgroup for ``rmdir``."""

    def rmdir(self_path):
        if any(child.is_dir() for child in self_path.iterdir()):
            raise OSError(18, "Directory not empty")
        shutil.rmtree(self_path)

    patcher = mock.patch.object(Path, "rmdir", rmdir)
    patcher.start()
    test.addCleanup(patcher.stop)


class _FakeEffectParent:
    """An ordinary directory shaped like a delegated effect parent.

    It is never kernel evidence: the delegated class below drives the same code
    against a real ``Delegate=yes`` subtree.  This fixture exists so the
    *obligation* -- what is retained, what a drain retries, what is refused --
    is provable without privilege, on a host that delegates nothing.
    """

    def __init__(self, test: unittest.TestCase) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-b50-"))
        test.addCleanup(shutil.rmtree, str(self.root), True)
        self.parent = self.root / "svc"
        self.parent.mkdir()
        (self.parent / "cgroup.controllers").write_text("memory pids", encoding="utf-8")
        (self.parent / "cgroup.subtree_control").write_text("memory pids", encoding="utf-8")
        (self.parent / "cgroup.procs").write_text("", encoding="utf-8")
        self.manager = self.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        self.manager.mkdir()
        (self.manager / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="utf-8")
        patcher = mock.patch.object(Path, "mkdir", _cgroupfs_mkdir)
        patcher.start()
        test.addCleanup(patcher.stop)
        _cgroupfs_rmdir(test)
        # cgroup.kill is atomic over the subtree and leaves cgroup.procs empty.
        # The fixture models that exactly, so the settlement's kill, quiescence
        # and removal steps are three distinct observations here as well.
        real_write = rl._write_control

        def killing_write(path, text):
            error = real_write(path, text)
            procs = Path(path).parent / "cgroup.procs"
            # The kernel never recreates an interface file it does not have, so
            # a membership that cannot be read stays unreadable through a kill.
            if error is None and Path(path).name == "cgroup.kill" and procs.exists():
                procs.write_text("", encoding="utf-8")
            return error

        kill_patch = mock.patch.object(rl, "_write_control", killing_write)
        kill_patch.start()
        test.addCleanup(kill_patch.stop)

    def delegation(self) -> rl.CgroupDelegation:
        return rl.CgroupDelegation(
            available=True,
            detail="constructed",
            unified_root=str(self.root),
            delegated_path=str(self.parent),
            controllers=("memory", "pids"),
            code=rl.TOPOLOGY_INITIALIZED,
            manager_leaf=str(self.manager),
            enabled_controllers=("memory", "pids"),
        )

    def effect_cgroups(self) -> list[Path]:
        return sorted(self.parent.glob(f"{rl.EFFECT_PREFIX}*"))


class EffectCgroupRemovalObligationTests(unittest.TestCase):
    """A cgroup this controller created and could not remove is an obligation."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        self.fake = _FakeEffectParent(self)
        self.delegation = self.fake.delegation()

    def _cgroup(self, label: str) -> rl.EffectCgroup:
        cgroup = rl.EffectCgroup(self.delegation, rl.ResourceBounds.for_timeout(1_000), label)
        self.assertTrue(cgroup.create(), cgroup.create_error)
        return cgroup

    def _populate(self, cgroup: rl.EffectCgroup, pids: str) -> None:
        Path(cgroup.path, "cgroup.procs").write_text(pids, encoding="utf-8")

    def test_an_unremovable_cgroup_is_retained_and_registered(self) -> None:
        cgroup = self._cgroup(f"obligation-{os.getpid()}")
        path = Path(cgroup.path)
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close(), "a populated cgroup was reported removed")
        removal = cgroup.removal_evidence()
        self.assertFalse(removal["removed"])
        self.assertEqual(removal["residual_members"], [424242])
        self.assertTrue(path.exists(), "the cgroup was removed while it still held a member")
        # The obligation outlives the frame that discovered it.
        self.assertIsNotNone(cgroup.cleanup_registry_id, "the removal was not retained")
        entry = pw._CLEANUP_REGISTRY.entry(cgroup.cleanup_registry_id)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.kind, pw.CLEANUP_KIND_EFFECT_CGROUP)
        self.assertEqual(entry.evidence()["effect_cgroup_path"], str(path))
        self.assertEqual(
            entry.evidence()["cleanup_retry_operation"], pw.CLEANUP_RETRY_REMOVE_CGROUP
        )
        self.assertFalse(cgroup.removal_settled)

    def test_a_later_bounded_drain_removes_that_exact_cgroup(self) -> None:
        cgroup = self._cgroup(f"drained-{os.getpid()}")
        path = Path(cgroup.path)
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        entry_id = cgroup.cleanup_registry_id
        # The domain becomes quiescent, exactly as a real kill domain does.
        self._populate(cgroup, "")
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
        drained = [row for row in results if row["entry_id"] == entry_id]
        self.assertEqual(len(drained), 1, results)
        self.assertTrue(drained[0]["cleanup_complete"], drained)
        self.assertTrue(drained[0]["removed"])
        self.assertFalse(path.exists(), "the drain did not remove the exact owned cgroup")
        self.assertTrue(cgroup.removal_settled)
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(entry_id))
        self.assertEqual(self.fake.effect_cgroups(), [])

    def test_the_entry_remains_while_removal_fails(self) -> None:
        cgroup = self._cgroup(f"stuck-{os.getpid()}")
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        entry_id = cgroup.cleanup_registry_id
        real_write = rl._write_control

        def failing_kill(path, text):
            if Path(path).name == "cgroup.kill":
                return "EPERM"
            return real_write(path, text)

        # The domain cannot be destroyed, so it never becomes quiescent and the
        # removal keeps failing.  The obligation is not thereby discharged.
        with mock.patch.object(rl, "_write_control", failing_kill):
            for _ in range(3):
                results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(200, "drain"))
                self.assertEqual(len(results), 1, results)
                self.assertFalse(results[0]["cleanup_complete"])
                self.assertFalse(results[0]["removed"])
                self.assertIsNotNone(
                    pw._CLEANUP_REGISTRY.entry(entry_id),
                    "an entry was dropped while its cgroup still held a member",
                )
        self.assertTrue(Path(cgroup.path).exists())
        self.assertFalse(cgroup.removal_settled)
        self.assertEqual(
            pw._CLEANUP_REGISTRY.entry(entry_id).evidence()["cleanup_retry_operation"],
            pw.CLEANUP_RETRY_REMOVE_CGROUP,
        )

    def test_the_entry_remains_while_membership_is_unreadable(self) -> None:
        cgroup = self._cgroup(f"unreadable-{os.getpid()}")
        path = Path(cgroup.path)
        (path / "cgroup.procs").unlink()
        self.assertFalse(cgroup.close(), "an unreadable membership was treated as empty")
        removal = cgroup.removal_evidence()
        self.assertFalse(removal["membership_readable"])
        self.assertFalse(removal["removed"])
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id)
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(200, "drain"))
        self.assertIsNotNone(
            pw._CLEANUP_REGISTRY.entry(entry_id),
            "an entry was dropped while its membership could not be read",
        )
        self.assertTrue(path.exists())

    def test_removal_is_attempted_only_for_the_exactly_owned_cgroup(self) -> None:
        cgroup = self._cgroup(f"identity-{os.getpid()}")
        path = Path(cgroup.path)
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        # The directory is replaced by a different one carrying the same name:
        # a different cgroup, with different controller state and members.  The
        # owned inode is moved aside rather than freed, so the replacement is
        # guaranteed to be a different inode rather than a reused one.
        moved = path.parent / "moved-away"
        os.rename(path, moved)
        self.addCleanup(shutil.rmtree, str(moved), True)
        _REAL_MKDIR(path)
        (path / "cgroup.procs").write_text("", encoding="utf-8")
        self.assertNotEqual(
            rl._directory_identity(path), rl._directory_identity(moved), "the fixture reused an inode"
        )
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(500, "settle"))
        removal = settlement["removal"]
        self.assertFalse(removal["removed"], "a replacement cgroup was removed")
        self.assertFalse(removal["identity_verified"])
        self.assertTrue(path.exists(), "the impostor directory was destroyed")
        self.assertIsNotNone(pw._CLEANUP_REGISTRY.entry(cgroup.cleanup_registry_id))

    def test_no_unrelated_cgroup_is_removed_by_a_drain(self) -> None:
        mine = self._cgroup(f"mine-{os.getpid()}")
        stranger = self.fake.parent / f"{rl.EFFECT_PREFIX}not-mine"
        _REAL_MKDIR(stranger)
        (stranger / "cgroup.procs").write_text("", encoding="utf-8")
        self._populate(mine, "424242\n")
        self.assertFalse(mine.close())
        self._populate(mine, "")
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
        self.assertFalse(Path(mine.path or "").exists() if mine.path else False)
        self.assertTrue(stranger.exists(), "a cgroup this controller never created was removed")
        self.assertEqual(self.fake.effect_cgroups(), [stranger])

    def test_repeated_drains_are_idempotent(self) -> None:
        cgroup = self._cgroup(f"idempotent-{os.getpid()}")
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        self._populate(cgroup, "")
        first = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "drain"))
        second = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "drain"))
        third = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "drain"))
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(third, [])
        self.assertTrue(cgroup.removal_settled)
        self.assertEqual(pw.incomplete_cleanups(), ())

    def test_a_cgroup_removed_by_another_agent_discharges_its_entry(self) -> None:
        """An obligation reaches absence, however the absence came about."""

        cgroup = self._cgroup(f"vanished-{os.getpid()}")
        path = Path(cgroup.path)
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id)
        # The whole subtree goes away underneath the obligation, exactly as a
        # transient unit's teardown removes it.
        shutil.rmtree(path)
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "drain"))
        drained = [row for row in results if row["entry_id"] == entry_id]
        self.assertEqual(len(drained), 1, results)
        self.assertTrue(drained[0]["cleanup_complete"], drained)
        self.assertTrue(cgroup.removal_settled)
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(entry_id), "a stuck entry consumed capacity")
        # It removed nothing, and does not claim it did.
        removal = cgroup.removal_evidence()
        self.assertFalse(removal["removed"])
        self.assertTrue(removal["absence_verified"])

    def test_a_removed_cgroup_is_never_registered(self) -> None:
        cgroup = self._cgroup(f"clean-{os.getpid()}")
        path = Path(cgroup.path)
        self.assertTrue(cgroup.close(), "an empty owned cgroup was not removed")
        self.assertFalse(path.exists())
        self.assertTrue(cgroup.removal_settled)
        self.assertIsNone(cgroup.cleanup_registry_id)
        self.assertEqual(pw.incomplete_cleanups(), ())

    def test_the_settlement_evidence_states_each_step_separately(self) -> None:
        cgroup = self._cgroup(f"stepwise-{os.getpid()}")
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        # The domain is still populated when the settlement runs, so the kill is
        # the settlement's own first step rather than something the test did.
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(500, "settle"))
        self.assertIsNotNone(settlement["kill_domain"])
        self.assertTrue(settlement["quiescence"]["quiescent"])
        self.assertTrue(settlement["removal"]["removed"])
        self.assertTrue(settlement["removal"]["absence_verified"])
        self.assertTrue(settlement["settled"])
        # A kill is never a quiescence and a quiescence is never a removal.
        self.assertNotEqual(settlement["kill_domain"], settlement["quiescence"])
        self.assertNotEqual(settlement["quiescence"], settlement["removal"])

    def test_the_registry_entry_names_no_workspace_or_repository_path(self) -> None:
        cgroup = self._cgroup(f"paths-{os.getpid()}")
        self._populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        evidence = pw.cleanup_registry_evidence()
        text = json.dumps(evidence)
        self.assertNotIn(str(REPOSITORY_ROOT), text, "the registry retained a worktree path")
        self.assertNotIn(tempfile.gettempdir() + "/admissible-m2", text)
        entry = [row for row in evidence["entries"] if row["kind"] == pw.CLEANUP_KIND_EFFECT_CGROUP]
        self.assertEqual(len(entry), 1)
        # The containment path *is* retained: a removal that cannot name its
        # target cannot be retried.
        self.assertEqual(entry[0]["effect_cgroup_path"], cgroup.owned_path)
        self.assertTrue(entry[0]["effect_cgroup_path"].startswith(str(self.fake.parent)))


# --- M2-M49: the current artifacts may not overstate this closure -------------


CURRENT_VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
CLOSURE_REPORT = IMPLEMENTATION / "M2_PROCESS_OWNER_CLEANUP_PROPAGATION_CLOSURE_REPORT.json"
PRIOR_CLOSURE_REPORT = IMPLEMENTATION / "M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
STARTING_COMMIT = "4a451c859bc528d6281bfd1368ab3ca74fd3933c"
STARTING_COMMIT_PARENT = "2f7eaac796e6f4b3d93419ac3087183302b2a54e"
BRANCH = "paired-runner/m2-process-owner-cleanup-propagation-closure"
INDEPENDENT_AUDIT_SHA256 = "b729263d5c6c107addf23260be6b976dd5cd91a812dd0389c97b793d70566ee0"
QUALIFICATION_MODULES = (
    "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
    "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
    "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
    "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
    "tests.test_admissible_paired_runner_m2_ownership_debt_reap_closure",
    "tests.test_admissible_paired_runner_m2_process_owner_cleanup_propagation_closure",
)
PHYSICAL_STATUSES = (
    "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2",
    "OPERATOR_QUALIFICATION_REQUIRED",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class CurrentArtifactSemanticTests(unittest.TestCase):
    """A current claim is rejected unless the live code exhibits it.

    M2-M49.  The superseded artifacts asserted process-wide active ownership,
    retryable failed-start cleanup, a helper retry that could settle a
    restoration, and a preparation that propagated incomplete cleanup.  Each was
    falsified by a reproduction.  These tests are the standing form of that
    audit: the report may make the claim only while the code answers for it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _load(CURRENT_VALIDATION_REPORT)
        cls.closure = _load(CLOSURE_REPORT)

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def test_a_process_wide_ownership_claim_requires_a_process_wide_record(self) -> None:
        model = self.closure["process_wide_active_ownership_model"]
        if not model["one_active_record_per_process"]:
            self.skipTest("the report makes no process-wide ownership claim")
        first = ChildSubreaperOwnership()
        second = ChildSubreaperOwnership()
        reference = first.acquire_reference()
        self.addCleanup(reference.release)
        self.assertEqual(
            second.state()["depth"],
            first.state()["depth"],
            "the report claims one process-wide depth and the objects disagree",
        )
        self.assertEqual(second.state()["previous_value"], first.state()["previous_value"])
        for field in model["process_wide_facts"]:
            self.assertIn(field, po.ownership_architecture_description()["process_wide_facts"], field)

    def test_a_retryable_cleanup_claim_requires_a_reachable_operation(self) -> None:
        for name in self.closure["helper_debt_retry_model"]["retry_operations"]:
            with self.subTest(operation=name):
                self.assertIn(
                    name,
                    (
                        pw.CLEANUP_RETRY_REAP,
                        pw.CLEANUP_RETRY_RELEASE,
                        pw.CLEANUP_RETRY_SETTLE,
                        pw.CLEANUP_RETRY_NONE,
                    ),
                )
        # And the operation the code names for an unsettled cleanup is one a
        # production caller performs, not a label.
        source = inspect.getsource(pw.PrivateMountHelper.close)
        self.assertIn("_settle_restoration_debt", source)

    def test_a_completion_claim_is_rejected_while_debt_remains(self) -> None:
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        with _injected(_RestorationInjection.MISMATCH, self.before):
            evidence = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "close"))
        self.assertTrue(evidence["debt_outstanding"])
        self.assertFalse(
            evidence["cleanup_complete"],
            "a cleanup claimed completion while the process owed a restoration",
        )
        helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settle"))

    def test_a_production_propagation_claim_requires_fields_on_the_outcome(self) -> None:
        model = self.closure["production_propagation_model"]
        fields = {field.name for field in dataclasses.fields(ef.EffectExecutionOutcome)}
        for name in model["outcome_fields"]:
            with self.subTest(field=name):
                self.assertIn(name, fields, "the report claims a field the outcome does not carry")
        self.assertIsNotNone(
            ef._EffectPreparation.close.__annotations__.get("return"),
            "the report claims _EffectPreparation.close propagates and it returns None",
        )
        for name in model["propagating_call_sites"]:
            with self.subTest(site=name):
                self.assertTrue(name)

    def test_the_current_report_declares_a_retained_registry_requirement(self) -> None:
        model = self.closure["process_cleanup_registry_model"]
        for field in (
            "pid_bound",
            "retains_only_incomplete",
            "deterministic_ids",
            "bounded_drain",
            "capacity",
            "capacity_refusal",
            "removed_only_when_terminal",
            "idempotent",
            "retains_no_worktree_path",
        ):
            self.assertIn(field, model, field)
        self.assertTrue(model["pid_bound"])
        self.assertTrue(model["retains_only_incomplete"])
        self.assertEqual(model["capacity"], pw.CLEANUP_REGISTRY_CAPACITY)
        self.assertTrue(model["removed_only_when_terminal"])

    def test_the_superseded_claims_are_recorded_as_falsified(self) -> None:
        withdrawn = self.closure["superseded_claims_withdrawn"]
        self.assertTrue(withdrawn)
        for entry in withdrawn:
            with self.subTest(claim=entry["claim"]):
                self.assertTrue(entry["artifact"])
                self.assertTrue(entry["reproduction"])
                self.assertTrue(entry["corrected_claim"])
        superseded = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        previous = json.loads(superseded.decode("utf-8"))
        # The audited sentence is reproduced from the artifact that made it.
        self.assertIn(
            "admissible/paired_runner/effects.py::_EffectPreparation.close",
            previous["retryable_cleanup_lifecycle"]["callers_propagating_incomplete_cleanup"],
        )
        self.assertTrue(previous["retryable_cleanup_lifecycle"]["retryable_while_incomplete"])

    def test_exactly_one_physical_state_is_current(self) -> None:
        current = self.report[self.report["current_closure_key"]]["delegated_run"]
        self.assertIn(current["status"], PHYSICAL_STATUSES)
        self.assertEqual(self.report["current_closure_key"], "m2_process_owner_cleanup_propagation_closure")
        if current["status"] == "OPERATOR_QUALIFICATION_REQUIRED":
            self.assertIsNone(current["executed"])
            self.assertEqual(current["exact_result"], "")
            self.assertIn("OPERATOR_QUALIFICATION_REQUIRED", self.report["terminal_verdict"])
            self.assertFalse(
                self.report["independent_validation"][
                    "real_delegated_cgroup_qualification_of_this_repair"
                ]
            )
        else:
            self.assertIsInstance(current["executed"], int)
            self.assertEqual(current["skipped"], 0, "a delegated skip is never counted as a pass")
            self.assertEqual(current["failures"], 0)
            self.assertEqual(current["errors"], 0)
            self.assertIn(f"Ran {current['executed']} tests", current["exact_result"])
            self.assertIn("OK", current["exact_result"])

    def test_a_prior_transcript_never_qualifies_this_code(self) -> None:
        prior = self.report["prior_physical_qualification"]
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertIn("does not qualify", prior["scope"])
        self.assertEqual(prior["qualified_commit"], STARTING_COMMIT)
        self.assertEqual(prior["transcript"], "Ran 399 tests in 122.922s\n\nOK")
        self.assertTrue(
            self.closure["delegated_physical_qualification"][
                "prior_transcripts_do_not_qualify_modified_code"
            ]
        )


# --- closure artifacts --------------------------------------------------------


class ClosureArtifactCoherenceTests(unittest.TestCase):
    """The closure report, the current validation report and the matrix agree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _load(CURRENT_VALIDATION_REPORT)
        cls.closure = _load(CLOSURE_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)

    def test_the_closure_report_declares_the_bounded_findings(self) -> None:
        self.assertEqual(
            self.closure["bounded_findings"], ["M2-B45", "M2-B46", "M2-B47", "M2-B48", "M2-M49"]
        )
        self.assertEqual(self.closure["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.closure["starting_commit_parent"], STARTING_COMMIT_PARENT)
        self.assertEqual(self.closure["branch"], BRANCH)
        self.assertTrue(self.closure["sole_parent_required"])
        self.assertNotIn("ending_commit", self.closure)
        self.assertEqual(self.closure["schema_version"], 1)
        self.assertEqual(
            self.closure["schema_id"],
            "admissible.paired_runner.m2.process_owner_cleanup_propagation_closure_report",
        )

    def test_the_current_validation_report_points_at_this_closure(self) -> None:
        self.assertTrue(self.report["is_current_validation_report"])
        self.assertEqual(self.report["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.report["branch"], BRANCH)
        self.assertEqual(
            self.report["final_repair_report"],
            "implementation/M2_PROCESS_OWNER_CLEANUP_PROPAGATION_CLOSURE_REPORT.json",
        )
        self.assertEqual(self.report["terminal_verdict"], self.closure["terminal_verdict"])
        self.assertIn(
            "implementation/M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
            self.report["superseded_closure_reports"],
        )

    def test_the_independent_audit_is_recorded_verbatim(self) -> None:
        self.assertEqual(self.closure["independent_audit_sha256"], INDEPENDENT_AUDIT_SHA256)
        self.assertEqual(
            self.closure["independent_audit_verdicts"],
            [
                "M2_OWNERSHIP_DEBT_REAP_FINAL_INDEPENDENT_CLOSURE_REFUSED",
                "MILESTONE_3_NOT_PERMITTED",
            ],
        )
        self.assertEqual(
            self.report["independent_audit_sha256"], self.closure["independent_audit_sha256"]
        )
        self.assertEqual(
            self.report["independent_audit_verdicts"], self.closure["independent_audit_verdicts"]
        )

    def test_the_process_wide_ownership_model_matches_the_module(self) -> None:
        model = self.closure["process_wide_active_ownership_model"]
        self.assertTrue(model["one_active_record_per_process"])
        self.assertTrue(model["one_original_baseline"])
        self.assertTrue(model["one_refcount"])
        self.assertTrue(model["one_serialization_primitive"])
        self.assertTrue(model["reference_validity_follows_the_generation"])
        self.assertFalse(model["relies_on_import_discipline"])
        self.assertEqual(model["record"], "admissible/paired_runner/process_ownership.py::_PROCESS_ACTIVE_OWNERSHIP")
        self.assertEqual(
            sorted(model["process_wide_facts"]),
            sorted(po.ownership_architecture_description()["process_wide_facts"]),
        )

    def test_the_failed_start_settlement_model_matches_the_module(self) -> None:
        model = self.closure["failed_start_settlement_model"]
        self.assertEqual(
            model["completion_requires"],
            [
                "the exact child positively reaped",
                "the exact ownership reference released exactly once",
                "a positively settled restoration",
                "no outstanding process-wide restoration debt",
            ],
        )
        self.assertTrue(model["entry_retained_until_terminal"])
        self.assertTrue(model["release_exactly_once"])
        self.assertTrue(model["pid_bound"])
        self.assertEqual(model["settlement_operation"], "settle_restoration_debt")
        self.assertEqual(
            model["registry"],
            "admissible/paired_runner/private_workspace.py::_UNSETTLED_FAILED_STARTS",
        )

    def test_the_helper_debt_retry_model_matches_the_module(self) -> None:
        model = self.closure["helper_debt_retry_model"]
        self.assertEqual(model["design"], "INTEGRATED_SETTLEMENT_IN_HELPER_CLOSE")
        self.assertTrue(model["terminal_requires_exact_baseline_readback"])
        self.assertTrue(model["idempotent_once_terminal"])
        self.assertTrue(model["release_exactly_once"])
        self.assertTrue(model["settlement_may_repeat"])
        self.assertEqual(
            sorted(model["retry_operations"]),
            sorted(
                [
                    pw.CLEANUP_RETRY_REAP,
                    pw.CLEANUP_RETRY_RELEASE,
                    pw.CLEANUP_RETRY_SETTLE,
                    pw.CLEANUP_RETRY_NONE,
                ]
            ),
        )

    def test_the_cleanup_registry_model_matches_the_module(self) -> None:
        model = self.closure["process_cleanup_registry_model"]
        self.assertEqual(model["capacity"], pw.CLEANUP_REGISTRY_CAPACITY)
        self.assertEqual(
            model["registry"],
            "admissible/paired_runner/private_workspace.py::_CLEANUP_REGISTRY",
        )
        self.assertEqual(
            sorted(model["kinds"]),
            sorted(set(pw._CLEANUP_KINDS.values())),
            "the report names a different set of retained obligations than the registry keeps",
        )
        self.assertIn(pw.CLEANUP_KIND_EFFECT_CGROUP, model["kinds"])
        self.assertTrue(model["entry_removed_only_when_every_obligation_is_terminal"])
        self.assertTrue(model["process_ownership_settled_does_not_settle_a_cgroup"])
        self.assertTrue(model["removal_targets_the_owned_identity_only"])
        self.assertEqual(
            model["cgroup_settlement_order"],
            [
                "DESTROY_THE_PROCESS_DOMAIN_AS_A_KILL_DOMAIN",
                "VERIFY_QUIESCENCE_BY_A_POSITIVE_EMPTY_MEMBERSHIP_READ",
                "REAP_THE_EXACTLY_OWNED_MEMBERS",
                "REMOVE_THE_EXACT_OWNED_DIRECTORY_AND_VERIFY_ITS_ABSENCE",
            ],
        )
        self.assertEqual(model["capacity_refusal"], "cleanup_registry_saturated")
        self.assertTrue(model["retains_no_worktree_path"])
        self.assertTrue(model["bounded_drain"])
        self.assertTrue(model["idempotent"])

    def test_the_production_propagation_model_names_every_call_site(self) -> None:
        model = self.closure["production_propagation_model"]
        for site in (
            "admissible/paired_runner/private_workspace.py::PrivateExecutionView.materialize",
            "admissible/paired_runner/private_workspace.py::PrivateExecutionView.close",
            "admissible/paired_runner/runtime_binding.py::BoundRuntime.close",
            "admissible/paired_runner/effects.py::_run_command",
            "admissible/paired_runner/effects.py::_EffectPreparation.close",
            "admissible/paired_runner/effects.py::SharedEffectSubstrate._execute_permitted_effect",
        ):
            self.assertIn(site, model["propagating_call_sites"], site)
        self.assertEqual(model["incomplete_completion_code"], ef.LIFECYCLE_CLEANUP_INCOMPLETE)
        self.assertTrue(model["positive_completion_cannot_hide_unresolved_cleanup"])
        self.assertTrue(model["effect_boundary_truth_preserved"])

    def test_the_declared_deterministic_totals_match_the_modules_on_disk(self) -> None:
        totals = self.closure["deterministic_test_totals"]
        loader = unittest.defaultTestLoader
        self.assertEqual(
            loader.loadTestsFromName(
                "tests.test_admissible_paired_runner_m2_process_owner_cleanup_propagation_closure"
            ).countTestCases(),
            totals["new_module"],
        )
        self.assertEqual(
            totals["qualification_modules_total"],
            sum(loader.loadTestsFromName(module).countTestCases() for module in QUALIFICATION_MODULES),
        )

    def test_the_expected_delegated_total_matches_the_six_modules(self) -> None:
        run = self.report[self.report["current_closure_key"]]["delegated_run"]
        self.assertEqual(run["expected_modules"], list(QUALIFICATION_MODULES))
        expected = sum(
            unittest.defaultTestLoader.loadTestsFromName(module).countTestCases()
            for module in run["expected_modules"]
        )
        self.assertEqual(run["expected_total"], expected)
        if run["executed"] is not None:
            self.assertEqual(run["executed"], expected)

    def test_the_declared_module_counts_match_the_modules_on_disk(self) -> None:
        counts = self.report["m2_test_count_semantics"]
        modules = {
            "tests.test_admissible_paired_runner_m2_b25_cgroup_topology": "m2_b25_topology_module",
            "tests.test_admissible_paired_runner_m2_b25_final_failclosed": (
                "m2_b25_final_failclosed_module"
            ),
            "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle": (
                "m2_final_protocol_lifecycle_module"
            ),
            "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure": (
                "m2_subreaper_deadline_closure_module"
            ),
            "tests.test_admissible_paired_runner_m2_ownership_debt_reap_closure": (
                "m2_ownership_debt_reap_closure_module"
            ),
            "tests.test_admissible_paired_runner_m2_process_owner_cleanup_propagation_closure": (
                "m2_process_owner_cleanup_propagation_closure_module"
            ),
        }
        for module, field in modules.items():
            loader = unittest.defaultTestLoader.loadTestsFromName(module)
            self.assertEqual(loader.countTestCases(), counts[field], module)
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_legacy_pre_b25"] + sum(counts[field] for field in modules.values()),
        )
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_skipped"] + counts["m2_non_skipped"],
        )

    def test_the_verdicts_match_the_requirement_matrix(self) -> None:
        dispositions = {row["requirement_id"]: row for row in self.report["requirement_dispositions"]}
        records = {row["requirement_id"]: row for row in self.matrix["requirements"]}
        for requirement_id, row in dispositions.items():
            self.assertEqual(row["status"], records[requirement_id]["current_status"], requirement_id)
        self.assertEqual(records["EXEC-06"]["current_status"], "VERIFIED_INTEGRATION")
        self.assertEqual(
            records["EVID-08"]["current_status"],
            "IMPLEMENTED",
            "provider retry accounting is Milestone 3 work and is not closed here",
        )

    def test_the_matrix_records_this_closure_without_claiming_more(self) -> None:
        records = {row["requirement_id"]: row for row in self.matrix["requirements"]}
        for requirement_id in ("EXEC-06", "EVID-08"):
            with self.subTest(requirement=requirement_id):
                entry = records[requirement_id]["m2_process_owner_cleanup_propagation_closure"]
                self.assertEqual(
                    entry["closed_by"],
                    "implementation/M2_PROCESS_OWNER_CLEANUP_PROPAGATION_CLOSURE_REPORT.json",
                )
                self.assertEqual(
                    entry["findings"], ["M2-B45", "M2-B46", "M2-B47", "M2-B48", "M2-M49"]
                )
                self.assertTrue(entry["implemented"])
                self.assertTrue(entry["unit_verified"])
                self.assertFalse(entry["independently_accepted"])
                self.assertFalse(entry["installed_path_qualified"])
                self.assertIn(entry["physically_verified"], PHYSICAL_STATUSES)

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
        for entry in self.closure["requirements_not_closed"]:
            self.assertTrue(entry)

    def test_the_historical_reports_are_untouched(self) -> None:
        for name in self.closure["historical_reports_preserved"]:
            with self.subTest(artifact=name):
                original = subprocess.run(
                    ["git", "show", f"{STARTING_COMMIT}:{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((REPOSITORY_ROOT / name).read_bytes(), original)
        self.assertEqual(self.closure["historical_reports_rewritten"], [])

    def test_the_superseded_current_report_is_preserved_in_git(self) -> None:
        superseded = self.report["supersedes_prior_current_report"]
        self.assertEqual(superseded["commit"], STARTING_COMMIT)
        self.assertEqual(superseded["path"], "implementation/M2_VALIDATION_REPORT.json")
        committed = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/M2_VALIDATION_REPORT.json"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(superseded["sha256"], hashlib.sha256(committed).hexdigest())
        self.assertEqual(
            json.loads(committed.decode("utf-8"))["terminal_verdict"],
            "M2_OWNERSHIP_DEBT_REAP_CLOSURE_VERIFIED",
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
            "descendant containment",
            "truthful probe cleanup",
            "stale-topology refusal",
            "monotonic release truth",
            "controller-owned per-RPC deadlines",
            "PR_SET_CHILD_SUBREAPER + pidfd observation architecture",
            "controller-side positive launcher reap after helper loss",
            "typed cgroup.procs reads",
            "acquisition failure before normal fork",
            "fork-failure rollback",
            "restoration mismatch refusal",
            "sticky restoration debt for one ownership object",
            "one true global abort deadline",
            "exact configured-total preservation",
            "topology-cache test isolation",
            "reap-before-release on the tested helper paths",
            "retryable helper cleanup on the tested reap path",
        ):
            self.assertIn(statement, preserved, statement)
        self.assertEqual(self.closure["accepted_tests_weakened_or_deleted"], [])

    def test_the_operator_command_runs_every_qualification_module(self) -> None:
        command = self.closure["delegated_physical_qualification"]["operator_command"]
        self.assertIn(BRANCH, command)
        self.assertIn(STARTING_COMMIT, command)
        self.assertIn("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1", command)
        self.assertIn("Delegate=yes", command)
        for module in QUALIFICATION_MODULES:
            self.assertIn(module, command, module)

    def test_the_declared_deadlines_still_match_the_module(self) -> None:
        for name, value in self.closure["controller_deadlines_ms"].items():
            self.assertEqual(getattr(po, name), value, name)

    def test_the_prior_closure_report_is_byte_identical(self) -> None:
        committed = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(PRIOR_CLOSURE_REPORT.read_bytes(), committed)


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
        text = Path(__file__).read_text(encoding="utf-8").split("\nclass ", 1)[0]
        for forbidden in ("requests", "urllib", "http.client", "socketserver"):
            self.assertNotIn(f"import {forbidden}", text, forbidden)
            self.assertNotIn(f"from {forbidden}", text, forbidden)

    def test_the_boundary_audit_declares_every_frontier_uncrossed(self) -> None:
        audit = _load(CLOSURE_REPORT)["milestone_3_boundary_audit"]
        for boundary, crossed in audit.items():
            self.assertFalse(crossed, boundary)
        for required in (
            "milestone_3_permitted",
            "provider_transport_started",
            "owner_authority_started",
            "installed_path_qualification_started",
        ):
            self.assertIn(required, audit)

    def test_the_repository_worktree_is_never_the_effect_workspace(self) -> None:
        with DisposableWorkspace() as disposable:
            self.assertNotEqual(disposable.workspace, REPOSITORY_ROOT)
            self.assertFalse(str(disposable.workspace).startswith(str(REPOSITORY_ROOT)))

    def test_the_registry_never_retains_a_repository_path(self) -> None:
        text = json.dumps(pw.cleanup_registry_evidence())
        self.assertNotIn(str(REPOSITORY_ROOT), text)


# --- delegated physical qualification -----------------------------------------


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _receipt_diagnosis(outcome) -> str:
    lines = [f"receipt={outcome.receipt.status}"]
    result = getattr(outcome, "tool_result", None)
    if result is not None:
        lines.append(f"outcome={getattr(result, 'outcome', None)!r}")
        lines.append(f"error_code={getattr(result, 'error_code', None)!r}")
    lines.append(f"cleanup={getattr(outcome, 'lifecycle_cleanup', None)!r}")
    lines.append(f"child_subreaper={CHILD_SUBREAPER.state()!r}")
    lines.append(f"debt={po.process_restoration_debt()!r}")
    lines.append(f"delegation={ps.cgroup_delegation()!r}")
    return "\n".join(lines)


class DelegatedProcessOwnerCleanupPropagationTests(unittest.TestCase):
    """Physical qualification of the four code closures on real kernel state."""

    @classmethod
    def setUpClass(cls) -> None:
        if REQUIRE_DELEGATED and not DELEGATION.available:
            raise AssertionError(
                "ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1 but no delegated cgroup v2 "
                f"topology is available: {DELEGATION.detail}"
            )

    def setUp(self) -> None:
        guard_process_wide_cgroup_caches(self)
        self.before = _ProcessGuard.install(self)

    def _require_live_delegation(self) -> None:
        delegation = ps.cgroup_delegation()
        self.assertTrue(
            delegation.available,
            "the process-wide delegation cache is not usable before this effect: "
            f"code={delegation.code!r} detail={delegation.detail!r}",
        )

    def test_the_no_false_green_variable_forbids_skipping(self) -> None:
        if REQUIRE_DELEGATED:
            self.assertTrue(DELEGATION.available, DELEGATION.detail)
            self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        else:
            self.skipTest("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP is not set")

    @delegated
    def test_two_real_owners_share_one_real_process_wide_flag(self) -> None:
        """M2-B45 physically, against the real process-wide flag."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        first = ChildSubreaperOwnership()
        second = ChildSubreaperOwnership()
        first_reference = first.acquire_reference()
        self.assertEqual(po.get_child_subreaper()[0], 1, "the acquisition did not take")
        second_reference = second.acquire_reference()
        self.assertEqual(po.process_active_ownership()["depth"], 2)
        self.assertEqual(po.process_active_ownership()["original_baseline"], self.before)
        first_reference.release()
        observed, error = po.get_child_subreaper()
        self.assertIsNone(error)
        self.assertEqual(observed, 1, "the kernel flag was restored under a live reference")
        self.assertEqual(po.process_active_ownership()["depth"], 1)
        self.assertTrue(second_reference.valid)
        self.assertTrue(second.active)
        second_reference.release()
        observed, error = po.get_child_subreaper()
        self.assertIsNone(error)
        self.assertEqual(observed, self.before, "the exact baseline was not read back")
        self.assertEqual(po.process_active_ownership()["depth"], 0)
        self.assertFalse(second_reference.valid)
        self.assertIsNone(po.process_restoration_debt())

    @delegated
    def test_a_real_failed_start_settles_its_restoration_on_a_later_retry(self) -> None:
        """M2-B46 physically: a real child, a real release, a real settlement."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        reference = ChildSubreaperOwnership().acquire_reference()
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            try:
                time.sleep(30)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, child)
        with mock.patch.object(
            pw,
            "reap_owned_child",
            return_value=po.ReapOutcome(
                reaped=False,
                exit_code=None,
                reaper_role=po.REAPER_NONE,
                reaper_pid=None,
                detail="injected",
                code=po.REAP_DEADLINE_EXPIRED,
            ),
        ):
            pw._roll_back_failed_start(pid=child, sockets=(), descriptors=(), subreaper=reference)
        entry = [row for row in pw.unsettled_failed_starts() if row.helper_pid == child][0]
        with _injected(_RestorationInjection.MISMATCH, self.before):
            first = entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(first["helper_reaped"], first)
        self.assertFalse(first["cleanup_complete"])
        self.assertTrue(first["registry_retained"])
        self.assertFalse(po.process_is_zombie(child))
        settled = entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settle"))
        self.assertTrue(settled["cleanup_complete"], settled)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertIsNone(po.process_restoration_debt())
        self.assertNotIn(child, _child_pids())

    @delegated
    def test_a_real_helper_settles_its_restoration_on_a_later_close(self) -> None:
        """M2-B47 physically: real reap, unsettled restoration, exact readback."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        with _injected(_RestorationInjection.MISMATCH, self.before):
            first = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "close"))
        self.assertTrue(first["reaped"], first)
        self.assertFalse(first["cleanup_complete"])
        self.assertEqual(first["cleanup_retry_operation"], pw.CLEANUP_RETRY_SETTLE)
        self.assertIsNotNone(first["cleanup_registry_id"])
        self.assertEqual(po.get_child_subreaper()[0], 1, "the flag is not at the baseline yet")
        second = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settle"))
        self.assertTrue(second["cleanup_complete"], second)
        observed, error = po.get_child_subreaper()
        self.assertIsNone(error)
        self.assertEqual(observed, self.before, "the exact baseline was not read back")
        self.assertFalse(po.process_is_zombie(helper.pid))
        self.assertEqual(pw.incomplete_cleanups(), ())

    @delegated
    def test_an_incomplete_cleanup_survives_the_wrappers_that_detected_it(self) -> None:
        """M2-B48 physically, through the real substrate on a real cgroup."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-process-owner-cleanup")
        self.addCleanup(harness.close)
        before_children = _child_pids()
        descriptors = _open_descriptor_count()
        with _injected(_RestorationInjection.SET_FAILED, self.before):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertTrue((harness.workspace / "sentinel.txt").exists(), _receipt_diagnosis(outcome))
        self.assertTrue(outcome.effect_crossed_boundary)
        self.assertNotEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertEqual(outcome.tool_result.error_code, ef.LIFECYCLE_CLEANUP_INCOMPLETE)
        self.assertFalse(outcome.lifecycle_cleanup_complete)
        self.assertTrue(outcome.cleanup_registry_ids)
        retained = {entry.entry_id for entry in pw.incomplete_cleanups()}
        self.assertTrue(set(outcome.cleanup_registry_ids) <= retained, retained)
        results = pw.drain_incomplete_cleanups(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain")
        )
        self.assertTrue(all(row["cleanup_complete"] for row in results), results)
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(pw.unsettled_failed_starts(), ())
        self.assertTrue(_await(lambda: _child_pids() == before_children, 5.0), _child_pids())
        self.assertTrue(_await(lambda: _open_descriptor_count() <= descriptors + 1, 5.0))

    @delegated
    def test_a_real_unremovable_cgroup_is_retained_and_later_drained(self) -> None:
        """M2-B48 physically: a live domain, a refused removal, a real drain.

        The exact shape that leaked: a per-effect cgroup created by this
        controller, holding a launcher that outlives the frame which created it.
        ``close()`` refuses truthfully; before this closure nothing kept the
        object, so the directory survived for the life of the controller.
        """

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        parent = Path(DELEGATION.delegated_path)
        self._require_live_delegation()
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        launcher = helper.spawn([PYTHON, "-c", "import time\ntime.sleep(120)\n"])
        self.addCleanup(_close_quietly, launcher.stdout_fd)
        self.addCleanup(_close_quietly, launcher.stderr_fd)
        cgroup = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b50-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        path = Path(cgroup.path)
        self.assertTrue(cgroup.attach_and_verify(launcher.pid), cgroup.attach_error)

        # The frame that owns the cgroup disappears without removing it.
        self.assertFalse(cgroup.close(), "a populated cgroup was reported removed")
        removal = cgroup.removal_evidence()
        self.assertFalse(removal["removed"])
        self.assertIn(launcher.pid, removal["residual_members"])
        self.assertTrue(path.exists(), "the kernel removed a populated cgroup")
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id, "the unremoved cgroup was not retained")
        entry = pw._CLEANUP_REGISTRY.entry(entry_id)
        self.assertEqual(entry.kind, pw.CLEANUP_KIND_EFFECT_CGROUP)
        self.assertEqual(entry.evidence()["effect_cgroup_path"], str(path))
        self.assertIn(path, _effect_cgroups(parent), "the leak is not observable")
        del cgroup

        # A later bounded drain kills the domain, verifies quiescence, reaps
        # what it killed, and removes the exact directory.
        helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "helper_close"))
        results = pw.drain_incomplete_cleanups(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain")
        )
        drained = [row for row in results if row["entry_id"] == entry_id]
        self.assertEqual(len(drained), 1, results)
        self.assertTrue(drained[0]["cleanup_complete"], drained)
        self.assertTrue(drained[0]["removed"])
        self.assertFalse(path.exists(), "the exact owned cgroup survived the drain")
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(entry_id))
        self.assertFalse(po.process_is_zombie(launcher.pid), "the drain left a zombie")
        self.assertFalse(po.process_is_zombie(helper.pid))
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertIsNone(po.process_restoration_debt())
        # And a repeat performs nothing.
        self.assertEqual(
            pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "again")), []
        )

    @delegated
    def test_a_nominal_effect_completes_and_retains_nothing(self) -> None:
        """The accepted nominal path is unchanged by all four code closures."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-process-owner-nominal")
        self.addCleanup(harness.close)
        before_children = _child_pids()
        outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertTrue(outcome.lifecycle_cleanup_complete)
        self.assertEqual(outcome.cleanup_registry_ids, ())
        self.assertEqual(_effect_cgroups(parent), [])
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertEqual(pw.unsettled_failed_starts(), ())
        self.assertTrue(_await(lambda: _child_pids() == before_children, 5.0))

    @delegated
    def test_registry_capacity_refuses_a_real_effect_before_any_fork(self) -> None:
        """M2-B48 fail-closed, against the real substrate."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        self._require_live_delegation()
        harness = _Harness(run_id="run-process-owner-capacity")
        self.addCleanup(harness.close)
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _StubCleanup(helper_pid=4000 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "REFUSED", _receipt_diagnosis(outcome))
        self.assertFalse(outcome.effect_crossed_boundary)
        self.assertFalse(forked.called)
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(po.get_child_subreaper()[0], self.before)


if __name__ == "__main__":
    unittest.main()
