"""M2 ownership-debt and reap closure: B41, B42, B43, M44.

Each finding is closed by making an untrue statement impossible to produce.

M2-B41 -- a nested acquisition is an acquisition
    ``ChildSubreaperOwnership.acquire`` had a cached branch that incremented the
    reference count without asking the kernel anything.  A second acquisition
    could therefore be declared valid -- and authorize a second helper fork --
    while the process-wide flag had been cleared or contradicted underneath it,
    leaving a controller that believed it would inherit the right to reap an
    orphaned launcher it would in fact never be given.  Every acquisition that
    can authorize a fork now reads ``PR_GET_CHILD_SUBREAPER`` immediately before
    it increments the depth, and a contradiction refuses without touching the
    depth, the outstanding references, or the original baseline.

M2-B42 -- a failed restoration is a debt, not a footnote
    After a final release failed its restoration verification the object was
    left at depth zero with nothing owed on paper.  The next ``acquire`` then
    read the *residual* kernel value as a fresh baseline, overwrote the original
    one, and a later release could report a green ``RESTORED`` to a value this
    process never found.  A failed restoration now latches explicit process-wide
    ownership debt: the original baseline is immutable, every new acquisition
    refuses, replacing the ownership object inherits the debt rather than a
    clean slate, and only an explicit settlement that reads the owed baseline
    back can clear it.

M2-B43 -- reap before release, and an incomplete cleanup is retryable
    ``PrivateMountHelper.close`` set one flag on entry and used it for two
    questions.  A helper that could not be reaped inside the deadline therefore
    had its subreaper ownership released anyway -- the very flag that grants the
    right to reap it -- reported the restoration complete, and could never be
    retried, because the second call returned immediately.  Protocol closure and
    lifecycle completion are now separate states: ownership is released only
    after a positive reap of the exact PID, an incomplete cleanup stays
    retryable, and every caller propagates that truth rather than a flag.

M2-M44 -- one current physical qualification state
    The current validation report asserted both a verified delegated transcript
    and, in its current ``known_limitations``, that the qualification had not
    been performed.  The semantic tests here reject that combination in either
    direction, permanently, rather than repairing one sentence.

Deterministic tests drive real ``prctl`` calls, real forked helpers, real
zombies, real socket pairs, real private views, and injected kernel failures.
Delegated physical tests run the production path inside a real ``Delegate=yes``
cgroup v2 subtree and, under ``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail
rather than skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
import errno
import hashlib
import inspect
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
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
from admissible.paired_runner.resource_limits import (  # noqa: E402
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

#: Generous on purpose: the property under test is finiteness, not latency.
BOUND_SLACK_SECONDS = 10.0
#: A retry budget long enough that a real kill and reap always fit inside it.
RETRY_BUDGET_MS = 5_000

SENTINEL_SCRIPT = "open('sentinel.txt', 'w').write('the command executed')\n"
SLEEPER_SCRIPT = "import time\ntime.sleep(120)\n"


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


# --- shared fixtures ----------------------------------------------------------


class _OwnershipGuard:
    """Put back every process-wide fact a test can disturb.

    Three of them are genuinely process-wide: the child-subreaper flag itself,
    the M2-B42 restoration-debt latch that lives beside it, and the reference
    depth of the ownership domain.

    M2-B45 makes the third of those explicit.  The depth, baseline, owner PID,
    applied bit and activation generation are one record per process addressed
    by every ownership handle, so restoring "the singleton's fields" is no
    longer a description of anything: what is recorded and put back is the
    process-wide record itself, through the module's own capture and restore.
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
        return int(before or 0)


def _await(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _open_descriptor_count() -> int:
    try:
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))
    except OSError:  # pragma: no cover - /proc is part of the platform contract
        return -1


def _child_pids() -> list[int]:
    try:
        raw = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text(encoding="ascii")
    except OSError:  # pragma: no cover - CONFIG_PROC_CHILDREN absent
        return []
    return sorted(int(value) for value in raw.split())


def _resume(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGCONT)
    except OSError:
        pass


def _reap_quietly(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass


class _StoppedHelper:
    """A real trusted helper, alive and scheduled out, that will not exit.

    Nothing about the ownership topology is simulated: the helper unshared a
    real user+mount namespace, it is a real child of this controller, and it
    really holds the process-wide acquisition taken before it was forked.  It is
    stopped so that a bounded cleanup provably cannot reap it, which is the
    state M2-B43 is about.
    """

    def __init__(self, test: unittest.TestCase) -> None:
        self.helper = PrivateMountHelper.start()
        test.addCleanup(self.close)
        os.kill(self.helper.pid, signal.SIGSTOP)
        test.addCleanup(_resume, self.helper.pid)

    @property
    def pid(self) -> int:
        return self.helper.pid

    def close(self) -> None:
        _resume(self.helper.pid)
        try:
            self.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "fixture_close"))
        except Exception:  # pragma: no cover - the fixture never masks a failure
            pass
        _reap_quietly(self.helper.pid)


class _NoSignal:
    """Suppress exactly the SIGKILL a bounded cleanup would send.

    A helper that is stopped and then killed dies, and a single non-blocking
    ``waitpid`` after the kill would resolve by a race rather than by the
    property under test.  Suppressing the signal for one call makes the outcome
    a fact -- the helper is genuinely still there and genuinely unreaped -- with
    the reap itself left entirely real.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def __call__(self, pid: int, signal_number: int) -> dict:
        self.calls.append((int(pid), int(signal_number)))
        return {"pid": pid, "signal": int(signal_number), "delivered": False, "error": "SUPPRESSED"}


def _view(test: unittest.TestCase) -> PrivateExecutionView:
    """A real private execution view over a disposable source tree."""

    directory = Path(tempfile.mkdtemp(prefix="admissible-m2-b43-view-"))
    test.addCleanup(shutil.rmtree, str(directory), True)
    (directory / "tracked.txt").write_text("source\n", encoding="utf-8")
    source_fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    test.addCleanup(_close_quietly, source_fd)
    view = PrivateExecutionView.materialize(directory, source_fd)
    test.addCleanup(_close_view, view)
    return view


def _close_quietly(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _close_view(view: PrivateExecutionView) -> None:
    _resume(view.helper.pid)
    try:
        view.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "fixture_view_close"))
    except Exception:  # pragma: no cover - the fixture never masks a failure
        pass
    _reap_quietly(view.helper.pid)


# --- M2-B41: a nested acquisition must revalidate the live kernel -------------


class NestedAcquisitionRevalidationTests(unittest.TestCase):
    """A cached flag is a memory of a syscall, not an answer about now."""

    def setUp(self) -> None:
        self.before = _OwnershipGuard.install(self)
        self.ownership = ChildSubreaperOwnership()

    def _held(self) -> po.SubreaperReference:
        reference = self.ownership.acquire_reference()
        self.addCleanup(reference.release)
        return reference

    def test_a_nested_acquisition_reads_the_kernel_before_it_counts(self) -> None:
        self._held()
        reads = {"count": 0}
        real_read = po.get_child_subreaper

        def counting_read():
            reads["count"] += 1
            return real_read()

        with mock.patch.object(po, "get_child_subreaper", counting_read):
            state = self.ownership.acquire()
        self.assertGreaterEqual(
            reads["count"], 1, "the nested acquisition counted a reference without asking the kernel"
        )
        self.assertEqual(state["depth"], 2)
        self.assertEqual(state["ownership_state"], po.SUBREAPER_STATE_NESTED)
        self.ownership.release()

    def test_a_nested_acquisition_is_refused_when_the_flag_was_externally_cleared(self) -> None:
        """The audited defect: the kernel says 0 and the object says APPLIED."""

        self._held()
        self.assertEqual(po.get_child_subreaper()[0], 1)
        # Some other part of this process clears the process-wide flag.
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable) as raised:
            self.ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_NESTED_CONTRADICTED)
        self.assertIn("expected 1, observed 0", raised.exception.detail)

    def test_a_nested_acquisition_is_refused_when_the_readback_fails(self) -> None:
        self._held()
        with mock.patch.object(po, "get_child_subreaper", return_value=(None, "EPERM")):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                self.ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_NESTED_READBACK_FAILED)
        self.assertIn("EPERM", raised.exception.detail)

    def test_a_contradiction_changes_neither_the_depth_nor_the_reference(self) -> None:
        reference = self._held()
        before = self.ownership.state()
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable):
            self.ownership.acquire()
        after = self.ownership.state()
        self.assertEqual(after["depth"], before["depth"], "a refused acquisition counted a reference")
        self.assertEqual(after["depth"], 1)
        # The reference is *retained*: it was not released, not discarded, and it
        # is still the exact handle that will release this acquisition once.
        self.assertFalse(reference.released, "the outstanding reference was released by a refusal")
        self.assertIn(reference, [reference])
        self.assertEqual(reference.generation, po.ownership_generation())
        # M2-B45.  It does not, however, still describe ownership: the kernel has
        # been cleared underneath it and the process owes a restoration.  A
        # handle that answered "valid" here would be the object-local snapshot
        # speaking over a live contradiction, which is the defect this closes.
        self.assertFalse(
            reference.valid, "a handle reported valid ownership over a contradicted kernel flag"
        )
        self.assertFalse(self.ownership.active)

    def test_a_contradiction_preserves_the_original_baseline(self) -> None:
        self._held()
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable):
            self.ownership.acquire()
        state = self.ownership.state()
        self.assertEqual(state["previous_value"], self.before)
        self.assertEqual(state["original_baseline"], self.before)
        self.assertEqual(state["restoration_debt"]["owed_baseline"], self.before)

    def test_a_repeated_contradictory_acquisition_remains_refused(self) -> None:
        self._held()
        po.set_child_subreaper(0)
        codes = []
        for _ in range(3):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                self.ownership.acquire()
            codes.append(raised.exception.code)
        self.assertEqual(codes[0], po.SUBREAPER_NESTED_CONTRADICTED)
        for code in codes[1:]:
            self.assertIn(code, po.SUBREAPER_FORK_FORBIDDEN_CODES)
        self.assertEqual(self.ownership.state()["depth"], 1)

    def test_a_contradicted_ownership_is_never_reported_active(self) -> None:
        self._held()
        self.assertTrue(self.ownership.active)
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable):
            self.ownership.acquire()
        self.assertFalse(
            self.ownership.active,
            "a contradicted ownership still reported this process a child subreaper",
        )
        self.assertFalse(self.ownership.cleanup_complete)

    def test_the_outstanding_reference_can_still_be_released_after_a_contradiction(self) -> None:
        """A refusal must not strand the reference somebody still holds."""

        reference = self.ownership.acquire_reference()
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable):
            self.ownership.acquire()
        released = reference.release()
        self.assertIn(released["code"], po.SUBREAPER_RELEASE_RESULTS)
        self.assertEqual(self.ownership.state()["depth"], 0)

    def test_a_nested_acquisition_over_an_agreeing_kernel_still_counts(self) -> None:
        """The accepted reference-counting behaviour is not weakened."""

        self._held()
        second = self.ownership.acquire()
        self.assertEqual(second["code"], po.SUBREAPER_APPLIED)
        self.assertEqual(second["depth"], 2)
        self.assertTrue(self.ownership.active)
        retained = self.ownership.release()
        self.assertEqual(retained["code"], po.SUBREAPER_REFERENCE_RETAINED)
        self.assertEqual(po.get_child_subreaper()[0], 1)

    def test_no_fork_follows_a_contradicted_acquisition(self) -> None:
        """The production launch path, over the production owner's reference.

        ``PrivateMountHelper.start`` acquires from the module-level owner, so
        the reference held here is that owner's: the second acquisition the
        launch path makes is the nested one under test, and the fork that
        follows it is the fork that must not happen.
        """

        reference = CHILD_SUBREAPER.acquire_reference()
        self.addCleanup(reference.release)
        po.set_child_subreaper(0)
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            with self.assertRaises(PrivateWorkspaceError) as raised:
                PrivateMountHelper.start()
        self.assertFalse(forked.called, "a helper was forked without live proved ownership")
        self.assertEqual(raised.exception.code, "private_mountns_subreaper_unavailable")
        self.assertIn(po.SUBREAPER_NESTED_CONTRADICTED, str(raised.exception))

    def test_the_singleton_owner_refuses_the_same_way(self) -> None:
        """The production owner, not only a locally constructed one."""

        reference = CHILD_SUBREAPER.acquire_reference()
        self.addCleanup(reference.release)
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable) as raised:
            CHILD_SUBREAPER.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_NESTED_CONTRADICTED)
        self.assertFalse(CHILD_SUBREAPER.active)

    def test_every_ownership_state_refusal_is_declared(self) -> None:
        self.assertEqual(
            sorted(po.SUBREAPER_OWNERSHIP_STATE_REFUSALS),
            sorted(
                [
                    po.SUBREAPER_NESTED_READBACK_FAILED,
                    po.SUBREAPER_NESTED_CONTRADICTED,
                    po.SUBREAPER_NESTED_NOT_OWNED,
                    po.SUBREAPER_DEBT_OUTSTANDING,
                ]
            ),
        )
        self.assertNotIn(po.SUBREAPER_APPLIED, po.SUBREAPER_OWNERSHIP_STATE_REFUSALS)

    def test_the_fork_forbidden_codes_are_the_union_of_both_refusal_sets(self) -> None:
        self.assertEqual(
            sorted(po.SUBREAPER_FORK_FORBIDDEN_CODES),
            sorted(
                set(po.SUBREAPER_ACQUISITION_REFUSALS)
                | set(po.SUBREAPER_OWNERSHIP_STATE_REFUSALS)
            ),
        )
        self.assertNotIn(po.SUBREAPER_APPLIED, po.SUBREAPER_FORK_FORBIDDEN_CODES)

    def test_the_declared_ownership_states_are_exhaustive_and_distinct(self) -> None:
        self.assertEqual(len(set(po.SUBREAPER_STATES)), len(po.SUBREAPER_STATES))
        for state in (
            po.SUBREAPER_STATE_CLEAN,
            po.SUBREAPER_STATE_OWNED,
            po.SUBREAPER_STATE_NESTED,
            po.SUBREAPER_STATE_RESTORATION_OWED,
            po.SUBREAPER_STATE_POISONED,
            po.SUBREAPER_STATE_TERMINAL_RESTORED,
            po.SUBREAPER_STATE_INHERITED_DISCARDED,
        ):
            self.assertIn(state, po.SUBREAPER_STATES)
        for state in po.SUBREAPER_DEBT_STATES:
            self.assertIn(state, po.SUBREAPER_STATES)


# --- M2-B42: a failed restoration must stay owed ------------------------------


class RestorationDebtStickinessTests(unittest.TestCase):
    """Unresolved process-wide debt blocks reacquisition until it is settled."""

    def setUp(self) -> None:
        self.before = _OwnershipGuard.install(self)

    def _owning(self) -> ChildSubreaperOwnership:
        ownership = ChildSubreaperOwnership()
        ownership.acquire()
        return ownership

    def _fail_restoration(self, ownership: ChildSubreaperOwnership, injection: str) -> dict:
        matrix = {
            "set_failed": ("EPERM", (self.before, None)),
            "readback_failed": (None, (None, "EPERM")),
            "mismatch": (None, (1 - self.before, None)),
        }
        set_result, read_result = matrix[injection]
        with mock.patch.object(po, "set_child_subreaper", return_value=set_result):
            with mock.patch.object(po, "get_child_subreaper", return_value=read_result):
                return ownership.release()

    def test_a_restore_mismatch_blocks_the_next_acquisition(self) -> None:
        ownership = self._owning()
        result = self._fail_restoration(ownership, "mismatch")
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertTrue(result["debt_outstanding"])
        with self.assertRaises(ChildSubreaperUnavailable) as raised:
            ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)

    def test_a_restore_set_failure_blocks_the_next_acquisition(self) -> None:
        ownership = self._owning()
        result = self._fail_restoration(ownership, "set_failed")
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_SET_FAILED)
        with self.assertRaises(ChildSubreaperUnavailable) as raised:
            ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)

    def test_a_restore_readback_failure_blocks_the_next_acquisition(self) -> None:
        ownership = self._owning()
        result = self._fail_restoration(ownership, "readback_failed")
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_READBACK_FAILED)
        with self.assertRaises(ChildSubreaperUnavailable) as raised:
            ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)

    def test_repeated_reacquisition_attempts_stay_refused(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        for _ in range(4):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                ownership.acquire()
            self.assertEqual(raised.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)
        self.assertEqual(ownership.state()["depth"], 0)

    def test_the_original_baseline_is_never_redefined_by_a_later_attempt(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        owed = po.process_restoration_debt()["owed_baseline"]
        self.assertEqual(owed, self.before)
        # Every later contradiction updates what was last seen and never what is
        # owed: the baseline is the value this process actually found.
        for _ in range(3):
            with mock.patch.object(po, "set_child_subreaper", return_value=None):
                with mock.patch.object(po, "get_child_subreaper", return_value=(1 - self.before, None)):
                    ownership.settle_restoration_debt()
            self.assertEqual(po.process_restoration_debt()["owed_baseline"], owed)
        self.assertEqual(ownership.state()["original_baseline"], self.before)

    def test_the_residual_kernel_value_is_never_adopted_as_a_new_baseline(self) -> None:
        """The exact audited sequence: mismatch, then reacquire, then release."""

        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        # The process-wide flag is really still 1 here: the release could not
        # put it back.  A reacquisition that were granted would record 1 as its
        # baseline and later "restore" the flag to the value it should not have.
        self.assertEqual(po.get_child_subreaper()[0], 1)
        with self.assertRaises(ChildSubreaperUnavailable):
            ownership.acquire()
        self.assertEqual(ownership.state()["original_baseline"], self.before)
        replacement = ChildSubreaperOwnership()
        with self.assertRaises(ChildSubreaperUnavailable):
            replacement.acquire()
        self.assertEqual(replacement.state()["original_baseline"], self.before)

    def test_a_replacement_ownership_object_inherits_the_debt(self) -> None:
        """Replacing the object may not be a way to forget what is owed."""

        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        for _ in range(2):
            replacement = ChildSubreaperOwnership()
            self.assertTrue(replacement.debt_outstanding)
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                replacement.acquire()
            self.assertEqual(raised.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)

    def test_state_acquire_and_release_never_clear_the_debt(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        latched = po.process_restoration_debt()
        for _ in range(2):
            ownership.state()
            with self.assertRaises(ChildSubreaperUnavailable):
                ownership.acquire()
            ownership.release()
            self.assertIsNotNone(po.process_restoration_debt())
        self.assertEqual(po.process_restoration_debt()["owed_baseline"], latched["owed_baseline"])

    def test_a_settled_debt_restores_the_baseline_and_permits_acquisition(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        settlement = ownership.settle_restoration_debt()
        self.assertTrue(settlement["performed"])
        self.assertTrue(settlement["settled"], settlement)
        self.assertEqual(settlement["owed_baseline"], self.before)
        self.assertEqual(settlement["observed"], self.before)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(
            settlement["state"]["ownership_state"], po.SUBREAPER_STATE_TERMINAL_RESTORED
        )
        # Only now is an acquisition granted again.
        state = ownership.acquire()
        self.assertEqual(state["code"], po.SUBREAPER_APPLIED)
        self.assertEqual(state["previous_value"], self.before)
        ownership.release()

    def test_an_unsuccessful_settlement_remains_sticky(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", return_value=(1 - self.before, None)):
                settlement = ownership.settle_restoration_debt()
        self.assertTrue(settlement["performed"])
        self.assertFalse(settlement["settled"], settlement)
        self.assertIsNotNone(po.process_restoration_debt())
        with self.assertRaises(ChildSubreaperUnavailable) as raised:
            ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)
        self.assertEqual(po.process_restoration_debt()["attempts"], 1)

    def test_a_settlement_is_refused_while_a_reference_is_outstanding(self) -> None:
        """Restoring the baseline under a live helper would take back its right."""

        ownership = ChildSubreaperOwnership()
        held = ownership.acquire_reference()
        self.addCleanup(held.release)
        po.set_child_subreaper(0)
        with self.assertRaises(ChildSubreaperUnavailable):
            ownership.acquire()
        settlement = ownership.settle_restoration_debt()
        self.assertFalse(settlement["performed"])
        self.assertFalse(settlement["settled"])
        self.assertIn("outstanding", settlement["reason"])
        self.assertIsNotNone(po.process_restoration_debt())

    def test_settling_nothing_is_not_a_settlement(self) -> None:
        ownership = ChildSubreaperOwnership()
        settlement = ownership.settle_restoration_debt()
        self.assertFalse(settlement["performed"])
        self.assertFalse(settlement["settled"])
        self.assertIsNone(settlement["owed_baseline"])

    def test_no_release_after_a_debt_sequence_reports_restored(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        for _ in range(3):
            with self.assertRaises(ChildSubreaperUnavailable):
                ownership.acquire()
            result = ownership.release()
            self.assertNotEqual(result["code"], po.SUBREAPER_RESTORED)
            self.assertFalse(result["cleanup_complete"])
            self.assertFalse(result["restoration_verified"])

    def test_a_forked_child_cannot_settle_or_overwrite_the_parent_debt(self) -> None:
        """The debt is PID-bound: a child owes nothing and may settle nothing."""

        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        owed = po.process_restoration_debt()
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - child process
            code = 0
            try:
                os.close(read_fd)
                child = ChildSubreaperOwnership()
                report = {
                    "debt_visible": po.process_restoration_debt() is not None,
                    "settlement": child.settle_restoration_debt()["performed"],
                    "state": child.state()["ownership_state"],
                }
                os.write(write_fd, json.dumps(report).encode("utf-8"))
            except BaseException:
                code = 1
            finally:
                os._exit(code)
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as handle:
            raw = handle.read()
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, raw)
        report = json.loads(raw.decode("utf-8"))
        self.assertFalse(report["debt_visible"], "the child inherited a debt it does not owe")
        self.assertFalse(report["settlement"], "the child settled its parent's debt")
        # And the parent still owes exactly what it owed.
        self.assertEqual(po.process_restoration_debt(), owed)

    def test_a_failed_rewrite_during_a_refused_acquisition_owes_the_baseline(self) -> None:
        """Putting the previous value back is a restoration, and can fail."""

        ownership = ChildSubreaperOwnership()
        reads = {"count": 0}

        def read_after_write():
            reads["count"] += 1
            if reads["count"] == 1:
                return self.before, None
            if reads["count"] == 2:
                # The write of 1 reported success; the kernel disagrees, so the
                # acquisition is refused and the previous value is rewritten.
                return 0, None
            # ...and the rewrite's own readback disagrees with it too, so the
            # baseline this process found is still owed.
            return 1 - self.before, None

        with mock.patch.object(po, "set_child_subreaper", return_value=None):
            with mock.patch.object(po, "get_child_subreaper", read_after_write):
                with self.assertRaises(ChildSubreaperUnavailable) as raised:
                    ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_READBACK_MISMATCH)
        debt = po.process_restoration_debt()
        self.assertIsNotNone(debt, "an unobserved rewrite left nothing owed")
        self.assertEqual(debt["owed_baseline"], self.before)
        with self.assertRaises(ChildSubreaperUnavailable) as second:
            ownership.acquire()
        self.assertEqual(second.exception.code, po.SUBREAPER_DEBT_OUTSTANDING)

    def test_a_refused_acquisition_whose_rewrite_is_observed_owes_nothing(self) -> None:
        """The accepted B37 refusal path is unchanged when the flag is put back."""

        ownership = ChildSubreaperOwnership()
        with mock.patch.object(po, "set_child_subreaper", return_value="EINVAL"):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                ownership.acquire()
        self.assertEqual(raised.exception.code, po.SUBREAPER_SET_FAILED)
        self.assertIsNone(po.process_restoration_debt())
        self.assertEqual(ownership.acquire()["code"], po.SUBREAPER_APPLIED)
        ownership.release()

    def test_the_debt_is_recorded_in_every_ownership_state_document(self) -> None:
        ownership = self._owning()
        self._fail_restoration(ownership, "mismatch")
        state = ownership.state()
        self.assertTrue(state["debt_outstanding"])
        self.assertEqual(state["ownership_state"], po.SUBREAPER_STATE_RESTORATION_OWED)
        debt = state["restoration_debt"]
        self.assertEqual(debt["kind"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertEqual(debt["owner_pid"], os.getpid())
        self.assertEqual(debt["last_observed"], 1 - self.before)
        self.assertFalse(state["cleanup_complete"])
        for value in _walk_values(state):
            self.assertNotIsInstance(value, float, state)


def _walk_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_values(item)
    else:
        yield value


# --- M2-B43: reap before release, and retry what did not finish ---------------


class ReapBeforeReleaseTests(unittest.TestCase):
    """Ownership outlives an unreaped helper, never the other way round."""

    def setUp(self) -> None:
        self.before = _OwnershipGuard.install(self)

    def test_an_expired_deadline_leaves_the_helper_unreaped_and_owned(self) -> None:
        fixture = _StoppedHelper(self)
        depth_before = CHILD_SUBREAPER.state()["depth"]
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            closure = fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        self.assertFalse(closure["reaped"], closure)
        self.assertTrue(closure["ownership_retained"])
        self.assertFalse(closure["subreaper_released_by_this_call"])
        self.assertFalse(closure["cleanup_complete"])
        self.assertTrue(closure["cleanup_retryable"])
        self.assertTrue(closure["helper_present"] or closure["helper_zombie"])
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], depth_before)
        self.assertEqual(po.get_child_subreaper()[0], 1, "the flag was restored over a live helper")

    def test_cleanup_is_incomplete_while_the_helper_remains(self) -> None:
        fixture = _StoppedHelper(self)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        self.assertFalse(fixture.helper.cleanup_complete)
        self.assertTrue(fixture.helper.protocol_closed, "the protocol was not closed")
        lifecycle = fixture.helper.lifecycle()
        self.assertEqual(lifecycle["state"], pw.HELPER_LIFECYCLE_HELPER_ALIVE)
        self.assertTrue(lifecycle["protocol_closed"])
        self.assertFalse(lifecycle["helper_reaped"])
        self.assertTrue(lifecycle["ownership_retained"])
        self.assertFalse(lifecycle["ownership_released"])
        self.assertFalse(lifecycle["cleanup_complete"])

    def test_no_release_is_attempted_before_the_reap(self) -> None:
        fixture = _StoppedHelper(self)
        events: list[str] = []
        real_release = pw.PrivateMountHelper._release_subreaper

        def recording_release(helper):
            events.append("release")
            return real_release(helper)

        with mock.patch.object(pw.PrivateMountHelper, "_release_subreaper", recording_release):
            with mock.patch.object(pw, "signal_process", _NoSignal()):
                fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
            self.assertEqual(events, [], "ownership was released over an unreaped helper")
            _resume(fixture.pid)
            fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertEqual(events, ["release"], "the retry did not release exactly once")

    def test_a_second_call_with_a_live_budget_reaps_then_releases(self) -> None:
        fixture = _StoppedHelper(self)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            first = fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        self.assertFalse(first["cleanup_complete"])
        pid = fixture.pid
        second = fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(second["reaped"], second)
        self.assertEqual(second["reaper_pid"], os.getpid())
        self.assertTrue(second["subreaper_released_by_this_call"])
        self.assertTrue(second["cleanup_complete"])
        self.assertFalse(second["ownership_retained"])
        self.assertEqual(second["lifecycle"]["state"], pw.HELPER_LIFECYCLE_CLEANUP_COMPLETE)
        self.assertFalse(po.process_is_zombie(pid), "a zombie survived the retry")
        self.assertEqual(second["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_the_release_happens_exactly_once(self) -> None:
        fixture = _StoppedHelper(self)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        released = []
        for _ in range(3):
            closure = fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
            released.append(closure["subreaper_released_by_this_call"])
        self.assertEqual(released, [True, False, False], released)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)

    def test_a_repeated_call_after_completion_reaps_and_releases_nothing(self) -> None:
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        first = helper.close()
        self.assertTrue(first["cleanup_complete"], first)
        self.assertFalse(first["already_closed"])
        reaps: list[int] = []
        real_reap = pw.reap_owned_child

        def counting_reap(pid, deadline, *, role=po.REAPER_TRUSTED_CONTROLLER):
            reaps.append(pid)
            return real_reap(pid, deadline, role=role)

        with mock.patch.object(pw, "reap_owned_child", counting_reap):
            second = helper.close()
        self.assertTrue(second["already_closed"])
        self.assertTrue(second["cleanup_complete"])
        self.assertFalse(second["subreaper_released_by_this_call"])
        self.assertEqual(reaps, [], "a completed cleanup reaped again")

    def test_a_zombie_helper_is_positively_reaped_before_the_release(self) -> None:
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        os.kill(helper.pid, signal.SIGKILL)
        self.assertTrue(
            _await(lambda: po.process_is_zombie(helper.pid), 5.0), "the helper never became a zombie"
        )
        events: list[str] = []
        real_reap = pw.reap_owned_child
        real_release = pw.PrivateMountHelper._release_subreaper

        def recording_reap(pid, deadline, *, role=po.REAPER_TRUSTED_CONTROLLER):
            outcome = real_reap(pid, deadline, role=role)
            events.append(f"reap:{outcome.reaped}")
            return outcome

        def recording_release(instance):
            events.append("release")
            return real_release(instance)

        with mock.patch.object(pw, "reap_owned_child", recording_reap):
            with mock.patch.object(pw.PrivateMountHelper, "_release_subreaper", recording_release):
                closure = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "zombie"))
        self.assertTrue(closure["reaped"], closure)
        self.assertIn("release", events)
        self.assertEqual(events[events.index("release") - 1], "reap:True")
        self.assertFalse(po.process_is_zombie(helper.pid))
        self.assertTrue(closure["cleanup_complete"])

    def test_a_concurrent_unrelated_child_is_never_reaped(self) -> None:
        """The retry waits on one PID, so nothing else of ours is consumed."""

        unrelated = os.fork()
        if unrelated == 0:  # pragma: no cover - child process
            try:
                time.sleep(30)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, unrelated)
        fixture = _StoppedHelper(self)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        waited, _status = os.waitpid(unrelated, os.WNOHANG)
        self.assertEqual(waited, 0, "the bounded cleanup consumed an unrelated child")

    def test_no_cleanup_path_waits_on_a_non_addressable_pid(self) -> None:
        for function in (
            pw.PrivateMountHelper.close,
            pw.PrivateMountHelper.terminate_and_reap,
            pw._roll_back_failed_start,
            pw._UnsettledFailedStart.retry,
        ):
            with self.subTest(function=function.__qualname__):
                source = inspect.getsource(function)
                self.assertNotIn("waitpid(-1", source)
                self.assertNotIn("waitpid(0", source)
                self.assertNotIn("os.waitpid", source)

    def test_protocol_closure_is_not_lifecycle_completion(self) -> None:
        """The two questions that one flag used to answer."""

        fixture = _StoppedHelper(self)
        self.assertFalse(fixture.helper.protocol_closed)
        self.assertFalse(fixture.helper.cleanup_complete)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        self.assertTrue(fixture.helper.protocol_closed)
        self.assertFalse(fixture.helper.cleanup_complete)
        with self.assertRaises(PrivateWorkspaceError):
            fixture.helper.spawn([PYTHON, "-c", "pass"])
        fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(fixture.helper.protocol_closed)
        self.assertTrue(fixture.helper.cleanup_complete)

    def test_a_helper_reaped_by_the_abort_path_still_closes_its_descriptors(self) -> None:
        """Lifecycle completion may not skip the closure of what is still open.

        The bounded abort path can reap the helper and end its ownership before
        any shutdown runs.  A close that treated the ownership lifecycle as the
        whole answer would then return without closing the socket and the view
        descriptor this object still holds.
        """

        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        before = _open_descriptor_count()
        helper.terminate_and_reap(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "abort"))
        released = helper.release_subreaper_if_reaped(
            deadline=Deadline.after_ms(1_000, "release")
        )
        self.assertTrue(released["performed"], released)
        self.assertTrue(helper.cleanup_complete, "the abort path did not end the lifecycle")
        self.assertFalse(helper.protocol_closed, "the abort path closed the protocol socket")
        closure = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "close"))
        self.assertFalse(closure["already_closed"], "the shutdown skipped its own descriptors")
        self.assertTrue(closure["cleanup_complete"])
        self.assertLess(
            _open_descriptor_count(), before, "the socket and view descriptor leaked"
        )
        repeat = helper.close()
        self.assertTrue(repeat["already_closed"])

    def test_the_declared_lifecycle_states_are_distinct(self) -> None:
        self.assertEqual(len(set(pw.HELPER_LIFECYCLE_STATES)), len(pw.HELPER_LIFECYCLE_STATES))
        for state in (
            pw.HELPER_LIFECYCLE_PROTOCOL_OPEN,
            pw.HELPER_LIFECYCLE_HELPER_ALIVE,
            pw.HELPER_LIFECYCLE_EXIT_OBSERVED,
            pw.HELPER_LIFECYCLE_REAPED_OWNERSHIP_RETAINED,
            pw.HELPER_LIFECYCLE_CLEANUP_COMPLETE,
        ):
            self.assertIn(state, pw.HELPER_LIFECYCLE_STATES)

    def test_the_abort_path_still_refuses_to_release_over_a_live_helper(self) -> None:
        """The accepted M2-B40 ordering, restated as the same invariant."""

        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        self.addCleanup(helper.close)
        release = helper.release_subreaper_if_reaped(
            deadline=Deadline.after_ms(1_000, "release")
        )
        self.assertFalse(release["performed"])
        self.assertFalse(release["helper_reaped"])
        self.assertTrue(release["ownership_retained"])
        self.assertTrue(CHILD_SUBREAPER.active)


class FailedStartRollbackOrderingTests(unittest.TestCase):
    """A rollback that cannot reap its child keeps the ownership it needs."""

    def setUp(self) -> None:
        self.before = _OwnershipGuard.install(self)
        self.addCleanup(self._drain)

    def _drain(self) -> None:
        for pending in pw.unsettled_failed_starts():
            _resume(pending.helper_pid)
            pending.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))
            _reap_quietly(pending.helper_pid)
            if pending in pw._UNSETTLED_FAILED_STARTS:
                pw._UNSETTLED_FAILED_STARTS.remove(pending)

    def test_a_rollback_over_an_unreaped_child_retains_the_acquisition(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
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
            evidence = pw._roll_back_failed_start(
                pid=child, sockets=(), descriptors=(), subreaper=reference
            )
        self.assertFalse(evidence["helper_reaped"])
        self.assertFalse(evidence["subreaper_released"])
        self.assertTrue(evidence["ownership_retained"])
        self.assertFalse(evidence["cleanup_complete"])
        self.assertTrue(evidence["cleanup_retryable"])
        self.assertEqual(ownership.state()["depth"], 1, "the acquisition was released too early")
        self.assertEqual(po.get_child_subreaper()[0], 1)
        pending = [entry for entry in pw.unsettled_failed_starts() if entry.helper_pid == child]
        self.assertEqual(len(pending), 1, "the incomplete rollback left nothing to retry")

    def test_a_retry_reaps_then_releases_exactly_once(self) -> None:
        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
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
        results = pw.retry_unsettled_failed_starts(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry")
        )
        mine = [entry for entry in results if entry["helper_pid"] == child]
        self.assertEqual(len(mine), 1, results)
        self.assertTrue(mine[0]["helper_reaped"], mine[0])
        self.assertTrue(mine[0]["subreaper_released"])
        self.assertTrue(mine[0]["cleanup_complete"])
        self.assertEqual(mine[0]["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(ownership.state()["depth"], 0)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertFalse(po.process_is_zombie(child))
        # The entry is gone, so a later sweep releases nothing a second time.
        self.assertEqual(
            [entry for entry in pw.unsettled_failed_starts() if entry.helper_pid == child], []
        )

    def test_a_rollback_that_reaps_releases_immediately(self) -> None:
        """The accepted M2-B38 behaviour, unchanged where the reap succeeds."""

        ownership = ChildSubreaperOwnership()
        reference = ownership.acquire_reference()
        evidence = pw._roll_back_failed_start(
            pid=None, sockets=(), descriptors=(), subreaper=reference
        )
        self.assertTrue(evidence["subreaper_released"])
        self.assertTrue(evidence["cleanup_complete"])
        self.assertEqual(evidence["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(ownership.state()["depth"], 0)


class ViewAndCallerCleanupPropagationTests(unittest.TestCase):
    """Every caller reports the cleanup that happened, not the one it asked for."""

    def setUp(self) -> None:
        self.before = _OwnershipGuard.install(self)

    def test_the_private_execution_view_propagates_incomplete_cleanup(self) -> None:
        view = _view(self)
        os.kill(view.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, view.helper.pid)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            first = view.close(deadline=Deadline.already_expired("expired_close"))
        self.assertFalse(first["cleanup_complete"], first)
        self.assertTrue(first["ownership_retained"])
        self.assertFalse(view.cleanup_complete)
        _resume(view.helper.pid)
        second = view.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(second["cleanup_complete"], second)
        self.assertTrue(view.cleanup_complete)
        third = view.close()
        self.assertTrue(third["already_closed"])
        self.assertTrue(third["cleanup_complete"])

    def test_the_bound_runtime_returns_the_views_cleanup_evidence(self) -> None:
        view = _view(self)
        runtime = rb.BoundRuntime.__new__(rb.BoundRuntime)
        descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(4)]
        (
            runtime.launcher_fd,
            runtime.interpreter_fd,
            runtime.init_fd,
            runtime.workspace_fd,
        ) = descriptors
        runtime.private_view = view
        runtime._closed = False
        runtime.private_view_cleanup = None
        os.kill(view.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, view.helper.pid)
        # Nothing about the shutdown is faked: it spends its whole real bound
        # against a helper that is stopped and, with the kill suppressed, never
        # exits.  The reap therefore genuinely fails.
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            first = runtime.close()
        self.assertFalse(first["cleanup_complete"], first)
        self.assertEqual(runtime.private_view_cleanup["cleanup_complete"], False)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        _resume(view.helper.pid)
        second = runtime.close()
        self.assertTrue(second["cleanup_complete"], second)
        self.assertTrue(runtime.private_view_cleanup["cleanup_complete"])

    def test_the_preparation_keeps_the_view_while_its_cleanup_is_incomplete(self) -> None:
        view = _view(self)

        class _Chain:
            closed = False

            def close(self) -> None:
                self.closed = True

        chain = _Chain()
        preparation = ef._EffectPreparation(chain=chain, private_view=view)
        os.kill(view.helper.pid, signal.SIGSTOP)
        self.addCleanup(_resume, view.helper.pid)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            preparation.close()
        self.assertTrue(chain.closed)
        self.assertIsNotNone(
            preparation.private_view, "the only handle to an unreaped helper was dropped"
        )
        self.assertFalse(preparation.private_view_cleanup["cleanup_complete"])
        _resume(view.helper.pid)
        preparation.close()
        self.assertTrue(preparation.private_view_cleanup["cleanup_complete"])
        self.assertIsNone(preparation.private_view)


# --- M2-M44: one current physical qualification state -------------------------


CURRENT_VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
CLOSURE_REPORT = IMPLEMENTATION / "M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json"
PRIOR_CLOSURE_REPORT = IMPLEMENTATION / "M2_SUBREAPER_DEADLINE_CLOSURE_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
STARTING_COMMIT = "2f7eaac796e6f4b3d93419ac3087183302b2a54e"
STARTING_COMMIT_PARENT = "c30bf3d38445f59271b61ad4db8520ed053af281"
BRANCH = "paired-runner/m2-ownership-debt-reap-closure"
QUALIFICATION_MODULES = (
    "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
    "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
    "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
    "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
    "tests.test_admissible_paired_runner_m2_ownership_debt_reap_closure",
)
#: Phrases that assert a physical qualification has *not* happened.  In a
#: current artifact whose run is verified, every one of them is a contradiction.
PENDING_PHRASES = (
    "has not been performed",
    "not yet been performed",
    "has not yet been performed",
    "not yet performed",
    "qualification is pending",
    "nothing physical is claimed",
    "no physical qualification",
    "not physically qualified",
)
#: The keys whose subtrees are explicitly historical.  Everything else in the
#: current report speaks about the present.
HISTORICAL_KEYS = (
    "first_delegated_qualification",
    "prior_physical_qualification",
    "supersedes_prior_current_report",
    "supersedes_validation_report",
    "superseded_closure_reports",
    "delegated_qualification_findings",
    "historical_delegated_qualifications",
)
PHYSICAL_STATUSES = (
    "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2",
    "OPERATOR_QUALIFICATION_REQUIRED",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _current_subtree(value):
    """The report with every explicitly historical subtree removed."""

    if isinstance(value, dict):
        return {
            key: _current_subtree(item)
            for key, item in value.items()
            if key not in HISTORICAL_KEYS
        }
    if isinstance(value, list):
        return [_current_subtree(item) for item in value]
    return value


def _statuses(value) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        status = value.get("status")
        if isinstance(status, str) and status in PHYSICAL_STATUSES:
            found.append(status)
        for item in value.values():
            found.extend(_statuses(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_statuses(item))
    return found


def _accompanying_validation_report() -> dict:
    """The validation report that was current when *this* closure was.

    The M2 model keeps exactly one current validation report and a later pass
    moves it.  These assertions are about this closure, so they follow the
    report that accompanied it: the live report names the commit whose blob it
    superseded, that blob is loaded from git, and its hash is checked against
    the one the live report records.  Anchoring to whatever happens to be
    current later would make this class assert another pass's claims.
    """

    report = _load(CURRENT_VALIDATION_REPORT)
    seen: set[tuple[str, str]] = set()
    while report.get("current_closure_key") != "m2_ownership_debt_reap_closure":
        superseded = report["supersedes_prior_current_report"]
        link = (superseded["commit"], superseded["path"])
        assert link not in seen, "the superseded-report chain loops"
        seen.add(link)
        raw = subprocess.run(
            ["git", "show", f"{superseded['commit']}:{superseded['path']}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        assert hashlib.sha256(raw).hexdigest() == superseded["sha256"], superseded["path"]
        report = json.loads(raw.decode("utf-8"))
    return report


class ValidationArtifactSemanticCoherenceTests(unittest.TestCase):
    """A current artifact states one physical qualification state, or refuses."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.live = _load(CURRENT_VALIDATION_REPORT)
        cls.report = _accompanying_validation_report()
        cls.current = cls.report[cls.report["current_closure_key"]]
        cls.delegated = cls.current["delegated_run"]

    def test_the_current_physical_state_forbids_the_language_of_the_other(self) -> None:
        """The exact M2-M44 defect, in both directions and without skipping.

        A skip here would be a hole in the delegated qualification, which is
        required to have none: whichever state the current report is in, this
        asserts the language that state forbids.
        """

        self.assertIn(self.delegated["status"], PHYSICAL_STATUSES)
        text = json.dumps(_current_subtree(self.report), sort_keys=True).lower()
        if self.delegated["status"] == "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
            for phrase in PENDING_PHRASES:
                self.assertNotIn(
                    phrase,
                    text,
                    f"a current field says {phrase!r} beside a verified delegated transcript",
                )
            return
        # The other direction: an unperformed run may not read as a performed
        # one anywhere in the current subtree.
        for phrase in ("physically_verified_on_delegated_cgroup_v2", "zero skips, zero failures"):
            self.assertNotIn(
                phrase,
                text,
                f"a current field says {phrase!r} while no run has been performed",
            )
        self.assertTrue(
            any(phrase in text for phrase in PENDING_PHRASES),
            "an unperformed qualification is not disclosed anywhere in the current report",
        )

    def test_an_unperformed_run_claims_nothing(self) -> None:
        if self.delegated["status"] != "OPERATOR_QUALIFICATION_REQUIRED":
            # A performed run is checked by the verified-verdict test below; this
            # one states what an *unperformed* record may not contain, and
            # returns rather than skipping so the delegated run has no holes.
            self.assertIsNotNone(self.delegated["executed"])
            return
        self.assertIsNone(self.delegated["executed"])
        self.assertEqual(self.delegated["exact_result"], "")
        self.assertFalse(
            self.report["independent_validation"][
                "real_delegated_cgroup_qualification_of_this_repair"
            ]
        )
        self.assertIn("OPERATOR_QUALIFICATION_REQUIRED", self.report["terminal_verdict"])
        self.assertNotIn("CLOSURE_VERIFIED", self.report["terminal_verdict"])

    def test_a_verified_verdict_requires_a_qualifying_transcript(self) -> None:
        verdict = self.report["terminal_verdict"]
        if "VERIFIED" not in verdict:
            self.assertIn("OPERATOR_QUALIFICATION_REQUIRED", verdict)
            return
        self.assertEqual(self.delegated["status"], "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2")
        self.assertIsInstance(self.delegated["executed"], int)
        self.assertIn(f"Ran {self.delegated['executed']} tests", self.delegated["exact_result"])
        self.assertIn("OK", self.delegated["exact_result"])
        self.assertEqual(self.delegated["skipped"], 0, "a delegated skip is never counted as a pass")
        self.assertEqual(self.delegated["failures"], 0)
        self.assertEqual(self.delegated["errors"], 0)

    def test_exactly_one_current_physical_state_exists(self) -> None:
        statuses = _statuses(_current_subtree(self.report))
        self.assertEqual(
            len(statuses), 1, f"the current report asserts {len(statuses)} physical states: {statuses}"
        )
        self.assertEqual(statuses[0], self.delegated["status"])

    def test_a_historical_failed_run_is_never_presented_as_current(self) -> None:
        historical = self.report.get("historical_delegated_qualifications") or []
        self.assertTrue(historical, "the earlier failed run was discarded rather than preserved")
        for entry in historical:
            with self.subTest(entry=entry.get("status")):
                self.assertNotIn(entry["status"], PHYSICAL_STATUSES)
                self.assertFalse(entry["qualifies_the_current_revision"])
                self.assertTrue(entry["exact_result"])
        failed = [entry for entry in historical if entry["failures"]]
        self.assertTrue(failed, "the 303-test failure is no longer preserved")
        self.assertEqual(failed[0]["executed"], 303)
        self.assertEqual(failed[0]["failures"], 2)

    def test_the_current_known_limitations_do_not_contradict_each_other(self) -> None:
        limitations = self.report["known_limitations"]
        self.assertTrue(limitations)
        pending = [
            line
            for line in limitations
            if any(phrase in line.lower() for phrase in PENDING_PHRASES)
        ]
        verified = [line for line in limitations if "re-qualified" in line or "passing" in line]
        if self.delegated["status"] == "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
            self.assertEqual(
                pending, [], "a current limitation denies the verified run beside it"
            )
        else:
            self.assertTrue(
                pending, "an unperformed qualification is not disclosed as a limitation"
            )
            for line in verified:
                self.assertIn(
                    "historical",
                    line.lower(),
                    "a verified transcript of an earlier revision is stated as current",
                )

    def test_a_prior_transcript_is_never_offered_as_qualifying_this_code(self) -> None:
        prior = self.report["prior_physical_qualification"]
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertIn("does not qualify", prior["scope"])
        self.assertTrue(prior["transcript"], "the prior transcript was discarded")
        self.assertRegex(prior["qualified_commit"], r"^[0-9a-f]{40}$")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", prior["qualified_commit"], STARTING_COMMIT],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
        )
        self.assertEqual(ancestor.returncode, 0, "the prior transcript claims a later commit")

    def test_the_stale_pending_statement_is_gone_from_the_current_limitations(self) -> None:
        """The literal sentence M2-M44 names, in the artifact it named."""

        stale = (
            "The delegated physical qualification of this closure has not been performed; the "
            "operator command is recorded and nothing physical is claimed until its transcript "
            "replaces the delegated_run object."
        )
        superseded = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/M2_VALIDATION_REPORT.json"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        previous = json.loads(superseded.decode("utf-8"))
        self.assertIn(stale, previous["known_limitations"], "the audited sentence is not reproduced")
        self.assertEqual(
            previous[previous["current_closure_key"]]["delegated_run"]["status"],
            "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2",
            "the audited contradiction is not reproduced",
        )
        self.assertNotIn(stale, self.report["known_limitations"])


# --- closure artifacts --------------------------------------------------------


class ClosureArtifactCoherenceTests(unittest.TestCase):
    """The closure report, the current validation report and the matrix agree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.live = _load(CURRENT_VALIDATION_REPORT)
        cls.report = _accompanying_validation_report()
        cls.closure = _load(CLOSURE_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)

    def test_the_closure_report_declares_the_bounded_findings(self) -> None:
        self.assertEqual(
            self.closure["bounded_findings"], ["M2-B41", "M2-B42", "M2-B43", "M2-M44"]
        )
        self.assertEqual(self.closure["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.closure["starting_commit_parent"], STARTING_COMMIT_PARENT)
        self.assertEqual(self.closure["branch"], BRANCH)
        self.assertTrue(self.closure["sole_parent_required"])
        self.assertNotIn("ending_commit", self.closure)
        self.assertEqual(self.closure["schema_version"], 1)
        self.assertEqual(
            self.closure["schema_id"], "admissible.paired_runner.m2.ownership_debt_reap_closure_report"
        )

    def test_the_validation_report_of_this_closure_points_at_it(self) -> None:
        self.assertTrue(self.report["is_current_validation_report"])
        self.assertEqual(self.report["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.report["branch"], BRANCH)
        self.assertEqual(
            self.report["final_repair_report"],
            "implementation/M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
        )
        self.assertEqual(self.report["current_closure_key"], "m2_ownership_debt_reap_closure")
        self.assertEqual(self.report["terminal_verdict"], self.closure["terminal_verdict"])
        # Exactly one validation report is current -- whether or not that is
        # still this closure's.  A later pass moves it and must record this
        # closure as superseded rather than simply forgetting it.
        self.assertTrue(self.live["is_current_validation_report"])
        if self.live != self.report:
            self.assertIn(
                "implementation/M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
                self.live["superseded_closure_reports"],
                "the later current report does not record this closure as superseded",
            )
            self.assertNotEqual(self.live["current_closure_key"], "m2_ownership_debt_reap_closure")

    def test_the_independent_audit_is_recorded_verbatim(self) -> None:
        self.assertEqual(
            self.closure["independent_audit_sha256"],
            "5365b0c4fc561a562ce30824807531ac9fee10b5aeea513cd6ae65b1363e00c5",
        )
        self.assertEqual(
            self.closure["independent_audit_verdicts"],
            [
                "M2_SUBREAPER_DEADLINE_FINAL_INDEPENDENT_CLOSURE_REFUSED",
                "MILESTONE_3_NOT_PERMITTED",
            ],
        )
        self.assertEqual(
            self.report["independent_audit_sha256"], self.closure["independent_audit_sha256"]
        )
        self.assertEqual(
            self.report["independent_audit_verdicts"], self.closure["independent_audit_verdicts"]
        )

    def test_the_closure_report_declares_the_revalidation_model(self) -> None:
        model = self.closure["nested_acquisition_revalidation_model"]
        self.assertTrue(model["kernel_read_before_every_depth_increment"])
        self.assertEqual(model["required_value"], 1)
        self.assertTrue(model["owner_pid_verified"])
        self.assertFalse(model["cached_branch_can_authorize_a_fork"])
        self.assertEqual(
            sorted(model["refusals"]), sorted(po.SUBREAPER_OWNERSHIP_STATE_REFUSALS)
        )

    def test_the_closure_report_declares_the_debt_state_machine(self) -> None:
        machine = self.closure["restoration_debt_state_machine"]
        self.assertEqual(sorted(machine["states"]), sorted(po.SUBREAPER_STATES))
        self.assertEqual(sorted(machine["unsettled_results"]), sorted(po.SUBREAPER_UNSETTLED_RESULTS))
        self.assertTrue(machine["baseline_immutable"])
        self.assertTrue(machine["pid_bound"])
        self.assertTrue(machine["survives_object_replacement"])
        self.assertFalse(machine["cleared_by_state_acquire_or_release"])
        self.assertEqual(machine["settlement_operation"], "settle_restoration_debt")

    def test_the_closure_report_declares_the_reap_before_release_ordering(self) -> None:
        ordering = self.closure["reap_before_release_ordering"]
        self.assertEqual(
            ordering["order"],
            ["OBSERVE_OR_FORCE_EXIT", "REAP_THE_EXACT_PID", "RELEASE_THE_ACQUISITION_ONCE"],
        )
        self.assertTrue(ordering["applies_to_normal_close"])
        self.assertTrue(ordering["applies_to_abort_cleanup"])
        self.assertTrue(ordering["applies_to_failed_start_rollback"])
        self.assertTrue(ordering["applies_to_repeated_cleanup"])
        self.assertFalse(ordering["waitpid_over_minus_one_reachable"])

    def test_the_closure_report_declares_the_retryable_lifecycle(self) -> None:
        lifecycle = self.closure["retryable_cleanup_lifecycle"]
        self.assertEqual(sorted(lifecycle["states"]), sorted(pw.HELPER_LIFECYCLE_STATES))
        self.assertTrue(lifecycle["idempotent_once_complete"])
        self.assertTrue(lifecycle["retryable_while_incomplete"])
        self.assertTrue(lifecycle["release_exactly_once"])

    def test_the_declared_deterministic_totals_match_the_modules_on_disk(self) -> None:
        totals = self.closure["deterministic_test_totals"]
        loader = unittest.defaultTestLoader
        self.assertEqual(
            loader.loadTestsFromName(
                "tests.test_admissible_paired_runner_m2_ownership_debt_reap_closure"
            ).countTestCases(),
            totals["new_module"],
        )
        self.assertEqual(
            totals["qualification_modules_total"],
            sum(
                loader.loadTestsFromName(module).countTestCases()
                for module in QUALIFICATION_MODULES
            ),
        )

    def test_the_expected_delegated_total_matches_the_five_modules(self) -> None:
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
        # The modules on disk are the current ones, so the counts they are
        # compared against must come from the current report; a frozen
        # historical decomposition describes modules that have moved on.
        counts = self.live["m2_test_count_semantics"]
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
            "tests.test_admissible_paired_runner_m2_cgroup_identity_reap_registry_serialization_closure": (
                "m2_cgroup_identity_reap_registry_serialization_closure_module"
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

    def test_the_matrix_records_this_closure_without_claiming_more(self) -> None:
        records = {row["requirement_id"]: row for row in self.matrix["requirements"]}
        for requirement_id in ("EXEC-06", "EVID-08"):
            with self.subTest(requirement=requirement_id):
                entry = records[requirement_id]["m2_ownership_debt_reap_closure"]
                self.assertEqual(
                    entry["closed_by"],
                    "implementation/M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
                )
                self.assertEqual(entry["findings"], ["M2-B41", "M2-B42", "M2-B43", "M2-M44"])
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
            "M2_SUBREAPER_DEADLINE_CLOSURE_VERIFIED",
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
            "tested fork-failure rollback paths",
            "tested restoration mismatch",
            "one true global abort deadline",
            "exact configured total preservation",
            "topology-cache test isolation",
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


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _receipt_diagnosis(outcome) -> str:
    lines = [f"receipt={outcome.receipt.status}"]
    result = getattr(outcome, "result", None)
    if result is not None:
        lines.append(f"outcome={getattr(result, 'outcome', None)!r}")
        lines.append(f"error_code={getattr(result, 'error_code', None)!r}")
    lines.append(f"child_subreaper={CHILD_SUBREAPER.state()!r}")
    lines.append(f"debt={po.process_restoration_debt()!r}")
    lines.append(f"delegation={ps.cgroup_delegation()!r}")
    return "\n".join(lines)


class DelegatedOwnershipDebtReapTests(unittest.TestCase):
    """Physical qualification of the three code closures on real kernel state."""

    @classmethod
    def setUpClass(cls) -> None:
        if REQUIRE_DELEGATED and not DELEGATION.available:
            raise AssertionError(
                "ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1 but no delegated cgroup v2 "
                f"topology is available: {DELEGATION.detail}"
            )

    def setUp(self) -> None:
        guard_process_wide_cgroup_caches(self)
        self.before = _OwnershipGuard.install(self)

    def _require_live_delegation(self) -> None:
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
    def test_a_cleared_kernel_flag_refuses_the_next_real_acquisition(self) -> None:
        """M2-B41 physically, against the real process-wide flag."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        reference = CHILD_SUBREAPER.acquire_reference()
        self.addCleanup(reference.release)
        self.assertEqual(po.get_child_subreaper()[0], 1, "the acquisition did not take")
        depth = CHILD_SUBREAPER.state()["depth"]
        # The process-wide flag is cleared by something that is not this owner.
        self.assertIsNone(po.set_child_subreaper(0))
        self.assertEqual(po.get_child_subreaper()[0], 0)
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            with self.assertRaises(ChildSubreaperUnavailable) as raised:
                CHILD_SUBREAPER.acquire()
            with self.assertRaises(PrivateWorkspaceError):
                PrivateMountHelper.start()
        self.assertIn(raised.exception.code, po.SUBREAPER_FORK_FORBIDDEN_CODES)
        self.assertFalse(forked.called, "a helper was forked after a contradicted acquisition")
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], depth, "the refusal counted a reference")
        self.assertFalse(CHILD_SUBREAPER.active)

    @delegated
    def test_a_real_restoration_mismatch_blocks_reacquisition_until_settled(self) -> None:
        """M2-B42 physically: injected readback, real flag, real settlement."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        ownership = ChildSubreaperOwnership()
        ownership.acquire()
        self.assertEqual(po.get_child_subreaper()[0], 1)
        with mock.patch.object(po, "get_child_subreaper", return_value=(1 - self.before, None)):
            with mock.patch.object(po, "set_child_subreaper", return_value=None):
                result = ownership.release()
        self.assertEqual(result["code"], po.SUBREAPER_RESTORE_MISMATCH)
        self.assertTrue(result["debt_outstanding"])
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            with self.assertRaises(PrivateWorkspaceError):
                PrivateMountHelper.start()
        self.assertFalse(forked.called, "a helper was forked while a restoration was owed")
        settlement = ownership.settle_restoration_debt()
        self.assertTrue(settlement["settled"], settlement)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        closure = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settled_close"))
        self.assertTrue(closure["cleanup_complete"], closure)
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    @delegated
    def test_an_expired_deadline_leaves_a_real_helper_unreaped_and_owned(self) -> None:
        """M2-B43 physical test A."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        fixture = _StoppedHelper(self)
        depth = CHILD_SUBREAPER.state()["depth"]
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            closure = fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        self.assertTrue(
            po.process_present(fixture.pid) or po.process_is_zombie(fixture.pid),
            "the helper neither survived nor became a zombie",
        )
        self.assertFalse(closure["reaped"], closure)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], depth, "ownership was released early")
        self.assertEqual(po.get_child_subreaper()[0], 1, "the kernel flag was restored early")
        self.assertFalse(closure["cleanup_complete"])
        self.assertTrue(closure["ownership_retained"])
        self.assertIn(fixture.pid, _child_pids())

    @delegated
    def test_a_retry_reaps_the_exact_pid_and_releases_exactly_once(self) -> None:
        """M2-B43 physical test B."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        fixture = _StoppedHelper(self)
        with mock.patch.object(pw, "signal_process", _NoSignal()):
            fixture.helper.close(deadline=Deadline.already_expired("expired_close"))
        pid = fixture.pid
        retry = fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
        self.assertTrue(retry["reaped"], retry)
        self.assertEqual(retry["reaper_pid"], os.getpid())
        self.assertEqual(retry["reaper_role"], po.REAPER_TRUSTED_CONTROLLER)
        self.assertFalse(po.process_is_zombie(pid), "a zombie survived the retry")
        self.assertNotIn(pid, _child_pids())
        self.assertTrue(retry["subreaper_released_by_this_call"])
        self.assertEqual(retry["subreaper"]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertTrue(retry["cleanup_complete"])
        again = fixture.helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "again"))
        self.assertTrue(again["already_closed"])
        self.assertFalse(again["subreaper_released_by_this_call"])
        self.assertIsNone(po.process_restoration_debt())

    @delegated
    def test_a_nominal_effect_still_completes_and_leaves_nothing_owed(self) -> None:
        """The accepted nominal path is unchanged by all three code closures."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        self._require_live_delegation()
        harness = _Harness(run_id="run-ownership-debt-reap")
        self.addCleanup(harness.close)
        before_children = _child_pids()
        outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(_effect_cgroups(parent), [])
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertIsNone(po.process_restoration_debt(), "a nominal effect left a debt")
        self.assertTrue(CHILD_SUBREAPER.cleanup_complete)
        self.assertEqual(pw.unsettled_failed_starts(), ())
        self.assertTrue(_await(lambda: _child_pids() == before_children, 5.0))

    @delegated
    def test_a_wedged_effect_abort_still_retains_ownership_for_a_live_helper(self) -> None:
        """The accepted abort ordering, restated against a real cgroup domain."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        self.addCleanup(helper.close)
        launcher = helper.spawn([PYTHON, "-c", SLEEPER_SCRIPT])
        self.addCleanup(_close_quietly, launcher.stdout_fd)
        self.addCleanup(_close_quietly, launcher.stderr_fd)
        cgroup = EffectCgroup(DELEGATION, ResourceBounds.for_timeout(1000), f"debt-{os.getpid()}")
        self.assertTrue(cgroup.create(), cgroup.create_error)
        self.addCleanup(cgroup.close)
        self.assertTrue(cgroup.attach_and_verify(launcher.pid), cgroup.attach_error)
        release = launcher.release_owned_subreaper(Deadline.after_ms(1_000, "release"))
        self.assertFalse(release["performed"], release)
        self.assertTrue(release["ownership_retained"])
        self.assertTrue(CHILD_SUBREAPER.active)
        self.assertEqual(po.get_child_subreaper()[0], 1)


if __name__ == "__main__":
    unittest.main()
