"""M2 cgroup-identity / reap / registry-serialization closure: B50-B54, M55.

Each finding is closed by making an untrue statement impossible to produce.

M2-B50 -- exact cgroup identity before every action
    ``EffectCgroup.settle_cleanup`` resolved a *pathname*, read its membership,
    wrote ``cgroup.kill``, signalled the PIDs it had just enumerated, waited for
    quiescence, attempted a reap, and only then -- inside ``close()`` -- asked
    whether the pathname still named the directory this controller created.  The
    identity check therefore protected the final ``rmdir`` and nothing else: a
    same-named replacement had already been enumerated, already been killed and
    already had its members signalled by the time it ran.  Ownership is now a
    *capability*: a directory descriptor opened at creation, the ``dev:ino``
    observed through it, and a descriptor for the parent that holds the name.
    Every read that informs a destructive decision and every destructive action
    is descriptor-relative, and each is preceded by a proof that the descriptor
    still addresses the exact created object.

M2-B51 -- a positive reap is a separate terminal obligation
    Containment settlement took one membership snapshot, called
    ``waitpid(pid, WNOHANG)`` once over it, accepted ``0``, ``ECHILD`` and any
    ``OSError`` indiscriminately, removed the directory, and declared terminal
    cleanup from the cgroup's absence.  A removed cgroup does not prove a child
    was reaped; a process that joined after the snapshot was never in the reap
    set at all; and ``ECHILD`` means "not this controller's child", which is
    equally true of a process somebody else reaped and of one nobody did.
    Process obligations are now retained per exact PID, independently of
    membership, and terminal cleanup requires containment *and* a positive reap
    by this controller or durable evidence naming another trusted reaper.

M2-B52 -- the registry is atomic, hard-bounded and fail-closed
    ``require_capacity()`` checked and returned; ``record()`` then allocated an
    id and inserted unconditionally, with a whole effect in between and no lock
    anywhere.  The cgroup registrar called ``record()`` after the effect could
    already have crossed its boundary, and swallowed every exception it raised --
    leaving an obligation that advertised a retry, carried no registry id, and
    had no surviving process-level handle.  Capacity is now *reserved*
    atomically before an obligation can be created, carried through, and
    converted exactly once; every registry transition happens under one lock;
    and a registration that fails is a typed lifecycle failure whose handle this
    process keeps.

M2-B53 -- linear release and serialised cleanup
    ``SubreaperReference.release`` was an unprotected check-then-set: two
    threads could both observe ``_released is False`` and both call the owner's
    release, and a loser of the race read back an empty document as though it
    were the terminal result.  Helper closure, failed-start retry and cgroup
    settlement had the same shape against a concurrent registry drain.  Each is
    now a linear capability with an explicit lock.

M2-B54 -- one deadline for one whole drain
    A drain with no caller deadline created a fresh helper-shutdown deadline
    *inside the loop*, once per entry, so a "bounded" drain at capacity could
    spend sixty-four complete budgets.  One absolute deadline is now created
    before the iteration and every entry receives only what is left of it.

M2-M55 -- one coherent current validation state
    The committed artifacts carried two different current M2 totals: 761/43 in
    the transcript and count section, 749/42 in the closure report and the
    regression section.  There is now exactly one canonical current run object,
    byte-identical in both reports, and the historical totals are explicitly
    historical.

Deterministic tests drive real descriptors, real forked children, real zombies,
real threads, the real process cleanup registry and a constructed cgroup tree.
Delegated physical tests run the production path inside a real ``Delegate=yes``
cgroup v2 subtree and, under ``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail
rather than skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
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
from admissible.paired_runner.private_workspace import (  # noqa: E402
    CleanupRegistrySaturated,
    PrivateMountHelper,
)
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    ChildSubreaperOwnership,
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

BRANCH = "paired-runner/m2-cgroup-identity-reap-registry-serialization-closure"
STARTING_COMMIT = "fd4e9fb409f648da356f90b9ca2c211183267354"
STARTING_COMMIT_PARENT = "4a451c859bc528d6281bfd1368ab3ca74fd3933c"
CLOSURE_REPORT = IMPLEMENTATION / "M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_CLOSURE_REPORT.json"
VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"

#: The contradictory pair M2-M55 closes.  They may appear only as history.
HISTORICAL_M2_TOTAL = 749
HISTORICAL_M2_SKIPPED = 42

RETRY_BUDGET_MS = 5_000
SENTINEL_SCRIPT = "open('sentinel.txt', 'w').write('the command executed')\n"

_REAL_MKDIR = Path.mkdir


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

    The child-subreaper flag, the restoration-debt latch, the active ownership
    record and the cleanup registry are process-wide, so a test that leaves any
    of them changed decides the outcome of every test after it.
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

    It is never kernel evidence: the delegated class at the end of this module
    drives the same production code against a real ``Delegate=yes`` subtree.
    This fixture exists so what is *refused* -- which reads happen, which writes
    happen, which processes are signalled, which object is removed -- is
    provable without privilege on a host that delegates nothing.
    """

    def __init__(self, test: unittest.TestCase) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-b50-identity-"))
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
        # The fixture models exactly that, and records every write it saw so a
        # test can state which object a destructive write actually reached.
        self.writes: list[tuple[str, str]] = []
        real_write = rl._write_control

        def killing_write(path, text, **kwargs):
            error = real_write(path, text, **kwargs)
            target = Path(path)
            self.writes.append((str(target), text))
            if error is not None or target.name != "cgroup.kill":
                return error
            # The kernel empties the cgroup the write actually reached, which is
            # the directory the descriptor names -- never whatever the pathname
            # happens to resolve to now.  The fixture models exactly that, so a
            # test can state which object a destructive write reached.
            dir_fd = kwargs.get("dir_fd")
            if dir_fd is None:
                procs = target.parent / "cgroup.procs"
                if procs.exists():
                    procs.write_text("", encoding="utf-8")
                return error
            try:
                handle = os.open("cgroup.procs", os.O_WRONLY | os.O_TRUNC, dir_fd=dir_fd)
            except OSError:
                return error
            os.close(handle)
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


class _CgroupFixture(unittest.TestCase):
    """A constructed delegated parent plus the production EffectCgroup over it."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        self.fake = _FakeEffectParent(self)
        self.delegation = self.fake.delegation()

    def cgroup(self, label: str) -> rl.EffectCgroup:
        cgroup = rl.EffectCgroup(self.delegation, rl.ResourceBounds.for_timeout(1_000), label)
        self.assertTrue(cgroup.create(), cgroup.create_error)
        return cgroup

    def populate(self, cgroup: rl.EffectCgroup, text: str) -> None:
        (Path(cgroup.path) / "cgroup.procs").write_text(text, encoding="utf-8")

    def replace_with_populated(self, cgroup: rl.EffectCgroup, members: str) -> Path:
        """Move the owned cgroup aside and put a populated impostor in its place.

        The owned inode is moved rather than freed, so the replacement is
        guaranteed to be a different inode and not a reused one.
        """

        path = Path(cgroup.owned_path)
        moved = path.parent / f"moved-{path.name}"
        os.rename(path, moved)
        self.addCleanup(shutil.rmtree, str(moved), True)
        _REAL_MKDIR(path)
        (path / "cgroup.procs").write_text(members, encoding="utf-8")
        (path / "cgroup.kill").write_text("0\n", encoding="utf-8")
        self.assertNotEqual(
            rl._directory_identity(path),
            rl._directory_identity(moved),
            "the fixture reused an inode",
        )
        return path


# --- M2-B50: exact identity before every read and every destructive action ----


class DescriptorBoundCgroupIdentityTests(_CgroupFixture):
    """Ownership is a descriptor, not a name."""

    def test_creation_binds_a_directory_descriptor_and_its_identity(self) -> None:
        cgroup = self.cgroup(f"bind-{os.getpid()}")
        self.assertTrue(cgroup.descriptor_bound, "no capability was retained")
        info = os.stat(cgroup.owned_path)
        self.assertEqual(cgroup.owned_identity, f"{info.st_dev}:{info.st_ino}")
        identity = cgroup.verify_owned_identity()
        self.assertTrue(identity["verified"], identity)
        self.assertEqual(identity["code"], rl.CGROUP_IDENTITY_VERIFIED)
        self.assertEqual(identity["observed_identity"], cgroup.owned_identity)
        self.assertEqual(identity["name_identity"], cgroup.owned_identity)
        cgroup.close()

    def test_a_populated_replacement_receives_no_cgroup_kill(self) -> None:
        cgroup = self.cgroup(f"nokill-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close(), "a populated cgroup was reported removed")
        impostor = self.replace_with_populated(cgroup, "919191\n")
        self.fake.writes.clear()
        evidence = cgroup.kill_domain()
        self.assertFalse(evidence["identity_verified"], evidence)
        self.assertEqual(evidence["mechanism"], "REFUSED_IDENTITY_UNPROVEN")
        self.assertEqual(evidence["members_signalled"], [])
        self.assertEqual(
            [row for row in self.fake.writes if row[0].startswith(str(impostor))],
            [],
            "cgroup.kill reached the replacement",
        )
        self.assertEqual(
            (impostor / "cgroup.procs").read_text(encoding="utf-8"),
            "919191\n",
            "the replacement's membership was cleared by a kill",
        )

    def test_a_populated_replacement_receives_no_per_member_signal(self) -> None:
        cgroup = self.cgroup(f"nosignal-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        impostor = self.replace_with_populated(cgroup, "919191\n")
        (impostor / "cgroup.kill").unlink()  # force the per-member signal path
        killed: list[int] = []
        with mock.patch.object(os, "kill", lambda pid, sig: killed.append(int(pid))):
            evidence = cgroup.kill_domain()
        self.assertEqual(killed, [], "a member of the replacement was signalled")
        self.assertEqual(evidence["members_signalled"], [])
        self.assertFalse(evidence["identity_verified"])

    def test_a_symlink_replacement_is_refused_before_any_read_or_write(self) -> None:
        cgroup = self.cgroup(f"symlink-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        path = Path(cgroup.owned_path)
        moved = path.parent / "moved-symlink-target"
        os.rename(path, moved)
        self.addCleanup(shutil.rmtree, str(moved), True)
        elsewhere = self.fake.root / "elsewhere"
        _REAL_MKDIR(elsewhere)
        (elsewhere / "cgroup.procs").write_text("717171\n", encoding="utf-8")
        os.symlink(str(elsewhere), str(path))
        identity = cgroup.verify_owned_identity()
        self.assertFalse(identity["verified"])
        self.assertEqual(identity["code"], rl.CGROUP_IDENTITY_NAME_NOT_A_DIRECTORY)
        self.fake.writes.clear()
        killed: list[int] = []
        with mock.patch.object(os, "kill", lambda pid, sig: killed.append(int(pid))):
            cgroup.kill_domain()
            self.assertFalse(cgroup.close())
        self.assertEqual(killed, [])
        self.assertEqual(self.fake.writes, [], "a write followed a symlink replacement")
        self.assertEqual(
            (elsewhere / "cgroup.procs").read_text(encoding="utf-8"), "717171\n"
        )
        self.assertTrue(Path(str(path)).is_symlink(), "the symlink was destroyed")

    def test_a_swap_between_the_check_and_the_action_cannot_redirect_it(self) -> None:
        """The action is descriptor-relative, so a later swap reaches nothing."""

        cgroup = self.cgroup(f"swap-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        real_read = rl.read_cgroup_members
        swapped: dict[str, Path] = {}

        def read_then_swap(path, **kwargs):
            membership = real_read(path, **kwargs)
            if "impostor" not in swapped and Path(path).name.startswith(rl.EFFECT_PREFIX):
                # Exactly the window the old code left open: the membership has
                # been read and the destructive write has not happened yet.
                swapped["impostor"] = self.replace_with_populated(cgroup, "919191\n")
            return membership

        with mock.patch.object(rl, "read_cgroup_members", read_then_swap):
            cgroup.kill_domain()
        impostor = swapped["impostor"]
        self.assertEqual(
            (impostor / "cgroup.procs").read_text(encoding="utf-8"),
            "919191\n",
            "the swap redirected the kill onto the replacement",
        )

    def test_membership_reads_still_address_the_original_object(self) -> None:
        cgroup = self.cgroup(f"reads-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        moved_members = "515151\n"
        path = Path(cgroup.owned_path)
        moved = path.parent / "moved-reads"
        os.rename(path, moved)
        self.addCleanup(shutil.rmtree, str(moved), True)
        (moved / "cgroup.procs").write_text(moved_members, encoding="utf-8")
        _REAL_MKDIR(path)
        (path / "cgroup.procs").write_text("919191\n", encoding="utf-8")
        membership = cgroup.read_members()
        self.assertEqual(
            list(membership.pids), [515151], "the read followed the name, not the descriptor"
        )

    def test_final_removal_targets_only_the_exact_owned_object(self) -> None:
        cgroup = self.cgroup(f"removal-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        impostor = self.replace_with_populated(cgroup, "")
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(500, "settle"))
        removal = settlement["removal"]
        self.assertFalse(removal["removed"], "a replacement cgroup was removed")
        self.assertFalse(removal["identity_verified"])
        self.assertEqual(removal["code"], rl.CGROUP_IDENTITY_NAME_REPLACED)
        self.assertTrue(impostor.exists(), "the impostor directory was destroyed")
        self.assertFalse(settlement["cleanup_complete"])
        self.assertIsNotNone(cgroup.cleanup_registry_id)

    def test_external_disappearance_discharges_without_adopting_a_replacement(self) -> None:
        cgroup = self.cgroup(f"vanish-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id)
        path = Path(cgroup.owned_path)
        shutil.rmtree(path)
        # Something else takes the name straight afterwards.  The obligation is
        # discharged by the disappearance of the *object*, and the replacement
        # is neither adopted nor touched.
        _REAL_MKDIR(path)
        (path / "cgroup.procs").write_text("818181\n", encoding="utf-8")
        self.addCleanup(shutil.rmtree, str(path), True)
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(500, "settle"))
        self.assertTrue(settlement["settled"])
        self.assertTrue(settlement["cleanup_complete"], settlement)
        self.assertTrue(settlement["removal"]["absence_verified"])
        self.assertFalse(settlement["removal"]["removed"], "it claimed a removal it did not perform")
        self.assertEqual(
            (path / "cgroup.procs").read_text(encoding="utf-8"),
            "818181\n",
            "the replacement was adopted and emptied",
        )
        self.assertTrue(path.exists(), "the replacement was removed")
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(entry_id))

    def test_an_unreadable_parent_refuses_rather_than_claiming_exactness(self) -> None:
        cgroup = self.cgroup(f"parent-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        real_stat = os.stat

        def failing(path, *args, **kwargs):
            if path == cgroup._leaf and kwargs.get("dir_fd") == cgroup._parent_fd:
                raise PermissionError(13, "EACCES")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(os, "stat", failing):
            identity = cgroup.verify_owned_identity()
            evidence = cgroup.kill_domain()
        self.assertFalse(identity["verified"])
        self.assertEqual(identity["code"], rl.CGROUP_IDENTITY_PARENT_UNREADABLE)
        self.assertEqual(evidence["mechanism"], "REFUSED_IDENTITY_UNPROVEN")

    def test_an_attach_into_a_replacement_is_refused(self) -> None:
        cgroup = self.cgroup(f"attach-{os.getpid()}")
        impostor = self.replace_with_populated(cgroup, "")
        self.assertFalse(cgroup.attach(os.getpid()), "a process was moved into a replacement")
        self.assertIn(rl.CGROUP_IDENTITY_NAME_REPLACED, cgroup.attach_error)
        self.assertEqual((impostor / "cgroup.procs").read_text(encoding="utf-8"), "")

    def test_every_identity_refusal_is_recorded_with_its_operation(self) -> None:
        cgroup = self.cgroup(f"refusals-{os.getpid()}")
        self.populate(cgroup, "424242\n")
        self.assertFalse(cgroup.close())
        self.replace_with_populated(cgroup, "919191\n")
        cgroup.kill_domain()
        cgroup.close()
        operations = [row["operation"] for row in cgroup.identity_refusals]
        self.assertIn("kill_domain", operations)
        self.assertIn("close", operations)
        for row in cgroup.identity_refusals:
            self.assertFalse(row["verified"])
            self.assertTrue(row["detail"])

    def test_the_capability_is_released_only_once_nothing_remains(self) -> None:
        before = _open_descriptor_count()
        cgroup = self.cgroup(f"fds-{os.getpid()}")
        self.assertGreaterEqual(_open_descriptor_count(), before + 2)
        self.assertTrue(cgroup.close())
        self.assertTrue(cgroup.cleanup_complete)
        self.assertFalse(cgroup.descriptor_bound, "the capability outlived the obligation")
        self.assertLessEqual(_open_descriptor_count(), before)


# --- M2-B51: a positive reap is a separate terminal obligation ----------------


class OwnedProcessReapObligationTests(_CgroupFixture):
    """An absent cgroup is containment, never lifecycle."""

    def _sleeping_child(self) -> int:
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            try:
                time.sleep(30)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, child)
        return child

    def test_waitpid_zero_retains_the_entry_and_reports_incomplete(self) -> None:
        cgroup = self.cgroup(f"pending-{os.getpid()}")
        child = self._sleeping_child()
        cgroup.record_owned_process(child, role="TEST_CHILD")
        self.populate(cgroup, "")
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "settle"))
        self.assertTrue(settlement["settled"], "containment did not finish")
        self.assertFalse(settlement["cleanup_complete"], settlement)
        self.assertEqual(settlement["process_obligations"]["still_running"], [child])
        self.assertEqual(cgroup.unresolved_owned_processes, (child,))
        evidence = cgroup.cleanup_evidence()
        self.assertTrue(evidence["containment_settled"])
        self.assertFalse(evidence["process_obligations_complete"])
        self.assertEqual(evidence["cleanup_retry_operation"], rl.CGROUP_RETRY_REAP)
        self.assertIsNotNone(cgroup.cleanup_registry_id, "the reap obligation was not retained")

    def test_a_later_retry_positively_reaps_and_completes(self) -> None:
        cgroup = self.cgroup(f"later-{os.getpid()}")
        child = self._sleeping_child()
        cgroup.record_owned_process(child, role="TEST_CHILD")
        self.populate(cgroup, "")
        first = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "first"))
        self.assertFalse(first["cleanup_complete"])
        entry_id = cgroup.cleanup_registry_id
        os.kill(child, signal.SIGKILL)
        self.assertTrue(_await(lambda: po.process_is_zombie(child), 5.0))
        second = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "second"))
        self.assertTrue(second["cleanup_complete"], second)
        self.assertEqual(second["process_obligations"]["reaped_here"], [child])
        self.assertFalse(po.process_is_zombie(child), "the retry left a zombie")
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(entry_id))

    def test_cgroup_removal_with_an_unreaped_owned_child_stays_incomplete(self) -> None:
        cgroup = self.cgroup(f"absent-{os.getpid()}")
        child = self._sleeping_child()
        cgroup.record_owned_process(child, role="TEST_CHILD")
        self.assertTrue(cgroup.close(), "an empty owned cgroup was not removed")
        self.assertTrue(cgroup.removal_settled, "containment is not settled")
        self.assertFalse(
            cgroup.cleanup_complete, "an absent directory completed a process lifecycle"
        )
        self.assertFalse(cgroup.process_obligations_complete)
        self.assertIsNotNone(cgroup.cleanup_registry_id)

    def test_echild_without_trusted_evidence_stays_unresolved(self) -> None:
        cgroup = self.cgroup(f"echild-{os.getpid()}")
        cgroup.record_owned_process(4_000_001, role="TEST_CHILD")
        self.populate(cgroup, "")
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "settle"))
        self.assertFalse(settlement["cleanup_complete"], settlement)
        self.assertEqual(settlement["process_obligations"]["unresolved"], [4_000_001])
        record = cgroup.owned_processes[4_000_001]
        self.assertEqual(record["reap_status"], rl.REAP_OBLIGATION_UNRESOLVED)
        self.assertIn("ECHILD", record["detail"])

    def test_echild_with_exact_trusted_evidence_is_accepted(self) -> None:
        cgroup = self.cgroup(f"trusted-{os.getpid()}")
        cgroup.record_owned_process(4_000_002, role="TEST_CHILD")
        cgroup.note_trusted_reap(
            4_000_002,
            reaper_role=po.REAPER_MOUNT_NAMESPACE_HELPER,
            reaper_pid=os.getpid(),
            detail="the trusted helper waited on the launcher it forked",
        )
        self.populate(cgroup, "")
        settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "settle"))
        self.assertTrue(settlement["cleanup_complete"], settlement)
        record = cgroup.owned_processes[4_000_002]
        self.assertEqual(record["reap_status"], rl.REAP_OBLIGATION_TRUSTED)
        self.assertEqual(record["reaper_role"], po.REAPER_MOUNT_NAMESPACE_HELPER)

    def test_trusted_evidence_must_name_a_reaper(self) -> None:
        cgroup = self.cgroup(f"unnamed-{os.getpid()}")
        cgroup.record_owned_process(4_000_003, role="TEST_CHILD")
        self.assertFalse(cgroup.note_trusted_reap(4_000_003, reaper_role=po.REAPER_NONE))
        self.assertEqual(
            cgroup.owned_processes[4_000_003]["reap_status"], rl.REAP_OBLIGATION_PENDING
        )

    def test_a_process_that_joins_after_the_snapshot_is_still_handled_truthfully(self) -> None:
        cgroup = self.cgroup(f"joiner-{os.getpid()}")
        child = self._sleeping_child()
        self.populate(cgroup, "")
        real_read = rl.read_cgroup_members
        joined = {"done": False}

        def joining(path, **kwargs):
            membership = real_read(path, **kwargs)
            if not joined["done"] and Path(path).name.startswith(rl.EFFECT_PREFIX):
                joined["done"] = True
                # The domain grows after the first read, exactly as a fork
                # inside it would.
                self.populate(cgroup, f"{child}\n")
            return membership

        os.kill(child, signal.SIGKILL)
        self.assertTrue(_await(lambda: po.process_is_zombie(child), 5.0))
        with mock.patch.object(rl, "read_cgroup_members", joining):
            settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "settle"))
        self.assertIn(child, cgroup.owned_processes, "a late joiner was never accounted for")
        self.assertEqual(settlement["process_obligations"]["reaped_here"], [child])
        self.assertFalse(po.process_is_zombie(child))

    def test_a_member_that_is_not_this_controllers_child_is_never_waited_on(self) -> None:
        cgroup = self.cgroup(f"stranger-{os.getpid()}")
        stranger = os.getppid()
        self.populate(cgroup, f"{stranger}\n")
        waited: list[int] = []
        real_waitpid = os.waitpid

        def recording(pid, options):
            waited.append(int(pid))
            return real_waitpid(pid, options)

        with mock.patch.object(os, "waitpid", recording):
            cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "settle"))
        self.assertNotIn(stranger, waited, "a process this controller does not own was waited on")
        self.assertNotIn(stranger, cgroup.owned_processes)

    def test_an_exact_owned_pid_is_reaped_once(self) -> None:
        cgroup = self.cgroup(f"once-{os.getpid()}")
        child = self._sleeping_child()
        cgroup.record_owned_process(child, role="TEST_CHILD")
        os.kill(child, signal.SIGKILL)
        self.assertTrue(_await(lambda: po.process_is_zombie(child), 5.0))
        waited: list[int] = []
        real_waitpid = os.waitpid

        def recording(pid, options):
            waited.append(int(pid))
            return real_waitpid(pid, options)

        with mock.patch.object(os, "waitpid", recording):
            first = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "first"))
            second = cgroup.settle_cleanup(deadline=Deadline.after_ms(300, "second"))
        self.assertTrue(first["cleanup_complete"], first)
        self.assertTrue(second["cleanup_complete"])
        self.assertEqual(waited.count(child), 1, "the exact owned PID was waited on twice")

    def test_containment_and_reap_are_separate_evidence_fields(self) -> None:
        cgroup = self.cgroup(f"fields-{os.getpid()}")
        child = self._sleeping_child()
        cgroup.record_owned_process(child, role="TEST_CHILD")
        self.assertTrue(cgroup.close())
        evidence = cgroup.cleanup_evidence()
        self.assertIn("containment_settled", evidence)
        self.assertIn("process_obligations_complete", evidence)
        self.assertNotEqual(
            evidence["containment_settled"],
            evidence["process_obligations_complete"],
            "the two obligations were collapsed into one answer",
        )
        entry = pw._CLEANUP_REGISTRY.entry(cgroup.cleanup_registry_id).evidence()
        self.assertTrue(entry["containment_settled"])
        self.assertFalse(entry["process_obligations_complete"])
        self.assertEqual(entry["unresolved_owned_processes"], [child])


# --- M2-B52: atomic, hard-bounded, fail-closed retention ----------------------


class _StubCleanup:
    """A handle reporting exactly the cleanup evidence a test states."""

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


class _SlowCleanup(_StubCleanup):
    """A handle whose settlement actually consumes the deadline it is given."""

    def __init__(self, seconds: float, helper_pid: int = 0) -> None:
        super().__init__(helper_pid=helper_pid)
        self.seconds = seconds
        self.granted: list[float] = []

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict:
        remaining = 0.0 if deadline is None else float(deadline.remaining_seconds)
        self.granted.append(remaining)
        time.sleep(min(self.seconds, remaining))
        return super().settle_cleanup(deadline=deadline)


class RegistryCapacityTests(unittest.TestCase):
    """Capacity is taken before an obligation can exist, and it is one number."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        self.registry = pw._CLEANUP_REGISTRY

    def _fill(self, count: int) -> list[_StubCleanup]:
        handles = []
        for index in range(count):
            handle = _StubCleanup(helper_pid=5_000 + index)
            self.registry.record(handle, handle.evidence())
            handles.append(handle)
        return handles

    def test_the_capacity_counts_reservations_and_entries_together(self) -> None:
        self._fill(60)
        reservations = [self.registry.reserve(f"r{index}") for index in range(4)]
        evidence = self.registry.evidence()
        self.assertEqual(evidence["retained"], 60)
        self.assertEqual(evidence["reserved"], 4)
        self.assertEqual(evidence["held"], pw.CLEANUP_REGISTRY_CAPACITY)
        self.assertTrue(evidence["saturated"])
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.reserve("one-too-many")
        reservations[0].release()
        self.registry.reserve("now-there-is-room").release()

    def test_the_sixty_fifth_obligation_is_refused(self) -> None:
        self._fill(pw.CLEANUP_REGISTRY_CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.reserve("sixty-fifth")
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.require_capacity()
        self.assertEqual(len(self.registry.entries()), pw.CLEANUP_REGISTRY_CAPACITY)

    def test_direct_record_cannot_exceed_the_capacity(self) -> None:
        self._fill(pw.CLEANUP_REGISTRY_CAPACITY)
        overflow = _StubCleanup(helper_pid=9_999)
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.record(overflow, overflow.evidence())
        self.assertEqual(len(self.registry.entries()), pw.CLEANUP_REGISTRY_CAPACITY)
        self.assertIsNone(overflow._registry_id)

    def test_concurrent_reservations_at_sixty_three_allow_exactly_one_more(self) -> None:
        self._fill(pw.CLEANUP_REGISTRY_CAPACITY - 1)
        start = threading.Barrier(8)
        taken: list[object] = []
        refused: list[BaseException] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            start.wait()
            try:
                reservation = self.registry.reserve(f"race-{index}")
            except CleanupRegistrySaturated as error:
                with lock:
                    refused.append(error)
                return
            with lock:
                taken.append(reservation)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(taken), 1, "more than one thread took the last unit of capacity")
        self.assertEqual(len(refused), 7)
        self.assertEqual(self.registry.evidence()["held"], pw.CLEANUP_REGISTRY_CAPACITY)

    def test_concurrent_records_never_exceed_the_capacity(self) -> None:
        self._fill(pw.CLEANUP_REGISTRY_CAPACITY - 4)
        start = threading.Barrier(16)
        accepted: list[str] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            handle = _StubCleanup(helper_pid=7_000 + index)
            start.wait()
            try:
                entry_id = self.registry.record(handle, handle.evidence())
            except CleanupRegistrySaturated:
                return
            with lock:
                accepted.append(entry_id)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(accepted), 4, accepted)
        self.assertEqual(len(set(accepted)), 4, "an entry id was reused")
        self.assertEqual(len(self.registry.entries()), pw.CLEANUP_REGISTRY_CAPACITY)

    def test_a_reservation_converts_exactly_once(self) -> None:
        reservation = self.registry.reserve("convert")
        handle = _StubCleanup(helper_pid=8_001)
        entry_id = self.registry.record(handle, handle.evidence(), reservation=reservation)
        self.assertIsNotNone(entry_id)
        self.assertFalse(reservation.active, "the reservation was not consumed")
        self.assertEqual(reservation.converted_to, entry_id)
        self.assertEqual(self.registry.evidence()["reserved"], 0)
        self.assertEqual(self.registry.evidence()["retained"], 1)
        self.assertFalse(reservation.release(), "a spent reservation was released again")

    def test_a_reservation_is_released_on_a_clean_completion(self) -> None:
        reservation = self.registry.reserve("clean")
        handle = _StubCleanup(helper_pid=8_002, complete=True)
        self.assertIsNone(self.registry.record(handle, handle.evidence(), reservation=reservation))
        self.assertFalse(reservation.active)
        self.assertEqual(self.registry.evidence()["held"], 0)

    def test_a_cgroup_reserves_before_it_creates_the_directory(self) -> None:
        fake = _FakeEffectParent(self)
        guard_process_wide_cgroup_caches(self)
        self._fill(pw.CLEANUP_REGISTRY_CAPACITY)
        made: list[Path] = []
        real_mkdir = Path.mkdir

        def recording(self_path, *args, **kwargs):
            made.append(Path(self_path))
            return real_mkdir(self_path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", recording):
            cgroup = rl.EffectCgroup(
                fake.delegation(), rl.ResourceBounds.for_timeout(1_000), f"saturated-{os.getpid()}"
            )
            self.assertFalse(cgroup.create(), "a cgroup was created at registry capacity")
        self.assertTrue(cgroup.create_error.startswith(rl.CGROUP_REGISTRY_SATURATED))
        self.assertEqual(made, [], "a directory was created before the refusal")
        self.assertEqual(fake.effect_cgroups(), [])

    def test_a_forked_child_trusts_no_parent_reservation_or_entry(self) -> None:
        self._fill(3)
        reservation = self.registry.reserve("parents-own")
        self.addCleanup(reservation.release)
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            code = 0
            try:
                evidence = pw._CLEANUP_REGISTRY.evidence()
                checks = [
                    evidence["retained"] == 0,
                    evidence["reserved"] == 0,
                    evidence["owner_pid"] == os.getpid(),
                ]
                code = 0 if all(checks) else 1 + checks.index(False)
            except BaseException:
                code = 90
            finally:
                os._exit(code)
        _pid, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, "a fork child adopted the parent's registry")
        self.assertEqual(self.registry.evidence()["retained"], 3)

    def test_concurrent_record_remove_and_evidence_stay_coherent(self) -> None:
        errors: list[BaseException] = []
        start = threading.Barrier(12)

        def churn(index: int) -> None:
            start.wait()
            try:
                for _round in range(20):
                    handle = _StubCleanup(helper_pid=6_000 + index)
                    entry_id = self.registry.record(handle, handle.evidence())
                    self.registry.evidence()
                    handle.complete = True
                    self.registry.record(handle, handle.evidence())
                    self.assertIsNone(self.registry.entry(entry_id))
            except BaseException as error:  # pragma: no cover - reported below
                errors.append(error)

        threads = [threading.Thread(target=churn, args=(index,)) for index in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.registry.entries(), ())
        self.assertEqual(self.registry.evidence()["held"], 0)


class RegistrarFailClosedTests(unittest.TestCase):
    """A registration that fails may not lose the obligation."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        self.fake = _FakeEffectParent(self)
        guard_process_wide_cgroup_caches(self)

    def test_a_registrar_exception_cannot_lose_a_cgroup_obligation(self) -> None:
        cgroup = rl.EffectCgroup(
            self.fake.delegation(), rl.ResourceBounds.for_timeout(1_000), f"lost-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        (Path(cgroup.path) / "cgroup.procs").write_text("424242\n", encoding="utf-8")

        def exploding(handle, evidence, *, reservation=None):
            raise RuntimeError("the registrar refused")

        with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
            self.assertFalse(cgroup.close())
        self.assertIsNone(cgroup.cleanup_registry_id)
        failure = cgroup.registration_failure
        self.assertIsNotNone(failure, "the exception was swallowed")
        self.assertEqual(failure["code"], rl.CGROUP_REGISTRATION_FAILED)
        self.assertIn(cgroup, rl.unregistered_cleanups(), "the handle was lost")
        evidence = cgroup.cleanup_evidence()
        self.assertFalse(evidence["cleanup_complete"])
        self.assertTrue(evidence["cleanup_retryable"])
        # And the obligation is reachable: a later drain finds it without an
        # entry id, because the entry is exactly what could not be created.
        (Path(cgroup.path) / "cgroup.procs").write_text("", encoding="utf-8")
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "drain"))
        self.assertTrue(any(row["cleanup_complete"] for row in results), results)
        self.assertTrue(cgroup.cleanup_complete)
        self.assertEqual(rl.unregistered_cleanups(), ())
        self.assertEqual(self.fake.effect_cgroups(), [])

    def test_a_registrar_exception_cannot_lose_a_helper_obligation(self) -> None:
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        original = pw._CLEANUP_REGISTRY.record

        def exploding(handle, evidence, *, reservation=None):
            if handle is helper:
                raise RuntimeError("the registrar refused")
            return original(handle, evidence, reservation=reservation)

        with mock.patch.object(pw._CLEANUP_REGISTRY, "record", exploding):
            with mock.patch.object(pw, "reap_owned_child", _unreaped):
                closure = helper.close(deadline=Deadline.after_ms(200, "close"))
        self.assertIsNone(closure["cleanup_registry_id"])
        self.assertFalse(closure["cleanup_complete"])
        self.assertTrue(closure["cleanup_retryable"])
        self.assertEqual(closure["cleanup_retry_operation"], pw.CLEANUP_RETRY_REGISTER)
        self.assertIsNotNone(closure["cleanup_registration_failure"])
        self.assertIn(helper, rl.unregistered_cleanups(), "the helper handle was lost")
        settled = helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "settle"))
        self.assertTrue(settled["cleanup_complete"], settled)
        self.assertIsNone(settled["cleanup_registration_failure"])
        self.assertEqual(rl.unregistered_cleanups(), ())

    def test_the_registry_evidence_counts_unregistered_obligations(self) -> None:
        cgroup = rl.EffectCgroup(
            self.fake.delegation(), rl.ResourceBounds.for_timeout(1_000), f"count-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        (Path(cgroup.path) / "cgroup.procs").write_text("424242\n", encoding="utf-8")

        def exploding(handle, evidence, *, reservation=None):
            raise RuntimeError("the registrar refused")

        with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
            cgroup.close()
        self.assertEqual(pw.cleanup_registry_evidence()["unregistered_obligations"], 1)
        (Path(cgroup.path) / "cgroup.procs").write_text("", encoding="utf-8")
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "drain"))
        self.assertEqual(pw.cleanup_registry_evidence()["unregistered_obligations"], 0)


def _unreaped(pid, deadline, *, role=po.REAPER_TRUSTED_CONTROLLER):
    """A reap that positively did not happen, without touching the process."""

    return po.ReapOutcome(
        reaped=False,
        exit_code=None,
        reaper_role=po.REAPER_NONE,
        reaper_pid=None,
        detail="injected",
        code=po.REAP_DEADLINE_EXPIRED,
    )


# --- M2-B53: linear release and serialised cleanup ----------------------------


class LinearReferenceReleaseTests(unittest.TestCase):
    """One reference, one owner release, one coherent result."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def test_two_simultaneous_releases_call_the_owner_once(self) -> None:
        owner = ChildSubreaperOwnership()
        reference = owner.acquire_reference()
        releases: list[int] = []
        real_release = owner.release
        lock = threading.Lock()

        def counting():
            with lock:
                releases.append(1)
            # Widen the window the unprotected check-then-set left open.
            time.sleep(0.05)
            return real_release()

        with mock.patch.object(owner, "release", counting):
            start = threading.Barrier(8)
            results: list[dict] = []

            def worker() -> None:
                start.wait()
                outcome = reference.release()
                with lock:
                    results.append(outcome)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(releases), 1, "the owner release ran more than once")
        self.assertEqual(len(results), 8)
        self.assertTrue(all(row == results[0] for row in results), "callers disagreed")
        self.assertTrue(results[0], "a caller received an empty release document")
        self.assertEqual(results[0]["code"], po.SUBREAPER_RESTORED)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(po.process_active_ownership()["depth"], 0)

    def test_all_callers_receive_one_coherent_result(self) -> None:
        owner = ChildSubreaperOwnership()
        reference = owner.acquire_reference()
        first = reference.release()
        for _repeat in range(3):
            self.assertEqual(reference.release(), first)
        self.assertTrue(reference.released)

    def test_an_owner_release_that_raises_leaves_the_reference_unspent(self) -> None:
        owner = ChildSubreaperOwnership()
        reference = owner.acquire_reference()
        self.addCleanup(reference.release)
        with mock.patch.object(owner, "release", side_effect=RuntimeError("kernel refused")):
            with self.assertRaises(RuntimeError):
                reference.release()
        self.assertFalse(reference.released, "a failed release spent the capability")
        self.assertEqual(po.process_active_ownership()["depth"], 1)


class SerializedCleanupHandleTests(unittest.TestCase):
    """A local cleanup and a registry drain settle one handle once."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        guard_process_wide_cgroup_caches(self)

    def test_concurrent_helper_close_and_drain_reap_and_release_once(self) -> None:
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        with mock.patch.object(pw, "reap_owned_child", _unreaped):
            helper.close(deadline=Deadline.after_ms(200, "first"))
        self.assertFalse(helper.cleanup_complete)
        self.assertIsNotNone(helper.registry_id)
        reaps: list[int] = []
        releases: list[int] = []
        real_reap = pw.reap_owned_child
        real_release = pw.PrivateMountHelper._release_subreaper
        lock = threading.Lock()

        def recording_reap(pid, deadline, *, role=po.REAPER_TRUSTED_CONTROLLER):
            outcome = real_reap(pid, deadline, role=role)
            if outcome.reaped:
                with lock:
                    reaps.append(int(pid))
            return outcome

        def recording_release(instance):
            performed = instance._subreaper_acquired
            outcome = real_release(instance)
            if performed:
                with lock:
                    releases.append(1)
            return outcome

        start = threading.Barrier(2)

        def local() -> None:
            start.wait()
            helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "local"))

        def drain() -> None:
            start.wait()
            pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))

        with mock.patch.object(pw, "reap_owned_child", recording_reap):
            with mock.patch.object(pw.PrivateMountHelper, "_release_subreaper", recording_release):
                threads = [threading.Thread(target=local), threading.Thread(target=drain)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
        self.assertEqual(reaps, [helper.pid], "the helper was reaped more than once")
        self.assertEqual(len(releases), 1, "the acquisition was released more than once")
        self.assertTrue(helper.cleanup_complete)
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(pw.incomplete_cleanups(), ())

    def test_concurrent_cgroup_close_and_drain_remove_once(self) -> None:
        fake = _FakeEffectParent(self)
        cgroup = rl.EffectCgroup(
            fake.delegation(), rl.ResourceBounds.for_timeout(1_000), f"race-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        (Path(cgroup.path) / "cgroup.procs").write_text("424242\n", encoding="utf-8")
        self.assertFalse(cgroup.close())
        (Path(cgroup.path) / "cgroup.procs").write_text("", encoding="utf-8")
        removals: list[str] = []
        real_remove = rl.EffectCgroup._remove
        lock = threading.Lock()

        def recording(path):
            removed, error = real_remove(path)
            if removed:
                with lock:
                    removals.append(str(path))
            return removed, error

        start = threading.Barrier(2)

        def local() -> None:
            start.wait()
            cgroup.settle_cleanup(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "local"))

        def drain() -> None:
            start.wait()
            pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))

        with mock.patch.object(rl.EffectCgroup, "_remove", staticmethod(recording)):
            threads = [threading.Thread(target=local), threading.Thread(target=drain)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(removals), 1, "the owned cgroup was removed more than once")
        self.assertTrue(cgroup.cleanup_complete)
        self.assertEqual(fake.effect_cgroups(), [])

    def test_concurrent_failed_start_retries_settle_once(self) -> None:
        reference = ChildSubreaperOwnership().acquire_reference()
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            try:
                time.sleep(30)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, child)
        with mock.patch.object(pw, "reap_owned_child", _unreaped):
            pw._roll_back_failed_start(pid=child, sockets=(), descriptors=(), subreaper=reference)
        entry = [row for row in pw.unsettled_failed_starts() if row.helper_pid == child][0]
        releases: list[int] = []
        lock = threading.Lock()
        real_release = reference.release

        def counting():
            spent = reference.released
            outcome = real_release()
            if not spent:
                with lock:
                    releases.append(1)
            return outcome

        start = threading.Barrier(6)

        def worker() -> None:
            start.wait()
            entry.retry(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))

        with mock.patch.object(reference, "release", counting):
            threads = [threading.Thread(target=worker) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(releases), 1, "the acquisition was released more than once")
        self.assertTrue(entry.cleanup_complete, entry.last_retry)
        self.assertFalse(po.process_is_zombie(child))
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    def test_two_drains_cannot_claim_the_same_entry(self) -> None:
        handle = _SlowCleanup(0.4, helper_pid=8_100)
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        start = threading.Barrier(2)
        claimed: list[list[dict]] = []
        lock = threading.Lock()

        def drain() -> None:
            start.wait()
            results = pw._CLEANUP_REGISTRY.drain(deadline=Deadline.after_ms(3_000, "drain"))
            with lock:
                claimed.append(results)

        threads = [threading.Thread(target=drain) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        settled = [row for results in claimed for row in results]
        self.assertEqual(len(settled), 1, "both drains claimed the same entry")
        self.assertEqual(handle.closes, 1)

    def test_a_stale_drain_cannot_remove_a_newer_generation_entry(self) -> None:
        handle = _StubCleanup(helper_pid=8_200)
        first_id = pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        first_entry = pw._CLEANUP_REGISTRY.entry(first_id)
        # The entry is removed and a fresh obligation takes its place under a new
        # id; the stale entry object is what a drain in flight would still hold.
        handle.complete = True
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        replacement = _StubCleanup(helper_pid=8_201)
        second_id = pw._CLEANUP_REGISTRY.record(replacement, replacement.evidence())
        self.assertNotEqual(first_id, second_id)
        second_entry = pw._CLEANUP_REGISTRY.entry(second_id)
        self.assertGreater(second_entry.generation, first_entry.generation)
        self.assertIsNone(pw._CLEANUP_REGISTRY.entry(first_id))
        self.assertIsNotNone(pw._CLEANUP_REGISTRY.entry(second_id))

    def test_nested_registry_and_handle_operations_do_not_deadlock(self) -> None:
        """A settlement that re-enters the registry completes, and is bounded."""

        handles = [_StubCleanup(helper_pid=8_300 + index) for index in range(8)]
        for handle in handles:
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        finished = threading.Event()

        def drain() -> None:
            for _round in range(5):
                pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "drain"))
            finished.set()

        thread = threading.Thread(target=drain)
        thread.start()
        for _round in range(200):
            pw.cleanup_registry_evidence()
            pw._CLEANUP_REGISTRY.entries()
        thread.join(timeout=30.0)
        self.assertTrue(finished.is_set(), "a nested registry/handle operation deadlocked")


# --- M2-B54: one global deadline for one whole drain --------------------------


class BoundedDrainTests(unittest.TestCase):
    """A drain spends one instant, however many entries it holds."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)

    def test_two_slow_entries_share_one_total_budget(self) -> None:
        first = _SlowCleanup(1.0, helper_pid=8_400)
        second = _SlowCleanup(1.0, helper_pid=8_401)
        for handle in (first, second):
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        started = time.monotonic()
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_200, "shared"))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0, "each entry received its own full budget")
        self.assertTrue(first.granted and second.granted)
        self.assertLess(
            second.granted[0], first.granted[0], "the second entry was given a fresh budget"
        )

    def test_sixty_four_entries_cannot_multiply_the_configured_bound(self) -> None:
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _SlowCleanup(0.05, helper_pid=8_500 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        started = time.monotonic()
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(400, "capped"))
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            pw.CLEANUP_REGISTRY_CAPACITY * 0.05,
            "the drain spent one budget per entry",
        )
        self.assertEqual(len(results), pw.CLEANUP_REGISTRY_CAPACITY)
        self.assertTrue(any(not row["attempted"] for row in results), "nothing was left unattempted")
        self.assertTrue(all(row["retained"] or row["cleanup_complete"] for row in results))

    def test_later_entries_receive_less_or_zero_time(self) -> None:
        handles = [_SlowCleanup(0.2, helper_pid=8_600 + index) for index in range(4)]
        for handle in handles:
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "descending"))
        granted = [handle.granted[0] for handle in handles if handle.granted]
        self.assertEqual(granted, sorted(granted, reverse=True), granted)

    def test_an_already_expired_drain_blocks_on_nothing(self) -> None:
        handles = [_SlowCleanup(2.0, helper_pid=8_700 + index) for index in range(4)]
        for handle in handles:
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        started = time.monotonic()
        results = pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("spent"))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0, "an expired drain blocked")
        self.assertTrue(all(not row["attempted"] for row in results))
        self.assertTrue(all(row["retained"] for row in results), "entries were dropped unattempted")
        self.assertEqual(len(pw.incomplete_cleanups()), 4)
        self.assertEqual([handle.granted for handle in handles], [[], [], [], []])

    def test_a_repeated_drain_is_a_new_caller_owned_operation(self) -> None:
        handle = _SlowCleanup(0.1, helper_pid=8_800)
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("spent"))
        self.assertEqual(handle.granted, [])
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(1_000, "fresh"))
        self.assertEqual(len(handle.granted), 1)
        self.assertGreater(handle.granted[0], 0.0)

    def test_the_drain_ledger_records_the_configured_total_and_exhaustion(self) -> None:
        for index in range(3):
            handle = _SlowCleanup(0.3, helper_pid=8_900 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(400, "ledger"))
        ledger = pw._CLEANUP_REGISTRY.last_drain_budget()
        self.assertEqual(ledger["configured_total_ms"], 400)
        self.assertTrue(ledger["caller_supplied_deadline"])
        self.assertFalse(ledger["renewed_after_a_step"])
        self.assertTrue(ledger["stage_grants"])
        self.assertTrue(ledger["deadline_exhausted"])

    def test_no_float_appears_in_the_durable_deadline_evidence(self) -> None:
        handle = _StubCleanup(helper_pid=9_000)
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(500, "floats"))
        ledger = pw._CLEANUP_REGISTRY.last_drain_budget()

        def walk(value, path="last_drain"):
            if isinstance(value, float):
                raise AssertionError(f"{path} carries a float: {value!r}")
            if isinstance(value, dict):
                for key, item in value.items():
                    walk(item, f"{path}.{key}")
            if isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, f"{path}[{index}]")

        walk(ledger)
        walk(Deadline.after_ms(500, "d").to_dict(), "deadline")


# --- M2-M55: one coherent current validation state ----------------------------


def _canonical_run(document: dict) -> dict:
    return document["canonical_current_run"]


class CanonicalCurrentValidationTests(unittest.TestCase):
    """Exactly one current run object, and every current field derives from it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.closure = json.loads(CLOSURE_REPORT.read_text(encoding="utf-8"))
        cls.validation = json.loads(VALIDATION_REPORT.read_text(encoding="utf-8"))
        cls.matrix = json.loads(REQUIREMENT_MATRIX.read_text(encoding="utf-8"))

    def test_the_canonical_run_object_is_byte_identical_in_both_reports(self) -> None:
        left = json.dumps(_canonical_run(self.closure), sort_keys=True, separators=(",", ":"))
        right = json.dumps(_canonical_run(self.validation), sort_keys=True, separators=(",", ":"))
        self.assertEqual(left, right, "the two current reports carry different current runs")

    def test_exactly_one_current_m2_total_exists(self) -> None:
        run = _canonical_run(self.validation)
        totals = {
            "canonical": run["m2_discovered_total"],
            "test_counts.m2_tests": self.validation["test_counts"]["m2_tests"],
            "m2_test_count_semantics": self.validation["m2_test_count_semantics"][
                "m2_discovered_by_discovery"
            ],
            "non_privileged_regression": self.validation["non_privileged_regression"][
                "m2_discovered_total"
            ],
            "closure.deterministic_test_totals": self.closure["deterministic_test_totals"][
                "m2_total"
            ],
            "closure.non_privileged_validation": self.closure["non_privileged_validation"][
                "m2_discovered_total"
            ],
        }
        self.assertEqual(
            len(set(totals.values())), 1, f"the current artifacts disagree about M2: {totals}"
        )

    def test_exactly_one_current_m2_skip_total_exists(self) -> None:
        run = _canonical_run(self.validation)
        totals = {
            "canonical": run["m2_skipped_total"],
            "test_counts.skipped": self.validation["test_counts"]["skipped"],
            "m2_test_count_semantics": self.validation["m2_test_count_semantics"]["m2_skipped"],
            "non_privileged_regression": self.validation["non_privileged_regression"]["m2_skipped"],
            "closure": self.closure["deterministic_test_totals"][
                "m2_skipped_on_an_undelegated_host"
            ],
        }
        self.assertEqual(
            len(set(totals.values())), 1, f"the current artifacts disagree about skips: {totals}"
        )

    def test_the_closure_report_and_the_validation_report_agree(self) -> None:
        for field in ("branch", "starting_commit", "starting_commit_parent", "terminal_verdict"):
            with self.subTest(field=field):
                self.assertEqual(self.closure[field], self.validation[field])
        self.assertEqual(self.validation["branch"], BRANCH)
        self.assertEqual(self.validation["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.validation["starting_commit_parent"], STARTING_COMMIT_PARENT)

    def test_the_current_count_matches_live_module_discovery(self) -> None:
        run = _canonical_run(self.validation)
        discovered = 0
        for path in sorted(Path(REPOSITORY_ROOT / "tests").glob("test_admissible_paired_runner_m2*.py")):
            module = unittest.defaultTestLoader.loadTestsFromName(f"tests.{path.stem}")
            discovered += module.countTestCases()
        self.assertEqual(
            run["m2_discovered_total"],
            discovered,
            "the canonical current total is not what discovery finds",
        )
        m1 = 0
        for path in sorted(Path(REPOSITORY_ROOT / "tests").glob("test_admissible_paired_runner_m1*.py")):
            module = unittest.defaultTestLoader.loadTestsFromName(f"tests.{path.stem}")
            m1 += module.countTestCases()
        self.assertEqual(run["m1_total"], m1)

    def test_the_historical_totals_are_never_presented_as_current(self) -> None:
        run = _canonical_run(self.validation)
        self.assertNotEqual(run["m2_discovered_total"], HISTORICAL_M2_TOTAL)
        self.assertNotEqual(run["m2_skipped_total"], HISTORICAL_M2_SKIPPED)
        for document, name in ((self.validation, "validation"), (self.closure, "closure")):
            for section in ("test_counts", "non_privileged_regression", "non_privileged_validation",
                            "deterministic_test_totals", "m2_test_count_semantics"):
                block = document.get(section)
                if not isinstance(block, dict):
                    continue
                with self.subTest(document=name, section=section):
                    self.assertNotIn(
                        HISTORICAL_M2_TOTAL,
                        [value for value in block.values() if isinstance(value, int)],
                        "a historical total occupies a current field",
                    )
        history = self.closure["historical_validation_totals"]
        self.assertEqual(history["m2_total"], HISTORICAL_M2_TOTAL)
        self.assertEqual(history["m2_skipped"], HISTORICAL_M2_SKIPPED)
        self.assertTrue(history["superseded_by"])

    def test_the_physical_run_is_associated_with_the_right_revision(self) -> None:
        run = _canonical_run(self.validation)
        physical = run["delegated_physical"]
        self.assertEqual(physical["revision_qualified"], run["revision_qualified"])
        self.assertIn(
            physical["status"],
            {"QUALIFIED", "OPERATOR_QUALIFICATION_REQUIRED"},
        )
        modules = physical["expected_modules"]
        self.assertEqual(
            physical["expected_total"],
            sum(physical["module_totals"][name] for name in modules),
            "the delegated total is not the sum of its modules",
        )
        for name in modules:
            with self.subTest(module=name):
                loaded = unittest.defaultTestLoader.loadTestsFromName(name)
                self.assertEqual(
                    loaded.countTestCases(),
                    physical["module_totals"][name],
                    "a delegated module total does not match the module",
                )
        prior = self.closure["prior_physical_qualification"]
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertEqual(prior["qualified_commit"], STARTING_COMMIT)
        self.assertIn("507", prior["transcript"])

    def test_the_reports_claim_no_acceptance_they_did_not_obtain(self) -> None:
        for document, name in ((self.validation, "validation"), (self.closure, "closure")):
            with self.subTest(document=name):
                self.assertFalse(document["independent_acceptance_claimed"])
                self.assertFalse(document["installed_path_qualification_claimed"])

    def test_the_boundary_audit_records_no_milestone_three_work(self) -> None:
        for boundary, crossed in self.validation["boundary_audit"].items():
            with self.subTest(boundary=boundary):
                self.assertFalse(crossed, boundary)
        for boundary, crossed in self.closure["milestone_3_boundary_audit"].items():
            with self.subTest(boundary=boundary):
                self.assertFalse(crossed, boundary)

    def test_the_requirement_matrix_agrees_with_the_closure(self) -> None:
        note = self.matrix["m2_cgroup_identity_reap_registry_serialization_closure_note"]
        self.assertIn("M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_CLOSURE_REPORT.json", note)
        for requirement in self.matrix["requirements"]:
            with self.subTest(requirement=requirement["requirement_id"]):
                self.assertNotEqual(requirement["current_status"], "VERIFIED_INSTALLED_PATH")
        touched = {row["requirement_id"] for row in self.closure["requirement_dispositions"]}
        matrix_ids = {row["requirement_id"] for row in self.matrix["requirements"]}
        self.assertTrue(touched <= matrix_ids, touched - matrix_ids)

    def test_every_bounded_finding_is_closed_with_a_reproduction(self) -> None:
        findings = {row["finding"]: row for row in self.closure["findings"]}
        self.assertEqual(
            sorted(findings),
            ["M2-B50", "M2-B51", "M2-B52", "M2-B53", "M2-B54", "M2-M55"],
        )
        for name, row in findings.items():
            with self.subTest(finding=name):
                self.assertEqual(row["status"], "CLOSED")
                self.assertTrue(row["current_code_path"])
                self.assertTrue(row["independent_reproduction"])
                self.assertTrue(row["violated_invariant"])
                self.assertTrue(row["minimal_production_change"])
                self.assertTrue(row["deterministic_tests"])
                self.assertTrue(row["durable_evidence"])
                self.assertTrue(row["refusal_condition"])

    def test_the_historical_reports_are_preserved_byte_for_byte(self) -> None:
        for name in (
            "M2_OWNERSHIP_DEBT_REAP_CLOSURE_REPORT.json",
            "M2_SUBREAPER_DEADLINE_CLOSURE_REPORT.json",
            "M2_PROCESS_OWNER_CLEANUP_PROPAGATION_CLOSURE_REPORT.json",
        ):
            with self.subTest(artifact=name):
                committed = subprocess.run(
                    ["git", "show", f"{STARTING_COMMIT}:implementation/{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), committed)

    def test_the_claimed_models_are_the_ones_the_code_exhibits(self) -> None:
        identity = self.closure["descriptor_bound_cgroup_identity_model"]
        for name in identity["verified_before"]:
            with self.subTest(operation=name):
                self.assertTrue(hasattr(rl.EffectCgroup, name), name)
        self.assertTrue(hasattr(rl.EffectCgroup, "verify_owned_identity"))
        reap = self.closure["owned_process_reap_obligation_model"]
        inert = rl.EffectCgroup(
            rl.CgroupDelegation(
                available=False,
                detail="none",
                unified_root=None,
                delegated_path=None,
                controllers=(),
                code=rl.TOPOLOGY_NOT_INITIALIZED,
            ),
            rl.ResourceBounds.for_timeout(1_000),
            "model-check",
        )
        document = inert.cleanup_evidence()
        for field in reap["evidence_fields"]:
            with self.subTest(field=field):
                self.assertIn(field, document, "the report claims a field the document lacks")
        for state in reap["reap_states"]:
            self.assertIn(state, rl.REAP_OBLIGATION_STATES)
        registry = self.closure["registry_reservation_capacity_model"]
        self.assertEqual(registry["capacity"], pw.CLEANUP_REGISTRY_CAPACITY)
        self.assertTrue(hasattr(pw._IncompleteCleanupRegistry, "reserve"))
        concurrency = self.closure["registry_concurrency_model"]
        self.assertTrue(concurrency["single_process_wide_lock"])
        self.assertIsInstance(pw._CLEANUP_REGISTRY._lock, type(threading.RLock()))
        linear = self.closure["linear_reference_model"]
        self.assertTrue(linear["release_is_serialised"])
        self.assertTrue(hasattr(po.SubreaperReference, "_release_locked"))
        drain = self.closure["one_global_drain_deadline_model"]
        self.assertEqual(drain["default_total_ms"], pw.CLEANUP_DRAIN_TOTAL_DEADLINE_MS)

    def test_no_milestone_three_module_was_created(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        for name in ("transport.py", "direct_mode.py", "governed_mode.py", "policy.py",
                     "authority.py", "evaluator.py", "archive.py"):
            with self.subTest(module=name):
                self.assertFalse((package / name).exists())

    def test_the_operator_command_is_exact_and_complete(self) -> None:
        command = self.closure["delegated_physical_qualification"]["operator_command"]
        self.assertIn(BRANCH, command)
        self.assertIn(STARTING_COMMIT, command)
        self.assertIn("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1", command)
        for module in self.closure["delegated_physical_qualification"]["expected_modules"]:
            with self.subTest(module=module):
                self.assertIn(module, command)


# --- production integration ---------------------------------------------------


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


class ProductionWiringTests(unittest.TestCase):
    """The production path records the obligations these closures depend on."""

    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        guard_process_wide_cgroup_caches(self)

    def test_supervision_records_the_launcher_as_an_owned_process(self) -> None:
        source = ps.supervise_command.__code__.co_consts
        text = "".join(str(item) for item in source if isinstance(item, str))
        self.assertIn("GATED_LAUNCHER", text)

    def test_the_abort_path_records_and_discharges_the_launcher_obligation(self) -> None:
        import inspect

        source = inspect.getsource(ps.abort_gated_effect)
        self.assertIn("record_owned_process", source)
        self.assertIn("note_trusted_reap", source)

    def test_registry_saturation_refuses_a_supervised_command_before_any_fork(self) -> None:
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _StubCleanup(helper_pid=4_000 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        with self.assertRaises(pw.CleanupRegistrySaturated):
            pw._CLEANUP_REGISTRY.reserve("no-room")


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


class DelegatedCgroupIdentityReapRegistryTests(unittest.TestCase):
    """Physical qualification of the five code closures on real kernel state."""

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
    def test_a_real_replacement_cgroup_is_never_signalled(self) -> None:
        """M2-B50 physically: a real populated replacement, no signal reaches it."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        victim = helper.spawn([PYTHON, "-c", "import time\ntime.sleep(120)\n"])
        self.addCleanup(_close_quietly, victim.stdout_fd)
        self.addCleanup(_close_quietly, victim.stderr_fd)
        cgroup = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b50-real-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        path = Path(cgroup.path)
        # The owned cgroup is emptied and removed by this controller, then a real
        # replacement is created under the same name and populated with a live
        # process.  Nothing this obligation does may reach it.
        self.assertTrue(cgroup.close(), cgroup.attach_error)
        self.assertFalse(path.exists())
        replacement_created = False
        try:
            path.mkdir(mode=0o700)
            replacement_created = True
            self.addCleanup(lambda: shutil.rmtree(str(path), ignore_errors=True))
            error = rl._write_control(path / "cgroup.procs", str(victim.pid))
            self.assertIsNone(error, f"the replacement could not adopt the victim: {error}")
            members = rl.read_cgroup_members(path)
            self.assertIn(victim.pid, members.pids, "the fixture did not populate the replacement")
            settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(500, "settle"))
            self.assertTrue(settlement["settled"], settlement)
            self.assertIsNone(settlement["kill_domain"], "a kill was issued after the obligation ended")
            self.assertTrue(
                _await(lambda: True, 0.2) and po.process_present(victim.pid),
                "the process in the replacement was killed",
            )
            after = rl.read_cgroup_members(path)
            self.assertIn(victim.pid, after.pids, "the replacement was emptied")
            self.assertTrue(path.exists(), "the replacement cgroup was removed")
        finally:
            if replacement_created:
                try:
                    rl._write_control(parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}" / "cgroup.procs", str(victim.pid))
                except Exception:  # pragma: no cover - best effort fixture teardown
                    pass
            helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "helper_close"))
            _reap_quietly(victim.pid)
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))
        shutil.rmtree(str(path), ignore_errors=True)
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    def test_a_real_delayed_reap_keeps_the_obligation_until_it_happens(self) -> None:
        """M2-B51 physically: a real child, a real delay, a real positive reap."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        cgroup = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b51-real-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            try:
                time.sleep(60)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, child)
        self.assertTrue(cgroup.attach_and_verify(child), cgroup.attach_error)
        cgroup.record_owned_process(child, role="TEST_CHILD")
        with mock.patch.object(os, "waitpid", side_effect=lambda pid, options: (0, 0)):
            first = cgroup.settle_cleanup(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "first"))
        self.assertFalse(first["cleanup_complete"], first)
        self.assertEqual(first["process_obligations"]["still_running"], [child])
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id, "the reap obligation was not retained")
        self.assertTrue(cgroup.removal_settled, "containment did not finish")
        results = pw.drain_incomplete_cleanups(
            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain")
        )
        drained = [row for row in results if row["entry_id"] == entry_id]
        self.assertEqual(len(drained), 1, results)
        self.assertTrue(drained[0]["cleanup_complete"], drained)
        self.assertFalse(po.process_is_zombie(child), "the drain left a zombie")
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    @capsule
    def test_real_capacity_exhaustion_refuses_a_real_effect(self) -> None:
        """M2-B52 physically, against the real substrate on a real cgroup."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-identity-capacity")
        self.addCleanup(harness.close)
        for index in range(pw.CLEANUP_REGISTRY_CAPACITY):
            handle = _StubCleanup(helper_pid=4_500 + index)
            pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        forked = mock.Mock(side_effect=AssertionError("fork() was reached"))
        with mock.patch.object(pw, "_fork", forked):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "REFUSED", _receipt_diagnosis(outcome))
        self.assertFalse(outcome.effect_crossed_boundary)
        self.assertFalse(forked.called)
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(_effect_cgroups(parent), [], "a cgroup was created at capacity")
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    @delegated
    def test_a_real_concurrent_close_and_drain_settle_once(self) -> None:
        """M2-B53 physically: a real cgroup, a real helper, two real threads."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        launcher = helper.spawn([PYTHON, "-c", "import time\ntime.sleep(120)\n"])
        self.addCleanup(_close_quietly, launcher.stdout_fd)
        self.addCleanup(_close_quietly, launcher.stderr_fd)
        cgroup = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b53-real-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        path = Path(cgroup.path)
        self.assertTrue(cgroup.attach_and_verify(launcher.pid), cgroup.attach_error)
        self.assertFalse(cgroup.close(), "a populated cgroup was reported removed")
        helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "helper_close"))
        removals: list[str] = []
        real_remove = rl.EffectCgroup._remove
        lock = threading.Lock()

        def recording(target):
            removed, error = real_remove(target)
            if removed:
                with lock:
                    removals.append(str(target))
            return removed, error

        start = threading.Barrier(2)

        def local() -> None:
            start.wait()
            cgroup.settle_cleanup(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "local"))

        def drain() -> None:
            start.wait()
            pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))

        with mock.patch.object(rl.EffectCgroup, "_remove", staticmethod(recording)):
            threads = [threading.Thread(target=local), threading.Thread(target=drain)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(removals), 1, "the exact owned cgroup was removed more than once")
        self.assertFalse(path.exists(), "the owned cgroup survived")
        self.assertTrue(cgroup.cleanup_complete)
        self.assertFalse(po.process_is_zombie(launcher.pid), "a zombie was left behind")
        self.assertFalse(po.process_is_zombie(helper.pid))
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(po.get_child_subreaper()[0], self.before)

    @delegated
    def test_a_real_multi_entry_drain_shares_one_deadline(self) -> None:
        """M2-B54 physically: real retained obligations, one bounded drain."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        cgroups = []
        launchers = []
        for index in range(3):
            launcher = helper.spawn([PYTHON, "-c", "import time\ntime.sleep(120)\n"])
            self.addCleanup(_close_quietly, launcher.stdout_fd)
            self.addCleanup(_close_quietly, launcher.stderr_fd)
            launchers.append(launcher)
            cgroup = rl.EffectCgroup(
                DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b54-real-{os.getpid()}-{index}"
            )
            self.assertTrue(cgroup.create(), cgroup.create_error)
            self.assertTrue(cgroup.attach_and_verify(launcher.pid), cgroup.attach_error)
            self.assertFalse(cgroup.close())
            cgroups.append(cgroup)
        self.assertEqual(len(pw.incomplete_cleanups()), 3)
        helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "helper_close"))
        started = time.monotonic()
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "one_budget"))
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            (RETRY_BUDGET_MS / 1000.0) * 2,
            "the drain spent more than one configured budget",
        )
        ledger = pw._CLEANUP_REGISTRY.last_drain_budget()
        self.assertEqual(ledger["configured_total_ms"], RETRY_BUDGET_MS)
        self.assertFalse(ledger["renewed_after_a_step"])
        for cgroup in cgroups:
            self.assertTrue(cgroup.cleanup_complete, cgroup.cleanup_evidence())
        for launcher in launchers:
            self.assertFalse(po.process_is_zombie(launcher.pid), "the drain left a zombie")
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    @capsule
    def test_a_nominal_effect_completes_and_retains_nothing(self) -> None:
        """Every accepted behaviour survives all five closures."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-identity-nominal")
        self.addCleanup(harness.close)
        before_children = _child_pids()
        descriptors = _open_descriptor_count()
        outcome = harness.command(SENTINEL_SCRIPT)
        self.assertEqual(outcome.receipt.status, "COMPLETED", _receipt_diagnosis(outcome))
        self.assertTrue((harness.workspace / "sentinel.txt").exists())
        self.assertTrue(outcome.lifecycle_cleanup_complete)
        self.assertEqual(outcome.cleanup_registry_ids, ())
        self.assertEqual(_effect_cgroups(parent), [])
        self.assertEqual(pw.incomplete_cleanups(), ())
        self.assertEqual(pw.unsettled_failed_starts(), ())
        self.assertEqual(rl.unregistered_cleanups(), ())
        self.assertEqual(pw.cleanup_registry_evidence()["held"], 0, "a reservation leaked")
        self.assertEqual(po.get_child_subreaper()[0], self.before)
        self.assertEqual(CHILD_SUBREAPER.state()["depth"], 0)
        self.assertIsNone(po.process_restoration_debt())
        self.assertTrue(_await(lambda: _child_pids() == before_children, 5.0), _child_pids())
        self.assertTrue(_await(lambda: _open_descriptor_count() <= descriptors + 1, 5.0))


if __name__ == "__main__":
    unittest.main()
