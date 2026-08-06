"""M2 exact-removal / global-drain / reservation-provenance closure: B56-B58.

Each finding is closed by making the untrue statement impossible to produce.

M2-B56 -- the final removal acts on the exact owned object or on nothing
    ``close()`` proved the retained identity and then removed through a
    *pathname*: ``before_removal = self.verify_owned_identity()`` followed, some
    instructions later, by ``self._remove(path)`` -- a separately overridable
    static taking a ``Path``.  A substitution landing in between destroyed a
    cgroup this controller never owned, and the evidence said the owned object
    had been removed and its absence verified.  Ownership is now enforced by an
    explicit exclusion boundary: one process-wide lock per delegated parent,
    taken by every controller-owned create, remove and replacement under that
    parent, entered *before* the final identity proof and held across the whole
    verify / prove-empty / re-prove / remove / prove-absent critical section.
    The removal itself is ``os.rmdir(leaf, dir_fd=parent_fd)``, so the parent is
    pinned by a descriptor rather than re-resolved from a name.

    The boundary is exactly as wide as the trusted computing base it names.
    Linux offers no remove-by-handle primitive for a directory, so a mutation
    performed *outside* this controller's TCB is not excluded by a userspace
    lock and no claim is made that it is.  Against that threat model this code
    fails closed: it refuses, retains the obligation, and classifies the refusal.

M2-B57 -- one drain, one budget, both collections
    ``_IncompleteCleanupRegistry.drain()`` spent one budget on the registered
    entries, and ``drain_incomplete_cleanups()`` then handed every *unregistered*
    obligation ``deadline or Deadline.after_ms(CLEANUP_DRAIN_TOTAL_DEADLINE_MS)``
    -- a fresh full default each.  A nominal 100 ms drain with two such
    obligations was independently reproduced taking 200 ms, each obligation
    receiving nearly the whole nominal total, and each row claiming
    ``attempted=True, deadline_exhausted=False`` whether or not it had any time.
    One ``CleanupBudget`` is now created at the outermost entry and nothing below
    may create another; both collections are walked as one list in ascending
    process-wide obligation sequence; an obligation reached after exhaustion is
    not attempted, is retained unchanged, and says so.

M2-B58 -- a reservation is a linear, registry-issued capability
    ``reservation is not None and reservation.active`` was the whole validity
    test.  A token issued by another registry instance, a token whose registry
    had since been PID-reset, a token already spent and a plain object with an
    ``active`` attribute were all accepted, each skipping the capacity check the
    reservation existed to have already passed; a stale token surviving a
    PID-bound reset was enough to put a second entry into a registry whose
    capacity was one, and the refusing registry mutated tokens it did not own.
    Provenance -- issuing registry object and identity, owner PID, registry
    epoch, id, and the exact object standing under that id in this registry's own
    table -- is now proved under the registry lock before a token grants
    anything, and the conversion is one atomic transition.

Deterministic tests drive real descriptors, real forked children, real threads,
the real process cleanup registry and a constructed cgroup tree.  Delegated
physical tests run the production path inside a real ``Delegate=yes`` cgroup v2
subtree and, under ``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than
skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
import errno
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

from admissible.paired_runner import private_workspace as pw  # noqa: E402
from admissible.paired_runner import process_ownership as po  # noqa: E402
from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner.private_workspace import (  # noqa: E402
    CleanupRegistrySaturated,
    CleanupReservationRefused,
    PrivateMountHelper,
)
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    Deadline,
)
from admissible.paired_runner.resource_limits import probe_cgroup_delegation  # noqa: E402

DELEGATION = probe_cgroup_delegation()
REQUIRE_DELEGATED = os.environ.get("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP") == "1"

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    guard_process_wide_cgroup_caches,
    guard_process_wide_cleanup_registry,
    guard_process_wide_restoration_debt,
    guard_process_wide_subreaper_ownership,
)
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = REPOSITORY_ROOT / "implementation"

BRANCH = "paired-runner/m2-exact-removal-global-drain-reservation-provenance-closure"
STARTING_COMMIT = "63df0305861fe8d1f3760c0f9a2083dafc51cdf5"
STARTING_COMMIT_PARENT = "fd4e9fb409f648da356f90b9ca2c211183267354"
INDEPENDENT_AUDIT_SHA256 = (
    "77f2d0265ebf31cb7564cd4b21744e14bfb6c8cf5e83e1f263693f7c2b75ffc5"
)
INDEPENDENT_AUDIT_VERDICTS = (
    "M2_CGROUP_IDENTITY_REAP_REGISTRY_SERIALIZATION_FINAL_INDEPENDENT_CLOSURE_REFUSED",
    "MILESTONE_3_NOT_PERMITTED",
)
CLOSURE_REPORT = (
    IMPLEMENTATION / "M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_CLOSURE_REPORT.json"
)
VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
#: The delegated transcript of the *starting* commit.  It is history, never a
#: qualification of the revision this closure produces.
PRIOR_DELEGATED_TRANSCRIPT = "Ran 583 tests in 179.065s\n\nOK"

RETRY_BUDGET_MS = 5_000

_REAL_MKDIR = Path.mkdir
_REAL_OS_RMDIR = os.rmdir


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


# --- shared helpers -----------------------------------------------------------


def _await(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


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


def _proc_state(pid: int) -> str:
    """The single-letter kernel state of ``pid``: 'S' sleeping, 'Z' zombie, ..."""

    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("State:"):
                    return line.split(":", 1)[1].strip().split()[0]
    except OSError:
        return "ABSENT"
    return "UNKNOWN"  # pragma: no cover - /proc always reports State


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def guard_process_wide_unregistered_cleanups(test: unittest.TestCase) -> None:
    """Discharge and restore the process-level registrar-failure collection.

    It is process-wide for the same reason the registry is: an obligation whose
    registration failed has no entry to be found by, so the only thing keeping it
    reachable is this list.

    It is *drained* before it is restored, and the drain runs from a registered
    cleanup so it happens whether the test passed or raised.  Simply restoring
    the list -- which is what this guard used to do -- dropped every obligation
    the test had added without removing anything, so a failed assertion left a
    real cgroup standing in the delegated parent and the next physical test
    failed on a leak it did not create.  A failed assertion may report a defect;
    it may not manufacture one for its successor.
    """

    saved = list(rl._UNREGISTERED_CLEANUPS)
    saved_pid = rl._UNREGISTERED_OWNER_PID
    saved_ledger = dict(pw._LAST_DRAIN_LEDGER)

    def restore() -> None:
        try:
            _discharge_unregistered_obligations(added_only=saved)
        finally:
            rl._UNREGISTERED_CLEANUPS[:] = saved
            rl._UNREGISTERED_OWNER_PID = saved_pid
            pw._LAST_DRAIN_LEDGER = saved_ledger

    test.addCleanup(restore)


def _discharge_unregistered_obligations(*, added_only: list) -> None:
    """Settle every obligation this test added, on a fresh independent budget.

    Only obligations this test added are touched -- anything the test found is
    put back exactly as it was.  Every step goes through the production
    settlement, so nothing is removed, killed or reaped by a route the
    production code does not own: the settlement kills only the exact owned
    domain, reaps only exact owned children, and removes only the exact owned
    cgroup.  An obligation that genuinely cannot be settled stays retained and
    the test's own assertions are what report it.
    """

    def added() -> list:
        return [
            handle
            for handle in rl.unregistered_cleanups()
            if all(handle is not existing for existing in added_only)
        ]

    for _attempt in range(4):
        outstanding = added()
        if not outstanding:
            return
        for handle in outstanding:
            try:
                handle.settle_cleanup(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "teardown"))
            except Exception:  # pragma: no cover - the guard never masks a failure
                pass
            if getattr(handle, "cleanup_complete", False):
                rl._release_unregistered(handle)


class _ProcessGuard:
    """Put back every process-wide fact a test in this module can disturb."""

    @staticmethod
    def install(test: unittest.TestCase) -> int:
        before, error = po.get_child_subreaper()
        test.assertIsNone(error, "this kernel does not expose PR_GET_CHILD_SUBREAPER")
        guard_process_wide_restoration_debt(test)
        guard_process_wide_subreaper_ownership(test)
        guard_process_wide_cleanup_registry(test)
        guard_process_wide_unregistered_cleanups(test)

        def restore() -> None:
            po.set_child_subreaper(int(before or 0))

        test.addCleanup(restore)
        return int(before or 0)


# --- a constructed delegated parent -------------------------------------------


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
    """Make an ordinary directory behave like a cgroup for both ``rmdir`` forms.

    The kernel destroys a cgroup's interface files with the cgroup and refuses
    only when the cgroup still has children.  Since M2-B56 the exact removal is
    ``os.rmdir(name, dir_fd=parent_fd)``, so the descriptor-relative form is
    modelled alongside the pathname one; without it these tests would be about
    the fixture's tmpfs control files rather than about the removal logic.
    """

    def rmdir(self_path):
        if any(child.is_dir() for child in self_path.iterdir()):
            raise OSError(errno.ENOTEMPTY, "Directory not empty")
        shutil.rmtree(self_path)

    def os_rmdir(path, *, dir_fd=None):
        if dir_fd is None:
            return _REAL_OS_RMDIR(path)
        target = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / str(path)
        if not target.is_dir():
            return _REAL_OS_RMDIR(path, dir_fd=dir_fd)
        if any(child.is_dir() for child in target.iterdir()):
            raise OSError(errno.ENOTEMPTY, "Directory not empty", str(target))
        for child in target.iterdir():
            child.unlink()
        return _REAL_OS_RMDIR(path, dir_fd=dir_fd)

    for patcher in (
        mock.patch.object(Path, "rmdir", rmdir),
        mock.patch.object(os, "rmdir", os_rmdir),
    ):
        patcher.start()
        test.addCleanup(patcher.stop)


class _FakeEffectParent:
    """An ordinary directory shaped like a delegated effect parent.

    Never kernel evidence: the delegated class at the end of this module drives
    the same production code against a real ``Delegate=yes`` subtree.  This
    fixture exists so what is *refused* -- which object is removed, which is
    left alone, which mutation blocks -- is provable without privilege on a host
    that delegates nothing.
    """

    def __init__(self, test: unittest.TestCase) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-b56-exact-"))
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

    def domain(self) -> str:
        identity = rl.cgroup_mutation_domain_of(self.parent)
        assert identity is not None
        return identity

    def effect_cgroups(self) -> list[Path]:
        return _effect_cgroups(self.parent)


class _CgroupFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.before = _ProcessGuard.install(self)
        guard_process_wide_cgroup_caches(self)
        self.fake = _FakeEffectParent(self)
        self.delegation = self.fake.delegation()

    def cgroup(self, label: str) -> rl.EffectCgroup:
        cgroup = rl.EffectCgroup(self.delegation, rl.ResourceBounds.for_timeout(1_000), label)
        self.assertTrue(cgroup.create(), cgroup.create_error)
        return cgroup

    def replace_in_place(self, cgroup: rl.EffectCgroup) -> Path:
        """Move the owned inode aside and put a different cgroup in its place.

        The owned inode is *renamed* rather than destroyed, so the replacement is
        guaranteed to be a different inode and the retained child descriptor
        still serves the object it was opened on -- which is what makes the
        refusal a statement about identity rather than about a read that failed.
        """

        path = Path(cgroup.owned_path)
        aside = path.parent / f"aside-{path.name}"
        os.rename(path, aside)
        self.addCleanup(shutil.rmtree, str(aside), True)
        _REAL_MKDIR(path, mode=0o700)
        (path / "cgroup.procs").write_text("", encoding="utf-8")
        (path / "cgroup.kill").write_text("0\n", encoding="utf-8")
        self.assertNotEqual(
            rl._directory_identity(path), rl._directory_identity(aside), "the fixture reused an inode"
        )
        return path


# --- M2-B56: the final removal reaches the exact owned object or nothing -------


class ExactOwnedRemovalTests(_CgroupFixture):
    """A destructive removal never acts on an object this controller does not own."""

    def test_an_exact_owned_empty_cgroup_is_removed_exactly_once(self) -> None:
        cgroup = self.cgroup(f"exact-{os.getpid()}")
        path = Path(cgroup.owned_path)
        removals: list[tuple[int, str]] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append((parent_fd, leaf))
            return real(parent_fd, leaf)

        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            self.assertTrue(cgroup.close(), cgroup.attach_error)
            first = cgroup.removal_evidence()
            first_disposition = cgroup.removal_disposition()
            self.assertTrue(cgroup.close(), "the idempotent second call refused")
        self.assertEqual(len(removals), 1, "the owned cgroup was removed more than once")
        self.assertEqual(removals[0][1], cgroup._leaf)
        self.assertFalse(path.exists())
        self.assertEqual(first_disposition["code"], rl.CGROUP_REMOVAL_EXACT, first)
        self.assertTrue(first["removed"])
        self.assertTrue(first["absence_verified"])
        # ...and the repeated call says it removed nothing, because it did not.
        self.assertFalse(cgroup.removal_evidence()["removed"])
        self.assertTrue(cgroup.removal_evidence()["absence_verified"])
        self.assertEqual(self.fake.effect_cgroups(), [])

    def test_repeated_cleanup_is_idempotent(self) -> None:
        cgroup = self.cgroup(f"idem-{os.getpid()}")
        self.assertTrue(cgroup.close())
        for _ in range(3):
            settlement = cgroup.settle_cleanup(deadline=Deadline.after_ms(500, "idempotent"))
            self.assertTrue(settlement["cleanup_complete"], settlement)
        self.assertEqual(self.fake.effect_cgroups(), [])

    def test_a_replacement_inserted_before_the_critical_section_is_refused(self) -> None:
        cgroup = self.cgroup(f"pre-swap-{os.getpid()}")
        replacement = self.replace_in_place(cgroup)
        replacement_identity = rl._directory_identity(replacement)
        self.assertFalse(cgroup.close(), "a replacement was accepted as the owned cgroup")
        self.assertTrue(replacement.exists(), "the replacement was destroyed")
        self.assertEqual(
            rl._directory_identity(replacement),
            replacement_identity,
            "the replacement inode changed",
        )
        evidence = cgroup.removal_evidence()
        self.assertFalse(evidence["removed"])
        self.assertFalse(evidence["absence_verified"])
        self.assertIn(
            evidence.get("code"),
            {rl.CGROUP_IDENTITY_NAME_REPLACED, rl.CGROUP_REMOVAL_REPLACEMENT_REFUSED},
            evidence,
        )
        self.assertFalse(cgroup.removal_settled, "the obligation was discharged by a replacement")
        self.assertIsNotNone(cgroup.cleanup_registry_id, "the obligation was not retained")

    def test_a_swap_at_the_old_pathname_removal_location_cannot_redirect_it(self) -> None:
        """The exact reproduction of the finding, closed.

        A substitution landing after the last identity proof and before the
        pathname the removal used to resolve destroyed a cgroup this controller
        never owned, and the evidence called it a verified removal of the owned
        object.
        """

        cgroup = self.cgroup(f"swap-{os.getpid()}")
        domain = self.fake.domain()
        state: dict[str, object] = {"swapped": False, "replacement": None}
        real_members = rl.EffectCgroup.read_members

        def read_then_swap(self_cgroup):
            answer = real_members(self_cgroup)
            # Inside the critical section, after the emptiness proof and before
            # the removal: the exact window the old pathname resolution left open.
            if (
                self_cgroup is cgroup
                and not state["swapped"]
                and rl.cgroup_mutation_boundary_held(domain)
            ):
                state["swapped"] = True
                state["replacement"] = self.replace_in_place(cgroup)
            return answer

        with mock.patch.object(rl.EffectCgroup, "read_members", read_then_swap):
            self.assertFalse(cgroup.close(), "the swap redirected the destructive operation")
        self.assertTrue(state["swapped"], "the fixture never performed the substitution")
        replacement = state["replacement"]
        self.assertTrue(replacement.exists(), "the replacement cgroup was removed")
        evidence = cgroup.removal_evidence()
        self.assertFalse(evidence["removed"], evidence)
        self.assertNotIn("was removed and its absence was verified", evidence.get("detail", ""))
        self.assertFalse(cgroup.removal_settled)

    def test_the_evidence_never_calls_a_vanished_replacement_an_owned_removal(self) -> None:
        cgroup = self.cgroup(f"never-lie-{os.getpid()}")
        self.replace_in_place(cgroup)
        cgroup.close()
        evidence = cgroup.removal_evidence()
        self.assertFalse(evidence["removed"])
        disposition = cgroup.removal_disposition()
        if disposition:
            self.assertNotEqual(disposition["code"], rl.CGROUP_REMOVAL_EXACT)
        cleanup = cgroup.cleanup_evidence()
        self.assertFalse(cleanup["containment_settled"])
        self.assertTrue(cleanup["cleanup_retryable"])
        self.assertEqual(cleanup["cleanup_retry_operation"], rl.CGROUP_RETRY_REMOVE)

    def test_a_symlink_substitution_is_refused(self) -> None:
        cgroup = self.cgroup(f"symlink-{os.getpid()}")
        path = Path(cgroup.owned_path)
        elsewhere = self.fake.parent / "somebody-elses-domain"
        _REAL_MKDIR(elsewhere, mode=0o700)
        (elsewhere / "cgroup.procs").write_text("717171\n", encoding="utf-8")
        aside = path.parent / f"aside-{path.name}"
        os.rename(path, aside)
        self.addCleanup(shutil.rmtree, str(aside), True)
        os.symlink(str(elsewhere), str(path))
        self.assertFalse(cgroup.close(), "a symlink was followed to a removal")
        self.assertTrue(elsewhere.is_dir(), "the symlink target was removed")
        self.assertEqual(
            (elsewhere / "cgroup.procs").read_text(encoding="utf-8"),
            "717171\n",
            "the symlink target was written to",
        )
        self.assertTrue(os.path.islink(str(path)), "the symlink itself was removed")

    def test_a_replaced_parent_descriptor_refuses_before_any_removal(self) -> None:
        cgroup = self.cgroup(f"parent-{os.getpid()}")
        path = Path(cgroup.owned_path)
        cgroup._parent_identity = "9999999:9999999"
        identity = cgroup.verify_owned_identity()
        self.assertFalse(identity["verified"])
        self.assertEqual(identity["code"], rl.CGROUP_IDENTITY_PARENT_REPLACED, identity)
        disposition = cgroup._remove_exact_owned_child()
        self.assertEqual(disposition["code"], rl.CGROUP_REMOVAL_IDENTITY_AMBIGUOUS, disposition)
        self.assertTrue(path.exists(), "a cgroup was removed under an unproved parent")
        self.assertFalse(disposition["removal_evidence"]["removed"])

    def test_a_name_mapping_to_a_different_device_is_never_removed(self) -> None:
        cgroup = self.cgroup(f"dev-{os.getpid()}")
        path = Path(cgroup.owned_path)
        verified = cgroup.verify_owned_identity()
        self.assertTrue(verified["verified"], verified)
        # The name resolves to a directory on another device.  Nothing about the
        # inode number can make that the same object.
        other_device = dict(verified)
        other_device["name_identity"] = f"999:{verified['name_identity'].split(':', 1)[1]}"
        with mock.patch.object(
            rl.EffectCgroup, "verify_owned_identity", lambda _self: dict(other_device)
        ):
            disposition = cgroup._remove_exact_owned_child()
        self.assertEqual(disposition["code"], rl.CGROUP_REMOVAL_REPLACEMENT_REFUSED, disposition)
        self.assertTrue(path.exists(), "a cgroup on another device was removed")

    def test_an_ambiguous_disappearance_retains_the_obligation(self) -> None:
        cgroup = self.cgroup(f"ambiguous-{os.getpid()}")
        path = Path(cgroup.owned_path)
        aside = path.parent / f"aside-{path.name}"
        # The name is gone but the *object* is not: the retained descriptor still
        # serves it.  An unknown is never absence.
        os.rename(path, aside)
        self.addCleanup(shutil.rmtree, str(aside), True)
        identity = cgroup.verify_owned_identity()
        self.assertEqual(identity["code"], rl.CGROUP_IDENTITY_NAME_ABSENT, identity)
        self.assertTrue(identity["object_present"], identity)
        disposition = cgroup._remove_exact_owned_child()
        self.assertEqual(disposition["code"], rl.CGROUP_REMOVAL_IDENTITY_AMBIGUOUS, disposition)
        self.assertFalse(disposition["removal_evidence"]["absence_verified"])
        self.assertTrue(aside.exists(), "the displaced owned object was removed")
        self.assertFalse(cgroup.removal_settled, "an unknown was reported as a discharge")

    def test_a_positively_absent_object_is_discharged_without_a_removal(self) -> None:
        cgroup = self.cgroup(f"absent-{os.getpid()}")
        path = Path(cgroup.owned_path)
        for child in path.iterdir():
            child.unlink()
        _REAL_OS_RMDIR(str(path))
        disposition = cgroup._remove_exact_owned_child()
        self.assertEqual(disposition["code"], rl.CGROUP_REMOVAL_ALREADY_ABSENT, disposition)
        self.assertFalse(disposition["removal_evidence"]["removed"], "a no-op claimed a removal")
        self.assertTrue(disposition["removal_evidence"]["absence_verified"])

    def test_a_member_arriving_inside_the_boundary_still_refuses(self) -> None:
        """Emptiness is proved inside the boundary, not carried in from outside."""

        cgroup = self.cgroup(f"populated-{os.getpid()}")
        path = Path(cgroup.owned_path)
        domain = self.fake.domain()
        state = {"joined": False}
        real_verify = rl.EffectCgroup.verify_owned_identity

        def join_when_inside(self_cgroup):
            answer = real_verify(self_cgroup)
            if (
                self_cgroup is cgroup
                and not state["joined"]
                and rl.cgroup_mutation_boundary_held(domain)
            ):
                state["joined"] = True
                (path / "cgroup.procs").write_text("636363\n", encoding="utf-8")
            return answer

        with mock.patch.object(rl.EffectCgroup, "verify_owned_identity", join_when_inside):
            self.assertFalse(cgroup.close(), "a populated cgroup was removed")
        self.assertTrue(state["joined"], "the fixture never joined the domain")
        self.assertTrue(path.exists(), "a populated cgroup was removed")
        evidence = cgroup.removal_evidence()
        self.assertFalse(evidence["removed"])
        self.assertEqual(evidence["code"], rl.CGROUP_REMOVAL_NOT_EMPTY, evidence)
        self.assertEqual(evidence["residual_members"], [636363])

    def test_the_final_removal_is_unreachable_without_the_boundary(self) -> None:
        cgroup = self.cgroup(f"no-boundary-{os.getpid()}")
        path = Path(cgroup.owned_path)
        removals: list[str] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append(leaf)
            return real(parent_fd, leaf)

        class _Ungranted:
            """A boundary object that acquires nothing.  Nothing may follow it."""

            def __enter__(self):
                return self

            def __exit__(self, *exception):
                return None

        with mock.patch.object(rl, "_rmdir_owned_child", recording), mock.patch.object(
            rl, "cgroup_mutation_boundary", lambda identity: _Ungranted()
        ):
            disposition = cgroup._remove_exact_owned_child()
        self.assertEqual(
            disposition["code"], rl.CGROUP_REMOVAL_BOUNDARY_UNAVAILABLE, disposition
        )
        self.assertEqual(removals, [], "a destructive primitive ran without the boundary")
        self.assertTrue(path.exists())

    def test_no_descriptor_pair_refuses_under_the_declared_tcb(self) -> None:
        cgroup = self.cgroup(f"no-fd-{os.getpid()}")
        path = Path(cgroup.owned_path)
        parent_fd, cgroup._parent_fd = cgroup._parent_fd, None
        self.addCleanup(_close_quietly, parent_fd)
        disposition = cgroup._remove_exact_owned_child()
        self.assertEqual(
            disposition["code"], rl.CGROUP_REMOVAL_BOUNDARY_UNAVAILABLE, disposition
        )
        self.assertTrue(path.exists())
        self.assertFalse(disposition["removal_evidence"]["removed"])

    def test_the_final_removal_never_reaches_the_overridable_pathname_callback(self) -> None:
        cgroup = self.cgroup(f"no-callback-{os.getpid()}")
        calls: list[str] = []
        real_remove = rl.EffectCgroup._remove

        def recording(target):
            calls.append(str(target))
            return real_remove(target)

        with mock.patch.object(rl.EffectCgroup, "_remove", staticmethod(recording)):
            self.assertTrue(cgroup.close())
        self.assertEqual(
            calls,
            [],
            "the final removal still routes through a separately overridable pathname callback",
        )

    def test_the_removal_holds_the_boundary_across_the_whole_critical_section(self) -> None:
        cgroup = self.cgroup(f"held-{os.getpid()}")
        domain = self.fake.domain()
        observations: list[bool] = []
        real_members = rl.EffectCgroup.read_members

        def observing(self_cgroup):
            if self_cgroup is cgroup:
                observations.append(rl.cgroup_mutation_boundary_held(domain))
            return real_members(self_cgroup)

        with mock.patch.object(rl.EffectCgroup, "read_members", observing):
            self.assertTrue(cgroup.close())
        self.assertTrue(observations, "the fixture never observed the critical section")
        self.assertTrue(
            observations[-1],
            "the emptiness proof of the final removal ran outside the exclusion boundary",
        )
        self.assertFalse(
            rl.cgroup_mutation_boundary_held(domain), "the boundary outlived the removal"
        )

    def test_a_controller_owned_creation_blocks_until_the_removal_finishes(self) -> None:
        """The other controller-owned mutation path cannot land mid-removal."""

        cgroup = self.cgroup(f"blocking-{os.getpid()}")
        leaf = cgroup._leaf
        domain = self.fake.domain()
        inside = threading.Event()
        proceed = threading.Event()
        created_at: list[float] = []
        real_members = rl.EffectCgroup.read_members

        def hold(self_cgroup):
            answer = real_members(self_cgroup)
            # Only the read taken *inside* the critical section holds it open.
            if self_cgroup is cgroup and rl.cgroup_mutation_boundary_held(domain):
                inside.set()
                proceed.wait(5.0)
            return answer

        replacement: dict[str, object] = {}

        def create_replacement() -> None:
            inside.wait(5.0)
            other = rl.EffectCgroup(
                self.delegation, rl.ResourceBounds.for_timeout(1_000), cgroup._label
            )
            ok = other.create()
            created_at.append(time.monotonic())
            replacement["cgroup"] = other
            replacement["ok"] = ok

        worker = threading.Thread(target=create_replacement)
        worker.start()
        try:
            with mock.patch.object(rl.EffectCgroup, "read_members", hold):
                closing = threading.Thread(target=cgroup.close)
                closing.start()
                self.assertTrue(inside.wait(5.0), "the removal never entered its critical section")
                # The creation is waiting on the same parent domain, so nothing
                # can have appeared under the owned name while the removal holds
                # the boundary.
                time.sleep(0.2)
                self.assertEqual(
                    created_at, [], "a controller-owned creation landed inside the critical section"
                )
                self.assertFalse(
                    rl.cgroup_mutation_boundary_held(domain),
                    "the boundary is per-thread; this thread never entered it",
                )
                proceed.set()
                closing.join(10.0)
                self.assertFalse(closing.is_alive(), "the removal never finished")
        finally:
            proceed.set()
            worker.join(10.0)
        self.assertTrue(replacement.get("ok"), "the blocked creation never completed")
        other = replacement["cgroup"]
        self.addCleanup(other.close)
        self.assertEqual(
            cgroup.removal_disposition()["code"],
            rl.CGROUP_REMOVAL_EXACT,
            cgroup.removal_evidence(),
        )
        # The replacement carries the owned name and survives: the removal ran
        # to completion before the creation was allowed to take the name, and
        # nothing the owned obligation did afterwards reached the new object.
        self.assertTrue(Path(other.owned_path).exists(), "the replacement was destroyed")
        self.assertEqual(Path(other.owned_path).name, leaf)
        self.assertTrue(cgroup.removal_settled)
        self.assertFalse(other.removal_settled, "the replacement was adopted as settled")

    def test_the_declared_boundary_does_not_claim_hostile_host_atomicity(self) -> None:
        tcb = rl.CGROUP_MUTATION_TCB
        self.assertFalse(tcb["remove_by_handle_available"])
        self.assertFalse(tcb["atomicity_claimed_against_a_hostile_host"])
        self.assertIn("dev:ino", tcb["boundary"])
        self.assertIn("final_removal", tcb["serialized_operations"])
        self.assertIn("outside this controller's trusted computing base", tcb["does_not_exclude"])
        self.assertIn("refused", tcb["outside_the_boundary"])
        evidence = rl.cgroup_mutation_domains_evidence()
        self.assertEqual(evidence["trusted_computing_base"], dict(tcb))

    def test_the_cleanup_evidence_classifies_the_removal_separately(self) -> None:
        cgroup = self.cgroup(f"classified-{os.getpid()}")
        self.assertTrue(cgroup.close())
        cleanup = cgroup.cleanup_evidence()
        self.assertEqual(cleanup["removal_disposition"], rl.CGROUP_REMOVAL_EXACT)
        self.assertTrue(cleanup["containment_settled"])
        self.assertTrue(cleanup["process_obligations_complete"])
        self.assertEqual(cleanup["mutation_boundary"], dict(rl.CGROUP_MUTATION_TCB))


# --- M2-B57: one drain, one budget, both collections ---------------------------


class _StubObligation:
    """A retained handle that spends exactly what it is granted."""

    def __init__(self, name: str, *, spend: bool = True, complete: bool = False) -> None:
        self.name = name
        self.spend = spend
        self.complete = complete
        self._registry_id: str | None = None
        self.grants: list[int] = []
        self.attempts = 0

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict:
        self.attempts += 1
        remaining = 0.0 if deadline is None else float(deadline.remaining_seconds)
        self.grants.append(int(remaining * 1000))
        if self.spend:
            # Spend the whole grant and a hair more, so the shared budget is
            # unambiguously exhausted rather than exhausted-by-a-microsecond.
            time.sleep(remaining + 0.02)
        return {"name": self.name, "granted_ms": self.grants[-1]}

    def evidence(self) -> dict:
        return {
            "helper_pid": 0,
            "cleanup_complete": self.complete,
            "cleanup_retryable": not self.complete,
            "cleanup_retry_operation": (
                rl.CGROUP_RETRY_NONE if self.complete else rl.CGROUP_RETRY_REMOVE
            ),
            "settlement_attempts": self.attempts,
        }

    def cleanup_evidence(self) -> dict:
        return self.evidence()


class GlobalDrainBudgetTests(unittest.TestCase):
    """One call to the drain has exactly one absolute budget."""

    #: The scheduler tolerance a bounded sleep-and-wake sequence may exceed its
    #: absolute deadline by on a loaded host.  It is a tolerance on *observed
    #: wall clock*, never a second budget: the code grants nothing beyond the one
    #: deadline, and this number exists only because ``time.sleep`` may return
    #: late.
    TOLERANCE_MS = 250

    def setUp(self) -> None:
        _ProcessGuard.install(self)
        self.total_ms = 200
        patcher = mock.patch.object(pw, "CLEANUP_DRAIN_TOTAL_DEADLINE_MS", self.total_ms)
        patcher.start()
        self.addCleanup(patcher.stop)

    def retain_unregistered(self, handle: _StubObligation, *, sequence: int | None = None) -> None:
        rl._retain_unregistered(handle)
        if sequence is not None:
            handle._cleanup_obligation_sequence = sequence

    def register(self, handle: _StubObligation, *, sequence: int | None = None) -> str:
        entry_id = pw._CLEANUP_REGISTRY.record(handle, handle.evidence())
        self.assertIsNotNone(entry_id)
        if sequence is not None:
            pw._CLEANUP_REGISTRY.entry(entry_id).sequence = sequence
        return entry_id

    def test_two_unregistered_obligations_cannot_each_take_the_whole_default(self) -> None:
        first = _StubObligation("first")
        second = _StubObligation("second")
        self.retain_unregistered(first)
        self.retain_unregistered(second)
        started = time.monotonic()
        results = pw.drain_incomplete_cleanups()
        elapsed_ms = (time.monotonic() - started) * 1000
        self.assertLess(
            elapsed_ms,
            self.total_ms + self.TOLERANCE_MS,
            f"the drain spent {elapsed_ms:.0f}ms against a configured total of {self.total_ms}ms",
        )
        self.assertLessEqual(sum(first.grants) + sum(second.grants), self.total_ms)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]["attempted"])
        self.assertFalse(results[1]["attempted"], results[1])
        self.assertEqual(
            results[1]["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED
        )
        self.assertEqual(second.grants, [], "the second obligation received a renewed deadline")

    def test_registered_work_consuming_the_budget_stops_later_unregistered_work(self) -> None:
        registered = _StubObligation("registered")
        unregistered = _StubObligation("unregistered")
        self.register(registered, sequence=1)
        self.retain_unregistered(unregistered, sequence=2)
        results = pw.drain_incomplete_cleanups()
        by_collection = {row["collection"]: row for row in results}
        self.assertTrue(by_collection["REGISTERED"]["attempted"])
        self.assertFalse(by_collection["UNREGISTERED"]["attempted"], by_collection)
        self.assertEqual(
            by_collection["UNREGISTERED"]["unattempted_reason"],
            pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED,
        )
        self.assertEqual(unregistered.attempts, 0, "the unattempted obligation was settled anyway")
        self.assertTrue(by_collection["UNREGISTERED"]["retained"])

    def test_unregistered_work_consuming_the_budget_stops_later_registered_work(self) -> None:
        unregistered = _StubObligation("unregistered")
        registered = _StubObligation("registered")
        self.retain_unregistered(unregistered, sequence=1)
        self.register(registered, sequence=2)
        results = pw.drain_incomplete_cleanups()
        by_collection = {row["collection"]: row for row in results}
        self.assertEqual(
            [row["collection"] for row in results],
            ["UNREGISTERED", "REGISTERED"],
            "the declared ascending-sequence ordering was not followed",
        )
        self.assertTrue(by_collection["UNREGISTERED"]["attempted"])
        self.assertFalse(by_collection["REGISTERED"]["attempted"], by_collection)
        self.assertEqual(
            by_collection["REGISTERED"]["unattempted_reason"],
            pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED,
        )
        self.assertEqual(registered.attempts, 0)
        self.assertTrue(by_collection["REGISTERED"]["retained"])

    def test_a_caller_supplied_deadline_is_propagated_unchanged(self) -> None:
        self.retain_unregistered(_StubObligation("only", spend=False))
        supplied = Deadline.after_ms(1_234, "caller")
        pw.drain_incomplete_cleanups(deadline=supplied)
        ledger = pw.cleanup_drain_ledger()
        self.assertTrue(ledger["caller_supplied_deadline"])
        self.assertEqual(ledger["configured_total_ms"], 1_234)
        self.assertFalse(ledger["renewed_after_a_step"])

    def test_no_second_full_default_deadline_is_created_inside_the_drain(self) -> None:
        self.retain_unregistered(_StubObligation("a", spend=False), sequence=1)
        self.retain_unregistered(_StubObligation("b", spend=False), sequence=2)
        self.register(_StubObligation("c", spend=False), sequence=3)
        labels: list[str] = []
        real = po.Deadline.after_ms.__func__

        def recording(cls, milliseconds, label=""):
            labels.append(label)
            return real(cls, milliseconds, label)

        with mock.patch.object(po.Deadline, "after_ms", classmethod(recording)):
            pw.drain_incomplete_cleanups()
        self.assertEqual(
            [label for label in labels if label == "cleanup_drain"],
            ["cleanup_drain"],
            f"more than one whole-drain deadline was created: {labels}",
        )

    def test_the_ledger_covers_both_collections_once(self) -> None:
        self.retain_unregistered(_StubObligation("u1", spend=False), sequence=1)
        self.register(_StubObligation("r1", spend=False), sequence=2)
        self.retain_unregistered(_StubObligation("u2", spend=False), sequence=3)
        results = pw.drain_incomplete_cleanups()
        ledger = pw.cleanup_drain_ledger()
        self.assertEqual(ledger["collections"], {"REGISTERED": 1, "UNREGISTERED": 2})
        self.assertEqual(ledger["obligations_attempted"], 3)
        self.assertEqual(ledger["obligations_unattempted"], 0)
        self.assertEqual(
            [row["sequence"] for row in ledger["order"]], [row["sequence"] for row in results]
        )
        self.assertEqual(ledger["ordering"], "ascending process-wide cleanup obligation sequence")
        self.assertEqual(ledger["configured_total_ms"], self.total_ms)
        self.assertEqual(len(ledger["stage_grants"]), 3, ledger["stage_grants"])
        # One ledger, reachable from the registry's own durable evidence too.
        self.assertEqual(pw.cleanup_registry_evidence()["last_drain"], ledger)

    def test_an_obligation_reached_after_exhaustion_is_retained_unchanged(self) -> None:
        first = _StubObligation("spender")
        second = _StubObligation("untouched")
        self.retain_unregistered(first, sequence=1)
        self.retain_unregistered(second, sequence=2)
        pw.drain_incomplete_cleanups()
        self.assertEqual(second.attempts, 0)
        self.assertEqual(second.grants, [])
        retained = [handle for handle in rl.unregistered_cleanups() if handle is second]
        self.assertEqual(len(retained), 1, "the unattempted obligation was dropped")
        ledger = pw.cleanup_drain_ledger()
        self.assertEqual(ledger["obligations_unattempted"], 1)
        self.assertEqual(ledger["obligations_retained"], 2)

    def test_repeated_drains_stay_retryable_and_settle_the_remainder(self) -> None:
        first = _StubObligation("spender")
        second = _StubObligation("later", spend=False)
        self.retain_unregistered(first, sequence=1)
        self.retain_unregistered(second, sequence=2)
        pw.drain_incomplete_cleanups()
        self.assertEqual(second.attempts, 0, "the exhausted drain settled it anyway")
        # The first obligation settles; a later, independent drain then reaches
        # the one the exhausted drain retained.  Retention is what makes the
        # retry possible at all.
        first.spend = False
        first.complete = True
        second_pass = pw.drain_incomplete_cleanups()
        self.assertEqual(len(second_pass), 2)
        self.assertTrue(all(row["attempted"] for row in second_pass), second_pass)
        self.assertGreaterEqual(second.attempts, 1, "a later independent retry never reached it")

    def test_a_nested_drain_joins_the_outer_budget(self) -> None:
        """A cleanup path that re-enters the drain spends what is already running."""

        nested_rows: list[int] = []
        state = {"reentered": False}

        class _Reentrant(_StubObligation):
            def settle_cleanup(self, *, deadline=None):
                # A settlement that reaches the drain again.  Converting its
                # grant back into a full budget is the same defect one frame
                # deeper, so the nested call must join rather than mint.
                if not state["reentered"]:
                    state["reentered"] = True
                    nested_rows.append(len(pw.drain_incomplete_cleanups()))
                return super().settle_cleanup(deadline=deadline)

        self.retain_unregistered(_Reentrant("reentrant", spend=False), sequence=1)
        self.retain_unregistered(_StubObligation("plain", spend=False), sequence=2)
        labels: list[str] = []
        real = po.Deadline.after_ms.__func__

        def recording(cls, milliseconds, label=""):
            labels.append(label)
            return real(cls, milliseconds, label)

        started = time.monotonic()
        with mock.patch.object(po.Deadline, "after_ms", classmethod(recording)):
            pw.drain_incomplete_cleanups()
        elapsed_ms = (time.monotonic() - started) * 1000
        self.assertTrue(nested_rows, "the fixture never re-entered the drain")
        self.assertEqual(
            [label for label in labels if label == "cleanup_drain"],
            ["cleanup_drain"],
            f"a nested drain minted a second whole budget: {labels}",
        )
        self.assertLess(elapsed_ms, self.total_ms + self.TOLERANCE_MS)

    def test_a_registrar_failure_obligation_is_never_lost_by_the_shared_drain(self) -> None:
        handle = _StubObligation("registrar-failed", spend=False)
        self.retain_unregistered(handle, sequence=1)
        results = pw.drain_incomplete_cleanups()
        rows = [row for row in results if row["collection"] == "UNREGISTERED"]
        self.assertEqual(len(rows), 1, results)
        self.assertTrue(rows[0]["attempted"])
        self.assertTrue(rows[0]["retained"], "the obligation was silently dropped")
        self.assertEqual(handle.attempts, 1)

    def test_the_registry_drain_alone_still_owns_exactly_one_budget(self) -> None:
        self.register(_StubObligation("solo", spend=False))
        pw._CLEANUP_REGISTRY.drain(deadline=Deadline.after_ms(500, "solo"))
        budget = pw._CLEANUP_REGISTRY.last_drain_budget()
        self.assertEqual(budget["configured_total_ms"], 500)
        self.assertTrue(budget["caller_supplied_deadline"])

    def test_every_row_carries_exactly_one_state_from_the_closed_table(self) -> None:
        self.register(_StubObligation("r", spend=False), sequence=1)
        self.retain_unregistered(_StubObligation("u", spend=False), sequence=2)
        for row in pw.drain_incomplete_cleanups():
            with self.subTest(collection=row["collection"]):
                self.assertIn(row["state"], pw.DRAIN_STATES)
                self.assertIn("resource_outstanding", row)
                self.assertIn("alias_of", row)


class DrainStateTruthfulnessTests(_CgroupFixture):
    """The states the delegated qualification refused this closure over.

    The refusal was a single row: an unregistered obligation reported
    ``attempted=false`` because the shared budget was exhausted, with a retry
    operation naming a cgroup removal, while the cgroup it named had already been
    removed -- by its own ordinary ``close()``, before the drain began.  Nothing
    had bypassed the budget and no two obligations aliased one resource; the
    evidence model folded "the registrar refused to write this down" into "a
    destructive obligation is outstanding".
    """

    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(pw, "CLEANUP_DRAIN_TOTAL_DEADLINE_MS", 200)
        patcher.start()
        self.addCleanup(patcher.stop)

    def unregistered_cgroup(self, label: str, *, populated: bool) -> rl.EffectCgroup:
        """A real EffectCgroup retained through the fail-closed registrar path."""

        cgroup = self.cgroup(label)
        if populated:
            (Path(cgroup.owned_path) / "cgroup.procs").write_text("515151\n", encoding="utf-8")

        def exploding(handle, evidence, *, reservation=None):
            raise RuntimeError("the registrar refuses this obligation")

        with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
            cgroup.close()
        self.assertIsNotNone(cgroup.registration_failure, "the failure was swallowed")
        self.assertTrue(any(h is cgroup for h in rl.unregistered_cleanups()))
        return cgroup

    def test_a_discharged_resource_is_never_reported_as_an_outstanding_removal(self) -> None:
        """The exact row the delegated qualification refused."""

        cgroup = self.unregistered_cgroup(f"discharged-{os.getpid()}", populated=False)
        path = Path(cgroup.owned_path)
        # Its own close() removed it, under the removal's own exclusion boundary,
        # before any drain existed.  That is correct; what must not follow is a
        # drain row calling it an unattempted removal.
        self.assertFalse(path.exists(), "the fixture did not discharge the resource")
        self.assertTrue(cgroup.removal_settled)
        evidence = cgroup.cleanup_evidence()
        self.assertFalse(evidence["resource_outstanding"])
        self.assertEqual(evidence["outstanding_work"], (rl.OUTSTANDING_REGISTRATION,))
        self.assertEqual(evidence["cleanup_retry_operation"], rl.CGROUP_RETRY_RECORD)
        self.assertNotEqual(evidence["cleanup_retry_operation"], rl.CGROUP_RETRY_REMOVE)

        results = pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("spent"))
        row = [r for r in results if r["collection"] == "UNREGISTERED"][0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_RESOURCE_DISCHARGED, row)
        self.assertEqual(row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_RESOURCE_DISCHARGED)
        self.assertNotEqual(row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED)
        self.assertFalse(row["resource_outstanding"])
        self.assertEqual(row["cleanup_retry_operation"], rl.CGROUP_RETRY_RECORD)
        self.assertTrue(row["retained"], "the registration failure was lost")

    def test_a_row_claiming_budget_exhaustion_over_a_discharged_resource_is_refused(self) -> None:
        """The invariant is enforced where the row is built, not only where read."""

        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(
                {
                    "state": pw.DRAIN_STATE_RETAINED_UNATTEMPTED,
                    "attempted": False,
                    "resource_outstanding": False,
                    "effect_cgroup_path": "/somewhere/that/is/already/gone",
                }
            )

    def test_an_outstanding_resource_reached_after_exhaustion_is_physically_untouched(self) -> None:
        cgroup = self.unregistered_cgroup(f"outstanding-{os.getpid()}", populated=True)
        path = Path(cgroup.owned_path)
        self.assertTrue(path.exists())
        self.assertTrue(cgroup.cleanup_evidence()["resource_outstanding"])
        identity_before = rl._directory_identity(path)
        results = pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("spent"))
        row = [r for r in results if r["collection"] == "UNREGISTERED"][0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_RETAINED_UNATTEMPTED, row)
        self.assertEqual(row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED)
        self.assertTrue(row["resource_outstanding"])
        self.assertEqual(row["granted_ms"], 0)
        self.assertTrue(path.exists(), "a zero-grant obligation was destroyed anyway")
        self.assertEqual(rl._directory_identity(path), identity_before)

    def test_a_zero_grant_registered_entry_runs_no_destructive_primitive(self) -> None:
        cgroup = self.cgroup(f"zero-grant-{os.getpid()}")
        path = Path(cgroup.owned_path)
        (path / "cgroup.procs").write_text("515151\n", encoding="utf-8")
        self.assertFalse(cgroup.close(), "a populated cgroup was reported removed")
        self.assertIsNotNone(cgroup.cleanup_registry_id)
        # Emptied again, so a settlement *would* remove it if one ran.
        (path / "cgroup.procs").write_text("", encoding="utf-8")
        removals: list[str] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append(leaf)
            return real(parent_fd, leaf)

        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            results = pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("spent"))
        row = [r for r in results if r["collection"] == "REGISTERED"][0]
        self.assertFalse(row["attempted"])
        self.assertEqual(row["granted_ms"], 0)
        self.assertEqual(removals, [], "a destructive primitive ran on a zero grant")
        self.assertTrue(path.exists(), "a zero-grant drain removed a cgroup")

    def test_two_handles_for_one_exact_cgroup_settle_it_once(self) -> None:
        cgroup = self.cgroup(f"alias-{os.getpid()}")
        path = Path(cgroup.owned_path)
        (path / "cgroup.procs").write_text("515151\n", encoding="utf-8")
        self.assertFalse(cgroup.close())
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id)
        # A second handle naming the exact same cgroup: same dev:ino, retained in
        # the other collection.
        alias = rl.EffectCgroup(self.delegation, rl.ResourceBounds.for_timeout(1_000), "alias-twin")
        alias._parent_fd = os.dup(cgroup._parent_fd)
        alias._dir_fd = os.dup(cgroup._dir_fd)
        alias._parent_identity = cgroup._parent_identity
        alias._owned_identity = cgroup._owned_identity
        alias._leaf = cgroup._leaf
        alias._path = cgroup._path
        alias._owned_path = cgroup._owned_path
        rl._retain_unregistered(alias)
        self.addCleanup(rl._release_unregistered, alias)
        (path / "cgroup.procs").write_text("", encoding="utf-8")
        removals: list[str] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append(leaf)
            return real(parent_fd, leaf)

        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "alias"))
        self.assertEqual(len(removals), 1, "one cgroup was removed more than once")
        canonical = [r for r in results if r["alias_of"] is None]
        aliases = [r for r in results if r["alias_of"] is not None]
        self.assertEqual(len(aliases), 1, results)
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertEqual(aliases[0]["unattempted_reason"], pw.DRAIN_UNATTEMPTED_ALIAS)
        self.assertEqual(aliases[0]["granted_ms"], 0, "an alias spent a second grant")
        self.assertEqual(aliases[0]["alias_of"], canonical[0]["label"])
        ledger = pw.cleanup_drain_ledger()
        self.assertEqual(ledger["distinct_resources"], 1)
        self.assertEqual(ledger["aliases_discharged_by_a_canonical_obligation"], 1)

    def test_distinct_cgroups_are_never_treated_as_aliases(self) -> None:
        first = self.unregistered_cgroup(f"distinct-a-{os.getpid()}", populated=True)
        second = self.unregistered_cgroup(f"distinct-b-{os.getpid()}", populated=True)
        self.assertNotEqual(first.owned_identity, second.owned_identity)
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "distinct"))
        self.assertEqual([row["alias_of"] for row in results], [None, None], results)
        self.assertEqual(pw.cleanup_drain_ledger()["distinct_resources"], 2)
        self.assertTrue(Path(first.owned_path).exists())
        self.assertTrue(Path(second.owned_path).exists())

    def test_the_same_pathname_with_a_different_identity_is_not_an_alias(self) -> None:
        first = self.unregistered_cgroup(f"samename-{os.getpid()}", populated=True)
        path = Path(first.owned_path)
        # A second handle under the *same pathname* but a different inode.  A
        # pathname is not an identity, and canonicalization must not say it is.
        twin = rl.EffectCgroup(self.delegation, rl.ResourceBounds.for_timeout(1_000), "samename-twin")
        twin._parent_fd = os.dup(first._parent_fd)
        twin._dir_fd = os.dup(first._dir_fd)
        twin._parent_identity = first._parent_identity
        twin._leaf = first._leaf
        twin._path = path
        twin._owned_path = path
        twin._owned_identity = "999999:999999"
        rl._retain_unregistered(twin)
        self.addCleanup(rl._release_unregistered, twin)
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "samename"))
        self.assertEqual(
            [row["alias_of"] for row in results],
            [None, None],
            "two different objects under one pathname were merged",
        )
        self.assertEqual(pw.cleanup_drain_ledger()["distinct_resources"], 2)

    def test_an_obligation_with_no_provable_identity_is_never_an_alias(self) -> None:
        first = _StubObligation("no-identity-a", spend=False)
        second = _StubObligation("no-identity-b", spend=False)
        rl._retain_unregistered(first)
        rl._retain_unregistered(second)
        self.addCleanup(rl._release_unregistered, first)
        self.addCleanup(rl._release_unregistered, second)
        results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "anon"))
        rows = [row for row in results if row["kind"] and row["entry_id"] is None]
        self.assertEqual([row["alias_of"] for row in rows], [None, None], rows)
        self.assertTrue(all(row["canonical_for_resource"] is False for row in rows))


# --- M2-B58: reservation provenance and atomic consumption --------------------


class _RegistryObligation:
    """The minimum a registry entry needs: an incomplete cleanup document."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._registry_id: str | None = None

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict:
        return {}

    def evidence(self) -> dict:
        return {"helper_pid": 0, "cleanup_complete": False, "cleanup_retryable": True}

    def cleanup_evidence(self) -> dict:
        return self.evidence()


class ReservationProvenanceTests(unittest.TestCase):
    """A reservation is valid for exactly one registry, PID, epoch, id and object."""

    def setUp(self) -> None:
        _ProcessGuard.install(self)
        patcher = mock.patch.object(pw, "CLEANUP_REGISTRY_CAPACITY", 1)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.registry = pw._IncompleteCleanupRegistry()

    def fill(self, registry: pw._IncompleteCleanupRegistry | None = None) -> None:
        registry = registry or self.registry
        handle = _RegistryObligation("occupant")
        self.assertIsNotNone(registry.record(handle, handle.evidence()))

    def attempt(self, registry, token) -> str:
        handle = _RegistryObligation("smuggled")
        with self.assertRaises(CleanupReservationRefused) as caught:
            registry.record(handle, handle.evidence(), reservation=token)
        self.assertIsNone(handle._registry_id, "a refused insertion still marked the handle")
        return caught.exception.code

    def test_a_stale_token_surviving_a_pid_reset_is_refused(self) -> None:
        token = self.registry.reserve("stale")
        self.registry._owner_pid = -1
        self.registry._reset_after_fork()
        self.fill()
        self.assertTrue(self.registry.saturated())
        code = self.attempt(self.registry, token)
        self.assertEqual(code, pw.RESERVATION_REFUSED_STALE_EPOCH)
        self.assertEqual(len(self.registry.entries()), 1, "the capacity of one was exceeded")
        self.assertEqual(token.state, pw.RESERVATION_RESERVED, "the stale token was mutated")
        self.assertTrue(token.active)
        self.assertIsNone(token.converted_to)

    def test_a_fork_inherited_active_token_is_refused_in_the_child(self) -> None:
        token = self.registry.reserve("parents-own")
        registry = self.registry
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            code = 0
            try:
                os.close(read_fd)
                registry._reset_after_fork()
                handle = _RegistryObligation("child")
                registry.record(handle, handle.evidence())
                outcome = "NO_REFUSAL"
                try:
                    other = _RegistryObligation("inherited")
                    registry.record(other, other.evidence(), reservation=token)
                except CleanupReservationRefused as error:
                    outcome = error.code
                payload = json.dumps(
                    {
                        "outcome": outcome,
                        "entries": len(registry.entries()),
                        "token_state": token.state,
                        "token_active": token.active,
                    }
                ).encode("utf-8")
                os.write(write_fd, payload)
                os.close(write_fd)
            except BaseException:  # pragma: no cover - the child never raises out
                code = 70
            finally:
                os._exit(code)
        os.close(write_fd)
        self.addCleanup(_close_quietly, read_fd)
        raw = b""
        while True:
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            raw += chunk
        _pid, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        answer = json.loads(raw.decode("utf-8"))
        self.assertIn(
            answer["outcome"],
            {pw.RESERVATION_REFUSED_FOREIGN_PID, pw.RESERVATION_REFUSED_STALE_EPOCH},
            answer,
        )
        self.assertEqual(answer["entries"], 1, "the child exceeded its own capacity")
        self.assertEqual(answer["token_state"], pw.RESERVATION_RESERVED)
        # The parent's capability is untouched by whatever the child did.
        self.assertEqual(token.state, pw.RESERVATION_RESERVED)
        self.assertEqual(self.registry.evidence()["reserved"], 1)
        self.assertEqual(self.registry.evidence()["retained"], 0)

    def test_a_token_from_another_registry_instance_is_refused(self) -> None:
        other = pw._IncompleteCleanupRegistry()
        foreign = other.reserve("foreign")
        self.fill()
        code = self.attempt(self.registry, foreign)
        self.assertEqual(code, pw.RESERVATION_REFUSED_FOREIGN_REGISTRY)
        self.assertEqual(len(self.registry.entries()), 1)
        self.assertEqual(other.evidence()["reserved"], 1, "the issuing registry was mutated")
        self.assertEqual(foreign.state, pw.RESERVATION_RESERVED)
        self.assertNotEqual(other.registry_identity, self.registry.registry_identity)

    def test_a_forged_token_with_copied_fields_is_refused(self) -> None:
        real = self.registry.reserve("real")
        fields = real.to_dict()
        real.release()

        class _Forged:
            active = True
            state = pw.RESERVATION_RESERVED
            converted_to = None
            reservation_id = fields["reservation_id"]
            registry_identity = fields["registry_identity"]
            owner_pid = fields["owner_pid"]
            epoch = fields["epoch"]
            label = "forged"

            def release(self):
                return False

        self.fill()
        code = self.attempt(self.registry, _Forged())
        self.assertEqual(code, pw.RESERVATION_REFUSED_FOREIGN_TYPE)
        self.assertEqual(len(self.registry.entries()), 1)

    def test_the_same_id_standing_for_a_different_object_is_refused(self) -> None:
        real = self.registry.reserve("real")
        impostor = pw._CapacityReservation(
            self.registry,
            real.reservation_id,
            "impostor",
            registry_identity=self.registry.registry_identity,
            epoch=self.registry.epoch,
        )
        code = self.attempt(self.registry, impostor)
        self.assertEqual(code, pw.RESERVATION_REFUSED_NOT_THE_SAME_OBJECT)
        self.assertEqual(len(self.registry.entries()), 0)
        self.assertEqual(real.state, pw.RESERVATION_RESERVED, "the real token was mutated")
        self.assertEqual(self.registry.evidence()["reserved"], 1)

    def test_a_token_absent_from_the_reservation_table_is_refused(self) -> None:
        token = self.registry.reserve("removed-behind-its-back")
        self.registry._reservations.pop(token.reservation_id)
        code = self.attempt(self.registry, token)
        self.assertEqual(code, pw.RESERVATION_REFUSED_NOT_IN_TABLE)
        self.assertEqual(len(self.registry.entries()), 0)

    def test_a_consumed_token_cannot_be_reused(self) -> None:
        token = self.registry.reserve("linear")
        handle = _RegistryObligation("first")
        entry_id = self.registry.record(handle, handle.evidence(), reservation=token)
        self.assertIsNotNone(entry_id)
        self.assertEqual(token.state, pw.RESERVATION_CONSUMED)
        self.assertEqual(token.converted_to, entry_id)
        self.assertFalse(token.active)
        code = self.attempt(self.registry, token)
        self.assertEqual(code, pw.RESERVATION_REFUSED_ALREADY_CONSUMED)
        self.assertEqual(len(self.registry.entries()), 1, "one token became two entries")

    def test_a_released_token_cannot_be_consumed(self) -> None:
        token = self.registry.reserve("given-back")
        self.assertTrue(token.release())
        self.assertEqual(token.state, pw.RESERVATION_RELEASED)
        self.assertFalse(token.release(), "a spent reservation was released twice")
        self.fill()
        code = self.attempt(self.registry, token)
        self.assertEqual(code, pw.RESERVATION_REFUSED_ALREADY_RELEASED)
        self.assertEqual(len(self.registry.entries()), 1)

    def test_a_stale_token_cannot_release_capacity_it_does_not_hold(self) -> None:
        other = pw._IncompleteCleanupRegistry()
        foreign = other.reserve("foreign")
        # A registry that never issued it may not decrement anything for it.
        self.assertFalse(self.registry._release_reservation(foreign))
        self.assertEqual(other.evidence()["reserved"], 1)
        self.assertEqual(foreign.state, pw.RESERVATION_RESERVED)
        refusals = [row["code"] for row in self.registry.reservation_refusals()]
        self.assertIn(pw.RESERVATION_REFUSED_FOREIGN_REGISTRY, refusals)

    def test_every_refusal_is_classified_in_the_durable_evidence(self) -> None:
        other = pw._IncompleteCleanupRegistry()
        self.attempt(self.registry, other.reserve("foreign"))
        evidence = self.registry.evidence()
        self.assertEqual(evidence["registry_identity"], self.registry.registry_identity)
        self.assertEqual(evidence["epoch"], self.registry.epoch)
        self.assertEqual(len(evidence["reservation_refusals"]), 1, evidence)
        record = evidence["reservation_refusals"][0]
        self.assertEqual(record["operation"], "record")
        self.assertEqual(record["code"], pw.RESERVATION_REFUSED_FOREIGN_REGISTRY)
        self.assertEqual(record["capacity"], 1)

    def test_the_capacity_counts_entries_and_live_reservations_together(self) -> None:
        token = self.registry.reserve("held")
        evidence = self.registry.evidence()
        self.assertEqual(evidence["reserved"], 1)
        self.assertEqual(evidence["retained"], 0)
        self.assertEqual(evidence["held"], 1)
        self.assertTrue(evidence["saturated"])
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.reserve("no-room")
        handle = _RegistryObligation("direct")
        entry_id = self.registry.record(handle, handle.evidence(), reservation=token)
        self.assertIsNotNone(entry_id)
        self.assertEqual(self.registry.evidence()["held"], 1, "the conversion changed the total")

    def test_two_concurrent_consumers_of_one_token_yield_exactly_one_entry(self) -> None:
        token = self.registry.reserve("contested")
        start = threading.Barrier(8)
        accepted: list[str] = []
        refused: list[str] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            handle = _RegistryObligation(f"racer-{index}")
            start.wait()
            try:
                entry_id = self.registry.record(handle, handle.evidence(), reservation=token)
            except CleanupReservationRefused as error:
                with lock:
                    refused.append(error.code)
                return
            except CleanupRegistrySaturated:
                with lock:
                    refused.append("SATURATED")
                return
            with lock:
                accepted.append(entry_id)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(accepted), 1, f"one token became {len(accepted)} entries")
        self.assertEqual(len(refused), 7, refused)
        self.assertEqual(
            set(refused), {pw.RESERVATION_REFUSED_ALREADY_CONSUMED}, "an unclassified refusal"
        )
        self.assertEqual(len(self.registry.entries()), 1)
        self.assertEqual(self.registry.evidence()["held"], 1)

    def test_an_insertion_failure_rolls_the_reservation_back(self) -> None:
        token = self.registry.reserve("rollback")
        handle = _RegistryObligation("doomed")

        class _Boom(Exception):
            pass

        def exploding(*args, **kwargs):
            raise _Boom("the entry could not be constructed")

        with mock.patch.object(pw, "_IncompleteCleanup", exploding):
            with self.assertRaises(_Boom):
                self.registry.record(handle, handle.evidence(), reservation=token)
        self.assertEqual(token.state, pw.RESERVATION_RESERVED, "the capacity was lost")
        self.assertIsNone(token.converted_to)
        self.assertEqual(self.registry.evidence()["reserved"], 1)
        self.assertEqual(self.registry.evidence()["retained"], 0)
        self.assertEqual(self.registry.evidence()["held"], 1)
        self.assertIsNone(handle._registry_id)
        # ...and the rolled-back capability is still spendable exactly once.
        entry_id = self.registry.record(handle, handle.evidence(), reservation=token)
        self.assertIsNotNone(entry_id)
        self.assertEqual(token.state, pw.RESERVATION_CONSUMED)

    def test_a_reservation_converts_exactly_once_and_frees_its_unit(self) -> None:
        token = self.registry.reserve("convert")
        handle = _RegistryObligation("obligation")
        entry_id = self.registry.record(handle, handle.evidence(), reservation=token)
        self.assertEqual(self.registry.evidence()["reserved"], 0)
        self.assertEqual(self.registry.evidence()["retained"], 1)
        self.assertEqual(token.converted_to, entry_id)
        # A repeated registration of the *same* obligation is the ordinary case
        # and is not a second conversion.
        again = self.registry.record(handle, handle.evidence(), reservation=token)
        self.assertEqual(again, entry_id)
        self.assertEqual(len(self.registry.entries()), 1)

    def test_a_clean_completion_gives_the_unit_back(self) -> None:
        token = self.registry.reserve("clean")
        handle = _RegistryObligation("finished")
        evidence = handle.evidence()
        evidence["cleanup_complete"] = True
        self.assertIsNone(self.registry.record(handle, evidence, reservation=token))
        self.assertEqual(self.registry.evidence()["held"], 0)
        self.assertEqual(token.state, pw.RESERVATION_RELEASED)

    def test_the_active_flag_cannot_be_written(self) -> None:
        token = self.registry.reserve("read-only")
        with self.assertRaises(AttributeError):
            token.active = True  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            token.state = pw.RESERVATION_RESERVED  # type: ignore[misc]

    def test_the_production_registrar_refuses_a_foreign_token_fail_closed(self) -> None:
        """The cgroup registrar's exception path is the fail-closed one (M2-B52)."""

        other = pw._IncompleteCleanupRegistry()
        foreign = other.reserve("foreign")
        handle = _RegistryObligation("via-registrar")
        with mock.patch.object(pw, "_CLEANUP_REGISTRY", self.registry):
            with self.assertRaises(CleanupReservationRefused):
                pw._record_cleanup(handle, handle.evidence(), reservation=foreign)
        self.assertEqual(len(self.registry.entries()), 0)


# --- artifact coherence -------------------------------------------------------


def _accompanying_validation_report() -> dict:
    """The validation report that was current when *this* closure was.

    The M2 model keeps exactly one current validation report and a later bounded
    pass moves it.  The assertions in this class are about this closure, so they
    follow the report that accompanied it: the live report names the commit whose
    blob it superseded, that blob is loaded from git, and its hash is checked
    against the one the live report records.  Anchoring to whatever happens to be
    current later would make this class assert another pass's claims.
    """

    report = _load(VALIDATION_REPORT)
    seen: set = set()
    while (
        report.get("current_closure_key")
        != "m2_exact_removal_global_drain_reservation_provenance_closure"
    ):
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


class ClosureArtifactTests(unittest.TestCase):
    """The current artifacts describe this code and nothing stronger."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _load(CLOSURE_REPORT)
        cls.validation = _accompanying_validation_report()
        cls.live = _load(VALIDATION_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)

    def test_the_report_names_only_this_pass_and_its_starting_point(self) -> None:
        self.assertEqual(self.report["branch"], BRANCH)
        self.assertEqual(self.report["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.report["starting_commit_parent"], STARTING_COMMIT_PARENT)
        self.assertEqual(sorted(self.report["findings"]), ["M2-B56", "M2-B57", "M2-B58"])
        for finding in self.report["finding_details"]:
            with self.subTest(finding=finding["finding"]):
                self.assertEqual(finding["status"], "IMPLEMENTED")
                self.assertTrue(finding["reproduction"])
                self.assertTrue(finding["closure"])
                self.assertTrue(finding["evidence"])
                self.assertTrue(finding["refusal_condition"])

    def test_the_report_records_the_independent_refusal_verbatim(self) -> None:
        self.assertEqual(self.report["independent_audit_sha256"], INDEPENDENT_AUDIT_SHA256)
        self.assertEqual(
            tuple(self.report["independent_audit_verdicts"]), INDEPENDENT_AUDIT_VERDICTS
        )
        self.assertEqual(self.validation["independent_audit_sha256"], INDEPENDENT_AUDIT_SHA256)
        self.assertEqual(
            tuple(self.validation["independent_audit_verdicts"]), INDEPENDENT_AUDIT_VERDICTS
        )

    def test_nothing_claims_acceptance_installation_or_milestone_three(self) -> None:
        for document, name in ((self.report, "closure"), (self.validation, "validation")):
            with self.subTest(document=name):
                self.assertFalse(document["independent_acceptance_claimed"])
                self.assertFalse(document["installed_path_qualification_claimed"])
                for boundary, crossed in document["boundary_audit"].items():
                    self.assertFalse(crossed, f"{name}:{boundary}")

    def test_exactly_one_validation_state_declares_itself_current(self) -> None:
        """Whether or not that is still this closure's."""

        self.assertTrue(self.live["is_current_validation_report"])
        current = [
            path
            for path in IMPLEMENTATION.glob("M2_VALIDATION_REPORT*.json")
            if _load(path).get("is_current_validation_report")
        ]
        self.assertEqual([path.name for path in current], ["M2_VALIDATION_REPORT.json"])
        if self.live != self.validation:
            # A later pass moved it, and must record this closure as superseded
            # rather than simply forgetting it.
            self.assertIn(
                "implementation/M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_"
                "CLOSURE_REPORT.json",
                self.live["superseded_closure_reports"],
                "the later current report does not record this closure as superseded",
            )
            self.assertNotEqual(
                self.live["current_closure_key"],
                "m2_exact_removal_global_drain_reservation_provenance_closure",
            )

    def test_the_two_current_reports_carry_one_canonical_run(self) -> None:
        self.assertEqual(
            self.validation["canonical_current_run"], self.report["canonical_current_run"]
        )
        self.assertEqual(self.validation["branch"], self.report["branch"])
        self.assertEqual(self.validation["starting_commit"], self.report["starting_commit"])
        self.assertEqual(self.validation["terminal_verdict"], self.report["terminal_verdict"])
        self.assertEqual(
            self.validation["final_repair_report"],
            "implementation/M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_CLOSURE_REPORT.json",
        )

    def test_the_prior_transcript_is_history_and_not_this_qualification(self) -> None:
        prior = self.validation["prior_physical_qualification"]
        self.assertEqual(prior["qualified_commit"], STARTING_COMMIT)
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertEqual(prior["transcript"], PRIOR_DELEGATED_TRANSCRIPT)
        current = self.validation["canonical_current_run"]["delegated_physical"]
        self.assertNotEqual(current["transcript"], PRIOR_DELEGATED_TRANSCRIPT)

    def test_the_qualification_command_names_the_new_module(self) -> None:
        module = (
            "tests.test_admissible_paired_runner_m2_exact_removal_global_drain_"
            "reservation_provenance_closure"
        )
        delegated_run = self.validation["canonical_current_run"]["delegated_physical"]
        self.assertIn(module, delegated_run["expected_modules"])
        self.assertEqual(len(delegated_run["expected_modules"]), 8)
        self.assertEqual(delegated_run["expected_skips"], 0)
        self.assertIn(module, self.report["operator_command"])

    def test_the_module_counts_match_the_files_on_disk(self) -> None:
        counts = self.validation["test_counts"]["per_module"]
        for name in counts:
            with self.subTest(module=name):
                self.assertTrue(
                    (REPOSITORY_ROOT / "tests" / f"{name}.py").is_file(),
                    f"{name} is counted but is not a file on disk",
                )
        this_module = (
            "test_admissible_paired_runner_m2_exact_removal_global_drain_"
            "reservation_provenance_closure"
        )
        live = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__]).countTestCases()
        self.assertEqual(counts[this_module], live, "this module's declared count is stale")
        self.assertEqual(
            self.report["deterministic_tests"] + self.report["delegated_tests"],
            live,
            "the closure report's split of this module does not add up",
        )
        m1 = sum(value for name, value in counts.items() if "_m1" in name)
        m2 = sum(value for name, value in counts.items() if "_m2" in name)
        self.assertEqual(m1, self.validation["test_counts"]["m1_tests"])
        self.assertEqual(m2, self.validation["test_counts"]["m2_tests"])
        self.assertEqual(m1 + m2, self.validation["test_counts"]["discovered_total"])
        self.assertEqual(
            self.validation["test_counts"]["total"],
            self.validation["test_counts"]["discovered_total"],
        )

    def test_the_module_count_on_disk_matches_the_declared_package(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        modules = sorted(path.name for path in package.glob("*.py"))
        self.assertEqual(self.report["module_inventory"], modules)
        self.assertEqual(self.report["module_count"], len(modules))

    def test_the_matrix_records_this_closure_without_reopening_anything(self) -> None:
        note = self.matrix["m2_exact_removal_global_drain_reservation_provenance_closure_note"]
        for finding in ("M2-B56", "M2-B57", "M2-B58"):
            self.assertIn(finding, note)
        self.assertIn(
            "M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_CLOSURE_REPORT.json", note
        )
        self.assertEqual(self.matrix["requirement_count"], len(self.matrix["requirements"]))

    def test_b26_and_b27_remain_closed(self) -> None:
        fourth = _load(IMPLEMENTATION / "M2_FOURTH_CRITICAL_REPAIR_REPORT.json")
        findings = {row["finding"]: row for row in fourth["findings"]}
        for name in ("M2-B26", "M2-B27"):
            with self.subTest(finding=name):
                self.assertEqual(findings[name]["disposition"], "VERIFIED_PHYSICAL")
        self.assertTrue(self.report["preserved_closures"]["b26_and_b27_closed"])
        # The bytes that record them are preserved by this pass, not rewritten.
        self.assertIn(
            "M2_FOURTH_CRITICAL_REPAIR_REPORT.json", self.report["preserved_historical_artifacts"]
        )

    def test_the_historical_reports_are_unchanged(self) -> None:
        for name in self.report["preserved_historical_artifacts"]:
            with self.subTest(artifact=name):
                committed = subprocess.run(
                    ["git", "show", f"{STARTING_COMMIT}:implementation/{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), committed)

    def test_no_forbidden_scope_was_entered(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        present = {path.name for path in package.glob("*.py")}
        for name in (
            "transport.py",
            "direct_mode.py",
            "governed_mode.py",
            "policy.py",
            "authority.py",
            "evaluator.py",
            "archive.py",
            "benchmark.py",
        ):
            self.assertNotIn(name, present)
        for module in ("resource_limits.py", "private_workspace.py", "process_ownership.py"):
            text = (package / module).read_text(encoding="utf-8")
            for token in ("requests", "urllib", "http", "socket"):
                if module == "private_workspace.py" and token == "socket":
                    continue
                with self.subTest(module=module, forbidden=token):
                    self.assertNotIn(f"import {token}", text)
                    self.assertNotIn(f"from {token}", text)


class ProductionWiringTests(unittest.TestCase):
    """The production code paths carry the closures, not just the tests."""

    def setUp(self) -> None:
        _ProcessGuard.install(self)

    def test_the_final_removal_is_descriptor_relative_in_the_source(self) -> None:
        import inspect

        source = inspect.getsource(rl.EffectCgroup._remove_inside_boundary)
        self.assertIn("_rmdir_owned_child(self._parent_fd, self._leaf)", source)
        self.assertNotIn("path.rmdir()", source)
        primitive = inspect.getsource(rl._rmdir_owned_child)
        self.assertIn("os.rmdir(leaf, dir_fd=parent_fd)", primitive)

    def test_the_close_path_enters_the_boundary_before_the_final_proof(self) -> None:
        import inspect

        source = inspect.getsource(rl.EffectCgroup._remove_exact_owned_child)
        boundary = source.index("cgroup_mutation_boundary(domain)")
        handoff = source.index("_remove_inside_boundary")
        self.assertLess(boundary, handoff, "the identity proof runs outside the boundary")

    def test_the_drain_opens_exactly_one_budget_at_the_outermost_entry(self) -> None:
        import inspect

        source = inspect.getsource(pw.drain_incomplete_cleanups)
        self.assertEqual(source.count("CleanupBudget.open"), 1)
        inner = inspect.getsource(pw._drain_unregistered_obligation)
        self.assertNotIn("Deadline.after_ms", inner)
        self.assertNotIn("CleanupBudget.open", inner)

    def test_the_registry_verifies_provenance_before_granting_capacity(self) -> None:
        import inspect

        source = inspect.getsource(pw._IncompleteCleanupRegistry._classify_reservation_locked)
        for check in (
            "isinstance(token, _CapacityReservation)",
            "token._registry is not self",
            "token.registry_identity != self._identity",
            "token.owner_pid != os.getpid()",
            "token.epoch != self._epoch",
            "self._reservations.get(token.reservation_id)",
            "outstanding is not token",
        ):
            with self.subTest(check=check):
                self.assertIn(check, source)


# --- delegated physical qualification -----------------------------------------


class DelegatedExactRemovalDrainReservationTests(unittest.TestCase):
    """Physical qualification of B56, B57 and B58 on real kernel state."""

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
        # Registered last, so it runs *first* on the way out -- before the
        # guards put the process-wide collections back.  Registered rather than
        # written into each test, so it survives an assertion that raises.
        self.addCleanup(self._teardown_every_obligation)

    def _teardown_every_obligation(self) -> None:
        """Discharge everything this test owns, on a fresh independent budget.

        A failed assertion may report a defect; it may not manufacture one for
        the next physical test.  Every step is the production settlement, so
        only exact owned live processes are killed, only exact owned children are
        reaped, and only exact owned cgroups are removed.
        """

        for _attempt in range(4):
            retained = list(pw.incomplete_cleanups()) + list(rl.unregistered_cleanups())
            if not retained:
                break
            try:
                pw.drain_incomplete_cleanups(
                    deadline=Deadline.after_ms(RETRY_BUDGET_MS, "delegated_teardown")
                )
            except Exception:  # pragma: no cover - the teardown never masks a failure
                break

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

    def test_the_branch_and_revision_are_the_ones_under_qualification(self) -> None:
        def git(*arguments: str) -> str:
            return subprocess.run(
                ["git", *arguments],
                cwd=REPOSITORY_ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        branch = git("branch", "--show-current")
        # This module is qualified on its own bounded branch, and is re-run as a
        # regression by each later bounded closure on that closure's branch.
        self.assertTrue(
            branch.startswith("paired-runner/m2-"),
            f"this module is qualified only on a bounded Milestone 2 closure branch: {branch!r}",
        )
        # Exactly the bounded range this pass is permitted: the starting commit
        # is an ancestor of HEAD, its parent chain is unchanged, and at most one
        # commit stands on top of it per bounded pass.
        self.assertEqual(git("merge-base", STARTING_COMMIT, "HEAD"), STARTING_COMMIT)
        self.assertEqual(git("rev-parse", f"{STARTING_COMMIT}^"), STARTING_COMMIT_PARENT)
        ahead = int(git("rev-list", "--count", f"{STARTING_COMMIT}..HEAD"))
        self.assertLessEqual(
            ahead,
            1 if branch == BRANCH else 2,
            "more than one commit stands on top of this closure's starting point",
        )

    @delegated
    def test_a_real_same_name_replacement_survives_the_owned_removal(self) -> None:
        """M2-B56 physically: a real replacement through the controller's own path."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        domain = rl.cgroup_mutation_domain_of(parent)
        self.assertIsNotNone(domain, "the delegated parent has no readable identity")
        label = f"b56-real-{os.getpid()}"
        owned = rl.EffectCgroup(DELEGATION, rl.ResourceBounds.for_timeout(1_000), label)
        self.assertTrue(owned.create(), owned.create_error)
        owned_identity = owned.owned_identity
        owned_path = Path(owned.owned_path)

        inside = threading.Event()
        proceed = threading.Event()
        created: list[bool] = []
        replacement: dict[str, object] = {}
        real_members = rl.EffectCgroup.read_members

        def hold(self_cgroup):
            answer = real_members(self_cgroup)
            # Only the read taken inside the removal's own critical section.
            if self_cgroup is owned and rl.cgroup_mutation_boundary_held(domain):
                inside.set()
                proceed.wait(10.0)
            return answer

        def replace() -> None:
            inside.wait(10.0)
            other = rl.EffectCgroup(DELEGATION, rl.ResourceBounds.for_timeout(1_000), label)
            ok = other.create()
            replacement["cgroup"] = other
            created.append(bool(ok))

        worker = threading.Thread(target=replace)
        worker.start()
        try:
            with mock.patch.object(rl.EffectCgroup, "read_members", hold):
                closing = threading.Thread(target=owned.close)
                closing.start()
                self.assertTrue(inside.wait(10.0), "the removal never entered its boundary")
                time.sleep(0.3)
                self.assertEqual(
                    created, [], "a controller-owned creation landed inside the critical section"
                )
                proceed.set()
                closing.join(20.0)
                self.assertFalse(closing.is_alive(), "the removal never finished")
        finally:
            proceed.set()
            worker.join(20.0)

        self.assertEqual(created, [True], "the blocked creation never completed")
        other = replacement["cgroup"]
        self.addCleanup(other.close)
        self.assertEqual(
            owned.removal_disposition()["code"], rl.CGROUP_REMOVAL_EXACT, owned.removal_evidence()
        )
        self.assertTrue(owned.removal_evidence()["removed"])
        self.assertTrue(Path(other.owned_path).exists(), "the replacement was removed")
        self.assertEqual(Path(other.owned_path).name, owned_path.name)
        self.assertIsNotNone(owned_identity)

        # A live process inside the replacement is never signalled by the
        # settled obligation, and the replacement is never removed by it.
        helper = PrivateMountHelper.start()
        self.addCleanup(_reap_quietly, helper.pid)
        victim = helper.spawn([PYTHON, "-c", "import time\ntime.sleep(120)\n"])
        self.addCleanup(_close_quietly, victim.stdout_fd)
        self.addCleanup(_close_quietly, victim.stderr_fd)
        try:
            self.assertTrue(other.attach_and_verify(victim.pid), other.attach_error)
            settlement = owned.settle_cleanup(deadline=Deadline.after_ms(500, "settle"))
            self.assertTrue(settlement["cleanup_complete"], settlement)
            self.assertIsNone(settlement["kill_domain"], "a kill was issued after the obligation ended")
            self.assertTrue(_await(lambda: True, 0.3) and po.process_present(victim.pid),
                            "a process inside the replacement was signalled")
            members = rl.read_cgroup_members(Path(other.owned_path))
            self.assertIn(victim.pid, members.pids, "the replacement was emptied")
        finally:
            helper.close(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "helper_close"))
            _reap_quietly(victim.pid)
        other.close()
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "drain"))
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertFalse(rl.cgroup_mutation_boundary_held(domain))

    @delegated
    def test_a_real_mixed_drain_spends_exactly_one_budget(self) -> None:
        """M2-B57 physically: one real registered and one real unregistered obligation."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        total_ms = 300
        # A real registered obligation: a populated cgroup whose removal refuses.
        registered = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b57-registered-{os.getpid()}"
        )
        self.assertTrue(registered.create(), registered.create_error)
        child = os.fork()
        if child == 0:  # pragma: no cover - child process
            try:
                time.sleep(120)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, child)
        self.assertTrue(registered.attach_and_verify(child), registered.attach_error)
        registered.record_owned_process(child, role="TEST_CHILD")
        self.assertFalse(registered.close(), "a populated cgroup was reported removed")
        entry_id = registered.cleanup_registry_id
        self.assertIsNotNone(entry_id, "the removal obligation was not retained")

        # A real unregistered obligation, produced through the fail-closed
        # registrar path exactly as a registrar failure produces one.  It carries
        # a live member, so its removal genuinely *is* outstanding when the drain
        # reaches it.  The first version of this test created an empty cgroup,
        # whose own close() removed it before the drain began; the drain then
        # truthfully found nothing outstanding, and the delegated qualification
        # correctly refused the row that called that an unattempted removal.
        unregistered = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b57-unregistered-{os.getpid()}"
        )
        self.assertTrue(unregistered.create(), unregistered.create_error)
        unregistered_path = Path(unregistered.owned_path)
        occupant = os.fork()
        if occupant == 0:  # pragma: no cover - child process
            try:
                time.sleep(120)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, occupant)
        self.assertTrue(unregistered.attach_and_verify(occupant), unregistered.attach_error)
        unregistered.record_owned_process(occupant, role="TEST_CHILD")

        def exploding(handle, evidence, *, reservation=None):
            raise RuntimeError("the registrar refuses this obligation")

        with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
            self.assertFalse(unregistered.close(), "a populated cgroup was reported removed")
        self.assertIsNotNone(unregistered.registration_failure, "the failure was swallowed")
        self.assertTrue(
            any(handle is unregistered for handle in rl.unregistered_cleanups()),
            "the unregistered obligation was lost",
        )
        # The premise of the assertion below: this obligation really does still
        # owe a removal when the drain reaches it.
        self.assertTrue(unregistered_path.exists())
        self.assertTrue(unregistered.cleanup_evidence()["resource_outstanding"])
        # The occupant is alive, is this process's child, and is physically in
        # this exact cgroup's cgroup.procs.  Containment work therefore genuinely
        # remains; so does the reap.  Both are named, because both are true.
        self.assertEqual(_proc_state(occupant), "S", f"the occupant is not alive: {occupant}")
        self.assertEqual(
            rl.read_cgroup_members(unregistered_path).pids,
            (occupant,),
            "the occupant is not attached to the exact unregistered cgroup",
        )
        outstanding = unregistered.cleanup_evidence()["outstanding_work"]
        self.assertIn(rl.OUTSTANDING_CONTAINMENT, outstanding, outstanding)
        self.assertIn(rl.OUTSTANDING_PROCESSES, outstanding, outstanding)

        # The registered obligation is reached first and is made to spend the
        # whole budget; the unregistered one must receive nothing.
        real_settle = rl.EffectCgroup.settle_cleanup

        def slow_settle(self_cgroup, *, deadline=None):
            if self_cgroup is registered and deadline is not None:
                time.sleep(float(deadline.remaining_seconds) + 0.02)
                return real_settle(self_cgroup, deadline=deadline)
            return real_settle(self_cgroup, deadline=deadline)

        started = time.monotonic()
        with mock.patch.object(rl.EffectCgroup, "settle_cleanup", slow_settle):
            results = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(total_ms, "b57"))
        elapsed_ms = (time.monotonic() - started) * 1000
        self.assertLess(
            elapsed_ms, total_ms + 400, f"the drain spent {elapsed_ms:.0f}ms against {total_ms}ms"
        )
        rows = {row["collection"]: row for row in results}
        self.assertIn("UNREGISTERED", rows, results)
        self.assertFalse(rows["UNREGISTERED"]["attempted"], rows["UNREGISTERED"])
        self.assertEqual(
            rows["UNREGISTERED"]["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED
        )
        self.assertEqual(
            rows["UNREGISTERED"]["state"], pw.DRAIN_STATE_RETAINED_UNATTEMPTED, rows["UNREGISTERED"]
        )
        self.assertTrue(rows["UNREGISTERED"]["resource_outstanding"])
        self.assertEqual(rows["UNREGISTERED"]["granted_ms"], 0, "an unattempted row took a grant")
        self.assertTrue(rows["UNREGISTERED"]["retained"], "the obligation was dropped")
        # Two distinct cgroups: neither is an alias of the other.
        self.assertIsNone(rows["UNREGISTERED"]["alias_of"])
        self.assertIsNone(rows["REGISTERED"]["alias_of"])
        self.assertNotEqual(
            rows["UNREGISTERED"]["resource_identity"], rows["REGISTERED"]["resource_identity"]
        )
        ledger = pw.cleanup_drain_ledger()
        self.assertEqual(ledger["configured_total_ms"], total_ms)
        self.assertEqual(ledger["obligations_unattempted"], 1)
        self.assertEqual(ledger["distinct_resources"], 2)
        self.assertEqual(ledger["aliases_discharged_by_a_canonical_obligation"], 0)
        self.assertTrue(unregistered_path.exists(), "an unattempted removal happened anyway")

        # A later independent retry settles what the exhausted drain retained.
        # The children are *not* reaped here: an owned child reaped behind the
        # controller's back leaves it a bare ECHILD, which M2-B51 correctly
        # refuses to accept as a discharge.  The production settlement kills the
        # exact owned domain and positively reaps its own children.
        for _ in range(5):
            pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
            if not unregistered_path.exists() and registered.cleanup_complete:
                break
        self.assertTrue(unregistered.cleanup_complete, unregistered.cleanup_evidence())
        self.assertTrue(registered.cleanup_complete, registered.cleanup_evidence())
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    def test_a_real_discharged_resource_is_never_reported_as_an_unattempted_removal(self) -> None:
        """M2-B57 physically: the row the delegated qualification refused.

        A real cgroup whose own ``close()`` removed it, whose registration then
        failed, must be classified by its outstanding *work* and not by the
        budget: it owes bookkeeping, not a removal.  And a real drain with no
        budget left must run no destructive primitive at all.
        """

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)

        def exploding(handle, evidence, *, reservation=None):
            raise RuntimeError("the registrar refuses this obligation")

        # (1) A real, empty cgroup: its own close() discharges it under the
        # removal's exclusion boundary, before any drain exists.
        discharged = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b57-discharged-{os.getpid()}"
        )
        self.assertTrue(discharged.create(), discharged.create_error)
        discharged_path = Path(discharged.owned_path)
        with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
            self.assertTrue(discharged.close(), discharged.attach_error)
        self.assertFalse(discharged_path.exists(), "the fixture did not discharge the resource")
        self.assertEqual(
            discharged.removal_disposition()["code"], rl.CGROUP_REMOVAL_EXACT,
            discharged.removal_evidence(),
        )
        evidence = discharged.cleanup_evidence()
        self.assertFalse(evidence["resource_outstanding"])
        self.assertEqual(evidence["outstanding_work"], (rl.OUTSTANDING_REGISTRATION,))
        self.assertEqual(evidence["cleanup_retry_operation"], rl.CGROUP_RETRY_RECORD)

        # (2) A real, occupied cgroup whose removal genuinely is outstanding.
        outstanding = rl.EffectCgroup(
            DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b57-outstanding-{os.getpid()}"
        )
        self.assertTrue(outstanding.create(), outstanding.create_error)
        outstanding_path = Path(outstanding.owned_path)
        occupant = os.fork()
        if occupant == 0:  # pragma: no cover - child process
            try:
                time.sleep(120)
            finally:
                os._exit(0)
        self.addCleanup(_reap_quietly, occupant)
        self.assertTrue(outstanding.attach_and_verify(occupant), outstanding.attach_error)
        outstanding.record_owned_process(occupant, role="TEST_CHILD")
        with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
            self.assertFalse(outstanding.close(), "a populated cgroup was reported removed")
        self.assertTrue(outstanding.cleanup_evidence()["resource_outstanding"])

        # (3) A real drain with nothing left to spend: no primitive may run.
        removals: list[str] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append(leaf)
            return real(parent_fd, leaf)

        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            results = pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("spent"))
        self.assertEqual(removals, [], "a destructive primitive ran on an exhausted budget")
        self.assertTrue(outstanding_path.exists(), "an untouched obligation was destroyed")

        rows = {row["effect_cgroup_path"]: row for row in results}
        discharged_row = rows[str(discharged_path)]
        outstanding_row = rows[str(outstanding_path)]
        self.assertEqual(discharged_row["state"], pw.DRAIN_STATE_RESOURCE_DISCHARGED, discharged_row)
        self.assertEqual(
            discharged_row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_RESOURCE_DISCHARGED
        )
        self.assertNotEqual(
            discharged_row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED
        )
        self.assertFalse(discharged_row["resource_outstanding"])
        self.assertEqual(outstanding_row["state"], pw.DRAIN_STATE_RETAINED_UNATTEMPTED)
        self.assertEqual(
            outstanding_row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED
        )
        self.assertTrue(outstanding_row["resource_outstanding"])
        self.assertEqual(outstanding_row["granted_ms"], 0)
        # Two distinct real cgroups; neither is an alias of the other.
        self.assertIsNone(discharged_row["alias_of"])
        self.assertIsNone(outstanding_row["alias_of"])

        # A later independent retry settles what the exhausted drain retained.
        # The occupant is not reaped here: the production settlement kills the
        # exact owned domain and positively reaps its own child, and a bare
        # ECHILD from a reap this test performed is not a discharge.
        for _ in range(5):
            pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "retry"))
            if outstanding.cleanup_complete and discharged.cleanup_complete:
                break
        self.assertTrue(outstanding.cleanup_complete, outstanding.cleanup_evidence())
        self.assertTrue(discharged.cleanup_complete, discharged.cleanup_evidence())
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    def test_a_real_inherited_reservation_is_refused_before_any_fork_or_mkdir(self) -> None:
        """M2-B58 physically: a real PID reset, a real capacity of one, no bypass."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        with mock.patch.object(pw, "CLEANUP_REGISTRY_CAPACITY", 1):
            token = pw._CLEANUP_REGISTRY.reserve("parent-owns")
            self.addCleanup(token.release)
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:  # pragma: no cover - child process
                code = 0
                try:
                    os.close(read_fd)
                    pw._CLEANUP_REGISTRY._reset_after_fork()
                    occupant = _RegistryObligation("child-occupant")
                    pw._CLEANUP_REGISTRY.record(occupant, occupant.evidence())
                    made: list[str] = []
                    forked: list[int] = []
                    real_mkdir = Path.mkdir
                    real_fork = os.fork

                    def recording_mkdir(self_path, *args, **kwargs):
                        made.append(str(self_path))
                        return real_mkdir(self_path, *args, **kwargs)

                    def recording_fork():
                        forked.append(1)
                        return real_fork()

                    outcome = "NO_REFUSAL"
                    with mock.patch.object(Path, "mkdir", recording_mkdir), mock.patch.object(
                        os, "fork", recording_fork
                    ):
                        try:
                            smuggled = _RegistryObligation("smuggled")
                            pw._CLEANUP_REGISTRY.record(
                                smuggled, smuggled.evidence(), reservation=token
                            )
                        except CleanupReservationRefused as error:
                            outcome = error.code
                    payload = json.dumps(
                        {
                            "outcome": outcome,
                            "entries": len(pw._CLEANUP_REGISTRY.entries()),
                            "directories_created": made,
                            "forks": len(forked),
                            "token_state": token.state,
                        }
                    ).encode("utf-8")
                    os.write(write_fd, payload)
                    os.close(write_fd)
                except BaseException:  # pragma: no cover - the child never raises out
                    code = 70
                finally:
                    os._exit(code)
            os.close(write_fd)
            self.addCleanup(_close_quietly, read_fd)
            raw = b""
            while True:
                chunk = os.read(read_fd, 4096)
                if not chunk:
                    break
                raw += chunk
            _pid, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            answer = json.loads(raw.decode("utf-8"))
            self.assertIn(
                answer["outcome"],
                {pw.RESERVATION_REFUSED_FOREIGN_PID, pw.RESERVATION_REFUSED_STALE_EPOCH},
                answer,
            )
            self.assertEqual(answer["entries"], 1, "the child exceeded a capacity of one")
            self.assertEqual(answer["directories_created"], [], "a cgroup was created before the refusal")
            self.assertEqual(answer["forks"], 0, "a fork happened before the refusal")
            self.assertEqual(answer["token_state"], pw.RESERVATION_RESERVED)
            # The parent's capability is exactly as it was.
            self.assertEqual(token.state, pw.RESERVATION_RESERVED)
            self.assertTrue(token.active)
            evidence = pw.cleanup_registry_evidence()
            self.assertEqual(evidence["reserved"], 1)
            self.assertEqual(evidence["retained"], 0)
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    def test_an_assertion_after_the_first_drain_still_leaves_no_residue(self) -> None:
        """A failed physical test may not contaminate the next one.

        The delegated qualification refused this closure four times over, and two
        of those four were not defects at all: a real cgroup left standing by a
        test that raised before its own cleanup line, which the next physical
        test then found and reported as a leak it did not create.  The teardown
        is a registered cleanup on a fresh independent budget, so it runs whether
        the body returned or raised -- and this test proves it by raising.
        """

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)

        def exploding(handle, evidence, *, reservation=None):
            raise RuntimeError("the registrar refuses this obligation")

        observed: dict[str, object] = {}

        class _IntentionalFailure(AssertionError):
            pass

        def body() -> None:
            """Exactly the shape of the test that leaked: obligations, then raise."""

            registered = rl.EffectCgroup(
                DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b57-residue-r-{os.getpid()}"
            )
            self.assertTrue(registered.create(), registered.create_error)
            first = os.fork()
            if first == 0:  # pragma: no cover - child process
                try:
                    time.sleep(120)
                finally:
                    os._exit(0)
            self.assertTrue(registered.attach_and_verify(first), registered.attach_error)
            registered.record_owned_process(first, role="TEST_CHILD")
            self.assertFalse(registered.close())

            unregistered = rl.EffectCgroup(
                DELEGATION, rl.ResourceBounds.for_timeout(1_000), f"b57-residue-u-{os.getpid()}"
            )
            self.assertTrue(unregistered.create(), unregistered.create_error)
            second = os.fork()
            if second == 0:  # pragma: no cover - child process
                try:
                    time.sleep(120)
                finally:
                    os._exit(0)
            self.assertTrue(unregistered.attach_and_verify(second), unregistered.attach_error)
            unregistered.record_owned_process(second, role="TEST_CHILD")
            with mock.patch.object(rl, "_CLEANUP_REGISTRAR", exploding):
                self.assertFalse(unregistered.close())
            observed["paths"] = [Path(registered.owned_path), Path(unregistered.owned_path)]
            observed["pids"] = [first, second]
            # One bounded drain that settles nothing, then the abort -- exactly
            # where the real test raised, with both obligations retained and both
            # cgroups present and populated.
            rows = pw.drain_incomplete_cleanups(deadline=Deadline.already_expired("residue"))
            self.assertTrue(all(not row["attempted"] for row in rows), rows)
            self.assertTrue(all(p.exists() for p in observed["paths"]))
            raise _IntentionalFailure("the intentional abort this regression exists to survive")

        with self.assertRaises(_IntentionalFailure):
            body()
        self.assertTrue(observed["paths"], "the fixture never created its obligations")
        self.assertTrue(
            any(p.exists() for p in observed["paths"]),
            "the fixture aborted before it had anything to leak",
        )

        # The production teardown, exactly as the registered cleanup runs it.
        self._teardown_every_obligation()

        for path in observed["paths"]:
            self.assertFalse(path.exists(), f"{path} survived the teardown")
        for pid in observed["pids"]:
            self.assertFalse(po.process_present(pid), f"pid {pid} survived the teardown")
            self.assertFalse(po.process_is_zombie(pid), f"pid {pid} was left a zombie")
        self.assertEqual(rl.unregistered_cleanups(), (), "an unregistered obligation survived")
        self.assertEqual(pw.incomplete_cleanups(), (), "a registry entry survived")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)
        self.assertIsNone(po.process_restoration_debt(), "restoration debt survived")
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    def test_no_residual_state_survives_this_module(self) -> None:
        """Nothing owned, retained, held or owed is left behind."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "residual"))
        parent = Path(DELEGATION.delegated_path)
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(rl.unregistered_cleanups(), (), "an unregistered obligation leaked")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)
        self.assertEqual(pw.unsettled_failed_starts(), (), "a failed start leaked")
        self.assertFalse(CHILD_SUBREAPER.active, "subreaper ownership leaked")
        self.assertIsNone(po.process_restoration_debt(), "restoration debt leaked")
        self.assertEqual(po.get_child_subreaper()[0], self.before, "the kernel flag was left changed")
        self.assertEqual(
            rl.cgroup_mutation_domains_evidence()["held_by_this_thread"],
            [],
            "a mutation boundary was left held",
        )


if __name__ == "__main__":
    unittest.main()
