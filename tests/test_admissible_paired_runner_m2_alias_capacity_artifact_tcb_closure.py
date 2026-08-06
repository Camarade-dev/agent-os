"""M2 alias-truth / combined-capacity / artifact-coherence / mutation-TCB closure.

Each finding is closed by making the untrue statement impossible to produce.

M2-B59 -- an alias is discharged by a canonical *result*, never by a relationship
    ``_drain_within`` identified the alias before the canonical obligation ran,
    and ``_classify_drain_row`` then prioritised ``alias_of`` over everything the
    canonical obligation actually did.  The independently reproduced consequence
    was a false cleanup claim over a resource that was still standing:

        canonical: attempted=true  state=UNRESOLVED_AND_RETAINED  outstanding=true
        alias:     attempted=false state=DISCHARGED_BY_CANONICAL  outstanding=true

    Sharing a resource with an obligation that failed to settle it is not a
    discharge.  Each exact-resource identity group is now an explicit state
    machine: one canonical obligation is selected deterministically, it is
    executed, observed or claimed, exactly one canonical result is published, and
    every alias is classified from that exact published result.  Without a result
    proving the exact shared resource is no longer outstanding the alias is
    retained under its own truthful state -- and still spends no second grant.
    The row guard refuses the contradictory shapes where they are built.

M2-B60 -- one combined capacity, enforced by every insertion
    The registry defines held capacity as entries plus live reservations, and
    ``reserve()``, ``saturated()`` and ``require_capacity()`` all enforce that.
    A reservation-less ``record()`` checked ``len(self._entries)`` alone, so at
    capacity one a single reservation plus one direct insertion produced
    ``reserved=1 retained=1 held=2 capacity=1``.  The direct path now takes the
    same combined count inside the same critical section, before anything is
    mutated, and the atomic reservation-conversion path is untouched.

M2-M61 -- the current artifacts say one thing about one run
    The current reports claimed ``PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2``
    with ``executed = 663`` while retaining text saying the qualification was an
    operator hand-off, that the run "must show 652 tests", and that the object
    was "not updated to QUALIFIED".  The transcript existed; the description
    contradicted it.  The current state objects now describe this commit, this
    wrapper-executed run and these counts, superseded excerpts and transcripts
    live only in explicitly historical structures, and the assertions below are
    semantic implications rather than byte equality between two files.

M2-M62 -- the declared mutation TCB is not broader than the code
    ``CGROUP_MUTATION_TCB`` declares every controller-owned child creation,
    rename, replacement, removal and final removal under a delegated parent
    serialized by one boundary.  Effect creation, manager-leaf mutation, final
    removal and probe removal took it; probe creation ran ``probe.mkdir`` outside
    it.  The preferred resolution is taken: probe creation now enters the same
    parent boundary and holds it across the parent identity proof, the collision
    check, the ``mkdir``, the created-object identity capture and the rollback of
    a partial creation, so the declaration is true rather than aspirational.

Deterministic tests drive real descriptors, real threads, the real process
cleanup registry and a constructed cgroup tree.  Delegated physical tests run the
production path inside a real ``Delegate=yes`` cgroup v2 subtree and, under
``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than skip.

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
)
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    Deadline,
)
from admissible.paired_runner.resource_limits import probe_cgroup_delegation  # noqa: E402

DELEGATION = probe_cgroup_delegation()
REQUIRE_DELEGATED = os.environ.get("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP") == "1"

from _paired_runner_m2_fixtures import (  # noqa: E402
    guard_process_wide_cgroup_caches,
    guard_process_wide_cleanup_registry,
    guard_process_wide_restoration_debt,
    guard_process_wide_subreaper_ownership,
)
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = REPOSITORY_ROOT / "implementation"

BRANCH = "paired-runner/m2-alias-capacity-artifact-tcb-closure"
STARTING_COMMIT = "6d687d4c778ae917f925da18aa89b2c53cdac911"
STARTING_COMMIT_PARENT = "63df0305861fe8d1f3760c0f9a2083dafc51cdf5"
INDEPENDENT_AUDIT_SHA256 = (
    "db18f0b0ec583ecabfd2a64b95441d0a288cc0a4267263da67febbe7c6292b12"
)
INDEPENDENT_AUDIT_VERDICTS = (
    "M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_FINAL_INDEPENDENT_CLOSURE_REFUSED",
    "MILESTONE_3_NOT_PERMITTED",
)
CLOSURE_KEY = "m2_alias_capacity_artifact_tcb_closure"
CLOSURE_REPORT = IMPLEMENTATION / "M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_REPORT.json"
VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
THIS_MODULE = "tests.test_admissible_paired_runner_m2_alias_capacity_artifact_tcb_closure"
#: The nine modules the delegated qualification of this closure must run.
QUALIFICATION_MODULES = (
    "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
    "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
    "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
    "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
    "tests.test_admissible_paired_runner_m2_ownership_debt_reap_closure",
    "tests.test_admissible_paired_runner_m2_process_owner_cleanup_propagation_closure",
    "tests.test_admissible_paired_runner_m2_cgroup_identity_reap_registry_serialization_closure",
    "tests.test_admissible_paired_runner_m2_exact_removal_global_drain_reservation_provenance_closure",
    THIS_MODULE,
)
#: The delegated transcript of the *starting* commit.  It is history, never a
#: qualification of the revision this closure produces.
PRIOR_DELEGATED_TRANSCRIPT = "Ran 663 tests in 335.480s\n\nOK"
#: The stale sentences the independent audit found in the current state objects.
#: They may appear only inside explicitly historical structures.
STALE_HANDOFF_PHRASES = (
    "is an operator hand-off",
    "this object is not updated to QUALIFIED",
    "must show 652 tests",
)

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


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _await(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def guard_process_wide_unregistered_cleanups(test: unittest.TestCase) -> None:
    """Discharge and restore the process-level registrar-failure collection.

    It is drained before it is restored, from a registered cleanup, so it happens
    whether the test passed or raised.  A failed assertion may report a defect;
    it may not manufacture one for its successor.
    """

    saved = list(rl._UNREGISTERED_CLEANUPS)
    saved_pid = rl._UNREGISTERED_OWNER_PID
    saved_ledger = dict(pw._LAST_DRAIN_LEDGER)

    def restore() -> None:
        try:
            for _attempt in range(4):
                added = [
                    handle
                    for handle in rl.unregistered_cleanups()
                    if all(handle is not existing for existing in saved)
                ]
                if not added:
                    break
                for handle in added:
                    try:
                        handle.settle_cleanup(
                            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "teardown")
                        )
                    except Exception:  # pragma: no cover - the guard masks nothing
                        pass
                    if getattr(handle, "cleanup_complete", False):
                        rl._release_unregistered(handle)
        finally:
            rl._UNREGISTERED_CLEANUPS[:] = saved
            rl._UNREGISTERED_OWNER_PID = saved_pid
            pw._LAST_DRAIN_LEDGER = saved_ledger

    test.addCleanup(restore)


def guard_process_wide_canonical_results(test: unittest.TestCase) -> None:
    """Restore the process-wide published canonical results (M2-B59).

    They are process-wide for the same reason the registry is: a drain whose
    canonical obligation is claimed by another drain reads the terminal result
    that other drain published.  A test that publishes one therefore puts back
    what it found, so it neither discharges another test's alias nor is
    discharged by another test's result.
    """

    saved = dict(pw._CANONICAL_RESULTS)
    saved_generation = pw._CANONICAL_RESULT_GENERATION

    def restore() -> None:
        pw._CANONICAL_RESULTS.clear()
        pw._CANONICAL_RESULTS.update(saved)
        pw._CANONICAL_RESULT_GENERATION = saved_generation

    test.addCleanup(restore)


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
        guard_process_wide_canonical_results(test)

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
    """Make an ordinary directory behave like a cgroup for both ``rmdir`` forms."""

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
    the same production code against a real ``Delegate=yes`` subtree.
    """

    def __init__(self, test: unittest.TestCase) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-b59-alias-"))
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


# --- M2-B59: the shared-resource state machine --------------------------------


class _SharedResource:
    """One underlying resource two obligations can name.

    ``destructive_primitives`` is what makes "settled once" checkable: it counts
    the times a settlement actually destroyed something, not the times one was
    reported.
    """

    def __init__(self, identity: str) -> None:
        self.identity = identity
        self.outstanding = True
        self.destructive_primitives = 0


class _SharedResourceObligation:
    """A retained obligation naming an exact resource identity by construction.

    The exact-identity canonicalisation is about ``dev:ino``, not about cgroups,
    so the state machine is provable without privilege.  The delegated class at
    the end of this module drives the identical production path against two real
    handles for one real cgroup.
    """

    def __init__(
        self,
        name: str,
        resource: _SharedResource,
        *,
        settles: bool = True,
        raises: type[BaseException] | None = None,
        identity_override: str | None = None,
        registration_outstanding: bool = False,
    ) -> None:
        self.name = name
        self.resource = resource
        self.settles = settles
        self.raises = raises
        self.identity_override = identity_override
        #: The M2-B57 shape: the resource is discharged and only the registry
        #: entry the registrar refused is still owed.
        self.registration_outstanding = registration_outstanding
        self._registry_id: str | None = None
        self.attempts = 0
        self.grants: list[int] = []

    @property
    def identity(self) -> str:
        return self.identity_override or self.resource.identity

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict:
        self.attempts += 1
        self.grants.append(0 if deadline is None else int(deadline.remaining_seconds * 1000))
        if self.raises is not None:
            raise self.raises(f"{self.name}: the settlement failed")
        # A settlement that finds the resource already gone destroys nothing,
        # exactly as the production removal does when the owned object is absent.
        if self.settles and self.resource.outstanding:
            self.resource.destructive_primitives += 1
            self.resource.outstanding = False
        return {"name": self.name, "granted_ms": self.grants[-1]}

    def cleanup_evidence(self) -> dict:
        outstanding = self.resource.outstanding
        complete = not outstanding and not self.registration_outstanding
        return {
            "kind": "EFFECT_CGROUP",
            "effect_path": f"/fixture/{self.name}",
            "owned_identity": self.identity,
            "containment_settled": not outstanding,
            "process_obligations_complete": True,
            "resource_outstanding": outstanding,
            "outstanding_work": (
                (rl.OUTSTANDING_CONTAINMENT,)
                if outstanding
                else ((rl.OUTSTANDING_REGISTRATION,) if not complete else (rl.OUTSTANDING_NOTHING,))
            ),
            "cleanup_complete": complete,
            "cleanup_retryable": not complete,
            "cleanup_retry_operation": (
                rl.CGROUP_RETRY_REMOVE
                if outstanding
                else (rl.CGROUP_RETRY_RECORD if not complete else rl.CGROUP_RETRY_NONE)
            ),
            "settlement_attempts": self.attempts,
            "helper_pid": 0,
        }

    def evidence(self) -> dict:
        return self.cleanup_evidence()


class CanonicalResultAliasDischargeTests(unittest.TestCase):
    """An alias is discharged by a published canonical result, or not at all."""

    def setUp(self) -> None:
        _ProcessGuard.install(self)
        patcher = mock.patch.object(pw, "CLEANUP_DRAIN_TOTAL_DEADLINE_MS", 400)
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- construction helpers --

    def group(
        self, identity: str, *, settles: bool = True, raises=None, aliases: int = 1
    ) -> tuple[_SharedResource, list[_SharedResourceObligation]]:
        resource = _SharedResource(identity)
        obligations = [
            _SharedResourceObligation("canonical", resource, settles=settles, raises=raises)
        ]
        for index in range(aliases):
            obligations.append(
                _SharedResourceObligation(f"alias-{index}", resource, settles=settles)
            )
        for handle in obligations:
            self.retain_unregistered(handle)
        return resource, obligations

    def retain_unregistered(self, handle) -> None:
        rl._retain_unregistered(handle)
        self.addCleanup(rl._release_unregistered, handle)

    def register(self, handle) -> None:
        pw._CLEANUP_REGISTRY.record(handle, handle.evidence())

    def drain(self, ms: int = 2_000) -> list[dict]:
        return pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(ms, "alias"))

    @staticmethod
    def split(rows: list[dict]) -> tuple[dict, list[dict]]:
        canonical = [row for row in rows if row["alias_of"] is None]
        aliases = [row for row in rows if row["alias_of"] is not None]
        return canonical[0], aliases

    # -- the state machine --

    def test_a_successful_canonical_discharges_its_aliases_once(self) -> None:
        resource, _ = self.group("11:22", settles=True, aliases=2)
        rows = self.drain()
        canonical, aliases = self.split(rows)
        self.assertEqual(canonical["state"], pw.DRAIN_STATE_ATTEMPTED)
        self.assertFalse(canonical["resource_outstanding"])
        self.assertEqual(len(aliases), 2, rows)
        for alias in aliases:
            with self.subTest(alias=alias["label"]):
                self.assertEqual(alias["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
                self.assertEqual(alias["unattempted_reason"], pw.DRAIN_UNATTEMPTED_ALIAS)
                self.assertFalse(alias["attempted"])
                self.assertEqual(alias["granted_ms"], 0, "an alias spent a second grant")
                self.assertEqual(alias["alias_of"], canonical["label"])
                self.assertTrue(alias["canonical_result"]["proves_discharge"])
        self.assertEqual(resource.destructive_primitives, 1, "the resource was settled twice")

    def test_an_unresolved_canonical_never_discharges_its_alias(self) -> None:
        """The exact row the independent audit reproduced."""

        resource, obligations = self.group("33:44", settles=False, aliases=1)
        rows = self.drain()
        canonical, aliases = self.split(rows)
        self.assertEqual(canonical["state"], pw.DRAIN_STATE_UNRESOLVED)
        self.assertTrue(canonical["attempted"])
        self.assertTrue(canonical["resource_outstanding"])
        self.assertTrue(canonical["retained"])
        alias = aliases[0]
        self.assertNotEqual(
            alias["state"],
            pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
            "an alias was called discharged over a resource that is still outstanding",
        )
        self.assertEqual(alias["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertEqual(
            alias["unattempted_reason"], pw.DRAIN_UNATTEMPTED_CANONICAL_UNRESOLVED
        )
        self.assertTrue(alias["resource_outstanding"])
        self.assertTrue(alias["retained"])
        self.assertFalse(alias["attempted"])
        self.assertEqual(alias["granted_ms"], 0, "an alias spent a second grant")
        self.assertFalse(alias["canonical_result"]["proves_discharge"])
        self.assertTrue(resource.outstanding)
        self.assertEqual(obligations[1].attempts, 0, "the alias ran a settlement")

    def test_an_unattempted_canonical_leaves_its_alias_retained_unattempted(self) -> None:
        resource, obligations = self.group("55:66", settles=True, aliases=1)
        rows = self.drain(ms=0)
        canonical, aliases = self.split(rows)
        self.assertFalse(canonical["attempted"])
        self.assertEqual(canonical["state"], pw.DRAIN_STATE_RETAINED_UNATTEMPTED)
        self.assertEqual(
            canonical["unattempted_reason"], pw.DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED
        )
        alias = aliases[0]
        self.assertEqual(alias["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertFalse(alias["attempted"])
        self.assertTrue(alias["retained"])
        self.assertEqual(alias["granted_ms"], 0)
        self.assertTrue(resource.outstanding)
        self.assertEqual([handle.attempts for handle in obligations], [0, 0])

    def test_a_canonical_that_raises_publishes_no_result_and_discharges_nothing(self) -> None:
        resource, obligations = self.group("77:88", settles=True, raises=RuntimeError, aliases=1)
        with self.assertRaises(RuntimeError):
            self.drain()
        # Nothing was published, so nothing anywhere can discharge this resource.
        self.assertIsNone(
            pw._published_canonical_result("77:88"),
            "a canonical obligation that raised published a discharging result",
        )
        self.assertTrue(resource.outstanding)
        self.assertEqual(obligations[1].attempts, 0, "the alias ran a settlement")
        # The failure is not sticky: with the settlement repaired, the next drain
        # settles the group truthfully.
        obligations[0].raises = None
        canonical, aliases = self.split(self.drain())
        self.assertEqual(canonical["state"], pw.DRAIN_STATE_ATTEMPTED)
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertEqual(resource.destructive_primitives, 1)

    def test_a_canonical_claimed_by_another_drain_discharges_nothing(self) -> None:
        resource = _SharedResource("99:11")
        canonical_handle = _SharedResourceObligation("canonical", resource)
        alias_handle = _SharedResourceObligation("alias", resource)
        self.register(canonical_handle)
        self.retain_unregistered(alias_handle)
        entry = pw._CLEANUP_REGISTRY.pending()[0]
        # Another drain owns it and has published no terminal result.
        entry.claimed_by = threading.get_ident() + 1
        self.addCleanup(setattr, entry, "claimed_by", None)
        rows = self.drain()
        self.assertEqual([row["collection"] for row in rows], ["UNREGISTERED"], rows)
        alias = rows[0]
        self.assertEqual(alias["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertEqual(
            alias["canonical_result"]["unresolved_reason"], pw.CANONICAL_UNPUBLISHED_CLAIMED
        )
        self.assertFalse(alias["canonical_result"]["proves_discharge"])
        self.assertTrue(resource.outstanding)
        self.assertEqual(canonical_handle.attempts, 0)
        self.assertEqual(alias_handle.attempts, 0)

    def test_an_alias_may_discharge_from_a_terminal_result_another_drain_published(self) -> None:
        resource = _SharedResource("12:34")
        first = _SharedResourceObligation("first", resource)
        self.retain_unregistered(first)
        self.split(self.drain())  # publishes the terminal result for 12:34
        published = pw._published_canonical_result("12:34")
        self.assertIsNotNone(published, "the terminal result was not published")
        self.assertTrue(published.proves_discharge_of("12:34"))
        rl._release_unregistered(first)
        # A later drain over the same exact resource whose own canonical is
        # claimed elsewhere: the alias discharges from *that exact* result.  Both
        # still owe the registry entry the registrar refused, which is why they
        # are retained at all; the resource itself is gone.
        canonical_handle = _SharedResourceObligation(
            "canonical", resource, registration_outstanding=True
        )
        alias_handle = _SharedResourceObligation(
            "alias", resource, registration_outstanding=True
        )
        self.register(canonical_handle)
        self.retain_unregistered(alias_handle)
        entry = pw._CLEANUP_REGISTRY.pending()[0]
        entry.claimed_by = threading.get_ident() + 1
        self.addCleanup(setattr, entry, "claimed_by", None)
        rows = self.drain()
        self.assertEqual(len(rows), 1, rows)
        alias = rows[0]
        # M2-B63.  The resource really is discharged, but not by the canonical
        # obligation this drain selected, so the row names the published result
        # that proves it rather than crediting the group's canonical.
        self.assertEqual(alias["state"], pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT)
        self.assertEqual(
            alias["discharge_proof_origin"],
            pw.DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT,
        )
        self.assertEqual(alias["discharge_proof_source_label"], published.label)
        self.assertEqual(alias["discharge_proof_generation"], published.generation)
        self.assertNotEqual(alias["discharge_proof_source_label"], alias["group_canonical_label"])
        self.assertEqual(alias["canonical_result"]["resource_identity"], "12:34")
        self.assertTrue(alias["canonical_result"]["proves_discharge"])
        self.assertEqual(alias["granted_ms"], 0)

    def test_a_published_result_for_a_different_identity_discharges_nothing(self) -> None:
        other = _SharedResource("aa:bb")
        settled = _SharedResourceObligation("other", other)
        self.retain_unregistered(settled)
        self.drain()
        rl._release_unregistered(settled)
        self.assertIsNotNone(pw._published_canonical_result("aa:bb"))
        # A different exact resource, whose own canonical is claimed elsewhere.
        resource = _SharedResource("cc:dd")
        canonical_handle = _SharedResourceObligation("canonical", resource, settles=False)
        alias_handle = _SharedResourceObligation("alias", resource, settles=False)
        self.register(canonical_handle)
        self.retain_unregistered(alias_handle)
        entry = pw._CLEANUP_REGISTRY.pending()[0]
        entry.claimed_by = threading.get_ident() + 1
        self.addCleanup(setattr, entry, "claimed_by", None)
        rows = self.drain()
        self.assertEqual(rows[0]["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertTrue(resource.outstanding)

    def test_one_pathname_with_two_identities_is_not_an_alias_relationship(self) -> None:
        first = _SharedResource("70:1")
        second = _SharedResource("71:1")
        left = _SharedResourceObligation("same-name", first, settles=False)
        right = _SharedResourceObligation("same-name", second, settles=False)
        self.retain_unregistered(left)
        self.retain_unregistered(right)
        rows = self.drain()
        self.assertEqual(
            [row["alias_of"] for row in rows],
            [None, None],
            "two different exact resources under one pathname were merged",
        )
        self.assertEqual(pw.cleanup_drain_ledger()["distinct_resources"], 2)
        self.assertEqual([handle.attempts for handle in (left, right)], [1, 1])

    def test_an_exact_identity_group_spends_exactly_one_grant(self) -> None:
        _, obligations = self.group("13:57", settles=True, aliases=3)
        rows = self.drain()
        granted = [row["granted_ms"] for row in rows]
        self.assertEqual(sum(1 for value in granted if value > 0), 1, granted)
        self.assertEqual(sum(handle.attempts for handle in obligations), 1)

    def test_an_alias_never_runs_a_second_destructive_primitive(self) -> None:
        resource, obligations = self.group("24:68", settles=True, aliases=2)
        self.drain()
        self.assertEqual(resource.destructive_primitives, 1)
        # ...and a repeat drain of the same group runs no further primitive.
        self.drain()
        self.assertEqual(resource.destructive_primitives, 1)
        self.assertTrue(
            all(handle.attempts == 0 for handle in obligations[1:]),
            "an alias ran a settlement of its own",
        )

    def test_repeated_drains_settle_a_previously_unresolved_group(self) -> None:
        resource, obligations = self.group("31:41", settles=False, aliases=1)
        canonical, aliases = self.split(self.drain())
        self.assertEqual(canonical["state"], pw.DRAIN_STATE_UNRESOLVED)
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        for handle in obligations:
            handle.settles = True
        canonical, aliases = self.split(self.drain())
        self.assertEqual(canonical["state"], pw.DRAIN_STATE_ATTEMPTED)
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertFalse(resource.outstanding)
        self.assertEqual(resource.destructive_primitives, 1)
        # Idempotent from there on: a later drain destroys nothing further.
        self.drain()
        self.assertEqual(resource.destructive_primitives, 1)
        self.assertEqual(obligations[1].attempts, 0, "the alias ran a settlement")

    def test_the_ledger_separates_discharged_aliases_from_retained_ones(self) -> None:
        self.group("52:63", settles=False, aliases=2)
        self.drain()
        ledger = pw.cleanup_drain_ledger()
        self.assertEqual(ledger["aliases_identified"], 2)
        self.assertEqual(ledger["aliases_discharged_by_a_canonical_obligation"], 0)
        self.assertEqual(ledger["aliases_retained_pending_canonical"], 2)
        self.assertEqual(len(ledger["canonical_results"]), 1)
        self.assertFalse(ledger["canonical_results"][0]["proves_discharge"])
        self.assertTrue(all(not row["canonical_proved_discharge"] for row in ledger["order"]))

    def test_the_published_result_table_is_bounded_and_evicts_fail_closed(self) -> None:
        for index in range(pw.CANONICAL_RESULT_RETENTION + 8):
            resource = _SharedResource(f"90:{index}")
            handle = _SharedResourceObligation(f"bounded-{index}", resource)
            rl._retain_unregistered(handle)
            try:
                self.drain()
            finally:
                rl._release_unregistered(handle)
        self.assertLessEqual(
            len(pw.published_canonical_results()),
            pw.CANONICAL_RESULT_RETENTION,
            "the process-wide canonical result table grew without limit",
        )
        # Eviction removes the oldest publication, so the newest survive.
        surviving = pw.published_canonical_results()
        self.assertIn(f"90:{pw.CANONICAL_RESULT_RETENTION + 7}", surviving)
        self.assertNotIn("90:0", surviving)
        # ...and an evicted result discharges nothing, which is fail-closed.
        self.assertIsNone(pw._published_canonical_result("90:0"))

    def test_an_obligation_with_no_provable_identity_is_never_an_alias(self) -> None:
        resource = _SharedResource("")
        left = _SharedResourceObligation("anon-a", resource, settles=False, identity_override="")
        right = _SharedResourceObligation("anon-b", resource, settles=False, identity_override="")
        self.retain_unregistered(left)
        self.retain_unregistered(right)
        rows = self.drain()
        self.assertEqual([row["alias_of"] for row in rows], [None, None], rows)
        self.assertTrue(all(row["canonical_for_resource"] is False for row in rows))
        self.assertTrue(all(row["canonical_result"] is None for row in rows))


class DrainRowGuardTests(unittest.TestCase):
    """The row guard refuses every contradictory discharge shape."""

    @staticmethod
    def row(**overrides) -> dict:
        base = {
            "state": pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
            "attempted": False,
            "granted_ms": 0,
            "label": "UNREGISTERED:2",
            "alias_of": "UNREGISTERED:1",
            # M2-B63: the group's canonical obligation, the obligation whose
            # result proves the discharge, and which publication of it was read.
            "group_canonical_label": "UNREGISTERED:1",
            "discharge_proof_source_label": "UNREGISTERED:1",
            "discharge_proof_generation": 1,
            "discharge_proof_origin": pw.DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL,
            "resource_outstanding": False,
            "resource_identity": "1:2",
            "effect_cgroup_path": "/fixture/alias",
        }
        base.update(overrides)
        return base

    @staticmethod
    def result(identity: str = "1:2", *, published: bool = True, outstanding: bool = False,
               state: str = pw.DRAIN_STATE_ATTEMPTED) -> pw._CanonicalResult:
        result = pw._CanonicalResult(
            resource_identity=identity, label="UNREGISTERED:1", generation=1
        )
        if published:
            result.published = True
            result.state = state
            result.resource_outstanding = outstanding
        return result

    def test_the_audited_shape_is_refused(self) -> None:
        """``DISCHARGED_BY_CANONICAL`` over an outstanding resource."""

        with self.assertRaises(pw.DrainEvidenceContradiction) as caught:
            pw._guard_drain_row(
                self.row(resource_outstanding=True), canonical_result=self.result()
            )
        self.assertIn("still outstanding", str(caught.exception))

    def test_a_discharge_with_no_canonical_result_is_refused(self) -> None:
        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(self.row(), canonical_result=None)

    def test_a_discharge_from_an_unpublished_result_is_refused(self) -> None:
        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(self.row(), canonical_result=self.result(published=False))

    def test_a_discharge_from_another_identitys_result_is_refused(self) -> None:
        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(self.row(), canonical_result=self.result(identity="9:9"))

    def test_a_discharge_from_a_result_that_is_itself_outstanding_is_refused(self) -> None:
        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(self.row(), canonical_result=self.result(outstanding=True))

    def test_a_discharge_from_a_nonterminal_canonical_state_is_refused(self) -> None:
        for state in (
            pw.DRAIN_STATE_UNRESOLVED,
            pw.DRAIN_STATE_RETAINED_UNATTEMPTED,
            pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL,
            pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
        ):
            with self.subTest(canonical_state=state):
                with self.assertRaises(pw.DrainEvidenceContradiction):
                    pw._guard_drain_row(
                        self.row(), canonical_result=self.result(state=state)
                    )

    def test_a_coherent_discharge_is_accepted(self) -> None:
        row = pw._guard_drain_row(self.row(), canonical_result=self.result())
        self.assertEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)

    def test_an_alias_waiting_on_its_canonical_may_not_have_spent_a_grant(self) -> None:
        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(
                self.row(
                    state=pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL,
                    resource_outstanding=True,
                    attempted=True,
                    granted_ms=25,
                )
            )

    def test_the_budget_exhaustion_shape_is_still_refused_over_a_discharged_resource(self) -> None:
        with self.assertRaises(pw.DrainEvidenceContradiction):
            pw._guard_drain_row(
                self.row(
                    state=pw.DRAIN_STATE_RETAINED_UNATTEMPTED,
                    alias_of=None,
                    resource_outstanding=False,
                )
            )

    def test_only_terminal_discharge_states_may_prove_a_discharge(self) -> None:
        self.assertEqual(
            set(pw.DRAIN_STATES_PROVING_DISCHARGE),
            {pw.DRAIN_STATE_ATTEMPTED, pw.DRAIN_STATE_RESOURCE_DISCHARGED},
        )
        for state in pw.DRAIN_STATES:
            result = self.result(state=state)
            with self.subTest(state=state):
                self.assertEqual(
                    result.proves_discharge_of("1:2"),
                    state in pw.DRAIN_STATES_PROVING_DISCHARGE,
                )


class RealAliasDischargeTests(_CgroupFixture):
    """Two real handles for one real cgroup, through the production drain."""

    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(pw, "CLEANUP_DRAIN_TOTAL_DEADLINE_MS", 400)
        patcher.start()
        self.addCleanup(patcher.stop)

    def twinned(self, label: str) -> tuple[rl.EffectCgroup, rl.EffectCgroup, Path]:
        """One cgroup named by a registered obligation and an unregistered twin."""

        cgroup = self.cgroup(label)
        path = Path(cgroup.owned_path)
        (path / "cgroup.procs").write_text("515151\n", encoding="utf-8")
        self.assertFalse(cgroup.close())
        self.assertIsNotNone(cgroup.cleanup_registry_id)
        twin = rl.EffectCgroup(
            self.delegation, rl.ResourceBounds.for_timeout(1_000), f"{label}-twin"
        )
        twin._parent_fd = os.dup(cgroup._parent_fd)
        twin._dir_fd = os.dup(cgroup._dir_fd)
        twin._parent_identity = cgroup._parent_identity
        twin._owned_identity = cgroup._owned_identity
        twin._leaf = cgroup._leaf
        twin._path = cgroup._path
        twin._owned_path = cgroup._owned_path
        rl._retain_unregistered(twin)
        self.addCleanup(rl._release_unregistered, twin)
        self.assertEqual(cgroup.owned_identity, twin.owned_identity)
        return cgroup, twin, path

    def test_a_real_unresolved_canonical_leaves_the_cgroup_and_the_alias_retained(self) -> None:
        cgroup, twin, path = self.twinned(f"unresolved-{os.getpid()}")
        removals: list[str] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append(leaf)
            return real(parent_fd, leaf)

        # The cgroup keeps a member, so the canonical removal is truthfully
        # refused and the resource stays outstanding.
        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            rows = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "unresolved"))
        self.assertEqual(removals, [], "a populated cgroup was removed")
        canonical = [row for row in rows if row["alias_of"] is None]
        aliases = [row for row in rows if row["alias_of"] is not None]
        self.assertEqual(len(aliases), 1, rows)
        self.assertTrue(canonical[0]["resource_outstanding"])
        self.assertNotEqual(aliases[0]["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertTrue(aliases[0]["resource_outstanding"])
        self.assertTrue(path.exists(), "the retained cgroup was removed anyway")
        # With the member gone, a fresh budget settles it exactly once and both
        # callers receive coherent final evidence.
        (path / "cgroup.procs").write_text("", encoding="utf-8")
        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            rows = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "settle"))
        self.assertEqual(len(removals), 1, "one cgroup was removed more than once")
        canonical = [row for row in rows if row["alias_of"] is None]
        aliases = [row for row in rows if row["alias_of"] is not None]
        self.assertFalse(canonical[0]["resource_outstanding"])
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertFalse(aliases[0]["resource_outstanding"])
        self.assertFalse(path.exists())
        self.assertTrue(cgroup.removal_settled)
        self.assertTrue(twin.removal_settled)

    def test_a_real_successful_canonical_settles_the_cgroup_once(self) -> None:
        cgroup, twin, path = self.twinned(f"settled-{os.getpid()}")
        (path / "cgroup.procs").write_text("", encoding="utf-8")
        removals: list[str] = []
        real = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            removals.append(leaf)
            return real(parent_fd, leaf)

        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            rows = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "settled"))
        self.assertEqual(len(removals), 1)
        aliases = [row for row in rows if row["alias_of"] is not None]
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertTrue(aliases[0]["canonical_result"]["proves_discharge"])
        self.assertFalse(path.exists())
        self.assertEqual(pw.cleanup_drain_ledger()["distinct_resources"], 1)
        self.assertIsNotNone(twin.owned_identity)


# --- M2-B60: one combined capacity ---------------------------------------------


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


class CombinedCapacityTests(unittest.TestCase):
    """``len(entries) + len(reservations) <= capacity`` at every visible state."""

    CAPACITY = 4

    def setUp(self) -> None:
        _ProcessGuard.install(self)
        patcher = mock.patch.object(pw, "CLEANUP_REGISTRY_CAPACITY", self.CAPACITY)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.registry = pw._IncompleteCleanupRegistry()

    def held(self) -> int:
        evidence = self.registry.evidence()
        return evidence["held"]

    def direct(self, name: str = "direct") -> str | None:
        handle = _RegistryObligation(name)
        return self.registry.record(handle, handle.evidence())

    def entry(self, name: str) -> _RegistryObligation:
        reservation = self.registry.reserve(name)
        handle = _RegistryObligation(name)
        self.registry.record(handle, handle.evidence(), reservation=reservation)
        return handle

    def terminate(self, handle: _RegistryObligation) -> None:
        """Remove an entry the only way the registry removes one: it completed."""

        self.registry.record(handle, {**handle.evidence(), "cleanup_complete": True})

    def test_capacity_reservations_refuse_one_direct_record(self) -> None:
        reservations = [self.registry.reserve(f"r{index}") for index in range(self.CAPACITY)]
        self.assertEqual(self.held(), self.CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated) as caught:
            self.direct()
        self.assertIn("outstanding reservations", str(caught.exception))
        self.assertEqual(self.held(), self.CAPACITY)
        self.assertEqual(len(reservations), self.CAPACITY)

    def test_the_audited_capacity_one_reproduction_is_refused(self) -> None:
        with mock.patch.object(pw, "CLEANUP_REGISTRY_CAPACITY", 1):
            registry = pw._IncompleteCleanupRegistry()
            registry.reserve("only")
            with self.assertRaises(CleanupRegistrySaturated):
                handle = _RegistryObligation("direct")
                registry.record(handle, handle.evidence())
            evidence = registry.evidence()
            self.assertEqual(evidence["reserved"], 1)
            self.assertEqual(evidence["retained"], 0)
            self.assertEqual(evidence["held"], 1)
            self.assertLessEqual(evidence["held"], evidence["capacity"])

    def test_a_mixed_held_count_refuses_one_direct_record(self) -> None:
        self.entry("entry")
        reservations = [
            self.registry.reserve(f"r{index}") for index in range(self.CAPACITY - 1)
        ]
        self.assertEqual(self.held(), self.CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct()
        evidence = self.registry.evidence()
        self.assertEqual(evidence["retained"], 1)
        self.assertEqual(evidence["reserved"], len(reservations))
        self.assertEqual(evidence["held"], self.CAPACITY)

    def test_a_refusal_mutates_nothing(self) -> None:
        self.entry("entry")
        for index in range(self.CAPACITY - 1):
            self.registry.reserve(f"r{index}")
        before = self.registry.evidence()
        handle = _RegistryObligation("refused")
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.record(handle, handle.evidence())
        after = self.registry.evidence()
        self.assertEqual(before["held"], after["held"])
        self.assertEqual(before["retained"], after["retained"])
        self.assertEqual(before["reserved"], after["reserved"])
        self.assertEqual(
            [row["reservation_id"] for row in before["reservations"]],
            [row["reservation_id"] for row in after["reservations"]],
        )
        self.assertEqual(
            [row["state"] for row in before["reservations"]],
            [row["state"] for row in after["reservations"]],
        )
        self.assertEqual(
            [row["entry_id"] for row in before["entries"]],
            [row["entry_id"] for row in after["entries"]],
        )
        self.assertIsNone(handle._registry_id, "a refused handle was given an entry id")
        # The refusal itself consumes no capacity and leaves the counters alone.
        self.assertEqual(self.registry._counter, before["retained"])

    def test_one_unit_of_combined_headroom_admits_exactly_one_winner(self) -> None:
        for index in range(self.CAPACITY - 1):
            self.registry.reserve(f"r{index}")
        self.assertEqual(self.held(), self.CAPACITY - 1)
        start = threading.Barrier(6)
        accepted: list[str] = []
        refused: list[str] = []
        lock = threading.Lock()

        def attempt(index: int) -> None:
            start.wait()
            handle = _RegistryObligation(f"racer-{index}")
            try:
                entry_id = self.registry.record(handle, handle.evidence())
            except CleanupRegistrySaturated:
                with lock:
                    refused.append(f"racer-{index}")
                return
            with lock:
                accepted.append(entry_id)

        threads = [threading.Thread(target=attempt, args=(index,)) for index in range(5)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(timeout=20)
            self.assertFalse(thread.is_alive(), "a racing insertion never finished")
        self.assertEqual(len(accepted), 1, (accepted, refused))
        self.assertEqual(len(refused), 4, (accepted, refused))
        self.assertEqual(self.held(), self.CAPACITY)

    def test_concurrent_reservations_and_direct_records_never_exceed_capacity(self) -> None:
        observed: list[int] = []
        stop = threading.Event()
        lock = threading.Lock()

        def sampler() -> None:
            while not stop.is_set():
                evidence = self.registry.evidence()
                with lock:
                    observed.append(evidence["held"])
                time.sleep(0.001)

        def worker(index: int) -> None:
            for _round in range(40):
                if index % 2 == 0:
                    try:
                        reservation = self.registry.reserve(f"w{index}")
                    except CleanupRegistrySaturated:
                        continue
                    self.registry._release_reservation(reservation)
                else:
                    handle = _RegistryObligation(f"w{index}")
                    try:
                        entry_id = self.registry.record(handle, handle.evidence())
                    except CleanupRegistrySaturated:
                        continue
                    if entry_id is not None:
                        self.registry.record(
                            handle, {**handle.evidence(), "cleanup_complete": True}
                        )

        watcher = threading.Thread(target=sampler)
        watcher.start()
        threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "a stress worker never finished")
        stop.set()
        watcher.join(timeout=10)
        self.assertTrue(observed, "the sampler observed nothing")
        self.assertLessEqual(max(observed), self.CAPACITY, "held exceeded the capacity")
        self.assertGreaterEqual(min(observed), 0)

    def test_a_direct_record_succeeds_after_an_exact_reservation_is_released(self) -> None:
        reservations = [self.registry.reserve(f"r{index}") for index in range(self.CAPACITY)]
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct()
        self.assertTrue(self.registry._release_reservation(reservations[1]))
        entry_id = self.direct("after-release")
        self.assertIsNotNone(entry_id)
        self.assertEqual(self.held(), self.CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct("one-too-many")

    def test_a_direct_record_succeeds_after_an_entry_is_terminally_removed(self) -> None:
        handles = [self.entry(f"entry-{index}") for index in range(self.CAPACITY)]
        self.assertEqual(self.held(), self.CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct()
        self.terminate(handles[0])
        self.assertEqual(self.held(), self.CAPACITY - 1)
        self.assertIsNotNone(self.direct("after-removal"))
        self.assertEqual(self.held(), self.CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct("one-too-many")

    def test_a_pid_generation_reset_cannot_bypass_or_negate_the_bound(self) -> None:
        for index in range(self.CAPACITY - 1):
            self.registry.reserve(f"r{index}")
        self.entry("entry")
        self.assertEqual(self.held(), self.CAPACITY)
        # A forked child inherits this memory and owns none of it.
        self.registry._owner_pid = os.getpid() + 1
        evidence = self.registry.evidence()
        self.assertEqual(evidence["held"], 0)
        self.assertGreaterEqual(evidence["held"], 0)
        self.assertEqual(evidence["owner_pid"], os.getpid())
        for index in range(self.CAPACITY):
            self.assertIsNotNone(self.direct(f"child-{index}"))
        self.assertEqual(self.held(), self.CAPACITY)
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct("child-overflow")

    def test_the_reservation_conversion_path_is_unchanged(self) -> None:
        reservation = self.registry.reserve("converted")
        handle = _RegistryObligation("converted")
        entry_id = self.registry.record(handle, handle.evidence(), reservation=reservation)
        self.assertIsNotNone(entry_id)
        self.assertEqual(reservation.state, pw.RESERVATION_CONSUMED)
        self.assertEqual(reservation.converted_to, entry_id)
        evidence = self.registry.evidence()
        self.assertEqual(evidence["retained"], 1)
        self.assertEqual(evidence["reserved"], 0)
        self.assertEqual(evidence["held"], 1)

    def test_every_capacity_gate_reads_the_same_combined_count(self) -> None:
        for index in range(self.CAPACITY - 1):
            self.registry.reserve(f"r{index}")
        self.entry("entry")
        self.assertTrue(self.registry.saturated())
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.require_capacity()
        with self.assertRaises(CleanupRegistrySaturated):
            self.registry.reserve("one-more")
        with self.assertRaises(CleanupRegistrySaturated):
            self.direct()

    def test_the_production_registrar_refuses_a_direct_record_at_combined_capacity(self) -> None:
        pw._CLEANUP_REGISTRY.reserve("production")
        with mock.patch.object(pw, "CLEANUP_REGISTRY_CAPACITY", 1):
            handle = _RegistryObligation("production-direct")
            with self.assertRaises(CleanupRegistrySaturated):
                pw._record_cleanup(handle, handle.evidence())
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0)
        self.assertEqual(evidence["reserved"], 1)


# --- M2-M62: the declared mutation TCB covers the code -------------------------


class ProbeCreationMutationBoundaryTests(unittest.TestCase):
    """Probe creation is a controller-owned mutation and takes the boundary."""

    def setUp(self) -> None:
        _ProcessGuard.install(self)
        guard_process_wide_cgroup_caches(self)
        self.fake = _FakeEffectParent(self)
        self.parent = self.fake.parent
        self.domain = self.fake.domain()
        self.probe = self.parent / f"{rl.PROBE_PREFIX}{os.getpid()}"

    def create(self, probe: Path | None = None) -> dict:
        return rl._create_probe_inside_boundary(probe or self.probe, self.parent)

    def test_probe_creation_enters_the_exact_parent_mutation_boundary(self) -> None:
        held: list[bool] = []
        real = _cgroupfs_mkdir

        def recording(self_path, *args, **kwargs):
            held.append(rl.cgroup_mutation_boundary_held(self.domain))
            return real(self_path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", recording):
            outcome = self.create()
        self.assertIsNone(outcome["code"], outcome)
        self.assertEqual(held, [True], "the probe mkdir ran outside the parent boundary")
        self.assertEqual(outcome["mutation_boundary"], self.domain)
        self.assertTrue(outcome["boundary_held"])
        self.assertEqual(outcome["probe_identity"], rl._directory_identity(self.probe))
        self.assertTrue(self.probe.is_dir())

    def test_the_boundary_is_released_before_the_call_returns(self) -> None:
        outcome = self.create()
        self.assertIsNone(outcome["code"], outcome)
        self.assertFalse(rl.cgroup_mutation_boundary_held(self.domain))
        self.assertEqual(
            rl.cgroup_mutation_domains_evidence()["held_by_this_thread"], []
        )

    def test_a_parent_with_no_readable_identity_refuses_rather_than_creating(self) -> None:
        missing = self.parent / "absent"
        probe = missing / f"{rl.PROBE_PREFIX}{os.getpid()}"
        outcome = rl._create_probe_inside_boundary(probe, missing)
        self.assertEqual(outcome["code"], rl.TOPOLOGY_EFFECT_CREATE_FAILED)
        self.assertIn("mutation boundary", outcome["detail"])
        self.assertIsNone(outcome["mutation_boundary"])
        self.assertFalse(probe.exists(), "a probe was created outside the declared TCB")

    def test_a_collision_is_refused_inside_the_boundary_without_adopting_it(self) -> None:
        _REAL_MKDIR(self.probe, mode=0o700)
        outcome = self.create()
        self.assertEqual(outcome["code"], rl.TOPOLOGY_EFFECT_COLLISION)
        self.assertTrue(self.probe.is_dir(), "the colliding object was destroyed")
        self.assertFalse(rl.cgroup_mutation_boundary_held(self.domain))

    def test_a_creation_whose_identity_cannot_be_read_is_rolled_back(self) -> None:
        held_during_rollback: list[bool] = []
        real_rmdir = Path.rmdir

        def recording_rmdir(self_path):
            held_during_rollback.append(rl.cgroup_mutation_boundary_held(self.domain))
            return real_rmdir(self_path)

        with mock.patch.object(rl, "_directory_identity", lambda path: None):
            with mock.patch.object(Path, "rmdir", recording_rmdir):
                outcome = self.create()
        self.assertEqual(outcome["code"], rl.TOPOLOGY_EFFECT_CREATE_FAILED)
        self.assertIn("rolled back", outcome["detail"])
        self.assertEqual(
            held_during_rollback, [True], "the rollback left the declared boundary"
        )
        self.assertFalse(self.probe.exists(), "a partial creation survived")

    def test_a_parent_replaced_before_the_boundary_is_entered_refuses(self) -> None:
        calls: list[int] = []
        real = rl.cgroup_mutation_domain_of

        def shifting(path):
            calls.append(1)
            # The first read keys the boundary; the second, inside it, is the
            # proof -- and it reports a different object.
            return real(path) if len(calls) == 1 else "0:0"

        with mock.patch.object(rl, "cgroup_mutation_domain_of", shifting):
            outcome = self.create()
        self.assertEqual(outcome["code"], rl.TOPOLOGY_EFFECT_CREATE_FAILED)
        self.assertIn("replaced", outcome["detail"])
        self.assertFalse(self.probe.exists(), "a probe was created under an unproved parent")

    def test_a_concurrent_effect_creation_cannot_interleave_with_probe_creation(self) -> None:
        """Both are controller-owned creations under one parent, so both serialize."""

        inside = threading.Event()
        release = threading.Event()
        observed: list[str] = []

        def holder() -> None:
            with rl.cgroup_mutation_boundary(self.domain):
                observed.append("holder-in")
                inside.set()
                release.wait(10)
                observed.append("holder-out")

        thread = threading.Thread(target=holder)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.assertTrue(inside.wait(10), "the holder never entered the boundary")
        creator = threading.Thread(target=lambda: (self.create(), observed.append("probe")))
        creator.start()
        self.addCleanup(creator.join, 10)
        # The probe creation is blocked for as long as the boundary is held.
        self.assertFalse(
            _await(lambda: "probe" in observed, 0.5),
            "probe creation ran while the parent boundary was held elsewhere",
        )
        release.set()
        thread.join(timeout=10)
        creator.join(timeout=10)
        self.assertEqual(observed, ["holder-in", "holder-out", "probe"])
        self.assertTrue(self.probe.is_dir())

    def test_a_real_effect_creation_and_a_probe_creation_serialize_without_deadlock(self) -> None:
        """Two controller-owned creations under one parent, both taking the boundary."""

        _ProcessGuard.install(self)
        delegation = self.fake.delegation()
        entered: list[str] = []
        lock = threading.Lock()
        real = _cgroupfs_mkdir

        def recording(self_path, *args, **kwargs):
            # Every controller-owned child creation under this parent must hold
            # the parent's boundary at the instant it creates the directory.
            if self_path.parent == self.parent:
                with lock:
                    entered.append(
                        f"{self_path.name}:{rl.cgroup_mutation_boundary_held(self.domain)}"
                    )
            return real(self_path, *args, **kwargs)

        outcomes: list[object] = []
        start = threading.Barrier(2)

        def make_effect() -> None:
            start.wait()
            cgroup = rl.EffectCgroup(
                delegation, rl.ResourceBounds.for_timeout(1_000), f"m62-{os.getpid()}"
            )
            created = cgroup.create()
            with lock:
                outcomes.append(("effect", created, cgroup.create_error))
            self.addCleanup(cgroup.close)

        def make_probe() -> None:
            start.wait()
            outcome = self.create()
            with lock:
                outcomes.append(("probe", outcome["code"] is None, outcome["code"]))

        with mock.patch.object(Path, "mkdir", recording):
            threads = [threading.Thread(target=make_effect), threading.Thread(target=make_probe)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
                self.assertFalse(thread.is_alive(), "a concurrent creation deadlocked")
        self.assertEqual(len(outcomes), 2, outcomes)
        self.assertTrue(all(row[1] for row in outcomes), outcomes)
        self.assertTrue(entered, "no controller-owned creation was observed")
        for record in entered:
            with self.subTest(created=record):
                self.assertTrue(
                    record.endswith(":True"),
                    f"{record} created a child outside the parent mutation boundary",
                )
        # Disjoint namespaces: the two creations can never contend for one name.
        self.assertTrue(self.probe.is_dir())
        self.assertEqual(len(_effect_cgroups(self.parent)), 1)

    def test_probe_creation_and_probe_removal_do_not_deadlock(self) -> None:
        outcome = self.create()
        self.assertIsNone(outcome["code"], outcome)
        finished = threading.Event()

        def teardown() -> None:
            rl._remove_owned_probe(self.probe)
            finished.set()

        thread = threading.Thread(target=teardown)
        thread.start()
        thread.join(timeout=15)
        self.assertTrue(finished.is_set(), "probe creation and removal deadlocked")
        self.assertFalse(self.probe.exists())

    def test_two_concurrent_probe_creations_yield_one_creation_and_one_collision(self) -> None:
        start = threading.Barrier(2)
        outcomes: list[dict] = []
        lock = threading.Lock()

        def attempt() -> None:
            start.wait()
            outcome = self.create()
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive(), "a concurrent probe creation never finished")
        codes = sorted(str(outcome["code"]) for outcome in outcomes)
        self.assertEqual(codes, [rl.TOPOLOGY_EFFECT_COLLISION, "None"])
        self.assertTrue(self.probe.is_dir())

    def test_the_controller_owned_child_namespaces_cannot_collide(self) -> None:
        prefixes = rl.CONTROLLER_OWNED_CHILD_PREFIXES
        self.assertEqual(
            set(prefixes),
            {rl.MANAGER_LEAF_PREFIX, rl.EFFECT_PREFIX, rl.PROBE_PREFIX},
        )
        for left in prefixes:
            for right in prefixes:
                if left is right:
                    continue
                with self.subTest(left=left, right=right):
                    self.assertFalse(
                        left.startswith(right) or right.startswith(left),
                        f"{left!r} and {right!r} can name the same child",
                    )

    def test_the_declared_tcb_matches_the_serialized_call_sites(self) -> None:
        source = (
            REPOSITORY_ROOT / "admissible" / "paired_runner" / "resource_limits.py"
        ).read_text(encoding="utf-8")
        self.assertIn("create", rl.CGROUP_MUTATION_TCB["serialized_operations"])
        # Every controller-owned child creation reaches a boundary.  The probe's
        # is the one this closure moved inside it.
        self.assertIn("with cgroup_mutation_boundary(domain):", source)
        self.assertIn("with cgroup_mutation_boundary(parent_identity):", source)
        creation = source.split("def _create_probe_inside_boundary")[1].split("\ndef ")[0]
        self.assertIn("with cgroup_mutation_boundary(domain):", creation)
        self.assertIn("probe.mkdir(mode=0o700)", creation)
        # ...and nothing else in the module creates the probe.
        self.assertEqual(source.count("probe.mkdir("), 1)

    def test_the_declared_boundary_does_not_claim_hostile_host_atomicity(self) -> None:
        tcb = rl.CGROUP_MUTATION_TCB
        self.assertFalse(tcb["atomicity_claimed_against_a_hostile_host"])
        self.assertFalse(tcb["remove_by_handle_available"])
        self.assertIn("outside this controller's trusted computing base", tcb["does_not_exclude"])
        evidence = rl.cgroup_mutation_domains_evidence()
        self.assertEqual(evidence["trusted_computing_base"], dict(tcb))

    def test_the_delegation_evidence_carries_what_the_creation_actually_held(self) -> None:
        outcome = self.create()
        delegation = rl.CgroupDelegation(
            available=True,
            detail="constructed",
            unified_root=str(self.fake.root),
            delegated_path=str(self.parent),
            controllers=("memory", "pids"),
            code=rl.TOPOLOGY_INITIALIZED,
            probe_creation=outcome,
        )
        published = delegation.to_dict()["probe_creation"]
        self.assertEqual(published["mutation_boundary"], self.domain)
        self.assertTrue(published["boundary_held"])
        self.assertIsNotNone(published["probe_identity"])


# --- production wiring ---------------------------------------------------------


class ProductionWiringTests(unittest.TestCase):
    """The production code carries the closures, not just the tests."""

    def setUp(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        self.private_workspace = (package / "private_workspace.py").read_text(encoding="utf-8")
        self.resource_limits = (package / "resource_limits.py").read_text(encoding="utf-8")

    def test_the_alias_classifier_consults_a_canonical_result(self) -> None:
        body = self.private_workspace.split("def _classify_drain_row")[1].split("\ndef ")[0]
        self.assertIn("canonical_result.proves_discharge_of(resource_identity)", body)
        self.assertIn("DRAIN_STATE_RETAINED_PENDING_CANONICAL", body)

    def test_the_direct_insertion_uses_the_combined_held_count(self) -> None:
        body = self.private_workspace.split("    def record(")[1].split("\n    def ")[0]
        self.assertIn(
            "if reservation is None and self._held_locked() >= CLEANUP_REGISTRY_CAPACITY:", body
        )
        self.assertNotIn("len(self._entries) >= CLEANUP_REGISTRY_CAPACITY", body)

    def test_the_registry_capacity_check_is_inside_the_lock(self) -> None:
        body = self.private_workspace.split("    def record(")[1].split("\n    def ")[0]
        guard = body.index("if reservation is None and self._held_locked()")
        self.assertLess(body.index("with self._lock:"), guard)
        # ...and before anything the insertion mutates.
        for mutation in ("self._counter += 1", "self._generation += 1", "self._entries[entry_id]"):
            with self.subTest(mutation=mutation):
                self.assertLess(guard, body.index(mutation))

    def test_the_probe_creation_is_wired_through_the_boundary_helper(self) -> None:
        body = self.resource_limits.split("def probe_cgroup_delegation")[1].split("\ndef ")[0]
        self.assertIn("_create_probe_inside_boundary(probe, parent)", body)
        self.assertNotIn("probe.mkdir", body)

    def test_the_drain_publishes_one_canonical_result_per_exact_resource(self) -> None:
        body = self.private_workspace.split("def _drain_within")[1].split("\ndef ")[0]
        self.assertIn("result.publish(row)", body)
        self.assertIn("_publish_canonical_result(result)", body)
        self.assertIn("CANONICAL_UNPUBLISHED_CLAIMED", body)
        self.assertIn("CANONICAL_UNPUBLISHED_THREW", body)


# --- M2-M61: the current artifacts are semantically coherent -------------------


def _accompanying_validation_report(key: str) -> dict:
    """The validation report that was current when ``key``'s closure was.

    The M2 model keeps exactly one current validation report and a later pass
    moves it.  Assertions about *this* closure follow the report that
    accompanied it: the live report names the commit whose blob it superseded,
    that blob is loaded from git, and its hash is checked against the one the
    live report records.
    """

    report = _load(VALIDATION_REPORT)
    seen: set = set()
    while report.get("current_closure_key") != key:
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


class ClosureArtifactCoherenceTests(unittest.TestCase):
    """The current artifacts describe this code, this run, and nothing stronger."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.closure = _load(CLOSURE_REPORT)
        # These assertions are about *this* closure, so they follow the report
        # that accompanied it rather than whatever is current later; anchoring to
        # the live report would make this class assert another pass's claims.
        cls.validation = _accompanying_validation_report(CLOSURE_KEY)
        cls.live = _load(VALIDATION_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)
        cls.current_run = cls.validation["canonical_current_run"]
        cls.delegated_run = cls.current_run["delegated_physical"]

    # -- identity of the pass --

    def test_the_report_names_only_this_pass_and_its_starting_point(self) -> None:
        self.assertEqual(self.closure["branch"], BRANCH)
        self.assertEqual(self.closure["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.closure["starting_commit_parent"], STARTING_COMMIT_PARENT)
        self.assertEqual(self.closure["sole_parent_required"], STARTING_COMMIT)
        self.assertEqual(
            sorted(self.closure["findings"]), ["M2-B59", "M2-B60", "M2-M61", "M2-M62"]
        )
        for finding in self.closure["finding_details"]:
            with self.subTest(finding=finding["finding"]):
                self.assertEqual(finding["status"], "IMPLEMENTED")
                self.assertTrue(finding["reproduction"])
                self.assertTrue(finding["closure"])
                self.assertTrue(finding["evidence"])
                self.assertTrue(finding["refusal_condition"])
        self.assertNotIn("ending_commit", self.closure)

    def test_the_independent_refusal_is_recorded_verbatim(self) -> None:
        for document, name in ((self.closure, "closure"), (self.validation, "validation")):
            with self.subTest(document=name):
                self.assertEqual(document["independent_audit_sha256"], INDEPENDENT_AUDIT_SHA256)
                self.assertEqual(
                    tuple(document["independent_audit_verdicts"]), INDEPENDENT_AUDIT_VERDICTS
                )

    def test_nothing_claims_acceptance_installation_or_milestone_three(self) -> None:
        for document, name in ((self.closure, "closure"), (self.validation, "validation")):
            with self.subTest(document=name):
                self.assertFalse(document["independent_acceptance_claimed"])
                self.assertFalse(document["installed_path_qualification_claimed"])
                for boundary, crossed in document["boundary_audit"].items():
                    self.assertFalse(crossed, f"{name}:{boundary}")
        self.assertFalse(self.closure["milestone_3_permitted"])
        self.assertEqual(self.closure["milestone_3_status"], "NOT_PERMITTED_AND_NOT_STARTED")

    def test_exactly_one_validation_state_declares_itself_current(self) -> None:
        """Whether or not that is still this closure's."""

        self.assertTrue(self.live["is_current_validation_report"])
        current = [
            path
            for path in IMPLEMENTATION.glob("M2_VALIDATION_REPORT*.json")
            if _load(path).get("is_current_validation_report")
        ]
        self.assertEqual([path.name for path in current], ["M2_VALIDATION_REPORT.json"])
        self.assertEqual(self.validation["current_closure_key"], CLOSURE_KEY)
        self.assertIn(CLOSURE_KEY, self.validation)
        if self.live != self.validation:
            # A later pass moved it, and must record this closure as superseded
            # rather than simply forgetting it.
            self.assertIn(
                "implementation/M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_REPORT.json",
                self.live["superseded_closure_reports"],
                "the later current report does not record this closure as superseded",
            )
            self.assertNotEqual(self.live["current_closure_key"], CLOSURE_KEY)

    def test_the_two_current_reports_carry_one_canonical_run(self) -> None:
        self.assertEqual(self.closure["canonical_current_run"], self.current_run)
        self.assertEqual(self.validation["branch"], self.closure["branch"])
        self.assertEqual(self.validation["starting_commit"], self.closure["starting_commit"])
        self.assertEqual(self.validation["terminal_verdict"], self.closure["terminal_verdict"])
        self.assertEqual(
            self.validation["final_repair_report"],
            "implementation/M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_REPORT.json",
        )

    # -- M2-M61: semantic implications, not byte equality --

    def test_the_current_run_nodes_agree_on_one_status(self) -> None:
        statuses = {name: node["status"] for node, name in self._current_run_nodes()}
        self.assertEqual(
            len(set(statuses.values())), 1, f"the current objects disagree: {statuses}"
        )

    def test_a_physically_verified_status_implies_an_integer_executed_total(self) -> None:
        for node, name in self._current_run_nodes():
            with self.subTest(node=name):
                if node.get("status") != "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
                    continue
                self.assertIsInstance(node["executed"], int, name)
                self.assertEqual(node["executed"], node["expected_total"], name)
                self.assertEqual(node["skipped"], 0, name)
                self.assertEqual(node["failures"], 0, name)
                self.assertEqual(node["errors"], 0, name)
                self.assertEqual(node["result"], "OK", name)

    def test_a_physically_verified_object_never_says_execution_is_pending(self) -> None:
        for node, name in self._current_run_nodes():
            with self.subTest(node=name):
                if node.get("status") != "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
                    continue
                text = json.dumps(node)
                for phrase in STALE_HANDOFF_PHRASES:
                    self.assertNotIn(phrase, text, f"{name} still says {phrase!r}")
                for phrase in ("operator hand-off", "has not been performed", "pending"):
                    self.assertNotIn(phrase, text, f"{name} still says {phrase!r}")

    def test_no_stale_expected_count_appears_in_a_current_state_detail(self) -> None:
        for node, name in self._current_run_nodes():
            with self.subTest(node=name):
                detail = json.dumps(node)
                self.assertNotIn("652", detail, f"{name} carries a superseded expected count")

    def test_the_physical_qualification_state_is_internally_coherent(self) -> None:
        """Either a complete transcript, or an explicit absence.  Never both."""

        run = self.delegated_run
        self.assertIn(
            run["status"],
            {"OPERATOR_QUALIFICATION_REQUIRED", "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2"},
        )
        claimed = self.validation["independent_validation"][
            "real_delegated_cgroup_qualification_of_this_repair"
        ]
        if run["status"] != "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
            self.assertFalse(claimed, "a physical qualification is claimed with no transcript")
            self.assertFalse(run["transcript_available"])
            self.assertIsNone(run["executed"])
            self.assertIsNone(run["transcript_sha256"])
            return
        self.assertTrue(claimed)
        self.assertTrue(run["transcript_available"])
        self.assertEqual(
            hashlib.sha256(run["transcript"].encode("utf-8")).hexdigest(),
            run["transcript_sha256"],
        )
        self.assertEqual(run["transcript"], run["exact_result"])
        self.assertIn(f"Ran {run['executed']} tests", run["exact_result"])
        self.assertTrue(run["exact_result"].endswith("OK"))
        self.assertEqual(run["executed"], run["expected_total"])
        self.assertEqual(
            run["performed_by"],
            "the implementing agent, non-interactively, through the restricted delegated "
            "qualification wrapper /usr/local/sbin/admissible-m2-alias-capacity-qualify full",
        )
        self.assertFalse(run["operator_hand_off"])
        self.assertTrue(run["executed_non_interactively"])

    def test_the_declared_qualification_modules_are_the_nine_on_disk(self) -> None:
        run = self.delegated_run
        self.assertEqual(tuple(run["expected_modules"]), QUALIFICATION_MODULES)
        self.assertEqual(len(run["expected_modules"]), 9)
        self.assertEqual(run["expected_skips"], 0)
        for module in run["expected_modules"]:
            with self.subTest(module=module):
                path = REPOSITORY_ROOT / f"{module.replace('.', '/')}.py"
                self.assertTrue(path.is_file(), f"{module} is declared but is not on disk")

    def test_the_expected_delegated_total_matches_the_modules_as_they_stand(self) -> None:
        run = self.delegated_run
        expected = sum(
            unittest.defaultTestLoader.loadTestsFromName(module).countTestCases()
            for module in run["expected_modules"]
        )
        self.assertEqual(run["expected_total"], expected)
        if run["executed"] is not None:
            self.assertEqual(run["executed"], expected)
        self.assertEqual(sum(run["module_totals"].values()), expected)
        for module, total in run["module_totals"].items():
            with self.subTest(module=module):
                self.assertEqual(
                    unittest.defaultTestLoader.loadTestsFromName(module).countTestCases(),
                    total,
                )

    def test_only_historical_nodes_may_describe_a_superseded_run(self) -> None:
        historical_transcripts = [
            record.get("exact_result")
            for record in self.current_run["historical_delegated_qualifications"]
        ]
        historical_transcripts.append(
            self.validation["prior_physical_qualification"]["transcript"]
        )
        # The superseded transcript is preserved -- in history, and only there.
        self.assertIn(PRIOR_DELEGATED_TRANSCRIPT, historical_transcripts)
        self.assertNotEqual(self.delegated_run["transcript"], PRIOR_DELEGATED_TRANSCRIPT)
        self.assertEqual(self.current_run["failed_delegated_qualifications"], [])
        prior = self.validation["prior_physical_qualification"]
        self.assertEqual(prior["qualified_commit"], STARTING_COMMIT)
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertEqual(prior["transcript"], PRIOR_DELEGATED_TRANSCRIPT)
        for record in self.current_run["historical_delegated_qualifications"]:
            with self.subTest(record=record.get("run_id")):
                self.assertTrue(record["historical"])
                self.assertFalse(record["qualifies_this_revision"])

    def test_both_current_reports_and_the_matrix_agree_on_verdict_and_counts(self) -> None:
        # The verdict follows the physical qualification state rather than
        # standing ahead of it: VERIFIED only once the transcript exists.
        if self.delegated_run["status"] == "PHYSICALLY_VERIFIED_ON_DELEGATED_CGROUP_V2":
            self.assertEqual(
                self.validation["terminal_verdict"],
                "M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_VERIFIED",
            )
        else:
            self.assertEqual(
                self.validation["terminal_verdict"],
                "M2_ALIAS_CAPACITY_ARTIFACT_TCB_OPERATOR_QUALIFICATION_REQUIRED",
            )
        note = self.matrix[f"{CLOSURE_KEY}_note"]
        for finding in ("M2-B59", "M2-B60", "M2-M61", "M2-M62"):
            self.assertIn(finding, note)
        self.assertIn("M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_REPORT.json", note)
        self.assertEqual(self.matrix["requirement_count"], len(self.matrix["requirements"]))
        self.assertEqual(
            self.closure["module_tests_total"],
            unittest.TestLoader().loadTestsFromModule(sys.modules[__name__]).countTestCases(),
        )
        self.assertEqual(
            self.closure["deterministic_tests"] + self.closure["delegated_tests"],
            self.closure["module_tests_total"],
        )

    def test_the_live_discovery_counts_match_the_files_on_disk(self) -> None:
        counts = self.validation["test_counts"]["per_module"]
        for name in counts:
            with self.subTest(module=name):
                self.assertTrue(
                    (REPOSITORY_ROOT / "tests" / f"{name}.py").is_file(),
                    f"{name} is counted but is not a file on disk",
                )
        this_module = THIS_MODULE.split(".", 1)[1]
        live = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__]).countTestCases()
        self.assertEqual(counts[this_module], live, "this module's declared count is stale")
        m1 = sum(value for name, value in counts.items() if "_m1" in name)
        m2 = sum(value for name, value in counts.items() if "_m2" in name)
        self.assertEqual(m1, self.validation["test_counts"]["m1_tests"])
        self.assertEqual(m2, self.validation["test_counts"]["m2_tests"])
        self.assertEqual(m1 + m2, self.validation["test_counts"]["discovered_total"])
        self.assertEqual(
            self.validation["test_counts"]["total"],
            self.validation["test_counts"]["discovered_total"],
        )
        self.assertEqual(self.current_run["m1_total"], self.validation["test_counts"]["m1_tests"])
        self.assertEqual(self.current_run["m2_discovered_total"], self.validation["test_counts"]["m2_tests"])

    def test_the_module_inventory_matches_the_package_on_disk(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        modules = sorted(path.name for path in package.glob("*.py"))
        self.assertEqual(self.closure["module_inventory"], modules)
        self.assertEqual(self.closure["module_count"], len(modules))

    # -- supersession and preservation --

    def test_the_superseded_closure_report_is_recorded_and_unchanged(self) -> None:
        superseded = (
            "implementation/M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_CLOSURE_REPORT.json"
        )
        self.assertIn(superseded, self.validation["superseded_closure_reports"])
        link = self.validation["supersedes_prior_current_report"]
        self.assertEqual(link["commit"], STARTING_COMMIT)
        self.assertEqual(link["path"], "implementation/M2_VALIDATION_REPORT.json")
        raw = subprocess.run(
            ["git", "show", f"{link['commit']}:{link['path']}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(hashlib.sha256(raw).hexdigest(), link["sha256"])

    def test_the_historical_artifacts_are_preserved_byte_for_byte(self) -> None:
        for name in self.closure["preserved_historical_artifacts"]:
            with self.subTest(artifact=name):
                committed = subprocess.run(
                    ["git", "show", f"{STARTING_COMMIT}:implementation/{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), committed)

    def test_b26_and_b27_remain_closed_and_b56_to_b58_are_not_reopened(self) -> None:
        fourth = _load(IMPLEMENTATION / "M2_FOURTH_CRITICAL_REPAIR_REPORT.json")
        findings = {row["finding"]: row for row in fourth["findings"]}
        for name in ("M2-B26", "M2-B27"):
            with self.subTest(finding=name):
                self.assertEqual(findings[name]["disposition"], "VERIFIED_PHYSICAL")
        self.assertTrue(self.closure["preserved_closures"]["b26_and_b27_closed"])
        self.assertTrue(self.closure["preserved_closures"]["b56_to_b58_preserved"])
        prior = _load(
            IMPLEMENTATION
            / "M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_CLOSURE_REPORT.json"
        )
        self.assertEqual(sorted(prior["findings"]), ["M2-B56", "M2-B57", "M2-B58"])
        self.assertIn(
            "M2_EXACT_REMOVAL_GLOBAL_DRAIN_RESERVATION_PROVENANCE_CLOSURE_REPORT.json",
            self.closure["preserved_historical_artifacts"],
        )

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

    def _current_run_nodes(self) -> list[tuple[dict, str]]:
        """Every object in the current reports that states a run status."""

        nodes = [
            (self.delegated_run, "validation.canonical_current_run.delegated_physical"),
            (
                self.validation[CLOSURE_KEY]["delegated_run"],
                f"validation.{CLOSURE_KEY}.delegated_run",
            ),
            (
                self.closure["delegated_physical_qualification"]["run"],
                "closure.delegated_physical_qualification.run",
            ),
        ]
        return nodes


# --- delegated physical qualification -----------------------------------------


class DelegatedAliasCapacityArtifactTcbTests(unittest.TestCase):
    """Physical qualification of B59, B60 and M62 on real kernel state."""

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
        # Registered last, so it runs *first* on the way out -- before the guards
        # put the process-wide collections back.
        self.addCleanup(self._teardown_every_obligation)

    def _teardown_every_obligation(self) -> None:
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

    def _real_cgroup(self, label: str) -> rl.EffectCgroup:
        delegation = ps.cgroup_delegation()
        cgroup = rl.EffectCgroup(delegation, rl.ResourceBounds.for_timeout(1_000), label)
        self.assertTrue(cgroup.create(), cgroup.create_error)
        return cgroup

    def test_the_no_false_green_variable_forbids_skipping(self) -> None:
        if REQUIRE_DELEGATED:
            self.assertTrue(DELEGATION.available, DELEGATION.detail)
            self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        else:
            self.skipTest("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP is not set")

    def test_the_branch_and_revision_are_the_ones_under_qualification(self) -> None:
        branch = _git("branch", "--show-current")
        # This module is qualified on its own bounded branch, and is re-run as a
        # regression by each later bounded closure on that closure's branch.
        self.assertTrue(
            branch.startswith("paired-runner/m2-"),
            f"this module is qualified only on a bounded Milestone 2 closure branch: {branch!r}",
        )
        self.assertEqual(_git("merge-base", STARTING_COMMIT, "HEAD"), STARTING_COMMIT)
        self.assertEqual(_git("rev-parse", f"{STARTING_COMMIT}^"), STARTING_COMMIT_PARENT)
        ahead = int(_git("rev-list", "--count", f"{STARTING_COMMIT}..HEAD"))
        self.assertLessEqual(
            ahead,
            1 if branch == BRANCH else 2,
            "more than one commit stands on top of this closure's starting point",
        )

    @delegated
    def test_a_real_unresolved_canonical_never_discharges_its_alias(self) -> None:
        """M2-B59 physically, on a real delegated cgroup.  The wrapper names this."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        cgroup = self._real_cgroup(f"b59-real-{os.getpid()}")
        path = Path(cgroup.owned_path)
        self.assertTrue(path.is_dir())
        # A real nested cgroup inside the owned domain.  The kernel itself then
        # refuses the owned rmdir with ENOTEMPTY, so the canonical settlement is
        # genuinely unresolved on the first drain: no primitive is stubbed and no
        # failure is simulated.
        nested = path / "nested"
        nested.mkdir(mode=0o700)
        self.addCleanup(lambda: nested.is_dir() and nested.rmdir())
        self.assertFalse(cgroup.close(), "a cgroup with a live child was removed")
        entry_id = cgroup.cleanup_registry_id
        self.assertIsNotNone(entry_id, "the unresolved obligation was not retained")

        # A second obligation naming the exact same owned cgroup.
        alias = rl.EffectCgroup(
            ps.cgroup_delegation(), rl.ResourceBounds.for_timeout(1_000), "b59-real-twin"
        )
        alias._parent_fd = os.dup(cgroup._parent_fd)
        alias._dir_fd = os.dup(cgroup._dir_fd)
        alias._parent_identity = cgroup._parent_identity
        alias._owned_identity = cgroup._owned_identity
        alias._leaf = cgroup._leaf
        alias._path = cgroup._path
        alias._owned_path = cgroup._owned_path
        rl._retain_unregistered(alias)
        self.addCleanup(rl._release_unregistered, alias)
        self.assertEqual(cgroup.owned_identity, alias.owned_identity)

        # First drain: the kernel refuses the owned removal while the nested
        # cgroup stands, so the canonical obligation is truthfully unresolved.
        rows = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(2_000, "b59-first"))
        canonical = [row for row in rows if row["alias_of"] is None]
        aliases = [row for row in rows if row["alias_of"] is not None]
        self.assertEqual(len(canonical), 1, rows)
        self.assertEqual(len(aliases), 1, rows)
        self.assertTrue(canonical[0]["resource_outstanding"], canonical[0])
        self.assertTrue(canonical[0]["retained"], canonical[0])
        self.assertNotEqual(
            aliases[0]["state"],
            pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
            "a real alias was called discharged over a cgroup that is still standing",
        )
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertTrue(aliases[0]["resource_outstanding"], aliases[0])
        self.assertTrue(aliases[0]["retained"], aliases[0])
        self.assertEqual(aliases[0]["granted_ms"], 0, "a real alias spent a second grant")
        self.assertTrue(path.is_dir(), "the retained cgroup was removed anyway")
        self.assertTrue(nested.is_dir(), "the nested cgroup was removed by a refused settlement")

        # Retry with a fresh budget once the obstruction is gone: the resource
        # settles positively, exactly once, and both callers receive coherent
        # final evidence.
        nested.rmdir()
        rows = pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "b59-retry"))
        self.assertTrue(
            _await(lambda: not path.exists(), 10), "the owned cgroup was never removed"
        )
        self.assertTrue(cgroup.removal_settled)
        self.assertTrue(alias.removal_settled)
        self.assertTrue(cgroup.cleanup_complete, cgroup.cleanup_evidence())
        for row in rows:
            with self.subTest(label=row.get("label")):
                self.assertFalse(row["resource_outstanding"], row)
        # The alias spent no grant, so its own bookkeeping is still owed: it was
        # discharged as a *resource*, not as an obligation.  The next drain is
        # where it is settled, because it is then the canonical obligation for a
        # resource that is already absent -- which is exactly the convergence the
        # retryable model promises, and is not a leak.
        self.assertEqual(rl.unregistered_cleanups(), (alias,), "the alias was dropped, not settled")
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "b59-converge"))
        # No residual cgroup, process, registry entry, reservation or debt.
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(rl.unregistered_cleanups(), (), "an unregistered obligation leaked")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)
        self.assertFalse(CHILD_SUBREAPER.active, "subreaper ownership leaked")
        self.assertIsNone(po.process_restoration_debt(), "restoration debt leaked")

    @delegated
    def test_real_combined_capacity_refuses_direct_registration_before_side_effects(self) -> None:
        """M2-B60 physically, on a real delegated parent.  The wrapper names this."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        before = _effect_cgroups(parent)
        self.assertEqual(before, [], "the delegated parent was not clean")
        registry = pw._CLEANUP_REGISTRY
        with mock.patch.object(pw, "CLEANUP_REGISTRY_CAPACITY", 2):
            # Fill the combined capacity: one retained entry over a real cgroup
            # and one live reservation.
            cgroup = self._real_cgroup(f"b60-real-{os.getpid()}")
            path = Path(cgroup.owned_path)
            nested = path / "nested"
            nested.mkdir(mode=0o700)
            self.addCleanup(lambda: nested.is_dir() and nested.rmdir())
            self.assertFalse(cgroup.close(), "a cgroup with a live child was removed")
            reservation = registry.reserve("delegated-b60")
            evidence = registry.evidence()
            self.assertEqual(evidence["retained"], 1, evidence)
            self.assertEqual(evidence["reserved"], 1, evidence)
            self.assertEqual(evidence["held"], 2, evidence)
            self.assertTrue(registry.saturated(), evidence)

            # A reservation-less direct registration, before any new fork or
            # cgroup creation, is refused -- and refused before side effects.
            cgroups_before = _effect_cgroups(parent)
            handle = _RegistryObligation("delegated-direct")
            with self.assertRaises(CleanupRegistrySaturated):
                pw._record_cleanup(handle, handle.evidence())
            self.assertIsNone(handle._registry_id)
            self.assertEqual(_effect_cgroups(parent), cgroups_before, "a cgroup was created")
            after = registry.evidence()
            self.assertEqual(after["held"], 2, after)
            self.assertEqual(after["retained"], 1, after)
            self.assertEqual(after["reserved"], 1, after)

            # ...and a whole new effect refuses fail-closed before it creates a
            # directory, because the capacity it would need is not there.
            refused = rl.EffectCgroup(
                ps.cgroup_delegation(), rl.ResourceBounds.for_timeout(1_000), "b60-refused"
            )
            self.assertFalse(refused.create(), "an effect was created at capacity")
            self.assertEqual(_effect_cgroups(parent), cgroups_before, "a cgroup was created")

            # Release exactly one unit; exactly one later insertion succeeds.
            self.assertTrue(registry._release_reservation(reservation))
            self.assertEqual(registry.evidence()["held"], 1)
            second = _RegistryObligation("delegated-direct-after-release")
            entry_id = pw._record_cleanup(second, second.evidence())
            self.assertIsNotNone(entry_id)
            self.assertEqual(registry.evidence()["held"], 2)
            third = _RegistryObligation("delegated-direct-too-many")
            with self.assertRaises(CleanupRegistrySaturated):
                pw._record_cleanup(third, third.evidence())
            registry.record(second, {**second.evidence(), "cleanup_complete": True})
            self.assertEqual(registry.evidence()["held"], 1)

        # Settle the real obligation and prove no residue.
        nested.rmdir()
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "b60-settle"))
        self.assertTrue(_await(lambda: not path.exists(), 10), "the owned cgroup leaked")
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)

    @delegated
    def test_a_real_probe_creation_serializes_against_an_owned_final_removal(self) -> None:
        """M2-M62 physically: both are controller-owned mutations under one parent."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        domain = rl.cgroup_mutation_domain_of(parent)
        self.assertIsNotNone(domain, "the delegated parent has no readable identity")
        cgroup = self._real_cgroup(f"m62-real-{os.getpid()}")
        path = Path(cgroup.owned_path)
        order: list[str] = []
        lock = threading.Lock()
        inside = threading.Event()
        release = threading.Event()
        real_rmdir = rl._rmdir_owned_child

        def slow_removal(parent_fd, leaf):
            with lock:
                order.append("removal-in")
            inside.set()
            release.wait(10)
            outcome = real_rmdir(parent_fd, leaf)
            with lock:
                order.append("removal-out")
            return outcome

        probe = parent / f"{rl.PROBE_PREFIX}m62-{os.getpid()}"
        self.addCleanup(lambda: probe.exists() and rl._remove_owned_probe(probe))

        def create_probe() -> None:
            outcome = rl._create_probe_inside_boundary(probe, parent)
            with lock:
                order.append(f"probe:{outcome['code']}")

        with mock.patch.object(rl, "_rmdir_owned_child", slow_removal):
            remover = threading.Thread(target=cgroup.close)
            remover.start()
            self.assertTrue(inside.wait(10), "the owned removal never reached its primitive")
            creator = threading.Thread(target=create_probe)
            creator.start()
            # The probe creation cannot interleave with the final removal.
            self.assertFalse(
                _await(lambda: any(item.startswith("probe") for item in order), 0.5),
                "a real probe creation ran inside a concurrent owned final removal",
            )
            release.set()
            remover.join(timeout=15)
            creator.join(timeout=15)
        self.assertEqual(order, ["removal-in", "removal-out", "probe:None"], order)
        self.assertFalse(path.exists(), "the owned cgroup was not removed")
        self.assertTrue(probe.is_dir(), "the probe was not created after the removal finished")
        cleanup = rl._remove_owned_probe(probe)
        self.assertTrue(cleanup["removed"], cleanup)
        self.assertTrue(cleanup["absence_verified"], cleanup)
        self.assertEqual(
            rl.cgroup_mutation_domains_evidence()["held_by_this_thread"],
            [],
            "a mutation boundary was left held",
        )
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")

    @delegated
    def test_no_residual_state_survives_this_module(self) -> None:
        """Nothing owned, retained, held or owed is left behind."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "residual"))
        parent = Path(DELEGATION.delegated_path)
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(sorted(parent.glob(f"{rl.PROBE_PREFIX}*")), [], "a probe cgroup leaked")
        self.assertEqual(rl.unregistered_cleanups(), (), "an unregistered obligation leaked")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)
        self.assertEqual(pw.unsettled_failed_starts(), (), "a failed start leaked")
        self.assertFalse(CHILD_SUBREAPER.active, "subreaper ownership leaked")
        self.assertIsNone(po.process_restoration_debt(), "restoration debt leaked")
        self.assertEqual(
            po.get_child_subreaper()[0], self.before, "the kernel flag was left changed"
        )
        self.assertEqual(
            rl.cgroup_mutation_domains_evidence()["held_by_this_thread"],
            [],
            "a mutation boundary was left held",
        )


if __name__ == "__main__":
    unittest.main()
