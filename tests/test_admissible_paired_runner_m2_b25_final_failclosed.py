"""M2-B25 final fail-closed repair: B28 probe cleanup, B29 stale cache, B30 release state, M31 counts.

Four bounded findings are closed here, and each is closed by making a *claim*
that the code was not entitled to make impossible to produce.

M2-B28
    ``probe_cgroup_delegation`` could construct ``available=True`` with the
    detail "... was removed" and then swallow the ``rmdir`` failure in a
    ``finally``.  Availability is now built from completed cleanup evidence, so
    a residual probe cgroup and a positive result cannot coexist.

M2-B29
    A cached topology was re-derived from PID, path existence, membership, and a
    *basename*.  A replaced directory, a re-populated parent, or a controller
    the kernel stopped distributing all left those checks green.  Every cached
    reuse now revalidates the material kernel state and fails closed.

M2-B30
    The trusted helper wrote the gate and *then* acknowledged, so an exception
    from ``release()`` could mean either "the gate never opened" or "the gate
    opened and the answer was lost".  The protocol now acknowledges on both
    sides of the write, and the controller reports ``NOT_RELEASED``,
    ``RELEASED``, or ``RELEASE_OUTCOME_UNKNOWN`` from what was acknowledged --
    never from the fact that an exception was raised.

M2-M31
    The recorded M2 counts named 254 executed against 304 discovered.  The
    validation report now distinguishes discovery, skips, legacy tests, and the
    new modules, and a test in this file recomputes them.

Deterministic tests here drive constructed trees, injected kernel failures, and
a real socket-pair protocol peer.  Delegated physical tests run the production
path inside a real ``Delegate=yes`` cgroup v2 subtree and, under
``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
import errno
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner.cgroup_launch import (  # noqa: E402
    RELEASE_NOT_RELEASED,
    RELEASE_OUTCOME_UNKNOWN,
    RELEASE_PHASE_ACCEPTED,
    RELEASE_PHASE_ACCEPT_FRAME_LOST,
    RELEASE_PHASE_ACK_AMBIGUOUS,
    RELEASE_PHASE_ACK_LOST,
    RELEASE_PHASE_WRITE_COMPLETED,
    RELEASE_PHASE_WRITE_FAILED,
    RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
    RELEASE_RELEASED,
    GateReleaseOutcome,
    classify_release_frames,
)
from admissible.paired_runner.resource_limits import (  # noqa: E402
    CgroupDelegation,
    CgroupTopology,
    EffectCgroup,
    MECHANISM_CGROUP_AND_RLIMIT,
    ResourceBounds,
    ResourceContainmentUnavailable,
    initialize_cgroup_topology,
    probe_cgroup_delegation,
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
from admissible.paired_runner.private_workspace import (  # noqa: E402
    PrivateMountHelper,
    SpawnedLauncher,
    _send_framed,
    _recv_framed,
)
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


# --- deterministic fixtures ---------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


_REAL_MKDIR = Path.mkdir


def _cgroupfs_mkdir(self_path, *args, **kwargs):
    """Create a fixture cgroup carrying the interface files the kernel creates.

    M2-B35.  cgroup2 creates ``cgroup.procs`` together with the cgroup itself,
    so a fixture that omitted it would present an absent membership file where
    the kernel always presents an empty one -- making "unreadable" and "empty"
    indistinguishable in the fixture, which is exactly the ambiguity this repair
    removes from the production code.  The patch applies only inside a
    constructed cgroup tree, identified by its parent's ``cgroup.controllers``.
    """

    _REAL_MKDIR(self_path, *args, **kwargs)
    if (self_path.parent / "cgroup.controllers").exists():
        procs = self_path / "cgroup.procs"
        if not procs.exists():
            procs.write_text("", encoding="utf-8")


def _cgroupfs_rmdir(test: unittest.TestCase) -> None:
    """Make an ordinary directory behave like a cgroup for ``rmdir``.

    Removing a real cgroup removes its kernel interface files with it, and fails
    only when the cgroup still has children.  A tmpfs fixture instead reports
    ``ENOTEMPTY`` for the control files this code itself wrote, which would test
    the fixture rather than the cleanup logic.
    """

    def rmdir(self_path):
        if any(child.is_dir() for child in self_path.iterdir()):
            raise OSError(errno.ENOTEMPTY, "Directory not empty")
        shutil.rmtree(self_path)

    patcher = mock.patch.object(Path, "rmdir", rmdir)
    patcher.start()
    test.addCleanup(patcher.stop)


class _FakeParent:
    """An ordinary directory shaped like a delegated effect parent.

    It is never kernel evidence: every test that uses it either drives a code
    path with ``cgroup2_required=False`` or patches the magic check explicitly,
    and :class:`ProbeCleanupTruthfulnessTests` proves the production default
    still refuses an ordinary filesystem.
    """

    def __init__(
        self,
        *,
        controllers: str = "cpuset cpu io memory pids",
        subtree: str = "memory pids",
        parent_procs: str = "",
        manager_procs: str | None = None,
    ) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-b25-final-"))
        self.parent = self.root / "svc"
        self.parent.mkdir()
        _write(self.parent / "cgroup.controllers", controllers)
        _write(self.parent / "cgroup.subtree_control", subtree)
        _write(self.parent / "cgroup.procs", parent_procs)
        self.manager = self.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        self.manager.mkdir()
        _write(
            self.manager / "cgroup.procs",
            f"{os.getpid()}\n" if manager_procs is None else manager_procs,
        )
        # Anything the production code creates beneath this parent from here on
        # gets the interface files a real cgroup mkdir creates.
        self._mkdir_patcher = mock.patch.object(Path, "mkdir", _cgroupfs_mkdir)
        self._mkdir_patcher.start()

    def topology(self, **overrides) -> CgroupTopology:
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
        return CgroupTopology(**fields)

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

    def close(self) -> None:
        self._mkdir_patcher.stop()
        shutil.rmtree(self.root, ignore_errors=True)


# --- M2-B28: probe cleanup truthfulness --------------------------------------


class ProbeCleanupTruthfulnessTests(unittest.TestCase):
    """A positive probe result is built from completed, verified cleanup."""

    def setUp(self) -> None:
        self.fake = _FakeParent()
        self.addCleanup(self.fake.close)
        self.topology = self.fake.topology()
        patcher = mock.patch.object(
            rl, "initialize_cgroup_topology", lambda **_kwargs: self.topology
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        _cgroupfs_rmdir(self)
        self.probe = self.fake.parent / f"{rl.PROBE_PREFIX}{os.getpid()}"

    def test_a_successful_probe_removes_the_probe_and_verifies_its_absence(self) -> None:
        delegation = probe_cgroup_delegation()
        self.assertTrue(delegation.available, delegation.detail)
        cleanup = delegation.probe_cleanup
        self.assertTrue(cleanup["removed"])
        self.assertTrue(cleanup["absence_verified"])
        self.assertFalse(cleanup["residual_path_exists"])
        self.assertIsNone(cleanup["code"])
        self.assertFalse(self.probe.exists(), "the probe cgroup survived a positive result")
        self.assertIn("absence verified", delegation.detail)

    def test_an_ebusy_rmdir_refuses_and_never_says_removed(self) -> None:
        def busy(_self):
            raise OSError(errno.EBUSY, "Device or resource busy")

        with mock.patch.object(Path, "rmdir", busy):
            delegation = probe_cgroup_delegation()
        self.assertFalse(delegation.available)
        self.assertEqual(delegation.code, rl.TOPOLOGY_PROBE_CLEANUP_FAILED)
        self.assertEqual(delegation.probe_cleanup["rmdir_errno"], "EBUSY")
        self.assertTrue(delegation.probe_cleanup["residual_path_exists"])
        self.assertNotIn("was removed", delegation.detail)
        self.assertTrue(self.probe.exists())
        shutil.rmtree(self.probe)

    def test_an_eacces_rmdir_refuses_with_its_exact_errno(self) -> None:
        def denied(_self):
            raise OSError(errno.EACCES, "Permission denied")

        with mock.patch.object(Path, "rmdir", denied):
            delegation = probe_cgroup_delegation()
        self.assertFalse(delegation.available)
        self.assertEqual(delegation.code, rl.TOPOLOGY_PROBE_CLEANUP_FAILED)
        self.assertEqual(delegation.probe_cleanup["rmdir_errno"], "EACCES")
        self.assertTrue(delegation.probe_cleanup["residual_path_exists"])
        self.assertEqual(delegation.probe_cleanup["probe_path"], str(self.probe))
        shutil.rmtree(self.probe)

    def test_a_success_that_leaves_the_path_behind_is_refused(self) -> None:
        with mock.patch.object(Path, "rmdir", lambda _self: None):
            delegation = probe_cgroup_delegation()
        self.assertFalse(delegation.available)
        self.assertEqual(delegation.code, rl.TOPOLOGY_PROBE_RESIDUAL_PATH)
        self.assertTrue(delegation.probe_cleanup["residual_path_exists"])
        self.assertFalse(delegation.probe_cleanup["removed"])
        self.assertTrue(self.probe.exists())
        shutil.rmtree(self.probe)

    def test_an_unexpected_disappearance_is_classified_not_called_success(self) -> None:
        real_rmdir = Path.rmdir

        def vanished(self_path):
            shutil.rmtree(self_path, ignore_errors=True)
            raise FileNotFoundError(errno.ENOENT, "No such file or directory")

        with mock.patch.object(Path, "rmdir", vanished):
            delegation = probe_cgroup_delegation()
        self.assertFalse(delegation.available, "ENOENT was treated as a safe removal")
        self.assertEqual(delegation.code, rl.TOPOLOGY_PROBE_DISAPPEARED)
        self.assertEqual(delegation.probe_cleanup["rmdir_errno"], "ENOENT")
        self.assertFalse(delegation.probe_cleanup["residual_path_exists"])
        self.assertIs(Path.rmdir, real_rmdir)

    def test_an_occupied_probe_is_never_removed_and_never_reported_removed(self) -> None:
        real_apply = rl._apply_and_read_back_limits

        def occupying(cgroup, intended):
            result = real_apply(cgroup, intended)
            _write(cgroup / "cgroup.procs", "424242\n")
            return result

        with mock.patch.object(rl, "_apply_and_read_back_limits", occupying):
            delegation = probe_cgroup_delegation()
        self.assertFalse(delegation.available)
        self.assertEqual(delegation.code, rl.TOPOLOGY_PROBE_NOT_EMPTY)
        self.assertFalse(delegation.probe_cleanup["rmdir_attempted"])
        self.assertEqual(delegation.probe_cleanup["members_before_removal"], [424242])
        self.assertTrue(self.probe.exists())
        shutil.rmtree(self.probe)

    def test_no_positive_result_is_constructed_before_cleanup_completes(self) -> None:
        order: list[str] = []
        real_remove = rl._remove_owned_probe
        real_delegation = rl.CgroupDelegation

        def recording_remove(probe):
            evidence = real_remove(probe)
            order.append("cleanup")
            return evidence

        def recording_delegation(*args, **kwargs):
            built = real_delegation(*args, **kwargs)
            if built.available:
                order.append("positive_result")
            return built

        with mock.patch.object(rl, "_remove_owned_probe", recording_remove), mock.patch.object(
            rl, "CgroupDelegation", recording_delegation
        ):
            delegation = probe_cgroup_delegation()
        self.assertTrue(delegation.available, delegation.detail)
        self.assertEqual(order, ["cleanup", "positive_result"])

    def test_a_repeated_probe_after_a_cleanup_failure_cannot_false_green(self) -> None:
        def busy(_self):
            raise OSError(errno.EBUSY, "Device or resource busy")

        with mock.patch.object(Path, "rmdir", busy):
            first = probe_cgroup_delegation()
        self.assertFalse(first.available)
        self.assertTrue(self.probe.exists())
        # The residue is still there; the next probe collides rather than
        # adopting a cgroup whose state this process cannot account for.
        second = probe_cgroup_delegation()
        self.assertFalse(second.available, "a probe over its own residue reported availability")
        self.assertEqual(second.code, rl.TOPOLOGY_EFFECT_COLLISION)
        shutil.rmtree(self.probe)

    def test_the_production_default_still_refuses_an_ordinary_filesystem(self) -> None:
        topology = initialize_cgroup_topology(
            unified_root=self.fake.root, own_cgroup="/svc", cache=False
        )
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_CGROUP2_NOT_MOUNTED)


# --- M2-B29: stale cached topology -------------------------------------------


class StaleCachedTopologyTests(unittest.TestCase):
    """A cached topology is a promise about the kernel; it is checked again."""

    def setUp(self) -> None:
        self.fake = _FakeParent()
        self.addCleanup(self.fake.close)

    def test_an_unchanged_topology_revalidates(self) -> None:
        self.assertIsNone(revalidate_cgroup_topology(self.fake.topology()))

    def test_a_disabled_memory_controller_is_refused(self) -> None:
        _write(self.fake.parent / "cgroup.subtree_control", "pids")
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail)
        self.assertIn("memory", detail)

    def test_a_disabled_pids_controller_is_refused(self) -> None:
        _write(self.fake.parent / "cgroup.subtree_control", "memory")
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail)
        self.assertIn("pids", detail)

    def test_an_unreadable_subtree_control_is_refused(self) -> None:
        (self.fake.parent / "cgroup.subtree_control").unlink()
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail)
        self.assertIn("subtree_control", detail)

    def test_a_missing_available_controller_is_refused(self) -> None:
        _write(self.fake.parent / "cgroup.controllers", "cpu io memory")
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail)
        self.assertIn("pids", detail)

    def test_a_controller_that_disappeared_from_the_cached_set_is_refused(self) -> None:
        topology = self.fake.topology(enabled_controllers=("memory", "pids", "io"))
        detail = revalidate_cgroup_topology(topology)
        self.assertIsNotNone(detail)
        self.assertIn("io", detail)

    def test_the_same_basename_at_a_different_full_path_is_refused(self) -> None:
        topology = self.fake.topology(cgroup2_required=True)
        impostor = f"/somewhere/else/{self.fake.manager.name}"
        with mock.patch.object(rl, "is_cgroup2_filesystem", lambda _path: True), mock.patch.object(
            rl, "_own_unified_cgroup", lambda: impostor
        ):
            detail = revalidate_cgroup_topology(topology)
        self.assertIsNotNone(detail, "a matching basename was accepted as the same cgroup")
        self.assertIn(impostor, detail)

    def test_the_matching_full_path_is_accepted(self) -> None:
        topology = self.fake.topology(cgroup2_required=True)
        with mock.patch.object(rl, "is_cgroup2_filesystem", lambda _path: True), mock.patch.object(
            rl, "_own_unified_cgroup", lambda: f"/svc/{self.fake.manager.name}"
        ):
            self.assertIsNone(revalidate_cgroup_topology(topology))

    def test_the_recorded_identity_is_the_directory_it_names(self) -> None:
        info = os.stat(self.fake.parent)
        self.assertEqual(
            rl._directory_identity(self.fake.parent), f"{info.st_dev}:{info.st_ino}"
        )
        self.assertIsNone(rl._directory_identity(self.fake.parent / "cgroup.procs"))

    def test_a_replaced_effect_parent_inode_is_refused(self) -> None:
        # A cgroup removed and recreated under the same name is a different
        # cgroup.  The recorded identity is supplied here rather than obtained by
        # recreating the fixture, because tmpfs reuses inode numbers and would
        # make the fixture -- not the check -- decide the outcome.
        detail = revalidate_cgroup_topology(self.fake.topology(effect_parent_identity="9:99"))
        self.assertIsNotNone(detail, "a recreated effect parent was reused")
        self.assertIn("replaced", detail)
        self.assertIn(str(self.fake.parent), detail)

    def test_a_replaced_manager_leaf_is_refused(self) -> None:
        detail = revalidate_cgroup_topology(self.fake.topology(manager_leaf_identity="9:99"))
        self.assertIsNotNone(detail, "a recreated manager leaf was reused")
        self.assertIn("replaced", detail)
        self.assertIn(str(self.fake.manager), detail)

    def test_a_removed_manager_leaf_is_refused(self) -> None:
        topology = self.fake.topology()
        shutil.rmtree(self.fake.manager)
        detail = revalidate_cgroup_topology(topology)
        self.assertIsNotNone(detail)
        self.assertIn("no longer exists", detail)

    def test_a_parent_that_gained_an_unrelated_process_is_refused(self) -> None:
        _write(self.fake.parent / "cgroup.procs", "999999\n")
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail, "a populated effect parent was still trusted")
        self.assertIn("999999", detail)

    def test_a_controller_no_longer_in_the_manager_leaf_is_refused(self) -> None:
        _write(self.fake.manager / "cgroup.procs", "")
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail)
        self.assertIn("no longer a member", detail)

    def test_a_controller_in_two_contradictory_locations_is_refused(self) -> None:
        _write(self.fake.parent / "cgroup.procs", f"{os.getpid()}\n")
        detail = revalidate_cgroup_topology(self.fake.topology())
        self.assertIsNotNone(detail, "the controller was accepted in the parent and the leaf")
        self.assertIn(str(os.getpid()), detail)

    def test_a_nested_manager_leaf_is_refused(self) -> None:
        nested = self.fake.manager / "nested"
        nested.mkdir()
        _write(nested / "cgroup.procs", f"{os.getpid()}\n")
        detail = revalidate_cgroup_topology(
            self.fake.topology(
                manager_leaf=str(nested),
                manager_leaf_identity=rl._directory_identity(nested),
            )
        )
        self.assertIsNotNone(detail)
        self.assertIn("no longer a child", detail)

    def test_a_fork_inherited_cache_is_refused(self) -> None:
        detail = revalidate_cgroup_topology(self.fake.topology(owner_pid=os.getpid() + 100_000))
        self.assertIsNotNone(detail)
        self.assertIn("cache_pid=", detail)

    def test_the_topology_cache_refuses_and_does_not_rebuild(self) -> None:
        saved = rl._TOPOLOGY
        try:
            rl._TOPOLOGY = self.fake.topology()
            _write(self.fake.parent / "cgroup.subtree_control", "")
            first = initialize_cgroup_topology()
            self.assertFalse(first.initialized)
            self.assertEqual(first.code, rl.TOPOLOGY_STALE_CACHED_TOPOLOGY)
            # No implicit reconstruction: a second call returns the same refusal
            # and no new manager leaf appears beneath the parent.
            second = initialize_cgroup_topology()
            self.assertIs(second, first)
            leaves = sorted(self.fake.parent.glob(f"{rl.MANAGER_LEAF_PREFIX}*"))
            self.assertEqual([str(path) for path in leaves], [str(self.fake.manager)])
        finally:
            rl._TOPOLOGY = saved


class SupervisorDelegationCacheTests(unittest.TestCase):
    """``process_supervision.cgroup_delegation`` never returns an unchecked object."""

    def setUp(self) -> None:
        self.fake = _FakeParent()
        self.addCleanup(self.fake.close)
        self.saved = (ps._DELEGATION_CACHE, ps._DELEGATION_PID)

        def restore():
            ps._DELEGATION_CACHE, ps._DELEGATION_PID = self.saved

        self.addCleanup(restore)

    def test_a_cached_available_result_is_revalidated_on_every_reuse(self) -> None:
        calls: list[int] = []
        cached = self.fake.delegation()
        ps._DELEGATION_CACHE = cached
        ps._DELEGATION_PID = os.getpid()
        topology = self.fake.topology()

        def revalidating(**_kwargs):
            calls.append(1)
            return topology

        with mock.patch.object(ps, "initialize_cgroup_topology", revalidating):
            self.assertIs(ps.cgroup_delegation(), cached)
            self.assertIs(ps.cgroup_delegation(), cached)
        self.assertEqual(len(calls), 2, "the cached delegation was reused without revalidation")

    def test_a_stale_cached_result_is_refused_and_replaced(self) -> None:
        ps._DELEGATION_CACHE = self.fake.delegation()
        ps._DELEGATION_PID = os.getpid()
        stale = CgroupTopology(
            initialized=False,
            code=rl.TOPOLOGY_STALE_CACHED_TOPOLOGY,
            detail="the effect parent was replaced",
            unified_root=str(self.fake.root),
            effect_parent=str(self.fake.parent),
            manager_leaf=str(self.fake.manager),
            owner_pid=os.getpid(),
        )
        with mock.patch.object(ps, "initialize_cgroup_topology", lambda **_k: stale):
            delegation = ps.cgroup_delegation()
        self.assertFalse(delegation.available)
        self.assertEqual(delegation.code, rl.TOPOLOGY_STALE_CACHED_TOPOLOGY)
        self.assertIn("replaced", delegation.detail)

    def test_no_effect_cgroup_is_created_after_a_stale_cache_refusal(self) -> None:
        ps._DELEGATION_CACHE = self.fake.delegation()
        ps._DELEGATION_PID = os.getpid()
        stale = CgroupTopology(
            initialized=False,
            code=rl.TOPOLOGY_STALE_CACHED_TOPOLOGY,
            detail="stale",
            unified_root=str(self.fake.root),
            effect_parent=str(self.fake.parent),
            manager_leaf=str(self.fake.manager),
            owner_pid=os.getpid(),
        )
        with mock.patch.object(ps, "initialize_cgroup_topology", lambda **_k: stale):
            delegation = ps.cgroup_delegation()
        cgroup = EffectCgroup(delegation, ResourceBounds.for_timeout(1000), "stale-refusal")
        cgroup.create()
        self.assertFalse(cgroup.directory_present)
        self.assertEqual(list(self.fake.parent.glob(f"{rl.EFFECT_PREFIX}*")), [])

    def test_a_stale_cache_never_downgrades_a_promised_mechanism(self) -> None:
        refused = rl.delegation_from_topology_failure(
            CgroupTopology(
                initialized=False,
                code=rl.TOPOLOGY_STALE_CACHED_TOPOLOGY,
                detail="stale",
                owner_pid=os.getpid(),
            )
        )
        mechanism = rl.effective_mechanism(
            refused,
            membership_verified=False,
            required_mechanism=MECHANISM_CGROUP_AND_RLIMIT,
        )
        self.assertEqual(mechanism, rl.MECHANISM_NONE)

    def test_a_fork_inherited_delegation_cache_is_reprobed(self) -> None:
        sentinel = self.fake.delegation()
        ps._DELEGATION_CACHE = sentinel
        ps._DELEGATION_PID = os.getpid() + 100_000
        with mock.patch.object(ps, "probe_cgroup_delegation", lambda force=False: "reprobed"):
            self.assertEqual(ps.cgroup_delegation(), "reprobed")
        self.assertEqual(ps._DELEGATION_PID, os.getpid())


# --- M2-B30: the release-state model -----------------------------------------


class ReleaseStateClassificationTests(unittest.TestCase):
    """What the helper acknowledged -- not what the caller caught -- decides."""

    def test_a_completed_acknowledged_write_is_released(self) -> None:
        outcome = classify_release_frames(
            {"phase": RELEASE_PHASE_ACCEPTED},
            {"phase": RELEASE_PHASE_WRITE_COMPLETED, "released": True},
        )
        self.assertEqual(outcome.state, RELEASE_RELEASED)
        self.assertTrue(outcome.released)
        self.assertEqual(outcome.sentinel_claim, "THE_LAUNCHER_WAS_RELEASED")

    def test_a_terminal_first_frame_is_not_released(self) -> None:
        outcome = classify_release_frames(
            {"phase": RELEASE_PHASE_WRITE_NOT_ATTEMPTED, "error": "unknown_pid"}, None
        )
        self.assertEqual(outcome.state, RELEASE_NOT_RELEASED)
        self.assertEqual(outcome.phase, RELEASE_PHASE_WRITE_NOT_ATTEMPTED)
        self.assertEqual(outcome.sentinel_claim, "NO_INSTRUCTION_EXECUTED")

    def test_a_failed_write_is_not_released(self) -> None:
        outcome = classify_release_frames(
            {"phase": RELEASE_PHASE_ACCEPTED},
            {"phase": RELEASE_PHASE_WRITE_FAILED, "released": False, "error": "32"},
        )
        self.assertEqual(outcome.state, RELEASE_NOT_RELEASED)
        self.assertEqual(outcome.detail, "32")

    def test_a_lost_accept_frame_is_unknown(self) -> None:
        outcome = classify_release_frames(None, None, transport_detail="helper died")
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACCEPT_FRAME_LOST)
        self.assertEqual(outcome.sentinel_claim, "EXECUTION_OUTCOME_UNKNOWN")

    def test_a_lost_completion_frame_is_unknown(self) -> None:
        outcome = classify_release_frames({"phase": RELEASE_PHASE_ACCEPTED}, None)
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACK_LOST)

    def test_an_unrecognised_completion_frame_is_unknown_not_absent(self) -> None:
        outcome = classify_release_frames(
            {"phase": RELEASE_PHASE_ACCEPTED}, {"phase": "SOMETHING_ELSE"}
        )
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACK_AMBIGUOUS)

    def test_the_unknown_state_never_claims_that_nothing_executed(self) -> None:
        outcome = GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "lost")
        self.assertNotEqual(outcome.sentinel_claim, "NO_INSTRUCTION_EXECUTED")
        self.assertEqual(outcome.to_dict()["sentinel_claim"], "EXECUTION_OUTCOME_UNKNOWN")


class _ProtocolPeer(threading.Thread):
    """A trusted-helper stand-in that speaks the two-phase release protocol."""

    def __init__(self, sock: socket.socket, script: str) -> None:
        super().__init__(daemon=True)
        self.sock = sock
        self.script = script
        self.request: dict | None = None

    def run(self) -> None:
        try:
            self.request, _fds = _recv_framed(self.sock)
        except Exception:
            return
        if self.script == "unknown_pid":
            _send_framed(
                self.sock,
                {"phase": RELEASE_PHASE_WRITE_NOT_ATTEMPTED, "ok": False, "error": "unknown_pid"},
            )
        elif self.script == "write_failed":
            _send_framed(self.sock, {"phase": RELEASE_PHASE_ACCEPTED, "ok": True})
            _send_framed(
                self.sock,
                {"phase": RELEASE_PHASE_WRITE_FAILED, "ok": False, "released": False, "error": "32"},
            )
        elif self.script == "released":
            _send_framed(self.sock, {"phase": RELEASE_PHASE_ACCEPTED, "ok": True})
            _send_framed(
                self.sock, {"phase": RELEASE_PHASE_WRITE_COMPLETED, "ok": True, "released": True}
            )
        elif self.script == "die_after_accept":
            _send_framed(self.sock, {"phase": RELEASE_PHASE_ACCEPTED, "ok": True})
        # "die_before_accept" sends nothing at all.
        try:
            self.sock.close()
        except OSError:
            pass


class ReleaseProtocolTests(unittest.TestCase):
    """The client half of the two-phase release, over a real socket pair."""

    def _helper(self, script: str) -> PrivateMountHelper:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        peer = _ProtocolPeer(child, script)
        peer.start()
        helper = PrivateMountHelper(pid=-1, conn=parent, view_fd=-1, staging_path="/nowhere")
        self.addCleanup(child.close)
        self.addCleanup(parent.close)
        self.addCleanup(peer.join, 5)
        return helper

    def test_a_nominal_release_reports_released(self) -> None:
        outcome = self._helper("released").release(4242)
        self.assertEqual(outcome.state, RELEASE_RELEASED)

    def test_an_unknown_pid_reports_not_released(self) -> None:
        outcome = self._helper("unknown_pid").release(4242)
        self.assertEqual(outcome.state, RELEASE_NOT_RELEASED)
        self.assertEqual(outcome.detail, "unknown_pid")

    def test_a_gate_write_failure_reports_not_released(self) -> None:
        outcome = self._helper("write_failed").release(4242)
        self.assertEqual(outcome.state, RELEASE_NOT_RELEASED)
        self.assertEqual(outcome.phase, RELEASE_PHASE_WRITE_FAILED)

    def test_a_helper_that_dies_after_accepting_reports_unknown(self) -> None:
        outcome = self._helper("die_after_accept").release(4242)
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACK_LOST)

    def test_a_helper_that_answers_nothing_reports_unknown(self) -> None:
        outcome = self._helper("die_before_accept").release(4242)
        self.assertEqual(outcome.state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(outcome.phase, RELEASE_PHASE_ACCEPT_FRAME_LOST)

    def test_release_never_raises_on_a_protocol_failure(self) -> None:
        helper = self._helper("die_before_accept")
        outcome = helper.release(1)
        self.assertIsInstance(outcome, GateReleaseOutcome)

    def test_an_ungated_launcher_is_never_reported_released(self) -> None:
        helper = self._helper("released")
        launcher = SpawnedLauncher(pid=7, stdout_fd=-1, stderr_fd=-1, _helper=helper)
        outcome = launcher.release()
        self.assertEqual(outcome.state, RELEASE_NOT_RELEASED)
        self.assertEqual(outcome.phase, rl_release_phase_not_gated())

    def test_a_second_release_of_a_released_launcher_repeats_the_outcome(self) -> None:
        helper = self._helper("released")
        launcher = SpawnedLauncher(
            pid=7, stdout_fd=-1, stderr_fd=-1, _helper=helper, _awaiting_release=True
        )
        first = launcher.release()
        self.assertEqual(first.state, RELEASE_RELEASED)
        second = launcher.release()
        self.assertEqual(second.state, RELEASE_RELEASED)
        self.assertIs(second, first)


def rl_release_phase_not_gated() -> str:
    from admissible.paired_runner.cgroup_launch import RELEASE_PHASE_NOT_GATED

    return RELEASE_PHASE_NOT_GATED


class _FakeProcess:
    """A launcher stand-in that records exactly what the abort path did to it."""

    def __init__(self, *, alive: bool = True, kill_raises: bool = False, wait_raises: bool = False) -> None:
        self.alive = alive
        self.kill_raises = kill_raises
        self.wait_raises = wait_raises
        self.kill_calls = 0
        self.wait_calls = 0
        self.returncode = None if alive else -9

    def kill(self, *_args) -> None:
        self.kill_calls += 1
        if self.kill_raises:
            raise OSError(errno.ESRCH, "No such process")
        self.alive = False
        self.returncode = -9

    def wait(self, timeout=None) -> int:
        self.wait_calls += 1
        if self.wait_raises:
            raise TimeoutError("wedged")
        self.alive = False
        self.returncode = -9 if self.returncode is None else self.returncode
        return self.returncode

    def poll(self):
        return self.returncode


class AbortGatedEffectTests(unittest.TestCase):
    """Bounded, idempotent, truthful cleanup of a refused or ambiguous effect."""

    def setUp(self) -> None:
        self.fake = _FakeParent()
        self.addCleanup(self.fake.close)
        _cgroupfs_rmdir(self)
        self.cgroup = EffectCgroup(
            self.fake.delegation(), ResourceBounds.for_timeout(1000), f"abort-{os.getpid()}"
        )
        self.assertTrue(self.cgroup.create(), self.cgroup.create_error)

    def _descriptors(self) -> tuple[int, ...]:
        read_a, write_a = os.pipe()
        read_b, write_b = os.pipe()
        return (read_a, write_a, read_b, write_b)

    def test_a_pre_release_refusal_kills_reaps_closes_and_removes(self) -> None:
        process = _FakeProcess()
        descriptors = self._descriptors()
        evidence = ps.abort_gated_effect(
            process=process,
            cgroup=self.cgroup,
            descriptors=descriptors,
            release_outcome=GateReleaseOutcome(
                RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_NOT_ATTEMPTED, "membership refused"
            ),
            reason="cgroup_membership_unverified",
        )
        self.assertEqual(evidence["release"]["release_state"], RELEASE_NOT_RELEASED)
        self.assertEqual(evidence["release"]["sentinel_claim"], "NO_INSTRUCTION_EXECUTED")
        self.assertTrue(evidence["launcher_killed"])
        self.assertTrue(evidence["launcher_reaped"])
        self.assertTrue(evidence["quiescence"]["quiescent"])
        self.assertTrue(evidence["cgroup_removal"]["removed"])
        self.assertTrue(evidence["cgroup_removal"]["absence_verified"])
        self.assertEqual(sorted(evidence["descriptors"]["closed"]), sorted(descriptors))
        self.assertEqual(list(self.fake.parent.glob(f"{rl.EFFECT_PREFIX}*")), [])

    def test_an_unknown_release_outcome_still_kills_but_claims_no_absence(self) -> None:
        process = _FakeProcess()
        evidence = ps.abort_gated_effect(
            process=process,
            cgroup=self.cgroup,
            descriptors=self._descriptors(),
            release_outcome=GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, "the helper died after the write"
            ),
            reason="gate_release_not_confirmed",
        )
        self.assertEqual(evidence["release"]["release_state"], RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(evidence["release"]["sentinel_claim"], "EXECUTION_OUTCOME_UNKNOWN")
        self.assertNotIn("NO_INSTRUCTION_EXECUTED", json.dumps(evidence))
        self.assertTrue(evidence["launcher_killed"])
        self.assertTrue(evidence["launcher_reaped"])
        self.assertTrue(evidence["cgroup_removal"]["removed"])
        self.assertIsNotNone(evidence["kill_domain"])

    def test_the_kill_domain_is_the_effect_cgroup_and_reaches_only_its_members(self) -> None:
        _write(Path(self.cgroup.path) / "cgroup.procs", "")
        evidence = self.cgroup.kill_domain()
        self.assertEqual(evidence["effect_path"], self.cgroup.path)
        self.assertEqual(evidence["members_signalled"], [])
        self.assertEqual(evidence["errors"], [])

    def test_cleanup_is_idempotent_over_repeated_calls(self) -> None:
        process = _FakeProcess()
        descriptors = self._descriptors()
        outcome = GateReleaseOutcome(RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_NOT_ATTEMPTED, "")
        first = ps.abort_gated_effect(
            process=process,
            cgroup=self.cgroup,
            descriptors=descriptors,
            release_outcome=outcome,
            reason="first",
        )
        second = ps.abort_gated_effect(
            process=process,
            cgroup=self.cgroup,
            descriptors=descriptors,
            release_outcome=outcome,
            reason="second",
        )
        self.assertTrue(first["cgroup_removal"]["removed"])
        # The cgroup is already gone: the second pass reports the absence rather
        # than a second removal, and touches nothing.
        self.assertFalse(second["cgroup_removal"]["removed"])
        self.assertTrue(second["cgroup_removal"]["absence_verified"])
        self.assertEqual(second["descriptors"]["closed"], [])
        self.assertEqual(sorted(second["descriptors"]["already_closed"]), sorted(descriptors))
        self.assertEqual(list(self.fake.parent.glob(f"{rl.EFFECT_PREFIX}*")), [])

    def test_cleanup_survives_an_already_reaped_process(self) -> None:
        process = _FakeProcess(alive=False, kill_raises=True)
        evidence = ps.abort_gated_effect(
            process=process,
            cgroup=self.cgroup,
            descriptors=(),
            release_outcome=GateReleaseOutcome(RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_FAILED, ""),
            reason="already-dead",
        )
        self.assertFalse(evidence["launcher_killed"])
        self.assertTrue(evidence["launcher_reaped"])
        self.assertTrue(evidence["cgroup_removal"]["removed"])

    def test_a_wedged_launcher_does_not_wedge_the_cleanup(self) -> None:
        process = _FakeProcess(wait_raises=True)
        evidence = ps.abort_gated_effect(
            process=process,
            cgroup=self.cgroup,
            descriptors=(),
            release_outcome=GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, ""),
            reason="wedged",
        )
        self.assertEqual(process.wait_calls, 1)
        self.assertTrue(evidence["launcher_reaped"], "poll observed the reaped launcher")

    def test_no_owned_descriptor_is_leaked_by_the_exceptional_path(self) -> None:
        descriptors = self._descriptors()
        ps.abort_gated_effect(
            process=_FakeProcess(),
            cgroup=self.cgroup,
            descriptors=descriptors,
            release_outcome=GateReleaseOutcome(RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, ""),
            reason="descriptor-inventory",
        )
        for descriptor in descriptors:
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptor)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_a_cgroup_with_live_members_is_never_reported_removed(self) -> None:
        _write(Path(self.cgroup.path) / "cgroup.procs", "999999\n")
        self.assertFalse(self.cgroup.close())
        evidence = self.cgroup.removal_evidence()
        self.assertFalse(evidence["removed"])
        self.assertTrue(evidence["residual_path_exists"])
        self.assertEqual(evidence["residual_members"], [999999])
        _write(Path(self.cgroup.path) / "cgroup.procs", "")
        self.assertTrue(self.cgroup.close())

    def test_quiescence_is_bounded_when_a_member_never_leaves(self) -> None:
        _write(Path(self.cgroup.path) / "cgroup.procs", "999999\n")
        evidence = self.cgroup.wait_quiescent(0.05)
        self.assertFalse(evidence["quiescent"])
        self.assertEqual(evidence["residual_members"], [999999])
        _write(Path(self.cgroup.path) / "cgroup.procs", "")
        self.assertTrue(self.cgroup.close())


class ContainmentRefusalEvidenceTests(unittest.TestCase):
    """The refusal carries the release state, and the effect record repeats it."""

    def test_the_refusal_carries_the_release_state_and_cleanup_evidence(self) -> None:
        error = ResourceContainmentUnavailable(
            "the gated launcher was not confirmed released",
            release_state=RELEASE_OUTCOME_UNKNOWN,
            cleanup_evidence={"launcher_reaped": True, "quiescence": {"quiescent": True}},
        )
        self.assertEqual(error.release_state, RELEASE_OUTCOME_UNKNOWN)
        self.assertTrue(error.cleanup_evidence["launcher_reaped"])

    def test_a_refusal_without_a_release_state_defaults_to_none(self) -> None:
        error = ResourceContainmentUnavailable("something else")
        self.assertIsNone(error.release_state)
        self.assertEqual(error.cleanup_evidence, {})

    def test_an_unknown_outcome_is_not_recorded_as_a_process_that_never_started(self) -> None:
        from admissible.paired_runner import effects as fx

        request = RunCommandRequest.create(
            tool_grammar_fingerprint=build_specification(
                "DIRECT", run_id="run-b30-record"
            ).tool_grammar.grammar_fingerprint,
            argv=[PYTHON, "-c", "pass"],
            timeout_ms=1000,
        )
        unknown = fx._command_start_failure(
            request,
            "cgroup_gate_release_outcome_unknown",
            execution_outcome_semantics=(
                "EXECUTION_OUTCOME_UNKNOWN: the trusted gate write may have completed before "
                "the acknowledgement was lost"
            ),
        )
        self.assertEqual(
            unknown.process_observation.start_failure_class,
            "cgroup_gate_release_outcome_unknown",
        )
        self.assertIsNone(unknown.process_observation.exit_code)
        self.assertFalse(unknown.process_observation.status_document_present)
        self.assertEqual(unknown.result.outcome, "FAILED")
        # The durable evidence states the ambiguity rather than asserting that
        # nothing executed.
        self.assertIn(
            "EXECUTION_OUTCOME_UNKNOWN", unknown.resource_observation.containment_semantics
        )
        self.assertIn(
            "EXECUTION_OUTCOME_UNKNOWN", unknown.resource_observation.measurement_semantics
        )

        refused = fx._command_start_failure(request, "cgroup_membership_unverified")
        self.assertNotIn(
            "EXECUTION_OUTCOME_UNKNOWN", refused.resource_observation.containment_semantics
        )
        self.assertFalse(refused.process_observation.process_started)


# --- M2-M31: count semantics --------------------------------------------------


class ValidationReportCountTests(unittest.TestCase):
    """The declared M2 totals must add up to what discovery actually ran."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(
            (REPOSITORY_ROOT / "implementation" / "M2_VALIDATION_REPORT.json").read_text(
                encoding="utf-8"
            )
        )

    def _counts(self) -> dict:
        counts = self.report.get("m2_test_count_semantics")
        self.assertIsInstance(counts, dict, "M2_VALIDATION_REPORT.json declares no count semantics")
        return counts

    def test_every_count_field_is_named_unambiguously(self) -> None:
        counts = self._counts()
        for field in (
            "m1_discovered_by_discovery",
            "m2_discovered_by_discovery",
            "m2_skipped",
            "m2_non_skipped",
            "m2_legacy_pre_b25",
            "m2_b25_topology_module",
            "m2_b25_final_failclosed_module",
            "delegated_physical_tests",
            "delegated_physical_skips",
        ):
            self.assertIn(field, counts, field)
            self.assertIsInstance(counts[field], int, field)

    def test_the_declared_totals_are_internally_consistent(self) -> None:
        counts = self._counts()
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_skipped"] + counts["m2_non_skipped"],
            "skipped + non-skipped must equal what discovery ran",
        )
        self.assertEqual(
            counts["m2_discovered_by_discovery"],
            counts["m2_legacy_pre_b25"]
            + counts["m2_b25_topology_module"]
            + counts["m2_b25_final_failclosed_module"]
            # M2-M36 added the final protocol/lifecycle module to this milestone,
            # and M2-B40 added the subreaper/deadline closure module.
            + counts["m2_final_protocol_lifecycle_module"]
            + counts["m2_subreaper_deadline_closure_module"],
            "the legacy and new modules must account for the whole discovery total",
        )

    def test_the_legacy_count_is_never_presented_as_the_whole_of_m2(self) -> None:
        counts = self._counts()
        self.assertLess(
            counts["m2_legacy_pre_b25"],
            counts["m2_discovered_by_discovery"],
            "the pre-B25 count is not the complete executed count",
        )
        self.assertEqual(counts["m2_legacy_pre_b25"], 254)

    def test_the_declared_module_sizes_match_the_modules_on_disk(self) -> None:
        counts = self._counts()
        for module, field in (
            (
                "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
                "m2_b25_topology_module",
            ),
            (
                "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
                "m2_b25_final_failclosed_module",
            ),
        ):
            loader = unittest.defaultTestLoader.loadTestsFromName(module)
            self.assertEqual(loader.countTestCases(), counts[field], module)

    def test_the_delegated_physical_totals_are_declared(self) -> None:
        counts = self._counts()
        self.assertGreater(counts["delegated_physical_tests"], 0)
        self.assertEqual(
            counts["delegated_physical_skips"],
            0,
            "a delegated physical skip is never recorded as a pass",
        )


# --- delegated physical qualification ----------------------------------------


class _Harness:
    """The production shared effect substrate over a disposable workspace."""

    def __init__(self, *, run_id: str) -> None:
        self.run_id = run_id
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
SLOW_SENTINEL_SCRIPT = "import time\ntime.sleep(30)\nopen('late.txt','w').write('late')\n"


def _open_descriptor_count() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:  # pragma: no cover - /proc is part of the platform contract
        return -1


def _live_pids_under(parent: Path) -> list[int]:
    live: list[int] = []
    for entry in sorted(parent.glob(f"{rl.EFFECT_PREFIX}*")):
        live.extend(rl.read_cgroup_members(entry).pids)
    return sorted(live)


class DelegatedFinalFailClosedTests(unittest.TestCase):
    """Physical qualification of the repaired paths under a real delegated cgroup."""

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
    def test_a_positive_probe_leaves_no_probe_cgroup_and_a_second_probe_agrees(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        parent = Path(DELEGATION.delegated_path)
        self.assertTrue(DELEGATION.probe_cleanup["removed"])
        self.assertTrue(DELEGATION.probe_cleanup["absence_verified"])
        self.assertFalse(Path(DELEGATION.probe_cleanup["probe_path"]).exists())
        self.assertEqual(list(parent.glob(f"{rl.PROBE_PREFIX}*")), [])

        # A second probe must not collide with residue from the first.
        again = probe_cgroup_delegation(force=True)
        self.assertTrue(again.available, again.detail)
        self.assertTrue(again.probe_cleanup["absence_verified"])
        self.assertEqual(list(parent.glob(f"{rl.PROBE_PREFIX}*")), [])

    @delegated
    def test_repeated_production_effects_pass_through_revalidation(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        revalidations: list[str | None] = []
        real_revalidate = rl._topology_is_still_true

        def recording(topology):
            detail = real_revalidate(topology)
            revalidations.append(detail)
            return detail

        harness = _Harness(run_id="run-b29-revalidate")
        self.addCleanup(harness.close)
        with mock.patch.object(rl, "_topology_is_still_true", recording):
            for _ in range(2):
                outcome = harness.command("print('revalidated')\n")
                self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertTrue(revalidations, "a production effect reused the cache without revalidating")
        self.assertTrue(
            all(detail is None for detail in revalidations),
            f"revalidation contradicted the cached topology: {revalidations}",
        )

    @delegated
    def test_a_contradicted_cache_refuses_the_next_effect(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-b29-contradiction")
        self.addCleanup(harness.close)

        def restore() -> None:
            rl.initialize_cgroup_topology(force=True)
            ps.cgroup_delegation(force=True)

        # The refusal is deliberately sticky, so the caches are rebuilt for the
        # tests that follow even if an assertion below fails.
        self.addCleanup(restore)
        with mock.patch.object(
            rl, "_topology_is_still_true", lambda _t: "injected kernel contradiction"
        ):
            outcome = harness.command(SENTINEL_SCRIPT)
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [])
        # The refusal is not a silent rebuild: the topology cache still holds a
        # classified refusal until it is forced.
        self.assertEqual(rl._TOPOLOGY.code, rl.TOPOLOGY_STALE_CACHED_TOPOLOGY)

    @delegated
    def test_a_failure_before_the_release_write_executes_no_command(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-b30-not-released")
        self.addCleanup(harness.close)
        captured: list[dict] = []
        real_abort = ps.abort_gated_effect
        released: list[int] = []
        real_release = SpawnedLauncher.release

        def recording_abort(**kwargs):
            evidence = real_abort(**kwargs)
            captured.append(evidence)
            return evidence

        def recording_release(self_launcher):
            released.append(self_launcher.pid)
            return real_release(self_launcher)

        def refusing_attach(cgroup, pid):
            cgroup.attach_error = "injected_membership_refusal"
            return False

        before = _open_descriptor_count()
        with mock.patch.object(ps, "attach_and_verify_real", refusing_attach), mock.patch.object(
            ps, "abort_gated_effect", recording_abort
        ), mock.patch.object(SpawnedLauncher, "release", recording_release):
            outcome = harness.command(SENTINEL_SCRIPT)

        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(released, [], "the gate was released after a refused membership proof")
        self.assertFalse((harness.workspace / "sentinel.txt").exists())
        self.assertEqual(len(captured), 1)
        evidence = captured[0]
        self.assertEqual(evidence["release"]["release_state"], RELEASE_NOT_RELEASED)
        self.assertEqual(evidence["release"]["sentinel_claim"], "NO_INSTRUCTION_EXECUTED")
        self.assertTrue(evidence["launcher_reaped"])
        self.assertTrue(evidence["quiescence"]["quiescent"])
        self.assertTrue(evidence["cgroup_removal"]["removed"])
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [])
        self.assertEqual(_live_pids_under(parent), [])
        self.assertLessEqual(_open_descriptor_count(), before + 2)

    @delegated
    def test_a_lost_release_acknowledgement_is_recorded_as_unknown(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        harness = _Harness(run_id="run-b30-unknown")
        self.addCleanup(harness.close)
        captured: list[dict] = []
        outcomes: list[GateReleaseOutcome] = []
        real_abort = ps.abort_gated_effect
        real_release = SpawnedLauncher.release

        def recording_abort(**kwargs):
            evidence = real_abort(**kwargs)
            captured.append(evidence)
            return evidence

        def faulting_release(self_launcher):
            # The trusted helper writes the gate and then dies before its
            # acknowledgement reaches this controller.
            self_launcher._helper.release_fault = "die_after_write"
            outcome = real_release(self_launcher)
            outcomes.append(outcome)
            return outcome

        before = _open_descriptor_count()
        with mock.patch.object(ps, "abort_gated_effect", recording_abort), mock.patch.object(
            SpawnedLauncher, "release", faulting_release
        ):
            outcome = harness.command(SLOW_SENTINEL_SCRIPT, timeout_ms=60_000)

        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].state, RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(len(captured), 1)
        evidence = captured[0]
        self.assertEqual(evidence["release"]["release_state"], RELEASE_OUTCOME_UNKNOWN)
        self.assertEqual(evidence["release"]["sentinel_claim"], "EXECUTION_OUTCOME_UNKNOWN")
        self.assertNotIn("NO_INSTRUCTION_EXECUTED", json.dumps(evidence))
        self.assertIsNotNone(evidence["kill_domain"])
        self.assertTrue(evidence["quiescence"]["quiescent"], evidence["quiescence"])
        self.assertTrue(evidence["cgroup_removal"]["removed"], evidence["cgroup_removal"])
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [])
        self.assertEqual(_live_pids_under(parent), [])
        self.assertFalse(
            (harness.workspace / "late.txt").exists(),
            "the killed command still completed its write",
        )
        # The effect is recorded as an unknown execution outcome, never as a
        # command that provably did not start.
        process = harness.store.load("process-observation", "proposal-1")
        self.assertEqual(process["start_failure_class"], "cgroup_gate_release_outcome_unknown")
        self.assertLessEqual(_open_descriptor_count(), before + 2)

    @delegated
    def test_a_nominal_release_still_completes_and_cleans_up(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        outcomes: list[GateReleaseOutcome] = []
        real_release = SpawnedLauncher.release

        def recording_release(self_launcher):
            outcome = real_release(self_launcher)
            outcomes.append(outcome)
            return outcome

        harness = _Harness(run_id="run-b30-nominal")
        self.addCleanup(harness.close)
        before = _open_descriptor_count()
        with mock.patch.object(SpawnedLauncher, "release", recording_release):
            outcome = harness.command("print('released normally')\n")

        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual([item.state for item in outcomes], [RELEASE_RELEASED])
        self.assertEqual(outcomes[0].phase, RELEASE_PHASE_WRITE_COMPLETED)
        resource = harness.store.load("resource-observation", "proposal-1")
        self.assertEqual(resource["containment_mechanism"], MECHANISM_CGROUP_AND_RLIMIT)
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [])
        self.assertEqual(list(parent.glob(f"{rl.PROBE_PREFIX}*")), [])
        self.assertLessEqual(_open_descriptor_count(), before + 2)

    @delegated
    def test_repeated_cleanup_after_a_physical_refusal_reports_no_second_success(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        topology = initialize_cgroup_topology()
        self.assertTrue(topology.initialized, topology.detail)
        delegation = probe_cgroup_delegation()
        cgroup = EffectCgroup(
            delegation, ResourceBounds.for_timeout(1000), f"idem-{os.getpid()}"
        )
        self.assertTrue(cgroup.create(), cgroup.create_error)
        process = _FakeProcess()
        first = ps.abort_gated_effect(
            process=process,
            cgroup=cgroup,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_NOT_ATTEMPTED, ""
            ),
            reason="physical-idempotence-1",
        )
        second = ps.abort_gated_effect(
            process=process,
            cgroup=cgroup,
            descriptors=(),
            release_outcome=GateReleaseOutcome(
                RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_NOT_ATTEMPTED, ""
            ),
            reason="physical-idempotence-2",
        )
        self.assertTrue(first["cgroup_removal"]["removed"])
        self.assertFalse(second["cgroup_removal"]["removed"])
        self.assertTrue(second["cgroup_removal"]["absence_verified"])
        self.assertEqual(
            list(Path(topology.effect_parent).glob(f"{rl.EFFECT_PREFIX}idem-*")), []
        )


# --- boundary -----------------------------------------------------------------


class MilestoneBoundaryTests(unittest.TestCase):
    """This repair stays inside Milestone 2."""

    FORBIDDEN = (
        "provider_transport",
        "model_execution",
        "multi_session_continuation",
        "direct_mode_orchestration",
        "governed_mode_orchestration",
        "policy_evaluation",
        "owner_authority_m3",
        "evaluator_execution",
        "paired_environment_preparation",
        "installed_path_qualification",
        "benchmark_execution",
    )

    def test_no_milestone_3_module_was_created(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        names = {path.stem for path in package.glob("*.py")}
        for forbidden in self.FORBIDDEN:
            self.assertNotIn(forbidden, names)

    def test_this_module_imports_no_network_client(self) -> None:
        import ast

        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        for forbidden in ("urllib", "http", "requests", "httpx", "ftplib", "smtplib", "xmlrpc"):
            self.assertNotIn(forbidden, imported, forbidden)
        # The only socket in this module is an AF_UNIX socketpair standing in for
        # the trusted helper; it reaches no host and no address family with a
        # network on the other end.
        used = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "socket"
        }
        self.assertTrue(used <= {"socketpair", "socket", "AF_UNIX", "SOCK_STREAM"}, sorted(used))

    def test_the_repository_worktree_is_not_the_effect_workspace(self) -> None:
        harness_root = Path(tempfile.gettempdir())
        self.assertNotEqual(harness_root.resolve(), REPOSITORY_ROOT.resolve())


if __name__ == "__main__":
    unittest.main()
