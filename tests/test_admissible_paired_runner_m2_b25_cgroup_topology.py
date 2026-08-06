"""M2-B25: the production cgroup-before-exec topology, proven rather than promised.

Two classes of test live here.

Deterministic fault tests drive every transition of the manager-leaf bootstrap
against a constructed directory tree and against injected kernel failures.  They
never claim physical qualification: an ordinary filesystem fixture is refused as
kernel evidence by the same code path production uses, and one of the tests
below asserts exactly that.

Delegated physical tests run the *production* path -- ``SharedEffectSubstrate``
down through ``supervise_command`` -- inside a real ``Delegate=yes`` cgroup v2
subtree.  With ``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1`` they fail rather than
skip, so a green run under that variable cannot be a false green.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.  Every effect
happens inside a disposable temporary workspace owned by the test process.
"""

from __future__ import annotations

from pathlib import Path
import errno
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner.cgroup_launch import (  # noqa: E402
    LAUNCH_ORDER,
    attach_and_verify_real,
)
from admissible.paired_runner.resource_limits import (  # noqa: E402
    CgroupDelegation,
    EffectCgroup,
    MECHANISM_CGROUP_AND_RLIMIT,
    MECHANISM_NONE,
    ResourceBounds,
    effective_mechanism,
    initialize_cgroup_topology,
    probe_cgroup_delegation,
    topology_lifecycle_description,
)

# The manager-leaf topology must be bootstrapped before any trusted helper
# process is forked, because a helper left in the delegated parent would keep
# the parent populated and the bootstrap would -- correctly -- refuse.  Probing
# here, at import, is the same ordering the production readiness probe uses.
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
from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner.private_workspace import SpawnedLauncher  # noqa: E402
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402


CAPSULE_READY = probe_capsule_readiness()


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


# --- deterministic fixtures ---------------------------------------------------


_REAL_MKDIR = Path.mkdir
_REAL_RMDIR = Path.rmdir


def _cgroupfs_rmdir(self_path):
    """Remove a fixture cgroup the way cgroupfs removes a real one.

    The kernel destroys a cgroup's interface files with the cgroup, and refuses
    only when the cgroup still has children.  A plain tmpfs directory instead
    reports ``ENOTEMPTY`` for the very interface files the fixture created,
    which would test the fixture rather than the removal logic.
    """

    if not (self_path / "cgroup.procs").exists():
        _REAL_RMDIR(self_path)
        return
    if any(child.is_dir() for child in self_path.iterdir()):
        raise OSError(errno.ENOTEMPTY, "Directory not empty", str(self_path))
    shutil.rmtree(self_path)


def _cgroupfs_mkdir(self_path, *args, **kwargs):
    """Create a fixture cgroup carrying the interface files the kernel creates.

    M2-B35.  cgroup2 creates ``cgroup.procs`` together with the cgroup itself.
    A fixture that omitted it would present an absent membership file where the
    kernel always presents an empty one, making "unreadable" and "empty"
    indistinguishable in the fixture -- exactly the ambiguity this milestone
    removes from the production code.  The patch applies only inside a
    constructed cgroup tree, identified by its parent's ``cgroup.controllers``.
    """

    _REAL_MKDIR(self_path, *args, **kwargs)
    if (self_path.parent / "cgroup.controllers").exists():
        procs = self_path / "cgroup.procs"
        if not procs.exists():
            procs.write_text("", encoding="utf-8")


class _FakeCgroupTree:
    """An ordinary directory tree shaped like a delegated cgroup.

    It is deliberately *not* kernel evidence.  Every test that uses it passes
    ``require_cgroup2=False`` explicitly, and :class:`EvidenceRuleTests` proves
    that the production default refuses it.
    """

    def __init__(self, *, controllers: str = "cpuset cpu io memory pids", procs: str | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="admissible-b25-fake-"))
        self.own = "/svc"
        self.parent = self.root / "svc"
        self.parent.mkdir()
        (self.parent / "cgroup.controllers").write_text(controllers, encoding="utf-8")
        (self.parent / "cgroup.subtree_control").write_text("", encoding="utf-8")
        (self.parent / "cgroup.procs").write_text(
            f"{os.getpid()}\n" if procs is None else procs, encoding="utf-8"
        )
        self._patchers = [
            mock.patch.object(Path, "mkdir", _cgroupfs_mkdir),
            mock.patch.object(Path, "rmdir", _cgroupfs_rmdir),
        ]
        for patcher in self._patchers:
            patcher.start()

    def bootstrap(self, **overrides):
        return initialize_cgroup_topology(
            unified_root=self.root,
            own_cgroup=self.own,
            require_cgroup2=False,
            cache=False,
            **overrides,
        )

    def children(self) -> set[str]:
        return {entry.name for entry in self.parent.iterdir() if entry.is_dir()}

    def close(self) -> None:
        for patcher in reversed(self._patchers):
            patcher.stop()
        shutil.rmtree(self.root, ignore_errors=True)


class EvidenceRuleTests(unittest.TestCase):
    """An ordinary filesystem fixture is never physical cgroup evidence."""

    def test_a_filesystem_fixture_is_refused_by_the_production_default(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        topology = initialize_cgroup_topology(
            unified_root=tree.root, own_cgroup=tree.own, cache=False
        )
        self.assertFalse(topology.initialized)
        self.assertIn(
            topology.code,
            {rl.TOPOLOGY_CGROUP2_NOT_MOUNTED, rl.TOPOLOGY_DELEGATED_PATH_NOT_CGROUP2},
        )
        self.assertEqual(tree.children(), set(), "no cgroup was created on a refused host")

    def test_the_cgroup2_magic_test_is_the_one_production_uses(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        self.assertFalse(rl.is_cgroup2_filesystem(tree.parent))
        if DELEGATION.available:
            self.assertTrue(rl.is_cgroup2_filesystem(Path(DELEGATION.delegated_path)))


class FalsePositiveProbeRegressionTests(unittest.TestCase):
    """The old probe answered 'mkdir succeeded'.  That answer is now refused."""

    def test_mkdir_and_rmdir_alone_no_longer_report_availability(self) -> None:
        # This tree satisfies the old probe exactly: the controllers are
        # present and a child directory can be created and removed.  What it
        # does not satisfy is the constraint that actually matters -- the
        # delegated parent still holds an unrelated process, so it can never
        # distribute memory or pids to a per-effect child.
        tree = _FakeCgroupTree(procs=f"{os.getpid()}\n4294967\n")
        self.addCleanup(tree.close)
        old_probe_would_have_passed = (
            "memory" in (tree.parent / "cgroup.controllers").read_text(encoding="utf-8")
            and "pids" in (tree.parent / "cgroup.controllers").read_text(encoding="utf-8")
        )
        scratch = tree.parent / ".old-style-probe"
        scratch.mkdir()
        scratch.rmdir()
        self.assertTrue(old_probe_would_have_passed)

        topology = tree.bootstrap()
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_PARENT_STILL_POPULATED)

    def test_availability_now_names_a_classified_code(self) -> None:
        delegation = probe_cgroup_delegation(force=True)
        self.assertIn(delegation.code, rl.TOPOLOGY_CODES)
        if not delegation.available:
            self.assertNotEqual(delegation.code, rl.TOPOLOGY_INITIALIZED)
        else:
            self.assertEqual(delegation.code, rl.TOPOLOGY_INITIALIZED)
            self.assertEqual(
                sorted(delegation.probe_effect_limits),
                ["memory.max", "pids.max"],
            )


class ManagerLeafBootstrapTests(unittest.TestCase):
    """Every transition of the bootstrap is classified."""

    def test_successful_bootstrap_moves_only_the_controller(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        topology = tree.bootstrap()
        self.assertTrue(topology.initialized, topology.detail)
        self.assertEqual(topology.code, rl.TOPOLOGY_INITIALIZED)
        self.assertEqual(topology.effect_parent, str(tree.parent))
        self.assertTrue(Path(topology.manager_leaf).name.startswith(rl.MANAGER_LEAF_PREFIX))
        self.assertEqual(Path(topology.manager_leaf).parent, tree.parent)
        self.assertEqual(topology.owner_pid, os.getpid())
        self.assertEqual(set(topology.enabled_controllers), {"memory", "pids"})
        members = (Path(topology.manager_leaf) / "cgroup.procs").read_text(encoding="utf-8")
        self.assertEqual(members.split(), [str(os.getpid())])

    def test_missing_controllers_are_refused(self) -> None:
        tree = _FakeCgroupTree(controllers="cpuset cpu io")
        self.addCleanup(tree.close)
        topology = tree.bootstrap()
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_MISSING_CONTROLLERS)
        self.assertEqual(tree.children(), set())

    def test_only_memory_missing_is_refused(self) -> None:
        tree = _FakeCgroupTree(controllers="cpuset cpu io pids")
        self.addCleanup(tree.close)
        self.assertEqual(tree.bootstrap().code, rl.TOPOLOGY_MISSING_CONTROLLERS)

    def test_unreadable_controllers_are_refused(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        (tree.parent / "cgroup.controllers").unlink()
        self.assertEqual(tree.bootstrap().code, rl.TOPOLOGY_CONTROLLERS_UNREADABLE)

    def test_an_unrelated_process_in_the_parent_refuses_rather_than_moves_it(self) -> None:
        tree = _FakeCgroupTree(procs=f"{os.getpid()}\n4294967\n")
        self.addCleanup(tree.close)
        topology = tree.bootstrap()
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_PARENT_STILL_POPULATED)
        self.assertIn("4294967", topology.detail)
        # The unrelated PID was never written into a cgroup this process owns,
        # and the rollback outcome is reported rather than assumed.
        leaf = tree.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        if leaf.exists():
            self.assertEqual(
                (leaf / "cgroup.procs").read_text(encoding="utf-8").split(), [str(os.getpid())]
            )
        self.assertIn("controller_returned=True", topology.detail)
        self.assertIn("manager_leaf_removed=", topology.detail)

    def test_manager_leaf_collision_refuses_and_removes_nothing(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        squatter = tree.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        squatter.mkdir()
        (squatter / "marker").write_text("not ours", encoding="utf-8")
        topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_MANAGER_COLLISION)
        self.assertTrue((squatter / "marker").exists(), "an unowned cgroup was not touched")

    def test_manager_leaf_creation_failure_is_classified(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        os.chmod(tree.parent, 0o500)
        self.addCleanup(os.chmod, tree.parent, 0o700)
        self.assertEqual(tree.bootstrap().code, rl.TOPOLOGY_MANAGER_CREATE_FAILED)

    def test_controller_move_failure_rolls_back(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        real_write = rl._write_control

        def failing(path: Path, payload: str, **kwargs):
            if path.parent.name.startswith(rl.MANAGER_LEAF_PREFIX):
                return "EACCES"
            return real_write(path, payload, **kwargs)

        with mock.patch.object(rl, "_write_control", failing):
            topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_CONTROLLER_MOVE_FAILED)
        self.assertIn("manager_leaf_removed=True", topology.detail)
        self.assertEqual(tree.children(), set())

    def test_controller_move_not_observed_rolls_back(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        real_members = rl.read_cgroup_members

        def blind(path: Path, **kwargs):
            if Path(path).name.startswith(rl.MANAGER_LEAF_PREFIX):
                # A successful read that does not list the controller.  This is
                # deliberately *not* an unreadable membership: it proves the
                # move-not-observed branch, not the M2-B35 refusal branch.
                return rl.CgroupMembership(str(path), read_ok=True, pids=())
            return real_members(path, **kwargs)

        with mock.patch.object(rl, "read_cgroup_members", blind):
            topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_CONTROLLER_MOVE_NOT_OBSERVED)
        self.assertIn("controller_returned=True", topology.detail)

    def test_subtree_control_write_failure_rolls_back(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        real_write = rl._write_control

        def failing(path: Path, payload: str, **kwargs):
            if path.name == "cgroup.subtree_control":
                return "EBUSY"
            return real_write(path, payload, **kwargs)

        with mock.patch.object(rl, "_write_control", failing):
            topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_SUBTREE_CONTROL_WRITE_FAILED)
        self.assertIn("EBUSY", topology.detail)
        self.assertIn("controller_returned=True", topology.detail)

    def test_subtree_control_unreadable_rolls_back(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        real_read = rl._read_control

        def failing(path: Path, **kwargs):
            if path.name == "cgroup.subtree_control":
                return None, "ENODEV"
            return real_read(path, **kwargs)

        with mock.patch.object(rl, "_read_control", failing):
            topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_SUBTREE_CONTROL_UNREADABLE)

    def test_partial_controller_activation_is_refused(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        real_read = rl._read_control

        def partial(path: Path, **kwargs):
            if path.name == "cgroup.subtree_control":
                return "memory", None
            return real_read(path, **kwargs)

        with mock.patch.object(rl, "_read_control", partial):
            topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_CONTROLLER_READBACK_MISMATCH)
        self.assertIn("pids", topology.detail)
        self.assertIn("controller_returned=True", topology.detail)

    def test_controller_readback_mismatch_reports_what_the_kernel_said(self) -> None:
        tree = _FakeCgroupTree()
        self.addCleanup(tree.close)
        real_read = rl._read_control

        def wrong(path: Path, **kwargs):
            if path.name == "cgroup.subtree_control":
                return "cpu io", None
            return real_read(path, **kwargs)

        with mock.patch.object(rl, "_read_control", wrong):
            topology = tree.bootstrap()
        self.assertEqual(topology.code, rl.TOPOLOGY_CONTROLLER_READBACK_MISMATCH)
        self.assertIn("cpu", topology.detail)

    def test_no_partial_activation_is_ever_reported_available(self) -> None:
        for code in (
            rl.TOPOLOGY_CONTROLLER_READBACK_MISMATCH,
            rl.TOPOLOGY_SUBTREE_CONTROL_WRITE_FAILED,
            rl.TOPOLOGY_PARENT_STILL_POPULATED,
        ):
            with self.subTest(code=code):
                delegation = rl._delegation_from_failure(rl._failed(code, "x"))
                self.assertFalse(delegation.available)
                self.assertEqual(delegation.code, code)


class TopologyIdempotenceTests(unittest.TestCase):
    """One topology per controller process; no nested leaves; PID-bound cache."""

    def setUp(self) -> None:
        self._saved = rl._TOPOLOGY
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        rl._TOPOLOGY = self._saved

    def test_repeated_calls_return_the_same_topology(self) -> None:
        first = initialize_cgroup_topology()
        second = initialize_cgroup_topology()
        self.assertIs(first, second)

    def test_an_existing_manager_leaf_is_reused_and_never_nested(self) -> None:
        tree = _FakeCgroupTree(procs="")
        self.addCleanup(tree.close)
        manager = tree.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        manager.mkdir()
        (manager / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="utf-8")
        (tree.parent / "cgroup.subtree_control").write_text("memory pids", encoding="utf-8")
        before = tree.children()
        topology = initialize_cgroup_topology(
            unified_root=tree.root,
            own_cgroup=f"/svc/{manager.name}",
            require_cgroup2=False,
            cache=False,
        )
        self.assertTrue(topology.initialized, topology.detail)
        self.assertFalse(topology.manager_leaf_created)
        self.assertEqual(topology.manager_leaf, str(manager))
        self.assertEqual(topology.effect_parent, str(tree.parent))
        self.assertEqual(tree.children(), before, "no nested manager leaf was created")
        self.assertEqual(set(manager.iterdir()), {manager / "cgroup.procs"})

    def test_a_reused_manager_leaf_still_requires_an_unpopulated_parent(self) -> None:
        tree = _FakeCgroupTree(procs="4294967\n")
        self.addCleanup(tree.close)
        manager = tree.parent / f"{rl.MANAGER_LEAF_PREFIX}-{os.getpid()}"
        manager.mkdir()
        topology = initialize_cgroup_topology(
            unified_root=tree.root,
            own_cgroup=f"/svc/{manager.name}",
            require_cgroup2=False,
            cache=False,
        )
        self.assertEqual(topology.code, rl.TOPOLOGY_PARENT_STILL_POPULATED)

    def test_a_cache_inherited_across_fork_is_not_trusted(self) -> None:
        rl._TOPOLOGY = rl.CgroupTopology(
            initialized=True,
            code=rl.TOPOLOGY_INITIALIZED,
            detail="inherited",
            unified_root="/sys/fs/cgroup",
            effect_parent="/sys/fs/cgroup/svc",
            manager_leaf="/sys/fs/cgroup/svc/admissible-manager-1",
            owner_pid=1,
        )
        topology = initialize_cgroup_topology()
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_STALE_CACHED_TOPOLOGY)
        self.assertIn("cache_pid=1", topology.detail)

    def test_a_removed_manager_leaf_fails_closed(self) -> None:
        vanished = Path(tempfile.mkdtemp(prefix="admissible-b25-gone-"))
        shutil.rmtree(vanished)
        rl._TOPOLOGY = rl.CgroupTopology(
            initialized=True,
            code=rl.TOPOLOGY_INITIALIZED,
            detail="stale",
            unified_root="/sys/fs/cgroup",
            effect_parent=str(vanished.parent),
            manager_leaf=str(vanished),
            owner_pid=os.getpid(),
        )
        topology = initialize_cgroup_topology()
        self.assertFalse(topology.initialized)
        self.assertEqual(topology.code, rl.TOPOLOGY_STALE_CACHED_TOPOLOGY)
        self.assertIn("no longer exists", topology.detail)

    def test_a_manager_leaf_that_no_longer_holds_the_controller_fails_closed(self) -> None:
        manager = Path(tempfile.mkdtemp(prefix="admissible-b25-replaced-"))
        self.addCleanup(shutil.rmtree, manager, True)
        (manager / "cgroup.procs").write_text("", encoding="utf-8")
        rl._TOPOLOGY = rl.CgroupTopology(
            initialized=True,
            code=rl.TOPOLOGY_INITIALIZED,
            detail="replaced",
            unified_root="/sys/fs/cgroup",
            effect_parent=str(manager.parent),
            manager_leaf=str(manager),
            owner_pid=os.getpid(),
        )
        topology = initialize_cgroup_topology()
        self.assertEqual(topology.code, rl.TOPOLOGY_STALE_CACHED_TOPOLOGY)
        self.assertIn("no longer a member", topology.detail)

    def test_the_supervisor_delegation_cache_is_pid_bound(self) -> None:
        saved_cache, saved_pid = ps._DELEGATION_CACHE, ps._DELEGATION_PID
        try:
            sentinel = CgroupDelegation(True, "inherited", "/x", "/x", ("memory", "pids"))
            ps._DELEGATION_CACHE = sentinel
            ps._DELEGATION_PID = -1
            self.assertIsNot(ps.cgroup_delegation(), sentinel)
            self.assertEqual(ps._DELEGATION_PID, os.getpid())
        finally:
            ps._DELEGATION_CACHE, ps._DELEGATION_PID = saved_cache, saved_pid


class KernelWriteTests(unittest.TestCase):
    """Complete writes, explicit newlines, exact readback."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="admissible-b25-write-"))
        self.addCleanup(shutil.rmtree, self.directory, True)

    def test_a_short_write_is_classified_and_never_retried_into_another_value(self) -> None:
        target = self.directory / "pids.max"
        target.write_text("", encoding="utf-8")
        with mock.patch.object(os, "write", return_value=2):
            error = rl._write_control(target, "64\n")
        self.assertIsNotNone(error)
        self.assertTrue(error.startswith("SHORT_WRITE:"))

    def test_a_write_failure_is_classified_by_errno(self) -> None:
        target = self.directory / "unwritable"
        target.write_text("", encoding="utf-8")
        os.chmod(target, 0o400)
        self.addCleanup(os.chmod, target, 0o600)
        self.assertEqual(rl._write_control(target, "1\n"), "EACCES")

    def test_max_is_never_accepted_as_a_finite_bound(self) -> None:
        (self.directory / "memory.max").write_text("max\n", encoding="utf-8")
        (self.directory / "pids.max").write_text("max\n", encoding="utf-8")
        code, detail, observed = rl._apply_and_read_back_limits(
            self.directory, {"memory.max": 10, "pids.max": 5}
        )
        # The write succeeded against the plain file; the readback is what refuses.
        self.assertIn(code, {rl.TOPOLOGY_LIMIT_READBACK_MISMATCH, rl.TOPOLOGY_LIMIT_WRITE_FAILED})
        self.assertEqual(observed, {})

    def test_a_surprising_kernel_value_is_refused(self) -> None:
        real_read = rl._read_control
        (self.directory / "pids.max").write_text("", encoding="utf-8")
        (self.directory / "memory.max").write_text("", encoding="utf-8")

        def surprising(path: Path, **kwargs):
            if path.name == "pids.max":
                return "unbounded", None
            return real_read(path, **kwargs)

        with mock.patch.object(rl, "_read_control", surprising):
            code, detail, observed = rl._apply_and_read_back_limits(
                self.directory, {"memory.max": 10, "pids.max": 5}
            )
        self.assertEqual(code, rl.TOPOLOGY_LIMIT_READBACK_MISMATCH)
        self.assertIn("unbounded", detail)

    def test_a_wrong_readback_value_is_refused(self) -> None:
        real_read = rl._read_control
        (self.directory / "pids.max").write_text("", encoding="utf-8")

        def wrong(path: Path, **kwargs):
            if path.name == "pids.max":
                return "63\n", None
            return real_read(path, **kwargs)

        with mock.patch.object(rl, "_read_control", wrong):
            code, detail, _ = rl._apply_and_read_back_limits(self.directory, {"pids.max": 64})
        self.assertEqual(code, rl.TOPOLOGY_LIMIT_READBACK_MISMATCH)
        self.assertIn("not the intended 64", detail)

    def test_an_exact_readback_reports_the_kernel_value(self) -> None:
        (self.directory / "pids.max").write_text("", encoding="utf-8")
        (self.directory / "memory.max").write_text("", encoding="utf-8")
        code, _, observed = rl._apply_and_read_back_limits(
            self.directory, {"pids.max": 64, "memory.max": 2 * 1024**3}
        )
        self.assertIsNone(code)
        self.assertEqual(observed, {"pids.max": 64, "memory.max": 2 * 1024**3})


class EffectCgroupTests(unittest.TestCase):
    """Directory creation alone is never success."""

    def setUp(self) -> None:
        self.parent = Path(tempfile.mkdtemp(prefix="admissible-b25-effect-"))
        self.addCleanup(shutil.rmtree, self.parent, True)
        self.delegation = CgroupDelegation(
            available=True,
            detail="fixture",
            unified_root=str(self.parent),
            delegated_path=str(self.parent),
            controllers=("memory", "pids"),
        )
        self.bounds = ResourceBounds.for_timeout(1000)

    def _cgroup(self, label: str) -> EffectCgroup:
        return EffectCgroup(self.delegation, self.bounds, label)

    def _assert_no_effect_is_claimed(self, cgroup: EffectCgroup) -> None:
        """A refused setup claims no cgroup and leaves nothing it did not write.

        Removal is attempted unconditionally.  On a real cgroup2 filesystem
        ``rmdir`` of an owned, member-free cgroup succeeds and the directory is
        gone -- that is asserted physically in
        :class:`DelegatedCgroupTopologyTests`.  On the constructed tree used
        here the limit files this module just wrote are ordinary files, so the
        directory survives its own ``rmdir``; what must still hold is that no
        effect cgroup is claimed and that nothing beyond those limit files was
        created or adopted.
        """

        self.assertIsNone(cgroup.path)
        self.assertFalse(cgroup.active)
        self.assertFalse(cgroup.directory_present)
        self.assertEqual(cgroup.applied, {})
        leftover = {
            entry.name
            for directory in self.parent.iterdir()
            for entry in directory.iterdir()
        }
        self.assertLessEqual(leftover, {"pids.max", "memory.max"})

    def test_an_unsafe_label_is_refused(self) -> None:
        for label in ("../escape", "a/b", "", ".hidden", "x" * 200):
            with self.subTest(label=label):
                cgroup = self._cgroup(label)
                self.assertFalse(cgroup.create())
                self.assertEqual(cgroup.create_error, rl.TOPOLOGY_INVALID_LABEL)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_an_existing_directory_is_never_adopted(self) -> None:
        squatter = self.parent / f"{rl.EFFECT_PREFIX}dup"
        squatter.mkdir()
        (squatter / "marker").write_text("theirs", encoding="utf-8")
        cgroup = self._cgroup("dup")
        self.assertFalse(cgroup.create())
        self.assertEqual(cgroup.create_error, rl.TOPOLOGY_EFFECT_COLLISION)
        self.assertTrue((squatter / "marker").exists())
        self.assertIsNone(cgroup.path)

    def test_a_limit_write_failure_removes_the_owned_empty_cgroup(self) -> None:
        real_write = rl._write_control
        with mock.patch.object(
            rl,
            "_write_control",
            lambda path, payload, **kw: "EACCES" if path.name == "pids.max" else real_write(path, payload, **kw),
        ):
            cgroup = self._cgroup("wfail")
            self.assertFalse(cgroup.create())
        self.assertIn(rl.TOPOLOGY_LIMIT_WRITE_FAILED, cgroup.create_error)
        self._assert_no_effect_is_claimed(cgroup)

    def test_a_memory_limit_write_failure_removes_the_owned_empty_cgroup(self) -> None:
        real_write = rl._write_control
        with mock.patch.object(
            rl,
            "_write_control",
            lambda path, payload, **kw: "EACCES" if path.name == "memory.max" else real_write(path, payload, **kw),
        ):
            cgroup = self._cgroup("mfail")
            self.assertFalse(cgroup.create())
        self.assertIn(rl.TOPOLOGY_LIMIT_WRITE_FAILED, cgroup.create_error)
        self._assert_no_effect_is_claimed(cgroup)

    def test_a_pids_readback_mismatch_refuses(self) -> None:
        real_read = rl._read_control
        with mock.patch.object(
            rl,
            "_read_control",
            lambda path, **kw: ("1\n", None) if path.name == "pids.max" else real_read(path, **kw),
        ):
            cgroup = self._cgroup("prb")
            self.assertFalse(cgroup.create())
        self.assertIn(rl.TOPOLOGY_LIMIT_READBACK_MISMATCH, cgroup.create_error)
        self._assert_no_effect_is_claimed(cgroup)

    def test_a_memory_readback_mismatch_refuses(self) -> None:
        real_read = rl._read_control
        with mock.patch.object(
            rl,
            "_read_control",
            lambda path, **kw: ("max\n", None) if path.name == "memory.max" else real_read(path, **kw),
        ):
            cgroup = self._cgroup("mrb")
            self.assertFalse(cgroup.create())
        self.assertIn(rl.TOPOLOGY_LIMIT_READBACK_MISMATCH, cgroup.create_error)
        self._assert_no_effect_is_claimed(cgroup)

    def test_applied_values_are_the_ones_read_back(self) -> None:
        cgroup = self._cgroup("ok")
        self.assertTrue(cgroup.create())
        self.assertEqual(
            cgroup.applied,
            {"pids.max": self.bounds.max_processes, "memory.max": self.bounds.max_address_space_bytes},
        )
        self.assertFalse(cgroup.active, "creation is not membership")

    def test_an_undelegated_host_leaves_the_cgroup_layer_inert(self) -> None:
        inert = EffectCgroup(
            CgroupDelegation(False, "none", None, None, ()), self.bounds, "inert"
        )
        self.assertTrue(inert.create())
        self.assertFalse(inert.directory_present)
        self.assertFalse(inert.active)


class RefusalOrderingTests(unittest.TestCase):
    """A failed attach must leave the command unexecuted."""

    def test_a_failed_membership_verification_never_reports_cgroup_containment(self) -> None:
        delegation = CgroupDelegation(True, "fixture", "/x", "/x", ("memory", "pids"))
        self.assertEqual(
            effective_mechanism(
                delegation,
                membership_verified=False,
                required_mechanism=MECHANISM_CGROUP_AND_RLIMIT,
            ),
            MECHANISM_NONE,
        )

    def test_attach_and_verify_real_refuses_a_synthetic_procs_file(self) -> None:
        parent = Path(tempfile.mkdtemp(prefix="admissible-b25-synth-"))
        self.addCleanup(shutil.rmtree, parent, True)
        delegation = CgroupDelegation(True, "fixture", str(parent), str(parent), ("memory", "pids"))
        cgroup = EffectCgroup(delegation, ResourceBounds.for_timeout(1000), "synth")
        self.assertTrue(cgroup.create())
        (Path(cgroup.path) / "cgroup.procs").write_text("", encoding="utf-8")
        self.assertFalse(attach_and_verify_real(cgroup, os.getpid()))
        self.assertFalse(cgroup.active)

    def test_the_launch_order_places_verification_before_release(self) -> None:
        self.assertLess(
            LAUNCH_ORDER.index("VERIFY_KERNEL_MEMBERSHIP"), LAUNCH_ORDER.index("RELEASE_GATE")
        )
        self.assertLess(LAUNCH_ORDER.index("RELEASE_GATE"), LAUNCH_ORDER.index("EXEC_LAUNCHER"))


class LifecycleTests(unittest.TestCase):
    def test_the_manager_leaf_is_not_claimed_to_be_removed(self) -> None:
        lifecycle = topology_lifecycle_description()
        self.assertFalse(lifecycle["manager_leaf"]["removed_by_this_process"])
        self.assertIn("transient systemd unit", lifecycle["manager_leaf"]["reclaimed_by"])
        self.assertIn("not a leak-free manual removal", lifecycle["manager_leaf"]["leak_claim"])
        self.assertIn("quiescent", lifecycle["effect_cgroup"]["removed"])

    def test_a_cgroup_with_live_members_is_never_reported_removed(self) -> None:
        parent = Path(tempfile.mkdtemp(prefix="admissible-b25-live-"))
        self.addCleanup(shutil.rmtree, parent, True)
        delegation = CgroupDelegation(True, "fixture", str(parent), str(parent), ("memory", "pids"))
        cgroup = EffectCgroup(delegation, ResourceBounds.for_timeout(1000), "live")
        self.assertTrue(cgroup.create())
        (Path(cgroup.path) / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="utf-8")
        self.assertFalse(cgroup.close())
        self.assertTrue(cgroup.directory_present)


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


class _EffectCgroupObserver(threading.Thread):
    """Watch the delegated parent for per-effect cgroups while an effect runs."""

    def __init__(self, parent: Path) -> None:
        super().__init__(daemon=True)
        self.parent = parent
        self.stop_event = threading.Event()
        self.observations: list[dict] = []

    def run(self) -> None:
        while not self.stop_event.is_set():
            for entry in sorted(self.parent.glob(f"{rl.EFFECT_PREFIX}*")):
                membership = rl.read_cgroup_members(entry)
                if not membership.observed_populated:
                    continue
                self.observations.append(
                    {
                        "path": str(entry),
                        "members": list(membership.pids),
                        "pids.max": rl._parse_limit(rl._read_control(entry / "pids.max")[0]),
                        "memory.max": rl._parse_limit(rl._read_control(entry / "memory.max")[0]),
                    }
                )
            time.sleep(0.02)

    def stop(self) -> dict | None:
        self.stop_event.set()
        self.join(timeout=5)
        if not self.observations:
            return None
        return max(self.observations, key=lambda item: len(item["members"]))


DESCENDANT_SCRIPT = """
import os, time
mine = open('/proc/self/cgroup').read().strip()
read_fd, write_fd = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_fd)
    os.write(write_fd, open('/proc/self/cgroup').read().strip().encode())
    time.sleep(2.0)
    os._exit(0)
os.close(write_fd)
child = os.read(read_fd, 4096).decode()
os.waitpid(pid, 0)
open('cgroup_evidence.txt', 'w').write(mine + chr(10) + child + chr(10))
"""

SENTINEL_SCRIPT = "open('sentinel.txt', 'w').write('the command executed')\n"


class DelegatedCgroupTopologyTests(unittest.TestCase):
    """Physical qualification against a real Delegate=yes cgroup v2 subtree."""

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
    def test_real_delegated_cgroup_bootstrap_and_effect_limits(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        topology = initialize_cgroup_topology()
        self.assertTrue(topology.initialized, topology.detail)
        manager = Path(topology.manager_leaf)
        parent = Path(topology.effect_parent)

        self.assertTrue(rl.is_cgroup2_filesystem(parent))
        self.assertEqual(manager.parent, parent)
        manager_members = rl.read_cgroup_members(manager)
        self.assertTrue(manager_members.usable, manager_members.refusal_detail())
        self.assertIn(os.getpid(), manager_members.pids)
        parent_members = rl.read_cgroup_members(parent)
        self.assertTrue(
            parent_members.observed_empty,
            f"the effect parent must be observed unpopulated: {parent_members.to_dict()}",
        )
        enabled, _ = rl._enabled_controllers(parent)
        self.assertEqual({"memory", "pids"} & set(enabled), {"memory", "pids"})

        bounds = ResourceBounds.for_timeout(1000)
        cgroup = EffectCgroup(DELEGATION, bounds, f"unit-{os.getpid()}")
        self.assertTrue(cgroup.create(), cgroup.create_error)
        try:
            self.assertEqual(Path(cgroup.path).parent, parent)
            self.assertEqual(
                cgroup.applied,
                {
                    "pids.max": bounds.max_processes,
                    "memory.max": bounds.max_address_space_bytes,
                },
            )
            self.assertEqual(
                rl._parse_limit(rl._read_control(Path(cgroup.path) / "pids.max")[0]),
                bounds.max_processes,
            )
            self.assertEqual(
                rl._parse_limit(rl._read_control(Path(cgroup.path) / "memory.max")[0]),
                bounds.max_address_space_bytes,
            )
        finally:
            self.assertTrue(cgroup.close())
        self.assertFalse(Path(str(parent / f"{rl.EFFECT_PREFIX}unit-{os.getpid()}")).exists())

    @delegated
    def test_production_command_is_member_before_gate_release(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        self.assertEqual(CAPSULE_READY.containment_mechanism, MECHANISM_CGROUP_AND_RLIMIT)

        events: list[tuple[str, float, object]] = []
        real_attach = ps.attach_and_verify_real
        real_release = SpawnedLauncher.release

        def observing_attach(cgroup, pid):
            before = {
                "comm": _read_text_or_none(f"/proc/{pid}/comm"),
                "members_before": sorted(cgroup.members()),
            }
            result = real_attach(cgroup, pid)
            events.append(
                (
                    "attach",
                    time.monotonic(),
                    {
                        **before,
                        "result": result,
                        "members_after": sorted(cgroup.members()),
                        "effect_path": cgroup.path,
                        "proc_pid_cgroup": rl._pid_unified_cgroup(pid),
                    },
                )
            )
            return result

        def observing_release(self_launcher):
            events.append(("release", time.monotonic(), {"pid": self_launcher.pid}))
            return real_release(self_launcher)

        harness = _Harness(run_id="run-b25-member")
        self.addCleanup(harness.close)
        with mock.patch.object(ps, "attach_and_verify_real", observing_attach), mock.patch.object(
            SpawnedLauncher, "release", observing_release
        ):
            outcome = harness.command("print('bounded by a real cgroup')\n")

        self.assertEqual(outcome.receipt.status, "COMPLETED")
        kinds = [name for name, _, _ in events]
        self.assertIn("attach", kinds)
        self.assertIn("release", kinds)
        self.assertLess(kinds.index("attach"), kinds.index("release"))
        attach_event = next(payload for name, _, payload in events if name == "attach")
        self.assertTrue(attach_event["result"])
        self.assertEqual(attach_event["members_before"], [])
        self.assertTrue(attach_event["members_after"], "membership was observed from the kernel")
        # The child had not exec'd the launcher: it was still the trusted
        # helper's forked interpreter, blocked in the gate read.
        self.assertNotIn("bwrap", (attach_event["comm"] or ""))

        resource = harness.store.load("resource-observation", "proposal-1")
        self.assertEqual(resource["containment_mechanism"], MECHANISM_CGROUP_AND_RLIMIT)
        self.assertEqual(resource["containment_availability"], "OBSERVED")
        bounds = ResourceBounds.for_timeout(60_000)
        self.assertIn(f"cgroup.pids.max={bounds.max_processes}", resource["containment_bounds"])
        self.assertIn(
            f"cgroup.memory.max={bounds.max_address_space_bytes}", resource["containment_bounds"]
        )

    @delegated
    def test_failed_membership_verification_executes_no_command(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        harness = _Harness(run_id="run-b25-refuse")
        self.addCleanup(harness.close)
        released: list[int] = []
        real_release = SpawnedLauncher.release

        def recording_release(self_launcher):
            released.append(self_launcher.pid)
            return real_release(self_launcher)

        def refusing_attach(cgroup, pid):
            cgroup.attach_error = "injected_membership_refusal"
            return False

        with mock.patch.object(ps, "attach_and_verify_real", refusing_attach), mock.patch.object(
            SpawnedLauncher, "release", recording_release
        ):
            outcome = harness.command(SENTINEL_SCRIPT)

        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(released, [], "the gate was never released")
        self.assertFalse(
            (harness.workspace / "sentinel.txt").exists(),
            "the proposed command executed despite a refused membership proof",
        )
        # No per-effect cgroup was left behind by the refusal.
        parent = Path(DELEGATION.delegated_path)
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [])

    @delegated
    def test_descendant_inherits_effect_cgroup(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        parent = Path(DELEGATION.delegated_path)
        observer = _EffectCgroupObserver(parent)
        harness = _Harness(run_id="run-b25-descendant")
        self.addCleanup(harness.close)
        observer.start()
        try:
            outcome = harness.command(DESCENDANT_SCRIPT)
        finally:
            best = observer.stop()

        self.assertEqual(outcome.receipt.status, "COMPLETED")
        evidence = (harness.workspace / "cgroup_evidence.txt").read_text(encoding="utf-8").split("\n")
        command_cgroup, descendant_cgroup = evidence[0], evidence[1]
        self.assertTrue(command_cgroup)
        self.assertEqual(
            command_cgroup,
            descendant_cgroup,
            "a descendant left the effect cgroup its parent was placed in",
        )

        self.assertIsNotNone(best, "the controller never observed a populated effect cgroup")
        self.assertGreaterEqual(
            len(best["members"]), 2, f"the descendant was not accounted to the effect cgroup: {best}"
        )
        bounds = ResourceBounds.for_timeout(60_000)
        self.assertEqual(best["pids.max"], bounds.max_processes)
        self.assertEqual(best["memory.max"], bounds.max_address_space_bytes)
        self.assertEqual(Path(best["path"]).parent, parent)

        resource = harness.store.load("resource-observation", "proposal-1")
        self.assertEqual(resource["containment_mechanism"], MECHANISM_CGROUP_AND_RLIMIT)
        # The effect cgroup is removed once the process tree is quiescent.
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [])

    @delegated
    def test_repeated_production_effects_reuse_one_manager_topology(self) -> None:
        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        topology = initialize_cgroup_topology()
        parent = Path(topology.effect_parent)
        harness = _Harness(run_id="run-b25-repeat")
        self.addCleanup(harness.close)
        for _ in range(3):
            outcome = harness.command("print('again')\n")
            self.assertEqual(outcome.receipt.status, "COMPLETED")
            again = initialize_cgroup_topology()
            self.assertTrue(again.initialized, again.detail)
            self.assertEqual(again.manager_leaf, topology.manager_leaf)
            self.assertIs(again, topology)

        leaves = sorted(parent.glob(f"{rl.MANAGER_LEAF_PREFIX}*"))
        self.assertEqual(
            [str(path) for path in leaves],
            [topology.manager_leaf],
            "a second manager leaf was created",
        )
        self.assertEqual(list(parent.glob(f"{rl.EFFECT_PREFIX}*")), [], "effect cgroups leaked")
        self.assertEqual(list(parent.glob(f"{rl.PROBE_PREFIX}*")), [], "probe cgroups leaked")


def _read_text_or_none(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


if __name__ == "__main__":
    unittest.main()
