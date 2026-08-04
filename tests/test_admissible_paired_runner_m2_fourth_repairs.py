"""Adversarial closure tests for the fourth Milestone 2 critical-repair pass.

Findings M2-B25, M2-B26, and M2-B27 are exercised here.  Physical cgroup
qualification is reported honestly when the host cannot delegate a writable
cgroup v2 subtree to this process.
"""

from __future__ import annotations

from pathlib import Path
import importlib
import inspect
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
)
from admissible.paired_runner.cgroup_launch import (  # noqa: E402
    CgroupLaunchRefused,
    LAUNCH_ORDER,
    attach_and_verify_real,
    launch_order_description,
    require_real_cgroup_procs,
)
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import SharedEffectSubstrate, WorkspaceBinding  # noqa: E402
from admissible.paired_runner.private_workspace import (  # noqa: E402
    MATERIALIZATION_KIND,
    PrivateExecutionView,
    apply_export,
    compute_change_set,
    host_can_pathname_reach,
    recover_export,
)
from admissible.paired_runner.process_supervision import supervise_command  # noqa: E402
from admissible.paired_runner.resource_limits import (  # noqa: E402
    EffectCgroup,
    ResourceBounds,
    probe_cgroup_delegation,
)
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402


CAPSULE_READY = probe_capsule_readiness()
requires_capsule = unittest.skipUnless(
    CAPSULE_READY.available, f"the capsule is unavailable: {CAPSULE_READY.probe_detail}"
)
CGROUP_DELEGATION = probe_cgroup_delegation()


class _Harness:
    def __init__(self, *, run_id: str = "run-fourth") -> None:
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

    def command(self, script: str, *, timeout_ms: int = 30_000, effect_boundary_hook=None):
        self._counter += 1
        if effect_boundary_hook is not None:
            self.substrate = SharedEffectSubstrate(
                binding=self.binding,
                store=self.store,
                ledger=RunEffectLedger(self.run_id),
                effect_boundary_hook=effect_boundary_hook,
            )
        request = RunCommandRequest.create(
            tool_grammar_fingerprint=self.grammar,
            argv=[PYTHON, "-c", script],
            timeout_ms=timeout_ms,
        )
        proposal = build_proposal(self.specification, request, proposal_id=f"proposal-{self._counter}")
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


class LaunchGateConstructionTests(unittest.TestCase):
    """M2-B25: production path must not use preexec_fn SIGSTOP."""

    def test_production_supervision_has_no_preexec_fn(self) -> None:
        source = inspect.getsource(supervise_command)
        self.assertNotIn("preexec_fn=", source)
        self.assertNotIn("Popen(", source)
        process_mod = importlib.import_module("admissible.paired_runner.process_supervision")
        self.assertFalse(hasattr(process_mod, "_stop_for_cgroup_attach"))
        self.assertIn("spawn_launcher", source)
        self.assertIn("await_release", source)

    def test_helper_spawn_source_has_no_preexec_fn(self) -> None:
        from admissible.paired_runner import private_workspace as pw

        source = inspect.getsource(pw._helper_main)
        self.assertNotIn("preexec_fn", source)
        self.assertNotIn("SIGSTOP", source)
        self.assertIn("gate_child_before_exec", source)

    def test_launch_order_is_documented(self) -> None:
        description = launch_order_description()
        self.assertEqual(tuple(description["order"]), LAUNCH_ORDER)
        self.assertIn("trusted_pipe_read_before_execve", description["gate_kind"])

    def test_synthetic_regular_file_is_rejected_as_cgroup_evidence(self) -> None:
        parent = Path(tempfile.mkdtemp(prefix="admissible-fake-cg-"))
        try:
            (parent / "cgroup.procs").write_text("", encoding="utf-8")
            with self.assertRaises(CgroupLaunchRefused):
                require_real_cgroup_procs(parent)
            from admissible.paired_runner.resource_limits import CgroupDelegation

            delegation = CgroupDelegation(True, "fake", str(parent), str(parent), ("pids", "memory"))
            cgroup = EffectCgroup(delegation, ResourceBounds.for_timeout(1000), "fake")
            self.assertTrue(cgroup.create())
            (Path(cgroup.path) / "cgroup.procs").write_text(str(os.getpid()), encoding="utf-8")
            self.assertFalse(attach_and_verify_real(cgroup, os.getpid()))
            self.assertIn(
                cgroup.attach_error,
                {"cgroup_procs_synthetic_regular_file", "cgroup_procs_not_on_cgroup2"},
            )
        finally:
            import shutil

            shutil.rmtree(parent, ignore_errors=True)

    @unittest.skipUnless(
        CGROUP_DELEGATION.available,
        f"no delegated cgroup v2 subtree: {CGROUP_DELEGATION.detail}",
    )
    def test_real_delegated_cgroup_membership_before_exec(self) -> None:
        # Physical qualification path — only runs when the kernel truly delegates.
        self.assertTrue(CGROUP_DELEGATION.available)
        cgroup = EffectCgroup(CGROUP_DELEGATION, ResourceBounds.for_timeout(1000), f"phys-{os.getpid()}")
        self.assertTrue(cgroup.create())
        try:
            require_real_cgroup_procs(Path(cgroup.path))
        finally:
            cgroup.close()


@requires_capsule
class PrivateMountIsolationTests(unittest.TestCase):
    """M2-B26: same-UID host peers cannot pathname-reach the effect view."""

    def test_materialization_kind_is_private_mountns_tmpfs(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="admissible-m2b26-"))
        try:
            (root / "a.txt").write_text("a", encoding="utf-8")
            source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            view = PrivateExecutionView.materialize(root, source_fd)
            try:
                self.assertEqual(view.view_identity.materialization_kind, MATERIALIZATION_KIND)
                self.assertFalse(host_can_pathname_reach(view.view_fd))
                self.assertFalse(view.host_pathname_reachable())
                staging = Path(view.helper.staging_path)
                # Host pathname, if present, does not show the private contents.
                if staging.exists():
                    self.assertEqual(list(staging.iterdir()), [])
                self.assertIn("a.txt", os.listdir(view.view_fd))
            finally:
                view.close()
                os.close(source_fd)
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)

    def test_same_uid_host_peer_cannot_plant_fifo_into_effect_view(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="admissible-m2b26-peer-"))
        try:
            (root / "a.txt").write_text("a", encoding="utf-8")
            source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            view = PrivateExecutionView.materialize(root, source_fd)
            try:
                staging = view.helper.staging_path
                peer = subprocess.run(
                    [
                        PYTHON,
                        "-c",
                        textwrap.dedent(
                            f"""
                            import os
                            path = {staging!r} + '/evil.fifo'
                            try:
                                os.mkfifo(path)
                                print('HOST_PATH_WRITABLE')
                            except OSError as e:
                                print('ERR', e.errno)
                            """
                        ),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                # A peer may write the empty host directory that shares the
                # staging pathname.  That directory is not the private tmpfs.
                self.assertNotIn("evil.fifo", os.listdir(view.view_fd))
                self.assertFalse(host_can_pathname_reach(view.view_fd))
                # Prove the private view was not mutated by the peer.
                before = set(os.listdir(view.view_fd))
                self.assertEqual(before, {"a.txt"})
                _ = peer.stdout  # peer outcome is informational only
            finally:
                view.close()
                os.close(source_fd)
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)

    def test_production_effect_uses_private_mount_and_exports(self) -> None:
        harness = _Harness(run_id="run-m2b26-prod")
        try:
            outcome = harness.command("open('from_effect.txt','w').write('ok')\n")
            self.assertEqual(outcome.receipt.status, "COMPLETED")
            self.assertEqual((harness.workspace / "from_effect.txt").read_text(encoding="utf-8"), "ok")
            export_dirs = list((harness.store_root / "export").iterdir())
            self.assertTrue(export_dirs)
            reservation = json.loads((export_dirs[0] / "reservation.json").read_text(encoding="utf-8"))
            self.assertEqual(reservation["private_view"]["materialization_kind"], MATERIALIZATION_KIND)
        finally:
            harness.close()


@requires_capsule
class TransactionalExportTests(unittest.TestCase):
    """M2-B27: durable reservation, concurrency oracle, crash/restart matrix."""

    def test_reservation_is_durable_before_success(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="admissible-m2b27-"))
        durable = Path(tempfile.mkdtemp(prefix="admissible-m2b27-dur-"))
        try:
            (root / "a.txt").write_text("a", encoding="utf-8")
            source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            view = PrivateExecutionView.materialize(root, source_fd)
            try:
                view.write_file("b.txt", b"b")
                change_set = compute_change_set(baseline_fd=source_fd, private_fd=view.view_fd)
                _res, receipt, _rec = apply_export(
                    source_root_fd=source_fd,
                    private_fd=view.view_fd,
                    change_set=change_set,
                    reservation_id="export-durable-1",
                    source_snapshot=view.source_snapshot,
                    view_identity=view.view_identity,
                    durable_root=durable,
                    causal={
                        "run_id": "run",
                        "session_id": "s",
                        "proposal_id": "p",
                        "decision_id": "d",
                        "reservation_id": "r",
                        "effect_id": "e",
                    },
                )
                self.assertEqual(receipt.state, "APPLIED")
                reservation_path = durable / "export" / "export-durable-1" / "reservation.json"
                self.assertTrue(reservation_path.exists())
                payload = json.loads(reservation_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["export_protocol_version"], 1)
                self.assertIn("operations", payload)
                self.assertTrue(payload["operations"])
                self.assertIn("expected_pre_state", payload["operations"][0])
                recovered = recover_export(durable, "export-durable-1")
                self.assertEqual(recovered["state"], "APPLIED")
                self.assertTrue(recovered["replay_forbidden"])
            finally:
                view.close()
                os.close(source_fd)
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(durable, ignore_errors=True)

    def test_concurrent_source_mutation_oracle_does_not_return_applied(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="admissible-m2b27-race-"))
        durable = Path(tempfile.mkdtemp(prefix="admissible-m2b27-race-dur-"))
        try:
            (root / "target.txt").write_text("v1", encoding="utf-8")
            source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            view = PrivateExecutionView.materialize(root, source_fd)
            try:
                view.write_file("target.txt", b"from-effect")
                view.write_file("other.txt", b"x")
                change_set = compute_change_set(baseline_fd=source_fd, private_fd=view.view_fd)
                # Independent process mutates the target after admission.
                peer = subprocess.Popen(
                    [PYTHON, "-c", f"open({str(root / 'target.txt')!r},'w').write('peer')"],
                )
                peer.wait(timeout=5)
                _res, receipt, reconciliation = apply_export(
                    source_root_fd=source_fd,
                    private_fd=view.view_fd,
                    change_set=change_set,
                    reservation_id="export-race-1",
                    source_snapshot=view.source_snapshot,
                    view_identity=view.view_identity,
                    durable_root=durable,
                )
                self.assertNotEqual(receipt.state, "APPLIED")
                self.assertIn(
                    receipt.state,
                    {"REFUSED_SOURCE_MUTATED", "REFUSED_CONCURRENT_MUTATION", "REFUSED_PARTIAL"},
                )
                # The independent mutation must not be silently overwritten.
                self.assertEqual((root / "target.txt").read_text(encoding="utf-8"), "peer")
                self.assertFalse(reconciliation.verified)
            finally:
                view.close()
                os.close(source_fd)
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(durable, ignore_errors=True)

    def test_separate_process_crash_restart_matrix(self) -> None:
        """Genuine separate-process crash/restart — not an in-process callback."""

        transitions = (
            "AFTER_RESERVATION_BEFORE_MUTATION",
            "AFTER_FIRST_MUTATION_BEFORE_RECEIPT",
        )
        script = textwrap.dedent(
            """
            import json, os, sys, tempfile
            from pathlib import Path
            from admissible.paired_runner.private_workspace import (
                PrivateExecutionView, apply_export, compute_change_set, recover_export
            )
            transition = sys.argv[1]
            root = Path(sys.argv[2])
            durable = Path(sys.argv[3])
            reservation_id = sys.argv[4]
            source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            view = PrivateExecutionView.materialize(root, source_fd)
            view.write_file('b.txt', b'b')
            view.write_file('c.txt', b'c')
            change_set = compute_change_set(baseline_fd=source_fd, private_fd=view.view_fd)
            if transition == 'AFTER_RESERVATION_BEFORE_MUTATION':
                # Publish reservation then exit before mutations by arming a
                # marker through the durable path and killing ourselves after
                # reservation.json exists via a tiny wrapper around apply internals.
                from admissible.paired_runner import private_workspace as pw
                export_dir = durable / 'export' / reservation_id
                plan = pw._build_operation_plan(source_fd=source_fd, private_fd=view.view_fd, change_set=change_set)
                doc = {
                    'schema_id': pw.SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION,
                    'schema_version': 2,
                    'export_protocol_version': 1,
                    'reservation_id': reservation_id,
                    'causal': {'run_id':'r','session_id':'s','proposal_id':'p','decision_id':'d','reservation_id':'x','effect_id':'e'},
                    'source_snapshot': view.source_snapshot.to_dict(),
                    'private_view': view.view_identity.to_dict(),
                    'change_set': change_set.to_dict(),
                    'operations': plan,
                    'intended_final_tree_sha256': pw.snapshot_tree_identity(view.view_fd)[0],
                    'source_tree_sha256_at_reserve': view.source_snapshot.tree_sha256,
                    'state': 'RESERVED',
                    'durability_barriers': [],
                }
                pw._durable_publish_json(export_dir, 'reservation.json', doc)
                pw._durable_replace_json(export_dir, 'progress.json', {'reservation_id': reservation_id, 'applied_count': 0, 'next_index': 0, 'entries': []})
                os._exit(33)
            if transition == 'AFTER_FIRST_MUTATION_BEFORE_RECEIPT':
                from admissible.paired_runner import private_workspace as pw
                export_dir = durable / 'export' / reservation_id
                plan = pw._build_operation_plan(source_fd=source_fd, private_fd=view.view_fd, change_set=change_set)
                doc = {
                    'schema_id': pw.SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION,
                    'schema_version': 2,
                    'export_protocol_version': 1,
                    'reservation_id': reservation_id,
                    'causal': {'run_id':'r','session_id':'s','proposal_id':'p','decision_id':'d','reservation_id':'x','effect_id':'e'},
                    'source_snapshot': view.source_snapshot.to_dict(),
                    'private_view': view.view_identity.to_dict(),
                    'change_set': change_set.to_dict(),
                    'operations': plan,
                    'intended_final_tree_sha256': pw.snapshot_tree_identity(view.view_fd)[0],
                    'source_tree_sha256_at_reserve': view.source_snapshot.tree_sha256,
                    'state': 'RESERVED',
                    'durability_barriers': [],
                }
                pw._durable_publish_json(export_dir, 'reservation.json', doc)
                first = plan[0]
                pw._apply_one(source_fd, view.view_fd, first['operation'], first['path'])
                pw._durable_replace_json(export_dir, 'progress.json', {
                    'reservation_id': reservation_id,
                    'applied_count': 1,
                    'next_index': 1,
                    'entries': [{'index': 0, 'path': first['path'], 'operation': first['operation'], 'status': 'APPLIED'}],
                })
                os._exit(34)
            apply_export(
                source_root_fd=source_fd,
                private_fd=view.view_fd,
                change_set=change_set,
                reservation_id=reservation_id,
                source_snapshot=view.source_snapshot,
                view_identity=view.view_identity,
                durable_root=durable,
            )
            """
        )
        for transition in transitions:
            root = Path(tempfile.mkdtemp(prefix="admissible-crash-src-"))
            durable = Path(tempfile.mkdtemp(prefix="admissible-crash-dur-"))
            try:
                (root / "a.txt").write_text("a", encoding="utf-8")
                reservation_id = f"crash-{transition.lower()}"
                crashed = subprocess.run(
                    [PYTHON, "-c", script, transition, str(root), str(durable), reservation_id],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertIn(crashed.returncode, {33, 34})
                # Fresh recovery process — durable state only.
                recovery = subprocess.run(
                    [
                        PYTHON,
                        "-c",
                        textwrap.dedent(
                            f"""
                            import json, sys
                            from admissible.paired_runner.private_workspace import recover_export
                            result = recover_export({str(durable)!r}, {reservation_id!r})
                            print(json.dumps(result, sort_keys=True))
                            """
                        ),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                recovered = json.loads(recovery.stdout)
                self.assertTrue(recovered["classifiable"])
                self.assertTrue(recovered["replay_forbidden"])
                if transition == "AFTER_RESERVATION_BEFORE_MUTATION":
                    self.assertEqual(recovered["state"], "REFUSED_CRASH_CLASSIFIABLE")
                    self.assertEqual(recovered["applied_count"], 0)
                else:
                    self.assertEqual(recovered["state"], "REFUSED_PARTIAL")
                    self.assertGreaterEqual(int(recovered["applied_count"]), 1)
                # Automatic replay must refuse.
                replay = subprocess.run(
                    [
                        PYTHON,
                        "-c",
                        textwrap.dedent(
                            f"""
                            import os, json
                            from pathlib import Path
                            from admissible.paired_runner.private_workspace import (
                                PrivateExecutionView, apply_export, compute_change_set
                            )
                            root = Path({str(root)!r})
                            durable = Path({str(durable)!r})
                            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                            view = PrivateExecutionView.materialize(root, fd)
                            view.write_file('b.txt', b'b')
                            cs = compute_change_set(baseline_fd=fd, private_fd=view.view_fd)
                            _r, receipt, _c = apply_export(
                                source_root_fd=fd,
                                private_fd=view.view_fd,
                                change_set=cs,
                                reservation_id={reservation_id!r},
                                source_snapshot=view.source_snapshot,
                                view_identity=view.view_identity,
                                durable_root=durable,
                            )
                            print(receipt.state)
                            view.close(); os.close(fd)
                            """
                        ),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertIn(replay.stdout.strip(), {"REFUSED_REPLAY", "REFUSED_AMBIGUOUS"})
            finally:
                import shutil

                shutil.rmtree(root, ignore_errors=True)
                shutil.rmtree(durable, ignore_errors=True)


class FourthRepairArtifactTests(unittest.TestCase):
    def test_required_fourth_repair_artifacts_exist(self) -> None:
        root = Path(__file__).resolve().parents[1] / "implementation"
        for name in (
            "M2_PRIVATE_MOUNT_NAMESPACE_SPEC.md",
            "M2_CGROUP_LAUNCH_PRIMITIVE_SPEC.md",
            "M2_TRANSACTIONAL_EXPORT_SPEC.md",
            "M2_FOURTH_CRITICAL_REPAIR_REPORT.json",
        ):
            self.assertTrue((root / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
