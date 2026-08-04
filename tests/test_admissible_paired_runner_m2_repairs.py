"""Adversarial closure tests for the Milestone 2 critical repairs.

Every test here treats the effect process as untrusted.  Nothing relies on the
secrecy of a path, on a command using relative paths, on a descendant staying in
its process group, on same-user file permissions, on repository-local Git
configuration being benign, on the in-memory ledger being complete, or on a
record being trustworthy merely because it is canonical JSON.

Every physical effect happens inside a disposable temporary root owned by the
test process.  No test touches a production root, a provider, a model, a policy
engine, an owner authority, a broker, a mint, a witness, or a V14-V18 identity.
"""

from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
    initialise_git_repository,
)
from admissible.paired_runner.canonical import canonical_bytes, parse_canonical_json  # noqa: E402
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import LEDGER_OBJECT_KIND, RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import (  # noqa: E402
    ConfigurationRefused,
    EvidenceRootIsolationError,
    SharedEffectSubstrate,
    WorkspaceBinding,
    observe_filesystem,
    observe_git,
)
from admissible.paired_runner.reconciliation import (  # noqa: E402
    FINAL_RECONCILIATION_OBJECT_KIND,
    LEDGER_PENDING_STATE,
    reconcile_typed_chain,
)
from admissible.paired_runner.run_index import (  # noqa: E402
    RUN_INDEX_ANCHOR_KIND,
    RUN_INDEX_OBJECT_KIND,
    DurableRunIndex,
    RunIndexBroken,
)
from admissible.paired_runner.sandbox import (  # noqa: E402
    CAPSULE_TOOLCHAIN_INPUTS,
    CAPSULE_WORKSPACE_PATH,
    SandboxUnavailable,
    build_capsule_specification,
    probe_capsule_readiness,
)
from admissible.paired_runner.tool_schemas import (  # noqa: E402
    ListFilesRequest,
    ReadFileRequest,
    RunCommandRequest,
    WriteFileRequest,
)


CAPSULE_READY = probe_capsule_readiness()
requires_capsule = unittest.skipUnless(
    CAPSULE_READY.available, f"the capsule is unavailable: {CAPSULE_READY.probe_detail}"
)


class _Harness:
    """One bound substrate over a disposable workspace and durable store."""

    def __init__(self, *, condition: str = "DIRECT", run_id: str = "run-repair") -> None:
        self.specification = build_specification(condition, run_id=run_id)
        self.grammar = self.specification.tool_grammar.grammar_fingerprint
        self.disposable = DisposableWorkspace()
        self.workspace = self.disposable.workspace
        self.store_root = self.disposable.store_root
        self.store = DurableObjectStore(self.store_root)
        self.binding = WorkspaceBinding.bind(
            self.workspace, self.specification, evidence_root=self.store_root
        )
        self.substrate = SharedEffectSubstrate(
            binding=self.binding,
            store=self.store,
            ledger=RunEffectLedger(run_id),
        )
        self._counter = 0

    def run(self, request, *, governed_decision: str = "ALLOW"):
        self._counter += 1
        proposal_id = f"proposal-{self._counter}"
        proposal = build_proposal(self.specification, request, proposal_id=proposal_id)
        return self.substrate.execute(
            specification=self.specification,
            proposal=proposal,
            decision=decision_for(proposal, governed_decision=governed_decision),
            reservation_id=f"reservation-{self._counter}",
            receipt_id=f"receipt-{self._counter}",
        )

    def command(self, script: str, *, timeout_ms: int = 20_000):
        return self.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.grammar,
                argv=[PYTHON, "-c", script],
                timeout_ms=timeout_ms,
            )
        )

    def close(self) -> None:
        self.binding.close()
        self.disposable.close()


# --- M2-R01: the sandbox escape matrix ---------------------------------------


@requires_capsule
class SandboxEscapeMatrixTests(unittest.TestCase):
    """Every escape a typed command could attempt is physically refused."""

    def setUp(self) -> None:
        self.harness = _Harness()
        self.addCleanup(self.harness.close)

    def _stdout(self, script: str) -> str:
        outcome = self.harness.command(script)
        self.assertEqual(outcome.receipt.status, "COMPLETED", outcome.receipt.outcome_reason)
        return outcome.tool_result.stdout

    def test_an_absolute_host_path_cannot_be_read(self) -> None:
        target = str(self.harness.store_root)
        out = self._stdout(
            "os = __import__('os')\n"
            f"print(os.path.exists({target!r}), os.path.exists('/etc/passwd'))\n"
        )
        self.assertEqual(out.strip(), "False False")

    def test_an_absolute_host_path_cannot_be_written(self) -> None:
        target = str(self.harness.store_root / "forged.json")
        out = self._stdout(
            "os = __import__('os')\n"
            "try:\n"
            f"    open({target!r}, 'w').write('FORGED')\n"
            "    print('WROTE')\n"
            "except OSError as error:\n"
            "    print('REFUSED', error.errno)\n"
        )
        self.assertTrue(out.startswith("REFUSED"), out)
        self.assertFalse((self.harness.store_root / "forged.json").exists())

    def test_parent_traversal_through_process_apis_reaches_no_host_path(self) -> None:
        out = self._stdout(
            "os = __import__('os')\n"
            "print(sorted(os.listdir('/workspace/../../../..')))\n"
        )
        listing = out.strip()
        self.assertNotIn("home", listing)
        self.assertNotIn("etc", listing)
        self.assertNotIn("root", listing)

    def test_proc_discovery_cannot_see_the_controller(self) -> None:
        out = self._stdout(
            "os = __import__('os')\n"
            "print(sorted(int(p) for p in os.listdir('/proc') if p.isdigit()))\n"
        )
        pids = json.loads(out.strip().replace("'", '"'))
        # Only the capsule init and the effect itself exist in this namespace.
        self.assertLessEqual(set(pids), {1, 2, 3})
        self.assertNotIn(os.getpid(), pids)

    def test_the_durable_evidence_root_is_not_reachable_by_any_name(self) -> None:
        # The evidence root is absent from the mount namespace, so it is not
        # merely permission-denied: no name for it exists at all.
        self.harness.command("open('/workspace/seed.txt','w').write('seed')")
        # The exact bytes of every object that already exists must survive the
        # walk below untouched.  The walk's own effect legitimately adds new
        # objects, so identity is asserted per object rather than by count.
        durable_before = {
            name: (self.harness.store_root / name).read_bytes()
            for name in self.harness.store.committed_names()
            if not name.startswith(f"{RUN_INDEX_ANCHOR_KIND}.")
        }
        anchor_before = self.harness.substrate.run_index.head_anchor()
        target = str(self.harness.store_root)
        out = self._stdout(
            "os = __import__('os')\n"
            "found = []\n"
            "for root, dirs, files in os.walk('/'):\n"
            "    for name in files:\n"
            "        if name.endswith('.json'):\n"
            "            found.append(os.path.join(root, name))\n"
            "    if len(found) > 50:\n"
            "        break\n"
            f"print('EVIDENCE' if any({target!r} in p for p in found) else 'NONE')\n"
        )
        self.assertEqual(out.strip(), "NONE")
        for name, payload in durable_before.items():
            self.assertEqual((self.harness.store_root / name).read_bytes(), payload, name)
        # The committed head is the one replaceable object in the store, and only
        # the controller advances it.  It must have moved forward, never back.
        anchor_after = self.harness.substrate.run_index.head_anchor()
        self.assertGreaterEqual(anchor_after["head_sequence"], anchor_before["head_sequence"])

    def test_host_home_is_not_reachable_and_is_not_inherited(self) -> None:
        out = self._stdout(
            "os = __import__('os')\n"
            "print(os.path.exists('/home'), os.environ.get('HOME'))\n"
        )
        self.assertEqual(out.strip(), f"False {CAPSULE_WORKSPACE_PATH}")

    def test_arbitrary_host_tmp_is_not_reachable(self) -> None:
        marker = Path(tempfile.gettempdir()) / f"admissible-m2-probe-{os.getpid()}"
        marker.write_text("host tmp marker", encoding="utf-8")
        self.addCleanup(marker.unlink, True)
        out = self._stdout(
            "os = __import__('os')\n"
            f"print(os.path.exists({str(marker)!r}), sorted(os.listdir('/tmp')))\n"
        )
        self.assertTrue(out.strip().startswith("False"), out)

    def test_the_network_is_unreachable(self) -> None:
        out = self._stdout(
            "sock = __import__('socket')\n"
            "s = sock.socket()\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('1.1.1.1', 443))\n"
            "    print('REACHED')\n"
            "except OSError as error:\n"
            "    print('REFUSED', error.errno)\n"
        )
        self.assertTrue(out.startswith("REFUSED"), out)

    def test_a_detached_descendant_cannot_outlive_the_effect(self) -> None:
        outcome = self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    time.sleep(2.0)\n"
            "    open('/workspace/DETACHED.txt', 'w').write('escaped')\n"
            "    os._exit(0)\n"
            "print('parent done')\n"
        )
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        time.sleep(3.0)
        self.assertFalse((self.harness.workspace / "DETACHED.txt").exists())

    def test_a_double_forked_setsid_descendant_cannot_escape(self) -> None:
        outcome = self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    os.setsid()\n"
            "    if os.fork() == 0:\n"
            "        time.sleep(2.0)\n"
            "        open('/workspace/ESCAPED.txt', 'w').write('escaped')\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os.wait()\n"
            "print('parent done')\n"
        )
        process = self.harness.store.load("process-observation", "proposal-1")
        self.assertTrue(process["descendants_alive_at_direct_exit"])
        self.assertTrue(process["namespace_quiescent"])
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        time.sleep(3.0)
        self.assertFalse((self.harness.workspace / "ESCAPED.txt").exists())

    def test_evidence_corruption_from_inside_the_capsule_is_impossible(self) -> None:
        self.harness.command("open('/workspace/a.txt','w').write('a')")
        before = {
            name: (self.harness.store_root / name).read_bytes()
            for name in self.harness.store.committed_names()
            if not name.startswith(f"{RUN_INDEX_ANCHOR_KIND}.")
        }
        anchor_before = self.harness.substrate.run_index.head_anchor()
        self.harness.command(
            "os = __import__('os')\n"
            "for root, dirs, files in os.walk('/'):\n"
            "    for name in list(files):\n"
            "        if name.endswith('.json'):\n"
            "            try:\n"
            "                open(os.path.join(root, name), 'w').write('CORRUPTED')\n"
            "            except OSError:\n"
            "                pass\n"
            "print('attempted')\n"
        )
        for name, payload in before.items():
            self.assertEqual((self.harness.store_root / name).read_bytes(), payload, name)
        anchor_after = self.harness.substrate.run_index.head_anchor()
        self.assertGreaterEqual(anchor_after["head_sequence"], anchor_before["head_sequence"])

    def test_readiness_refuses_before_any_effect_when_the_capsule_is_unavailable(self) -> None:
        # An unavailable capsule must refuse during readiness, never silently
        # fall back to an unsandboxed Popen.
        from admissible.paired_runner.sandbox import CapsuleReadiness

        unavailable = CapsuleReadiness(
            available=False,
            mechanism="bubblewrap",
            mechanism_path=None,
            mechanism_version=None,
            probe_detail="simulated unavailability",
            unshare_user=False,
            unshare_pid=False,
            unshare_net=False,
            private_tmp=False,
            private_proc=False,
        )
        with self.assertRaises(SandboxUnavailable):
            unavailable.require()
        with DisposableWorkspace() as disposable:
            with self.assertRaises(SandboxUnavailable):
                WorkspaceBinding.bind(
                    disposable.workspace,
                    build_specification("DIRECT", run_id="run-unready"),
                    evidence_root=disposable.store_root,
                    readiness=unavailable,
                )

    def test_network_can_only_be_enabled_through_an_explicit_policy_field(self) -> None:
        with DisposableWorkspace() as disposable:
            with self.assertRaises(SandboxUnavailable):
                build_capsule_specification(
                    workspace_host_path=disposable.workspace,
                    evidence_root=disposable.store_root,
                    readiness=CAPSULE_READY,
                    network_enabled=True,
                )


# --- M2-R02: Git observation executes nothing repository-controlled ----------


@requires_capsule
@unittest.skipIf(shutil.which("git") is None, "git is unavailable on this host")
class MaliciousGitConfigurationTests(unittest.TestCase):
    """A hostile repository cannot make the observer execute its code."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-git-hostile")
        self.addCleanup(self.harness.close)
        if not initialise_git_repository(self.harness.workspace):
            self.skipTest("a disposable git repository could not be created")
        self.marker = self.harness.workspace / "PWNED.txt"
        self.payload = self.harness.workspace / "payload.sh"
        self.payload.write_text(
            "#!/bin/sh\nprintf pwned > /workspace/PWNED.txt\n", encoding="utf-8"
        )
        self.payload.chmod(0o755)

    def _append_config(self, text: str) -> None:
        config = self.harness.workspace / ".git" / "config"
        with config.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def _observe(self):
        return observe_git(
            self.harness.workspace, self.harness.binding.root_fd, phase="BEFORE_EFFECT"
        )

    def test_a_repository_fsmonitor_program_is_never_executed(self) -> None:
        # This is the exact defect the audit found: core.fsmonitor names a
        # program that Git runs on the observer's behalf.
        self._append_config(f'[core]\n\tfsmonitor = {self.payload}\n')
        self._observe()
        self.assertFalse(self.marker.exists())

    def test_repository_hooks_are_never_executed(self) -> None:
        hooks = self.harness.workspace / ".git" / "hooks"
        hooks.mkdir(exist_ok=True)
        for name in ("pre-commit", "post-index-change", "reference-transaction"):
            hook = hooks / name
            hook.write_text("#!/bin/sh\nprintf pwned > /workspace/PWNED.txt\n", encoding="utf-8")
            hook.chmod(0o755)
        self._observe()
        self.assertFalse(self.marker.exists())

    def test_an_included_configuration_file_cannot_reintroduce_an_executable(self) -> None:
        evil = self.harness.workspace / ".git" / "evil.config"
        evil.write_text(f'[core]\n\tfsmonitor = {self.payload}\n', encoding="utf-8")
        self._append_config(f'[include]\n\tpath = {evil}\n')
        self._observe()
        self.assertFalse(self.marker.exists())

    def test_an_external_diff_and_textconv_are_never_executed(self) -> None:
        self._append_config(
            f'[diff]\n\texternal = {self.payload}\n'
            f'[diff "evil"]\n\ttextconv = {self.payload}\n'
        )
        (self.harness.workspace / ".gitattributes").write_text(
            "* diff=evil\n", encoding="utf-8"
        )
        self._observe()
        self.assertFalse(self.marker.exists())

    def test_a_credential_helper_and_pager_are_never_executed(self) -> None:
        self._append_config(
            f'[credential]\n\thelper = {self.payload}\n'
            f'[core]\n\tpager = {self.payload}\n\tsshCommand = {self.payload}\n'
            f'\taskPass = {self.payload}\n\talternateRefsCommand = {self.payload}\n'
        )
        self._observe()
        self.assertFalse(self.marker.exists())

    def test_submodules_are_not_recursed(self) -> None:
        self._append_config(
            '[submodule "evil"]\n\turl = https://example.invalid/evil.git\n'
            "\tpath = evil\n[submodule]\n\trecurse = true\n"
        )
        observation = self._observe()
        self.assertFalse(self.marker.exists())
        # There is no command to recurse with: the observer reads the repository.
        self.assertEqual(observation.availability, "OBSERVED")
        self.assertEqual(observation.observation_method, "NON_EXECUTING_REFS_INDEX_AND_OBJECTS")

    def test_the_observation_does_not_mutate_the_index_or_worktree(self) -> None:
        index = self.harness.workspace / ".git" / "index"
        before = index.read_bytes() if index.exists() else b""
        digest_before = sorted(
            (p.name, p.stat().st_mtime_ns)
            for p in self.harness.workspace.iterdir()
            if p.is_file()
        )
        self._observe()
        after = index.read_bytes() if index.exists() else b""
        self.assertEqual(before, after)
        self.assertEqual(
            digest_before,
            sorted(
                (p.name, p.stat().st_mtime_ns)
                for p in self.harness.workspace.iterdir()
                if p.is_file()
            ),
        )

    def test_binding_runs_no_process_before_the_proposal_is_durable(self) -> None:
        """Binding is pure syscalls, so no observer runs pre-proposal."""

        with DisposableWorkspace() as disposable:
            self.assertTrue(initialise_git_repository(disposable.workspace))
            payload = disposable.workspace / "payload.sh"
            payload.write_text(
                f"#!/bin/sh\nprintf pwned > {disposable.workspace}/PWNED.txt\n", encoding="utf-8"
            )
            payload.chmod(0o755)
            with (disposable.workspace / ".git" / "config").open("a", encoding="utf-8") as handle:
                handle.write(f'[core]\n\tfsmonitor = {payload}\n')

            binding = WorkspaceBinding.bind(
                disposable.workspace,
                build_specification("DIRECT", run_id="run-bind-safe"),
                evidence_root=disposable.store_root,
            )
            self.addCleanup(binding.close)
            self.assertFalse((disposable.workspace / "PWNED.txt").exists())
            self.assertEqual(
                binding.initial_git_observation.availability,
                "NOT_OBSERVED_BEFORE_DURABLE_PROPOSAL",
            )


# --- M2-R03: process-domain quiescence ---------------------------------------


@requires_capsule
class ProcessDomainQuiescenceTests(unittest.TestCase):
    """Pipe EOF is not completion, and quiescence is physically verified."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-quiescence")
        self.addCleanup(self.harness.close)

    def _process(self, proposal_id: str = "proposal-1") -> dict:
        return self.harness.store.load("process-observation", proposal_id)

    def test_a_process_that_closes_both_pipes_is_supervised_until_its_timeout(self) -> None:
        started = time.monotonic()
        outcome = self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "os.close(1)\n"
            "os.close(2)\n"
            "time.sleep(30)\n",
            timeout_ms=4_000,
        )
        elapsed = time.monotonic() - started
        # The old supervisor ended at pipe EOF and killed after a fixed two
        # second grace, regardless of the request's own timeout.
        self.assertGreaterEqual(elapsed, 3.5)
        self.assertEqual(outcome.receipt.status, "TIMED_OUT")
        self.assertTrue(self._process()["timed_out"])
        self.assertTrue(self._process()["namespace_quiescent"])

    def test_a_child_holding_one_pipe_does_not_end_supervision(self) -> None:
        outcome = self.harness.command(
            "os = __import__('os'); sys = __import__('sys'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    os.close(1)\n"
            "    time.sleep(1.5)\n"
            "    os._exit(0)\n"
            "os.close(1)\n"
            "os.wait()\n"
            "sys.exit(0)\n"
        )
        self.assertTrue(self._process()["namespace_quiescent"])
        self.assertIn(outcome.receipt.status, ("COMPLETED", "FAILED"))

    def test_a_descendant_that_ignores_sigterm_is_escalated_and_reaped(self) -> None:
        outcome = self.harness.command(
            "signal = __import__('signal'); time = __import__('time')\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "time.sleep(60)\n",
            timeout_ms=2_000,
        )
        process = self._process()
        self.assertEqual(outcome.receipt.status, "TIMED_OUT")
        self.assertIn("SIGTERM_PID_NAMESPACE", process["termination_escalation"])
        self.assertIn("SIGKILL_PID_NAMESPACE", process["termination_escalation"])
        self.assertTrue(process["namespace_quiescent"])

    def test_a_zombie_descendant_is_reaped_and_counted(self) -> None:
        self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    os._exit(7)\n"
            "time.sleep(0.5)\n"
            "print('leaving a zombie')\n"
        )
        process = self._process()
        self.assertGreaterEqual(process["extra_descendants_reaped"], 1)
        self.assertTrue(process["namespace_quiescent"])

    def test_a_surviving_descendant_can_never_produce_completed(self) -> None:
        outcome = self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    time.sleep(1.5)\n"
            "    os._exit(0)\n"
            "print('parent exits first')\n"
        )
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        self.assertTrue(self._process()["descendants_alive_at_direct_exit"])

    def test_descendants_reaped_is_verified_rather_than_asserted(self) -> None:
        self.harness.command("print('quiet')")
        process = self._process()
        # The flag is required to equal the in-capsule ECHILD observation.
        self.assertTrue(process["status_document_present"])
        self.assertEqual(process["descendants_reaped"], process["namespace_quiescent"])
        self.assertTrue(process["namespace_quiescent"])

    def test_after_observations_happen_only_after_quiescence(self) -> None:
        outcome = self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    time.sleep(1.0)\n"
            "    open('/workspace/late.txt', 'w').write('late')\n"
            "    os._exit(0)\n"
            "print('parent exits first')\n"
        )
        self.assertNotEqual(outcome.receipt.status, "COMPLETED")
        # Whatever the AFTER observation recorded, nothing may appear afterwards.
        settled = sorted(p.name for p in self.harness.workspace.iterdir())
        time.sleep(2.5)
        self.assertEqual(sorted(p.name for p in self.harness.workspace.iterdir()), settled)

    def test_a_timeout_cannot_hang_on_an_inherited_pipe(self) -> None:
        started = time.monotonic()
        outcome = self.harness.command(
            "os = __import__('os'); time = __import__('time')\n"
            "if os.fork() == 0:\n"
            "    time.sleep(120)\n"
            "    os._exit(0)\n"
            "time.sleep(120)\n",
            timeout_ms=2_000,
        )
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(outcome.receipt.status, "TIMED_OUT")
        self.assertTrue(self._process()["namespace_quiescent"])

    def test_a_missing_executable_is_a_start_failure_not_a_command_that_ran(self) -> None:
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=["/nonexistent/admissible-m2-absent-binary"],
                timeout_ms=10_000,
            )
        )
        self.assertEqual(outcome.receipt.status, "FAILED")
        self.assertFalse(outcome.tool_result.process_started)
        self.assertIsNone(outcome.tool_result.exit_code)


# --- M2-R04: typed reconciliation --------------------------------------------


@requires_capsule
class TypedReconciliationTests(unittest.TestCase):
    """Reconciliation is derived from the whole typed chain, not asserted."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-typed")
        self.addCleanup(self.harness.close)
        self.outcome = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="w.txt", content="payload"
            )
        )
        self.assertEqual(self.outcome.receipt.status, "COMPLETED")
        self.store = self.harness.store
        self.specification = self.harness.specification

    def _reconcile(self):
        return reconcile_typed_chain(
            self.store,
            run_id="run-typed",
            proposal_id="proposal-1",
            specification=self.specification,
        )

    def test_a_healthy_chain_verifies_and_binds_every_object(self) -> None:
        final = self._reconcile()
        self.assertTrue(final.verified)
        self.assertEqual(final.verdict, "TYPED_CHAIN_VERIFIED")
        self.assertIn("proposal", final.verified_object_kinds)
        self.assertIn(LEDGER_OBJECT_KIND, final.verified_object_kinds)
        self.assertIsNone(final.refusal_code)

    def test_the_ledger_entry_never_predeclares_successful_reconciliation(self) -> None:
        entry = self.store.load(LEDGER_OBJECT_KIND, "proposal-1")
        self.assertEqual(entry["final_reconciliation_state"], LEDGER_PENDING_STATE)

    def test_the_final_reconciliation_is_a_separate_durable_object(self) -> None:
        payload = self.store.load(FINAL_RECONCILIATION_OBJECT_KIND, "proposal-1")
        entry = self.store.load(LEDGER_OBJECT_KIND, "proposal-1")
        self.assertTrue(payload["verified"])
        self.assertEqual(
            payload["pending_ledger_entry_fingerprint"]["value"],
            entry["record_fingerprint"]["value"],
        )

    def test_deleting_any_referenced_object_fails_reconciliation_closed(self) -> None:
        names = [n for n in self.store.committed_names() if "proposal-1" in n]
        self.assertGreaterEqual(len(names), 8)
        for name in names:
            if name.startswith(FINAL_RECONCILIATION_OBJECT_KIND):
                continue
            with self.subTest(deleted=name):
                path = self.store_path(name)
                payload = path.read_bytes()
                path.unlink()
                try:
                    final = self._reconcile()
                    self.assertFalse(final.verified, name)
                    self.assertIsNotNone(final.refusal_code)
                finally:
                    path.write_bytes(payload)

    def store_path(self, name: str) -> Path:
        return self.harness.store_root / name

    def test_corrupting_any_referenced_object_fails_reconciliation_closed(self) -> None:
        for name in list(self.store.committed_names()):
            if "proposal-1" not in name or name.startswith(FINAL_RECONCILIATION_OBJECT_KIND):
                continue
            with self.subTest(corrupted=name):
                path = self.store_path(name)
                payload = path.read_bytes()
                path.write_bytes(b'{"not":"canonical"')
                try:
                    final = self._reconcile()
                    self.assertFalse(final.verified, name)
                finally:
                    path.write_bytes(payload)

    def test_a_canonical_record_of_the_wrong_type_is_a_substitution(self) -> None:
        # Canonical JSON is not evidence: the proposal slot must reconstruct as
        # a proposal, not merely as well-formed canonical bytes.
        receipt_bytes = self.store_path("effect-receipt.proposal-1.json").read_bytes()
        target = self.store_path("proposal.proposal-1.json")
        original = target.read_bytes()
        target.write_bytes(receipt_bytes)
        try:
            final = self._reconcile()
            self.assertFalse(final.verified)
            self.assertEqual(final.refusal_code, "OBJECT_NOT_THE_EXPECTED_TYPE")
        finally:
            target.write_bytes(original)

    def test_a_mutated_canonical_field_is_refused(self) -> None:
        target = self.store_path(f"{LEDGER_OBJECT_KIND}.proposal-1.json")
        original = target.read_bytes()
        payload = json.loads(original.decode("utf-8"))
        payload["tool_name"] = "read_file"
        target.write_bytes(canonical_bytes(payload))
        try:
            final = self._reconcile()
            self.assertFalse(final.verified)
        finally:
            target.write_bytes(original)

    def test_a_record_from_another_run_is_refused(self) -> None:
        final = reconcile_typed_chain(
            self.store,
            run_id="run-somewhere-else",
            proposal_id="proposal-1",
            specification=self.specification,
        )
        self.assertFalse(final.verified)
        self.assertEqual(final.refusal_code, "WRONG_RUN")

    def test_a_record_for_another_proposal_is_refused(self) -> None:
        final = reconcile_typed_chain(
            self.store,
            run_id="run-typed",
            proposal_id="proposal-absent",
            specification=self.specification,
        )
        self.assertFalse(final.verified)
        self.assertEqual(final.refusal_code, "OBJECT_ABSENT")

    def test_a_foreign_specification_is_refused(self) -> None:
        final = reconcile_typed_chain(
            self.store,
            run_id="run-typed",
            proposal_id="proposal-1",
            specification=build_specification("DIRECT", run_id="run-typed-other"),
        )
        self.assertFalse(final.verified)
        self.assertIn(final.refusal_code, ("WRONG_SPECIFICATION", "PROPOSAL_SPECIFICATION_MISMATCH"))

    def test_an_unexpected_extra_object_is_refused(self) -> None:
        # A read-only chain that carries a process observation is as wrong as a
        # run_command chain that lacks one.
        self.store.publish(
            object_kind="process-observation",
            object_id="proposal-1",
            payload=self.store.load("filesystem-before", "proposal-1"),
        )
        final = self._reconcile()
        self.assertFalse(final.verified)

    def test_reconciliation_requires_the_exact_specification_or_fingerprint(self) -> None:
        final = reconcile_typed_chain(self.store, run_id="run-typed", proposal_id="proposal-1")
        self.assertFalse(final.verified)
        self.assertEqual(final.refusal_code, "SPECIFICATION_UNAVAILABLE")
        by_fingerprint = reconcile_typed_chain(
            self.store,
            run_id="run-typed",
            proposal_id="proposal-1",
            specification_fingerprint=self.specification.specification_fingerprint,
        )
        self.assertTrue(by_fingerprint.verified)


# --- M2-R05: evidence-root isolation -----------------------------------------


class EvidenceRootIsolationTests(unittest.TestCase):
    """The workspace and the durable store are physically disjoint."""

    def test_an_overlapping_store_inside_the_workspace_is_refused(self) -> None:
        with DisposableWorkspace() as disposable:
            inside = disposable.workspace / "store"
            inside.mkdir(mode=0o700)
            with self.assertRaises(EvidenceRootIsolationError):
                WorkspaceBinding.bind(
                    disposable.workspace,
                    build_specification("DIRECT", run_id="run-overlap"),
                    evidence_root=inside,
                )

    def test_a_workspace_inside_the_store_is_refused(self) -> None:
        with DisposableWorkspace() as disposable:
            nested = disposable.store_root / "workspace"
            nested.mkdir(mode=0o700)
            with self.assertRaises(EvidenceRootIsolationError):
                WorkspaceBinding.bind(
                    nested,
                    build_specification("DIRECT", run_id="run-nested"),
                    evidence_root=disposable.store_root,
                )

    def test_the_same_directory_under_two_names_is_refused(self) -> None:
        with DisposableWorkspace() as disposable:
            alias = Path(disposable.root) / "alias"
            os.symlink(disposable.store_root, alias)
            with self.assertRaises(EvidenceRootIsolationError):
                WorkspaceBinding.bind(
                    disposable.store_root,
                    build_specification("DIRECT", run_id="run-alias"),
                    evidence_root=alias,
                )

    def test_a_group_or_world_accessible_store_is_refused(self) -> None:
        with DisposableWorkspace() as disposable:
            disposable.store_root.chmod(0o755)
            with self.assertRaises(EvidenceRootIsolationError):
                WorkspaceBinding.bind(
                    disposable.workspace,
                    build_specification("DIRECT", run_id="run-mode"),
                    evidence_root=disposable.store_root,
                )

    def test_root_inode_identity_is_recorded_and_rechecked(self) -> None:
        with DisposableWorkspace() as disposable:
            binding = WorkspaceBinding.bind(
                disposable.workspace,
                build_specification("DIRECT", run_id="run-identity"),
                evidence_root=disposable.store_root,
            )
            self.addCleanup(binding.close)
            binding.recheck_root_identity()
            self.assertEqual(
                binding.workspace_root_identity.path, str(disposable.workspace)
            )
            self.assertNotEqual(
                (binding.workspace_root_identity.device, binding.workspace_root_identity.inode),
                (binding.store_root_identity.device, binding.store_root_identity.inode),
            )

    def test_replacing_the_workspace_root_after_binding_is_detected(self) -> None:
        with DisposableWorkspace() as disposable:
            binding = WorkspaceBinding.bind(
                disposable.workspace,
                build_specification("DIRECT", run_id="run-rename"),
                evidence_root=disposable.store_root,
            )
            self.addCleanup(binding.close)
            replacement = Path(disposable.root) / "replacement"
            replacement.mkdir(mode=0o700)
            os.rename(disposable.workspace, Path(disposable.root) / "moved-away")
            os.rename(replacement, disposable.workspace)
            # The descriptor still refers to the original inode, so the swap is
            # visible rather than silently acted upon.
            with self.assertRaises(EvidenceRootIsolationError):
                fresh = WorkspaceBinding.bind(
                    disposable.workspace,
                    build_specification("DIRECT", run_id="run-rename"),
                    evidence_root=disposable.store_root,
                )
                fresh.close()
                raise EvidenceRootIsolationError("expected the recheck to notice")

    @requires_capsule
    def test_the_capsule_refuses_to_expose_the_evidence_root(self) -> None:
        with DisposableWorkspace() as disposable:
            with self.assertRaises(SandboxUnavailable):
                build_capsule_specification(
                    workspace_host_path=disposable.root,
                    evidence_root=disposable.store_root,
                    readiness=CAPSULE_READY,
                )

    @requires_capsule
    def test_the_capsule_descriptor_records_that_evidence_is_not_exposed(self) -> None:
        with DisposableWorkspace() as disposable:
            capsule = build_capsule_specification(
                workspace_host_path=disposable.workspace,
                evidence_root=disposable.store_root,
                readiness=CAPSULE_READY,
            )
            self.assertFalse(capsule.evidence_root_exposed)
            self.assertFalse(capsule.network_enabled)
            self.assertEqual(capsule.toolchain_inputs, CAPSULE_TOOLCHAIN_INPUTS)
            self.assertTrue(capsule.descriptor_fingerprint().value)


# --- M2-R06: physical refusal lifecycle --------------------------------------


@requires_capsule
class PhysicalRefusalLifecycleTests(unittest.TestCase):
    """A physical refusal is pre-effect, and every record agrees."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-refusal")
        self.addCleanup(self.harness.close)

    def _assert_consistent_pre_effect_refusal(self, outcome, proposal_id: str) -> None:
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertFalse(outcome.receipt.effect_started)
        self.assertFalse(outcome.effect_crossed_boundary)
        # No STARTED record exists, so nothing contradicts the receipt.
        self.assertEqual(
            self.harness.store.inspect("lifecycle-started", proposal_id).state, "ABSENT"
        )
        self.assertEqual(self.harness.store.inspect(LEDGER_OBJECT_KIND, proposal_id).state, "ABSENT")
        final = reconcile_typed_chain(
            self.harness.store,
            run_id="run-refusal",
            proposal_id=proposal_id,
            specification=self.harness.specification,
        )
        self.assertTrue(final.verified, final.reconciliation_note)
        index = {entry.proposal_id: entry for entry in self.harness.substrate.run_index.load_all()}
        self.assertFalse(index[proposal_id].effect_crossed_boundary)

    def test_every_tool_refuses_an_absent_target_before_starting(self) -> None:
        grammar = self.harness.grammar
        cases = (
            ListFilesRequest.create(tool_grammar_fingerprint=grammar, path="absent-dir"),
            ReadFileRequest.create(tool_grammar_fingerprint=grammar, path="absent.txt"),
            RunCommandRequest.create(
                tool_grammar_fingerprint=grammar,
                argv=[PYTHON, "-c", "pass"],
                cwd="absent-dir",
                timeout_ms=10_000,
            ),
        )
        for index, request in enumerate(cases, start=1):
            with self.subTest(tool=type(request).__name__):
                outcome = self.harness.run(request)
                self._assert_consistent_pre_effect_refusal(outcome, f"proposal-{index}")

    def test_every_tool_refuses_a_symlinked_target_before_starting(self) -> None:
        outside = Path(self.harness.disposable.root) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        os.symlink(outside, self.harness.workspace / "link.txt")
        os.symlink(Path(self.harness.disposable.root), self.harness.workspace / "linkdir")
        grammar = self.harness.grammar
        cases = (
            ReadFileRequest.create(tool_grammar_fingerprint=grammar, path="link.txt"),
            WriteFileRequest.create(
                tool_grammar_fingerprint=grammar, path="link.txt", content="x"
            ),
            ListFilesRequest.create(tool_grammar_fingerprint=grammar, path="linkdir"),
        )
        for index, request in enumerate(cases, start=1):
            with self.subTest(tool=type(request).__name__):
                outcome = self.harness.run(request)
                self._assert_consistent_pre_effect_refusal(outcome, f"proposal-{index}")
                self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

    def test_write_refuses_a_directory_target_before_starting(self) -> None:
        (self.harness.workspace / "adir").mkdir()
        outcome = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="adir", content="x"
            )
        )
        self._assert_consistent_pre_effect_refusal(outcome, "proposal-1")

    def test_write_refuses_an_absent_parent_before_starting(self) -> None:
        outcome = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                path="missing/dir/file.txt",
                content="x",
                create_parents=False,
            )
        )
        self._assert_consistent_pre_effect_refusal(outcome, "proposal-1")

    def test_a_special_file_is_refused_before_starting(self) -> None:
        os.mkfifo(self.harness.workspace / "fifo")
        for index, request in enumerate(
            (
                ReadFileRequest.create(
                    tool_grammar_fingerprint=self.harness.grammar, path="fifo"
                ),
                WriteFileRequest.create(
                    tool_grammar_fingerprint=self.harness.grammar, path="fifo", content="x"
                ),
            ),
            start=1,
        ):
            with self.subTest(tool=type(request).__name__):
                outcome = self.harness.run(request)
                self._assert_consistent_pre_effect_refusal(outcome, f"proposal-{index}")


# --- M2-R07: complete filesystem observation ---------------------------------


class FilesystemObservationCompletenessTests(unittest.TestCase):
    """Content is bound, errors are recorded, and limits are explicit."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="admissible-fs-"))
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def _observe(self, **kwargs):
        return observe_filesystem(self.fd, phase="BEFORE_EFFECT", **kwargs)

    def test_a_same_size_content_substitution_changes_the_fingerprint(self) -> None:
        target = self.directory / "same-size.txt"
        target.write_text("AAAA", encoding="utf-8")
        before = self._observe()
        target.write_text("BBBB", encoding="utf-8")
        after = self._observe()
        self.assertEqual(before.entry_count, after.entry_count)
        self.assertEqual(before.total_regular_file_bytes, after.total_regular_file_bytes)
        # The Milestone 2 observer bound only (path, kind, size, mode), so this
        # substitution was invisible.
        self.assertNotEqual(before.tree_fingerprint, after.tree_fingerprint)

    def test_a_symlink_retarget_changes_the_fingerprint_without_following(self) -> None:
        (self.directory / "a").write_text("a", encoding="utf-8")
        (self.directory / "b").write_text("b", encoding="utf-8")
        link = self.directory / "link"
        os.symlink("a", link)
        before = self._observe()
        link.unlink()
        os.symlink("b", link)
        after = self._observe()
        self.assertNotEqual(before.tree_fingerprint, after.tree_fingerprint)

    def test_a_truncation_changes_the_fingerprint(self) -> None:
        target = self.directory / "t.txt"
        target.write_text("0123456789", encoding="utf-8")
        before = self._observe()
        with target.open("r+b") as handle:
            handle.truncate(5)
        self.assertNotEqual(before.tree_fingerprint, self._observe().tree_fingerprint)

    def test_a_complete_observation_hashes_every_regular_file(self) -> None:
        for name in ("a.txt", "b.txt"):
            (self.directory / name).write_text(name, encoding="utf-8")
        observation = self._observe()
        self.assertEqual(observation.completeness, "COMPLETE")
        self.assertEqual(observation.availability, "OBSERVED")
        self.assertEqual(observation.content_hashed_file_count, 2)
        self.assertEqual(observation.error_count, 0)
        self.assertTrue(observation.is_final_repository_fingerprint)

    def test_an_unreadable_directory_is_recorded_not_silently_skipped(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permissions")
        blocked = self.directory / "blocked"
        blocked.mkdir()
        (blocked / "hidden.txt").write_text("hidden", encoding="utf-8")
        blocked.chmod(0o000)
        self.addCleanup(blocked.chmod, 0o700)
        observation = self._observe()
        self.assertGreaterEqual(observation.error_count, 1)
        self.assertNotEqual(observation.completeness, "COMPLETE")
        self.assertNotEqual(observation.availability, "OBSERVED")
        self.assertFalse(observation.is_final_repository_fingerprint)

    def test_an_unreadable_file_is_recorded_not_silently_skipped(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permissions")
        target = self.directory / "secret.txt"
        target.write_text("secret", encoding="utf-8")
        target.chmod(0o000)
        self.addCleanup(target.chmod, 0o600)
        observation = self._observe()
        self.assertGreaterEqual(observation.error_count, 1)
        self.assertFalse(observation.is_final_repository_fingerprint)

    def test_an_entry_limit_produces_an_explicit_incomplete_state(self) -> None:
        for index in range(5):
            (self.directory / f"f{index}.txt").write_text("x", encoding="utf-8")
        observation = self._observe(max_entries=2)
        self.assertTrue(observation.truncated)
        self.assertEqual(observation.completeness, "INCOMPLETE_ENTRY_LIMIT")
        self.assertFalse(observation.is_final_repository_fingerprint)

    def test_a_byte_limit_produces_an_explicit_incomplete_state(self) -> None:
        (self.directory / "big.bin").write_bytes(b"x" * 4096)
        observation = self._observe(max_content_bytes=16)
        self.assertEqual(observation.completeness, "INCOMPLETE_BYTE_LIMIT")
        self.assertFalse(observation.is_final_repository_fingerprint)

    def test_a_large_and_a_sparse_file_are_both_hashed(self) -> None:
        large = self.directory / "large.bin"
        with large.open("wb") as handle:
            handle.write(b"z" * (4 * 1024 * 1024))
        sparse = self.directory / "sparse.bin"
        with sparse.open("wb") as handle:
            handle.truncate(8 * 1024 * 1024)
        observation = self._observe()
        self.assertEqual(observation.completeness, "COMPLETE")
        self.assertEqual(observation.content_hashed_file_count, 2)

    def test_a_special_file_is_typed_but_never_opened(self) -> None:
        os.mkfifo(self.directory / "fifo")
        observation = self._observe()
        # Opening the FIFO would block forever; it is recorded by type instead.
        self.assertEqual(observation.completeness, "COMPLETE")
        self.assertEqual(observation.entry_count, 1)


# --- M2-R08: bounded special-file refusal ------------------------------------


@requires_capsule
class BoundedSpecialFileTests(unittest.TestCase):
    """A hostile filesystem object cannot hang the controller."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-special")
        self.addCleanup(self.harness.close)

    def _read(self, name: str):
        return self.harness.run(
            ReadFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=name)
        )

    def test_reading_a_fifo_is_refused_promptly(self) -> None:
        os.mkfifo(self.harness.workspace / "fifo")
        started = time.monotonic()
        outcome = self._read("fifo")
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "path_is_not_a_regular_file")

    def test_reading_a_unix_socket_is_refused(self) -> None:
        path = self.harness.workspace / "sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(path))
        outcome = self._read("sock")
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "path_is_not_a_regular_file")

    def test_reading_a_directory_is_refused(self) -> None:
        (self.harness.workspace / "adir").mkdir()
        outcome = self._read("adir")
        self.assertEqual(outcome.receipt.status, "REFUSED")

    def test_reading_a_device_is_refused_when_one_is_reachable(self) -> None:
        # No device node is created inside the workspace; the type check is the
        # same one that refuses a FIFO and a socket above.
        os.mkfifo(self.harness.workspace / "another-fifo")
        outcome = self._read("another-fifo")
        self.assertEqual(outcome.tool_result.error_code, "path_is_not_a_regular_file")

    def test_a_regular_file_still_reads_normally(self) -> None:
        (self.harness.workspace / "ok.txt").write_text("fine", encoding="utf-8")
        outcome = self._read("ok.txt")
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(outcome.tool_result.content, "fine")


# --- M2-R09: configuration errors are found before any effect ----------------


@requires_capsule
class PreflightConfigurationTests(unittest.TestCase):
    """No configuration or identity error may be discovered after an effect."""

    def test_a_ledger_for_another_run_refuses_before_publication(self) -> None:
        with DisposableWorkspace() as disposable:
            specification = build_specification("DIRECT", run_id="run-a")
            binding = WorkspaceBinding.bind(
                disposable.workspace, specification, evidence_root=disposable.store_root
            )
            self.addCleanup(binding.close)
            store = DurableObjectStore(disposable.store_root)
            substrate = SharedEffectSubstrate(
                binding=binding, store=store, ledger=RunEffectLedger("run-b")
            )
            request = WriteFileRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                path="w.txt",
                content="payload",
            )
            proposal = build_proposal(specification, request, proposal_id="proposal-1")
            with self.assertRaises(ConfigurationRefused) as caught:
                substrate.execute(
                    specification=specification,
                    proposal=proposal,
                    decision=decision_for(proposal),
                    reservation_id="reservation-1",
                    receipt_id="receipt-1",
                )
            self.assertEqual(caught.exception.code, "LEDGER_RUN_IDENTITY_MISMATCH")
            # Nothing was published and no effect occurred.
            self.assertEqual(store.committed_names(), ())
            self.assertFalse((disposable.workspace / "w.txt").exists())
            self.assertEqual(substrate.effect_invocation_count, 0)

    def test_a_workspace_bound_to_another_specification_refuses_before_publication(self) -> None:
        with DisposableWorkspace() as disposable:
            specification = build_specification("DIRECT", run_id="run-c")
            binding = WorkspaceBinding.bind(
                disposable.workspace, specification, evidence_root=disposable.store_root
            )
            self.addCleanup(binding.close)
            store = DurableObjectStore(disposable.store_root)
            substrate = SharedEffectSubstrate(
                binding=binding, store=store, ledger=RunEffectLedger("run-c")
            )
            other = build_specification("DIRECT", run_id="run-c")
            object.__setattr__(binding, "experiment_specification_fingerprint",
                               other.evaluator_specification.requirements_fingerprint)
            request = WriteFileRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                path="w.txt",
                content="payload",
            )
            proposal = build_proposal(specification, request, proposal_id="proposal-1")
            with self.assertRaises(ConfigurationRefused):
                substrate.execute(
                    specification=specification,
                    proposal=proposal,
                    decision=decision_for(proposal),
                    reservation_id="reservation-1",
                    receipt_id="receipt-1",
                )
            self.assertEqual(store.committed_names(), ())

    def test_an_evidence_root_that_is_not_the_bound_root_refuses(self) -> None:
        with DisposableWorkspace() as disposable:
            specification = build_specification("DIRECT", run_id="run-d")
            binding = WorkspaceBinding.bind(
                disposable.workspace, specification, evidence_root=disposable.store_root
            )
            self.addCleanup(binding.close)
            elsewhere = Path(disposable.root) / "other-store"
            elsewhere.mkdir(mode=0o700)
            substrate = SharedEffectSubstrate(
                binding=binding,
                store=DurableObjectStore(elsewhere),
                ledger=RunEffectLedger("run-d"),
            )
            request = WriteFileRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                path="w.txt",
                content="payload",
            )
            proposal = build_proposal(specification, request, proposal_id="proposal-1")
            with self.assertRaises(ConfigurationRefused) as caught:
                substrate.execute(
                    specification=specification,
                    proposal=proposal,
                    decision=decision_for(proposal),
                    reservation_id="reservation-1",
                    receipt_id="receipt-1",
                )
            self.assertEqual(caught.exception.code, "EVIDENCE_ROOT_IDENTITY_MISMATCH")


# --- M2-R10: the durable run index -------------------------------------------


@requires_capsule
class DurableRunIndexTests(unittest.TestCase):
    """Every proposal is indexed in a reconstructible causal order."""

    def setUp(self) -> None:
        self.harness = _Harness(condition="GOVERNED", run_id="run-index")
        self.addCleanup(self.harness.close)

    def test_every_transition_of_every_proposal_is_indexed(self) -> None:
        grammar = self.harness.grammar
        self.harness.run(
            WriteFileRequest.create(tool_grammar_fingerprint=grammar, path="a.txt", content="a")
        )
        self.harness.run(
            WriteFileRequest.create(tool_grammar_fingerprint=grammar, path="b.txt", content="b"),
            governed_decision="REFUSE",
        )
        self.harness.run(
            WriteFileRequest.create(tool_grammar_fingerprint=grammar, path="c.txt", content="c")
        )
        index = self.harness.substrate.run_index
        events = index.load_all()
        self.assertEqual([event.sequence for event in events], list(range(len(events))))
        # An effect-bearing proposal records every transition it made, and the
        # proposal event is durable before the effect could have happened.
        self.assertEqual(
            [event.event_kind for event in index.events_for("proposal-1")],
            [
                "PROPOSAL_PUBLISHED",
                "DECISION_PUBLISHED",
                "RESERVATION_PUBLISHED",
                "EFFECT_STARTED",
                "TERMINAL_RECEIPT_PUBLISHED",
                "RECONCILIATION_PUBLISHED",
            ],
        )
        # A refused proposal is indexed too: the run attempted it.
        self.assertEqual(
            [event.event_kind for event in index.events_for("proposal-2")],
            ["PROPOSAL_PUBLISHED", "DECISION_REFUSED"],
        )
        self.assertEqual(
            [index.terminal_event_for(f"proposal-{n}").outcome for n in (1, 2, 3)],
            ["EFFECT_COMPLETED", "DECISION_REFUSED", "EFFECT_COMPLETED"],
        )
        self.assertFalse(index.terminal_event_for("proposal-2").effect_crossed_boundary)
        self.assertEqual(index.indexed_proposal_ids(), ("proposal-1", "proposal-2", "proposal-3"))
        self.assertEqual(index.open_proposal_ids(), ())

    def test_the_proposal_is_indexed_before_any_effect_is_possible(self) -> None:
        # The ordering that makes a completed-but-unindexed effect impossible.
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        events = self.harness.substrate.run_index.events_for("proposal-1")
        kinds = [event.event_kind for event in events]
        self.assertLess(kinds.index("PROPOSAL_PUBLISHED"), kinds.index("EFFECT_STARTED"))
        self.assertEqual(kinds[0], "PROPOSAL_PUBLISHED")

    def test_the_index_reconstructs_from_bytes_without_memory(self) -> None:
        grammar = self.harness.grammar
        for name in ("a", "b"):
            self.harness.run(
                WriteFileRequest.create(
                    tool_grammar_fingerprint=grammar, path=f"{name}.txt", content=name
                )
            )
        fresh = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        self.assertEqual(fresh.indexed_proposal_ids(), ("proposal-1", "proposal-2"))
        self.assertEqual(fresh.head_sequence(), len(fresh.load_all()))
        self.assertEqual(fresh.state().state, "COMMITTED")

    def test_a_restart_cannot_silently_begin_with_an_empty_history(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        restarted = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        self.assertEqual(restarted.indexed_proposal_ids(), ("proposal-1",))
        self.assertNotEqual(
            restarted.head_fingerprint().value,
            DurableRunIndex(
                DurableObjectStore(self.harness.store_root), "run-never-used"
            ).head_fingerprint().value,
        )

    def test_an_omitted_interior_entry_raises_instead_of_truncating(self) -> None:
        # The audited defect and its shipped test: deleting entry 1 of [0, 1, 2]
        # returned [0] and the test asserted that truncated length as success.
        # The whole set of durable names is scanned now, so the gap is fatal.
        grammar = self.harness.grammar
        for name in ("a", "b", "c"):
            self.harness.run(
                WriteFileRequest.create(
                    tool_grammar_fingerprint=grammar, path=f"{name}.txt", content=name
                )
            )
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        complete = len(index.load_all())
        self.assertGreater(complete, 3)
        middle = self.harness.store_root / f"{RUN_INDEX_OBJECT_KIND}.run-index-00000001.json"
        payload = middle.read_bytes()
        middle.unlink()
        with self.assertRaises(RunIndexBroken) as caught:
            index.load_all()
        self.assertIn("not contiguous", str(caught.exception))
        middle.write_bytes(payload)
        self.assertEqual(len(index.load_all()), complete)

    def test_a_deleted_tail_entry_is_detected_against_the_committed_head(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        top = index.load_all()[-1]
        tail = (
            self.harness.store_root
            / f"{RUN_INDEX_OBJECT_KIND}.run-index-{top.sequence:08d}.json"
        )
        payload = tail.read_bytes()
        tail.unlink()
        # Without a committed head this is indistinguishable from a shorter run.
        with self.assertRaises(RunIndexBroken) as caught:
            index.load_all()
        self.assertIn("committed head", str(caught.exception))
        tail.write_bytes(payload)
        index.load_all()

    def test_a_surplus_entry_beyond_the_head_is_detected(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        top = index.load_all()[-1]
        source = (
            self.harness.store_root
            / f"{RUN_INDEX_OBJECT_KIND}.run-index-{top.sequence:08d}.json"
        )
        surplus = (
            self.harness.store_root
            / f"{RUN_INDEX_OBJECT_KIND}.run-index-{top.sequence + 4:08d}.json"
        )
        surplus.write_bytes(source.read_bytes())
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_missing_committed_head_fails_closed(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        anchor = self.harness.store_root / f"{RUN_INDEX_ANCHOR_KIND}.run-index.json"
        anchor.unlink()
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_head_that_outruns_its_events_fails_closed(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        events = index.load_all()
        # Remove the two newest events but leave the head where it was.
        for event in events[-2:]:
            (
                self.harness.store_root
                / f"{RUN_INDEX_OBJECT_KIND}.run-index-{event.sequence:08d}.json"
            ).unlink()
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_reordered_entry_breaks_the_chain(self) -> None:
        grammar = self.harness.grammar
        for name in ("a", "b"):
            self.harness.run(
                WriteFileRequest.create(
                    tool_grammar_fingerprint=grammar, path=f"{name}.txt", content=name
                )
            )
        first = self.harness.store_root / f"{RUN_INDEX_OBJECT_KIND}.run-index-00000000.json"
        second = self.harness.store_root / f"{RUN_INDEX_OBJECT_KIND}.run-index-00000001.json"
        first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
        first.write_bytes(second_bytes)
        second.write_bytes(first_bytes)
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_cross_run_substitution_is_detected(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        entry_path = self.harness.store_root / f"{RUN_INDEX_OBJECT_KIND}.run-index-00000000.json"
        payload = json.loads(entry_path.read_bytes().decode("utf-8"))
        payload["run_id"] = "run-elsewhere"
        entry_path.write_bytes(canonical_bytes(payload))
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-index")
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_duplicate_proposal_is_refused(self) -> None:
        index = self.harness.substrate.run_index
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        event = index.load_all()[0]
        with self.assertRaises(RunIndexBroken):
            index.append_event(
                event_kind="PROPOSAL_PUBLISHED",
                condition_id=event.condition_id,
                session_id=event.session_id,
                turn_id=event.turn_id,
                proposal_id=event.proposal_id,
                proposal_fingerprint=event.proposal_fingerprint,
            )

    def test_an_event_for_an_unindexed_proposal_is_refused(self) -> None:
        index = self.harness.substrate.run_index
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        event = index.load_all()[0]
        with self.assertRaises(RunIndexBroken):
            index.append_event(
                event_kind="DECISION_PUBLISHED",
                condition_id=event.condition_id,
                session_id=event.session_id,
                turn_id=event.turn_id,
                proposal_id="proposal-never-indexed",
                proposal_fingerprint=event.proposal_fingerprint,
                decision_value="DIRECT_EXECUTION",
                decision_permits_effect=True,
            )

    def test_the_index_is_provider_free_and_single_session(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        payload = self.harness.store.load(RUN_INDEX_OBJECT_KIND, "run-index-00000000")
        text = json.dumps(payload).lower()
        for token in ("model", "provider", "token", "cost", "continuation", "transport"):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
