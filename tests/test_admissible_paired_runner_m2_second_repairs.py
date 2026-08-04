"""Adversarial closure tests for the second Milestone 2 critical-repair pass.

Findings M2-B12 through M2-B16 and M2-M17 through M2-M20 are closed here.  Every
test treats the effect process, the repository under observation, and the durable
store as untrusted, and none of them relies on:

* an unshared network namespace isolating *filesystem* IPC;
* a denylist of the Git settings that name a program;
* a durable index discovering its own extent by counting until a name is absent;
* an in-memory ledger being an authority on what a run has already done;
* the name of an executable being its identity;
* a wall-clock timeout being a resource quota;
* a file holding still while it is being hashed.

Every physical effect happens inside a disposable temporary root owned by the
test process.  No test touches a production root, a provider, a model, a policy
engine, an owner authority, a broker, a mint, a witness, or a V14-V18 identity.
"""

from __future__ import annotations

from pathlib import Path
import array
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
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
from admissible.paired_runner import capsule_seccomp  # noqa: E402
from admissible.paired_runner.canonical import canonical_bytes  # noqa: E402
from admissible.paired_runner.capsule_identity import (  # noqa: E402
    CapsuleIdentityRefused,
    CapsuleRuntimeManifest,
    build_runtime_manifest,
    package_source_identity,
)
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import (  # noqa: E402
    LEDGER_OBJECT_KIND,
    RunEffectLedger,
)
from admissible.paired_runner.effects import (  # noqa: E402
    OBJECT_KIND_PROPOSAL,
    ConfigurationRefused,
    SharedEffectSubstrate,
    WorkspaceBinding,
    WorkspaceIpcEndpointRefused,
    observe_filesystem,
    observe_git,
    recover_run_index,
    require_no_workspace_ipc_endpoints,
    scan_workspace_ipc_endpoints,
    stable_identity,
)
from admissible.paired_runner.observation import ObservationError  # noqa: E402
from admissible.paired_runner.reconciliation import (  # noqa: E402
    FINAL_RECONCILIATION_OBJECT_KIND,
)
from admissible.paired_runner.resource_limits import (  # noqa: E402
    ResourceBounds,
    probe_cgroup_delegation,
)
from admissible.paired_runner.run_index import (  # noqa: E402
    RUN_INDEX_ANCHOR_KIND,
    RUN_INDEX_OBJECT_KIND,
    DurableRunIndex,
    RunIndexBroken,
)
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import (  # noqa: E402
    ReadFileRequest,
    RunCommandRequest,
    WriteFileRequest,
)


CAPSULE_READY = probe_capsule_readiness()
requires_capsule = unittest.skipUnless(
    CAPSULE_READY.available, f"the capsule is unavailable: {CAPSULE_READY.probe_detail}"
)
requires_git = unittest.skipIf(shutil.which("git") is None, "git is unavailable on this host")


class _Harness:
    """One bound substrate over a disposable workspace and durable store."""

    def __init__(self, *, condition: str = "DIRECT", run_id: str = "run-second") -> None:
        self.run_id = run_id
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
            binding=self.binding, store=self.store, ledger=RunEffectLedger(run_id)
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

    def command(self, script: str, *, timeout_ms: int = 30_000):
        return self.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.grammar,
                argv=[PYTHON, "-c", script],
                timeout_ms=timeout_ms,
            )
        )

    def restart(self) -> SharedEffectSubstrate:
        """A fresh controller over the same durable bytes, with no memory."""

        self.store = DurableObjectStore(self.store_root)
        self.substrate = SharedEffectSubstrate(
            binding=self.binding, store=self.store, ledger=RunEffectLedger(self.run_id)
        )
        return self.substrate

    def close(self) -> None:
        self.binding.close()
        self.disposable.close()


# --- M2-B12: filesystem IPC cannot bridge the capsule -------------------------


@requires_capsule
class WorkspaceIpcBridgeTests(unittest.TestCase):
    """A pathname Unix socket crosses an unshared network namespace.  It must not.

    The corrected statement is physical: ``--unshare-net`` isolates the *network*
    namespace, and an ``AF_UNIX`` socket is a filesystem object.  Two independent
    mechanisms close the bridge, and each is tested on its own so that neither
    can be mistaken for the other working.
    """

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-ipc")
        self.addCleanup(self.harness.close)

    def _run(self, script: str):
        return self.harness.command(script)

    def test_the_kernel_really_does_carry_unix_sockets_across_a_network_namespace(self) -> None:
        # The premise, demonstrated rather than asserted: without the repair this
        # is a working bidirectional bridge, so the network namespace alone was
        # never sufficient.
        directory = tempfile.mkdtemp(prefix="admissible-unix-premise-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "bridge.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(path)
        server.listen(1)

        def serve() -> None:
            try:
                connection, _ = server.accept()
                connection.sendall(b"host-reply")
                connection.close()
            except OSError:  # pragma: no cover - the accept raced teardown
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        completed = subprocess.run(  # noqa: S603 - explicit argv, disposable root
            [
                "unshare",
                "-Urn",
                PYTHON,
                "-c",
                "import socket,sys\n"
                "s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "s.connect(sys.argv[1])\n"
                "print(s.recv(32).decode())\n",
                path,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        thread.join(timeout=5)
        if completed.returncode != 0:
            self.skipTest(f"unshare is unavailable on this host: {completed.stderr[:120]}")
        self.assertEqual(completed.stdout.strip(), "host-reply")

    def test_a_pathname_unix_socket_cannot_be_created_inside_the_capsule(self) -> None:
        outcome = self._run(
            "import socket, sys\n"
            "try:\n"
            "    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "    print('CREATED')\n"
            "except OSError as error:\n"
            "    print('DENIED', error.errno)\n"
        )
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertTrue(outcome.tool_result.stdout.startswith("DENIED"), outcome.tool_result.stdout)

    def test_an_abstract_unix_socket_cannot_be_created_inside_the_capsule(self) -> None:
        # An abstract socket has no filesystem entry at all, so the admission
        # scan cannot see it.  The syscall boundary is what closes this one.
        outcome = self._run(
            "import socket\n"
            "try:\n"
            "    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "    s.bind('\\0admissible-abstract')\n"
            "    print('BOUND')\n"
            "except OSError as error:\n"
            "    print('DENIED', error.errno)\n"
        )
        self.assertTrue(outcome.tool_result.stdout.startswith("DENIED"), outcome.tool_result.stdout)

    def test_socketpair_and_therefore_scm_rights_are_unavailable(self) -> None:
        # SCM_RIGHTS travels only over an AF_UNIX socket; with no way to make one,
        # there is no route for a descriptor to enter or leave the capsule.
        outcome = self._run(
            "import socket\n"
            "try:\n"
            "    socket.socketpair()\n"
            "    print('CREATED')\n"
            "except OSError as error:\n"
            "    print('DENIED', error.errno)\n"
        )
        self.assertTrue(outcome.tool_result.stdout.startswith("DENIED"), outcome.tool_result.stdout)

    def test_a_host_server_socket_cannot_be_reached_from_inside_the_capsule(self) -> None:
        # The full bridge attempt: a real host server, a real socket file, and a
        # capsuled client.  The client cannot even construct the socket.
        server_path = self.harness.workspace / "host.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(server_path))
        server.listen(1)
        secret = Path(tempfile.mkdtemp(prefix="admissible-outside-")) / "evidence.txt"
        self.addCleanup(shutil.rmtree, secret.parent, True)
        secret.write_text("HOST BYTES THE CAPSULE MUST NEVER SEE\n", encoding="utf-8")

        def serve() -> None:
            try:
                connection, _ = server.accept()
                handle = os.open(secret, os.O_RDONLY)
                connection.sendmsg(
                    [b"host"],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [handle]).tobytes())],
                )
                os.close(handle)
                connection.close()
            except OSError:  # pragma: no cover - nothing ever connects
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            outcome = self._run(
                "import socket\n"
                "try:\n"
                "    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "    s.connect('/workspace/host.sock')\n"
                "    print('CONNECTED')\n"
                "except OSError as error:\n"
                "    print('DENIED', error.errno)\n"
            )
        finally:
            thread.join(timeout=1)
        # Admission refuses before the effect boundary, because a workspace with a
        # socket in it is not admitted at all.
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "workspace_contains_a_host_ipc_endpoint")
        self.assertFalse(outcome.effect_crossed_boundary)

    def test_a_host_fifo_in_the_workspace_is_refused_before_the_effect(self) -> None:
        os.mkfifo(self.harness.workspace / "host.fifo")
        outcome = self._run("print('should never run')")
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "workspace_contains_a_host_ipc_endpoint")

    def test_a_special_inode_in_the_initial_snapshot_is_named_by_the_admission_scan(self) -> None:
        os.mkfifo(self.harness.workspace / "a.fifo")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.harness.workspace / "b.sock"))
        (self.harness.workspace / "sub").mkdir()
        os.mkfifo(self.harness.workspace / "sub" / "c.fifo")
        found = scan_workspace_ipc_endpoints(self.harness.binding.root_fd)
        self.assertEqual(found, ("a.fifo:fifo", "b.sock:socket", "sub/c.fifo:fifo"))
        with self.assertRaises(WorkspaceIpcEndpointRefused):
            require_no_workspace_ipc_endpoints(self.harness.binding.root_fd)

    def test_the_effect_cannot_create_a_fifo_a_host_process_could_open(self) -> None:
        outcome = self._run(
            "import os\n"
            "try:\n"
            "    os.mkfifo('/workspace/child.fifo')\n"
            "    print('CREATED')\n"
            "except OSError as error:\n"
            "    print('DENIED', error.errno)\n"
        )
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertTrue(outcome.tool_result.stdout.startswith("DENIED"), outcome.tool_result.stdout)
        self.assertFalse((self.harness.workspace / "child.fifo").exists())

    def test_no_socket_fifo_or_device_is_exported_by_an_effect(self) -> None:
        self._run(
            "import os, socket\n"
            "for attempt in ('sock', 'fifo', 'dev'):\n"
            "    try:\n"
            "        if attempt == 'sock':\n"
            "            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "            s.bind('/workspace/effect.sock')\n"
            "        elif attempt == 'fifo':\n"
            "            os.mkfifo('/workspace/effect.fifo')\n"
            "        else:\n"
            "            os.mknod('/workspace/effect.dev', 0o600 | 0x2000, os.makedev(1, 3))\n"
            "    except OSError:\n"
            "        pass\n"
            "open('/workspace/ordinary.txt', 'w').write('regular file effects still work')\n"
            "print('done')\n"
        )
        after = self.harness.store.load("filesystem-after", "proposal-1")
        self.assertEqual(after["ipc_endpoint_count"], 0)
        self.assertEqual(after["ipc_endpoints"], [])
        self.assertEqual(
            (self.harness.workspace / "ordinary.txt").read_text(encoding="utf-8"),
            "regular file effects still work",
        )

    def test_ordinary_regular_file_effects_remain_correct(self) -> None:
        outcome = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                path="d/e.txt",
                content="nested\n",
                create_parents=True,
            )
        )
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(
            (self.harness.workspace / "d" / "e.txt").read_text(encoding="utf-8"), "nested\n"
        )
        command = self.harness.command(
            "print(open('/workspace/d/e.txt').read().strip())"
        )
        self.assertEqual(command.receipt.status, "COMPLETED")
        self.assertEqual(command.tool_result.stdout.strip(), "nested")

    def test_the_filesystem_observation_names_every_endpoint_by_exact_kind(self) -> None:
        os.mkfifo(self.harness.workspace / "p.fifo")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.harness.workspace / "q.sock"))
        observation = observe_filesystem(self.harness.binding.root_fd, phase="INITIAL")
        self.assertEqual(observation.ipc_endpoint_count, 2)
        self.assertEqual(observation.ipc_endpoints, ("p.fifo:fifo", "q.sock:socket"))


class SeccompProgramTests(unittest.TestCase):
    """The syscall boundary is assembled correctly and fails closed."""

    def test_the_program_is_well_formed_classic_bpf(self) -> None:
        program = capsule_seccomp.build_program()
        self.assertEqual(len(program) % 8, 0)
        instructions = [
            struct.unpack("<HBBI", program[offset : offset + 8])
            for offset in range(0, len(program), 8)
        ]
        # Every jump target lands inside the program.
        for position, (code, jt, jf, _) in enumerate(instructions):
            if code & 0x07 == 0x05:  # BPF_JMP
                for offset in (jt, jf):
                    self.assertLess(position + 1 + offset, len(instructions))

    def test_a_foreign_architecture_kills_the_process(self) -> None:
        program = capsule_seccomp.build_program()
        first = struct.unpack("<HBBI", program[8:16])
        # Instruction 1 compares seccomp_data.arch and jumps to the kill return.
        self.assertEqual(first[0], 0x15)
        kill_index = 1 + 1 + first[2]
        code, _, _, action = struct.unpack("<HBBI", program[kill_index * 8 : kill_index * 8 + 8])
        self.assertEqual(code, 0x06)
        self.assertEqual(action, capsule_seccomp.SECCOMP_RET_KILL_PROCESS)

    def test_an_unknown_architecture_is_a_refusal_not_an_unfiltered_capsule(self) -> None:
        with self.assertRaises(capsule_seccomp.SeccompUnavailable):
            capsule_seccomp.current_profile("nonexistent-architecture")

    def test_the_program_digest_is_stable_and_recorded(self) -> None:
        self.assertEqual(
            capsule_seccomp.program_digest(), capsule_seccomp.describe()["program_sha256"]
        )
        self.assertIn("socket(AF_UNIX)", capsule_seccomp.describe()["denied_syscalls"])


# --- M2-B13: the Git observer executes nothing -------------------------------


@requires_git
class NonExecutingGitObserverTests(unittest.TestCase):
    """No repository-controlled program may execute during an observation."""

    def setUp(self) -> None:
        self.disposable = DisposableWorkspace()
        self.addCleanup(self.disposable.close)
        self.workspace = self.disposable.workspace
        if not initialise_git_repository(self.workspace):
            self.skipTest("a disposable git repository could not be created")
        self.marker = self.disposable.root / "EXECUTED"
        self.script = self.disposable.root / "driver.sh"
        self.script.write_text(
            f"#!/bin/sh\necho ran >> {self.marker}\ncat\n", encoding="utf-8"
        )
        self.script.chmod(0o755)
        self.root_fd = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root_fd)

    def _git(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603 - explicit argv, disposable root
            [shutil.which("git"), *arguments],
            cwd=str(self.workspace),
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(self.workspace),
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
            },
        )

    def _observe(self):
        return observe_git(self.workspace, self.root_fd, phase="BEFORE_EFFECT")

    def _executions(self) -> int:
        return self.marker.read_text(encoding="utf-8").count("ran") if self.marker.exists() else 0

    def _modify_same_size(self) -> None:
        # A same-size modification is what forces a client to convert and hash the
        # working-tree file rather than short-circuiting on the stat cache.  The
        # audit's reproduction depended on exactly this.
        target = self.workspace / "tracked.txt"
        target.write_text("TRACKED\n", encoding="utf-8")

    def test_a_clean_filter_driver_is_never_executed(self) -> None:
        (self.workspace / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
        self._git("config", "filter.evil.clean", str(self.script))
        self._modify_same_size()
        observation = self._observe()
        self.assertEqual(self._executions(), 0)
        self.assertEqual(observation.availability, "GIT_CONVERSION_REQUIRED")
        self.assertIsNotNone(observation.refusal_reason)

    def test_a_process_filter_driver_is_never_executed(self) -> None:
        (self.workspace / ".gitattributes").write_text("*.txt filter=proc\n", encoding="utf-8")
        self._git("config", "filter.proc.process", str(self.script))
        self._modify_same_size()
        self.assertEqual(self._observe().availability, "GIT_CONVERSION_REQUIRED")
        self.assertEqual(self._executions(), 0)

    def test_a_required_filter_is_never_executed(self) -> None:
        (self.workspace / ".gitattributes").write_text("*.txt filter=req\n", encoding="utf-8")
        self._git("config", "filter.req.clean", str(self.script))
        self._git("config", "filter.req.required", "true")
        self._modify_same_size()
        self.assertEqual(self._observe().availability, "GIT_CONVERSION_REQUIRED")
        self.assertEqual(self._executions(), 0)

    def test_a_nested_gitattributes_file_is_found(self) -> None:
        nested = self.workspace / "deep" / "deeper"
        nested.mkdir(parents=True)
        (nested / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
        (nested / "x.txt").write_text("x\n", encoding="utf-8")
        self._git("config", "filter.evil.clean", str(self.script))
        self.assertEqual(self._observe().availability, "GIT_CONVERSION_REQUIRED")
        self.assertEqual(self._executions(), 0)

    def test_attributes_that_exist_only_in_the_index_are_found(self) -> None:
        (self.workspace / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
        self._git("add", ".gitattributes")
        self._git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "-m", "attrs")
        os.unlink(self.workspace / ".gitattributes")
        self._git("config", "filter.evil.clean", str(self.script))
        observation = self._observe()
        self.assertEqual(observation.availability, "GIT_CONVERSION_REQUIRED")
        self.assertIn("tracked", observation.refusal_reason)
        self.assertEqual(self._executions(), 0)

    def test_a_filter_that_would_mutate_the_workspace_never_runs(self) -> None:
        mutator = self.disposable.root / "mutate.sh"
        mutator.write_text(
            f"#!/bin/sh\necho ran >> {self.marker}\n"
            f"printf pwned > {self.workspace}/PWNED.txt\ncat\n",
            encoding="utf-8",
        )
        mutator.chmod(0o755)
        (self.workspace / ".gitattributes").write_text("*.txt filter=mut\n", encoding="utf-8")
        self._git("config", "filter.mut.clean", str(mutator))
        self._modify_same_size()
        self._observe()
        self.assertEqual(self._executions(), 0)
        self.assertFalse((self.workspace / "PWNED.txt").exists())

    def test_a_filter_that_would_open_a_unix_socket_never_runs(self) -> None:
        bridge = self.disposable.root / "bridge.sh"
        bridge.write_text(
            f"#!/bin/sh\necho ran >> {self.marker}\n"
            f"{PYTHON} -c \"import socket;s=socket.socket(socket.AF_UNIX);s.bind('{self.disposable.root}/f.sock')\"\ncat\n",
            encoding="utf-8",
        )
        bridge.chmod(0o755)
        (self.workspace / ".gitattributes").write_text("*.txt filter=ipc\n", encoding="utf-8")
        self._git("config", "filter.ipc.clean", str(bridge))
        self._modify_same_size()
        self._observe()
        self.assertEqual(self._executions(), 0)
        self.assertFalse((self.disposable.root / "f.sock").exists())

    def test_a_filter_that_would_fork_never_runs(self) -> None:
        forker = self.disposable.root / "fork.sh"
        forker.write_text(
            f"#!/bin/sh\necho ran >> {self.marker}\n(sleep 30 &)\ncat\n", encoding="utf-8"
        )
        forker.chmod(0o755)
        (self.workspace / ".gitattributes").write_text("*.txt filter=forky\n", encoding="utf-8")
        self._git("config", "filter.forky.clean", str(forker))
        self._modify_same_size()
        self._observe()
        self.assertEqual(self._executions(), 0)

    def test_core_autocrlf_is_a_declared_conversion(self) -> None:
        self._git("config", "core.autocrlf", "true")
        self.assertEqual(self._observe().availability, "GIT_CONVERSION_REQUIRED")

    def test_a_repository_without_conversion_is_fully_observed(self) -> None:
        observation = self._observe()
        self.assertEqual(observation.availability, "OBSERVED")
        self.assertEqual(observation.observation_method, "NON_EXECUTING_REFS_INDEX_AND_OBJECTS")
        self.assertEqual(observation.head_reference, "refs/heads/main")
        self.assertFalse(observation.worktree_dirty)
        self.assertFalse(observation.index_dirty)
        self.assertIsNotNone(observation.untracked_semantics)
        self.assertEqual(self._executions(), 0)

    def test_the_observation_matches_a_real_client_on_ordinary_repositories(self) -> None:
        # A differential check against the tool this observer replaces, over the
        # states an effect actually produces.
        def client_view() -> dict[str, bool | str]:
            status = self._git(
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=all",
                "--no-renames",
            ).stdout
            lines = [line for line in status.splitlines() if line]
            return {
                "head": self._git("rev-parse", "HEAD").stdout.strip(),
                "index_dirty": any(line[0] not in " ?" for line in lines),
                "worktree_dirty": any(len(line) > 1 and line[1] not in " ?" for line in lines),
                "untracked_present": any(line.startswith("??") for line in lines),
            }

        def compare(label: str) -> None:
            expected = client_view()
            observed = self._observe()
            self.assertEqual(observed.availability, "OBSERVED", label)
            self.assertEqual(observed.head_commit, expected["head"], label)
            self.assertEqual(observed.index_dirty, expected["index_dirty"], label)
            self.assertEqual(observed.worktree_dirty, expected["worktree_dirty"], label)
            self.assertEqual(observed.untracked_present, expected["untracked_present"], label)

        compare("clean")
        (self.workspace / "tracked.txt").write_text("changed\n", encoding="utf-8")
        compare("worktree modified")
        self._git("add", "tracked.txt")
        compare("staged")
        (self.workspace / "fresh.txt").write_text("fresh\n", encoding="utf-8")
        compare("untracked")
        os.unlink(self.workspace / "tracked.txt")
        compare("missing")

    def test_a_packed_repository_is_observed_through_its_packfiles(self) -> None:
        for index in range(30):
            (self.workspace / f"f{index}.txt").write_text("x" * index + "\n", encoding="utf-8")
        self._git("add", "-A")
        self._git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "-m", "bulk")
        for index in range(0, 30, 3):
            (self.workspace / f"f{index}.txt").write_text("y" * index + "\n", encoding="utf-8")
        self._git("add", "-A")
        self._git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "-m", "bulk2")
        packed = self._git("gc", "-q", "--aggressive")
        if packed.returncode != 0:  # pragma: no cover - gc is available in practice
            self.skipTest("git gc failed on this host")
        self.assertFalse(any(self.workspace.glob(".git/objects/[0-9a-f][0-9a-f]/*")))
        observation = self._observe()
        self.assertEqual(observation.availability, "OBSERVED")
        self.assertEqual(observation.head_commit, self._git("rev-parse", "HEAD").stdout.strip())
        self.assertFalse(observation.worktree_dirty)

    def test_the_observer_does_not_mutate_the_repository(self) -> None:
        index = self.workspace / ".git" / "index"
        before = index.read_bytes()
        stamps = sorted(
            (path.name, path.stat().st_mtime_ns)
            for path in self.workspace.iterdir()
            if path.is_file()
        )
        self._observe()
        self.assertEqual(index.read_bytes(), before)
        self.assertEqual(
            stamps,
            sorted(
                (path.name, path.stat().st_mtime_ns)
                for path in self.workspace.iterdir()
                if path.is_file()
            ),
        )

    def test_a_corrupt_index_fails_closed(self) -> None:
        index = self.workspace / ".git" / "index"
        raw = bytearray(index.read_bytes())
        raw[20] ^= 0xFF
        index.write_bytes(bytes(raw))
        observation = self._observe()
        self.assertEqual(observation.availability, "GIT_METADATA_UNREADABLE")
        self.assertIsNone(observation.head_commit)

    def test_a_git_file_layout_is_refused_rather_than_guessed(self) -> None:
        shutil.rmtree(self.workspace / ".git")
        (self.workspace / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
        self.assertEqual(self._observe().availability, "GIT_REPOSITORY_UNSUPPORTED_LAYOUT")


# --- M2-B14 and M2-B15: the durable event index -------------------------------


@requires_capsule
class DurableEventIndexTests(unittest.TestCase):
    """The run's causal order is complete, committed, and crash-classifiable."""

    def setUp(self) -> None:
        self.harness = _Harness(condition="GOVERNED", run_id="run-events")
        self.addCleanup(self.harness.close)

    def _write(self, name: str, *, governed_decision: str = "ALLOW"):
        return self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path=f"{name}.txt", content=name
            ),
            governed_decision=governed_decision,
        )

    def test_the_committed_head_names_the_last_event(self) -> None:
        self._write("a")
        index = self.harness.substrate.run_index
        anchor = index.load_anchor()
        events = index.load_all()
        self.assertIsNotNone(anchor)
        self.assertEqual(anchor.head_sequence, events[-1].sequence)
        self.assertEqual(anchor.head_event_fingerprint, events[-1].record_fingerprint)
        self.assertEqual(anchor.event_count, len(events))

    def test_the_head_anchor_is_the_value_an_external_anchor_would_pin(self) -> None:
        self._write("a")
        anchor = self.harness.substrate.run_index.head_anchor()
        self.assertEqual(anchor["run_id"], "run-events")
        self.assertIsInstance(anchor["head_sequence"], int)
        self.assertEqual(len(anchor["head_event_fingerprint"]), 64)

    def test_a_forged_head_that_does_not_match_its_event_fails_closed(self) -> None:
        self._write("a")
        path = self.harness.store_root / f"{RUN_INDEX_ANCHOR_KIND}.run-events.json"
        payload = json.loads(path.read_bytes().decode("utf-8"))
        payload["head_event_fingerprint"]["value"] = "0" * 64
        path.write_bytes(canonical_bytes(payload))
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-events")
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_cross_run_anchor_is_refused(self) -> None:
        self._write("a")
        path = self.harness.store_root / f"{RUN_INDEX_ANCHOR_KIND}.run-events.json"
        payload = json.loads(path.read_bytes().decode("utf-8"))
        payload["run_id"] = "run-elsewhere"
        path.write_bytes(canonical_bytes(payload))
        index = DurableRunIndex(DurableObjectStore(self.harness.store_root), "run-events")
        with self.assertRaises(RunIndexBroken):
            index.load_all()

    def test_a_completed_effect_whose_index_event_was_lost_is_recovered(self) -> None:
        # M2-B15 exactly: a real effect, a verified final reconciliation, and no
        # index event closing it.  Recovery must close it from durable bytes and
        # must never replay the effect.
        self._write("a")
        store = DurableObjectStore(self.harness.store_root)
        index = DurableRunIndex(store, "run-events")
        events = index.load_all()
        terminal = events[-1]
        self.assertEqual(terminal.event_kind, "RECONCILIATION_PUBLISHED")
        (
            self.harness.store_root
            / f"{RUN_INDEX_OBJECT_KIND}.run-events-{terminal.sequence:08d}.json"
        ).unlink()
        anchor_path = self.harness.store_root / f"{RUN_INDEX_ANCHOR_KIND}.run-events.json"
        anchor = json.loads(anchor_path.read_bytes().decode("utf-8"))
        anchor["head_sequence"] = terminal.sequence - 1
        anchor["event_count"] = terminal.sequence
        anchor["head_event_fingerprint"] = events[terminal.sequence - 1].record_fingerprint.to_dict()
        anchor.pop("record_fingerprint")
        from admissible.paired_runner.run_index import RunIndexAnchor

        anchor_path.write_bytes(
            canonical_bytes(
                RunIndexAnchor.create(
                    run_id="run-events",
                    head_sequence=anchor["head_sequence"],
                    event_count=anchor["event_count"],
                    head_event_fingerprint=events[terminal.sequence - 1].record_fingerprint,
                ).to_dict()
            )
        )

        self.assertEqual(index.open_proposal_ids(), ("proposal-1",))
        content_before = (self.harness.workspace / "a.txt").read_bytes()

        recovery = recover_run_index(store, "run-events")
        self.assertFalse(recovery.replayed_any_effect)
        self.assertEqual(recovery.still_open_proposal_ids, ())
        self.assertEqual(recovery.appended_events, ("proposal-1:RECONCILIATION_PUBLISHED",))
        self.assertEqual(index.state().state, "COMMITTED")
        closing = index.terminal_event_for("proposal-1")
        self.assertEqual(closing.event_kind, "RECONCILIATION_PUBLISHED")
        self.assertEqual(closing.outcome, "EFFECT_COMPLETED")
        self.assertTrue(closing.effect_crossed_boundary)
        # Nothing was re-executed: the workspace bytes are untouched.
        self.assertEqual((self.harness.workspace / "a.txt").read_bytes(), content_before)

    def test_a_pending_committed_head_blocks_an_append_until_it_is_recovered(self) -> None:
        self._write("a")
        store = DurableObjectStore(self.harness.store_root)
        index = DurableRunIndex(store, "run-events")
        events = index.load_all()
        anchor_path = self.harness.store_root / f"{RUN_INDEX_ANCHOR_KIND}.run-events.json"
        from admissible.paired_runner.run_index import RunIndexAnchor

        anchor_path.write_bytes(
            canonical_bytes(
                RunIndexAnchor.create(
                    run_id="run-events",
                    head_sequence=events[-2].sequence,
                    event_count=events[-2].sequence + 1,
                    head_event_fingerprint=events[-2].record_fingerprint,
                ).to_dict()
            )
        )
        self.assertEqual(index.state().state, "HEAD_UPDATE_PENDING")
        with self.assertRaises(RunIndexBroken):
            index.append_event(
                event_kind="PROPOSAL_PUBLISHED",
                condition_id=events[0].condition_id,
                session_id=events[0].session_id,
                turn_id=events[0].turn_id,
                proposal_id="proposal-new",
                proposal_fingerprint=events[0].proposal_fingerprint,
            )
        self.assertEqual(index.recover_head(), "COMMITTED")

    def test_the_index_records_no_provider_model_or_continuation_field(self) -> None:
        self._write("a")
        for name in self.harness.store.committed_names():
            if not name.startswith(f"{RUN_INDEX_OBJECT_KIND}."):
                continue
            text = (self.harness.store_root / name).read_text(encoding="utf-8").lower()
            for token in ("model", "provider", "token", "cost", "continuation", "transport"):
                self.assertNotIn(token, text, name)


# --- M2-B16: the ledger is derived from the index -----------------------------


@requires_capsule
class DerivedEffectLedgerTests(unittest.TestCase):
    """History is derived from durable bytes, never supplied by the caller."""

    def setUp(self) -> None:
        self.harness = _Harness(condition="GOVERNED", run_id="run-ledger")
        self.addCleanup(self.harness.close)

    def _write(self, name: str, *, governed_decision: str = "ALLOW"):
        return self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path=f"{name}.txt", content=name
            ),
            governed_decision=governed_decision,
        )

    def test_verification_takes_no_caller_supplied_history(self) -> None:
        # The audited signature accepted the proposal identities to check.  There
        # is no such parameter now, so no caller can select a subset.
        import inspect

        signature = inspect.signature(RunEffectLedger.verify)
        self.assertNotIn("proposal_ids", signature.parameters)
        for name, parameter in signature.parameters.items():
            if name in {"store", "run_id", "cls"}:
                continue
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)

    def test_a_restart_reconstructs_the_complete_history_before_a_new_effect(self) -> None:
        self._write("a")
        self._write("b", governed_decision="REFUSE")
        self._write("c")
        # A brand new controller with an empty in-memory ledger.
        substrate = self.harness.restart()
        self.assertEqual(substrate.ledger.entries, ())
        self._write("d")
        # The new effect did not begin from an empty history: every earlier
        # effect-bearing proposal is present, in order, including the one that
        # ran before this process existed.
        self.assertEqual(
            [entry.proposal_id for entry in substrate.ledger.entries],
            ["proposal-1", "proposal-3", "proposal-4"],
        )
        derived = RunEffectLedger.verify(
            self.harness.store, "run-ledger", specification=self.harness.specification
        )
        self.assertEqual(
            [entry.proposal_id for entry in derived.entries],
            ["proposal-1", "proposal-3", "proposal-4"],
        )

    def test_no_historical_proposal_can_be_omitted(self) -> None:
        self._write("a")
        self._write("b")
        derived = RunEffectLedger.verify(
            self.harness.store, "run-ledger", specification=self.harness.specification
        )
        self.assertEqual(len(derived.entries), 2)
        # Deleting an entry the index recorded is a refusal, not a shorter run.
        (self.harness.store_root / f"{LEDGER_OBJECT_KIND}.proposal-1.json").unlink()
        with self.assertRaises(ObservationError):
            RunEffectLedger.verify(
                self.harness.store, "run-ledger", specification=self.harness.specification
            )

    def test_a_ledger_entry_the_index_never_recorded_is_surplus(self) -> None:
        self._write("a")
        source = self.harness.store_root / f"{LEDGER_OBJECT_KIND}.proposal-1.json"
        shutil.copyfile(source, self.harness.store_root / f"{LEDGER_OBJECT_KIND}.proposal-99.json")
        with self.assertRaises(ObservationError) as caught:
            RunEffectLedger.verify(
                self.harness.store, "run-ledger", specification=self.harness.specification
            )
        self.assertIn("never recorded", str(caught.exception))

    def test_a_refusal_carries_no_ledger_entry_and_that_absence_is_checked(self) -> None:
        self._write("a", governed_decision="REFUSE")
        derived = RunEffectLedger.verify(
            self.harness.store, "run-ledger", specification=self.harness.specification
        )
        self.assertEqual(derived.entries, ())
        # Planting an entry for a refused proposal is a contradiction.
        self._write("b")
        shutil.copyfile(
            self.harness.store_root / f"{LEDGER_OBJECT_KIND}.proposal-2.json",
            self.harness.store_root / f"{LEDGER_OBJECT_KIND}.proposal-1.json",
        )
        with self.assertRaises(ObservationError):
            RunEffectLedger.verify(
                self.harness.store, "run-ledger", specification=self.harness.specification
            )

    def test_an_in_memory_ledger_that_contradicts_the_durable_history_refuses(self) -> None:
        self._write("a")
        foreign = RunEffectLedger("run-ledger")
        foreign.append(self.harness.substrate.ledger.entries[0])
        substitute = SharedEffectSubstrate(
            binding=self.harness.binding,
            store=DurableObjectStore(self.harness.store_root),
            ledger=foreign,
        )
        # A ledger holding exactly the durable history is fine.
        proposal = build_proposal(
            self.harness.specification,
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="z.txt", content="z"
            ),
            proposal_id="proposal-z",
        )
        substitute.preflight(self.harness.specification, proposal)

        # A ledger holding an entry the durable index does not is not.
        other = _Harness(condition="GOVERNED", run_id="run-ledger")
        self.addCleanup(other.close)
        other.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=other.grammar, path="q.txt", content="q"
            )
        )
        mismatched = RunEffectLedger("run-ledger")
        mismatched.append(other.substrate.ledger.entries[0])
        contradicting = SharedEffectSubstrate(
            binding=self.harness.binding,
            store=DurableObjectStore(self.harness.store_root),
            ledger=mismatched,
        )
        with self.assertRaises(ConfigurationRefused) as caught:
            contradicting.preflight(self.harness.specification, proposal)
        self.assertEqual(caught.exception.code, "LEDGER_CONTRADICTS_DURABLE_HISTORY")

    def test_the_ledger_fingerprints_bind_the_complete_history(self) -> None:
        self._write("a")
        index = self.harness.substrate.run_index
        ledger = self.harness.substrate.ledger
        head = index.head_fingerprint().value
        bound = ledger.proposal_ledger_fingerprint(index_head=head)
        unbound = ledger.proposal_ledger_fingerprint()
        self.assertNotEqual(bound, unbound)
        self._write("b")
        self.assertNotEqual(
            ledger.proposal_ledger_fingerprint(index_head=index.head_fingerprint().value), bound
        )


# --- M2-M17: the capsule runtime identity -------------------------------------


@requires_capsule
class CapsuleRuntimeIdentityTests(unittest.TestCase):
    """The capsule is bound by the bytes it is made of, not by a name."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-identity")
        self.addCleanup(self.harness.close)
        self.manifest = self.harness.binding.capsule_runtime_manifest

    def test_the_manifest_binds_every_input_the_capsule_depends_on(self) -> None:
        payload = self.manifest.to_dict()
        for field in (
            "mechanism_sha256",
            "mechanism_device",
            "mechanism_inode",
            "mechanism_mode",
            "mechanism_owner_uid",
            "mechanism_version",
            "interpreter_sha256",
            "capsule_init_sha256",
            "seccomp_program_sha256",
            "package_source_sha256",
            "toolchain_input_manifest_fingerprint",
            "namespace_contract",
            "mount_contract",
            "containment_mechanism",
        ):
            self.assertIn(field, payload)
        self.assertEqual(len(self.manifest.mechanism_sha256), 64)
        self.assertEqual(self.manifest.package_source_sha256, package_source_identity()[0])

    def test_the_manifest_is_durable_and_bound_by_every_started_event(self) -> None:
        self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="a.txt", content="a"
            )
        )
        stored = CapsuleRuntimeManifest.from_dict(
            self.harness.store.load("capsule-runtime-manifest", "run-identity")
        )
        self.assertEqual(stored.record_fingerprint, self.manifest.record_fingerprint)
        started = [
            event
            for event in self.harness.substrate.run_index.load_all()
            if event.event_kind == "EFFECT_STARTED"
        ]
        self.assertEqual(len(started), 1)
        self.assertEqual(
            started[0].capsule_runtime_manifest_fingerprint, self.manifest.record_fingerprint
        )

    def test_the_capsule_descriptor_binds_the_manifest_fingerprint(self) -> None:
        descriptor = self.harness.binding.capsule.to_dict()
        self.assertEqual(
            descriptor["runtime_manifest_fingerprint"], self.manifest.record_fingerprint.to_dict()
        )
        self.assertEqual(
            descriptor["seccomp_program_sha256"], capsule_seccomp.program_digest()
        )
        self.assertTrue(descriptor["unix_domain_sockets_denied"])
        self.assertTrue(descriptor["special_file_creation_denied"])

    def _manifest_with(self, **overrides) -> CapsuleRuntimeManifest:
        payload = self.manifest.to_dict()
        payload.update(overrides)
        payload.pop("record_fingerprint")
        payload.pop("schema_id")
        payload.pop("schema_version")
        from admissible.paired_runner.canonical import Fingerprint

        for name in (
            "toolchain_input_manifest_fingerprint",
            "containment_bounds_fingerprint",
        ):
            payload[name] = Fingerprint.from_dict(payload[name])
        for name in ("toolchain_inputs", "namespace_contract", "mount_contract"):
            payload[name] = tuple(payload[name])
        return CapsuleRuntimeManifest.create(**payload)

    def test_a_replaced_launcher_binary_is_refused(self) -> None:
        forged = self._manifest_with(mechanism_sha256="0" * 64)
        with self.assertRaises(CapsuleIdentityRefused):
            forged.recheck()

    def test_a_replaced_interpreter_is_refused(self) -> None:
        forged = self._manifest_with(interpreter_sha256="1" * 64)
        with self.assertRaises(CapsuleIdentityRefused):
            forged.recheck()

    def test_a_replaced_in_capsule_init_is_refused(self) -> None:
        forged = self._manifest_with(capsule_init_sha256="2" * 64)
        with self.assertRaises(CapsuleIdentityRefused):
            forged.recheck()

    def test_a_moved_launcher_inode_is_refused(self) -> None:
        forged = self._manifest_with(mechanism_inode=self.manifest.mechanism_inode + 1)
        with self.assertRaises(CapsuleIdentityRefused):
            forged.recheck()

    def test_a_changed_package_source_identity_is_refused(self) -> None:
        forged = self._manifest_with(package_source_sha256="3" * 64)
        with self.assertRaises(CapsuleIdentityRefused):
            forged.recheck()

    def test_a_path_substitution_is_refused_even_with_the_recorded_bytes_intact(self) -> None:
        shadow = Path(tempfile.mkdtemp(prefix="admissible-shadow-"))
        self.addCleanup(shutil.rmtree, shadow, True)
        shutil.copyfile(self.manifest.mechanism_path, shadow / "bwrap")
        os.chmod(shadow / "bwrap", 0o755)
        with self.assertRaises(CapsuleIdentityRefused) as caught:
            self.manifest.recheck(resolver=lambda: str(shadow / "bwrap"))
        self.assertIn("resolves to", str(caught.exception))

    def test_a_group_writable_capsule_input_is_refused(self) -> None:
        copy = Path(tempfile.mkdtemp(prefix="admissible-mode-"))
        self.addCleanup(shutil.rmtree, copy, True)
        target = copy / "bwrap"
        shutil.copyfile(self.manifest.mechanism_path, target)
        os.chmod(target, 0o775)
        with self.assertRaises(CapsuleIdentityRefused) as caught:
            build_runtime_manifest(
                mechanism="bubblewrap",
                mechanism_version="test",
                mechanism_path=str(target),
                interpreter_path=self.manifest.interpreter_path,
                capsule_init_path=self.manifest.capsule_init_path,
                toolchain_inputs=(),
                namespace_contract=(),
                mount_contract=(),
                containment_mechanism="RLIMIT",
                containment_bounds={},
            )
        self.assertIn("world-writable", str(caught.exception))

    def test_a_substituted_capsule_refuses_before_the_proposal_is_durable(self) -> None:
        import dataclasses

        # The forged manifest travels on a private readiness object.  The shared
        # readiness singleton is never mutated: poisoning it would silently
        # change every other test in this process.
        forged = self._manifest_with(mechanism_sha256="4" * 64)
        readiness = dataclasses.replace(CAPSULE_READY, runtime_manifest=forged)
        specification = build_specification("DIRECT", run_id="run-substituted")
        disposable = DisposableWorkspace()
        self.addCleanup(disposable.close)
        binding = WorkspaceBinding.bind(
            disposable.workspace,
            specification,
            evidence_root=disposable.store_root,
            readiness=readiness,
        )
        self.addCleanup(binding.close)
        store = DurableObjectStore(disposable.store_root)
        substrate = SharedEffectSubstrate(
            binding=binding, store=store, ledger=RunEffectLedger("run-substituted")
        )
        proposal = build_proposal(
            specification,
            WriteFileRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                path="a.txt",
                content="a",
            ),
            proposal_id="proposal-1",
        )
        with self.assertRaises(ConfigurationRefused) as caught:
            substrate.execute(
                specification=specification,
                proposal=proposal,
                decision=decision_for(proposal),
                reservation_id="reservation-1",
                receipt_id="receipt-1",
            )
        self.assertEqual(caught.exception.code, "CAPSULE_RUNTIME_IDENTITY_REFUSED")
        # Nothing became durable: the refusal is genuinely pre-proposal.
        self.assertEqual(store.inspect(OBJECT_KIND_PROPOSAL, "proposal-1").state, "ABSENT")


# --- M2-M18: resource containment ---------------------------------------------


@requires_capsule
class ResourceContainmentTests(unittest.TestCase):
    """The untrusted process domain is bounded, not merely timed."""

    def setUp(self) -> None:
        self.harness = _Harness(run_id="run-bounds")
        self.addCleanup(self.harness.close)

    def test_readiness_records_the_mechanism_actually_in_force(self) -> None:
        self.assertTrue(CAPSULE_READY.resource_bounds_enforced)
        self.assertIn(CAPSULE_READY.containment_mechanism, ("CGROUP_V2_AND_RLIMIT", "RLIMIT"))
        delegation = probe_cgroup_delegation()
        if not delegation.available:
            # An honest record: no aggregate accounting is claimed on a host that
            # delegates no cgroup subtree.
            self.assertEqual(CAPSULE_READY.containment_mechanism, "RLIMIT")

    def test_a_fork_bomb_is_bounded(self) -> None:
        outcome = self.harness.command(
            "import os, errno\n"
            "forked = 0\n"
            "try:\n"
            "    while forked < 5000:\n"
            "        if os.fork() == 0:\n"
            "            os._exit(0)\n"
            "        forked += 1\n"
            "except OSError as error:\n"
            "    print('BOUNDED', forked, error.errno == errno.EAGAIN)\n"
            "else:\n"
            "    print('UNBOUNDED', forked)\n"
        )
        self.assertTrue(outcome.tool_result.stdout.startswith("BOUNDED"), outcome.tool_result.stdout)
        bounded, count, correct_errno = outcome.tool_result.stdout.split()
        self.assertLess(int(count), 5000)
        self.assertEqual(correct_errno, "True")

    def test_a_memory_allocation_is_bounded(self) -> None:
        outcome = self.harness.command(
            "try:\n"
            "    bytearray(8 * 1024 * 1024 * 1024)\n"
            "    print('UNBOUNDED')\n"
            "except MemoryError:\n"
            "    print('BOUNDED')\n"
        )
        self.assertEqual(outcome.tool_result.stdout.strip(), "BOUNDED")

    def test_descriptor_exhaustion_is_bounded(self) -> None:
        outcome = self.harness.command(
            "import os, errno\n"
            "handles = []\n"
            "try:\n"
            "    while len(handles) < 100000:\n"
            "        handles.append(os.open('/dev/null', os.O_RDONLY))\n"
            "    print('UNBOUNDED')\n"
            "except OSError as error:\n"
            "    print('BOUNDED', len(handles), error.errno == errno.EMFILE)\n"
        )
        self.assertTrue(outcome.tool_result.stdout.startswith("BOUNDED"), outcome.tool_result.stdout)

    def test_a_large_file_write_is_bounded(self) -> None:
        outcome = self.harness.command(
            "import os, signal, sys\n"
            "signal.signal(signal.SIGXFSZ, lambda *a: sys.exit('BOUNDED_BY_SIGNAL'))\n"
            "handle = os.open('/workspace/big.bin', os.O_CREAT | os.O_WRONLY, 0o600)\n"
            "written = 0\n"
            "try:\n"
            "    while written < 4 * 1024 * 1024 * 1024:\n"
            "        written += os.write(handle, b'x' * (4 * 1024 * 1024))\n"
            "    print('UNBOUNDED', written)\n"
            "except OSError:\n"
            "    print('BOUNDED', written)\n",
            timeout_ms=60_000,
        )
        combined = outcome.tool_result.stdout + outcome.tool_result.stderr
        self.assertNotIn("UNBOUNDED", combined)
        written = (self.harness.workspace / "big.bin").stat().st_size
        self.assertLessEqual(written, ResourceBounds.for_timeout(0).max_file_size_bytes)

    def test_a_cpu_loop_is_stopped_by_the_requested_timeout(self) -> None:
        outcome = self.harness.command("while True:\n    pass\n", timeout_ms=2_000)
        self.assertEqual(outcome.receipt.status, "TIMED_OUT")
        process = self.harness.store.load("process-observation", "proposal-1")
        self.assertTrue(process["timed_out"])
        # The escalation is namespace-wide and ordered: SIGTERM first, and
        # SIGKILL only if anything survived the grace period.
        self.assertEqual(process["termination_escalation"][0], "SIGTERM_PID_NAMESPACE")
        self.assertTrue(process["namespace_quiescent"])

    def test_the_effective_bounds_are_recorded_in_the_durable_observation(self) -> None:
        self.harness.command("print('bounded')")
        resource = self.harness.store.load("resource-observation", "proposal-1")
        self.assertIn(resource["containment_mechanism"], ("CGROUP_V2_AND_RLIMIT", "RLIMIT"))
        self.assertEqual(resource["containment_availability"], "OBSERVED")
        recorded = {item.split("=")[0] for item in resource["containment_bounds"]}
        self.assertEqual(
            recorded
            & {
                "max_processes",
                "max_address_space_bytes",
                "max_cpu_seconds",
                "max_open_files",
                "max_file_size_bytes",
                "core_dump_bytes",
            },
            {
                "max_processes",
                "max_address_space_bytes",
                "max_cpu_seconds",
                "max_open_files",
                "max_file_size_bytes",
                "core_dump_bytes",
            },
        )
        self.assertIn("core_dump_bytes=0", resource["containment_bounds"])

    def test_an_unrelated_host_process_is_untouched(self) -> None:
        sentinel = subprocess.Popen(  # noqa: S603 - explicit argv, disposable
            [PYTHON, "-c", "import time; time.sleep(20)"]
        )
        self.addCleanup(sentinel.kill)
        try:
            self.harness.command(
                "import os\n"
                "for _ in range(50):\n"
                "    try:\n"
                "        if os.fork() == 0:\n"
                "            os._exit(0)\n"
                "    except OSError:\n"
                "        break\n"
                "print('done')\n"
            )
        finally:
            self.assertIsNone(sentinel.poll())


# --- M2-M19: observation race detection ---------------------------------------


class ObservationRaceTests(unittest.TestCase):
    """A file that moves while it is hashed is never reported as complete."""

    def setUp(self) -> None:
        self.disposable = DisposableWorkspace()
        self.addCleanup(self.disposable.close)
        self.root_fd = os.open(self.disposable.workspace, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root_fd)

    def test_the_stable_identity_covers_every_field_a_rewrite_can_move(self) -> None:
        target = self.disposable.workspace / "a.txt"
        target.write_bytes(b"x" * 64)
        before = stable_identity(os.stat(target))
        time.sleep(0.01)
        # A same-size rewrite: the audited case that left size unchanged.
        target.write_bytes(b"y" * 64)
        self.assertNotEqual(stable_identity(os.stat(target)), before)

    def test_a_same_size_mutation_during_hashing_is_detected(self) -> None:
        target = self.disposable.workspace / "big.bin"
        size = 48 * 1024 * 1024
        target.write_bytes(b"a" * size)
        detected = False
        for _ in range(24):
            stop = threading.Event()

            def rewrite() -> None:
                time.sleep(0.004)
                if stop.is_set():
                    return
                with open(target, "r+b") as handle:
                    handle.seek(size // 2)
                    handle.write(b"b" * 4096)

            writer = threading.Thread(target=rewrite, daemon=True)
            writer.start()
            observation = observe_filesystem(self.root_fd, phase="INITIAL")
            stop.set()
            writer.join(timeout=5)
            if any("changed_while_it_was_being_hashed" in error for error in observation.errors):
                detected = True
                self.assertEqual(observation.completeness, "INCOMPLETE_OBSERVATION_ERROR")
                self.assertEqual(observation.availability, "OBSERVED_BEST_EFFORT")
                self.assertFalse(observation.is_final_repository_fingerprint)
                break
            target.write_bytes(b"a" * size)
        self.assertTrue(detected, "a concurrent same-size rewrite was never detected")

    def test_a_quiet_file_still_hashes_completely(self) -> None:
        (self.disposable.workspace / "a.txt").write_text("quiet\n", encoding="utf-8")
        observation = observe_filesystem(self.root_fd, phase="INITIAL")
        self.assertEqual(observation.completeness, "COMPLETE")
        self.assertEqual(observation.content_hashed_file_count, 1)
        self.assertTrue(observation.is_final_repository_fingerprint)


# --- M2-M20: the schema preflight check ---------------------------------------


@requires_capsule
class SchemaPreflightTests(unittest.TestCase):
    """The preflight schema check compares against a constant, not itself."""

    def test_the_check_is_against_the_supported_version(self) -> None:
        import inspect

        from admissible.paired_runner import effects

        source = inspect.getsource(effects.SharedEffectSubstrate.preflight)
        self.assertNotIn(
            "specification.schema_version != specification.schema_version", source
        )
        self.assertIn("SUPPORTED_SPECIFICATION_SCHEMA_VERSION", source)

    def test_an_unsupported_specification_schema_is_refused(self) -> None:
        harness = _Harness(run_id="run-schema")
        self.addCleanup(harness.close)
        proposal = build_proposal(
            harness.specification,
            WriteFileRequest.create(
                tool_grammar_fingerprint=harness.grammar, path="a.txt", content="a"
            ),
            proposal_id="proposal-1",
        )
        object.__setattr__(harness.specification, "schema_version", 999)
        with self.assertRaises(ConfigurationRefused) as caught:
            harness.substrate.preflight(harness.specification, proposal)
        self.assertEqual(caught.exception.code, "SCHEMA_VERSION_MISMATCH")


if __name__ == "__main__":
    unittest.main()
