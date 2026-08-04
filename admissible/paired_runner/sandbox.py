"""The one Linux capsule every paired-runner effect process executes inside.

Milestone 2 shipped ``run_command`` as a bare :class:`subprocess.Popen` whose
only restriction was its working directory.  That restricts nothing: a typed
command may name any absolute host path, so it could read the operator's home
directory, reach the network, and -- decisively -- open and rewrite the durable
evidence store that is supposed to be the independent record of what it did.
An effect process that can edit its own evidence is not observed, it is trusted.

This module replaces that path with a single capsule construction shared by the
future DIRECT and GOVERNED modes.  There is exactly one implementation here and
no mode ever gets a different one; the condition is not an input to any function
in this file.

Provenance
----------
The construction is the approved strong-canary boundary launcher shape recorded
in ``implementation/M2_SANDBOX_CONTRACT.md``:

* a ``bubblewrap`` boundary launcher rather than an in-process restriction, so
  the boundary is enforced by the kernel and not by the cooperation of the
  command;
* mount-namespace construction in which the workspace appears at one fixed
  internal path and nothing else of the host filesystem is named;
* a private PID namespace with an explicit init that reaps
  (:mod:`admissible.paired_runner._capsule_init`);
* network isolation by unshared network namespace, never by a filter the
  command could route around;
* a seccomp syscall boundary that denies every Unix-domain socket and every
  ``mknod``, because a network namespace does *not* isolate filesystem IPC
  (:mod:`admissible.paired_runner.capsule_seccomp`);
* per-command resource bounds applied inside the capsule, because a PID
  namespace is a naming boundary and not a quota
  (:mod:`admissible.paired_runner.resource_limits`);
* descriptor and evidence-root separation, so the process-domain observation
  travels on a descriptor the effect does not hold and the evidence root is
  never mounted at all.

Governing principle
-------------------
The effect process is untrusted.  Nothing here depends on the command choosing
to behave: not on relative paths, not on staying in its process group, not on
declining to call ``setsid``, not on declining to open a socket, and not on the
secrecy of any path.  The evidence root is unreachable because it is absent from
the mount namespace, which no amount of path construction inside the capsule can
undo.

Correction recorded by the independent audit
--------------------------------------------
The earlier statement that "an unshared network namespace plus an absent
evidence path means no host capability is reachable" was **false**.  A pathname
``AF_UNIX`` socket is a filesystem object that crosses an unshared network
namespace and can transfer an open file descriptor with ``SCM_RIGHTS``; a FIFO
in the writable workspace is the same bridge.  The capsule now enforces, by two
independent mechanisms, that the command sees no host-backed IPC endpoint and
cannot create one: workspace admission refuses a workspace containing a socket,
FIFO, or device, and the seccomp filter denies their creation and use.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from typing import Any

from .canonical import Fingerprint, fingerprint
from .capsule_identity import CapsuleIdentityRefused, CapsuleRuntimeManifest, build_runtime_manifest
from .capsule_seccomp import SeccompUnavailable, describe as describe_seccomp, open_program_descriptor
from .resource_limits import (
    MECHANISM_CGROUP_AND_RLIMIT,
    MECHANISM_RLIMIT,
    CgroupDelegation,
    ResourceBounds,
    probe_cgroup_delegation,
)


#: The single internal path at which the authorized workspace is exposed.
CAPSULE_WORKSPACE_PATH = "/workspace"
#: The internal path of the read-only init/reaper.
CAPSULE_INIT_PATH = "/.admissible-capsule-init"
#: The mechanism this milestone requires.  There is no fallback.
CAPSULE_MECHANISM = "bubblewrap"

#: The explicit, closed list of host inputs a capsule may expose read-only.
#: Every entry is a runtime or toolchain input.  ``/etc`` is deliberately absent
#: so no host credential, account, or resolver configuration is nameable, and
#: ``/home`` is deliberately absent so no operator data is nameable.
CAPSULE_TOOLCHAIN_INPUTS: tuple[str, ...] = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
)

#: The exact environment a capsuled effect receives.  It is built from nothing:
#: ``--clearenv`` discards the controller's environment inside the capsule, so
#: no credential, token, provider variable, or host ``HOME`` can be inherited.
CAPSULE_ENVIRONMENT: dict[str, str] = {
    "PATH": "/usr/bin:/bin",
    "HOME": CAPSULE_WORKSPACE_PATH,
    "PWD": CAPSULE_WORKSPACE_PATH,
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "TMPDIR": "/tmp",
}

CAPSULE_DESCRIPTOR_DOMAIN = "admissible.paired_runner.m2.capsule.descriptor"

#: The isolation flags every capsule is launched with, recorded in the runtime
#: manifest so the contract is durable evidence rather than a code comment.
CAPSULE_NAMESPACE_CONTRACT: tuple[str, ...] = (
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
    "--clearenv",
    "--die-with-parent",
    "--new-session",
    "--as-pid-1",
    "--seccomp",
)

#: The mount construction, in the same durable form.
CAPSULE_MOUNT_CONTRACT: tuple[str, ...] = (
    "proc:/proc",
    "tmpfs:/tmp",
    "dev:/dev",
    f"ro-bind-try:{':'.join(CAPSULE_TOOLCHAIN_INPUTS)}",
    f"bind:<authorized workspace>->{CAPSULE_WORKSPACE_PATH}",
    f"ro-bind:<in-capsule init>->{CAPSULE_INIT_PATH}",
    "absent:<durable evidence root>",
)

#: Bound on the status document the in-capsule init may write.
MAX_STATUS_BYTES = 4096
#: How long the controller waits for the capsule to disappear after it kills it.
CAPSULE_TEARDOWN_TIMEOUT_SECONDS = 30.0
#: The bounds the readiness probe demands the kernel actually enforce.
PROBE_BOUNDS = ResourceBounds(
    max_processes=16,
    max_address_space_bytes=512 * 1024 * 1024,
    max_cpu_seconds=30,
    max_open_files=64,
    max_file_size_bytes=1024 * 1024,
    core_dump_bytes=0,
)


class SandboxUnavailable(RuntimeError):
    """The capsule mechanism is not usable, so no effect may be attempted.

    This is raised during readiness, before any proposal is published and
    therefore before any effect boundary exists.  It is never downgraded to an
    unsandboxed execution: an unsandboxed ``Popen`` is not a degraded capsule,
    it is the absence of the boundary this milestone exists to provide.
    """


@dataclass(frozen=True)
class CapsuleReadiness:
    """The typed outcome of physically probing the capsule mechanism."""

    available: bool
    mechanism: str
    mechanism_path: str | None
    mechanism_version: str | None
    probe_detail: str
    unshare_user: bool
    unshare_pid: bool
    unshare_net: bool
    private_tmp: bool
    private_proc: bool
    unix_domain_sockets_denied: bool = False
    special_file_creation_denied: bool = False
    resource_bounds_enforced: bool = False
    containment_mechanism: str = "NONE"
    cgroup_delegation: CgroupDelegation | None = None
    runtime_manifest: CapsuleRuntimeManifest | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "mechanism": self.mechanism,
            "mechanism_path": self.mechanism_path,
            "mechanism_version": self.mechanism_version,
            "probe_detail": self.probe_detail,
            "unshare_user": self.unshare_user,
            "unshare_pid": self.unshare_pid,
            "unshare_net": self.unshare_net,
            "private_tmp": self.private_tmp,
            "private_proc": self.private_proc,
            "unix_domain_sockets_denied": self.unix_domain_sockets_denied,
            "special_file_creation_denied": self.special_file_creation_denied,
            "resource_bounds_enforced": self.resource_bounds_enforced,
            "containment_mechanism": self.containment_mechanism,
            "cgroup_delegation": None if self.cgroup_delegation is None else self.cgroup_delegation.to_dict(),
            "runtime_manifest_fingerprint": (
                None if self.runtime_manifest is None else self.runtime_manifest.record_fingerprint.to_dict()
            ),
        }

    def require(self) -> "CapsuleReadiness":
        if not self.available:
            raise SandboxUnavailable(
                f"the {self.mechanism} capsule is unavailable: {self.probe_detail}"
            )
        return self


@dataclass(frozen=True)
class CapsuleProcessStatus:
    """The one exact process-domain observation the capsule returns."""

    started: bool
    direct_exit_code: int | None
    direct_terminating_signal: int | None
    extra_descendants_reaped: int
    descendants_alive_at_direct_exit: bool
    namespace_quiescent: bool
    timed_out: bool
    cancelled: bool
    termination_escalation: tuple[str, ...]
    launcher_pid: int | None
    launcher_exit_code: int | None
    status_document_present: bool
    start_failure_class: str | None


def _base_argv(mechanism_path: str, *, seccomp_fd: int | None) -> list[str]:
    argv = [
        mechanism_path,
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--clearenv",
        "--die-with-parent",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]
    if seccomp_fd is not None:
        argv += ["--seccomp", str(seccomp_fd)]
    for source in CAPSULE_TOOLCHAIN_INPUTS:
        argv += ["--ro-bind-try", source, source]
    return argv


def _probe_command(mechanism_path: str, script: str, *, seccomp: bool) -> tuple[bool, str]:
    """Run one throwaway capsule and report whether it behaved as required."""

    descriptor = None
    try:
        descriptor = open_program_descriptor() if seccomp else None
    except (SeccompUnavailable, OSError) as error:
        return False, f"seccomp_unavailable:{error}"
    try:
        argv = _base_argv(mechanism_path, seccomp_fd=descriptor)
        argv += ["--", os.path.realpath(os.sys.executable), "-c", script]
        try:
            completed = subprocess.run(  # noqa: S603 - explicit argv, never a shell
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=60,
                check=False,
                pass_fds=() if descriptor is None else (descriptor,),
            )
        except (OSError, subprocess.SubprocessError) as error:
            return False, f"probe_failed:{type(error).__name__}"
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:200]
        return False, f"probe_exit_{completed.returncode}:{detail}"
    return True, completed.stdout.decode("utf-8", "replace").strip()[:200]


_READINESS_LOCK = threading.Lock()
_READINESS_CACHE: CapsuleReadiness | None = None


def probe_capsule_readiness(*, force: bool = False) -> CapsuleReadiness:
    """Physically prove the capsule works before any effect is attempted.

    The probe is not a version check.  It constructs a real capsule and requires
    the kernel to demonstrate each isolation the contract depends on, because a
    present ``bwrap`` binary on a host whose unprivileged user namespaces are
    disabled would otherwise be mistaken for a working boundary.  The same
    applies to the two mechanisms this repair adds: a seccomp program the kernel
    silently failed to load, and a resource bound the kernel did not honour, are
    each a readiness refusal rather than an unbounded capsule.
    """

    global _READINESS_CACHE
    with _READINESS_LOCK:
        if _READINESS_CACHE is not None and not force:
            return _READINESS_CACHE
        readiness = _probe_capsule_readiness_uncached()
        _READINESS_CACHE = readiness
        return readiness


def _unavailable(detail: str, path: str | None = None) -> CapsuleReadiness:
    return CapsuleReadiness(
        available=False,
        mechanism=CAPSULE_MECHANISM,
        mechanism_path=path,
        mechanism_version=None,
        probe_detail=detail,
        unshare_user=False,
        unshare_pid=False,
        unshare_net=False,
        private_tmp=False,
        private_proc=False,
    )


#: The isolation probe.  It resolves its modules through ``__import__`` rather
#: than an import statement because the package is asserted elsewhere to contain
#: no network import, and a probe string is not an exception worth carving out.
_ISOLATION_PROBE = (
    "os = __import__('os'); sys = __import__('sys')\n"
    "sock = __import__('socket')\n"
    "assert not os.path.exists('/home'), 'host /home is visible'\n"
    "assert not os.path.exists('/etc/passwd'), 'host /etc is visible'\n"
    "assert os.path.isdir('/proc/self'), 'private /proc is absent'\n"
    "assert os.stat('/tmp').st_dev != os.stat('/usr').st_dev, 'private /tmp is absent'\n"
    "assert not os.listdir('/tmp'), 'private /tmp is not empty'\n"
    "s=sock.socket()\n"
    "s.settimeout(2)\n"
    "try:\n"
    "    s.connect(('192.0.2.1',80))\n"
    "    sys.exit('network reachable')\n"
    "except OSError as error:\n"
    "    assert error.errno == %d, 'network not unshared: %%r' %% (error,)\n"
    # The seccomp boundary, proven from inside: a Unix-domain socket of either
    # flavour and a FIFO must all be refused by the kernel.
    "try:\n"
    "    sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)\n"
    "    sys.exit('AF_UNIX socket creation was permitted')\n"
    "except OSError as error:\n"
    "    assert error.errno == %d, 'AF_UNIX not denied: %%r' %% (error,)\n"
    "try:\n"
    "    sock.socketpair()\n"
    "    sys.exit('AF_UNIX socketpair was permitted')\n"
    "except OSError as error:\n"
    "    assert error.errno == %d, 'socketpair not denied: %%r' %% (error,)\n"
    "try:\n"
    "    os.mkfifo('/tmp/probe-fifo')\n"
    "    sys.exit('FIFO creation was permitted')\n"
    "except OSError as error:\n"
    "    assert error.errno == %d, 'mknod not denied: %%r' %% (error,)\n"
    "print('capsule-isolations-verified')\n"
    % (errno.ENETUNREACH, errno.EPERM, errno.EPERM, errno.EPERM)
)

#: The containment probe.  It runs through the real init, with the real bounds
#: argument, and requires the kernel to stop an unbounded consumer.
_CONTAINMENT_PROBE = (
    "os = __import__('os'); sys = __import__('sys')\n"
    "errno_module = __import__('errno')\n"
    "forked = 0\n"
    "try:\n"
    "    while forked < 200:\n"
    "        pid = os.fork()\n"
    "        if pid == 0:\n"
    "            os._exit(0)\n"
    "        forked += 1\n"
    "except OSError as error:\n"
    "    assert error.errno == errno_module.EAGAIN, 'fork failed for the wrong reason'\n"
    "else:\n"
    "    sys.exit('the process bound was not enforced')\n"
    "try:\n"
    "    bytearray(1024 * 1024 * 1024)\n"
    "    sys.exit('the address-space bound was not enforced')\n"
    "except MemoryError:\n"
    "    pass\n"
    "descriptors = []\n"
    "try:\n"
    "    while len(descriptors) < 4096:\n"
    "        descriptors.append(os.open('/dev/null', os.O_RDONLY))\n"
    "    sys.exit('the descriptor bound was not enforced')\n"
    "except OSError as error:\n"
    "    assert error.errno == errno_module.EMFILE, 'descriptors failed for the wrong reason'\n"
    "print('capsule-containment-verified')\n"
)


def _probe_containment(mechanism_path: str) -> tuple[bool, str]:
    """Run the real init, with real bounds, and require enforcement."""

    workspace = tempfile.mkdtemp(prefix="admissible-capsule-probe-")
    status_read, status_write = os.pipe()
    control_read, control_write = os.pipe()
    descriptor = None
    try:
        descriptor = open_program_descriptor()
        argv = _base_argv(mechanism_path, seccomp_fd=descriptor)
        argv += ["--dev", "/dev", "--new-session", "--as-pid-1"]
        argv += ["--bind", workspace, CAPSULE_WORKSPACE_PATH]
        argv += ["--ro-bind", _init_source_path(), CAPSULE_INIT_PATH]
        argv += ["--chdir", CAPSULE_WORKSPACE_PATH]
        argv += [
            "--",
            os.path.realpath(os.sys.executable),
            CAPSULE_INIT_PATH,
            str(status_write),
            str(control_read),
            "60000",
            PROBE_BOUNDS.encode(),
            os.path.realpath(os.sys.executable),
            "-c",
            _CONTAINMENT_PROBE,
        ]
        completed = subprocess.run(  # noqa: S603 - explicit argv, never a shell
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=120,
            check=False,
            pass_fds=(status_write, control_read, descriptor),
        )
        os.close(status_write)
        status_write = -1
        raw = b""
        while len(raw) < MAX_STATUS_BYTES:
            chunk = os.read(status_read, 512)
            if not chunk:
                break
            raw += chunk
        status = parse_capsule_status(raw)
        if completed.returncode != 0:
            return False, f"containment_probe_exit_{completed.returncode}"
        if b"capsule-containment-verified" not in completed.stdout:
            return False, f"containment_probe_output:{completed.stdout.decode('utf-8', 'replace')[:120]}"
        if status is None:
            return False, "containment_probe_status_document_absent"
        if not status.get("resource_limits_applied"):
            return False, f"containment_probe_limits_not_applied:{status.get('resource_limit_failure_errno')}"
        if status.get("direct_exit_code") != 0:
            return False, f"containment_probe_direct_exit:{status.get('direct_exit_code')}"
        return True, "capsule-containment-verified"
    except (OSError, subprocess.SubprocessError, SeccompUnavailable) as error:
        return False, f"containment_probe_failed:{type(error).__name__}:{error}"
    finally:
        for handle in (status_read, status_write, control_read, control_write, descriptor):
            if handle is None or handle < 0:
                continue
            try:
                os.close(handle)
            except OSError:  # pragma: no cover
                pass
        shutil.rmtree(workspace, ignore_errors=True)


def _probe_capsule_readiness_uncached() -> CapsuleReadiness:
    resolved = shutil.which("bwrap")
    if resolved is None:
        return _unavailable("the bwrap executable is not on PATH")
    mechanism_path = os.path.realpath(resolved)

    try:
        version = subprocess.run(  # noqa: S603 - explicit argv, never a shell
            [mechanism_path, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
        ).stdout.decode("utf-8", "replace").strip()[:100]
    except (OSError, subprocess.SubprocessError) as error:
        return _unavailable(f"bwrap --version failed:{type(error).__name__}", mechanism_path)

    ok, detail = _probe_command(mechanism_path, _ISOLATION_PROBE, seccomp=True)
    if not ok:
        return _unavailable(detail, mechanism_path)

    contained, containment_detail = _probe_containment(mechanism_path)
    if not contained:
        return _unavailable(containment_detail, mechanism_path)

    delegation = probe_cgroup_delegation()
    mechanism_in_force = MECHANISM_CGROUP_AND_RLIMIT if delegation.available else MECHANISM_RLIMIT

    try:
        manifest = build_runtime_manifest(
            mechanism=CAPSULE_MECHANISM,
            mechanism_version=version,
            mechanism_path=mechanism_path,
            interpreter_path=os.path.realpath(os.sys.executable),
            capsule_init_path=_init_source_path(),
            toolchain_inputs=CAPSULE_TOOLCHAIN_INPUTS,
            namespace_contract=CAPSULE_NAMESPACE_CONTRACT,
            mount_contract=CAPSULE_MOUNT_CONTRACT,
            containment_mechanism=mechanism_in_force,
            containment_bounds=ResourceBounds.for_timeout(0).to_dict(),
        )
    except (CapsuleIdentityRefused, SeccompUnavailable) as error:
        return _unavailable(f"capsule_runtime_identity_refused:{error}", mechanism_path)

    return CapsuleReadiness(
        available=True,
        mechanism=CAPSULE_MECHANISM,
        mechanism_path=mechanism_path,
        mechanism_version=version,
        probe_detail=f"{detail};{containment_detail}",
        unshare_user=True,
        unshare_pid=True,
        unshare_net=True,
        private_tmp=True,
        private_proc=True,
        unix_domain_sockets_denied=True,
        special_file_creation_denied=True,
        resource_bounds_enforced=True,
        containment_mechanism=mechanism_in_force,
        cgroup_delegation=delegation,
        runtime_manifest=manifest,
    )


def _init_source_path() -> str:
    return os.path.realpath(str(Path(__file__).with_name("_capsule_init.py")))


@dataclass(frozen=True)
class CapsuleSpecification:
    """Exactly how one capsule is constructed, as durable evidence."""

    mechanism: str
    mechanism_path: str
    workspace_host_path: str
    workspace_capsule_path: str
    toolchain_inputs: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    network_enabled: bool
    private_tmp: bool
    private_proc: bool
    private_pid_namespace: bool
    dies_with_supervisor: bool
    evidence_root_exposed: bool
    seccomp_program_sha256: str
    unix_domain_sockets_denied: bool
    special_file_creation_denied: bool
    containment_mechanism: str
    resource_bounds: tuple[tuple[str, int], ...]
    runtime_manifest_fingerprint: Fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "mechanism_path": self.mechanism_path,
            "workspace_host_path": self.workspace_host_path,
            "workspace_capsule_path": self.workspace_capsule_path,
            "toolchain_inputs": list(self.toolchain_inputs),
            "environment": [list(pair) for pair in self.environment],
            "network_enabled": self.network_enabled,
            "private_tmp": self.private_tmp,
            "private_proc": self.private_proc,
            "private_pid_namespace": self.private_pid_namespace,
            "dies_with_supervisor": self.dies_with_supervisor,
            "evidence_root_exposed": self.evidence_root_exposed,
            "seccomp_program_sha256": self.seccomp_program_sha256,
            "unix_domain_sockets_denied": self.unix_domain_sockets_denied,
            "special_file_creation_denied": self.special_file_creation_denied,
            "containment_mechanism": self.containment_mechanism,
            "resource_bounds": [list(pair) for pair in self.resource_bounds],
            "runtime_manifest_fingerprint": self.runtime_manifest_fingerprint.to_dict(),
        }

    def descriptor_fingerprint(self) -> Fingerprint:
        return fingerprint(self.to_dict(), domain=CAPSULE_DESCRIPTOR_DOMAIN)


def _is_within(candidate: Path, ancestor: Path) -> bool:
    try:
        candidate.relative_to(ancestor)
    except ValueError:
        return False
    return True


def build_capsule_specification(
    *,
    workspace_host_path: Path,
    evidence_root: Path,
    readiness: CapsuleReadiness,
    network_enabled: bool = False,
) -> CapsuleSpecification:
    """Describe one capsule and refuse any construction that leaks evidence.

    ``network_enabled`` exists so a future policy field has somewhere exact to
    land.  Milestone 2 never sets it, and enabling it would still not join the
    host network namespace: it is reserved for an explicit future construction,
    not for an ambient inheritance.
    """

    readiness.require()
    if network_enabled:
        raise SandboxUnavailable(
            "network access requires an explicit future policy field that Milestone 2 does not implement"
        )
    if readiness.runtime_manifest is None:
        raise SandboxUnavailable("the capsule runtime manifest is absent, so no capsule identity is bound")

    workspace = Path(os.path.realpath(workspace_host_path))
    evidence = Path(os.path.realpath(evidence_root))

    # The evidence root must not be reachable through any exposed input, and it
    # must not be the workspace or inside it.  This is checked against canonical
    # paths so no symlink or alias can smuggle it in.
    if evidence == workspace or _is_within(evidence, workspace):
        raise SandboxUnavailable("the durable evidence root is inside the exposed workspace")
    exposed_prefixes = [Path(item) for item in CAPSULE_TOOLCHAIN_INPUTS]
    for prefix in exposed_prefixes:
        if evidence == prefix or _is_within(evidence, prefix):
            raise SandboxUnavailable(
                f"the durable evidence root is inside the exposed toolchain input {prefix}"
            )

    return CapsuleSpecification(
        mechanism=CAPSULE_MECHANISM,
        mechanism_path=str(readiness.mechanism_path),
        workspace_host_path=str(workspace),
        workspace_capsule_path=CAPSULE_WORKSPACE_PATH,
        toolchain_inputs=CAPSULE_TOOLCHAIN_INPUTS,
        environment=tuple(sorted(CAPSULE_ENVIRONMENT.items())),
        network_enabled=False,
        private_tmp=True,
        private_proc=True,
        private_pid_namespace=True,
        dies_with_supervisor=True,
        evidence_root_exposed=False,
        seccomp_program_sha256=str(describe_seccomp()["program_sha256"]),
        unix_domain_sockets_denied=True,
        special_file_creation_denied=True,
        containment_mechanism=readiness.containment_mechanism,
        resource_bounds=tuple(sorted(ResourceBounds.for_timeout(0).to_dict().items())),
        runtime_manifest_fingerprint=readiness.runtime_manifest.record_fingerprint,
    )


def capsule_argv(
    specification: CapsuleSpecification,
    *,
    relative_cwd: str,
    status_fd: int,
    control_fd: int,
    seccomp_fd: int,
    timeout_ms: int,
    bounds: ResourceBounds,
    command: tuple[str, ...],
) -> list[str]:
    """The exact launcher argv for one capsuled effect."""

    internal_cwd = (
        CAPSULE_WORKSPACE_PATH
        if relative_cwd in {"", "."}
        else f"{CAPSULE_WORKSPACE_PATH}/{relative_cwd}"
    )
    argv = [
        specification.mechanism_path,
        # Isolation.  Every namespace is unshared; nothing is inherited that the
        # contract does not name.
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        # Credentials and host HOME cannot survive --clearenv.
        "--clearenv",
        # The capsule cannot outlive its supervisor.
        "--die-with-parent",
        # A new terminal session, so no controlling terminal is shared.
        "--new-session",
        # Our init is PID 1 of the private namespace, so every orphan reparents
        # to it and quiescence is derived from ECHILD rather than assumed.
        "--as-pid-1",
        # The syscall boundary.  An unshared network namespace does not isolate
        # filesystem IPC, so Unix-domain sockets and mknod are denied here.
        "--seccomp",
        str(seccomp_fd),
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--dev",
        "/dev",
    ]
    for source in specification.toolchain_inputs:
        argv += ["--ro-bind-try", source, source]
    # The one writable host object in the capsule, at one fixed internal path.
    argv += ["--bind", specification.workspace_host_path, CAPSULE_WORKSPACE_PATH]
    # The init is read-only and lives outside the workspace, so the effect can
    # neither rewrite it nor make the controller execute something else.
    argv += ["--ro-bind", _init_source_path(), CAPSULE_INIT_PATH]
    for name, value in specification.environment:
        argv += ["--setenv", name, value]
    argv += ["--chdir", internal_cwd]
    argv += [
        "--",
        os.path.realpath(os.sys.executable),
        CAPSULE_INIT_PATH,
        str(status_fd),
        str(control_fd),
        str(timeout_ms),
        bounds.encode(),
        *command,
    ]
    return argv


def parse_capsule_status(raw: bytes) -> dict[str, Any] | None:
    """Decode the init's status document, refusing anything unexpected."""

    if not raw or len(raw) > MAX_STATUS_BYTES:
        return None
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    return value


__all__ = [
    "CAPSULE_DESCRIPTOR_DOMAIN",
    "CAPSULE_ENVIRONMENT",
    "CAPSULE_INIT_PATH",
    "CAPSULE_MECHANISM",
    "CAPSULE_MOUNT_CONTRACT",
    "CAPSULE_NAMESPACE_CONTRACT",
    "CAPSULE_TOOLCHAIN_INPUTS",
    "CAPSULE_WORKSPACE_PATH",
    "CAPSULE_TEARDOWN_TIMEOUT_SECONDS",
    "CapsuleProcessStatus",
    "CapsuleReadiness",
    "CapsuleSpecification",
    "MAX_STATUS_BYTES",
    "PROBE_BOUNDS",
    "SandboxUnavailable",
    "build_capsule_specification",
    "capsule_argv",
    "parse_capsule_status",
    "probe_capsule_readiness",
]
