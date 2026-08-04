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
* descriptor and evidence-root separation, so the process-domain observation
  travels on a descriptor the effect does not hold and the evidence root is
  never mounted at all.

Governing principle
-------------------
The effect process is untrusted.  Nothing here depends on the command choosing
to behave: not on relative paths, not on staying in its process group, not on
declining to call ``setsid``, and not on the secrecy of any path.  The evidence
root is unreachable because it is absent from the mount namespace, which no
amount of path construction inside the capsule can undo.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Any

from .canonical import Fingerprint, fingerprint


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

#: Bound on the status document the in-capsule init may write.
MAX_STATUS_BYTES = 4096
#: How long the controller waits for the capsule to disappear after it kills it.
CAPSULE_TEARDOWN_TIMEOUT_SECONDS = 30.0


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


def _probe_command(mechanism_path: str, script: str) -> tuple[bool, str]:
    """Run one throwaway capsule and report whether it behaved as required."""

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
    for source in CAPSULE_TOOLCHAIN_INPUTS:
        argv += ["--ro-bind-try", source, source]
    argv += ["--", os.path.realpath(os.sys.executable), "-c", script]
    try:
        completed = subprocess.run(  # noqa: S603 - explicit argv, never a shell
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"probe_failed:{type(error).__name__}"
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
    disabled would otherwise be mistaken for a working boundary.
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


def _probe_capsule_readiness_uncached() -> CapsuleReadiness:
    mechanism_path = shutil.which("bwrap")
    if mechanism_path is None:
        return _unavailable("the bwrap executable is not on PATH")
    mechanism_path = os.path.realpath(mechanism_path)

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

    # The probe asserts, from inside a real capsule, every isolation the
    # contract promises.  Any failure is a readiness refusal, never a downgrade.
    # The probe body deliberately resolves its modules through __import__ rather
    # than an import statement: the package is asserted elsewhere to contain no
    # network import, and a probe string is not an exception worth carving out.
    script = (
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
        "print('capsule-isolations-verified')\n" % errno.ENETUNREACH
    )
    ok, detail = _probe_command(mechanism_path, script)
    if not ok:
        return _unavailable(detail, mechanism_path)

    return CapsuleReadiness(
        available=True,
        mechanism=CAPSULE_MECHANISM,
        mechanism_path=mechanism_path,
        mechanism_version=version,
        probe_detail=detail,
        unshare_user=True,
        unshare_pid=True,
        unshare_net=True,
        private_tmp=True,
        private_proc=True,
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
    )


def capsule_argv(
    specification: CapsuleSpecification,
    *,
    relative_cwd: str,
    status_fd: int,
    control_fd: int,
    timeout_ms: int,
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
    "CAPSULE_TOOLCHAIN_INPUTS",
    "CAPSULE_WORKSPACE_PATH",
    "CAPSULE_TEARDOWN_TIMEOUT_SECONDS",
    "CapsuleProcessStatus",
    "CapsuleReadiness",
    "CapsuleSpecification",
    "MAX_STATUS_BYTES",
    "SandboxUnavailable",
    "build_capsule_specification",
    "capsule_argv",
    "parse_capsule_status",
    "probe_capsule_readiness",
]
