"""Boundary launcher for already-confined controller and Codex processes.

The launcher is part of the V0 TCB.  It creates all socketpairs before the
general controller exists, starts the Docker-owning broker outside the
controller mount/network namespaces, and launches the controller into an
empty bubblewrap view.  No authentication source path is accepted by the
controller launch interface.
"""

from __future__ import annotations

import ctypes
import argparse
import errno
import fcntl
import os
import platform
import socket
import stat
import struct
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.authentication_broker import (
    AuthenticationBrokerProcess,
)
from admissible.capsule.boundary_authority import (
    DestinationManifest,
    OSBoundaryAuthority,
    fixed_cleanup_policy,
)
from admissible.capsule.broker_transport import (
    make_seqpacket_socketpair,
    protocol_schema_identities,
)
from admissible.capsule.capsule_broker import (
    CapsuleBrokerConfig,
    CapsuleBrokerProcess,
    capsule_broker_component_identity,
)
from admissible.capsule.common import (
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_sha256,
    sha256_bytes,
)
from admissible.capsule.egress_relay import send_listener_descriptor
from admissible.capsule.execution_authority import (
    ExecutableFileIdentity,
    source_component_identity,
    synthetic_component_identity,
    validate_component_identity,
)
from admissible.capsule.model_authority import (
    CodexModelAuthority,
    validate_launch_configuration_bytes,
)


BOUNDARY_LIFECYCLE_SCHEMA_VERSION = "admissible_codex_boundary_lifecycle_v1"
EPHEMERAL_CONFIG_FILENAME = "config.toml"
#: The only Codex arguments the namespace bootstrap will exec.  No ``-c`` /
#: ``--config`` override is ever passed: the configuration channel is the
#: broker-generated ephemeral file plus the app-server request fields, and both
#: are byte-bound into the model authority.
#:
#: ``--strict-config`` is deliberately *not* used.  Pinned 0.145.0 applies it to
#: the ``thread/start`` configuration overlay as well, and the audited
#: preventive control overlay legitimately carries feature keys this build does
#: not recognize, so the flag would refuse the existing production thread.
CODEX_APP_SERVER_ARGUMENTS = ["app-server", "--stdio"]
CONTROLLER_ROOT = "/control"
CONTROLLER_EXECUTABLE = "/runtime/controller"
CONTROLLER_CWD = "/control/data"
CODEX_EXECUTABLE = "/runtime/codex"
CODEX_HOME = "/control/codex-home"
CODEX_CWD = "/control/empty"

PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULESET_VERSION_FLAG = 1
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14


def boundary_launcher_component_identity() -> Mapping[str, Any]:
    return source_component_identity(
        component="boundary_launcher",
        source_bytes=Path(__file__).read_bytes(),
        provider_request_capable=False,
    )


def _component_from_module(component: str, module_path: Path) -> Mapping[str, Any]:
    return source_component_identity(
        component=component,
        source_bytes=module_path.read_bytes(),
        provider_request_capable=False,
    )


def provider_free_os_boundary_authority(
    *,
    dependent_identities: Sequence[Mapping[str, Any]],
    dependent_authorities: Mapping[str, str] | None = None,
) -> OSBoundaryAuthority:
    """Exact source authority for provider-free tests and scripted sessions."""

    root = Path(__file__).parent
    return OSBoundaryAuthority.create(
        boundary_launcher_identity=boundary_launcher_component_identity(),
        authentication_broker_identity=_component_from_module(
            "authentication_broker", root / "authentication_broker.py"
        ),
        capsule_broker_identity=capsule_broker_component_identity(),
        egress_relay_identity=_component_from_module(
            "egress_relay", root / "egress_relay.py"
        ),
        broker_protocol_schema_identities=protocol_schema_identities(),
        destination_manifest=DestinationManifest.load_packaged(),
        dependent_identities=dependent_identities,
        dependent_authorities=(
            dependent_authorities
            if dependent_authorities is not None
            else {
                "capsule_image_content_id": "sha256:" + "0" * 64,
                "capsule_execution_authority_fingerprint": "1" * 64,
                "capsule_broker_runtime_authority_fingerprint": "2" * 64,
                "codex_protocol_schema_identity": "3" * 64,
                "dynamic_tools_schema_identity": "4" * 64,
                "model_binding_policy_fingerprint": "5" * 64,
                "candidate_serialization_witness_receipt_identity": "6" * 64,
                "owner_binding_state": "NON_PRODUCTION_NO_OWNER_BINDING",
                "owner_bound_serialization_receipt_identity": "0" * 64,
            }
        ),
    )


@dataclass(frozen=True)
class BoundaryLaunchSpec:
    argv: tuple[str, ...]
    executable: str
    pass_fds: tuple[int, ...]
    environment: Mapping[str, str]
    cwd: str
    launch_fingerprint: str


@dataclass(frozen=True)
class ControllerConfinementLaunchPolicy:
    """Descriptor-only empty-root launch policy for the general controller."""

    bwrap_identity: ExecutableFileIdentity
    controller_identity: ExecutableFileIdentity
    control_data_descriptors: Mapping[str, int]
    app_server_descriptor: int
    capsule_broker_descriptor: int

    def validated(self) -> "ControllerConfinementLaunchPolicy":
        self.bwrap_identity.reattest(label="boundary bubblewrap executable")
        self.controller_identity.reattest(label="general controller executable")
        if not self.control_data_descriptors:
            raise ValueError("controller requires explicit immutable control data")
        for destination, descriptor in self.control_data_descriptors.items():
            if (
                not destination.startswith(f"{CONTROLLER_CWD}/")
                or ".." in Path(destination).parts
                or not isinstance(descriptor, int)
                or descriptor < 0
            ):
                raise ValueError("invalid controller control-data descriptor binding")
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("controller control data must be regular files")
        channels = (self.app_server_descriptor, self.capsule_broker_descriptor)
        if any(not isinstance(item, int) or item < 0 for item in channels):
            raise ValueError("controller broker channel descriptor is invalid")
        if len(
            {
                *self.control_data_descriptors.values(),
                self.app_server_descriptor,
                self.capsule_broker_descriptor,
            }
        ) != len(self.control_data_descriptors) + 2:
            raise ValueError("controller launch descriptors overlap")
        return self

    @contextmanager
    def descriptor_launch(self):
        self.validated()
        bwrap_fd = os.open(
            self.bwrap_identity.canonical_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        controller_fd = os.open(
            self.controller_identity.canonical_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            argv: list[str] = [
                "bwrap-content-attested",
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--unshare-user",
                "--disable-userns",
                "--clearenv",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/runtime",
                "--tmpfs",
                CONTROLLER_ROOT,
                "--dir",
                CONTROLLER_CWD,
                "--ro-bind-fd",
                str(controller_fd),
                CONTROLLER_EXECUTABLE,
            ]
            for destination, descriptor in sorted(
                self.control_data_descriptors.items()
            ):
                argv.extend(("--ro-bind-fd", str(descriptor), destination))
            argv.extend(
                (
                    "--remount-ro",
                    "/runtime",
                    "--remount-ro",
                    CONTROLLER_ROOT,
                    "--setenv",
                    "LANG",
                    "C.UTF-8",
                    "--setenv",
                    "LC_ALL",
                    "C.UTF-8",
                    "--setenv",
                    "HOME",
                    "/nonexistent",
                    "--setenv",
                    "APP_SERVER_FD",
                    str(self.app_server_descriptor),
                    "--setenv",
                    "CAPSULE_BROKER_FD",
                    str(self.capsule_broker_descriptor),
                    "--chdir",
                    CONTROLLER_CWD,
                    CONTROLLER_EXECUTABLE,
                )
            )
            environment = {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": "/nonexistent",
            }
            policy = {
                "argv": argv,
                "environment": environment,
                "cwd": "/",
                "pass_fd_roles": [
                    "bwrap_executable",
                    "controller_executable",
                    *[
                        f"control_data:{destination}"
                        for destination in sorted(self.control_data_descriptors)
                    ],
                    "app_server",
                    "capsule_broker",
                ],
                "docker_socket_visible": False,
                "docker_executable_visible": False,
                "authentication_visible": False,
                "host_network_visible": False,
            }
            yield BoundaryLaunchSpec(
                argv=tuple(argv),
                executable=f"/proc/self/fd/{bwrap_fd}",
                pass_fds=(
                    bwrap_fd,
                    controller_fd,
                    *(
                        self.control_data_descriptors[key]
                        for key in sorted(self.control_data_descriptors)
                    ),
                    self.app_server_descriptor,
                    self.capsule_broker_descriptor,
                ),
                environment=environment,
                cwd="/",
                launch_fingerprint=fingerprint(policy),
            )
        finally:
            os.close(controller_fd)
            os.close(bwrap_fd)

    def launch(self) -> subprocess.Popen[bytes]:
        """Start the controller already inside its pathname/network boundary."""

        with self.descriptor_launch() as spec:
            return subprocess.Popen(
                spec.argv,
                executable=spec.executable,
                pass_fds=spec.pass_fds,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(spec.environment),
                cwd=spec.cwd,
                start_new_session=True,
                close_fds=True,
            )


@dataclass(frozen=True)
class CodexConfinementLaunchPolicy:
    """Exact private mount/PID/network launch using broker-owned home FD."""

    bwrap_identity: ExecutableFileIdentity
    codex_identity: ExecutableFileIdentity
    namespace_bootstrap_identity: ExecutableFileIdentity
    codex_home_descriptor: int
    app_server_descriptor: int
    proxy_transfer_descriptor: int
    session_id: str
    pin_fingerprint: str
    runtime_dependency_descriptors: Mapping[str, int]
    model_authority: "CodexModelAuthority | None" = None

    def _reattest_effective_configuration(self) -> str:
        """Re-read the broker-owned configuration bytes before starting Codex.

        Only the non-secret ``config.toml`` is read, and only through the
        already-held home directory descriptor.  ``auth.json`` is never opened
        here, and no host pathname is reconstructed.
        """

        if self.model_authority is None:
            raise ValueError("Codex confinement requires an explicit model authority")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            EPHEMERAL_CONFIG_FILENAME,
            flags,
            dir_fd=self.codex_home_descriptor,
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("effective Codex configuration is not a private file")
            expected = self.model_authority.ephemeral_config_bytes
            if info.st_size != len(expected):
                raise ValueError("effective Codex configuration size differs")
            observed = bytearray()
            while len(observed) <= len(expected):
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                observed.extend(chunk)
            if os.fstat(descriptor).st_mtime_ns != info.st_mtime_ns:
                raise ValueError("effective Codex configuration changed while attested")
        finally:
            os.close(descriptor)
        return validate_launch_configuration_bytes(
            bytes(observed), self.model_authority
        )

    def validated(self) -> "CodexConfinementLaunchPolicy":
        self.bwrap_identity.reattest(label="Codex boundary bubblewrap executable")
        self.codex_identity.reattest(label="pinned Codex 0.145.0 executable")
        self.namespace_bootstrap_identity.reattest(
            label="Codex namespace bootstrap executable"
        )
        require_identifier(self.session_id, "Codex boundary session")
        require_sha256(self.pin_fingerprint, "Codex destination pin")
        if self.model_authority is None:
            raise ValueError("Codex confinement requires an explicit model authority")
        self.model_authority.validated().require_revalidated_candidate_receipt()
        if dict(self.model_authority.codex_executable_identity) != (
            self.codex_identity.to_dict()
        ):
            raise ValueError("model authority binds another Codex executable")
        home = os.fstat(self.codex_home_descriptor)
        if not stat.S_ISDIR(home.st_mode):
            raise ValueError("Codex home descriptor is not a directory")
        for descriptor in (
            self.app_server_descriptor,
            self.proxy_transfer_descriptor,
        ):
            if not stat.S_ISSOCK(os.fstat(descriptor).st_mode):
                raise ValueError("Codex boundary channel is not a socket")
        for destination, descriptor in self.runtime_dependency_descriptors.items():
            if (
                not destination.startswith(("/lib/", "/lib64/", "/runtime/lib/"))
                or ".." in Path(destination).parts
                or not stat.S_ISREG(os.fstat(descriptor).st_mode)
            ):
                raise ValueError("invalid Codex runtime dependency binding")
        return self

    @contextmanager
    def descriptor_launch(self):
        self.validated()
        effective_config_identity = self._reattest_effective_configuration()
        opened: list[int] = []
        try:
            for identity in (
                self.bwrap_identity,
                self.codex_identity,
                self.namespace_bootstrap_identity,
            ):
                descriptor = os.open(
                    identity.canonical_path,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                opened.append(descriptor)
            bwrap_fd, codex_fd, bootstrap_fd = opened
            arguments: list[str] = [
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--unshare-user",
                "--disable-userns",
                "--clearenv",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/runtime",
                "--tmpfs",
                "/control",
                "--dir",
                CODEX_CWD,
                "--bind-fd",
                str(self.codex_home_descriptor),
                CODEX_HOME,
                "--ro-bind-fd",
                str(codex_fd),
                CODEX_EXECUTABLE,
                "--ro-bind-fd",
                str(bootstrap_fd),
                "/runtime/namespace-bootstrap",
            ]
            for destination, descriptor in sorted(
                self.runtime_dependency_descriptors.items()
            ):
                arguments.extend(("--ro-bind-fd", str(descriptor), destination))
            arguments.extend(
                (
                    "--remount-ro",
                    "/runtime",
                    "--setenv",
                    "LANG",
                    "C.UTF-8",
                    "--setenv",
                    "LC_ALL",
                    "C.UTF-8",
                    "--setenv",
                    "HOME",
                    CODEX_HOME,
                    "--setenv",
                    "CODEX_HOME",
                    CODEX_HOME,
                    "--setenv",
                    "PATH",
                    "/runtime",
                    "--setenv",
                    "APP_SERVER_FD",
                    str(self.app_server_descriptor),
                    "--setenv",
                    "PROXY_TRANSFER_FD",
                    str(self.proxy_transfer_descriptor),
                    "--setenv",
                    "BOUNDARY_SESSION_ID",
                    self.session_id,
                    "--setenv",
                    "DESTINATION_PIN_FINGERPRINT",
                    self.pin_fingerprint,
                    "--chdir",
                    CODEX_CWD,
                    "/runtime/namespace-bootstrap",
                    "--codex-executable",
                    CODEX_EXECUTABLE,
                    "--",
                    *CODEX_APP_SERVER_ARGUMENTS,
                )
            )
            namespace_command = tuple(arguments[-6:])
            bwrap_arguments = arguments[:-6]
            argument_bytes = b"\0".join(
                part.encode("utf-8") for part in bwrap_arguments
            )
            arguments_fd = os.memfd_create(
                "admissible-bwrap-arguments",
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
            )
            opened.append(arguments_fd)
            os.write(arguments_fd, argument_bytes)
            os.lseek(arguments_fd, 0, os.SEEK_SET)
            fcntl.fcntl(
                arguments_fd,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE,
            )
            policy = {
                "bwrap_arguments": bwrap_arguments,
                "sandbox_command": namespace_command,
                "bwrap_argument_transport": (
                    "sealed_memfd_--args_options_command_in_argv"
                ),
                "authentication_source_path_in_argv": False,
                "real_authentication_source_mounted": False,
                "codex_home_binding": "broker_directory_fd_read_write",
                "network": "private_loopback_created_by_bootstrap",
                "resolver": "absent",
                "pid_namespace": "private",
                "mount_namespace": "empty_exact_fd_bindings",
                "workspace_visible": False,
                "docker_visible": False,
                "model_authority_fingerprint": (
                    self.model_authority.authority_fingerprint
                ),
                "model_configuration_fingerprint": (
                    self.model_authority.configuration_fingerprint
                ),
                "model_binding_policy_fingerprint": (
                    self.model_authority.model_binding_policy_fingerprint
                ),
                "candidate_serialization_witness_receipt_identity": (
                    self.model_authority.candidate_witness_receipt_identity
                ),
                "candidate_serialization_witness_run_identity": (
                    self.model_authority.candidate_witness_run_identity
                ),
                "configured_model": self.model_authority.configured_model,
                "configured_reasoning_effort": (
                    self.model_authority.configured_reasoning_effort
                ),
                "effective_config_identity": effective_config_identity,
                "user_or_project_config_discovery": False,
                "config_override_arguments": False,
                "codex_arguments": list(CODEX_APP_SERVER_ARGUMENTS),
            }
            yield BoundaryLaunchSpec(
                argv=(
                    "bwrap-content-attested",
                    "--args",
                    str(arguments_fd),
                    *namespace_command,
                ),
                executable=f"/proc/self/fd/{bwrap_fd}",
                pass_fds=(
                    bwrap_fd,
                    codex_fd,
                    bootstrap_fd,
                    arguments_fd,
                    self.codex_home_descriptor,
                    self.app_server_descriptor,
                    self.proxy_transfer_descriptor,
                    *(
                        self.runtime_dependency_descriptors[key]
                        for key in sorted(self.runtime_dependency_descriptors)
                    ),
                ),
                environment={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "HOME": "/nonexistent",
                },
                cwd="/",
                launch_fingerprint=fingerprint(policy),
            )
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    def launch(self) -> subprocess.Popen[bytes]:
        with self.descriptor_launch() as spec:
            return subprocess.Popen(
                spec.argv,
                executable=spec.executable,
                pass_fds=spec.pass_fds,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(spec.environment),
                cwd=spec.cwd,
                start_new_session=True,
                close_fds=True,
            )


def namespace_bootstrap_main(argv: Sequence[str] | None = None) -> int:
    """Namespace-local listener creator, then exact exec of pinned Codex."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--codex-executable", required=True)
    parser.add_argument("codex_arguments", nargs=argparse.REMAINDER)
    values = parser.parse_args(argv)
    arguments = list(values.codex_arguments)
    if arguments and arguments[0] == "--":
        arguments.pop(0)
    if arguments != CODEX_APP_SERVER_ARGUMENTS:
        raise ValueError("namespace bootstrap refuses non-app-server arguments")
    required_environment = {
        key: os.environ[key]
        for key in (
            "APP_SERVER_FD",
            "PROXY_TRANSFER_FD",
            "BOUNDARY_SESSION_ID",
            "DESTINATION_PIN_FINGERPRINT",
            "HOME",
            "CODEX_HOME",
            "LANG",
            "LC_ALL",
            "PATH",
        )
    }
    app_descriptor = int(required_environment["APP_SERVER_FD"])
    transfer_descriptor = int(required_environment["PROXY_TRANSFER_FD"])
    transfer_channel = socket.socket(fileno=transfer_descriptor)
    host, port = create_and_transfer_proxy_listener(
        transfer_channel,
        session_id=required_environment["BOUNDARY_SESSION_ID"],
        pin_fingerprint=required_environment["DESTINATION_PIN_FINGERPRINT"],
    )
    transfer_channel.close()
    os.dup2(app_descriptor, 0)
    os.dup2(app_descriptor, 1)
    if app_descriptor not in {0, 1}:
        os.close(app_descriptor)
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": CODEX_HOME,
        "CODEX_HOME": CODEX_HOME,
        "PATH": "/runtime",
        "HTTPS_PROXY": f"http://{host}:{port}",
        "HTTP_PROXY": f"http://{host}:{port}",
        "ALL_PROXY": f"http://{host}:{port}",
        "NO_PROXY": "",
    }
    os.execve(
        values.codex_executable,
        [values.codex_executable, *arguments],
        environment,
    )
    return 127

def _landlock_syscalls() -> tuple[int, int]:
    machine = platform.machine()
    if machine in {"x86_64", "amd64", "aarch64", "arm64"}:
        return 444, 446
    raise OSError(errno.ENOSYS, "unsupported architecture for Landlock syscalls")


def apply_landlock_deny_new_path_access() -> bool:
    """Deny all future path opens; inherited descriptors remain usable.

    The empty bubblewrap mount namespace is the primary boundary.  This
    Landlock ruleset is deliberately empty and therefore defense in depth for
    controllers whose complete data/socket interface was inherited by FD.
    """

    create_ruleset, restrict_self = _landlock_syscalls()
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(
        create_ruleset,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(LANDLOCK_RULESET_VERSION_FLAG),
    )
    if abi < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            return False
        raise OSError(error, os.strerror(error))
    handled = (
        LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
    )
    if abi >= 2:
        handled |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    attributes = RulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(
        create_ruleset,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
        ctypes.c_uint(0),
    )
    if ruleset_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if libc.syscall(restrict_self, ruleset_fd, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        os.close(ruleset_fd)
    return True


def bring_up_private_loopback() -> None:
    """Enable only ``lo`` in the already-private Codex network namespace."""

    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_UP = 0x1
    interface = b"lo\0" + b"\0" * 13
    control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    try:
        request = struct.pack("16sh", interface, 0)
        response = fcntl.ioctl(control.fileno(), SIOCGIFFLAGS, request)
        _name, flags = struct.unpack("16sh", response)
        request = struct.pack("16sh", interface, flags | IFF_UP)
        fcntl.ioctl(control.fileno(), SIOCSIFFLAGS, request)
    finally:
        control.close()


def create_and_transfer_proxy_listener(
    transfer_channel: socket.socket,
    *,
    session_id: str,
    pin_fingerprint: str,
) -> tuple[str, int]:
    """Run inside Codex netns before exec and transfer the listener by SCM_RIGHTS."""

    bring_up_private_loopback()
    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM | socket.SOCK_CLOEXEC,
    )
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        address = listener.getsockname()
        send_listener_descriptor(
            transfer_channel,
            listener,
            session_id=session_id,
            pin_fingerprint=pin_fingerprint,
        )
        return str(address[0]), int(address[1])
    finally:
        listener.close()


@dataclass(frozen=True)
class BoundaryLifecycleEvidence:
    schema_version: str
    session_id: str
    authority_fingerprint: str
    records: tuple[Mapping[str, Any], ...]
    terminal_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        authority_fingerprint: str,
        records: Sequence[Mapping[str, Any]],
    ) -> "BoundaryLifecycleEvidence":
        required_order = [
            "BOUNDARY_AUTHORITY_ACCEPTED",
            "EXECUTABLES_AND_BROKERS_ATTESTED",
            "JOURNAL_ANCHOR_CREATED",
            "AUTHENTICATION_HOME_PREPARED",
            "CODEX_NAMESPACES_AND_PROXY_LISTENER_CREATED",
            "EGRESS_PIN_MANIFEST_SEALED",
            "CAPSULE_BROKER_STARTED",
            "CONTROLLER_STARTED_CONFINED",
            "CODEX_APP_SERVER_STARTED",
            "DYNAMIC_TOOLS_AND_BROKER_RESULTS_PAIRED",
            "CODEX_PROCESS_TERMINAL_RECORDED",
            "CAPSULE_TERMINATED_AND_WORKSPACE_FROZEN",
            "BROKER_CLEANUP_COMPLETED",
            "PROVIDER_OUTPUT_DURABLY_PUBLISHED",
            "CANONICAL_INTAKE_HANDOFF",
        ]
        observed = [item.get("classification") for item in records]
        if observed != required_order:
            raise ValueError("boundary lifecycle records are missing or out of order")
        body = {
            "schema_version": BOUNDARY_LIFECYCLE_SCHEMA_VERSION,
            "session_id": require_identifier(session_id, "boundary lifecycle session"),
            "authority_fingerprint": require_sha256(
                authority_fingerprint, "boundary lifecycle authority"
            ),
            "records": [dict(item) for item in records],
        }
        return cls(
            schema_version=body["schema_version"],
            session_id=body["session_id"],
            authority_fingerprint=body["authority_fingerprint"],
            records=tuple(dict(item) for item in records),
            terminal_fingerprint=fingerprint(body),
        ).validated()

    def validated(self) -> "BoundaryLifecycleEvidence":
        if self.schema_version != BOUNDARY_LIFECYCLE_SCHEMA_VERSION:
            raise ValueError("unsupported boundary lifecycle evidence schema")
        require_identifier(self.session_id, "boundary lifecycle session")
        require_sha256(self.authority_fingerprint, "boundary lifecycle authority")
        require_sha256(self.terminal_fingerprint, "boundary lifecycle terminal")
        body = {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "authority_fingerprint": self.authority_fingerprint,
            "records": [dict(item) for item in self.records],
        }
        if fingerprint(body) != self.terminal_fingerprint:
            raise ValueError("boundary lifecycle terminal fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "authority_fingerprint": self.authority_fingerprint,
            "records": [dict(item) for item in self.records],
            "terminal_fingerprint": self.terminal_fingerprint,
        }


class BoundaryLauncher:
    """Trusted construction order; it never accepts auth bytes or Docker RPC."""

    def __init__(self, authority: OSBoundaryAuthority):
        self.authority = authority.validated()
        self.auth_broker: AuthenticationBrokerProcess | None = None
        self.capsule_broker = None

    def start_authentication_broker(
        self,
        *,
        source_descriptor: int,
        ephemeral_root: Path,
        session_id: str,
        model_authority: CodexModelAuthority,
    ) -> AuthenticationBrokerProcess:
        if self.auth_broker is not None:
            raise ValueError("authentication broker already started")
        self.auth_broker = AuthenticationBrokerProcess.start(
            source_descriptor=source_descriptor,
            ephemeral_root=ephemeral_root,
            session_id=session_id,
            authority_fingerprint=self.authority.authority_fingerprint,
            configuration_bytes=(
                model_authority.validated()
                .require_revalidated_candidate_receipt()
                .ephemeral_config_bytes
            ),
        )
        return self.auth_broker

    def start_capsule_broker(self, config: CapsuleBrokerConfig):
        if self.capsule_broker is not None:
            raise ValueError("capsule broker already started")
        self.capsule_broker = CapsuleBrokerProcess.start(config)
        return self.capsule_broker

    def start_capsule_broker_for_controller(
        self,
        config: CapsuleBrokerConfig,
    ) -> tuple[int, Mapping[str, Any]]:
        """Start Docker authority first, then release only its closed endpoint."""

        client = self.start_capsule_broker(config)
        return client.release_for_confined_controller()

    def reap_controller_owned_capsule_broker(self) -> Mapping[str, Any]:
        if self.capsule_broker is None:
            raise ValueError("capsule broker was not started")
        waited, status = os.waitpid(self.capsule_broker.process_pid, 0)
        if waited != self.capsule_broker.process_pid:
            raise RuntimeError("boundary launcher reaped the wrong capsule broker")
        exit_code = os.waitstatus_to_exitcode(status)
        evidence = {
            "process_pid": self.capsule_broker.process_pid,
            "exit_code": exit_code,
            "exit_normal": exit_code == 0,
            "forced": exit_code < 0,
        }
        return {**evidence, "process_terminal_fingerprint": fingerprint(evidence)}
