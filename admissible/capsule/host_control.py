"""OS boundary for the host Codex app-server control process.

Authentication bytes are never opened here.  Production remains mechanically
blocked until an architecture-owned ``AuthenticationBoundary`` supplies both
an exclusive mount construction and service-only egress enforcement.
"""

from __future__ import annotations

import os
import stat
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from admissible.capsule.codex_protocol import CODEX_APP_SERVER_PROTOCOL_VERSION
from admissible.capsule.common import (
    fingerprint,
    require_sha256,
)
from admissible.capsule.execution_authority import (
    ExecutableFileIdentity,
    validate_component_identity,
)


HOST_CONTROL_AUTHORITY_SCHEMA_VERSION = "admissible_host_codex_control_authority_v2"
HOST_CONTROL_POLICY_SCHEMA_VERSION = "admissible_host_codex_bwrap_policy_v2"
SYNTHETIC_MINIMAL_CONFIG = (
    b"[analytics]\nenabled = false\n"
    b"[features]\nweb_search = false\n"
)

CONTROL_CODEX_HOME = PurePosixPath("/control/codex-home")
CONTROL_EMPTY_CWD = PurePosixPath("/control/empty")
CONTROL_EXECUTABLE = PurePosixPath("/runtime/codex")


def _absolute_lexical(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _is_within(path: Path, root: Path) -> bool:
    try:
        _absolute_lexical(path).relative_to(_absolute_lexical(root))
    except ValueError:
        return False
    return True


def _source_identity_without_reading(path: Path, label: str) -> tuple[int, ...]:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be an absolute path without '..'")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} has a symlinked component: {current}")
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be an exact regular file")
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _reject_existing_symlink_components(path: Path, label: str) -> None:
    """Reject aliases without requiring a not-yet-created forbidden leaf."""

    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} has a symlinked component: {current}")


class AuthenticationBoundary(ABC):
    """Closed integration point owned by the independent auth architecture."""

    @property
    @abstractmethod
    def state(self) -> str:
        """OS_ENFORCED, SYNTHETIC_PROVIDER_FREE, or BLOCKED_PENDING_OS_ENFORCEMENT."""

    @property
    @abstractmethod
    def provider_request_capable(self) -> bool:
        pass

    @property
    @abstractmethod
    def authentication_sources(self) -> tuple[tuple[Path, str], ...]:
        """Non-secret source locations and fixed in-sandbox destinations."""

    @property
    @abstractmethod
    def network_argv(self) -> tuple[str, ...]:
        """Exact bwrap networking arguments; empty means isolated network."""

    @property
    @abstractmethod
    def boundary_fingerprint(self) -> str:
        pass

    @abstractmethod
    def attest_ready(self) -> None:
        """Independently re-attest OS enforcement immediately before launch."""


@dataclass(frozen=True)
class PendingAuthenticationBoundary(AuthenticationBoundary):
    """Default production posture: no auth mount, no network, no launch."""

    reason: str = "auth/service-egress architecture has no OS-enforced implementation"

    @property
    def state(self) -> str:
        return "BLOCKED_PENDING_OS_ENFORCEMENT"

    @property
    def provider_request_capable(self) -> bool:
        return False

    @property
    def authentication_sources(self) -> tuple[tuple[Path, str], ...]:
        return ()

    @property
    def network_argv(self) -> tuple[str, ...]:
        return ()

    @property
    def boundary_fingerprint(self) -> str:
        return fingerprint(
            {
                "kind": "pending_authentication_boundary",
                "state": self.state,
                "auth_mounted": False,
                "network": "isolated",
            }
        )

    def attest_ready(self) -> None:
        raise RuntimeError(self.reason)


@dataclass(frozen=True)
class SyntheticAuthenticationBoundary(AuthenticationBoundary):
    """Provider-free fixture location; never production/provider capable."""

    authentication_file: Path
    _identity: tuple[int, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_identity",
            _source_identity_without_reading(
                self.authentication_file,
                "synthetic authentication fixture",
            ),
        )

    @property
    def state(self) -> str:
        return "SYNTHETIC_PROVIDER_FREE"

    @property
    def provider_request_capable(self) -> bool:
        return False

    @property
    def authentication_sources(self) -> tuple[tuple[Path, str], ...]:
        return ((self.authentication_file, str(CONTROL_CODEX_HOME / "auth.json")),)

    @property
    def network_argv(self) -> tuple[str, ...]:
        return ()

    @property
    def boundary_fingerprint(self) -> str:
        # The source location and contents are deliberately absent.
        return fingerprint(
            {
                "kind": "synthetic_authentication_boundary",
                "state": self.state,
                "destination": str(CONTROL_CODEX_HOME / "auth.json"),
                "provider_request_capable": False,
                "network": "isolated",
            }
        )

    def attest_ready(self) -> None:
        if (
            _source_identity_without_reading(
                self.authentication_file,
                "synthetic authentication fixture",
            )
            != self._identity
        ):
            raise ValueError("synthetic authentication source changed after attestation")


@dataclass(frozen=True)
class AuthenticatedControlAuthority:
    """Content-backed authority for the process allowed to use login state."""

    schema_version: str
    codex_protocol_version: str
    executable_identity: Mapping[str, Any]
    policy_fingerprint: str
    authentication_boundary_state: str
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        codex_protocol_version: str,
        executable_identity: Mapping[str, Any],
        policy_fingerprint: str,
        authentication_boundary_state: str,
    ) -> "AuthenticatedControlAuthority":
        body = {
            "schema_version": HOST_CONTROL_AUTHORITY_SCHEMA_VERSION,
            "codex_protocol_version": codex_protocol_version,
            "executable_identity": dict(executable_identity),
            "policy_fingerprint": policy_fingerprint,
            "authentication_boundary_state": authentication_boundary_state,
        }
        return cls(**body, authority_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "codex_protocol_version": self.codex_protocol_version,
            "executable_identity": dict(self.executable_identity),
            "policy_fingerprint": self.policy_fingerprint,
            "authentication_boundary_state": self.authentication_boundary_state,
        }

    def validated(self) -> "AuthenticatedControlAuthority":
        if self.schema_version != HOST_CONTROL_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported host-control authority schema")
        if self.codex_protocol_version != CODEX_APP_SERVER_PROTOCOL_VERSION:
            raise ValueError("wrong host-control Codex protocol version")
        validate_component_identity(self.executable_identity, "control executable")
        require_sha256(self.policy_fingerprint, "host-control policy fingerprint")
        if self.authentication_boundary_state not in {
            "OS_ENFORCED",
            "SYNTHETIC_PROVIDER_FREE",
            "BLOCKED_PENDING_OS_ENFORCEMENT",
        }:
            raise ValueError("unknown authentication boundary state")
        require_sha256(self.authority_fingerprint, "host-control authority fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("host-control authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "authority_fingerprint": self.authority_fingerprint}


@dataclass(frozen=True)
class HostControlLaunchSpec:
    argv: tuple[str, ...]
    executable: str
    pass_fds: tuple[int, ...]


@dataclass(frozen=True)
class HostControlBwrapPolicy:
    """An empty bwrap view whose production path is auth-architecture gated."""

    bwrap_executable: Path
    codex_executable: Path
    authentication_boundary: AuthenticationBoundary = field(
        default_factory=PendingAuthenticationBoundary
    )
    configuration_file: Path | None = None
    certificate_bundle: Path | None = None
    resolver_file: Path | None = None
    hosts_file: Path | None = None
    forbidden_host_roots: tuple[Path, ...] = ()
    _bwrap_identity: ExecutableFileIdentity = field(init=False, repr=False, compare=False)
    _codex_identity: ExecutableFileIdentity = field(init=False, repr=False, compare=False)
    _source_identities: tuple[tuple[str, tuple[int, ...]], ...] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_bwrap_identity",
            ExecutableFileIdentity.attest(self.bwrap_executable, label="bubblewrap executable"),
        )
        object.__setattr__(
            self,
            "_codex_identity",
            ExecutableFileIdentity.attest(self.codex_executable, label="Codex executable"),
        )
        identities = []
        for source, label in self._non_executable_sources():
            identities.append((os.fspath(source), _source_identity_without_reading(source, label)))
        object.__setattr__(self, "_source_identities", tuple(identities))
        self.validated()

    def _non_executable_sources(self) -> tuple[tuple[Path, str], ...]:
        sources: list[tuple[Path, str]] = list(self.authentication_boundary.authentication_sources)
        for path, label in (
            (self.configuration_file, "synthetic Codex configuration"),
            (self.certificate_bundle, "certificate bundle"),
            (self.resolver_file, "resolver file"),
            (self.hosts_file, "hosts file"),
        ):
            if path is not None:
                sources.append((path, label))
        return tuple(sources)

    @property
    def bwrap_identity(self) -> ExecutableFileIdentity:
        return self._bwrap_identity

    @property
    def codex_identity(self) -> ExecutableFileIdentity:
        return self._codex_identity

    def validated(self) -> "HostControlBwrapPolicy":
        if not isinstance(self.authentication_boundary, AuthenticationBoundary):
            raise ValueError("host control requires the closed authentication-boundary interface")
        if self.authentication_boundary.provider_request_capable and (
            self.authentication_boundary.state != "OS_ENFORCED"
        ):
            raise ValueError("provider-capable auth boundary is not OS enforced")
        if self.authentication_boundary.state == "OS_ENFORCED":
            # The independent architecture gate has not supplied a concrete
            # implementation in this branch. A caller-defined subclass and
            # asserted state string are not OS attestation.
            raise ValueError(
                "no architecture-approved OS-enforced authentication boundary "
                "is integrated"
            )
        if self.authentication_boundary.state == "SYNTHETIC_PROVIDER_FREE":
            if self.configuration_file is None:
                raise ValueError("synthetic control requires the generated minimal configuration")
            if self.configuration_file.read_bytes() != SYNTHETIC_MINIMAL_CONFIG:
                raise ValueError("synthetic Codex configuration is not the closed minimal policy")
        roots = []
        for root in self.forbidden_host_roots:
            if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
                raise ValueError("forbidden host roots must be absolute canonical paths")
            _reject_existing_symlink_components(root, "forbidden host root")
            roots.append(root)
        sources = (
            self.bwrap_executable,
            self.codex_executable,
            *(path for path, _label in self._non_executable_sources()),
        )
        for source in sources:
            for root in roots:
                if _is_within(source, root) or _is_within(root, source):
                    raise ValueError(f"host-control source aliases forbidden root: {root}")
        if len({os.fspath(item) for item in sources}) != len(sources):
            raise ValueError("host-control sources overlap or alias one another")
        return self

    def attest_launch(self) -> None:
        self.validated()
        self._bwrap_identity.reattest(label="bubblewrap executable")
        self._codex_identity.reattest(label="Codex executable")
        observed = tuple(
            (
                os.fspath(source),
                _source_identity_without_reading(source, label),
            )
            for source, label in self._non_executable_sources()
        )
        if observed != self._source_identities:
            raise ValueError("host-control source object changed after attestation")
        self.authentication_boundary.attest_ready()

    @property
    def policy_fingerprint(self) -> str:
        return fingerprint(
            {
                "schema_version": HOST_CONTROL_POLICY_SCHEMA_VERSION,
                "network": (
                    "service-only-os-enforced"
                    if self.authentication_boundary.state == "OS_ENFORCED"
                    else "isolated"
                ),
                "root_view": "empty-explicit-files-only",
                "process_namespace": "private",
                "session": "new",
                "bwrap_identity": self._bwrap_identity.identity_fingerprint,
                "codex_identity": self._codex_identity.identity_fingerprint,
                "authentication_boundary": self.authentication_boundary.boundary_fingerprint,
                "codex_destination": str(CONTROL_EXECUTABLE),
                "configuration_present": self.configuration_file is not None,
                "certificate_present": self.certificate_bundle is not None,
                "resolver_present": self.resolver_file is not None,
                "hosts_present": self.hosts_file is not None,
                "workspace_visible": False,
                "docker_socket_visible": False,
                "host_shell_visible": False,
                "native_effect_capability_roots": [],
            }
        )

    @property
    def visible_destinations(self) -> tuple[str, ...]:
        destinations = [
            str(CONTROL_EXECUTABLE),
            "/proc",
            "/dev",
            "/tmp",
            str(CONTROL_EMPTY_CWD),
        ]
        destinations.extend(
            destination
            for _source, destination in self.authentication_boundary.authentication_sources
        )
        if self.configuration_file is not None:
            destinations.append(str(CONTROL_CODEX_HOME / "config.toml"))
        if self.certificate_bundle is not None:
            destinations.append("/etc/ssl/certs/ca-certificates.crt")
        if self.resolver_file is not None:
            destinations.append("/etc/resolv.conf")
        if self.hosts_file is not None:
            destinations.append("/etc/hosts")
        return tuple(destinations)

    def _ro_bind(
        self,
        source: Path,
        destination: str,
        source_descriptors: Mapping[str, int] | None = None,
    ) -> list[str]:
        if source_descriptors is None:
            return ["--ro-bind", os.fspath(source), destination]
        try:
            descriptor = source_descriptors[os.fspath(source)]
        except KeyError as error:
            raise ValueError("launch source lacks an inode-bound descriptor") from error
        return ["--ro-bind-fd", str(descriptor), destination]

    def _build_argv(
        self,
        app_server_arguments: Sequence[str] = ("app-server", "--stdio"),
        *,
        source_descriptors: Mapping[str, int] | None = None,
        launcher_descriptor: int | None = None,
    ) -> tuple[str, ...]:
        if not app_server_arguments or any(
            not isinstance(part, str) or not part or "\x00" in part
            for part in app_server_arguments
        ):
            raise ValueError("invalid app-server arguments")
        argv: list[str] = [
            (
                "bwrap-content-attested"
                if source_descriptors is not None
                else self._bwrap_identity.canonical_path
            ),
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            *self.authentication_boundary.network_argv,
            "--clearenv",
        ]
        if launcher_descriptor is not None:
            # Make bwrap consume and close its own exec descriptor, then hide
            # that temporary mount beneath the real empty runtime tmpfs.
            argv.extend(
                (
                    "--dir",
                    "/runtime",
                    "--ro-bind-fd",
                    str(launcher_descriptor),
                    "/runtime/.attested-bwrap",
                )
            )
        argv.extend(
            [
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
            "/control/home",
            "--tmpfs",
            str(CONTROL_CODEX_HOME),
            "--dir",
            str(CONTROL_EMPTY_CWD),
            "--tmpfs",
            "/etc",
            "--dir",
            "/etc/ssl",
            "--dir",
            "/etc/ssl/certs",
            ]
        )
        argv.extend(
            self._ro_bind(
                self.codex_executable,
                str(CONTROL_EXECUTABLE),
                source_descriptors,
            )
        )
        for source, destination in self.authentication_boundary.authentication_sources:
            argv.extend(self._ro_bind(source, destination, source_descriptors))
        if self.configuration_file is not None:
            argv.extend(
                self._ro_bind(
                    self.configuration_file,
                    str(CONTROL_CODEX_HOME / "config.toml"),
                    source_descriptors,
                )
            )
        if self.certificate_bundle is not None:
            argv.extend(
                self._ro_bind(
                    self.certificate_bundle,
                    "/etc/ssl/certs/ca-certificates.crt",
                    source_descriptors,
                )
            )
        if self.resolver_file is not None:
            argv.extend(
                self._ro_bind(
                    self.resolver_file,
                    "/etc/resolv.conf",
                    source_descriptors,
                )
            )
        if self.hosts_file is not None:
            argv.extend(
                self._ro_bind(
                    self.hosts_file,
                    "/etc/hosts",
                    source_descriptors,
                )
            )
        argv.extend(
            [
                "--remount-ro",
                "/runtime",
                "--remount-ro",
                str(CONTROL_CODEX_HOME),
                "--remount-ro",
                "/control",
                "--remount-ro",
                "/etc",
                "--setenv",
                "HOME",
                "/control/home",
                "--setenv",
                "CODEX_HOME",
                str(CONTROL_CODEX_HOME),
                "--setenv",
                "PATH",
                "/runtime",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--chdir",
                str(CONTROL_EMPTY_CWD),
                str(CONTROL_EXECUTABLE),
                *app_server_arguments,
            ]
        )
        return tuple(argv)

    def build_argv(
        self,
        app_server_arguments: Sequence[str] = ("app-server", "--stdio"),
    ) -> tuple[str, ...]:
        """Human-inspectable argv; production launch uses descriptor_argv()."""

        self.attest_launch()
        return self._build_argv(app_server_arguments)

    @contextmanager
    def descriptor_argv(
        self,
        app_server_arguments: Sequence[str] = ("app-server", "--stdio"),
    ):
        """Yield an inode-bound launch with no host source paths in argv."""

        self.attest_launch()
        descriptors: list[int] = []
        source_descriptors: dict[str, int] = {}
        try:
            executable_flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                executable_flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                executable_flags |= os.O_NOFOLLOW
            bwrap_descriptor = os.open(self.bwrap_executable, executable_flags)
            descriptors.append(bwrap_descriptor)
            bwrap_info = os.fstat(bwrap_descriptor)
            if (
                bwrap_info.st_dev != self._bwrap_identity.device
                or bwrap_info.st_ino != self._bwrap_identity.inode
                or stat.S_IMODE(bwrap_info.st_mode) != self._bwrap_identity.mode
                or bwrap_info.st_size != self._bwrap_identity.size
                or bwrap_info.st_mtime_ns != self._bwrap_identity.mtime_ns
            ):
                raise ValueError("bubblewrap descriptor differs from attested executable")

            expected_sources = dict(self._source_identities)
            for source, label in (
                (self.codex_executable, "Codex executable"),
                *self._non_executable_sources(),
            ):
                descriptor = os.open(source, executable_flags)
                descriptors.append(descriptor)
                info = os.fstat(descriptor)
                observed = (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_nlink,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
                if source == self.codex_executable:
                    if (
                        info.st_dev != self._codex_identity.device
                        or info.st_ino != self._codex_identity.inode
                        or stat.S_IMODE(info.st_mode) != self._codex_identity.mode
                        or info.st_size != self._codex_identity.size
                        or info.st_mtime_ns != self._codex_identity.mtime_ns
                    ):
                        raise ValueError("Codex descriptor differs from attested executable")
                elif observed != expected_sources[os.fspath(source)]:
                    raise ValueError(f"{label} descriptor changed after attestation")
                source_descriptors[os.fspath(source)] = descriptor
            argv = self._build_argv(
                app_server_arguments,
                source_descriptors=source_descriptors,
                launcher_descriptor=bwrap_descriptor,
            )
            yield HostControlLaunchSpec(
                argv=argv,
                executable=f"/proc/self/fd/{bwrap_descriptor}",
                pass_fds=tuple(descriptors),
            )
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    @property
    def argv_policy_fingerprint(self) -> str:
        # No host source path is durable; the exact option/destination policy is.
        return fingerprint(
            {
                "schema_version": HOST_CONTROL_POLICY_SCHEMA_VERSION,
                "options": [
                    "die-with-parent",
                    "new-session",
                    "unshare-all",
                    "clearenv",
                    "inode-bound-bwrap-exec",
                    "inode-bound-ro-bind-fd",
                    "no-inherited-fds",
                    "private-proc",
                    "minimal-dev",
                    "tmpfs-tmp",
                    "read-only-runtime",
                    "read-only-codex-home",
                    "read-only-etc",
                    "controlled-cwd",
                ],
                "destinations": sorted(self.visible_destinations),
                "network_argv": list(self.authentication_boundary.network_argv),
                "app_server_arguments": ["app-server", "--stdio"],
            }
        )

    def evidence(self) -> Mapping[str, Any]:
        return {
            "schema_version": HOST_CONTROL_POLICY_SCHEMA_VERSION,
            "policy_fingerprint": self.policy_fingerprint,
            "argv_policy_fingerprint": self.argv_policy_fingerprint,
            "visible_destinations": list(self.visible_destinations),
            "authentication_boundary_state": self.authentication_boundary.state,
            # Kept false until the architecture gate supplies and this module
            # explicitly integrates an OS-enforced implementation.
            "production_ready": False,
            "host_root_visible": False,
            "host_shell_visible": False,
            "workspace_visible": False,
            "docker_socket_visible": False,
            "native_capability_roots": [],
            "network": (
                "service-only-os-enforced"
                if self.authentication_boundary.state == "OS_ENFORCED"
                else "isolated"
            ),
        }


def assert_no_forbidden_launch_source(
    argv: Iterable[str],
    forbidden_roots: Iterable[Path],
) -> None:
    roots = tuple(forbidden_roots)
    for part in argv:
        if not isinstance(part, str) or not part.startswith("/"):
            continue
        candidate = Path(part)
        for root in roots:
            if _is_within(candidate, root):
                raise ValueError(f"launch argv exposes forbidden host root: {root}")
