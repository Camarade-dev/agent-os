"""Host confinement for an authenticated Codex app-server control process.

The control process is deliberately outside the execution capsule because it
uses the operator's existing Codex login and needs provider network access.
It receives no workspace mount, host shell, repository, Docker socket, intake
tree, verification copy, or finalizer path.  Its only effect authority is the
bidirectional app-server dynamic-tool protocol handled by the trusted
controller.

This module deals only in authentication *locations*.  It never opens, reads,
copies, serializes, or hashes authentication or configuration contents.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from admissible.capsule.common import fingerprint, require_nonempty_text, require_sha256


HOST_CONTROL_AUTHORITY_SCHEMA_VERSION = "admissible_host_codex_control_authority_v1"
HOST_CONTROL_POLICY_SCHEMA_VERSION = "admissible_host_codex_bwrap_policy_v1"

CONTROL_CODEX_HOME = PurePosixPath("/control/codex-home")
CONTROL_EMPTY_CWD = PurePosixPath("/control/empty")
CONTROL_EXECUTABLE = PurePosixPath("/runtime/codex")


def _absolute_lexical(path: Path) -> Path:
    """Return an absolute path without resolving or reading a symlink target."""

    return path if path.is_absolute() else Path.cwd() / path


def _is_within(path: Path, root: Path) -> bool:
    try:
        _absolute_lexical(path).relative_to(_absolute_lexical(root))
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class AuthenticatedControlAuthority:
    """Non-secret identity for the process allowed to use Codex login state."""

    schema_version: str
    codex_protocol_version: str
    executable_identity: str
    policy_fingerprint: str
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        codex_protocol_version: str,
        executable_identity: str,
        policy_fingerprint: str,
    ) -> "AuthenticatedControlAuthority":
        body = {
            "schema_version": HOST_CONTROL_AUTHORITY_SCHEMA_VERSION,
            "codex_protocol_version": codex_protocol_version,
            "executable_identity": executable_identity,
            "policy_fingerprint": policy_fingerprint,
        }
        return cls(
            **body,
            authority_fingerprint=fingerprint(body),
        ).validated()

    def validated(self) -> "AuthenticatedControlAuthority":
        if self.schema_version != HOST_CONTROL_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported host-control authority schema")
        require_nonempty_text(self.codex_protocol_version, "codex protocol version", max_bytes=64)
        require_nonempty_text(self.executable_identity, "control executable identity", max_bytes=512)
        require_sha256(self.policy_fingerprint, "host-control policy fingerprint")
        require_sha256(self.authority_fingerprint, "host-control authority fingerprint")
        body = {
            "schema_version": self.schema_version,
            "codex_protocol_version": self.codex_protocol_version,
            "executable_identity": self.executable_identity,
            "policy_fingerprint": self.policy_fingerprint,
        }
        if fingerprint(body) != self.authority_fingerprint:
            raise ValueError("host-control authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "codex_protocol_version": self.codex_protocol_version,
            "executable_identity": self.executable_identity,
            "policy_fingerprint": self.policy_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
        }


@dataclass(frozen=True)
class HostControlBwrapPolicy:
    """A rootless bubblewrap view containing only exact required files.

    Source paths appear only in the launch argv consumed by bubblewrap.  The
    durable policy identity contains destination names and boolean presence,
    never source paths or file bytes.
    """

    bwrap_executable: Path
    codex_executable: Path
    authentication_file: Path
    configuration_file: Path | None = None
    certificate_bundle: Path | None = Path("/etc/ssl/certs/ca-certificates.crt")
    resolver_file: Path | None = Path("/etc/resolv.conf")
    hosts_file: Path | None = Path("/etc/hosts")
    forbidden_host_roots: tuple[Path, ...] = ()

    def validated(self) -> "HostControlBwrapPolicy":
        sources = [
            self.bwrap_executable,
            self.codex_executable,
            self.authentication_file,
            self.configuration_file,
            self.certificate_bundle,
            self.resolver_file,
            self.hosts_file,
        ]
        for source in (item for item in sources if item is not None):
            if not isinstance(source, Path) or not source.is_absolute():
                raise ValueError("host-control source locations must be absolute paths")
            if source.is_symlink() or not source.is_file():
                raise ValueError("host-control sources must be exact regular files, not symlinks")
        if not os.access(self.bwrap_executable, os.X_OK):
            raise ValueError("bubblewrap executable is not executable")
        if not os.access(self.codex_executable, os.X_OK):
            raise ValueError("Codex control executable is not executable")
        for root in self.forbidden_host_roots:
            if not isinstance(root, Path) or not root.is_absolute():
                raise ValueError("forbidden host roots must be absolute paths")
        for source in (item for item in sources if item is not None):
            for root in self.forbidden_host_roots:
                if _is_within(source, root):
                    raise ValueError(f"host-control source overlaps forbidden root: {source}")
        if self.authentication_file == self.configuration_file:
            raise ValueError("authentication and configuration locations must be distinct")
        return self

    @property
    def policy_fingerprint(self) -> str:
        self.validated()
        # Deliberately excludes source paths and all source file contents.
        return fingerprint(
            {
                "schema_version": HOST_CONTROL_POLICY_SCHEMA_VERSION,
                "network_namespace": "host-provider-network",
                "root_view": "empty-explicit-files-only",
                "process_namespace": "private",
                "session": "new",
                "codex_destination": str(CONTROL_EXECUTABLE),
                "authentication_destination": str(CONTROL_CODEX_HOME / "auth.json"),
                "configuration_present": self.configuration_file is not None,
                "certificate_present": self.certificate_bundle is not None,
                "resolver_present": self.resolver_file is not None,
                "hosts_present": self.hosts_file is not None,
                "workspace_visible": False,
                "docker_socket_visible": False,
                "host_shell_visible": False,
            }
        )

    @property
    def visible_destinations(self) -> tuple[str, ...]:
        destinations = [
            str(CONTROL_EXECUTABLE),
            str(CONTROL_CODEX_HOME / "auth.json"),
            "/proc",
            "/dev",
            "/tmp",
            str(CONTROL_EMPTY_CWD),
        ]
        if self.configuration_file is not None:
            destinations.append(str(CONTROL_CODEX_HOME / "config.toml"))
        if self.certificate_bundle is not None:
            destinations.append("/etc/ssl/certs/ca-certificates.crt")
        if self.resolver_file is not None:
            destinations.append("/etc/resolv.conf")
        if self.hosts_file is not None:
            destinations.append("/etc/hosts")
        return tuple(destinations)

    def _ro_bind(self, source: Path, destination: str) -> list[str]:
        return ["--ro-bind", os.fspath(source), destination]

    def build_argv(self, app_server_arguments: Sequence[str] = ("app-server", "--stdio")) -> tuple[str, ...]:
        """Build the exact bwrap launch argv without inspecting source bytes."""

        self.validated()
        if not app_server_arguments or any(
            not isinstance(part, str) or not part or "\x00" in part for part in app_server_arguments
        ):
            raise ValueError("invalid app-server arguments")
        argv: list[str] = [
            os.fspath(self.bwrap_executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--share-net",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
            "--dir",
            "/control",
            "--dir",
            "/control/home",
            "--dir",
            str(CONTROL_CODEX_HOME),
            "--dir",
            str(CONTROL_EMPTY_CWD),
            "--dir",
            "/etc",
            "--dir",
            "/etc/ssl",
            "--dir",
            "/etc/ssl/certs",
        ]
        argv.extend(self._ro_bind(self.codex_executable, str(CONTROL_EXECUTABLE)))
        argv.extend(self._ro_bind(self.authentication_file, str(CONTROL_CODEX_HOME / "auth.json")))
        if self.configuration_file is not None:
            argv.extend(self._ro_bind(self.configuration_file, str(CONTROL_CODEX_HOME / "config.toml")))
        if self.certificate_bundle is not None:
            argv.extend(self._ro_bind(self.certificate_bundle, "/etc/ssl/certs/ca-certificates.crt"))
        if self.resolver_file is not None:
            argv.extend(self._ro_bind(self.resolver_file, "/etc/resolv.conf"))
        if self.hosts_file is not None:
            argv.extend(self._ro_bind(self.hosts_file, "/etc/hosts"))
        argv.extend(
            [
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

    def evidence(self) -> Mapping[str, Any]:
        """Return non-secret durable policy evidence."""

        return {
            "schema_version": HOST_CONTROL_POLICY_SCHEMA_VERSION,
            "policy_fingerprint": self.policy_fingerprint,
            "visible_destinations": list(self.visible_destinations),
            "host_root_visible": False,
            "host_shell_visible": False,
            "workspace_visible": False,
            "docker_socket_visible": False,
            "network": "provider-only-host-network",
        }


def assert_no_forbidden_launch_source(argv: Iterable[str], forbidden_roots: Iterable[Path]) -> None:
    """Provider-free audit helper for a fully rendered bwrap argv."""

    roots = tuple(forbidden_roots)
    for part in argv:
        if not isinstance(part, str) or not part.startswith("/"):
            continue
        candidate = Path(part)
        for root in roots:
            if _is_within(candidate, root):
                raise ValueError(f"launch argv exposes forbidden host root: {root}")
