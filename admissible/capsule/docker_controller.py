"""Docker-backed execution authority for dynamic capsule tools.

Only this trusted controller can use the host Docker client.  The Codex
control process receives neither the Docker socket nor a host workspace path.
All provider-requested reads, writes, listings, and commands execute through
fixed `docker exec` operations in one sealed, disposable container.
"""

from __future__ import annotations

import os
import hashlib
import re
import shutil
import signal
import selectors
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from admissible.capsule.common import (
    fingerprint,
    fsync_directory,
    mode_type,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    sha256_bytes,
    strict_json_loads,
    validate_closed_relative_path,
    portable_path_collision_key,
)
from admissible.capsule.execution_authority import ExecutableFileIdentity
from admissible.capsule.models import ByteTreeObservation, CleanupResult, ObservedEntry
from admissible.capsule.session_store import (
    DurableToolRequest,
    DurableToolResult,
    ToolTerminalClassification,
)


CONTROLLER_AUTHORITY_SCHEMA_VERSION = "admissible_durable_capsule_controller_authority_v2"
CAPSULE_EXECUTION_AUTHORITY_SCHEMA_VERSION = "admissible_docker_capsule_execution_authority_v1"
DOCKER_WORKSPACE_ROOT = "/workspace"
CAPSULE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ALLOWED_DYNAMIC_TOOLS = ("list_files", "read_file", "write_file", "run_command")


LIST_SCRIPT = r"""
lexical="$(realpath -s -m -- "/workspace/$1")"
target="$(realpath -m -- "/workspace/$1")"
case "$target" in /workspace|/workspace/*) ;; *) exit 72 ;; esac
[ "$target" = "$lexical" ] || exit 75
[ -d "$target" ] || exit 66
cd /workspace
find_arg="./${1#./}"
[ "$1" = "." ] && find_arg="."
find "$find_arg" -mindepth 1 -maxdepth "$2" -printf '%y %s %p\n' | LC_ALL=C sort
""".strip()

READ_SCRIPT = r"""
lexical="$(realpath -s -m -- "/workspace/$1")"
target="$(realpath -e -- "/workspace/$1")"
case "$target" in /workspace/*) ;; *) exit 72 ;; esac
[ "$target" = "$lexical" ] || exit 75
[ -f "$target" ] && [ ! -L "/workspace/$1" ] || exit 66
cat -- "$target"
""".strip()

WRITE_SCRIPT = r"""
lexical="$(realpath -s -m -- "/workspace/$1")"
target="$(realpath -m -- "/workspace/$1")"
case "$target" in /workspace/*) ;; *) exit 72 ;; esac
[ "$target" = "$lexical" ] || exit 75
parent="$(dirname -- "$target")"
mkdir -p -- "$parent"
parent="$(realpath -e -- "$parent")"
case "$parent" in /workspace|/workspace/*) ;; *) exit 72 ;; esac
case "$2" in
  create) [ ! -e "$target" ] || exit 73 ;;
  replace) [ -f "$target" ] && [ ! -L "$target" ] || exit 74 ;;
  upsert) [ ! -L "$target" ] || exit 75 ;;
  *) exit 76 ;;
esac
tmp="$parent/.admissible-write-$$"
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
umask 077
cat > "$tmp"
chmod 0600 "$tmp"
mv -f -- "$tmp" "$target"
trap - EXIT HUP INT TERM
""".strip()


def _reject_existing_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} has a symlinked component: {current}")


@dataclass(frozen=True)
class DockerCapsuleLimits:
    image: str = "ubuntu:24.04"
    image_identity: str = "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
    uid: int = os.getuid()
    gid: int = os.getgid()
    cpus: str = "0.50"
    memory: str = "256m"
    pids: int = 64
    command_timeout_seconds: float = 10.0
    session_timeout_seconds: float = 60.0
    output_limit_bytes: int = 64 * 1024
    write_limit_bytes: int = 256 * 1024
    file_count_limit: int = 4096
    tree_bytes_limit: int = 16 * 1024 * 1024

    def validated(self) -> "DockerCapsuleLimits":
        require_nonempty_text(self.image, "capsule image", max_bytes=512)
        require_nonempty_text(self.image_identity, "capsule image identity", max_bytes=512)
        if not self.image_identity.startswith("sha256:"):
            raise ValueError("capsule image identity must be a sha256 content identity")
        require_sha256(self.image_identity.removeprefix("sha256:"), "capsule image identity")
        if self.uid <= 0 or self.gid <= 0:
            raise ValueError("capsule UID and GID must be non-root")
        try:
            cpu_value = Decimal(self.cpus)
        except (InvalidOperation, TypeError) as error:
            raise ValueError("capsule CPU limit must be a canonical decimal") from error
        if (
            not re.fullmatch(r"(?:0\.[0-9]{2}|[1-8]\.[0-9]{2})", self.cpus)
            or not Decimal("0.05") <= cpu_value <= Decimal("8.00")
        ):
            raise ValueError("capsule CPU limit must be canonical in [0.05, 8.00]")
        if not re.fullmatch(r"(?:[1-9][0-9]{1,3})m", self.memory):
            raise ValueError("capsule memory limit must be canonical whole MiB")
        memory_mib = int(self.memory[:-1])
        if not 16 <= memory_mib <= 4096:
            raise ValueError("capsule memory limit is out of bounds")
        if not (1 <= self.pids <= 1024):
            raise ValueError("capsule PID limit is out of bounds")
        if not (0.05 <= self.command_timeout_seconds <= 300):
            raise ValueError("capsule command timeout is out of bounds")
        if not (self.command_timeout_seconds <= self.session_timeout_seconds <= 3600):
            raise ValueError("capsule session timeout is out of bounds")
        if not (1024 <= self.output_limit_bytes <= 4 * 1024 * 1024):
            raise ValueError("capsule output bound is out of bounds")
        if not (1 <= self.write_limit_bytes <= self.tree_bytes_limit):
            raise ValueError("capsule write bound is out of bounds")
        if not (1 <= self.file_count_limit <= 100_000):
            raise ValueError("capsule file-count bound is out of bounds")
        if not (1024 <= self.tree_bytes_limit <= 1024 * 1024 * 1024):
            raise ValueError("capsule workspace-byte bound is out of bounds")
        return self

    @property
    def cpu_millis(self) -> int:
        self.validated()
        return int(Decimal(self.cpus) * 1000)

    @property
    def memory_bytes(self) -> int:
        self.validated()
        return int(self.memory[:-1]) * 1024 * 1024


@dataclass(frozen=True)
class CapsuleExecutionAuthority:
    schema_version: str
    image_identity: str
    security_profile: Mapping[str, Any]
    authority_fingerprint: str

    @classmethod
    def create(cls, limits: DockerCapsuleLimits) -> "CapsuleExecutionAuthority":
        limits.validated()
        profile = {
            "uid": limits.uid,
            "gid": limits.gid,
            "read_only_root": True,
            "capabilities": [],
            "no_new_privileges": True,
            "network": "none",
            "docker_socket_mounted": False,
            "init_process": True,
            "cpus": limits.cpus,
            "cpu_millis": limits.cpu_millis,
            "memory_bytes": limits.memory_bytes,
            "pids": limits.pids,
            "session_timeout_seconds": limits.session_timeout_seconds,
            "command_timeout_seconds": limits.command_timeout_seconds,
            "output_limit_bytes": limits.output_limit_bytes,
            "workspace_bytes_limit": limits.tree_bytes_limit,
            "workspace_quota": "docker_local_tmpfs_volume",
            "image_launch_reference": "verified_content_id",
        }
        body = {
            "schema_version": CAPSULE_EXECUTION_AUTHORITY_SCHEMA_VERSION,
            "image_identity": limits.image_identity,
            "security_profile": profile,
        }
        return cls(
            schema_version=body["schema_version"],
            image_identity=body["image_identity"],
            security_profile=MappingProxyType(profile),
            authority_fingerprint=fingerprint(body),
        ).validated()

    def validated(self) -> "CapsuleExecutionAuthority":
        if self.schema_version != CAPSULE_EXECUTION_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported capsule execution authority")
        require_nonempty_text(self.image_identity, "capsule execution image identity", max_bytes=512)
        if not isinstance(self.security_profile, Mapping):
            raise ValueError("capsule security profile must be an object")
        if self.security_profile.get("uid") == 0:
            raise ValueError("capsule execution authority cannot be root")
        for required_false in ("docker_socket_mounted",):
            if self.security_profile.get(required_false) is not False:
                raise ValueError(f"capsule security profile requires {required_false}=false")
        if self.security_profile.get("network") != "none":
            raise ValueError("capsule execution authority requires network none")
        require_sha256(self.authority_fingerprint, "capsule execution authority fingerprint")
        body = {
            "schema_version": self.schema_version,
            "image_identity": self.image_identity,
            "security_profile": dict(self.security_profile),
        }
        if fingerprint(body) != self.authority_fingerprint:
            raise ValueError("capsule execution authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "image_identity": self.image_identity,
            "security_profile": dict(self.security_profile),
            "authority_fingerprint": self.authority_fingerprint,
        }


@dataclass(frozen=True)
class DurableControllerAuthority:
    schema_version: str
    dynamic_tools: tuple[str, ...]
    execution_authority_fingerprint: str
    implementation_source_sha256: str
    request_pairing: str
    controller_fingerprint: str

    @classmethod
    def create(cls, execution: CapsuleExecutionAuthority) -> "DurableControllerAuthority":
        body = {
            "schema_version": CONTROLLER_AUTHORITY_SCHEMA_VERSION,
            "dynamic_tools": list(ALLOWED_DYNAMIC_TOOLS),
            "execution_authority_fingerprint": execution.authority_fingerprint,
            "implementation_source_sha256": sha256_bytes(
                Path(__file__).read_bytes()
            ),
            "request_pairing": "fsync-request-before-effect-exactly-one-result",
        }
        return cls(
            schema_version=body["schema_version"],
            dynamic_tools=tuple(body["dynamic_tools"]),
            execution_authority_fingerprint=body["execution_authority_fingerprint"],
            implementation_source_sha256=body["implementation_source_sha256"],
            request_pairing=body["request_pairing"],
            controller_fingerprint=fingerprint(body),
        ).validated()

    def validated(self) -> "DurableControllerAuthority":
        if self.schema_version != CONTROLLER_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported durable controller authority")
        if self.dynamic_tools != ALLOWED_DYNAMIC_TOOLS:
            raise ValueError("durable controller authority has an unexpected tool set")
        require_sha256(
            self.execution_authority_fingerprint,
            "controller execution authority fingerprint",
        )
        require_sha256(
            self.implementation_source_sha256,
            "controller implementation source identity",
        )
        if self.implementation_source_sha256 != sha256_bytes(Path(__file__).read_bytes()):
            raise ValueError("controller implementation source identity changed")
        if self.request_pairing != "fsync-request-before-effect-exactly-one-result":
            raise ValueError("durable controller request-pairing law changed")
        require_sha256(self.controller_fingerprint, "durable controller fingerprint")
        body = {
            "schema_version": self.schema_version,
            "dynamic_tools": list(self.dynamic_tools),
            "execution_authority_fingerprint": self.execution_authority_fingerprint,
            "implementation_source_sha256": self.implementation_source_sha256,
            "request_pairing": self.request_pairing,
        }
        if fingerprint(body) != self.controller_fingerprint:
            raise ValueError("durable controller fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dynamic_tools": list(self.dynamic_tools),
            "execution_authority_fingerprint": self.execution_authority_fingerprint,
            "implementation_source_sha256": self.implementation_source_sha256,
            "request_pairing": self.request_pairing,
            "controller_fingerprint": self.controller_fingerprint,
        }


@dataclass
class DockerWorkspaceHandle:
    session_id: str
    controller_session_id: str
    capsule_handle: str
    mission_authority_fingerprint: str
    workspace_id: str
    container_name: str
    container_id: str
    volume_name: str
    source_path: Path
    frozen_path: Path
    started_monotonic: float
    container_alive: bool = True
    frozen_workspace_fingerprint: str | None = None
    frozen_observation: ByteTreeObservation | None = None
    frozen_binding_fingerprint: str | None = None
    capsule_exit_code: int | None = None
    capsule_exit_normal: bool = False
    capsule_exit_forced: bool = False
    capsule_exit_observed: bool = False
    container_quarantined: bool = False

    @property
    def public_process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "docker_container",
            "container_id": self.container_id,
            "container_name": self.container_name,
            "controller_session_id": self.controller_session_id,
            "capsule_handle": self.capsule_handle,
            "mission_authority_fingerprint": self.mission_authority_fingerprint,
            "volume_name": self.volume_name,
            "workspace_id": self.workspace_id,
        }


@dataclass(frozen=True)
class ControllerCleanupEvidence:
    container_removed: bool
    complete_process_tree_reaped: bool
    disposable_workspace_removed: bool
    frozen_output_retained: bool
    volume_removed: bool = True

    @property
    def cleanup_proven(self) -> bool:
        return (
            self.container_removed
            and self.complete_process_tree_reaped
            and self.disposable_workspace_removed
            and self.volume_removed
        )

    def to_dict(self) -> dict[str, bool]:
        return {
            "container_removed": self.container_removed,
            "complete_process_tree_reaped": self.complete_process_tree_reaped,
            "disposable_workspace_removed": self.disposable_workspace_removed,
            "frozen_output_retained": self.frozen_output_retained,
            "volume_removed": self.volume_removed,
        }

    def provider_cleanup_result(self) -> CleanupResult:
        return CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1",
            workspace_removed=(
                self.disposable_workspace_removed
                and self.container_removed
                and self.volume_removed
            ),
            processes_reaped=self.complete_process_tree_reaped,
        ).validated()


@dataclass(frozen=True)
class _Capture:
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


class DockerCapsuleController:
    """Trusted controller for a single disposable Docker workspace at a time."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        frozen_output_root: Path,
        limits: DockerCapsuleLimits | None = None,
        docker_executable: Path | None = None,
    ):
        if not workspace_root.is_absolute() or not frozen_output_root.is_absolute():
            raise ValueError("Docker controller roots must be absolute")
        if ".." in workspace_root.parts or ".." in frozen_output_root.parts:
            raise ValueError("Docker controller roots must not contain '..'")
        _reject_existing_symlink_components(workspace_root, "Docker workspace root")
        _reject_existing_symlink_components(frozen_output_root, "Docker frozen-output root")
        if (
            workspace_root == frozen_output_root
            or workspace_root.is_relative_to(frozen_output_root)
            or frozen_output_root.is_relative_to(workspace_root)
        ):
            raise ValueError("Docker controller roots must not overlap")
        self.workspace_root = workspace_root
        self.frozen_output_root = frozen_output_root
        self.limits = (limits or DockerCapsuleLimits()).validated()
        if docker_executable is None:
            fixed_entrypoint = Path("/usr/bin/docker")
            docker_executable = Path(os.path.realpath(fixed_entrypoint))
        elif not isinstance(docker_executable, Path):
            raise ValueError("Docker executable must be an exact absolute Path")
        self.docker_identity = ExecutableFileIdentity.attest(
            docker_executable,
            label="Docker executable",
        )
        self.docker_executable = self.docker_identity.canonical_path
        self.execution_authority = CapsuleExecutionAuthority.create(self.limits)
        self.controller_authority = DurableControllerAuthority.create(self.execution_authority)
        self.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.frozen_output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _reject_existing_symlink_components(self.workspace_root, "Docker workspace root")
        _reject_existing_symlink_components(self.frozen_output_root, "Docker frozen-output root")
        self._objects_root = self.frozen_output_root / "objects"
        self._manifests_root = self.frozen_output_root / "manifests"
        self._objects_root.mkdir(exist_ok=True, mode=0o700)
        self._manifests_root.mkdir(exist_ok=True, mode=0o700)
        self._handles: dict[str, DockerWorkspaceHandle] = {}

    def docker_run_argv(
        self,
        *,
        session_id: str,
        volume_name: str,
        container_name: str,
        capsule_handle: str,
        mission_authority_fingerprint: str,
    ) -> tuple[str, ...]:
        require_identifier(session_id, "Docker capsule session_id")
        require_identifier(volume_name, "Docker capsule volume")
        require_identifier(container_name, "Docker capsule container")
        require_identifier(capsule_handle, "Docker capsule handle")
        require_sha256(mission_authority_fingerprint, "Docker mission authority")
        return (
            self.docker_executable,
            "run",
            "--detach",
            "--name",
            container_name,
            "--label",
            f"admissible.capsule.session={session_id}",
            "--label",
            f"admissible.capsule.controller={self.controller_authority.controller_fingerprint}",
            "--label",
            f"admissible.capsule.handle={capsule_handle}",
            "--label",
            f"admissible.capsule.mission={mission_authority_fingerprint}",
            "--init",
            "--user",
            f"{self.limits.uid}:{self.limits.gid}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--network",
            "none",
            "--cpus",
            self.limits.cpus,
            "--memory",
            self.limits.memory,
            "--memory-swap",
            self.limits.memory,
            "--pids-limit",
            str(self.limits.pids),
            "--ulimit",
            "nofile=256:256",
            "--stop-timeout",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--mount",
            f"type=volume,src={volume_name},dst={DOCKER_WORKSPACE_ROOT},volume-nocopy",
            "--workdir",
            DOCKER_WORKSPACE_ROOT,
            "--env",
            "HOME=/nonexistent",
            "--env",
            "CODEX_HOME=/nonexistent",
            "--env",
            f"PATH={CAPSULE_PATH}",
            self.limits.image_identity,
            "/bin/sleep",
            "infinity",
        )

    def _subprocess_environment(self) -> dict[str, str]:
        return {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "/nonexistent",
            "DOCKER_CONFIG": "/nonexistent",
        }

    def _capture(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        input_bytes: bytes | None = None,
        output_limit: int | None = None,
    ) -> _Capture:
        limit = output_limit if output_limit is not None else self.limits.output_limit_bytes
        if not isinstance(limit, int) or limit < 1:
            raise ValueError("capture output limit must be positive")
        self.docker_identity.reattest(label="Docker executable")
        process = subprocess.Popen(
            [str(part) for part in argv],
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._subprocess_environment(),
            cwd=self.workspace_root,
            start_new_session=True,
            close_fds=True,
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("bounded Docker capture pipes were not created")
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        pending_input = memoryview(input_bytes or b"")
        if input_bytes is not None:
            if process.stdin is None:
                raise RuntimeError("bounded Docker input pipe was not created")
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        stdout = bytearray()
        stderr = bytearray()
        stdout_total = 0
        stderr_total = 0
        timed_out = False
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                events = selector.select(remaining_time)
                if not events:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                for key, mask in events:
                    stream = key.fileobj
                    if key.data == "stdin":
                        if not pending_input:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        try:
                            written = os.write(stream.fileno(), pending_input[:65536])
                        except BrokenPipeError:
                            written = 0
                            selector.unregister(stream)
                            stream.close()
                        pending_input = pending_input[written:]
                        continue
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    if key.data == "stdout":
                        stdout_total += len(chunk)
                        room = max(0, limit - len(stdout))
                        stdout.extend(chunk[:room])
                    else:
                        stderr_total += len(chunk)
                        room = max(0, limit - len(stdout) - len(stderr))
                        stderr.extend(chunk[:room])
                    if stdout_total + stderr_total > limit:
                        os.killpg(process.pid, signal.SIGKILL)
                        selector.close()
                        break
                if not selector.get_map():
                    break
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            exit_code: int | None = None if timed_out else process.returncode
        finally:
            selector.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            if process.stdout is not None and not process.stdout.closed:
                process.stdout.close()
            if process.stderr is not None and not process.stderr.closed:
                process.stderr.close()
        stdout_truncated = stdout_total > len(stdout)
        stderr_truncated = stderr_total > len(stderr)
        return _Capture(
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    def _authority_labels(
        self,
        *,
        session_id: str,
        capsule_handle: str,
        mission_authority_fingerprint: str,
    ) -> dict[str, str]:
        return {
            "admissible.capsule.session": session_id,
            "admissible.capsule.controller": self.controller_authority.controller_fingerprint,
            "admissible.capsule.handle": capsule_handle,
            "admissible.capsule.mission": mission_authority_fingerprint,
        }

    def _inspect_object(
        self,
        kind: str,
        identifier: str,
    ) -> Mapping[str, Any] | None:
        if kind not in {"container", "volume"}:
            raise ValueError("unknown Docker object kind")
        command = (
            (self.docker_executable, "inspect", identifier)
            if kind == "container"
            else (self.docker_executable, "volume", "inspect", identifier)
        )
        capture = self._capture(command, timeout=5, output_limit=64 * 1024)
        if capture.timed_out:
            raise RuntimeError(f"Docker {kind} inspection timed out (UNKNOWN)")
        if capture.exit_code != 0:
            detail = capture.stderr.decode("utf-8", "replace")
            absence_markers = (
                "no such object",
                "no such container",
                "no such volume",
            )
            if any(marker in detail.lower() for marker in absence_markers):
                return None
            raise RuntimeError(f"Docker {kind} inspection failed (UNKNOWN): {detail[:512]}")
        value = strict_json_loads(capture.stdout, label=f"Docker {kind} inspection")
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise RuntimeError(f"Docker {kind} inspection was ambiguous")
        return value[0]

    def _attest_object(
        self,
        kind: str,
        identifier: str,
        expected_labels: Mapping[str, str],
    ) -> Mapping[str, Any]:
        inspection = self._inspect_object(kind, identifier)
        if inspection is None:
            raise RuntimeError(f"authorized Docker {kind} is absent")
        labels = (
            inspection.get("Config", {}).get("Labels")
            if kind == "container"
            else inspection.get("Labels")
        )
        if not isinstance(labels, Mapping) or any(
            labels.get(key) != value for key, value in expected_labels.items()
        ):
            raise RuntimeError(f"Docker {kind} authority labels do not match this session")
        return inspection

    def _remove_owned_object(
        self,
        kind: str,
        identifier: str,
        expected_labels: Mapping[str, str],
    ) -> bool:
        inspection = self._inspect_object(kind, identifier)
        if inspection is None:
            return True
        self._attest_object(kind, identifier, expected_labels)
        command = (
            (self.docker_executable, "rm", "--force", identifier)
            if kind == "container"
            else (self.docker_executable, "volume", "rm", "--force", identifier)
        )
        removed = self._capture(command, timeout=10, output_limit=4096)
        if removed.timed_out or removed.exit_code != 0:
            raise RuntimeError(f"authorized Docker {kind} removal failed")
        return self._inspect_object(kind, identifier) is None

    def prepare(
        self,
        *,
        session_id: str,
        workspace_id: str,
        mission_authority_fingerprint: str | None = None,
    ) -> DockerWorkspaceHandle:
        require_identifier(session_id, "capsule session_id")
        require_identifier(workspace_id, "capsule workspace_id")
        mission_authority_fingerprint = (
            mission_authority_fingerprint
            or fingerprint({"legacy_capsule_session": session_id})
        )
        require_sha256(mission_authority_fingerprint, "capsule mission authority")
        if workspace_id in self._handles:
            raise ValueError("workspace is already prepared")
        source_path = self.workspace_root / workspace_id
        frozen_path = self._objects_root / f"pending-{uuid.uuid4().hex}"
        source_path.mkdir(parents=True, exist_ok=False, mode=0o700)
        if (source_path / ".git").exists():
            raise ValueError("capsule workspace must not contain Git state")
        image = self._capture(
            (
                self.docker_executable,
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                self.limits.image,
            ),
            timeout=10,
            output_limit=1024,
        )
        observed_image_identity = image.stdout.decode("ascii", "replace").strip()
        if (
            image.timed_out
            or image.exit_code != 0
            or observed_image_identity != self.limits.image_identity
        ):
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError("configured capsule image does not match its content identity")
        capsule_handle = f"capsule-{uuid.uuid4().hex}"
        controller_session_id = f"controller-{uuid.uuid4().hex}"
        container_name = f"admissible-capsule-{uuid.uuid4().hex}"
        volume_name = f"admissible-workspace-{uuid.uuid4().hex}"
        labels = self._authority_labels(
            session_id=session_id,
            capsule_handle=capsule_handle,
            mission_authority_fingerprint=mission_authority_fingerprint,
        )
        volume_argv: list[str] = [
            self.docker_executable,
            "volume",
            "create",
            "--driver",
            "local",
        ]
        for key, value in sorted(labels.items()):
            volume_argv.extend(("--label", f"{key}={value}"))
        volume_argv.extend(
            (
                "--opt",
                "type=tmpfs",
                "--opt",
                "device=tmpfs",
                "--opt",
                (
                    f"o=size={self.limits.tree_bytes_limit},uid={self.limits.uid},"
                    f"gid={self.limits.gid},mode=0700"
                ),
                volume_name,
            )
        )
        volume = self._capture(volume_argv, timeout=10, output_limit=4096)
        if volume.timed_out or volume.exit_code != 0 or volume.stdout.decode().strip() != volume_name:
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError("hard-quota Docker workspace volume creation failed")
        volume_inspection = self._attest_object("volume", volume_name, labels)
        expected_volume_options = {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": (
                f"size={self.limits.tree_bytes_limit},uid={self.limits.uid},"
                f"gid={self.limits.gid},mode=0700"
            ),
        }
        if (
            volume_inspection.get("Driver") != "local"
            or volume_inspection.get("Options") != expected_volume_options
        ):
            self._remove_owned_object("volume", volume_name, labels)
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError("Docker workspace quota volume differs from its authority")
        capture = self._capture(
            self.docker_run_argv(
                session_id=session_id,
                volume_name=volume_name,
                container_name=container_name,
                capsule_handle=capsule_handle,
                mission_authority_fingerprint=mission_authority_fingerprint,
            ),
            timeout=20,
            output_limit=4096,
        )
        if capture.timed_out or capture.exit_code != 0:
            # A colliding name with missing/wrong labels is never deleted.
            existing = self._inspect_object("container", container_name)
            if existing is not None:
                existing_labels = existing.get("Config", {}).get("Labels")
                if isinstance(existing_labels, Mapping) and all(
                    existing_labels.get(key) == value for key, value in labels.items()
                ):
                    self._remove_owned_object("container", container_name, labels)
            self._remove_owned_object("volume", volume_name, labels)
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError(
                "Docker capsule failed to start: "
                + capture.stderr.decode("utf-8", "replace")
            )
        container_id = capture.stdout.decode("ascii", "strict").strip()
        if not container_id:
            existing = self._inspect_object("container", container_name)
            if existing is not None:
                existing_labels = existing.get("Config", {}).get("Labels")
                if isinstance(existing_labels, Mapping) and all(
                    existing_labels.get(key) == value for key, value in labels.items()
                ):
                    self._remove_owned_object("container", container_name, labels)
            self._remove_owned_object("volume", volume_name, labels)
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError("Docker capsule returned no process identity")
        try:
            inspection = self._attest_object("container", container_id, labels)
            if inspection.get("Image") != self.limits.image_identity:
                raise RuntimeError("started capsule image differs from immutable authority")
            host_config = inspection.get("HostConfig", {})
            configuration = inspection.get("Config", {})
            if not isinstance(host_config, Mapping) or not isinstance(
                configuration, Mapping
            ):
                raise RuntimeError("started Docker capsule has ambiguous configuration")
            configured_mounts = host_config.get("Mounts")
            observed_mounts = inspection.get("Mounts")
            expected_configured_mounts = [
                {
                    "Type": "volume",
                    "Source": volume_name,
                    "Target": DOCKER_WORKSPACE_ROOT,
                    "VolumeOptions": {"NoCopy": True},
                }
            ]
            exact_checks = {
                "read-only root": host_config.get("ReadonlyRootfs") is True,
                "network": host_config.get("NetworkMode") == "none",
                "privileged": host_config.get("Privileged") is False,
                "added capabilities": host_config.get("CapAdd") is None,
                "dropped capabilities": host_config.get("CapDrop") == ["ALL"],
                "no-new-privileges": (
                    "no-new-privileges:true"
                    in host_config.get("SecurityOpt", [])
                ),
                "PID limit": host_config.get("PidsLimit") == self.limits.pids,
                "CPU limit": (
                    host_config.get("NanoCpus")
                    == self.limits.cpu_millis * 1_000_000
                ),
                "memory limit": host_config.get("Memory") == self.limits.memory_bytes,
                "memory-swap limit": (
                    host_config.get("MemorySwap") == self.limits.memory_bytes
                ),
                "init": host_config.get("Init") is True,
                "file-descriptor limit": (
                    host_config.get("Ulimits")
                    == [{"Name": "nofile", "Hard": 256, "Soft": 256}]
                ),
                "temporary filesystem": (
                    host_config.get("Tmpfs")
                    == {"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777"}
                ),
                "bind mounts": host_config.get("Binds") is None,
                "devices": host_config.get("Devices") == [],
                "supplementary groups": host_config.get("GroupAdd") is None,
                "configured mounts": configured_mounts == expected_configured_mounts,
                "observed mounts": (
                    isinstance(observed_mounts, list)
                    and len(observed_mounts) == 1
                    and observed_mounts[0].get("Type") == "volume"
                    and observed_mounts[0].get("Name") == volume_name
                    and observed_mounts[0].get("Destination")
                    == DOCKER_WORKSPACE_ROOT
                    and observed_mounts[0].get("RW") is True
                ),
                "user": (
                    configuration.get("User")
                    == f"{self.limits.uid}:{self.limits.gid}"
                ),
                "working directory": (
                    configuration.get("WorkingDir") == DOCKER_WORKSPACE_ROOT
                ),
                "image": configuration.get("Image") == self.limits.image_identity,
                "command": configuration.get("Cmd") == ["/bin/sleep", "infinity"],
                "entrypoint": configuration.get("Entrypoint") is None,
                "environment": (
                    isinstance(configuration.get("Env"), list)
                    and len(configuration["Env"]) == 3
                    and set(configuration["Env"])
                    == {
                        "HOME=/nonexistent",
                        "CODEX_HOME=/nonexistent",
                        f"PATH={CAPSULE_PATH}",
                    }
                ),
                "stop timeout": configuration.get("StopTimeout") == 1,
            }
            mismatches = [name for name, matched in exact_checks.items() if not matched]
            if mismatches:
                raise RuntimeError(
                    "started Docker capsule differs from its security authority: "
                    + ", ".join(mismatches)
                )
        except BaseException:
            existing = self._inspect_object("container", container_id)
            if existing is not None:
                existing_labels = existing.get("Config", {}).get("Labels")
                if isinstance(existing_labels, Mapping) and all(
                    existing_labels.get(key) == value for key, value in labels.items()
                ):
                    self._remove_owned_object("container", container_id, labels)
            self._remove_owned_object("volume", volume_name, labels)
            shutil.rmtree(source_path, ignore_errors=True)
            raise
        handle = DockerWorkspaceHandle(
            session_id=session_id,
            controller_session_id=controller_session_id,
            capsule_handle=capsule_handle,
            mission_authority_fingerprint=mission_authority_fingerprint,
            workspace_id=workspace_id,
            container_name=container_name,
            container_id=container_id,
            volume_name=volume_name,
            source_path=source_path,
            frozen_path=frozen_path,
            started_monotonic=time.monotonic(),
        )
        self._handles[workspace_id] = handle
        return handle

    def get(self, workspace_id: str) -> DockerWorkspaceHandle:
        try:
            return self._handles[workspace_id]
        except KeyError as error:
            raise ValueError("unknown capsule workspace") from error

    def _validate_relative_path(self, value: Any) -> str:
        return validate_closed_relative_path(
            value,
            label="capsule relative path",
            allow_root=True,
        )

    def _handle_labels(self, handle: DockerWorkspaceHandle) -> Mapping[str, str]:
        return self._authority_labels(
            session_id=handle.session_id,
            capsule_handle=handle.capsule_handle,
            mission_authority_fingerprint=handle.mission_authority_fingerprint,
        )

    def _container_running(self, handle: DockerWorkspaceHandle) -> bool:
        if not handle.container_alive:
            return False
        inspection = self._inspect_object("container", handle.container_id)
        if inspection is None:
            handle.container_alive = False
            return False
        self._attest_object("container", handle.container_id, self._handle_labels(handle))
        state = inspection.get("State")
        if not isinstance(state, Mapping) or not isinstance(state.get("Running"), bool):
            raise RuntimeError("Docker inspect returned an ambiguous running state")
        running = state["Running"]
        handle.container_alive = running
        if not running:
            self._record_capsule_exit(handle, inspection)
        return running

    def _record_capsule_exit(
        self,
        handle: DockerWorkspaceHandle,
        inspection: Mapping[str, Any],
        *,
        forced: bool | None = None,
    ) -> None:
        state = inspection.get("State")
        if (
            not isinstance(state, Mapping)
            or state.get("Running") is not False
            or isinstance(state.get("ExitCode"), bool)
            or not isinstance(state.get("ExitCode"), int)
        ):
            raise RuntimeError("Docker capsule exit state is ambiguous")
        exit_code = state["ExitCode"]
        inferred_forced = (
            forced
            if forced is not None
            else bool(state.get("OOMKilled")) or exit_code >= 128
        )
        handle.capsule_exit_code = exit_code
        handle.capsule_exit_forced = inferred_forced
        handle.capsule_exit_normal = not inferred_forced
        handle.capsule_exit_observed = True

    def _kill_container(self, handle: DockerWorkspaceHandle) -> None:
        if not handle.container_alive:
            return
        inspection = self._attest_object(
            "container",
            handle.container_id,
            self._handle_labels(handle),
        )
        if (
            isinstance(inspection.get("State"), Mapping)
            and inspection["State"].get("Paused") is True
        ):
            self._unpause_container(handle)
        killed = self._capture(
            (self.docker_executable, "kill", handle.container_id),
            timeout=5,
            output_limit=1024,
        )
        inspection = self._inspect_object("container", handle.container_id)
        stopped = (
            inspection is not None
            and isinstance(inspection.get("State"), Mapping)
            and inspection["State"].get("Running") is False
        )
        handle.container_alive = not stopped
        if not stopped or killed.timed_out or killed.exit_code != 0:
            raise RuntimeError("complete capsule process-tree termination was unconfirmed")
        self._record_capsule_exit(handle, inspection, forced=True)

    def _quarantine_container(self, handle: DockerWorkspaceHandle) -> None:
        """Stop every effect while preserving the mounted hard-quota tmpfs."""

        inspection = self._inspect_object("container", handle.container_id)
        if inspection is None:
            handle.container_alive = False
            raise RuntimeError("capsule disappeared before quarantine")
        self._attest_object("container", handle.container_id, self._handle_labels(handle))
        state = inspection.get("State")
        if not isinstance(state, Mapping) or state.get("Running") is not True:
            handle.container_alive = False
            raise RuntimeError("capsule was not running at quarantine")
        if state.get("Paused") is not True:
            self._pause_container(handle)
        handle.container_quarantined = True

    def _pause_container(self, handle: DockerWorkspaceHandle) -> None:
        if not self._container_running(handle):
            raise RuntimeError("capsule process is not running for coherent freeze")
        self._attest_object("container", handle.container_id, self._handle_labels(handle))
        paused = self._capture(
            (self.docker_executable, "pause", handle.container_id),
            timeout=5,
            output_limit=1024,
        )
        inspection = self._inspect_object("container", handle.container_id)
        if (
            paused.timed_out
            or paused.exit_code != 0
            or inspection is None
            or not isinstance(inspection.get("State"), Mapping)
            or inspection["State"].get("Paused") is not True
        ):
            raise RuntimeError("complete capsule process-tree pause was unconfirmed")

    def _unpause_container(self, handle: DockerWorkspaceHandle) -> None:
        unpaused = self._capture(
            (self.docker_executable, "unpause", handle.container_id),
            timeout=5,
            output_limit=1024,
        )
        if unpaused.timed_out or unpaused.exit_code != 0:
            raise RuntimeError("capsule could not leave its frozen state for cleanup")

    def _docker_exec(
        self,
        handle: DockerWorkspaceHandle,
        argv: Sequence[str],
        *,
        timeout: float,
        input_bytes: bytes | None = None,
    ) -> _Capture:
        if time.monotonic() - handle.started_monotonic > self.limits.session_timeout_seconds:
            self._quarantine_container(handle)
            return _Capture(None, True, b"", b"capsule session wall time exceeded", False, False)
        if not self._container_running(handle):
            return _Capture(125, False, b"", b"capsule process is not running", False, False)
        docker_argv = [
            self.docker_executable,
            "exec",
            "--workdir",
            DOCKER_WORKSPACE_ROOT,
        ]
        if input_bytes is not None:
            docker_argv.append("--interactive")
        docker_argv.extend((handle.container_id, *argv))
        capture = self._capture(
            docker_argv,
            timeout=min(timeout, self.limits.command_timeout_seconds),
            input_bytes=input_bytes,
        )
        if capture.timed_out or capture.stdout_truncated or capture.stderr_truncated:
            # The CLI dying does not prove the in-container descendant died.
            # Pausing the entire container closes effects while retaining the
            # hard-quota tmpfs for a coherent evidence freeze.
            self._quarantine_container(handle)
        return capture

    def _result(
        self,
        request: DurableToolRequest,
        capture: _Capture,
        *,
        refused: bool = False,
    ) -> DurableToolResult:
        if capture.timed_out:
            classification = ToolTerminalClassification.TIMED_OUT
        elif capture.stdout_truncated or capture.stderr_truncated:
            classification = ToolTerminalClassification.OUTPUT_LIMIT_REFUSED
        elif refused:
            classification = ToolTerminalClassification.REFUSED
        elif capture.exit_code == 0:
            classification = ToolTerminalClassification.SUCCEEDED
        else:
            classification = ToolTerminalClassification.FAILED
        return DurableToolResult.create(
            request=request,
            classification=classification,
            exit_code=capture.exit_code,
            timed_out=capture.timed_out,
            stdout=capture.stdout.decode("utf-8", "replace").replace("\x00", "\ufffd"),
            stderr=capture.stderr.decode("utf-8", "replace").replace("\x00", "\ufffd"),
            stdout_truncated=capture.stdout_truncated,
            stderr_truncated=capture.stderr_truncated,
        )

    def _audit_live_workspace(self, handle: DockerWorkspaceHandle) -> None:
        capture = self._docker_exec(
            handle,
            (
                "/usr/bin/find",
                "/workspace",
                "-xdev",
                "-mindepth",
                "1",
                "-printf",
                "%y %n %s %P\\0",
            ),
            timeout=self.limits.command_timeout_seconds,
        )
        if capture.timed_out or capture.exit_code != 0:
            raise ValueError("live workspace could not be audited safely")
        if capture.stdout_truncated or capture.stderr_truncated:
            raise ValueError("live workspace audit exceeded its bounded namespace")
        records = capture.stdout.split(b"\0")
        if records and records[-1] == b"":
            records.pop()
        if len(records) > self.limits.file_count_limit:
            raise ValueError("live workspace file-count quota exceeded")
        collisions: dict[str, str] = {}
        total = 0
        for raw in records:
            try:
                kind, links, size, raw_path = raw.split(b" ", 3)
                relative = raw_path.decode("utf-8", "strict")
            except (ValueError, UnicodeDecodeError) as error:
                raise ValueError("live workspace has an ambiguous directory record") from error
            validate_closed_relative_path(relative, label="live workspace path")
            key = portable_path_collision_key(relative)
            if key in collisions:
                raise ValueError("live workspace has a case-fold/Unicode collision")
            collisions[key] = relative
            if kind not in {b"f", b"d"}:
                raise ValueError("live workspace contains a symlink or special file")
            if kind == b"f":
                if links != b"1":
                    raise ValueError("live workspace contains a hard-linked file")
                try:
                    total += int(size)
                except ValueError as error:
                    raise ValueError("live workspace size record is invalid") from error
        if total > self.limits.tree_bytes_limit:
            # The tmpfs mount is the hard enforcement; this is independent
            # evidence that its configured authority was not exceeded.
            raise ValueError("live workspace byte quota exceeded")

    def _audit_process_tree(self, handle: DockerWorkspaceHandle) -> None:
        """Prove no provider descendant can race a later file operation."""

        if not self._container_running(handle):
            raise ValueError("capsule process is not running")
        capture = self._capture(
            (
                self.docker_executable,
                "top",
                handle.container_id,
                "-eo",
                "pid,ppid,comm,args",
            ),
            timeout=5,
            output_limit=4096,
        )
        if capture.timed_out or capture.exit_code != 0:
            raise ValueError("capsule process tree could not be audited")
        try:
            lines = capture.stdout.decode("utf-8", "strict").splitlines()
        except UnicodeDecodeError as error:
            raise ValueError("capsule process tree was ambiguous") from error
        if len(lines) != 3:
            raise ValueError("capsule has an unauthorized surviving descendant")
        rows = [line.split(None, 3) for line in lines[1:]]
        if any(len(row) != 4 or not row[0].isdigit() or not row[1].isdigit() for row in rows):
            raise ValueError("capsule process tree was malformed")
        init, sleeper = rows
        if not (
            init[2:] == ["docker-init", "/sbin/docker-init -- /bin/sleep infinity"]
            and sleeper[1] == init[0]
            and sleeper[2:] == ["sleep", "/bin/sleep infinity"]
        ):
            raise ValueError("capsule process tree differs from its sealed idle authority")

    def refusal(self, request: DurableToolRequest, detail: str) -> DurableToolResult:
        require_nonempty_text(detail, "tool refusal detail", max_bytes=8192)
        return self._result(
            request,
            _Capture(64, False, b"", detail.encode("utf-8"), False, False),
            refused=True,
        )

    def execute(self, handle: DockerWorkspaceHandle, request: DurableToolRequest) -> DurableToolResult:
        """Execute one already-durable request and return one bounded result."""

        request.validated()
        if (
            request.session_id != handle.session_id
            or request.controller_session_id != handle.controller_session_id
            or request.capsule_handle != handle.capsule_handle
            or request.mission_authority_fingerprint
            != handle.mission_authority_fingerprint
        ):
            return self.refusal(
                request,
                "request identity does not match the exact capsule session/handle/mission",
            )
        if handle.container_quarantined:
            return self.refusal(request, "capsule is quarantined after a terminal effect")
        if request.namespace != "capsule_effects" or request.tool not in ALLOWED_DYNAMIC_TOOLS:
            return self.refusal(request, "tool is outside the explicit capsule_effects grammar")
        try:
            self._audit_process_tree(handle)
            self._audit_live_workspace(handle)
            if request.tool == "list_files":
                if set(request.arguments) != {"path", "max_depth"}:
                    raise ValueError("list_files arguments must be exactly path and max_depth")
                relative = self._validate_relative_path(request.arguments["path"])
                depth = request.arguments["max_depth"]
                if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 8:
                    raise ValueError("list_files max_depth must be in [1, 8]")
                capture = self._docker_exec(
                    handle,
                    ("/bin/sh", "-ceu", LIST_SCRIPT, "--", relative, str(depth)),
                    timeout=self.limits.command_timeout_seconds,
                )
            elif request.tool == "read_file":
                if set(request.arguments) != {"path"}:
                    raise ValueError("read_file arguments must contain only path")
                relative = self._validate_relative_path(request.arguments["path"])
                capture = self._docker_exec(
                    handle,
                    ("/bin/sh", "-ceu", READ_SCRIPT, "--", relative),
                    timeout=self.limits.command_timeout_seconds,
                )
            elif request.tool == "write_file":
                if set(request.arguments) != {"path", "content", "operation"}:
                    raise ValueError("write_file arguments must be exactly path, content, operation")
                relative = self._validate_relative_path(request.arguments["path"])
                content = request.arguments["content"]
                operation = request.arguments["operation"]
                if not isinstance(content, str) or "\x00" in content:
                    raise ValueError("write_file content must be UTF-8 text without NUL")
                encoded = content.encode("utf-8")
                if len(encoded) > self.limits.write_limit_bytes:
                    raise ValueError("write_file content exceeds its byte bound")
                if operation not in {"create", "replace", "upsert"}:
                    raise ValueError("write_file operation is not allowed")
                capture = self._docker_exec(
                    handle,
                    ("/bin/sh", "-ceu", WRITE_SCRIPT, "--", relative, operation),
                    timeout=self.limits.command_timeout_seconds,
                    input_bytes=encoded,
                )
            else:
                if set(request.arguments) != {"argv", "cwd", "timeout_ms"}:
                    raise ValueError("run_command arguments must be exactly argv, cwd, timeout_ms")
                command = request.arguments["argv"]
                if (
                    not isinstance(command, list)
                    or not 1 <= len(command) <= 32
                    or any(
                        not isinstance(part, str)
                        or not part
                        or "\x00" in part
                        or len(part.encode("utf-8")) > 4096
                        for part in command
                    )
                    or sum(len(part.encode("utf-8")) for part in command) > 16 * 1024
                ):
                    raise ValueError("run_command argv exceeds its structural bounds")
                cwd = self._validate_relative_path(request.arguments["cwd"])
                timeout_ms = request.arguments["timeout_ms"]
                if (
                    isinstance(timeout_ms, bool)
                    or not isinstance(timeout_ms, int)
                    or not 50 <= timeout_ms <= int(self.limits.command_timeout_seconds * 1000)
                ):
                    raise ValueError("run_command timeout_ms is out of bounds")
                guard = (
                    'lexical="$(realpath -s -m -- "/workspace/$1")"; '
                    'target="$(realpath -e -- "/workspace/$1")"; '
                    'case "$target" in /workspace|/workspace/*) ;; *) exit 72 ;; esac; '
                    '[ "$target" = "$lexical" ] || exit 75; '
                    'shift; cd -- "$target"; exec "$@"'
                )
                capture = self._docker_exec(
                    handle,
                    ("/bin/sh", "-ceu", guard, "--", cwd, *command),
                    timeout=timeout_ms / 1000,
                )
        except ValueError as error:
            return self.refusal(request, str(error))
        result = self._result(request, capture)
        if handle.container_alive and not handle.container_quarantined:
            try:
                self._audit_process_tree(handle)
                self._audit_live_workspace(handle)
            except ValueError as error:
                self._quarantine_container(handle)
                return self.refusal(request, str(error))
        return result

    def _observe_secure_tree(
        self,
        root: Path,
    ) -> tuple[ByteTreeObservation, list[Mapping[str, Any]]]:
        entries: list[ObservedEntry] = []
        manifest: list[Mapping[str, Any]] = []
        collision_keys: dict[str, str] = {}
        file_count = 0
        tree_bytes = 0
        root_device = root.stat(follow_symlinks=False).st_dev
        for current, directories, files in os.walk(root, followlinks=False):
            directories.sort()
            files.sort()
            current_path = Path(current)
            for name in [*directories, *files]:
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                validate_closed_relative_path(relative, label="frozen output path")
                collision_key = portable_path_collision_key(relative)
                if collision_key in collision_keys:
                    raise ValueError(
                        "provider output contains a case-fold/Unicode-normalization collision"
                    )
                collision_keys[collision_key] = relative
                info = path.lstat()
                kind = mode_type(info.st_mode)
                if info.st_dev != root_device:
                    raise ValueError("provider output crosses a filesystem boundary")
                if kind not in {"directory", "regular"}:
                    raise ValueError(
                        f"provider output contains forbidden {kind} entry: {relative}"
                    )
                digest = None
                size = 0
                if kind == "regular":
                    if info.st_nlink != 1:
                        raise ValueError("provider output contains a hard-linked file")
                    file_count += 1
                    tree_bytes += info.st_size
                    if (
                        file_count > self.limits.file_count_limit
                        or tree_bytes > self.limits.tree_bytes_limit
                    ):
                        raise ValueError("provider output tree exceeds its bound")
                    flags = os.O_RDONLY
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(path, flags)
                    try:
                        before = os.fstat(descriptor)
                        hasher = hashlib.sha256()
                        while True:
                            block = os.read(descriptor, 64 * 1024)
                            if not block:
                                break
                            hasher.update(block)
                        after = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                    identity = (
                        before.st_dev,
                        before.st_ino,
                        before.st_mode,
                        before.st_nlink,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    )
                    if identity != (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                        after.st_nlink,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        raise ValueError("provider output mutated during freeze observation")
                    digest = hasher.hexdigest()
                    size = before.st_size
                entry = ObservedEntry(
                    relative_path=relative,
                    kind=kind,
                    size=size,
                    sha256=digest,
                ).validated()
                entries.append(entry)
                manifest.append(
                    {
                        **entry.to_dict(),
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
        return ByteTreeObservation.create(entries=tuple(entries)), manifest

    def _extract_workspace_volume(
        self,
        handle: DockerWorkspaceHandle,
        destination: Path,
    ) -> None:
        labels = self._handle_labels(handle)
        extractor_name = f"admissible-freezer-{uuid.uuid4().hex}"
        argv: list[str] = [
            self.docker_executable,
            "run",
            "--name",
            extractor_name,
        ]
        for key, value in sorted(labels.items()):
            argv.extend(("--label", f"{key}={value}"))
        argv.extend(
            (
                "--user",
                f"{self.limits.uid}:{self.limits.gid}",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--network",
                "none",
                "--pids-limit",
                str(self.limits.pids),
                "--memory",
                self.limits.memory,
                "--memory-swap",
                self.limits.memory,
                "--mount",
                f"type=volume,src={handle.volume_name},dst=/workspace,readonly,volume-nocopy",
                "--mount",
                f"type=bind,src={destination},dst=/frozen",
                "--workdir",
                "/workspace",
                self.limits.image_identity,
                "/bin/cp",
                "-a",
                "/workspace/.",
                "/frozen/",
            )
        )
        capture = self._capture(argv, timeout=30, output_limit=4096)
        try:
            if capture.timed_out or capture.exit_code != 0:
                raise RuntimeError(
                    "content-addressed workspace extraction failed: "
                    + capture.stderr.decode("utf-8", "replace")
                )
        finally:
            existing = self._inspect_object("container", extractor_name)
            if existing is not None:
                self._remove_owned_object(
                    "container",
                    extractor_name,
                    labels,
                )

    def freeze_output(self, handle: DockerWorkspaceHandle) -> ByteTreeObservation:
        if handle.frozen_workspace_fingerprint is not None:
            raise ValueError("frozen provider output already exists")
        # Pause init and every descendant while the still-mounted hard-quota
        # tmpfs is extracted. A completed turn is not quiescence evidence. An
        # independently attested stopped container is already quiescent and
        # its exact labeled volume remains recoverable after a process crash.
        inspection = self._inspect_object("container", handle.container_id)
        if inspection is None:
            raise RuntimeError("capsule object absence prevents coherent freeze")
        self._attest_object("container", handle.container_id, self._handle_labels(handle))
        state = inspection.get("State")
        if not isinstance(state, Mapping) or not isinstance(state.get("Running"), bool):
            raise RuntimeError("Docker inspect returned ambiguous freeze state")
        if state["Running"] and state.get("Paused") is not True:
            self._pause_container(handle)
        elif state["Running"]:
            handle.container_quarantined = True
        else:
            handle.container_alive = False
            self._record_capsule_exit(handle, inspection)
        temporary = self._objects_root / f".extract-{uuid.uuid4().hex}"
        temporary.mkdir(mode=0o700)
        published_destination: Path | None = None
        published_manifest: Path | None = None
        try:
            self._extract_workspace_volume(handle, temporary)
            observation, manifest_entries = self._observe_secure_tree(temporary)
            manifest_body = {
                "schema_version": "admissible_capsule_frozen_snapshot_manifest_v1",
                "capsule_authority_fingerprint": handle.mission_authority_fingerprint,
                "workspace_id": handle.workspace_id,
                "tree_hash": observation.tree_hash,
                "entries": manifest_entries,
            }
            snapshot_fingerprint = fingerprint(manifest_body)
            destination = self._objects_root / snapshot_fingerprint
            if destination.exists():
                raise ValueError("content-addressed frozen snapshot already exists")
            for root, _directories, _files in os.walk(temporary, topdown=False):
                fsync_directory(Path(root))
            os.replace(temporary, destination)
            published_destination = destination
            fsync_directory(self._objects_root)
            manifest_path = self._manifests_root / f"{snapshot_fingerprint}.json"
            published_manifest = manifest_path
            from admissible.capsule.common import atomic_json

            atomic_json(
                manifest_path,
                {
                    **manifest_body,
                    "snapshot_fingerprint": snapshot_fingerprint,
                    "observation": observation.to_dict(),
                },
                mode=0o400,
            )
            handle.frozen_path = destination
            handle.frozen_workspace_fingerprint = snapshot_fingerprint
            handle.frozen_observation = observation
            return self.observe_frozen_output(handle)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            if handle.frozen_workspace_fingerprint is None:
                if published_manifest is not None:
                    published_manifest.unlink(missing_ok=True)
                    fsync_directory(self._manifests_root)
                if published_destination is not None:
                    shutil.rmtree(published_destination, ignore_errors=True)
                    fsync_directory(self._objects_root)
            raise
        finally:
            inspection = self._inspect_object("container", handle.container_id)
            if (
                inspection is not None
                and isinstance(inspection.get("State"), Mapping)
                and inspection["State"].get("Paused") is True
            ):
                self._unpause_container(handle)
            if handle.container_alive:
                self._kill_container(handle)

    def observe_frozen_output(self, handle: DockerWorkspaceHandle) -> ByteTreeObservation:
        if (
            handle.frozen_workspace_fingerprint is None
            or handle.frozen_observation is None
            or handle.frozen_path.name != handle.frozen_workspace_fingerprint
            or not handle.frozen_path.is_dir()
        ):
            raise ValueError("provider output is not a published content-addressed snapshot")
        observation, manifest_entries = self._observe_secure_tree(handle.frozen_path)
        manifest_body = {
            "schema_version": "admissible_capsule_frozen_snapshot_manifest_v1",
            "capsule_authority_fingerprint": handle.mission_authority_fingerprint,
            "workspace_id": handle.workspace_id,
            "tree_hash": observation.tree_hash,
            "entries": manifest_entries,
        }
        if (
            fingerprint(manifest_body) != handle.frozen_workspace_fingerprint
            or observation != handle.frozen_observation
        ):
            raise ValueError("frozen provider output mutated after publication")
        manifest = strict_json_loads(
            (
                self._manifests_root
                / f"{handle.frozen_workspace_fingerprint}.json"
            ).read_bytes(),
            label="frozen snapshot manifest",
        )
        if (
            manifest.get("snapshot_fingerprint")
            != handle.frozen_workspace_fingerprint
            or manifest.get("observation") != observation.to_dict()
        ):
            raise ValueError("frozen snapshot manifest binding mismatch")
        return observation

    def bind_frozen_snapshot(
        self,
        handle: DockerWorkspaceHandle,
        *,
        journal_tail_fingerprint: str,
        cleanup_fingerprint: str,
    ) -> str:
        require_sha256(journal_tail_fingerprint, "snapshot journal-tail binding")
        require_sha256(cleanup_fingerprint, "snapshot cleanup binding")
        self.observe_frozen_output(handle)
        body = {
            "schema_version": "admissible_capsule_frozen_snapshot_binding_v1",
            "snapshot_fingerprint": handle.frozen_workspace_fingerprint,
            "journal_tail_fingerprint": journal_tail_fingerprint,
            "cleanup_fingerprint": cleanup_fingerprint,
        }
        binding_fingerprint = fingerprint(body)
        from admissible.capsule.common import atomic_json

        atomic_json(
            self._manifests_root
            / f"{handle.frozen_workspace_fingerprint}.binding.json",
            {**body, "binding_fingerprint": binding_fingerprint},
            mode=0o400,
        )
        handle.frozen_binding_fingerprint = binding_fingerprint
        return binding_fingerprint

    def cleanup(self, handle: DockerWorkspaceHandle) -> ControllerCleanupEvidence:
        labels = self._handle_labels(handle)
        inspection = self._inspect_object("container", handle.container_id)
        if inspection is not None:
            self._attest_object("container", handle.container_id, labels)
            state = inspection.get("State")
            if not isinstance(state, Mapping) or not isinstance(state.get("Running"), bool):
                raise RuntimeError("Docker cleanup found ambiguous capsule process state")
            if state["Running"]:
                handle.container_alive = True
                self._kill_container(handle)
            elif not handle.capsule_exit_observed:
                self._record_capsule_exit(handle, inspection)
        container_removed = self._remove_owned_object(
            "container",
            handle.container_id,
            labels,
        )
        handle.container_alive = not container_removed
        volume_removed = self._remove_owned_object(
            "volume",
            handle.volume_name,
            labels,
        )
        shutil.rmtree(handle.source_path, ignore_errors=True)
        workspace_removed = not handle.source_path.exists()
        return ControllerCleanupEvidence(
            container_removed=container_removed,
            complete_process_tree_reaped=(
                container_removed
                and volume_removed
                and handle.capsule_exit_observed
            ),
            disposable_workspace_removed=workspace_removed,
            frozen_output_retained=handle.frozen_path.is_dir(),
            volume_removed=volume_removed,
        )

    def frozen_output_path(self, workspace_id: str) -> Path:
        """Output-intake authority path; never passed to the control process."""

        handle = self.get(workspace_id)
        self.observe_frozen_output(handle)
        if handle.frozen_binding_fingerprint is None:
            raise ValueError("frozen output has no journal-tail/cleanup binding")
        binding = strict_json_loads(
            (
                self._manifests_root
                / f"{handle.frozen_workspace_fingerprint}.binding.json"
            ).read_bytes(),
            label="frozen snapshot binding",
        )
        body = {key: value for key, value in binding.items() if key != "binding_fingerprint"}
        if (
            binding.get("binding_fingerprint") != handle.frozen_binding_fingerprint
            or fingerprint(body) != handle.frozen_binding_fingerprint
        ):
            raise ValueError("frozen snapshot binding was mutated")
        return handle.frozen_path
