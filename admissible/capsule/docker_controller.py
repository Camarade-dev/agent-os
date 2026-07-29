"""Docker-backed execution authority for dynamic capsule tools.

Only this trusted controller can use the host Docker client.  The Codex
control process receives neither the Docker socket nor a host workspace path.
All provider-requested reads, writes, listings, and commands execute through
fixed `docker exec` operations in one sealed, disposable container.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
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
)
from admissible.capsule.models import ByteTreeObservation, CleanupResult, ObservedEntry
from admissible.capsule.session_store import (
    DurableToolRequest,
    DurableToolResult,
    ToolTerminalClassification,
)


CONTROLLER_AUTHORITY_SCHEMA_VERSION = "admissible_durable_capsule_controller_authority_v1"
CAPSULE_EXECUTION_AUTHORITY_SCHEMA_VERSION = "admissible_docker_capsule_execution_authority_v1"
DOCKER_WORKSPACE_ROOT = "/workspace"
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
        return self


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
            "memory": limits.memory,
            "pids": limits.pids,
            "session_timeout_seconds": limits.session_timeout_seconds,
            "command_timeout_seconds": limits.command_timeout_seconds,
            "output_limit_bytes": limits.output_limit_bytes,
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
    request_pairing: str
    controller_fingerprint: str

    @classmethod
    def create(cls, execution: CapsuleExecutionAuthority) -> "DurableControllerAuthority":
        body = {
            "schema_version": CONTROLLER_AUTHORITY_SCHEMA_VERSION,
            "dynamic_tools": list(ALLOWED_DYNAMIC_TOOLS),
            "execution_authority_fingerprint": execution.authority_fingerprint,
            "request_pairing": "fsync-request-before-effect-exactly-one-result",
        }
        return cls(
            schema_version=body["schema_version"],
            dynamic_tools=tuple(body["dynamic_tools"]),
            execution_authority_fingerprint=body["execution_authority_fingerprint"],
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
        if self.request_pairing != "fsync-request-before-effect-exactly-one-result":
            raise ValueError("durable controller request-pairing law changed")
        require_sha256(self.controller_fingerprint, "durable controller fingerprint")
        body = {
            "schema_version": self.schema_version,
            "dynamic_tools": list(self.dynamic_tools),
            "execution_authority_fingerprint": self.execution_authority_fingerprint,
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
            "request_pairing": self.request_pairing,
            "controller_fingerprint": self.controller_fingerprint,
        }


@dataclass
class DockerWorkspaceHandle:
    session_id: str
    workspace_id: str
    container_name: str
    container_id: str
    source_path: Path
    frozen_path: Path
    started_monotonic: float
    container_alive: bool = True

    @property
    def public_process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "docker_container",
            "container_id": self.container_id,
            "container_name": self.container_name,
            "workspace_id": self.workspace_id,
        }


@dataclass(frozen=True)
class ControllerCleanupEvidence:
    container_removed: bool
    complete_process_tree_reaped: bool
    disposable_workspace_removed: bool
    frozen_output_retained: bool

    @property
    def cleanup_proven(self) -> bool:
        return (
            self.container_removed
            and self.complete_process_tree_reaped
            and self.disposable_workspace_removed
        )

    def to_dict(self) -> dict[str, bool]:
        return {
            "container_removed": self.container_removed,
            "complete_process_tree_reaped": self.complete_process_tree_reaped,
            "disposable_workspace_removed": self.disposable_workspace_removed,
            "frozen_output_retained": self.frozen_output_retained,
        }

    def provider_cleanup_result(self) -> CleanupResult:
        return CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1",
            workspace_removed=self.disposable_workspace_removed and self.container_removed,
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
        docker_executable: str = "docker",
    ):
        self.workspace_root = workspace_root
        self.frozen_output_root = frozen_output_root
        self.limits = (limits or DockerCapsuleLimits()).validated()
        self.docker_executable = docker_executable
        self.execution_authority = CapsuleExecutionAuthority.create(self.limits)
        self.controller_authority = DurableControllerAuthority.create(self.execution_authority)
        self.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.frozen_output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._handles: dict[str, DockerWorkspaceHandle] = {}

    def docker_run_argv(self, *, session_id: str, source_path: Path, container_name: str) -> tuple[str, ...]:
        require_identifier(session_id, "Docker capsule session_id")
        return (
            self.docker_executable,
            "run",
            "--detach",
            "--name",
            container_name,
            "--label",
            f"admissible.capsule.session={session_id}",
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
            f"type=bind,src={source_path},dst={DOCKER_WORKSPACE_ROOT}",
            "--workdir",
            DOCKER_WORKSPACE_ROOT,
            "--env",
            "HOME=/nonexistent",
            "--env",
            "CODEX_HOME=/nonexistent",
            self.limits.image,
            "/bin/sleep",
            "infinity",
        )

    def _subprocess_environment(self) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        # A non-default daemon endpoint is controller transport configuration,
        # not provider or capsule authentication, so preserve only this one
        # Docker client selector when present.
        if "DOCKER_HOST" in os.environ:
            environment["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
        return environment

    def _capture(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        input_bytes: bytes | None = None,
        output_limit: int | None = None,
    ) -> _Capture:
        limit = output_limit if output_limit is not None else self.limits.output_limit_bytes
        process = subprocess.Popen(
            [str(part) for part in argv],
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._subprocess_environment(),
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
            exit_code: int | None = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            exit_code = None
        stdout_truncated = len(stdout) > limit
        kept_stdout = stdout[:limit]
        remaining = max(0, limit - len(kept_stdout))
        stderr_truncated = len(stderr) > remaining
        kept_stderr = stderr[:remaining]
        return _Capture(
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=kept_stdout,
            stderr=kept_stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    def prepare(self, *, session_id: str, workspace_id: str) -> DockerWorkspaceHandle:
        require_identifier(session_id, "capsule session_id")
        require_identifier(workspace_id, "capsule workspace_id")
        if workspace_id in self._handles:
            raise ValueError("workspace is already prepared")
        source_path = self.workspace_root / workspace_id
        frozen_path = self.frozen_output_root / workspace_id
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
        container_name = f"admissible-capsule-{fingerprint({'session': session_id, 'workspace': workspace_id})[:24]}"
        capture = self._capture(
            self.docker_run_argv(
                session_id=session_id,
                source_path=source_path,
                container_name=container_name,
            ),
            timeout=20,
            output_limit=4096,
        )
        if capture.timed_out or capture.exit_code != 0:
            self._capture(
                (self.docker_executable, "rm", "--force", container_name),
                timeout=5,
                output_limit=1024,
            )
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError(
                "Docker capsule failed to start: "
                + capture.stderr.decode("utf-8", "replace")
            )
        container_id = capture.stdout.decode("ascii", "strict").strip()
        if not container_id:
            shutil.rmtree(source_path, ignore_errors=True)
            raise RuntimeError("Docker capsule returned no process identity")
        handle = DockerWorkspaceHandle(
            session_id=session_id,
            workspace_id=workspace_id,
            container_name=container_name,
            container_id=container_id,
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
        require_nonempty_text(value, "capsule relative path", max_bytes=4096)
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", "..", ".git"} for part in path.parts):
            raise ValueError("path escapes or targets forbidden workspace state")
        normalized = str(path)
        if normalized in {"", "."}:
            return "."
        return normalized

    def _container_running(self, handle: DockerWorkspaceHandle) -> bool:
        if not handle.container_alive:
            return False
        capture = self._capture(
            (
                self.docker_executable,
                "inspect",
                "--format",
                "{{.State.Running}}",
                handle.container_id,
            ),
            timeout=5,
            output_limit=1024,
        )
        running = capture.exit_code == 0 and capture.stdout.strip() == b"true"
        handle.container_alive = running
        return running

    def _kill_container(self, handle: DockerWorkspaceHandle) -> None:
        if not handle.container_alive:
            return
        killed = self._capture(
            (self.docker_executable, "kill", handle.container_id),
            timeout=5,
            output_limit=1024,
        )
        inspected = self._capture(
            (
                self.docker_executable,
                "inspect",
                "--format",
                "{{.State.Running}}",
                handle.container_id,
            ),
            timeout=5,
            output_limit=1024,
        )
        stopped = (
            inspected.exit_code != 0
            or inspected.stdout.strip() == b"false"
        )
        handle.container_alive = not stopped
        if not stopped and (killed.timed_out or killed.exit_code != 0):
            raise RuntimeError("complete capsule process-tree termination was unconfirmed")

    def _docker_exec(
        self,
        handle: DockerWorkspaceHandle,
        argv: Sequence[str],
        *,
        timeout: float,
        input_bytes: bytes | None = None,
    ) -> _Capture:
        if time.monotonic() - handle.started_monotonic > self.limits.session_timeout_seconds:
            self._kill_container(handle)
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
            # Terminating the entire container makes that terminal path closed.
            self._kill_container(handle)
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
        if request.namespace != "capsule_effects" or request.tool not in ALLOWED_DYNAMIC_TOOLS:
            return self.refusal(request, "tool is outside the explicit capsule_effects grammar")
        try:
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
        return self._result(request, capture)

    def _copy_tree_without_following(self, source: Path, destination: Path) -> None:
        temporary = destination.parent / f".{destination.name}.tmp-{uuid.uuid4().hex}"
        temporary.mkdir(mode=0o700)
        file_count = 0
        tree_bytes = 0

        def copy_directory(source_directory: Path, destination_directory: Path) -> None:
            nonlocal file_count, tree_bytes
            for entry in sorted(os.scandir(source_directory), key=lambda item: item.name):
                source_entry = Path(entry.path)
                destination_entry = destination_directory / entry.name
                info = entry.stat(follow_symlinks=False)
                kind = mode_type(info.st_mode)
                if kind == "directory":
                    destination_entry.mkdir(mode=0o700)
                    copy_directory(source_entry, destination_entry)
                    fsync_directory(destination_entry)
                elif kind == "regular":
                    file_count += 1
                    tree_bytes += info.st_size
                    if file_count > self.limits.file_count_limit or tree_bytes > self.limits.tree_bytes_limit:
                        raise ValueError("provider output tree exceeds its bound")
                    source_fd = os.open(source_entry, os.O_RDONLY | os.O_NOFOLLOW)
                    destination_fd = os.open(
                        destination_entry,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                    try:
                        while True:
                            block = os.read(source_fd, 64 * 1024)
                            if not block:
                                break
                            os.write(destination_fd, block)
                        os.fsync(destination_fd)
                    finally:
                        os.close(source_fd)
                        os.close(destination_fd)
                elif kind == "symlink":
                    os.symlink(os.readlink(source_entry), destination_entry)
                else:
                    raise ValueError(f"provider output contains unsupported entry: {kind}")

        try:
            copy_directory(source, temporary)
            fsync_directory(temporary)
            os.replace(temporary, destination)
            fsync_directory(destination.parent)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    def freeze_output(self, handle: DockerWorkspaceHandle) -> ByteTreeObservation:
        if handle.frozen_path.exists():
            raise ValueError("frozen provider output already exists")
        # Stop init and all descendants before observing host-backed bytes.
        # A completed app-server turn is not proof that it left no background
        # process mutating the workspace.
        self._kill_container(handle)
        if handle.container_alive:
            raise RuntimeError("capsule process tree was not quiesced before output freeze")
        self._copy_tree_without_following(handle.source_path, handle.frozen_path)
        return self.observe_frozen_output(handle)

    def observe_frozen_output(self, handle: DockerWorkspaceHandle) -> ByteTreeObservation:
        entries: list[ObservedEntry] = []
        for root, directories, files in os.walk(handle.frozen_path, followlinks=False):
            directories.sort()
            files.sort()
            root_path = Path(root)
            for name in [*directories, *files]:
                path = root_path / name
                relative = path.relative_to(handle.frozen_path).as_posix()
                info = path.lstat()
                kind = mode_type(info.st_mode)
                digest = None
                if kind == "regular":
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        chunks: list[bytes] = []
                        while True:
                            block = os.read(descriptor, 64 * 1024)
                            if not block:
                                break
                            chunks.append(block)
                        digest = sha256_bytes(b"".join(chunks))
                    finally:
                        os.close(descriptor)
                entries.append(
                    ObservedEntry(
                        relative_path=relative,
                        kind=kind,
                        size=info.st_size if kind == "regular" else 0,
                        sha256=digest,
                    ).validated()
                )
        return ByteTreeObservation.create(entries=tuple(entries))

    def cleanup(self, handle: DockerWorkspaceHandle) -> ControllerCleanupEvidence:
        removal = self._capture(
            (self.docker_executable, "rm", "--force", handle.container_id),
            timeout=10,
            output_limit=4096,
        )
        handle.container_alive = False
        inspect = self._capture(
            (self.docker_executable, "inspect", handle.container_id),
            timeout=5,
            output_limit=1024,
        )
        container_removed = (
            not removal.timed_out
            and removal.exit_code == 0
            and inspect.exit_code != 0
        )
        shutil.rmtree(handle.source_path, ignore_errors=True)
        workspace_removed = not handle.source_path.exists()
        return ControllerCleanupEvidence(
            container_removed=container_removed,
            complete_process_tree_reaped=container_removed,
            disposable_workspace_removed=workspace_removed,
            frozen_output_retained=handle.frozen_path.is_dir(),
        )

    def frozen_output_path(self, workspace_id: str) -> Path:
        """Output-intake authority path; never passed to the control process."""

        handle = self.get(workspace_id)
        if not handle.frozen_path.is_dir():
            raise ValueError("provider output is not frozen")
        return handle.frozen_path
