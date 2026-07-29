"""Concrete host-Codex-control / Docker-capsule-effect backend.

The authenticated app-server is only a control process.  It never sees the
provider workspace and it owns no file, shell, intake, verification, Git, or
finalization authority.  Every accepted effect request crosses the pinned
Codex 0.145.0 ``item/tool/call`` dynamic-tools boundary, is durably paired by
the controller, and executes inside the sealed capsule.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import socket
import stat
import subprocess
import time
import uuid
import inspect
from abc import ABC, abstractmethod
from collections import deque
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.backend import CapsuleAuthority, CapsuleBackend
from admissible.capsule.common import (
    CrashInjected,
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    sha256_bytes,
    strict_json_loads,
)
from admissible.capsule.codex_protocol import (
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    protocol_schema_identity,
    validate_schema,
)
from admissible.capsule.docker_controller import (
    ALLOWED_DYNAMIC_TOOLS,
    ControllerCleanupEvidence,
    DockerCapsuleController,
    DockerWorkspaceHandle,
)
from admissible.capsule.capsule_broker import CapsuleBrokerClient
from admissible.capsule.boundary_authority import OSBoundaryAuthority
from admissible.capsule.boundary_launcher import provider_free_os_boundary_authority
from admissible.capsule.broker_transport import receive_packet
from admissible.capsule.host_control import (
    AuthenticatedControlAuthority,
    CONTROL_CODEX_HOME,
    CONTROL_EMPTY_CWD,
    HostControlBwrapPolicy,
)
from admissible.capsule.execution_authority import (
    BackendExecutionAuthority,
    HOST_CODEX_BACKEND_KIND,
    source_component_identity,
    synthetic_component_identity,
    validate_component_identity_metadata,
)
from admissible.capsule.finalizer import (
    DurabilityReceipt,
    FinalizationEvidence,
    FinalizationResult,
)
from admissible.capsule.intake import AcceptedMaterialIdentity
from admissible.capsule.model_authority import (
    CodexModelAuthority,
    ModelConfigurationError,
    canary_model_binding_policy,
    canary_model_authority,
    validate_effective_thread_configuration,
)
from admissible.capsule.models import (
    ByteTreeObservation,
    CleanupResult,
    ProcessResult,
    ProviderCompletionClaim,
    ProviderOutput,
    ExecutionTruth,
    TransportResult,
    WorkspaceReference,
)
from admissible.capsule.session_store import (
    DurableCapsuleSessionStore,
    DurableToolRequest,
    DurableToolResult,
    SessionTerminalClassification,
    ToolIdDisposition,
    ToolTerminalClassification,
)
from admissible.capsule.verification import BehaviorResult, CheckpointResult


DYNAMIC_TOOL_NAMESPACE = "capsule_effects"
APP_SERVER_MESSAGE_LIMIT = 256 * 1024
AGENT_TEXT_LIMIT = 32 * 1024

PASSIVE_ITEM_TYPES = {
    "userMessage",
    "agentMessage",
    "plan",
    "reasoning",
    "dynamicToolCall",
}
class AppServerProtocolError(RuntimeError):
    pass


class AppServerReceiveTimeout(TimeoutError):
    pass


class AppServerConnection(ABC):
    """Minimal bidirectional app-server connection used by the backend."""

    @property
    @abstractmethod
    def process_identity(self) -> Mapping[str, Any]:
        pass

    @property
    @abstractmethod
    def returncode(self) -> int | None:
        pass

    @property
    def forced_close(self) -> bool:
        return False

    @property
    def eof_observed(self) -> bool:
        return False

    @abstractmethod
    def send(self, message: Mapping[str, Any]) -> None:
        pass

    @abstractmethod
    def receive(self, timeout: float) -> Mapping[str, Any] | None:
        """Return one message, or None for EOF."""

    @abstractmethod
    def begin_protocol_close(self) -> None:
        """Close the request side so bounded terminal draining can prove EOF."""

    @abstractmethod
    def close(self) -> None:
        pass


class AppServerConnectionFactory(ABC):
    @property
    @abstractmethod
    def connection_mode(self) -> str:
        pass

    @property
    @abstractmethod
    def component_identity(self) -> Mapping[str, Any]:
        pass

    @property
    @abstractmethod
    def codex_component_identity(self) -> Mapping[str, Any]:
        pass

    @property
    @abstractmethod
    def bwrap_component_identity(self) -> Mapping[str, Any]:
        pass

    @property
    @abstractmethod
    def host_policy_fingerprint(self) -> str:
        pass

    @property
    @abstractmethod
    def bwrap_argv_policy_fingerprint(self) -> str:
        pass

    @property
    @abstractmethod
    def authentication_boundary_state(self) -> str:
        pass

    @abstractmethod
    def attest_launch(self) -> None:
        pass

    @abstractmethod
    def open(self, session_id: str) -> AppServerConnection:
        pass


class BwrapCodexAppServerConnection(AppServerConnection):
    """Production stdio connection launched under the minimal bwrap view."""

    def __init__(
        self,
        *,
        policy: HostControlBwrapPolicy,
        authority: AuthenticatedControlAuthority,
    ):
        self._authority = authority.validated()
        self._policy = policy.validated()
        if (
            dict(self._authority.executable_identity)
            != self._policy.codex_identity.to_dict()
            or self._authority.policy_fingerprint != self._policy.policy_fingerprint
            or self._authority.authentication_boundary_state
            != self._policy.authentication_boundary.state
        ):
            raise ValueError("host-control authority differs from actual bwrap policy")
        with policy.descriptor_argv() as launch:
            self._process = subprocess.Popen(
                launch.argv,
                executable=launch.executable,
                pass_fds=launch.pass_fds,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                cwd="/",
                start_new_session=True,
                close_fds=True,
                bufsize=0,
            )
        if self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("failed to open app-server stdio")
        os.set_blocking(self._process.stdout.fileno(), False)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._process.stdout, selectors.EVENT_READ)
        self._receive_buffer = bytearray()
        self._forced_close = False
        self._eof_observed = False

    @property
    def process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "bwrap_codex_app_server",
            "pid": self._process.pid,
            "codex_protocol_version": self._authority.codex_protocol_version,
            "control_authority_fingerprint": self._authority.authority_fingerprint,
            "policy_fingerprint": self._policy.policy_fingerprint,
            "codex_executable_identity": self._policy.codex_identity.to_dict(),
            "bwrap_executable_identity": self._policy.bwrap_identity.to_dict(),
            "authentication_boundary_state": self._policy.authentication_boundary.state,
        }

    @property
    def returncode(self) -> int | None:
        return self._process.poll()

    @property
    def forced_close(self) -> bool:
        return self._forced_close

    @property
    def eof_observed(self) -> bool:
        return self._eof_observed

    def send(self, message: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(message) + b"\n"
        if len(encoded) > APP_SERVER_MESSAGE_LIMIT:
            raise AppServerProtocolError("outbound app-server message exceeds its bound")
        if self._process.stdin is None:
            raise AppServerProtocolError("app-server stdin is closed")
        self._process.stdin.write(encoded)
        self._process.stdin.flush()

    def receive(self, timeout: float) -> Mapping[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            newline = self._receive_buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._receive_buffer[:newline])
                del self._receive_buffer[: newline + 1]
                if not raw:
                    raise AppServerProtocolError("app-server emitted an empty JSONL record")
                try:
                    value = strict_json_loads(raw, label="app-server JSON")
                except ValueError as error:
                    raise AppServerProtocolError("app-server emitted invalid JSON") from error
                if not isinstance(value, dict):
                    raise AppServerProtocolError("app-server record is not an object")
                return value
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AppServerReceiveTimeout("app-server receive timed out")
            events = self._selector.select(remaining)
            if not events:
                raise AppServerReceiveTimeout("app-server receive timed out")
            chunk = os.read(self._process.stdout.fileno(), 64 * 1024)
            if not chunk:
                if self._receive_buffer:
                    raise AppServerProtocolError("app-server ended with a partial JSONL record")
                self._eof_observed = True
                return None
            self._receive_buffer.extend(chunk)
            if len(self._receive_buffer) > APP_SERVER_MESSAGE_LIMIT:
                raise AppServerProtocolError("inbound app-server message exceeds its bound")

    def begin_protocol_close(self) -> None:
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()

    def close(self) -> None:
        self.begin_protocol_close()
        try:
            self._process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._forced_close = True
            os.killpg(self._process.pid, signal.SIGKILL)
            self._process.wait(timeout=3)
        self._selector.close()


class BwrapCodexConnectionFactory(AppServerConnectionFactory):
    def __init__(
        self,
        *,
        policy: HostControlBwrapPolicy,
        authority: AuthenticatedControlAuthority,
    ):
        self.policy = policy
        self.authority = authority

    @property
    def connection_mode(self) -> str:
        return "production_bwrap"

    @property
    def component_identity(self) -> Mapping[str, Any]:
        source = inspect.getsource(type(self)).encode("utf-8")
        return source_component_identity(
            component="bwrap_connection_factory_code",
            source_bytes=source,
            provider_request_capable=True,
        )

    @property
    def codex_component_identity(self) -> Mapping[str, Any]:
        return self.policy.codex_identity.to_dict()

    @property
    def bwrap_component_identity(self) -> Mapping[str, Any]:
        return self.policy.bwrap_identity.to_dict()

    @property
    def host_policy_fingerprint(self) -> str:
        return self.policy.policy_fingerprint

    @property
    def bwrap_argv_policy_fingerprint(self) -> str:
        return self.policy.argv_policy_fingerprint

    @property
    def authentication_boundary_state(self) -> str:
        return self.policy.authentication_boundary.state

    def attest_launch(self) -> None:
        self.policy.attest_launch()
        if (
            dict(self.authority.executable_identity)
            != self.policy.codex_identity.to_dict()
            or self.authority.policy_fingerprint != self.policy.policy_fingerprint
            or self.authority.authentication_boundary_state
            != self.policy.authentication_boundary.state
        ):
            raise ValueError("connection factory/control authority substitution refused")

    def open(self, session_id: str) -> AppServerConnection:
        require_identifier(session_id, "app-server session_id")
        self.attest_launch()
        return BwrapCodexAppServerConnection(policy=self.policy, authority=self.authority)


CODEX_TERMINAL_STATUS_SCHEMA_VERSION = "admissible_codex_process_terminal_status_v1"


class BoundaryCodexAppServerConnection(AppServerConnection):
    """Controller side of a Codex process prelaunched by the boundary TCB."""

    def __init__(
        self,
        *,
        session_id: str,
        app_server_descriptor: int,
        terminal_status_descriptor: int,
        os_boundary_authority_fingerprint: str,
        control_authority_fingerprint: str,
    ):
        self._session_id = require_identifier(session_id, "boundary Codex session")
        self._boundary_fingerprint = require_sha256(
            os_boundary_authority_fingerprint,
            "boundary Codex OS authority",
        )
        self._control_authority_fingerprint = require_sha256(
            control_authority_fingerprint,
            "boundary Codex control authority",
        )
        self._socket = socket.socket(fileno=os.dup(app_server_descriptor))
        if self._socket.family != socket.AF_UNIX:
            self._socket.close()
            raise ValueError("boundary app-server channel is not an inherited Unix socket")
        self._socket.setblocking(False)
        self._status = socket.socket(fileno=os.dup(terminal_status_descriptor))
        if self._status.family != socket.AF_UNIX:
            self._socket.close()
            self._status.close()
            raise ValueError("Codex terminal-status channel is not an inherited Unix socket")
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ)
        self._receive_buffer = bytearray()
        self._returncode: int | None = None
        self._forced = False
        self._eof = False
        self._closed = False

    @property
    def process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "os_boundary_prelaunched_codex_app_server",
            "codex_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "control_authority_fingerprint": self._control_authority_fingerprint,
            "os_boundary_authority_fingerprint": self._boundary_fingerprint,
            "authentication_visible_to_controller": False,
            "provider_request_capable": True,
        }

    @property
    def returncode(self) -> int | None:
        return self._returncode

    @property
    def forced_close(self) -> bool:
        return self._forced

    @property
    def eof_observed(self) -> bool:
        return self._eof

    def send(self, message: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(message) + b"\n"
        if len(encoded) > APP_SERVER_MESSAGE_LIMIT:
            raise AppServerProtocolError("outbound app-server message exceeds its bound")
        self._socket.setblocking(True)
        try:
            self._socket.sendall(encoded)
        finally:
            self._socket.setblocking(False)

    def receive(self, timeout: float) -> Mapping[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            newline = self._receive_buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._receive_buffer[:newline])
                del self._receive_buffer[: newline + 1]
                if not raw:
                    raise AppServerProtocolError(
                        "boundary app-server emitted an empty record"
                    )
                value = strict_json_loads(raw, label="boundary app-server JSON")
                if not isinstance(value, dict):
                    raise AppServerProtocolError(
                        "boundary app-server record is not an object"
                    )
                return value
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AppServerReceiveTimeout("boundary app-server receive timed out")
            events = self._selector.select(remaining)
            if not events:
                raise AppServerReceiveTimeout("boundary app-server receive timed out")
            try:
                chunk = self._socket.recv(64 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                if self._receive_buffer:
                    raise AppServerProtocolError(
                        "boundary app-server ended with a partial record"
                    )
                self._eof = True
                return None
            self._receive_buffer.extend(chunk)
            if len(self._receive_buffer) > APP_SERVER_MESSAGE_LIMIT:
                raise AppServerProtocolError(
                    "boundary app-server message exceeds its bound"
                )

    def begin_protocol_close(self) -> None:
        try:
            self._socket.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _receive_terminal_status(self) -> None:
        self._status.settimeout(3)
        try:
            value, descriptors = receive_packet(self._status)
        except (EOFError, OSError, ValueError):
            return
        if descriptors:
            for descriptor in descriptors:
                os.close(descriptor)
            raise AppServerProtocolError(
                "Codex terminal status carried an unauthorized descriptor"
            )
        require_exact_keys(
            value,
            {
                "schema_version",
                "session_id",
                "os_boundary_authority_fingerprint",
                "exit_code",
                "exit_normal",
                "forced",
                "process_terminal_fingerprint",
            },
            "Codex terminal process status",
        )
        body = {
            key: value[key]
            for key in value
            if key != "process_terminal_fingerprint"
        }
        if (
            value["schema_version"] != CODEX_TERMINAL_STATUS_SCHEMA_VERSION
            or value["session_id"] != self._session_id
            or value["os_boundary_authority_fingerprint"]
            != self._boundary_fingerprint
            or fingerprint(body) != value["process_terminal_fingerprint"]
            or not isinstance(value["exit_normal"], bool)
            or not isinstance(value["forced"], bool)
        ):
            raise AppServerProtocolError("Codex terminal process status differs")
        exit_code = value["exit_code"]
        if isinstance(exit_code, bool) or (
            exit_code is not None and not isinstance(exit_code, int)
        ):
            raise AppServerProtocolError("Codex terminal exit code is invalid")
        self._returncode = exit_code
        self._forced = value["forced"]

    def close(self) -> None:
        if self._closed:
            return
        self.begin_protocol_close()
        self._receive_terminal_status()
        self._selector.close()
        self._socket.close()
        self._status.close()
        self._closed = True


class BoundaryCodexConnectionFactory(AppServerConnectionFactory):
    """No auth/Docker authority: only inherited app-server/status channels."""

    def __init__(
        self,
        *,
        app_server_descriptor: int,
        terminal_status_descriptor: int,
        control_authority: AuthenticatedControlAuthority,
        os_boundary_authority: OSBoundaryAuthority,
        codex_component_identity: Mapping[str, Any],
        bwrap_component_identity: Mapping[str, Any],
    ):
        self.app_server_descriptor = app_server_descriptor
        self.terminal_status_descriptor = terminal_status_descriptor
        self.control_authority = control_authority.validated()
        self.os_boundary_authority = os_boundary_authority.validated()
        self._codex_identity = dict(codex_component_identity)
        self._bwrap_identity = dict(bwrap_component_identity)
        self._opened = False
        self._component_identity = source_component_identity(
            component="os_boundary_connection_factory",
            source_bytes=inspect.getsource(type(self)).encode("utf-8"),
            provider_request_capable=True,
        )

    @property
    def connection_mode(self) -> str:
        return "production_os_boundary"

    @property
    def component_identity(self) -> Mapping[str, Any]:
        return self._component_identity

    @property
    def codex_component_identity(self) -> Mapping[str, Any]:
        return self._codex_identity

    @property
    def bwrap_component_identity(self) -> Mapping[str, Any]:
        return self._bwrap_identity

    @property
    def host_policy_fingerprint(self) -> str:
        return self.os_boundary_authority.authority_fingerprint

    @property
    def bwrap_argv_policy_fingerprint(self) -> str:
        return self.os_boundary_authority.launch_fingerprint

    @property
    def authentication_boundary_state(self) -> str:
        return "OS_ENFORCED"

    def attest_launch(self) -> None:
        if self._opened:
            raise ValueError("boundary Codex connection is single-use")
        for descriptor in (
            self.app_server_descriptor,
            self.terminal_status_descriptor,
        ):
            info = os.fstat(descriptor)
            if not stat.S_ISSOCK(info.st_mode):
                raise ValueError("boundary Codex channel descriptor changed")
        self.os_boundary_authority.validated()

    def open(self, session_id: str) -> AppServerConnection:
        self.attest_launch()
        self._opened = True
        return BoundaryCodexAppServerConnection(
            session_id=session_id,
            app_server_descriptor=self.app_server_descriptor,
            terminal_status_descriptor=self.terminal_status_descriptor,
            os_boundary_authority_fingerprint=(
                self.os_boundary_authority.authority_fingerprint
            ),
            control_authority_fingerprint=(
                self.control_authority.authority_fingerprint
            ),
        )


class ScriptedCodexAppServerConnection(AppServerConnection):
    """Provider-free Codex 0.145.0 event source used by witness tests."""

    def __init__(
        self,
        messages: Sequence[Mapping[str, Any] | bytes | str | BaseException],
        *,
        returncode: int = 0,
        identity: str = "synthetic-codex-app-server-0.145.0",
        force_on_close: bool = False,
    ):
        self._messages = deque(messages)
        self._configured_returncode = returncode
        self._force_on_close = force_on_close
        self._closed = False
        self._forced_close = False
        self._eof_observed = False
        self.sent: list[dict[str, Any]] = []
        self._identity = identity

    @property
    def process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "synthetic_app_server",
            "fixture_identity": fingerprint(
                {
                    "class_source_sha256": sha256_bytes(
                        inspect.getsource(type(self)).encode("utf-8")
                    ),
                    "configured_returncode": self._configured_returncode,
                    "force_on_close": self._force_on_close,
                }
            ),
            "codex_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "provider_request_capable": False,
        }

    @property
    def returncode(self) -> int | None:
        if not self._closed and self._messages:
            return None
        return self._configured_returncode

    @property
    def eof_observed(self) -> bool:
        return self._eof_observed

    @property
    def forced_close(self) -> bool:
        return self._forced_close

    def send(self, message: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(message)
        if len(encoded) > APP_SERVER_MESSAGE_LIMIT:
            raise AppServerProtocolError("synthetic outbound message exceeds its bound")
        self.sent.append(json.loads(encoded))

    def queue_messages(
        self,
        messages: Sequence[Mapping[str, Any] | bytes | str | BaseException],
    ) -> None:
        if self._closed:
            raise ValueError("synthetic app-server connection is closed")
        self._messages.extend(messages)

    def receive(self, timeout: float) -> Mapping[str, Any] | None:
        if not self._messages:
            self._eof_observed = True
            return None
        message = self._messages.popleft()
        if isinstance(message, BaseException):
            raise message
        encoded = (
            message.encode("utf-8")
            if isinstance(message, str)
            else message
            if isinstance(message, bytes)
            else canonical_bytes(message)
        )
        if len(encoded) > APP_SERVER_MESSAGE_LIMIT:
            raise AppServerProtocolError("synthetic inbound message exceeds its bound")
        try:
            decoded = strict_json_loads(encoded, label="synthetic app-server JSON")
        except ValueError as error:
            raise AppServerProtocolError(str(error)) from error
        if not isinstance(decoded, dict):
            raise AppServerProtocolError("synthetic app-server record is not an object")
        return decoded

    def begin_protocol_close(self) -> None:
        # Scripted records already represent the complete provider-free stream.
        return None

    def close(self) -> None:
        self._forced_close = self._force_on_close
        self._closed = True


class ScriptedCodexConnectionFactory(AppServerConnectionFactory):
    """Single-use factory that exposes the connection for response assertions."""

    def __init__(
        self,
        connection: ScriptedCodexAppServerConnection,
        *,
        codex_component_identity: Mapping[str, Any] | None = None,
    ):
        self.connection = connection
        self.open_count = 0
        source = inspect.getsource(type(self)).encode("utf-8")
        self._component_identity = synthetic_component_identity(
            component="scripted_connection_factory",
            fixture_material={"source_sha256": sha256_bytes(source)},
        )
        self._codex_identity = (
            validate_component_identity_metadata(
                codex_component_identity,
                "scripted factory externally witnessed Codex",
            )
            if codex_component_identity is not None
            else synthetic_component_identity(
                component="scripted_codex_app_server",
                fixture_material={
                    "source_sha256": sha256_bytes(
                        inspect.getsource(
                            ScriptedCodexAppServerConnection
                        ).encode("utf-8")
                    ),
                    "protocol": CODEX_APP_SERVER_PROTOCOL_VERSION,
                },
            )
        )
        self._bwrap_identity = synthetic_component_identity(
            component="synthetic_no_bwrap",
            fixture_material={"used": False},
        )

    @property
    def connection_mode(self) -> str:
        return "synthetic_provider_free"

    @property
    def component_identity(self) -> Mapping[str, Any]:
        return self._component_identity

    @property
    def codex_component_identity(self) -> Mapping[str, Any]:
        return self._codex_identity

    @property
    def bwrap_component_identity(self) -> Mapping[str, Any]:
        return self._bwrap_identity

    @property
    def host_policy_fingerprint(self) -> str:
        return fingerprint(
            {
                "kind": "synthetic_provider_free_control",
                "workspace_visible": False,
                "network": "none",
                "native_capabilities": [],
            }
        )

    @property
    def bwrap_argv_policy_fingerprint(self) -> str:
        return fingerprint({"kind": "synthetic_no_bwrap_argv", "argv": []})

    @property
    def authentication_boundary_state(self) -> str:
        return "SYNTHETIC_PROVIDER_FREE"

    def attest_launch(self) -> None:
        if self.connection.process_identity.get("provider_request_capable") is not False:
            raise ValueError("synthetic connection became provider-capable")

    def open(self, session_id: str) -> AppServerConnection:
        if self.open_count:
            raise ValueError("scripted app-server connection is single-use")
        self.open_count += 1
        self.attest_launch()
        return self.connection


def dynamic_tools_grammar() -> list[dict[str, Any]]:
    """Exact experimental ``thread/start.dynamicTools`` grammar."""

    relative_path = {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "description": "Relative path inside the sealed capsule workspace; absolute and .. paths are refused.",
    }
    return [
        {
            "type": "namespace",
            "name": DYNAMIC_TOOL_NAMESPACE,
            "description": "Bounded file and command effects executed only inside the sealed capsule.",
            "tools": [
                {
                    "type": "function",
                    "name": "list_files",
                    "description": "List bounded entries below a relative capsule workspace directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": relative_path,
                            "max_depth": {"type": "integer", "minimum": 1, "maximum": 8},
                        },
                        "required": ["path", "max_depth"],
                        "additionalProperties": False,
                    },
                },
                {
                    "type": "function",
                    "name": "read_file",
                    "description": "Read one bounded regular file inside the capsule workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": relative_path},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                },
                {
                    "type": "function",
                    "name": "write_file",
                    "description": "Create, replace, or upsert one authorized UTF-8 workspace file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": relative_path,
                            "content": {"type": "string", "maxLength": 262144},
                            "operation": {
                                "type": "string",
                                "enum": ["create", "replace", "upsert"],
                            },
                        },
                        "required": ["path", "content", "operation"],
                        "additionalProperties": False,
                    },
                },
                {
                    "type": "function",
                    "name": "run_command",
                    "description": "Execute one bounded argv command with a relative cwd inside the capsule.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "argv": {
                                "type": "array",
                                "items": {"type": "string", "minLength": 1, "maxLength": 4096},
                                "minItems": 1,
                                "maxItems": 32,
                            },
                            "cwd": relative_path,
                            "timeout_ms": {"type": "integer", "minimum": 50, "maximum": 10000},
                        },
                        "required": ["argv", "cwd", "timeout_ms"],
                        "additionalProperties": False,
                    },
                },
            ],
        }
    ]


def initialize_request(request_id: str) -> dict[str, Any]:
    request = {
        "method": "initialize",
        "id": request_id,
        "params": {
            "clientInfo": {
                "name": "admissible_host_capsule",
                "title": "Admissible Host Capsule Controller",
                "version": "1.0.0",
            },
            "capabilities": {"experimentalApi": True},
        },
    }
    validate_schema(
        "v1/InitializeParams.json",
        request["params"],
        label="initialize request",
    )
    return request


def preventive_control_config() -> dict[str, Any]:
    """Synthetic thread overlay omitting every non-dynamic native capability."""

    return {
        "analytics": {"enabled": False},
        "hooks": {},
        "mcp_servers": {},
        "project_doc_max_bytes": 0,
        "features": {
            "apps": False,
            "memories": False,
            "plugins": False,
            "shell_snapshot": False,
            "skills": False,
            "web_search": False,
        },
    }


def thread_start_request(
    request_id: str,
    *,
    model_authority: CodexModelAuthority,
) -> dict[str, Any]:
    """Bind the exact model and reasoning effort onto ``thread/start``.

    The model arrives as the schema-typed ``model`` request field with
    ``allowProviderModelFallback`` explicitly false.  ``ThreadStartParams``
    declares no reasoning-effort property in pinned 0.145.0, so the effort
    arrives through the ``config`` overlay; both are then reported back on
    ``ThreadStartResponse`` and validated before any effect can run.
    """

    model_fields = model_authority.validated().thread_start_fields
    overlay = {**preventive_control_config(), **model_fields.pop("config")}
    request = {
        "method": "thread/start",
        "id": request_id,
        "params": {
            "cwd": str(CONTROL_EMPTY_CWD),
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "ephemeral": True,
            **model_fields,
            "config": overlay,
            "environments": [],
            "runtimeWorkspaceRoots": [],
            "selectedCapabilityRoots": [],
            "developerInstructions": (
                "Use only capsule_effects dynamic tools for file or command effects. "
                "Native command, file, shell, MCP, web, image, or host effects are forbidden."
            ),
            "dynamicTools": dynamic_tools_grammar(),
        },
    }
    validate_schema(
        "v2/ThreadStartParams.json",
        request["params"],
        label="thread/start request",
    )
    validate_bound_thread_start_request(request["params"], model_authority)
    return request


def turn_start_request(
    request_id: str,
    *,
    thread_id: str,
    prompt: str,
    model_authority: CodexModelAuthority,
) -> dict[str, Any]:
    require_identifier(thread_id, "turn-start thread_id")
    require_nonempty_text(prompt, "capsule mission prompt", max_bytes=64 * 1024)
    request = {
        "method": "turn/start",
        "id": request_id,
        "params": {
            "threadId": thread_id,
            **model_authority.validated().turn_start_fields,
            "input": [{"type": "text", "text": prompt}],
        },
    }
    validate_schema(
        "v2/TurnStartParams.json",
        request["params"],
        label="turn/start request",
    )
    validate_bound_turn_start_request(request["params"], model_authority)
    return request


def validate_bound_thread_start_request(
    params: Mapping[str, Any],
    model_authority: CodexModelAuthority,
) -> None:
    """Strictly validate the exact model/effort fields actually serialized."""

    expected = model_authority.thread_start_fields
    overlay = expected.pop("config")
    if params.get("model") != expected["model"]:
        raise ModelConfigurationError(
            "thread/start request does not carry the bound model"
        )
    if params.get("allowProviderModelFallback") is not False:
        raise ModelConfigurationError(
            "thread/start request does not refuse provider model fallback"
        )
    config = params.get("config")
    if not isinstance(config, Mapping):
        raise ModelConfigurationError("thread/start request has no configuration overlay")
    for key, value in overlay.items():
        if config.get(key) != value:
            raise ModelConfigurationError(
                f"thread/start configuration overlay does not bind {key}"
            )


def validate_bound_turn_start_request(
    params: Mapping[str, Any],
    model_authority: CodexModelAuthority,
) -> None:
    expected = model_authority.turn_start_fields
    if params.get("model") != expected["model"]:
        raise ModelConfigurationError("turn/start request does not carry the bound model")
    if params.get("effort") != expected["effort"]:
        raise ModelConfigurationError(
            "turn/start request does not carry the bound reasoning effort"
        )


def protocol_request_policy_fingerprint(
    model_authority: CodexModelAuthority,
) -> str:
    """Bind every caller-controlled protocol policy byte except session data."""

    return fingerprint(
        {
            "initialize_params": initialize_request("policy-request")["params"],
            "initialized_notification": {"method": "initialized", "params": {}},
            "thread_start_params": thread_start_request(
                "policy-request", model_authority=model_authority
            )["params"],
            "turn_start_shape": {
                "method": "turn/start",
                "params": {
                    "threadId": "<bound-thread-id>",
                    **model_authority.turn_start_fields,
                    "input": [{"type": "text", "text": "<bound-prompt-bytes>"}],
                },
            },
            "model_authority_fingerprint": model_authority.authority_fingerprint,
        }
    )


class HostCodexAppServerCapsuleBackend(CapsuleBackend):
    """Concrete implementation of the generic capsule backend contract."""

    def __init__(
        self,
        *,
        authority: CapsuleAuthority,
        control_authority: AuthenticatedControlAuthority,
        controller: DockerCapsuleController | CapsuleBrokerClient,
        session_store: DurableCapsuleSessionStore,
        connection_factory: AppServerConnectionFactory,
        mission_prompt: str,
        mission_bytes: bytes | None = None,
        os_boundary_authority: OSBoundaryAuthority | None = None,
        event_timeout_seconds: float = 10.0,
        protocol_drain_timeout_seconds: float = 3.0,
        protocol_drain_record_limit: int = 64,
    ):
        self._authority = authority.validated()
        self.control_authority = control_authority.validated()
        self.controller = controller
        self.session_store = session_store
        self.connection_factory = connection_factory
        if (
            self.connection_factory.connection_mode
            in {"production_bwrap", "production_os_boundary"}
            and not isinstance(self.controller, CapsuleBrokerClient)
        ):
            raise ValueError(
                "production controller must use the closed capsule broker"
            )
        prompt = require_nonempty_text(
            mission_prompt, "capsule mission prompt", max_bytes=64 * 1024
        )
        self._prompt_bytes = prompt.encode("utf-8")
        self._mission_bytes = (
            bytes(mission_bytes) if mission_bytes is not None else self._prompt_bytes
        )
        if not self._mission_bytes or len(self._mission_bytes) > 64 * 1024:
            raise ValueError("capsule mission bytes are empty or exceed their bound")
        if sha256_bytes(self._mission_bytes) != self._authority.mission_fingerprint:
            raise ValueError("mission bytes differ from the generic capsule authority")
        self.mission_prompt = prompt
        if not 0.05 <= event_timeout_seconds <= 300:
            raise ValueError("app-server event timeout is out of bounds")
        if not 0.05 <= protocol_drain_timeout_seconds <= 30:
            raise ValueError("protocol drain timeout is out of bounds")
        if not 1 <= protocol_drain_record_limit <= 1024:
            raise ValueError("protocol drain record limit is out of bounds")
        if self._authority.backend_kind != HOST_CODEX_BACKEND_KIND:
            raise ValueError("concrete backend refuses arbitrary backend kinds")
        if (
            self._authority.capsule_image_identity
            != self.controller.execution_authority.image_identity
        ):
            raise ValueError("capsule authority/controller image substitution refused")
        if (
            self.control_authority.codex_protocol_version
            != CODEX_APP_SERVER_PROTOCOL_VERSION
            or dict(self.control_authority.executable_identity)
            != dict(self.connection_factory.codex_component_identity)
            or self.control_authority.policy_fingerprint
            != self.connection_factory.host_policy_fingerprint
            or self.control_authority.authentication_boundary_state
            != self.connection_factory.authentication_boundary_state
        ):
            raise ValueError("control authority/connection factory substitution refused")
        if self.session_store.trusted_witness_store is None:
            raise ValueError(
                "backend requires an externally anchored witness store"
            )
        self.model_binding_policy = canary_model_binding_policy(
            codex_executable_identity=(
                self.connection_factory.codex_component_identity
            )
        )
        self.verified_witness_receipt = (
            self.session_store.trusted_witness_store.load_current_verified_receipt(
                expected_policy=self.model_binding_policy,
                expected_executable_identity=(
                    self.connection_factory.codex_component_identity
                ),
            )
        )
        self.model_authority = canary_model_authority(
            model_binding_policy=self.model_binding_policy,
            verified_witness_receipt=self.verified_witness_receipt,
            trusted_witness_store=self.session_store.trusted_witness_store,
        )
        if dict(self.model_authority.codex_executable_identity) != dict(
            self.connection_factory.codex_component_identity
        ):
            raise ValueError("model authority binds another Codex executable")
        # Set only after the app server reports the effective model
        # configuration; no capsule effect may run before that.
        self._effective_model_binding: Mapping[str, Any] | None = None
        self.event_timeout_seconds = event_timeout_seconds
        self.protocol_drain_timeout_seconds = protocol_drain_timeout_seconds
        self.protocol_drain_record_limit = protocol_drain_record_limit
        self._workspace_sessions: dict[str, str] = {}
        self._execution_authorities: dict[str, BackendExecutionAuthority] = {}
        if (
            self.connection_factory.connection_mode
            in {"production_bwrap", "production_os_boundary"}
            and os_boundary_authority is None
        ):
            raise ValueError("production backend requires explicit OS boundary authority")
        self.os_boundary_authority = (
            os_boundary_authority.validated()
            if os_boundary_authority is not None
            else provider_free_os_boundary_authority(
                dependent_identities=(
                    self.connection_factory.codex_component_identity,
                    self.connection_factory.bwrap_component_identity,
                    self._docker_component_identity(),
                    self.connection_factory.component_identity,
                ),
                dependent_authorities={
                    "capsule_image_content_id": (
                        self.controller.execution_authority.image_identity
                    ),
                    "capsule_execution_authority_fingerprint": (
                        self.controller.execution_authority.authority_fingerprint
                    ),
                    "capsule_broker_runtime_authority_fingerprint": (
                        self.controller.controller_authority.controller_fingerprint
                    ),
                    "codex_protocol_schema_identity": protocol_schema_identity(),
                    "dynamic_tools_schema_identity": fingerprint(
                        dynamic_tools_grammar()
                    ),
                    "model_binding_policy_fingerprint": (
                        self.model_binding_policy.policy_fingerprint
                    ),
                    "verified_serialization_witness_receipt_identity": (
                        self.verified_witness_receipt.receipt_identity
                    ),
                },
            )
        )
        factory_boundary = getattr(
            self.connection_factory, "os_boundary_authority", None
        )
        if (
            factory_boundary is not None
            and factory_boundary.authority_fingerprint
            != self.os_boundary_authority.authority_fingerprint
        ):
            raise ValueError("connection factory OS boundary authority differs")
        expected_dependent_authorities = {
            "capsule_image_content_id": (
                self.controller.execution_authority.image_identity
            ),
            "capsule_execution_authority_fingerprint": (
                self.controller.execution_authority.authority_fingerprint
            ),
            "capsule_broker_runtime_authority_fingerprint": (
                self.controller.controller_authority.controller_fingerprint
            ),
            "codex_protocol_schema_identity": protocol_schema_identity(),
            "dynamic_tools_schema_identity": fingerprint(dynamic_tools_grammar()),
            "model_binding_policy_fingerprint": (
                self.model_binding_policy.policy_fingerprint
            ),
            "verified_serialization_witness_receipt_identity": (
                self.verified_witness_receipt.receipt_identity
            ),
        }
        if (
            dict(self.os_boundary_authority.dependent_authorities)
            != expected_dependent_authorities
        ):
            raise ValueError("OS boundary dependent image/protocol authority differs")

    @property
    def authority(self) -> CapsuleAuthority:
        return self._authority

    def _docker_component_identity(self) -> Mapping[str, Any]:
        if isinstance(self.controller, CapsuleBrokerClient):
            return dict(self.controller.docker_component_identity)
        return self.controller.docker_identity.to_dict()

    def _attest_capsule_authority(self) -> None:
        if isinstance(self.controller, CapsuleBrokerClient):
            self.controller.attest_authority()
        else:
            # Direct Docker authority exists only in the synthetic compatibility
            # harness. Production construction above refuses it.
            self.controller.docker_identity.reattest(label="Docker executable")
            self.controller.controller_authority.validated()

    def _attest_control_binding(self) -> None:
        self.connection_factory.attest_launch()
        if (
            self.control_authority.codex_protocol_version
            != CODEX_APP_SERVER_PROTOCOL_VERSION
            or dict(self.control_authority.executable_identity)
            != dict(self.connection_factory.codex_component_identity)
            or self.control_authority.policy_fingerprint
            != self.connection_factory.host_policy_fingerprint
            or self.control_authority.authentication_boundary_state
            != self.connection_factory.authentication_boundary_state
        ):
            raise ValueError("control authority changed before launch")

    def _revalidate_witness_binding(self) -> None:
        """Reload the current durable evidence pack before launch or effects."""

        store = self.session_store.trusted_witness_store
        if store is None:
            raise AppServerProtocolError(
                "trusted serialization witness store is unavailable"
            )
        receipt = store.load_verified_receipt(
            receipt_identity=self.verified_witness_receipt.receipt_identity,
            witness_run_identity=self.verified_witness_receipt.witness_run_identity,
            expected_policy=self.model_binding_policy,
            expected_executable_identity=(
                self.connection_factory.codex_component_identity
            ),
        )
        rebound = canary_model_authority(
            model_binding_policy=self.model_binding_policy,
            verified_witness_receipt=receipt,
            trusted_witness_store=store,
        )
        if (
            receipt.receipt_identity
            != self.verified_witness_receipt.receipt_identity
            or receipt.witness_run_identity
            != self.verified_witness_receipt.witness_run_identity
            or rebound.authority_fingerprint
            != self.model_authority.authority_fingerprint
            or not rebound.receipt_revalidated
        ):
            raise AppServerProtocolError(
                "durable serialization witness changed before launch or effect"
            )

    def _require_validated_model_configuration(self) -> Mapping[str, Any]:
        """Refuse every effectful dynamic tool call before model validation.

        ``_run_protocol`` validates ``ThreadStartResponse`` before ``turn/start``,
        so this guard is ordering defence in depth: it makes the invariant
        explicit and independently testable rather than implied by call order.
        """

        self._revalidate_witness_binding()
        self.model_binding_policy.validated_canary()
        self.model_authority.require_verified_receipt()
        binding = self._effective_model_binding
        if binding is None:
            raise AppServerProtocolError(
                "capsule effects are refused before the bound model "
                "configuration is validated"
            )
        if (
            binding.get("model_authority_fingerprint")
            != self.model_authority.authority_fingerprint
            or binding.get("app_server_effective_model")
            != self.model_authority.configured_model
            or binding.get("app_server_effective_reasoning_effort")
            != self.model_authority.configured_reasoning_effort
        ):
            raise AppServerProtocolError(
                "active session model configuration differs from the bound authority"
            )
        return binding

    def _attest_execution_binding(
        self,
        execution_authority: BackendExecutionAuthority,
    ) -> None:
        self._revalidate_witness_binding()
        self._attest_control_binding()
        self._attest_capsule_authority()
        expected = {
            "codex": dict(self.connection_factory.codex_component_identity),
            "bwrap": dict(self.connection_factory.bwrap_component_identity),
            "factory": dict(self.connection_factory.component_identity),
            "docker": self._docker_component_identity(),
        }
        if (
            dict(execution_authority.codex_executable_identity) != expected["codex"]
            or dict(execution_authority.bwrap_executable_identity) != expected["bwrap"]
            or dict(execution_authority.connection_factory_identity) != expected["factory"]
            or dict(execution_authority.docker_executable_identity) != expected["docker"]
            or execution_authority.host_control_policy_fingerprint
            != self.connection_factory.host_policy_fingerprint
            or execution_authority.bwrap_argv_policy_fingerprint
            != self.connection_factory.bwrap_argv_policy_fingerprint
            or execution_authority.connection_mode
            != self.connection_factory.connection_mode
            or execution_authority.authentication_boundary_state
            != self.connection_factory.authentication_boundary_state
            or execution_authority.controller_identity
            != self.controller.controller_authority.controller_fingerprint
            or execution_authority.capsule_image_content_id
            != self.controller.execution_authority.image_identity
            or execution_authority.dynamic_tools_schema_identity
            != fingerprint(dynamic_tools_grammar())
            or execution_authority.protocol_request_policy_fingerprint
            != protocol_request_policy_fingerprint(self.model_authority)
            or execution_authority.model_authority_fingerprint
            != self.model_authority.authority_fingerprint
            or dict(execution_authority.model_authority)
            != self.model_authority.to_dict()
            or execution_authority.model_binding_policy_fingerprint
            != self.model_binding_policy.policy_fingerprint
            or dict(execution_authority.model_binding_policy)
            != self.model_binding_policy.to_dict()
            or execution_authority.verified_witness_receipt_identity
            != self.verified_witness_receipt.receipt_identity
            or execution_authority.verified_witness_run_identity
            != self.verified_witness_receipt.witness_run_identity
            or execution_authority.mission_fingerprint
            != sha256_bytes(self._mission_bytes)
            or execution_authority.prompt_fingerprint
            != sha256_bytes(self._prompt_bytes)
            or execution_authority.os_boundary_authority_fingerprint
            != self.os_boundary_authority.authority_fingerprint
        ):
            raise ValueError("backend execution authority changed before launch")

    def prepare_workspace(self) -> WorkspaceReference:
        self._revalidate_witness_binding()
        self._attest_control_binding()
        self._attest_capsule_authority()
        token = uuid.uuid4().hex
        session_id = f"capsule-session-{token}"
        run_id = f"capsule-run-{uuid.uuid4().hex}"
        workspace_id = f"workspace-{token}"
        execution_authority = BackendExecutionAuthority.create(
            capsule_authority_fingerprint=self.authority.authority_fingerprint,
            generic_mission_fingerprint=self.authority.mission_fingerprint,
            codex_executable_identity=self.connection_factory.codex_component_identity,
            host_control_policy_fingerprint=self.connection_factory.host_policy_fingerprint,
            bwrap_executable_identity=self.connection_factory.bwrap_component_identity,
            bwrap_argv_policy_fingerprint=(
                self.connection_factory.bwrap_argv_policy_fingerprint
            ),
            controller_identity=self.controller.controller_authority.controller_fingerprint,
            capsule_image_content_id=self.controller.execution_authority.image_identity,
            docker_executable_identity=self._docker_component_identity(),
            dynamic_tools_schema_identity=fingerprint(dynamic_tools_grammar()),
            model_authority=self.model_authority,
            verified_witness_receipt=self.verified_witness_receipt,
            trusted_witness_store=self.session_store.trusted_witness_store,
            protocol_request_policy_fingerprint=(
                protocol_request_policy_fingerprint(self.model_authority)
            ),
            mission_bytes=self._mission_bytes,
            prompt_bytes=self._prompt_bytes,
            backend_session_id=session_id,
            run_id=run_id,
            connection_mode=self.connection_factory.connection_mode,
            connection_factory_identity=self.connection_factory.component_identity,
            authentication_boundary_state=(
                self.connection_factory.authentication_boundary_state
            ),
            os_boundary_authority=self.os_boundary_authority.to_dict(),
            budgets={
                "event_timeout_ms": int(self.event_timeout_seconds * 1000),
                "protocol_drain_timeout_ms": int(
                    self.protocol_drain_timeout_seconds * 1000
                ),
                "protocol_drain_records": self.protocol_drain_record_limit,
                "app_server_message_bytes": APP_SERVER_MESSAGE_LIMIT,
                "agent_text_bytes": AGENT_TEXT_LIMIT,
                "capsule_command_timeout_ms": int(
                    self.controller.limits.command_timeout_seconds * 1000
                ),
                "capsule_session_timeout_ms": int(
                    self.controller.limits.session_timeout_seconds * 1000
                ),
                "capsule_output_bytes": self.controller.limits.output_limit_bytes,
                "capsule_workspace_bytes": self.controller.limits.tree_bytes_limit,
                "capsule_pids": self.controller.limits.pids,
                "capsule_cpu_millis": self.controller.limits.cpu_millis,
                "capsule_memory_bytes": self.controller.limits.memory_bytes,
            },
            terminal_policy={
                "post_terminal_drain": "BOUNDED_UNTIL_PROCESS_CLOSED",
                "late_record_policy": "FAIL_SESSION",
                "completion_requires": [
                    "protocol_terminal",
                    "app_server_process_closed",
                    "capsule_cleanup",
                    "frozen_provider_output",
                ],
            },
        )
        reference = WorkspaceReference.create(
            workspace_id=workspace_id,
            capsule_authority_fingerprint=self.authority.authority_fingerprint,
            host_owned=False,
        )
        handle = self.controller.prepare(
            session_id=session_id,
            workspace_id=workspace_id,
            mission_authority_fingerprint=execution_authority.authority_fingerprint,
        )
        try:
            self.session_store.create_session(
                session_id=session_id,
                authority_identity={
                    "backend_execution_authority": execution_authority.to_dict(),
                    "capsule_authority": self.authority.to_dict(),
                    "authenticated_control_authority": self.control_authority.to_dict(),
                    "capsule_execution_authority": self.controller.execution_authority.to_dict(),
                    "os_boundary_authority": self.os_boundary_authority.to_dict(),
                },
                controller_authority=self.controller.controller_authority.to_dict(),
                workspace=reference.to_dict(),
            )
            self.session_store.record_capsule_process(session_id, handle.public_process_identity)
        except BaseException:
            self.controller.cleanup(handle)
            raise
        self._workspace_sessions[workspace_id] = session_id
        self._execution_authorities[workspace_id] = execution_authority
        return reference

    def _session_for(self, workspace: WorkspaceReference) -> tuple[str, DockerWorkspaceHandle]:
        workspace.validated()
        if workspace.capsule_authority_fingerprint != self.authority.authority_fingerprint:
            raise ValueError("workspace belongs to another capsule authority")
        try:
            session_id = self._workspace_sessions[workspace.workspace_id]
        except KeyError as error:
            raise ValueError("workspace was not minted by this backend instance") from error
        handle = self.controller.get(workspace.workspace_id)
        execution_authority = self._execution_authorities[workspace.workspace_id]
        execution_authority.validated()
        if (
            handle.session_id != session_id
            or handle.mission_authority_fingerprint
            != execution_authority.authority_fingerprint
        ):
            raise ValueError("capsule handle differs from backend execution authority")
        snapshot = self.session_store.reconstruct(session_id)
        if (
            snapshot.authority_identity.get("backend_execution_authority")
            != execution_authority.to_dict()
        ):
            raise ValueError("durable backend execution authority substitution refused")
        return session_id, handle

    def _expect_response(
        self,
        connection: AppServerConnection,
        request_id: str,
        schema: str,
    ) -> Mapping[str, Any]:
        message = connection.receive(self.event_timeout_seconds)
        if message is None:
            raise AppServerProtocolError("app-server ended before its response")
        if set(message) != {"id", "result"} or message.get("id") != request_id:
            raise AppServerProtocolError("app-server returned a malformed or wrong-ID response")
        if not isinstance(message["result"], dict):
            raise AppServerProtocolError("app-server response result is not an object")
        try:
            validate_schema(schema, message["result"], label=f"response {request_id}")
        except ValueError as error:
            raise AppServerProtocolError(str(error)) from error
        return message["result"]

    def _expect_response_and_notification(
        self,
        connection: AppServerConnection,
        *,
        request_id: str,
        response_schema: str,
        notification_method: str,
        notification_schema: str,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        response = None
        notification = None
        for _ in range(2):
            message = connection.receive(self.event_timeout_seconds)
            if message is None:
                raise AppServerProtocolError("app-server ended during lifecycle handshake")
            if "id" in message:
                if response is not None:
                    raise AppServerProtocolError("duplicate lifecycle response")
                if set(message) != {"id", "result"} or message["id"] != request_id:
                    raise AppServerProtocolError("malformed or wrong-ID lifecycle response")
                if not isinstance(message["result"], dict):
                    raise AppServerProtocolError("lifecycle response result is not an object")
                try:
                    validate_schema(
                        response_schema,
                        message["result"],
                        label=f"response {request_id}",
                    )
                except ValueError as error:
                    raise AppServerProtocolError(str(error)) from error
                response = message["result"]
            else:
                if notification is not None:
                    raise AppServerProtocolError("duplicate lifecycle notification")
                if (
                    set(message) != {"method", "params"}
                    or message.get("method") != notification_method
                    or not isinstance(message.get("params"), dict)
                ):
                    raise AppServerProtocolError("unexpected lifecycle notification")
                try:
                    validate_schema(
                        notification_schema,
                        message["params"],
                        label=notification_method,
                    )
                except ValueError as error:
                    raise AppServerProtocolError(str(error)) from error
                notification = message["params"]
        if response is None or notification is None:
            raise AppServerProtocolError("incomplete lifecycle response/notification pair")
        return response, notification

    def _tool_response(self, result: DurableToolResult) -> dict[str, Any]:
        body = {
            "classification": result.classification.value,
            "exitCode": result.exit_code,
            "timedOut": result.timed_out,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "stdoutTruncated": result.stdout_truncated,
            "stderrTruncated": result.stderr_truncated,
        }
        response = {
            "contentItems": [{"type": "inputText", "text": canonical_bytes(body).decode("utf-8")}],
            "success": result.classification == ToolTerminalClassification.SUCCEEDED,
        }
        try:
            validate_schema(
                "DynamicToolCallResponse.json",
                response,
                label="dynamic tool result",
            )
        except ValueError as error:
            raise AppServerProtocolError(str(error)) from error
        return response

    def _send_protocol_error(
        self, connection: AppServerConnection, rpc_id: int | str, message: str
    ) -> None:
        connection.send(
            {
                "id": rpc_id,
                "error": {
                    "code": -32000,
                    "message": message[:1024],
                },
            }
        )

    def _parse_tool_call(
        self,
        session_id: str,
        handle: DockerWorkspaceHandle,
        message: Mapping[str, Any],
    ) -> DurableToolRequest:
        if set(message) != {"method", "id", "params"} or message["method"] != "item/tool/call":
            raise AppServerProtocolError("invalid dynamic-tool request envelope")
        params = message["params"]
        try:
            validate_schema("DynamicToolCallParams.json", params, label="item/tool/call")
        except ValueError as error:
            raise AppServerProtocolError(str(error)) from error
        if not isinstance(params, Mapping) or set(params) != {
            "threadId",
            "turnId",
            "callId",
            "namespace",
            "tool",
            "arguments",
        }:
            raise AppServerProtocolError("invalid item/tool/call params")
        if params["namespace"] != DYNAMIC_TOOL_NAMESPACE:
            raise AppServerProtocolError("dynamic tool uses an unauthorized namespace")
        if params["tool"] not in ALLOWED_DYNAMIC_TOOLS:
            raise AppServerProtocolError("dynamic tool is outside the explicit grammar")
        try:
            return self.session_store.make_tool_request(
                session_id,
                rpc_id=message["id"],
                call_id=params["callId"],
                thread_id=params["threadId"],
                turn_id=params["turnId"],
                namespace=params["namespace"],
                tool=params["tool"],
                arguments=params["arguments"],
                controller_session_id=handle.controller_session_id,
                capsule_handle=handle.capsule_handle,
                mission_authority_fingerprint=handle.mission_authority_fingerprint,
            )
        except ValueError as error:
            raise AppServerProtocolError(str(error)) from error

    def _item_type(self, message: Mapping[str, Any]) -> str:
        params = message.get("params")
        if not isinstance(params, Mapping):
            raise AppServerProtocolError("item notification params are not an object")
        item = params.get("item")
        if not isinstance(item, Mapping):
            raise AppServerProtocolError("item notification has no item object")
        item_type = item.get("type")
        if not isinstance(item_type, str):
            raise AppServerProtocolError("item notification has no item type")
        return item_type

    def _run_protocol(
        self,
        *,
        session_id: str,
        handle: DockerWorkspaceHandle,
        connection: AppServerConnection,
    ) -> tuple[SessionTerminalClassification, str, str, str]:
        init_id = f"init-{session_id}"
        thread_request_id = f"thread-{session_id}"
        turn_request_id = f"turn-{session_id}"
        connection.send(initialize_request(init_id))
        initialized = self._expect_response(
            connection,
            init_id,
            "v1/InitializeResponse.json",
        )
        if (
            initialized.get("codexHome") != str(CONTROL_CODEX_HOME)
            or re.search(
                rf"(?:^|/){re.escape(CODEX_APP_SERVER_PROTOCOL_VERSION)}(?:$|[ (])",
                initialized.get("userAgent", ""),
            )
            is None
        ):
            raise AppServerProtocolError(
                "initialize response does not attest the pinned control home/protocol"
            )
        connection.send({"method": "initialized", "params": {}})
        self._effective_model_binding = None
        connection.send(
            thread_start_request(
                thread_request_id,
                model_authority=self.model_authority,
            )
        )
        thread_result, thread_started = self._expect_response_and_notification(
            connection,
            request_id=thread_request_id,
            response_schema="v2/ThreadStartResponse.json",
            notification_method="thread/started",
            notification_schema="v2/ThreadStartedNotification.json",
        )
        if (
            thread_result.get("cwd") != str(CONTROL_EMPTY_CWD)
            or thread_result.get("approvalPolicy") != "never"
            or thread_result.get("sandbox")
            != {"type": "readOnly", "networkAccess": False}
        ):
            raise AppServerProtocolError("thread/start response changed the control policy")
        # Configuration/protocol mismatch terminates here: before turn/start and
        # therefore before any dynamic tool call can reach the capsule.
        self._effective_model_binding = validate_effective_thread_configuration(
            thread_result,
            self.model_authority,
        )
        thread = thread_result.get("thread")
        started_thread = thread_started.get("thread")
        if not isinstance(thread, Mapping) or not isinstance(started_thread, Mapping):
            raise AppServerProtocolError("thread lifecycle has no thread")
        thread_id = thread.get("id")
        app_server_session_id = thread.get("sessionId")
        require_identifier(thread_id, "app-server thread id")
        require_identifier(app_server_session_id, "app-server session id")
        if (
            thread.get("cliVersion") != CODEX_APP_SERVER_PROTOCOL_VERSION
            or dict(started_thread) != dict(thread)
        ):
            raise AppServerProtocolError(
                "thread/started identity or state differs from thread/start"
            )

        connection.send(
            turn_start_request(
                turn_request_id,
                thread_id=thread_id,
                prompt=self.mission_prompt,
                model_authority=self.model_authority,
            )
        )
        turn_result, turn_started = self._expect_response_and_notification(
            connection,
            request_id=turn_request_id,
            response_schema="v2/TurnStartResponse.json",
            notification_method="turn/started",
            notification_schema="v2/TurnStartedNotification.json",
        )
        turn = turn_result.get("turn")
        started_turn = turn_started.get("turn")
        if not isinstance(turn, Mapping) or not isinstance(started_turn, Mapping):
            raise AppServerProtocolError("turn lifecycle has no turn")
        turn_id = turn.get("id")
        require_identifier(turn_id, "app-server turn id")
        if (
            turn_started.get("threadId") != thread_id
            or dict(started_turn) != dict(turn)
            or turn.get("status") != "inProgress"
            or started_turn.get("status") != "inProgress"
        ):
            raise AppServerProtocolError("turn/started identity or phase mismatch")
        self.session_store.bind_protocol(
            session_id,
            app_server_session_id=app_server_session_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )

        agent_text = bytearray()
        items: dict[str, dict[str, Any]] = {}
        terminal_classification: str | None = None
        terminal_session_classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
        terminal_detail = ""
        while True:
            message = connection.receive(self.event_timeout_seconds)
            if message is None:
                raise AppServerProtocolError("app-server ended before turn/completed")
            method = message.get("method")
            if "id" in message and method != "item/tool/call":
                raise AppServerProtocolError("native or unknown server request refused")
            if method == "item/tool/call":
                self._require_validated_model_configuration()
                request = self._parse_tool_call(session_id, handle, message)
                active = items.get(request.call_id)
                if (
                    active is None
                    or active["state"] != "started"
                    or active["type"] != "dynamicToolCall"
                    or active["item"].get("tool") != request.tool
                    or active["item"].get("arguments") != dict(request.arguments)
                ):
                    raise AppServerProtocolError(
                        "dynamic tool request has no exact active item identity"
                    )
                disposition, existing = self.session_store.tool_id_disposition(session_id, request)
                if disposition == ToolIdDisposition.DUPLICATE:
                    self._send_protocol_error(connection, request.rpc_id, "duplicate tool ID refused")
                    return (
                        SessionTerminalClassification.DUPLICATE_TOOL_ID_REFUSED,
                        "PROTOCOL_REFUSED",
                        f"duplicate tool ID refused; original sequence={existing.sequence if existing else 'unknown'}",
                        agent_text.decode("utf-8", "replace"),
                    )
                if disposition == ToolIdDisposition.CONFLICT:
                    self._send_protocol_error(connection, request.rpc_id, "conflicting tool ID refused")
                    return (
                        SessionTerminalClassification.CONFLICTING_TOOL_ID_REFUSED,
                        "PROTOCOL_REFUSED",
                        f"conflicting tool ID refused; original sequence={existing.sequence if existing else 'unknown'}",
                        agent_text.decode("utf-8", "replace"),
                    )
                self.session_store.record_tool_request(request)
                self.session_store.record_effect_execution_started(request)
                result = self.controller.execute(handle, request)
                self.session_store.record_tool_result(result)
                connection.send({"id": request.rpc_id, "result": self._tool_response(result)})
                if result.classification == ToolTerminalClassification.TIMED_OUT:
                    return (
                        SessionTerminalClassification.TIMED_OUT,
                        "TIMED_OUT",
                        "capsule tool exceeded bounded wall time",
                        agent_text.decode("utf-8", "replace"),
                    )
                if result.classification == ToolTerminalClassification.OUTPUT_LIMIT_REFUSED:
                    return (
                        SessionTerminalClassification.OUTPUT_LIMIT_REFUSED,
                        "PROTOCOL_REFUSED",
                        "capsule tool output exceeded its bound",
                        agent_text.decode("utf-8", "replace"),
                    )
                if (
                    handle.container_quarantined
                    or not handle.container_alive
                    or (
                        result.classification == ToolTerminalClassification.FAILED
                        and result.exit_code == 125
                    )
                ):
                    return (
                        SessionTerminalClassification.CAPSULE_FAILED,
                        "FAILED",
                        "capsule process was unavailable during tool execution",
                        agent_text.decode("utf-8", "replace"),
                    )
                continue
            if method in {"item/started", "item/completed"}:
                if set(message) != {"method", "params"}:
                    raise AppServerProtocolError("invalid item lifecycle envelope")
                schema = (
                    "v2/ItemStartedNotification.json"
                    if method == "item/started"
                    else "v2/ItemCompletedNotification.json"
                )
                try:
                    validate_schema(schema, message["params"], label=method)
                except ValueError as error:
                    raise AppServerProtocolError(str(error)) from error
                params = message["params"]
                if (
                    params.get("threadId") != thread_id
                    or params.get("turnId") != turn_id
                ):
                    raise AppServerProtocolError("item lifecycle identity mismatch")
                item_type = self._item_type(message)
                if item_type not in PASSIVE_ITEM_TYPES:
                    return (
                        SessionTerminalClassification.NATIVE_EFFECT_REFUSED,
                        "PROTOCOL_REFUSED",
                        f"native Codex effect item refused: {item_type}",
                        agent_text.decode("utf-8", "replace"),
                    )
                item = params["item"]
                item_id = item.get("id")
                require_identifier(item_id, "app-server item id")
                if method == "item/started":
                    if item_id in items:
                        raise AppServerProtocolError("duplicate or ambiguous item/start")
                    if (
                        item_type == "dynamicToolCall"
                        and item.get("status") != "inProgress"
                    ):
                        raise AppServerProtocolError(
                            "dynamic item/start has a non-active status"
                        )
                    items[item_id] = {
                        "state": "started",
                        "type": item_type,
                        "item": dict(item),
                    }
                    continue
                active = items.get(item_id)
                if active is None or active["state"] != "started" or active["type"] != item_type:
                    raise AppServerProtocolError("item/completed has no exact started item")
                if item_type == "dynamicToolCall" and not any(
                    request.call_id == item_id
                    and request.sequence in self.session_store.reconstruct(
                        session_id
                    ).results_by_sequence
                    for request in self.session_store.reconstruct(session_id).requests
                ):
                    raise AppServerProtocolError(
                        "dynamic item completed before its exact tool result"
                    )
                if item_type == "dynamicToolCall":
                    for field in ("id", "type", "namespace", "tool", "arguments"):
                        if item.get(field) != active["item"].get(field):
                            raise AppServerProtocolError(
                                "dynamic item/completed identity differs from item/started"
                            )
                    if item.get("status") not in {"completed", "failed"}:
                        raise AppServerProtocolError(
                            "dynamic item/completed has a nonterminal status"
                        )
                active["state"] = "completed"
                active["item"] = dict(item)
                if item_type == "agentMessage" and method == "item/completed":
                    text = item.get("text", "")
                    if not isinstance(text, str):
                        raise AppServerProtocolError("completed agent message has no text")
                    encoded = text.encode("utf-8")
                    if len(encoded) > AGENT_TEXT_LIMIT:
                        return (
                            SessionTerminalClassification.OUTPUT_LIMIT_REFUSED,
                            "PROTOCOL_REFUSED",
                            "agent message exceeded its bound",
                            agent_text.decode("utf-8", "replace"),
                        )
                    agent_text[:] = encoded
                continue
            if method == "turn/completed":
                if set(message) != {"method", "params"}:
                    raise AppServerProtocolError("invalid turn/completed envelope")
                try:
                    validate_schema(
                        "v2/TurnCompletedNotification.json",
                        message["params"],
                        label="turn/completed",
                    )
                except ValueError as error:
                    raise AppServerProtocolError(str(error)) from error
                params = message["params"]
                completed_turn = params["turn"]
                if (
                    params.get("threadId") != thread_id
                    or completed_turn.get("id") != turn_id
                ):
                    raise AppServerProtocolError("turn/completed does not match the bound turn")
                if any(item["state"] != "completed" for item in items.values()):
                    raise AppServerProtocolError("turn completed with active item lifecycle")
                terminal_items = completed_turn.get("items")
                if not isinstance(terminal_items, list) or any(
                    not isinstance(item, Mapping) for item in terminal_items
                ):
                    raise AppServerProtocolError("turn/completed items are malformed")
                terminal_by_id = {
                    item.get("id"): dict(item)
                    for item in terminal_items
                    if isinstance(item.get("id"), str)
                }
                if (
                    len(terminal_by_id) != len(terminal_items)
                    or set(terminal_by_id) != set(items)
                    or any(
                        terminal_by_id[item_id] != state["item"]
                        for item_id, state in items.items()
                    )
                ):
                    raise AppServerProtocolError(
                        "turn/completed item set differs from exact lifecycle records"
                    )
                status = completed_turn.get("status")
                if status == "completed":
                    terminal_classification = "COMPLETED"
                    terminal_session_classification = SessionTerminalClassification.COMPLETED
                    terminal_detail = (
                        "Codex app-server turn completed through dynamic tools"
                    )
                elif status == "failed":
                    if not isinstance(completed_turn.get("error"), Mapping):
                        raise AppServerProtocolError("failed turn lacks terminal error fields")
                    terminal_classification = "FAILED"
                    terminal_session_classification = (
                        SessionTerminalClassification.PROVIDER_PROCESS_FAILED
                    )
                    terminal_detail = "Codex app-server turn failed"
                elif status == "interrupted":
                    terminal_classification = "INTERRUPTED"
                    terminal_session_classification = (
                        SessionTerminalClassification.PROVIDER_PROCESS_FAILED
                    )
                    terminal_detail = "Codex app-server turn was interrupted"
                else:
                    raise AppServerProtocolError(
                        f"turn/completed has nonterminal status: {status!r}"
                    )
            elif method == "error":
                if set(message) != {"method", "params"}:
                    raise AppServerProtocolError("invalid error notification envelope")
                try:
                    validate_schema(
                        "v2/ErrorNotification.json",
                        message["params"],
                        label="error notification",
                    )
                except ValueError as error:
                    raise AppServerProtocolError(str(error)) from error
                if (
                    message["params"].get("threadId") != thread_id
                    or message["params"].get("turnId") != turn_id
                ):
                    raise AppServerProtocolError("error notification identity mismatch")
                terminal_classification = "ERROR"
                terminal_session_classification = (
                    SessionTerminalClassification.PROVIDER_PROCESS_FAILED
                )
                terminal_detail = "Codex app-server emitted a terminal error"
            else:
                # Includes command/file deltas, approvals, MCP, web, process
                # spawning, warnings in the wrong phase, and future methods.
                raise AppServerProtocolError(
                    f"unrecognized or effectful app-server method: {method!r}"
                )

            if terminal_classification is not None:
                connection.begin_protocol_close()
                for _ in range(self.protocol_drain_record_limit):
                    late = connection.receive(self.protocol_drain_timeout_seconds)
                    if late is None:
                        return (
                            terminal_session_classification,
                            terminal_classification,
                            terminal_detail,
                            agent_text.decode("utf-8", "replace"),
                        )
                    raise AppServerProtocolError(
                        "app-server emitted a record after terminal state"
                    )
                raise AppServerProtocolError("app-server protocol drain exceeded its bound")

    def _process_result(
        self,
        classification: SessionTerminalClassification,
        returncode: int | None,
        forced_close: bool,
    ) -> ProcessResult:
        timed_out = classification == SessionTerminalClassification.TIMED_OUT
        if timed_out:
            exit_code = None
        elif returncode is not None and returncode >= 0:
            exit_code = returncode
        else:
            exit_code = None
        signal_name: str | None = None
        if returncode is not None and returncode < 0:
            signal_number = -returncode
            try:
                signal_name = signal.Signals(signal_number).name
            except ValueError:
                signal_name = f"SIGNAL_{signal_number}"
        return ProcessResult(
            schema_version="admissible_capsule_process_result_v1",
            exit_code=exit_code,
            timed_out=timed_out,
            signal=signal_name,
        ).validated()

    def run(self, workspace: WorkspaceReference) -> ProviderOutput:
        session_id, handle = self._session_for(workspace)
        execution_authority = self._execution_authorities[workspace.workspace_id]
        snapshot = self.session_store.reconstruct(session_id)
        if snapshot.provider_output is not None:
            if snapshot.recorded_terminal_classification is None or snapshot.cleanup is None:
                raise ValueError("ProviderOutput has no exact terminal/cleanup journal chain")
            if handle.frozen_workspace_fingerprint is not None:
                self.controller.observe_frozen_output(handle)
            return snapshot.provider_output
        classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
        protocol_terminal = "PROTOCOL_REFUSED"
        detail = "app-server did not start"
        claim_text = ""
        connected = False
        connection: AppServerConnection | None = None
        returncode: int | None = None
        forced_close = False
        eof_observed = False
        fatal_error: BaseException | None = None
        try:
            self._attest_execution_binding(execution_authority)
            connection = self.connection_factory.open(session_id)
            connected = True
            self.session_store.record_app_server_process(session_id, connection.process_identity)
            classification, protocol_terminal, detail, claim_text = self._run_protocol(
                session_id=session_id,
                handle=handle,
                connection=connection,
            )
        except AppServerReceiveTimeout as error:
            classification = SessionTerminalClassification.TIMED_OUT
            protocol_terminal = "TIMED_OUT"
            detail = str(error)
        except CrashInjected as error:
            classification = SessionTerminalClassification.CAPSULE_FAILED
            protocol_terminal = "PROTOCOL_REFUSED"
            detail = "crash injected after a durable protocol boundary"
            fatal_error = error
        except (AppServerProtocolError, ValueError, OSError, RuntimeError) as error:
            classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
            protocol_terminal = "PROTOCOL_REFUSED"
            detail = str(error)
        except BaseException as error:
            # Preserve crash semantics and still close/freeze/clean the exact
            # session before propagating. An unpaired request remains
            # indeterminate and is never replay authorization.
            classification = SessionTerminalClassification.CAPSULE_FAILED
            protocol_terminal = "PROTOCOL_REFUSED"
            detail = f"fatal controller exception: {type(error).__name__}"
            fatal_error = error
        finally:
            if connection is not None:
                try:
                    connection.close()
                except (OSError, RuntimeError) as error:
                    classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
                    protocol_terminal = "PROTOCOL_REFUSED"
                    detail = f"app-server cleanup failed: {error}"
                returncode = connection.returncode
                forced_close = connection.forced_close
                eof_observed = connection.eof_observed

        if returncode not in (None, 0) or forced_close:
            classification = SessionTerminalClassification.PROVIDER_PROCESS_FAILED
            detail = (
                "app-server process closure failed "
                f"(exit={returncode}, forced={forced_close}, eof={eof_observed})"
            )
        elif (
            classification == SessionTerminalClassification.COMPLETED
            and not eof_observed
        ):
            classification = SessionTerminalClassification.PROVIDER_PROCESS_FAILED
            detail = "app-server completed protocol without a proven closed boundary"

        self.session_store.record_control_terminal(
            session_id,
            {
                "protocol_terminal_classification": protocol_terminal,
                "app_server_exit_code": returncode,
                "app_server_exit_normal": (
                    returncode is not None and returncode >= 0 and not forced_close
                ),
                "app_server_forced": forced_close,
                "app_server_eof_observed": eof_observed,
                "controller_classification": classification.value,
            },
        )

        freeze_succeeded = False
        try:
            observation = self.controller.freeze_output(handle)
            freeze_succeeded = True
        except ValueError as error:
            if classification == SessionTerminalClassification.COMPLETED:
                classification = SessionTerminalClassification.OUTPUT_LIMIT_REFUSED
                detail = f"provider output freeze refused: {error}"
            else:
                detail = (
                    f"{detail}; post-terminal output freeze refused without "
                    f"changing the established {classification.value} classification: "
                    f"{error}"
                )
            observation = ByteTreeObservation.create(entries=())
        except (OSError, RuntimeError) as error:
            if classification == SessionTerminalClassification.COMPLETED:
                classification = SessionTerminalClassification.CAPSULE_FAILED
                detail = f"provider output freeze failed: {error}"
            else:
                detail = (
                    f"{detail}; post-terminal output freeze failed without "
                    f"changing the established {classification.value} classification: "
                    f"{error}"
                )
            observation = ByteTreeObservation.create(entries=())

        try:
            cleanup_evidence = self.controller.cleanup(handle)
        except (OSError, RuntimeError, ValueError) as error:
            cleanup_evidence = ControllerCleanupEvidence(
                container_removed=False,
                complete_process_tree_reaped=False,
                disposable_workspace_removed=False,
                frozen_output_retained=bool(
                    handle.frozen_workspace_fingerprint
                    and handle.frozen_path.is_dir()
                ),
                volume_removed=False,
            )
            classification = SessionTerminalClassification.CLEANUP_FAILED
            detail = f"capsule cleanup failed or unknown: {error}"
        self.session_store.record_cleanup(session_id, cleanup_evidence.to_dict())
        if not cleanup_evidence.cleanup_proven:
            classification = SessionTerminalClassification.CLEANUP_FAILED
            detail = "capsule container, descendants, or disposable workspace cleanup was unconfirmed"

        cleanup_fingerprint = fingerprint(cleanup_evidence.to_dict())
        cleanup_tail = self.session_store.reconstruct(session_id).events[-1].event_fingerprint
        broker_terminal_evidence = getattr(
            self.controller, "broker_terminal_evidence", None
        )
        capsule_broker_terminal_fingerprint = (
            broker_terminal_evidence.get("terminal_fingerprint")
            if isinstance(broker_terminal_evidence, Mapping)
            else None
        )
        if capsule_broker_terminal_fingerprint is None:
            capsule_broker_terminal_fingerprint = fingerprint(
                {
                    "kind": "synthetic_direct_controller_terminal",
                    "connection_mode": self.connection_factory.connection_mode,
                    "cleanup_fingerprint": cleanup_fingerprint,
                }
            )
        require_sha256(
            capsule_broker_terminal_fingerprint,
            "capsule broker terminal fingerprint",
        )
        boundary_terminal_fingerprint = getattr(
            self.controller,
            "complete_boundary_terminal_fingerprint",
            None,
        )
        production_boundary_complete = boundary_terminal_fingerprint is not None
        if boundary_terminal_fingerprint is None:
            boundary_terminal_fingerprint = fingerprint(
                {
                    "kind": "provider_free_boundary_terminal",
                    "connection_mode": self.connection_factory.connection_mode,
                    "os_boundary_authority_fingerprint": (
                        self.os_boundary_authority.authority_fingerprint
                    ),
                    "capsule_broker_terminal_fingerprint": (
                        capsule_broker_terminal_fingerprint
                    ),
                    "cleanup_fingerprint": cleanup_fingerprint,
                    "journal_tail_fingerprint": cleanup_tail,
                }
            )
            if self.connection_factory.connection_mode in {
                "production_bwrap",
                "production_os_boundary",
            }:
                classification = SessionTerminalClassification.CLEANUP_FAILED
                detail = (
                    "complete authentication/egress/capsule boundary terminal "
                    "evidence is missing"
                )
        self.session_store.record_boundary_terminal(
            session_id,
            {
                "os_boundary_authority_fingerprint": (
                    self.os_boundary_authority.authority_fingerprint
                ),
                "capsule_broker_terminal_fingerprint": (
                    capsule_broker_terminal_fingerprint
                ),
                "boundary_terminal_fingerprint": boundary_terminal_fingerprint,
                "production_complete": production_boundary_complete,
            },
        )
        cleanup_tail = (
            self.session_store.reconstruct(session_id)
            .events[-1]
            .event_fingerprint
        )
        frozen_workspace_fingerprint = (
            handle.frozen_workspace_fingerprint
            if freeze_succeeded and handle.frozen_workspace_fingerprint is not None
            else fingerprint(
                {
                    "schema_version": "admissible_absent_frozen_workspace_v1",
                    "session_id": session_id,
                    "freeze_succeeded": False,
                }
            )
        )
        if freeze_succeeded:
            frozen_binding_fingerprint = self.controller.bind_frozen_snapshot(
                handle,
                journal_tail_fingerprint=cleanup_tail,
                cleanup_fingerprint=cleanup_fingerprint,
            )
        else:
            frozen_binding_fingerprint = fingerprint(
                {
                    "schema_version": "admissible_absent_frozen_binding_v1",
                    "frozen_workspace_fingerprint": frozen_workspace_fingerprint,
                    "journal_tail_fingerprint": cleanup_tail,
                    "cleanup_fingerprint": cleanup_fingerprint,
                }
            )

        if fatal_error is not None:
            raise fatal_error

        completion = (
            classification == SessionTerminalClassification.COMPLETED
            and returncode == 0
            and not forced_close
            and eof_observed
            and cleanup_evidence.cleanup_proven
            and freeze_succeeded
        )
        if classification == SessionTerminalClassification.COMPLETED and not completion:
            classification = (
                SessionTerminalClassification.CLEANUP_FAILED
                if not cleanup_evidence.cleanup_proven
                else SessionTerminalClassification.CAPSULE_FAILED
            )
            detail = "completion prerequisites were not all independently proven"

        output = ProviderOutput.create(
            capsule_authority_fingerprint=self.authority.authority_fingerprint,
            workspace=workspace,
            observation=observation,
            process_result=self._process_result(classification, returncode, forced_close),
            transport_result=TransportResult(
                schema_version="admissible_capsule_transport_result_v1",
                transport_kind="codex_app_server_dynamic_tools_v1",
                connected=connected,
                closed_cleanly=(
                    connected
                    and eof_observed
                    and returncode == 0
                    and not forced_close
                ),
            ).validated(),
            cleanup_result=cleanup_evidence.provider_cleanup_result(),
            completion_claim=ProviderCompletionClaim(
                schema_version="admissible_capsule_provider_completion_claim_v1",
                claimed_complete=completion,
                claim_text=claim_text[:8192],
            ).validated(),
            execution_truth=ExecutionTruth.create(
                backend_execution_authority_fingerprint=(
                    execution_authority.authority_fingerprint
                ),
                app_server_exit_code=returncode,
                app_server_exit_normal=(
                    returncode is not None and returncode >= 0 and not forced_close
                ),
                app_server_forced=forced_close,
                protocol_terminal_classification=protocol_terminal,
                capsule_process_classification=(
                    "FORCED_EXIT"
                    if handle.capsule_exit_observed and handle.capsule_exit_forced
                    else "NORMAL_EXIT"
                    if handle.capsule_exit_observed and handle.capsule_exit_normal
                    else "UNKNOWN"
                ),
                capsule_process_exit_code=handle.capsule_exit_code,
                capsule_process_exit_normal=handle.capsule_exit_normal,
                capsule_process_forced=handle.capsule_exit_forced,
                controller_classification=classification.value,
                cleanup_fingerprint=cleanup_fingerprint,
                journal_tail_fingerprint=cleanup_tail,
                frozen_workspace_fingerprint=frozen_workspace_fingerprint,
                frozen_binding_fingerprint=frozen_binding_fingerprint,
                os_boundary_authority_fingerprint=(
                    execution_authority.os_boundary_authority_fingerprint
                ),
                capsule_broker_terminal_fingerprint=(
                    capsule_broker_terminal_fingerprint
                ),
                boundary_terminal_fingerprint=boundary_terminal_fingerprint,
            ),
        )
        self.session_store.freeze_provider_output(session_id, output)
        self.session_store.record_terminal(session_id, classification, detail)
        reconstructed = self.session_store.reconstruct(session_id)
        if (
            reconstructed.provider_output != output
            or reconstructed.recorded_terminal_classification != classification
            or reconstructed.cleanup != cleanup_evidence.to_dict()
        ):
            raise ValueError("ProviderOutput terminal journal chain is not mutually bound")
        return reconstructed.provider_output

    def cleanup(self, workspace: WorkspaceReference) -> CleanupResult:
        session_id, handle = self._session_for(workspace)
        snapshot = self.session_store.reconstruct(session_id)
        if snapshot.cleanup is not None:
            evidence = snapshot.cleanup
            return CleanupResult(
                schema_version="admissible_capsule_cleanup_result_v1",
                workspace_removed=bool(
                    evidence.get("disposable_workspace_removed")
                    and evidence.get("container_removed")
                    and evidence.get("volume_removed")
                ),
                processes_reaped=bool(evidence.get("complete_process_tree_reaped")),
            ).validated()
        if snapshot.control_terminal is None:
            self.session_store.record_control_terminal(
                session_id,
                {
                    "protocol_terminal_classification": "PROTOCOL_REFUSED",
                    "app_server_exit_code": None,
                    "app_server_exit_normal": False,
                    "app_server_forced": False,
                    "app_server_eof_observed": False,
                    "controller_classification": (
                        SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED.value
                    ),
                },
            )
        cleanup_evidence = self.controller.cleanup(handle)
        self.session_store.record_cleanup(session_id, cleanup_evidence.to_dict())
        return cleanup_evidence.provider_cleanup_result()

    def frozen_output_path(self, workspace: WorkspaceReference) -> Path:
        """Concrete handoff to CanonicalIntake; never a control-process path."""

        session_id, handle = self._session_for(workspace)
        path = self.controller.frozen_output_path(workspace.workspace_id)
        if handle.frozen_workspace_fingerprint is None:
            raise ValueError("frozen workspace has no content identity")
        self.session_store.record_downstream_handoff(
            session_id,
            frozen_workspace_fingerprint=handle.frozen_workspace_fingerprint,
        )
        # Re-observe after the durable handoff record as the final pre-intake
        # same-identity mutation check.
        self.controller.observe_frozen_output(handle)
        return path

    def reconstruct(self, workspace: WorkspaceReference):
        session_id, _handle = self._session_for(workspace)
        return self.session_store.reconstruct(session_id)

    def bind_accepted_material(
        self,
        workspace: WorkspaceReference,
        accepted_material: AcceptedMaterialIdentity,
    ) -> None:
        """Durably bind downstream acceptance to this session's exact intake bytes."""

        session_id, _handle = self._session_for(workspace)
        self.session_store.record_accepted_material(session_id, accepted_material)

    def record_checkpoint_verification(
        self,
        workspace: WorkspaceReference,
        result: CheckpointResult,
    ) -> None:
        session_id, _handle = self._session_for(workspace)
        self.session_store.record_checkpoint_result(session_id, result)

    def record_behavior_verification(
        self,
        workspace: WorkspaceReference,
        result: BehaviorResult,
    ) -> None:
        session_id, _handle = self._session_for(workspace)
        self.session_store.record_behavior_result(session_id, result)

    def record_finalization_prepared(
        self,
        workspace: WorkspaceReference,
        evidence: FinalizationEvidence,
        receipt: DurabilityReceipt,
    ) -> None:
        session_id, _handle = self._session_for(workspace)
        self.session_store.record_finalization_prepared(session_id, evidence, receipt)

    def record_finalization_result(
        self,
        workspace: WorkspaceReference,
        result: FinalizationResult,
    ) -> None:
        session_id, _handle = self._session_for(workspace)
        self.session_store.record_finalization_result(session_id, result)
