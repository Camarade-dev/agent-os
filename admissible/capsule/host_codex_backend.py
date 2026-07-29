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
import selectors
import signal
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.backend import CapsuleAuthority, CapsuleBackend
from admissible.capsule.common import (
    CrashInjected,
    canonical_bytes,
    require_identifier,
    require_nonempty_text,
)
from admissible.capsule.docker_controller import (
    ALLOWED_DYNAMIC_TOOLS,
    DockerCapsuleController,
    DockerWorkspaceHandle,
)
from admissible.capsule.host_control import (
    AuthenticatedControlAuthority,
    CONTROL_EMPTY_CWD,
    HostControlBwrapPolicy,
)
from admissible.capsule.finalizer import (
    DurabilityReceipt,
    FinalizationEvidence,
    FinalizationResult,
)
from admissible.capsule.intake import AcceptedMaterialIdentity
from admissible.capsule.models import (
    ByteTreeObservation,
    CleanupResult,
    ProcessResult,
    ProviderCompletionClaim,
    ProviderOutput,
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


CODEX_APP_SERVER_PROTOCOL_VERSION = "0.145.0"
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
BENIGN_NOTIFICATION_METHODS = {
    "thread/started",
    "turn/started",
    "thread/tokenUsage/updated",
    "item/agentMessage/delta",
    "item/reasoning/summaryTextDelta",
    "item/reasoning/textDelta",
    "warning",
    "configWarning",
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

    @abstractmethod
    def send(self, message: Mapping[str, Any]) -> None:
        pass

    @abstractmethod
    def receive(self, timeout: float) -> Mapping[str, Any] | None:
        """Return one message, or None for EOF."""

    @abstractmethod
    def close(self) -> None:
        pass


class AppServerConnectionFactory(ABC):
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
        self._process = subprocess.Popen(
            policy.build_argv(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            bufsize=0,
        )
        if self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("failed to open app-server stdio")
        os.set_blocking(self._process.stdout.fileno(), False)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._process.stdout, selectors.EVENT_READ)
        self._receive_buffer = bytearray()

    @property
    def process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "bwrap_codex_app_server",
            "pid": self._process.pid,
            "codex_protocol_version": self._authority.codex_protocol_version,
            "control_authority_fingerprint": self._authority.authority_fingerprint,
            "policy_fingerprint": self._policy.policy_fingerprint,
        }

    @property
    def returncode(self) -> int | None:
        return self._process.poll()

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
                    value = json.loads(raw)
                except json.JSONDecodeError as error:
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
                return None
            self._receive_buffer.extend(chunk)
            if len(self._receive_buffer) > APP_SERVER_MESSAGE_LIMIT:
                raise AppServerProtocolError("inbound app-server message exceeds its bound")

    def close(self) -> None:
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=3)
        except subprocess.TimeoutExpired:
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

    def open(self, session_id: str) -> AppServerConnection:
        require_identifier(session_id, "app-server session_id")
        return BwrapCodexAppServerConnection(policy=self.policy, authority=self.authority)


class ScriptedCodexAppServerConnection(AppServerConnection):
    """Provider-free Codex 0.145.0 event source used by witness tests."""

    def __init__(
        self,
        messages: Sequence[Mapping[str, Any] | BaseException],
        *,
        returncode: int = 0,
        identity: str = "synthetic-codex-app-server-0.145.0",
    ):
        self._messages = deque(messages)
        self._configured_returncode = returncode
        self._closed = False
        self.sent: list[dict[str, Any]] = []
        self._identity = identity

    @property
    def process_identity(self) -> Mapping[str, Any]:
        return {
            "kind": "synthetic_app_server",
            "identity": self._identity,
            "codex_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "provider_request_capable": False,
        }

    @property
    def returncode(self) -> int | None:
        if not self._closed and self._messages:
            return None
        return self._configured_returncode

    def send(self, message: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(message)
        if len(encoded) > APP_SERVER_MESSAGE_LIMIT:
            raise AppServerProtocolError("synthetic outbound message exceeds its bound")
        self.sent.append(json.loads(encoded))

    def queue_messages(self, messages: Sequence[Mapping[str, Any] | BaseException]) -> None:
        if self._closed:
            raise ValueError("synthetic app-server connection is closed")
        self._messages.extend(messages)

    def receive(self, timeout: float) -> Mapping[str, Any] | None:
        if not self._messages:
            return None
        message = self._messages.popleft()
        if isinstance(message, BaseException):
            raise message
        encoded = canonical_bytes(message)
        if len(encoded) > APP_SERVER_MESSAGE_LIMIT:
            raise AppServerProtocolError("synthetic inbound message exceeds its bound")
        return json.loads(encoded)

    def close(self) -> None:
        self._closed = True


class ScriptedCodexConnectionFactory(AppServerConnectionFactory):
    """Single-use factory that exposes the connection for response assertions."""

    def __init__(self, connection: ScriptedCodexAppServerConnection):
        self.connection = connection
        self.open_count = 0

    def open(self, session_id: str) -> AppServerConnection:
        if self.open_count:
            raise ValueError("scripted app-server connection is single-use")
        self.open_count += 1
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
    return {
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


def thread_start_request(request_id: str) -> dict[str, Any]:
    return {
        "method": "thread/start",
        "id": request_id,
        "params": {
            "cwd": str(CONTROL_EMPTY_CWD),
            "approvalPolicy": "never",
            "sandbox": "readOnly",
            "ephemeral": True,
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


def turn_start_request(request_id: str, *, thread_id: str, prompt: str) -> dict[str, Any]:
    require_identifier(thread_id, "turn-start thread_id")
    require_nonempty_text(prompt, "capsule mission prompt", max_bytes=64 * 1024)
    return {
        "method": "turn/start",
        "id": request_id,
        "params": {
            "threadId": thread_id,
            "input": [{"type": "text", "text": prompt}],
        },
    }


class HostCodexAppServerCapsuleBackend(CapsuleBackend):
    """Concrete implementation of the generic capsule backend contract."""

    def __init__(
        self,
        *,
        authority: CapsuleAuthority,
        control_authority: AuthenticatedControlAuthority,
        controller: DockerCapsuleController,
        session_store: DurableCapsuleSessionStore,
        connection_factory: AppServerConnectionFactory,
        mission_prompt: str,
        event_timeout_seconds: float = 10.0,
    ):
        self._authority = authority.validated()
        self.control_authority = control_authority.validated()
        self.controller = controller
        self.session_store = session_store
        self.connection_factory = connection_factory
        self.mission_prompt = require_nonempty_text(
            mission_prompt, "capsule mission prompt", max_bytes=64 * 1024
        )
        if not 0.05 <= event_timeout_seconds <= 300:
            raise ValueError("app-server event timeout is out of bounds")
        self.event_timeout_seconds = event_timeout_seconds
        self._workspace_sessions: dict[str, str] = {}

    @property
    def authority(self) -> CapsuleAuthority:
        return self._authority

    def prepare_workspace(self) -> WorkspaceReference:
        token = uuid.uuid4().hex
        session_id = f"capsule-session-{token}"
        workspace_id = f"workspace-{token}"
        reference = WorkspaceReference.create(
            workspace_id=workspace_id,
            capsule_authority_fingerprint=self.authority.authority_fingerprint,
            host_owned=False,
        )
        handle = self.controller.prepare(session_id=session_id, workspace_id=workspace_id)
        try:
            self.session_store.create_session(
                session_id=session_id,
                authority_identity={
                    "capsule_authority": self.authority.to_dict(),
                    "authenticated_control_authority": self.control_authority.to_dict(),
                    "capsule_execution_authority": self.controller.execution_authority.to_dict(),
                },
                controller_authority=self.controller.controller_authority.to_dict(),
                workspace=reference.to_dict(),
            )
            self.session_store.record_capsule_process(session_id, handle.public_process_identity)
        except BaseException:
            self.controller.cleanup(handle)
            raise
        self._workspace_sessions[workspace_id] = session_id
        return reference

    def _session_for(self, workspace: WorkspaceReference) -> tuple[str, DockerWorkspaceHandle]:
        workspace.validated()
        if workspace.capsule_authority_fingerprint != self.authority.authority_fingerprint:
            raise ValueError("workspace belongs to another capsule authority")
        try:
            session_id = self._workspace_sessions[workspace.workspace_id]
        except KeyError as error:
            raise ValueError("workspace was not minted by this backend instance") from error
        return session_id, self.controller.get(workspace.workspace_id)

    def _expect_response(
        self,
        connection: AppServerConnection,
        request_id: str,
    ) -> Mapping[str, Any]:
        while True:
            message = connection.receive(self.event_timeout_seconds)
            if message is None:
                raise AppServerProtocolError("app-server ended before its response")
            if message.get("id") == request_id:
                if set(message) != {"id", "result"} or not isinstance(message["result"], Mapping):
                    raise AppServerProtocolError("app-server returned an invalid response")
                return message["result"]
            method = message.get("method")
            if method not in {"configWarning", "warning", "thread/started"}:
                raise AppServerProtocolError(
                    f"unexpected app-server message before response: {method!r}"
                )

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
        return {
            "contentItems": [{"type": "inputText", "text": canonical_bytes(body).decode("utf-8")}],
            "success": result.classification == ToolTerminalClassification.SUCCEEDED,
        }

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
        message: Mapping[str, Any],
    ) -> DurableToolRequest:
        if set(message) != {"method", "id", "params"} or message["method"] != "item/tool/call":
            raise AppServerProtocolError("invalid dynamic-tool request envelope")
        params = message["params"]
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
    ) -> tuple[SessionTerminalClassification, str, str]:
        init_id = f"init-{session_id}"
        thread_request_id = f"thread-{session_id}"
        turn_request_id = f"turn-{session_id}"
        connection.send(initialize_request(init_id))
        self._expect_response(connection, init_id)
        connection.send({"method": "initialized", "params": {}})
        connection.send(thread_start_request(thread_request_id))
        thread_result = self._expect_response(connection, thread_request_id)
        thread = thread_result.get("thread")
        if not isinstance(thread, Mapping):
            raise AppServerProtocolError("thread/start result has no thread")
        thread_id = thread.get("id")
        require_identifier(thread_id, "app-server thread id")

        connection.send(
            turn_start_request(
                turn_request_id,
                thread_id=thread_id,
                prompt=self.mission_prompt,
            )
        )
        turn_result = self._expect_response(connection, turn_request_id)
        turn = turn_result.get("turn")
        if not isinstance(turn, Mapping):
            raise AppServerProtocolError("turn/start result has no turn")
        turn_id = turn.get("id")
        require_identifier(turn_id, "app-server turn id")
        self.session_store.bind_protocol(session_id, thread_id=thread_id, turn_id=turn_id)

        agent_text = bytearray()
        while True:
            message = connection.receive(self.event_timeout_seconds)
            if message is None:
                if connection.returncode not in (None, 0):
                    return (
                        SessionTerminalClassification.PROVIDER_PROCESS_FAILED,
                        f"synthetic/provider process exited {connection.returncode}",
                        agent_text.decode("utf-8", "replace"),
                    )
                raise AppServerProtocolError("app-server ended before turn/completed")
            method = message.get("method")
            if "id" in message and method != "item/tool/call":
                raise AppServerProtocolError("native or unknown server request refused")
            if method == "item/tool/call":
                request = self._parse_tool_call(session_id, message)
                disposition, existing = self.session_store.tool_id_disposition(session_id, request)
                if disposition == ToolIdDisposition.DUPLICATE:
                    self._send_protocol_error(connection, request.rpc_id, "duplicate tool ID refused")
                    return (
                        SessionTerminalClassification.DUPLICATE_TOOL_ID_REFUSED,
                        f"duplicate tool ID refused; original sequence={existing.sequence if existing else 'unknown'}",
                        agent_text.decode("utf-8", "replace"),
                    )
                if disposition == ToolIdDisposition.CONFLICT:
                    self._send_protocol_error(connection, request.rpc_id, "conflicting tool ID refused")
                    return (
                        SessionTerminalClassification.CONFLICTING_TOOL_ID_REFUSED,
                        f"conflicting tool ID refused; original sequence={existing.sequence if existing else 'unknown'}",
                        agent_text.decode("utf-8", "replace"),
                    )
                self.session_store.record_tool_request(request)
                result = self.controller.execute(handle, request)
                self.session_store.record_tool_result(result)
                connection.send({"id": request.rpc_id, "result": self._tool_response(result)})
                if result.classification == ToolTerminalClassification.TIMED_OUT:
                    return (
                        SessionTerminalClassification.TIMED_OUT,
                        "capsule tool exceeded bounded wall time",
                        agent_text.decode("utf-8", "replace"),
                    )
                if result.classification == ToolTerminalClassification.OUTPUT_LIMIT_REFUSED:
                    return (
                        SessionTerminalClassification.OUTPUT_LIMIT_REFUSED,
                        "capsule tool output exceeded its bound",
                        agent_text.decode("utf-8", "replace"),
                    )
                if (
                    result.classification == ToolTerminalClassification.FAILED
                    and (result.exit_code == 125 or not handle.container_alive)
                ):
                    return (
                        SessionTerminalClassification.CAPSULE_FAILED,
                        "capsule process was unavailable during tool execution",
                        agent_text.decode("utf-8", "replace"),
                    )
                continue
            if method in {"item/started", "item/completed"}:
                item_type = self._item_type(message)
                if item_type not in PASSIVE_ITEM_TYPES:
                    return (
                        SessionTerminalClassification.NATIVE_EFFECT_REFUSED,
                        f"native Codex effect item refused: {item_type}",
                        agent_text.decode("utf-8", "replace"),
                    )
                if item_type == "agentMessage" and method == "item/completed":
                    item = message["params"]["item"]
                    text = item.get("text", "")
                    if isinstance(text, str):
                        encoded = text.encode("utf-8")
                        if len(encoded) > AGENT_TEXT_LIMIT:
                            return (
                                SessionTerminalClassification.OUTPUT_LIMIT_REFUSED,
                                "agent message exceeded its bound",
                                agent_text.decode("utf-8", "replace"),
                            )
                        agent_text[:] = encoded
                continue
            if method == "item/agentMessage/delta":
                params = message.get("params")
                delta = params.get("delta") if isinstance(params, Mapping) else None
                if not isinstance(delta, str):
                    raise AppServerProtocolError("agent-message delta is not text")
                agent_text.extend(delta.encode("utf-8"))
                if len(agent_text) > AGENT_TEXT_LIMIT:
                    return (
                        SessionTerminalClassification.OUTPUT_LIMIT_REFUSED,
                        "agent message exceeded its bound",
                        agent_text[:AGENT_TEXT_LIMIT].decode("utf-8", "replace"),
                    )
                continue
            if method == "turn/completed":
                params = message.get("params")
                completed_turn = params.get("turn") if isinstance(params, Mapping) else None
                if not isinstance(completed_turn, Mapping) or completed_turn.get("id") != turn_id:
                    raise AppServerProtocolError("turn/completed does not match the bound turn")
                status = completed_turn.get("status")
                if status == "completed":
                    return (
                        SessionTerminalClassification.COMPLETED,
                        "Codex app-server turn completed through dynamic tools",
                        agent_text.decode("utf-8", "replace"),
                    )
                return (
                    SessionTerminalClassification.PROVIDER_PROCESS_FAILED,
                    f"Codex app-server turn terminal status was {status!r}",
                    agent_text.decode("utf-8", "replace"),
                )
            if method in BENIGN_NOTIFICATION_METHODS:
                continue
            # Includes command/file deltas, turn diffs, approvals, MCP, web,
            # process spawning, shell commands, and unknown future effects.
            raise AppServerProtocolError(f"unrecognized or effectful app-server method: {method!r}")

    def _process_result(
        self,
        classification: SessionTerminalClassification,
        returncode: int | None,
    ) -> ProcessResult:
        timed_out = classification == SessionTerminalClassification.TIMED_OUT
        if timed_out:
            exit_code = None
        elif classification == SessionTerminalClassification.COMPLETED:
            exit_code = 0
        elif returncode not in (None, 0):
            exit_code = returncode
        else:
            exit_code = 1
        return ProcessResult(
            schema_version="admissible_capsule_process_result_v1",
            exit_code=exit_code,
            timed_out=timed_out,
            signal=None,
        ).validated()

    def run(self, workspace: WorkspaceReference) -> ProviderOutput:
        session_id, handle = self._session_for(workspace)
        snapshot = self.session_store.reconstruct(session_id)
        if snapshot.provider_output is not None:
            return snapshot.provider_output
        classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
        detail = "app-server did not start"
        claim_text = ""
        connected = False
        connection: AppServerConnection | None = None
        returncode: int | None = None
        try:
            connection = self.connection_factory.open(session_id)
            connected = True
            self.session_store.record_app_server_process(session_id, connection.process_identity)
            classification, detail, claim_text = self._run_protocol(
                session_id=session_id,
                handle=handle,
                connection=connection,
            )
        except AppServerReceiveTimeout as error:
            classification = SessionTerminalClassification.TIMED_OUT
            detail = str(error)
        except CrashInjected:
            raise
        except (AppServerProtocolError, ValueError, OSError, RuntimeError) as error:
            classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
            detail = str(error)
        except BaseException:
            # Preserve crash semantics: an already durable unpaired request
            # must remain unpaired for evidence-only recovery. Cleanup is still
            # attempted by the caller/finally path, then the crash propagates.
            raise
        finally:
            if connection is not None:
                try:
                    connection.close()
                except (OSError, RuntimeError) as error:
                    classification = SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
                    detail = f"app-server cleanup failed: {error}"
                returncode = connection.returncode

        try:
            observation = self.controller.freeze_output(handle)
        except ValueError as error:
            classification = SessionTerminalClassification.OUTPUT_LIMIT_REFUSED
            detail = f"provider output freeze refused: {error}"
            observation = ByteTreeObservation.create(entries=())
        except (OSError, RuntimeError) as error:
            classification = SessionTerminalClassification.CAPSULE_FAILED
            detail = f"provider output freeze failed: {error}"
            observation = ByteTreeObservation.create(entries=())

        cleanup_evidence = self.controller.cleanup(handle)
        self.session_store.record_cleanup(session_id, cleanup_evidence.to_dict())
        if not cleanup_evidence.cleanup_proven:
            classification = SessionTerminalClassification.CLEANUP_FAILED
            detail = "capsule container, descendants, or disposable workspace cleanup was unconfirmed"

        output = ProviderOutput.create(
            capsule_authority_fingerprint=self.authority.authority_fingerprint,
            workspace=workspace,
            observation=observation,
            process_result=self._process_result(classification, returncode),
            transport_result=TransportResult(
                schema_version="admissible_capsule_transport_result_v1",
                transport_kind="codex_app_server_dynamic_tools_v1",
                connected=connected,
                closed_cleanly=classification == SessionTerminalClassification.COMPLETED,
            ).validated(),
            cleanup_result=cleanup_evidence.provider_cleanup_result(),
            completion_claim=ProviderCompletionClaim(
                schema_version="admissible_capsule_provider_completion_claim_v1",
                claimed_complete=classification == SessionTerminalClassification.COMPLETED,
                claim_text=claim_text[:8192],
            ).validated(),
        )
        self.session_store.freeze_provider_output(session_id, output)
        self.session_store.record_terminal(session_id, classification, detail)
        return output

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
                ),
                processes_reaped=bool(evidence.get("complete_process_tree_reaped")),
            ).validated()
        cleanup_evidence = self.controller.cleanup(handle)
        self.session_store.record_cleanup(session_id, cleanup_evidence.to_dict())
        if snapshot.recorded_terminal_classification is None:
            terminal = (
                SessionTerminalClassification.CLEANUP_FAILED
                if not cleanup_evidence.cleanup_proven
                else SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
            )
            self.session_store.record_terminal(
                session_id,
                terminal,
                "workspace cleaned before a provider output was frozen",
            )
        return cleanup_evidence.provider_cleanup_result()

    def frozen_output_path(self, workspace: WorkspaceReference) -> Path:
        """Concrete handoff to CanonicalIntake; never a control-process path."""

        _session_id, _handle = self._session_for(workspace)
        return self.controller.frozen_output_path(workspace.workspace_id)

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
