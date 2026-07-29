"""Hash-chained durable evidence for host-control capsule sessions.

A tool request is fsynced before the controller is allowed to execute it.  A
result is then appended exactly once and is cryptographically bound to that
request.  Evidence-only reconstruction treats every unpaired request as an
indeterminate effect and therefore as terminal failure; it never promotes the
request to assumed success.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    atomic_json,
    canonical_bytes,
    fingerprint,
    fsync_directory,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    require_strict_int,
)
from admissible.capsule.models import ProviderOutput


SESSION_EVENT_SCHEMA_VERSION = "admissible_host_codex_session_event_v1"
TOOL_REQUEST_SCHEMA_VERSION = "admissible_host_codex_tool_request_v1"
TOOL_RESULT_SCHEMA_VERSION = "admissible_host_codex_tool_result_v1"
ZERO_FINGERPRINT = "0" * 64
MAX_EVENT_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 32 * 1024
MAX_CAPTURE_TEXT_BYTES = 64 * 1024


class ToolTerminalClassification(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_REFUSED = "OUTPUT_LIMIT_REFUSED"


class SessionTerminalClassification(str, Enum):
    COMPLETED = "COMPLETED"
    PROVIDER_PROCESS_FAILED = "PROVIDER_PROCESS_FAILED"
    APP_SERVER_PROTOCOL_FAILED = "APP_SERVER_PROTOCOL_FAILED"
    CAPSULE_FAILED = "CAPSULE_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_REFUSED = "OUTPUT_LIMIT_REFUSED"
    NATIVE_EFFECT_REFUSED = "NATIVE_EFFECT_REFUSED"
    DUPLICATE_TOOL_ID_REFUSED = "DUPLICATE_TOOL_ID_REFUSED"
    CONFLICTING_TOOL_ID_REFUSED = "CONFLICTING_TOOL_ID_REFUSED"
    CRASH_UNPAIRED_REQUEST = "CRASH_UNPAIRED_REQUEST"


class ToolIdDisposition(str, Enum):
    NEW = "NEW"
    DUPLICATE = "DUPLICATE"
    CONFLICT = "CONFLICT"


def _validate_rpc_id(value: Any) -> Any:
    if isinstance(value, bool):
        raise ValueError("JSON-RPC id must not be boolean")
    if isinstance(value, int):
        return require_strict_int(value, "JSON-RPC id", minimum=-(2**53), maximum=2**53)
    return require_nonempty_text(value, "JSON-RPC id", max_bytes=256)


def _validate_json_object(value: Any, label: str, *, max_bytes: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    try:
        encoded = canonical_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} must be canonical JSON") from error
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds its byte bound")
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise ValueError(f"{label} must be an object")
    return decoded


@dataclass(frozen=True)
class DurableToolRequest:
    schema_version: str
    session_id: str
    sequence: int
    rpc_id: int | str
    call_id: str
    thread_id: str
    turn_id: str
    namespace: str
    tool: str
    arguments: Mapping[str, Any]
    request_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        sequence: int,
        rpc_id: int | str,
        call_id: str,
        thread_id: str,
        turn_id: str,
        namespace: str,
        tool: str,
        arguments: Mapping[str, Any],
    ) -> "DurableToolRequest":
        body = {
            "schema_version": TOOL_REQUEST_SCHEMA_VERSION,
            "session_id": session_id,
            "sequence": sequence,
            "rpc_id": rpc_id,
            "call_id": call_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "namespace": namespace,
            "tool": tool,
            "arguments": _validate_json_object(arguments, "tool arguments", max_bytes=MAX_ARGUMENT_BYTES),
        }
        return cls(**body, request_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "rpc_id": self.rpc_id,
            "call_id": self.call_id,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "namespace": self.namespace,
            "tool": self.tool,
            "arguments": dict(self.arguments),
        }

    def validated(self) -> "DurableToolRequest":
        if self.schema_version != TOOL_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported durable tool-request schema")
        require_identifier(self.session_id, "tool request session_id")
        require_strict_int(self.sequence, "tool request sequence", minimum=1, maximum=1_000_000)
        _validate_rpc_id(self.rpc_id)
        require_identifier(self.call_id, "tool call_id")
        require_identifier(self.thread_id, "tool thread_id")
        require_identifier(self.turn_id, "tool turn_id")
        require_identifier(self.namespace, "tool namespace")
        require_identifier(self.tool, "tool name")
        _validate_json_object(self.arguments, "tool arguments", max_bytes=MAX_ARGUMENT_BYTES)
        require_sha256(self.request_fingerprint, "tool request fingerprint")
        if fingerprint(self._body()) != self.request_fingerprint:
            raise ValueError("tool request fingerprint mismatch")
        return self

    @property
    def collision_body(self) -> dict[str, Any]:
        body = self._body()
        del body["sequence"]
        return body

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "request_fingerprint": self.request_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DurableToolRequest":
        require_exact_keys(
            data,
            {
                "schema_version",
                "session_id",
                "sequence",
                "rpc_id",
                "call_id",
                "thread_id",
                "turn_id",
                "namespace",
                "tool",
                "arguments",
                "request_fingerprint",
            },
            "durable tool request",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class DurableToolResult:
    schema_version: str
    session_id: str
    sequence: int
    request_fingerprint: str
    classification: ToolTerminalClassification
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    result_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        request: DurableToolRequest,
        classification: ToolTerminalClassification,
        exit_code: int | None,
        timed_out: bool,
        stdout: str,
        stderr: str,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
    ) -> "DurableToolResult":
        body = {
            "schema_version": TOOL_RESULT_SCHEMA_VERSION,
            "session_id": request.session_id,
            "sequence": request.sequence,
            "request_fingerprint": request.request_fingerprint,
            "classification": classification.value,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }
        return cls(
            schema_version=body["schema_version"],
            session_id=body["session_id"],
            sequence=body["sequence"],
            request_fingerprint=body["request_fingerprint"],
            classification=classification,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            result_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "request_fingerprint": self.request_fingerprint,
            "classification": self.classification.value,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }

    def validated(self) -> "DurableToolResult":
        if self.schema_version != TOOL_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported durable tool-result schema")
        require_identifier(self.session_id, "tool result session_id")
        require_strict_int(self.sequence, "tool result sequence", minimum=1, maximum=1_000_000)
        require_sha256(self.request_fingerprint, "paired request fingerprint")
        if not isinstance(self.classification, ToolTerminalClassification):
            raise ValueError("unknown tool terminal classification")
        if self.exit_code is not None:
            require_strict_int(self.exit_code, "tool exit code", minimum=-(2**31), maximum=2**31 - 1)
        require_bool(self.timed_out, "tool timed_out")
        for label, text in (("tool stdout", self.stdout), ("tool stderr", self.stderr)):
            if not isinstance(text, str) or "\x00" in text:
                raise ValueError(f"{label} must be text without NUL")
            if len(text.encode("utf-8")) > MAX_CAPTURE_TEXT_BYTES:
                raise ValueError(f"{label} exceeds evidence bound")
        require_bool(self.stdout_truncated, "tool stdout_truncated")
        require_bool(self.stderr_truncated, "tool stderr_truncated")
        if self.timed_out != (self.classification == ToolTerminalClassification.TIMED_OUT):
            raise ValueError("tool timeout evidence disagrees with classification")
        require_sha256(self.result_fingerprint, "tool result fingerprint")
        if fingerprint(self._body()) != self.result_fingerprint:
            raise ValueError("tool result fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_fingerprint": self.result_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DurableToolResult":
        require_exact_keys(
            data,
            {
                "schema_version",
                "session_id",
                "sequence",
                "request_fingerprint",
                "classification",
                "exit_code",
                "timed_out",
                "stdout",
                "stderr",
                "stdout_truncated",
                "stderr_truncated",
                "result_fingerprint",
            },
            "durable tool result",
        )
        values = dict(data)
        values["classification"] = ToolTerminalClassification(values["classification"])
        return cls(**values).validated()


@dataclass(frozen=True)
class DurableSessionEvent:
    schema_version: str
    index: int
    session_id: str
    kind: str
    payload: Mapping[str, Any]
    previous_fingerprint: str
    event_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        index: int,
        session_id: str,
        kind: str,
        payload: Mapping[str, Any],
        previous_fingerprint: str,
    ) -> "DurableSessionEvent":
        body = {
            "schema_version": SESSION_EVENT_SCHEMA_VERSION,
            "index": index,
            "session_id": session_id,
            "kind": kind,
            "payload": _validate_json_object(payload, "session event payload", max_bytes=MAX_EVENT_BYTES // 2),
            "previous_fingerprint": previous_fingerprint,
        }
        return cls(**body, event_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "index": self.index,
            "session_id": self.session_id,
            "kind": self.kind,
            "payload": dict(self.payload),
            "previous_fingerprint": self.previous_fingerprint,
        }

    def validated(self) -> "DurableSessionEvent":
        if self.schema_version != SESSION_EVENT_SCHEMA_VERSION:
            raise ValueError("unsupported durable session-event schema")
        require_strict_int(self.index, "session event index", minimum=0, maximum=10_000_000)
        require_identifier(self.session_id, "session event session_id")
        require_identifier(self.kind, "session event kind")
        _validate_json_object(self.payload, "session event payload", max_bytes=MAX_EVENT_BYTES // 2)
        require_sha256(self.previous_fingerprint, "previous event fingerprint")
        require_sha256(self.event_fingerprint, "event fingerprint")
        if fingerprint(self._body()) != self.event_fingerprint:
            raise ValueError("session event fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "event_fingerprint": self.event_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DurableSessionEvent":
        require_exact_keys(
            data,
            {
                "schema_version",
                "index",
                "session_id",
                "kind",
                "payload",
                "previous_fingerprint",
                "event_fingerprint",
            },
            "durable session event",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class ReconstructedCapsuleSession:
    session_id: str
    events: tuple[DurableSessionEvent, ...]
    authority_identity: Mapping[str, Any]
    controller_authority: Mapping[str, Any]
    workspace: Mapping[str, Any]
    app_server_process_identity: Mapping[str, Any] | None
    protocol_binding: Mapping[str, Any] | None
    capsule_process_identity: Mapping[str, Any] | None
    requests: tuple[DurableToolRequest, ...]
    results: tuple[DurableToolResult, ...]
    cleanup: Mapping[str, Any] | None
    provider_output: ProviderOutput | None
    recorded_terminal_classification: SessionTerminalClassification | None
    terminal_detail: str | None

    @property
    def results_by_sequence(self) -> dict[int, DurableToolResult]:
        return {result.sequence: result for result in self.results}

    @property
    def unpaired_requests(self) -> tuple[DurableToolRequest, ...]:
        paired = self.results_by_sequence
        return tuple(request for request in self.requests if request.sequence not in paired)

    @property
    def effective_terminal_classification(self) -> SessionTerminalClassification | None:
        if self.unpaired_requests:
            return SessionTerminalClassification.CRASH_UNPAIRED_REQUEST
        return self.recorded_terminal_classification

    @property
    def next_tool_sequence(self) -> int:
        return len(self.requests) + 1


class DurableCapsuleSessionStore:
    """One append-only, fsynced, hash-chained log per capsule session."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def session_directory(self, session_id: str) -> Path:
        require_identifier(session_id, "session_id")
        return self.root / session_id

    def _log_path(self, session_id: str) -> Path:
        return self.session_directory(session_id) / "evidence.jsonl"

    def _provider_output_path(self, session_id: str) -> Path:
        return self.session_directory(session_id) / "provider-output.json"

    def create_session(
        self,
        *,
        session_id: str,
        authority_identity: Mapping[str, Any],
        controller_authority: Mapping[str, Any],
        workspace: Mapping[str, Any],
    ) -> None:
        directory = self.session_directory(session_id)
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        fsync_directory(self.root)
        self._append(
            session_id,
            "session_created",
            {
                "authority_identity": dict(authority_identity),
                "controller_authority": dict(controller_authority),
                "workspace": dict(workspace),
            },
        )

    def _read_events(self, session_id: str) -> tuple[DurableSessionEvent, ...]:
        path = self._log_path(session_id)
        raw = path.read_bytes()
        if not raw or not raw.endswith(b"\n"):
            raise ValueError("durable session log is empty or has a partial final record")
        events: list[DurableSessionEvent] = []
        previous = ZERO_FINGERPRINT
        for index, line in enumerate(raw.splitlines()):
            if len(line) > MAX_EVENT_BYTES:
                raise ValueError("durable session event exceeds its byte bound")
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError("invalid durable session JSON") from error
            event = DurableSessionEvent.from_dict(decoded)
            if event.index != index:
                raise ValueError("durable session event index discontinuity")
            if event.session_id != session_id:
                raise ValueError("durable session event belongs to another session")
            if event.previous_fingerprint != previous:
                raise ValueError("durable session hash chain mismatch")
            previous = event.event_fingerprint
            events.append(event)
        return tuple(events)

    def _append(self, session_id: str, kind: str, payload: Mapping[str, Any]) -> DurableSessionEvent:
        path = self._log_path(session_id)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, os.fstat(descriptor).st_size)
            if raw and not raw.endswith(b"\n"):
                raise ValueError("cannot append after a partial durable session event")
            lines = raw.splitlines()
            previous = ZERO_FINGERPRINT
            if lines:
                last = DurableSessionEvent.from_dict(json.loads(lines[-1]))
                previous = last.event_fingerprint
            event = DurableSessionEvent.create(
                index=len(lines),
                session_id=session_id,
                kind=kind,
                payload=payload,
                previous_fingerprint=previous,
            )
            encoded = canonical_bytes(event.to_dict()) + b"\n"
            if len(encoded) > MAX_EVENT_BYTES:
                raise ValueError("durable session event exceeds its byte bound")
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
            return event
        finally:
            os.close(descriptor)

    def record_capsule_process(self, session_id: str, identity: Mapping[str, Any]) -> None:
        snapshot = self.reconstruct(session_id)
        if snapshot.capsule_process_identity is not None:
            raise ValueError("capsule process identity is already durable")
        self._append(session_id, "capsule_process_started", {"identity": dict(identity)})

    def record_app_server_process(self, session_id: str, identity: Mapping[str, Any]) -> None:
        snapshot = self.reconstruct(session_id)
        if snapshot.app_server_process_identity is not None:
            raise ValueError("app-server process identity is already durable")
        self._append(session_id, "app_server_process_started", {"identity": dict(identity)})

    def bind_protocol(self, session_id: str, *, thread_id: str, turn_id: str) -> None:
        snapshot = self.reconstruct(session_id)
        if snapshot.protocol_binding is not None:
            raise ValueError("app-server protocol is already bound")
        require_identifier(thread_id, "bound thread_id")
        require_identifier(turn_id, "bound turn_id")
        self._append(session_id, "protocol_bound", {"thread_id": thread_id, "turn_id": turn_id})

    def make_tool_request(
        self,
        session_id: str,
        *,
        rpc_id: int | str,
        call_id: str,
        thread_id: str,
        turn_id: str,
        namespace: str,
        tool: str,
        arguments: Mapping[str, Any],
    ) -> DurableToolRequest:
        snapshot = self.reconstruct(session_id)
        if snapshot.recorded_terminal_classification is not None or snapshot.unpaired_requests:
            raise ValueError("terminal or indeterminate session cannot accept a tool request")
        return DurableToolRequest.create(
            session_id=session_id,
            sequence=snapshot.next_tool_sequence,
            rpc_id=rpc_id,
            call_id=call_id,
            thread_id=thread_id,
            turn_id=turn_id,
            namespace=namespace,
            tool=tool,
            arguments=arguments,
        )

    def tool_id_disposition(
        self, session_id: str, request: DurableToolRequest
    ) -> tuple[ToolIdDisposition, DurableToolRequest | None]:
        snapshot = self.reconstruct(session_id)
        for existing in snapshot.requests:
            if existing.rpc_id == request.rpc_id or existing.call_id == request.call_id:
                if existing.collision_body == request.collision_body:
                    return ToolIdDisposition.DUPLICATE, existing
                return ToolIdDisposition.CONFLICT, existing
        return ToolIdDisposition.NEW, None

    def record_tool_request(self, request: DurableToolRequest) -> None:
        request.validated()
        disposition, _existing = self.tool_id_disposition(request.session_id, request)
        if disposition != ToolIdDisposition.NEW:
            raise ValueError(f"tool request ID is not new: {disposition.value}")
        snapshot = self.reconstruct(request.session_id)
        if request.sequence != snapshot.next_tool_sequence:
            raise ValueError("tool request sequence is not the next durable sequence")
        binding = snapshot.protocol_binding
        if binding is None:
            raise ValueError("tool request arrived before protocol binding")
        if request.thread_id != binding["thread_id"] or request.turn_id != binding["turn_id"]:
            raise ValueError("tool request does not match durable protocol binding")
        self._append(request.session_id, "tool_request", {"request": request.to_dict()})

    def record_tool_result(self, result: DurableToolResult) -> None:
        result.validated()
        snapshot = self.reconstruct(result.session_id)
        request = next((item for item in snapshot.requests if item.sequence == result.sequence), None)
        if request is None:
            raise ValueError("tool result has no durable request")
        if result.request_fingerprint != request.request_fingerprint:
            raise ValueError("tool result is paired with another request")
        if result.sequence in snapshot.results_by_sequence:
            raise ValueError("tool request already has exactly one result")
        self._append(result.session_id, "tool_result", {"result": result.to_dict()})

    def record_cleanup(self, session_id: str, cleanup: Mapping[str, Any]) -> None:
        snapshot = self.reconstruct(session_id)
        if snapshot.cleanup is not None:
            if dict(snapshot.cleanup) != dict(cleanup):
                raise ValueError("conflicting cleanup evidence")
            return
        self._append(session_id, "cleanup_recorded", {"cleanup": dict(cleanup)})

    def freeze_provider_output(self, session_id: str, output: ProviderOutput) -> None:
        output.validated()
        snapshot = self.reconstruct(session_id)
        if snapshot.provider_output is not None:
            if snapshot.provider_output != output:
                raise ValueError("conflicting frozen provider output")
            return
        path = self._provider_output_path(session_id)
        atomic_json(path, output.to_dict(), mode=0o600)
        self._append(
            session_id,
            "provider_output_frozen",
            {
                "file": path.name,
                "output_fingerprint": output.output_fingerprint,
            },
        )

    def record_terminal(
        self,
        session_id: str,
        classification: SessionTerminalClassification,
        detail: str,
    ) -> None:
        snapshot = self.reconstruct(session_id)
        if snapshot.recorded_terminal_classification is not None:
            if (
                snapshot.recorded_terminal_classification != classification
                or snapshot.terminal_detail != detail
            ):
                raise ValueError("conflicting terminal classification")
            return
        require_nonempty_text(detail, "terminal detail", max_bytes=8192)
        self._append(
            session_id,
            "session_terminal",
            {"classification": classification.value, "detail": detail},
        )

    def reconstruct(self, session_id: str) -> ReconstructedCapsuleSession:
        events = self._read_events(session_id)
        if not events or events[0].kind != "session_created":
            raise ValueError("session log does not start with session_created")
        created = events[0].payload
        require_exact_keys(
            created,
            {"authority_identity", "controller_authority", "workspace"},
            "session_created payload",
        )
        app_server_process = None
        protocol_binding = None
        capsule_process = None
        cleanup = None
        provider_output = None
        terminal = None
        terminal_detail = None
        requests: list[DurableToolRequest] = []
        results: list[DurableToolResult] = []
        for event in events[1:]:
            if terminal is not None:
                raise ValueError("durable event appears after terminal classification")
            if event.kind == "capsule_process_started":
                if capsule_process is not None:
                    raise ValueError("duplicate capsule process identity")
                capsule_process = _validate_json_object(
                    event.payload.get("identity"), "capsule process identity", max_bytes=8192
                )
            elif event.kind == "app_server_process_started":
                if app_server_process is not None:
                    raise ValueError("duplicate app-server process identity")
                app_server_process = _validate_json_object(
                    event.payload.get("identity"), "app-server process identity", max_bytes=8192
                )
            elif event.kind == "protocol_bound":
                if protocol_binding is not None:
                    raise ValueError("duplicate protocol binding")
                require_exact_keys(event.payload, {"thread_id", "turn_id"}, "protocol binding")
                require_identifier(event.payload["thread_id"], "bound thread_id")
                require_identifier(event.payload["turn_id"], "bound turn_id")
                protocol_binding = dict(event.payload)
            elif event.kind == "tool_request":
                require_exact_keys(event.payload, {"request"}, "tool_request event")
                request = DurableToolRequest.from_dict(event.payload["request"])
                if request.session_id != session_id or request.sequence != len(requests) + 1:
                    raise ValueError("invalid durable tool request sequence")
                if any(
                    old.rpc_id == request.rpc_id or old.call_id == request.call_id for old in requests
                ):
                    raise ValueError("duplicate tool ID persisted")
                if protocol_binding is None or (
                    request.thread_id != protocol_binding["thread_id"]
                    or request.turn_id != protocol_binding["turn_id"]
                ):
                    raise ValueError("persisted tool request violates protocol binding")
                requests.append(request)
            elif event.kind == "tool_result":
                require_exact_keys(event.payload, {"result"}, "tool_result event")
                result = DurableToolResult.from_dict(event.payload["result"])
                if result.session_id != session_id:
                    raise ValueError("tool result belongs to another session")
                request = next((item for item in requests if item.sequence == result.sequence), None)
                if request is None or result.request_fingerprint != request.request_fingerprint:
                    raise ValueError("tool result is not paired with a durable request")
                if any(item.sequence == result.sequence for item in results):
                    raise ValueError("tool request has more than one result")
                results.append(result)
            elif event.kind == "cleanup_recorded":
                if cleanup is not None:
                    raise ValueError("duplicate cleanup evidence")
                require_exact_keys(event.payload, {"cleanup"}, "cleanup event")
                cleanup = _validate_json_object(event.payload["cleanup"], "cleanup evidence", max_bytes=8192)
            elif event.kind == "provider_output_frozen":
                if provider_output is not None:
                    raise ValueError("duplicate frozen provider output")
                require_exact_keys(
                    event.payload,
                    {"file", "output_fingerprint"},
                    "provider_output_frozen event",
                )
                if event.payload["file"] != "provider-output.json":
                    raise ValueError("unexpected provider output evidence filename")
                require_sha256(event.payload["output_fingerprint"], "frozen output fingerprint")
                output_data = json.loads(self._provider_output_path(session_id).read_bytes())
                provider_output = ProviderOutput.from_dict(output_data)
                if provider_output.output_fingerprint != event.payload["output_fingerprint"]:
                    raise ValueError("frozen ProviderOutput does not match durable event")
            elif event.kind == "session_terminal":
                require_exact_keys(event.payload, {"classification", "detail"}, "terminal event")
                terminal = SessionTerminalClassification(event.payload["classification"])
                terminal_detail = require_nonempty_text(
                    event.payload["detail"], "terminal detail", max_bytes=8192
                )
            else:
                raise ValueError(f"unknown durable session event kind: {event.kind}")
        return ReconstructedCapsuleSession(
            session_id=session_id,
            events=events,
            authority_identity=dict(created["authority_identity"]),
            controller_authority=dict(created["controller_authority"]),
            workspace=dict(created["workspace"]),
            app_server_process_identity=app_server_process,
            protocol_binding=protocol_binding,
            capsule_process_identity=capsule_process,
            requests=tuple(requests),
            results=tuple(results),
            cleanup=cleanup,
            provider_output=provider_output,
            recorded_terminal_classification=terminal,
            terminal_detail=terminal_detail,
        )
