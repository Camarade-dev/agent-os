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
import secrets
import stat
from contextlib import contextmanager
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
    strict_json_loads,
)
from admissible.capsule.models import ProviderOutput
from admissible.capsule.finalizer import (
    DurabilityReceipt,
    FinalizationEvidence,
    FinalizationResult,
)
from admissible.capsule.intake import AcceptedMaterialIdentity
from admissible.capsule.verification import (
    BehaviorResult,
    CheckpointResult,
    require_independent_copies,
)


SESSION_EVENT_SCHEMA_VERSION = "admissible_host_codex_session_event_v1"
TOOL_REQUEST_SCHEMA_VERSION = "admissible_host_codex_tool_request_v1"
TOOL_RESULT_SCHEMA_VERSION = "admissible_host_codex_tool_result_v1"
ZERO_FINGERPRINT = "0" * 64
MAX_EVENT_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 32 * 1024
MAX_CAPTURE_TEXT_BYTES = 64 * 1024
SESSION_ANCHOR_SCHEMA_VERSION = "admissible_host_codex_session_anchor_v1"
SESSION_TAIL_SCHEMA_VERSION = "admissible_host_codex_durable_tail_v1"


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


def _validate_control_terminal_evidence(value: Any) -> dict[str, Any]:
    evidence = _validate_json_object(
        value,
        "control terminal evidence",
        max_bytes=16 * 1024,
    )
    require_exact_keys(
        evidence,
        {
            "protocol_terminal_classification",
            "app_server_exit_code",
            "app_server_exit_normal",
            "app_server_forced",
            "app_server_eof_observed",
            "controller_classification",
        },
        "control terminal evidence",
    )
    if evidence["protocol_terminal_classification"] not in {
        "COMPLETED",
        "FAILED",
        "INTERRUPTED",
        "ERROR",
        "EOF_BEFORE_TERMINAL",
        "PROTOCOL_REFUSED",
        "TIMED_OUT",
    }:
        raise ValueError("unknown protocol terminal classification")
    exit_code = evidence["app_server_exit_code"]
    if exit_code is not None:
        require_strict_int(
            exit_code,
            "app-server exit code",
            minimum=-(2**31),
            maximum=2**31 - 1,
        )
    normal = require_bool(
        evidence["app_server_exit_normal"],
        "app-server normal-exit truth",
    )
    forced = require_bool(
        evidence["app_server_forced"],
        "app-server forced-exit truth",
    )
    require_bool(
        evidence["app_server_eof_observed"],
        "app-server EOF truth",
    )
    if normal and (forced or exit_code is None or exit_code < 0):
        raise ValueError("normal app-server exit truth is contradictory")
    if evidence["controller_classification"] not in {
        item.value for item in SessionTerminalClassification
    }:
        raise ValueError("unknown controller terminal classification")
    return evidence


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
    controller_session_id: str
    capsule_handle: str
    mission_authority_fingerprint: str
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
        controller_session_id: str | None = None,
        capsule_handle: str | None = None,
        mission_authority_fingerprint: str | None = None,
    ) -> "DurableToolRequest":
        body = {
            "schema_version": TOOL_REQUEST_SCHEMA_VERSION,
            "session_id": session_id,
            "controller_session_id": controller_session_id or session_id,
            "capsule_handle": capsule_handle or session_id,
            "mission_authority_fingerprint": (
                mission_authority_fingerprint
                or fingerprint({"legacy_request_session": session_id})
            ),
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
            "controller_session_id": self.controller_session_id,
            "capsule_handle": self.capsule_handle,
            "mission_authority_fingerprint": self.mission_authority_fingerprint,
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
        require_identifier(self.controller_session_id, "tool request controller_session_id")
        require_identifier(self.capsule_handle, "tool request capsule_handle")
        require_sha256(
            self.mission_authority_fingerprint,
            "tool request mission authority",
        )
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
                "controller_session_id",
                "capsule_handle",
                "mission_authority_fingerprint",
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
    effect_executions: tuple[Mapping[str, Any], ...]
    results: tuple[DurableToolResult, ...]
    control_terminal: Mapping[str, Any] | None
    cleanup: Mapping[str, Any] | None
    boundary_terminal: Mapping[str, Any] | None
    provider_output: ProviderOutput | None
    downstream_handoff: Mapping[str, Any] | None
    accepted_material: AcceptedMaterialIdentity | None
    checkpoint_result: CheckpointResult | None
    behavior_result: BehaviorResult | None
    finalization_evidence: FinalizationEvidence | None
    durability_receipt: DurabilityReceipt | None
    finalization_result: FinalizationResult | None
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

    @property
    def journal_tail_identity(self) -> Mapping[str, Any]:
        last = self.events[-1]
        return {
            "event_index": last.index,
            "event_fingerprint": last.event_fingerprint,
        }


class DurableCapsuleSessionStore:
    """One append-only, fsynced, hash-chained log per capsule session."""

    def __init__(
        self,
        root: Path,
        *,
        trusted_anchor_root: Path | None = None,
        trusted_witness_store: Any | None = None,
    ):
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("session journal root must be absolute without '..'")
        _reject_existing_symlink_components(root, "session journal root")
        self.root = root
        root_created = not self.root.exists()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _reject_existing_symlink_components(self.root, "session journal root")
        if root_created:
            fsync_directory(self.root.parent)
        self.trusted_anchor_root = (
            trusted_anchor_root
            if trusted_anchor_root is not None
            else root.parent / f"{root.name}.trusted-authority"
        )
        if (
            not self.trusted_anchor_root.is_absolute()
            or ".." in self.trusted_anchor_root.parts
        ):
            raise ValueError("trusted anchor root must be absolute without '..'")
        _reject_existing_symlink_components(
            self.trusted_anchor_root,
            "trusted anchor root",
        )
        if self.trusted_anchor_root == self.root or self.trusted_anchor_root.is_relative_to(self.root):
            raise ValueError("trusted session-authority anchors must be external to mutable logs")
        self._anchors = self.trusted_anchor_root / "anchors"
        self._tails = self.trusted_anchor_root / "tails"
        self._locks = self.trusted_anchor_root / "locks"
        for directory in (self.trusted_anchor_root, self._anchors, self._tails, self._locks):
            created = not directory.exists()
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            _reject_existing_symlink_components(directory, "trusted journal directory")
            if created:
                fsync_directory(directory.parent)
        self._witness_store_reference_path = (
            self.trusted_anchor_root / "codex-witness-store-reference.json"
        )
        self.trusted_witness_store = self._bind_trusted_witness_store(
            trusted_witness_store
        )

    def _bind_trusted_witness_store(self, supplied: Any | None):
        """Seal or reload the witness-store reference outside mutable logs."""

        from admissible.capsule.serialization_witness import (
            TrustedSerializationWitnessStore,
            trusted_witness_verifier_identity,
        )

        if supplied is not None and not isinstance(
            supplied, TrustedSerializationWitnessStore
        ):
            raise ValueError("trusted witness store has the wrong type")
        if supplied is not None:
            reference = dict(supplied.anchor_reference())
            if self._witness_store_reference_path.exists():
                existing = strict_json_loads(
                    self._witness_store_reference_path.read_bytes(),
                    label="trusted witness-store reference",
                )
                if existing != reference:
                    raise ValueError(
                        "session trust root is already bound to another witness store"
                    )
            else:
                descriptor = os.open(
                    self._witness_store_reference_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    encoded = canonical_bytes(reference)
                    offset = 0
                    while offset < len(encoded):
                        offset += os.write(descriptor, encoded[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                fsync_directory(self.trusted_anchor_root)
            return supplied
        if not self._witness_store_reference_path.exists():
            return None
        reference = strict_json_loads(
            self._witness_store_reference_path.read_bytes(),
            label="trusted witness-store reference",
        )
        require_exact_keys(
            reference,
            {
                "schema_version",
                "canonical_root",
                "canonical_trusted_anchor_root",
                "store_root_identity",
                "trusted_anchor_root_identity",
                "store_anchor_fingerprint",
                "trusted_verifier_identity",
                "reference_identity",
            },
            "trusted witness-store reference",
        )
        body = {
            key: value for key, value in reference.items()
            if key != "reference_identity"
        }
        if (
            reference["schema_version"]
            != "admissible_codex_witness_store_reference_v1"
            or fingerprint(body) != reference["reference_identity"]
            or reference["trusted_verifier_identity"]
            != trusted_witness_verifier_identity()
        ):
            raise ValueError("trusted witness-store reference is invalid")
        candidate = TrustedSerializationWitnessStore(
            Path(reference["canonical_root"]),
            trusted_anchor_root=Path(
                reference["canonical_trusted_anchor_root"]
            ),
        )
        if dict(candidate.anchor_reference()) != dict(reference):
            raise ValueError("trusted witness-store reference changed")
        return candidate

    def session_directory(self, session_id: str) -> Path:
        require_identifier(session_id, "session_id")
        return self.root / session_id

    def _log_path(self, session_id: str) -> Path:
        return self.session_directory(session_id) / "evidence.jsonl"

    def _provider_output_path(self, session_id: str) -> Path:
        return self.session_directory(session_id) / "provider-output.json"

    def _anchor_path(self, session_id: str) -> Path:
        return self._anchors / f"{session_id}.json"

    def _tail_path(self, session_id: str) -> Path:
        return self._tails / f"{session_id}.json"

    @contextmanager
    def _writer_lock(self, session_id: str):
        path = self._locks / f"{session_id}.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_anchor(self, session_id: str) -> Mapping[str, Any]:
        value = strict_json_loads(
            self._anchor_path(session_id).read_bytes(),
            label="trusted session-authority anchor",
        )
        require_exact_keys(
            value,
            {
                "schema_version",
                "session_id",
                "authority_identity",
                "controller_authority",
                "workspace",
                "nonce",
                "anchor_fingerprint",
            },
            "trusted session-authority anchor",
        )
        if value["schema_version"] != SESSION_ANCHOR_SCHEMA_VERSION:
            raise ValueError("unsupported trusted session-authority anchor")
        if value["session_id"] != session_id:
            raise ValueError("trusted anchor belongs to another session")
        require_sha256(value["nonce"], "trusted anchor nonce")
        require_sha256(value["anchor_fingerprint"], "trusted anchor fingerprint")
        body = {key: item for key, item in value.items() if key != "anchor_fingerprint"}
        if fingerprint(body) != value["anchor_fingerprint"]:
            raise ValueError("trusted session-authority anchor fingerprint mismatch")
        return value

    def _publish_tail(
        self,
        session_id: str,
        *,
        event: DurableSessionEvent,
        log_size: int,
        anchor_fingerprint: str,
    ) -> None:
        body = {
            "schema_version": SESSION_TAIL_SCHEMA_VERSION,
            "session_id": session_id,
            "anchor_fingerprint": anchor_fingerprint,
            "event_index": event.index,
            "event_fingerprint": event.event_fingerprint,
            "log_size": log_size,
        }
        atomic_json(
            self._tail_path(session_id),
            {**body, "tail_fingerprint": fingerprint(body)},
            mode=0o600,
        )

    def _read_tail(self, session_id: str) -> Mapping[str, Any]:
        value = strict_json_loads(
            self._tail_path(session_id).read_bytes(),
            label="durable session tail",
        )
        require_exact_keys(
            value,
            {
                "schema_version",
                "session_id",
                "anchor_fingerprint",
                "event_index",
                "event_fingerprint",
                "log_size",
                "tail_fingerprint",
            },
            "durable session tail",
        )
        if value["schema_version"] != SESSION_TAIL_SCHEMA_VERSION:
            raise ValueError("unsupported durable session tail")
        if value["session_id"] != session_id:
            raise ValueError("durable tail belongs to another session")
        require_sha256(value["anchor_fingerprint"], "tail anchor fingerprint")
        require_sha256(value["event_fingerprint"], "tail event fingerprint")
        require_sha256(value["tail_fingerprint"], "durable tail fingerprint")
        require_strict_int(value["event_index"], "tail event index", minimum=0, maximum=10_000_000)
        require_strict_int(value["log_size"], "tail log size", minimum=1, maximum=2**63 - 1)
        body = {key: item for key, item in value.items() if key != "tail_fingerprint"}
        if fingerprint(body) != value["tail_fingerprint"]:
            raise ValueError("durable session tail fingerprint mismatch")
        return value

    def create_session(
        self,
        *,
        session_id: str,
        authority_identity: Mapping[str, Any],
        controller_authority: Mapping[str, Any],
        workspace: Mapping[str, Any],
    ) -> None:
        with self._writer_lock(session_id):
            body = {
                "schema_version": SESSION_ANCHOR_SCHEMA_VERSION,
                "session_id": session_id,
                "authority_identity": dict(authority_identity),
                "controller_authority": dict(controller_authority),
                "workspace": dict(workspace),
                "nonce": secrets.token_hex(32),
            }
            anchor = {**body, "anchor_fingerprint": fingerprint(body)}
            anchor_path = self._anchor_path(session_id)
            descriptor = os.open(anchor_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                encoded = canonical_bytes(anchor)
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(self._anchors)
            directory = self.session_directory(session_id)
            try:
                directory.mkdir(parents=True, exist_ok=False, mode=0o700)
                fsync_directory(self.root)
                self._append_locked(
                    session_id,
                    "session_created",
                    {
                        "anchor_fingerprint": anchor["anchor_fingerprint"],
                        "authority_identity": dict(authority_identity),
                        "controller_authority": dict(controller_authority),
                        "workspace": dict(workspace),
                    },
                )
            except BaseException:
                # The trusted anchor intentionally survives a failed mutable-log
                # creation; reuse/substitution of this session id is refused.
                raise

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
                decoded = strict_json_loads(line, label="durable session JSON")
            except ValueError as error:
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
        anchor = self._read_anchor(session_id)
        tail = self._read_tail(session_id)
        last = events[-1]
        if (
            tail["anchor_fingerprint"] != anchor["anchor_fingerprint"]
            or tail["event_index"] != last.index
            or tail["event_fingerprint"] != last.event_fingerprint
            or tail["log_size"] != len(raw)
        ):
            raise ValueError("mutable journal does not match its externally durable tail")
        return tuple(events)

    def _append(self, session_id: str, kind: str, payload: Mapping[str, Any]) -> DurableSessionEvent:
        with self._writer_lock(session_id):
            return self._append_locked(session_id, kind, payload)

    def _append_locked(
        self,
        session_id: str,
        kind: str,
        payload: Mapping[str, Any],
    ) -> DurableSessionEvent:
        path = self._log_path(session_id)
        existed = path.exists()
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, os.fstat(descriptor).st_size)
            if raw and not raw.endswith(b"\n"):
                raise ValueError("cannot append after a partial durable session event")
            lines = raw.splitlines()
            previous = ZERO_FINGERPRINT
            if lines:
                validated_events: list[DurableSessionEvent] = []
                for index, line in enumerate(lines):
                    if len(line) > MAX_EVENT_BYTES:
                        raise ValueError("durable session event exceeds its byte bound")
                    event = DurableSessionEvent.from_dict(
                        strict_json_loads(line, label="durable session JSON")
                    )
                    if event.index != index:
                        raise ValueError("cannot append after a journal index discontinuity")
                    if event.session_id != session_id:
                        raise ValueError("cannot append to another session's journal")
                    if event.previous_fingerprint != previous:
                        raise ValueError("cannot append after a journal hash-chain mismatch")
                    previous = event.event_fingerprint
                    validated_events.append(event)
                anchor = self._read_anchor(session_id)
                tail = self._read_tail(session_id)
                last = validated_events[-1]
                if (
                    tail["anchor_fingerprint"] != anchor["anchor_fingerprint"]
                    or tail["event_index"] != last.index
                    or tail["event_fingerprint"] != last.event_fingerprint
                    or tail["log_size"] != len(raw)
                ):
                    raise ValueError("cannot append after a substituted or unanchored journal tail")
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
            if not existed:
                fsync_directory(path.parent)
            log_size = len(raw) + len(encoded)
            anchor = self._read_anchor(session_id)
            self._publish_tail(
                session_id,
                event=event,
                log_size=log_size,
                anchor_fingerprint=anchor["anchor_fingerprint"],
            )
            return event
        finally:
            os.close(descriptor)

    def record_capsule_process(self, session_id: str, identity: Mapping[str, Any]) -> None:
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.capsule_process_identity is not None:
                raise ValueError("capsule process identity is already durable")
            self._append_locked(
                session_id,
                "capsule_process_started",
                {"identity": dict(identity)},
            )

    def record_app_server_process(self, session_id: str, identity: Mapping[str, Any]) -> None:
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.app_server_process_identity is not None:
                raise ValueError("app-server process identity is already durable")
            self._append_locked(
                session_id,
                "app_server_process_started",
                {"identity": dict(identity)},
            )

    def bind_protocol(
        self,
        session_id: str,
        *,
        app_server_session_id: str,
        thread_id: str,
        turn_id: str,
    ) -> None:
        require_identifier(app_server_session_id, "bound app-server session_id")
        require_identifier(thread_id, "bound thread_id")
        require_identifier(turn_id, "bound turn_id")
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.protocol_binding is not None:
                raise ValueError("app-server protocol is already bound")
            self._append_locked(
                session_id,
                "protocol_bound",
                {
                    "app_server_session_id": app_server_session_id,
                    "thread_id": thread_id,
                    "turn_id": turn_id,
                },
            )

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
        controller_session_id: str | None = None,
        capsule_handle: str | None = None,
        mission_authority_fingerprint: str | None = None,
    ) -> DurableToolRequest:
        snapshot = self.reconstruct(session_id)
        if (
            snapshot.control_terminal is not None
            or snapshot.cleanup is not None
            or snapshot.provider_output is not None
            or snapshot.recorded_terminal_classification is not None
            or snapshot.unpaired_requests
        ):
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
            controller_session_id=controller_session_id,
            capsule_handle=capsule_handle,
            mission_authority_fingerprint=mission_authority_fingerprint,
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
        with self._writer_lock(request.session_id):
            snapshot = self.reconstruct(request.session_id)
            if (
                snapshot.control_terminal is not None
                or snapshot.cleanup is not None
                or snapshot.provider_output is not None
                or snapshot.recorded_terminal_classification is not None
            ):
                raise ValueError("tool request after control terminal state refused")
            for existing in snapshot.requests:
                if existing.rpc_id == request.rpc_id or existing.call_id == request.call_id:
                    disposition = (
                        ToolIdDisposition.DUPLICATE
                        if existing.collision_body == request.collision_body
                        else ToolIdDisposition.CONFLICT
                    )
                    raise ValueError(f"tool request ID is not new: {disposition.value}")
            if request.sequence != snapshot.next_tool_sequence:
                raise ValueError("tool request sequence is not the next durable sequence")
            binding = snapshot.protocol_binding
            if binding is None:
                raise ValueError("tool request arrived before protocol binding")
            if request.thread_id != binding["thread_id"] or request.turn_id != binding["turn_id"]:
                raise ValueError("tool request does not match durable protocol binding")
            self._append_locked(
                request.session_id,
                "tool_request",
                {"request": request.to_dict()},
            )

    def record_tool_result(self, result: DurableToolResult) -> None:
        result.validated()
        with self._writer_lock(result.session_id):
            snapshot = self.reconstruct(result.session_id)
            if snapshot.control_terminal is not None:
                raise ValueError("tool result after control terminal state refused")
            request = next((item for item in snapshot.requests if item.sequence == result.sequence), None)
            if request is None:
                raise ValueError("tool result has no durable request")
            if result.request_fingerprint != request.request_fingerprint:
                raise ValueError("tool result is paired with another request")
            if result.sequence in snapshot.results_by_sequence:
                raise ValueError("tool request already has exactly one result")
            if (
                "backend_execution_authority" in snapshot.authority_identity
                and not any(
                    item["sequence"] == result.sequence
                    for item in snapshot.effect_executions
                )
            ):
                raise ValueError("tool result cannot precede durable effect execution")
            self._append_locked(
                result.session_id,
                "tool_result",
                {"result": result.to_dict()},
            )

    def record_effect_execution_started(self, request: DurableToolRequest) -> None:
        """Durably mark the request/effect boundary before calling the controller."""

        request.validated()
        with self._writer_lock(request.session_id):
            snapshot = self.reconstruct(request.session_id)
            durable = next(
                (item for item in snapshot.requests if item.sequence == request.sequence),
                None,
            )
            if durable != request:
                raise ValueError("effect execution has no exact durable request")
            if any(
                item["sequence"] == request.sequence
                for item in snapshot.effect_executions
            ):
                raise ValueError("effect execution is already durable")
            if (
                snapshot.control_terminal is not None
                or snapshot.cleanup is not None
                or snapshot.provider_output is not None
                or snapshot.recorded_terminal_classification is not None
            ):
                raise ValueError("effect execution after terminal state refused")
            self._append_locked(
                request.session_id,
                "effect_execution_started",
                {
                    "sequence": request.sequence,
                    "request_fingerprint": request.request_fingerprint,
                    "controller_session_id": request.controller_session_id,
                    "capsule_handle": request.capsule_handle,
                    "mission_authority_fingerprint": request.mission_authority_fingerprint,
                },
            )

    def record_control_terminal(
        self,
        session_id: str,
        evidence: Mapping[str, Any],
    ) -> None:
        """Record protocol/process closure truth before capsule freeze/cleanup."""

        validated = _validate_control_terminal_evidence(evidence)
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.control_terminal is not None:
                if dict(snapshot.control_terminal) != validated:
                    raise ValueError("conflicting control terminal evidence")
                return
            self._append_locked(
                session_id,
                "control_process_terminal",
                {"evidence": validated},
            )

    def record_cleanup(self, session_id: str, cleanup: Mapping[str, Any]) -> None:
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.cleanup is not None:
                if dict(snapshot.cleanup) != dict(cleanup):
                    raise ValueError("conflicting cleanup evidence")
                return
            if (
                "backend_execution_authority" in snapshot.authority_identity
                and snapshot.control_terminal is None
            ):
                raise ValueError("capsule cleanup cannot precede control-process terminal truth")
            self._append_locked(session_id, "cleanup_recorded", {"cleanup": dict(cleanup)})

    def record_boundary_terminal(
        self,
        session_id: str,
        evidence: Mapping[str, Any],
    ) -> None:
        require_exact_keys(
            evidence,
            {
                "os_boundary_authority_fingerprint",
                "capsule_broker_terminal_fingerprint",
                "boundary_terminal_fingerprint",
                "production_complete",
            },
            "boundary terminal evidence",
        )
        for key in (
            "os_boundary_authority_fingerprint",
            "capsule_broker_terminal_fingerprint",
            "boundary_terminal_fingerprint",
        ):
            require_sha256(evidence[key], key)
        require_bool(evidence["production_complete"], "production boundary complete")
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.boundary_terminal is not None:
                if dict(snapshot.boundary_terminal) != dict(evidence):
                    raise ValueError("conflicting boundary terminal evidence")
                return
            if snapshot.cleanup is None or snapshot.provider_output is not None:
                raise ValueError(
                    "boundary terminal must follow cleanup and precede ProviderOutput"
                )
            self._append_locked(
                session_id,
                "boundary_terminal_recorded",
                {"evidence": dict(evidence)},
            )

    def freeze_provider_output(self, session_id: str, output: ProviderOutput) -> None:
        output.validated()
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.provider_output is not None:
                if snapshot.provider_output != output:
                    raise ValueError("conflicting frozen provider output")
                return
            if snapshot.cleanup is None:
                raise ValueError("ProviderOutput cannot be frozen before capsule cleanup")
            path = self._provider_output_path(session_id)
            atomic_json(path, output.to_dict(), mode=0o600)
            self._append_locked(
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
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(
                session_id,
                _allow_preterminal_provider_output=True,
            )
            if snapshot.recorded_terminal_classification is not None:
                if (
                    snapshot.recorded_terminal_classification != classification
                    or snapshot.terminal_detail != detail
                ):
                    raise ValueError("conflicting terminal classification")
                return
            require_nonempty_text(detail, "terminal detail", max_bytes=8192)
            if snapshot.cleanup is None or snapshot.provider_output is None:
                raise ValueError("session terminal requires durable cleanup and ProviderOutput")
            if snapshot.unpaired_requests:
                raise ValueError("session terminal cannot hide an unpaired effect request")
            if (
                classification == SessionTerminalClassification.COMPLETED
                and not snapshot.provider_output.cleanup_result.cleanup_proven
            ):
                raise ValueError("COMPLETED requires proven cleanup")
            self._append_locked(
                session_id,
                "session_terminal",
                {"classification": classification.value, "detail": detail},
            )

    def record_downstream_handoff(
        self,
        session_id: str,
        *,
        frozen_workspace_fingerprint: str,
    ) -> None:
        require_sha256(frozen_workspace_fingerprint, "frozen workspace fingerprint")
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.downstream_handoff is not None:
                if (
                    snapshot.downstream_handoff["frozen_workspace_fingerprint"]
                    != frozen_workspace_fingerprint
                ):
                    raise ValueError("conflicting downstream handoff")
                return
            if (
                snapshot.recorded_terminal_classification is None
                or snapshot.provider_output is None
                or snapshot.cleanup is None
            ):
                raise ValueError("downstream handoff requires terminal frozen provider evidence")
            self._append_locked(
                session_id,
                "downstream_handoff",
                {
                    "frozen_workspace_fingerprint": frozen_workspace_fingerprint,
                    "provider_output_fingerprint": snapshot.provider_output.output_fingerprint,
                    "terminal_event_fingerprint": snapshot.events[-1].event_fingerprint,
                },
            )

    def record_accepted_material(
        self,
        session_id: str,
        accepted_material: AcceptedMaterialIdentity,
    ) -> None:
        accepted_material.validated()
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.accepted_material is not None:
                if snapshot.accepted_material != accepted_material:
                    raise ValueError("conflicting accepted-material identity")
                return
            if snapshot.provider_output is None or snapshot.recorded_terminal_classification is None:
                raise ValueError("accepted material cannot precede frozen terminal provider evidence")
            self._append_locked(
                session_id,
                "accepted_material_bound",
                {"accepted_material": accepted_material.to_dict()},
            )

    def record_checkpoint_result(self, session_id: str, result: CheckpointResult) -> None:
        result.validated()
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.checkpoint_result is not None:
                if snapshot.checkpoint_result != result:
                    raise ValueError("conflicting checkpoint evidence")
                return
            if (
                snapshot.accepted_material is None
                or result.accepted_material != snapshot.accepted_material
            ):
                raise ValueError("checkpoint evidence is bound to different accepted material")
            self._append_locked(
                session_id,
                "checkpoint_verified",
                {"checkpoint_result": result.to_dict()},
            )

    def record_behavior_result(self, session_id: str, result: BehaviorResult) -> None:
        result.validated()
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.behavior_result is not None:
                if snapshot.behavior_result != result:
                    raise ValueError("conflicting behavior evidence")
                return
            if (
                snapshot.accepted_material is None
                or result.accepted_material != snapshot.accepted_material
            ):
                raise ValueError("behavior evidence is bound to different accepted material")
            if snapshot.checkpoint_result is None or not snapshot.checkpoint_result.passed:
                raise ValueError("behavior evidence requires checkpoint PASS")
            require_independent_copies(snapshot.checkpoint_result.copy, result.copy)
            self._append_locked(
                session_id,
                "behavior_verified",
                {"behavior_result": result.to_dict()},
            )

    def record_finalization_prepared(
        self,
        session_id: str,
        evidence: FinalizationEvidence,
        receipt: DurabilityReceipt,
    ) -> None:
        evidence.validated()
        receipt.verify(evidence)
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.finalization_evidence is not None:
                if (
                    snapshot.finalization_evidence != evidence
                    or snapshot.durability_receipt != receipt
                ):
                    raise ValueError("conflicting finalization preparation evidence")
                return
            if (
                snapshot.accepted_material is None
                or evidence.accepted_material != snapshot.accepted_material
            ):
                raise ValueError("finalization preparation is bound to different accepted material")
            if snapshot.behavior_result is None or not snapshot.behavior_result.passed:
                raise ValueError("finalization preparation requires behavioral PASS")
            self._append_locked(
                session_id,
                "finalization_prepared",
                {
                    "finalization_evidence": evidence.to_dict(),
                    "durability_receipt": receipt.to_dict(),
                },
            )

    def record_finalization_result(self, session_id: str, result: FinalizationResult) -> None:
        result.validated()
        with self._writer_lock(session_id):
            snapshot = self.reconstruct(session_id)
            if snapshot.finalization_result is not None:
                if snapshot.finalization_result != result:
                    raise ValueError("conflicting finalization result evidence")
                return
            if (
                snapshot.finalization_evidence is None
                or snapshot.durability_receipt is None
                or result.durable_evidence != snapshot.finalization_evidence
                or result.durability_receipt != snapshot.durability_receipt
                or result.accepted_material != snapshot.accepted_material
            ):
                raise ValueError("finalization result differs from durable session authorization")
            self._append_locked(
                session_id,
                "finalization_completed",
                {"finalization_result": result.to_dict()},
            )

    def reconstruct(
        self,
        session_id: str,
        *,
        _allow_preterminal_provider_output: bool = False,
    ) -> ReconstructedCapsuleSession:
        events = self._read_events(session_id)
        if not events or events[0].kind != "session_created":
            raise ValueError("session log does not start with session_created")
        created = events[0].payload
        require_exact_keys(
            created,
            {
                "anchor_fingerprint",
                "authority_identity",
                "controller_authority",
                "workspace",
            },
            "session_created payload",
        )
        anchor = self._read_anchor(session_id)
        if (
            created["anchor_fingerprint"] != anchor["anchor_fingerprint"]
            or dict(created["authority_identity"]) != dict(anchor["authority_identity"])
            or dict(created["controller_authority"]) != dict(anchor["controller_authority"])
            or dict(created["workspace"]) != dict(anchor["workspace"])
        ):
            raise ValueError("session creation differs from its external trusted anchor")
        app_server_process = None
        protocol_binding = None
        capsule_process = None
        control_terminal = None
        cleanup = None
        boundary_terminal = None
        provider_output = None
        downstream_handoff = None
        accepted_material = None
        checkpoint_result = None
        behavior_result = None
        finalization_evidence = None
        durability_receipt = None
        finalization_result = None
        terminal = None
        terminal_detail = None
        requests: list[DurableToolRequest] = []
        effect_executions: list[Mapping[str, Any]] = []
        results: list[DurableToolResult] = []
        for event in events[1:]:
            if terminal is not None and event.kind not in {
                "accepted_material_bound",
                "checkpoint_verified",
                "behavior_verified",
                "finalization_prepared",
                "finalization_completed",
                "downstream_handoff",
            }:
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
                require_exact_keys(
                    event.payload,
                    {"app_server_session_id", "thread_id", "turn_id"},
                    "protocol binding",
                )
                require_identifier(
                    event.payload["app_server_session_id"],
                    "bound app-server session_id",
                )
                require_identifier(event.payload["thread_id"], "bound thread_id")
                require_identifier(event.payload["turn_id"], "bound turn_id")
                protocol_binding = dict(event.payload)
            elif event.kind == "tool_request":
                require_exact_keys(event.payload, {"request"}, "tool_request event")
                if control_terminal is not None:
                    raise ValueError("tool request appears after control terminal evidence")
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
            elif event.kind == "effect_execution_started":
                if control_terminal is not None:
                    raise ValueError("effect execution appears after control terminal evidence")
                require_exact_keys(
                    event.payload,
                    {
                        "sequence",
                        "request_fingerprint",
                        "controller_session_id",
                        "capsule_handle",
                        "mission_authority_fingerprint",
                    },
                    "effect execution event",
                )
                sequence = event.payload["sequence"]
                request = next(
                    (item for item in requests if item.sequence == sequence),
                    None,
                )
                if request is None:
                    raise ValueError("effect execution precedes its durable request")
                if (
                    event.payload["request_fingerprint"] != request.request_fingerprint
                    or event.payload["controller_session_id"] != request.controller_session_id
                    or event.payload["capsule_handle"] != request.capsule_handle
                    or event.payload["mission_authority_fingerprint"]
                    != request.mission_authority_fingerprint
                ):
                    raise ValueError("effect execution identity differs from its request")
                if any(item["sequence"] == sequence for item in effect_executions):
                    raise ValueError("duplicate effect execution record")
                effect_executions.append(dict(event.payload))
            elif event.kind == "tool_result":
                require_exact_keys(event.payload, {"result"}, "tool_result event")
                if control_terminal is not None:
                    raise ValueError("tool result appears after control terminal evidence")
                result = DurableToolResult.from_dict(event.payload["result"])
                if result.session_id != session_id:
                    raise ValueError("tool result belongs to another session")
                request = next((item for item in requests if item.sequence == result.sequence), None)
                if request is None or result.request_fingerprint != request.request_fingerprint:
                    raise ValueError("tool result is not paired with a durable request")
                if any(item.sequence == result.sequence for item in results):
                    raise ValueError("tool request has more than one result")
                if (
                    "backend_execution_authority" in created["authority_identity"]
                    and not any(
                        item["sequence"] == result.sequence
                        for item in effect_executions
                    )
                ):
                    raise ValueError("tool result precedes effect execution")
                results.append(result)
            elif event.kind == "control_process_terminal":
                if control_terminal is not None:
                    raise ValueError("duplicate control terminal evidence")
                require_exact_keys(
                    event.payload,
                    {"evidence"},
                    "control process terminal event",
                )
                control_terminal = _validate_control_terminal_evidence(
                    event.payload["evidence"]
                )
            elif event.kind == "cleanup_recorded":
                if cleanup is not None:
                    raise ValueError("duplicate cleanup evidence")
                require_exact_keys(event.payload, {"cleanup"}, "cleanup event")
                if (
                    "backend_execution_authority" in created["authority_identity"]
                    and control_terminal is None
                ):
                    raise ValueError("cleanup precedes control terminal evidence")
                cleanup = _validate_json_object(event.payload["cleanup"], "cleanup evidence", max_bytes=8192)
            elif event.kind == "boundary_terminal_recorded":
                if boundary_terminal is not None:
                    raise ValueError("duplicate boundary terminal evidence")
                require_exact_keys(
                    event.payload,
                    {"evidence"},
                    "boundary terminal event",
                )
                evidence = _validate_json_object(
                    event.payload["evidence"],
                    "boundary terminal evidence",
                    max_bytes=8192,
                )
                require_exact_keys(
                    evidence,
                    {
                        "os_boundary_authority_fingerprint",
                        "capsule_broker_terminal_fingerprint",
                        "boundary_terminal_fingerprint",
                        "production_complete",
                    },
                    "boundary terminal evidence",
                )
                for key in (
                    "os_boundary_authority_fingerprint",
                    "capsule_broker_terminal_fingerprint",
                    "boundary_terminal_fingerprint",
                ):
                    require_sha256(evidence[key], key)
                require_bool(
                    evidence["production_complete"],
                    "production boundary complete",
                )
                if cleanup is None:
                    raise ValueError("boundary terminal precedes cleanup evidence")
                boundary_terminal = evidence
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
                if cleanup is None:
                    raise ValueError("ProviderOutput was frozen before cleanup evidence")
                if event.index == 0 or events[event.index - 1].kind not in {
                    "cleanup_recorded",
                    "boundary_terminal_recorded",
                }:
                    raise ValueError(
                        "ProviderOutput is not immediately bound to terminal evidence"
                    )
                output_data = strict_json_loads(
                    self._provider_output_path(session_id).read_bytes(),
                    label="frozen ProviderOutput JSON",
                )
                provider_output = ProviderOutput.from_dict(output_data)
                if provider_output.output_fingerprint != event.payload["output_fingerprint"]:
                    raise ValueError("frozen ProviderOutput does not match durable event")
                backend_authority = created["authority_identity"].get(
                    "backend_execution_authority"
                )
                if backend_authority is not None:
                    truth = provider_output.execution_truth
                    if not isinstance(backend_authority, Mapping) or truth is None:
                        raise ValueError(
                            "concrete ProviderOutput lacks backend execution truth"
                        )
                    if (
                        truth.backend_execution_authority_fingerprint
                        != backend_authority.get("authority_fingerprint")
                        or truth.cleanup_fingerprint != fingerprint(cleanup)
                        or truth.journal_tail_fingerprint
                        != event.previous_fingerprint
                        or control_terminal is None
                        or truth.protocol_terminal_classification
                        != control_terminal.get("protocol_terminal_classification")
                        or truth.app_server_exit_code
                        != control_terminal.get("app_server_exit_code")
                        or truth.app_server_exit_normal
                        != control_terminal.get("app_server_exit_normal")
                        or truth.app_server_forced
                        != control_terminal.get("app_server_forced")
                        or (
                            boundary_terminal is not None
                            and (
                                truth.os_boundary_authority_fingerprint
                                != boundary_terminal[
                                    "os_boundary_authority_fingerprint"
                                ]
                                or truth.capsule_broker_terminal_fingerprint
                                != boundary_terminal[
                                    "capsule_broker_terminal_fingerprint"
                                ]
                                or truth.boundary_terminal_fingerprint
                                != boundary_terminal[
                                    "boundary_terminal_fingerprint"
                                ]
                            )
                        )
                    ):
                        raise ValueError(
                            "ProviderOutput truth differs from authority, process, "
                            "cleanup, or journal-tail evidence"
                        )
            elif event.kind == "session_terminal":
                if provider_output is None or cleanup is None:
                    raise ValueError("session terminal precedes cleanup or ProviderOutput")
                if event.index == 0 or events[event.index - 1].kind != "provider_output_frozen":
                    raise ValueError("session terminal is not bound to exact ProviderOutput")
                if any(
                    request.sequence not in {result.sequence for result in results}
                    for request in requests
                ):
                    raise ValueError("session terminal hides an unpaired effect request")
                require_exact_keys(event.payload, {"classification", "detail"}, "terminal event")
                terminal = SessionTerminalClassification(event.payload["classification"])
                terminal_detail = require_nonempty_text(
                    event.payload["detail"], "terminal detail", max_bytes=8192
                )
                if terminal == SessionTerminalClassification.COMPLETED and (
                    not provider_output.cleanup_result.cleanup_proven
                ):
                    raise ValueError("COMPLETED lacks proven cleanup")
            elif event.kind == "downstream_handoff":
                if downstream_handoff is not None:
                    raise ValueError("duplicate downstream handoff")
                if terminal is None or provider_output is None:
                    raise ValueError("downstream handoff precedes terminal ProviderOutput")
                require_exact_keys(
                    event.payload,
                    {
                        "frozen_workspace_fingerprint",
                        "provider_output_fingerprint",
                        "terminal_event_fingerprint",
                    },
                    "downstream handoff",
                )
                require_sha256(
                    event.payload["frozen_workspace_fingerprint"],
                    "handoff frozen workspace fingerprint",
                )
                if (
                    event.payload["provider_output_fingerprint"]
                    != provider_output.output_fingerprint
                    or event.payload["terminal_event_fingerprint"]
                    != events[event.index - 1].event_fingerprint
                ):
                    raise ValueError("downstream handoff binding mismatch")
                downstream_handoff = dict(event.payload)
            elif event.kind == "accepted_material_bound":
                if accepted_material is not None:
                    raise ValueError("duplicate accepted-material evidence event")
                if terminal is None or provider_output is None:
                    raise ValueError("accepted-material evidence precedes frozen terminal provider evidence")
                require_exact_keys(event.payload, {"accepted_material"}, "accepted material event")
                accepted_material = AcceptedMaterialIdentity.from_dict(
                    event.payload["accepted_material"]
                )
            elif event.kind == "checkpoint_verified":
                if checkpoint_result is not None:
                    raise ValueError("duplicate checkpoint evidence event")
                require_exact_keys(event.payload, {"checkpoint_result"}, "checkpoint event")
                checkpoint_result = CheckpointResult.from_dict(event.payload["checkpoint_result"])
                if accepted_material is None or checkpoint_result.accepted_material != accepted_material:
                    raise ValueError("replayed checkpoint is bound to different accepted material")
            elif event.kind == "behavior_verified":
                if behavior_result is not None:
                    raise ValueError("duplicate behavior evidence event")
                require_exact_keys(event.payload, {"behavior_result"}, "behavior event")
                behavior_result = BehaviorResult.from_dict(event.payload["behavior_result"])
                if (
                    accepted_material is None
                    or behavior_result.accepted_material != accepted_material
                    or checkpoint_result is None
                    or not checkpoint_result.passed
                ):
                    raise ValueError("replayed behavior is not bound to accepted checkpoint material")
                require_independent_copies(checkpoint_result.copy, behavior_result.copy)
            elif event.kind == "finalization_prepared":
                if finalization_evidence is not None or durability_receipt is not None:
                    raise ValueError("duplicate finalization preparation event")
                require_exact_keys(
                    event.payload,
                    {"finalization_evidence", "durability_receipt"},
                    "finalization preparation event",
                )
                finalization_evidence = FinalizationEvidence.from_dict(
                    event.payload["finalization_evidence"]
                )
                durability_receipt = DurabilityReceipt.from_dict(
                    event.payload["durability_receipt"]
                )
                durability_receipt.verify(finalization_evidence)
                if (
                    accepted_material is None
                    or finalization_evidence.accepted_material != accepted_material
                    or behavior_result is None
                    or not behavior_result.passed
                ):
                    raise ValueError("replayed finalization preparation is not authorized")
            elif event.kind == "finalization_completed":
                if finalization_result is not None:
                    raise ValueError("duplicate finalization result event")
                require_exact_keys(event.payload, {"finalization_result"}, "finalization result event")
                finalization_result = FinalizationResult.from_dict(
                    event.payload["finalization_result"]
                )
                if (
                    finalization_evidence is None
                    or durability_receipt is None
                    or finalization_result.durable_evidence != finalization_evidence
                    or finalization_result.durability_receipt != durability_receipt
                    or finalization_result.accepted_material != accepted_material
                ):
                    raise ValueError("replayed finalization result differs from authorization")
            else:
                raise ValueError(f"unknown durable session event kind: {event.kind}")
        if (
            provider_output is not None
            and terminal is None
            and not _allow_preterminal_provider_output
        ):
            raise ValueError("ProviderOutput lacks an exact terminal journal record")
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
            effect_executions=tuple(effect_executions),
            results=tuple(results),
            control_terminal=control_terminal,
            cleanup=cleanup,
            boundary_terminal=boundary_terminal,
            provider_output=provider_output,
            downstream_handoff=downstream_handoff,
            accepted_material=accepted_material,
            checkpoint_result=checkpoint_result,
            behavior_result=behavior_result,
            finalization_evidence=finalization_evidence,
            durability_receipt=durability_receipt,
            finalization_result=finalization_result,
            recorded_terminal_classification=terminal,
            terminal_detail=terminal_detail,
        )
