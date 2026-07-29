"""Closed, bounded, replay-resistant Unix seqpacket broker transport."""

from __future__ import annotations

import array
import os
import socket
import struct
import threading
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    sha256_bytes,
    strict_json_loads,
)


BROKER_REQUEST_SCHEMA_VERSION = "admissible_capsule_broker_request_v1"
BROKER_RESULT_SCHEMA_VERSION = "admissible_capsule_broker_result_v1"
AUTH_BROKER_REQUEST_SCHEMA_VERSION = "admissible_auth_broker_request_v1"
AUTH_BROKER_RESULT_SCHEMA_VERSION = "admissible_auth_broker_result_v1"
EGRESS_EVIDENCE_SCHEMA_VERSION = "admissible_egress_relay_evidence_v1"
MAX_BROKER_MESSAGE_BYTES = 256 * 1024
MAX_BROKER_FDS = 4


class BrokerProtocolError(RuntimeError):
    """A closed transport or schema invariant was violated."""


def protocol_schema_identities() -> dict[str, str]:
    root = files("admissible.capsule").joinpath("broker_schemas")
    names = (
        "CapsuleBrokerRequest.json",
        "CapsuleBrokerResult.json",
        "AuthenticationBrokerRequest.json",
        "AuthenticationBrokerResult.json",
        "EgressRelayEvidence.json",
    )
    return {
        name.removesuffix(".json"): sha256_bytes(root.joinpath(name).read_bytes())
        for name in names
    }


def _bounded_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_BROKER_MESSAGE_BYTES:
        raise ValueError(f"{label} exceeds its byte bound")
    decoded = strict_json_loads(encoded, label=label)
    if not isinstance(decoded, dict):
        raise ValueError(f"{label} must be an object")
    return decoded


@dataclass(frozen=True)
class BrokerRequest:
    schema_version: str
    request_id: str
    operation: str
    backend_session_id: str
    controller_session_id: str
    capsule_session_id: str
    authority_fingerprint: str
    sequence: int
    tool_call_identity: str
    payload: Mapping[str, Any]
    request_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        operation: str,
        backend_session_id: str,
        controller_session_id: str,
        capsule_session_id: str,
        authority_fingerprint: str,
        sequence: int,
        tool_call_identity: str,
        payload: Mapping[str, Any],
    ) -> "BrokerRequest":
        body = {
            "schema_version": BROKER_REQUEST_SCHEMA_VERSION,
            "request_id": request_id,
            "operation": operation,
            "backend_session_id": backend_session_id,
            "controller_session_id": controller_session_id,
            "capsule_session_id": capsule_session_id,
            "authority_fingerprint": authority_fingerprint,
            "sequence": sequence,
            "tool_call_identity": tool_call_identity,
            "payload": _bounded_object(payload, "capsule broker request payload"),
        }
        return cls(**body, request_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "operation": self.operation,
            "backend_session_id": self.backend_session_id,
            "controller_session_id": self.controller_session_id,
            "capsule_session_id": self.capsule_session_id,
            "authority_fingerprint": self.authority_fingerprint,
            "sequence": self.sequence,
            "tool_call_identity": self.tool_call_identity,
            "payload": dict(self.payload),
        }

    def validated(self) -> "BrokerRequest":
        if self.schema_version != BROKER_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported capsule broker request schema")
        require_identifier(self.request_id, "broker request id")
        if self.operation not in {
            "CREATE_SESSION",
            "EXECUTE_TOOL",
            "FREEZE_WORKSPACE",
            "OBSERVE_FROZEN",
            "BIND_FROZEN",
            "TERMINATE_CLEANUP",
            "GET_FROZEN_REFERENCE",
            "SHUTDOWN",
        }:
            raise ValueError("capsule broker operation is not in the closed protocol")
        for label, value in (
            ("backend session", self.backend_session_id),
            ("controller session", self.controller_session_id),
            ("capsule session", self.capsule_session_id),
            ("tool-call identity", self.tool_call_identity),
        ):
            require_identifier(value, label)
        require_sha256(self.authority_fingerprint, "broker request authority")
        require_strict_int(
            self.sequence, "broker request sequence", minimum=1, maximum=1_000_000
        )
        _bounded_object(self.payload, "capsule broker request payload")
        require_sha256(self.request_fingerprint, "broker request fingerprint")
        if fingerprint(self._body()) != self.request_fingerprint:
            raise ValueError("capsule broker request fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "request_fingerprint": self.request_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrokerRequest":
        require_exact_keys(
            value,
            {
                "schema_version",
                "request_id",
                "operation",
                "backend_session_id",
                "controller_session_id",
                "capsule_session_id",
                "authority_fingerprint",
                "sequence",
                "tool_call_identity",
                "payload",
                "request_fingerprint",
            },
            "capsule broker request",
        )
        return cls(**dict(value)).validated()


@dataclass(frozen=True)
class BrokerResult:
    schema_version: str
    request_fingerprint: str
    sequence: int
    classification: str
    terminal: bool
    payload: Mapping[str, Any]
    result_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        request: BrokerRequest,
        classification: str,
        terminal: bool,
        payload: Mapping[str, Any],
    ) -> "BrokerResult":
        body = {
            "schema_version": BROKER_RESULT_SCHEMA_VERSION,
            "request_fingerprint": request.request_fingerprint,
            "sequence": request.sequence,
            "classification": classification,
            "terminal": terminal,
            "payload": _bounded_object(payload, "capsule broker result payload"),
        }
        return cls(**body, result_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_fingerprint": self.request_fingerprint,
            "sequence": self.sequence,
            "classification": self.classification,
            "terminal": self.terminal,
            "payload": dict(self.payload),
        }

    def validated(self) -> "BrokerResult":
        if self.schema_version != BROKER_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported capsule broker result schema")
        require_sha256(self.request_fingerprint, "broker paired request")
        require_strict_int(
            self.sequence, "broker result sequence", minimum=1, maximum=1_000_000
        )
        if self.classification not in {"SUCCEEDED", "REFUSED", "FAILED", "UNKNOWN"}:
            raise ValueError("unknown capsule broker result classification")
        if not isinstance(self.terminal, bool):
            raise ValueError("broker terminal field must be boolean")
        _bounded_object(self.payload, "capsule broker result payload")
        require_sha256(self.result_fingerprint, "broker result fingerprint")
        if fingerprint(self._body()) != self.result_fingerprint:
            raise ValueError("capsule broker result fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_fingerprint": self.result_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrokerResult":
        require_exact_keys(
            value,
            {
                "schema_version",
                "request_fingerprint",
                "sequence",
                "classification",
                "terminal",
                "payload",
                "result_fingerprint",
            },
            "capsule broker result",
        )
        return cls(**dict(value)).validated()


def make_seqpacket_socketpair() -> tuple[socket.socket, socket.socket]:
    left, right = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,
    )
    for item in (left, right):
        item.set_inheritable(False)
    return left, right


def peer_credentials(channel: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerProtocolError("SO_PEERCRED is unavailable")
    raw = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack("3i", raw)


def send_packet(
    channel: socket.socket,
    value: Mapping[str, Any],
    *,
    descriptors: tuple[int, ...] = (),
) -> None:
    encoded = canonical_bytes(value)
    if not encoded or len(encoded) > MAX_BROKER_MESSAGE_BYTES:
        raise BrokerProtocolError("outbound broker packet exceeds its byte bound")
    if len(descriptors) > MAX_BROKER_FDS:
        raise BrokerProtocolError("outbound broker packet has too many descriptors")
    ancillary = []
    if descriptors:
        rights = array.array("i", descriptors)
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights))
    sent = channel.sendmsg([encoded], ancillary)
    if sent != len(encoded):
        raise BrokerProtocolError("broker packet was not sent atomically")


def receive_packet(
    channel: socket.socket,
    *,
    max_descriptors: int = 0,
) -> tuple[dict[str, Any], tuple[int, ...]]:
    if not 0 <= max_descriptors <= MAX_BROKER_FDS:
        raise ValueError("invalid inbound descriptor bound")
    ancillary_size = socket.CMSG_SPACE(max_descriptors * array.array("i").itemsize)
    data, ancillary, flags, _address = channel.recvmsg(
        MAX_BROKER_MESSAGE_BYTES + 1,
        ancillary_size,
    )
    received: list[int] = []
    try:
        if not data:
            raise EOFError("broker channel closed")
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise BrokerProtocolError("truncated broker packet refused")
        if len(data) > MAX_BROKER_MESSAGE_BYTES:
            raise BrokerProtocolError("oversized broker packet refused")
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise BrokerProtocolError("unexpected broker ancillary record")
            rights = array.array("i")
            rights.frombytes(payload[: len(payload) - (len(payload) % rights.itemsize)])
            received.extend(rights)
        if len(received) > max_descriptors:
            raise BrokerProtocolError("too many broker descriptors received")
        value = strict_json_loads(data, label="broker protocol JSON")
        if not isinstance(value, dict):
            raise BrokerProtocolError("broker packet is not an object")
        return value, tuple(received)
    except BaseException:
        for descriptor in received:
            os.close(descriptor)
        raise


class SingleOwnerBrokerClient:
    """Serializes one controller's requests and verifies exact pairing."""

    def __init__(
        self,
        channel: socket.socket,
        *,
        expected_peer_pid: int | None,
    ):
        self._channel = channel
        self._expected_peer_pid = expected_peer_pid
        self._owner_pid = os.getpid()
        self._lock = threading.Lock()
        self._sequence = 0
        self._closed = False

    @property
    def sequence(self) -> int:
        return self._sequence

    def transact(self, request: BrokerRequest) -> BrokerResult:
        if os.getpid() != self._owner_pid:
            raise BrokerProtocolError("broker client ownership changed across process")
        if self._closed:
            raise BrokerProtocolError("broker client is closed")
        if not self._lock.acquire(blocking=False):
            raise BrokerProtocolError("concurrent controller ownership refused")
        try:
            expected = self._sequence + 1
            if request.sequence != expected:
                raise BrokerProtocolError("local broker request sequence mismatch")
            if self._expected_peer_pid is not None:
                observed_pid, observed_uid, _gid = peer_credentials(self._channel)
                if observed_pid != self._expected_peer_pid or observed_uid != os.getuid():
                    raise BrokerProtocolError("capsule broker peer identity changed")
            send_packet(self._channel, request.to_dict())
            raw, descriptors = receive_packet(self._channel)
            if descriptors:
                raise BrokerProtocolError("capsule broker returned unexpected descriptors")
            result = BrokerResult.from_dict(raw)
            if (
                result.request_fingerprint != request.request_fingerprint
                or result.sequence != request.sequence
            ):
                raise BrokerProtocolError("capsule broker result pairing mismatch")
            self._sequence = expected
            return result
        finally:
            self._lock.release()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._channel.close()

    def release_inherited_descriptor(self) -> int:
        """Transfer the unused endpoint into an exec-confined controller."""

        if self._closed or self._sequence != 0:
            raise BrokerProtocolError(
                "only an unused broker channel can cross the controller boundary"
            )
        if os.getpid() != self._owner_pid:
            raise BrokerProtocolError("broker channel release owner changed")
        descriptor = self._channel.detach()
        os.set_inheritable(descriptor, False)
        self._closed = True
        return descriptor
