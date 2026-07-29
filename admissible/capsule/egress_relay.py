"""Preventive CONNECT-only relay for the isolated Codex network namespace."""

from __future__ import annotations

import ipaddress
import os
import selectors
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from admissible.capsule.boundary_authority import (
    DestinationManifest,
    SealedDestinationPinManifest,
)
from admissible.capsule.broker_transport import receive_packet, send_packet
from admissible.capsule.common import (
    atomic_json,
    canonical_bytes,
    fingerprint,
    fsync_directory,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    strict_json_loads,
)


CONNECT_HEADER_LIMIT = 8192
RELAY_CHUNK_BYTES = 64 * 1024
LISTENER_HANDOFF_SCHEMA_VERSION = "admissible_egress_listener_handoff_v1"
EGRESS_RECORD_SCHEMA_VERSION = "admissible_egress_relay_evidence_v1"
EGRESS_JOURNAL_SCHEMA_VERSION = "admissible_egress_relay_journal_v1"


@dataclass(frozen=True)
class EgressBudgets:
    connection_timeout_seconds: float = 5.0
    connection_duration_seconds: float = 120.0
    per_connection_bytes: int = 16 * 1024 * 1024
    session_bytes: int = 128 * 1024 * 1024
    concurrency: int = 4
    connections: int = 32

    def validated(self) -> "EgressBudgets":
        if not 0.05 <= self.connection_timeout_seconds <= 30:
            raise ValueError("egress connection timeout is out of bounds")
        if not 1 <= self.connection_duration_seconds <= 3600:
            raise ValueError("egress connection duration is out of bounds")
        if not 1024 <= self.per_connection_bytes <= 1024 * 1024 * 1024:
            raise ValueError("egress per-connection bytes are out of bounds")
        if not self.per_connection_bytes <= self.session_bytes <= 8 * 1024**3:
            raise ValueError("egress session bytes are out of bounds")
        if not 1 <= self.concurrency <= 64:
            raise ValueError("egress concurrency is out of bounds")
        if not self.concurrency <= self.connections <= 4096:
            raise ValueError("egress connection count is out of bounds")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {
            "connection_timeout_ms": int(self.connection_timeout_seconds * 1000),
            "connection_duration_ms": int(self.connection_duration_seconds * 1000),
            "per_connection_bytes": self.per_connection_bytes,
            "session_bytes": self.session_bytes,
            "concurrency": self.concurrency,
            "connections": self.connections,
        }


def resolve_and_seal(
    authority: DestinationManifest,
    *,
    session_id: str,
    resolver: Callable[[str, int], Sequence[str]] | None = None,
    synthetic_provider_free: bool = False,
) -> SealedDestinationPinManifest:
    """Resolve every authorized name once, then close the resolution surface."""

    authority.validated()
    if resolver is None:
        def resolver(hostname: str, port: int) -> Sequence[str]:
            results = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            return tuple(item[4][0] for item in results)

    resolved: dict[tuple[str, int], Sequence[str]] = {}
    for hostname, port in sorted(authority.endpoints):
        addresses = resolver(hostname, port)
        resolved[(hostname, port)] = tuple(addresses)
    return SealedDestinationPinManifest.create(
        authority_manifest=authority,
        session_id=session_id,
        resolved=resolved,
        synthetic_provider_free=synthetic_provider_free,
    )


@dataclass(frozen=True)
class EgressConnectionEvidence:
    schema_version: str
    session_id: str
    connection_id: str
    destination_hostname: str
    destination_port: int
    pinned_ip: str
    bytes_from_codex: int
    bytes_to_codex: int
    terminal_classification: str
    evidence_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        connection_id: str,
        destination_hostname: str,
        destination_port: int,
        pinned_ip: str,
        bytes_from_codex: int,
        bytes_to_codex: int,
        terminal_classification: str,
    ) -> "EgressConnectionEvidence":
        body = {
            "schema_version": EGRESS_RECORD_SCHEMA_VERSION,
            "session_id": session_id,
            "connection_id": connection_id,
            "destination_hostname": destination_hostname,
            "destination_port": destination_port,
            "pinned_ip": pinned_ip,
            "bytes_from_codex": bytes_from_codex,
            "bytes_to_codex": bytes_to_codex,
            "terminal_classification": terminal_classification,
        }
        return cls(**body, evidence_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in self.__dict__.items()
            if key != "evidence_fingerprint"
        }

    def validated(self) -> "EgressConnectionEvidence":
        if self.schema_version != EGRESS_RECORD_SCHEMA_VERSION:
            raise ValueError("unsupported egress evidence schema")
        require_identifier(self.session_id, "egress session")
        require_identifier(self.connection_id, "egress connection")
        if self.destination_hostname:
            if (
                self.destination_hostname != self.destination_hostname.lower()
                or "/" in self.destination_hostname
                or "\x00" in self.destination_hostname
            ):
                raise ValueError("invalid egress destination hostname evidence")
        if self.destination_port not in {0, 443}:
            raise ValueError("egress evidence contains an unauthorized port")
        if self.pinned_ip:
            ipaddress.ip_address(self.pinned_ip)
        for label, value in (
            ("bytes from Codex", self.bytes_from_codex),
            ("bytes to Codex", self.bytes_to_codex),
        ):
            require_strict_int(value, label, minimum=0, maximum=8 * 1024**3)
        if self.terminal_classification not in {
            "CLOSED",
            "CONNECT_REFUSED",
            "PIN_CONNECT_FAILED",
            "BYTE_BUDGET_EXCEEDED",
            "DURATION_EXCEEDED",
            "SESSION_STOPPED",
            "PROTOCOL_REFUSED",
        }:
            raise ValueError("unknown egress terminal classification")
        require_sha256(self.evidence_fingerprint, "egress evidence fingerprint")
        if fingerprint(self._body()) != self.evidence_fingerprint:
            raise ValueError("egress evidence fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "evidence_fingerprint": self.evidence_fingerprint}


class DurableEgressJournal:
    """Single-writer fsynced relay evidence with no headers or bodies."""

    def __init__(self, root: Path, *, session_id: str):
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("egress journal root must be an absolute lexical path")
        self.root = root
        self.session_id = require_identifier(session_id, "egress journal session")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = root / f"{session_id}.egress.jsonl"
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        self._descriptor = descriptor
        self._tail = "0" * 64
        self._sequence = 0
        self._lock = threading.Lock()
        fsync_directory(root)

    @property
    def tail_fingerprint(self) -> str:
        return self._tail

    def append(self, evidence: EgressConnectionEvidence) -> str:
        evidence.validated()
        if evidence.session_id != self.session_id:
            raise ValueError("egress evidence belongs to another session")
        with self._lock:
            body = {
                "schema_version": EGRESS_JOURNAL_SCHEMA_VERSION,
                "session_id": self.session_id,
                "sequence": self._sequence + 1,
                "previous_fingerprint": self._tail,
                "evidence": evidence.to_dict(),
            }
            record = {**body, "record_fingerprint": fingerprint(body)}
            encoded = canonical_bytes(record) + b"\n"
            offset = 0
            while offset < len(encoded):
                offset += os.write(self._descriptor, encoded[offset:])
            os.fsync(self._descriptor)
            self._sequence += 1
            self._tail = record["record_fingerprint"]
            return self._tail

    def close(self) -> None:
        if self._descriptor >= 0:
            os.fsync(self._descriptor)
            os.close(self._descriptor)
            self._descriptor = -1
            fsync_directory(self.root)


def send_listener_descriptor(
    transfer_channel: socket.socket,
    listener: socket.socket,
    *,
    session_id: str,
    pin_fingerprint: str,
) -> None:
    body = {
        "schema_version": LISTENER_HANDOFF_SCHEMA_VERSION,
        "session_id": require_identifier(session_id, "listener session"),
        "pin_fingerprint": require_sha256(
            pin_fingerprint, "listener pin fingerprint"
        ),
        "listener_family": "AF_INET_LOOPBACK",
        "listener_protocol": "TCP",
    }
    send_packet(transfer_channel, body, descriptors=(listener.fileno(),))


def receive_listener_descriptor(
    transfer_channel: socket.socket,
    *,
    expected_session_id: str,
    expected_pin_fingerprint: str,
) -> socket.socket:
    value, descriptors = receive_packet(transfer_channel, max_descriptors=1)
    require_exact_keys(
        value,
        {
            "schema_version",
            "session_id",
            "pin_fingerprint",
            "listener_family",
            "listener_protocol",
        },
        "egress listener handoff",
    )
    if (
        value["schema_version"] != LISTENER_HANDOFF_SCHEMA_VERSION
        or value["session_id"] != expected_session_id
        or value["pin_fingerprint"] != expected_pin_fingerprint
        or value["listener_family"] != "AF_INET_LOOPBACK"
        or value["listener_protocol"] != "TCP"
        or len(descriptors) != 1
    ):
        for descriptor in descriptors:
            os.close(descriptor)
        raise ValueError("egress listener handoff authority mismatch")
    listener = socket.socket(fileno=descriptors[0])
    if listener.family != socket.AF_INET or listener.type & 0xF != socket.SOCK_STREAM:
        listener.close()
        raise ValueError("transferred egress listener has the wrong socket type")
    address = listener.getsockname()
    if not isinstance(address, tuple) or address[0] != "127.0.0.1":
        listener.close()
        raise ValueError("transferred egress listener is not loopback-only")
    return listener


def _read_connect_request(client: socket.socket, timeout: float) -> tuple[str, int]:
    client.settimeout(timeout)
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = client.recv(min(1024, CONNECT_HEADER_LIMIT + 1 - len(data)))
        if not chunk:
            raise ValueError("CONNECT request ended before headers")
        data.extend(chunk)
        if len(data) > CONNECT_HEADER_LIMIT:
            raise ValueError("CONNECT request exceeds its byte bound")
    end = data.find(b"\r\n\r\n") + 4
    if end != len(data):
        raise ValueError("CONNECT request carried early tunnel/application bytes")
    try:
        lines = bytes(data).decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise ValueError("CONNECT control request is not ASCII") from error
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise ValueError("relay accepts CONNECT HTTP/1.1 only")
    authority = parts[1]
    if authority.count(":") != 1:
        raise ValueError("CONNECT authority is ambiguous")
    hostname, raw_port = authority.rsplit(":", 1)
    if (
        not hostname
        or hostname != hostname.lower()
        or "/" in hostname
        or "\\" in hostname
        or "\x00" in hostname
    ):
        raise ValueError("CONNECT hostname is not canonical")
    if raw_port != "443":
        raise ValueError("relay accepts CONNECT port 443 only")
    allowed_headers = {"host", "proxy-connection"}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError("CONNECT header framing is ambiguous")
        name, _value = line.split(":", 1)
        if name.lower() not in allowed_headers:
            raise ValueError("CONNECT carries an unauthorized control header")
    return hostname, 443


def _connect_pinned(address: str, port: int, timeout: float) -> socket.socket:
    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    outbound = socket.socket(family, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    outbound.settimeout(timeout)
    try:
        target: tuple[Any, ...] = (
            (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        )
        outbound.connect(target)
        outbound.settimeout(None)
        return outbound
    except BaseException:
        outbound.close()
        raise


class PreventiveEgressRelay:
    """Tunnel bytes only to addresses already stored in a sealed pin manifest."""

    def __init__(
        self,
        *,
        listener: socket.socket,
        pins: SealedDestinationPinManifest,
        journal: DurableEgressJournal,
        budgets: EgressBudgets | None = None,
        synthetic_connector: Callable[[str, int, float], socket.socket]
        | None = None,
    ):
        self.listener = listener
        self.pins = pins.validated()
        self.journal = journal
        self.budgets = (budgets or EgressBudgets()).validated()
        if synthetic_connector is not None and not pins.synthetic_provider_free:
            raise ValueError("custom egress connector is provider-free only")
        self.synthetic_connector = synthetic_connector
        if journal.session_id != pins.session_id:
            raise ValueError("egress journal and pins belong to different sessions")
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._active = 0
        self._connections = 0
        self._session_bytes = 0
        self._threads: list[threading.Thread] = []
        self._records: list[EgressConnectionEvidence] = []

    @property
    def records(self) -> tuple[EgressConnectionEvidence, ...]:
        with self._lock:
            return tuple(self._records)

    def _record(self, evidence: EgressConnectionEvidence) -> None:
        self.journal.append(evidence)
        with self._lock:
            self._records.append(evidence)

    def _refusal(
        self,
        client: socket.socket,
        *,
        connection_id: str,
        hostname: str = "",
        port: int = 0,
        classification: str = "CONNECT_REFUSED",
    ) -> None:
        try:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        self._record(
            EgressConnectionEvidence.create(
                session_id=self.pins.session_id,
                connection_id=connection_id,
                destination_hostname=hostname,
                destination_port=port,
                pinned_ip="",
                bytes_from_codex=0,
                bytes_to_codex=0,
                terminal_classification=classification,
            )
        )

    def _relay(self, client: socket.socket, connection_id: str) -> None:
        outbound: socket.socket | None = None
        hostname = ""
        port = 0
        pinned_ip = ""
        from_codex = 0
        to_codex = 0
        classification = "CLOSED"
        try:
            try:
                hostname, port = _read_connect_request(
                    client, self.budgets.connection_timeout_seconds
                )
                addresses = self.pins.addresses_for(hostname, port)
            except (OSError, ValueError):
                self._refusal(
                    client,
                    connection_id=connection_id,
                    hostname=hostname,
                    port=port,
                    classification="PROTOCOL_REFUSED",
                )
                return
            for address in addresses:
                try:
                    outbound = (
                        self.synthetic_connector(
                            address,
                            port,
                            self.budgets.connection_timeout_seconds,
                        )
                        if self.synthetic_connector is not None
                        else _connect_pinned(
                            address,
                            port,
                            self.budgets.connection_timeout_seconds,
                        )
                    )
                    pinned_ip = address
                    break
                except OSError:
                    continue
            if outbound is None:
                self._refusal(
                    client,
                    connection_id=connection_id,
                    hostname=hostname,
                    port=port,
                    classification="PIN_CONNECT_FAILED",
                )
                return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client.setblocking(False)
            outbound.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(client, selectors.EVENT_READ, (client, outbound, "from"))
            selector.register(outbound, selectors.EVENT_READ, (outbound, client, "to"))
            deadline = time.monotonic() + self.budgets.connection_duration_seconds
            try:
                while selector.get_map() and not self._stop.is_set():
                    if time.monotonic() >= deadline:
                        classification = "DURATION_EXCEEDED"
                        break
                    events = selector.select(min(0.5, max(0, deadline - time.monotonic())))
                    for key, _mask in events:
                        source, destination, direction = key.data
                        try:
                            chunk = source.recv(RELAY_CHUNK_BYTES)
                        except BlockingIOError:
                            continue
                        except (ConnectionResetError, BrokenPipeError):
                            try:
                                selector.unregister(source)
                            except KeyError:
                                pass
                            continue
                        if not chunk:
                            selector.unregister(source)
                            try:
                                destination.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            continue
                        if direction == "from":
                            from_codex += len(chunk)
                        else:
                            to_codex += len(chunk)
                        connection_total = from_codex + to_codex
                        with self._lock:
                            projected_session = self._session_bytes + len(chunk)
                            if (
                                connection_total > self.budgets.per_connection_bytes
                                or projected_session > self.budgets.session_bytes
                            ):
                                classification = "BYTE_BUDGET_EXCEEDED"
                                break
                            self._session_bytes = projected_session
                        try:
                            destination.sendall(chunk)
                        except (ConnectionResetError, BrokenPipeError):
                            try:
                                selector.unregister(destination)
                            except KeyError:
                                pass
                    if classification == "BYTE_BUDGET_EXCEEDED":
                        break
                if self._stop.is_set() and classification == "CLOSED":
                    classification = "SESSION_STOPPED"
            finally:
                selector.close()
            self._record(
                EgressConnectionEvidence.create(
                    session_id=self.pins.session_id,
                    connection_id=connection_id,
                    destination_hostname=hostname,
                    destination_port=port,
                    pinned_ip=pinned_ip,
                    bytes_from_codex=from_codex,
                    bytes_to_codex=to_codex,
                    terminal_classification=classification,
                )
            )
        finally:
            if outbound is not None:
                outbound.close()
            client.close()
            with self._lock:
                self._active -= 1

    def serve(self) -> None:
        self.listener.settimeout(0.5)
        while not self._stop.is_set():
            try:
                client, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            with self._lock:
                if (
                    self._active >= self.budgets.concurrency
                    or self._connections >= self.budgets.connections
                ):
                    connection_id = f"egress-{uuid.uuid4().hex}"
                    refused = True
                else:
                    self._active += 1
                    self._connections += 1
                    connection_id = f"egress-{uuid.uuid4().hex}"
                    refused = False
            if refused:
                self._refusal(client, connection_id=connection_id)
                client.close()
                continue
            worker = threading.Thread(
                target=self._relay,
                args=(client, connection_id),
                daemon=True,
            )
            self._threads.append(worker)
            worker.start()

    def stop(self) -> Mapping[str, Any]:
        self._stop.set()
        self.listener.close()
        for worker in self._threads:
            worker.join(timeout=self.budgets.connection_timeout_seconds + 1)
        live = sum(worker.is_alive() for worker in self._threads)
        evidence = {
            "session_id": self.pins.session_id,
            "pin_fingerprint": self.pins.pin_fingerprint,
            "journal_tail_fingerprint": self.journal.tail_fingerprint,
            "connections_started": self._connections,
            "connection_records": len(self.records),
            "session_bytes": self._session_bytes,
            "live_workers": live,
            "tls_terminated": False,
            "headers_or_bodies_recorded": False,
            "terminal_classification": "CLEANED" if live == 0 else "CLEANUP_FAILED",
        }
        self.journal.close()
        return {**evidence, "terminal_fingerprint": fingerprint(evidence)}
