"""Minimal FD-only authentication broker for an ephemeral Codex home.

Only this process reads the authentication descriptor.  The source pathname is
not accepted by the protocol and is never recorded.  The broker returns a
directory descriptor suitable for bubblewrap ``--bind-fd``; it never returns a
host pathname or authentication bytes.
"""

from __future__ import annotations

import os
import secrets
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.boundary_authority import fixed_auth_metadata_policy
from admissible.capsule.broker_transport import (
    AUTH_BROKER_REQUEST_SCHEMA_VERSION,
    AUTH_BROKER_RESULT_SCHEMA_VERSION,
    BrokerProtocolError,
    make_seqpacket_socketpair,
    peer_credentials,
    receive_packet,
    send_packet,
)
from admissible.capsule.common import (
    fingerprint,
    fsync_directory,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
)


AUTH_BROKER_MAX_SOURCE_BYTES = 16 * 1024 * 1024
AUTH_FILENAME = "auth.json"
CONFIG_FILENAME = "config.toml"
MINIMAL_CONFIG = (
    b"[analytics]\nenabled = false\n"
    b"[features]\nweb_search = false\n"
)


def authentication_metadata_policy_fingerprint() -> str:
    return fingerprint(fixed_auth_metadata_policy())


@dataclass(frozen=True)
class AuthenticationBrokerRequest:
    schema_version: str
    session_id: str
    operation: str
    authority_fingerprint: str
    sequence: int
    metadata_policy_fingerprint: str
    request_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        operation: str,
        authority_fingerprint: str,
        sequence: int,
    ) -> "AuthenticationBrokerRequest":
        body = {
            "schema_version": AUTH_BROKER_REQUEST_SCHEMA_VERSION,
            "session_id": session_id,
            "operation": operation,
            "authority_fingerprint": authority_fingerprint,
            "sequence": sequence,
            "metadata_policy_fingerprint": (
                authentication_metadata_policy_fingerprint()
            ),
        }
        return cls(**body, request_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "operation": self.operation,
            "authority_fingerprint": self.authority_fingerprint,
            "sequence": self.sequence,
            "metadata_policy_fingerprint": self.metadata_policy_fingerprint,
        }

    def validated(self) -> "AuthenticationBrokerRequest":
        if self.schema_version != AUTH_BROKER_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported authentication broker request schema")
        require_identifier(self.session_id, "authentication broker session")
        if self.operation not in {"PREPARE", "HANDOFF", "CLEANUP", "SHUTDOWN"}:
            raise ValueError("unknown authentication broker operation")
        require_sha256(self.authority_fingerprint, "authentication broker authority")
        require_strict_int(
            self.sequence,
            "authentication broker sequence",
            minimum=1,
            maximum=16,
        )
        if (
            self.metadata_policy_fingerprint
            != authentication_metadata_policy_fingerprint()
        ):
            raise ValueError("authentication metadata policy changed")
        require_sha256(self.request_fingerprint, "authentication broker request")
        if fingerprint(self._body()) != self.request_fingerprint:
            raise ValueError("authentication broker request fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "request_fingerprint": self.request_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthenticationBrokerRequest":
        require_exact_keys(
            value,
            {
                "schema_version",
                "session_id",
                "operation",
                "authority_fingerprint",
                "sequence",
                "metadata_policy_fingerprint",
                "request_fingerprint",
            },
            "authentication broker request",
        )
        return cls(**dict(value)).validated()


@dataclass(frozen=True)
class AuthenticationBrokerResult:
    schema_version: str
    session_id: str
    sequence: int
    classification: str
    evidence: Mapping[str, Any]
    result_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        request: AuthenticationBrokerRequest,
        classification: str,
        evidence: Mapping[str, Any],
    ) -> "AuthenticationBrokerResult":
        body = {
            "schema_version": AUTH_BROKER_RESULT_SCHEMA_VERSION,
            "session_id": request.session_id,
            "sequence": request.sequence,
            "classification": classification,
            "evidence": dict(evidence),
        }
        return cls(**body, result_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "classification": self.classification,
            "evidence": dict(self.evidence),
        }

    def validated(self) -> "AuthenticationBrokerResult":
        if self.schema_version != AUTH_BROKER_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported authentication broker result schema")
        require_identifier(self.session_id, "authentication result session")
        require_strict_int(
            self.sequence,
            "authentication result sequence",
            minimum=1,
            maximum=16,
        )
        if self.classification not in {
            "PREPARED",
            "HANDED_OFF",
            "CLEANED",
            "REFUSED",
            "FAILED",
        }:
            raise ValueError("unknown authentication result classification")
        if not isinstance(self.evidence, Mapping):
            raise ValueError("authentication result evidence must be an object")
        if self.classification == "PREPARED":
            require_exact_keys(
                self.evidence,
                {
                    "broker_identity",
                    "source_metadata",
                    "ephemeral_home_identity",
                    "successful_install",
                    "source_descriptor_closed",
                    "raw_authentication_in_evidence",
                },
                "prepared authentication evidence",
            )
            require_exact_keys(
                self.evidence["source_metadata"],
                {
                    "file_type",
                    "device",
                    "inode",
                    "mode",
                    "link_count",
                    "owner_uid",
                    "size",
                    "mtime_ns",
                },
                "authentication source metadata",
            )
            require_exact_keys(
                self.evidence["ephemeral_home_identity"],
                {"device", "inode", "mode", "identity_fingerprint"},
                "ephemeral home identity",
            )
            source = self.evidence["source_metadata"]
            if (
                self.evidence["broker_identity"]
                != "content_attested_authentication_broker"
                or source["file_type"] != "regular"
            ):
                raise ValueError("prepared authentication identity changed")
            for key in (
                "device",
                "inode",
                "mode",
                "link_count",
                "owner_uid",
                "size",
                "mtime_ns",
            ):
                require_strict_int(
                    source[key],
                    f"authentication source metadata {key}",
                    minimum=0,
                    maximum=2**63 - 1,
                )
            home = self.evidence["ephemeral_home_identity"]
            for key in ("device", "inode", "mode"):
                require_strict_int(
                    home[key],
                    f"ephemeral home identity {key}",
                    minimum=0,
                    maximum=2**63 - 1,
                )
            require_sha256(
                home["identity_fingerprint"],
                "ephemeral home identity fingerprint",
            )
            if (
                self.evidence["successful_install"] is not True
                or self.evidence["source_descriptor_closed"] is not True
                or self.evidence["raw_authentication_in_evidence"] is not False
            ):
                raise ValueError("prepared authentication evidence is contradictory")
        elif self.classification == "HANDED_OFF":
            require_exact_keys(
                self.evidence,
                {
                    "successful_handoff",
                    "handoff_kind",
                    "source_present_in_codex_namespace",
                    "raw_authentication_in_handoff",
                },
                "authentication handoff evidence",
            )
            if self.evidence != {
                "successful_handoff": True,
                "handoff_kind": "directory_fd_for_bwrap_bind_fd",
                "source_present_in_codex_namespace": False,
                "raw_authentication_in_handoff": False,
            }:
                raise ValueError("authentication handoff evidence changed")
        elif self.classification == "CLEANED":
            allowed_shapes = (
                {
                    "wipe_completed",
                    "ephemeral_home_removed",
                    "wiped_file_count",
                    "raw_authentication_in_evidence",
                },
                {"wipe_completed", "ephemeral_home_removed", "idempotent"},
            )
            if set(self.evidence) not in allowed_shapes:
                raise ValueError("authentication cleanup evidence shape changed")
            if (
                self.evidence["wipe_completed"] is not True
                or self.evidence["ephemeral_home_removed"] is not True
            ):
                raise ValueError("authentication cleanup is unproven")
        elif self.classification == "FAILED":
            require_exact_keys(
                self.evidence,
                {"terminal_error_type", "raw_authentication_in_evidence"},
                "failed authentication evidence",
            )
            if self.evidence["raw_authentication_in_evidence"] is not False:
                raise ValueError("failed authentication evidence contains raw material")
        else:
            require_exact_keys(
                self.evidence,
                {"reason_code"},
                "refused authentication evidence",
            )
            require_identifier(
                self.evidence["reason_code"],
                "authentication refusal reason",
            )
        require_sha256(self.result_fingerprint, "authentication result fingerprint")
        if fingerprint(self._body()) != self.result_fingerprint:
            raise ValueError("authentication result fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_fingerprint": self.result_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthenticationBrokerResult":
        require_exact_keys(
            value,
            {
                "schema_version",
                "session_id",
                "sequence",
                "classification",
                "evidence",
                "result_fingerprint",
            },
            "authentication broker result",
        )
        return cls(**dict(value)).validated()


def _source_metadata(descriptor: int) -> dict[str, Any]:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("authentication source descriptor is not a regular file")
    if info.st_nlink != 1:
        raise ValueError("authentication source descriptor has aliases")
    if not 1 <= info.st_size <= AUTH_BROKER_MAX_SOURCE_BYTES:
        raise ValueError("authentication source size is out of bounds")
    return {
        "file_type": "regular",
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": info.st_nlink,
        "owner_uid": info.st_uid,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


class AuthenticationBrokerServer:
    def __init__(
        self,
        channel: socket.socket,
        *,
        source_descriptor: int,
        ephemeral_root: Path,
        session_id: str,
        authority_fingerprint: str,
        expected_peer_pid: int,
    ):
        self.channel = channel
        self.source_descriptor = source_descriptor
        self.ephemeral_root = ephemeral_root
        self.session_id = require_identifier(session_id, "authentication session")
        self.authority_fingerprint = require_sha256(
            authority_fingerprint, "authentication authority"
        )
        self.expected_peer_pid = expected_peer_pid
        self.sequence = 0
        self.home: Path | None = None
        self.home_descriptor: int | None = None
        self.source_closed = False
        self.cleaned = False

    def _attest_peer(self) -> None:
        pid, uid, _gid = peer_credentials(self.channel)
        if pid != self.expected_peer_pid or uid != os.getuid():
            raise BrokerProtocolError("authentication broker peer identity changed")

    def _prepare(self) -> Mapping[str, Any]:
        if self.home is not None:
            raise ValueError("ephemeral Codex home is already prepared")
        metadata = _source_metadata(self.source_descriptor)
        self.ephemeral_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.ephemeral_root.is_symlink():
            raise ValueError("ephemeral authentication root is a symlink")
        home = self.ephemeral_root / (
            f"codex-home-{self.session_id}-{secrets.token_hex(16)}"
        )
        home.mkdir(mode=0o700)
        destination = home / AUTH_FILENAME
        output = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.lseek(self.source_descriptor, 0, os.SEEK_SET)
            remaining = metadata["size"]
            while remaining:
                chunk = os.read(self.source_descriptor, min(remaining, 128 * 1024))
                if not chunk:
                    raise ValueError("authentication source ended before attested size")
                offset = 0
                while offset < len(chunk):
                    offset += os.write(output, chunk[offset:])
                remaining -= len(chunk)
            if os.read(self.source_descriptor, 1):
                raise ValueError("authentication source grew during installation")
            os.fsync(output)
        finally:
            os.close(output)
            os.close(self.source_descriptor)
            self.source_closed = True
        config = home / CONFIG_FILENAME
        config_fd = os.open(
            config,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(config_fd, MINIMAL_CONFIG)
            os.fsync(config_fd)
        finally:
            os.close(config_fd)
        fsync_directory(home)
        home_descriptor = os.open(
            home,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        identity = os.fstat(home_descriptor)
        self.home = home
        self.home_descriptor = home_descriptor
        return {
            "broker_identity": "content_attested_authentication_broker",
            "source_metadata": metadata,
            "ephemeral_home_identity": {
                "device": identity.st_dev,
                "inode": identity.st_ino,
                "mode": stat.S_IMODE(identity.st_mode),
                "identity_fingerprint": fingerprint(
                    {
                        "device": identity.st_dev,
                        "inode": identity.st_ino,
                        "mode": stat.S_IMODE(identity.st_mode),
                        "session_id": self.session_id,
                    }
                ),
            },
            "successful_install": True,
            "source_descriptor_closed": True,
            "raw_authentication_in_evidence": False,
        }

    def _handoff(self) -> tuple[Mapping[str, Any], tuple[int, ...]]:
        if self.home_descriptor is None or self.cleaned:
            raise ValueError("ephemeral Codex home is unavailable")
        return (
            {
                "successful_handoff": True,
                "handoff_kind": "directory_fd_for_bwrap_bind_fd",
                "source_present_in_codex_namespace": False,
                "raw_authentication_in_handoff": False,
            },
            (self.home_descriptor,),
        )

    def _wipe_one(self, path: Path) -> bool:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("ephemeral Codex home contains a non-regular file")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            remaining = info.st_size
            zeros = b"\0" * min(128 * 1024, max(1, remaining))
            while remaining:
                written = os.write(descriptor, zeros[:remaining])
                if written <= 0:
                    raise OSError("ephemeral authentication overwrite made no progress")
                remaining -= written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        path.unlink()
        return True

    def _cleanup(self) -> Mapping[str, Any]:
        if self.cleaned:
            return {
                "wipe_completed": True,
                "ephemeral_home_removed": True,
                "idempotent": True,
            }
        if self.home_descriptor is not None:
            os.close(self.home_descriptor)
            self.home_descriptor = None
        wiped_files = 0
        if self.home is not None and self.home.exists():
            for entry in self.home.iterdir():
                self._wipe_one(entry)
                wiped_files += 1
            fsync_directory(self.home)
            self.home.rmdir()
            fsync_directory(self.ephemeral_root)
        self.cleaned = True
        return {
            "wipe_completed": True,
            "ephemeral_home_removed": self.home is None or not self.home.exists(),
            "wiped_file_count": wiped_files,
            "raw_authentication_in_evidence": False,
        }

    def serve(self) -> int:
        exit_code = 0
        try:
            while True:
                self._attest_peer()
                raw, descriptors = receive_packet(self.channel)
                if descriptors:
                    raise BrokerProtocolError(
                        "authentication commands must not carry descriptors"
                    )
                request = AuthenticationBrokerRequest.from_dict(raw)
                if (
                    request.session_id != self.session_id
                    or request.authority_fingerprint != self.authority_fingerprint
                    or request.sequence != self.sequence + 1
                ):
                    raise BrokerProtocolError(
                        "authentication request authority or sequence mismatch"
                    )
                response_fds: tuple[int, ...] = ()
                try:
                    if request.operation == "PREPARE":
                        evidence = self._prepare()
                        classification = "PREPARED"
                    elif request.operation == "HANDOFF":
                        evidence, response_fds = self._handoff()
                        classification = "HANDED_OFF"
                    elif request.operation == "CLEANUP":
                        evidence = self._cleanup()
                        classification = "CLEANED"
                    else:
                        evidence = self._cleanup()
                        classification = "CLEANED"
                    result = AuthenticationBrokerResult.create(
                        request=request,
                        classification=classification,
                        evidence=evidence,
                    )
                except (OSError, ValueError) as error:
                    result = AuthenticationBrokerResult.create(
                        request=request,
                        classification="FAILED",
                        evidence={
                            "terminal_error_type": type(error).__name__,
                            "raw_authentication_in_evidence": False,
                        },
                    )
                    exit_code = 1
                send_packet(
                    self.channel,
                    result.to_dict(),
                    descriptors=response_fds,
                )
                self.sequence = request.sequence
                if request.operation == "SHUTDOWN" or result.classification == "FAILED":
                    break
        except (EOFError, BrokerProtocolError, ValueError, OSError):
            exit_code = 1
        finally:
            try:
                self._cleanup()
            except (OSError, ValueError):
                exit_code = 1
            if not self.source_closed:
                os.close(self.source_descriptor)
                self.source_closed = True
            self.channel.close()
        return exit_code


class AuthenticationBrokerProcess:
    """Boundary-launcher-side owner of the dedicated broker process."""

    def __init__(
        self,
        channel: socket.socket,
        *,
        pid: int,
        session_id: str,
        authority_fingerprint: str,
        ephemeral_root: Path,
    ):
        self.channel = channel
        self.pid = pid
        self.session_id = session_id
        self.authority_fingerprint = authority_fingerprint
        self.ephemeral_root = ephemeral_root
        self.sequence = 0
        self.home_descriptor: int | None = None
        self.terminal_evidence: Mapping[str, Any] | None = None
        self.closed = False

    @classmethod
    def start(
        cls,
        *,
        source_descriptor: int,
        ephemeral_root: Path,
        session_id: str,
        authority_fingerprint: str,
    ) -> "AuthenticationBrokerProcess":
        parent, child = make_seqpacket_socketpair()
        launcher_pid = os.getpid()
        pid = os.fork()
        if pid == 0:
            parent.close()
            code = 1
            try:
                code = AuthenticationBrokerServer(
                    child,
                    source_descriptor=source_descriptor,
                    ephemeral_root=ephemeral_root,
                    session_id=session_id,
                    authority_fingerprint=authority_fingerprint,
                    expected_peer_pid=launcher_pid,
                ).serve()
            finally:
                os._exit(code)
        child.close()
        os.close(source_descriptor)
        return cls(
            parent,
            pid=pid,
            session_id=session_id,
            authority_fingerprint=authority_fingerprint,
            ephemeral_root=ephemeral_root,
        )

    def _request(
        self,
        operation: str,
        *,
        expect_descriptor: bool = False,
    ) -> AuthenticationBrokerResult:
        if self.closed:
            raise BrokerProtocolError("authentication broker client is closed")
        _creation_pid, uid, _gid = peer_credentials(self.channel)
        if uid != os.getuid():
            raise BrokerProtocolError("authentication broker process identity changed")
        try:
            waited, _status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError as error:
            raise BrokerProtocolError("authentication broker process is not owned") from error
        if waited:
            raise BrokerProtocolError("authentication broker exited before protocol")
        request = AuthenticationBrokerRequest.create(
            session_id=self.session_id,
            operation=operation,
            authority_fingerprint=self.authority_fingerprint,
            sequence=self.sequence + 1,
        )
        send_packet(self.channel, request.to_dict())
        raw, descriptors = receive_packet(
            self.channel,
            max_descriptors=1 if expect_descriptor else 0,
        )
        result = AuthenticationBrokerResult.from_dict(raw)
        if result.sequence != request.sequence:
            for descriptor in descriptors:
                os.close(descriptor)
            raise BrokerProtocolError("authentication broker result sequence mismatch")
        if expect_descriptor:
            if len(descriptors) != 1 or result.classification != "HANDED_OFF":
                for descriptor in descriptors:
                    os.close(descriptor)
                raise BrokerProtocolError("authentication handoff descriptor is absent")
            self.home_descriptor = descriptors[0]
        elif descriptors:
            for descriptor in descriptors:
                os.close(descriptor)
            raise BrokerProtocolError("unexpected authentication broker descriptor")
        self.sequence = request.sequence
        if result.classification in {"REFUSED", "FAILED"}:
            raise BrokerProtocolError(
                f"authentication broker {result.classification.lower()}"
            )
        return result

    def prepare(self) -> AuthenticationBrokerResult:
        return self._request("PREPARE")

    def handoff(self) -> tuple[AuthenticationBrokerResult, int]:
        result = self._request("HANDOFF", expect_descriptor=True)
        assert self.home_descriptor is not None
        return result, self.home_descriptor

    def cleanup(self) -> AuthenticationBrokerResult:
        result = self._request("CLEANUP")
        self.terminal_evidence = result.evidence
        if self.home_descriptor is not None:
            os.close(self.home_descriptor)
            self.home_descriptor = None
        return result

    def shutdown(self) -> tuple[int, AuthenticationBrokerResult]:
        result = self._request("SHUTDOWN")
        self.terminal_evidence = result.evidence
        self.channel.close()
        self.closed = True
        waited, status = os.waitpid(self.pid, 0)
        if waited != self.pid:
            raise RuntimeError("wrong authentication broker process reaped")
        return os.waitstatus_to_exitcode(status), result

    def force_terminate_and_recover(self) -> Mapping[str, Any]:
        """Launcher recovery for a broker killed outside its ``finally`` path."""

        if not self.closed:
            try:
                os.kill(self.pid, 9)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
            self.channel.close()
            self.closed = True
        recovered = 0
        prefix = f"codex-home-{self.session_id}-"
        if self.ephemeral_root.exists():
            for home in self.ephemeral_root.iterdir():
                if not home.name.startswith(prefix) or home.is_symlink():
                    continue
                for entry in home.iterdir():
                    info = os.lstat(entry)
                    if not stat.S_ISREG(info.st_mode):
                        raise RuntimeError(
                            "authentication recovery found unexpected object"
                        )
                    descriptor = os.open(
                        entry,
                        os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    )
                    try:
                        remaining = info.st_size
                        zeros = b"\0" * min(128 * 1024, max(1, remaining))
                        while remaining:
                            written = os.write(descriptor, zeros[:remaining])
                            if written <= 0:
                                raise OSError(
                                    "authentication recovery overwrite stalled"
                                )
                            remaining -= written
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    entry.unlink()
                fsync_directory(home)
                home.rmdir()
                recovered += 1
            fsync_directory(self.ephemeral_root)
        evidence = {
            "session_id": self.session_id,
            "forced_broker_termination": True,
            "recovered_home_count": recovered,
            "ephemeral_home_removed": not any(
                item.name.startswith(prefix)
                for item in self.ephemeral_root.iterdir()
            )
            if self.ephemeral_root.exists()
            else True,
            "raw_authentication_in_evidence": False,
            "terminal_classification": "FAILED_CLEANED",
        }
        return {**evidence, "recovery_fingerprint": fingerprint(evidence)}
