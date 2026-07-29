"""Dedicated root-equivalent Docker capsule broker with a closed protocol."""

from __future__ import annotations

import fcntl
import os
import platform
import socket
import stat
import subprocess
import sys
import sysconfig
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from admissible.capsule.broker_transport import (
    BrokerProtocolError,
    BrokerRequest,
    BrokerResult,
    SingleOwnerBrokerClient,
    make_seqpacket_socketpair,
    peer_credentials,
    protocol_schema_identities,
    receive_packet,
    send_packet,
)
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
from admissible.capsule.docker_controller import (
    CapsuleExecutionAuthority,
    ControllerCleanupEvidence,
    DockerCapsuleController,
    DockerCapsuleLimits,
    DockerWorkspaceHandle,
    DurableControllerAuthority,
)
from admissible.capsule.execution_authority import (
    ExecutableFileIdentity,
    source_component_identity,
)
from admissible.capsule.models import ByteTreeObservation
from admissible.capsule.session_store import DurableToolRequest, DurableToolResult


CAPSULE_BROKER_AUTHORITY_SCHEMA_VERSION = "admissible_capsule_broker_authority_v1"
CAPSULE_BROKER_HELLO_SCHEMA_VERSION = "admissible_capsule_broker_hello_v1"
CAPSULE_BROKER_CONFIG_SCHEMA_VERSION = "admissible_capsule_broker_config_v1"


def capsule_broker_component_identity() -> Mapping[str, Any]:
    return source_component_identity(
        component="capsule_broker",
        source_bytes=Path(__file__).read_bytes(),
        provider_request_capable=False,
    )


def _validate_public_executable_identity(value: Mapping[str, Any]) -> None:
    """Validate attested metadata without reopening an executable in controller."""

    require_exact_keys(
        value,
        {
            "schema_version",
            "canonical_path",
            "sha256",
            "device",
            "inode",
            "mode",
            "size",
            "mtime_ns",
            "identity_fingerprint",
        },
        "broker-public Docker executable identity",
    )
    if value["schema_version"] != "admissible_executable_file_identity_v1":
        raise ValueError("unsupported broker-public executable identity")
    if (
        not isinstance(value["canonical_path"], str)
        or not value["canonical_path"].startswith("/")
        or "\x00" in value["canonical_path"]
        or ".." in Path(value["canonical_path"]).parts
    ):
        raise ValueError("invalid broker-public executable path metadata")
    require_sha256(value["sha256"], "broker-public executable content identity")
    for key, maximum in (
        ("device", 2**63 - 1),
        ("inode", 2**63 - 1),
        ("mode", 0o7777),
        ("size", 2**63 - 1),
        ("mtime_ns", 2**63 - 1),
    ):
        require_strict_int(
            value[key],
            f"broker-public executable {key}",
            minimum=0,
            maximum=maximum,
        )
    body = {key: value[key] for key in value if key != "identity_fingerprint"}
    require_sha256(
        value["identity_fingerprint"],
        "broker-public executable identity fingerprint",
    )
    if fingerprint(body) != value["identity_fingerprint"]:
        raise ValueError("broker-public executable identity fingerprint mismatch")


def _limits_to_dict(limits: DockerCapsuleLimits) -> dict[str, Any]:
    limits.validated()
    return {
        "image": limits.image,
        "image_identity": limits.image_identity,
        "uid": limits.uid,
        "gid": limits.gid,
        "cpus": limits.cpus,
        "memory": limits.memory,
        "pids": limits.pids,
        "command_timeout_seconds": limits.command_timeout_seconds,
        "session_timeout_seconds": limits.session_timeout_seconds,
        "output_limit_bytes": limits.output_limit_bytes,
        "write_limit_bytes": limits.write_limit_bytes,
        "file_count_limit": limits.file_count_limit,
        "tree_bytes_limit": limits.tree_bytes_limit,
    }


def _limits_from_dict(value: Mapping[str, Any]) -> DockerCapsuleLimits:
    require_exact_keys(
        value,
        {
            "image",
            "image_identity",
            "uid",
            "gid",
            "cpus",
            "memory",
            "pids",
            "command_timeout_seconds",
            "session_timeout_seconds",
            "output_limit_bytes",
            "write_limit_bytes",
            "file_count_limit",
            "tree_bytes_limit",
        },
        "capsule broker limits",
    )
    return DockerCapsuleLimits(**dict(value)).validated()


def _read_bounded_descriptor(descriptor: int, limit: int = 256 * 1024) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if not data or len(data) > limit:
        raise ValueError("capsule broker configuration exceeds its byte bound")
    return bytes(data)


def capsule_broker_subprocess_main() -> int:
    """Exec-clean entry inside the capsule broker's empty mount namespace."""

    channel_descriptor = int(os.environ["CAPSULE_BROKER_CHANNEL_FD"])
    config_descriptor = int(os.environ["CAPSULE_BROKER_CONFIG_FD"])
    raw = _read_bounded_descriptor(config_descriptor)
    value = strict_json_loads(raw, label="capsule broker sealed configuration")
    require_exact_keys(
        value,
        {
            "schema_version",
            "workspace_root",
            "frozen_output_root",
            "limits",
            "docker_executable",
            "expected_peer_pid",
            "config_fingerprint",
        },
        "capsule broker sealed configuration",
    )
    body = {key: value[key] for key in value if key != "config_fingerprint"}
    if (
        value["schema_version"] != CAPSULE_BROKER_CONFIG_SCHEMA_VERSION
        or fingerprint(body) != value["config_fingerprint"]
        or value["docker_executable"] != "/runtime/docker"
    ):
        raise ValueError("capsule broker sealed configuration differs")
    expected_peer_pid = value["expected_peer_pid"]
    if (
        isinstance(expected_peer_pid, bool)
        or not isinstance(expected_peer_pid, int)
        or expected_peer_pid != 0
    ):
        raise ValueError(
            "capsule broker peer must be the outside-namespace socket creator"
        )
    channel = socket.socket(fileno=channel_descriptor)
    controller = DockerCapsuleController(
        workspace_root=Path(value["workspace_root"]),
        frozen_output_root=Path(value["frozen_output_root"]),
        limits=_limits_from_dict(value["limits"]),
        docker_executable=Path("/runtime/docker"),
    )
    authority = CapsuleBrokerAuthority.create(controller=controller)
    return CapsuleBrokerServer(
        channel,
        controller=controller,
        authority=authority,
        expected_peer_pid=expected_peer_pid,
    ).serve()


@dataclass(frozen=True)
class CapsuleBrokerAuthority:
    schema_version: str
    implementation_identity: Mapping[str, Any]
    protocol_schema_identities: Mapping[str, str]
    docker_executable_identity: Mapping[str, Any]
    capsule_execution_authority: Mapping[str, Any]
    docker_controller_authority: Mapping[str, Any]
    fixed_interface: tuple[str, ...]
    root_equivalent: bool
    authentication_visible: bool
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        controller: DockerCapsuleController,
    ) -> "CapsuleBrokerAuthority":
        body = {
            "schema_version": CAPSULE_BROKER_AUTHORITY_SCHEMA_VERSION,
            "implementation_identity": dict(capsule_broker_component_identity()),
            "protocol_schema_identities": protocol_schema_identities(),
            "docker_executable_identity": controller.docker_identity.to_dict(),
            "capsule_execution_authority": controller.execution_authority.to_dict(),
            "docker_controller_authority": controller.controller_authority.to_dict(),
            "fixed_interface": [
                "CREATE_SESSION",
                "RECOVER_CLEANUP",
                "EXECUTE_TOOL",
                "FREEZE_WORKSPACE",
                "OBSERVE_FROZEN",
                "BIND_FROZEN",
                "TERMINATE_CLEANUP",
                "GET_FROZEN_REFERENCE",
                "SHUTDOWN",
            ],
            "root_equivalent": True,
            "authentication_visible": False,
        }
        return cls(
            schema_version=body["schema_version"],
            implementation_identity=MappingProxyType(body["implementation_identity"]),
            protocol_schema_identities=MappingProxyType(
                body["protocol_schema_identities"]
            ),
            docker_executable_identity=MappingProxyType(
                body["docker_executable_identity"]
            ),
            capsule_execution_authority=MappingProxyType(
                body["capsule_execution_authority"]
            ),
            docker_controller_authority=MappingProxyType(
                body["docker_controller_authority"]
            ),
            fixed_interface=tuple(body["fixed_interface"]),
            root_equivalent=True,
            authentication_visible=False,
            authority_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "implementation_identity": dict(self.implementation_identity),
            "protocol_schema_identities": dict(self.protocol_schema_identities),
            "docker_executable_identity": dict(self.docker_executable_identity),
            "capsule_execution_authority": dict(self.capsule_execution_authority),
            "docker_controller_authority": dict(self.docker_controller_authority),
            "fixed_interface": list(self.fixed_interface),
            "root_equivalent": self.root_equivalent,
            "authentication_visible": self.authentication_visible,
        }

    def validated(self) -> "CapsuleBrokerAuthority":
        if self.schema_version != CAPSULE_BROKER_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported capsule broker authority schema")
        if dict(self.implementation_identity) != dict(
            capsule_broker_component_identity()
        ):
            raise ValueError("capsule broker implementation identity changed")
        if dict(self.protocol_schema_identities) != protocol_schema_identities():
            raise ValueError("capsule broker protocol schema identity changed")
        _validate_public_executable_identity(self.docker_executable_identity)
        execution = self.capsule_execution_authority
        require_exact_keys(
            execution,
            {
                "schema_version",
                "image_identity",
                "security_profile",
                "authority_fingerprint",
            },
            "broker capsule execution authority",
        )
        CapsuleExecutionAuthority(
            schema_version=execution["schema_version"],
            image_identity=execution["image_identity"],
            security_profile=MappingProxyType(dict(execution["security_profile"])),
            authority_fingerprint=execution["authority_fingerprint"],
        ).validated()
        controller = self.docker_controller_authority
        require_exact_keys(
            controller,
            {
                "schema_version",
                "dynamic_tools",
                "execution_authority_fingerprint",
                "implementation_source_sha256",
                "request_pairing",
                "controller_fingerprint",
            },
            "broker Docker controller authority",
        )
        DurableControllerAuthority(
            schema_version=controller["schema_version"],
            dynamic_tools=tuple(controller["dynamic_tools"]),
            execution_authority_fingerprint=controller[
                "execution_authority_fingerprint"
            ],
            implementation_source_sha256=controller["implementation_source_sha256"],
            request_pairing=controller["request_pairing"],
            controller_fingerprint=controller["controller_fingerprint"],
        ).validated()
        if self.fixed_interface != (
            "CREATE_SESSION",
            "RECOVER_CLEANUP",
            "EXECUTE_TOOL",
            "FREEZE_WORKSPACE",
            "OBSERVE_FROZEN",
            "BIND_FROZEN",
            "TERMINATE_CLEANUP",
            "GET_FROZEN_REFERENCE",
            "SHUTDOWN",
        ):
            raise ValueError("capsule broker fixed interface changed")
        if self.root_equivalent is not True or self.authentication_visible is not False:
            raise ValueError("capsule broker trust classification changed")
        require_sha256(self.authority_fingerprint, "capsule broker authority")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("capsule broker authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "authority_fingerprint": self.authority_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapsuleBrokerAuthority":
        require_exact_keys(
            value,
            {
                "schema_version",
                "implementation_identity",
                "protocol_schema_identities",
                "docker_executable_identity",
                "capsule_execution_authority",
                "docker_controller_authority",
                "fixed_interface",
                "root_equivalent",
                "authentication_visible",
                "authority_fingerprint",
            },
            "capsule broker authority",
        )
        return cls(
            schema_version=value["schema_version"],
            implementation_identity=MappingProxyType(
                dict(value["implementation_identity"])
            ),
            protocol_schema_identities=MappingProxyType(
                dict(value["protocol_schema_identities"])
            ),
            docker_executable_identity=MappingProxyType(
                dict(value["docker_executable_identity"])
            ),
            capsule_execution_authority=MappingProxyType(
                dict(value["capsule_execution_authority"])
            ),
            docker_controller_authority=MappingProxyType(
                dict(value["docker_controller_authority"])
            ),
            fixed_interface=tuple(value["fixed_interface"]),
            root_equivalent=value["root_equivalent"],
            authentication_visible=value["authentication_visible"],
            authority_fingerprint=value["authority_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class CapsuleBrokerConfig:
    """Trusted launcher input; never part of the controller wire protocol."""

    workspace_root: Path
    frozen_output_root: Path
    limits: DockerCapsuleLimits
    docker_executable: Path = Path("/usr/bin/docker")

    def validated(self) -> "CapsuleBrokerConfig":
        for value, label in (
            (self.workspace_root, "broker workspace root"),
            (self.frozen_output_root, "broker frozen-output root"),
            (self.docker_executable, "broker Docker executable"),
        ):
            if not value.is_absolute() or ".." in value.parts:
                raise ValueError(f"{label} must be an absolute lexical path")
        if self.workspace_root == self.frozen_output_root:
            raise ValueError("capsule broker roots overlap")
        self.limits.validated()
        return self


@dataclass
class BrokerWorkspaceHandle:
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
            "kind": "capsule_broker_session",
            "container_id": self.container_id,
            "container_name": self.container_name,
            "controller_session_id": self.controller_session_id,
            "capsule_handle": self.capsule_handle,
            "mission_authority_fingerprint": self.mission_authority_fingerprint,
            "volume_name": self.volume_name,
            "workspace_id": self.workspace_id,
            "host_paths_visible_to_controller": False,
        }


@dataclass(frozen=True)
class BrokerControllerAuthority:
    """Controller-visible authority metadata; confers no Docker executable."""

    controller_fingerprint: str
    broker_authority_fingerprint: str
    docker_controller_fingerprint: str
    protocol_schema_identities: Mapping[str, str]

    def validated(self) -> "BrokerControllerAuthority":
        for label, value in (
            ("broker controller", self.controller_fingerprint),
            ("capsule broker", self.broker_authority_fingerprint),
            ("Docker controller", self.docker_controller_fingerprint),
        ):
            require_sha256(value, f"{label} fingerprint")
        if self.controller_fingerprint != self.broker_authority_fingerprint:
            raise ValueError("broker controller authority is not the broker authority")
        if dict(self.protocol_schema_identities) != protocol_schema_identities():
            raise ValueError("broker controller protocol schemas changed")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {
            "kind": "closed_capsule_broker",
            "controller_fingerprint": self.controller_fingerprint,
            "broker_authority_fingerprint": self.broker_authority_fingerprint,
            "docker_controller_fingerprint": self.docker_controller_fingerprint,
            "protocol_schema_identities": dict(self.protocol_schema_identities),
            "docker_executable_authority_visible": False,
            "docker_socket_visible": False,
        }


def _public_handle(handle: DockerWorkspaceHandle) -> dict[str, Any]:
    return {
        "session_id": handle.session_id,
        "controller_session_id": handle.controller_session_id,
        "capsule_handle": handle.capsule_handle,
        "mission_authority_fingerprint": handle.mission_authority_fingerprint,
        "workspace_id": handle.workspace_id,
        "container_name": handle.container_name,
        "container_id": handle.container_id,
        "volume_name": handle.volume_name,
        "started_monotonic": handle.started_monotonic,
        "container_alive": handle.container_alive,
        "frozen_workspace_fingerprint": handle.frozen_workspace_fingerprint,
        "frozen_binding_fingerprint": handle.frozen_binding_fingerprint,
        "capsule_exit_code": handle.capsule_exit_code,
        "capsule_exit_normal": handle.capsule_exit_normal,
        "capsule_exit_forced": handle.capsule_exit_forced,
        "capsule_exit_observed": handle.capsule_exit_observed,
        "container_quarantined": handle.container_quarantined,
    }


def _local_handle(value: Mapping[str, Any]) -> BrokerWorkspaceHandle:
    require_exact_keys(
        value,
        {
            "session_id",
            "controller_session_id",
            "capsule_handle",
            "mission_authority_fingerprint",
            "workspace_id",
            "container_name",
            "container_id",
            "volume_name",
            "started_monotonic",
            "container_alive",
            "frozen_workspace_fingerprint",
            "frozen_binding_fingerprint",
            "capsule_exit_code",
            "capsule_exit_normal",
            "capsule_exit_forced",
            "capsule_exit_observed",
            "container_quarantined",
        },
        "capsule broker public handle",
    )
    workspace_id = require_identifier(value["workspace_id"], "broker workspace")
    return BrokerWorkspaceHandle(
        **dict(value),
        source_path=Path(f"/broker-private/disposable/{workspace_id}"),
        frozen_path=Path(f"/broker-private/frozen/{workspace_id}"),
    )


class CapsuleBrokerServer:
    def __init__(
        self,
        channel: socket.socket,
        *,
        controller: DockerCapsuleController,
        authority: CapsuleBrokerAuthority,
        expected_peer_pid: int,
    ):
        self.channel = channel
        self.controller = controller
        self.authority = authority.validated()
        self.expected_peer_pid = expected_peer_pid
        self.sequence = 0
        self.sessions: dict[str, DockerWorkspaceHandle] = {}
        self.binding_ids: dict[str, tuple[str, str]] = {}
        self.terminal_evidence: list[Mapping[str, Any]] = []

    def _attest_peer(self) -> None:
        pid, uid, _gid = peer_credentials(self.channel)
        if pid != self.expected_peer_pid or uid != os.getuid():
            raise BrokerProtocolError("capsule broker peer identity changed")

    def _session(self, request: BrokerRequest) -> DockerWorkspaceHandle:
        try:
            handle = self.sessions[request.backend_session_id]
            controller_id, capsule_id = self.binding_ids[request.backend_session_id]
        except KeyError as error:
            raise ValueError("capsule broker session is absent") from error
        if (
            request.controller_session_id != controller_id
            or request.capsule_session_id != capsule_id
            or handle.session_id != request.backend_session_id
        ):
            raise ValueError("capsule broker session binding differs")
        return handle

    def _dispatch(self, request: BrokerRequest) -> tuple[Mapping[str, Any], bool]:
        if request.authority_fingerprint != self.authority.authority_fingerprint:
            raise ValueError("capsule broker authority fingerprint differs")
        if request.operation == "RECOVER_CLEANUP":
            require_exact_keys(
                request.payload,
                {"handle"},
                "capsule recovery payload",
            )
            if request.backend_session_id in self.sessions:
                raise ValueError("capsule recovery session already exists")
            public = _local_handle(request.payload["handle"])
            if public.session_id != request.backend_session_id:
                raise ValueError("capsule recovery backend session differs")
            recovered = DockerWorkspaceHandle(
                session_id=public.session_id,
                controller_session_id=public.controller_session_id,
                capsule_handle=public.capsule_handle,
                mission_authority_fingerprint=(
                    public.mission_authority_fingerprint
                ),
                workspace_id=public.workspace_id,
                container_name=public.container_name,
                container_id=public.container_id,
                volume_name=public.volume_name,
                source_path=self.controller.workspace_root / public.workspace_id,
                frozen_path=(
                    self.controller.frozen_output_root
                    / "objects"
                    / f"crash-recovery-{public.workspace_id}"
                ),
                started_monotonic=public.started_monotonic,
                container_alive=True,
            )
            labels = self.controller._handle_labels(recovered)
            self.controller._attest_object(
                "container", recovered.container_id, labels
            )
            self.controller._attest_object(
                "volume", recovered.volume_name, labels
            )
            cleanup = self.controller.cleanup(recovered)
            return {
                "session_id": public.session_id,
                "container_name": public.container_name,
                "volume_name": public.volume_name,
                "cleanup": cleanup.to_dict(),
                "ownership_proved_before_removal": cleanup.cleanup_proven,
                "docker_absence_inferred_from_failure": False,
            }, True
        if request.operation == "CREATE_SESSION":
            require_exact_keys(
                request.payload,
                {"workspace_id", "mission_authority_fingerprint"},
                "capsule create payload",
            )
            if request.backend_session_id in self.sessions:
                raise ValueError("capsule broker session already exists")
            workspace_id = require_identifier(
                request.payload["workspace_id"], "capsule broker workspace"
            )
            mission = require_sha256(
                request.payload["mission_authority_fingerprint"],
                "capsule broker mission",
            )
            handle = self.controller.prepare(
                session_id=request.backend_session_id,
                workspace_id=workspace_id,
                mission_authority_fingerprint=mission,
            )
            self.sessions[request.backend_session_id] = handle
            self.binding_ids[request.backend_session_id] = (
                request.controller_session_id,
                request.capsule_session_id,
            )
            return {"handle": _public_handle(handle)}, False
        handle = self._session(request)
        if request.operation == "EXECUTE_TOOL":
            require_exact_keys(
                request.payload,
                {"durable_tool_request"},
                "capsule execute payload",
            )
            tool_request = DurableToolRequest.from_dict(
                request.payload["durable_tool_request"]
            )
            if request.tool_call_identity != tool_request.request_fingerprint:
                raise ValueError("broker tool-call identity differs from durable request")
            result = self.controller.execute(handle, tool_request)
            return {"durable_tool_result": result.to_dict()}, False
        if request.operation == "FREEZE_WORKSPACE":
            require_exact_keys(request.payload, set(), "capsule freeze payload")
            observation = self.controller.freeze_output(handle)
            return {
                "observation": observation.to_dict(),
                "handle": _public_handle(handle),
            }, False
        if request.operation == "OBSERVE_FROZEN":
            require_exact_keys(request.payload, set(), "capsule observe payload")
            observation = self.controller.observe_frozen_output(handle)
            return {"observation": observation.to_dict()}, False
        if request.operation == "BIND_FROZEN":
            require_exact_keys(
                request.payload,
                {"journal_tail_fingerprint", "cleanup_fingerprint"},
                "capsule frozen binding payload",
            )
            binding = self.controller.bind_frozen_snapshot(
                handle,
                journal_tail_fingerprint=require_sha256(
                    request.payload["journal_tail_fingerprint"],
                    "broker journal tail",
                ),
                cleanup_fingerprint=require_sha256(
                    request.payload["cleanup_fingerprint"],
                    "broker cleanup fingerprint",
                ),
            )
            return {
                "frozen_binding_fingerprint": binding,
                "handle": _public_handle(handle),
            }, False
        if request.operation == "TERMINATE_CLEANUP":
            require_exact_keys(request.payload, set(), "capsule cleanup payload")
            cleanup = self.controller.cleanup(handle)
            terminal = {
                "cleanup": cleanup.to_dict(),
                "handle": _public_handle(handle),
                "broker_authority_fingerprint": self.authority.authority_fingerprint,
                "terminal_classification": (
                    "CLEANED" if cleanup.cleanup_proven else "CLEANUP_UNKNOWN"
                ),
            }
            terminal["terminal_fingerprint"] = fingerprint(terminal)
            self.terminal_evidence.append(terminal)
            return terminal, True
        if request.operation == "GET_FROZEN_REFERENCE":
            require_exact_keys(request.payload, set(), "capsule reference payload")
            path = self.controller.frozen_output_path(handle.workspace_id)
            return {
                "broker_owned_frozen_path": os.fspath(path),
                "frozen_workspace_fingerprint": handle.frozen_workspace_fingerprint,
            }, False
        raise ValueError("SHUTDOWN cannot target an active capsule session")

    def _cleanup_all(self) -> bool:
        complete = True
        for handle in tuple(self.sessions.values()):
            if not handle.container_alive and handle.capsule_exit_observed:
                continue
            try:
                evidence = self.controller.cleanup(handle)
                complete = complete and evidence.cleanup_proven
            except (OSError, RuntimeError, ValueError):
                complete = False
        return complete

    def serve(self) -> int:
        exit_code = 0
        try:
            hello_body = {
                "schema_version": CAPSULE_BROKER_HELLO_SCHEMA_VERSION,
                "authority": self.authority.to_dict(),
                "limits": _limits_to_dict(self.controller.limits),
                "server_nonce": uuid.uuid4().hex,
            }
            send_packet(
                self.channel,
                {**hello_body, "hello_fingerprint": fingerprint(hello_body)},
            )
            while True:
                self._attest_peer()
                raw, descriptors = receive_packet(self.channel)
                if descriptors:
                    raise BrokerProtocolError(
                        "capsule broker protocol accepts no descriptors"
                    )
                request = BrokerRequest.from_dict(raw)
                if request.sequence != self.sequence + 1:
                    raise BrokerProtocolError("capsule broker replay or sequence gap")
                if request.operation == "SHUTDOWN":
                    require_exact_keys(
                        request.payload, set(), "capsule shutdown payload"
                    )
                    if any(handle.container_alive for handle in self.sessions.values()):
                        result = BrokerResult.create(
                            request=request,
                            classification="REFUSED",
                            terminal=True,
                            payload={"reason": "active capsule sessions remain"},
                        )
                    else:
                        result = BrokerResult.create(
                            request=request,
                            classification="SUCCEEDED",
                            terminal=True,
                            payload={
                                "broker_cleanup_complete": True,
                                "terminal_evidence_count": len(self.terminal_evidence),
                            },
                        )
                    send_packet(self.channel, result.to_dict())
                    self.sequence = request.sequence
                    break
                try:
                    payload, terminal = self._dispatch(request)
                    classification = "SUCCEEDED"
                except ValueError as error:
                    payload = {
                        "refusal": str(error)[:1024],
                        "docker_absence_claimed": False,
                    }
                    terminal = False
                    classification = "REFUSED"
                except (OSError, RuntimeError) as error:
                    payload = {
                        "failure_type": type(error).__name__,
                        "docker_state": "UNKNOWN",
                        "docker_absence_claimed": False,
                    }
                    terminal = True
                    classification = "UNKNOWN"
                    exit_code = 1
                result = BrokerResult.create(
                    request=request,
                    classification=classification,
                    terminal=terminal,
                    payload=payload,
                )
                send_packet(self.channel, result.to_dict())
                self.sequence = request.sequence
                if classification == "UNKNOWN":
                    break
        except (EOFError, BrokerProtocolError, OSError, ValueError):
            exit_code = 1
        finally:
            if not self._cleanup_all():
                exit_code = 1
            self.channel.close()
        return exit_code


class CapsuleBrokerClient:
    """The general controller's only capsule authority."""

    def __init__(
        self,
        transport: SingleOwnerBrokerClient,
        *,
        process_pid: int,
        authority: CapsuleBrokerAuthority,
        limits: DockerCapsuleLimits,
        owns_process: bool = True,
    ):
        self._transport = transport
        self.process_pid = process_pid
        self.owns_process = owns_process
        self.broker_authority = authority.validated()
        self.limits = limits.validated()
        execution = self.broker_authority.capsule_execution_authority
        self.execution_authority = CapsuleExecutionAuthority(
            schema_version=execution["schema_version"],
            image_identity=execution["image_identity"],
            security_profile=MappingProxyType(dict(execution["security_profile"])),
            authority_fingerprint=execution["authority_fingerprint"],
        ).validated()
        controller = self.broker_authority.docker_controller_authority
        self.controller_authority = BrokerControllerAuthority(
            controller_fingerprint=self.broker_authority.authority_fingerprint,
            broker_authority_fingerprint=self.broker_authority.authority_fingerprint,
            docker_controller_fingerprint=controller["controller_fingerprint"],
            protocol_schema_identities=MappingProxyType(protocol_schema_identities()),
        ).validated()
        self.docker_component_identity = dict(
            self.broker_authority.docker_executable_identity
        )
        self._handles: dict[str, BrokerWorkspaceHandle] = {}
        self._wire_bindings: dict[str, tuple[str, str]] = {}
        self.broker_terminal_evidence: Mapping[str, Any] | None = None
        self.complete_boundary_terminal_fingerprint: str | None = None
        self.closed = False

    def attest_authority(self) -> None:
        self.broker_authority.validated()
        if self.owns_process:
            try:
                waited, _status = os.waitpid(self.process_pid, os.WNOHANG)
            except ChildProcessError as error:
                raise BrokerProtocolError("capsule broker process is not owned") from error
            if waited:
                raise BrokerProtocolError(
                    "capsule broker exited before terminal protocol"
                )
        else:
            try:
                os.kill(self.process_pid, 0)
            except ProcessLookupError as error:
                raise BrokerProtocolError(
                    "capsule broker exited before terminal protocol"
                ) from error

    def _request(
        self,
        *,
        operation: str,
        handle: BrokerWorkspaceHandle | None,
        backend_session_id: str,
        payload: Mapping[str, Any],
        tool_call_identity: str,
        controller_session_id: str | None = None,
        capsule_session_id: str | None = None,
    ) -> BrokerResult:
        if handle is not None:
            controller_session_id, capsule_session_id = self._wire_bindings[
                handle.session_id
            ]
        assert controller_session_id is not None
        assert capsule_session_id is not None
        sequence = self._transport.sequence + 1
        request = BrokerRequest.create(
            request_id=f"broker-request-{sequence}",
            operation=operation,
            backend_session_id=backend_session_id,
            controller_session_id=controller_session_id,
            capsule_session_id=capsule_session_id,
            authority_fingerprint=self.broker_authority.authority_fingerprint,
            sequence=sequence,
            tool_call_identity=tool_call_identity,
            payload=payload,
        )
        result = self._transport.transact(request)
        if result.classification != "SUCCEEDED":
            raise BrokerProtocolError(
                f"capsule broker {result.classification.lower()}: "
                f"{dict(result.payload)!r}"
            )
        return result

    def prepare(
        self,
        *,
        session_id: str,
        workspace_id: str,
        mission_authority_fingerprint: str | None = None,
    ) -> BrokerWorkspaceHandle:
        self.attest_authority()
        mission = mission_authority_fingerprint or fingerprint(
            {"legacy_capsule_session": session_id}
        )
        controller_id = f"controller-channel-{uuid.uuid4().hex}"
        capsule_id = f"capsule-channel-{uuid.uuid4().hex}"
        result = self._request(
            operation="CREATE_SESSION",
            handle=None,
            backend_session_id=session_id,
            controller_session_id=controller_id,
            capsule_session_id=capsule_id,
            tool_call_identity="lifecycle-create-session",
            payload={
                "workspace_id": workspace_id,
                "mission_authority_fingerprint": mission,
            },
        )
        handle = _local_handle(result.payload["handle"])
        self._handles[workspace_id] = handle
        self._wire_bindings[session_id] = (controller_id, capsule_id)
        return handle

    def recover_cleanup(
        self,
        handle: BrokerWorkspaceHandle,
    ) -> Mapping[str, Any]:
        """Clean one journal-recovered handle through the closed broker."""

        self.attest_authority()
        result = self._request(
            operation="RECOVER_CLEANUP",
            handle=None,
            backend_session_id=handle.session_id,
            controller_session_id=f"recovery-controller-{uuid.uuid4().hex}",
            capsule_session_id=f"recovery-capsule-{uuid.uuid4().hex}",
            tool_call_identity=f"recovery-cleanup-{handle.capsule_handle}",
            payload={"handle": _public_handle(handle)},
        )
        return result.payload

    def execute(
        self,
        handle: BrokerWorkspaceHandle,
        request: DurableToolRequest,
    ) -> DurableToolResult:
        result = self._request(
            operation="EXECUTE_TOOL",
            handle=handle,
            backend_session_id=handle.session_id,
            tool_call_identity=request.request_fingerprint,
            payload={"durable_tool_request": request.to_dict()},
        )
        return DurableToolResult.from_dict(result.payload["durable_tool_result"])

    def freeze_output(self, handle: BrokerWorkspaceHandle) -> ByteTreeObservation:
        result = self._request(
            operation="FREEZE_WORKSPACE",
            handle=handle,
            backend_session_id=handle.session_id,
            tool_call_identity="lifecycle-freeze-workspace",
            payload={},
        )
        observation = ByteTreeObservation.from_dict(result.payload["observation"])
        refreshed = _local_handle(result.payload["handle"])
        handle.frozen_workspace_fingerprint = refreshed.frozen_workspace_fingerprint
        handle.frozen_observation = observation
        return observation

    def observe_frozen_output(
        self, handle: BrokerWorkspaceHandle
    ) -> ByteTreeObservation:
        result = self._request(
            operation="OBSERVE_FROZEN",
            handle=handle,
            backend_session_id=handle.session_id,
            tool_call_identity="lifecycle-observe-frozen",
            payload={},
        )
        return ByteTreeObservation.from_dict(result.payload["observation"])

    def bind_frozen_snapshot(
        self,
        handle: BrokerWorkspaceHandle,
        *,
        journal_tail_fingerprint: str,
        cleanup_fingerprint: str,
    ) -> str:
        result = self._request(
            operation="BIND_FROZEN",
            handle=handle,
            backend_session_id=handle.session_id,
            tool_call_identity="lifecycle-bind-frozen",
            payload={
                "journal_tail_fingerprint": journal_tail_fingerprint,
                "cleanup_fingerprint": cleanup_fingerprint,
            },
        )
        binding = require_sha256(
            result.payload["frozen_binding_fingerprint"],
            "broker frozen binding",
        )
        handle.frozen_binding_fingerprint = binding
        return binding

    def cleanup(
        self, handle: BrokerWorkspaceHandle
    ) -> ControllerCleanupEvidence:
        result = self._request(
            operation="TERMINATE_CLEANUP",
            handle=handle,
            backend_session_id=handle.session_id,
            tool_call_identity="lifecycle-terminate-cleanup",
            payload={},
        )
        refreshed = _local_handle(result.payload["handle"])
        for name in (
            "container_alive",
            "capsule_exit_code",
            "capsule_exit_normal",
            "capsule_exit_forced",
            "capsule_exit_observed",
            "container_quarantined",
        ):
            setattr(handle, name, getattr(refreshed, name))
        self.broker_terminal_evidence = dict(result.payload)
        return ControllerCleanupEvidence(**dict(result.payload["cleanup"]))

    def frozen_output_path(self, workspace_id: str) -> Path:
        handle = self._handles[workspace_id]
        result = self._request(
            operation="GET_FROZEN_REFERENCE",
            handle=handle,
            backend_session_id=handle.session_id,
            tool_call_identity="lifecycle-frozen-reference",
            payload={},
        )
        path = Path(result.payload["broker_owned_frozen_path"])
        if not path.is_absolute() or ".." in path.parts:
            raise BrokerProtocolError("broker returned an invalid frozen reference")
        return path

    def shutdown(self) -> Mapping[str, Any]:
        if self.closed:
            return self.broker_terminal_evidence or {}
        result = self._request(
            operation="SHUTDOWN",
            handle=None,
            backend_session_id="broker-lifecycle",
            controller_session_id="broker-controller-lifecycle",
            capsule_session_id="broker-capsule-lifecycle",
            tool_call_identity="lifecycle-shutdown",
            payload={},
        )
        self._transport.close()
        self.closed = True
        if self.owns_process:
            waited, status = os.waitpid(self.process_pid, 0)
            if waited != self.process_pid:
                raise RuntimeError("wrong capsule broker process reaped")
            exit_code = os.waitstatus_to_exitcode(status)
        else:
            exit_code = None
        evidence = {
            **dict(result.payload),
            "broker_exit_code": exit_code,
            "broker_exit_normal": exit_code == 0 if exit_code is not None else False,
            "broker_reap_owner": (
                "controller" if self.owns_process else "boundary_launcher"
            ),
        }
        evidence["broker_process_terminal_fingerprint"] = fingerprint(evidence)
        self.broker_terminal_evidence = evidence
        if exit_code not in {0, None}:
            raise BrokerProtocolError("capsule broker process exited nonzero")
        return evidence

    def release_for_confined_controller(self) -> tuple[int, Mapping[str, Any]]:
        """Launcher-side one-time transfer; no Docker object is exposed."""

        if self._handles or self.closed:
            raise BrokerProtocolError("active capsule broker cannot be handed off")
        descriptor = self._transport.release_inherited_descriptor()
        self.closed = True
        metadata = {
            "process_pid": self.process_pid,
            "authority": self.broker_authority.to_dict(),
            "limits": _limits_to_dict(self.limits),
            "peer_creation_pid": os.getpid(),
        }
        body = {**metadata, "handoff_fingerprint": fingerprint(metadata)}
        return descriptor, body

    @classmethod
    def from_inherited_controller_handoff(
        cls,
        descriptor: int,
        metadata: Mapping[str, Any],
    ) -> "CapsuleBrokerClient":
        require_exact_keys(
            metadata,
            {
                "process_pid",
                "authority",
                "limits",
                "peer_creation_pid",
                "handoff_fingerprint",
            },
            "capsule broker controller handoff",
        )
        body = {
            key: metadata[key]
            for key in metadata
            if key != "handoff_fingerprint"
        }
        if fingerprint(body) != metadata["handoff_fingerprint"]:
            raise BrokerProtocolError("capsule broker handoff fingerprint mismatch")
        process_pid = metadata["process_pid"]
        peer_pid = metadata["peer_creation_pid"]
        if (
            isinstance(process_pid, bool)
            or not isinstance(process_pid, int)
            or process_pid <= 1
            or isinstance(peer_pid, bool)
            or not isinstance(peer_pid, int)
            or peer_pid <= 1
        ):
            raise BrokerProtocolError("capsule broker handoff process identity invalid")
        channel = socket.socket(fileno=descriptor)
        return cls(
            SingleOwnerBrokerClient(channel, expected_peer_pid=peer_pid),
            process_pid=process_pid,
            authority=CapsuleBrokerAuthority.from_dict(metadata["authority"]),
            limits=_limits_from_dict(metadata["limits"]),
            owns_process=False,
        )

    def bind_complete_boundary_terminal(
        self,
        evidence: Mapping[str, Any],
    ) -> str:
        """Accept only the launcher's closed aggregate of all terminal records."""

        require_exact_keys(
            evidence,
            {
                "os_boundary_authority_fingerprint",
                "authentication_cleanup_fingerprint",
                "codex_process_terminal_fingerprint",
                "egress_terminal_fingerprint",
                "capsule_broker_terminal_fingerprint",
                "journal_tail_fingerprint",
                "all_process_trees_reaped",
                "all_namespaces_reaped",
                "all_sockets_closed",
            },
            "complete boundary terminal evidence",
        )
        for key in (
            "os_boundary_authority_fingerprint",
            "authentication_cleanup_fingerprint",
            "codex_process_terminal_fingerprint",
            "egress_terminal_fingerprint",
            "capsule_broker_terminal_fingerprint",
            "journal_tail_fingerprint",
        ):
            require_sha256(evidence[key], key)
        if any(
            evidence[key] is not True
            for key in (
                "all_process_trees_reaped",
                "all_namespaces_reaped",
                "all_sockets_closed",
            )
        ):
            raise ValueError("complete boundary terminal cleanup is unproven")
        if (
            evidence["capsule_broker_terminal_fingerprint"]
            != (
                self.broker_terminal_evidence or {}
            ).get("terminal_fingerprint")
        ):
            raise ValueError("boundary aggregate names another capsule terminal")
        self.complete_boundary_terminal_fingerprint = fingerprint(evidence)
        return self.complete_boundary_terminal_fingerprint


class CapsuleBrokerProcess:
    @classmethod
    def start(cls, config: CapsuleBrokerConfig) -> CapsuleBrokerClient:
        config.validated()
        for root in (config.workspace_root, config.frozen_output_root):
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if root.is_symlink():
                raise ValueError("capsule broker root is a symlink")
        parent, child = make_seqpacket_socketpair()
        launcher_pid = os.getpid()
        bwrap_path = Path("/usr/bin/bwrap")
        python_path = Path(f"/usr/bin/python{sys.version_info.major}.{sys.version_info.minor}")
        stdlib_path = Path(
            f"/usr/lib/python{sys.version_info.major}.{sys.version_info.minor}"
        )
        multiarch = sysconfig.get_config_var("MULTIARCH")
        if not isinstance(multiarch, str) or not multiarch:
            raise RuntimeError("Python multiarch runtime identity is unavailable")
        platform_libraries = Path("/lib") / multiarch
        loader_source = Path("/lib64/ld-linux-x86-64.so.2")
        if platform.machine() in {"aarch64", "arm64"}:
            loader_source = Path("/lib/ld-linux-aarch64.so.1")
        loader_source = Path(os.path.realpath(loader_source))
        docker_source = Path(os.path.realpath(config.docker_executable))
        capsule_package = Path(__file__).parent
        docker_socket = Path("/var/run/docker.sock")

        descriptors: list[int] = []

        def open_source(path: Path, *, directory: bool = False) -> int:
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if directory:
                flags |= os.O_DIRECTORY
            descriptor = os.open(path, flags)
            descriptors.append(descriptor)
            return descriptor

        bwrap_fd = open_source(bwrap_path)
        python_fd = open_source(python_path)
        stdlib_fd = open_source(stdlib_path, directory=True)
        platform_libraries_fd = open_source(platform_libraries, directory=True)
        loader_fd = open_source(loader_source)
        docker_fd = open_source(docker_source)
        capsule_package_fd = open_source(capsule_package, directory=True)
        admissible_init_fd = os.memfd_create(
            "admissible-capsule-broker-package-init",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        descriptors.append(admissible_init_fd)
        fcntl.fcntl(
            admissible_init_fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        workspace_fd = open_source(config.workspace_root, directory=True)
        frozen_fd = open_source(config.frozen_output_root, directory=True)
        docker_socket_fd = os.open(
            docker_socket,
            os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        descriptors.append(docker_socket_fd)

        config_body = {
            "schema_version": CAPSULE_BROKER_CONFIG_SCHEMA_VERSION,
            "workspace_root": os.fspath(config.workspace_root),
            "frozen_output_root": os.fspath(config.frozen_output_root),
            "limits": _limits_to_dict(config.limits),
            "docker_executable": "/runtime/docker",
            # Linux reports an inherited peer outside a private PID namespace
            # as PID zero.  The unnameable socketpair still binds possession
            # to the launcher, and the outside client independently checks
            # SO_PEERCRED against launcher_pid.
            "expected_peer_pid": 0,
        }
        config_bytes = canonical_bytes(
            {**config_body, "config_fingerprint": fingerprint(config_body)}
        )
        config_fd = os.memfd_create(
            "admissible-capsule-broker-config",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        descriptors.append(config_fd)
        os.write(config_fd, config_bytes)
        os.lseek(config_fd, 0, os.SEEK_SET)
        fcntl.fcntl(
            config_fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )

        destination_parents: list[str] = []
        seen_parents: set[str] = {
            "/tmp",
            "/runtime",
            "/var",
            "/var/run",
            "/lib",
            "/lib64",
        }
        for root in (config.workspace_root, config.frozen_output_root):
            for parent_path in reversed(root.parents):
                rendered = os.fspath(parent_path)
                if rendered == "/" or rendered in seen_parents:
                    continue
                seen_parents.add(rendered)
                destination_parents.append(rendered)

        bwrap_arguments: list[str] = [
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/runtime",
            "--dir",
            "/runtime/site",
            "--dir",
            "/runtime/site/admissible",
            "--tmpfs",
            "/usr",
            "--dir",
            "/usr/bin",
            "--dir",
            "/usr/lib",
            "--tmpfs",
            "/lib",
            "--dir",
            os.fspath(Path("/lib") / multiarch),
            "--tmpfs",
            "/lib64",
            "--tmpfs",
            "/var",
            "--dir",
            "/var/run",
        ]
        for destination in destination_parents:
            bwrap_arguments.extend(("--dir", destination))
        bwrap_arguments.extend(
            (
                "--ro-bind-fd",
                str(python_fd),
                os.fspath(python_path),
                "--ro-bind-fd",
                str(stdlib_fd),
                os.fspath(stdlib_path),
                "--ro-bind-fd",
                str(platform_libraries_fd),
                os.fspath(Path("/lib") / multiarch),
                "--ro-bind-fd",
                str(loader_fd),
                (
                    "/lib/ld-linux-aarch64.so.1"
                    if platform.machine() in {"aarch64", "arm64"}
                    else "/lib64/ld-linux-x86-64.so.2"
                ),
                "--ro-bind-fd",
                str(docker_fd),
                "/runtime/docker",
                "--ro-bind-fd",
                str(capsule_package_fd),
                "/runtime/site/admissible/capsule",
                "--ro-bind-data",
                str(admissible_init_fd),
                "/runtime/site/admissible/__init__.py",
                "--bind-fd",
                str(workspace_fd),
                os.fspath(config.workspace_root),
                "--bind-fd",
                str(frozen_fd),
                os.fspath(config.frozen_output_root),
                "--bind-fd",
                str(docker_socket_fd),
                "/var/run/docker.sock",
                "--remount-ro",
                "/runtime",
                "--remount-ro",
                "/usr",
                "--remount-ro",
                "/lib",
                "--remount-ro",
                "/lib64",
                "--remount-ro",
                "/var",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--setenv",
                "HOME",
                "/nonexistent",
                "--setenv",
                "DOCKER_CONFIG",
                "/nonexistent",
                "--setenv",
                "PYTHONDONTWRITEBYTECODE",
                "1",
                "--setenv",
                "CAPSULE_BROKER_CHANNEL_FD",
                str(child.fileno()),
                "--setenv",
                "CAPSULE_BROKER_CONFIG_FD",
                str(config_fd),
                "--chdir",
                "/runtime",
            )
        )
        broker_command = (
            os.fspath(python_path),
            "-I",
            "-c",
            (
                "import sys;"
                "sys.path.insert(0,'/runtime/site');"
                "from admissible.capsule.capsule_broker import "
                "capsule_broker_subprocess_main;"
                "raise SystemExit(capsule_broker_subprocess_main())"
            ),
        )
        arguments_fd = os.memfd_create(
            "admissible-capsule-broker-bwrap-args",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        descriptors.append(arguments_fd)
        os.write(
            arguments_fd,
            b"\0".join(item.encode("utf-8") for item in bwrap_arguments),
        )
        os.lseek(arguments_fd, 0, os.SEEK_SET)
        fcntl.fcntl(
            arguments_fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        process = subprocess.Popen(
            (
                "bwrap-content-attested",
                "--args",
                str(arguments_fd),
                *broker_command,
            ),
            executable=f"/proc/self/fd/{bwrap_fd}",
            pass_fds=(
                *descriptors,
                child.fileno(),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": "/nonexistent",
            },
            cwd="/",
            start_new_session=True,
            close_fds=True,
        )
        pid = process.pid
        child.close()
        for descriptor in descriptors:
            os.close(descriptor)
        parent.settimeout(10)
        try:
            raw, received_descriptors = receive_packet(parent)
        except BaseException as error:
            parent.close()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            startup_stderr = (
                process.stderr.read(16384).decode("utf-8", "replace")
                if process.stderr is not None
                else ""
            )
            raise BrokerProtocolError(
                f"confined capsule broker failed to start: {startup_stderr}"
            ) from error
        parent.settimeout(None)
        if process.stderr is not None:
            process.stderr.close()
        if received_descriptors:
            for descriptor in received_descriptors:
                os.close(descriptor)
            parent.close()
            raise BrokerProtocolError("capsule broker hello carried descriptors")
        require_exact_keys(
            raw,
            {
                "schema_version",
                "authority",
                "limits",
                "server_nonce",
                "hello_fingerprint",
            },
            "capsule broker hello",
        )
        body = {key: raw[key] for key in raw if key != "hello_fingerprint"}
        if (
            raw["schema_version"] != CAPSULE_BROKER_HELLO_SCHEMA_VERSION
            or fingerprint(body) != raw["hello_fingerprint"]
        ):
            parent.close()
            raise BrokerProtocolError("capsule broker hello fingerprint mismatch")
        authority = CapsuleBrokerAuthority.from_dict(raw["authority"])
        limits = _limits_from_dict(raw["limits"])
        return CapsuleBrokerClient(
            SingleOwnerBrokerClient(parent, expected_peer_pid=launcher_pid),
            process_pid=pid,
            authority=authority,
            limits=limits,
        )

    @classmethod
    def recover_after_forced_exit(
        cls,
        config: CapsuleBrokerConfig,
        handles: tuple[BrokerWorkspaceHandle, ...],
    ) -> Mapping[str, Any]:
        """Run exact ownership-proving cleanup in a replacement broker child."""

        config.validated()
        client = cls.start(config)
        try:
            results = [client.recover_cleanup(handle) for handle in handles]
            terminal = client.shutdown()
            if terminal.get("broker_exit_normal") is not True:
                raise BrokerProtocolError("recovery broker exit is unknown")
        except BaseException:
            if not client.closed:
                client._transport.close()
            raise
        body = {
            "classification": (
                "FAILED_CLEANED"
                if all(
                    item["cleanup"]["container_removed"]
                    and item["cleanup"]["volume_removed"]
                    and item["cleanup"]["complete_process_tree_reaped"]
                    for item in results
                )
                else "FAILED_CLEANUP_UNKNOWN"
            ),
            "results": results,
            "ownership_proved_before_removal": all(
                item["ownership_proved_before_removal"] for item in results
            ),
            "docker_absence_inferred_from_failure": False,
            "recovery_broker_terminal_fingerprint": terminal[
                "broker_process_terminal_fingerprint"
            ],
        }
        value = {**body, "recovery_fingerprint": fingerprint(body)}
        if value["classification"] != "FAILED_CLEANED":
            raise BrokerProtocolError("recovery broker cleanup is unknown")
        return value
