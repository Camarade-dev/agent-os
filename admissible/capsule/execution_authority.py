"""Canonical immutable authority for one host-Codex/Docker execution."""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.codex_protocol import (
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    protocol_schema_identity,
)
from admissible.capsule.common import (
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    sha256_bytes,
)


FILE_IDENTITY_SCHEMA_VERSION = "admissible_executable_file_identity_v1"
BACKEND_EXECUTION_AUTHORITY_SCHEMA_VERSION = (
    "admissible_host_codex_docker_execution_authority_v4"
)
HOST_CODEX_BACKEND_KIND = "host_codex_app_server_capsule_v1"


def _secure_lexical_path(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if ".." in path.parts:
        raise ValueError(f"{label} must not contain a '..' alias")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} has a symlinked component: {current}")
    return path


@dataclass(frozen=True)
class ExecutableFileIdentity:
    schema_version: str
    canonical_path: str
    sha256: str
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    identity_fingerprint: str

    @classmethod
    def attest(cls, path: Path, *, label: str) -> "ExecutableFileIdentity":
        exact = _secure_lexical_path(path, label)
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(exact, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{label} must be a regular file")
            if before.st_mode & 0o111 == 0:
                raise ValueError(f"{label} must be executable")
            hasher = hashlib.sha256()
            while True:
                block = os.read(descriptor, 256 * 1024)
                if not block:
                    break
                hasher.update(block)
            after = os.fstat(descriptor)
            identity = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
            )
            if identity != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ValueError(f"{label} changed during content attestation")
        finally:
            os.close(descriptor)
        body = {
            "schema_version": FILE_IDENTITY_SCHEMA_VERSION,
            "canonical_path": os.fspath(exact),
            "sha256": hasher.hexdigest(),
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode": stat.S_IMODE(before.st_mode),
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
        }
        return cls(**body, identity_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "canonical_path": self.canonical_path,
            "sha256": self.sha256,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
        }

    def validated(self) -> "ExecutableFileIdentity":
        if self.schema_version != FILE_IDENTITY_SCHEMA_VERSION:
            raise ValueError("unsupported executable identity schema")
        path = _secure_lexical_path(Path(self.canonical_path), "attested executable")
        if os.fspath(path) != self.canonical_path:
            raise ValueError("executable path is not canonical")
        require_sha256(self.sha256, "executable content identity")
        for label, value, maximum in (
            ("executable device", self.device, 2**63 - 1),
            ("executable inode", self.inode, 2**63 - 1),
            ("executable mode", self.mode, 0o7777),
            ("executable size", self.size, 2**63 - 1),
            ("executable mtime", self.mtime_ns, 2**63 - 1),
        ):
            require_strict_int(value, label, minimum=0, maximum=maximum)
        require_sha256(self.identity_fingerprint, "executable identity fingerprint")
        if fingerprint(self._body()) != self.identity_fingerprint:
            raise ValueError("executable identity fingerprint mismatch")
        return self

    def reattest(self, *, label: str) -> "ExecutableFileIdentity":
        observed = type(self).attest(Path(self.canonical_path), label=label)
        if observed != self:
            raise ValueError(f"{label} identity changed after authority construction")
        return observed

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "identity_fingerprint": self.identity_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutableFileIdentity":
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
            "executable file identity",
        )
        return cls(**dict(value)).validated()


def synthetic_component_identity(
    *,
    component: str,
    fixture_material: Any,
    provider_request_capable: bool = False,
) -> Mapping[str, Any]:
    require_identifier(component, "synthetic component")
    require_bool(provider_request_capable, "synthetic provider_request_capable")
    body = {
        "kind": "synthetic_provider_free_fixture",
        "component": component,
        "fixture_fingerprint": fingerprint(fixture_material),
        "provider_request_capable": provider_request_capable,
    }
    return {**body, "identity_fingerprint": fingerprint(body)}


def source_component_identity(
    *,
    component: str,
    source_bytes: bytes,
    provider_request_capable: bool,
) -> Mapping[str, Any]:
    require_identifier(component, "source component")
    if not isinstance(source_bytes, bytes) or not source_bytes:
        raise ValueError("source component requires exact non-empty source bytes")
    require_bool(provider_request_capable, "source provider_request_capable")
    body = {
        "kind": "source_attested_component",
        "component": component,
        "source_sha256": sha256_bytes(source_bytes),
        "provider_request_capable": provider_request_capable,
    }
    return {**body, "identity_fingerprint": fingerprint(body)}


def validate_component_identity(value: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an attested component identity")
    if value.get("schema_version") == FILE_IDENTITY_SCHEMA_VERSION:
        ExecutableFileIdentity.from_dict(value)
        return dict(value)
    kind = value.get("kind")
    if kind == "source_attested_component":
        require_exact_keys(
            value,
            {
                "kind",
                "component",
                "source_sha256",
                "provider_request_capable",
                "identity_fingerprint",
            },
            label,
        )
        require_identifier(value["component"], f"{label} component")
        require_sha256(value["source_sha256"], f"{label} source identity")
        require_bool(
            value["provider_request_capable"],
            f"{label} provider_request_capable",
        )
        body = {key: value[key] for key in value if key != "identity_fingerprint"}
        if fingerprint(body) != value["identity_fingerprint"]:
            raise ValueError(f"{label} identity fingerprint mismatch")
        return dict(value)
    if kind != "synthetic_provider_free_fixture":
        raise ValueError(f"{label} has an unknown attestation kind")
    require_exact_keys(
        value,
        {
            "kind",
            "component",
            "fixture_fingerprint",
            "provider_request_capable",
            "identity_fingerprint",
        },
        label,
    )
    require_identifier(value["component"], f"{label} component")
    require_sha256(value["fixture_fingerprint"], f"{label} fixture identity")
    if value["provider_request_capable"] is not False:
        raise ValueError(f"{label} synthetic fixture must not be provider-capable")
    body = {key: value[key] for key in value if key != "identity_fingerprint"}
    if fingerprint(body) != value["identity_fingerprint"]:
        raise ValueError(f"{label} identity fingerprint mismatch")
    return dict(value)


def validate_component_identity_metadata(
    value: Mapping[str, Any],
    label: str,
) -> Mapping[str, Any]:
    """Validate public identity bytes without reopening a hidden executable.

    The boundary launcher performs ``ExecutableFileIdentity.reattest`` before
    confinement.  The already-confined controller may validate the resulting
    immutable metadata but must not regain pathname access merely to validate
    it.
    """

    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an attested component identity")
    if value.get("schema_version") != FILE_IDENTITY_SCHEMA_VERSION:
        return validate_component_identity(value, label)
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
        label,
    )
    path = value["canonical_path"]
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or ".." in Path(path).parts
        or "\x00" in path
    ):
        raise ValueError(f"{label} has invalid canonical path metadata")
    require_sha256(value["sha256"], f"{label} content identity")
    for key, maximum in (
        ("device", 2**63 - 1),
        ("inode", 2**63 - 1),
        ("mode", 0o7777),
        ("size", 2**63 - 1),
        ("mtime_ns", 2**63 - 1),
    ):
        require_strict_int(
            value[key],
            f"{label} {key}",
            minimum=0,
            maximum=maximum,
        )
    require_sha256(
        value["identity_fingerprint"],
        f"{label} identity fingerprint",
    )
    body = {key: value[key] for key in value if key != "identity_fingerprint"}
    if fingerprint(body) != value["identity_fingerprint"]:
        raise ValueError(f"{label} identity fingerprint mismatch")
    return dict(value)


@dataclass(frozen=True)
class BackendExecutionAuthority:
    """Every authority and byte binding for one concrete backend session."""

    schema_version: str
    backend_kind: str
    app_server_protocol_version: str
    protocol_schema_identity: str
    capsule_authority_fingerprint: str
    generic_mission_fingerprint: str
    codex_executable_identity: Mapping[str, Any]
    model_authority: Mapping[str, Any]
    model_authority_fingerprint: str
    host_control_policy_fingerprint: str
    bwrap_executable_identity: Mapping[str, Any]
    bwrap_argv_policy_fingerprint: str
    controller_identity: str
    capsule_image_content_id: str
    docker_executable_identity: Mapping[str, Any]
    dynamic_tools_schema_identity: str
    protocol_request_policy_fingerprint: str
    mission_base64: str
    mission_fingerprint: str
    prompt_base64: str
    prompt_fingerprint: str
    backend_session_id: str
    run_id: str
    connection_mode: str
    connection_factory_identity: Mapping[str, Any]
    authentication_boundary_state: str
    os_boundary_authority: Mapping[str, Any]
    os_boundary_authority_fingerprint: str
    budgets: Mapping[str, Any]
    terminal_policy: Mapping[str, Any]
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        capsule_authority_fingerprint: str,
        generic_mission_fingerprint: str,
        codex_executable_identity: Mapping[str, Any],
        model_authority: Mapping[str, Any],
        host_control_policy_fingerprint: str,
        bwrap_executable_identity: Mapping[str, Any],
        bwrap_argv_policy_fingerprint: str,
        controller_identity: str,
        capsule_image_content_id: str,
        docker_executable_identity: Mapping[str, Any],
        dynamic_tools_schema_identity: str,
        protocol_request_policy_fingerprint: str,
        mission_bytes: bytes,
        prompt_bytes: bytes,
        backend_session_id: str,
        run_id: str,
        connection_mode: str,
        connection_factory_identity: Mapping[str, Any],
        authentication_boundary_state: str,
        budgets: Mapping[str, Any],
        terminal_policy: Mapping[str, Any],
        os_boundary_authority: Mapping[str, Any] | None = None,
    ) -> "BackendExecutionAuthority":
        if os_boundary_authority is None:
            if connection_mode != "synthetic_provider_free":
                raise ValueError(
                    "production execution requires an explicit OS boundary authority"
                )
            from admissible.capsule.boundary_launcher import (
                provider_free_os_boundary_authority,
            )

            boundary = provider_free_os_boundary_authority(
                dependent_identities=(
                    codex_executable_identity,
                    bwrap_executable_identity,
                    docker_executable_identity,
                    connection_factory_identity,
                ),
                dependent_authorities={
                    "capsule_image_content_id": capsule_image_content_id,
                    "capsule_execution_authority_fingerprint": fingerprint(
                        {
                            "image_identity": capsule_image_content_id,
                            "synthetic_compatibility": True,
                        }
                    ),
                    "capsule_broker_runtime_authority_fingerprint": (
                        controller_identity
                    ),
                    "codex_protocol_schema_identity": protocol_schema_identity(),
                    "dynamic_tools_schema_identity": dynamic_tools_schema_identity,
                },
            )
        else:
            from admissible.capsule.boundary_authority import OSBoundaryAuthority

            boundary = OSBoundaryAuthority.from_dict(os_boundary_authority)
        from admissible.capsule.model_authority import CodexModelAuthority

        bound_model = CodexModelAuthority.from_dict(model_authority)
        body = {
            "schema_version": BACKEND_EXECUTION_AUTHORITY_SCHEMA_VERSION,
            "backend_kind": HOST_CODEX_BACKEND_KIND,
            "app_server_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "protocol_schema_identity": protocol_schema_identity(),
            "capsule_authority_fingerprint": capsule_authority_fingerprint,
            "generic_mission_fingerprint": generic_mission_fingerprint,
            "codex_executable_identity": dict(codex_executable_identity),
            "model_authority": bound_model.to_dict(),
            "model_authority_fingerprint": bound_model.authority_fingerprint,
            "host_control_policy_fingerprint": host_control_policy_fingerprint,
            "bwrap_executable_identity": dict(bwrap_executable_identity),
            "bwrap_argv_policy_fingerprint": bwrap_argv_policy_fingerprint,
            "controller_identity": controller_identity,
            "capsule_image_content_id": capsule_image_content_id,
            "docker_executable_identity": dict(docker_executable_identity),
            "dynamic_tools_schema_identity": dynamic_tools_schema_identity,
            "protocol_request_policy_fingerprint": protocol_request_policy_fingerprint,
            "mission_base64": base64.b64encode(mission_bytes).decode("ascii"),
            "mission_fingerprint": sha256_bytes(mission_bytes),
            "prompt_base64": base64.b64encode(prompt_bytes).decode("ascii"),
            "prompt_fingerprint": sha256_bytes(prompt_bytes),
            "backend_session_id": backend_session_id,
            "run_id": run_id,
            "connection_mode": connection_mode,
            "connection_factory_identity": dict(connection_factory_identity),
            "authentication_boundary_state": authentication_boundary_state,
            "os_boundary_authority": boundary.to_dict(),
            "os_boundary_authority_fingerprint": boundary.authority_fingerprint,
            "budgets": dict(budgets),
            "terminal_policy": dict(terminal_policy),
        }
        return cls(**body, authority_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            key: (dict(value) if isinstance(value, Mapping) else value)
            for key, value in self.__dict__.items()
            if key != "authority_fingerprint"
        }

    def validated(self) -> "BackendExecutionAuthority":
        if self.schema_version != BACKEND_EXECUTION_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported backend execution authority")
        if self.backend_kind != HOST_CODEX_BACKEND_KIND:
            raise ValueError("arbitrary backend kind refused")
        if self.app_server_protocol_version != CODEX_APP_SERVER_PROTOCOL_VERSION:
            raise ValueError("wrong Codex app-server protocol version")
        if self.protocol_schema_identity != protocol_schema_identity():
            raise ValueError("generated protocol/schema identity mismatch")
        for label, value in (
            ("capsule authority", self.capsule_authority_fingerprint),
            ("generic mission", self.generic_mission_fingerprint),
            ("host-control policy", self.host_control_policy_fingerprint),
            ("bwrap argv policy", self.bwrap_argv_policy_fingerprint),
            ("controller", self.controller_identity),
            ("dynamic tools schema", self.dynamic_tools_schema_identity),
            ("protocol request policy", self.protocol_request_policy_fingerprint),
            ("mission", self.mission_fingerprint),
            ("prompt", self.prompt_fingerprint),
        ):
            require_sha256(value, f"{label} fingerprint")
        if (
            not self.capsule_image_content_id.startswith("sha256:")
            or len(self.capsule_image_content_id) != 71
        ):
            raise ValueError("capsule image authority is not an immutable content ID")
        require_sha256(
            self.capsule_image_content_id.removeprefix("sha256:"),
            "capsule image content ID",
        )
        if self.connection_mode not in {
            "production_bwrap",
            "production_os_boundary",
            "synthetic_provider_free",
        }:
            raise ValueError("connection mode substitution refused")
        component_validator = (
            validate_component_identity_metadata
            if self.connection_mode == "production_os_boundary"
            else validate_component_identity
        )
        component_validator(self.codex_executable_identity, "Codex executable")
        from admissible.capsule.model_authority import CodexModelAuthority

        bound_model = CodexModelAuthority.from_dict(self.model_authority)
        require_sha256(self.model_authority_fingerprint, "model authority fingerprint")
        if bound_model.authority_fingerprint != self.model_authority_fingerprint:
            raise ValueError("model authority binding differs")
        if dict(bound_model.codex_executable_identity) != dict(
            self.codex_executable_identity
        ):
            raise ValueError("model authority binds another Codex executable")
        if bound_model.to_dict()["app_server_protocol_version"] != (
            self.app_server_protocol_version
        ):
            raise ValueError("model authority binds another app-server protocol")
        if bound_model.to_dict()["protocol_schema_identity"] != (
            self.protocol_schema_identity
        ):
            raise ValueError("model authority binds another protocol schema identity")
        component_validator(self.bwrap_executable_identity, "bwrap executable")
        component_validator(self.docker_executable_identity, "Docker executable")
        factory_identity = component_validator(
            self.connection_factory_identity,
            "connection factory",
        )
        from admissible.capsule.boundary_authority import OSBoundaryAuthority

        boundary = OSBoundaryAuthority.from_dict(self.os_boundary_authority)
        require_sha256(
            self.os_boundary_authority_fingerprint,
            "OS boundary authority fingerprint",
        )
        if boundary.authority_fingerprint != self.os_boundary_authority_fingerprint:
            raise ValueError("OS boundary authority binding differs")
        mission = base64.b64decode(self.mission_base64, validate=True)
        prompt = base64.b64decode(self.prompt_base64, validate=True)
        if sha256_bytes(mission) != self.mission_fingerprint:
            raise ValueError("mission bytes and fingerprint disagree")
        if self.mission_fingerprint != self.generic_mission_fingerprint:
            raise ValueError("generic and concrete mission authority disagree")
        if sha256_bytes(prompt) != self.prompt_fingerprint:
            raise ValueError("prompt bytes and fingerprint disagree")
        require_identifier(self.backend_session_id, "backend session identity")
        require_identifier(self.run_id, "backend run identity")
        if self.authentication_boundary_state not in {
            "OS_ENFORCED",
            "SYNTHETIC_PROVIDER_FREE",
            "BLOCKED_PENDING_OS_ENFORCEMENT",
        }:
            raise ValueError("unknown authentication-boundary state")
        if (
            self.connection_mode in {"production_bwrap", "production_os_boundary"}
            and self.authentication_boundary_state != "OS_ENFORCED"
        ):
            raise ValueError("production launch requires an OS-enforced authentication boundary")
        if (
            self.connection_mode in {"production_bwrap", "production_os_boundary"}
            and factory_identity.get("provider_request_capable") is not True
        ):
            raise ValueError("production factory lacks a provider-capable source attestation")
        if (
            self.connection_mode == "synthetic_provider_free"
            and factory_identity.get("provider_request_capable") is not False
        ):
            raise ValueError("synthetic factory became provider-capable")
        dependent_fingerprints = {
            item["identity_fingerprint"] for item in boundary.dependent_identities
        }
        for label, identity in (
            ("Codex", self.codex_executable_identity),
            ("bubblewrap", self.bwrap_executable_identity),
            ("Docker", self.docker_executable_identity),
            ("connection factory", self.connection_factory_identity),
        ):
            if identity["identity_fingerprint"] not in dependent_fingerprints:
                raise ValueError(f"{label} identity is absent from OS boundary dependencies")
        if (
            boundary.dependent_authorities["capsule_image_content_id"]
            != self.capsule_image_content_id
            or boundary.dependent_authorities[
                "capsule_broker_runtime_authority_fingerprint"
            ]
            != self.controller_identity
            or boundary.dependent_authorities["codex_protocol_schema_identity"]
            != self.protocol_schema_identity
            or boundary.dependent_authorities["dynamic_tools_schema_identity"]
            != self.dynamic_tools_schema_identity
        ):
            raise ValueError("OS boundary image or protocol dependency differs")
        required_budgets = {
            "event_timeout_ms",
            "protocol_drain_timeout_ms",
            "protocol_drain_records",
            "app_server_message_bytes",
            "agent_text_bytes",
            "capsule_command_timeout_ms",
            "capsule_session_timeout_ms",
            "capsule_output_bytes",
            "capsule_workspace_bytes",
            "capsule_pids",
            "capsule_cpu_millis",
            "capsule_memory_bytes",
        }
        require_exact_keys(self.budgets, required_budgets, "backend budgets")
        for key, value in self.budgets.items():
            require_strict_int(value, key, minimum=1, maximum=2**63 - 1)
        require_exact_keys(
            self.terminal_policy,
            {
                "post_terminal_drain",
                "late_record_policy",
                "completion_requires",
            },
            "backend terminal policy",
        )
        if self.terminal_policy["post_terminal_drain"] != "BOUNDED_UNTIL_PROCESS_CLOSED":
            raise ValueError("terminal drain policy changed")
        if self.terminal_policy["late_record_policy"] != "FAIL_SESSION":
            raise ValueError("late protocol record policy changed")
        if self.terminal_policy["completion_requires"] != [
            "protocol_terminal",
            "app_server_process_closed",
            "capsule_cleanup",
            "frozen_provider_output",
        ]:
            raise ValueError("backend completion prerequisites changed")
        require_sha256(self.authority_fingerprint, "backend execution authority fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("backend execution authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "authority_fingerprint": self.authority_fingerprint}
