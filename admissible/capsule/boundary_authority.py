"""Canonical authority for the Codex authentication and service boundary.

The objects in this module are public metadata.  They deliberately contain no
authentication bytes, authentication source path, bearer header, cookie, or
TLS application data.  A string supplied by a caller is never accepted as an
OS attestation: executable identities are content/inode attestations and every
policy is a closed schema whose complete bytes are fingerprinted.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from admissible.capsule.common import (
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    require_strict_int,
)
from admissible.capsule.execution_authority import (
    validate_component_identity_metadata,
)


OS_BOUNDARY_AUTHORITY_SCHEMA_VERSION = "admissible_codex_os_boundary_authority_v1"
DESTINATION_MANIFEST_SCHEMA_VERSION = "admissible_codex_destination_manifest_v1"
SEALED_PIN_MANIFEST_SCHEMA_VERSION = "admissible_codex_sealed_pin_manifest_v1"
CODEX_BOUNDARY_VERSION = "0.145.0"

_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)


def _closed_mapping(
    value: Mapping[str, Any],
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    require_exact_keys(value, keys, label)
    return dict(value)


def _validate_hostname(value: Any, label: str) -> str:
    require_nonempty_text(value, label, max_bytes=253)
    if value != value.lower() or not _HOSTNAME.fullmatch(value):
        raise ValueError(f"{label} must be a canonical lower-case DNS name")
    return value


@dataclass(frozen=True)
class DestinationManifest:
    """Version-bound names Codex may request; this is not a DNS pin set."""

    schema_version: str
    codex_version: str
    policy_revision: str
    destinations: tuple[Mapping[str, Any], ...]
    dynamic_widening: bool
    manifest_fingerprint: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DestinationManifest":
        require_exact_keys(
            value,
            {
                "schema_version",
                "codex_version",
                "policy_revision",
                "destinations",
                "dynamic_widening",
                "manifest_fingerprint",
            },
            "destination authority manifest",
        )
        destinations = value["destinations"]
        if not isinstance(destinations, list):
            raise ValueError("destination manifest destinations must be a list")
        return cls(
            schema_version=value["schema_version"],
            codex_version=value["codex_version"],
            policy_revision=value["policy_revision"],
            destinations=tuple(MappingProxyType(dict(item)) for item in destinations),
            dynamic_widening=value["dynamic_widening"],
            manifest_fingerprint=value["manifest_fingerprint"],
        ).validated()

    @classmethod
    def load_packaged(cls) -> "DestinationManifest":
        resource = files("admissible.capsule").joinpath(
            "destination_manifests/codex-0.145.0-chatgpt.json"
        )
        value = json.loads(resource.read_text(encoding="utf-8"))
        return cls.from_dict(value)

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "codex_version": self.codex_version,
            "policy_revision": self.policy_revision,
            "destinations": [dict(item) for item in self.destinations],
            "dynamic_widening": self.dynamic_widening,
        }

    def validated(self) -> "DestinationManifest":
        if self.schema_version != DESTINATION_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported destination manifest schema")
        if self.codex_version != CODEX_BOUNDARY_VERSION:
            raise ValueError("destination manifest is not bound to Codex 0.145.0")
        require_identifier(self.policy_revision, "destination policy revision")
        if self.dynamic_widening is not False:
            raise ValueError("destination manifest must forbid dynamic widening")
        if not self.destinations:
            raise ValueError("destination manifest cannot be empty")
        observed: set[tuple[str, int]] = set()
        for item in self.destinations:
            require_exact_keys(
                item,
                {"hostname", "port", "evidence", "canary_requirement"},
                "destination manifest entry",
            )
            hostname = _validate_hostname(item["hostname"], "destination hostname")
            port = require_strict_int(
                item["port"], "destination port", minimum=1, maximum=65535
            )
            if port != 443:
                raise ValueError("Codex service manifest permits only port 443")
            if item["evidence"] not in {
                "OBSERVED_REQUIRED",
                "OBSERVED_STARTUP",
                "STATICALLY_DISCOVERED_NOT_EXERCISED",
            }:
                raise ValueError("unknown destination evidence status")
            if item["canary_requirement"] != "REFUSE_RUN_IF_UNSEALED_REQUESTED":
                raise ValueError("destination canary fail-closed policy changed")
            key = (hostname, port)
            if key in observed:
                raise ValueError("duplicate destination manifest entry")
            observed.add(key)
        require_sha256(self.manifest_fingerprint, "destination manifest fingerprint")
        if fingerprint(self._body()) != self.manifest_fingerprint:
            raise ValueError("destination manifest fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "manifest_fingerprint": self.manifest_fingerprint}

    @property
    def endpoints(self) -> frozenset[tuple[str, int]]:
        return frozenset(
            (str(item["hostname"]), int(item["port"])) for item in self.destinations
        )


@dataclass(frozen=True)
class SealedDestinationPinManifest:
    """The once-resolved public IP set used by one relay session."""

    schema_version: str
    authority_manifest_fingerprint: str
    session_id: str
    pins: tuple[Mapping[str, Any], ...]
    resolver_calls: int
    sealed: bool
    synthetic_provider_free: bool
    pin_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        authority_manifest: DestinationManifest,
        session_id: str,
        resolved: Mapping[tuple[str, int], Sequence[str]],
        synthetic_provider_free: bool = False,
    ) -> "SealedDestinationPinManifest":
        authority_manifest.validated()
        require_identifier(session_id, "pin session")
        require_bool(synthetic_provider_free, "synthetic pin mode")
        if set(resolved) != set(authority_manifest.endpoints):
            raise ValueError("pin input must cover the exact destination authority")
        pins: list[dict[str, Any]] = []
        for item in authority_manifest.destinations:
            endpoint = (str(item["hostname"]), int(item["port"]))
            addresses = tuple(sorted(set(resolved[endpoint])))
            if not addresses:
                raise ValueError("authorized destination resolved to no addresses")
            for address in addresses:
                parsed = ipaddress.ip_address(address)
                if not synthetic_provider_free and not parsed.is_global:
                    raise ValueError("production destination pin is not public")
            pins.append(
                {
                    "hostname": endpoint[0],
                    "port": endpoint[1],
                    "evidence": item["evidence"],
                    "ip_addresses": list(addresses),
                }
            )
        body = {
            "schema_version": SEALED_PIN_MANIFEST_SCHEMA_VERSION,
            "authority_manifest_fingerprint": authority_manifest.manifest_fingerprint,
            "session_id": session_id,
            "pins": pins,
            "resolver_calls": len(authority_manifest.destinations),
            "sealed": True,
            "synthetic_provider_free": synthetic_provider_free,
        }
        return cls(
            schema_version=body["schema_version"],
            authority_manifest_fingerprint=body["authority_manifest_fingerprint"],
            session_id=session_id,
            pins=tuple(MappingProxyType(item) for item in pins),
            resolver_calls=body["resolver_calls"],
            sealed=True,
            synthetic_provider_free=synthetic_provider_free,
            pin_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_manifest_fingerprint": self.authority_manifest_fingerprint,
            "session_id": self.session_id,
            "pins": [
                {
                    **dict(item),
                    "ip_addresses": list(item["ip_addresses"]),
                }
                for item in self.pins
            ],
            "resolver_calls": self.resolver_calls,
            "sealed": self.sealed,
            "synthetic_provider_free": self.synthetic_provider_free,
        }

    def validated(self) -> "SealedDestinationPinManifest":
        if self.schema_version != SEALED_PIN_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported pin manifest schema")
        require_sha256(
            self.authority_manifest_fingerprint,
            "pin authority manifest fingerprint",
        )
        require_identifier(self.session_id, "pin session")
        require_bool(self.synthetic_provider_free, "synthetic pin mode")
        if self.sealed is not True:
            raise ValueError("destination pins are not sealed")
        if not self.pins:
            raise ValueError("pin manifest cannot be empty")
        for item in self.pins:
            require_exact_keys(
                item,
                {"hostname", "port", "evidence", "ip_addresses"},
                "destination pin",
            )
            _validate_hostname(item["hostname"], "pinned hostname")
            if item["port"] != 443:
                raise ValueError("destination pin permits a non-443 port")
            addresses = item["ip_addresses"]
            if not isinstance(addresses, (list, tuple)) or not addresses:
                raise ValueError("destination pin requires addresses")
            for address in addresses:
                parsed = ipaddress.ip_address(address)
                if not self.synthetic_provider_free and not parsed.is_global:
                    raise ValueError("production destination pin is not public")
        if self.resolver_calls != len(self.pins):
            raise ValueError("destination resolution was not exactly once per name")
        require_sha256(self.pin_fingerprint, "destination pin fingerprint")
        if fingerprint(self._body()) != self.pin_fingerprint:
            raise ValueError("destination pin fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "pin_fingerprint": self.pin_fingerprint}

    def addresses_for(self, hostname: str, port: int) -> tuple[str, ...]:
        for item in self.pins:
            if item["hostname"] == hostname and item["port"] == port:
                return tuple(item["ip_addresses"])
        raise ValueError("CONNECT destination is absent from sealed pins")


def fixed_fd_topology() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_codex_boundary_fd_topology_v1",
        "inheritance": "closed_allowlist_close_fds",
        "channels": [
            {
                "name": "auth_source",
                "kind": "sealed_memfd_or_inherited_regular_fd",
                "endpoints": ["boundary_launcher", "authentication_broker"],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "codex_home",
                "kind": "directory_fd_bind_fd",
                "endpoints": ["authentication_broker", "codex_launcher"],
                "controller_visible": False,
                "codex_visible_after_handoff": True,
            },
            {
                "name": "codex_launch_inputs",
                "kind": (
                    "sealed_bwrap_options_memfd_plus_exact_executable_"
                    "and_runtime_fds"
                ),
                "endpoints": [
                    "boundary_launcher",
                    "bubblewrap",
                    "codex_namespace",
                ],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "app_server",
                "kind": "inherited_stream_socketpair",
                "endpoints": ["controller", "codex"],
                "controller_visible": True,
                "codex_visible_after_handoff": True,
            },
            {
                "name": "capsule_broker",
                "kind": "inherited_seqpacket_socketpair",
                "endpoints": ["controller", "capsule_broker"],
                "controller_visible": True,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "capsule_broker_config",
                "kind": "sealed_memfd",
                "endpoints": ["boundary_launcher", "capsule_broker"],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "capsule_broker_launch_inputs",
                "kind": (
                    "sealed_bwrap_options_memfd_plus_exact_runtime_"
                    "and_broker_root_fds"
                ),
                "endpoints": [
                    "boundary_launcher",
                    "bubblewrap",
                    "capsule_broker",
                ],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "docker_authority",
                "kind": "exact_executable_and_socket_fd_bindings",
                "endpoints": ["boundary_launcher", "capsule_broker"],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "proxy_listener_transfer",
                "kind": "scm_rights_seqpacket_socketpair",
                "endpoints": ["codex_namespace_wrapper", "egress_relay"],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
            {
                "name": "journal",
                "kind": "append_only_inherited_fd",
                "endpoints": ["boundary_launcher", "journal_writer"],
                "controller_visible": False,
                "codex_visible_after_handoff": False,
            },
        ],
    }


def fixed_controller_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_general_controller_confinement_v1",
        "mount_namespace": "empty_explicit_control_data_only",
        "landlock": "defense_in_depth_required_when_available",
        "network_namespace": "private_no_interfaces",
        "auth_source_visible": False,
        "ephemeral_codex_home_visible": False,
        "docker_socket_visible": False,
        "docker_executable_visible": False,
        "host_home_writable": False,
        "host_user_manager_sockets_visible": False,
        "path_unix_sockets": "only_inherited_broker_channels",
        "abstract_unix_sockets": "separate_network_namespace",
        "environment": [
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "HOME=/nonexistent",
            "APP_SERVER_FD=<inherited>",
            "CAPSULE_BROKER_FD=<inherited>",
        ],
        "inherited_descriptors": ["app_server", "capsule_broker"],
        "cwd": "/control",
    }


def fixed_codex_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_codex_confinement_policy_v1",
        "codex_version": CODEX_BOUNDARY_VERSION,
        "mount_namespace": "empty_exact_runtime_and_ephemeral_home",
        "pid_namespace": "private",
        "network_namespace": "private_loopback_only",
        "resolver": "absent",
        "workspace_visible": False,
        "source_repository_visible": False,
        "capsule_paths_visible": False,
        "finalizer_paths_visible": False,
        "docker_socket_visible": False,
        "host_unix_sockets_visible": False,
        "abstract_unix_sockets": "separate_network_namespace",
        "proc": "private_minimal",
        "dev": "minimal",
        "channels": ["app_server", "loopback_connect_proxy"],
        "environment": [
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "HOME=/control/codex-home",
            "CODEX_HOME=/control/codex-home",
            "PATH=/runtime",
            "APP_SERVER_FD=<inherited>",
            "PROXY_TRANSFER_FD=<inherited>",
            "BOUNDARY_SESSION_ID=<authority-bound>",
            "DESTINATION_PIN_FINGERPRINT=<sealed>",
        ],
        "cwd": "/control/empty-cwd",
        "inherited_descriptors": [
            "ephemeral_codex_home",
            "app_server",
            "proxy_listener_transfer",
            "exact_runtime_closure",
        ],
    }


def fixed_capsule_broker_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_capsule_broker_confinement_v1",
        "root_equivalent": True,
        "authentication_visible": False,
        "launch": "exec_clean_content_attested_bwrap",
        "mount_namespace": (
            "empty_exact_runtime_docker_socket_and_broker_owned_roots"
        ),
        "pid_namespace": "private_outside_peer_pid_zero",
        "network_namespace": "private_no_interfaces_except_docker_unix_socket",
        "user_namespace": "private_uid_gid_mapping",
        "cwd": "/runtime",
        "environment": [
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "HOME=/nonexistent",
            "DOCKER_CONFIG=/nonexistent",
            "PYTHONDONTWRITEBYTECODE=1",
            "CAPSULE_BROKER_CHANNEL_FD=<inherited>",
            "CAPSULE_BROKER_CONFIG_FD=<sealed>",
        ],
        "inherited_descriptors": [
            "closed_seqpacket_channel",
            "sealed_configuration",
            "content_attested_runtime_closure",
            "content_attested_docker_executable",
            "exact_docker_socket",
            "broker_owned_workspace_roots",
        ],
        "crash_recovery": "same_confined_closed_broker_protocol",
        "interface": "authority_bound_closed_seqpacket_protocol",
        "caller_host_bind_paths": False,
        "arbitrary_images": False,
        "generic_docker_commands": False,
        "privileged": False,
        "host_pid_namespace": False,
        "host_network_namespace": False,
        "docker_socket_mount_into_capsule": False,
        "arbitrary_devices": False,
        "additional_capabilities": False,
        "environment_inheritance": False,
        "ownership_proof_before_remove": True,
        "docker_failure_means_absence": False,
    }


def fixed_network_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_codex_egress_network_policy_v1",
        "codex_route": "loopback_only",
        "proxy_protocol": "CONNECT_ONLY",
        "ports": [443],
        "dns_in_codex_namespace": False,
        "resolve": "once_before_session_outside_codex_namespace",
        "connect": "stored_pinned_ip_without_reresolution",
        "tls": "end_to_end_not_terminated",
        "plaintext_inspection": False,
        "redirect_policy": "new_connect_must_already_be_sealed",
        "private_destinations": False,
        "loopback_destinations": False,
        "link_local_destinations": False,
        "unix_destinations": False,
    }


def fixed_auth_metadata_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_auth_source_metadata_policy_v1",
        "allowed_metadata": [
            "file_type",
            "device",
            "inode",
            "mode",
            "link_count",
            "owner_uid",
            "size",
            "mtime_ns",
        ],
        "forbidden_evidence": [
            "source_path",
            "content",
            "content_hash",
            "cookie",
            "token",
            "authorization_header",
        ],
        "regular_file": True,
        "symlinks": False,
        "hardlinks": False,
        "descriptor_handoff": True,
    }


def fixed_ephemeral_home_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_ephemeral_codex_home_policy_v1",
        "destination": "/control/codex-home",
        "auth_destination": "/control/codex-home/auth.json",
        "codex_writable": True,
        "controller_visible": False,
        "capsule_broker_visible": False,
        "capsule_visible": False,
        "real_source_in_codex_namespace_after_install": False,
        "backing": "broker_owned_private_tmpfs_or_private_directory",
    }


def fixed_cleanup_policy() -> Mapping[str, Any]:
    return {
        "schema_version": "admissible_codex_boundary_cleanup_policy_v1",
        "order": [
            "codex_process_tree_reaped",
            "proxy_listener_closed",
            "egress_sessions_closed",
            "capsule_frozen",
            "docker_objects_owner_attested_and_removed",
            "ephemeral_codex_home_overwritten_and_removed",
            "broker_sockets_closed",
            "namespaces_reaped",
            "terminal_evidence_fsynced",
            "provider_output_published",
        ],
        "missing_record_classification": "FAILED_OR_UNKNOWN_NEVER_SUCCESS",
        "docker_communication_failure": "UNKNOWN",
        "auth_cleanup": "overwrite_fsync_unlink_directory_fsync_remove",
    }


@dataclass(frozen=True)
class OSBoundaryAuthority:
    """One canonical binding for every executable, policy and wire schema."""

    schema_version: str
    boundary_launcher_identity: Mapping[str, Any]
    authentication_broker_identity: Mapping[str, Any]
    capsule_broker_identity: Mapping[str, Any]
    egress_relay_identity: Mapping[str, Any]
    broker_protocol_schema_identities: Mapping[str, str]
    fd_socket_topology: Mapping[str, Any]
    controller_confinement_policy: Mapping[str, Any]
    codex_confinement_policy: Mapping[str, Any]
    capsule_broker_confinement_policy: Mapping[str, Any]
    network_namespace_policy: Mapping[str, Any]
    destination_manifest_identity: str
    authentication_source_metadata_policy: Mapping[str, Any]
    ephemeral_codex_home_policy: Mapping[str, Any]
    cleanup_policy: Mapping[str, Any]
    dependent_identities: tuple[Mapping[str, Any], ...]
    dependent_authorities: Mapping[str, str]
    launch_fingerprint: str
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        boundary_launcher_identity: Mapping[str, Any],
        authentication_broker_identity: Mapping[str, Any],
        capsule_broker_identity: Mapping[str, Any],
        egress_relay_identity: Mapping[str, Any],
        broker_protocol_schema_identities: Mapping[str, str],
        destination_manifest: DestinationManifest,
        dependent_identities: Sequence[Mapping[str, Any]],
        dependent_authorities: Mapping[str, str],
    ) -> "OSBoundaryAuthority":
        destination_manifest.validated()
        launch_body = {
            "boundary_launcher_identity": dict(boundary_launcher_identity),
            "authentication_broker_identity": dict(authentication_broker_identity),
            "capsule_broker_identity": dict(capsule_broker_identity),
            "egress_relay_identity": dict(egress_relay_identity),
            "broker_protocol_schema_identities": dict(
                sorted(broker_protocol_schema_identities.items())
            ),
            "fd_socket_topology": fixed_fd_topology(),
            "controller_confinement_policy": fixed_controller_policy(),
            "codex_confinement_policy": fixed_codex_policy(),
            "capsule_broker_confinement_policy": fixed_capsule_broker_policy(),
            "network_namespace_policy": fixed_network_policy(),
            "destination_manifest_identity": destination_manifest.manifest_fingerprint,
            "authentication_source_metadata_policy": fixed_auth_metadata_policy(),
            "ephemeral_codex_home_policy": fixed_ephemeral_home_policy(),
            "cleanup_policy": fixed_cleanup_policy(),
            "dependent_identities": [dict(item) for item in dependent_identities],
            "dependent_authorities": dict(sorted(dependent_authorities.items())),
        }
        body = {
            "schema_version": OS_BOUNDARY_AUTHORITY_SCHEMA_VERSION,
            **launch_body,
            "launch_fingerprint": fingerprint(launch_body),
        }
        return cls(
            schema_version=body["schema_version"],
            boundary_launcher_identity=MappingProxyType(
                dict(boundary_launcher_identity)
            ),
            authentication_broker_identity=MappingProxyType(
                dict(authentication_broker_identity)
            ),
            capsule_broker_identity=MappingProxyType(dict(capsule_broker_identity)),
            egress_relay_identity=MappingProxyType(dict(egress_relay_identity)),
            broker_protocol_schema_identities=MappingProxyType(
                dict(sorted(broker_protocol_schema_identities.items()))
            ),
            fd_socket_topology=MappingProxyType(fixed_fd_topology()),
            controller_confinement_policy=MappingProxyType(fixed_controller_policy()),
            codex_confinement_policy=MappingProxyType(fixed_codex_policy()),
            capsule_broker_confinement_policy=MappingProxyType(
                fixed_capsule_broker_policy()
            ),
            network_namespace_policy=MappingProxyType(fixed_network_policy()),
            destination_manifest_identity=destination_manifest.manifest_fingerprint,
            authentication_source_metadata_policy=MappingProxyType(
                fixed_auth_metadata_policy()
            ),
            ephemeral_codex_home_policy=MappingProxyType(
                fixed_ephemeral_home_policy()
            ),
            cleanup_policy=MappingProxyType(fixed_cleanup_policy()),
            dependent_identities=tuple(
                MappingProxyType(dict(item)) for item in dependent_identities
            ),
            dependent_authorities=MappingProxyType(
                dict(sorted(dependent_authorities.items()))
            ),
            launch_fingerprint=body["launch_fingerprint"],
            authority_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "boundary_launcher_identity": dict(self.boundary_launcher_identity),
            "authentication_broker_identity": dict(
                self.authentication_broker_identity
            ),
            "capsule_broker_identity": dict(self.capsule_broker_identity),
            "egress_relay_identity": dict(self.egress_relay_identity),
            "broker_protocol_schema_identities": dict(
                self.broker_protocol_schema_identities
            ),
            "fd_socket_topology": dict(self.fd_socket_topology),
            "controller_confinement_policy": dict(
                self.controller_confinement_policy
            ),
            "codex_confinement_policy": dict(self.codex_confinement_policy),
            "capsule_broker_confinement_policy": dict(
                self.capsule_broker_confinement_policy
            ),
            "network_namespace_policy": dict(self.network_namespace_policy),
            "destination_manifest_identity": self.destination_manifest_identity,
            "authentication_source_metadata_policy": dict(
                self.authentication_source_metadata_policy
            ),
            "ephemeral_codex_home_policy": dict(self.ephemeral_codex_home_policy),
            "cleanup_policy": dict(self.cleanup_policy),
            "dependent_identities": [dict(item) for item in self.dependent_identities],
            "dependent_authorities": dict(self.dependent_authorities),
            "launch_fingerprint": self.launch_fingerprint,
        }

    def validated(self) -> "OSBoundaryAuthority":
        if self.schema_version != OS_BOUNDARY_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported OS boundary authority schema")
        for label, identity in (
            ("boundary launcher", self.boundary_launcher_identity),
            ("authentication broker", self.authentication_broker_identity),
            ("capsule broker", self.capsule_broker_identity),
            ("egress relay", self.egress_relay_identity),
        ):
            validate_component_identity_metadata(identity, label)
        if not self.broker_protocol_schema_identities:
            raise ValueError("boundary authority requires broker protocol schemas")
        for name, identity in self.broker_protocol_schema_identities.items():
            require_identifier(name, "broker protocol schema name")
            require_sha256(identity, f"{name} schema identity")
        expected_policies = (
            (self.fd_socket_topology, fixed_fd_topology(), "FD/socket topology"),
            (
                self.controller_confinement_policy,
                fixed_controller_policy(),
                "controller confinement",
            ),
            (self.codex_confinement_policy, fixed_codex_policy(), "Codex confinement"),
            (
                self.capsule_broker_confinement_policy,
                fixed_capsule_broker_policy(),
                "capsule-broker confinement",
            ),
            (
                self.network_namespace_policy,
                fixed_network_policy(),
                "network namespace",
            ),
            (
                self.authentication_source_metadata_policy,
                fixed_auth_metadata_policy(),
                "authentication metadata",
            ),
            (
                self.ephemeral_codex_home_policy,
                fixed_ephemeral_home_policy(),
                "ephemeral Codex home",
            ),
            (self.cleanup_policy, fixed_cleanup_policy(), "cleanup"),
        )
        for actual, expected, label in expected_policies:
            if dict(actual) != expected:
                raise ValueError(f"{label} policy differs from the closed authority")
        require_sha256(
            self.destination_manifest_identity, "destination manifest identity"
        )
        if not self.dependent_identities:
            raise ValueError("boundary authority requires dependent identities")
        for identity in self.dependent_identities:
            validate_component_identity_metadata(identity, "boundary dependency")
        require_exact_keys(
            self.dependent_authorities,
            {
                "capsule_image_content_id",
                "capsule_execution_authority_fingerprint",
                "capsule_broker_runtime_authority_fingerprint",
                "codex_protocol_schema_identity",
                "dynamic_tools_schema_identity",
                "model_binding_policy_fingerprint",
                "verified_serialization_witness_receipt_identity",
            },
            "boundary dependent authorities",
        )
        image = self.dependent_authorities["capsule_image_content_id"]
        if not image.startswith("sha256:") or len(image) != 71:
            raise ValueError("boundary capsule image is not an immutable content ID")
        require_sha256(
            image.removeprefix("sha256:"),
            "boundary capsule image content ID",
        )
        for key in (
            "capsule_execution_authority_fingerprint",
            "capsule_broker_runtime_authority_fingerprint",
            "codex_protocol_schema_identity",
            "dynamic_tools_schema_identity",
            "model_binding_policy_fingerprint",
            "verified_serialization_witness_receipt_identity",
        ):
            require_sha256(self.dependent_authorities[key], key)
        launch_body = self._body()
        del launch_body["schema_version"]
        del launch_body["launch_fingerprint"]
        require_sha256(self.launch_fingerprint, "boundary launch fingerprint")
        if fingerprint(launch_body) != self.launch_fingerprint:
            raise ValueError("boundary launch fingerprint mismatch")
        require_sha256(self.authority_fingerprint, "OS boundary authority fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("OS boundary authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "authority_fingerprint": self.authority_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OSBoundaryAuthority":
        require_exact_keys(
            value,
            {
                "schema_version",
                "boundary_launcher_identity",
                "authentication_broker_identity",
                "capsule_broker_identity",
                "egress_relay_identity",
                "broker_protocol_schema_identities",
                "fd_socket_topology",
                "controller_confinement_policy",
                "codex_confinement_policy",
                "capsule_broker_confinement_policy",
                "network_namespace_policy",
                "destination_manifest_identity",
                "authentication_source_metadata_policy",
                "ephemeral_codex_home_policy",
                "cleanup_policy",
                "dependent_identities",
                "dependent_authorities",
                "launch_fingerprint",
                "authority_fingerprint",
            },
            "OS boundary authority",
        )
        dependencies = value["dependent_identities"]
        if not isinstance(dependencies, list):
            raise ValueError("boundary dependent identities must be a list")
        return cls(
            schema_version=value["schema_version"],
            boundary_launcher_identity=MappingProxyType(
                dict(value["boundary_launcher_identity"])
            ),
            authentication_broker_identity=MappingProxyType(
                dict(value["authentication_broker_identity"])
            ),
            capsule_broker_identity=MappingProxyType(
                dict(value["capsule_broker_identity"])
            ),
            egress_relay_identity=MappingProxyType(
                dict(value["egress_relay_identity"])
            ),
            broker_protocol_schema_identities=MappingProxyType(
                dict(value["broker_protocol_schema_identities"])
            ),
            fd_socket_topology=MappingProxyType(dict(value["fd_socket_topology"])),
            controller_confinement_policy=MappingProxyType(
                dict(value["controller_confinement_policy"])
            ),
            codex_confinement_policy=MappingProxyType(
                dict(value["codex_confinement_policy"])
            ),
            capsule_broker_confinement_policy=MappingProxyType(
                dict(value["capsule_broker_confinement_policy"])
            ),
            network_namespace_policy=MappingProxyType(
                dict(value["network_namespace_policy"])
            ),
            destination_manifest_identity=value["destination_manifest_identity"],
            authentication_source_metadata_policy=MappingProxyType(
                dict(value["authentication_source_metadata_policy"])
            ),
            ephemeral_codex_home_policy=MappingProxyType(
                dict(value["ephemeral_codex_home_policy"])
            ),
            cleanup_policy=MappingProxyType(dict(value["cleanup_policy"])),
            dependent_identities=tuple(
                MappingProxyType(dict(item)) for item in dependencies
            ),
            dependent_authorities=MappingProxyType(
                dict(value["dependent_authorities"])
            ),
            launch_fingerprint=value["launch_fingerprint"],
            authority_fingerprint=value["authority_fingerprint"],
        ).validated()
