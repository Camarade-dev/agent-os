"""The generic CapsuleBackend interface.

This module defines the contract a Linux capsule backend must satisfy. It is
deliberately generic: nothing here names a concrete mission, runtime, agent,
or provider transport. A capsule backend produces only an untrusted
transient workspace and a `ProviderOutput` — it owns no Git stage, commit, or
publication authority. Acceptance authority lives exclusively downstream, in
canonical intake, independent verification, and the Admissible-owned
finalizer (see `admissible.capsule.intake`, `admissible.capsule.verification`,
and `admissible.capsule.finalizer`).

No concrete provider implementation is required or provided here. Historical
backend code elsewhere in the package remains protocol-handling defense in
depth; it is not, and does not become, the trusted root authority for this
capsule backend contract.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping

from admissible.capsule.common import (
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
)

if TYPE_CHECKING:
    from admissible.capsule.models import CleanupResult, ProviderOutput, WorkspaceReference


CAPSULE_AUTHORITY_SCHEMA_VERSION = "admissible_capsule_authority_v1"


class CapsuleTerminalClassification(str, Enum):
    """The exact, closed set of ways a capsule execution can terminate.

    These are backend-observed transport/process outcomes only. They say
    nothing about acceptance: acceptance is decided later by canonical
    intake and independent verification, never by the backend itself.
    """

    PROVIDER_COMPLETED_CLAIM = "PROVIDER_COMPLETED_CLAIM"
    PROVIDER_EXITED_NONZERO = "PROVIDER_EXITED_NONZERO"
    PROVIDER_TIMED_OUT = "PROVIDER_TIMED_OUT"
    PROVIDER_CRASHED = "PROVIDER_CRASHED"
    TRANSPORT_LOST = "TRANSPORT_LOST"
    CLEANUP_UNCONFIRMED = "CLEANUP_UNCONFIRMED"


@dataclass(frozen=True)
class CapsuleAuthority:
    """Immutable authority describing which capsule image/mission may run.

    This is intentionally generic: `backend_kind` is a stable identifier
    (e.g. "linux_capsule_v1"), not a provider name, and
    `capsule_image_identity` is an opaque content identity (for example a
    digest) rather than a runtime-specific reference string.
    """

    schema_version: str
    backend_kind: str
    capsule_image_identity: str
    mission_fingerprint: str
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        backend_kind: str,
        capsule_image_identity: str,
        mission_fingerprint: str,
    ) -> "CapsuleAuthority":
        from admissible.capsule.common import fingerprint

        body = {
            "schema_version": CAPSULE_AUTHORITY_SCHEMA_VERSION,
            "backend_kind": backend_kind,
            "capsule_image_identity": capsule_image_identity,
            "mission_fingerprint": mission_fingerprint,
        }
        return cls(
            schema_version=CAPSULE_AUTHORITY_SCHEMA_VERSION,
            backend_kind=backend_kind,
            capsule_image_identity=capsule_image_identity,
            mission_fingerprint=mission_fingerprint,
            authority_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "backend_kind": self.backend_kind,
            "capsule_image_identity": self.capsule_image_identity,
            "mission_fingerprint": self.mission_fingerprint,
        }

    def validated(self) -> "CapsuleAuthority":
        from admissible.capsule.common import fingerprint

        if self.schema_version != CAPSULE_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported capsule authority schema")
        require_identifier(self.backend_kind, "backend_kind")
        require_nonempty_text(self.capsule_image_identity, "capsule_image_identity", max_bytes=1024)
        require_sha256(self.mission_fingerprint, "mission_fingerprint")
        require_sha256(self.authority_fingerprint, "authority_fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("capsule authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["authority_fingerprint"] = self.authority_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CapsuleAuthority":
        require_exact_keys(
            data,
            {
                "schema_version",
                "backend_kind",
                "capsule_image_identity",
                "mission_fingerprint",
                "authority_fingerprint",
            },
            "capsule authority",
        )
        return cls(**dict(data)).validated()


class CapsuleBackend(abc.ABC):
    """A Linux capsule backend that produces only an untrusted workspace.

    Implementations MUST NOT stage, commit, or publish Git state, and MUST
    NOT be coupled to a specific transport or runtime command at the interface
    level — those details belong to a
    concrete backend, not this contract.
    """

    @property
    @abc.abstractmethod
    def authority(self) -> CapsuleAuthority:
        """The immutable capsule authority this backend runs under."""

    @abc.abstractmethod
    def prepare_workspace(self) -> "WorkspaceReference":
        """Create a transient, non-Git workspace source for a provider run.

        The returned reference identifies the workspace; it is never a Git
        ref, branch, or commit, and it confers no publication authority.
        """

    @abc.abstractmethod
    def run(self, workspace: "WorkspaceReference") -> "ProviderOutput":
        """Execute the provider process/session and freeze its output.

        The return value is an untrusted `ProviderOutput`: it carries a
        provider-reported completion only as an unverified statement, never
        as an accepted fact.
        """

    @abc.abstractmethod
    def cleanup(self, workspace: "WorkspaceReference") -> "CleanupResult":
        """Tear down the transient workspace and report cleanup evidence."""
