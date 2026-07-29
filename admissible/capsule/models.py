"""ProviderOutput: the untrusted result a capsule backend produces.

A `ProviderOutput` is deliberately powerless. It carries a frozen workspace
reference, a byte/tree observation, a process result, a transport result, a
cleanup result, and the provider's own completion claim as an untrusted
statement. It never contains, and cannot be made to require, a
provider-created Git commit — Git authority belongs exclusively to
`admissible.capsule.finalizer.AdmissibleFinalizer`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from admissible.capsule.common import (
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    require_strict_int,
)


WORKSPACE_REFERENCE_SCHEMA_VERSION = "admissible_capsule_workspace_reference_v1"
BYTE_TREE_OBSERVATION_SCHEMA_VERSION = "admissible_capsule_byte_tree_observation_v1"
PROCESS_RESULT_SCHEMA_VERSION = "admissible_capsule_process_result_v1"
TRANSPORT_RESULT_SCHEMA_VERSION = "admissible_capsule_transport_result_v1"
CLEANUP_RESULT_SCHEMA_VERSION = "admissible_capsule_cleanup_result_v1"
PROVIDER_COMPLETION_CLAIM_SCHEMA_VERSION = "admissible_capsule_provider_completion_claim_v1"
PROVIDER_OUTPUT_SCHEMA_VERSION = "admissible_capsule_provider_output_v1"
EXECUTION_TRUTH_SCHEMA_VERSION = "admissible_capsule_execution_truth_v1"


@dataclass(frozen=True)
class WorkspaceReference:
    """A frozen identity for a transient, non-Git workspace.

    This is an opaque handle: it carries no filesystem path, branch, or Git
    ref. Consumers resolve it through the backend that minted it, never by
    treating it as a source of trust on its own.
    """

    schema_version: str
    workspace_id: str
    capsule_authority_fingerprint: str
    host_owned: bool
    reference_fingerprint: str

    @classmethod
    def create(
        cls, *, workspace_id: str, capsule_authority_fingerprint: str, host_owned: bool
    ) -> "WorkspaceReference":
        body = {
            "schema_version": WORKSPACE_REFERENCE_SCHEMA_VERSION,
            "workspace_id": workspace_id,
            "capsule_authority_fingerprint": capsule_authority_fingerprint,
            "host_owned": host_owned,
        }
        return cls(
            schema_version=WORKSPACE_REFERENCE_SCHEMA_VERSION,
            workspace_id=workspace_id,
            capsule_authority_fingerprint=capsule_authority_fingerprint,
            host_owned=host_owned,
            reference_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "workspace_id": self.workspace_id,
            "capsule_authority_fingerprint": self.capsule_authority_fingerprint,
            "host_owned": self.host_owned,
        }

    def validated(self) -> "WorkspaceReference":
        if self.schema_version != WORKSPACE_REFERENCE_SCHEMA_VERSION:
            raise ValueError("unsupported workspace reference schema")
        require_identifier(self.workspace_id, "workspace_id")
        require_sha256(self.capsule_authority_fingerprint, "capsule_authority_fingerprint")
        require_bool(self.host_owned, "host_owned")
        require_sha256(self.reference_fingerprint, "reference_fingerprint")
        if fingerprint(self._body()) != self.reference_fingerprint:
            raise ValueError("workspace reference fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["reference_fingerprint"] = self.reference_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkspaceReference":
        require_exact_keys(
            data,
            {
                "schema_version",
                "workspace_id",
                "capsule_authority_fingerprint",
                "host_owned",
                "reference_fingerprint",
            },
            "workspace reference",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class ObservedEntry:
    relative_path: str
    kind: str
    size: int
    sha256: str | None

    def validated(self) -> "ObservedEntry":
        require_nonempty_text(self.relative_path, "observed entry relative_path", max_bytes=4096)
        if self.kind not in {"regular", "directory", "symlink", "fifo", "socket", "block_device", "character_device", "unknown"}:
            raise ValueError("unknown observed entry kind")
        require_strict_int(self.size, "observed entry size", minimum=0, maximum=1024 * 1024 * 1024)
        if self.sha256 is not None:
            require_sha256(self.sha256, "observed entry sha256")
        if self.kind == "regular" and self.sha256 is None:
            raise ValueError("a regular file observation requires a byte hash")
        if self.kind != "regular" and self.sha256 is not None:
            raise ValueError("only regular files carry a byte hash")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ObservedEntry":
        require_exact_keys(data, {"relative_path", "kind", "size", "sha256"}, "observed entry")
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class ByteTreeObservation:
    """A complete, frozen observation of the provider workspace's bytes.

    This is an observation, not a ruling: acceptance is decided later by
    canonical intake, never inferred from the presence of this record.
    """

    schema_version: str
    tree_hash: str
    file_count: int
    entries: tuple[ObservedEntry, ...]
    observation_fingerprint: str

    @classmethod
    def create(cls, *, entries: tuple[ObservedEntry, ...]) -> "ByteTreeObservation":
        ordered = tuple(sorted(entries, key=lambda item: item.relative_path))
        tree_hash = fingerprint([entry.to_dict() for entry in ordered])
        file_count = sum(1 for entry in ordered if entry.kind == "regular")
        body = {
            "schema_version": BYTE_TREE_OBSERVATION_SCHEMA_VERSION,
            "tree_hash": tree_hash,
            "file_count": file_count,
            "entries": [entry.to_dict() for entry in ordered],
        }
        return cls(
            schema_version=BYTE_TREE_OBSERVATION_SCHEMA_VERSION,
            tree_hash=tree_hash,
            file_count=file_count,
            entries=ordered,
            observation_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tree_hash": self.tree_hash,
            "file_count": self.file_count,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    def validated(self) -> "ByteTreeObservation":
        if self.schema_version != BYTE_TREE_OBSERVATION_SCHEMA_VERSION:
            raise ValueError("unsupported byte-tree observation schema")
        require_sha256(self.tree_hash, "tree_hash")
        require_strict_int(self.file_count, "file_count", minimum=0, maximum=1_000_000)
        if not isinstance(self.entries, tuple):
            raise ValueError("observation entries must be immutable")
        for entry in self.entries:
            if not isinstance(entry, ObservedEntry):
                raise ValueError("invalid observation entry type")
            entry.validated()
        paths = [entry.relative_path for entry in self.entries]
        if len(set(paths)) != len(paths):
            raise ValueError("observation entries must have unique paths")
        if list(paths) != sorted(paths):
            raise ValueError("observation entries must be canonically ordered")
        require_sha256(self.observation_fingerprint, "observation_fingerprint")
        if fingerprint(self._body()) != self.observation_fingerprint:
            raise ValueError("byte-tree observation fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["observation_fingerprint"] = self.observation_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ByteTreeObservation":
        require_exact_keys(
            data,
            {"schema_version", "tree_hash", "file_count", "entries", "observation_fingerprint"},
            "byte-tree observation",
        )
        if not isinstance(data["entries"], list):
            raise ValueError("observation entries must be an array")
        return cls(
            schema_version=data["schema_version"],
            tree_hash=data["tree_hash"],
            file_count=data["file_count"],
            entries=tuple(ObservedEntry.from_dict(item) for item in data["entries"]),
            observation_fingerprint=data["observation_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class ProcessResult:
    """The provider process/session result, as observed by the backend."""

    schema_version: str
    exit_code: int | None
    timed_out: bool
    signal: str | None

    def validated(self) -> "ProcessResult":
        if self.schema_version != PROCESS_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported process result schema")
        if self.exit_code is not None:
            require_strict_int(self.exit_code, "exit_code", minimum=-2**31, maximum=2**31 - 1)
        require_bool(self.timed_out, "timed_out")
        if self.signal is not None:
            require_identifier(self.signal, "signal")
        if self.timed_out and self.exit_code is not None:
            raise ValueError("a timed-out process cannot also report a clean exit code")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "signal": self.signal,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProcessResult":
        require_exact_keys(data, {"schema_version", "exit_code", "timed_out", "signal"}, "process result")
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class TransportResult:
    """Transport evidence for the provider session, kept transport-agnostic.

    `transport_kind` is a stable identifier chosen by the concrete backend
    (e.g. "loopback_relay_v1"); this module does not hardcode Neon Relay or
    Docker-specific command strings.
    """

    schema_version: str
    transport_kind: str
    connected: bool
    closed_cleanly: bool

    def validated(self) -> "TransportResult":
        if self.schema_version != TRANSPORT_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported transport result schema")
        require_identifier(self.transport_kind, "transport_kind")
        require_bool(self.connected, "connected")
        require_bool(self.closed_cleanly, "closed_cleanly")
        if self.closed_cleanly and not self.connected:
            raise ValueError("a transport that never connected cannot close cleanly")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "transport_kind": self.transport_kind,
            "connected": self.connected,
            "closed_cleanly": self.closed_cleanly,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TransportResult":
        require_exact_keys(
            data,
            {"schema_version", "transport_kind", "connected", "closed_cleanly"},
            "transport result",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class CleanupResult:
    """Evidence that the transient capsule workspace was torn down."""

    schema_version: str
    workspace_removed: bool
    processes_reaped: bool

    def validated(self) -> "CleanupResult":
        if self.schema_version != CLEANUP_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported cleanup result schema")
        require_bool(self.workspace_removed, "workspace_removed")
        require_bool(self.processes_reaped, "processes_reaped")
        return self

    @property
    def cleanup_proven(self) -> bool:
        return self.workspace_removed and self.processes_reaped

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "workspace_removed": self.workspace_removed,
            "processes_reaped": self.processes_reaped,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CleanupResult":
        require_exact_keys(
            data,
            {"schema_version", "workspace_removed", "processes_reaped"},
            "cleanup result",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class ProviderCompletionClaim:
    """The provider's own statement that it finished. This is never trusted.

    Nothing downstream may treat `claimed_complete=True` as evidence of
    acceptance. It exists only so that a disagreement between the provider's
    self-report and the independently observed evidence is itself
    inspectable.
    """

    schema_version: str
    claimed_complete: bool
    claim_text: str

    def validated(self) -> "ProviderCompletionClaim":
        if self.schema_version != PROVIDER_COMPLETION_CLAIM_SCHEMA_VERSION:
            raise ValueError("unsupported provider completion claim schema")
        require_bool(self.claimed_complete, "claimed_complete")
        if not isinstance(self.claim_text, str) or "\x00" in self.claim_text:
            raise ValueError("invalid provider completion claim text")
        if len(self.claim_text.encode("utf-8")) > 8192:
            raise ValueError("provider completion claim text exceeds its bound")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claimed_complete": self.claimed_complete,
            "claim_text": self.claim_text,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProviderCompletionClaim":
        require_exact_keys(
            data,
            {"schema_version", "claimed_complete", "claim_text"},
            "provider completion claim",
        )
        return cls(**dict(data)).validated()


class ProviderTerminalClassification(str, Enum):
    """Exact terminal classifications for a frozen `ProviderOutput`.

    This is a closed vocabulary. Every `ProviderOutput` resolves to exactly
    one of these; none of them implies acceptance.
    """

    RAN_TO_COMPLETION_CLAIM = "RAN_TO_COMPLETION_CLAIM"
    EXITED_NONZERO = "EXITED_NONZERO"
    TIMED_OUT = "TIMED_OUT"
    TRANSPORT_LOST = "TRANSPORT_LOST"
    CLEANUP_UNCONFIRMED = "CLEANUP_UNCONFIRMED"


@dataclass(frozen=True)
class ExecutionTruth:
    """Concrete process/protocol/cleanup/snapshot truth, never acceptance."""

    schema_version: str
    backend_execution_authority_fingerprint: str
    app_server_exit_code: int | None
    app_server_exit_normal: bool
    app_server_forced: bool
    protocol_terminal_classification: str
    capsule_process_classification: str
    capsule_process_exit_code: int | None
    capsule_process_exit_normal: bool
    capsule_process_forced: bool
    controller_classification: str
    cleanup_fingerprint: str
    journal_tail_fingerprint: str
    frozen_workspace_fingerprint: str
    frozen_binding_fingerprint: str
    truth_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        backend_execution_authority_fingerprint: str,
        app_server_exit_code: int | None,
        app_server_exit_normal: bool,
        app_server_forced: bool,
        protocol_terminal_classification: str,
        capsule_process_classification: str,
        capsule_process_exit_code: int | None,
        capsule_process_exit_normal: bool,
        capsule_process_forced: bool,
        controller_classification: str,
        cleanup_fingerprint: str,
        journal_tail_fingerprint: str,
        frozen_workspace_fingerprint: str,
        frozen_binding_fingerprint: str,
    ) -> "ExecutionTruth":
        body = {
            "schema_version": EXECUTION_TRUTH_SCHEMA_VERSION,
            "backend_execution_authority_fingerprint": backend_execution_authority_fingerprint,
            "app_server_exit_code": app_server_exit_code,
            "app_server_exit_normal": app_server_exit_normal,
            "app_server_forced": app_server_forced,
            "protocol_terminal_classification": protocol_terminal_classification,
            "capsule_process_classification": capsule_process_classification,
            "capsule_process_exit_code": capsule_process_exit_code,
            "capsule_process_exit_normal": capsule_process_exit_normal,
            "capsule_process_forced": capsule_process_forced,
            "controller_classification": controller_classification,
            "cleanup_fingerprint": cleanup_fingerprint,
            "journal_tail_fingerprint": journal_tail_fingerprint,
            "frozen_workspace_fingerprint": frozen_workspace_fingerprint,
            "frozen_binding_fingerprint": frozen_binding_fingerprint,
        }
        return cls(**body, truth_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in self.__dict__.items()
            if key != "truth_fingerprint"
        }

    def validated(self) -> "ExecutionTruth":
        if self.schema_version != EXECUTION_TRUTH_SCHEMA_VERSION:
            raise ValueError("unsupported execution-truth schema")
        require_sha256(
            self.backend_execution_authority_fingerprint,
            "backend execution authority fingerprint",
        )
        if self.app_server_exit_code is not None:
            require_strict_int(
                self.app_server_exit_code,
                "app-server exit code",
                minimum=-(2**31),
                maximum=2**31 - 1,
            )
        require_bool(self.app_server_exit_normal, "app-server exit-normal truth")
        require_bool(self.app_server_forced, "app-server forced-close truth")
        if self.app_server_exit_normal and self.app_server_forced:
            raise ValueError("app-server exit cannot be both normal and forced")
        if self.app_server_exit_normal and self.app_server_exit_code is None:
            raise ValueError("normal app-server exit requires an exit code")
        if self.protocol_terminal_classification not in {
            "COMPLETED",
            "FAILED",
            "INTERRUPTED",
            "ERROR",
            "EOF_BEFORE_TERMINAL",
            "PROTOCOL_REFUSED",
            "TIMED_OUT",
        }:
            raise ValueError("unknown protocol terminal classification")
        if self.capsule_process_classification not in {
            "NORMAL_EXIT",
            "FORCED_EXIT",
            "UNKNOWN",
        }:
            raise ValueError("unknown capsule process classification")
        if self.capsule_process_exit_code is not None:
            require_strict_int(
                self.capsule_process_exit_code,
                "capsule process exit code",
                minimum=-(2**31),
                maximum=2**31 - 1,
            )
        require_bool(self.capsule_process_exit_normal, "capsule exit-normal truth")
        require_bool(self.capsule_process_forced, "capsule forced-exit truth")
        if self.capsule_process_exit_normal and self.capsule_process_forced:
            raise ValueError("capsule exit cannot be both normal and forced")
        if (
            self.capsule_process_classification == "NORMAL_EXIT"
            and (
                not self.capsule_process_exit_normal
                or self.capsule_process_forced
                or self.capsule_process_exit_code is None
            )
        ):
            raise ValueError("normal capsule classification lacks exact exit truth")
        if (
            self.capsule_process_classification == "FORCED_EXIT"
            and (
                not self.capsule_process_forced
                or self.capsule_process_exit_normal
                or self.capsule_process_exit_code is None
            )
        ):
            raise ValueError("forced capsule classification lacks exact exit truth")
        if self.capsule_process_classification == "UNKNOWN" and (
            self.capsule_process_exit_normal
            or self.capsule_process_forced
            or self.capsule_process_exit_code is not None
        ):
            raise ValueError("unknown capsule classification claims exit truth")
        require_identifier(self.controller_classification, "controller classification")
        for label, value in (
            ("cleanup", self.cleanup_fingerprint),
            ("journal tail", self.journal_tail_fingerprint),
            ("frozen workspace", self.frozen_workspace_fingerprint),
            ("frozen binding", self.frozen_binding_fingerprint),
            ("execution truth", self.truth_fingerprint),
        ):
            require_sha256(value, f"{label} fingerprint")
        if fingerprint(self._body()) != self.truth_fingerprint:
            raise ValueError("execution-truth fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "truth_fingerprint": self.truth_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionTruth":
        require_exact_keys(
            data,
            {
                "schema_version",
                "backend_execution_authority_fingerprint",
                "app_server_exit_code",
                "app_server_exit_normal",
                "app_server_forced",
                "protocol_terminal_classification",
                "capsule_process_classification",
                "capsule_process_exit_code",
                "capsule_process_exit_normal",
                "capsule_process_forced",
                "controller_classification",
                "cleanup_fingerprint",
                "journal_tail_fingerprint",
                "frozen_workspace_fingerprint",
                "frozen_binding_fingerprint",
                "truth_fingerprint",
            },
            "execution truth",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class ProviderOutput:
    """The complete, frozen, untrusted result of one capsule provider run."""

    schema_version: str
    capsule_authority_fingerprint: str
    workspace: WorkspaceReference
    observation: ByteTreeObservation
    process_result: ProcessResult
    transport_result: TransportResult
    cleanup_result: CleanupResult
    completion_claim: ProviderCompletionClaim
    output_fingerprint: str
    execution_truth: ExecutionTruth | None = None

    @classmethod
    def create(
        cls,
        *,
        capsule_authority_fingerprint: str,
        workspace: WorkspaceReference,
        observation: ByteTreeObservation,
        process_result: ProcessResult,
        transport_result: TransportResult,
        cleanup_result: CleanupResult,
        completion_claim: ProviderCompletionClaim,
        execution_truth: ExecutionTruth | None = None,
    ) -> "ProviderOutput":
        provisional = cls(
            schema_version=PROVIDER_OUTPUT_SCHEMA_VERSION,
            capsule_authority_fingerprint=capsule_authority_fingerprint,
            workspace=workspace,
            observation=observation,
            process_result=process_result,
            transport_result=transport_result,
            cleanup_result=cleanup_result,
            completion_claim=completion_claim,
            output_fingerprint="0" * 64,
            execution_truth=execution_truth,
        )
        return cls(
            **{**provisional.__dict__, "output_fingerprint": fingerprint(provisional._body())}
        ).validated()

    def _body(self) -> dict[str, Any]:
        body = {
            "schema_version": self.schema_version,
            "capsule_authority_fingerprint": self.capsule_authority_fingerprint,
            "workspace": self.workspace.to_dict(),
            "observation": self.observation.to_dict(),
            "process_result": self.process_result.to_dict(),
            "transport_result": self.transport_result.to_dict(),
            "cleanup_result": self.cleanup_result.to_dict(),
            "completion_claim": self.completion_claim.to_dict(),
        }
        if self.execution_truth is not None:
            body["execution_truth"] = self.execution_truth.to_dict()
        return body

    def validated(self) -> "ProviderOutput":
        if self.schema_version != PROVIDER_OUTPUT_SCHEMA_VERSION:
            raise ValueError("unsupported provider output schema")
        require_sha256(self.capsule_authority_fingerprint, "capsule_authority_fingerprint")
        self.workspace.validated()
        if self.workspace.capsule_authority_fingerprint != self.capsule_authority_fingerprint:
            raise ValueError("provider output workspace is bound to another capsule authority")
        self.observation.validated()
        self.process_result.validated()
        self.transport_result.validated()
        self.cleanup_result.validated()
        self.completion_claim.validated()
        if self.execution_truth is not None:
            if not isinstance(self.execution_truth, ExecutionTruth):
                raise ValueError("invalid concrete execution truth")
            self.execution_truth.validated()
        require_sha256(self.output_fingerprint, "output_fingerprint")
        if fingerprint(self._body()) != self.output_fingerprint:
            raise ValueError("provider output fingerprint mismatch")
        return self

    @property
    def terminal_classification(self) -> ProviderTerminalClassification:
        if not self.cleanup_result.cleanup_proven:
            return ProviderTerminalClassification.CLEANUP_UNCONFIRMED
        if self.process_result.timed_out:
            return ProviderTerminalClassification.TIMED_OUT
        if self.process_result.exit_code not in (0, None):
            return ProviderTerminalClassification.EXITED_NONZERO
        if not self.transport_result.connected or not self.transport_result.closed_cleanly:
            return ProviderTerminalClassification.TRANSPORT_LOST
        return ProviderTerminalClassification.RAN_TO_COMPLETION_CLAIM

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["output_fingerprint"] = self.output_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProviderOutput":
        expected = {
                "schema_version",
                "capsule_authority_fingerprint",
                "workspace",
                "observation",
                "process_result",
                "transport_result",
                "cleanup_result",
                "completion_claim",
                "output_fingerprint",
            }
        if "execution_truth" in data:
            expected.add("execution_truth")
        require_exact_keys(data, expected, "provider output")
        return cls(
            schema_version=data["schema_version"],
            capsule_authority_fingerprint=data["capsule_authority_fingerprint"],
            workspace=WorkspaceReference.from_dict(data["workspace"]),
            observation=ByteTreeObservation.from_dict(data["observation"]),
            process_result=ProcessResult.from_dict(data["process_result"]),
            transport_result=TransportResult.from_dict(data["transport_result"]),
            cleanup_result=CleanupResult.from_dict(data["cleanup_result"]),
            completion_claim=ProviderCompletionClaim.from_dict(data["completion_claim"]),
            output_fingerprint=data["output_fingerprint"],
            execution_truth=(
                ExecutionTruth.from_dict(data["execution_truth"])
                if "execution_truth" in data
                else None
            ),
        ).validated()
