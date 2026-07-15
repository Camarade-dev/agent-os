"""Immutable authoritative state for the isolated Admissible V0 controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping

from admissible.execution.bounded_write import WorkspaceAuthorityDescriptor
from admissible.v0_controller.commands import Command


V0_SCHEMA_VERSION = "admissible_v0_controller_state_v3"


class Phase(str, Enum):
    PLAN = "plan"
    READY_TO_INVOKE = "ready_to_invoke"
    WAITING_FOR_AGENT = "waiting_for_agent"
    ADMITTING = "admitting"
    READY_TO_EXECUTE = "ready_to_execute"
    CHECKING_FILES = "checking_files"
    AWAITING_HUMAN = "awaiting_human"
    COMPLETED = "completed"
    FAILED = "failed"
    TECHNICAL_PAUSE = "technical_pause"


class InvocationLifecycle(str, Enum):
    PREPARED = "prepared"
    DISPATCHED = "dispatched"
    RESULT_RECEIVED = "result_received"
    CONSUMED = "consumed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNCERTAIN = "uncertain"


class BatchStatus(str, Enum):
    PREPARED = "prepared"
    ADMITTED = "admitted"
    EXECUTING = "executing"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class WaitKind(str, Enum):
    AGENT_RESULT = "agent_result"
    ADMISSION_RESULT = "admission_result"
    EXECUTION_RESULT = "execution_result"
    STRUCTURAL_CHECK_RESULT = "structural_check_result"
    HUMAN_DECISION = "human_decision"


class ReasonCode(str, Enum):
    ID_FACTORY_REQUIRED = "id_factory_required"
    INVOCATION_LIMIT_REACHED = "invocation_limit_reached"
    INVOCATION_FAILED = "invocation_failed"
    COMMAND_OUTCOME_UNCERTAIN = "command_outcome_uncertain"
    DISPATCHER_FAILURE = "dispatcher_failure"
    EXECUTION_FAILED = "execution_failed"
    STRUCTURAL_CHECK_FAILED = "structural_check_failed"
    STRUCTURAL_CHECK_TECHNICAL = "structural_check_technical"
    HUMAN_DECLINED = "human_declined"
    INVALID_EXTERNAL_RESULT = "invalid_external_result"
    INVARIANT_FAILURE = "invariant_failure"
    DURABILITY_UNCERTAIN = "durability_uncertain"
    WORKSPACE_AUTHORITY_CHANGED = "workspace_authority_changed"
    WORKSPACE_CONTAINMENT_CHANGED = "workspace_containment_changed"
    PHYSICAL_ATTESTATION_FAILED = "physical_attestation_failed"


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_relative_path(path: str) -> bool:
    """Validate the canonical logical path form used by the pure reducer."""

    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return False
    windows = PureWindowsPath(path)
    if windows.is_absolute() or windows.drive:
        return False
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        return False
    if any(":" in part for part in candidate.parts):
        return False
    return str(candidate) == path


def _is_sha256(value: str | None, *, required: bool = False) -> bool:
    if value is None:
        return not required
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


@dataclass(frozen=True)
class WorkspacePolicy:
    """Owner-supplied workspace constraints; no owner path is hard-coded."""

    rejected_path_prefixes: tuple[str, ...] = ()

    def permits(self, path: str) -> bool:
        if not _safe_relative_path(path):
            return False
        return not any(path == prefix or path.startswith(f"{prefix}/") for prefix in self.rejected_path_prefixes)

    def to_dict(self) -> dict[str, Any]:
        return {"rejected_path_prefixes": list(self.rejected_path_prefixes)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkspacePolicy":
        if set(data) != {"rejected_path_prefixes"} or not isinstance(data["rejected_path_prefixes"], list):
            raise ValueError("invalid workspace policy")
        prefixes = tuple(data["rejected_path_prefixes"])
        if any(not _safe_relative_path(prefix) for prefix in prefixes):
            raise ValueError("invalid rejected path prefix")
        return cls(rejected_path_prefixes=prefixes)


@dataclass(frozen=True)
class MissionContract:
    """The narrow V0 contract authority, embedded immutably in each session."""

    contract_id: str
    target_workspace: str
    mandatory_paths: tuple[str, ...]
    structural_completion_only: bool = False
    max_invocations: int = 8
    max_batches: int = 8
    max_commands: int = 32
    workspace_policy: WorkspacePolicy = field(default_factory=WorkspacePolicy)
    # The immutable, operator-approved mission specification.  It is the sole
    # mission-content authority for the governed instruction; it is never derived
    # from CLI text, UI projection, diagnostics, or mutable process state after
    # session creation.  Empty by default so pre-mission contracts round-trip.
    mission_specification: str = ""

    MAX_MISSION_SPECIFICATION_BYTES = 8192

    def __post_init__(self) -> None:
        if not self.contract_id or not self.target_workspace:
            raise ValueError("contract_id and target_workspace are required")
        if len(set(self.mandatory_paths)) != len(self.mandatory_paths):
            raise ValueError("mandatory_paths must be an exact set")
        if any(not self.workspace_policy.permits(path) for path in self.mandatory_paths):
            raise ValueError("mandatory path escapes or violates workspace policy")
        if min(self.max_invocations, self.max_batches, self.max_commands) <= 0:
            raise ValueError("contract limits must be positive")
        if "\x00" in self.mission_specification:
            raise ValueError("mission specification may not contain NUL characters")
        if len(self.mission_specification.encode("utf-8")) > self.MAX_MISSION_SPECIFICATION_BYTES:
            raise ValueError("mission specification exceeds the bounded size")

    def permits_path(self, path: str) -> bool:
        return self.workspace_policy.permits(path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "target_workspace": self.target_workspace,
            "mandatory_paths": list(self.mandatory_paths),
            "structural_completion_only": self.structural_completion_only,
            "max_invocations": self.max_invocations,
            "max_batches": self.max_batches,
            "max_commands": self.max_commands,
            "workspace_policy": self.workspace_policy.to_dict(),
            "mission_specification": self.mission_specification,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MissionContract":
        required = {
            "contract_id",
            "target_workspace",
            "mandatory_paths",
            "structural_completion_only",
            "max_invocations",
            "max_batches",
            "max_commands",
            "workspace_policy",
        }
        # ``mission_specification`` is accepted but optional, so a contract
        # persisted before the field existed still round-trips deterministically.
        allowed = required | {"mission_specification"}
        keys = set(data)
        if not required.issubset(keys) or not keys.issubset(allowed) or not isinstance(data["mandatory_paths"], list):
            raise ValueError("invalid mission contract")
        return cls(
            contract_id=data["contract_id"],
            target_workspace=data["target_workspace"],
            mandatory_paths=tuple(data["mandatory_paths"]),
            structural_completion_only=data["structural_completion_only"],
            max_invocations=data["max_invocations"],
            max_batches=data["max_batches"],
            max_commands=data["max_commands"],
            workspace_policy=WorkspacePolicy.from_dict(data["workspace_policy"]),
            mission_specification=data.get("mission_specification", ""),
        )


@dataclass(frozen=True)
class V0ExecutionReceipt:
    """The complete immutable V0 fact for one confirmed bounded write."""

    schema_version: str
    receipt_id: str
    session_id: str
    issued_revision: int
    execution_command_id: str
    batch_id: str
    invocation_id: str
    action_id: str
    operation_kind: str
    path: str
    resolved_target: str
    physical_identity_key: str
    sha256: str
    byte_count: int
    success: bool
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        text = (
            self.schema_version, self.receipt_id, self.session_id, self.execution_command_id,
            self.batch_id, self.invocation_id, self.action_id, self.operation_kind,
            self.path, self.resolved_target, self.physical_identity_key, self.sha256,
        )
        if (
            any(not isinstance(value, str) or not value for value in text)
            or self.schema_version != "admissible_v0_execution_receipt_v1"
            or self.issued_revision < 0
            or not _safe_relative_path(self.path)
            or not _is_sha256(self.sha256, required=True)
            or not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
            or self.success is not True
            or (self.diagnostic is not None and not isinstance(self.diagnostic, str))
        ):
            raise ValueError("invalid V0 execution receipt")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "issued_revision": self.issued_revision,
            "execution_command_id": self.execution_command_id,
            "batch_id": self.batch_id,
            "invocation_id": self.invocation_id,
            "action_id": self.action_id,
            "operation_kind": self.operation_kind,
            "path": self.path,
            "resolved_target": self.resolved_target,
            "physical_identity_key": self.physical_identity_key,
            "sha256": self.sha256,
            "byte_count": self.byte_count,
            "success": self.success,
            "diagnostic": self.diagnostic,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "V0ExecutionReceipt":
        expected = {
            "schema_version", "receipt_id", "session_id", "issued_revision", "execution_command_id",
            "batch_id", "invocation_id", "action_id", "operation_kind", "path", "resolved_target",
            "physical_identity_key", "sha256", "byte_count", "success", "diagnostic",
        }
        if set(data) != expected:
            raise ValueError("invalid V0 execution receipt fields")
        return cls(**dict(data))


@dataclass(frozen=True)
class FileEvidence:
    """Durable receipt-derived evidence with its physical target identity.

    ``path`` remains the canonical logical contract path.  The remaining
    correlation and identity fields are emitted only after the executor
    boundary has validated a physical target; they are not agent proposals.
    """

    path: str
    resolved_target: str
    physical_identity_key: str
    sha256: str
    byte_count: int
    action_id: str
    execution_command_id: str
    batch_id: str
    invocation_id: str
    execution_receipt_id: str

    def __post_init__(self) -> None:
        if (
            not _safe_relative_path(self.path)
            or not isinstance(self.resolved_target, str)
            or not self.resolved_target
            or not isinstance(self.physical_identity_key, str)
            or not self.physical_identity_key
            or not _is_sha256(self.sha256, required=True)
            or not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
            or not self.action_id
            or not self.execution_command_id
            or not self.batch_id
            or not self.invocation_id
            or not self.execution_receipt_id
        ):
            raise ValueError("invalid file evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "resolved_target": self.resolved_target,
            "physical_identity_key": self.physical_identity_key,
            "sha256": self.sha256,
            "byte_count": self.byte_count,
            "action_id": self.action_id,
            "execution_command_id": self.execution_command_id,
            "batch_id": self.batch_id,
            "invocation_id": self.invocation_id,
            "execution_receipt_id": self.execution_receipt_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FileEvidence":
        if set(data) != {
            "path",
            "resolved_target",
            "physical_identity_key",
            "sha256",
            "byte_count",
            "action_id",
            "execution_command_id",
            "batch_id",
            "invocation_id",
            "execution_receipt_id",
        }:
            raise ValueError("invalid file evidence fields")
        return cls(**dict(data))


@dataclass(frozen=True)
class ProposedOperation:
    """One proposal stored as canonical JSON instead of mutable provider data."""

    operation_id: str
    path: str
    operation_json: str

    @classmethod
    def from_operation(cls, *, operation_id: str, operation: Mapping[str, Any]) -> "ProposedOperation":
        path = operation.get("path")
        if not isinstance(path, str):
            raise ValueError("proposed operation needs a string path")
        return cls(operation_id=operation_id, path=path, operation_json=_canonical_json(operation))

    @property
    def operation(self) -> dict[str, Any]:
        value = json.loads(self.operation_json)
        if not isinstance(value, dict):
            raise ValueError("proposed operation must be an object")
        return value

    def __post_init__(self) -> None:
        if not self.operation_id or not _safe_relative_path(self.path):
            raise ValueError("invalid proposed operation")
        if self.operation.get("path") != self.path:
            raise ValueError("proposal path must match operation path")

    def to_dict(self) -> dict[str, Any]:
        return {"operation_id": self.operation_id, "path": self.path, "operation": self.operation}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProposedOperation":
        if set(data) != {"operation_id", "path", "operation"} or not isinstance(data["operation"], dict):
            raise ValueError("invalid proposed operation fields")
        return cls.from_operation(operation_id=data["operation_id"], operation=data["operation"])


@dataclass(frozen=True)
class DispatchAuthorityRecord:
    """Independent engine-issued authority for one real proposal dispatch.

    The command payload carries a capability for the callable backend.  This
    record lives on the active invocation instead, so a partial raw-store
    mutation of either location is detectable before a process may start.
    It is intentionally structural rather than a claim of cryptographic
    protection against a coherent rewrite of the complete session file.
    """

    schema_version: str
    nonce: str
    session_id: str
    issued_revision: int
    command_id: str
    batch_id: str
    invocation_id: str
    wait_token_id: str
    wait_owner_id: str
    backend_fingerprint: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != "admissible_v0_dispatch_authority_v1"
            or not self.nonce
            or not self.session_id
            or not isinstance(self.issued_revision, int)
            or isinstance(self.issued_revision, bool)
            or self.issued_revision < 0
            or not self.command_id
            or not self.batch_id
            or not self.invocation_id
            or not self.wait_token_id
            or not self.wait_owner_id
            or not self.backend_fingerprint
        ):
            raise ValueError("invalid dispatch authority record")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "nonce": self.nonce,
            "session_id": self.session_id,
            "issued_revision": self.issued_revision,
            "command_id": self.command_id,
            "batch_id": self.batch_id,
            "invocation_id": self.invocation_id,
            "wait_token_id": self.wait_token_id,
            "wait_owner_id": self.wait_owner_id,
            "backend_fingerprint": self.backend_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DispatchAuthorityRecord":
        expected = {
            "schema_version",
            "nonce",
            "session_id",
            "issued_revision",
            "command_id",
            "batch_id",
            "invocation_id",
            "wait_token_id",
            "wait_owner_id",
            "backend_fingerprint",
        }
        if set(data) != expected:
            raise ValueError("invalid dispatch authority fields")
        return cls(**dict(data))


@dataclass(frozen=True)
class InvocationRecord:
    invocation_id: str
    lifecycle: InvocationLifecycle
    request_at: str
    response_reference: str | None = None
    diagnostics: tuple[str, ...] = ()
    dispatch_authority: DispatchAuthorityRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "lifecycle": self.lifecycle.value,
            "request_at": self.request_at,
            "response_reference": self.response_reference,
            "diagnostics": list(self.diagnostics),
            "dispatch_authority": (
                None if self.dispatch_authority is None else self.dispatch_authority.to_dict()
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InvocationRecord":
        expected = {
            "invocation_id",
            "lifecycle",
            "request_at",
            "response_reference",
            "diagnostics",
            "dispatch_authority",
        }
        legacy_expected = expected - {"dispatch_authority"}
        if set(data) not in (expected, legacy_expected) or not isinstance(data["diagnostics"], list):
            raise ValueError("invalid invocation record")
        raw_authority = data.get("dispatch_authority")
        if raw_authority is not None and not isinstance(raw_authority, dict):
            raise ValueError("invalid invocation dispatch authority")
        return cls(
            invocation_id=data["invocation_id"],
            lifecycle=InvocationLifecycle(data["lifecycle"]),
            request_at=data["request_at"],
            response_reference=data["response_reference"],
            diagnostics=tuple(data["diagnostics"]),
            dispatch_authority=(
                None if raw_authority is None else DispatchAuthorityRecord.from_dict(raw_authority)
            ),
        )


@dataclass(frozen=True)
class BatchRecord:
    batch_id: str
    invocation_id: str
    proposed_operations: tuple[ProposedOperation, ...]
    admitted_operation_ids: tuple[str, ...]
    executed_operation_ids: tuple[str, ...]
    materialized_evidence: tuple[FileEvidence, ...]
    remaining_mandatory_paths: tuple[str, ...]
    status: BatchStatus
    remaining_action_ids: tuple[str, ...] = ()
    interruption_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "invocation_id": self.invocation_id,
            "proposed_operations": [item.to_dict() for item in self.proposed_operations],
            "admitted_operation_ids": list(self.admitted_operation_ids),
            "executed_operation_ids": list(self.executed_operation_ids),
            "materialized_evidence": [item.to_dict() for item in self.materialized_evidence],
            "remaining_mandatory_paths": list(self.remaining_mandatory_paths),
            "status": self.status.value,
            "remaining_action_ids": list(self.remaining_action_ids),
            "interruption_code": self.interruption_code,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BatchRecord":
        expected = {
            "batch_id", "invocation_id", "proposed_operations", "admitted_operation_ids",
            "executed_operation_ids", "materialized_evidence", "remaining_mandatory_paths", "status",
            "remaining_action_ids", "interruption_code",
        }
        if set(data) != expected:
            raise ValueError("invalid batch record")
        list_fields = ("proposed_operations", "admitted_operation_ids", "executed_operation_ids", "materialized_evidence", "remaining_mandatory_paths", "remaining_action_ids")
        if any(not isinstance(data[name], list) for name in list_fields):
            raise ValueError("invalid batch list field")
        code = data["interruption_code"]
        if code is not None and (not isinstance(code, str) or not code):
            raise ValueError("invalid batch interruption code")
        return cls(
            batch_id=data["batch_id"],
            invocation_id=data["invocation_id"],
            proposed_operations=tuple(ProposedOperation.from_dict(item) for item in data["proposed_operations"]),
            admitted_operation_ids=tuple(data["admitted_operation_ids"]),
            executed_operation_ids=tuple(data["executed_operation_ids"]),
            materialized_evidence=tuple(FileEvidence.from_dict(item) for item in data["materialized_evidence"]),
            remaining_mandatory_paths=tuple(data["remaining_mandatory_paths"]),
            status=BatchStatus(data["status"]),
            remaining_action_ids=tuple(data["remaining_action_ids"]),
            interruption_code=code,
        )


@dataclass(frozen=True)
class WaitToken:
    kind: WaitKind
    owner_id: str
    command_id: str | None
    expected_event: str
    deadline: str | None = None
    token_id: str | None = None
    correlation_nonce: str | None = None

    def __post_init__(self) -> None:
        if not self.owner_id or not self.expected_event:
            raise ValueError("wait token owner and expected event are required")
        if self.kind == WaitKind.HUMAN_DECISION:
            if self.command_id is not None:
                raise ValueError("human wait tokens cannot claim a command")
        elif not self.command_id:
            raise ValueError("external-result wait tokens require a command id")
        if self.token_id is not None and not self.token_id:
            raise ValueError("wait token id cannot be empty")
        if self.correlation_nonce is not None and not self.correlation_nonce:
            raise ValueError("wait correlation nonce cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "owner_id": self.owner_id,
            "command_id": self.command_id,
            "expected_event": self.expected_event,
            "deadline": self.deadline,
            "token_id": self.token_id,
            "correlation_nonce": self.correlation_nonce,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WaitToken":
        expected = {
            "kind",
            "owner_id",
            "command_id",
            "expected_event",
            "deadline",
            "token_id",
            "correlation_nonce",
        }
        legacy_expected = expected - {"token_id", "correlation_nonce"}
        if set(data) not in (expected, legacy_expected):
            raise ValueError("invalid wait token")
        return cls(
            kind=WaitKind(data["kind"]),
            owner_id=data["owner_id"],
            command_id=data["command_id"],
            expected_event=data["expected_event"],
            deadline=data["deadline"],
            token_id=data.get("token_id"),
            correlation_nonce=data.get("correlation_nonce"),
        )


@dataclass(frozen=True)
class OutcomeReason:
    code: ReasonCode
    message: str
    operator_action: str

    def __post_init__(self) -> None:
        if not self.message or not self.operator_action:
            raise ValueError("outcome reasons must be actionable")

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "message": self.message, "operator_action": self.operator_action}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OutcomeReason":
        if set(data) != {"code", "message", "operator_action"}:
            raise ValueError("invalid outcome reason")
        return cls(ReasonCode(data["code"]), data["message"], data["operator_action"])


@dataclass(frozen=True)
class StructuralFileCheck:
    path: str
    exists: bool
    non_empty: bool
    inside_workspace: bool
    sha256: str | None
    structural_command_id: str = ""
    check_kind: str = "mandatory_file"
    passed: bool = True
    failure_code: str | None = None
    expected_sha256: str | None = None
    observed_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "non_empty": self.non_empty,
            "inside_workspace": self.inside_workspace,
            "sha256": self.sha256,
            "structural_command_id": self.structural_command_id,
            "check_kind": self.check_kind,
            "passed": self.passed,
            "failure_code": self.failure_code,
            "expected_sha256": self.expected_sha256,
            "observed_sha256": self.observed_sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StructuralFileCheck":
        if set(data) != {
            "path", "exists", "non_empty", "inside_workspace", "sha256", "structural_command_id",
            "check_kind", "passed", "failure_code", "expected_sha256", "observed_sha256",
        }:
            raise ValueError("invalid structural file check")
        check = cls(**dict(data))
        if (
            not _safe_relative_path(check.path)
            or not _is_sha256(check.sha256)
            or not isinstance(check.structural_command_id, str)
            or not isinstance(check.check_kind, str)
            or not check.check_kind
            or not isinstance(check.passed, bool)
            or (check.failure_code is not None and (not isinstance(check.failure_code, str) or not check.failure_code))
            or not _is_sha256(check.expected_sha256)
            or not _is_sha256(check.observed_sha256)
        ):
            raise ValueError("invalid structural file check path or hash")
        return check


@dataclass(frozen=True)
class StructuralVerification:
    checks: tuple[StructuralFileCheck, ...]
    passed: bool
    completed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"checks": [item.to_dict() for item in self.checks], "passed": self.passed, "completed_at": self.completed_at}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StructuralVerification":
        if set(data) != {"checks", "passed", "completed_at"} or not isinstance(data["checks"], list):
            raise ValueError("invalid structural verification")
        return cls(tuple(StructuralFileCheck.from_dict(item) for item in data["checks"]), data["passed"], data["completed_at"])


@dataclass(frozen=True)
class Counters:
    invocations: int = 0
    batches: int = 0
    commands: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"invocations": self.invocations, "batches": self.batches, "commands": self.commands}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Counters":
        if set(data) != {"invocations", "batches", "commands"}:
            raise ValueError("invalid counters")
        result = cls(**dict(data))
        if min(result.invocations, result.batches, result.commands) < 0:
            raise ValueError("counters cannot be negative")
        return result


@dataclass(frozen=True)
class SessionState:
    schema_version: str
    session_id: str
    revision: int
    semantic_state_version: int
    phase: Phase
    contract: MissionContract
    mandatory_paths: tuple[str, ...]
    workspace_authority: WorkspaceAuthorityDescriptor | None = None
    materialized_evidence: tuple[FileEvidence, ...] = ()
    execution_receipt_history: tuple[V0ExecutionReceipt, ...] = ()
    current_invocation: InvocationRecord | None = None
    invocation_history: tuple[InvocationRecord, ...] = ()
    current_batch: BatchRecord | None = None
    batch_history: tuple[BatchRecord, ...] = ()
    pending_command: Command | None = None
    completed_command_ids: tuple[str, ...] = ()
    uncertain_command_ids: tuple[str, ...] = ()
    wait_token: WaitToken | None = None
    structural_verification: StructuralVerification | None = None
    outcome_reason: OutcomeReason | None = None
    counters: Counters = field(default_factory=Counters)

    def remaining_paths(self) -> tuple[str, ...]:
        confirmed = {evidence.path for evidence in self.materialized_evidence}
        return tuple(path for path in self.mandatory_paths if path not in confirmed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "revision": self.revision,
            "semantic_state_version": self.semantic_state_version,
            "phase": self.phase.value,
            "contract": self.contract.to_dict(),
            "mandatory_paths": list(self.mandatory_paths),
            "workspace_authority": None if self.workspace_authority is None else self.workspace_authority.to_dict(),
            "materialized_evidence": [item.to_dict() for item in self.materialized_evidence],
            "execution_receipt_history": [item.to_dict() for item in self.execution_receipt_history],
            "current_invocation": None if self.current_invocation is None else self.current_invocation.to_dict(),
            "invocation_history": [item.to_dict() for item in self.invocation_history],
            "current_batch": None if self.current_batch is None else self.current_batch.to_dict(),
            "batch_history": [item.to_dict() for item in self.batch_history],
            "pending_command": None if self.pending_command is None else self.pending_command.to_dict(),
            "completed_command_ids": list(self.completed_command_ids),
            "uncertain_command_ids": list(self.uncertain_command_ids),
            "wait_token": None if self.wait_token is None else self.wait_token.to_dict(),
            "structural_verification": None if self.structural_verification is None else self.structural_verification.to_dict(),
            "outcome_reason": None if self.outcome_reason is None else self.outcome_reason.to_dict(),
            "counters": self.counters.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SessionState":
        expected = {
            "schema_version", "session_id", "revision", "semantic_state_version", "phase", "contract", "mandatory_paths",
            "materialized_evidence", "execution_receipt_history", "current_invocation", "invocation_history", "current_batch", "batch_history",
            "pending_command", "completed_command_ids", "uncertain_command_ids", "wait_token", "structural_verification",
            "outcome_reason", "counters", "workspace_authority",
        }
        legacy_expected = expected - {"workspace_authority"}
        if set(data) != expected and set(data) != legacy_expected:
            raise ValueError("invalid V0 session state fields")
        list_fields = ("mandatory_paths", "materialized_evidence", "execution_receipt_history", "invocation_history", "batch_history", "completed_command_ids", "uncertain_command_ids")
        if any(not isinstance(data[name], list) for name in list_fields):
            raise ValueError("invalid V0 session list field")
        state = cls(
            schema_version=data["schema_version"],
            session_id=data["session_id"],
            revision=data["revision"],
            semantic_state_version=data["semantic_state_version"],
            phase=Phase(data["phase"]),
            contract=MissionContract.from_dict(data["contract"]),
            mandatory_paths=tuple(data["mandatory_paths"]),
            workspace_authority=(
                None
                if data.get("workspace_authority") is None
                else WorkspaceAuthorityDescriptor.from_dict(data["workspace_authority"])
            ),
            materialized_evidence=tuple(FileEvidence.from_dict(item) for item in data["materialized_evidence"]),
            execution_receipt_history=tuple(V0ExecutionReceipt.from_dict(item) for item in data["execution_receipt_history"]),
            current_invocation=None if data["current_invocation"] is None else InvocationRecord.from_dict(data["current_invocation"]),
            invocation_history=tuple(InvocationRecord.from_dict(item) for item in data["invocation_history"]),
            current_batch=None if data["current_batch"] is None else BatchRecord.from_dict(data["current_batch"]),
            batch_history=tuple(BatchRecord.from_dict(item) for item in data["batch_history"]),
            pending_command=None if data["pending_command"] is None else Command.from_dict(data["pending_command"]),
            completed_command_ids=tuple(data["completed_command_ids"]),
            uncertain_command_ids=tuple(data["uncertain_command_ids"]),
            wait_token=None if data["wait_token"] is None else WaitToken.from_dict(data["wait_token"]),
            structural_verification=None if data["structural_verification"] is None else StructuralVerification.from_dict(data["structural_verification"]),
            outcome_reason=None if data["outcome_reason"] is None else OutcomeReason.from_dict(data["outcome_reason"]),
            counters=Counters.from_dict(data["counters"]),
        )
        if state.schema_version != V0_SCHEMA_VERSION:
            raise ValueError("unsupported V0 session schema")
        if not isinstance(state.session_id, str) or not state.session_id:
            raise ValueError("invalid V0 session id")
        if not isinstance(state.revision, int) or isinstance(state.revision, bool):
            raise ValueError("revision must be an integer")
        if not isinstance(state.semantic_state_version, int) or isinstance(state.semantic_state_version, bool):
            raise ValueError("semantic_state_version must be an integer")
        return state


def new_session_state(
    *,
    session_id: str,
    contract: MissionContract,
    workspace_authority: WorkspaceAuthorityDescriptor | None = None,
) -> SessionState:
    """Build an in-memory bootstrap state; the engine persists creation atomically."""

    if not session_id:
        raise ValueError("session_id is required")
    return SessionState(
        schema_version=V0_SCHEMA_VERSION,
        session_id=session_id,
        revision=0,
        semantic_state_version=0,
        phase=Phase.PLAN,
        contract=contract,
        mandatory_paths=contract.mandatory_paths,
        workspace_authority=workspace_authority,
    )
