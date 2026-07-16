"""Strict immutable value objects for the independent delegated-gate protocol."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, TypeAlias

from admissible.delegated_gate.canonical import (
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_optional_git_oid,
    require_safe_relative_path,
    require_sha256,
    require_strict_int,
    require_string_list,
)


MISSION_SCHEMA_VERSION = "admissible_delegated_mission_v1"
GATE_CONTRACT_SCHEMA_VERSION = "admissible_delegated_gate_contract_v1"
GATE_PLAN_SCHEMA_VERSION = "admissible_delegated_gate_plan_v1"
CHECKPOINT_SCHEMA_VERSION = "admissible_delegated_checkpoint_v1"
AUDIT_VERDICT_SCHEMA_VERSION = "admissible_delegated_audit_verdict_v1"
MAX_GATES = 4
BUILD_WEEK_GATE_COUNT = 3


class EvidenceKind(str, Enum):
    TARGET_TREE = "target_tree"
    GIT_STATE = "git_state"
    VERIFICATION_COMMAND = "verification_command"


class EvidenceStatus(str, Enum):
    OBSERVED = "observed"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(str, Enum):
    BLOCKING = "blocking"
    WARNING = "warning"


class Verdict(str, Enum):
    PASS = "PASS"
    FIX_REQUIRED = "FIX_REQUIRED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class Mission:
    schema_version: str
    mission_id: str
    specification: str
    mission_fingerprint: str

    @classmethod
    def create(cls, *, mission_id: str, specification: str) -> "Mission":
        body = {
            "schema_version": MISSION_SCHEMA_VERSION,
            "mission_id": mission_id,
            "specification": specification,
        }
        return cls(
            schema_version=MISSION_SCHEMA_VERSION,
            mission_id=mission_id,
            specification=specification,
            mission_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mission_id": self.mission_id,
            "specification": self.specification,
        }

    def validated(self) -> "Mission":
        if self.schema_version != MISSION_SCHEMA_VERSION:
            raise ValueError("unsupported delegated mission schema")
        require_identifier(self.mission_id, "mission_id")
        require_nonempty_text(self.specification, "mission specification")
        require_sha256(self.mission_fingerprint, "mission_fingerprint")
        if fingerprint(self._body()) != self.mission_fingerprint:
            raise ValueError("mission fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["mission_fingerprint"] = self.mission_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Mission":
        require_exact_keys(
            data,
            {"schema_version", "mission_id", "specification", "mission_fingerprint"},
            "mission",
        )
        return cls(
            schema_version=data["schema_version"],
            mission_id=data["mission_id"],
            specification=data["specification"],
            mission_fingerprint=data["mission_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class GateClause:
    clause_id: str
    text: str

    def validated(self) -> "GateClause":
        require_identifier(self.clause_id, "clause_id")
        require_nonempty_text(self.text, "gate clause", max_bytes=4096)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"clause_id": self.clause_id, "text": self.text}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GateClause":
        require_exact_keys(data, {"clause_id", "text"}, "gate clause")
        return cls(clause_id=data["clause_id"], text=data["text"]).validated()


@dataclass(frozen=True)
class VerificationCommand:
    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int = 30
    max_capture_bytes: int = 65536

    def validated(self) -> "VerificationCommand":
        require_identifier(self.command_id, "command_id")
        if not isinstance(self.argv, tuple) or not self.argv:
            raise ValueError("verification argv must be a non-empty tuple")
        for arg in self.argv:
            if not isinstance(arg, str) or not arg or "\x00" in arg:
                raise ValueError("verification argv contains an invalid argument")
        require_strict_int(self.timeout_seconds, "timeout_seconds", minimum=1, maximum=300)
        require_strict_int(
            self.max_capture_bytes,
            "max_capture_bytes",
            minimum=1,
            maximum=1024 * 1024,
        )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "max_capture_bytes": self.max_capture_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationCommand":
        require_exact_keys(
            data,
            {"command_id", "argv", "timeout_seconds", "max_capture_bytes"},
            "verification command",
        )
        argv = require_string_list(data["argv"], "verification argv")
        return cls(
            command_id=data["command_id"],
            argv=argv,
            timeout_seconds=data["timeout_seconds"],
            max_capture_bytes=data["max_capture_bytes"],
        ).validated()


@dataclass(frozen=True)
class GateContract:
    schema_version: str
    gate_id: str
    objective: str
    clauses: tuple[GateClause, ...]
    required_evidence_kinds: tuple[EvidenceKind, ...]
    checkpoint_verification_commands: tuple[VerificationCommand, ...]
    repair_budget: int
    contract_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        gate_id: str,
        objective: str,
        clauses: tuple[GateClause, ...],
        required_evidence_kinds: tuple[EvidenceKind, ...],
        checkpoint_verification_commands: tuple[VerificationCommand, ...] = (),
        repair_budget: int = 1,
    ) -> "GateContract":
        provisional = cls(
            schema_version=GATE_CONTRACT_SCHEMA_VERSION,
            gate_id=gate_id,
            objective=objective,
            clauses=clauses,
            required_evidence_kinds=required_evidence_kinds,
            checkpoint_verification_commands=checkpoint_verification_commands,
            repair_budget=repair_budget,
            contract_fingerprint="0" * 64,
        )
        result = cls(
            **{**provisional.__dict__, "contract_fingerprint": fingerprint(provisional._body())}
        )
        return result.validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "gate_id": self.gate_id,
            "objective": self.objective,
            "clauses": [clause.to_dict() for clause in self.clauses],
            "required_evidence_kinds": [kind.value for kind in self.required_evidence_kinds],
            "checkpoint_verification_commands": [
                command.to_dict() for command in self.checkpoint_verification_commands
            ],
            "repair_budget": self.repair_budget,
        }

    def validated(self) -> "GateContract":
        if self.schema_version != GATE_CONTRACT_SCHEMA_VERSION:
            raise ValueError("unsupported gate contract schema")
        require_identifier(self.gate_id, "gate_id")
        require_nonempty_text(self.objective, "gate objective", max_bytes=8192)
        if not isinstance(self.clauses, tuple) or not self.clauses:
            raise ValueError("gate contract requires a finite non-empty clause tuple")
        for clause in self.clauses:
            if not isinstance(clause, GateClause):
                raise ValueError("invalid gate clause type")
            clause.validated()
        clause_ids = [clause.clause_id for clause in self.clauses]
        if len(set(clause_ids)) != len(clause_ids):
            raise ValueError("duplicate clause IDs are forbidden")
        if not isinstance(self.required_evidence_kinds, tuple):
            raise ValueError("required evidence kinds must be immutable")
        if any(not isinstance(kind, EvidenceKind) for kind in self.required_evidence_kinds):
            raise ValueError("unknown required evidence kind")
        if len(set(self.required_evidence_kinds)) != len(self.required_evidence_kinds):
            raise ValueError("required evidence kinds must be unique")
        if not isinstance(self.checkpoint_verification_commands, tuple):
            raise ValueError("verification commands must be immutable")
        for command in self.checkpoint_verification_commands:
            if not isinstance(command, VerificationCommand):
                raise ValueError("invalid verification command type")
            command.validated()
        command_ids = [command.command_id for command in self.checkpoint_verification_commands]
        if len(set(command_ids)) != len(command_ids):
            raise ValueError("duplicate verification command IDs are forbidden")
        if self.checkpoint_verification_commands and EvidenceKind.VERIFICATION_COMMAND not in self.required_evidence_kinds:
            raise ValueError("declared commands require verification_command evidence")
        require_strict_int(self.repair_budget, "repair_budget", minimum=0, maximum=1)
        require_sha256(self.contract_fingerprint, "contract_fingerprint")
        if fingerprint(self._body()) != self.contract_fingerprint:
            raise ValueError("gate contract fingerprint mismatch")
        return self

    @property
    def clause_ids(self) -> frozenset[str]:
        return frozenset(clause.clause_id for clause in self.clauses)

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["contract_fingerprint"] = self.contract_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GateContract":
        require_exact_keys(
            data,
            {
                "schema_version",
                "gate_id",
                "objective",
                "clauses",
                "required_evidence_kinds",
                "checkpoint_verification_commands",
                "repair_budget",
                "contract_fingerprint",
            },
            "gate contract",
        )
        if not isinstance(data["clauses"], list):
            raise ValueError("clauses must be an array")
        if not isinstance(data["checkpoint_verification_commands"], list):
            raise ValueError("verification commands must be an array")
        raw_kinds = require_string_list(data["required_evidence_kinds"], "required evidence kinds")
        try:
            kinds = tuple(EvidenceKind(value) for value in raw_kinds)
        except ValueError as exc:
            raise ValueError("unknown required evidence kind") from exc
        return cls(
            schema_version=data["schema_version"],
            gate_id=data["gate_id"],
            objective=data["objective"],
            clauses=tuple(GateClause.from_dict(item) for item in data["clauses"]),
            required_evidence_kinds=kinds,
            checkpoint_verification_commands=tuple(
                VerificationCommand.from_dict(item)
                for item in data["checkpoint_verification_commands"]
            ),
            repair_budget=data["repair_budget"],
            contract_fingerprint=data["contract_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class GatePlan:
    schema_version: str
    immutable_mission_fingerprint: str
    ordered_gate_contracts: tuple[GateContract, ...]
    plan_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        mission: Mission,
        ordered_gate_contracts: tuple[GateContract, ...],
    ) -> "GatePlan":
        mission.validated()
        provisional = cls(
            schema_version=GATE_PLAN_SCHEMA_VERSION,
            immutable_mission_fingerprint=mission.mission_fingerprint,
            ordered_gate_contracts=ordered_gate_contracts,
            plan_fingerprint="0" * 64,
        )
        result = cls(
            **{**provisional.__dict__, "plan_fingerprint": fingerprint(provisional._body())}
        )
        return result.validated()

    @classmethod
    def create_build_week(
        cls,
        *,
        mission: Mission,
        ordered_gate_contracts: tuple[GateContract, ...],
    ) -> "GatePlan":
        if len(ordered_gate_contracts) != BUILD_WEEK_GATE_COUNT:
            raise ValueError("the Build Week canonical plan requires exactly three gates")
        return cls.create(mission=mission, ordered_gate_contracts=ordered_gate_contracts)

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "immutable_mission_fingerprint": self.immutable_mission_fingerprint,
            "ordered_gate_contracts": [gate.to_dict() for gate in self.ordered_gate_contracts],
        }

    def validated(self) -> "GatePlan":
        if self.schema_version != GATE_PLAN_SCHEMA_VERSION:
            raise ValueError("unsupported gate plan schema")
        require_sha256(self.immutable_mission_fingerprint, "immutable_mission_fingerprint")
        if not isinstance(self.ordered_gate_contracts, tuple):
            raise ValueError("ordered gates must be immutable")
        if not 1 <= len(self.ordered_gate_contracts) <= MAX_GATES:
            raise ValueError("gate count must be fixed between one and four")
        for gate in self.ordered_gate_contracts:
            if not isinstance(gate, GateContract):
                raise ValueError("invalid gate contract type")
            gate.validated()
        gate_ids = [gate.gate_id for gate in self.ordered_gate_contracts]
        if len(set(gate_ids)) != len(gate_ids):
            raise ValueError("duplicate gate IDs are forbidden")
        require_sha256(self.plan_fingerprint, "plan_fingerprint")
        if fingerprint(self._body()) != self.plan_fingerprint:
            raise ValueError("gate plan fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["plan_fingerprint"] = self.plan_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GatePlan":
        require_exact_keys(
            data,
            {
                "schema_version",
                "immutable_mission_fingerprint",
                "ordered_gate_contracts",
                "plan_fingerprint",
            },
            "gate plan",
        )
        if not isinstance(data["ordered_gate_contracts"], list):
            raise ValueError("ordered gates must be an array")
        return cls(
            schema_version=data["schema_version"],
            immutable_mission_fingerprint=data["immutable_mission_fingerprint"],
            ordered_gate_contracts=tuple(
                GateContract.from_dict(item) for item in data["ordered_gate_contracts"]
            ),
            plan_fingerprint=data["plan_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class ArtifactReference:
    artifact_id: str
    purpose: str
    relative_path: str
    sha256: str
    byte_count: int
    truncated: bool

    def validated(self) -> "ArtifactReference":
        require_identifier(self.artifact_id, "artifact_id")
        if self.purpose not in {"stdout", "stderr"}:
            raise ValueError("unsupported checkpoint artifact purpose")
        require_safe_relative_path(self.relative_path, "artifact relative_path")
        require_sha256(self.sha256, "artifact sha256")
        require_strict_int(self.byte_count, "artifact byte_count", minimum=0, maximum=1024 * 1024)
        require_bool(self.truncated, "artifact truncated")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "purpose": self.purpose,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "byte_count": self.byte_count,
            "truncated": self.truncated,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ArtifactReference":
        require_exact_keys(
            data,
            {"artifact_id", "purpose", "relative_path", "sha256", "byte_count", "truncated"},
            "artifact reference",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class TreeEvidence:
    evidence_id: str
    kind: EvidenceKind
    status: EvidenceStatus
    tree_hash: str
    file_count: int

    def validated(self) -> "TreeEvidence":
        require_identifier(self.evidence_id, "evidence_id")
        if self.kind != EvidenceKind.TARGET_TREE or self.status != EvidenceStatus.OBSERVED:
            raise ValueError("invalid target-tree evidence classification")
        require_sha256(self.tree_hash, "tree evidence hash")
        require_strict_int(self.file_count, "tree file_count", minimum=0, maximum=1_000_000)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "tree_hash": self.tree_hash,
            "file_count": self.file_count,
        }


@dataclass(frozen=True)
class GitEvidence:
    evidence_id: str
    kind: EvidenceKind
    status: EvidenceStatus
    head: str | None
    porcelain_status: str

    def validated(self) -> "GitEvidence":
        require_identifier(self.evidence_id, "evidence_id")
        if self.kind != EvidenceKind.GIT_STATE or self.status != EvidenceStatus.OBSERVED:
            raise ValueError("invalid Git evidence classification")
        require_optional_git_oid(self.head, "Git HEAD")
        if not isinstance(self.porcelain_status, str) or "\x00" in self.porcelain_status:
            raise ValueError("invalid Git porcelain status")
        if len(self.porcelain_status.encode("utf-8")) > 1024 * 1024:
            raise ValueError("Git porcelain status exceeds its bound")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "head": self.head,
            "porcelain_status": self.porcelain_status,
        }


@dataclass(frozen=True)
class CommandEvidence:
    evidence_id: str
    kind: EvidenceKind
    status: EvidenceStatus
    command_id: str
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    cleanup_proven: bool
    output_truncated: bool
    stdout_artifact_id: str
    stderr_artifact_id: str

    def validated(self) -> "CommandEvidence":
        require_identifier(self.evidence_id, "evidence_id")
        if self.kind != EvidenceKind.VERIFICATION_COMMAND:
            raise ValueError("invalid command evidence kind")
        if self.status not in {EvidenceStatus.PASSED, EvidenceStatus.FAILED, EvidenceStatus.INCONCLUSIVE}:
            raise ValueError("invalid command evidence status")
        require_identifier(self.command_id, "command_id")
        if not isinstance(self.argv, tuple) or not self.argv or any(
            not isinstance(arg, str) or not arg or "\x00" in arg for arg in self.argv
        ):
            raise ValueError("invalid command evidence argv")
        if self.exit_code is not None:
            require_strict_int(self.exit_code, "exit_code", minimum=-2**31, maximum=2**31 - 1)
        require_bool(self.timed_out, "timed_out")
        require_bool(self.cleanup_proven, "cleanup_proven")
        require_bool(self.output_truncated, "output_truncated")
        require_identifier(self.stdout_artifact_id, "stdout_artifact_id")
        require_identifier(self.stderr_artifact_id, "stderr_artifact_id")
        if self.status == EvidenceStatus.PASSED and (
            self.exit_code != 0 or self.timed_out or not self.cleanup_proven
        ):
            raise ValueError("passed command evidence contradicts its process result")
        if (self.timed_out or not self.cleanup_proven) and self.status != EvidenceStatus.INCONCLUSIVE:
            raise ValueError("uncertain process cleanup/timeout must be inconclusive")
        if (
            self.exit_code not in (None, 0)
            and not self.timed_out
            and self.cleanup_proven
            and self.status != EvidenceStatus.FAILED
        ):
            raise ValueError("nonzero command evidence must be failed")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "command_id": self.command_id,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "cleanup_proven": self.cleanup_proven,
            "output_truncated": self.output_truncated,
            "stdout_artifact_id": self.stdout_artifact_id,
            "stderr_artifact_id": self.stderr_artifact_id,
        }


EvidenceRecord: TypeAlias = TreeEvidence | GitEvidence | CommandEvidence


def evidence_from_dict(data: Mapping[str, Any]) -> EvidenceRecord:
    if not isinstance(data, Mapping):
        raise ValueError("evidence record must be an object")
    try:
        kind = EvidenceKind(data.get("kind"))
    except ValueError as exc:
        raise ValueError("unknown evidence record kind") from exc
    if kind == EvidenceKind.TARGET_TREE:
        require_exact_keys(
            data,
            {"evidence_id", "kind", "status", "tree_hash", "file_count"},
            "tree evidence",
        )
        return TreeEvidence(
            evidence_id=data["evidence_id"],
            kind=kind,
            status=EvidenceStatus(data["status"]),
            tree_hash=data["tree_hash"],
            file_count=data["file_count"],
        ).validated()
    if kind == EvidenceKind.GIT_STATE:
        require_exact_keys(
            data,
            {"evidence_id", "kind", "status", "head", "porcelain_status"},
            "Git evidence",
        )
        return GitEvidence(
            evidence_id=data["evidence_id"],
            kind=kind,
            status=EvidenceStatus(data["status"]),
            head=data["head"],
            porcelain_status=data["porcelain_status"],
        ).validated()
    require_exact_keys(
        data,
        {
            "evidence_id",
            "kind",
            "status",
            "command_id",
            "argv",
            "exit_code",
            "timed_out",
            "cleanup_proven",
            "output_truncated",
            "stdout_artifact_id",
            "stderr_artifact_id",
        },
        "command evidence",
    )
    return CommandEvidence(
        evidence_id=data["evidence_id"],
        kind=kind,
        status=EvidenceStatus(data["status"]),
        command_id=data["command_id"],
        argv=require_string_list(data["argv"], "command evidence argv"),
        exit_code=data["exit_code"],
        timed_out=data["timed_out"],
        cleanup_proven=data["cleanup_proven"],
        output_truncated=data["output_truncated"],
        stdout_artifact_id=data["stdout_artifact_id"],
        stderr_artifact_id=data["stderr_artifact_id"],
    ).validated()


@dataclass(frozen=True)
class Checkpoint:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    material_tree_hash: str
    git_head: str | None
    git_worktree_status: str
    evidence_records: tuple[EvidenceRecord, ...]
    artifact_references: tuple[ArtifactReference, ...]
    checkpoint_fingerprint: str

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "gate_id": self.gate_id,
            "execution_attempt_index": self.execution_attempt_index,
            "material_tree_hash": self.material_tree_hash,
            "git_head": self.git_head,
            "git_worktree_status": self.git_worktree_status,
            "evidence_records": [record.to_dict() for record in self.evidence_records],
            "artifact_references": [artifact.to_dict() for artifact in self.artifact_references],
        }

    def validated(self) -> "Checkpoint":
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint schema")
        require_identifier(self.session_id, "session_id")
        require_identifier(self.gate_id, "gate_id")
        require_strict_int(self.execution_attempt_index, "execution_attempt_index", minimum=0, maximum=1)
        require_sha256(self.material_tree_hash, "material_tree_hash")
        require_optional_git_oid(self.git_head, "git_head")
        if not isinstance(self.git_worktree_status, str) or "\x00" in self.git_worktree_status:
            raise ValueError("invalid git_worktree_status")
        if not isinstance(self.evidence_records, tuple) or not isinstance(self.artifact_references, tuple):
            raise ValueError("checkpoint evidence and artifacts must be immutable")
        for record in self.evidence_records:
            if not isinstance(record, (TreeEvidence, GitEvidence, CommandEvidence)):
                raise ValueError("invalid checkpoint evidence type")
            record.validated()
        for artifact in self.artifact_references:
            if not isinstance(artifact, ArtifactReference):
                raise ValueError("invalid checkpoint artifact type")
            artifact.validated()
        evidence_ids = [record.evidence_id for record in self.evidence_records]
        artifact_ids = [artifact.artifact_id for artifact in self.artifact_references]
        artifact_paths = [artifact.relative_path for artifact in self.artifact_references]
        if len(set(evidence_ids)) != len(evidence_ids) or len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("checkpoint evidence and artifact IDs must be unique")
        if len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("checkpoint artifact relative paths must be unique")
        trees = [record for record in self.evidence_records if isinstance(record, TreeEvidence)]
        git_records = [record for record in self.evidence_records if isinstance(record, GitEvidence)]
        if len(trees) != 1 or trees[0].tree_hash != self.material_tree_hash:
            raise ValueError("checkpoint tree identity does not match its typed evidence")
        if len(git_records) != 1 or (
            git_records[0].head != self.git_head
            or git_records[0].porcelain_status != self.git_worktree_status
        ):
            raise ValueError("checkpoint Git identity does not match its typed evidence")
        artifact_set = set(artifact_ids)
        for record in self.evidence_records:
            if isinstance(record, CommandEvidence) and not {
                record.stdout_artifact_id,
                record.stderr_artifact_id,
            }.issubset(artifact_set):
                raise ValueError("command evidence cites a missing output artifact")
        require_sha256(self.checkpoint_fingerprint, "checkpoint_fingerprint")
        if fingerprint(self._body()) != self.checkpoint_fingerprint:
            raise ValueError("checkpoint fingerprint mismatch")
        return self

    @property
    def evidence_reference_ids(self) -> frozenset[str]:
        return frozenset(
            [record.evidence_id for record in self.evidence_records]
            + [artifact.artifact_id for artifact in self.artifact_references]
        )

    @property
    def evidence_kinds(self) -> frozenset[EvidenceKind]:
        return frozenset(record.kind for record in self.evidence_records)

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["checkpoint_fingerprint"] = self.checkpoint_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Checkpoint":
        require_exact_keys(
            data,
            {
                "schema_version",
                "session_id",
                "gate_id",
                "execution_attempt_index",
                "material_tree_hash",
                "git_head",
                "git_worktree_status",
                "evidence_records",
                "artifact_references",
                "checkpoint_fingerprint",
            },
            "checkpoint",
        )
        if not isinstance(data["evidence_records"], list) or not isinstance(data["artifact_references"], list):
            raise ValueError("checkpoint evidence and artifacts must be arrays")
        return cls(
            schema_version=data["schema_version"],
            session_id=data["session_id"],
            gate_id=data["gate_id"],
            execution_attempt_index=data["execution_attempt_index"],
            material_tree_hash=data["material_tree_hash"],
            git_head=data["git_head"],
            git_worktree_status=data["git_worktree_status"],
            evidence_records=tuple(evidence_from_dict(item) for item in data["evidence_records"]),
            artifact_references=tuple(
                ArtifactReference.from_dict(item) for item in data["artifact_references"]
            ),
            checkpoint_fingerprint=data["checkpoint_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class AuditFinding:
    finding_id: str
    gate_id: str
    checkpoint_fingerprint: str
    cited_gate_clause_id: str
    severity: FindingSeverity
    observed_defect: str
    supporting_evidence_references: tuple[str, ...]
    bounded_repair_surface: tuple[str, ...]
    requires_human_escalation: bool

    def validated(self) -> "AuditFinding":
        require_identifier(self.finding_id, "finding_id")
        require_identifier(self.gate_id, "finding gate_id")
        require_sha256(self.checkpoint_fingerprint, "finding checkpoint_fingerprint")
        require_identifier(self.cited_gate_clause_id, "cited_gate_clause_id")
        if not isinstance(self.severity, FindingSeverity):
            raise ValueError("unknown finding severity")
        require_nonempty_text(self.observed_defect, "observed defect", max_bytes=4096)
        if not isinstance(self.supporting_evidence_references, tuple) or not self.supporting_evidence_references:
            raise ValueError("finding requires supporting evidence references")
        for reference in self.supporting_evidence_references:
            require_identifier(reference, "supporting evidence reference")
        if len(set(self.supporting_evidence_references)) != len(self.supporting_evidence_references):
            raise ValueError("supporting evidence references must be unique")
        if not isinstance(self.bounded_repair_surface, tuple):
            raise ValueError("bounded repair surface must be immutable")
        for surface in self.bounded_repair_surface:
            require_nonempty_text(surface, "bounded repair surface item", max_bytes=512)
        if len(set(self.bounded_repair_surface)) != len(self.bounded_repair_surface):
            raise ValueError("bounded repair surface must be unique")
        require_bool(self.requires_human_escalation, "requires_human_escalation")
        if self.bounded_repair_surface and self.requires_human_escalation:
            raise ValueError("a finding cannot grant repair and require human escalation")
        if self.severity == FindingSeverity.BLOCKING and not (
            self.bounded_repair_surface or self.requires_human_escalation
        ):
            raise ValueError("blocking finding requires bounded repair or human escalation")
        if self.severity == FindingSeverity.WARNING and (
            self.bounded_repair_surface or self.requires_human_escalation
        ):
            raise ValueError("warning findings cannot become transition authority")
        return self

    @property
    def enforceable_repair(self) -> bool:
        return (
            self.severity == FindingSeverity.BLOCKING
            and bool(self.bounded_repair_surface)
            and not self.requires_human_escalation
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "gate_id": self.gate_id,
            "checkpoint_fingerprint": self.checkpoint_fingerprint,
            "cited_gate_clause_id": self.cited_gate_clause_id,
            "severity": self.severity.value,
            "observed_defect": self.observed_defect,
            "supporting_evidence_references": list(self.supporting_evidence_references),
            "bounded_repair_surface": list(self.bounded_repair_surface),
            "requires_human_escalation": self.requires_human_escalation,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditFinding":
        require_exact_keys(
            data,
            {
                "finding_id",
                "gate_id",
                "checkpoint_fingerprint",
                "cited_gate_clause_id",
                "severity",
                "observed_defect",
                "supporting_evidence_references",
                "bounded_repair_surface",
                "requires_human_escalation",
            },
            "audit finding",
        )
        return cls(
            finding_id=data["finding_id"],
            gate_id=data["gate_id"],
            checkpoint_fingerprint=data["checkpoint_fingerprint"],
            cited_gate_clause_id=data["cited_gate_clause_id"],
            severity=FindingSeverity(data["severity"]),
            observed_defect=data["observed_defect"],
            supporting_evidence_references=require_string_list(
                data["supporting_evidence_references"], "supporting evidence references"
            ),
            bounded_repair_surface=require_string_list(
                data["bounded_repair_surface"], "bounded repair surface"
            ),
            requires_human_escalation=data["requires_human_escalation"],
        ).validated()


@dataclass(frozen=True)
class AuditVerdict:
    schema_version: str
    session_id: str
    gate_id: str
    checkpoint_fingerprint: str
    auditor_invocation_identity: str
    verdict: Verdict
    findings: tuple[AuditFinding, ...]
    verdict_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        gate_id: str,
        checkpoint_fingerprint: str,
        auditor_invocation_identity: str,
        verdict: Verdict,
        findings: tuple[AuditFinding, ...] = (),
    ) -> "AuditVerdict":
        provisional = cls(
            schema_version=AUDIT_VERDICT_SCHEMA_VERSION,
            session_id=session_id,
            gate_id=gate_id,
            checkpoint_fingerprint=checkpoint_fingerprint,
            auditor_invocation_identity=auditor_invocation_identity,
            verdict=verdict,
            findings=findings,
            verdict_fingerprint="0" * 64,
        )
        result = cls(
            **{**provisional.__dict__, "verdict_fingerprint": fingerprint(provisional._body())}
        )
        return result.validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "gate_id": self.gate_id,
            "checkpoint_fingerprint": self.checkpoint_fingerprint,
            "auditor_invocation_identity": self.auditor_invocation_identity,
            "verdict": self.verdict.value,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def validated(self) -> "AuditVerdict":
        if self.schema_version != AUDIT_VERDICT_SCHEMA_VERSION:
            raise ValueError("unsupported audit verdict schema")
        require_identifier(self.session_id, "verdict session_id")
        require_identifier(self.gate_id, "verdict gate_id")
        require_sha256(self.checkpoint_fingerprint, "verdict checkpoint_fingerprint")
        require_identifier(self.auditor_invocation_identity, "auditor invocation identity")
        if not isinstance(self.verdict, Verdict):
            raise ValueError("unknown audit verdict")
        if not isinstance(self.findings, tuple):
            raise ValueError("findings must be immutable")
        for finding in self.findings:
            if not isinstance(finding, AuditFinding):
                raise ValueError("invalid finding type")
            finding.validated()
            if finding.gate_id != self.gate_id or finding.checkpoint_fingerprint != self.checkpoint_fingerprint:
                raise ValueError("finding is bound to another gate or checkpoint")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("duplicate finding IDs are forbidden")
        blocking = [finding for finding in self.findings if finding.severity == FindingSeverity.BLOCKING]
        if self.verdict == Verdict.PASS and blocking:
            raise ValueError("PASS cannot contain blocking findings")
        if self.verdict == Verdict.FIX_REQUIRED and (
            not any(finding.enforceable_repair for finding in blocking)
            or any(not finding.enforceable_repair for finding in blocking)
        ):
            raise ValueError("FIX_REQUIRED requires enforceable repair findings only")
        if self.verdict == Verdict.BLOCKED and not any(
            finding.severity == FindingSeverity.BLOCKING and finding.requires_human_escalation
            for finding in self.findings
        ):
            raise ValueError("BLOCKED requires a human-escalation finding")
        if self.verdict == Verdict.INCONCLUSIVE and blocking:
            raise ValueError("INCONCLUSIVE cannot carry asserted blocking defects")
        require_sha256(self.verdict_fingerprint, "verdict_fingerprint")
        if fingerprint(self._body()) != self.verdict_fingerprint:
            raise ValueError("audit verdict fingerprint mismatch")
        return self

    def validate_against(self, *, contract: GateContract, checkpoint: Checkpoint) -> "AuditVerdict":
        self.validated()
        contract.validated()
        checkpoint.validated()
        if self.gate_id != contract.gate_id or self.gate_id != checkpoint.gate_id:
            raise ValueError("verdict is bound to another gate")
        if self.session_id != checkpoint.session_id:
            raise ValueError("verdict is bound to another session")
        if self.checkpoint_fingerprint != checkpoint.checkpoint_fingerprint:
            raise ValueError("verdict is bound to another checkpoint")
        for finding in self.findings:
            if finding.cited_gate_clause_id not in contract.clause_ids:
                raise ValueError("finding cites an unknown gate-contract clause")
            if not set(finding.supporting_evidence_references).issubset(
                checkpoint.evidence_reference_ids
            ):
                raise ValueError("finding cites evidence outside the checkpoint")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["verdict_fingerprint"] = self.verdict_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditVerdict":
        require_exact_keys(
            data,
            {
                "schema_version",
                "session_id",
                "gate_id",
                "checkpoint_fingerprint",
                "auditor_invocation_identity",
                "verdict",
                "findings",
                "verdict_fingerprint",
            },
            "audit verdict",
        )
        if not isinstance(data["findings"], list):
            raise ValueError("findings must be an array")
        return cls(
            schema_version=data["schema_version"],
            session_id=data["session_id"],
            gate_id=data["gate_id"],
            checkpoint_fingerprint=data["checkpoint_fingerprint"],
            auditor_invocation_identity=data["auditor_invocation_identity"],
            verdict=Verdict(data["verdict"]),
            findings=tuple(AuditFinding.from_dict(item) for item in data["findings"]),
            verdict_fingerprint=data["verdict_fingerprint"],
        ).validated()
