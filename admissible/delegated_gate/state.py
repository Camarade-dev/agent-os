"""Immutable authoritative state for an independent delegated-gate session."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from admissible.delegated_gate.canonical import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    require_strict_int,
    require_string_list,
)
from admissible.delegated_gate.models import (
    AuditVerdict,
    Checkpoint,
    GatePlan,
    Mission,
)


SESSION_SCHEMA_VERSION = "admissible_delegated_gate_session_v1"
HUMAN_DISPOSITION_SCHEMA_VERSION = "admissible_delegated_human_disposition_v1"


class Phase(str, Enum):
    READY_FOR_GATE = "READY_FOR_GATE"
    GATE_EXECUTING = "GATE_EXECUTING"
    CHECKPOINT_CAPTURED = "CHECKPOINT_CAPTURED"
    AUDITING = "AUDITING"
    REPAIR_AUTHORIZED = "REPAIR_AUTHORIZED"
    REPAIR_EXECUTING = "REPAIR_EXECUTING"
    REAUDITING = "REAUDITING"
    GATE_PASSED = "GATE_PASSED"
    AWAITING_HUMAN = "AWAITING_HUMAN"
    COMPLETED = "COMPLETED"


class HumanBoundaryReason(str, Enum):
    FINAL_REVIEW = "final_review"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    REPAIR_BUDGET_UNAVAILABLE = "repair_budget_unavailable"
    FAILED_REAUDIT = "failed_reaudit"


@dataclass(frozen=True)
class RepairAuthority:
    gate_id: str
    checkpoint_fingerprint: str
    source_verdict_fingerprint: str
    accepted_finding_ids: tuple[str, ...]
    bounded_repair_surface: tuple[str, ...]

    def validated(self) -> "RepairAuthority":
        require_identifier(self.gate_id, "repair authority gate_id")
        require_sha256(self.checkpoint_fingerprint, "repair authority checkpoint fingerprint")
        require_sha256(self.source_verdict_fingerprint, "repair authority verdict fingerprint")
        if not isinstance(self.accepted_finding_ids, tuple) or not self.accepted_finding_ids:
            raise ValueError("repair authority requires accepted findings")
        for finding_id in self.accepted_finding_ids:
            require_identifier(finding_id, "accepted finding ID")
        if len(set(self.accepted_finding_ids)) != len(self.accepted_finding_ids):
            raise ValueError("repair authority finding IDs must be unique")
        if not isinstance(self.bounded_repair_surface, tuple) or not self.bounded_repair_surface:
            raise ValueError("repair authority requires a bounded surface")
        for surface in self.bounded_repair_surface:
            require_nonempty_text(surface, "repair surface", max_bytes=512)
        if len(set(self.bounded_repair_surface)) != len(self.bounded_repair_surface):
            raise ValueError("repair authority surface must be unique")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "checkpoint_fingerprint": self.checkpoint_fingerprint,
            "source_verdict_fingerprint": self.source_verdict_fingerprint,
            "accepted_finding_ids": list(self.accepted_finding_ids),
            "bounded_repair_surface": list(self.bounded_repair_surface),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RepairAuthority":
        require_exact_keys(
            data,
            {
                "gate_id",
                "checkpoint_fingerprint",
                "source_verdict_fingerprint",
                "accepted_finding_ids",
                "bounded_repair_surface",
            },
            "repair authority",
        )
        return cls(
            gate_id=data["gate_id"],
            checkpoint_fingerprint=data["checkpoint_fingerprint"],
            source_verdict_fingerprint=data["source_verdict_fingerprint"],
            accepted_finding_ids=require_string_list(
                data["accepted_finding_ids"], "accepted finding IDs"
            ),
            bounded_repair_surface=require_string_list(
                data["bounded_repair_surface"], "bounded repair surface"
            ),
        ).validated()


@dataclass(frozen=True)
class HumanDisposition:
    schema_version: str
    disposition_id: str
    actor_identity: str
    decision: str
    note: str
    disposition_fingerprint: str

    @classmethod
    def accept(
        cls,
        *,
        disposition_id: str,
        actor_identity: str,
        note: str = "",
    ) -> "HumanDisposition":
        provisional = cls(
            schema_version=HUMAN_DISPOSITION_SCHEMA_VERSION,
            disposition_id=disposition_id,
            actor_identity=actor_identity,
            decision="ACCEPTED",
            note=note,
            disposition_fingerprint="0" * 64,
        )
        result = cls(
            **{
                **provisional.__dict__,
                "disposition_fingerprint": fingerprint(provisional._body()),
            }
        )
        return result.validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "disposition_id": self.disposition_id,
            "actor_identity": self.actor_identity,
            "decision": self.decision,
            "note": self.note,
        }

    def validated(self) -> "HumanDisposition":
        if self.schema_version != HUMAN_DISPOSITION_SCHEMA_VERSION:
            raise ValueError("unsupported human disposition schema")
        require_identifier(self.disposition_id, "disposition_id")
        require_identifier(self.actor_identity, "actor_identity")
        if self.decision != "ACCEPTED":
            raise ValueError("Act 1 only defines the final ACCEPTED disposition")
        if not isinstance(self.note, str) or "\x00" in self.note or len(self.note.encode("utf-8")) > 4096:
            raise ValueError("invalid disposition note")
        require_sha256(self.disposition_fingerprint, "disposition_fingerprint")
        if fingerprint(self._body()) != self.disposition_fingerprint:
            raise ValueError("human disposition fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["disposition_fingerprint"] = self.disposition_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HumanDisposition":
        require_exact_keys(
            data,
            {
                "schema_version",
                "disposition_id",
                "actor_identity",
                "decision",
                "note",
                "disposition_fingerprint",
            },
            "human disposition",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class DelegatedSessionState:
    schema_version: str
    session_id: str
    revision: int
    phase: Phase
    mission: Mission
    gate_plan: GatePlan
    current_gate_index: int
    checkpoint_history: tuple[Checkpoint, ...]
    audit_history: tuple[AuditVerdict, ...]
    repair_authority: RepairAuthority | None
    human_boundary_reason: HumanBoundaryReason | None
    human_disposition: HumanDisposition | None
    state_fingerprint: str

    @property
    def current_gate(self):
        return self.gate_plan.ordered_gate_contracts[self.current_gate_index]

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "revision": self.revision,
            "phase": self.phase.value,
            "mission": self.mission.to_dict(),
            "gate_plan": self.gate_plan.to_dict(),
            "current_gate_index": self.current_gate_index,
            "checkpoint_history": [checkpoint.to_dict() for checkpoint in self.checkpoint_history],
            "audit_history": [verdict.to_dict() for verdict in self.audit_history],
            "repair_authority": (
                self.repair_authority.to_dict() if self.repair_authority is not None else None
            ),
            "human_boundary_reason": (
                self.human_boundary_reason.value if self.human_boundary_reason is not None else None
            ),
            "human_disposition": (
                self.human_disposition.to_dict() if self.human_disposition is not None else None
            ),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["state_fingerprint"] = self.state_fingerprint
        return data

    def validated_structure(self) -> "DelegatedSessionState":
        if self.schema_version != SESSION_SCHEMA_VERSION:
            raise ValueError("unsupported delegated session schema")
        require_identifier(self.session_id, "session_id")
        require_strict_int(self.revision, "revision", minimum=0, maximum=2**63 - 1)
        if not isinstance(self.phase, Phase):
            raise ValueError("unknown delegated session phase")
        self.mission.validated()
        self.gate_plan.validated()
        if self.gate_plan.immutable_mission_fingerprint != self.mission.mission_fingerprint:
            raise ValueError("gate plan is bound to another immutable mission")
        require_strict_int(
            self.current_gate_index,
            "current_gate_index",
            minimum=0,
            maximum=len(self.gate_plan.ordered_gate_contracts) - 1,
        )
        if not isinstance(self.checkpoint_history, tuple) or not isinstance(self.audit_history, tuple):
            raise ValueError("session histories must be immutable")
        for checkpoint in self.checkpoint_history:
            if not isinstance(checkpoint, Checkpoint):
                raise ValueError("invalid checkpoint history type")
            checkpoint.validated()
        for verdict in self.audit_history:
            if not isinstance(verdict, AuditVerdict):
                raise ValueError("invalid audit history type")
            verdict.validated()
        if self.repair_authority is not None:
            self.repair_authority.validated()
        if self.human_boundary_reason is not None and not isinstance(
            self.human_boundary_reason, HumanBoundaryReason
        ):
            raise ValueError("unknown human boundary reason")
        if self.human_disposition is not None:
            self.human_disposition.validated()
        require_sha256(self.state_fingerprint, "state_fingerprint")
        if fingerprint(self._body()) != self.state_fingerprint:
            raise ValueError("delegated session state fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DelegatedSessionState":
        require_exact_keys(
            data,
            {
                "schema_version",
                "session_id",
                "revision",
                "phase",
                "mission",
                "gate_plan",
                "current_gate_index",
                "checkpoint_history",
                "audit_history",
                "repair_authority",
                "human_boundary_reason",
                "human_disposition",
                "state_fingerprint",
            },
            "delegated session",
        )
        if not isinstance(data["checkpoint_history"], list) or not isinstance(data["audit_history"], list):
            raise ValueError("session histories must be arrays")
        state = cls(
            schema_version=data["schema_version"],
            session_id=data["session_id"],
            revision=data["revision"],
            phase=Phase(data["phase"]),
            mission=Mission.from_dict(data["mission"]),
            gate_plan=GatePlan.from_dict(data["gate_plan"]),
            current_gate_index=data["current_gate_index"],
            checkpoint_history=tuple(
                Checkpoint.from_dict(item) for item in data["checkpoint_history"]
            ),
            audit_history=tuple(AuditVerdict.from_dict(item) for item in data["audit_history"]),
            repair_authority=(
                RepairAuthority.from_dict(data["repair_authority"])
                if data["repair_authority"] is not None
                else None
            ),
            human_boundary_reason=(
                HumanBoundaryReason(data["human_boundary_reason"])
                if data["human_boundary_reason"] is not None
                else None
            ),
            human_disposition=(
                HumanDisposition.from_dict(data["human_disposition"])
                if data["human_disposition"] is not None
                else None
            ),
            state_fingerprint=data["state_fingerprint"],
        )
        return state.validated_structure()


def mint_state(**values: Any) -> DelegatedSessionState:
    """Construct a state with a protocol-side fingerprint."""

    provisional = DelegatedSessionState(**{**values, "state_fingerprint": "0" * 64})
    return DelegatedSessionState(
        **{**values, "state_fingerprint": fingerprint(provisional._body())}
    ).validated_structure()


def new_session_state(
    *,
    session_id: str,
    mission: Mission,
    gate_plan: GatePlan,
) -> DelegatedSessionState:
    state = mint_state(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=session_id,
        revision=0,
        phase=Phase.READY_FOR_GATE,
        mission=mission,
        gate_plan=gate_plan,
        current_gate_index=0,
        checkpoint_history=(),
        audit_history=(),
        repair_authority=None,
        human_boundary_reason=None,
        human_disposition=None,
    )
    from admissible.delegated_gate.invariants import validate_state

    validate_state(state)
    return state
