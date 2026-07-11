"""Durable schemas for RUN_044 runtime-verification orchestration.

Kept separate from :mod:`admissible.browser_runtime.models` (RUN_043's own
plan/evidence schemas, which stay inside the sealed ``browser_runtime``
subsystem) and from ``admissible.high_autonomy_controller.HighAutonomyRunState``
(the governed-run state itself). This module only describes:

- one durable runtime-verification *attempt* record (PART A.1);
- the transition object the orchestrator hands back to the controller
  (PART B.5), so the controller never has to reach into orchestrator
  internals to decide what to persist or show;
- one human-observation record, kept distinct from human-authority
  approval/refusal records (PART J).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_attempt_id() -> str:
    return f"runtime_attempt_{uuid.uuid4().hex[:12]}"


def new_observation_id() -> str:
    return f"human_observation_{uuid.uuid4().hex[:12]}"


# --- PART A.1 attempt statuses ----------------------------------------------
STATUS_PREPARED = "prepared"
STATUS_CAPABILITY_CHECKING = "capability_checking"
STATUS_UNAVAILABLE = "unavailable"
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_EVIDENCE_READY = "evidence_ready"
STATUS_EVIDENCE_APPLIED = "evidence_applied"
STATUS_FAILED = "failed"
STATUS_OBSERVABILITY_GAP = "observability_gap"
STATUS_AWAITING_HUMAN_OBSERVATION = "awaiting_human_observation"
STATUS_COMPLETED = "completed"
STATUS_INTERRUPTED = "interrupted"
STATUS_CANCELLED = "cancelled"

ATTEMPT_STATUSES = frozenset(
    {
        STATUS_PREPARED,
        STATUS_CAPABILITY_CHECKING,
        STATUS_UNAVAILABLE,
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_EVIDENCE_READY,
        STATUS_EVIDENCE_APPLIED,
        STATUS_FAILED,
        STATUS_OBSERVABILITY_GAP,
        STATUS_AWAITING_HUMAN_OBSERVATION,
        STATUS_COMPLETED,
        STATUS_INTERRUPTED,
        STATUS_CANCELLED,
    }
)

# Statuses in which an in-process worker may legitimately still be active.
ACTIVE_WORKER_STATUSES = frozenset({STATUS_QUEUED, STATUS_RUNNING})
# Statuses that are terminal for one attempt (a retry gets a new attempt_id).
TERMINAL_ATTEMPT_STATUSES = frozenset(
    {
        STATUS_UNAVAILABLE,
        STATUS_EVIDENCE_APPLIED,
        STATUS_FAILED,
        STATUS_INTERRUPTED,
        STATUS_CANCELLED,
    }
)


@dataclass
class RuntimeVerificationAttempt:
    """One durable browser-runtime verification attempt (PART A.1)."""

    attempt_id: str
    session_id: str
    mission_contract_sha256: str
    runtime_plan_sha256: str
    provider_id: str
    provider_capability_snapshot: dict[str, Any] = field(default_factory=dict)
    criterion_ids: list[str] = field(default_factory=list)
    affected_artifact_hashes: dict[str, str] = field(default_factory=dict)
    status: str = STATUS_PREPARED
    created_at: str = field(default_factory=_now_iso)
    started_at: str | None = None
    completed_at: str | None = None
    failure_class: str | None = None
    failure_message: str | None = None
    evidence_id: str | None = None
    evidence_paths: list[str] = field(default_factory=list)
    cleanup_status: str | None = None
    retry_of_attempt_id: str | None = None
    attempt_number: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "session_id": self.session_id,
            "mission_contract_sha256": self.mission_contract_sha256,
            "runtime_plan_sha256": self.runtime_plan_sha256,
            "provider_id": self.provider_id,
            "provider_capability_snapshot": dict(self.provider_capability_snapshot),
            "criterion_ids": list(self.criterion_ids),
            "affected_artifact_hashes": dict(self.affected_artifact_hashes),
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "failure_class": self.failure_class,
            "failure_message": self.failure_message,
            "evidence_id": self.evidence_id,
            "evidence_paths": list(self.evidence_paths),
            "cleanup_status": self.cleanup_status,
            "retry_of_attempt_id": self.retry_of_attempt_id,
            "attempt_number": self.attempt_number,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuntimeVerificationAttempt":
        return cls(
            attempt_id=str(data.get("attempt_id") or ""),
            session_id=str(data.get("session_id") or ""),
            mission_contract_sha256=str(data.get("mission_contract_sha256") or ""),
            runtime_plan_sha256=str(data.get("runtime_plan_sha256") or ""),
            provider_id=str(data.get("provider_id") or ""),
            provider_capability_snapshot=dict(data.get("provider_capability_snapshot") or {}),
            criterion_ids=list(data.get("criterion_ids") or []),
            affected_artifact_hashes=dict(data.get("affected_artifact_hashes") or {}),
            status=str(data.get("status") or STATUS_PREPARED),
            created_at=str(data.get("created_at") or _now_iso()),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            failure_class=data.get("failure_class"),
            failure_message=data.get("failure_message"),
            evidence_id=data.get("evidence_id"),
            evidence_paths=list(data.get("evidence_paths") or []),
            cleanup_status=data.get("cleanup_status"),
            retry_of_attempt_id=data.get("retry_of_attempt_id"),
            attempt_number=int(data.get("attempt_number") or 1),
        )


@dataclass
class RuntimeOrchestrationTransition:
    """What the orchestrator hands back to the controller for one decision (PART B.5).

    The controller only persists ``persisted_attempt``, projects the other
    fields into its own state/UI, and schedules the next tick according to
    ``next_step``/``auto_tick_safe``. It never inspects orchestrator
    internals (the worker registry, the provider, the plan builder).
    """

    transition_type: str
    changed: bool
    next_step: str
    mode: str
    semantic_status: str
    event_message: str
    persisted_attempt: dict[str, Any] | None = None
    evidence_refs: list[str] = field(default_factory=list)
    affected_criteria: list[str] = field(default_factory=list)
    auto_tick_safe: bool = True
    provider_call_required: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_type": self.transition_type,
            "changed": self.changed,
            "next_step": self.next_step,
            "mode": self.mode,
            "semantic_status": self.semantic_status,
            "event_message": self.event_message,
            "persisted_attempt": self.persisted_attempt,
            "evidence_refs": list(self.evidence_refs),
            "affected_criteria": list(self.affected_criteria),
            "auto_tick_safe": self.auto_tick_safe,
            "provider_call_required": self.provider_call_required,
            "extra": dict(self.extra),
        }


@dataclass
class RuntimeNeedAssessment:
    """PART C: what runtime verification (if any) is required right now."""

    required: bool
    reason: str
    plan: Any = None
    coverage_report: dict[str, Any] = field(default_factory=dict)
    runtime_criterion_ids: list[str] = field(default_factory=list)
    executable_now_criterion_ids: list[str] = field(default_factory=list)
    missing_observability_criterion_ids: list[str] = field(default_factory=list)
    human_observation_criterion_ids: list[str] = field(default_factory=list)
    unsupported_criterion_ids: list[str] = field(default_factory=list)
    ambiguous_criterion_ids: list[str] = field(default_factory=list)


@dataclass
class HumanObservationRecord:
    """One human observation of a subjective criterion (PART J.50).

    Distinct from :mod:`admissible.control_surface`'s ``HumanDecisionRecord``
    (human-authority approve/refuse of a genuinely dangerous action): this
    record only ever touches criteria classified ``human_observation_required``
    and is never counted as a human-authority interruption (PART J.51).
    """

    observation_id: str
    criterion_id: str
    actor: str
    disposition: str  # "pass" | "fail" | "waive"
    note: str
    timestamp: str = field(default_factory=_now_iso)
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "criterion_id": self.criterion_id,
            "actor": self.actor,
            "disposition": self.disposition,
            "note": self.note,
            "timestamp": self.timestamp,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HumanObservationRecord":
        return cls(
            observation_id=str(data.get("observation_id") or ""),
            criterion_id=str(data.get("criterion_id") or ""),
            actor=str(data.get("actor") or ""),
            disposition=str(data.get("disposition") or ""),
            note=str(data.get("note") or ""),
            timestamp=str(data.get("timestamp") or _now_iso()),
            evidence_refs=list(data.get("evidence_refs") or []),
        )
