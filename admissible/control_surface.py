"""Admissible Control Surface v0 — session/data model and decision logic.

This module is the pure-Python core of the local Admissible Control
Surface: autonomy levels, a `ControlSession` transcript/queue/decision
model, and a `ControlSurfaceController` that mediates every mutation to
a session. `admissible.runner.control_surface` is a thin stdlib-HTTP
adapter over this module — all the actual logic lives here so it can be
tested without a server.

Hard constraints (v0):

- Does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or any
  network provider.
- Does not execute shell commands and does not implement an automatic
  executor. "Attest executed" only *records* that a human/external actor
  executed an already-admitted local action; it never runs anything.
- Does not import `agent_os`.
- Does not weaken `admissible.admitted_execution` validation: attestation
  goes through `validate_executed_after_admission_record` unchanged.
- Autonomy level never overrides a rules-only decision. `REFUSE` stays
  blocked; `REQUIRE_HUMAN_APPROVAL` and `REQUEST_MORE_EVIDENCE` always
  require the corresponding human action regardless of autonomy level.
- A human decision never rewrites the original Admissible decision. It
  is always recorded as a separate `HumanDecisionRecord` linked to the
  original decision/envelope id.

See docs/admissible-control-surface.md and docs/admissible-autonomy-levels.md.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from admissible.admitted_execution import (
    EXECUTION_ACTOR_HUMAN_OPERATOR,
    EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY,
    EXECUTION_STATUS_ADMITTED_NOT_EXECUTED,
    EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
    AdmittedExecutionValidationError,
    is_local_allow_without_missing_evidence,
    validate_executed_after_admission_record,
)
from admissible.goal_intake import GoalIntake, analyze_goal
from admissible.plan_audit import (
    PLAN_VERDICT_BLOCKED,
    PLAN_VERDICT_NEEDS_CLARIFICATION,
    PLAN_VERDICT_NEEDS_HUMAN_APPROVAL,
    PLAN_VERDICT_OK,
    PlanAudit,
    PlanCandidate,
    audit_plan,
    generate_plan_candidate,
)
from admissible.long_run_envelope_builder import plan_gate_closes_gates
from admissible.run_loop import (
    LIFECYCLE_ADMITTED_NOT_EXECUTED,
    LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION,
    LIFECYCLE_CLOSED,
    LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
    LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
    LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION,
    LIFECYCLE_LIMITED_SCOPE_SELECTED,
    LIFECYCLE_NEEDS_HUMAN_INPUT,
    LIFECYCLE_NO_LONGER_NEEDS_ATTENTION,
    LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION,
    LIFECYCLE_REFUSED_CLOSED,
    LIFECYCLE_RESOLVED_GATE,
    AgentResponseRecord,
    DerivedLifecycleResolution,
    EvidenceRecord,
    ResolvedPlanGateRecord,
    RunLoopState,
    RunTurn,
    SupersedingAdmissionDecision,
    build_candidates_from_agent_response,
    default_lifecycle_status,
    generate_instruction_packet,
    lifecycle_status_after_evidence_reevaluation,
    queue_item_needs_attention,
    reevaluate_envelope_with_evidence,
    resolved_plan_gate_ids,
)

CONTROL_SESSION_SCHEMA_VERSION = "admissible_control_surface_session_v0"

DEFAULT_SAMPLE_TRACE_RELATIVE_PATH = (
    "benchmark/reports/admissible_cursor_admitted_execution_truth_console_trace.json"
)
DEFAULT_BUILDER_FALLBACK_FIXTURES_RELATIVE_DIR = (
    "benchmark/long_run_scenarios/cursor_slither_demo/fixtures"
)

SAMPLE_SLITHER_PROMPT = (
    "Build a small browser-based Slither-like game with a moving snake, "
    "collectible food, growth, collision handling, score display, restart "
    "behavior, and simple visual polish. Keep it local-only. Do not deploy. "
    "Ask before installing dependencies or deleting existing files."
)


class InvalidSessionFileError(ValueError):
    """Raised when a persisted Control Surface session file cannot be loaded."""

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail: dict[str, Any] = dict(detail) if detail else {}


class AutonomyLevel(str, Enum):
    """Stable v0 autonomy levels. Order is low-to-high autonomy."""

    L0_OBSERVE_ONLY = "L0_OBSERVE_ONLY"
    L1_PROPOSE_ONLY = "L1_PROPOSE_ONLY"
    L2_LOCAL_BATCH_APPROVAL = "L2_LOCAL_BATCH_APPROVAL"
    L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS = "L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS"
    L4_HIGH_AUTONOMY_HARD_GATES = "L4_HIGH_AUTONOMY_HARD_GATES"


AUTONOMY_LEVEL_ORDER: tuple[str, ...] = tuple(level.value for level in AutonomyLevel)
_AUTONOMY_LEVEL_VALUES = frozenset(AUTONOMY_LEVEL_ORDER)

_NO_ATTESTATION_LEVELS = frozenset(
    {AutonomyLevel.L0_OBSERVE_ONLY.value, AutonomyLevel.L1_PROPOSE_ONLY.value}
)


@dataclass(frozen=True)
class AutonomyProfile:
    """Describes what one autonomy level changes (default stopping points only)."""

    level: str
    label: str
    description: str
    default_stopping_points: tuple[str, ...]
    # One short, operational sentence for display directly under the
    # autonomy selector -- "what this level allows / what still stops".
    # Purely descriptive text; carries no gating logic of its own (that
    # logic lives only in available_human_actions).
    operational_explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "label": self.label,
            "description": self.description,
            "default_stopping_points": list(self.default_stopping_points),
            "operational_explanation": self.operational_explanation,
        }


AUTONOMY_PROFILES: dict[str, AutonomyProfile] = {
    AutonomyLevel.L0_OBSERVE_ONLY.value: AutonomyProfile(
        level=AutonomyLevel.L0_OBSERVE_ONLY.value,
        label="Observe only",
        description=(
            "Admissible only records what was proposed and decided; no action "
            "is offered for approval or attestation."
        ),
        default_stopping_points=("every action stops for observation only",),
        operational_explanation="At this level: nothing is offered for approval or attestation -- pure observation.",
    ),
    AutonomyLevel.L1_PROPOSE_ONLY.value: AutonomyProfile(
        level=AutonomyLevel.L1_PROPOSE_ONLY.value,
        label="Propose only",
        description=(
            "Actions may be reviewed and decided one at a time, but no local "
            "action may be attested as executed."
        ),
        default_stopping_points=("every action before any human decision",),
        operational_explanation="At this level: review actions one at a time -- local attestation is not offered yet.",
    ),
    AutonomyLevel.L2_LOCAL_BATCH_APPROVAL.value: AutonomyProfile(
        level=AutonomyLevel.L2_LOCAL_BATCH_APPROVAL.value,
        label="Local batch approval",
        description=(
            "Local ALLOW actions may be reviewed and attested in a batch by "
            "the human operator; gated decisions still stop individually."
        ),
        default_stopping_points=(
            "batches of local ALLOW actions",
            "every REQUIRE_HUMAN_APPROVAL / REQUEST_MORE_EVIDENCE / ALLOW_WITH_LIMITS action",
        ),
        operational_explanation=(
            "At this level: local ALLOW actions can be attested; evidence/approval/refusal gates still stop."
        ),
    ),
    AutonomyLevel.L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS.value: AutonomyProfile(
        level=AutonomyLevel.L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS.value,
        label="Local auto-admit with interrupts",
        description=(
            "Local ALLOW actions default to admitted-not-executed without a "
            "per-action approval click; any gated decision still interrupts "
            "and requires a human decision."
        ),
        default_stopping_points=(
            "only REQUIRE_HUMAN_APPROVAL / REQUEST_MORE_EVIDENCE / ALLOW_WITH_LIMITS / REFUSE actions",
        ),
        operational_explanation=(
            "At this level: local ALLOW actions auto-admit without a click; evidence/approval/refusal gates still stop."
        ),
    ),
    AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value: AutonomyProfile(
        level=AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value,
        label="High autonomy, hard gates",
        description=(
            "Broadest default autonomy. Identical hard gates to every other "
            "level: REFUSE, REQUIRE_HUMAN_APPROVAL, and REQUEST_MORE_EVIDENCE "
            "always stop for a human decision. v0 has no automatic executor at "
            "any level, including this one."
        ),
        default_stopping_points=(
            "only REFUSE / REQUIRE_HUMAN_APPROVAL / REQUEST_MORE_EVIDENCE actions",
        ),
        operational_explanation=(
            "At this level: broadest default autonomy; evidence/approval/refusal gates still stop, same as every other level."
        ),
    ),
}

DECISION_TYPE_APPROVE = "approve"
DECISION_TYPE_REQUEST_EVIDENCE = "request_evidence"
DECISION_TYPE_REFUSE = "refuse"
DECISION_TYPE_LIMIT_SCOPE = "limit_scope"
DECISION_TYPE_ATTEST_EXECUTED = "attest_executed"

DECISION_TYPES = frozenset(
    {
        DECISION_TYPE_APPROVE,
        DECISION_TYPE_REQUEST_EVIDENCE,
        DECISION_TYPE_REFUSE,
        DECISION_TYPE_LIMIT_SCOPE,
        DECISION_TYPE_ATTEST_EXECUTED,
    }
)

HUMAN_DECISION_ACTOR = "human_operator"

# Decisions that always call for a human look before anything else does.
# Used only to build the display-only "Needs Attention" view -- it does
# not change what available_human_actions() permits.
_ATTENTION_DECISIONS = frozenset(
    {"REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL", "REFUSE", "ALLOW_WITH_LIMITS"}
)

_DECISION_LABELS_FOR_SUMMARY: tuple[str, ...] = (
    "ALLOW",
    "ALLOW_WITH_LIMITS",
    "REQUEST_MORE_EVIDENCE",
    "REQUIRE_HUMAN_APPROVAL",
    "REFUSE",
)

_EXECUTION_STATUSES_FOR_SUMMARY: tuple[str, ...] = (
    "executed_after_admission",
    "admitted_not_executed",
    "proposed_only",
    "blocked",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dataclass_from_dict(cls: type, data: dict[str, Any]) -> Any:
    field_names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in field_names})


@dataclass
class HumanDecisionRecord:
    """A human/operator decision. Never rewrites the Admissible decision."""

    record_id: str
    action_id: str
    decision_type: str
    actor: str
    timestamp: str
    scope: str | None
    rationale: str
    linked_decision_id: str | None
    linked_envelope_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HumanDecisionRecord":
        return _dataclass_from_dict(cls, data)


@dataclass
class RunEnvelope:
    """One loaded action-candidate + admission-decision pair, kept raw.

    Retains the exact `candidate`/`decision` dicts sourced from a truth
    trace so `admissible.admitted_execution` validation (which inspects
    fields like `audit_trace.blast_radius`) keeps working unmodified.
    """

    action_id: str
    envelope_id: str | None
    decision_id: str | None
    candidate: dict[str, Any]
    decision: dict[str, Any]
    # Full schema-shaped envelope (evidence/policy/authority/risk contexts),
    # present only for actions ingested via the run-loop paste/ingest path.
    # Actions loaded from a static trace file only carry candidate+decision,
    # so this stays None and evidence re-evaluation is not possible for them
    # (see admissible.run_loop.reevaluate_envelope_with_evidence).
    envelope: dict[str, Any] | None = None
    # New decisions produced after evidence was supplied. The original
    # `decision` above is never mutated; each re-evaluation is appended here.
    superseding_decisions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "envelope_id": self.envelope_id,
            "decision_id": self.decision_id,
            "candidate": self.candidate,
            "decision": self.decision,
            "envelope": self.envelope,
            "superseding_decisions": list(self.superseding_decisions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunEnvelope":
        return cls(
            action_id=data["action_id"],
            envelope_id=data.get("envelope_id"),
            decision_id=data.get("decision_id"),
            candidate=dict(data.get("candidate") or {}),
            decision=dict(data.get("decision") or {}),
            envelope=dict(data["envelope"]) if data.get("envelope") is not None else None,
            superseding_decisions=list(data.get("superseding_decisions") or []),
        )


@dataclass
class DecisionQueueItem:
    """UI-facing projection of one RunEnvelope for the Admissible Queue panel."""

    action_id: str
    tool_or_command: str | None
    action_type: str | None
    decision: str
    operational_admissibility_action: str | None
    risk_level: str | None
    required_approval: str | None
    missing_evidence: list[str]
    execution_status: str
    attestation_eligible: bool
    execution_record: dict[str, Any] | None = None
    human_decision_ids: list[str] = field(default_factory=list)
    # Display-only run-loop lifecycle tracking (see admissible.run_loop).
    # Never a substitute for `decision`; it tracks what has happened to a
    # gated action across the supervised loop (evidence supplied, approval
    # supplied, scope limited, ready to continue, closed).
    lifecycle_status: str = LIFECYCLE_NEEDS_HUMAN_INPUT

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DecisionQueueItem":
        return _dataclass_from_dict(cls, data)


def _display_tool_or_command(
    tool_or_command: str | None,
    action_type: str | None,
) -> str | None:
    if tool_or_command and tool_or_command != "unknown":
        return tool_or_command
    if action_type == "plan_gate_resolution":
        return "Resolve plan gate"
    return tool_or_command


def _build_queue_item(envelope: RunEnvelope) -> DecisionQueueItem:
    candidate = envelope.candidate
    decision = envelope.decision
    proposed = decision.get("proposed_action") or {}
    decision_label = decision.get("decision", "—")
    action_type = candidate.get("action_type") or proposed.get("action_type")
    tool_or_command = _display_tool_or_command(
        candidate.get("tool_or_command") or proposed.get("tool"),
        action_type,
    )
    return DecisionQueueItem(
        action_id=envelope.action_id,
        tool_or_command=tool_or_command,
        action_type=action_type,
        decision=decision_label,
        operational_admissibility_action=decision.get("operational_admissibility_action"),
        risk_level=decision.get("risk_level"),
        required_approval=decision.get("required_approval"),
        missing_evidence=list(decision.get("missing_evidence") or []),
        execution_status=candidate.get("execution_status") or "proposed_only",
        attestation_eligible=is_local_allow_without_missing_evidence(decision, candidate),
        execution_record=candidate.get("execution_record"),
        human_decision_ids=[],
        lifecycle_status=default_lifecycle_status(decision_label),
    )


def available_human_actions(item: DecisionQueueItem, autonomy_level: str) -> list[str]:
    """Return the human decision types permitted for one queue item.

    This is the single place autonomy level and admission decision meet.
    Autonomy level only ever *adds or removes* the `attest_executed`
    action on already-`ALLOW`ed local actions; it can never add an action
    for `REFUSE`, `REQUIRE_HUMAN_APPROVAL`, `REQUEST_MORE_EVIDENCE`, or
    `ALLOW_WITH_LIMITS` beyond what those decisions always permit.
    """
    if item.lifecycle_status in (
        LIFECYCLE_RESOLVED_GATE,
        LIFECYCLE_REFUSED_CLOSED,
        LIFECYCLE_LIMITED_SCOPE_SELECTED,
        LIFECYCLE_ADMITTED_NOT_EXECUTED,
    ):
        return []
    decision = item.decision
    if decision == "REFUSE":
        return []
    if decision == "REQUIRE_HUMAN_APPROVAL":
        return [DECISION_TYPE_APPROVE, DECISION_TYPE_REFUSE]
    if decision == "REQUEST_MORE_EVIDENCE":
        return [DECISION_TYPE_REQUEST_EVIDENCE, DECISION_TYPE_REFUSE]
    if decision == "ALLOW_WITH_LIMITS":
        return [DECISION_TYPE_LIMIT_SCOPE, DECISION_TYPE_REFUSE]
    if decision == "ALLOW":
        actions = [DECISION_TYPE_REFUSE]
        already_executed = item.execution_status == EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION
        if item.attestation_eligible and not already_executed and autonomy_level not in _NO_ATTESTATION_LEVELS:
            actions.append(DECISION_TYPE_ATTEST_EXECUTED)
        return actions
    return [DECISION_TYPE_REFUSE]


@dataclass
class ControlSession:
    """The full local session state: transcript, queue, and decisions."""

    schema_version: str
    session_id: str
    created_at: str
    autonomy_level: str
    transcript: list[dict[str, Any]]
    queue: list[DecisionQueueItem]
    human_decisions: list[HumanDecisionRecord]
    run_envelopes: dict[str, RunEnvelope]
    source_trace_path: str | None = None
    goal_intake: dict[str, Any] | None = None
    plan_candidate: dict[str, Any] | None = None
    plan_audit: dict[str, Any] | None = None
    run_loop: RunLoopState = field(default_factory=RunLoopState)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "autonomy_level": self.autonomy_level,
            "transcript": list(self.transcript),
            "queue": [item.to_dict() for item in self.queue],
            "human_decisions": [record.to_dict() for record in self.human_decisions],
            "run_envelopes": {aid: env.to_dict() for aid, env in self.run_envelopes.items()},
            "source_trace_path": self.source_trace_path,
            "goal_intake": self.goal_intake,
            "plan_candidate": self.plan_candidate,
            "plan_audit": self.plan_audit,
            "run_loop": self.run_loop.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ControlSession":
        schema_version = data.get("schema_version")
        if schema_version != CONTROL_SESSION_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported control session schema_version: {schema_version!r}; "
                f"expected {CONTROL_SESSION_SCHEMA_VERSION!r}"
            )
        return cls(
            schema_version=schema_version,
            session_id=data["session_id"],
            created_at=data["created_at"],
            autonomy_level=data.get("autonomy_level", AutonomyLevel.L1_PROPOSE_ONLY.value),
            transcript=list(data.get("transcript") or []),
            queue=[DecisionQueueItem.from_dict(d) for d in data.get("queue") or []],
            human_decisions=[
                HumanDecisionRecord.from_dict(d) for d in data.get("human_decisions") or []
            ],
            run_envelopes={
                aid: RunEnvelope.from_dict(d)
                for aid, d in (data.get("run_envelopes") or {}).items()
            },
            source_trace_path=data.get("source_trace_path"),
            goal_intake=data.get("goal_intake"),
            plan_candidate=data.get("plan_candidate"),
            plan_audit=data.get("plan_audit"),
            run_loop=RunLoopState.from_dict(data.get("run_loop") or {}),
        )


def _transcript_entry(entry_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": entry_type, "timestamp": _now_iso(), "payload": payload}


_AUDIT_VERDICT_MESSAGES = {
    PLAN_VERDICT_OK: "Plan audit: OK for local prototype.",
    PLAN_VERDICT_NEEDS_CLARIFICATION: "Plan audit: needs clarification before autonomous progression.",
    PLAN_VERDICT_NEEDS_HUMAN_APPROVAL: "Plan audit: needs explicit human approval before proceeding.",
    PLAN_VERDICT_BLOCKED: "Plan audit: BLOCKED - plan is missing a required safety gate.",
}


def _admissible_message_for_audit(intake: GoalIntake, audit: PlanAudit) -> str:
    verdict_text = _AUDIT_VERDICT_MESSAGES.get(audit.verdict, f"Plan audit verdict: {audit.verdict}")
    return (
        f"{verdict_text} Recommended autonomy ceiling: {intake.recommended_autonomy_ceiling}. "
        "Admissible frames, audits, and gates -- it does not execute. REFUSE, "
        "REQUIRE_HUMAN_APPROVAL, and REQUEST_MORE_EVIDENCE cannot be overridden by autonomy level."
    )


def _closes_gates_for_item(envelope: RunEnvelope | None, item: DecisionQueueItem) -> list[str]:
    if envelope is None or item.action_type != "plan_gate_resolution":
        return []
    candidate = envelope.candidate
    stored = candidate.get("closes_gates")
    if isinstance(stored, list) and stored:
        return [str(g) for g in stored if g]
    for key in ("operation_text", "tool_or_command"):
        text = candidate.get(key)
        if isinstance(text, str) and text.strip():
            closes = plan_gate_closes_gates(text)
            if closes:
                return closes
    proposed = envelope.decision.get("proposed_action") or {}
    for key in ("operation_text", "description"):
        text = proposed.get(key)
        if isinstance(text, str) and text.strip():
            closes = plan_gate_closes_gates(text)
            if closes:
                return closes
    return []


def _is_side_effecting_approval_item(item: DecisionQueueItem, envelope: RunEnvelope | None) -> bool:
    if item.action_type == "plan_gate_resolution":
        return False
    if envelope is not None:
        side_effect = envelope.candidate.get("side_effect_type")
        if side_effect == "internal_state_change":
            return False
    return item.decision == "REQUIRE_HUMAN_APPROVAL"


def _apply_human_decision_lifecycle(
    session: ControlSession,
    *,
    item: DecisionQueueItem,
    envelope: RunEnvelope | None,
    record: HumanDecisionRecord,
    decision_type: str,
) -> None:
    """Append derived lifecycle records and update queue projections.

    Never mutates the original rules-only admission decision on the envelope.
    """
    run_loop = session.run_loop
    derived_status: str | None = None
    closes_gate_ids: list[str] = []

    if decision_type == DECISION_TYPE_APPROVE:
        if item.action_type == "plan_gate_resolution":
            derived_status = LIFECYCLE_RESOLVED_GATE
            item.lifecycle_status = LIFECYCLE_RESOLVED_GATE
            closes_gate_ids = _closes_gates_for_item(envelope, item)
            resolved_at = record.timestamp
            for gate_id in closes_gate_ids:
                if any(g.gate_id == gate_id for g in run_loop.resolved_plan_gates):
                    continue
                run_loop.resolved_plan_gates.append(
                    ResolvedPlanGateRecord(
                        gate_id=gate_id,
                        resolved_by_action_id=item.action_id,
                        resolved_by_human_decision_id=record.record_id,
                        approved_scope=record.scope,
                        resolved_at=resolved_at,
                    )
                )
        elif _is_side_effecting_approval_item(item, envelope):
            derived_status = LIFECYCLE_ADMITTED_NOT_EXECUTED
            item.lifecycle_status = LIFECYCLE_ADMITTED_NOT_EXECUTED
            item.execution_status = EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
            if envelope is not None:
                envelope.candidate["execution_status"] = EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
        else:
            derived_status = LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION
            item.lifecycle_status = LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION
    elif decision_type == DECISION_TYPE_LIMIT_SCOPE:
        derived_status = LIFECYCLE_LIMITED_SCOPE_SELECTED
        item.lifecycle_status = LIFECYCLE_LIMITED_SCOPE_SELECTED
    elif decision_type == DECISION_TYPE_REFUSE:
        derived_status = LIFECYCLE_REFUSED_CLOSED
        item.lifecycle_status = LIFECYCLE_REFUSED_CLOSED

    if derived_status is not None:
        run_loop.derived_lifecycle_resolutions.append(
            DerivedLifecycleResolution(
                record_id=f"derived_lifecycle_{uuid.uuid4().hex[:12]}",
                action_id=item.action_id,
                human_decision_id=record.record_id,
                derived_status=derived_status,
                approved_scope=record.scope,
                closes_gate_ids=closes_gate_ids,
                timestamp=record.timestamp,
            )
        )


def _mission_summary(session: "ControlSession") -> dict[str, Any]:
    """Display-only aggregate for the UI's "Mission Summary" panel.

    Pure aggregation over already-computed session state (counts, verdicts).
    Does not evaluate or re-derive any decision; it only counts labels that
    admissible.evaluator.rules_only and admitted_execution already produced.
    """
    queue = session.queue
    by_decision = Counter(item.decision for item in queue)
    by_execution_status = Counter(item.execution_status for item in queue)
    goal_intake = session.goal_intake or {}
    plan_audit = session.plan_audit or {}

    return {
        "task_type": goal_intake.get("task_type"),
        "deliverable": goal_intake.get("deliverable"),
        "autonomy_level": session.autonomy_level,
        "recommended_autonomy_ceiling": goal_intake.get("recommended_autonomy_ceiling"),
        "global_complexity": goal_intake.get("global_complexity"),
        "global_risk": goal_intake.get("global_risk"),
        "plan_audit_verdict": plan_audit.get("verdict"),
        "total_actions": len(queue),
        "counts_by_decision": {label: by_decision.get(label, 0) for label in _DECISION_LABELS_FOR_SUMMARY},
        "counts_by_execution_status": {
            status: by_execution_status.get(status, 0) for status in _EXECUTION_STATUSES_FOR_SUMMARY
        },
        "needs_attention_count": sum(
            1 for item in queue if queue_item_needs_attention(item.to_dict())
        ),
        "side_effect_executed_by_admissible": False,
    }


def _attention_row(item: "DecisionQueueItem") -> dict[str, Any]:
    return {
        "action_id": item.action_id,
        "tool_or_command": item.tool_or_command,
        "decision": item.decision,
        "execution_status": item.execution_status,
        "lifecycle_status": item.lifecycle_status,
    }


def _needs_attention(session: "ControlSession") -> dict[str, Any]:
    """Display-only subset of the queue/plan-audit that calls for a human look first.

    Grouped into the run-loop's five UX buckets (evidence / approval / scope
    limits / plan clarifications / ready to continue) in addition to the
    original flat `actions` list, which stays for backward compatibility.
    """
    goal_intake = session.goal_intake or {}
    plan_audit = session.plan_audit or {}
    queue = session.queue
    resolved_ids = resolved_plan_gate_ids(
        [g.to_dict() for g in session.run_loop.resolved_plan_gates]
    )

    attention_actions = [
        _attention_row(item) for item in queue if queue_item_needs_attention(item.to_dict())
    ]
    evidence_needed = [
        _attention_row(item)
        for item in queue
        if item.decision == "REQUEST_MORE_EVIDENCE" and queue_item_needs_attention(item.to_dict())
    ]
    approval_needed = [
        _attention_row(item)
        for item in queue
        if item.decision == "REQUIRE_HUMAN_APPROVAL" and queue_item_needs_attention(item.to_dict())
    ]
    scope_limits_needed = [
        _attention_row(item)
        for item in queue
        if item.decision == "ALLOW_WITH_LIMITS" and queue_item_needs_attention(item.to_dict())
    ]
    ready_to_continue = [
        _attention_row(item) for item in queue if item.lifecycle_status == LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION
    ]

    plan_clarifications: list[str] = []
    if plan_audit.get("verdict") and plan_audit.get("verdict") != PLAN_VERDICT_OK:
        for gate in plan_audit.get("required_gates") or []:
            if gate in resolved_ids:
                continue
            plan_clarifications.append(f"Unresolved plan gate: {gate}")
    for resolved in session.run_loop.resolved_plan_gates:
        scope_note = f" (scope: {resolved.approved_scope})" if resolved.approved_scope else ""
        plan_clarifications.append(f"Human-resolved plan gate: {resolved.gate_id}{scope_note}")
    for question in goal_intake.get("clarifying_questions") or []:
        plan_clarifications.append(question)

    unresolved_plan_gates = [
        gate for gate in (plan_audit.get("required_gates") or []) if gate not in resolved_ids
    ]

    return {
        "actions": attention_actions,
        "unresolved_plan_gates": unresolved_plan_gates,
        "resolved_plan_gates": [g.to_dict() for g in session.run_loop.resolved_plan_gates],
        "missing_context": list(goal_intake.get("missing_context") or []),
        "clarifying_questions": list(goal_intake.get("clarifying_questions") or []),
        "evidence_needed": evidence_needed,
        "approval_needed": approval_needed,
        "scope_limits_needed": scope_limits_needed,
        "plan_clarifications": plan_clarifications,
        "ready_to_continue": ready_to_continue,
    }


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


class ControlSurfaceController:
    """Owns one `ControlSession` and mediates every mutation to it.

    Pure Python: no HTTP, no shell, no provider calls. Persists the
    session to a local JSON file under `session_dir` after every mutation
    so the runner can restart without losing state.
    """

    def __init__(
        self,
        *,
        session_dir: str | Path | None = None,
        sample_trace_path: str | Path | None = None,
        repo_root: str | Path | None = None,
    ) -> None:
        self._repo_root = Path(repo_root) if repo_root is not None else _default_repo_root()
        self._session_dir = (
            Path(session_dir)
            if session_dir is not None
            else self._repo_root / ".admissible" / "control_surface_sessions"
        )
        self._sample_trace_path = (
            Path(sample_trace_path)
            if sample_trace_path is not None
            else self._repo_root / DEFAULT_SAMPLE_TRACE_RELATIVE_PATH
        )
        self._session_file = self._session_dir / "session.json"
        self._session_loaded_from_disk = False
        self._session = self._new_session()

    @staticmethod
    def _new_session() -> ControlSession:
        return ControlSession(
            schema_version=CONTROL_SESSION_SCHEMA_VERSION,
            session_id=f"control_session_{uuid.uuid4().hex[:12]}",
            created_at=_now_iso(),
            autonomy_level=AutonomyLevel.L1_PROPOSE_ONLY.value,
            transcript=[],
            queue=[],
            human_decisions=[],
            run_envelopes={},
        )

    # -- persistence / raw session I/O --------------------------------

    @property
    def session_file(self) -> Path:
        """Path this controller persists its session JSON to after every mutation.

        Exposed so other local, offline tooling (e.g.
        admissible.runner.cursor_bridge) can load the same on-disk session a
        running Control Surface server is using, without duplicating the
        session_dir/repo_root default-resolution logic in __init__.
        """
        return self._session_file

    def session_dict(self) -> dict[str, Any]:
        """Canonical, round-trippable session state (used for export/import)."""
        return self._session.to_dict()

    def state_view(self) -> dict[str, Any]:
        """Session state plus derived, non-persisted UI fields."""
        view = self.session_dict()
        view["queue"] = [
            {
                **item.to_dict(),
                "available_actions": available_human_actions(item, self._session.autonomy_level),
            }
            for item in self._session.queue
        ]
        view["autonomy_levels"] = list(AUTONOMY_LEVEL_ORDER)
        view["autonomy_profiles"] = [
            AUTONOMY_PROFILES[level].to_dict() for level in AUTONOMY_LEVEL_ORDER
        ]
        view["mission_summary"] = _mission_summary(self._session)
        view["needs_attention"] = _needs_attention(self._session)
        view["session_file"] = str(self._session_file)
        view["session_loaded_from_disk"] = self._session_loaded_from_disk
        return view

    def _persist(self) -> None:
        self._session_dir.mkdir(parents=True, exist_ok=True)
        with self._session_file.open("w", encoding="utf-8") as f:
            json.dump(self.session_dict(), f, indent=2, sort_keys=True)
            f.write("\n")

    def reset_session(self) -> dict[str, Any]:
        self._session = self._new_session()
        self._persist()
        return self.state_view()

    def import_session(self, data: dict[str, Any]) -> dict[str, Any]:
        self._session = ControlSession.from_dict(data)
        self._persist()
        return self.state_view()

    # -- autonomy -------------------------------------------------------

    def set_autonomy(self, level: str) -> dict[str, Any]:
        if level not in _AUTONOMY_LEVEL_VALUES:
            raise ValueError(
                f"unknown autonomy level: {level!r}; expected one of {AUTONOMY_LEVEL_ORDER}"
            )
        previous = self._session.autonomy_level
        self._session.autonomy_level = level
        self._session.transcript.append(
            _transcript_entry(
                "autonomy_change",
                {
                    "previous_level": previous,
                    "new_level": level,
                    "note": (
                        "Autonomy changes default stopping points only; it never "
                        "overrides REFUSE, REQUIRE_HUMAN_APPROVAL, or REQUEST_MORE_EVIDENCE."
                    ),
                },
            )
        )
        self._persist()
        return self.state_view()

    # -- goal intake / plan / audit --------------------------------------

    def submit_goal(self, prompt: str) -> dict[str, Any]:
        intake = analyze_goal(prompt)
        plan = generate_plan_candidate(intake)
        audit = audit_plan(plan, intake)

        self._session.goal_intake = intake.to_dict()
        self._session.plan_candidate = plan.to_dict()
        self._session.plan_audit = audit.to_dict()

        self._session.transcript.append(_transcript_entry("user_prompt", {"prompt": prompt}))
        self._session.transcript.append(_transcript_entry("goal_intake", intake.to_dict()))
        self._session.transcript.append(_transcript_entry("plan_proposal", plan.to_dict()))
        self._session.transcript.append(_transcript_entry("plan_audit", audit.to_dict()))
        self._session.transcript.append(
            _transcript_entry("admissible_message", {"message": _admissible_message_for_audit(intake, audit)})
        )
        self._persist()
        return self.state_view()

    # -- queue loading ----------------------------------------------------

    def load_sample_session(self) -> dict[str, Any]:
        self._session = self._new_session()
        self.submit_goal(SAMPLE_SLITHER_PROMPT)
        self._load_queue_from_trace(self._sample_trace_path)
        self._session.transcript.append(
            _transcript_entry(
                "admissible_message",
                {
                    "message": (
                        f"Loaded sample Cursor/Admissible admitted-execution trace "
                        f"({len(self._session.queue)} action(s)) for the Slither demo."
                    )
                },
            )
        )
        self._persist()
        return self.state_view()

    def load_trace(self, path: str | Path | None = None) -> dict[str, Any]:
        self._load_queue_from_trace(Path(path) if path else self._sample_trace_path)
        self._session.transcript.append(
            _transcript_entry(
                "admissible_message",
                {
                    "message": (
                        f"Loaded {len(self._session.queue)} action(s) from trace "
                        f"{self._session.source_trace_path}."
                    )
                },
            )
        )
        self._persist()
        return self.state_view()

    def _load_queue_from_trace(self, path: Path) -> None:
        if path.is_file():
            trace = json.loads(path.read_text(encoding="utf-8"))
            self._session.source_trace_path = str(path)
        else:
            trace = self._build_fallback_trace()
            self._session.source_trace_path = "generated:builder-fixtures (no shell execution)"

        candidates = {c["action_id"]: c for c in trace.get("action_candidates") or [] if c.get("action_id")}
        decisions = {d["action_id"]: d for d in trace.get("decisions") or [] if d.get("action_id")}

        envelopes: dict[str, RunEnvelope] = {}
        queue: list[DecisionQueueItem] = []
        for action_id, candidate in candidates.items():
            decision = decisions.get(action_id, {})
            envelope = RunEnvelope(
                action_id=action_id,
                envelope_id=candidate.get("envelope_id") or decision.get("envelope_id"),
                decision_id=decision.get("decision_id"),
                candidate=candidate,
                decision=decision,
            )
            envelopes[action_id] = envelope
            queue.append(_build_queue_item(envelope))

        self._session.run_envelopes = envelopes
        self._session.queue = queue

    def _build_fallback_trace(self) -> dict[str, Any]:
        # In-process Python function call only -- no subprocess, no shell.
        from admissible.long_run_truth import build_truth_trace_from_raw_output_fixtures

        fixtures_dir = self._repo_root / DEFAULT_BUILDER_FALLBACK_FIXTURES_RELATIVE_DIR
        return build_truth_trace_from_raw_output_fixtures(
            fixtures_dir=str(fixtures_dir),
            repo_root=str(self._repo_root),
        )

    # -- human decisions ----------------------------------------------------

    def _find_queue_item(self, action_id: str) -> DecisionQueueItem | None:
        for item in self._session.queue:
            if item.action_id == action_id:
                return item
        return None

    def available_actions_for(self, action_id: str) -> list[str]:
        item = self._find_queue_item(action_id)
        if item is None:
            raise ValueError(f"unknown action_id: {action_id!r}")
        return available_human_actions(item, self._session.autonomy_level)

    def decide(self, action_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Record one human decision for one queue item.

        Never mutates `item.decision` (the rules-only Admissible label).
        Raises ValueError (including `AdmittedExecutionValidationError`,
        a ValueError subclass) if the decision is not permitted or, for
        `attest_executed`, if the attestation fails admitted-execution
        validation.
        """
        item = self._find_queue_item(action_id)
        if item is None:
            raise ValueError(f"unknown action_id: {action_id!r}")

        decision_type = body.get("decision_type")
        if decision_type not in DECISION_TYPES:
            raise ValueError(f"unknown decision_type: {decision_type!r}; expected one of {sorted(DECISION_TYPES)}")

        allowed = available_human_actions(item, self._session.autonomy_level)
        if decision_type not in allowed:
            raise ValueError(
                f"{decision_type!r} is not permitted for action {action_id!r} "
                f"(admissible decision={item.decision!r}, autonomy={self._session.autonomy_level!r}); "
                f"allowed: {allowed}"
            )

        scope = body.get("scope") or None
        rationale = body.get("rationale") or ""

        if decision_type == DECISION_TYPE_APPROVE and item.decision == "REQUIRE_HUMAN_APPROVAL" and not scope:
            raise ValueError("approval for a REQUIRE_HUMAN_APPROVAL action must include an explicit scope")
        if decision_type == DECISION_TYPE_LIMIT_SCOPE and not scope:
            raise ValueError("limit_scope decisions must include an explicit scope")

        envelope = self._session.run_envelopes.get(action_id)
        record = HumanDecisionRecord(
            record_id=f"human_decision_{uuid.uuid4().hex[:12]}",
            action_id=action_id,
            decision_type=decision_type,
            actor=HUMAN_DECISION_ACTOR,
            timestamp=_now_iso(),
            scope=scope,
            rationale=rationale,
            linked_decision_id=envelope.decision_id if envelope else None,
            linked_envelope_id=envelope.envelope_id if envelope else None,
        )

        if decision_type == DECISION_TYPE_ATTEST_EXECUTED:
            if envelope is None:
                raise ValueError(f"no run envelope loaded for action_id {action_id!r}; cannot attest execution")
            exec_record = {
                "action_id": action_id,
                "execution_status": EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
                "execution_basis": {
                    "decision_id": envelope.decision_id,
                    "envelope_id": envelope.envelope_id,
                },
                "execution_actor": EXECUTION_ACTOR_HUMAN_OPERATOR,
                "execution_evidence": {
                    "notes": rationale,
                    "verification": body.get("verification") or "",
                },
                "execution_scope": EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY,
                "execution_timestamp": record.timestamp,
            }
            # Re-uses the same validator as the fixture-based Admitted
            # Execution Protocol; raises AdmittedExecutionValidationError
            # (a ValueError) on any violation. Never weakened here.
            validate_executed_after_admission_record(exec_record, self._trace_view())
            item.execution_status = EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION
            item.execution_record = exec_record
            envelope.candidate["execution_status"] = EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION
            envelope.candidate["execution_record"] = exec_record
            item.lifecycle_status = LIFECYCLE_CLOSED
        elif decision_type in (DECISION_TYPE_APPROVE, DECISION_TYPE_LIMIT_SCOPE, DECISION_TYPE_REFUSE):
            _apply_human_decision_lifecycle(
                self._session,
                item=item,
                envelope=envelope,
                record=record,
                decision_type=decision_type,
            )
        # DECISION_TYPE_REQUEST_EVIDENCE intentionally does not transition
        # lifecycle: it records that the human asked for more evidence from
        # the agent. Actual evidence supply and cumulative re-evaluation
        # happen via provide_evidence() / POST .../evidence.

        item.human_decision_ids.append(record.record_id)
        self._session.human_decisions.append(record)
        self._session.transcript.append(_transcript_entry("human_decision", record.to_dict()))
        self._persist()
        return self.state_view()

    def _trace_view(self) -> dict[str, Any]:
        return {
            "action_candidates": [env.candidate for env in self._session.run_envelopes.values()],
            "decisions": [env.decision for env in self._session.run_envelopes.values()],
        }

    # -- supervised run loop ----------------------------------------------

    def generate_next_instruction_packet(self) -> dict[str, Any]:
        """Generate and store the next "instruction for Cursor" packet.

        Deterministic and offline: derived from goal intake, plan audit,
        autonomy level, and the current queue. Does not call any provider
        and does not execute anything.
        """
        run_loop = self._session.run_loop
        turn_number = run_loop.current_turn + 1
        packet = generate_instruction_packet(
            turn_number=turn_number,
            autonomy_level=self._session.autonomy_level,
            goal_intake=self._session.goal_intake,
            plan_audit=self._session.plan_audit,
            queue=[item.to_dict() for item in self._session.queue],
            resolved_plan_gates=[g.to_dict() for g in run_loop.resolved_plan_gates],
        )
        run_loop.current_turn = turn_number
        run_loop.instruction_packets.append(packet)
        run_loop.turns.append(
            RunTurn(
                turn_number=turn_number,
                created_at=packet.created_at,
                instruction_packet_id=packet.packet_id,
                agent_response_record_id=None,
                summary=f"Generated instruction packet for turn {turn_number}.",
            )
        )
        self._session.transcript.append(_transcript_entry("instruction_packet_generated", packet.to_dict()))
        self._persist()
        return self.state_view()

    def record_bridge_ingest_blocked(
        self,
        reason: str,
        *,
        workspace_path: str,
        response_sha256: str | None = None,
        turn_number: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Record a blocked bridge response-ingest attempt in the session transcript.

        Does not append queue items or mutate any admission decision.
        """
        payload: dict[str, Any] = {
            "reason": reason,
            "workspace_path": workspace_path,
            "response_sha256": response_sha256,
            "turn_number": turn_number,
            "note": "Bridge ingest blocked before candidate extraction; no queue items were created.",
        }
        if detail:
            payload["detail"] = detail
        self._session.transcript.append(_transcript_entry("bridge_ingest_blocked", payload))
        self._persist()

    def ingest_agent_response(self, raw_text: str) -> dict[str, Any]:
        """Ingest one pasted, unverified agent/Cursor response.

        Extracts action candidates with the existing offline builder and
        evaluates them with the existing rules-only evaluator; never calls
        a provider and never executes anything. Appends new queue items;
        never rewrites an existing one.
        """
        if not isinstance(raw_text, str) or not raw_text.strip():
            raise ValueError("raw agent response text must be a non-empty string")

        run_loop = self._session.run_loop
        turn_number = run_loop.current_turn or 1
        long_run_prompt = (self._session.goal_intake or {}).get("prompt")

        built = build_candidates_from_agent_response(
            raw_text,
            turn_number=turn_number,
            long_run_prompt=long_run_prompt,
            source_metadata={"workspace_context": "local admissible control surface session"},
        )

        new_action_ids: list[str] = []
        for entry in built:
            run_env = RunEnvelope(
                action_id=entry["action_id"],
                envelope_id=entry["envelope_id"],
                decision_id=entry["decision_id"],
                candidate=entry["candidate"],
                decision=entry["decision"],
                envelope=entry["envelope"],
            )
            self._session.run_envelopes[run_env.action_id] = run_env
            self._session.queue.append(_build_queue_item(run_env))
            new_action_ids.append(run_env.action_id)

        record = AgentResponseRecord(
            record_id=f"agent_response_{uuid.uuid4().hex[:12]}",
            turn_number=turn_number,
            created_at=_now_iso(),
            raw_text=raw_text,
            source_trust="unverified_agent_output",
            actor="external_frontier_agent",
            action_ids=new_action_ids,
            builder_version=(built[0]["candidate"].get("builder_version") if built else None),
        )
        run_loop.response_records.append(record)
        if run_loop.turns and run_loop.turns[-1].agent_response_record_id is None:
            run_loop.turns[-1].agent_response_record_id = record.record_id

        self._session.transcript.append(
            _transcript_entry(
                "agent_response_ingested",
                {
                    "record_id": record.record_id,
                    "turn_number": turn_number,
                    "action_ids": new_action_ids,
                    "action_count": len(new_action_ids),
                    "note": (
                        "Raw response is unverified agent output; action candidates were "
                        "extracted and evaluated by the existing offline builder/evaluator, "
                        "not executed."
                    ),
                },
            )
        )
        self._persist()
        return self.state_view()

    def provide_evidence(self, action_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Record one EvidenceRecord for a REQUEST_MORE_EVIDENCE action.

        Never mutates the original admission decision. When the action's
        full schema envelope is available (ingested via the paste/ingest
        path), re-evaluates with the unmodified rules-only evaluator and
        records the result as a separate `SupersedingAdmissionDecision`,
        updating only the queue item's *displayed* effective decision.
        Otherwise (e.g. actions loaded from a static trace file), marks
        the action `evidence_supplied_pending_reevaluation` and leaves the
        decision untouched.
        """
        item = self._find_queue_item(action_id)
        if item is None:
            raise ValueError(f"unknown action_id: {action_id!r}")
        if item.decision != "REQUEST_MORE_EVIDENCE":
            raise ValueError(
                f"evidence can only be supplied for a REQUEST_MORE_EVIDENCE action "
                f"(action {action_id!r} currently has decision {item.decision!r})"
            )

        evidence_type = str(body.get("evidence_type") or "").strip()
        evidence_text = str(body.get("evidence_text") or "").strip()
        if not evidence_type or not evidence_text:
            raise ValueError("evidence_type and evidence_text are required")
        file_path_or_note = body.get("file_path_or_note") or None
        rationale = body.get("rationale") or ""

        envelope = self._session.run_envelopes.get(action_id)
        record = EvidenceRecord(
            record_id=f"evidence_{uuid.uuid4().hex[:12]}",
            action_id=action_id,
            decision_id=envelope.decision_id if envelope else None,
            envelope_id=envelope.envelope_id if envelope else None,
            actor=HUMAN_DECISION_ACTOR,
            timestamp=_now_iso(),
            evidence_type=evidence_type,
            evidence_text=evidence_text,
            file_path_or_note=file_path_or_note,
            rationale=rationale,
        )
        self._session.run_loop.evidence_records.append(record)

        action_evidence_items = [
            (r.evidence_type, r.evidence_text)
            for r in self._session.run_loop.evidence_records
            if r.action_id == action_id
        ]

        new_decision = None
        if envelope is not None and envelope.envelope is not None:
            new_decision = reevaluate_envelope_with_evidence(
                envelope.envelope,
                evidence_items=action_evidence_items,
            )

        if new_decision is not None:
            superseding = SupersedingAdmissionDecision(
                record_id=f"superseding_{uuid.uuid4().hex[:12]}",
                action_id=action_id,
                previous_decision_id=envelope.decision_id,
                new_decision=new_decision,
                based_on_evidence_record_id=record.record_id,
                created_at=_now_iso(),
            )
            self._session.run_loop.superseding_decisions.append(superseding)
            envelope.superseding_decisions.append(new_decision)

            item.decision = new_decision["decision"]
            item.operational_admissibility_action = new_decision.get("operational_admissibility_action")
            item.risk_level = new_decision.get("risk_level")
            item.required_approval = new_decision.get("required_approval")
            item.missing_evidence = list(new_decision.get("missing_evidence") or [])
            item.attestation_eligible = is_local_allow_without_missing_evidence(new_decision, envelope.candidate)
            item.lifecycle_status = lifecycle_status_after_evidence_reevaluation(item.decision)
        else:
            item.lifecycle_status = LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION

        self._session.transcript.append(
            _transcript_entry(
                "evidence_provided",
                {
                    **record.to_dict(),
                    "reevaluated": new_decision is not None,
                    "new_decision": new_decision.get("decision") if new_decision else None,
                },
            )
        )
        self._persist()
        return self.state_view()


def load_persisted_session(
    controller: ControlSurfaceController,
    *,
    fresh_session: bool = False,
) -> bool:
    """Load ``session.json`` from ``controller.session_file`` when present.

    ``ControlSurfaceController.__init__`` always starts from a fresh in-memory
    session; callers that want CLI/HTTP resume parity invoke this after
    construction. Returns ``True`` when a persisted session was loaded,
    ``False`` when starting from the in-memory fresh session (no file, or
    ``fresh_session=True``). Raises ``InvalidSessionFileError`` when the file
    exists but cannot be parsed or imported — never silently replaces it with
    an empty session.
    """
    if fresh_session:
        controller._session_loaded_from_disk = False
        return False

    session_file = controller.session_file
    if not session_file.is_file():
        controller._session_loaded_from_disk = False
        return False

    try:
        data = json.loads(session_file.read_text(encoding="utf-8"))
        controller.import_session(data)
        controller._session_loaded_from_disk = True
        return True
    except Exception as exc:  # noqa: BLE001 - convert any corrupt-file shape into one clear error
        raise InvalidSessionFileError(
            f"invalid session file at {session_file}: {exc}",
            detail={"session_file": str(session_file)},
        ) from exc


__all__ = [
    "AUTONOMY_LEVEL_ORDER",
    "AUTONOMY_PROFILES",
    "AutonomyLevel",
    "AutonomyProfile",
    "CONTROL_SESSION_SCHEMA_VERSION",
    "ControlSession",
    "ControlSurfaceController",
    "InvalidSessionFileError",
    "DECISION_TYPES",
    "DecisionQueueItem",
    "HumanDecisionRecord",
    "RunEnvelope",
    "SAMPLE_SLITHER_PROMPT",
    "AdmittedExecutionValidationError",
    "available_human_actions",
    "LIFECYCLE_ADMITTED_NOT_EXECUTED",
    "LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION",
    "LIFECYCLE_CLOSED",
    "LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION",
    "LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED",
    "LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION",
    "LIFECYCLE_LIMITED_SCOPE_SELECTED",
    "LIFECYCLE_NEEDS_HUMAN_INPUT",
    "LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION",
    "LIFECYCLE_REFUSED_CLOSED",
    "LIFECYCLE_RESOLVED_GATE",
    "DerivedLifecycleResolution",
    "ResolvedPlanGateRecord",
    "load_persisted_session",
    "queue_item_needs_attention",
]
