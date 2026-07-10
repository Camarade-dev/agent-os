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
- Does not execute shell commands and does not implement a general automatic
  executor. A narrow bounded local file executor (structured list/read/write
  only) may run for already-admitted actions via
  ``execute_bounded_local()``; "Attest executed" only *records* that a
  human/external actor executed an already-admitted local action.
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
import re
import threading
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
    EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
    AdmittedExecutionValidationError,
    is_local_allow_without_missing_evidence,
    validate_executed_after_admission_record,
)
from admissible.execution.bounded_local_executor import (
    ALLOWED_BOUNDED_OPERATIONS,
    DIAG_ALREADY_EXECUTED,
    DIAG_FORBIDDEN_OPERATION_CATEGORY,
    DIAG_NO_WORKSPACE_CONFIGURED,
    DIAG_UNSUPPORTED_OPERATION,
    BoundedExecutionError,
    assess_bounded_execution_eligibility,
    execute_bounded_local_action,
    extract_structured_operations,
    validate_relative_path_inside_workspace,
    validate_workspace_path,
)
from admissible.execution.bounded_local_verification import (
    BoundedVerificationError,
    VerificationRequest,
    run_bounded_verification,
    validate_verification_request,
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
from admissible.governed_run import (
    active_blocking_action_ids,
    build_agent_response_extraction_report,
    build_proposal_coverage_report,
    canonical_operation_fingerprint,
    canonical_operation_identity,
    canonicalize_session_export_payload,
    classify_optional_write_paths,
    current_file_sha256,
    DEFAULT_OUTCOME_IN_PROGRESS,
    extract_completion_candidate,
    latest_file_hashes,
    migrate_session_projection_fields,
    normalize_workspace_relative_path,
    repair_inconsistent_executable_lifecycle,
    ResponseExtractionFailed,
    sha256_text,
    validate_coherent_batch_limits,
)
from admissible.run_loop import (
    LIFECYCLE_ADMITTED_NOT_EXECUTED,
    LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION,
    LIFECYCLE_CLOSED,
    LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
    LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
    LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
    LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION,
    LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING,
    LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE,
    EVIDENCE_SOURCES,
    LIFECYCLE_LIMITED_SCOPE_SELECTED,
    LIFECYCLE_NEEDS_HUMAN_INPUT,
    LIFECYCLE_NO_LONGER_NEEDS_ATTENTION,
    LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION,
    LIFECYCLE_REFUSED_CLOSED,
    LIFECYCLE_RESOLVED_GATE,
    LIFECYCLE_SUPERSEDED,
    AgentResponseRecord,
    DerivedLifecycleResolution,
    EvidenceRecord,
    ResolvedPlanGateRecord,
    RunLoopState,
    RunTimeline,
    RunTurn,
    SupersedingAdmissionDecision,
    build_candidates_from_agent_response,
    build_continuation_instruction,
    build_run_timeline,
    default_lifecycle_status,
    derive_evidence_attention_state,
    generate_instruction_packet,
    initial_lifecycle_status_for_queue_item,
    normalize_evidence_satisfies,
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

# Machine-readable reason surfaced (in an error `detail`/`state_view` field)
# when an instruction-producing or response-ingesting action is attempted
# before a goal has been submitted. The HTTP layer forwards it verbatim so
# the UI can show one clear "submit a goal first" message.
GOAL_REQUIRED_REASON = "goal_required"
NO_INSTRUCTION_REASON = "no_instruction"
SESSION_NOT_EMPTY_REASON = "session_not_empty"

# Display-only product/run phases and the single next action each implies.
# These drive goal-first UI gating only; they never gate an admission
# decision (that logic stays in the rules-only evaluator and the gates).
RUN_PHASE_NEEDS_GOAL = "needs_goal"
RUN_PHASE_READY_TO_INSTRUCT = "ready_to_instruct"
RUN_PHASE_AWAITING_AGENT_RESPONSE = "awaiting_agent_response"
RUN_PHASE_REVIEWING_ACTIONS = "reviewing_actions"

NEXT_ACTION_SUBMIT_GOAL = "submit_goal"
NEXT_ACTION_WRITE_INSTRUCTION = "write_instruction"
NEXT_ACTION_INGEST_RESPONSE = "ingest_agent_response"
NEXT_ACTION_REVIEW_ACTIONS = "review_actions"


class InvalidSessionFileError(ValueError):
    """Raised when a persisted Control Surface session file cannot be loaded."""

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail: dict[str, Any] = dict(detail) if detail else {}


class NoGoalSubmittedError(ValueError):
    """Raised when an instruction packet is requested before a goal exists.

    A ValueError subclass so the HTTP adapter's existing ``except ValueError``
    branch turns it into a 400 with a machine-readable ``reason`` (``goal_required``)
    in the JSON body, and so bridge/CLI callers surface it unchanged.
    """

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail: dict[str, Any] = dict(detail) if detail else {}


class SessionNotEmptyError(ValueError):
    """Raised when a sample session load would replace a non-empty session.

    Callers must pass ``force=True`` (or HTTP ``force`` / ``confirmed``) after
    explicit user confirmation. A ValueError subclass so the HTTP adapter's
    existing ``except ValueError`` branch returns 400 with ``session_not_empty``.
    """

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
    "executed_by_bounded_executor",
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
    # Structured evidence satisfaction (slice ADMISSIBLE_EVIDENCE_007).
    satisfied_evidence_fields: list[str] = field(default_factory=list)
    non_evidence_blockers: list[str] = field(default_factory=list)
    original_missing_evidence: list[str] = field(default_factory=list)
    evidence_attention_summary: str | None = None
    latest_evidence_summary: str | None = None
    # Display-only run-loop lifecycle tracking (see admissible.run_loop).
    # Never a substitute for `decision`; it tracks what has happened to a
    # gated action across the supervised loop (evidence supplied, approval
    # supplied, scope limited, ready to continue, closed).
    lifecycle_status: str = LIFECYCLE_NEEDS_HUMAN_INPUT
    # Durable operation/gate hygiene (ADMISSIBLE_RUN_038).  ``decision`` stays
    # immutable policy output; these fields only record queue/execution state.
    operation_outcome: str | None = None
    operation_fingerprints: list[str] = field(default_factory=list)
    gate_identity: str | None = None
    closes_gate_ids: list[str] = field(default_factory=list)
    source_action_id: str | None = None
    semantic_gate_type: str | None = None
    gate_target: str | None = None
    suppressed_pseudo_gate: bool = False
    suppressed_non_action: bool = False
    merged_into_action_id: str | None = None
    superseded_by_action_id: str | None = None
    supersession_reason: str | None = None
    superseded_at: str | None = None
    safe_overwrite_review_required: bool = False

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
        lifecycle_status=initial_lifecycle_status_for_queue_item(
            decision_label, candidate=candidate
        ),
    )


_GATE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+\.(?:html?|css|js|mjs|json|md|txt|py))(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)


def _gate_target_for_envelope(envelope: RunEnvelope) -> str | None:
    candidate = envelope.candidate
    for key in ("gate_target", "target", "path"):
        value = candidate.get(key)
        if isinstance(value, str) and value.strip():
            try:
                return normalize_workspace_relative_path(value)
            except ValueError:
                return value.strip()
    text = "\n".join(
        str(candidate.get(key) or "")
        for key in ("operation_text", "tool_or_command", "raw_output")
    )
    match = _GATE_PATH_RE.search(text)
    return normalize_workspace_relative_path(match.group(1)) if match else None


def _canonical_gate_identity(envelope: RunEnvelope) -> tuple[str, str | None]:
    closes = sorted(_closes_gates_for_item(envelope, _build_queue_item(envelope)))
    target = _gate_target_for_envelope(envelope)
    subject = str(envelope.candidate.get("tool_or_command") or "decision").strip().lower()
    subject = re.sub(r"\s+", " ", subject)
    semantic = str(envelope.candidate.get("action_type") or "decision_only")
    identity_source = json.dumps(
        {
            "closes_gate_ids": closes,
            "semantic_gate_type": semantic,
            "target": target,
            "decision_subject": subject if not target and not closes else None,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return f"gate_{sha256_text(identity_source)[:20]}", target


def _gate_choice_explicit_in_user_goal(
    envelope: RunEnvelope, goal_text: str
) -> bool:
    """Conservative exact-token check for a choice already made by the user."""

    operation_text = str(envelope.candidate.get("operation_text") or "")
    match = re.search(
        r"proposal:\s*(.*?)(?:human\s+decision\s+required:|$)",
        operation_text,
        re.IGNORECASE,
    )
    if not match:
        return False
    proposal_text = match.group(1).lower()
    if "approve" in proposal_text or re.search(r"\b(?:write|create|overwrite)\b", proposal_text):
        return False
    stopwords = {
        "approve",
        "bounded",
        "choose",
        "local",
        "proposal",
        "the",
        "this",
        "use",
        "write",
        "with",
    }
    tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", proposal_text)
        if len(token) >= 4 and token not in stopwords
    }
    goal_tokens = set(re.findall(r"[a-z0-9]+", goal_text.lower()))
    return len(tokens) >= 2 and tokens.issubset(goal_tokens)


def _is_pseudo_gate_for_concrete_allow(
    envelope: RunEnvelope,
    *,
    concrete_allow_paths: set[str],
    response_restates_local_write_approval: bool = False,
    response_text: str = "",
) -> bool:
    """Whether model prose merely restates approval for an ALLOW operation."""

    if envelope.candidate.get("action_type") != "plan_gate_resolution":
        return False
    closes = _closes_gates_for_item(envelope, _build_queue_item(envelope))
    if closes:
        return False
    text = "\n".join(
        str(envelope.candidate.get(key) or "")
        for key in ("operation_text", "tool_or_command", "raw_output")
    ).lower()
    combined = f"{response_text}\n{text}".lower()
    if concrete_allow_paths and len(concrete_allow_paths) >= 2:
        aggregate_patterns = (
            r"approve\s+bounded\s+execution\s+of\s+the\s+(?:\d+|four|three|two|\w+)\s+structured\s+write",
            r"approve\s+bounded\s+execution\s+of\s+the\s+(?:\d+|four|three|two|\w+)\s+structured\s+write_file",
        )
        if any(re.search(pattern, combined) for pattern in aggregate_patterns):
            return True
        if "approve" in combined and (
            "operations below" in combined
            or "operations above" in combined
            or "write_file operations below" in combined
        ):
            return True
    if response_restates_local_write_approval and re.search(
        r"^(?:action_gate_|verdict\s+class:|closes\s+gates?:|side\s+effects?\s+if\s+approved:|proposal:|human\s+decision\s+required:)",
        str(envelope.candidate.get("operation_text") or "").strip(),
        re.IGNORECASE,
    ):
        return True
    if "human decision required" not in text and "approve" not in text:
        return False
    target = _gate_target_for_envelope(envelope)
    if target and target in concrete_allow_paths:
        return True
    return len(concrete_allow_paths) == 1 and any(
        phrase in text
        for phrase in ("this local write", "the local write", "approve this write", "approve the write")
    )


def _supersede_covered_gates(
    session: "ControlSession",
    *,
    executed_action_id: str,
    executed_paths: set[str],
) -> int:
    """Close stale gate rows after their concrete target has executed.

    This is queue hygiene only.  It creates no HumanDecisionRecord and grants
    no side-effect authority.
    """

    if not executed_paths:
        return 0
    count = 0
    now = _now_iso()
    for item in session.queue:
        if item.action_type != "plan_gate_resolution" or item.superseded_at:
            continue
        if item.lifecycle_status in (
            LIFECYCLE_RESOLVED_GATE,
            LIFECYCLE_REFUSED_CLOSED,
            LIFECYCLE_SUPERSEDED,
        ):
            continue
        if not item.gate_target or item.gate_target not in executed_paths:
            continue
        item.lifecycle_status = LIFECYCLE_SUPERSEDED
        item.superseded_by_action_id = executed_action_id
        item.supersession_reason = "target_operation_already_executed"
        item.superseded_at = now
        session.governance_records.append(
            {
                "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                "event_type": "gate_superseded",
                "action_id": item.action_id,
                "gate_identity": item.gate_identity,
                "superseded_by_action_id": executed_action_id,
                "supersession_reason": item.supersession_reason,
                "superseded_at": now,
            }
        )
        count += 1
    return count


def _repair_stale_aggregate_pseudo_gates(session: "ControlSession") -> int:
    """Suppress persisted aggregate approval pseudo-gates on session load."""

    sibling_paths: set[str] = set()
    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        if item.decision != "ALLOW" or not envelope:
            continue
        for operation in envelope.candidate.get("structured_operations") or []:
            try:
                sibling_paths.add(
                    normalize_workspace_relative_path(str(operation.get("path") or "."))
                )
            except ValueError:
                continue
    if len(sibling_paths) < 2:
        return 0
    repaired = 0
    now = _now_iso()
    for item in session.queue:
        if item.action_type != "plan_gate_resolution" or item.suppressed_pseudo_gate:
            continue
        if item.superseded_at:
            continue
        text = "\n".join(
            str(getattr(item, field, "") or "")
            for field in ("tool_or_command", "action_type")
        ).lower()
        envelope = session.run_envelopes.get(item.action_id)
        if envelope:
            text = f"{text}\n{envelope.candidate.get('operation_text') or ''}".lower()
        if not re.search(
            r"approve\s+bounded\s+execution\s+of\s+the\s+(?:\d+|four|three|two|\w+)\s+structured\s+write",
            text,
        ):
            continue
        item.suppressed_pseudo_gate = True
        item.lifecycle_status = LIFECYCLE_SUPERSEDED
        item.supersession_reason = "retrospective_aggregate_pseudo_gate_suppressed"
        item.superseded_at = now
        sibling_ids = [
            row.action_id
            for row in session.queue
            if row.decision == "ALLOW"
            and row.action_id != item.action_id
            and not row.superseded_at
        ]
        session.governance_records.append(
            {
                "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                "event_type": "retrospective_pseudo_gate_suppressed",
                "action_id": item.action_id,
                "reason": "aggregate_batch_approval_prose_with_concrete_sibling_operations",
                "sibling_action_ids": sibling_ids,
                "timestamp": now,
            }
        )
        repaired += 1
    return repaired


def _is_negated_non_action_source_text(text: str) -> bool:
    from admissible.long_run_envelope_builder import (
        CLI_011_NEGATED_CONSTRAINT_SENTENCE,
        _is_negated_segment,
        _should_suppress_prose_candidate,
    )

    normalized = re.sub(r"\s+", " ", (text or "")).strip()
    if not normalized:
        return False
    if normalized.rstrip(".") == CLI_011_NEGATED_CONSTRAINT_SENTENCE.rstrip("."):
        return True
    if not _is_negated_segment(normalized):
        return False
    suppress, _ = _should_suppress_prose_candidate(
        normalized,
        action_type="git_push" if "git push" in normalized.lower() else "unknown",
        long_run_prompt=None,
        has_structured_siblings=False,
    )
    return suppress


def _repair_stale_negated_non_actions(session: "ControlSession") -> int:
    """Suppress persisted prose candidates that are negative safety constraints."""

    sibling_paths: set[str] = set()
    sibling_action_ids: list[str] = []
    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        if item.decision != "ALLOW" or not envelope:
            continue
        for operation in envelope.candidate.get("structured_operations") or []:
            try:
                sibling_paths.add(
                    normalize_workspace_relative_path(str(operation.get("path") or "."))
                )
            except ValueError:
                continue
        sibling_action_ids.append(item.action_id)
    repaired = 0
    now = _now_iso()
    for item in session.queue:
        if item.suppressed_non_action or item.suppressed_pseudo_gate or item.superseded_at:
            continue
        text = "\n".join(
            str(getattr(item, field, "") or "")
            for field in ("tool_or_command", "action_type")
        )
        envelope = session.run_envelopes.get(item.action_id)
        if envelope:
            text = f"{text}\n{envelope.candidate.get('operation_text') or ''}"
        if not _is_negated_non_action_source_text(text):
            continue
        item.suppressed_non_action = True
        item.lifecycle_status = LIFECYCLE_SUPERSEDED
        item.supersession_reason = "retrospective_negated_non_action_suppressed"
        item.superseded_at = now
        session.governance_records.append(
            {
                "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                "event_type": "retrospective_non_action_suppressed",
                "action_id": item.action_id,
                "reason": "negated_constraint_prose_misclassified_as_side_effect",
                "source_text": (item.tool_or_command or text)[:240],
                "sibling_action_ids": list(sibling_action_ids),
                "sibling_structured_paths": sorted(sibling_paths),
                "timestamp": now,
            }
        )
        repaired += 1
    return repaired


def _operation_record(
    *,
    action_id: str,
    operation: dict[str, Any],
    outcome: str,
    fingerprint: str,
    identity: str,
    original_execution_record_id: str | None = None,
    current_sha256: str | None = None,
    overwrite: bool = False,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    content = operation.get("content")
    return {
        "record_id": f"operation_{uuid.uuid4().hex[:12]}",
        "action_id": action_id,
        "operation": str(operation.get("operation") or ""),
        "path": normalize_workspace_relative_path(str(operation.get("path") or ".")),
        "canonical_identity": identity,
        "fingerprint": fingerprint,
        "outcome": outcome,
        "proposed_sha256": sha256_text(content) if isinstance(content, str) else None,
        "current_sha256_before": current_sha256,
        "result_sha256": None,
        "original_execution_record_id": original_execution_record_id,
        "overwrite": overwrite,
        "timestamp": _now_iso(),
        "detail": dict(detail or {}),
    }


def _executed_record_for_fingerprint(
    session: "ControlSession", fingerprint: str
) -> dict[str, Any] | None:
    for record in session.operation_records:
        if record.get("fingerprint") != fingerprint:
            continue
        if record.get("outcome") in ("executed_mutation", "executed_read", "executed_list"):
            return record
    return None


def _latest_mutation_for_path(
    session: "ControlSession", path: str
) -> dict[str, Any] | None:
    for record in reversed(session.operation_records):
        if record.get("path") == path and record.get("outcome") == "executed_mutation":
            return record
    return None


def _action_has_human_approval(session: "ControlSession", action_id: str) -> bool:
    return any(
        record.action_id == action_id and record.decision_type == DECISION_TYPE_APPROVE
        for record in session.human_decisions
    )


def _preclassify_noop_operations(
    session: "ControlSession",
    *,
    action_id: str,
    operations: list[dict[str, Any]],
    workspace_path: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (new noop audit records, operations that still need execution)."""

    workspace = validate_workspace_path(workspace_path) if workspace_path else None
    records: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for operation in operations:
        try:
            rel_path = normalize_workspace_relative_path(
                str(operation.get("path") or ".")
            )
        except ValueError as exc:
            raise BoundedExecutionError(
                str(exc),
                diagnostic="path_outside_workspace",
                detail={"path": str(operation.get("path") or ".")},
            ) from exc
        target = (
            validate_relative_path_inside_workspace(workspace, rel_path) if workspace else None
        )
        observed_sha = current_file_sha256(target) if target and target.is_file() else None
        identity = canonical_operation_identity(operation, observed_sha256=observed_sha)
        fingerprint = canonical_operation_fingerprint(operation, observed_sha256=observed_sha)
        already_for_action = next(
            (
                record
                for record in session.operation_records
                if record.get("action_id") == action_id
                and record.get("fingerprint") == fingerprint
                and record.get("outcome") in ("duplicate_noop", "already_satisfied_noop")
            ),
            None,
        )
        if already_for_action:
            records.append(already_for_action)
            continue
        original = _executed_record_for_fingerprint(session, fingerprint)
        if original is not None:
            records.append(
                _operation_record(
                    action_id=action_id,
                    operation=operation,
                    outcome="duplicate_noop",
                    fingerprint=fingerprint,
                    identity=identity,
                    original_execution_record_id=original.get("record_id"),
                    current_sha256=observed_sha,
                    detail={"reason": "canonical_operation_already_executed"},
                )
            )
            continue
        if str(operation.get("operation") or "") == "write_file":
            proposed_sha = sha256_text(str(operation.get("content") or ""))
            if observed_sha and proposed_sha == observed_sha:
                records.append(
                    _operation_record(
                        action_id=action_id,
                        operation=operation,
                        outcome="already_satisfied_noop",
                        fingerprint=fingerprint,
                        identity=identity,
                        current_sha256=observed_sha,
                        detail={"reason": "proposed_sha_matches_current_file"},
                    )
                )
                continue
        pending.append(operation)
    return records, pending


def _safe_overwrite_review_required(
    session: "ControlSession",
    *,
    operation: dict[str, Any],
    workspace_path: str | None,
) -> bool:
    if not workspace_path or operation.get("operation") != "write_file":
        return False
    workspace = validate_workspace_path(workspace_path)
    rel_path = normalize_workspace_relative_path(str(operation.get("path") or "."))
    target = validate_relative_path_inside_workspace(workspace, rel_path)
    current_sha = current_file_sha256(target)
    if not current_sha:
        return False
    proposed_sha = sha256_text(str(operation.get("content") or ""))
    if proposed_sha == current_sha:
        return False
    sensitive_name = Path(rel_path).name.lower()
    if (
        sensitive_name.startswith(".env")
        or any(token in sensitive_name for token in ("secret", "credential", "token", "password"))
        or Path(rel_path).suffix.lower() in (".exe", ".cmd", ".bat", ".ps1", ".sh")
    ):
        return True
    # The operation was extracted under this immutable submitted goal.  An
    # absent goal means scope cannot be established; a present goal plus the
    # same-run file/sha lineage below is the bounded direct-goal relationship.
    if not str((session.goal_intake or {}).get("prompt") or "").strip():
        return True
    latest = _latest_mutation_for_path(session, rel_path)
    return not latest or latest.get("result_sha256") != current_sha


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
        LIFECYCLE_SUPERSEDED,
    ):
        return []
    if item.superseded_at or item.suppressed_pseudo_gate or item.suppressed_non_action:
        return []
    if item.safe_overwrite_review_required and not item.human_decision_ids:
        return [DECISION_TYPE_APPROVE, DECISION_TYPE_REFUSE]
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
        already_executed = item.execution_status in (
            EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
            EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
        )
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
    bounded_executor_workspace: str | None = None
    run_loop: RunLoopState = field(default_factory=RunLoopState)
    is_sample_session: bool = False
    high_autonomy_run: dict[str, Any] | None = None
    operation_records: list[dict[str, Any]] = field(default_factory=list)
    governance_records: list[dict[str, Any]] = field(default_factory=list)

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
            "bounded_executor_workspace": self.bounded_executor_workspace,
            "run_loop": self.run_loop.to_dict(),
            "is_sample_session": self.is_sample_session,
            "high_autonomy_run": dict(self.high_autonomy_run) if self.high_autonomy_run else None,
            "operation_records": [dict(record) for record in self.operation_records],
            "governance_records": [dict(record) for record in self.governance_records],
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
            bounded_executor_workspace=data.get("bounded_executor_workspace"),
            run_loop=RunLoopState.from_dict(data.get("run_loop") or {}),
            is_sample_session=bool(data.get("is_sample_session", False)),
            high_autonomy_run=data.get("high_autonomy_run"),
            operation_records=[dict(record) for record in data.get("operation_records") or []],
            governance_records=[dict(record) for record in data.get("governance_records") or []],
        )


def _bounded_execution_operation_fields(operations: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Derive display paths and operation kinds from structured operations."""
    target_paths: list[str] = []
    operation_types: list[str] = []
    for operation in operations:
        op_name = str(operation.get("operation") or "").strip()
        if op_name:
            operation_types.append(op_name)
        path = str(operation.get("path") or "").strip()
        if op_name in ("write_file", "read_file") and path:
            target_paths.append(path)
    return target_paths, operation_types


def _bounded_execution_view(
    item: DecisionQueueItem,
    envelope: RunEnvelope | None,
    *,
    body: dict[str, Any] | None = None,
    workspace_path: str | None = None,
) -> dict[str, Any]:
    """Display-only bounded executor eligibility for one queue item."""
    assessment = assess_bounded_execution_eligibility(item=item, envelope=envelope, body=body)
    operations = list(assessment.get("operations") or [])
    target_paths, operation_types = _bounded_execution_operation_fields(operations)
    already_executed = item.execution_status in (
        EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
        EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
    )
    eligible = bool(assessment["eligible"])
    diagnostic = assessment["diagnostic"]
    message = assessment["message"]
    for operation in operations:
        op_name = str(operation.get("operation") or "").strip()
        if op_name not in ALLOWED_BOUNDED_OPERATIONS:
            eligible = False
            diagnostic = (
                DIAG_FORBIDDEN_OPERATION_CATEGORY
                if op_name
                in {
                    "shell",
                    "run_command",
                    "execute_command",
                    "npm",
                    "pip",
                    "install",
                    "git_push",
                    "git_commit",
                    "deploy",
                    "network",
                    "delete_file",
                    "delete",
                    "remove_file",
                }
                else DIAG_UNSUPPORTED_OPERATION
            )
            message = (
                f"Not executable by bounded executor: unsupported or forbidden operation {op_name!r}."
            )
            break
    disabled_reason: str | None = None
    if not eligible:
        disabled_reason = diagnostic or message
    elif already_executed:
        disabled_reason = DIAG_ALREADY_EXECUTED
    elif not workspace_path:
        disabled_reason = DIAG_NO_WORKSPACE_CONFIGURED

    bounded_execution_ready = (
        eligible
        and not already_executed
        and bool(operations)
        and bool(workspace_path)
    )
    return {
        "bounded_execution_eligible": eligible,
        "bounded_execution_diagnostic": diagnostic,
        "bounded_execution_message": message,
        "structured_operation_count": len(operations),
        "bounded_execution_target_paths": target_paths,
        "bounded_execution_operation_types": operation_types,
        "bounded_execution_ready": bounded_execution_ready,
        "bounded_execution_disabled_reason": disabled_reason,
    }


def _ready_to_execute_locally_entry(
    item: DecisionQueueItem,
    envelope: RunEnvelope | None,
    *,
    workspace_path: str | None,
) -> dict[str, Any] | None:
    """Build one ready-to-execute row when the item is eligible for batch review."""
    view = _bounded_execution_view(item, envelope, workspace_path=workspace_path)
    if not view["bounded_execution_ready"]:
        return None
    operations = view["bounded_execution_operation_types"]
    primary_op = operations[0] if operations else "—"
    primary_path = view["bounded_execution_target_paths"][0] if view["bounded_execution_target_paths"] else "—"
    return {
        "action_id": item.action_id,
        "operation": primary_op,
        "path": primary_path,
        "decision": item.decision,
        "execution_status": item.execution_status,
        "structured_operation_count": view["structured_operation_count"],
        "bounded_execution_operation_types": operations,
        "bounded_execution_target_paths": view["bounded_execution_target_paths"],
    }


def _ready_to_execute_locally(session: ControlSession) -> list[dict[str, Any]]:
    """Admitted bounded local file actions ready for explicit batch execution."""
    workspace_path = session.bounded_executor_workspace
    ready: list[dict[str, Any]] = []
    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        entry = _ready_to_execute_locally_entry(item, envelope, workspace_path=workspace_path)
        if entry is not None:
            ready.append(entry)
    return ready


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

    def real_gate_ids(values: list[Any]) -> list[str]:
        return [
            str(value)
            for value in values
            if value
            and not re.match(
                r"^(?:none|null|n/?a)(?:\b|\s|[,;.])",
                str(value).strip(),
                re.IGNORECASE,
            )
        ]

    stored = candidate.get("closes_gates")
    if isinstance(stored, list) and stored:
        return real_gate_ids(stored)
    for key in ("operation_text", "tool_or_command"):
        text = candidate.get(key)
        if isinstance(text, str) and text.strip():
            closes = plan_gate_closes_gates(text)
            if closes:
                return real_gate_ids(closes)
    proposed = envelope.decision.get("proposed_action") or {}
    for key in ("operation_text", "description"):
        text = proposed.get(key)
        if isinstance(text, str) and text.strip():
            closes = plan_gate_closes_gates(text)
            if closes:
                return real_gate_ids(closes)
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
        "missing_evidence": list(item.missing_evidence),
        "original_missing_evidence": list(item.original_missing_evidence),
        "satisfied_evidence_fields": list(item.satisfied_evidence_fields),
        "non_evidence_blockers": list(item.non_evidence_blockers),
        "evidence_attention_summary": item.evidence_attention_summary,
        "latest_evidence_summary": item.latest_evidence_summary,
    }


def _structured_evidence_payload(record: EvidenceRecord) -> dict[str, Any]:
    return {
        "evidence_type": record.evidence_type,
        "evidence_text": record.evidence_text,
        "satisfies": list(record.satisfies),
        "source": record.source,
        "sha256": record.sha256,
    }


def _apply_evidence_attention_to_item(
    item: DecisionQueueItem,
    envelope: RunEnvelope | None,
    *,
    evidence_records: list[EvidenceRecord],
    latest_record: EvidenceRecord | None,
    effective_decision: dict[str, Any] | None,
    without_envelope_reevaluation: bool = False,
) -> None:
    """Project structured evidence satisfaction onto a queue item."""
    if effective_decision is None:
        return
    if envelope is not None:
        original_missing = list(envelope.decision.get("missing_evidence") or [])
        if not without_envelope_reevaluation and envelope.envelope is not None:
            original_missing = [
                str(note) if not isinstance(note, dict) else str(note.get("field_id") or note.get("summary") or "")
                for note in (envelope.envelope.get("evidence") or {}).get("missing") or []
            ] or original_missing
    else:
        original_missing = list(item.original_missing_evidence or item.missing_evidence or [])
    action_records = [r for r in evidence_records if r.action_id == item.action_id]
    attention = derive_evidence_attention_state(
        effective_decision,
        original_missing=original_missing,
        evidence_records=action_records,
        latest_record=latest_record,
        without_envelope_reevaluation=without_envelope_reevaluation,
    )
    item.satisfied_evidence_fields = list(attention["satisfied_evidence_fields"])
    item.non_evidence_blockers = list(attention["non_evidence_blockers"])
    item.evidence_attention_summary = attention["evidence_attention_summary"]
    item.original_missing_evidence = list(attention["previously_missing_evidence"])
    if latest_record is not None:
        item.latest_evidence_summary = latest_record.evidence_text
    if without_envelope_reevaluation:
        item.missing_evidence = list(attention["remaining_missing_evidence"])
    if action_records:
        item.lifecycle_status = attention["lifecycle_status"]


def _session_has_content(session: "ControlSession") -> bool:
    """Return whether the session has user-visible state worth protecting from replacement."""
    if session.goal_intake or session.queue or session.human_decisions or session.transcript:
        return True
    run_loop = session.run_loop
    if (
        run_loop.current_turn > 0
        or run_loop.instruction_packets
        or run_loop.response_records
        or run_loop.evidence_records
        or run_loop.superseding_decisions
        or run_loop.derived_lifecycle_resolutions
        or run_loop.resolved_plan_gates
    ):
        return True
    awaiting, _ = _bridge_awaiting_response(run_loop)
    return awaiting


def _bridge_awaiting_response(run_loop: RunLoopState) -> tuple[bool, list[int]]:
    """Return whether the latest instruction packet is outstanding without a response.

    Only the most recent instruction turn can be actively awaiting a bridge
    response. Older packets superseded by a later write are excluded so
    diagnostics do not permanently claim an outstanding response.
    """
    if not run_loop.instruction_packets:
        return False, []
    latest_turn = run_loop.instruction_packets[-1].turn_number
    response_turns = {record.turn_number for record in run_loop.response_records}
    if latest_turn in response_turns:
        return False, []
    return True, [latest_turn]


def _session_diagnostics(
    session: "ControlSession",
    *,
    session_file: Path,
    session_loaded_from_disk: bool,
) -> dict[str, Any]:
    """Display-only session/run-loop diagnostics for the Control Surface UI."""
    run_loop = session.run_loop
    awaiting, awaiting_turns = _bridge_awaiting_response(run_loop)
    evidence_records = run_loop.evidence_records
    latest_evidence = evidence_records[-1].to_dict() if evidence_records else None
    blocked_events = [
        entry["payload"]
        for entry in session.transcript
        if entry.get("type") == "bridge_ingest_blocked"
    ]
    return {
        "session_file": str(session_file),
        "session_loaded_from_disk": session_loaded_from_disk,
        "session_id": session.session_id,
        "current_turn": run_loop.current_turn,
        "bridge_awaiting_response": awaiting,
        "bridge_awaiting_turns": awaiting_turns,
        "evidence_record_count": len(evidence_records),
        "latest_evidence_record": latest_evidence,
        "bridge_blocked_ingest_events": blocked_events,
        "latest_bridge_blocked_ingest": blocked_events[-1] if blocked_events else None,
    }


def _product_state(
    session: "ControlSession",
    *,
    bridge_awaiting_response: bool,
) -> dict[str, Any]:
    """Display/control-only product state for goal-first UI gating.

    Pure projection over already-computed session state -- it carries no
    gating logic of its own: it only reports whether a goal exists and what
    the single next expected action is, so the UI can lead with the goal
    form and disable instruction/bridge controls before a goal is submitted.
    The server-side guard that actually blocks packet generation lives in
    ``ControlSurfaceController.generate_next_instruction_packet``; these
    fields mirror it for display and never substitute for an admission gate.
    """
    run_loop = session.run_loop
    has_goal = bool(session.goal_intake)
    has_instruction = bool(run_loop.instruction_packets)
    has_response = bool(run_loop.response_records)
    has_queue = bool(session.queue)

    if not has_goal:
        run_phase = RUN_PHASE_NEEDS_GOAL
        next_expected_action = NEXT_ACTION_SUBMIT_GOAL
    elif bridge_awaiting_response:
        run_phase = RUN_PHASE_AWAITING_AGENT_RESPONSE
        next_expected_action = NEXT_ACTION_INGEST_RESPONSE
    elif has_response or has_queue:
        run_phase = RUN_PHASE_REVIEWING_ACTIONS
        next_expected_action = NEXT_ACTION_REVIEW_ACTIONS
    else:
        run_phase = RUN_PHASE_READY_TO_INSTRUCT
        next_expected_action = NEXT_ACTION_WRITE_INSTRUCTION

    write_instruction_disabled_reason = None if has_goal else GOAL_REQUIRED_REASON
    if not has_goal:
        ingest_disabled_reason: str | None = GOAL_REQUIRED_REASON
    elif not has_instruction:
        ingest_disabled_reason = NO_INSTRUCTION_REASON
    else:
        ingest_disabled_reason = None

    return {
        "has_goal": has_goal,
        "run_phase": run_phase,
        "next_expected_action": next_expected_action,
        "can_write_instruction": has_goal,
        "write_instruction_disabled_reason": write_instruction_disabled_reason,
        "can_ingest_response": ingest_disabled_reason is None,
        "ingest_disabled_reason": ingest_disabled_reason,
    }


def _agent_backend_control(
    session: "ControlSession",
    *,
    repo_root: str | Path | None,
) -> dict[str, Any]:
    """Workspace-first agent-backend control block (slice ADMISSIBLE_RUN_032).

    Display/control-only: surfaces the *target* workspace as a first-class field,
    the isolated *agent* workspace, the selectable model-agnostic backends and
    their availability, and the reasons a high-autonomy run would be blocked or
    warned before Start. It carries no admission authority — it only projects
    already-computed workspace/backend state so the UI can lead with workspace +
    backend selection instead of hiding them under Advanced.
    """
    from admissible.agent_backend import (
        BACKEND_ID_CURSOR_CLI,
        BACKEND_ID_FILE_BRIDGE,
        assess_workspace_safety,
        describe_available_backends,
    )

    target = session.bounded_executor_workspace
    safety = assess_workspace_safety(
        target_workspace_path=target,
        repo_root=repo_root,
        high_autonomy=True,
    )
    backends = describe_available_backends()
    by_id = {b["backend_id"]: b for b in backends}

    # A backend is start-ready when its availability says available/external.
    # The file bridge is always available (semi-autonomous); Cursor CLI only when
    # configured; fixture is test-only and not offered as a start default.
    def _backend_available(backend_id: str) -> bool:
        entry = by_id.get(backend_id) or {}
        return bool((entry.get("availability") or {}).get("available"))

    start_blocking_reasons = list(safety.blocking_reasons)
    # No callable/external backend available at all would also block a start.
    any_startable = _backend_available(BACKEND_ID_FILE_BRIDGE) or _backend_available(
        BACKEND_ID_CURSOR_CLI
    )
    if not any_startable:
        start_blocking_reasons.append("No agent backend is available or configured.")

    return {
        "target_workspace_path": safety.target_workspace_path,
        "target_workspace_exists": safety.target_exists,
        "target_is_agent_os_repo": safety.target_is_agent_os_repo,
        "agent_workspace_path": safety.agent_workspace_path,
        "agent_equals_target": safety.agent_equals_target,
        "workspace_safety": safety.to_dict(),
        "backends": backends,
        "cursor_cli_configured": _backend_available(BACKEND_ID_CURSOR_CLI),
        "can_start_high_autonomy": not start_blocking_reasons,
        "start_blocking_reasons": start_blocking_reasons,
        "start_warnings": list(safety.warnings),
    }


def _lifecycle_overview(session: "ControlSession") -> dict[str, Any]:
    """Display-only lifecycle buckets for supervised-run demo clarity."""
    queue = session.queue

    def row(item: "DecisionQueueItem") -> dict[str, Any]:
        return _attention_row(item)

    pending_human_decision = [row(item) for item in queue if queue_item_needs_attention(item.to_dict())]
    admitted_not_executed = [
        row(item)
        for item in queue
        if item.execution_status == EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
        or item.lifecycle_status == LIFECYCLE_ADMITTED_NOT_EXECUTED
    ]
    refused_closed = [
        row(item)
        for item in queue
        if item.lifecycle_status in (LIFECYCLE_REFUSED_CLOSED, LIFECYCLE_CLOSED)
        or item.decision == "REFUSE"
    ]
    evidence_supplied_still_blocked = [
        row(item)
        for item in queue
        if item.lifecycle_status
        in (
            LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
            LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING,
            LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE,
            LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
        )
    ]
    evidence_satisfied_pending_human_decision = [
        row(item)
        for item in queue
        if item.lifecycle_status == LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION
    ]
    resolved_plan_gates = [gate.to_dict() for gate in session.run_loop.resolved_plan_gates]

    return {
        "pending_human_decision": pending_human_decision,
        "resolved_plan_gates": resolved_plan_gates,
        "admitted_not_executed": admitted_not_executed,
        "refused_closed": refused_closed,
        "evidence_supplied_still_blocked": evidence_supplied_still_blocked,
        "evidence_satisfied_pending_human_decision": evidence_satisfied_pending_human_decision,
    }


def _run_timeline_object(
    session: "ControlSession",
    *,
    bridge_awaiting_response: bool,
) -> RunTimeline:
    """Build the display-only run timeline object (slice ADMISSIBLE_RUN_021).

    Assembles the run as a readable sequence (goal -> turn -> proposal ->
    admission -> execution -> evidence) from already-computed session state.
    Pure aggregation: it never re-decides an admission, never executes
    anything, and never persists new source-of-truth state -- the queue,
    run-loop turns, and evidence records remain the single source of truth.
    """
    operation_context: dict[str, dict[str, Any]] = {}
    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        # Derive the structured local file operation details straight from the
        # candidate/envelope so they persist for the timeline even after the
        # action has been executed (the eligibility assessment stops returning
        # operations once execution_status flips to executed).
        operations = extract_structured_operations(
            candidate=envelope.candidate if envelope else None,
            envelope=envelope.envelope if envelope else None,
        )
        target_paths, operation_types = _bounded_execution_operation_fields(operations)
        operation_context[item.action_id] = {
            "operation_types": operation_types,
            "target_paths": target_paths,
            "structured_operation_count": len(operations),
        }
    pending_human_decision_count = sum(
        1 for item in session.queue if queue_item_needs_attention(item.to_dict())
    )
    return build_run_timeline(
        session_id=session.session_id,
        created_at=session.created_at,
        goal_intake=session.goal_intake,
        queue=[item.to_dict() for item in session.queue],
        run_loop=session.run_loop,
        operation_context=operation_context,
        bridge_awaiting_response=bridge_awaiting_response,
        pending_human_decision_count=pending_human_decision_count,
    )


def _continuation_instruction(
    session: "ControlSession", timeline: RunTimeline
) -> dict[str, Any]:
    """Display/handoff-only evidence-grounded continuation (slice ADMISSIBLE_RUN_022).

    Composes the next bounded continuation instruction from the same
    already-computed run timeline + evidence. Pure projection: it decides
    nothing, executes nothing, and calls no provider. The ``run_loop.current_turn
    + 1`` turn number here is display-only and does not advance the persisted
    run-loop turn (that only happens via ``generate_next_instruction_packet``),
    so first-turn instruction behavior is unchanged.
    """
    run_loop = session.run_loop
    result = build_continuation_instruction(
        turn_number=run_loop.current_turn + 1,
        autonomy_level=session.autonomy_level,
        goal_intake=session.goal_intake,
        plan_audit=session.plan_audit,
        queue=[item.to_dict() for item in session.queue],
        run_loop=run_loop,
        run_timeline=timeline,
        resolved_plan_gates=[g.to_dict() for g in run_loop.resolved_plan_gates],
    )
    projected = result.to_dict()
    ha = session.high_autonomy_run or {}
    if ha.get("active") and projected.get("instruction_text"):
        criteria = list(ha.get("acceptance_criteria") or [])
        satisfied = [
            item.get("criterion_id")
            for item in criteria
            if item.get("status") in ("verified_pass", "waived")
        ]
        open_criteria = [
            item.get("criterion_id")
            for item in criteria
            if item.get("status") not in ("verified_pass", "waived")
        ]
        pending_useful = [
            item.action_id
            for item in session.queue
            if item.execution_status == "proposed_only"
            and not item.superseded_at
            and item.decision == "ALLOW"
        ]
        stale = [
            {
                "action_id": item.action_id,
                "superseded_by_action_id": item.superseded_by_action_id,
                "reason": item.supersession_reason,
            }
            for item in session.queue
            if item.superseded_at
        ]
        ledger = {
            "acceptance_criteria": [
                {
                    "criterion_id": item.get("criterion_id"),
                    "status": item.get("status"),
                    "source_text": item.get("source_text"),
                }
                for item in criteria
            ],
            "satisfied_criteria": satisfied,
            "open_criteria": open_criteria,
            "current_final_file_hashes": latest_file_hashes(session.operation_records),
            "pending_useful_operations": pending_useful,
            "stale_or_superseded_actions": stale,
            "remaining_work_turn_budget": max(
                int(ha.get("max_turns") or 0)
                - int(ha.get("closure_reserve_turns") or 0)
                - int(ha.get("work_turns_used") or 0),
                0,
            ),
            "closure_phase_status": ha.get("closure_phase_status") or "not_started",
            "batch_limits": {
                "max_structured_operations_per_response": int(
                    ha.get("max_structured_operations_per_response") or 8
                ),
                "max_total_proposed_write_bytes": int(
                    ha.get("max_total_proposed_write_bytes") or 256 * 1024
                ),
            },
        }
        projected["progress_ledger"] = ledger
        projected["instruction_text"] = (
            str(projected["instruction_text"]).rstrip()
            + "\n\nSTRUCTURED PROGRESS LEDGER (current state only)\n"
            + json.dumps(ledger, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )
    return projected


def _verification_summary(session: "ControlSession") -> dict[str, Any]:
    """Display-only bounded verification readiness derived from stored verification runs."""
    records = list(session.run_loop.verification_records or [])
    if not records:
        return {
            "verification_count": 0,
            "readiness": "not_run",
            "latest": None,
            "latest_overall_status": None,
            "passed_count": 0,
            "failed_count": 0,
            "failed_check_messages": [],
        }
    latest = records[-1]
    failed_messages = [
        str(entry.get("message") or entry.get("check_id") or "check failed")
        for entry in (latest.get("results") or [])
        if entry.get("status") == "fail"
    ]
    return {
        "verification_count": len(records),
        "readiness": latest.get("overall_status") or "unknown",
        "latest": latest,
        "latest_overall_status": latest.get("overall_status"),
        "passed_count": latest.get("passed_count", 0),
        "failed_count": latest.get("failed_count", 0),
        "profile": latest.get("profile"),
        "workspace_path": latest.get("workspace_path"),
        "failed_check_messages": failed_messages,
    }


def _governed_run_overview(
    *,
    run_timeline: dict[str, Any],
    verification_summary: dict[str, Any],
    continuation_instruction: dict[str, Any],
) -> dict[str, Any]:
    """Top-level governed-run narrative for demo readability (display-only)."""
    blocked_ids = run_timeline.get("blocked_operation_ids") or []
    return {
        "goal": run_timeline.get("goal"),
        "status": run_timeline.get("status"),
        "turn_count": run_timeline.get("turn_count", 0),
        "ready_to_execute_local_count": run_timeline.get("ready_to_execute_local_count", 0),
        "blocked_count": len(blocked_ids),
        "write_evidence_count": run_timeline.get("evidence_count", 0),
        "verification_readiness": verification_summary.get("readiness", "not_run"),
        "verification_profile": verification_summary.get("profile"),
        "continuation_available": bool(continuation_instruction.get("available")),
        "continuation_status": continuation_instruction.get("status"),
    }


REHEARSAL_PACKET_SCHEMA_VERSION = "admissible_live_rehearsal_packet_v0"


def _rehearsal_operator_next_steps(
    *,
    product_state: dict[str, Any],
    governed_run_overview: dict[str, Any],
    continuation_instruction: dict[str, Any],
    ready_to_execute_locally: list[dict[str, Any]],
    bridge_awaiting_response: bool,
) -> list[str]:
    """Display-only operator guidance for live Cursor multi-turn rehearsal."""
    next_action = product_state.get("next_expected_action")
    steps: list[str] = []

    if next_action == NEXT_ACTION_SUBMIT_GOAL:
        steps.append("Submit the canonical tiny-game goal in the goal form.")
        return steps

    if next_action == NEXT_ACTION_WRITE_INSTRUCTION:
        steps.append("Enter workspace path and click Write instruction file.")
        steps.append("Optional: Open workspace in Cursor.")
        steps.append(
            "Turn 1 only: Cursor reads .admissible/next-agent-instruction.md and writes "
            ".admissible/agent-response.md."
        )
        steps.append(
            "Turn 2+: prefer Copy continuation instruction (after prior turn executed) "
            "instead of Write instruction file when evidence-grounded handoff is available."
        )
        return steps

    if next_action == NEXT_ACTION_INGEST_RESPONSE or bridge_awaiting_response:
        steps.append(
            "Confirm Cursor wrote .admissible/agent-response.md in the workspace."
        )
        steps.append("Click Ingest Cursor response file.")
        steps.append("Review admission decisions in the queue — nothing executes on ingest.")
        return steps

    if ready_to_execute_locally:
        steps.append(
            f"Execute all ready locally ({len(ready_to_execute_locally)} admitted file op(s)) "
            "before copying continuation."
        )

    if continuation_instruction.get("status") == "pending_local_execution":
        steps.append(
            "Continuation unavailable until pending admitted local ops are explicitly executed."
        )

    if continuation_instruction.get("available"):
        steps.append("Copy continuation instruction and hand off to Cursor for the next turn.")

    if governed_run_overview.get("blocked_count", 0) > 0:
        steps.append(
            "Review blocked/gated ops in Run Timeline — do not treat them as executed."
        )

    verification = governed_run_overview.get("verification_readiness", "not_run")
    turn_count = governed_run_overview.get("turn_count", 0)
    evidence_count = governed_run_overview.get("write_evidence_count", 0)
    if turn_count >= 4 and evidence_count >= 8 and verification == "not_run":
        steps.append("Run bounded verification when the four-turn recovery path is complete.")
    elif verification == "pass":
        steps.append("Live rehearsal complete — capture session export and verification summary.")
    elif verification == "fail":
        steps.append("Review failed verification checks before claiming rehearsal success.")

    if not steps:
        steps.append("Review queue and Supervised Run State; proceed per next_expected_action.")
    return steps


def _format_rehearsal_checklist_text(packet: dict[str, Any]) -> str:
    """Human-readable checklist for clipboard export (display-only)."""
    lines = [
        "ADMISSIBLE LIVE CURSOR MULTI-TURN REHEARSAL CHECKLIST",
        f"schema: {packet.get('schema_version')}",
        "",
        f"Goal: {packet.get('goal') or '(none yet)'}",
        f"Run phase: {packet.get('run_phase')}",
        f"Next expected action: {packet.get('next_expected_action')}",
        f"Current turn: {packet.get('current_turn')}",
        f"Bridge awaiting response: {packet.get('bridge_awaiting_response')}",
        "",
        f"Pending local execution: {packet.get('pending_local_execution_count')}",
        f"Write evidence count: {packet.get('write_evidence_count')}",
        f"Continuation available: {packet.get('continuation_available')} "
        f"({packet.get('continuation_status')})",
        f"Verification readiness: {packet.get('verification_readiness')}",
        "",
        "Operator next steps:",
    ]
    for index, step in enumerate(packet.get("operator_next_steps") or [], start=1):
        lines.append(f"  {index}. {step}")
    lines.extend(
        [
            "",
            "Cursor MAY: read instruction/continuation, write agent-response.md, "
            "propose structured local file ops.",
            "Cursor MUST NOT: execute shell/npm/network/deploy, write workspace files "
            "directly, or bypass Admissible admission.",
            "",
            "See docs/admissible-live-cursor-multi-turn-rehearsal.md",
        ]
    )
    return "\n".join(lines)


def _rehearsal_packet(
    *,
    session: "ControlSession",
    product_state: dict[str, Any],
    governed_run_overview: dict[str, Any],
    continuation_instruction: dict[str, Any],
    ready_to_execute_locally: list[dict[str, Any]],
    bridge_awaiting_response: bool,
) -> dict[str, Any]:
    """Display-only live rehearsal summary for operator handoff (slice DEMO_027).

    Pure projection: summarizes goal, phase, continuation, execution backlog,
    evidence, and verification readiness. Does not execute anything and does
    not call providers.
    """
    run_loop = session.run_loop
    goal_intake = session.goal_intake or {}
    latest_packet = run_loop.instruction_packets[-1] if run_loop.instruction_packets else None
    operator_next_steps = _rehearsal_operator_next_steps(
        product_state=product_state,
        governed_run_overview=governed_run_overview,
        continuation_instruction=continuation_instruction,
        ready_to_execute_locally=ready_to_execute_locally,
        bridge_awaiting_response=bridge_awaiting_response,
    )
    packet: dict[str, Any] = {
        "schema_version": REHEARSAL_PACKET_SCHEMA_VERSION,
        "goal": governed_run_overview.get("goal") or goal_intake.get("normalized_goal"),
        "run_phase": product_state.get("run_phase"),
        "next_expected_action": product_state.get("next_expected_action"),
        "current_turn": run_loop.current_turn,
        "bridge_awaiting_response": bridge_awaiting_response,
        "latest_instruction_turn": latest_packet.turn_number if latest_packet else None,
        "latest_instruction_written": bool(run_loop.instruction_packets),
        "continuation_available": bool(continuation_instruction.get("available")),
        "continuation_status": continuation_instruction.get("status"),
        "pending_local_execution_count": len(ready_to_execute_locally),
        "write_evidence_count": governed_run_overview.get("write_evidence_count", 0),
        "blocked_count": governed_run_overview.get("blocked_count", 0),
        "verification_readiness": governed_run_overview.get("verification_readiness", "not_run"),
        "operator_next_steps": operator_next_steps,
    }
    packet["checklist_text"] = _format_rehearsal_checklist_text(packet)
    return packet


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
        self._high_autonomy_transport: Any = None
        self._high_autonomy_tick_lock = threading.Lock()

    def _high_autonomy_state(self) -> Any:
        from admissible.high_autonomy_controller import HighAutonomyRunState

        raw = self._session.high_autonomy_run
        return HighAutonomyRunState.from_dict(raw)

    def _set_high_autonomy_state(self, state: Any) -> None:
        self._session.high_autonomy_run = state.to_dict()

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
        if self._session.high_autonomy_run is not None:
            from admissible.governed_run import build_canonical_metrics
            from admissible.high_autonomy_controller import HighAutonomyRunState

            ha_state = HighAutonomyRunState.from_dict(self._session.high_autonomy_run)
            ha_state.turns_remaining = max(
                ha_state.max_turns - self._session.run_loop.current_turn, 0
            )
            ha_state.blocked_action_count = len(
                active_blocking_action_ids(self._session.queue)
            )
            ha_state.metrics = build_canonical_metrics(
                operation_records=self._session.operation_records,
                governance_records=self._session.governance_records,
                verification_records=self._session.run_loop.verification_records,
                invocation_history=ha_state.invocation_history,
                human_decisions=self._session.human_decisions,
                queue=self._session.queue,
                work_turns_used=ha_state.work_turns_used,
                verification_turns_used=ha_state.verification_turns_used,
                closure_turns_used=ha_state.closure_turns_used,
                turns_remaining=ha_state.turns_remaining,
            )
            self._session.high_autonomy_run = ha_state.to_dict()
        payload = self._session.to_dict()
        return canonicalize_session_export_payload(payload)

    def state_view(self) -> dict[str, Any]:
        """Session state plus derived, non-persisted UI fields."""
        view = migrate_session_projection_fields(self.session_dict())
        workspace_path = self._session.bounded_executor_workspace
        view["queue"] = [
            {
                **item.to_dict(),
                "available_actions": available_human_actions(item, self._session.autonomy_level),
                **_bounded_execution_view(
                    item,
                    self._session.run_envelopes.get(item.action_id),
                    workspace_path=workspace_path,
                ),
            }
            for item in self._session.queue
        ]
        view["autonomy_levels"] = list(AUTONOMY_LEVEL_ORDER)
        view["autonomy_profiles"] = [
            AUTONOMY_PROFILES[level].to_dict() for level in AUTONOMY_LEVEL_ORDER
        ]
        view["mission_summary"] = _mission_summary(self._session)
        view["needs_attention"] = _needs_attention(self._session)
        view["session_diagnostics"] = _session_diagnostics(
            self._session,
            session_file=self._session_file,
            session_loaded_from_disk=self._session_loaded_from_disk,
        )
        view.update(
            _product_state(
                self._session,
                bridge_awaiting_response=view["session_diagnostics"]["bridge_awaiting_response"],
            )
        )
        view["session_has_content"] = _session_has_content(self._session)
        view["lifecycle_overview"] = _lifecycle_overview(self._session)
        timeline = _run_timeline_object(
            self._session,
            bridge_awaiting_response=view["session_diagnostics"]["bridge_awaiting_response"],
        )
        view["run_timeline"] = timeline.to_dict()
        view["continuation_instruction"] = _continuation_instruction(self._session, timeline)
        view["verification_summary"] = _verification_summary(self._session)
        view["governed_run_overview"] = _governed_run_overview(
            run_timeline=view["run_timeline"],
            verification_summary=view["verification_summary"],
            continuation_instruction=view["continuation_instruction"],
        )
        view["ready_to_execute_locally"] = _ready_to_execute_locally(self._session)
        view["rehearsal_packet"] = _rehearsal_packet(
            session=self._session,
            product_state={
                "run_phase": view["run_phase"],
                "next_expected_action": view["next_expected_action"],
            },
            governed_run_overview=view["governed_run_overview"],
            continuation_instruction=view["continuation_instruction"],
            ready_to_execute_locally=view["ready_to_execute_locally"],
            bridge_awaiting_response=view["session_diagnostics"]["bridge_awaiting_response"],
        )
        view["session_file"] = str(self._session_file)
        view["session_loaded_from_disk"] = self._session_loaded_from_disk
        ha_state = self._high_autonomy_state()
        from admissible.high_autonomy_controller import (
            build_high_autonomy_summary,
            build_live_high_autonomy_rehearsal_status,
        )

        view["high_autonomy_summary"] = build_high_autonomy_summary(
            ha_state=ha_state,
            state_view=view,
        )
        view["live_high_autonomy_rehearsal_status"] = build_live_high_autonomy_rehearsal_status(
            ha_state=ha_state,
            state_view=view,
        )
        view["canonical_run_metrics"] = dict(ha_state.metrics or {})
        view["governed_run_overview"]["blocked_count"] = int(
            (ha_state.metrics or {}).get("active_blocked_count", 0)
        )
        view["agent_backend_control"] = _agent_backend_control(
            self._session,
            repo_root=self._repo_root,
        )
        return view

    def set_bounded_executor_workspace(self, workspace_path: str | Path) -> dict[str, Any]:
        """Persist the validated local workspace used by bridge and bounded execution."""
        validated = validate_workspace_path(workspace_path)
        self._session.bounded_executor_workspace = str(validated)
        self._persist()
        return self.state_view()

    def _persist(self) -> None:
        self._session_dir.mkdir(parents=True, exist_ok=True)
        with self._session_file.open("w", encoding="utf-8") as f:
            json.dump(
                self.session_dict(), f, indent=2, sort_keys=True, ensure_ascii=False
            )
            f.write("\n")

    def reset_session(self) -> dict[str, Any]:
        self._session = self._new_session()
        self._persist()
        return self.state_view()

    def import_session(self, data: dict[str, Any]) -> dict[str, Any]:
        self._session = ControlSession.from_dict(data)
        repair_inconsistent_executable_lifecycle(
            self._session.queue,
            run_envelopes=self._session.run_envelopes,
            workspace_path=self._session.bounded_executor_workspace,
            governance_records=self._session.governance_records,
        )
        _repair_stale_aggregate_pseudo_gates(self._session)
        _repair_stale_negated_non_actions(self._session)
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

    def load_sample_session(self, *, force: bool = False) -> dict[str, Any]:
        if _session_has_content(self._session) and not force:
            raise SessionNotEmptyError(
                "cannot load sample session: current session has content; "
                "pass force=true after explicit confirmation to replace it",
                detail={"reason": SESSION_NOT_EMPTY_REASON},
            )
        self._session = self._new_session()
        self._session.is_sample_session = True
        self.submit_goal(SAMPLE_SLITHER_PROMPT)
        self._load_queue_from_trace(self._sample_trace_path)
        self._session.transcript.append(
            _transcript_entry(
                "admissible_message",
                {
                    "message": (
                        f"Loaded example admitted-execution trace "
                        f"({len(self._session.queue)} action(s))."
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

    def execute_bounded_local(self, action_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Execute one admitted action via the bounded local file executor.

        Never mutates the original rules-only admission decision. Updates only
        derived execution status and appends structured attestation evidence.
        """
        item = self._find_queue_item(action_id)
        if item is None:
            raise ValueError(f"unknown action_id: {action_id!r}")

        envelope = self._session.run_envelopes.get(action_id)
        workspace_path = body.get("workspace_path") or self._session.bounded_executor_workspace
        if body.get("workspace_path"):
            self._session.bounded_executor_workspace = str(body["workspace_path"]).strip()

        assessment = assess_bounded_execution_eligibility(item=item, envelope=envelope, body=body)
        if not assessment["eligible"]:
            raise BoundedExecutionError(
                assessment["message"],
                diagnostic=assessment["diagnostic"] or "not_admitted",
                detail={
                    "action_id": action_id,
                    "bounded_execution_diagnostic": assessment["diagnostic"],
                    "bounded_execution_message": assessment["message"],
                },
            )

        operations = list(assessment["operations"])
        noop_records, pending_operations = _preclassify_noop_operations(
            self._session,
            action_id=action_id,
            operations=operations,
            workspace_path=str(workspace_path) if workspace_path else None,
        )
        known_record_ids = {
            str(record.get("record_id")) for record in self._session.operation_records
        }
        for record in noop_records:
            if str(record.get("record_id")) not in known_record_ids:
                self._session.operation_records.append(record)

        for operation in pending_operations:
            if not _safe_overwrite_review_required(
                self._session,
                operation=operation,
                workspace_path=str(workspace_path) if workspace_path else None,
            ):
                continue
            if _action_has_human_approval(self._session, action_id):
                continue
            workspace = validate_workspace_path(workspace_path)
            rel_path = normalize_workspace_relative_path(str(operation.get("path") or "."))
            target = validate_relative_path_inside_workspace(workspace, rel_path)
            observed_sha = current_file_sha256(target)
            identity = canonical_operation_identity(operation, observed_sha256=observed_sha)
            fingerprint = canonical_operation_fingerprint(operation, observed_sha256=observed_sha)
            blocked_record = _operation_record(
                action_id=action_id,
                operation=operation,
                outcome="blocked",
                fingerprint=fingerprint,
                identity=identity,
                current_sha256=observed_sha,
                detail={"reason": "unsafe_overwrite_requires_human_review"},
            )
            self._session.operation_records.append(blocked_record)
            item.safe_overwrite_review_required = True
            if envelope is not None:
                envelope.candidate["requires_safe_overwrite_review"] = True
            self._persist()
            raise BoundedExecutionError(
                (
                    f"write_file for {rel_path!r} requires human review: the file predates "
                    "this run or its current sha256 differs from latest execution evidence"
                ),
                diagnostic="unsafe_overwrite_requires_review",
                detail={"action_id": action_id, "path": rel_path},
            )

        if pending_operations:
            result = execute_bounded_local_action(
                workspace_path=workspace_path,
                operations=pending_operations,
                action_id=action_id,
                decision_id=envelope.decision_id if envelope else None,
                envelope_id=envelope.envelope_id if envelope else None,
                turn_number=self._session.run_loop.current_turn or None,
            )
            if not result.success:
                for operation in pending_operations:
                    identity = canonical_operation_identity(operation)
                    self._session.operation_records.append(
                        _operation_record(
                            action_id=action_id,
                            operation=operation,
                            outcome="failed",
                            fingerprint=canonical_operation_fingerprint(operation),
                            identity=identity,
                            detail={"diagnostic": result.diagnostic, "message": result.message},
                        )
                    )
                self._persist()
                raise BoundedExecutionError(
                    result.message,
                    diagnostic=result.diagnostic or "unsupported_operation",
                    detail={
                        "action_id": action_id,
                        "bounded_execution_diagnostic": result.diagnostic,
                    },
                )
        else:
            from admissible.execution.bounded_local_executor import BoundedExecutionResult

            result = BoundedExecutionResult(
                success=True,
                message="All bounded operations were canonical no-ops.",
                action_id=action_id,
                operations_executed=[],
                evidence_records=[],
                execution_record={
                    "action_id": action_id,
                    "execution_status": EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
                    "execution_actor": "bounded_executor",
                    "execution_timestamp": _now_iso(),
                    "execution_evidence": {
                        "operations": [dict(record) for record in noop_records],
                        "notes": "No mutation or inspection repeated; canonical no-op handling.",
                    },
                },
            )

        operation_by_key = {
            (
                str(operation.get("operation") or ""),
                normalize_workspace_relative_path(str(operation.get("path") or ".")),
            ): operation
            for operation in pending_operations
        }
        executed_operation_records: list[dict[str, Any]] = []
        for executed in result.operations_executed:
            key = (str(executed.get("operation") or ""), str(executed.get("path") or "."))
            operation = operation_by_key.get(key, executed)
            observed_sha = executed.get("sha256") if key[0] == "read_file" else executed.get(
                "prior_sha256"
            )
            identity = canonical_operation_identity(operation, observed_sha256=observed_sha)
            fingerprint = canonical_operation_fingerprint(operation, observed_sha256=observed_sha)
            record = _operation_record(
                action_id=action_id,
                operation=operation,
                outcome=str(executed.get("outcome") or "failed"),
                fingerprint=fingerprint,
                identity=identity,
                current_sha256=executed.get("prior_sha256"),
                overwrite=bool(executed.get("overwrite")),
            )
            record["result_sha256"] = executed.get("sha256")
            record["detail"] = {
                key: value
                for key, value in executed.items()
                if key not in ("operation", "path", "outcome", "sha256")
            }
            self._session.operation_records.append(record)
            executed_operation_records.append(record)

        item.execution_status = EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        item.execution_record = result.execution_record
        item.lifecycle_status = LIFECYCLE_CLOSED
        all_operation_records = [*noop_records, *executed_operation_records]
        item.operation_fingerprints = [
            str(record.get("fingerprint")) for record in all_operation_records
        ]
        outcomes = [str(record.get("outcome")) for record in all_operation_records]
        item.operation_outcome = (
            "executed_mutation"
            if "executed_mutation" in outcomes
            else "executed_read"
            if "executed_read" in outcomes
            else "executed_list"
            if "executed_list" in outcomes
            else "duplicate_noop"
            if "duplicate_noop" in outcomes
            else "already_satisfied_noop"
        )
        if envelope is not None:
            envelope.candidate["execution_status"] = EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
            envelope.candidate["execution_record"] = result.execution_record
            # Original rules-only decision remains immutable (never assigned here).

        for record in result.evidence_records:
            self._session.run_loop.evidence_records.append(record)

        covered_write_paths = {
            str(record.get("path"))
            for record in all_operation_records
            if record.get("operation") == "write_file"
            and record.get("outcome")
            in ("executed_mutation", "duplicate_noop", "already_satisfied_noop")
        }
        superseded_gate_count = _supersede_covered_gates(
            self._session,
            executed_action_id=action_id,
            executed_paths=covered_write_paths,
        )
        mutated_paths = {
            str(record.get("path"))
            for record in executed_operation_records
            if record.get("outcome") == "executed_mutation"
        }
        if mutated_paths and self._session.high_autonomy_run is not None:
            criteria = self._session.high_autonomy_run.get("acceptance_criteria") or []
            for criterion in criteria:
                criterion_paths = {
                    str(path)
                    for request in criterion.get("verification") or []
                    for path in request.get("target_paths") or []
                }
                if criterion_paths & mutated_paths:
                    criterion["status"] = "evidence_available"
                    criterion.setdefault("verification_notes", []).append(
                        "Criterion-relevant file state changed; deterministic re-verification required."
                    )

        self._session.transcript.append(
            _transcript_entry(
                "bounded_local_execution",
                {
                    "action_id": action_id,
                    "workspace_path": str(workspace_path),
                    "operations_executed": result.operations_executed,
                    "operation_outcomes": [dict(record) for record in all_operation_records],
                    "superseded_gate_count": superseded_gate_count,
                    "execution_status": EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
                    "evidence_record_ids": [record.record_id for record in result.evidence_records],
                    "note": (
                        "Executed by Admissible bounded local executor v0; "
                        "no shell commands were run."
                    ),
                },
            )
        )
        self._persist()
        return self.state_view()

    def execute_bounded_local_batch(self, body: dict[str, Any]) -> dict[str, Any]:
        """Execute all currently eligible admitted local file actions in queue order.

        Explicit user action only; never called from ingest. Partial success is
        preserved in v0: successful file writes are not rolled back when a later
        action in the batch fails.
        """
        workspace_path = body.get("workspace_path") or self._session.bounded_executor_workspace
        if body.get("workspace_path"):
            self._session.bounded_executor_workspace = str(body["workspace_path"]).strip()
            workspace_path = self._session.bounded_executor_workspace

        if not workspace_path:
            raise BoundedExecutionError(
                "no workspace configured for bounded local batch execution",
                diagnostic=DIAG_NO_WORKSPACE_CONFIGURED,
            )

        ready_before = _ready_to_execute_locally(self._session)
        action_results: list[dict[str, Any]] = []
        for entry in ready_before:
            action_id = entry["action_id"]
            try:
                self.execute_bounded_local(action_id, {"workspace_path": workspace_path})
                item = self._find_queue_item(action_id)
                action_results.append(
                    {
                        "action_id": action_id,
                        "success": True,
                        "execution_status": item.execution_status if item else None,
                        "path": entry.get("path"),
                        "operation": entry.get("operation"),
                    }
                )
            except BoundedExecutionError as exc:
                action_results.append(
                    {
                        "action_id": action_id,
                        "success": False,
                        "message": str(exc),
                        "diagnostic": exc.diagnostic,
                        "path": entry.get("path"),
                        "operation": entry.get("operation"),
                    }
                )

        succeeded_count = sum(1 for result in action_results if result.get("success"))
        failed_count = len(action_results) - succeeded_count
        partial_success = succeeded_count > 0 and failed_count > 0

        self._session.transcript.append(
            _transcript_entry(
                "bounded_local_batch_execution",
                {
                    "workspace_path": str(workspace_path),
                    "action_count": len(action_results),
                    "succeeded_count": succeeded_count,
                    "failed_count": failed_count,
                    "partial_success": partial_success,
                    "action_results": action_results,
                    "note": (
                        "Explicit bounded local batch execution v0. Ingest never executes. "
                        "Partial success does not roll back earlier successful file writes."
                    ),
                },
            )
        )
        self._persist()
        view = self.state_view()
        view["bounded_local_batch_result"] = {
            "workspace_path": str(workspace_path),
            "action_results": action_results,
            "succeeded_count": succeeded_count,
            "failed_count": failed_count,
            "partial_success": partial_success,
            "note": (
                "Partial batch success preserves earlier file writes in v0; "
                "inspect per-action results below."
                if partial_success
                else None
            ),
        }
        return view

    def verify_bounded_local_workspace(self, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run explicit bounded verification checks against the local workspace.

        Human-triggered only; never called from ingest or model proposals.
        This is not shell authority: only allowlisted read-only checks run.
        """
        body = body or {}
        workspace_path = body.get("workspace_path") or self._session.bounded_executor_workspace
        if body.get("workspace_path"):
            self._session.bounded_executor_workspace = str(body["workspace_path"]).strip()
            workspace_path = self._session.bounded_executor_workspace

        if not workspace_path:
            raise BoundedVerificationError(
                "no workspace configured for bounded local verification",
                diagnostic=DIAG_NO_WORKSPACE_CONFIGURED,
            )

        profile = str(body.get("profile") or "tiny_game_demo").strip()
        include_node_syntax_check = bool(body.get("include_node_syntax_check"))
        raw_requests = body.get("requests")
        requests: list[VerificationRequest] | None = None
        if raw_requests is not None:
            requests = [VerificationRequest.from_dict(item) for item in raw_requests]
            for request in requests:
                validate_verification_request(request)
        elif profile == "acceptance_ledger":
            criteria = list((self._session.high_autonomy_run or {}).get("acceptance_criteria") or [])
            criterion_filter = {
                str(item) for item in (body.get("criterion_ids") or []) if str(item).strip()
            }
            requests = []
            for criterion in criteria:
                criterion_id = str(criterion.get("criterion_id") or "")
                if criterion_filter and criterion_id not in criterion_filter:
                    continue
                for raw_request in criterion.get("verification") or []:
                    request_data = dict(raw_request)
                    request_data.setdefault("criterion_id", criterion.get("criterion_id"))
                    request = VerificationRequest.from_dict(request_data)
                    validate_verification_request(request)
                    requests.append(request)

        evidence = run_bounded_verification(
            workspace_path=workspace_path,
            profile=profile,
            requests=requests,
            write_evidence_records=self._session.run_loop.evidence_records,
            include_node_syntax_check=include_node_syntax_check,
        )
        self._session.run_loop.verification_records.append(evidence.to_dict())
        if self._session.high_autonomy_run is not None:
            from admissible.high_autonomy_controller import HighAutonomyRunState
            from admissible.governed_run import apply_verification_results_to_ledger

            ha_state = HighAutonomyRunState.from_dict(self._session.high_autonomy_run)
            apply_verification_results_to_ledger(
                ha_state.acceptance_criteria, evidence.to_dict()
            )
            self._session.high_autonomy_run = ha_state.to_dict()

        self._session.transcript.append(
            _transcript_entry(
                "bounded_local_verification",
                {
                    "evidence_id": evidence.evidence_id,
                    "workspace_path": evidence.workspace_path,
                    "profile": evidence.profile,
                    "overall_status": evidence.overall_status,
                    "check_count": len(evidence.results),
                    "passed_count": sum(1 for result in evidence.results if result.status == "pass"),
                    "failed_count": sum(1 for result in evidence.results if result.status == "fail"),
                    "note": (
                        "Explicit bounded verification v0; allowlisted read-only checks only. "
                        "No shell/npm/network/deploy authority was granted."
                    ),
                },
            )
        )
        self._persist()
        view = self.state_view()
        view["bounded_local_verification_result"] = evidence.to_dict()
        return view

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

        Goal-first guard: raises ``NoGoalSubmittedError`` (a ValueError) when
        no goal has been submitted, before advancing the run-loop turn or
        producing any packet. This is the single server-side choke point for
        every instruction-producing path (the manual "Generate next agent
        instruction" fallback, the Cursor file bridge's
        ``write_next_instruction_with_controller``, and the CLI
        ``copy_next_instruction``), so a blank session can never write a
        placeholder "No goal has been submitted" instruction packet.
        """
        if not self._session.goal_intake:
            raise NoGoalSubmittedError(
                "Submit a goal to Admissible before generating an instruction packet.",
                detail={"reason": GOAL_REQUIRED_REASON},
            )
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

    def generate_next_continuation_instruction_packet(
        self,
        *,
        instruction_text: str,
    ) -> dict[str, Any]:
        """Advance the run-loop turn using evidence-grounded continuation text.

        Used by the high-autonomy controller to write continuation instructions
        without manual copy/paste. Does not weaken admission or execution gates.
        """
        if not self._session.goal_intake:
            raise NoGoalSubmittedError(
                "Submit a goal to Admissible before generating an instruction packet.",
                detail={"reason": GOAL_REQUIRED_REASON},
            )
        if not isinstance(instruction_text, str) or not instruction_text.strip():
            raise ValueError("continuation instruction_text must be a non-empty string")

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
        stored_packet = dataclasses.replace(packet, packet_text=instruction_text.strip())
        run_loop.current_turn = turn_number
        run_loop.instruction_packets.append(stored_packet)
        run_loop.turns.append(
            RunTurn(
                turn_number=turn_number,
                created_at=stored_packet.created_at,
                instruction_packet_id=stored_packet.packet_id,
                agent_response_record_id=None,
                summary=f"Generated evidence-grounded continuation for turn {turn_number}.",
            )
        )
        self._session.transcript.append(
            _transcript_entry(
                "continuation_instruction_packet_generated",
                {**stored_packet.to_dict(), "continuation_grounded": True},
            )
        )
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

        completion_candidate, action_text = extract_completion_candidate(raw_text)
        without_fences = re.sub(r"```(?:json)?|```", "", action_text, flags=re.IGNORECASE).strip()
        built = (
            build_candidates_from_agent_response(
                action_text,
                turn_number=turn_number,
                long_run_prompt=long_run_prompt,
                source_metadata={"workspace_context": "local admissible control surface session"},
            )
            if without_fences
            else []
        )

        ha_config = self._session.high_autonomy_run or {}
        all_structured_operations = [
            operation
            for entry in built
            for operation in (entry.get("candidate") or {}).get("structured_operations") or []
        ]
        validate_coherent_batch_limits(
            all_structured_operations,
            max_operations=int(
                ha_config.get("max_structured_operations_per_response") or 8
            ),
            max_total_write_bytes=int(
                ha_config.get("max_total_proposed_write_bytes") or 256 * 1024
            ),
        )

        run_envelopes = [
            RunEnvelope(
                action_id=entry["action_id"],
                envelope_id=entry["envelope_id"],
                decision_id=entry["decision_id"],
                candidate=entry["candidate"],
                decision=entry["decision"],
                envelope=entry["envelope"],
            )
            for entry in built
        ]
        concrete_allow_paths: set[str] = set()
        for run_env in run_envelopes:
            if run_env.decision.get("decision") != "ALLOW":
                continue
            for operation in run_env.candidate.get("structured_operations") or []:
                try:
                    concrete_allow_paths.add(
                        normalize_workspace_relative_path(str(operation.get("path") or "."))
                    )
                except ValueError:
                    continue
        closes_values = re.findall(
            r"closes\s+gates?:\s*([^\r\n]+)", action_text, re.IGNORECASE
        )
        non_none_closes = any(
            value.strip().lower() not in ("none", "null", "n/a", "na")
            for value in closes_values
        )
        response_restates_local_write_approval = bool(
            concrete_allow_paths
            and not non_none_closes
            and re.search(
                r"human\s+decision\s+required:.*approve.*(?:local\s+write|write)",
                action_text,
                re.IGNORECASE | re.DOTALL,
            )
        )

        new_action_ids: list[str] = []
        for run_env in run_envelopes:
            if _is_pseudo_gate_for_concrete_allow(
                run_env,
                concrete_allow_paths=concrete_allow_paths,
                response_restates_local_write_approval=response_restates_local_write_approval,
                response_text=action_text,
            ):
                self._session.governance_records.append(
                    {
                        "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                        "event_type": "pseudo_gate_suppressed",
                        "action_id": run_env.action_id,
                        "source_action_id": run_env.action_id,
                        "reason": "model_approval_prose_restates_separately_allowed_operation",
                        "sibling_action_ids": [
                            entry.action_id
                            for entry in run_envelopes
                            if entry.decision.get("decision") == "ALLOW"
                            and entry.action_id != run_env.action_id
                        ],
                        "timestamp": _now_iso(),
                    }
                )
                continue

            candidate_text = str(
                (run_env.candidate or {}).get("operation_text")
                or (run_env.candidate or {}).get("tool_or_command")
                or ""
            )
            if _is_negated_non_action_source_text(candidate_text):
                self._session.governance_records.append(
                    {
                        "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                        "event_type": "negated_non_action_suppressed",
                        "action_id": run_env.action_id,
                        "source_action_id": run_env.action_id,
                        "reason": "negated_non_action",
                        "source_text": candidate_text[:240],
                        "detected_action_type": run_env.candidate.get("action_type"),
                        "sibling_action_ids": [
                            entry.action_id
                            for entry in run_envelopes
                            if entry.decision.get("decision") == "ALLOW"
                            and entry.action_id != run_env.action_id
                        ],
                        "timestamp": _now_iso(),
                    }
                )
                continue

            item = _build_queue_item(run_env)
            item.source_action_id = run_env.action_id
            if item.action_type == "plan_gate_resolution":
                gate_identity, gate_target = _canonical_gate_identity(run_env)
                item.gate_identity = gate_identity
                item.closes_gate_ids = _closes_gates_for_item(run_env, item)
                item.semantic_gate_type = item.action_type
                item.gate_target = gate_target
                if _gate_choice_explicit_in_user_goal(
                    run_env, str(long_run_prompt or "")
                ):
                    item.lifecycle_status = LIFECYCLE_SUPERSEDED
                    item.superseded_by_action_id = "user_goal"
                    item.supersession_reason = "underlying_plan_choice_explicit_in_user_goal"
                    item.superseded_at = _now_iso()
                    self._session.governance_records.append(
                        {
                            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                            "event_type": "gate_superseded",
                            "action_id": run_env.action_id,
                            "gate_identity": gate_identity,
                            "superseded_by_action_id": "user_goal",
                            "supersession_reason": item.supersession_reason,
                            "superseded_at": item.superseded_at,
                        }
                    )
                equivalent = next(
                    (
                        existing
                        for existing in self._session.queue
                        if existing.gate_identity == gate_identity
                    ),
                    None,
                )
                if equivalent is not None:
                    self._session.governance_records.append(
                        {
                            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                            "event_type": "equivalent_gate_merged",
                            "action_id": run_env.action_id,
                            "gate_identity": gate_identity,
                            "merged_into_action_id": equivalent.action_id,
                            "timestamp": _now_iso(),
                        }
                    )
                    continue

            operations = list(run_env.candidate.get("structured_operations") or [])
            if operations:
                workspace = (
                    validate_workspace_path(self._session.bounded_executor_workspace)
                    if self._session.bounded_executor_workspace
                    else None
                )
                for operation in operations:
                    rel_path = normalize_workspace_relative_path(
                        str(operation.get("path") or ".")
                    )
                    target = (
                        validate_relative_path_inside_workspace(workspace, rel_path)
                        if workspace
                        else None
                    )
                    observed_sha = (
                        current_file_sha256(target)
                        if target is not None and target.is_file()
                        else None
                    )
                    item.operation_fingerprints.append(
                        canonical_operation_fingerprint(
                            operation, observed_sha256=observed_sha
                        )
                    )
            noop_records, pending_operations = _preclassify_noop_operations(
                self._session,
                action_id=run_env.action_id,
                operations=operations,
                workspace_path=self._session.bounded_executor_workspace,
            )
            if noop_records:
                self._session.operation_records.extend(noop_records)
            if operations and not pending_operations:
                item.operation_outcome = (
                    "duplicate_noop"
                    if any(record.get("outcome") == "duplicate_noop" for record in noop_records)
                    else "already_satisfied_noop"
                )
                item.execution_status = EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
                item.lifecycle_status = LIFECYCLE_CLOSED
                item.execution_record = {
                    "action_id": run_env.action_id,
                    "execution_status": EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
                    "execution_actor": "bounded_executor",
                    "execution_timestamp": _now_iso(),
                    "execution_evidence": {
                        "operations": [dict(record) for record in noop_records],
                        "notes": "No file operation executed; canonical no-op classification.",
                    },
                }
                run_env.candidate["execution_status"] = item.execution_status
                run_env.candidate["execution_record"] = item.execution_record
            elif any(
                _safe_overwrite_review_required(
                    self._session,
                    operation=operation,
                    workspace_path=self._session.bounded_executor_workspace,
                )
                for operation in pending_operations
            ):
                item.safe_overwrite_review_required = True
                run_env.candidate["requires_safe_overwrite_review"] = True

            self._session.run_envelopes[run_env.action_id] = run_env
            self._session.queue.append(item)
            new_action_ids.append(run_env.action_id)

        extraction_report = build_agent_response_extraction_report(
            raw_text,
            built=built,
            completion_candidate=completion_candidate,
            session=self._session,
            workspace_path=self._session.bounded_executor_workspace,
        )
        goal_text = str(long_run_prompt or "")
        avoid_optional = "avoid optional polish" in goal_text.lower()
        coverage_report = build_proposal_coverage_report(
            goal_text=goal_text,
            structured_operations=all_structured_operations,
            satisfied_paths=latest_file_hashes(self._session.operation_records),
            avoid_optional_polish=avoid_optional,
        )
        extraction_report["proposal_coverage"] = coverage_report
        optional_classifications = classify_optional_write_paths(coverage_report)
        for record in self._session.operation_records:
            path = str(record.get("path") or "")
            if path in optional_classifications:
                record["classification"] = optional_classifications[path]
        if self._session.high_autonomy_run is not None:
            self._session.high_autonomy_run["last_proposal_coverage_report"] = coverage_report
        if not coverage_report.get("coverage_complete"):
            self._session.governance_records.append(
                {
                    "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                    "event_type": "proposal_coverage_incomplete",
                    "missing_required_paths": list(coverage_report.get("missing_required_paths") or []),
                    "additional_paths": list(coverage_report.get("additional_paths") or []),
                    "timestamp": _now_iso(),
                }
            )
        if extraction_report.get("extraction_failed"):
            failed_record = AgentResponseRecord(
                record_id=f"agent_response_{uuid.uuid4().hex[:12]}",
                turn_number=turn_number,
                created_at=_now_iso(),
                raw_text=raw_text,
                source_trust="unverified_agent_output",
                actor="external_frontier_agent",
                action_ids=[],
                builder_version=None,
                extraction_report=extraction_report,
            )
            run_loop.response_records.append(failed_record)
            if run_loop.turns and run_loop.turns[-1].agent_response_record_id is None:
                run_loop.turns[-1].agent_response_record_id = failed_record.record_id
            self._session.transcript.append(
                _transcript_entry(
                    "agent_response_extraction_failed",
                    {
                        "record_id": failed_record.record_id,
                        "turn_number": turn_number,
                        "extraction_report": extraction_report,
                    },
                )
            )
            self._persist()
            raise ResponseExtractionFailed(
                "response_extraction_failed: structured markers present but zero actions survived"
            )

        if completion_candidate is not None and self._session.high_autonomy_run is not None:
            known_criterion_ids = {
                str(item.get("criterion_id"))
                for item in self._session.high_autonomy_run.get("acceptance_criteria") or []
            }
            claimed_ids = {
                str(item.get("criterion_id"))
                for item in completion_candidate.get("criteria") or []
                if item.get("criterion_id")
            }
            completion_candidate["unknown_criterion_ids"] = sorted(
                claimed_ids - known_criterion_ids
            )
            completion_candidate["advisory_only"] = True
            self._session.high_autonomy_run["completion_candidate"] = completion_candidate
            self._session.high_autonomy_run["completion_candidate_received_at"] = _now_iso()

        record = AgentResponseRecord(
            record_id=f"agent_response_{uuid.uuid4().hex[:12]}",
            turn_number=turn_number,
            created_at=_now_iso(),
            raw_text=raw_text,
            source_trust="unverified_agent_output",
            actor="external_frontier_agent",
            action_ids=new_action_ids,
            builder_version=(built[0]["candidate"].get("builder_version") if built else None),
            extraction_report=extraction_report,
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
                    "extraction_report": extraction_report,
                    "completion_candidate": completion_candidate,
                    "note": (
                        "Raw response is unverified agent output; action candidates were "
                        "extracted and evaluated by the existing offline builder/evaluator, "
                        "not executed."
                    ),
                },
            )
        )
        self._persist()
        ha_state = self._high_autonomy_state()
        if ha_state is not None and ha_state.active:
            from admissible.high_autonomy_controller import (
                _ingest_success_state,
                _save_ha_state,
                _sync_counters,
            )
            from admissible.high_autonomy_policy import HighAutonomyPolicy
            from admissible.governed_run import sha256_text as _sha256_text

            policy = HighAutonomyPolicy()
            _ingest_success_state(
                self,
                ha_state,
                response_sha256=_sha256_text(raw_text),
                event="Agent response ingested via control surface.",
                policy=policy,
            )
            _sync_counters(self, ha_state, policy)
            _save_ha_state(self, ha_state)
            self._persist()
        return self.state_view()

    def reextract_last_agent_response(self) -> dict[str, Any]:
        """Re-run local extraction on the latest stored agent response without a provider call."""

        run_loop = self._session.run_loop
        if not run_loop.response_records:
            raise ValueError("No agent response is available for local re-extraction.")
        record = run_loop.response_records[-1]
        if record.action_ids:
            raise ValueError(
                "Local re-extraction applies only to responses that previously yielded zero actions."
            )
        ha = self._session.high_autonomy_run
        if isinstance(ha, dict):
            ha["local_reextraction_attempt_count"] = int(
                ha.get("local_reextraction_attempt_count") or 0
            ) + 1
        run_loop.response_records.pop()
        if run_loop.turns:
            run_loop.turns[-1].agent_response_record_id = None
        return self.ingest_agent_response(record.raw_text)

    # -- high-autonomy governed loop (slice ADMISSIBLE_RUN_029) ---------------

    def set_high_autonomy_transport(self, transport: Any) -> None:
        """Attach a transport for tests or custom bridge implementations."""
        self._high_autonomy_transport = transport

    def start_high_autonomy_run(
        self,
        *,
        workspace_path: str,
        max_turns: int = 12,
        transport: Any = None,
        backend: Any = None,
        backend_id: str | None = None,
        agent_workspace_path: str | None = None,
        closure_reserve_turns: int = 2,
        max_structured_operations_per_response: int = 8,
        max_total_proposed_write_bytes: int = 256 * 1024,
        acceptance_criteria: list[str | dict[str, Any]] | None = None,
        automatic_empty_success_retries: int = 0,
    ) -> dict[str, Any]:
        from admissible.high_autonomy_controller import start_high_autonomy_run

        return start_high_autonomy_run(
            self,
            workspace_path=workspace_path,
            transport=transport,
            backend=backend,
            backend_id=backend_id,
            agent_workspace_path=agent_workspace_path,
            max_turns=max_turns,
            closure_reserve_turns=closure_reserve_turns,
            max_structured_operations_per_response=max_structured_operations_per_response,
            max_total_proposed_write_bytes=max_total_proposed_write_bytes,
            acceptance_criteria=acceptance_criteria,
            automatic_empty_success_retries=automatic_empty_success_retries,
        )

    def pause_high_autonomy_run(self) -> dict[str, Any]:
        from admissible.high_autonomy_controller import pause_high_autonomy_run

        return pause_high_autonomy_run(self)

    def resume_high_autonomy_run(self) -> dict[str, Any]:
        from admissible.high_autonomy_controller import resume_high_autonomy_run

        return resume_high_autonomy_run(self)

    def retry_callable_backend_invocation(self) -> dict[str, Any]:
        from admissible.high_autonomy_controller import retry_callable_backend_invocation

        return retry_callable_backend_invocation(self)

    def waive_high_autonomy_acceptance_criterion(
        self, criterion_id: str, *, rationale: str
    ) -> dict[str, Any]:
        """Record an explicit human waiver; a model completion claim cannot do this."""

        if not rationale.strip():
            raise ValueError("acceptance criterion waiver requires a human rationale")
        from admissible.high_autonomy_controller import HighAutonomyRunState

        ha_state = HighAutonomyRunState.from_dict(self._session.high_autonomy_run)
        criterion = next(
            (
                item
                for item in ha_state.acceptance_criteria
                if item.get("criterion_id") == criterion_id
            ),
            None,
        )
        if criterion is None:
            raise ValueError(f"unknown acceptance criterion id: {criterion_id!r}")
        record_id = f"governance_{uuid.uuid4().hex[:12]}"
        criterion["status"] = "waived"
        criterion.setdefault("evidence_refs", []).append(record_id)
        criterion.setdefault("verification_notes", []).append(
            f"Human waiver: {rationale.strip()}"
        )
        self._session.governance_records.append(
            {
                "record_id": record_id,
                "event_type": "acceptance_criterion_waived",
                "criterion_id": criterion_id,
                "actor": HUMAN_DECISION_ACTOR,
                "rationale": rationale.strip(),
                "timestamp": _now_iso(),
            }
        )
        self._session.high_autonomy_run = ha_state.to_dict()
        self._persist()
        return self.state_view()

    def stop_high_autonomy_run(self, *, reason: str = "Stopped by operator.") -> dict[str, Any]:
        from admissible.high_autonomy_controller import stop_high_autonomy_run

        return stop_high_autonomy_run(self, reason=reason)

    def tick_high_autonomy_run(self, *, policy: Any = None) -> dict[str, Any]:
        from admissible.high_autonomy_controller import tick_high_autonomy_run
        if not self._high_autonomy_tick_lock.acquire(blocking=False):
            state = self.state_view()
            state["high_autonomy_tick"] = {
                "step": "tick_already_in_progress",
                "reason": "single_flight_session_tick",
            }
            state["tick_already_in_progress"] = True
            return state
        try:
            return tick_high_autonomy_run(self, policy=policy)
        finally:
            self._high_autonomy_tick_lock.release()

    def approve_high_autonomy_human_action(
        self, action_id: str | None = None, *, rationale: str = "", scope: str | None = None
    ) -> dict[str, Any]:
        from admissible.high_autonomy_controller import approve_human_critical_action

        return approve_human_critical_action(
            self,
            action_id=(action_id or None),
            rationale=rationale or "Approved in high-autonomy human-required state.",
            scope=scope or None,
        )

    def refuse_high_autonomy_human_action(
        self, action_id: str | None = None, *, rationale: str = ""
    ) -> dict[str, Any]:
        from admissible.high_autonomy_controller import refuse_human_critical_action

        return refuse_human_critical_action(
            self,
            action_id=(action_id or None),
            rationale=rationale or "Refused in high-autonomy human-required state.",
        )

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
        raw_satisfies = body.get("satisfies")
        satisfies = normalize_evidence_satisfies(raw_satisfies, evidence_type)
        source = str(body.get("source") or "human").strip()
        if source not in EVIDENCE_SOURCES:
            source = "human"
        sha256 = body.get("sha256") or None

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
            source=source,
            satisfies=satisfies,
            sha256=sha256,
            turn_number=self._session.run_loop.current_turn or None,
        )
        self._session.run_loop.evidence_records.append(record)

        action_evidence_records = [
            r for r in self._session.run_loop.evidence_records if r.action_id == action_id
        ]
        structured_evidence = [_structured_evidence_payload(r) for r in action_evidence_records]

        new_decision = None
        if envelope is not None and envelope.envelope is not None:
            new_decision = reevaluate_envelope_with_evidence(
                envelope.envelope,
                structured_evidence=structured_evidence,
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
            _apply_evidence_attention_to_item(
                item,
                envelope,
                evidence_records=self._session.run_loop.evidence_records,
                latest_record=record,
                effective_decision=new_decision,
            )
        else:
            effective_decision = (
                envelope.decision
                if envelope is not None
                else {
                    "decision": item.decision,
                    "missing_evidence": list(item.missing_evidence),
                    "reasons": [],
                }
            )
            _apply_evidence_attention_to_item(
                item,
                envelope,
                evidence_records=self._session.run_loop.evidence_records,
                latest_record=record,
                effective_decision=effective_decision,
                without_envelope_reevaluation=True,
            )

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
    "NoGoalSubmittedError",
    "SessionNotEmptyError",
    "GOAL_REQUIRED_REASON",
    "SESSION_NOT_EMPTY_REASON",
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
    "LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION",
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
