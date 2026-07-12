"""High-autonomy governed run controller v0 — tick-driven state machine.

One safe step per ``tick_high_autonomy_run`` call. No hidden background loops.
"""

from __future__ import annotations

import uuid
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from admissible.agent_transport import AgentTransport

from admissible.high_autonomy_policy import HighAutonomyPolicy, open_executable_low_risk_actions
from admissible.governed_run import (
    DEFAULT_CLOSURE_RESERVE_TURNS,
    DEFAULT_MAX_REPAIR_ROUNDS,
    DEFAULT_MAX_STRUCTURED_OPERATIONS_PER_RESPONSE,
    DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES,
    DEFAULT_OUTCOME_IN_PROGRESS,
    FINAL_OUTCOMES,
    ResponseExtractionFailed,
    acceptance_counts,
    active_blocking_action_ids,
    build_canonical_metrics,
    build_repair_instruction_text,
    build_repair_packet,
    failed_mandatory_criteria,
    latest_file_hashes,
    make_acceptance_ledger,
    migrate_high_autonomy_projection,
    repair_inconsistent_executable_lifecycle,
)
from admissible.run_loop import (
    CONTINUATION_STATUS_EVIDENCE_GROUNDED,
    CONTINUATION_STATUS_FIRST_TURN,
    CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION,
)

if TYPE_CHECKING:
    from admissible.control_surface import ControlSurfaceController

HIGH_AUTONOMY_SCHEMA_VERSION = "admissible_high_autonomy_run_v0"

HA_MODE_OFF = "off"
HA_MODE_RUNNING = "running"
HA_MODE_WAITING_FOR_AGENT = "waiting_for_agent"
HA_MODE_REVIEWING = "reviewing"
HA_MODE_AUTO_EXECUTING = "auto_executing"
HA_MODE_RECOVERING = "recovering"
HA_MODE_VERIFYING = "verifying"
HA_MODE_HUMAN_REQUIRED = "human_required"
HA_MODE_PAUSED = "paused"
HA_MODE_STOPPED = "stopped"
HA_MODE_FAILED = "failed"
# RUN_044: runtime-verification-specific modes, kept distinct from
# HA_MODE_VERIFYING (static bounded verification) and HA_MODE_HUMAN_REQUIRED
# (human-authority approval) so the Control Surface can show a distinct
# banner and so a pending human observation is never counted as a human-
# authority interruption.
HA_MODE_RUNTIME_VERIFYING = "runtime_verifying"
HA_MODE_AWAITING_HUMAN_OBSERVATION = "awaiting_human_observation"
# RUN_045 PART E: a run that produced the same reasonless-wait fingerprint
# twice in a row stops here -- distinct from human_required (no human
# authority decision is pending) and from internal_livelock (that label is
# reserved for contradictory *execution* state, not a stuck wait).
HA_MODE_TECHNICAL_PAUSE = "technical_pause"

HA_NEXT_NONE = "none"
HA_NEXT_WRITE_INSTRUCTION = "write_instruction"
HA_NEXT_WAIT_FOR_RESPONSE = "wait_for_agent_response"
HA_NEXT_INGEST_RESPONSE = "ingest_response"
HA_NEXT_AUTO_EXECUTE = "auto_execute_low_risk"
HA_NEXT_WRITE_RECOVERY = "write_recovery_instruction"
HA_NEXT_WRITE_REPAIR = "write_repair_instruction"
HA_NEXT_VERIFY = "run_bounded_verification"
HA_NEXT_HUMAN_APPROVAL = "human_approval_required"
HA_NEXT_STOP = "stop"
# RUN_044: runtime orchestration next-actions. None of these are a model/
# provider turn (PART E.15); prepare+capability-check+start are one fast
# synchronous tick, poll/apply are later bounded, non-blocking ticks.
HA_NEXT_START_RUNTIME_VERIFICATION = "start_runtime_verification"
HA_NEXT_POLL_RUNTIME_VERIFICATION = "poll_runtime_verification"
HA_NEXT_APPLY_RUNTIME_EVIDENCE = "apply_runtime_evidence"
HA_NEXT_AWAIT_HUMAN_OBSERVATION = "await_human_observation"

HA_STEP_INTERNAL_LIVELOCK = "internal_livelock"
HA_STEP_RESPONSE_EXTRACTION_FAILED = "response_extraction_failed"
HA_STEP_INTERNAL_EXECUTION_MISMATCH = "internal_execution_state_mismatch"

REPAIR_PHASE_NONE = "none"
REPAIR_PHASE_VERIFICATION_FAILED_REPAIRABLE = "verification_failed_repairable"
REPAIR_PHASE_REPAIR_NEEDED = "repair_needed"
REPAIR_PHASE_WRITING_REPAIR_INSTRUCTION = "writing_repair_instruction"
REPAIR_PHASE_AWAITING_REPAIR_RESPONSE = "awaiting_repair_response"
REPAIR_PHASE_REPAIR_EXECUTING = "repair_executing"
REPAIR_PHASE_REPAIR_VERIFYING = "repair_verifying"

DEFAULT_MAX_TURNS = 12
DEFAULT_MALFORMED_RETRY_LIMIT = 1
MAX_NO_PROGRESS_TICKS = 2

# Terminal persisted invocation statuses — pause until explicit operator retry.
_TERMINAL_INVOCATION_RECORD_STATUSES = frozenset(
    {
        "timeout",
        "failed",
        "malformed",
        "empty_success",
    }
)

# Mirrors admissible.agent_transport.TRANSPORT_STATUS_MALFORMED_RETRY; kept as a
# local literal so the controller never needs a module-level transport import.
_TRANSPORT_STATUS_MALFORMED_RETRY = "malformed_response_retry"

_RECOVERY_PREAMBLE = (
    "RECOVERY REQUEST: prior turn proposed blocked dependency/deploy/network actions "
    "that must NOT be treated as done. Propose the smallest local-only admissible "
    "alternative — no npm, pip, shell, network, CDN, or deploy."
)

_REFUSAL_RECOVERY_PREAMBLE = (
    "RECOVERY REQUEST (human refusal): a human refused the human-critical action(s) "
    "listed below. They are NOT completed and must NOT be retried in their "
    "forbidden/human-critical form. Propose the next smallest admissible LOCAL-ONLY "
    "structured file operation that makes progress without them. Do not use shell, "
    "npm, pip, git push/commit, publish, deploy, network, CDN, secrets/env, or any "
    "path outside the workspace. Write only .admissible/agent-response.md."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class HighAutonomyRunState:
    """Persisted high-autonomy run controller state."""

    schema_version: str = HIGH_AUTONOMY_SCHEMA_VERSION
    active: bool = False
    mode: str = HA_MODE_OFF
    current_turn: int = 0
    last_event: str = ""
    next_action: str = HA_NEXT_NONE
    problem_summary: str = ""
    human_required_reason: str | None = None
    pending_low_risk_action_count: int = 0
    auto_executed_action_count: int = 0
    blocked_action_count: int = 0
    evidence_count: int = 0
    verification_readiness: str = "not_run"
    max_turns: int = DEFAULT_MAX_TURNS
    stop_reason: str | None = None
    paused: bool = False
    malformed_retry_count: int = 0
    last_response_cursor: str | None = None
    pending_human_action_id: str | None = None
    human_critical_pending: bool = False
    # Action-specific human-required state: every currently-open human-critical
    # action, so the UI/tests can show exactly what is blocking (not a generic
    # message) and refusal can clear all of them at once.
    human_required_action_ids: list[str] = field(default_factory=list)
    human_required_action_count: int = 0
    human_required_actions: list[dict[str, Any]] = field(default_factory=list)
    # Set when a human refuses the open human-critical action(s); drives the
    # next tick to compose a bounded local-only recovery instruction. Kept
    # separate from recovery_pending (recoverable-blocker recovery) so
    # _sync_counters never clobbers it.
    refusal_recovery_pending: bool = False
    last_refused_action_ids: list[str] = field(default_factory=list)
    awaiting_instruction_after_review: bool = False
    recovery_pending: bool = False
    recovery_attempted: bool = False
    transport_kind: str = "file_bridge"
    # Model-agnostic backend fields (slice ADMISSIBLE_RUN_032; display-only).
    backend_id: str | None = None
    agent_workspace_path: str | None = None
    backend_block_reason: str | None = None
    # Durable callable-backend response handoff (slice ADMISSIBLE_RUN_034).
    # A callable backend's response is persisted here — NOT only on the in-memory
    # transport — so it survives controller/transport reconstruction between HTTP
    # ticks and is ingested exactly once. Empty for the file-bridge transport.
    pending_agent_invocation: dict[str, Any] | None = None
    last_invocation_id: str | None = None
    last_consumed_invocation_id: str | None = None
    last_consumed_response_sha256: str | None = None
    backend_step: str | None = None
    backend_retry_required: bool = False
    backend_reinvoke_pending: bool = False
    # Live-rehearsal transport/bridge fields (display-only; not an authority).
    transport_status: str = "idle"
    workspace_path: str | None = None
    instruction_path: str | None = None
    response_path: str | None = None
    stale_response_blocked: bool = False
    started_at: str | None = None
    last_tick_at: str | None = None
    last_tick_step: str | None = None
    tick_count: int = 0
    # Cost-aware response bounds and reserved closure budget.
    max_structured_operations_per_response: int = (
        DEFAULT_MAX_STRUCTURED_OPERATIONS_PER_RESPONSE
    )
    max_total_proposed_write_bytes: int = DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES
    closure_reserve_turns: int = DEFAULT_CLOSURE_RESERVE_TURNS
    phase: str = "work"
    closure_phase_status: str = "not_started"
    work_turns_used: int = 0
    verification_turns_used: int = 0
    closure_turns_used: int = 0
    turns_remaining: int = DEFAULT_MAX_TURNS
    # Durable acceptance/completion contract.
    acceptance_criteria: list[dict[str, Any]] = field(default_factory=list)
    completion_candidate: dict[str, Any] | None = None
    completion_candidate_received_at: str | None = None
    outcome: str | None = DEFAULT_OUTCOME_IN_PROGRESS
    outcome_reason: str | None = None
    completed_criteria: list[str] = field(default_factory=list)
    unmet_criteria: list[str] = field(default_factory=list)
    pending_useful_operations: list[str] = field(default_factory=list)
    repair_phase: str = REPAIR_PHASE_NONE
    repair_round_count: int = 0
    max_repair_rounds: int = DEFAULT_MAX_REPAIR_ROUNDS
    repair_packet: dict[str, Any] | None = None
    repair_history: list[dict[str, Any]] = field(default_factory=list)
    last_proposal_coverage_report: dict[str, Any] | None = None
    contract_ledger_coverage_report: dict[str, Any] | None = None
    verification_plan_coverage_report: dict[str, Any] | None = None
    proposal_contract_conformance_report: dict[str, Any] | None = None
    instruction_fidelity_report: dict[str, Any] | None = None
    completion_eligibility_report: dict[str, Any] | None = None
    # Durable invocation lineage and visible retry/cost markers.
    invocation_history: list[dict[str, Any]] = field(default_factory=list)
    operator_retry_count: int = 0
    automatic_empty_success_retries: int = 0
    automatic_empty_success_retry_used: bool = False
    pending_retry_of_invocation_id: str | None = None
    metrics: dict[str, int] = field(default_factory=dict)
    current_step: str | None = None
    no_progress_tick_count: int = 0
    auto_tick_safe: bool = True
    last_progress_fingerprint: str | None = None
    extraction_failure_count: int = 0
    local_reextraction_attempt_count: int = 0
    pending_executable_selection_failures: list[dict[str, Any]] = field(default_factory=list)
    # RUN_044: bounded browser-runtime verification orchestration (durable
    # run-level fields; see admissible.runtime_verification_orchestrator and
    # admissible.runtime_orchestration_models for the attempt schema itself).
    runtime_verification_required: bool = False
    runtime_verification_status: str = "not_applicable"
    active_runtime_attempt_id: str | None = None
    # Full durable snapshot of the in-flight attempt/plan (beyond just the id)
    # so a reconstructed controller can resume polling/applying across ticks
    # and process restarts without holding anything only in memory.
    active_runtime_attempt: dict[str, Any] | None = None
    active_runtime_plan: dict[str, Any] | None = None
    runtime_attempt_history: list[dict[str, Any]] = field(default_factory=list)
    last_runtime_plan_sha256: str | None = None
    last_runtime_evidence_id: str | None = None
    runtime_criterion_ids: list[str] = field(default_factory=list)
    runtime_pending_criterion_ids: list[str] = field(default_factory=list)
    runtime_failed_criterion_ids: list[str] = field(default_factory=list)
    runtime_gap_criterion_ids: list[str] = field(default_factory=list)
    human_observation_pending_criterion_ids: list[str] = field(default_factory=list)
    human_observation_records: list[dict[str, Any]] = field(default_factory=list)
    runtime_capability_report: dict[str, Any] | None = None
    runtime_coverage_report: dict[str, Any] | None = None
    runtime_repair_kind: str | None = None
    # RUN_045 PART B.4: every `wait` transition must identify a durable,
    # typed reason -- never a generic reasonless wait (see
    # admissible.high_autonomy_state_invariants.SUPPORTED_WAIT_CONDITIONS).
    wait_reason: str | None = None
    wait_condition_type: str | None = None
    wait_condition_id: str | None = None
    wait_started_at: str | None = None
    wait_timeout_at: str | None = None
    expected_state_change: str | None = None
    wait_poll_count: int = 0
    # RUN_045 PART E: technical-pause state (distinct from human_required /
    # internal_livelock) for a run that produced the same reasonless-wait
    # fingerprint twice in a row.
    technical_pause_active: bool = False
    technical_pause_reason: str | None = None
    state_invariant_violations: list[dict[str, Any]] = field(default_factory=list)
    last_reconciliation: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "HighAutonomyRunState":
        if not data:
            return cls()
        migrated = migrate_high_autonomy_projection(data)
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {key: value for key, value in migrated.items() if key in known}
        return cls(**filtered)


def _transcript_entry(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"timestamp": _now_iso(), "event_type": event_type, "payload": payload}


def _append_coalesced_transcript(
    controller: "ControlSurfaceController",
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """Coalesce repeated identical transcript events."""

    transcript = controller._session.transcript
    if transcript:
        last = transcript[-1]
        if last.get("event_type") == event_type and last.get("payload") == payload:
            coalesced = last.setdefault("coalesced", {"first_at": last.get("timestamp")})
            coalesced["last_at"] = _now_iso()
            coalesced["repetition_count"] = int(coalesced.get("repetition_count") or 1) + 1
            return
    transcript.append(_transcript_entry(event_type, payload))


def _executable_actions(
    controller: "ControlSurfaceController",
    policy: HighAutonomyPolicy,
) -> list[dict[str, Any]]:
    session = controller._session
    return open_executable_low_risk_actions(
        queue=session.queue,
        run_envelopes=session.run_envelopes,
        workspace_path=session.bounded_executor_workspace,
        policy=policy,
    )


def _non_executable_pending_reasons(
    controller: "ControlSurfaceController",
    policy: HighAutonomyPolicy,
) -> list[dict[str, Any]]:
    session = controller._session
    executable_ids = {entry["action_id"] for entry in _executable_actions(controller, policy)}
    reasons: list[dict[str, Any]] = []
    for item in session.queue:
        action_id = getattr(item, "action_id", "")
        if action_id in executable_ids:
            continue
        if getattr(item, "execution_status", None) != "proposed_only":
            continue
        if getattr(item, "superseded_at", None):
            continue
        envelope = session.run_envelopes.get(action_id)
        classification = policy.classify_action(
            item=item,
            envelope=envelope,
            workspace_path=session.bounded_executor_workspace,
        )
        if classification.category == "auto_executable":
            continue
        if item.decision == "ALLOW" and item.operational_admissibility_action == "execute":
            reasons.append(
                {
                    "action_id": action_id,
                    "reason": classification.reason,
                    "lifecycle_status": item.lifecycle_status,
                }
            )
    return reasons


def _build_progress_fingerprint(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    policy: HighAutonomyPolicy,
) -> str:
    import json as _json

    executable = _executable_actions(controller, policy)
    view = controller.state_view()
    timeline = view.get("run_timeline") or {}
    latest_response_id = None
    records = controller._session.run_loop.response_records
    if records:
        latest_response_id = records[-1].record_id
    payload = {
        "current_step": ha_state.current_step or ha_state.last_tick_step,
        "mode": ha_state.mode,
        "pending_executable_action_ids": [entry["action_id"] for entry in executable],
        "pending_useful_operation_ids": list(ha_state.pending_useful_operations),
        "latest_response_id": latest_response_id,
        "latest_invocation_id": ha_state.last_invocation_id,
        "executed_count": timeline.get("executed_count", 0),
        "acceptance_statuses": [
            (item.get("criterion_id"), item.get("status"))
            for item in ha_state.acceptance_criteria
        ],
        "phase": ha_state.phase,
        "outcome": ha_state.outcome,
        # RUN_044: an attempt resolving (queued -> running -> evidence_ready
        # -> evidence_applied) is real progress even when nothing else above
        # changes tick-to-tick.
        "active_runtime_attempt_id": ha_state.active_runtime_attempt_id,
        "runtime_verification_status": ha_state.runtime_verification_status,
        "last_runtime_evidence_id": ha_state.last_runtime_evidence_id,
    }
    return _json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _pause_for_response_extraction_failed(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    *,
    reason: str,
    invocation_id: str | None = None,
) -> None:
    ha_state.mode = HA_MODE_PAUSED
    ha_state.paused = True
    ha_state.auto_tick_safe = False
    ha_state.current_step = HA_STEP_RESPONSE_EXTRACTION_FAILED
    ha_state.extraction_failure_count += 1
    ha_state.stop_reason = reason
    ha_state.last_event = reason
    ha_state.last_tick_step = HA_STEP_RESPONSE_EXTRACTION_FAILED
    ha_state.next_action = HA_NEXT_NONE
    ha_state.awaiting_instruction_after_review = False
    _append_coalesced_transcript(
        controller,
        "high_autonomy_response_extraction_failed",
        {"reason": reason, "invocation_id": invocation_id},
    )


def _pause_for_internal_execution_mismatch(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    *,
    pending_ids: list[str],
    selection_failures: list[dict[str, Any]],
) -> None:
    ha_state.mode = HA_MODE_PAUSED
    ha_state.paused = True
    ha_state.auto_tick_safe = False
    ha_state.current_step = HA_STEP_INTERNAL_EXECUTION_MISMATCH
    reason = (
        "Internal execution state mismatch — no provider call required. "
        f"Pending executable action(s): {', '.join(pending_ids) or 'none'}."
    )
    ha_state.stop_reason = reason
    ha_state.human_required_reason = reason
    ha_state.last_event = reason
    ha_state.last_tick_step = HA_STEP_INTERNAL_EXECUTION_MISMATCH
    ha_state.next_action = HA_NEXT_NONE
    ha_state.pending_executable_selection_failures = selection_failures
    _append_coalesced_transcript(
        controller,
        "high_autonomy_internal_execution_state_mismatch",
        {
            "pending_executable_action_ids": pending_ids,
            "selection_failures": selection_failures,
        },
    )


def _pause_for_no_progress_livelock(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    *,
    fingerprint: str,
) -> None:
    ha_state.mode = HA_MODE_PAUSED
    ha_state.paused = True
    ha_state.auto_tick_safe = False
    ha_state.current_step = HA_STEP_INTERNAL_LIVELOCK
    reason = (
        "Internal execution state mismatch — no provider call required. "
        f"Repeated no-progress fingerprint observed ({ha_state.no_progress_tick_count} tick(s))."
    )
    ha_state.stop_reason = reason
    ha_state.human_required_reason = reason
    ha_state.last_event = reason
    ha_state.last_tick_step = HA_STEP_INTERNAL_LIVELOCK
    ha_state.next_action = HA_NEXT_NONE
    _append_coalesced_transcript(
        controller,
        "high_autonomy_internal_livelock",
        {
            "fingerprint": fingerprint,
            "no_progress_tick_count": ha_state.no_progress_tick_count,
        },
    )


def _pause_for_technical_state_invariant(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    *,
    fingerprint: str,
    violation_code: str,
) -> None:
    """RUN_045 PART E: a reasonless wait (mode=waiting_for_agent with no
    legitimate pending condition) that repeated the same fingerprint twice.

    Distinct from `_pause_for_no_progress_livelock`/`internal_livelock`,
    which stays reserved for a genuine contradictory *execution* state
    (queue/operation mismatch) -- this is specifically a stuck *wait*, and
    auto-run must stop without ever invoking the backend again.
    """

    ha_state.mode = HA_MODE_TECHNICAL_PAUSE
    ha_state.paused = True
    ha_state.auto_tick_safe = False
    ha_state.technical_pause_active = True
    reason = (
        "Technical pause — a reasonless wait (no legitimate pending backend/runtime/"
        f"human condition) repeated the same fingerprint twice ({violation_code})."
    )
    ha_state.technical_pause_reason = reason
    ha_state.stop_reason = reason
    ha_state.last_event = reason
    ha_state.last_tick_step = "technical_pause"
    ha_state.next_action = HA_NEXT_NONE
    ha_state.current_step = None
    _append_coalesced_transcript(
        controller,
        "high_autonomy_technical_pause",
        {"fingerprint": fingerprint, "violation_code": violation_code},
    )


def _build_refusal_recovery_text(
    *,
    refused_actions: list[dict[str, Any]],
    continuation_text: str = "",
) -> str:
    """Compose a bounded local-only recovery instruction after a human refusal.

    Grounds the request in the exact refused human-critical action(s) so the
    agent does not retry them, and appends the evidence-grounded continuation
    instruction when one is available. Adds no new capability: it only asks for
    the next smallest admissible local-only structured operation.
    """
    lines = [_REFUSAL_RECOVERY_PREAMBLE, ""]
    if refused_actions:
        lines.append("Refused human-critical action(s) — do NOT retry these forms:")
        for entry in refused_actions:
            label = (
                entry.get("tool_or_command")
                or entry.get("action_type")
                or entry.get("action_id")
                or "action"
            )
            reason = entry.get("reason")
            action_type = entry.get("action_type")
            prefix = f"{action_type}: " if action_type else ""
            suffix = f" — {reason}" if reason else ""
            lines.append(f"- {prefix}{label}{suffix}")
        lines.append("")
    if continuation_text.strip():
        lines.append(continuation_text.strip())
    return "\n".join(lines).strip()


def _refused_action_details(
    controller: "ControlSurfaceController",
    action_ids: list[str],
) -> list[dict[str, Any]]:
    """Reconstruct refused human-critical action labels for the recovery text.

    Rebuilt from the persisted queue at write-time so the recovery instruction
    stays grounded even across the tick's state persist/reload boundary.
    """
    policy = HighAutonomyPolicy()
    workspace = controller._session.bounded_executor_workspace
    details: list[dict[str, Any]] = []
    for aid in action_ids:
        item = controller._find_queue_item(aid)
        if item is None:
            details.append({"action_id": aid})
            continue
        envelope = controller._session.run_envelopes.get(aid)
        classification = policy.classify_action(
            item=item, envelope=envelope, workspace_path=workspace
        )
        details.append(
            {
                "action_id": aid,
                "action_type": item.action_type,
                "tool_or_command": item.tool_or_command,
                "reason": classification.reason,
            }
        )
    return details


def build_high_autonomy_summary(
    *,
    ha_state: HighAutonomyRunState,
    state_view: dict[str, Any],
) -> dict[str, Any]:
    """Minimal high-autonomy summary for the primary UI panel."""
    timeline = state_view.get("run_timeline") or {}
    verification = state_view.get("verification_summary") or {}
    governed = state_view.get("governed_run_overview") or {}

    doing_now = {
        HA_MODE_OFF: "High-autonomy mode is off.",
        HA_MODE_RUNNING: "Preparing the next governed step.",
        HA_MODE_WAITING_FOR_AGENT: "Waiting for the agent to write its response file.",
        HA_MODE_REVIEWING: "Reviewing the latest agent response.",
        HA_MODE_AUTO_EXECUTING: "Auto-executing admitted low-risk local writes.",
        HA_MODE_RECOVERING: "Composing a local-only recovery instruction.",
        HA_MODE_VERIFYING: "Running bounded verification checks.",
        HA_MODE_HUMAN_REQUIRED: "Paused — human authority required.",
        HA_MODE_PAUSED: "Paused by operator.",
        HA_MODE_STOPPED: "Governed run reached a final outcome.",
        HA_MODE_FAILED: "Failed.",
        HA_MODE_RUNTIME_VERIFYING: "Running bounded browser-runtime verification.",
        HA_MODE_AWAITING_HUMAN_OBSERVATION: "Awaiting human observation of subjective criteria.",
        HA_MODE_TECHNICAL_PAUSE: "Technical pause — a reasonless wait was detected twice.",
    }.get(ha_state.mode, ha_state.mode)

    needed_now = {
        HA_NEXT_NONE: "No action required.",
        HA_NEXT_WRITE_INSTRUCTION: "Controller will write the next instruction automatically.",
        HA_NEXT_WAIT_FOR_RESPONSE: "Agent must write `.admissible/agent-response.md`.",
        HA_NEXT_INGEST_RESPONSE: "Controller will ingest the agent response on the next tick.",
        HA_NEXT_AUTO_EXECUTE: "Controller will auto-execute low-risk local writes.",
        HA_NEXT_WRITE_RECOVERY: "Controller will request a local-only recovery step.",
        HA_NEXT_WRITE_REPAIR: "Controller will request a targeted verification repair.",
        HA_NEXT_VERIFY: "Controller will run bounded verification.",
        HA_NEXT_HUMAN_APPROVAL: "Approve or refuse the human-critical action.",
        HA_NEXT_STOP: "Run is stopping.",
        HA_NEXT_START_RUNTIME_VERIFICATION: "Controller will start bounded browser-runtime verification.",
        HA_NEXT_POLL_RUNTIME_VERIFICATION: "Controller is waiting on the active runtime verification worker.",
        HA_NEXT_APPLY_RUNTIME_EVIDENCE: "Controller will apply runtime verification evidence.",
        HA_NEXT_AWAIT_HUMAN_OBSERVATION: "Record a human observation for the pending subjective criteria.",
    }.get(ha_state.next_action, ha_state.next_action)

    # Callable backends invoke the agent in-process; they never wait for an
    # external response file. Override the file-bridge-centric phrasing so the UI
    # never tells the operator to wait for `.admissible/agent-response.md`.
    is_callable_backend = ha_state.transport_kind == "callable_backend"
    backend_step = ha_state.backend_step
    backend_error = _callable_backend_error_summary(ha_state) if is_callable_backend else {}
    if is_callable_backend and _callable_terminal_failure_pending(ha_state):
        doing_now = "Cursor Agent invocation stopped before producing a usable proposal."
        needed_now = "Review diagnostics, then explicitly retry the backend invocation."
    elif is_callable_backend:
        callable_doing = {
            "invoking_agent": "Invoking the agent backend.",
            "response_ready": "Agent response ready — ingesting next.",
            "ingesting_response": "Ingesting the agent response.",
            "response_consumed": "Reviewing the ingested agent response.",
        }
        if ha_state.mode == HA_MODE_WAITING_FOR_AGENT:
            doing_now = callable_doing.get(backend_step, "Agent response ready — ingesting next.")
            needed_now = "Controller will ingest the agent response on the next tick."

    if ha_state.current_step in (
        HA_STEP_INTERNAL_EXECUTION_MISMATCH,
        HA_STEP_INTERNAL_LIVELOCK,
    ):
        doing_now = "Internal execution state mismatch — no provider call required"
        needed_now = (
            "Resolve the pending executable local action(s) or re-run local extraction; "
            "do not retry Cursor Agent for this condition."
        )
    elif ha_state.current_step == HA_STEP_RESPONSE_EXTRACTION_FAILED:
        doing_now = "Response extraction failed — local fix required"
        needed_now = "Repair extraction integration, then re-extract the preserved response locally."
    elif ha_state.repair_phase in (
        REPAIR_PHASE_REPAIR_NEEDED,
        REPAIR_PHASE_WRITING_REPAIR_INSTRUCTION,
    ):
        failed_count = len((ha_state.repair_packet or {}).get("failed_criteria") or [])
        doing_now = f"Preparing a targeted repair for {failed_count} failed criteria"
        needed_now = "No human action required"
    elif ha_state.repair_phase == REPAIR_PHASE_AWAITING_REPAIR_RESPONSE:
        doing_now = "Waiting for targeted repair response"
        needed_now = "No human action required"
    elif ha_state.repair_phase == REPAIR_PHASE_REPAIR_EXECUTING:
        doing_now = "Executing targeted repair operations"
        needed_now = "No human action required"
    elif ha_state.repair_phase == REPAIR_PHASE_REPAIR_VERIFYING:
        doing_now = "Re-verifying repaired criteria"
        needed_now = "No human action required"
    elif ha_state.mode == HA_MODE_RUNTIME_VERIFYING:
        attempt = ha_state.active_runtime_attempt or {}
        doing_now = f"Runtime verification ({attempt.get('provider_id') or 'browser'}): {ha_state.runtime_verification_status}"
        needed_now = "No human action required"
    elif ha_state.mode == HA_MODE_AWAITING_HUMAN_OBSERVATION:
        pending = ", ".join(ha_state.human_observation_pending_criterion_ids) or "none"
        doing_now = f"Awaiting human observation for: {pending}"
        needed_now = "Record an observed pass/fail, or an explicit waiver, for each pending criterion."

    verification_readiness = ha_state.verification_readiness or verification.get(
        "readiness", "not_run"
    )
    live_status = build_live_high_autonomy_rehearsal_status(
        ha_state=ha_state, state_view=state_view
    )
    pending_invocation = ha_state.pending_agent_invocation or {}
    acceptance = acceptance_counts(ha_state.acceptance_criteria)
    metrics = dict(ha_state.metrics or {})
    outcome_labels = {
        "in_progress": "In progress",
        "completed": "RUN COMPLETED — every mandatory contract criterion is satisfied.",
        "incomplete": "RUN INCOMPLETE — mandatory contract requirements remain unsatisfied.",
        "contract_incomplete": "MISSION CONTRACT INCOMPLETE — Admissible cannot safely continue or complete.",
        "acceptance_ledger_incomplete": "MISSION CONTRACT INCOMPLETE — acceptance ledger coverage is incomplete.",
        "verification_plan_incomplete": "VERIFICATION CAPABILITY GAP — the verification plan is incomplete.",
        "verification_capability_gap": "VERIFICATION CAPABILITY GAP — implementation may exist, but mandatory behavior has not been verified.",
        "runtime_observability_gap": "RUNTIME OBSERVABILITY GAP — mandatory behavior has no safe runtime observable.",
        "verification_plan_incomplete": "VERIFICATION CAPABILITY GAP — the runtime plan failed validation.",
        "awaiting_human_observation": "HUMAN ACTION REQUIRED — mandatory observation is pending.",
        "failed": "Failed",
        "stopped_by_budget": "Budget exhausted",
        "stopped_by_operator": "Stopped by operator",
    }
    projected_outcome = ha_state.outcome or DEFAULT_OUTCOME_IN_PROGRESS
    from admissible.browser_runtime.terminal_ui import select_runtime_banner

    runtime_banner_status = {
        HA_MODE_RUNTIME_VERIFYING: "runtime_verifying",
        HA_MODE_AWAITING_HUMAN_OBSERVATION: "awaiting_human_observation",
    }.get(ha_state.mode, ha_state.runtime_verification_status)
    runtime_banner = select_runtime_banner(
        runtime_banner_status, completion_eligible=(ha_state.outcome == "completed")
    )
    blocking_reason = ""
    if ha_state.human_required_reason:
        blocking_reason = ha_state.human_required_reason
    elif ha_state.repair_phase not in (REPAIR_PHASE_NONE, ""):
        blocking_reason = ""
    elif ha_state.unmet_criteria:
        blocking_reason = f"Unmet criteria: {', '.join(ha_state.unmet_criteria)}"
    return {
        "schema_version": HIGH_AUTONOMY_SCHEMA_VERSION,
        "active": ha_state.active,
        "mode": ha_state.mode,
        "current_turn": ha_state.current_turn or timeline.get("turn_count", 0),
        "last_event": ha_state.last_event,
        "next_action": ha_state.next_action,
        "doing_now": doing_now,
        "needed_now": needed_now,
        "problem_summary": ha_state.problem_summary,
        "human_required_reason": ha_state.human_required_reason,
        "human_action_required": ha_state.mode == HA_MODE_HUMAN_REQUIRED
        or ha_state.human_critical_pending,
        "pending_human_action_id": ha_state.pending_human_action_id,
        "human_required_action_ids": list(ha_state.human_required_action_ids),
        "human_required_action_count": ha_state.human_required_action_count,
        "human_required_actions": list(ha_state.human_required_actions),
        "pending_low_risk_action_count": ha_state.pending_low_risk_action_count,
        "auto_executed_action_count": ha_state.auto_executed_action_count,
        "blocked_action_count": metrics.get(
            "active_blocked_count", ha_state.blocked_action_count
        ),
        "evidence_count": ha_state.evidence_count or timeline.get("evidence_count", 0),
        "verification_readiness": verification_readiness,
        "verification_passed": verification_readiness == "pass",
        "max_turns": ha_state.max_turns,
        "stop_reason": ha_state.stop_reason,
        "paused": ha_state.paused,
        "primary_button": _primary_button(ha_state),
        "turn_count": timeline.get("turn_count", 0),
        "blocked_count": metrics.get(
            "active_blocked_count", ha_state.blocked_action_count
        ),
        "write_evidence_count": governed.get("write_evidence_count", 0),
        "tick_count": ha_state.tick_count,
        "transport_kind": ha_state.transport_kind,
        "backend_id": ha_state.backend_id,
        "is_callable_backend": is_callable_backend,
        "backend_step": backend_step,
        "last_invocation_id": ha_state.last_invocation_id,
        "pending_invocation_status": pending_invocation.get("status"),
        # RUN_049 PART K.48/51 -- the exact ACP sub-state, so the Control
        # Surface can show ACP-specific progress labels instead of the
        # generic "backend invocation running" text. ``None`` for any
        # non-ACP backend.
        "last_acp_invocation_state": pending_invocation.get("acp_invocation_state"),
        "agent_workspace_path": ha_state.agent_workspace_path,
        "backend_block_reason": ha_state.backend_block_reason,
        "backend_retry_required": ha_state.backend_retry_required,
        "backend_error": backend_error,
        # Live transport/bridge status (display-only) for the auto-tick UI.
        "transport_status": ha_state.transport_status,
        "workspace_path": ha_state.workspace_path,
        "instruction_path": ha_state.instruction_path,
        "response_path": ha_state.response_path,
        # A callable backend never waits on an external response file; only the
        # file bridge does. This flag drives the "Waiting for … response file" UI.
        "waiting_for_agent": ha_state.mode == HA_MODE_WAITING_FOR_AGENT
        and not is_callable_backend,
        "stale_response_blocked": ha_state.stale_response_blocked,
        "auto_tick_safe": _auto_tick_safe(ha_state),
        "live_rehearsal_status": live_status,
        "outcome": projected_outcome,
        "outcome_label": outcome_labels.get(projected_outcome, "In progress"),
        "outcome_reason": ha_state.outcome_reason,
        "pending_useful_operation_count": len(ha_state.pending_useful_operations),
        "active_blocked_count": metrics.get("active_blocked_count", 0),
        "blocking_reason": blocking_reason,
        "repair_phase": ha_state.repair_phase,
        "repair_round_count": ha_state.repair_round_count,
        "max_repair_rounds": ha_state.max_repair_rounds,
        "repair_packet": ha_state.repair_packet,
        "last_proposal_coverage_report": ha_state.last_proposal_coverage_report,
        "contract_ledger_coverage_report": ha_state.contract_ledger_coverage_report,
        "verification_plan_coverage_report": ha_state.verification_plan_coverage_report,
        "proposal_contract_conformance_report": ha_state.proposal_contract_conformance_report,
        "instruction_fidelity_report": ha_state.instruction_fidelity_report,
        "completion_eligibility_report": ha_state.completion_eligibility_report,
        "acceptance_criteria": [dict(item) for item in ha_state.acceptance_criteria],
        "acceptance_verified_count": acceptance["verified"],
        "acceptance_total_count": acceptance["total"],
        "completed_criteria": list(ha_state.completed_criteria),
        "unmet_criteria": list(ha_state.unmet_criteria),
        "pending_useful_operations": list(ha_state.pending_useful_operations),
        "remaining_useful_operations": list(ha_state.pending_useful_operations),
        "unique_instruction_turns": len(state_view.get("run_loop", {}).get("turns") or []),
        "total_model_invocations": metrics.get("model_invocation_count", 0),
        "explicit_retry_count": metrics.get("backend_retry_count", 0),
        "extraction_failure_count": ha_state.extraction_failure_count,
        "local_reextraction_attempt_count": ha_state.local_reextraction_attempt_count,
        "no_progress_tick_count": ha_state.no_progress_tick_count,
        "current_step": ha_state.current_step,
        "phase": ha_state.phase,
        "closure_phase_status": ha_state.closure_phase_status,
        "turns_remaining": ha_state.turns_remaining,
        "metrics": metrics,
        "completion_candidate": ha_state.completion_candidate,
        # RUN_044: runtime-verification + human-observation projection.
        "runtime_banner": runtime_banner,
        "runtime_verification_required": ha_state.runtime_verification_required,
        "runtime_verification_status": ha_state.runtime_verification_status,
        "active_runtime_attempt_id": ha_state.active_runtime_attempt_id,
        "active_runtime_attempt": ha_state.active_runtime_attempt,
        "runtime_attempt_history": list(ha_state.runtime_attempt_history),
        "last_runtime_plan_sha256": ha_state.last_runtime_plan_sha256,
        "last_runtime_evidence_id": ha_state.last_runtime_evidence_id,
        "runtime_criterion_ids": list(ha_state.runtime_criterion_ids),
        "runtime_pending_criterion_ids": list(ha_state.runtime_pending_criterion_ids),
        "runtime_failed_criterion_ids": list(ha_state.runtime_failed_criterion_ids),
        "runtime_gap_criterion_ids": list(ha_state.runtime_gap_criterion_ids),
        "runtime_coverage_report": ha_state.runtime_coverage_report,
        "human_observation_pending_criterion_ids": list(ha_state.human_observation_pending_criterion_ids),
        "human_observation_records": list(ha_state.human_observation_records),
        # RUN_045: typed wait/technical-pause/state-invariant visibility.
        "wait_reason": ha_state.wait_reason,
        "wait_condition_type": ha_state.wait_condition_type,
        "wait_condition_id": ha_state.wait_condition_id,
        "wait_started_at": ha_state.wait_started_at,
        "wait_timeout_at": ha_state.wait_timeout_at,
        "expected_state_change": ha_state.expected_state_change,
        "wait_poll_count": ha_state.wait_poll_count,
        "technical_pause_active": ha_state.technical_pause_active,
        "technical_pause_reason": ha_state.technical_pause_reason,
        "state_invariant_violations": list(ha_state.state_invariant_violations),
        "last_reconciliation": ha_state.last_reconciliation,
    }


# Modes in which a browser "auto-run while safe" loop may keep calling tick.
_AUTO_TICK_SAFE_MODES = frozenset(
    {
        HA_MODE_RUNNING,
        HA_MODE_WAITING_FOR_AGENT,
        HA_MODE_REVIEWING,
        HA_MODE_AUTO_EXECUTING,
        HA_MODE_RECOVERING,
        HA_MODE_VERIFYING,
        # RUN_044: auto-run may keep safely polling an active runtime worker
        # (PART H.35, PART K.55) -- it is a documented wait state, not a
        # provider/model turn. HA_MODE_AWAITING_HUMAN_OBSERVATION is
        # deliberately NOT included: only an explicit human action can
        # resume that state.
        HA_MODE_RUNTIME_VERIFYING,
    }
)


def _auto_tick_safe(ha_state: HighAutonomyRunState) -> bool:
    """Whether a frontend auto-tick loop may safely request another tick.

    Never true for human_required / paused / stopped / failed / off, so the
    browser loop halts on any human-critical pause or terminal state. Each
    backend tick still advances at most one safe step regardless.
    """
    if not ha_state.active or ha_state.paused:
        return False
    if not ha_state.auto_tick_safe:
        return False
    if ha_state.human_critical_pending:
        return False
    if _callable_terminal_failure_pending(ha_state):
        return False
    return ha_state.mode in _AUTO_TICK_SAFE_MODES


def build_live_high_autonomy_rehearsal_status(
    *,
    ha_state: HighAutonomyRunState,
    state_view: dict[str, Any],
) -> dict[str, Any]:
    """Display-only live-rehearsal readiness snapshot (slice ADMISSIBLE_RUN_030).

    Aggregates workspace/transport/turn state so the UI and tests can read one
    consistent picture of a live high-autonomy Cursor rehearsal. This is not a
    new authority source: it only projects already-computed run state.
    """
    verification = state_view.get("verification_summary") or {}
    verification_readiness = ha_state.verification_readiness or verification.get(
        "readiness", "not_run"
    )
    return {
        "schema_version": HIGH_AUTONOMY_SCHEMA_VERSION,
        "active": ha_state.active,
        "mode": ha_state.mode,
        "workspace_path": ha_state.workspace_path,
        "transport_kind": ha_state.transport_kind,
        "backend_id": ha_state.backend_id,
        "agent_workspace_path": ha_state.agent_workspace_path,
        "backend_block_reason": ha_state.backend_block_reason,
        "transport_status": ha_state.transport_status,
        "instruction_path": ha_state.instruction_path,
        "response_path": ha_state.response_path,
        "current_turn": ha_state.current_turn,
        "waiting_for_cursor": ha_state.mode == HA_MODE_WAITING_FOR_AGENT,
        "stale_response_blocked": ha_state.stale_response_blocked,
        "human_action_required": ha_state.mode == HA_MODE_HUMAN_REQUIRED
        or ha_state.human_critical_pending,
        "human_required_reason": ha_state.human_required_reason,
        "human_required_action_ids": list(ha_state.human_required_action_ids),
        "human_required_action_count": ha_state.human_required_action_count,
        "human_required_actions": list(ha_state.human_required_actions),
        "verification_passed": verification_readiness == "pass",
        "verification_readiness": verification_readiness,
        "auto_tick_safe": _auto_tick_safe(ha_state),
    }


def _primary_button(ha_state: HighAutonomyRunState) -> str:
    if not ha_state.active or ha_state.mode == HA_MODE_OFF:
        return "start"
    if _callable_terminal_failure_pending(ha_state):
        return "retry_backend"
    if ha_state.mode == HA_MODE_HUMAN_REQUIRED:
        return "approve_or_refuse"
    if ha_state.paused:
        return "resume"
    if ha_state.mode in (HA_MODE_STOPPED, HA_MODE_FAILED):
        return "start"
    return "pause"


def _transport_has_pending_response(transport: "AgentTransport | None") -> bool:
    """True when the transport still has an unread agent response queued."""
    if transport is None:
        return False
    if hasattr(transport, "has_pending_response"):
        return bool(transport.has_pending_response())
    if hasattr(transport, "_pending_response"):
        return getattr(transport, "_pending_response", None) is not None
    if hasattr(transport, "_pending_text"):
        return getattr(transport, "_pending_text", None) is not None
    if hasattr(transport, "_response_index") and hasattr(transport, "_responses"):
        return transport._response_index < len(transport._responses)
    return False


def _capture_transport_status(
    ha_state: HighAutonomyRunState, transport: "AgentTransport"
) -> None:
    """Persist a compact, display-only transport snapshot onto the run state.

    Lets ``build_high_autonomy_summary`` surface live bridge status from the
    persisted session even though it has no direct handle on the transport.
    """
    from admissible.agent_transport import TRANSPORT_STATUS_STALE_BLOCKED

    snap = transport.status_snapshot()
    ha_state.transport_status = str(snap.get("status") or "idle")
    if snap.get("instruction_path"):
        ha_state.instruction_path = snap.get("instruction_path")
    if snap.get("response_path"):
        ha_state.response_path = snap.get("response_path")
    if snap.get("workspace_path"):
        ha_state.workspace_path = snap.get("workspace_path")
    if snap.get("agent_workspace_path"):
        ha_state.agent_workspace_path = snap.get("agent_workspace_path")
    if snap.get("backend_id"):
        ha_state.backend_id = snap.get("backend_id")
    ha_state.stale_response_blocked = snap.get("status") == TRANSPORT_STATUS_STALE_BLOCKED


# -- durable callable-backend response handoff (slice ADMISSIBLE_RUN_034) -----


def _is_callable_backend(ha_state: HighAutonomyRunState) -> bool:
    return ha_state.transport_kind == "callable_backend"


def _pending_invocation_record(ha_state: HighAutonomyRunState) -> Any | None:
    from admissible.agent_backend import AgentInvocationRecord

    return AgentInvocationRecord.from_dict(ha_state.pending_agent_invocation)


def _callable_terminal_failure_pending(ha_state: HighAutonomyRunState) -> bool:
    """True when a callable backend failed terminally and awaits explicit retry."""
    if not _is_callable_backend(ha_state):
        return False
    if not ha_state.backend_retry_required:
        return False
    record = _pending_invocation_record(ha_state)
    if record is None:
        return False
    return record.status in _TERMINAL_INVOCATION_RECORD_STATUSES


def _callable_backend_error_summary(ha_state: HighAutonomyRunState) -> dict[str, Any]:
    """Display-only diagnostics for a terminal callable-backend failure."""
    record = _pending_invocation_record(ha_state)
    if record is None:
        return {}
    return {
        "backend_step": ha_state.backend_step or record.status,
        "invocation_id": record.invocation_id,
        "exit_code": record.exit_code,
        "invocation_duration_ms": record.invocation_duration_ms,
        "stdout_length": record.stdout_length,
        "stderr_summary": record.stderr_summary,
        "error_message": record.error_message,
        "environment_status": record.environment_status,
        "attempt_number": record.attempt_number,
        "retry_of_invocation_id": record.retry_of_invocation_id,
        "estimated_cost": record.estimated_cost,
        "operator_retry_count": record.operator_retry_count,
        "retry_required": ha_state.backend_retry_required,
        # RUN_045 PART G: process-success vs. usable-response diagnostics.
        "automatic_empty_success_retry_used": ha_state.automatic_empty_success_retry_used,
        "manual_retry_count": record.operator_retry_count,
        "latest_usable_response_invocation_id": ha_state.last_consumed_invocation_id,
    }


def _pending_ready_invocation(ha_state: HighAutonomyRunState) -> Any | None:
    """Return the persisted ``response_ready`` invocation record, if one awaits ingest.

    Reads the durable record from the run state (not the in-memory transport), so
    a response dispatched before a controller/transport reconstruction is still
    found. Exactly-once: a record already consumed (by id or sha) is ignored.
    """
    from admissible.agent_backend import (
        INVOCATION_STATUS_RESPONSE_READY,
        AgentInvocationRecord,
    )

    record = AgentInvocationRecord.from_dict(ha_state.pending_agent_invocation)
    if record is None or record.status != INVOCATION_STATUS_RESPONSE_READY:
        return None
    if record.invocation_id and record.invocation_id == ha_state.last_consumed_invocation_id:
        return None
    if (
        record.response_sha256
        and record.response_sha256 == ha_state.last_consumed_response_sha256
    ):
        return None
    if not (record.response_text or "").strip():
        return None
    return record


def _persist_invocation_from_transport(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    transport: "AgentTransport",
    *,
    instruction_id: str | None,
    turn_number: int | None,
) -> Any:
    """Persist the transport's last invocation result into the durable run state.

    Returns the built ``AgentInvocationRecord``. This is what makes a callable
    backend's response survive reconstruction: the source of truth is the run
    state, never the in-memory transport field.
    """
    from admissible.agent_backend import build_invocation_record

    result = getattr(transport, "last_invocation_result", None)
    retry_of = ha_state.pending_retry_of_invocation_id
    previous_attempt = next(
        (
            int(item.get("attempt_number") or 1)
            for item in reversed(ha_state.invocation_history)
            if item.get("invocation_id") == retry_of
        ),
        0,
    )
    record = build_invocation_record(
        result,
        backend_id=ha_state.backend_id or getattr(transport, "backend_id", "callable"),
        instruction_id=instruction_id,
        session_id=controller._session.session_id,
        turn_number=turn_number,
        attempt_number=previous_attempt + 1 if retry_of else 1,
        retry_of_invocation_id=retry_of,
        estimated_cost="unknown",
        operator_retry_count=ha_state.operator_retry_count,
    )
    ha_state.pending_agent_invocation = record.to_dict()
    ha_state.last_invocation_id = record.invocation_id
    ha_state.invocation_history.append(record.to_dict())
    ha_state.pending_retry_of_invocation_id = None
    return record


def _mark_invocation_consumed(ha_state: HighAutonomyRunState, record: Any) -> None:
    """Record exactly-once consumption of a persisted invocation record."""
    from admissible.agent_backend import CALLABLE_STEP_CONSUMED, INVOCATION_STATUS_CONSUMED

    ha_state.last_consumed_invocation_id = record.invocation_id
    ha_state.last_consumed_response_sha256 = record.response_sha256
    record.status = INVOCATION_STATUS_CONSUMED
    record.consumed_at = _now_iso()
    ha_state.pending_agent_invocation = record.to_dict()
    ha_state.backend_step = CALLABLE_STEP_CONSUMED


def _ensure_high_autonomy_transport(
    controller: "ControlSurfaceController", ha_state: HighAutonomyRunState
) -> "AgentTransport | None":
    """Return the live transport, rebuilding it best-effort after reconstruction.

    A reconstructed controller (fresh process / fresh HTTP controller) has no
    in-memory ``_high_autonomy_transport``. The file bridge rebuilds trivially
    from the workspace; a callable backend rebuilds from ``backend_id`` + env
    config. Rebuilding can legitimately fail (e.g. the CLI is no longer
    configured); callers must tolerate ``None`` and only need a live transport to
    *invoke* — ingest of an already-persisted response never needs one.
    """
    existing = controller._high_autonomy_transport
    if existing is not None:
        return existing
    workspace = ha_state.workspace_path
    if not workspace:
        return None
    try:
        if _is_callable_backend(ha_state):
            from admissible.agent_backend import CallableBackendTransport

            backend = _build_backend_from_id(ha_state.backend_id or "", workspace)
            if backend is None:
                # file_bridge id resolved to no callable backend.
                from admissible.agent_transport import FileBridgeAgentTransport

                transport: "AgentTransport" = FileBridgeAgentTransport(workspace)
            else:
                transport = CallableBackendTransport(
                    backend,
                    target_workspace_path=workspace,
                    agent_workspace_path=ha_state.agent_workspace_path or workspace,
                )
        else:
            from admissible.agent_transport import FileBridgeAgentTransport

            transport = FileBridgeAgentTransport(workspace)
    except Exception:
        return None
    controller._high_autonomy_transport = transport
    return transport


def _pause_for_unavailable_transport(
    ha_state: HighAutonomyRunState, step_result: dict[str, Any]
) -> None:
    """Pause when a callable backend/transport cannot be rebuilt after reconstruction."""
    reason = "Callable agent backend unavailable"
    ha_state.mode = HA_MODE_PAUSED
    ha_state.paused = True
    ha_state.backend_block_reason = reason
    ha_state.backend_retry_required = True
    ha_state.backend_step = "unavailable"
    ha_state.next_action = HA_NEXT_NONE
    ha_state.last_event = reason
    ha_state.last_tick_step = "backend_error"
    step_result["backend_block"] = {"status": "unavailable", "reason": reason}


def _finalize_write_instruction(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    transport: "AgentTransport",
    step_result: dict[str, Any],
    *,
    turn_number: int | None,
    event: str,
    event_type: str,
    tick_step: str,
) -> None:
    """Set run state after a ``write_instruction``, persisting callable responses.

    File bridge: mark WAITING for an external response file (unchanged). Callable
    backend: the backend was already invoked synchronously by ``write_instruction``
    — persist its result durably so it survives reconstruction. A ``response_ready``
    result marks the next tick to ingest; any other status pauses concisely (no
    spin, no repeated billing).
    """
    if not _is_callable_backend(ha_state):
        ha_state.backend_block_reason = None
        ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        ha_state.awaiting_instruction_after_review = False
        ha_state.last_event = event
        ha_state.last_tick_step = tick_step
        controller._session.transcript.append(
            _transcript_entry(event_type, {"turn": turn_number, "bridge": step_result.get("bridge")})
        )
        return

    from admissible.agent_backend import (
        CALLABLE_STEP_RESPONSE_READY,
        INVOCATION_STATUS_EMPTY_SUCCESS,
        INVOCATION_STATUS_RESPONSE_READY,
    )

    record = _persist_invocation_from_transport(
        controller,
        ha_state,
        transport,
        instruction_id=_latest_instruction_id(controller),
        turn_number=turn_number,
    )
    step_result["invocation_id"] = record.invocation_id
    step_result["invocation_status"] = record.status
    if record.status != INVOCATION_STATUS_RESPONSE_READY:
        reason = record.error_message or f"Agent invocation status {record.status!r}."
        if (
            record.status == INVOCATION_STATUS_EMPTY_SUCCESS
            and ha_state.automatic_empty_success_retries == 1
            and not ha_state.automatic_empty_success_retry_used
        ):
            ha_state.automatic_empty_success_retry_used = True
            ha_state.pending_retry_of_invocation_id = record.invocation_id
            ha_state.backend_reinvoke_pending = True
            ha_state.mode = HA_MODE_RUNNING
            ha_state.paused = False
            ha_state.backend_block_reason = reason
            ha_state.backend_step = record.status
            ha_state.backend_retry_required = False
            ha_state.transport_status = record.status
            ha_state.next_action = HA_NEXT_WRITE_INSTRUCTION
            ha_state.last_event = (
                "Cursor Agent returned empty_success; one configured visible automatic retry "
                "is queued with the same instruction id and sha256."
            )
            ha_state.last_tick_step = "empty_success_retry_queued"
            step_result["backend_block"] = {
                "status": record.status,
                "reason": reason,
                "automatic_retry_queued": True,
                "retry_of_invocation_id": record.invocation_id,
            }
            return
        ha_state.mode = HA_MODE_PAUSED
        ha_state.paused = True
        ha_state.backend_block_reason = reason
        ha_state.backend_step = record.status
        ha_state.backend_retry_required = True
        ha_state.transport_status = record.status
        ha_state.next_action = HA_NEXT_NONE
        ha_state.last_event = (
            "Cursor Agent invocation stopped before producing a usable proposal."
        )
        ha_state.last_tick_step = "backend_error"
        step_result["backend_block"] = {"status": record.status, "reason": reason}
        return
    ha_state.backend_block_reason = None
    ha_state.backend_retry_required = False
    ha_state.backend_step = CALLABLE_STEP_RESPONSE_READY
    ha_state.transport_status = "response_ready"
    ha_state.last_invocation_id = record.invocation_id
    ha_state.mode = HA_MODE_WAITING_FOR_AGENT
    ha_state.awaiting_instruction_after_review = False
    ha_state.last_event = (
        f"Invoked {ha_state.backend_id or 'agent'} for turn {turn_number}; response ready to ingest."
    )
    ha_state.last_tick_step = "invoke_agent"
    controller._session.transcript.append(
        _transcript_entry(
            event_type, {"turn": turn_number, "invocation_id": record.invocation_id}
        )
    )


def _ingest_success_state(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    *,
    response_sha256: str | None,
    event: str,
    invocation_id: str | None = None,
    policy: HighAutonomyPolicy | None = None,
) -> None:
    policy = policy or HighAutonomyPolicy()
    executable = _executable_actions(controller, policy)
    from admissible.mission_contract import proposal_contract_conformance
    proposed_paths: list[str] = []
    for envelope in controller._session.run_envelopes.values():
        for operation in envelope.candidate.get("structured_operations") or []:
            path = operation.get("path")
            if path and str(operation.get("operation")) == "write_file":
                proposed_paths.append(str(path))
    if controller._session.mission_contract:
        ha_state.proposal_contract_conformance_report = proposal_contract_conformance(
            controller._session.mission_contract, proposed_paths
        )
    ha_state.last_response_cursor = response_sha256
    ha_state.mode = HA_MODE_REVIEWING
    ha_state.awaiting_instruction_after_review = not executable
    ha_state.malformed_retry_count = 0
    if ha_state.repair_phase == REPAIR_PHASE_AWAITING_REPAIR_RESPONSE:
        ha_state.repair_phase = REPAIR_PHASE_REPAIR_EXECUTING
    ha_state.last_event = event
    ha_state.last_tick_step = "ingest_response"
    controller._session.transcript.append(
        _transcript_entry(
            "high_autonomy_response_ingested",
            {
                "turn": controller._session.run_loop.current_turn,
                "invocation_id": invocation_id,
                "executable_action_count": len(executable),
            },
        )
    )


def _fail_malformed(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    exc: Exception,
) -> None:
    ha_state.mode = HA_MODE_FAILED
    ha_state.active = False
    ha_state.stop_reason = f"Malformed agent response: {exc}"
    ha_state.outcome = "failed"
    ha_state.outcome_reason = ha_state.stop_reason
    ha_state.last_event = ha_state.stop_reason
    ha_state.last_tick_step = "failed"


def _tick_ingest_callable(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    transport: "AgentTransport | None",
    step_result: dict[str, Any],
) -> None:
    """Ingest a callable backend's persisted response exactly once (reconstruction-safe)."""
    from admissible.agent_backend import CALLABLE_STEP_INGESTING

    record = _pending_ready_invocation(ha_state)
    if record is None:
        # Already consumed, terminal failure, or nothing persisted: never re-invoke.
        ha_state.last_tick_step = "noop_waiting"
        step_result["reason"] = "no_ready_response"
        if _callable_terminal_failure_pending(ha_state):
            ha_state.mode = HA_MODE_PAUSED
            ha_state.paused = True
            ha_state.next_action = HA_NEXT_NONE
        elif ha_state.mode == HA_MODE_WAITING_FOR_AGENT and not _is_callable_backend(ha_state):
            ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        elif ha_state.mode == HA_MODE_WAITING_FOR_AGENT:
            ha_state.mode = HA_MODE_PAUSED
            ha_state.paused = True
            ha_state.next_action = HA_NEXT_NONE
        _save_ha_state(controller, ha_state)
        controller._persist()
        return

    ha_state.backend_step = CALLABLE_STEP_INGESTING
    ha_state.transport_status = "ingesting_response"
    try:
        controller.ingest_agent_response(record.response_text)
    except ResponseExtractionFailed as exc:
        _mark_invocation_consumed(ha_state, record)
        _pause_for_response_extraction_failed(
            controller,
            ha_state,
            reason=str(exc),
            invocation_id=record.invocation_id,
        )
        step_result["response_extraction_failed"] = True
        _save_ha_state(controller, ha_state)
        controller._persist()
        return
    except ValueError as exc:
        # A response that parsed into no admissible operations: consume it (never
        # re-ingest) and take the existing bounded retry, else fail.
        _mark_invocation_consumed(ha_state, record)
        if ha_state.malformed_retry_count < DEFAULT_MALFORMED_RETRY_LIMIT and transport is not None:
            ha_state.malformed_retry_count += 1
            retry_text = (
                "MALFORMED RESPONSE: your prior response could not be ingested. "
                f"Error: {exc}. Reply with structured operations only."
            )
            transport.note_status(_TRANSPORT_STATUS_MALFORMED_RETRY, error=str(exc))
            transport.write_instruction(
                retry_text,
                turn_number=controller._session.run_loop.current_turn,
                session_id=controller._session.session_id,
                instruction_id=_latest_instruction_id(controller),
            )
            _finalize_write_instruction(
                controller,
                ha_state,
                transport,
                step_result,
                turn_number=controller._session.run_loop.current_turn,
                event="Malformed response — sent one bounded retry instruction.",
                event_type="high_autonomy_malformed_retry",
                tick_step="malformed_retry",
            )
            step_result["retry"] = True
        else:
            _fail_malformed(controller, ha_state, exc)
        _save_ha_state(controller, ha_state)
        controller._persist()
        return

    _mark_invocation_consumed(ha_state, record)
    _ingest_success_state(
        controller,
        ha_state,
        response_sha256=record.response_sha256,
        event=(
            f"Ingested turn {controller._session.run_loop.current_turn} response "
            f"(invocation {record.invocation_id})."
        ),
        invocation_id=record.invocation_id,
        policy=HighAutonomyPolicy(),
    )
    step_result["ingested"] = True
    step_result["invocation_id"] = record.invocation_id
    _save_ha_state(controller, ha_state)
    controller._persist()


def _tick_ingest_file_bridge(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    transport: "AgentTransport",
    step_result: dict[str, Any],
) -> None:
    """File-bridge ingest: read a fresh external response file (unchanged behavior)."""
    read_result = transport.read_response_if_changed()
    if not read_result.changed or not read_result.text:
        ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        ha_state.last_tick_step = "noop_waiting"
        step_result["reason"] = "no_new_response"
        _save_ha_state(controller, ha_state)
        controller._persist()
        return
    try:
        controller.ingest_agent_response(read_result.text)
    except ValueError as exc:
        if ha_state.malformed_retry_count < DEFAULT_MALFORMED_RETRY_LIMIT:
            ha_state.malformed_retry_count += 1
            retry_text = (
                "MALFORMED RESPONSE: your prior response could not be ingested. "
                f"Error: {exc}. Reply with structured operations only."
            )
            transport.note_status(_TRANSPORT_STATUS_MALFORMED_RETRY, error=str(exc))
            transport.write_instruction(
                retry_text,
                turn_number=controller._session.run_loop.current_turn,
                session_id=controller._session.session_id,
            )
            ha_state.mode = HA_MODE_WAITING_FOR_AGENT
            ha_state.last_event = "Malformed response — sent one bounded retry instruction."
            ha_state.last_tick_step = "malformed_retry"
            step_result["retry"] = True
        else:
            _fail_malformed(controller, ha_state, exc)
        _save_ha_state(controller, ha_state)
        controller._persist()
        return
    transport.mark_response_consumed(
        turn_number=controller._session.run_loop.current_turn,
        response_sha256=read_result.cursor or "",
    )
    _ingest_success_state(
        controller,
        ha_state,
        response_sha256=read_result.cursor,
        event=f"Ingested turn {controller._session.run_loop.current_turn} response automatically.",
    )
    step_result["ingested"] = True
    _save_ha_state(controller, ha_state)
    controller._persist()


def _latest_instruction_id(controller: "ControlSurfaceController") -> str | None:
    """Packet id of the most recent instruction, for bridge/controller alignment."""
    packets = controller._session.run_loop.instruction_packets
    return packets[-1].packet_id if packets else None


def _ha_state(controller: "ControlSurfaceController") -> HighAutonomyRunState:
    return controller._high_autonomy_state()


def _save_ha_state(controller: "ControlSurfaceController", ha_state: HighAutonomyRunState) -> None:
    controller._set_high_autonomy_state(ha_state)


def _open_human_critical_actions(
    controller: "ControlSurfaceController",
    policy: HighAutonomyPolicy,
) -> list[dict[str, Any]]:
    """Every currently-open human-critical queue item that needs a human decision.

    An action counts as an *open* human-critical blocker only when it is (a)
    classified human-critical by the policy, (b) still an undecided proposal
    (``proposed_only`` with no recorded human decision), AND (c) actually has a
    human decision available for it. Condition (c) is important: a proposal the
    rules-only evaluator already ``REFUSE``d is human-critical by capability but
    offers no human action to take (``available_human_actions`` is empty), so it
    is already-blocked — it must not perpetually pin the loop in human_required
    nor cause ``decide(refuse)`` to raise. This is the single source of truth for
    "what is blocking" used by _sync_counters, refuse, and approve.
    """
    from admissible.control_surface import available_human_actions

    session = controller._session
    workspace = session.bounded_executor_workspace
    autonomy_level = session.autonomy_level
    open_actions: list[dict[str, Any]] = []
    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        classification = policy.classify_action(
            item=item, envelope=envelope, workspace_path=workspace
        )
        if classification.category != "human_critical":
            continue
        if item.execution_status != "proposed_only" or item.human_decision_ids:
            continue
        available = available_human_actions(item, autonomy_level)
        if not available:
            continue
        open_actions.append(
            {
                "action_id": item.action_id,
                "action_type": item.action_type,
                "tool_or_command": item.tool_or_command,
                "decision": item.decision,
                "reason": classification.reason,
                "available_actions": list(available),
            }
        )
    return open_actions


def _remaining_work_turn_budget(ha_state: HighAutonomyRunState) -> int:
    return max(
        ha_state.max_turns - ha_state.closure_reserve_turns - ha_state.work_turns_used,
        0,
    )


def _latest_verification_record(controller: "ControlSurfaceController") -> dict[str, Any] | None:
    records = controller._session.run_loop.verification_records
    return records[-1] if records else None


def _repairable_verification_failures(ha_state: HighAutonomyRunState) -> list[dict[str, Any]]:
    return failed_mandatory_criteria(ha_state.acceptance_criteria)


def _can_start_repair(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
) -> bool:
    if ha_state.human_critical_pending:
        return False
    if ha_state.repair_phase in (
        REPAIR_PHASE_REPAIR_EXECUTING,
        REPAIR_PHASE_REPAIR_VERIFYING,
        REPAIR_PHASE_AWAITING_REPAIR_RESPONSE,
    ):
        return False
    if int((ha_state.metrics or {}).get("active_blocked_count", 0)) > 0:
        return False
    if not _repairable_verification_failures(ha_state):
        return False
    if ha_state.repair_round_count >= ha_state.max_repair_rounds:
        return False
    if _remaining_work_turn_budget(ha_state) <= 0 and ha_state.current_turn >= ha_state.max_turns:
        return False
    if ha_state.current_turn >= ha_state.max_turns:
        return False
    return _verification_is_final(controller)


def _enter_repair_needed(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
) -> None:
    goal_text = str((controller._session.goal_intake or {}).get("prompt") or "")
    ha_state.repair_round_count += 1
    ha_state.repair_phase = REPAIR_PHASE_REPAIR_NEEDED
    ha_state.repair_packet = build_repair_packet(
        criteria=ha_state.acceptance_criteria,
        verification_record=_latest_verification_record(controller),
        satisfied_file_hashes=latest_file_hashes(controller._session.operation_records),
        goal_text=goal_text,
        remaining_turn_budget=_remaining_work_turn_budget(ha_state),
        repair_round=ha_state.repair_round_count,
        max_repair_rounds=ha_state.max_repair_rounds,
    )
    ha_state.repair_history.append(
        {
            "repair_round": ha_state.repair_round_count,
            "failed_criteria": list(ha_state.repair_packet.get("failed_criteria") or []),
            "started_at": _now_iso(),
        }
    )
    controller._session.governance_records.append(
        {
            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
            "event_type": "repair_round_started",
            "repair_round": ha_state.repair_round_count,
            "failed_criteria": list(ha_state.repair_packet.get("failed_criteria") or []),
            "timestamp": _now_iso(),
        }
    )
    ha_state.mode = HA_MODE_RECOVERING
    ha_state.next_action = HA_NEXT_WRITE_REPAIR
    ha_state.last_event = (
        f"Verification found {len(ha_state.repair_packet.get('failed_criteria') or [])} "
        "repairable failed criteria; preparing targeted repair."
    )
    ha_state.current_step = None
    ha_state.no_progress_tick_count = 0


def _enter_runtime_repair_needed(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    packet: dict[str, Any],
) -> None:
    """RUN_044 analogue of :func:`_enter_repair_needed` for a runtime-sourced packet.

    The packet itself is built by ``admissible.browser_runtime.repair``
    (kept inside the sealed browser_runtime subsystem); this only performs
    the same ha_state/governance bookkeeping the static repair path already
    does, so a runtime repair composes with the existing repair loop instead
    of inventing a parallel one.
    """

    ha_state.repair_round_count += 1
    ha_state.repair_phase = REPAIR_PHASE_REPAIR_NEEDED
    ha_state.repair_packet = packet
    ha_state.runtime_repair_kind = packet.get("kind")
    failed = list(packet.get("failed_criteria") or packet.get("gap_criteria") or [])
    ha_state.repair_history.append(
        {
            "repair_round": ha_state.repair_round_count,
            "failed_criteria": failed,
            "kind": packet.get("kind"),
            "started_at": _now_iso(),
        }
    )
    controller._session.governance_records.append(
        {
            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
            "event_type": "runtime_repair_round_started",
            "repair_round": ha_state.repair_round_count,
            "failed_criteria": failed,
            "kind": packet.get("kind"),
            "timestamp": _now_iso(),
        }
    )
    ha_state.mode = HA_MODE_RECOVERING
    ha_state.next_action = HA_NEXT_WRITE_REPAIR
    ha_state.last_event = (
        f"Runtime verification found {len(failed)} repairable {packet.get('kind')} "
        "criteria; preparing targeted repair."
    )
    ha_state.current_step = None
    ha_state.no_progress_tick_count = 0


# RUN_044: runtime_verification_status values in which an in-process worker
# may legitimately still be preparing/running/awaiting application -- these
# never count as no-progress and never finalize the run.
_RUNTIME_IN_FLIGHT_STATUSES = frozenset(
    {
        "runtime_verification_pending",
        "preparing_runtime_plan",
        "runtime_capability_check",
        "runtime_verification_queued",
        "runtime_verifying",
        "runtime_evidence_ready",
        "applying_runtime_evidence",
    }
)


def _runtime_pipeline_in_flight(ha_state: HighAutonomyRunState) -> bool:
    return ha_state.runtime_verification_status in _RUNTIME_IN_FLIGHT_STATUSES


def _sync_counters(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    policy: HighAutonomyPolicy,
) -> None:
    view = controller.state_view()
    session = controller._session
    workspace = session.bounded_executor_workspace
    pending_auto = 0
    recoverable = False

    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        classification = policy.classify_action(
            item=item, envelope=envelope, workspace_path=workspace
        )
        if (
            classification.category == "auto_executable"
            and item.execution_status == "proposed_only"
            and not getattr(item, "superseded_at", None)
        ):
            pending_auto += 1
        if (
            classification.category == "recoverable_blocker"
            and item.execution_status == "proposed_only"
            and not getattr(item, "superseded_at", None)
        ):
            recoverable = True

    # A genuinely human-critical proposal pauses only while it is still an open,
    # undecided proposal that a human can actually act on. Once every such
    # proposal has been approved/refused (or was already blocked outright), the
    # loop must not re-trigger a human_required pause on the next tick.
    open_human_critical = _open_human_critical_actions(controller, policy)

    ha_state.pending_low_risk_action_count = len(
        open_executable_low_risk_actions(
            queue=session.queue,
            run_envelopes=session.run_envelopes,
            workspace_path=workspace,
            policy=policy,
        )
    )
    active_blockers = active_blocking_action_ids(session.queue)
    ha_state.blocked_action_count = len(active_blockers)
    ha_state.evidence_count = (view.get("run_timeline") or {}).get("evidence_count", 0)
    ha_state.verification_readiness = (view.get("verification_summary") or {}).get(
        "readiness", "not_run"
    )
    ha_state.current_turn = session.run_loop.current_turn
    ha_state.recovery_pending = recoverable and pending_auto == 0 and not ha_state.recovery_attempted
    ha_state.turns_remaining = max(ha_state.max_turns - ha_state.current_turn, 0)
    work_limit = max(ha_state.max_turns - ha_state.closure_reserve_turns, 0)
    if ha_state.phase == "work" and ha_state.current_turn >= work_limit:
        ha_state.phase = "closure"
        ha_state.closure_phase_status = "completion_first"

    operation_records = session.operation_records
    evidence_paths: dict[str, list[str]] = {}
    for record in operation_records:
        if record.get("outcome") not in (
            "executed_mutation",
            "executed_read",
            "executed_list",
            "already_satisfied_noop",
            "duplicate_noop",
        ):
            continue
        path = str(record.get("path") or "")
        if path:
            evidence_paths.setdefault(path, []).append(str(record.get("record_id") or ""))
    for criterion in ha_state.acceptance_criteria:
        if criterion.get("status") not in ("open", "evidence_available"):
            continue
        requested_paths = {
            str(path)
            for request in criterion.get("verification") or []
            for path in request.get("target_paths") or []
        }
        refs = [
            record_id
            for path in requested_paths
            for record_id in evidence_paths.get(path, [])
            if record_id
        ]
        if refs:
            criterion["status"] = "evidence_available"
            existing_refs = criterion.setdefault("evidence_refs", [])
            for ref in refs:
                if ref not in existing_refs:
                    existing_refs.append(ref)

    counts = acceptance_counts(ha_state.acceptance_criteria)
    ha_state.completed_criteria = [
        str(item.get("criterion_id"))
        for item in ha_state.acceptance_criteria
        if item.get("status") in ("verified_pass", "waived")
    ]
    ha_state.unmet_criteria = [
        str(item.get("criterion_id"))
        for item in ha_state.acceptance_criteria
        if item.get("mandatory", True)
        and item.get("status") not in ("verified_pass", "waived")
    ]
    ha_state.pending_useful_operations = [
        entry["action_id"] for entry in open_executable_low_risk_actions(
            queue=session.queue,
            run_envelopes=session.run_envelopes,
            workspace_path=workspace,
            policy=policy,
        )
    ]
    del counts

    ha_state.human_critical_pending = bool(open_human_critical)
    ha_state.human_required_action_ids = [a["action_id"] for a in open_human_critical]
    ha_state.human_required_action_count = len(open_human_critical)
    ha_state.human_required_actions = open_human_critical
    if open_human_critical:
        ha_state.pending_human_action_id = open_human_critical[0]["action_id"]
        ha_state.human_required_reason = open_human_critical[0]["reason"]
    elif ha_state.mode != HA_MODE_HUMAN_REQUIRED:
        # No open human-critical proposal and not currently paused for one.
        ha_state.pending_human_action_id = None
        if not ha_state.paused:
            ha_state.human_required_reason = None

    ha_state.metrics = build_canonical_metrics(
        operation_records=session.operation_records,
        governance_records=session.governance_records,
        verification_records=session.run_loop.verification_records,
        invocation_history=ha_state.invocation_history,
        human_decisions=session.human_decisions,
        queue=session.queue,
        work_turns_used=ha_state.work_turns_used,
        verification_turns_used=ha_state.verification_turns_used,
        closure_turns_used=ha_state.closure_turns_used,
        turns_remaining=ha_state.turns_remaining,
    )
    contract = controller._session.mission_contract or {}
    coverage = ha_state.contract_ledger_coverage_report or {}
    verification_plan = ha_state.verification_plan_coverage_report or {}
    conformance = ha_state.proposal_contract_conformance_report or {}
    eligibility = ha_state.completion_eligibility_report or {}
    ha_state.metrics.update({
        "mission_contract_requirement_count": len(contract.get("mandatory_requirements") or []),
        "explicit_acceptance_criterion_count": len(contract.get("explicit_acceptance_criteria") or []),
        "represented_acceptance_criterion_count": int(coverage.get("represented_acceptance_criterion_count") or 0),
        "mandatory_path_count": len(contract.get("mandatory_paths") or []),
        "represented_mandatory_path_count": int(coverage.get("represented_path_count") or 0),
        "contract_coverage_ratio": coverage.get("coverage_ratio", 0.0),
        "verification_disposition_count": int(verification_plan.get("criteria_with_disposition_count") or 0),
        "unsupported_verification_count": len(verification_plan.get("unsupported_criterion_ids") or []),
        "proposal_contract_violation_count": len(conformance.get("missing_required_paths") or []) + len(conformance.get("architecture_constraints_violated") or []),
        "misplaced_substitute_count": len(conformance.get("likely_misplaced_substitutes") or []),
        "goal_resolved_gate_count": sum(1 for value in (contract.get("explicit_dependency_policy"), contract.get("explicit_architecture_decisions"), contract.get("explicit_execution_boundaries")) if value),
        "completion_eligibility_failure_count": len(eligibility.get("failed_invariants") or []),
        "legacy_false_completion_repair_count": int(bool(eligibility.get("legacy_false_completion_repaired"))),
    })

    refresh_runtime_projection_and_metrics(ha_state)


def refresh_runtime_projection_and_metrics(ha_state: HighAutonomyRunState) -> None:
    """RUN_044: refresh runtime/human-observation projection fields + metrics.

    Derived purely from already-persisted ``ha_state`` fields (the ledger,
    ``runtime_attempt_history``, ``human_observation_records``,
    ``runtime_coverage_report``), so it is safe and cheap to call from every
    place that projects ``ha_state.metrics`` for display -- not just from a
    tick. In particular, ``ControlSurfaceController.session_dict()``
    recomputes ``ha_state.metrics`` from scratch via
    :func:`~admissible.governed_run.build_canonical_metrics` on every call
    (including outside of a tick, e.g. right after recording a human
    observation); without also calling this here, that recompute would
    silently drop every RUN_044 metric between ticks.
    """

    from admissible.runtime_verification_orchestrator import build_runtime_metrics

    ha_state.runtime_pending_criterion_ids = [
        str(item.get("criterion_id"))
        for item in ha_state.acceptance_criteria
        if item.get("verification_disposition") == "deterministic_runtime"
        and item.get("status") not in ("verified_pass", "waived")
    ]
    ha_state.runtime_failed_criterion_ids = [
        str(item.get("criterion_id"))
        for item in ha_state.acceptance_criteria
        if item.get("verification_disposition") == "deterministic_runtime"
        and item.get("status") == "verified_fail"
    ]
    unobservable_ids = set((ha_state.runtime_coverage_report or {}).get("unobservable_criterion_ids") or [])
    ha_state.runtime_gap_criterion_ids = [
        str(item.get("criterion_id"))
        for item in ha_state.acceptance_criteria
        if str(item.get("criterion_id")) in unobservable_ids
        and item.get("status") not in ("verified_pass", "waived")
    ]
    ha_state.human_observation_pending_criterion_ids = [
        str(item.get("criterion_id"))
        for item in ha_state.acceptance_criteria
        if item.get("verification_disposition") == "human_observation_required"
        and item.get("status") not in ("verified_pass", "verified_fail", "waived")
    ]
    human_records = ha_state.human_observation_records
    ha_state.metrics = dict(ha_state.metrics or {})
    ha_state.metrics.update(build_runtime_metrics(ha_state.runtime_attempt_history))
    ha_state.metrics.update(
        {
            "human_observation_count": len(human_records),
            "human_observation_pass_count": sum(1 for r in human_records if r.get("disposition") == "pass"),
            "human_observation_fail_count": sum(1 for r in human_records if r.get("disposition") == "fail"),
            "human_observation_waiver_count": sum(1 for r in human_records if r.get("disposition") == "waive"),
        }
    )


def _has_acceptance_verification_plan(ha_state: HighAutonomyRunState) -> bool:
    return any(
        criterion.get("verification") for criterion in ha_state.acceptance_criteria
    )


def _mandatory_acceptance_complete(ha_state: HighAutonomyRunState) -> bool:
    mandatory = [
        item for item in ha_state.acceptance_criteria if item.get("mandatory", True)
    ]
    return bool(mandatory) and all(
        item.get("status") in ("verified_pass", "waived") for item in mandatory
    )


def _verification_is_final(controller: "ControlSurfaceController") -> bool:
    records = controller._session.run_loop.verification_records
    return bool(records and records[-1].get("overall_status") in ("pass", "fail"))


def _set_final_outcome(
    ha_state: HighAutonomyRunState,
    *,
    outcome: str,
    reason: str,
) -> None:
    ha_state.outcome = outcome
    ha_state.outcome_reason = reason
    ha_state.active = False
    ha_state.mode = HA_MODE_STOPPED if outcome != "failed" else HA_MODE_FAILED
    ha_state.stop_reason = reason
    ha_state.last_event = reason
    ha_state.next_action = HA_NEXT_NONE
    ha_state.closure_phase_status = "finalized"


def _try_finalize_outcome(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
) -> bool:
    """Finalize only from verified governance state, never model prose alone."""

    from admissible.mission_contract import evaluate_completion_eligibility

    no_human_critical = not ha_state.human_critical_pending
    no_pending_useful = not ha_state.pending_useful_operations
    no_active_blockers = int((ha_state.metrics or {}).get("active_blocked_count", 0)) == 0
    verification_final = _verification_is_final(controller)
    # RUN_044: an active runtime worker or a pending human observation is a
    # documented wait state (PART H.34-35), never grounds for finalizing —
    # neither "completed" (evidence has not landed yet) nor
    # "stopped_by_budget"/"incomplete" (runtime verification does not consume
    # provider-turn budget, so budget exhaustion alone must not cut it off).
    if _runtime_pipeline_in_flight(ha_state) or (
        ha_state.mode == HA_MODE_AWAITING_HUMAN_OBSERVATION and ha_state.human_observation_pending_criterion_ids
    ):
        return False
    contract = controller._session.mission_contract or {}
    eligibility_state = ha_state.to_dict()
    eligibility_state["active_blockers"] = (
        list(ha_state.human_required_action_ids) if ha_state.human_critical_pending else []
    )
    eligibility_state["contract_ledger_coverage_report"] = ha_state.contract_ledger_coverage_report
    eligibility_state["verification_plan_coverage_report"] = ha_state.verification_plan_coverage_report
    report = evaluate_completion_eligibility(eligibility_state, contract) if contract else {"eligible": False, "failed_invariants": ["contract_incomplete"]}
    ha_state.completion_eligibility_report = report
    if (
        report.get("eligible")
        and _mandatory_acceptance_complete(ha_state)
        and no_human_critical
        and no_pending_useful
        and no_active_blockers
        and verification_final
    ):
        _set_final_outcome(
            ha_state,
            outcome="completed",
            reason=(
                "All mandatory acceptance criteria are verified_pass or human-waived; "
                "no active human-critical blocker or useful admitted operation remains."
            ),
        )
        return True

    candidate = ha_state.completion_candidate or {}
    if (
        candidate.get("claimed_status") == "incomplete"
        and verification_final
        and no_pending_useful
        and no_human_critical
    ):
        _set_final_outcome(
            ha_state,
            outcome="incomplete",
            reason="Agent proposed an incomplete result and deterministic verification is final.",
        )
        return True

    if (
        not _has_acceptance_verification_plan(ha_state)
        and not ha_state.runtime_verification_required
        and verification_final
        and ha_state.mode == HA_MODE_VERIFYING
        and no_pending_useful
        and no_human_critical
        and ha_state.turns_remaining <= ha_state.closure_reserve_turns
    ):
        _set_final_outcome(
            ha_state,
            outcome="incomplete",
            reason=(
                "Bounded verification is final, but this run has no criterion-level "
                "verification contract; autonomous completion is not claimed."
            ),
        )
        return True

    if ha_state.current_turn >= ha_state.max_turns:
        # Response ingest, admitted execution, deterministic verification,
        # and repair are planned before this function is allowed to close the run.
        if _pending_ready_invocation(ha_state) is not None:
            return False
        if ha_state.mode == HA_MODE_WAITING_FOR_AGENT:
            return False
        if _transport_has_pending_response(controller._high_autonomy_transport):
            return False
        if ha_state.pending_useful_operations:
            return False
        if _has_acceptance_verification_plan(ha_state) and not verification_final:
            return False
        if _can_start_repair(controller, ha_state):
            return False
        if _repairable_verification_failures(ha_state) and verification_final:
            _set_final_outcome(
                ha_state,
                outcome="incomplete",
                reason=(
                    "Mandatory acceptance criteria remain failed after verification; "
                    f"repair rounds exhausted or unavailable ({ha_state.repair_round_count}/"
                    f"{ha_state.max_repair_rounds})."
                ),
            )
            return True
        _set_final_outcome(
            ha_state,
            outcome="stopped_by_budget",
            reason=(
                f"Model invocation budget exhausted at {ha_state.max_turns} turn(s); "
                f"unmet criteria: {', '.join(ha_state.unmet_criteria) or 'none'}; "
                f"pending useful operations: {', '.join(ha_state.pending_useful_operations) or 'none'}."
            ),
        )
        return True
    return False


def _active_runtime_attempt(ha_state: HighAutonomyRunState) -> Any | None:
    from admissible.runtime_orchestration_models import RuntimeVerificationAttempt

    if not ha_state.active_runtime_attempt or not ha_state.active_runtime_attempt_id:
        return None
    return RuntimeVerificationAttempt.from_dict(ha_state.active_runtime_attempt)


def _active_runtime_plan_obj(ha_state: HighAutonomyRunState) -> Any | None:
    from admissible.browser_runtime.models import BrowserRuntimeVerificationPlan

    if not ha_state.active_runtime_plan:
        return None
    return BrowserRuntimeVerificationPlan.from_dict(ha_state.active_runtime_plan)


def _plan_runtime_next_action(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
) -> str | None:
    """RUN_044 PART C/H: the next runtime-verification step, or ``None``.

    ``None`` means the runtime pipeline has nothing to do right now (not
    required, or genuinely waiting on an explicit human/operator action);
    the caller falls through to the rest of the static-verification/closure
    decision tree.
    """

    from admissible.runtime_orchestration_models import (
        STATUS_CANCELLED,
        STATUS_EVIDENCE_READY,
        STATUS_FAILED,
        STATUS_INTERRUPTED,
        STATUS_PREPARED,
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_UNAVAILABLE,
    )

    if ha_state.active_runtime_attempt_id:
        attempt = _active_runtime_attempt(ha_state)
        if attempt is not None:
            if attempt.status == STATUS_PREPARED:
                # An explicit retry (or a prepare that hasn't started yet)
                # already validated a plan+attempt; start that one instead
                # of building an unrelated second attempt (preserves PART
                # G.29 lineage: retry_of_attempt_id, plan sha, criteria).
                return HA_NEXT_START_RUNTIME_VERIFICATION
            if attempt.status in (STATUS_QUEUED, STATUS_RUNNING):
                return HA_NEXT_POLL_RUNTIME_VERIFICATION
            if attempt.status in (STATUS_EVIDENCE_READY, STATUS_UNAVAILABLE, STATUS_FAILED):
                return HA_NEXT_APPLY_RUNTIME_EVIDENCE
            if attempt.status in (STATUS_INTERRUPTED, STATUS_CANCELLED):
                return None  # requires an explicit operator retry (PART G.25 / PART L.58)

    if ha_state.mode == HA_MODE_AWAITING_HUMAN_OBSERVATION and ha_state.human_observation_pending_criterion_ids:
        return None  # a human must record an observation; not auto-resumable

    contract = controller._session.mission_contract or {}
    workspace = controller._session.bounded_executor_workspace
    if not contract or not workspace:
        return None

    from admissible.runtime_verification_orchestrator import assess_runtime_need

    assessment = assess_runtime_need(contract, ha_state.acceptance_criteria, workspace_root=workspace)
    ha_state.runtime_coverage_report = assessment.coverage_report
    ha_state.runtime_criterion_ids = list(assessment.runtime_criterion_ids)
    ha_state.runtime_verification_required = assessment.required
    if not assessment.required:
        return None
    return HA_NEXT_START_RUNTIME_VERIFICATION


def _plan_next_action(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    policy: HighAutonomyPolicy,
    transport: "AgentTransport | None",
) -> str:
    if ha_state.paused or ha_state.mode in (HA_MODE_STOPPED, HA_MODE_FAILED, HA_MODE_OFF):
        return HA_NEXT_NONE
    if _callable_terminal_failure_pending(ha_state):
        return HA_NEXT_NONE
    if ha_state.backend_reinvoke_pending:
        return HA_NEXT_WRITE_INSTRUCTION
    if ha_state.mode == HA_MODE_HUMAN_REQUIRED or ha_state.human_critical_pending:
        return HA_NEXT_HUMAN_APPROVAL
    # After a human refuses the open human-critical action(s), the next safe step
    # is composing a bounded local-only recovery instruction — never re-ingesting
    # the already-consumed response and never re-entering human_required.
    if ha_state.refusal_recovery_pending:
        return HA_NEXT_WRITE_RECOVERY
    # RUN_044 PART J: distinct from human-authority approval above -- a
    # pending subjective observation is a stable wait state, never routed
    # through HA_NEXT_WAIT_FOR_RESPONSE (which would wrongly flip the mode
    # to "waiting for agent") and never a livelock (excluded from the
    # no-progress-tick counter).
    if ha_state.mode == HA_MODE_AWAITING_HUMAN_OBSERVATION and ha_state.human_observation_pending_criterion_ids:
        return HA_NEXT_AWAIT_HUMAN_OBSERVATION

    if ha_state.repair_phase in (
        REPAIR_PHASE_REPAIR_NEEDED,
        REPAIR_PHASE_VERIFICATION_FAILED_REPAIRABLE,
    ) and _can_start_repair(controller, ha_state):
        return HA_NEXT_WRITE_REPAIR

    if ha_state.repair_phase == REPAIR_PHASE_AWAITING_REPAIR_RESPONSE:
        if _pending_ready_invocation(ha_state) is not None:
            return HA_NEXT_INGEST_RESPONSE
        if _transport_has_pending_response(transport):
            return HA_NEXT_INGEST_RESPONSE
        if _is_callable_backend(ha_state):
            return HA_NEXT_NONE
        return HA_NEXT_WAIT_FOR_RESPONSE

    # A callable backend response that is already dispatched-and-persisted must be
    # ingested next, even after the controller/transport were reconstructed and
    # the in-memory transport lost its pending text. Durable state is the source
    # of truth; this guarantees exactly-once ingest across the HTTP tick lifecycle.
    if _pending_ready_invocation(ha_state) is not None:
        return HA_NEXT_INGEST_RESPONSE

    view = controller.state_view()
    timeline = view.get("run_timeline") or {}
    continuation = view.get("continuation_instruction") or {}
    ready_count = max(
        timeline.get("ready_to_execute_local_count", 0),
        ha_state.pending_low_risk_action_count,
        len(
            open_executable_low_risk_actions(
                queue=controller._session.queue,
                run_envelopes=controller._session.run_envelopes,
                workspace_path=controller._session.bounded_executor_workspace,
                policy=policy,
            )
        ),
    )

    # RUN_045 PART B/C: whether a repair write already landed and a rerun is
    # due. Computed once, up front, so both the waiting_for_agent guard below
    # and the repair-phase branch further down agree on the same decision --
    # this is the exact condition the cli-002 livelock got stuck on.
    from admissible.high_autonomy_state_invariants import (
        plan_post_repair_verification,
        repair_needs_post_write_verification,
    )

    repair_verification_pending = repair_needs_post_write_verification(ha_state.repair_phase)

    if ha_state.mode == HA_MODE_WAITING_FOR_AGENT:
        if ready_count > 0:
            return HA_NEXT_AUTO_EXECUTE
        if _is_callable_backend(ha_state):
            if _pending_ready_invocation(ha_state) is not None:
                return HA_NEXT_INGEST_RESPONSE
            if _callable_terminal_failure_pending(ha_state):
                return HA_NEXT_NONE
            if not repair_verification_pending:
                return HA_NEXT_NONE
            # else: fall through -- a repair write already executed and
            # nothing is actually pending from the callable backend
            # (backend_step=response_consumed, no retry required); do not
            # keep reporting next_action=none forever (RUN_045).
        elif _transport_has_pending_response(transport):
            return HA_NEXT_INGEST_RESPONSE
        elif not repair_verification_pending:
            if ha_state.verification_readiness in ("pass", "fail"):
                return HA_NEXT_STOP
            return HA_NEXT_INGEST_RESPONSE
        # else: repair_verification_pending with no pending transport
        # response -- fall through to the repair-aware verification
        # routing below instead of ingesting a response that will never
        # arrive (RUN_045: the cli-002 livelock).

    if ready_count > 0 and ha_state.mode in (HA_MODE_REVIEWING, HA_MODE_RUNNING, HA_MODE_AUTO_EXECUTING):
        return HA_NEXT_AUTO_EXECUTE

    if ha_state.recovery_pending and ha_state.mode == HA_MODE_REVIEWING:
        cont_status = continuation.get("status")
        if cont_status == CONTINUATION_STATUS_EVIDENCE_GROUNDED and continuation.get("available"):
            return HA_NEXT_WRITE_RECOVERY

    acceptance_needs_verification = _has_acceptance_verification_plan(ha_state) and any(
        item.get("status") in ("open", "evidence_available")
        for item in ha_state.acceptance_criteria
        if item.get("mandatory", True)
    )
    if (
        acceptance_needs_verification
        and ready_count == 0
        and ha_state.repair_phase in (REPAIR_PHASE_NONE, "")
        and (
            ha_state.evidence_count > 0
            or ha_state.current_turn
            >= ha_state.max_turns - ha_state.closure_reserve_turns
        )
        and ha_state.mode
        in (HA_MODE_REVIEWING, HA_MODE_RUNNING, HA_MODE_AUTO_EXECUTING, HA_MODE_VERIFYING)
        and not _transport_has_pending_response(transport)
    ):
        return HA_NEXT_VERIFY

    # RUN_044: after static verification has run at least once and there is
    # nothing else more urgent to do, delegate to the runtime orchestrator.
    # This fires independently of _has_acceptance_verification_plan (a
    # criterion needing only a browser check never had a static `verification`
    # array in the first place), so runtime-checkable criteria never get
    # silently skipped into a premature "no verification contract" incomplete.
    if (
        ready_count == 0
        and ha_state.repair_phase in (REPAIR_PHASE_NONE, "")
        and not _transport_has_pending_response(transport)
        and _verification_is_final(controller)
    ):
        runtime_next = _plan_runtime_next_action(controller, ha_state)
        if runtime_next is not None:
            return runtime_next

    if (
        ha_state.repair_phase in (
            REPAIR_PHASE_REPAIR_EXECUTING,
            REPAIR_PHASE_REPAIR_VERIFYING,
        )
        and ready_count == 0
        and (
            _is_callable_backend(ha_state)
            or not _transport_has_pending_response(transport)
        )
    ):
        # A callable backend's pending-response state is already fully
        # accounted for above (the unconditional `_pending_ready_invocation`
        # and `_callable_terminal_failure_pending` checks earlier in this
        # function) via the durable invocation record, not the transport
        # object. `_transport_has_pending_response` inspects a file-bridge-
        # style staging attribute (`CallableBackendTransport._pending_text`)
        # that a callable backend's own durable-record ingest path never
        # clears, so it would otherwise report a stale "still pending"
        # forever after the very first response and block this repair-
        # verification hand-off indefinitely (RUN_045).
        post_repair_action = plan_post_repair_verification(
            repair_phase=ha_state.repair_phase,
            runtime_repair_kind=ha_state.runtime_repair_kind,
        )
        if post_repair_action == HA_NEXT_START_RUNTIME_VERIFICATION:
            # Delegate to the same active-attempt-aware dispatch the general
            # runtime branch above uses: a repair-verify re-entry must poll/
            # apply an already-started attempt rather than blindly starting
            # a second one every tick (RUN_044 exactly-once/single-flight).
            runtime_next = _plan_runtime_next_action(controller, ha_state)
            return runtime_next or HA_NEXT_START_RUNTIME_VERIFICATION
        if post_repair_action == HA_NEXT_VERIFY:
            return HA_NEXT_VERIFY

    if (
        _verification_is_final(controller)
        and _can_start_repair(controller, ha_state)
        and ready_count == 0
        and not _transport_has_pending_response(transport)
    ):
        return HA_NEXT_WRITE_REPAIR

    if policy.should_run_verification(
        evidence_count=ha_state.evidence_count,
        verification_readiness=ha_state.verification_readiness,
        ready_to_execute_local_count=ready_count,
        awaiting_next_instruction=ha_state.awaiting_instruction_after_review,
        has_recoverable_blockers=ha_state.recovery_pending,
    ):
        return HA_NEXT_VERIFY

    if (
        ha_state.outcome in FINAL_OUTCOMES
        and ready_count == 0
        and not _transport_has_pending_response(transport)
    ):
        return HA_NEXT_STOP

    if ha_state.awaiting_instruction_after_review or (
        ha_state.mode == HA_MODE_RUNNING
        and not view.get("session_diagnostics", {}).get("bridge_awaiting_response")
    ):
        if ready_count > 0:
            return HA_NEXT_AUTO_EXECUTE
        cont_status = continuation.get("status")
        if cont_status == CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION:
            return HA_NEXT_AUTO_EXECUTE
        if continuation.get("available") or cont_status == CONTINUATION_STATUS_FIRST_TURN:
            if ha_state.current_turn < ha_state.max_turns:
                if _transport_has_pending_response(transport):
                    return HA_NEXT_WRITE_INSTRUCTION
                if not ha_state.recovery_attempted and not _callable_terminal_failure_pending(
                    ha_state
                ):
                    return HA_NEXT_WRITE_INSTRUCTION

    if ha_state.current_turn >= ha_state.max_turns:
        return HA_NEXT_STOP

    return HA_NEXT_WAIT_FOR_RESPONSE


def _resolve_transport_kind(transport: "AgentTransport") -> str:
    """Compact display label for the attached transport (display-only)."""
    name = type(transport).__name__
    if name == "FixtureAgentTransport":
        return "fixture"
    if name == "CallableBackendTransport":
        return "callable_backend"
    return "file_bridge"


def _build_backend_from_id(
    backend_id: str, workspace_path: str, *, apply_transport_selection: bool = False
) -> Any:
    """Resolve a selectable/concrete backend id to a callable backend, or None.

    ``file_bridge`` stays a pull/external transport (returns None so the default
    FileBridgeAgentTransport is used). ``cursor_cli`` builds a callable Cursor
    backend; which *transport* it uses (legacy one-shot stdout vs the RUN_047
    ACP transport) is chosen by ``ADMISSIBLE_CURSOR_TRANSPORT`` **only at run
    start** (``apply_transport_selection``). The concrete transport id
    (``cursor_cli`` one-shot or ``cursor_acp``) is then persisted, so a
    reconstructed controller rebuilds the *same* transport and never silently
    switches transports mid-run (PART H.32). If ACP is selected but unavailable,
    this raises a technical capability gap rather than silently falling back to
    one-shot (PART H.33). ``fixture`` is test-only and not selectable from the
    HTTP surface.
    """
    from admissible.agent_backend import (
        AGENT_AVAILABILITY_AVAILABLE,
        BACKEND_ID_CURSOR_ACP,
        BACKEND_ID_CURSOR_CLI,
        BACKEND_ID_CURSOR_ONESHOT,
        BACKEND_ID_FILE_BRIDGE,
        BACKEND_ID_FIXTURE,
        CursorCliAgentBackend,
    )
    from admissible.cursor_acp_transport import (
        TRANSPORT_ACP,
        CursorAcpBackend,
        select_transport,
    )

    def _require_available(backend: Any, label: str) -> Any:
        availability = backend.availability()
        if availability.status != AGENT_AVAILABILITY_AVAILABLE:
            raise ValueError(f"{label} is not available: {availability.message}")
        return backend

    if not backend_id or backend_id == BACKEND_ID_FILE_BRIDGE:
        return None
    if backend_id == BACKEND_ID_CURSOR_ACP:
        # Explicit/persisted ACP id: never falls back to one-shot.
        return _require_available(CursorAcpBackend(), "Cursor Agent ACP transport")
    if backend_id == BACKEND_ID_CURSOR_ONESHOT:
        return _require_available(CursorCliAgentBackend(), "Cursor CLI one-shot transport")
    if backend_id == BACKEND_ID_CURSOR_CLI:
        if apply_transport_selection and select_transport() == TRANSPORT_ACP:
            # Operator explicitly selected the ACP transport; a capability gap
            # is surfaced, never silently downgraded to one-shot.
            return _require_available(CursorAcpBackend(), "Cursor Agent ACP transport")
        return _require_available(CursorCliAgentBackend(), "Cursor CLI backend")
    if backend_id == BACKEND_ID_FIXTURE:
        raise ValueError("The fixture backend is test-only and cannot be started from the UI.")
    raise ValueError(f"Unknown agent backend id: {backend_id!r}")


def start_high_autonomy_run(
    controller: "ControlSurfaceController",
    *,
    workspace_path: str,
    transport: "AgentTransport | None" = None,
    backend: Any = None,
    backend_id: str | None = None,
    agent_workspace_path: str | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    closure_reserve_turns: int = DEFAULT_CLOSURE_RESERVE_TURNS,
    max_structured_operations_per_response: int = DEFAULT_MAX_STRUCTURED_OPERATIONS_PER_RESPONSE,
    max_total_proposed_write_bytes: int = DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES,
    acceptance_criteria: list[str | dict[str, Any]] | None = None,
    automatic_empty_success_retries: int = 0,
) -> dict[str, Any]:
    """Start an opt-in high-autonomy run against a workspace.

    Backend selection (highest precedence first):

    - ``transport`` — an explicit ``AgentTransport`` (fixture/file-bridge, used
      by tests and the manual bridge). Pull/external mode, unchanged.
    - ``backend`` — a callable ``AgentBackend`` (fixture backend, Cursor CLI).
      Wrapped in a ``CallableBackendTransport`` so the same tick machine drives
      it: each write invokes the backend once (one safe tick step). The backend
      runs only in the isolated *agent* workspace and never gets direct write
      authority over the *target* workspace.
    - neither — defaults to the legacy Cursor GUI file bridge (semi-autonomous).
    """
    from admissible.agent_transport import FileBridgeAgentTransport
    from admissible.mission_contract import (
        contract_acceptance_ledger,
        ledger_coverage_report,
        verification_plan_coverage_report,
    )

    if not controller._session.goal_intake:
        raise ValueError("Submit a goal before starting a high-autonomy run.")
    if max_turns < 1:
        raise ValueError("max_turns must be at least 1")
    if closure_reserve_turns < 0 or closure_reserve_turns >= max_turns:
        raise ValueError("closure_reserve_turns must be non-negative and smaller than max_turns")
    if automatic_empty_success_retries not in (0, 1):
        raise ValueError("automatic_empty_success_retries must be 0 or 1")

    controller.set_bounded_executor_workspace(workspace_path)
    controller.set_autonomy("L4_HIGH_AUTONOMY_HARD_GATES")

    if transport is None and backend is None and backend_id:
        backend = _build_backend_from_id(
            backend_id, workspace_path, apply_transport_selection=True
        )

    resolved_agent_workspace: str | None = None
    if transport is None and backend is not None:
        from admissible.agent_backend import (
            CallableBackendTransport,
            default_agent_workspace_path,
            ensure_agent_workspace,
        )

        if agent_workspace_path:
            agent_ws = Path(str(agent_workspace_path))
            agent_ws.mkdir(parents=True, exist_ok=True)
        else:
            agent_ws = ensure_agent_workspace(workspace_path)
        resolved_agent_workspace = str(agent_ws)
        transport = CallableBackendTransport(
            backend,
            target_workspace_path=workspace_path,
            agent_workspace_path=resolved_agent_workspace,
        )
    if transport is None:
        transport = FileBridgeAgentTransport(workspace_path)

    snap = transport.status_snapshot()
    transport_kind = _resolve_transport_kind(transport)
    contract = controller._session.mission_contract or {}
    ledger = (
        make_acceptance_ledger(acceptance_criteria, goal_text=str((controller._session.goal_intake or {}).get("prompt") or ""))
        if acceptance_criteria is not None
        else contract_acceptance_ledger(contract)
    )
    if not ledger:
        ledger = make_acceptance_ledger(None, goal_text=str((controller._session.goal_intake or {}).get("prompt") or ""))
    for criterion in ledger:
        if not criterion.get("verification_disposition"):
            criterion["verification_disposition"] = (
                "deterministic_structural" if criterion.get("verification") else "evidence_required"
            )
    ha_state = HighAutonomyRunState(
        active=True,
        mode=HA_MODE_RUNNING,
        max_turns=max_turns,
        started_at=_now_iso(),
        transport_kind=transport_kind,
        backend_id=snap.get("backend_id"),
        agent_workspace_path=snap.get("agent_workspace_path") or resolved_agent_workspace,
        transport_status=str(snap.get("status") or "idle"),
        workspace_path=snap.get("workspace_path") or workspace_path,
        instruction_path=snap.get("instruction_path"),
        response_path=snap.get("response_path"),
        last_event="High-autonomy run started.",
        next_action=HA_NEXT_WRITE_INSTRUCTION,
        closure_reserve_turns=closure_reserve_turns,
        max_structured_operations_per_response=max_structured_operations_per_response,
        max_total_proposed_write_bytes=max_total_proposed_write_bytes,
        turns_remaining=max_turns,
        automatic_empty_success_retries=automatic_empty_success_retries,
        acceptance_criteria=ledger,
        contract_ledger_coverage_report=ledger_coverage_report(contract, ledger),
        verification_plan_coverage_report=verification_plan_coverage_report(ledger),
    )
    artifact_root = Path(ha_state.agent_workspace_path or workspace_path)
    artifact_path = artifact_root / ".admissible" / "mission-contract.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="")
    controller._high_autonomy_transport = transport
    _save_ha_state(controller, ha_state)
    controller._session.transcript.append(
        _transcript_entry(
            "high_autonomy_run_started",
            {
                "workspace_path": workspace_path,
                "agent_workspace_path": ha_state.agent_workspace_path,
                "max_turns": max_turns,
                "transport_kind": ha_state.transport_kind,
                "backend_id": ha_state.backend_id,
                "closure_reserve_turns": closure_reserve_turns,
                "max_structured_operations_per_response": max_structured_operations_per_response,
                "max_total_proposed_write_bytes": max_total_proposed_write_bytes,
                "automatic_empty_success_retries": automatic_empty_success_retries,
                "acceptance_criterion_ids": [
                    item["criterion_id"] for item in ha_state.acceptance_criteria
                ],
            },
        )
    )
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def pause_high_autonomy_run(controller: "ControlSurfaceController") -> dict[str, Any]:
    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run to pause.")
    ha_state.paused = True
    ha_state.mode = HA_MODE_PAUSED
    ha_state.last_event = "High-autonomy run paused by operator."
    ha_state.next_action = HA_NEXT_NONE
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def resume_high_autonomy_run(controller: "ControlSurfaceController") -> dict[str, Any]:
    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run to resume.")
    if _callable_terminal_failure_pending(ha_state):
        view = controller.state_view()
        view["high_autonomy_summary"] = build_high_autonomy_summary(
            ha_state=ha_state, state_view=view
        )
        view["high_autonomy_resume_blocked"] = {
            "reason": (
                "Backend invocation failed; explicit retry is required before the run can continue."
            )
        }
        return view
    ha_state.paused = False
    ha_state.mode = HA_MODE_RUNNING
    ha_state.last_event = "High-autonomy run resumed."
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    _sync_counters(controller, ha_state, HighAutonomyPolicy())
    ha_state.next_action = _plan_next_action(
        controller, ha_state, HighAutonomyPolicy(), controller._high_autonomy_transport
    )
    _save_ha_state(controller, ha_state)
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def retry_callable_backend_invocation(
    controller: "ControlSurfaceController",
) -> dict[str, Any]:
    """Clear a terminal callable-backend failure and allow one explicit re-invocation."""
    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run.")
    if not _is_callable_backend(ha_state):
        raise ValueError("Retry is only available for callable agent backends.")
    if not _callable_terminal_failure_pending(ha_state):
        raise ValueError("No terminal backend failure awaiting retry.")

    failed_record = _pending_invocation_record(ha_state)
    retry_of = failed_record.invocation_id if failed_record is not None else ha_state.last_invocation_id
    ha_state.pending_agent_invocation = None
    ha_state.backend_retry_required = False
    ha_state.backend_block_reason = None
    ha_state.backend_step = None
    ha_state.paused = False
    ha_state.mode = HA_MODE_RUNNING
    ha_state.last_event = "Operator cleared terminal backend failure; ready to re-invoke."
    ha_state.last_tick_step = "backend_retry_cleared"
    ha_state.operator_retry_count += 1
    ha_state.pending_retry_of_invocation_id = retry_of
    _ensure_high_autonomy_transport(controller, ha_state)
    ha_state.backend_reinvoke_pending = True
    ha_state.next_action = HA_NEXT_WRITE_INSTRUCTION
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def stop_high_autonomy_run(
    controller: "ControlSurfaceController",
    *,
    reason: str = "Stopped by operator.",
) -> dict[str, Any]:
    ha_state = _ha_state(controller)
    if not ha_state.active and ha_state.mode == HA_MODE_OFF:
        ha_state = HighAutonomyRunState()
    _set_final_outcome(
        ha_state,
        outcome="stopped_by_operator",
        reason=reason,
    )
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def _waiting_for_agent_signals(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    transport: "AgentTransport | None",
) -> Any:
    from admissible.high_autonomy_state_invariants import WaitingForAgentSignals
    from admissible.runtime_orchestration_models import STATUS_QUEUED, STATUS_RUNNING

    attempt = _active_runtime_attempt(ha_state)
    runtime_worker_active = attempt is not None and attempt.status in (STATUS_QUEUED, STATUS_RUNNING)
    pending_invocation_status = None
    if ha_state.pending_agent_invocation:
        pending_invocation_status = ha_state.pending_agent_invocation.get("status")
    return WaitingForAgentSignals(
        is_callable_backend=_is_callable_backend(ha_state),
        backend_step=ha_state.backend_step,
        pending_invocation_status=pending_invocation_status,
        backend_retry_required=bool(ha_state.backend_retry_required),
        backend_reinvoke_pending=bool(ha_state.backend_reinvoke_pending),
        transport_has_pending_response=_transport_has_pending_response(transport),
        runtime_worker_active=runtime_worker_active,
    )


def _reconcile_high_autonomy_state(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    transport: "AgentTransport | None",
) -> bool:
    """RUN_045 PART D: detect + repair one contradictory persisted state
    combination before planning/ticking (on session load and before every
    tick). Returns True when a repair was applied, and persists a recovery
    governance record. Never consumes a model turn, a repair round, or a
    human-intervention metric -- it only relabels already-persisted state
    that was never legitimately reachable.
    """

    from admissible.high_autonomy_state_invariants import ReconciliationSignals, reconcile_contradictory_state

    signals = ReconciliationSignals(
        mode=ha_state.mode,
        repair_phase=ha_state.repair_phase,
        runtime_repair_kind=ha_state.runtime_repair_kind,
        pending_useful_operation_count=len(ha_state.pending_useful_operations),
        active_blocked_count=int((ha_state.metrics or {}).get("active_blocked_count", 0)),
        waiting_for_agent_signals=_waiting_for_agent_signals(controller, ha_state, transport),
    )
    result = reconcile_contradictory_state(signals)
    if not result.changed:
        return False

    old_mode, old_next_action = ha_state.mode, ha_state.next_action
    mode_map = {"verifying": HA_MODE_VERIFYING, "runtime_verifying": HA_MODE_RUNTIME_VERIFYING}
    if result.new_mode is not None:
        ha_state.mode = mode_map.get(result.new_mode, ha_state.mode)
    if result.new_next_action is not None:
        ha_state.next_action = result.new_next_action
    ha_state.state_invariant_violations = [
        {"code": v.code, "message": v.message, "detail": dict(v.detail)} for v in result.violations
    ]
    record = {
        "record_id": f"governance_{uuid.uuid4().hex[:12]}",
        "event_type": "state_invariant_reconciliation",
        "violations": list(ha_state.state_invariant_violations),
        "old_mode": old_mode,
        "old_next_action": old_next_action,
        "new_mode": ha_state.mode,
        "new_next_action": ha_state.next_action,
        "triggering_invocation_id": ha_state.last_consumed_invocation_id,
        "timestamp": _now_iso(),
    }
    controller._session.governance_records.append(record)
    ha_state.last_reconciliation = record
    ha_state.current_step = None
    ha_state.no_progress_tick_count = 0
    _save_ha_state(controller, ha_state)
    controller._persist()
    return True


def tick_high_autonomy_run(
    controller: "ControlSurfaceController",
    *,
    policy: HighAutonomyPolicy | None = None,
) -> dict[str, Any]:
    """Advance the high-autonomy loop by at most one safe step."""
    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run.")

    if ha_state.paused or ha_state.mode in (HA_MODE_STOPPED, HA_MODE_FAILED):
        view = controller.state_view()
        view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
        view["high_autonomy_tick"] = {"step": "noop", "reason": ha_state.mode}
        return view

    if not ha_state.auto_tick_safe:
        view = controller.state_view()
        view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
        view["high_autonomy_tick"] = {
            "step": "noop",
            "reason": ha_state.current_step or "auto_tick_unsafe",
        }
        return view

    # A reconstructed controller (fresh HTTP request / server restart) has no
    # in-memory transport; rebuild it best-effort. A callable backend can still
    # ingest an already-persisted response even when this stays None.
    transport = _ensure_high_autonomy_transport(controller, ha_state)
    if transport is None and not _is_callable_backend(ha_state):
        raise ValueError("High-autonomy transport is not configured.")

    # RUN_045 PART D: reconcile one known-invalid persisted state combination
    # (on session load and before every tick) before planning/ticking at all.
    # Never consumes a model turn, a repair round, or a human-intervention
    # metric -- it only relabels already-persisted state.
    _reconcile_high_autonomy_state(controller, ha_state, transport)

    policy = policy or HighAutonomyPolicy()
    _sync_counters(controller, ha_state, policy)
    if _try_finalize_outcome(controller, ha_state):
        _save_ha_state(controller, ha_state)
        controller._persist()
        view = controller.state_view()
        view["high_autonomy_summary"] = build_high_autonomy_summary(
            ha_state=ha_state, state_view=view
        )
        view["high_autonomy_tick"] = {
            "step": "finalize_outcome",
            "outcome": ha_state.outcome,
            "reason": ha_state.outcome_reason,
        }
        return view
    planned = _plan_next_action(controller, ha_state, policy, transport)
    ha_state.next_action = planned
    _save_ha_state(controller, ha_state)
    ha_state.last_tick_at = _now_iso()
    ha_state.tick_count += 1
    step_result: dict[str, Any] = {"planned": planned}
    if planned != HA_NEXT_WAIT_FOR_RESPONSE:
        # RUN_045: leaving the wait state clears its durable bookkeeping so
        # a later, unrelated wait starts its own fresh poll count/fingerprint.
        ha_state.wait_started_at = None
        ha_state.wait_poll_count = 0

    if planned == HA_NEXT_STOP:
        if ha_state.outcome is None:
            _set_final_outcome(
                ha_state,
                outcome="stopped_by_budget",
                reason=(
                    f"Model invocation budget exhausted at {ha_state.max_turns} turn(s); "
                    f"unmet criteria: {', '.join(ha_state.unmet_criteria) or 'none'}."
                ),
            )
        ha_state.last_tick_step = "finalize_outcome"
        _save_ha_state(controller, ha_state)
        controller._persist()
        view = controller.state_view()
        view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
        view["high_autonomy_tick"] = step_result
        return view

    if planned == HA_NEXT_WRITE_INSTRUCTION:
        is_backend_retry = ha_state.backend_reinvoke_pending
        ha_state.backend_reinvoke_pending = False
        view_before = controller.state_view()
        continuation = view_before.get("continuation_instruction") or {}
        instruction_text = continuation.get("instruction_text")
        run_loop = controller._session.run_loop
        if is_backend_retry:
            if not run_loop.instruction_packets:
                raise ValueError("Cannot retry backend invocation without a prior instruction packet.")
            instruction_text = run_loop.instruction_packets[-1].packet_text
        elif not run_loop.response_records:
            if instruction_text:
                controller.generate_next_continuation_instruction_packet(
                    instruction_text=instruction_text
                )
            else:
                packet_view = controller.generate_next_instruction_packet()
                instruction_text = packet_view["run_loop"]["instruction_packets"][-1][
                    "packet_text"
                ]
        elif instruction_text:
            controller.generate_next_continuation_instruction_packet(instruction_text=instruction_text)
        else:
            packet_view = controller.generate_next_instruction_packet()
            instruction_text = packet_view["run_loop"]["instruction_packets"][-1]["packet_text"]

        contract = controller._session.mission_contract or {}
        if contract:
            open_ids = [
                item["criterion_id"] for item in ha_state.acceptance_criteria
                if item.get("mandatory", True) and item.get("status") not in ("verified_pass", "waived")
            ]
            missing_paths = list(contract.get("mandatory_paths") or [])
            architecture = [x.get("source_text") for x in contract.get("explicit_architecture_decisions") or []]
            contract_json = json.dumps(contract, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            contract_sha = hashlib.sha256(contract_json.encode("utf-8")).hexdigest()
            fidelity_header = (
                "MISSION CONTRACT AUTHORITY\n"
                ".admissible/mission-contract.json is the immutable canonical mission contract.\n"
                f"Mission-contract SHA-256: {contract_sha}\n"
                f"Raw-goal SHA-256: {contract.get('raw_goal_sha256')}\n"
                f"Open mandatory criterion IDs: {', '.join(open_ids) or 'none'}\n"
                f"Exact mandatory paths: {', '.join(missing_paths) or 'none'}\n"
                f"Architecture constraints: {' | '.join(str(x) for x in architecture) or 'none explicit'}\n"
                f"Verification capability status: unsupported={', '.join((ha_state.verification_plan_coverage_report or {}).get('unsupported_criterion_ids') or []) or 'none'}; human_observation={', '.join((ha_state.verification_plan_coverage_report or {}).get('human_observation_criterion_ids') or []) or 'none'}\n"
                "The progress ledger is a projection of the contract and cannot narrow the mission. "
                "Omitted contract requirements remain mandatory. Proposed substitutes do not change exact required paths.\n\n"
            )
            instruction_text = fidelity_header + str(instruction_text or "")
            from admissible.mission_contract import instruction_fidelity_report
            ha_state.instruction_fidelity_report = instruction_fidelity_report(contract, instruction_text)
            if not ha_state.instruction_fidelity_report.get("fidelity_complete"):
                ha_state.outcome = "contract_incomplete"
                ha_state.outcome_reason = "Mandatory mission-contract fields were omitted from the agent packet."
                ha_state.active = False
                ha_state.mode = HA_MODE_STOPPED
                _save_ha_state(controller, ha_state)
                controller._persist()
                view = controller.state_view()
                view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
                view["high_autonomy_tick"] = {"step": "contract_fidelity_pause"}
                return view

        turn_now = controller._session.run_loop.current_turn
        if not is_backend_retry:
            work_limit = max(ha_state.max_turns - ha_state.closure_reserve_turns, 0)
            if turn_now <= work_limit:
                ha_state.work_turns_used += 1
            else:
                ha_state.phase = "closure"
                ha_state.closure_phase_status = "completion_first"
                ha_state.closure_turns_used += 1
        if transport is None:
            _pause_for_unavailable_transport(ha_state, step_result)
            _save_ha_state(controller, ha_state)
            controller._persist()
        else:
            bridge_result = transport.write_instruction(
                instruction_text,
                turn_number=turn_now,
                session_id=controller._session.session_id,
                instruction_id=_latest_instruction_id(controller),
            )
            step_result.update({"bridge": bridge_result, "turn": turn_now})
            if is_backend_retry:
                step_result["retry_of_invocation_id"] = ha_state.pending_retry_of_invocation_id
            _finalize_write_instruction(
                controller,
                ha_state,
                transport,
                step_result,
                turn_number=turn_now,
                event=(
                    f"Re-invoked turn {turn_now} instruction with preserved instruction id."
                    if is_backend_retry
                    else f"Wrote turn {turn_now} instruction automatically."
                ),
                event_type="high_autonomy_instruction_written",
                tick_step="write_instruction",
            )
            _save_ha_state(controller, ha_state)
            controller._persist()

    elif planned == HA_NEXT_WRITE_RECOVERY:
        view_before = controller.state_view()
        continuation = view_before.get("continuation_instruction") or {}
        instruction_text = continuation.get("instruction_text") or ""
        is_refusal_recovery = ha_state.refusal_recovery_pending
        if is_refusal_recovery:
            recovery_text = _build_refusal_recovery_text(
                refused_actions=_refused_action_details(
                    controller, ha_state.last_refused_action_ids
                ),
                continuation_text=instruction_text,
            )
            recovery_event = (
                "Wrote local-only recovery instruction after human refusal automatically."
            )
            recovery_event_type = "high_autonomy_refusal_recovery_instruction_written"
        else:
            recovery_text = f"{_RECOVERY_PREAMBLE}\n\n{instruction_text}".strip()
            recovery_event = "Wrote local-only recovery instruction automatically."
            recovery_event_type = "high_autonomy_recovery_instruction_written"
        controller.generate_next_continuation_instruction_packet(instruction_text=recovery_text)
        ha_state.recovery_pending = False
        ha_state.refusal_recovery_pending = False
        ha_state.recovery_attempted = True
        turn_now = controller._session.run_loop.current_turn
        work_limit = max(ha_state.max_turns - ha_state.closure_reserve_turns, 0)
        if turn_now <= work_limit:
            ha_state.work_turns_used += 1
        else:
            ha_state.phase = "closure"
            ha_state.closure_phase_status = "completion_first"
            ha_state.closure_turns_used += 1
        if transport is None:
            _pause_for_unavailable_transport(ha_state, step_result)
        else:
            bridge_result = transport.write_instruction(
                recovery_text,
                turn_number=turn_now,
                session_id=controller._session.session_id,
                instruction_id=_latest_instruction_id(controller),
            )
            step_result.update({"bridge": bridge_result, "refusal_recovery": is_refusal_recovery})
            _finalize_write_instruction(
                controller,
                ha_state,
                transport,
                step_result,
                turn_number=turn_now,
                event=recovery_event,
                event_type=recovery_event_type,
                tick_step="write_recovery_instruction",
            )
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_WRITE_REPAIR:
        if not ha_state.repair_packet and _can_start_repair(controller, ha_state):
            _enter_repair_needed(controller, ha_state)
        ha_state.repair_phase = REPAIR_PHASE_WRITING_REPAIR_INSTRUCTION
        repair_kind = (ha_state.repair_packet or {}).get("kind")
        if repair_kind in ("runtime_verification_failure", "runtime_instrumentation_gap"):
            # RUN_044: a runtime-sourced repair packet was built by
            # admissible.browser_runtime.repair (see _enter_runtime_repair_needed);
            # only that module's own text builder understands its shape
            # (assertion diagnostics, console/page exceptions, missing
            # observables) -- the generic governed_run builder expects a
            # different packet shape.
            from admissible.browser_runtime.repair import build_runtime_repair_instruction_text

            repair_text = build_runtime_repair_instruction_text(ha_state.repair_packet or {})
        else:
            repair_text = build_repair_instruction_text(ha_state.repair_packet or {})
        controller.generate_next_continuation_instruction_packet(instruction_text=repair_text)
        turn_now = controller._session.run_loop.current_turn
        work_limit = max(ha_state.max_turns - ha_state.closure_reserve_turns, 0)
        if turn_now <= work_limit:
            ha_state.work_turns_used += 1
        else:
            ha_state.phase = "closure"
            ha_state.closure_phase_status = "completion_first"
            ha_state.closure_turns_used += 1
        if transport is None:
            _pause_for_unavailable_transport(ha_state, step_result)
        else:
            bridge_result = transport.write_instruction(
                repair_text,
                turn_number=turn_now,
                session_id=controller._session.session_id,
                instruction_id=_latest_instruction_id(controller),
            )
            step_result.update({"bridge": bridge_result, "repair_round": ha_state.repair_round_count})
            _finalize_write_instruction(
                controller,
                ha_state,
                transport,
                step_result,
                turn_number=turn_now,
                event="Wrote targeted verification repair instruction automatically.",
                event_type="high_autonomy_repair_instruction_written",
                tick_step="write_repair_instruction",
            )
        ha_state.repair_phase = REPAIR_PHASE_AWAITING_REPAIR_RESPONSE
        ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_INGEST_RESPONSE:
        if _is_callable_backend(ha_state):
            _tick_ingest_callable(controller, ha_state, transport, step_result)
        else:
            _tick_ingest_file_bridge(controller, ha_state, transport, step_result)

    elif planned == HA_NEXT_AUTO_EXECUTE:
        workspace = controller._session.bounded_executor_workspace
        session = controller._session
        executed_ids: list[str] = []
        failed_selections: list[dict[str, Any]] = []
        executable_entries = open_executable_low_risk_actions(
            queue=session.queue,
            run_envelopes=session.run_envelopes,
            workspace_path=workspace,
            policy=policy,
        )
        executable_ids = [entry["action_id"] for entry in executable_entries]
        for action_id in executable_ids:
            if len(executed_ids) >= policy.max_auto_executions_per_turn:
                break
            item = controller._find_queue_item(action_id)
            if item is None or item.execution_status != "proposed_only":
                continue
            try:
                controller.execute_bounded_local(
                    action_id, {"workspace_path": workspace}
                )
                executed_ids.append(action_id)
                refreshed_item = controller._find_queue_item(action_id)
                if refreshed_item and refreshed_item.operation_outcome in (
                    "executed_mutation",
                    "executed_read",
                    "executed_list",
                ):
                    ha_state.auto_executed_action_count += 1
            except Exception as exc:
                failed_selections.append(
                    {
                        "action_id": action_id,
                        "reason": str(exc),
                    }
                )
                continue

        ha_state.mode = HA_MODE_AUTO_EXECUTING if executed_ids else HA_MODE_REVIEWING
        if ha_state.repair_phase == REPAIR_PHASE_AWAITING_REPAIR_RESPONSE and executed_ids:
            ha_state.repair_phase = REPAIR_PHASE_REPAIR_EXECUTING
        elif ha_state.repair_phase == REPAIR_PHASE_REPAIR_EXECUTING and executed_ids:
            ha_state.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
        if executed_ids:
            ha_state.awaiting_instruction_after_review = False
            ha_state.last_event = (
                f"Auto-executed {len(executed_ids)} low-risk local write(s)."
            )
            remaining_executable = open_executable_low_risk_actions(
                queue=controller._session.queue,
                run_envelopes=controller._session.run_envelopes,
                workspace_path=workspace,
                policy=policy,
            )
            if not remaining_executable:
                if _mandatory_acceptance_complete(ha_state):
                    ha_state.awaiting_instruction_after_review = False
                elif not _has_acceptance_verification_plan(ha_state) and (
                    ha_state.turns_remaining > ha_state.closure_reserve_turns
                ):
                    ha_state.awaiting_instruction_after_review = True
                    ha_state.mode = HA_MODE_REVIEWING
        elif executable_ids:
            _pause_for_internal_execution_mismatch(
                controller,
                ha_state,
                pending_ids=executable_ids,
                selection_failures=failed_selections or _non_executable_pending_reasons(
                    controller, policy
                ),
            )
            step_result["internal_execution_state_mismatch"] = True
            _save_ha_state(controller, ha_state)
            controller._persist()
            view = controller.state_view()
            view["high_autonomy_summary"] = build_high_autonomy_summary(
                ha_state=ha_state, state_view=view
            )
            view["high_autonomy_tick"] = step_result
            return view
        else:
            ha_state.last_event = "No low-risk actions to auto-execute."
        ha_state.last_tick_step = "auto_execute"
        step_result["executed_action_ids"] = executed_ids
        _append_coalesced_transcript(
            controller,
            "high_autonomy_auto_executed",
            {"action_ids": executed_ids},
        )
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_VERIFY:
        workspace = controller._session.bounded_executor_workspace
        verification_profile = (
            "acceptance_ledger"
            if _has_acceptance_verification_plan(ha_state)
            else "tiny_game_demo"
        )
        ha_state.closure_phase_status = "verifying"
        verify_body: dict[str, Any] = {
            "workspace_path": workspace,
            "profile": verification_profile,
        }
        failed_ids = [
            str(item.get("criterion_id"))
            for item in _repairable_verification_failures(ha_state)
        ]
        if ha_state.repair_phase in (
            REPAIR_PHASE_REPAIR_EXECUTING,
            REPAIR_PHASE_REPAIR_VERIFYING,
        ) and failed_ids:
            verify_body["criterion_ids"] = failed_ids
        controller.verify_bounded_local_workspace(verify_body)
        refreshed = controller._high_autonomy_state()
        if refreshed is not None:
            ha_state.acceptance_criteria = refreshed.acceptance_criteria
        ha_state.mode = HA_MODE_VERIFYING
        ha_state.last_event = "Ran bounded verification as a controller step."
        ha_state.last_tick_step = "verify"
        step_result["verified"] = True
        step_result["verification_profile"] = verification_profile
        if ha_state.repair_phase in (
            REPAIR_PHASE_REPAIR_EXECUTING,
            REPAIR_PHASE_AWAITING_REPAIR_RESPONSE,
        ):
            ha_state.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
        if (
            _verification_is_final(controller)
            and _repairable_verification_failures(ha_state)
            and _can_start_repair(controller, ha_state)
        ):
            ha_state.repair_phase = REPAIR_PHASE_VERIFICATION_FAILED_REPAIRABLE
            _enter_repair_needed(controller, ha_state)
        elif (
            _verification_is_final(controller)
            and _repairable_verification_failures(ha_state)
            and not _can_start_repair(controller, ha_state)
        ):
            ha_state.repair_phase = REPAIR_PHASE_NONE
            _set_final_outcome(
                ha_state,
                outcome="incomplete",
                reason=(
                    "Mandatory acceptance criteria remain failed after verification; "
                    "repair is unavailable or repair rounds are exhausted."
                ),
            )
        elif _mandatory_acceptance_complete(ha_state):
            ha_state.repair_phase = REPAIR_PHASE_NONE
            ha_state.repair_packet = None
            for criterion_id in ha_state.completed_criteria:
                controller._session.governance_records.append(
                    {
                        "record_id": f"governance_{uuid.uuid4().hex[:12]}",
                        "event_type": "criterion_repaired",
                        "criterion_id": criterion_id,
                        "timestamp": _now_iso(),
                    }
                )
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_START_RUNTIME_VERIFICATION:
        from admissible.runtime_orchestration_models import STATUS_PREPARED, STATUS_QUEUED, STATUS_RUNNING
        from admissible.runtime_verification_orchestrator import (
            assess_runtime_need,
            default_runtime_provider,
            prepare_runtime_attempt,
            start_runtime_attempt,
        )

        contract = controller._session.mission_contract or {}
        workspace = controller._session.bounded_executor_workspace
        provider = controller._runtime_provider_override or default_runtime_provider()
        existing_attempt = _active_runtime_attempt(ha_state)

        if existing_attempt is not None and existing_attempt.status == STATUS_PREPARED:
            # An explicit retry (PART G.29) already validated a plan+attempt;
            # start that one as-is instead of building an unrelated second
            # attempt, so retry_of_attempt_id/plan sha/criteria lineage
            # survives into the started attempt.
            attempt = existing_attempt
            plan_for_start = _active_runtime_plan_obj(ha_state)
            prepare_transition = None
        else:
            assessment = assess_runtime_need(contract, ha_state.acceptance_criteria, workspace_root=workspace)
            ha_state.runtime_coverage_report = assessment.coverage_report
            ha_state.runtime_criterion_ids = list(assessment.runtime_criterion_ids)
            ha_state.runtime_verification_required = assessment.required
            attempt = None
            plan_for_start = None
            if not assessment.required or assessment.plan is None:
                ha_state.last_event = "Runtime verification is not required; nothing to start."
                ha_state.last_tick_step = "runtime_no_op"
                step_result["runtime_verification"] = {"required": False}
            else:
                attempt, prepare_transition = prepare_runtime_attempt(
                    session_id=controller._session.session_id,
                    mission_contract=contract,
                    ledger=ha_state.acceptance_criteria,
                    plan=assessment.plan,
                    provider=provider,
                    operation_records=controller._session.operation_records,
                )
                plan_for_start = assessment.plan

        if attempt is None:
            if prepare_transition is not None:
                ha_state.runtime_verification_status = "runtime_observability_gap"
                ha_state.last_event = prepare_transition.event_message
                ha_state.last_tick_step = "runtime_plan_rejected"
                step_result["runtime_verification"] = prepare_transition.to_dict()
                _set_final_outcome(
                    ha_state,
                    outcome="verification_plan_incomplete",
                    reason=prepare_transition.event_message,
                )
        else:
            ha_state.active_runtime_attempt_id = attempt.attempt_id
            ha_state.active_runtime_plan = plan_for_start.to_dict()
            ha_state.last_runtime_plan_sha256 = attempt.runtime_plan_sha256
            start_transition = start_runtime_attempt(
                attempt=attempt, plan=plan_for_start, provider=provider, control_root=workspace
            )
            ha_state.active_runtime_attempt = attempt.to_dict()
            ha_state.runtime_verification_status = (
                "runtime_verifying"
                if attempt.status in (STATUS_QUEUED, STATUS_RUNNING)
                else start_transition.semantic_status
            )
            ha_state.mode = HA_MODE_RUNTIME_VERIFYING
            ha_state.last_event = start_transition.event_message
            ha_state.last_tick_step = "start_runtime_verification"
            ha_state.no_progress_tick_count = 0
            step_result["runtime_verification"] = start_transition.to_dict()
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_POLL_RUNTIME_VERIFICATION:
        from admissible.runtime_verification_orchestrator import poll_runtime_attempt

        attempt = _active_runtime_attempt(ha_state)
        workspace = controller._session.bounded_executor_workspace
        if attempt is None:
            ha_state.last_event = "No active runtime attempt to poll."
            ha_state.last_tick_step = "runtime_poll_noop"
        else:
            transition = poll_runtime_attempt(attempt=attempt, control_root=workspace)
            ha_state.active_runtime_attempt = attempt.to_dict()
            ha_state.runtime_verification_status = (
                "runtime_verifying" if attempt.status in ("queued", "running") else attempt.status
            )
            ha_state.last_event = transition.event_message
            ha_state.last_tick_step = "poll_runtime_verification"
            step_result["runtime_verification"] = transition.to_dict()
        ha_state.mode = HA_MODE_RUNTIME_VERIFYING
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_APPLY_RUNTIME_EVIDENCE:
        from admissible.browser_runtime.repair import (
            build_instrumentation_repair_packet,
            build_runtime_repair_packet,
        )
        from admissible.runtime_orchestration_models import STATUS_FAILED
        from admissible.runtime_verification_orchestrator import apply_runtime_evidence, find_persisted_evidence

        attempt = _active_runtime_attempt(ha_state)
        plan_obj = _active_runtime_plan_obj(ha_state)
        workspace = controller._session.bounded_executor_workspace
        contract = controller._session.mission_contract or {}

        def _archive_attempt(semantic_status: str, *, extra: dict[str, Any] | None = None) -> None:
            extra = extra or {}
            ha_state.runtime_attempt_history.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "session_id": attempt.session_id,
                    "runtime_plan_sha256": attempt.runtime_plan_sha256,
                    "retry_of_attempt_id": attempt.retry_of_attempt_id,
                    "evidence_id": attempt.evidence_id,
                    "semantic_status": semantic_status,
                    "cleanup_status": attempt.cleanup_status,
                    "criterion_ids": list(attempt.criterion_ids),
                    "started_at": attempt.started_at,
                    "completed_at": attempt.completed_at,
                    **extra,
                }
            )
            ha_state.active_runtime_attempt_id = None
            ha_state.active_runtime_attempt = None
            ha_state.active_runtime_plan = None
            ha_state.runtime_verification_status = semantic_status

        if attempt is None or plan_obj is None:
            ha_state.last_event = "No active runtime attempt to apply evidence for."
            ha_state.last_tick_step = "runtime_apply_noop"
            step_result["runtime_verification"] = {"applied": False}
        elif attempt.status == STATUS_FAILED:
            # Defensive path only: execute_runtime_verification_plan already
            # catches provider exceptions into evidence, so a bare worker
            # exception is not expected in normal operation. No evidence
            # object exists here, so decide repair/finalize directly.
            _archive_attempt("runtime_verification_fail")
            ha_state.mode = HA_MODE_RUNNING
            if ha_state.repair_round_count < ha_state.max_repair_rounds:
                packet = {
                    "kind": "runtime_verification_failure",
                    "failed_criteria": list(attempt.criterion_ids),
                    "unchanged_passing_criteria": [],
                    "assertion_diagnostics": [{"message": attempt.failure_message}],
                    "console_entries": [],
                    "page_exceptions": [],
                    "blocked_external_request_attempts": [],
                    "missing_observables": [],
                    "repair_boundaries": {
                        "preserve_passing_artifacts": True,
                        "structured_operations_only": True,
                        "no_optional_polish": True,
                    },
                    "repair_round": ha_state.repair_round_count + 1,
                    "max_repair_rounds": ha_state.max_repair_rounds,
                    "remaining_repair_budget": max(0, ha_state.max_repair_rounds - ha_state.repair_round_count - 1),
                }
                _enter_runtime_repair_needed(controller, ha_state, packet)
            else:
                _set_final_outcome(
                    ha_state,
                    outcome="incomplete",
                    reason=(
                        "Runtime verification worker failed and repair rounds are exhausted: "
                        f"{attempt.failure_message}"
                    ),
                )
            step_result["runtime_verification"] = {"applied": False, "worker_failed": True}
        else:
            evidence = find_persisted_evidence(workspace, attempt.evidence_id)
            if evidence is None:
                attempt.status = "interrupted"
                ha_state.active_runtime_attempt = attempt.to_dict()
                ha_state.runtime_verification_status = "interrupted"
                ha_state.last_event = "Runtime evidence file could not be found; treating as interrupted."
                step_result["runtime_verification"] = {"applied": False, "evidence_missing": True}
            else:
                transition = apply_runtime_evidence(
                    ledger=ha_state.acceptance_criteria,
                    plan=plan_obj,
                    evidence=evidence,
                    mission_contract=contract,
                    attempt=attempt,
                )
                extra = transition.extra or {}
                if extra.get("contract_ledger_coverage_report") is not None:
                    ha_state.contract_ledger_coverage_report = extra["contract_ledger_coverage_report"]
                if extra.get("verification_plan_coverage_report") is not None:
                    ha_state.verification_plan_coverage_report = extra["verification_plan_coverage_report"]
                ha_state.last_event = transition.event_message
                step_result["runtime_verification"] = transition.to_dict()

                if not transition.changed:
                    # Exactly-once guard tripped: a stable no-op (test #10).
                    ha_state.runtime_verification_status = transition.semantic_status
                else:
                    ha_state.last_runtime_evidence_id = evidence.evidence_id
                    fail_ids = extra.get("fail_criterion_ids") or []
                    gap_ids = extra.get("gap_criterion_ids") or []
                    human_ids = extra.get("human_observation_criterion_ids") or []
                    _archive_attempt(
                        transition.semantic_status,
                        extra={
                            "policy_violation": bool(extra.get("policy_violation")),
                            "duration_ms": extra.get("duration_ms", 0),
                            "assertion_count": extra.get("assertion_count", 0),
                            "assertion_pass_count": extra.get("assertion_pass_count", 0),
                            "assertion_fail_count": extra.get("assertion_fail_count", 0),
                            "input_event_count": extra.get("input_event_count", 0),
                            "snapshot_count": extra.get("snapshot_count", 0),
                            "screenshot_count": extra.get("screenshot_count", 0),
                            "external_request_attempt_count": extra.get("external_request_attempt_count", 0),
                        },
                    )

                    if transition.semantic_status == "runtime_verification_capability_gap":
                        ha_state.mode = HA_MODE_RUNNING
                        _set_final_outcome(
                            ha_state,
                            outcome="verification_capability_gap",
                            reason=(
                                "Browser runtime is unavailable; mandatory runtime-verified "
                                "criteria cannot be checked."
                            ),
                        )
                    elif transition.semantic_status == "runtime_verification_fail" and fail_ids and (
                        ha_state.repair_round_count < ha_state.max_repair_rounds
                    ):
                        packet = build_runtime_repair_packet(
                            evidence=evidence,
                            repair_round=ha_state.repair_round_count + 1,
                            max_repair_rounds=ha_state.max_repair_rounds,
                        )
                        _enter_runtime_repair_needed(controller, ha_state, packet)
                    elif transition.semantic_status == "runtime_verification_fail":
                        ha_state.mode = HA_MODE_RUNNING
                        _set_final_outcome(
                            ha_state,
                            outcome="incomplete",
                            reason=(
                                "Mandatory runtime-verified criteria remain failed after "
                                "verification; repair rounds exhausted or unavailable "
                                f"({ha_state.repair_round_count}/{ha_state.max_repair_rounds})."
                            ),
                        )
                    elif transition.semantic_status == "runtime_observability_gap" and (
                        extra.get("instrumentation_fixable_gap_ids")
                        and plan_obj.debug_interface
                        and ha_state.repair_round_count < ha_state.max_repair_rounds
                    ):
                        packet = build_instrumentation_repair_packet(
                            evidence=evidence,
                            debug_interface=plan_obj.debug_interface,
                            repair_round=ha_state.repair_round_count + 1,
                            max_repair_rounds=ha_state.max_repair_rounds,
                        )
                        _enter_runtime_repair_needed(controller, ha_state, packet)
                    elif transition.semantic_status == "runtime_observability_gap":
                        ha_state.mode = HA_MODE_RUNNING
                        _set_final_outcome(
                            ha_state,
                            outcome="runtime_observability_gap",
                            reason=(
                                "Mandatory runtime-verified criteria have no safe observable "
                                "and instrumentation repair is unavailable or exhausted."
                            ),
                        )
                    elif transition.semantic_status == "awaiting_human_observation":
                        ha_state.mode = HA_MODE_AWAITING_HUMAN_OBSERVATION
                        ha_state.last_event = (
                            f"Awaiting human observation for {len(human_ids)} subjective criteria."
                        )
                    else:
                        ha_state.mode = HA_MODE_RUNNING
        ha_state.last_tick_step = "apply_runtime_evidence"
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_AWAIT_HUMAN_OBSERVATION:
        ha_state.mode = HA_MODE_AWAITING_HUMAN_OBSERVATION
        ha_state.last_event = (
            f"Awaiting human observation for {len(ha_state.human_observation_pending_criterion_ids)} "
            "subjective criteria."
        )
        ha_state.last_tick_step = "await_human_observation"
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_HUMAN_APPROVAL:
        ha_state.mode = HA_MODE_HUMAN_REQUIRED
        ha_state.human_required_reason = ha_state.human_required_reason or (
            "A human-critical action requires explicit approval."
        )
        ha_state.last_event = ha_state.human_required_reason
        ha_state.last_tick_step = "human_required"
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_WAIT_FOR_RESPONSE:
        ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        ha_state.last_tick_step = "wait"
        # RUN_045 PART B.4: every wait transition identifies a durable,
        # typed reason. When no legitimate condition is found here (a
        # rare/defensive case, since _plan_next_action only reaches this
        # branch when one exists or when genuinely awaiting a first
        # instruction), record that honestly rather than a blank reason.
        from admissible.high_autonomy_state_invariants import classify_waiting_for_agent_condition

        condition = classify_waiting_for_agent_condition(
            _waiting_for_agent_signals(controller, ha_state, transport)
        )
        if condition is not None:
            ha_state.wait_condition_type, ha_state.wait_condition_id = condition
            ha_state.wait_reason = condition[0]
        else:
            ha_state.wait_condition_type, ha_state.wait_condition_id = (None, None)
            ha_state.wait_reason = "awaiting_first_instruction_or_response"
        ha_state.wait_started_at = ha_state.wait_started_at or _now_iso()
        ha_state.wait_poll_count += 1
        _save_ha_state(controller, ha_state)
        controller._persist()

    _sync_counters(controller, ha_state, policy)
    _try_finalize_outcome(controller, ha_state)
    if transport is not None:
        _capture_transport_status(ha_state, transport)
    # For callable backends the durable backend_step (invoking/response_ready/
    # ingesting/consumed) is the honest status — never the raw file-bridge status.
    if _is_callable_backend(ha_state) and ha_state.backend_step:
        ha_state.transport_status = ha_state.backend_step
    ha_state.next_action = _plan_next_action(controller, ha_state, policy, transport)
    fingerprint = _build_progress_fingerprint(controller, ha_state, policy)
    progressed = (
        step_result.get("executed_action_ids")
        or step_result.get("ingested")
        or step_result.get("verified")
        or planned in (
            HA_NEXT_WRITE_INSTRUCTION,
            HA_NEXT_WRITE_RECOVERY,
            HA_NEXT_WRITE_REPAIR,
            HA_NEXT_HUMAN_APPROVAL,
            HA_NEXT_START_RUNTIME_VERIFICATION,
            HA_NEXT_APPLY_RUNTIME_EVIDENCE,
        )
        or ha_state.repair_phase
        not in (REPAIR_PHASE_NONE, "", None)
        or ha_state.last_tick_step
        in (
            "invoke_agent",
            "ingest_response",
            "verify",
            "finalize_outcome",
            "write_repair_instruction",
            "start_runtime_verification",
            "apply_runtime_evidence",
        )
    )
    if progressed or fingerprint != ha_state.last_progress_fingerprint:
        ha_state.no_progress_tick_count = 0
    elif planned in (HA_NEXT_AUTO_EXECUTE, HA_NEXT_NONE) or step_result.get("reason") == "no_ready_response":
        ha_state.no_progress_tick_count += 1
    ha_state.last_progress_fingerprint = fingerprint
    if ha_state.no_progress_tick_count >= MAX_NO_PROGRESS_TICKS:
        if _can_start_repair(controller, ha_state):
            _enter_repair_needed(controller, ha_state)
        elif _repairable_verification_failures(ha_state) and _verification_is_final(controller):
            _set_final_outcome(
                ha_state,
                outcome="incomplete",
                reason=(
                    "Mandatory acceptance criteria failed verification with no executable "
                    "action remaining; repair unavailable."
                ),
            )
        else:
            # RUN_045 PART E: a reasonless wait (mode=waiting_for_agent with
            # no legitimate pending backend/runtime/human condition) is a
            # distinct, typed technical pause -- never internal_livelock,
            # which stays reserved for a genuine contradictory execution
            # state.
            from admissible.high_autonomy_state_invariants import classify_waiting_for_agent_condition

            reasonless_wait = ha_state.mode == HA_MODE_WAITING_FOR_AGENT and (
                classify_waiting_for_agent_condition(
                    _waiting_for_agent_signals(controller, ha_state, transport)
                )
                is None
            )
            if reasonless_wait:
                _pause_for_technical_state_invariant(
                    controller,
                    ha_state,
                    fingerprint=fingerprint,
                    violation_code="waiting_for_agent_without_pending_condition",
                )
            else:
                _pause_for_no_progress_livelock(controller, ha_state, fingerprint=fingerprint)
    _save_ha_state(controller, ha_state)
    controller._persist()
    step_result["last_tick_step"] = ha_state.last_tick_step
    step_result["transport_status"] = ha_state.transport_status
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    view["high_autonomy_tick"] = step_result
    return view


def _require_human_required(ha_state: HighAutonomyRunState, *, verb: str) -> None:
    if not ha_state.active:
        raise ValueError("No active high-autonomy run.")
    if ha_state.mode != HA_MODE_HUMAN_REQUIRED and not ha_state.human_critical_pending:
        raise ValueError(f"No human-critical action pending {verb}.")


def approve_human_critical_action(
    controller: "ControlSurfaceController",
    *,
    action_id: str | None = None,
    rationale: str = "Approved in high-autonomy human-required state.",
    scope: str | None = None,
) -> dict[str, Any]:
    """Record approval/admission intent for one open human-critical action.

    Approval is a deliberate, per-action authority grant, so it targets a single
    action (the explicitly passed id, else the surfaced pending one). It never
    invents an executor: v0 has no automatic shell/network/deploy executor at any
    level, so an approved human-critical proposal is only recorded as
    admitted-not-executed — a human still runs it. If other human-critical
    actions remain undecided the loop stays in human_required for them.
    """
    from admissible.admitted_execution import EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
    from admissible.control_surface import (
        DECISION_TYPE_APPROVE,
        available_human_actions,
    )
    from admissible.run_loop import LIFECYCLE_ADMITTED_NOT_EXECUTED

    ha_state = _ha_state(controller)
    _require_human_required(ha_state, verb="approval")

    policy = HighAutonomyPolicy()
    open_actions = _open_human_critical_actions(controller, policy)
    open_ids = [a["action_id"] for a in open_actions]
    target_id = action_id or ha_state.pending_human_action_id or (open_ids[0] if open_ids else None)
    if not target_id:
        raise ValueError("No human-critical action pending approval.")

    item = controller._find_queue_item(target_id)
    if item is None:
        raise ValueError(f"unknown action_id: {target_id!r}")
    allowed = available_human_actions(item, controller._session.autonomy_level)
    if DECISION_TYPE_APPROVE not in allowed:
        raise ValueError(
            f"Action {target_id!r} (admissible decision {item.decision!r}) cannot be approved "
            "in high-autonomy; provide evidence or refuse instead."
        )

    controller.decide(
        target_id,
        {
            "decision_type": "approve",
            "rationale": rationale,
            "scope": scope or "high_autonomy_human_approved_local_only",
        },
    )
    # No safe executor exists for a human-critical action: if decide() did not
    # already flip it (side-effecting REQUIRE_HUMAN_APPROVAL items do), record the
    # approval as admitted-not-executed so it is never treated as done and never
    # re-opens as a pending human-critical proposal.
    item = controller._find_queue_item(target_id)
    if item is not None and item.execution_status == "proposed_only":
        item.execution_status = EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
        item.lifecycle_status = LIFECYCLE_ADMITTED_NOT_EXECUTED
        envelope = controller._session.run_envelopes.get(target_id)
        if envelope is not None:
            envelope.candidate["execution_status"] = EXECUTION_STATUS_ADMITTED_NOT_EXECUTED

    _sync_counters(controller, ha_state, policy)
    if ha_state.human_critical_pending:
        ha_state.mode = HA_MODE_HUMAN_REQUIRED
        ha_state.last_event = (
            f"Human approved action {target_id} (recorded only; no executor was invoked). "
            f"{ha_state.human_required_action_count} human-critical action(s) still require a decision."
        )
    else:
        ha_state.mode = HA_MODE_RUNNING
        ha_state.human_required_reason = None
        ha_state.pending_human_action_id = None
        ha_state.last_event = (
            f"Human approved action {target_id} (recorded only; no executor was invoked)."
        )
    if controller._high_autonomy_transport is not None:
        ha_state.next_action = _plan_next_action(
            controller, ha_state, policy, controller._high_autonomy_transport
        )
    else:
        ha_state.next_action = (
            HA_NEXT_HUMAN_APPROVAL if ha_state.human_critical_pending else HA_NEXT_WRITE_INSTRUCTION
        )
    controller._session.transcript.append(
        _transcript_entry(
            "high_autonomy_human_approved",
            {"action_id": target_id, "admitted_not_executed": True},
        )
    )
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def refuse_human_critical_action(
    controller: "ControlSurfaceController",
    *,
    action_id: str | None = None,
    rationale: str = "Refused in high-autonomy human-required state.",
) -> dict[str, Any]:
    """Refuse the open human-critical action(s) and hand off to local-only recovery.

    Refusal must always clear the ``human_required`` condition, so it records a
    refusal decision against *every* currently-open human-critical action (not
    just the surfaced one). Leaving any open would re-pin the loop in
    human_required on the next tick — the exact bug this fixes. The already-
    ingested response is not re-consumed; instead the next tick composes a bounded
    local-only recovery instruction grounded in the refused actions.
    """
    from admissible.control_surface import (
        DECISION_TYPE_REFUSE,
        available_human_actions,
    )

    ha_state = _ha_state(controller)
    _require_human_required(ha_state, verb="refusal")

    policy = HighAutonomyPolicy()
    open_actions = _open_human_critical_actions(controller, policy)
    # Refuse the whole open set; include an explicitly passed id defensively even
    # if classification shifted, so the caller's intent is always honoured.
    target_ids = [a["action_id"] for a in open_actions]
    if action_id and action_id not in target_ids:
        extra = controller._find_queue_item(action_id)
        if (
            extra is not None
            and extra.execution_status == "proposed_only"
            and not extra.human_decision_ids
            and DECISION_TYPE_REFUSE in available_human_actions(extra, controller._session.autonomy_level)
        ):
            target_ids.append(action_id)

    by_id = {a["action_id"]: a for a in open_actions}
    refused: list[dict[str, Any]] = []
    for aid in target_ids:
        item = controller._find_queue_item(aid)
        if item is None:
            continue
        if DECISION_TYPE_REFUSE not in available_human_actions(item, controller._session.autonomy_level):
            # Already blocked/closed by admission — nothing for a human to refuse.
            continue
        controller.decide(aid, {"decision_type": "refuse", "rationale": rationale})
        entry = by_id.get(aid) or {
            "action_id": aid,
            "action_type": item.action_type,
            "tool_or_command": item.tool_or_command,
            "reason": None,
        }
        refused.append(entry)

    ha_state.last_refused_action_ids = [entry["action_id"] for entry in refused]
    ha_state.human_critical_pending = False
    ha_state.pending_human_action_id = None
    ha_state.human_required_action_ids = []
    ha_state.human_required_action_count = 0
    ha_state.human_required_actions = []
    ha_state.human_required_reason = None
    ha_state.refusal_recovery_pending = True
    ha_state.awaiting_instruction_after_review = True
    ha_state.recovery_pending = False
    ha_state.mode = HA_MODE_RECOVERING
    count = len(refused)
    ha_state.last_event = (
        f"Human refused {count} human-critical action(s); composing a local-only "
        "recovery instruction."
        if count
        else "No open human-critical action to refuse; composing a local-only recovery instruction."
    )
    controller._session.transcript.append(
        _transcript_entry(
            "high_autonomy_human_refused",
            {"action_ids": ha_state.last_refused_action_ids, "count": count},
        )
    )
    # Recompute counters (all refused actions now carry a human decision, so none
    # remain open) and plan the recovery-instruction write for the next tick.
    _sync_counters(controller, ha_state, policy)
    if controller._high_autonomy_transport is not None:
        ha_state.next_action = _plan_next_action(
            controller, ha_state, policy, controller._high_autonomy_transport
        )
    else:
        # refusal_recovery_pending guarantees the recovery write regardless.
        ha_state.next_action = HA_NEXT_WRITE_RECOVERY
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


# --- RUN_044: narrowly-scoped runtime orchestration API surface -------------
# Only these four operations are exposed to the Control Surface (PART L.58):
# read status, retry an interrupted attempt, cancel an active attempt, record
# a human observation. None of them accept an arbitrary runtime plan,
# selector, JavaScript, browser argument, or URL from the caller (PART L.59-60)
# -- the plan always comes from admissible.mission_contract + the current
# acceptance ledger via admissible.runtime_verification_orchestrator.


def runtime_verification_status_view(controller: "ControlSurfaceController") -> dict[str, Any]:
    """PART L.58: read-only runtime-verification status projection."""

    ha_state = _ha_state(controller)
    return {
        "runtime_verification_required": ha_state.runtime_verification_required,
        "runtime_verification_status": ha_state.runtime_verification_status,
        "active_runtime_attempt_id": ha_state.active_runtime_attempt_id,
        "active_runtime_attempt": ha_state.active_runtime_attempt,
        "runtime_attempt_history": list(ha_state.runtime_attempt_history),
        "last_runtime_plan_sha256": ha_state.last_runtime_plan_sha256,
        "last_runtime_evidence_id": ha_state.last_runtime_evidence_id,
        "runtime_criterion_ids": list(ha_state.runtime_criterion_ids),
        "runtime_pending_criterion_ids": list(ha_state.runtime_pending_criterion_ids),
        "runtime_failed_criterion_ids": list(ha_state.runtime_failed_criterion_ids),
        "runtime_gap_criterion_ids": list(ha_state.runtime_gap_criterion_ids),
        "human_observation_pending_criterion_ids": list(ha_state.human_observation_pending_criterion_ids),
        "human_observation_records": list(ha_state.human_observation_records),
        "runtime_coverage_report": ha_state.runtime_coverage_report,
    }


def retry_interrupted_runtime_attempt(controller: "ControlSurfaceController") -> dict[str, Any]:
    """PART G.29 / PART L.58: explicitly retry an interrupted runtime attempt.

    Never auto-triggered by a tick (PART G.25); requires an explicit
    operator/API call, and preserves lineage to the interrupted attempt
    (prior attempt id, plan sha, affected criteria, artifact hashes).
    """

    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run.")
    from admissible.runtime_orchestration_models import STATUS_INTERRUPTED

    attempt = _active_runtime_attempt(ha_state)
    if attempt is None or attempt.status != STATUS_INTERRUPTED:
        raise ValueError("No interrupted runtime attempt to retry.")
    plan_obj = _active_runtime_plan_obj(ha_state)
    if plan_obj is None:
        raise ValueError("No persisted runtime plan to retry against.")

    from admissible.runtime_verification_orchestrator import build_retry_attempt, default_runtime_provider

    contract = controller._session.mission_contract or {}
    provider = controller._runtime_provider_override or default_runtime_provider()
    new_attempt, transition = build_retry_attempt(
        interrupted=attempt,
        session_id=controller._session.session_id,
        mission_contract=contract,
        ledger=ha_state.acceptance_criteria,
        plan=plan_obj,
        provider=provider,
        operation_records=controller._session.operation_records,
        reason="interrupted_attempt_retry",
    )
    if new_attempt is None:
        raise ValueError(transition.event_message)

    # Archive the superseded interrupted attempt into history before
    # replacing it, so the full attempt lineage stays observable even though
    # the new attempt also carries retry_of_attempt_id back to it.
    ha_state.runtime_attempt_history.append(
        {
            "attempt_id": attempt.attempt_id,
            "session_id": attempt.session_id,
            "runtime_plan_sha256": attempt.runtime_plan_sha256,
            "retry_of_attempt_id": attempt.retry_of_attempt_id,
            "semantic_status": "interrupted",
            "cleanup_status": attempt.cleanup_status,
            "criterion_ids": list(attempt.criterion_ids),
            "started_at": attempt.started_at,
            "completed_at": attempt.completed_at,
        }
    )
    ha_state.active_runtime_attempt_id = new_attempt.attempt_id
    ha_state.active_runtime_attempt = new_attempt.to_dict()
    ha_state.last_runtime_plan_sha256 = new_attempt.runtime_plan_sha256
    ha_state.runtime_verification_status = "runtime_verification_pending"
    ha_state.mode = HA_MODE_RUNTIME_VERIFYING
    ha_state.last_event = transition.event_message
    controller._session.governance_records.append(
        {
            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
            "event_type": "runtime_attempt_retry_requested",
            "attempt_id": new_attempt.attempt_id,
            "retry_of_attempt_id": attempt.attempt_id,
            "timestamp": _now_iso(),
        }
    )
    _save_ha_state(controller, ha_state)
    controller._persist()
    return controller.state_view()


def cancel_active_runtime_attempt(controller: "ControlSurfaceController") -> dict[str, Any]:
    """PART L.58: explicitly cancel an active runtime attempt and clean up."""

    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run.")
    attempt = _active_runtime_attempt(ha_state)
    if attempt is None:
        raise ValueError("No active runtime attempt to cancel.")

    from admissible.runtime_verification_orchestrator import cancel_runtime_attempt

    transition = cancel_runtime_attempt(attempt=attempt)
    ha_state.runtime_attempt_history.append(
        {
            "attempt_id": attempt.attempt_id,
            "session_id": attempt.session_id,
            "runtime_plan_sha256": attempt.runtime_plan_sha256,
            "retry_of_attempt_id": attempt.retry_of_attempt_id,
            "semantic_status": "cancelled",
            "cleanup_status": attempt.cleanup_status,
            "criterion_ids": list(attempt.criterion_ids),
            "started_at": attempt.started_at,
            "completed_at": attempt.completed_at,
        }
    )
    ha_state.active_runtime_attempt_id = None
    ha_state.active_runtime_attempt = None
    ha_state.active_runtime_plan = None
    ha_state.runtime_verification_status = "cancelled"
    ha_state.mode = HA_MODE_RUNNING
    ha_state.last_event = transition.event_message
    controller._session.governance_records.append(
        {
            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
            "event_type": "runtime_attempt_cancelled",
            "attempt_id": attempt.attempt_id,
            "timestamp": _now_iso(),
        }
    )
    _save_ha_state(controller, ha_state)
    controller._persist()
    return controller.state_view()


def record_human_observation_decision(
    controller: "ControlSurfaceController",
    *,
    criterion_id: str,
    actor: str,
    disposition: str,
    note: str,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    """PART J.47-51: record one human observation, distinct from human authority.

    Never counted in ``human_critical_pending``/``human_required_*``; tracked
    separately via ``human_observation_records`` and its own metrics
    (``human_observation_count`` etc., PART J.51).
    """

    ha_state = _ha_state(controller)
    if not ha_state or not ha_state.active:
        raise ValueError("No active high-autonomy run.")

    from admissible.runtime_verification_orchestrator import record_human_observation

    record, transition = record_human_observation(
        ledger=ha_state.acceptance_criteria,
        criterion_id=criterion_id,
        actor=actor,
        disposition=disposition,
        note=note,
        evidence_refs=evidence_refs,
    )
    ha_state.human_observation_records.append(record.to_dict())
    controller._session.governance_records.append(
        {
            "record_id": f"governance_{uuid.uuid4().hex[:12]}",
            "event_type": "human_observation_recorded",
            "criterion_id": criterion_id,
            "disposition": disposition,
            "actor": actor,
            "timestamp": _now_iso(),
        }
    )
    ha_state.last_event = transition.event_message
    _save_ha_state(controller, ha_state)
    controller._persist()
    return controller.state_view()
