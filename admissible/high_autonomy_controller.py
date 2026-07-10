"""High-autonomy governed run controller v0 — tick-driven state machine.

One safe step per ``tick_high_autonomy_run`` call. No hidden background loops.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from admissible.agent_transport import AgentTransport

from admissible.high_autonomy_policy import HighAutonomyPolicy
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

HA_NEXT_NONE = "none"
HA_NEXT_WRITE_INSTRUCTION = "write_instruction"
HA_NEXT_WAIT_FOR_RESPONSE = "wait_for_agent_response"
HA_NEXT_INGEST_RESPONSE = "ingest_response"
HA_NEXT_AUTO_EXECUTE = "auto_execute_low_risk"
HA_NEXT_WRITE_RECOVERY = "write_recovery_instruction"
HA_NEXT_VERIFY = "run_bounded_verification"
HA_NEXT_HUMAN_APPROVAL = "human_approval_required"
HA_NEXT_STOP = "stop"

DEFAULT_MAX_TURNS = 12
DEFAULT_MALFORMED_RETRY_LIMIT = 1

# Mirrors admissible.agent_transport.TRANSPORT_STATUS_MALFORMED_RETRY; kept as a
# local literal so the controller never needs a module-level transport import.
_TRANSPORT_STATUS_MALFORMED_RETRY = "malformed_response_retry"

_RECOVERY_PREAMBLE = (
    "RECOVERY REQUEST: prior turn proposed blocked dependency/deploy/network actions "
    "that must NOT be treated as done. Propose the smallest local-only admissible "
    "alternative — no npm, pip, shell, network, CDN, or deploy."
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
    awaiting_instruction_after_review: bool = False
    recovery_pending: bool = False
    recovery_attempted: bool = False
    transport_kind: str = "file_bridge"
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "HighAutonomyRunState":
        if not data:
            return cls()
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {key: value for key, value in data.items() if key in known}
        return cls(**filtered)


def _transcript_entry(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"timestamp": _now_iso(), "event_type": event_type, "payload": payload}


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
        HA_MODE_STOPPED: "Stopped.",
        HA_MODE_FAILED: "Failed.",
    }.get(ha_state.mode, ha_state.mode)

    needed_now = {
        HA_NEXT_NONE: "No action required.",
        HA_NEXT_WRITE_INSTRUCTION: "Controller will write the next instruction automatically.",
        HA_NEXT_WAIT_FOR_RESPONSE: "Agent must write `.admissible/agent-response.md`.",
        HA_NEXT_INGEST_RESPONSE: "Controller will ingest the agent response on the next tick.",
        HA_NEXT_AUTO_EXECUTE: "Controller will auto-execute low-risk local writes.",
        HA_NEXT_WRITE_RECOVERY: "Controller will request a local-only recovery step.",
        HA_NEXT_VERIFY: "Controller will run bounded verification.",
        HA_NEXT_HUMAN_APPROVAL: "Approve or refuse the human-critical action.",
        HA_NEXT_STOP: "Run is stopping.",
    }.get(ha_state.next_action, ha_state.next_action)

    verification_readiness = ha_state.verification_readiness or verification.get(
        "readiness", "not_run"
    )
    live_status = build_live_high_autonomy_rehearsal_status(
        ha_state=ha_state, state_view=state_view
    )
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
        "pending_low_risk_action_count": ha_state.pending_low_risk_action_count,
        "auto_executed_action_count": ha_state.auto_executed_action_count,
        "blocked_action_count": ha_state.blocked_action_count,
        "evidence_count": ha_state.evidence_count or timeline.get("evidence_count", 0),
        "verification_readiness": verification_readiness,
        "verification_passed": verification_readiness == "pass",
        "max_turns": ha_state.max_turns,
        "stop_reason": ha_state.stop_reason,
        "paused": ha_state.paused,
        "primary_button": _primary_button(ha_state),
        "turn_count": timeline.get("turn_count", 0),
        "blocked_count": governed.get("blocked_count", 0),
        "write_evidence_count": governed.get("write_evidence_count", 0),
        "tick_count": ha_state.tick_count,
        "transport_kind": ha_state.transport_kind,
        # Live transport/bridge status (display-only) for the auto-tick UI.
        "transport_status": ha_state.transport_status,
        "workspace_path": ha_state.workspace_path,
        "instruction_path": ha_state.instruction_path,
        "response_path": ha_state.response_path,
        "waiting_for_agent": ha_state.mode == HA_MODE_WAITING_FOR_AGENT,
        "stale_response_blocked": ha_state.stale_response_blocked,
        "auto_tick_safe": _auto_tick_safe(ha_state),
        "live_rehearsal_status": live_status,
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
    if ha_state.human_critical_pending:
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
        "transport_status": ha_state.transport_status,
        "instruction_path": ha_state.instruction_path,
        "response_path": ha_state.response_path,
        "current_turn": ha_state.current_turn,
        "waiting_for_cursor": ha_state.mode == HA_MODE_WAITING_FOR_AGENT,
        "stale_response_blocked": ha_state.stale_response_blocked,
        "human_action_required": ha_state.mode == HA_MODE_HUMAN_REQUIRED
        or ha_state.human_critical_pending,
        "human_required_reason": ha_state.human_required_reason,
        "verification_passed": verification_readiness == "pass",
        "verification_readiness": verification_readiness,
        "auto_tick_safe": _auto_tick_safe(ha_state),
    }


def _primary_button(ha_state: HighAutonomyRunState) -> str:
    if not ha_state.active or ha_state.mode == HA_MODE_OFF:
        return "start"
    if ha_state.mode == HA_MODE_HUMAN_REQUIRED:
        return "approve_or_refuse"
    if ha_state.paused:
        return "resume"
    if ha_state.mode in (HA_MODE_STOPPED, HA_MODE_FAILED):
        return "start"
    return "pause"


def _transport_has_pending_response(transport: "AgentTransport") -> bool:
    """True when the transport still has an unread agent response queued."""
    if hasattr(transport, "_response_index") and hasattr(transport, "_responses"):
        return transport._response_index < len(transport._responses)
    return True


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
    ha_state.stale_response_blocked = snap.get("status") == TRANSPORT_STATUS_STALE_BLOCKED


def _latest_instruction_id(controller: "ControlSurfaceController") -> str | None:
    """Packet id of the most recent instruction, for bridge/controller alignment."""
    packets = controller._session.run_loop.instruction_packets
    return packets[-1].packet_id if packets else None


def _ha_state(controller: "ControlSurfaceController") -> HighAutonomyRunState:
    return controller._high_autonomy_state()


def _save_ha_state(controller: "ControlSurfaceController", ha_state: HighAutonomyRunState) -> None:
    controller._set_high_autonomy_state(ha_state)


def _sync_counters(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    policy: HighAutonomyPolicy,
) -> None:
    view = controller.state_view()
    session = controller._session
    workspace = session.bounded_executor_workspace
    pending_auto = 0
    blocked = 0
    recoverable = False
    human_critical_id: str | None = None
    human_critical_reason: str | None = None

    for item in session.queue:
        envelope = session.run_envelopes.get(item.action_id)
        classification = policy.classify_action(
            item=item, envelope=envelope, workspace_path=workspace
        )
        if classification.category == "auto_executable":
            pending_auto += 1
        elif classification.category in ("blocked_not_completed", "recoverable_blocker"):
            blocked += 1
        # A genuinely human-critical proposal pauses only while it is still an
        # open, undecided proposal. Once a human has approved/refused it (the
        # item carries a human_decision_id, or execution_status left
        # proposed_only), it must not re-trigger a pause on the next tick.
        if (
            classification.category == "human_critical"
            and item.execution_status == "proposed_only"
            and not item.human_decision_ids
        ):
            if human_critical_id is None:
                human_critical_id = item.action_id
                human_critical_reason = classification.reason
        if classification.category == "recoverable_blocker":
            recoverable = True

    ha_state.pending_low_risk_action_count = pending_auto
    ha_state.blocked_action_count = blocked
    ha_state.evidence_count = (view.get("run_timeline") or {}).get("evidence_count", 0)
    ha_state.verification_readiness = (view.get("verification_summary") or {}).get(
        "readiness", "not_run"
    )
    ha_state.current_turn = session.run_loop.current_turn
    ha_state.recovery_pending = recoverable and pending_auto == 0 and not ha_state.recovery_attempted

    ha_state.human_critical_pending = human_critical_id is not None
    if human_critical_id is not None:
        ha_state.pending_human_action_id = human_critical_id
        ha_state.human_required_reason = human_critical_reason
    elif ha_state.mode != HA_MODE_HUMAN_REQUIRED:
        # No open human-critical proposal and not currently paused for one.
        ha_state.pending_human_action_id = None
        if not ha_state.paused:
            ha_state.human_required_reason = None


def _plan_next_action(
    controller: "ControlSurfaceController",
    ha_state: HighAutonomyRunState,
    policy: HighAutonomyPolicy,
    transport: "AgentTransport",
) -> str:
    if ha_state.paused or ha_state.mode in (HA_MODE_STOPPED, HA_MODE_FAILED, HA_MODE_OFF):
        return HA_NEXT_NONE
    if ha_state.mode == HA_MODE_HUMAN_REQUIRED or ha_state.human_critical_pending:
        return HA_NEXT_HUMAN_APPROVAL

    view = controller.state_view()
    timeline = view.get("run_timeline") or {}
    continuation = view.get("continuation_instruction") or {}
    ready_count = timeline.get("ready_to_execute_local_count", 0)

    if ha_state.mode == HA_MODE_WAITING_FOR_AGENT:
        if not _transport_has_pending_response(transport):
            if ha_state.verification_readiness in ("pass", "fail"):
                return HA_NEXT_STOP
        return HA_NEXT_INGEST_RESPONSE

    if ready_count > 0 and ha_state.mode in (HA_MODE_REVIEWING, HA_MODE_RUNNING, HA_MODE_AUTO_EXECUTING):
        return HA_NEXT_AUTO_EXECUTE

    if ha_state.recovery_pending and ha_state.mode == HA_MODE_REVIEWING:
        cont_status = continuation.get("status")
        if cont_status == CONTINUATION_STATUS_EVIDENCE_GROUNDED and continuation.get("available"):
            return HA_NEXT_WRITE_RECOVERY

    if policy.should_run_verification(
        evidence_count=ha_state.evidence_count,
        verification_readiness=ha_state.verification_readiness,
        ready_to_execute_local_count=ready_count,
        awaiting_next_instruction=ha_state.awaiting_instruction_after_review,
        has_recoverable_blockers=ha_state.recovery_pending,
    ):
        return HA_NEXT_VERIFY

    if (
        ha_state.verification_readiness in ("pass", "fail")
        and ready_count == 0
        and ha_state.pending_low_risk_action_count == 0
        and not _transport_has_pending_response(transport)
    ):
        return HA_NEXT_STOP

    if ha_state.awaiting_instruction_after_review or (
        ha_state.mode == HA_MODE_RUNNING
        and not view.get("session_diagnostics", {}).get("bridge_awaiting_response")
    ):
        cont_status = continuation.get("status")
        if cont_status == CONTINUATION_STATUS_PENDING_LOCAL_EXECUTION:
            return HA_NEXT_AUTO_EXECUTE
        if continuation.get("available") or cont_status == CONTINUATION_STATUS_FIRST_TURN:
            if ha_state.current_turn < ha_state.max_turns:
                if _transport_has_pending_response(transport):
                    return HA_NEXT_WRITE_INSTRUCTION
                if not ha_state.recovery_attempted:
                    return HA_NEXT_WRITE_INSTRUCTION

    if ha_state.current_turn >= ha_state.max_turns:
        return HA_NEXT_STOP

    return HA_NEXT_WAIT_FOR_RESPONSE


def start_high_autonomy_run(
    controller: "ControlSurfaceController",
    *,
    workspace_path: str,
    transport: "AgentTransport | None" = None,
    max_turns: int = DEFAULT_MAX_TURNS,
) -> dict[str, Any]:
    from admissible.agent_transport import FileBridgeAgentTransport

    if not controller._session.goal_intake:
        raise ValueError("Submit a goal before starting a high-autonomy run.")

    controller.set_bounded_executor_workspace(workspace_path)
    controller.set_autonomy("L4_HIGH_AUTONOMY_HARD_GATES")

    if transport is None:
        transport = FileBridgeAgentTransport(workspace_path)

    snap = transport.status_snapshot()
    ha_state = HighAutonomyRunState(
        active=True,
        mode=HA_MODE_RUNNING,
        max_turns=max_turns,
        started_at=_now_iso(),
        transport_kind=(
            "fixture" if type(transport).__name__ == "FixtureAgentTransport" else "file_bridge"
        ),
        transport_status=str(snap.get("status") or "idle"),
        workspace_path=snap.get("workspace_path") or workspace_path,
        instruction_path=snap.get("instruction_path"),
        response_path=snap.get("response_path"),
        last_event="High-autonomy run started.",
        next_action=HA_NEXT_WRITE_INSTRUCTION,
    )
    controller._high_autonomy_transport = transport
    _save_ha_state(controller, ha_state)
    controller._session.transcript.append(
        _transcript_entry(
            "high_autonomy_run_started",
            {
                "workspace_path": workspace_path,
                "max_turns": max_turns,
                "transport_kind": ha_state.transport_kind,
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


def stop_high_autonomy_run(
    controller: "ControlSurfaceController",
    *,
    reason: str = "Stopped by operator.",
) -> dict[str, Any]:
    ha_state = _ha_state(controller)
    if not ha_state.active and ha_state.mode == HA_MODE_OFF:
        ha_state = HighAutonomyRunState()
    ha_state.active = False
    ha_state.mode = HA_MODE_STOPPED
    ha_state.stop_reason = reason
    ha_state.last_event = reason
    ha_state.next_action = HA_NEXT_NONE
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


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

    transport = controller._high_autonomy_transport
    if transport is None:
        raise ValueError("High-autonomy transport is not configured.")

    policy = policy or HighAutonomyPolicy()
    _sync_counters(controller, ha_state, policy)
    planned = _plan_next_action(controller, ha_state, policy, transport)
    ha_state.next_action = planned
    ha_state.last_tick_at = _now_iso()
    ha_state.tick_count += 1
    step_result: dict[str, Any] = {"planned": planned}

    if planned == HA_NEXT_STOP:
        ha_state.mode = HA_MODE_STOPPED
        ha_state.active = False
        ha_state.stop_reason = f"Reached max turns ({ha_state.max_turns})."
        ha_state.last_event = ha_state.stop_reason
        ha_state.last_tick_step = "stop"
        _save_ha_state(controller, ha_state)
        controller._persist()
        view = controller.state_view()
        view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
        view["high_autonomy_tick"] = step_result
        return view

    if planned == HA_NEXT_WRITE_INSTRUCTION:
        view_before = controller.state_view()
        continuation = view_before.get("continuation_instruction") or {}
        instruction_text = continuation.get("instruction_text")
        run_loop = controller._session.run_loop
        if not run_loop.response_records:
            packet_view = controller.generate_next_instruction_packet()
            instruction_text = packet_view["run_loop"]["instruction_packets"][-1]["packet_text"]
        elif instruction_text:
            controller.generate_next_continuation_instruction_packet(instruction_text=instruction_text)
        else:
            packet_view = controller.generate_next_instruction_packet()
            instruction_text = packet_view["run_loop"]["instruction_packets"][-1]["packet_text"]

        bridge_result = transport.write_instruction(
            instruction_text,
            turn_number=controller._session.run_loop.current_turn,
            session_id=controller._session.session_id,
            instruction_id=_latest_instruction_id(controller),
        )
        ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        ha_state.last_event = f"Wrote turn {controller._session.run_loop.current_turn} instruction automatically."
        ha_state.awaiting_instruction_after_review = False
        ha_state.last_tick_step = "write_instruction"
        step_result.update({"bridge": bridge_result, "turn": controller._session.run_loop.current_turn})
        controller._session.transcript.append(
            _transcript_entry(
                "high_autonomy_instruction_written",
                {"turn": controller._session.run_loop.current_turn, "bridge": bridge_result},
            )
        )
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_WRITE_RECOVERY:
        view_before = controller.state_view()
        continuation = view_before.get("continuation_instruction") or {}
        instruction_text = continuation.get("instruction_text") or ""
        recovery_text = f"{_RECOVERY_PREAMBLE}\n\n{instruction_text}".strip()
        controller.generate_next_continuation_instruction_packet(instruction_text=recovery_text)
        bridge_result = transport.write_instruction(
            recovery_text,
            turn_number=controller._session.run_loop.current_turn,
            session_id=controller._session.session_id,
            instruction_id=_latest_instruction_id(controller),
        )
        ha_state.mode = HA_MODE_WAITING_FOR_AGENT
        ha_state.recovery_pending = False
        ha_state.recovery_attempted = True
        ha_state.last_event = "Wrote local-only recovery instruction automatically."
        ha_state.last_tick_step = "write_recovery_instruction"
        step_result.update({"bridge": bridge_result})
        controller._session.transcript.append(
            _transcript_entry("high_autonomy_recovery_instruction_written", {"bridge": bridge_result})
        )
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_INGEST_RESPONSE:
        read_result = transport.read_response_if_changed()
        if not read_result.changed or not read_result.text:
            ha_state.mode = HA_MODE_WAITING_FOR_AGENT
            ha_state.last_tick_step = "noop_waiting"
            step_result["reason"] = "no_new_response"
            _save_ha_state(controller, ha_state)
            controller._persist()
        else:
            try:
                controller.ingest_agent_response(read_result.text)
                ha_state.last_response_cursor = read_result.cursor
                ha_state.mode = HA_MODE_REVIEWING
                ha_state.awaiting_instruction_after_review = True
                ha_state.malformed_retry_count = 0
                ha_state.last_event = (
                    f"Ingested turn {controller._session.run_loop.current_turn} response automatically."
                )
                ha_state.last_tick_step = "ingest_response"
                step_result["ingested"] = True
                transport.mark_response_consumed(
                    turn_number=controller._session.run_loop.current_turn,
                    response_sha256=read_result.cursor or "",
                )
                controller._session.transcript.append(
                    _transcript_entry(
                        "high_autonomy_response_ingested",
                        {"turn": controller._session.run_loop.current_turn},
                    )
                )
                _save_ha_state(controller, ha_state)
                controller._persist()
            except ValueError as exc:
                if ha_state.malformed_retry_count < DEFAULT_MALFORMED_RETRY_LIMIT:
                    ha_state.malformed_retry_count += 1
                    retry_text = (
                        "MALFORMED RESPONSE: your prior response could not be ingested. "
                        f"Error: {exc}. Reply with structured operations only."
                    )
                    transport.note_status(
                        _TRANSPORT_STATUS_MALFORMED_RETRY, error=str(exc)
                    )
                    transport.write_instruction(
                        retry_text,
                        turn_number=controller._session.run_loop.current_turn,
                        session_id=controller._session.session_id,
                    )
                    ha_state.mode = HA_MODE_WAITING_FOR_AGENT
                    ha_state.last_event = "Malformed response — sent one bounded retry instruction."
                    ha_state.last_tick_step = "malformed_retry"
                    step_result["retry"] = True
                    _save_ha_state(controller, ha_state)
                    controller._persist()
                else:
                    ha_state.mode = HA_MODE_FAILED
                    ha_state.active = False
                    ha_state.stop_reason = f"Malformed agent response: {exc}"
                    ha_state.last_event = ha_state.stop_reason
                    ha_state.last_tick_step = "failed"
                    _save_ha_state(controller, ha_state)
                    controller._persist()

    elif planned == HA_NEXT_AUTO_EXECUTE:
        workspace = controller._session.bounded_executor_workspace
        session = controller._session
        executed_ids: list[str] = []
        for item in list(session.queue):
            envelope = session.run_envelopes.get(item.action_id)
            if not policy.is_auto_executable(item=item, envelope=envelope, workspace_path=workspace):
                continue
            if item.execution_status != "proposed_only":
                continue
            try:
                controller.execute_bounded_local(
                    item.action_id, {"workspace_path": workspace}
                )
                executed_ids.append(item.action_id)
                ha_state.auto_executed_action_count += 1
            except Exception:
                continue

        ha_state.mode = HA_MODE_AUTO_EXECUTING if executed_ids else HA_MODE_REVIEWING
        if executed_ids:
            if ha_state.recovery_attempted:
                ha_state.awaiting_instruction_after_review = False
            else:
                ha_state.awaiting_instruction_after_review = True
            ha_state.last_event = (
                f"Auto-executed {len(executed_ids)} low-risk local write(s)."
            )
        else:
            ha_state.last_event = "No low-risk actions to auto-execute."
        ha_state.last_tick_step = "auto_execute"
        step_result["executed_action_ids"] = executed_ids
        controller._session.transcript.append(
            _transcript_entry("high_autonomy_auto_executed", {"action_ids": executed_ids})
        )
        _save_ha_state(controller, ha_state)
        controller._persist()

    elif planned == HA_NEXT_VERIFY:
        workspace = controller._session.bounded_executor_workspace
        controller.verify_bounded_local_workspace({"workspace_path": workspace, "profile": "tiny_game_demo"})
        ha_state.mode = HA_MODE_VERIFYING
        ha_state.last_event = "Ran bounded verification as a controller step."
        ha_state.last_tick_step = "verify"
        step_result["verified"] = True
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
        _save_ha_state(controller, ha_state)
        controller._persist()

    _sync_counters(controller, ha_state, policy)
    _capture_transport_status(ha_state, transport)
    ha_state.next_action = _plan_next_action(controller, ha_state, policy, transport)
    _save_ha_state(controller, ha_state)
    controller._persist()
    step_result["last_tick_step"] = ha_state.last_tick_step
    step_result["transport_status"] = ha_state.transport_status
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    view["high_autonomy_tick"] = step_result
    return view


def approve_human_critical_action(
    controller: "ControlSurfaceController",
    *,
    action_id: str,
    rationale: str = "Approved in high-autonomy human-required state.",
    scope: str | None = None,
) -> dict[str, Any]:
    ha_state = _ha_state(controller)
    if not ha_state.active or ha_state.mode != HA_MODE_HUMAN_REQUIRED:
        raise ValueError("No human-critical action pending approval.")
    # Recording the decision never invents an executor: v0 has no automatic
    # shell/network/deploy executor at any level, so approving a human-critical
    # proposal only marks it admitted-not-executed. A human still runs it.
    decision_body: dict[str, Any] = {
        "decision_type": "approve",
        "rationale": rationale,
        "scope": scope or "high_autonomy_human_approved_local_only",
    }
    controller.decide(action_id, decision_body)
    ha_state.mode = HA_MODE_RUNNING
    ha_state.human_required_reason = None
    ha_state.pending_human_action_id = None
    ha_state.human_critical_pending = False
    ha_state.last_event = (
        f"Human approved action {action_id} (recorded only; no executor was invoked)."
    )
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view


def refuse_human_critical_action(
    controller: "ControlSurfaceController",
    *,
    action_id: str,
    rationale: str = "Refused in high-autonomy human-required state.",
) -> dict[str, Any]:
    ha_state = _ha_state(controller)
    if not ha_state.active or ha_state.mode != HA_MODE_HUMAN_REQUIRED:
        raise ValueError("No human-critical action pending refusal.")
    controller.decide(
        action_id,
        {"decision_type": "refuse", "rationale": rationale},
    )
    ha_state.mode = HA_MODE_RUNNING
    ha_state.human_required_reason = None
    ha_state.pending_human_action_id = None
    ha_state.human_critical_pending = False
    ha_state.recovery_pending = True
    ha_state.awaiting_instruction_after_review = True
    ha_state.last_event = f"Human refused action {action_id}; recovery may continue."
    _save_ha_state(controller, ha_state)
    controller._persist()
    view = controller.state_view()
    view["high_autonomy_summary"] = build_high_autonomy_summary(ha_state=ha_state, state_view=view)
    return view
