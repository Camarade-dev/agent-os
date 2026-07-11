"""RUN_045: centralized high-autonomy state-machine invariant checking.

Fixes the class of bug exposed by a real session
(`control_session_89d4376c8c43`, minimized as
`tests/fixtures/admissible/pixel_wanderer_cli_002_regression.json`): a
persisted state combination that is internally contradictory --
`mode=waiting_for_agent` while every durable signal says nothing is
actually pending from any backend -- was never detected, so every
auto-run tick returned a reasonless wait forever. This is a general
state-machine/liveness defect, not specific to Pixel Wanderer, game
controls, or the browser runtime.

Pure and standalone, like `admissible.browser_runtime.state_machine`
(RUN_043) and `admissible.runtime_verification_orchestrator` (RUN_044):
this module never mutates `HighAutonomyRunState` directly. It only
inspects already-gathered signals and returns typed decisions/violations;
`admissible.high_autonomy_controller` gathers the signals (it already owns
the private helpers for callable-backend/transport/runtime state) and
applies whatever this module decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- PART E.4: a closed, typed wait-condition vocabulary --------------------
WAIT_BACKEND_INVOCATION_RUNNING = "backend_invocation_running"
WAIT_RUNTIME_WORKER_RUNNING = "runtime_worker_running"
WAIT_EVIDENCE_FILE_PENDING = "evidence_file_pending"
WAIT_HUMAN_AUTHORITY_DECISION = "human_authority_decision"
WAIT_HUMAN_OBSERVATION = "human_observation"
WAIT_EXPLICIT_OPERATOR_RETRY = "explicit_operator_retry"

SUPPORTED_WAIT_CONDITIONS = frozenset(
    {
        WAIT_BACKEND_INVOCATION_RUNNING,
        WAIT_RUNTIME_WORKER_RUNNING,
        WAIT_EVIDENCE_FILE_PENDING,
        WAIT_HUMAN_AUTHORITY_DECISION,
        WAIT_HUMAN_OBSERVATION,
        WAIT_EXPLICIT_OPERATOR_RETRY,
    }
)

# repair_phase values that mean "a repair write already executed; a rerun is
# due" -- deliberately literal strings (not imported from
# high_autonomy_controller) so this module has zero import-time dependency
# on it; the controller already uses these same two literal values as
# REPAIR_PHASE_REPAIR_EXECUTING / REPAIR_PHASE_REPAIR_VERIFYING.
POST_REPAIR_WRITE_PHASES = frozenset({"repair_executing", "repair_verifying"})


@dataclass(frozen=True)
class WaitingForAgentSignals:
    """Every durable signal needed to judge whether `waiting_for_agent` is justified."""

    is_callable_backend: bool
    backend_step: str | None
    pending_invocation_status: str | None
    backend_retry_required: bool
    backend_reinvoke_pending: bool
    transport_has_pending_response: bool
    runtime_worker_active: bool = False


@dataclass(frozen=True)
class StateInvariantViolation:
    code: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


def classify_waiting_for_agent_condition(
    signals: WaitingForAgentSignals,
) -> tuple[str, str] | None:
    """PART B invariant A / PART E.4: the one legitimate reason
    `mode=waiting_for_agent` may still hold.

    Returns ``(wait_condition_type, wait_condition_id)`` when at least one
    of these holds:

    - a callable-backend instruction/invocation is queued/running or its
      response is awaiting ingestion (``pending_invocation_status`` not in
      ``(None, "consumed")``);
    - the file-bridge transport has a genuinely unread response;
    - an explicit operator retry is required
      (``backend_retry_required``/``backend_reinvoke_pending``).

    Returns ``None`` when none of these hold -- callers must never keep
    reporting/treating ``waiting_for_agent`` as legitimate in that case
    (this is exactly the invalid combination PART B.3.A names:
    ``backend_step=response_consumed`` + ``pending invocation
    status=consumed`` + ``backend_retry_required=false`` +
    ``backend_reinvoke_pending=false``).
    """

    if signals.runtime_worker_active:
        return (WAIT_RUNTIME_WORKER_RUNNING, "runtime_attempt")
    if signals.is_callable_backend:
        if signals.pending_invocation_status not in (None, "consumed"):
            return (WAIT_EVIDENCE_FILE_PENDING, signals.pending_invocation_status or "")
        if signals.backend_retry_required or signals.backend_reinvoke_pending:
            return (WAIT_EXPLICIT_OPERATOR_RETRY, "backend_retry")
        return None
    if signals.transport_has_pending_response:
        return (WAIT_EVIDENCE_FILE_PENDING, "response_file")
    if signals.backend_retry_required or signals.backend_reinvoke_pending:
        return (WAIT_EXPLICIT_OPERATOR_RETRY, "backend_retry")
    return None


def waiting_for_agent_is_valid(signals: WaitingForAgentSignals) -> bool:
    return classify_waiting_for_agent_condition(signals) is not None


def repair_needs_post_write_verification(repair_phase: str) -> bool:
    """PART C: true once a repair write has executed and a rerun is due."""

    return repair_phase in POST_REPAIR_WRITE_PHASES


def plan_post_repair_verification(
    *,
    repair_phase: str,
    runtime_repair_kind: str | None,
    runtime_repair_kinds: frozenset[str] = frozenset(
        {"runtime_verification_failure", "runtime_instrumentation_gap"}
    ),
) -> str | None:
    """PART C: the canonical post-repair-write verification routing decision.

    Returns ``None`` when repair isn't in a post-write state at all (nothing
    to schedule). Otherwise returns ``"start_runtime_verification"`` when the
    repair that just landed was runtime-sourced, else ``"run_bounded_verification"``
    (static) -- the exact two `high_autonomy_controller.HA_NEXT_*` constants,
    given as literals here so this module never needs to import the
    controller (avoiding any load-order coupling).
    """

    if not repair_needs_post_write_verification(repair_phase):
        return None
    if runtime_repair_kind in runtime_repair_kinds:
        return "start_runtime_verification"
    return "run_bounded_verification"


@dataclass(frozen=True)
class ReconciliationSignals:
    """Everything needed to detect + repair a contradictory persisted state
    on session load or before a tick (PART D)."""

    mode: str
    repair_phase: str
    runtime_repair_kind: str | None
    pending_useful_operation_count: int
    active_blocked_count: int
    waiting_for_agent_signals: WaitingForAgentSignals


@dataclass(frozen=True)
class ReconciliationResult:
    changed: bool
    new_mode: str | None = None
    new_next_action: str | None = None
    violations: tuple[StateInvariantViolation, ...] = ()


def reconcile_contradictory_state(signals: ReconciliationSignals) -> ReconciliationResult:
    """PART D: deterministically repair one known-invalid state combination.

    The canonical fixture combination -- ``mode=waiting_for_agent`` with no
    legitimate wait condition, ``repair_phase`` already past the write
    (``repair_executing``/``repair_verifying``), no pending useful
    operation, and no active blocker -- recovers to ``mode=verifying`` +
    ``next_action`` set by :func:`plan_post_repair_verification`. This never
    consumes a model turn, a repair round, or a human-intervention metric:
    it is a pure relabeling of already-persisted state, not a new action.
    """

    if signals.mode != "waiting_for_agent":
        return ReconciliationResult(changed=False)
    if waiting_for_agent_is_valid(signals.waiting_for_agent_signals):
        return ReconciliationResult(changed=False)
    if signals.pending_useful_operation_count > 0 or signals.active_blocked_count > 0:
        return ReconciliationResult(changed=False)

    violation = StateInvariantViolation(
        code="waiting_for_agent_without_pending_condition",
        message=(
            "mode=waiting_for_agent persisted with no legitimate pending "
            "backend/runtime/human condition (PART B invariant A)."
        ),
        detail={"repair_phase": signals.repair_phase},
    )

    post_repair_action = plan_post_repair_verification(
        repair_phase=signals.repair_phase,
        runtime_repair_kind=signals.runtime_repair_kind,
    )
    if post_repair_action is not None:
        return ReconciliationResult(
            changed=True,
            new_mode="verifying" if post_repair_action == "run_bounded_verification" else "runtime_verifying",
            new_next_action=post_repair_action,
            violations=(violation,),
        )
    # No repair-verification pending either: the only honest recovery is to
    # let the next tick re-plan from scratch rather than freeze in an
    # unjustified wait. Reset next_action to a neutral "none" (not "wait")
    # and leave mode alone for the controller's normal planner to resolve --
    # still recorded as a detected+handled violation.
    return ReconciliationResult(changed=True, new_mode=None, new_next_action="none", violations=(violation,))


def check_state_invariants(
    *,
    active: bool,
    mode: str,
    next_action: str,
    repair_phase: str,
    runtime_repair_kind: str | None,
    human_critical_pending: bool,
    runtime_worker_active: bool,
    human_observation_pending: bool,
    technical_pause_active: bool,
    pending_terminal_eligibility: bool,
    waiting_for_agent_signals: WaitingForAgentSignals,
) -> list[StateInvariantViolation]:
    """PART B.3: the full invariant sweep, for diagnostics/tests.

    Returns an empty list when the state is internally consistent.
    """

    violations: list[StateInvariantViolation] = []
    if not active:
        return violations

    if mode == "waiting_for_agent" and not waiting_for_agent_is_valid(waiting_for_agent_signals):
        violations.append(
            StateInvariantViolation(
                code="waiting_for_agent_without_pending_condition",
                message="mode=waiting_for_agent with no legitimate pending condition.",
            )
        )

    if repair_needs_post_write_verification(repair_phase) and next_action not in (
        "run_bounded_verification",
        "start_runtime_verification",
        "poll_runtime_verification",
        "apply_runtime_evidence",
    ):
        violations.append(
            StateInvariantViolation(
                code="repair_verifying_without_verification_scheduled",
                message=(
                    f"repair_phase={repair_phase} with executed repair evidence must "
                    "schedule static or runtime re-verification, never another model "
                    "call or an unqualified wait."
                ),
                detail={"next_action": next_action},
            )
        )

    if (
        next_action == "none"
        and not human_critical_pending
        and not runtime_worker_active
        and not human_observation_pending
        and not technical_pause_active
        and not pending_terminal_eligibility
    ):
        violations.append(
            StateInvariantViolation(
                code="next_action_none_without_justification",
                message=(
                    "next_action=none for an active non-terminal run requires a "
                    "genuine human state, a documented async worker, a technical "
                    "pause, or an immediately-pending terminal eligibility "
                    "evaluation."
                ),
            )
        )

    return violations
