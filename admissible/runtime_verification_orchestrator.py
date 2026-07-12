"""RUN_044 runtime-verification orchestration.

Wires the bounded browser-runtime verifier (``admissible.browser_runtime``,
RUN_043) into the high-autonomy governed-run lifecycle without embedding any
browser-provider logic in ``admissible.high_autonomy_controller``.

Browser discovery, CDP operations, HTTP serving, DSL interpretation, evidence
collection, and provider cleanup all stay inside ``admissible.browser_runtime``.
This module only:

- decides whether runtime verification is required (PART C);
- builds and validates a runtime plan from the Mission Contract (PART D);
- starts/polls/cancels exactly one bounded background worker per session
  (PART E, PART G);
- applies runtime evidence to the acceptance ledger exactly once (PART F);
- records human observations, kept distinct from human-authority approval
  (PART J).

The controller (``admissible.high_autonomy_controller``) only calls the
functions below, persists the returned :class:`RuntimeOrchestrationTransition`
and :class:`~admissible.runtime_orchestration_models.RuntimeVerificationAttempt`,
and schedules its next tick. Nothing here is a model/provider turn: every
function in this module is a bounded, local, synchronous decision or a
non-blocking check on an already-running background worker.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admissible.browser_runtime import dsl
from admissible.browser_runtime.evidence_store import evidence_directory_for, write_runtime_evidence
from admissible.browser_runtime.ledger_integration import apply_runtime_evidence_to_ledger
from admissible.browser_runtime.models import BrowserRuntimeEvidence, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.plan_builder import build_runtime_verification_plan
from admissible.browser_runtime.provider import BrowserRuntimeProvider
from admissible.browser_runtime.runner import (
    CRITERION_STATUS_ERROR,
    CRITERION_STATUS_FAIL,
    CRITERION_STATUS_GAP,
    CRITERION_STATUS_HUMAN,
    RuntimeExecutionResult,
    build_capability_gap_evidence,
    execute_runtime_verification_plan,
)
from admissible.governed_run import latest_file_hashes
from admissible.mission_contract import ledger_coverage_report, verification_plan_coverage_report
from admissible.runtime_orchestration_models import (
    ATTEMPT_STATUSES,
    STATUS_CANCELLED,
    STATUS_CAPABILITY_CHECKING,
    STATUS_EVIDENCE_APPLIED,
    STATUS_EVIDENCE_READY,
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_PREPARED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_UNAVAILABLE,
    HumanObservationRecord,
    RuntimeNeedAssessment,
    RuntimeOrchestrationTransition,
    RuntimeVerificationAttempt,
    _now_iso,
    new_attempt_id,
    new_observation_id,
)

__all__ = [
    "assess_runtime_need",
    "validate_runtime_plan",
    "prepare_runtime_attempt",
    "start_runtime_attempt",
    "poll_runtime_attempt",
    "apply_runtime_evidence",
    "classify_runtime_observability_gap_disposition",
    "RuntimeObservabilityGapDecision",
    "cancel_runtime_attempt",
    "reconcile_runtime_state_on_load",
    "record_human_observation",
    "build_runtime_metrics",
    "default_runtime_provider",
    "has_active_worker",
    "find_persisted_evidence",
]


def _plan_sha256(plan: BrowserRuntimeVerificationPlan) -> str:
    """Identical algorithm to `browser_runtime.runner`'s private helper.

    Recomputed locally (not imported) so this module never reaches into a
    private symbol of the sealed browser_runtime package; it is the same
    three-line deterministic hash, not provider logic.
    """

    payload = json.dumps(plan.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def default_runtime_provider() -> BrowserRuntimeProvider:
    """The real installed-browser provider, used when no test provider is supplied."""

    from admissible.browser_runtime.chromium_provider import ChromiumCdpRuntimeProvider

    return ChromiumCdpRuntimeProvider()


# --- PART C: runtime need assessment ----------------------------------------


def assess_runtime_need(
    mission_contract: dict[str, Any] | None,
    ledger: list[dict[str, Any]],
    *,
    workspace_root: str | None,
    entrypoint_path: str | None = None,
) -> RuntimeNeedAssessment:
    """Whether bounded runtime verification is required right now (PART C.7-10).

    Builds the same contract-derived plan
    :func:`~admissible.browser_runtime.plan_builder.build_runtime_verification_plan`
    would use to run the browser, purely to classify each mandatory
    subrequirement's disposition -- this function never launches a browser.
    Required exactly when a still-unsatisfied mandatory criterion's
    disposition is ``deterministic_runtime``; a criterion already
    ``verified_pass``/``waived`` is never rerun (PART C.7 second sentence).
    """

    if not mission_contract or not workspace_root:
        return RuntimeNeedAssessment(required=False, reason="no_mission_contract_or_workspace")
    if not ledger:
        return RuntimeNeedAssessment(required=False, reason="empty_acceptance_ledger")

    plan, coverage = build_runtime_verification_plan(
        mission_contract, ledger, workspace_root=workspace_root, entrypoint_path=entrypoint_path
    )
    status_by_id = {str(c.get("criterion_id")): c.get("status") for c in ledger}

    def _unresolved(criterion_id: str) -> bool:
        return status_by_id.get(criterion_id) not in ("verified_pass", "waived")

    runtime_criteria = [c for c in plan.criteria if c.disposition == "deterministic_runtime"]
    executable_now = [c.criterion_id for c in runtime_criteria if _unresolved(c.criterion_id)]
    human_ids = [c.criterion_id for c in plan.criteria if c.human_observation_required and _unresolved(c.criterion_id)]
    gap_ids = [
        c.criterion_id
        for c in plan.criteria
        if c.disposition == "unsupported_verifier" and _unresolved(c.criterion_id)
    ]

    return RuntimeNeedAssessment(
        required=bool(executable_now),
        reason=(
            "deterministic_runtime_criteria_unresolved"
            if executable_now
            else "no_unresolved_deterministic_runtime_criteria"
        ),
        plan=plan,
        coverage_report=coverage,
        runtime_criterion_ids=[c.criterion_id for c in runtime_criteria],
        executable_now_criterion_ids=executable_now,
        missing_observability_criterion_ids=gap_ids,
        human_observation_criterion_ids=human_ids,
        unsupported_criterion_ids=gap_ids,
    )


# --- PART D: plan preparation and validation ---------------------------------


def validate_runtime_plan(
    plan: BrowserRuntimeVerificationPlan,
    *,
    mission_contract: dict[str, Any],
    ledger: list[dict[str, Any]],
    authorized_workspace_root: str,
) -> list[str]:
    """PART D.12: hard validation gates before any browser attempt may start.

    Returns a list of human-readable violations; empty means the plan may be
    persisted and started.
    """

    errors: list[str] = []
    expected_sha = mission_contract.get("raw_goal_sha256") or ""
    if expected_sha and plan.mission_contract_sha256 != expected_sha:
        errors.append("plan mission_contract_sha256 does not match the current Mission Contract")

    try:
        authorized = Path(os.path.realpath(str(authorized_workspace_root)))
        got = Path(os.path.realpath(str(plan.workspace_root)))
        if got != authorized:
            errors.append("plan workspace_root is not the authorized bounded workspace")
    except OSError:
        errors.append("plan workspace_root could not be resolved")

    entry_norm = str(plan.entrypoint_path or "").replace("\\", "/")
    if not entry_norm or entry_norm.startswith("/") or ".." in entry_norm.split("/"):
        errors.append("plan entrypoint_path is not an exact authorized local path")

    try:
        dsl.validate_steps(plan.steps, max_steps=plan.max_steps)
        dsl.validate_plan_limits(
            max_duration_ms=plan.max_duration_ms,
            max_steps=plan.max_steps,
            max_input_events=plan.max_input_events,
            max_snapshots=plan.max_snapshots,
            max_screenshots=plan.max_screenshots,
        )
    except dsl.BrowserRuntimeDSLError as exc:
        errors.append(f"runtime plan failed DSL validation: {exc}")

    ledger_ids = {str(c.get("criterion_id")) for c in ledger}
    unknown = sorted({c.criterion_id for c in plan.criteria if c.criterion_id not in ledger_ids})
    if unknown:
        errors.append(f"plan references criterion id(s) not present in the current ledger: {', '.join(unknown)}")

    return errors


def prepare_runtime_attempt(
    *,
    session_id: str,
    mission_contract: dict[str, Any],
    ledger: list[dict[str, Any]],
    plan: BrowserRuntimeVerificationPlan,
    provider: BrowserRuntimeProvider,
    operation_records: list[dict[str, Any]] | None = None,
    retry_of_attempt: RuntimeVerificationAttempt | None = None,
    reason: str | None = None,
) -> tuple[RuntimeVerificationAttempt | None, RuntimeOrchestrationTransition]:
    """PART D.11-14: validate, then persist plan+attempt before any launch.

    Returns ``(None, transition)`` when the plan is not safe to run (never a
    silently weaker plan): the transition's ``semantic_status`` is
    ``verification_plan_incomplete`` in that case.
    """

    workspace_root = plan.workspace_root
    errors = validate_runtime_plan(
        plan,
        mission_contract=mission_contract,
        ledger=ledger,
        authorized_workspace_root=workspace_root,
    )
    if errors:
        return None, RuntimeOrchestrationTransition(
            transition_type="prepare_rejected",
            changed=False,
            next_step="runtime_observability_gap",
            mode="runtime_observability_gap",
            semantic_status="verification_plan_incomplete",
            event_message="Runtime plan failed validation: " + "; ".join(errors),
            auto_tick_safe=True,
        )

    capability = provider.detect_capability()
    attempt = RuntimeVerificationAttempt(
        attempt_id=new_attempt_id(),
        session_id=session_id,
        mission_contract_sha256=str(mission_contract.get("raw_goal_sha256") or ""),
        runtime_plan_sha256=_plan_sha256(plan),
        provider_id=capability.provider_id,
        provider_capability_snapshot=capability.to_dict(),
        criterion_ids=[c.criterion_id for c in plan.criteria if c.disposition == "deterministic_runtime"],
        affected_artifact_hashes=dict(latest_file_hashes(operation_records or [])),
        status=STATUS_PREPARED,
        retry_of_attempt_id=(retry_of_attempt.attempt_id if retry_of_attempt else None),
        attempt_number=((retry_of_attempt.attempt_number + 1) if retry_of_attempt else 1),
    )
    transition = RuntimeOrchestrationTransition(
        transition_type="prepared",
        changed=True,
        next_step="start",
        mode="preparing_runtime_plan",
        semantic_status="runtime_verification_pending",
        event_message=(
            f"Prepared runtime verification attempt {attempt.attempt_id} "
            f"({len(attempt.criterion_ids)} deterministic-runtime criteria)."
            + (f" Retry of {retry_of_attempt.attempt_id} ({reason})." if retry_of_attempt else "")
        ),
        persisted_attempt=attempt.to_dict(),
        affected_criteria=list(attempt.criterion_ids),
    )
    return attempt, transition


# --- PART E: single-flight background worker --------------------------------


class _RuntimeWorker:
    """Owns exactly one background thread running one bounded runtime attempt."""

    def __init__(self, *, attempt_id: str, plan: BrowserRuntimeVerificationPlan, provider: BrowserRuntimeProvider) -> None:
        self.attempt_id = attempt_id
        self.plan = plan
        self.provider = provider
        self.done = threading.Event()
        self.cancel_event = threading.Event()
        self.result: RuntimeExecutionResult | None = None
        self.error: str | None = None
        self._thread = threading.Thread(target=self._run, name=f"admissible-runtime-{attempt_id}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            self.result = execute_runtime_verification_plan(self.provider, self.plan, cancel_event=self.cancel_event)
        except Exception as exc:  # noqa: BLE001 - a worker thread must never raise unhandled
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.done.set()

    def is_alive(self) -> bool:
        return self._thread.is_alive()


_REGISTRY_LOCK = threading.Lock()
_WORKERS: dict[str, _RuntimeWorker] = {}  # keyed by session_id: one worker per session at most


def has_active_worker(session_id: str) -> bool:
    with _REGISTRY_LOCK:
        worker = _WORKERS.get(session_id)
        return worker is not None and worker.is_alive()


def start_runtime_attempt(
    *,
    attempt: RuntimeVerificationAttempt,
    plan: BrowserRuntimeVerificationPlan,
    provider: BrowserRuntimeProvider,
    control_root: str,
) -> RuntimeOrchestrationTransition:
    """PART E.15-19: validate+persist, capability-check, then start at most one worker.

    Returns promptly in every case: the capability-negative path is a fast
    synchronous evidence build (no browser/server ever touched); the
    capability-positive path only starts a background thread and returns.
    """

    with _REGISTRY_LOCK:
        existing = _WORKERS.get(attempt.session_id)
        if existing is not None and existing.is_alive():
            return RuntimeOrchestrationTransition(
                transition_type="start_single_flight_noop",
                changed=False,
                next_step="poll",
                mode="runtime_verifying",
                semantic_status="runtime_verifying",
                event_message="A runtime verification worker is already active for this session.",
                persisted_attempt=attempt.to_dict(),
            )

        attempt.status = STATUS_CAPABILITY_CHECKING
        capability = provider.detect_capability()
        attempt.provider_capability_snapshot = capability.to_dict()
        if not capability.available:
            attempt.status = STATUS_UNAVAILABLE
            evidence = build_capability_gap_evidence(plan, capability.to_dict())
            manifest = write_runtime_evidence(control_root, evidence)
            attempt.evidence_id = evidence.evidence_id
            attempt.evidence_paths = [f["relative_path"] for f in manifest.get("files") or []]
            attempt.completed_at = _now_iso()
            attempt.failure_class = "browser_capability_gap"
            attempt.failure_message = capability.unavailable_reason
            attempt.cleanup_status = "not_applicable_never_launched"
            return RuntimeOrchestrationTransition(
                transition_type="capability_gap",
                changed=True,
                next_step="apply_evidence",
                mode="runtime_verification_capability_gap",
                semantic_status="runtime_verification_capability_gap",
                event_message=f"Browser runtime unavailable: {capability.unavailable_reason}.",
                persisted_attempt=attempt.to_dict(),
                evidence_refs=[evidence.evidence_id],
            )

        attempt.status = STATUS_QUEUED
        attempt.started_at = _now_iso()
        worker = _RuntimeWorker(attempt_id=attempt.attempt_id, plan=plan, provider=provider)
        _WORKERS[attempt.session_id] = worker
        worker.start()
        attempt.status = STATUS_RUNNING
        return RuntimeOrchestrationTransition(
            transition_type="started",
            changed=True,
            next_step="poll",
            mode="runtime_verifying",
            semantic_status="runtime_verifying",
            event_message=f"Started bounded runtime verification attempt {attempt.attempt_id}.",
            persisted_attempt=attempt.to_dict(),
        )


def poll_runtime_attempt(
    *,
    attempt: RuntimeVerificationAttempt,
    control_root: str,
) -> RuntimeOrchestrationTransition:
    """PART E.17-18, PART F.20-22: non-blocking check on the owned worker.

    Never starts a second attempt. Consumes a finished worker's result
    exactly once (guarded by the registry lock); a racing poll observes the
    registry entry already gone and returns a stable no-op.
    """

    worker = _WORKERS.get(attempt.session_id)
    if worker is None or worker.attempt_id != attempt.attempt_id:
        if attempt.status in (STATUS_QUEUED, STATUS_RUNNING):
            return reconcile_runtime_state_on_load(attempt=attempt, control_root=control_root)
        return RuntimeOrchestrationTransition(
            transition_type="poll_noop",
            changed=False,
            next_step=("apply_evidence" if attempt.status == STATUS_EVIDENCE_READY else "wait"),
            mode="runtime_verifying",
            semantic_status=attempt.status,
            event_message="No active worker for this attempt; nothing to poll.",
            persisted_attempt=attempt.to_dict(),
        )

    if not worker.done.is_set():
        return RuntimeOrchestrationTransition(
            transition_type="poll_wait",
            changed=False,
            next_step="poll",
            mode="runtime_verifying",
            semantic_status="runtime_verifying",
            event_message="Runtime verification is still running.",
            persisted_attempt=attempt.to_dict(),
            auto_tick_safe=True,
        )

    with _REGISTRY_LOCK:
        current = _WORKERS.get(attempt.session_id)
        if current is not worker:
            # Already consumed by a racing poll (single-flight held by the
            # controller's own tick lock in practice, but this stays correct
            # even without it).
            return RuntimeOrchestrationTransition(
                transition_type="poll_noop",
                changed=False,
                next_step="wait",
                mode="runtime_verifying",
                semantic_status=attempt.status,
                event_message="Runtime evidence already consumed by another tick.",
                persisted_attempt=attempt.to_dict(),
            )
        del _WORKERS[attempt.session_id]

    if worker.error is not None or worker.result is None:
        attempt.status = STATUS_FAILED
        attempt.failure_class = "runtime_worker_error"
        attempt.failure_message = worker.error or "runtime worker produced no result"
        attempt.completed_at = _now_iso()
        return RuntimeOrchestrationTransition(
            transition_type="worker_error",
            changed=True,
            next_step="repair_or_finalize",
            mode="runtime_verification_fail",
            semantic_status="runtime_verification_fail",
            event_message=attempt.failure_message,
            persisted_attempt=attempt.to_dict(),
        )

    evidence = worker.result.evidence
    manifest = write_runtime_evidence(control_root, evidence, screenshot_blobs=worker.result.screenshot_blobs)
    attempt.status = STATUS_EVIDENCE_READY
    attempt.evidence_id = evidence.evidence_id
    attempt.evidence_paths = [f["relative_path"] for f in manifest.get("files") or []]
    attempt.completed_at = _now_iso()
    cleanup = evidence.resource_cleanup or {}
    attempt.cleanup_status = (
        "ok" if cleanup.get("browser_process_terminated") and cleanup.get("http_server_stopped") else "cleanup_incomplete"
    )
    return RuntimeOrchestrationTransition(
        transition_type="evidence_ready",
        changed=True,
        next_step="apply_evidence",
        mode="runtime_evidence_ready",
        semantic_status=evidence.status,
        event_message=f"Runtime verification finished: {evidence.status}.",
        persisted_attempt=attempt.to_dict(),
        evidence_refs=[evidence.evidence_id],
    )


def cancel_runtime_attempt(*, attempt: RuntimeVerificationAttempt) -> RuntimeOrchestrationTransition:
    """PART L.58: explicitly cancel an active runtime attempt and clean up."""

    with _REGISTRY_LOCK:
        worker = _WORKERS.get(attempt.session_id)
        owns = worker is not None and worker.attempt_id == attempt.attempt_id
    cleanup_ok = True
    if owns:
        worker.cancel_event.set()
        worker.done.wait(timeout=10.0)
        with _REGISTRY_LOCK:
            if _WORKERS.get(attempt.session_id) is worker:
                del _WORKERS[attempt.session_id]
        if worker.result is not None:
            cleanup = worker.result.evidence.resource_cleanup or {}
            cleanup_ok = bool(cleanup.get("browser_process_terminated") and cleanup.get("http_server_stopped"))
        elif not worker.done.is_set():
            cleanup_ok = False  # worker did not honor cancellation in time
    attempt.status = STATUS_CANCELLED
    attempt.completed_at = _now_iso()
    attempt.cleanup_status = "ok" if cleanup_ok else "cleanup_incomplete"
    return RuntimeOrchestrationTransition(
        transition_type="cancelled",
        changed=True,
        next_step="finalize_cancelled",
        mode="runtime_verification_fail",
        semantic_status="cancelled",
        event_message=f"Runtime verification attempt {attempt.attempt_id} was cancelled.",
        persisted_attempt=attempt.to_dict(),
    )


# --- PART G: persistence and recovery ---------------------------------------


def find_persisted_evidence(control_root: str, evidence_id: str | None) -> BrowserRuntimeEvidence | None:
    if not evidence_id:
        return None
    try:
        directory = evidence_directory_for(control_root, evidence_id)
    except ValueError:
        return None
    evidence_path = directory / "evidence.json"
    if not evidence_path.is_file():
        return None
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return BrowserRuntimeEvidence.from_dict(data)


def reconcile_runtime_state_on_load(
    *,
    attempt: RuntimeVerificationAttempt,
    control_root: str,
) -> RuntimeOrchestrationTransition:
    """PART G.25-27: what to do with a persisted attempt when a session loads.

    Never assumes pass. Recovers already-persisted evidence without
    relaunching the browser when it validates against the persisted plan;
    otherwise marks a stale ``running``/``queued`` attempt ``interrupted``
    and requires an explicit operator retry.
    """

    if attempt.status not in (STATUS_QUEUED, STATUS_RUNNING):
        return RuntimeOrchestrationTransition(
            transition_type="reconcile_noop",
            changed=False,
            next_step="wait",
            mode="runtime_verifying",
            semantic_status=attempt.status,
            event_message="Nothing to reconcile.",
            persisted_attempt=attempt.to_dict(),
        )

    if has_active_worker(attempt.session_id):
        worker = _WORKERS.get(attempt.session_id)
        if worker is not None and worker.attempt_id == attempt.attempt_id:
            return RuntimeOrchestrationTransition(
                transition_type="reconcile_active",
                changed=False,
                next_step="poll",
                mode="runtime_verifying",
                semantic_status="runtime_verifying",
                event_message="An owned worker is still active for this attempt.",
                persisted_attempt=attempt.to_dict(),
            )

    existing = find_persisted_evidence(control_root, attempt.evidence_id)
    if existing is not None and existing.plan_sha256 == attempt.runtime_plan_sha256:
        attempt.status = STATUS_EVIDENCE_READY
        attempt.evidence_id = existing.evidence_id
        return RuntimeOrchestrationTransition(
            transition_type="reconcile_recovered_evidence",
            changed=True,
            next_step="apply_evidence",
            mode="runtime_evidence_ready",
            semantic_status=existing.status,
            event_message="Recovered persisted runtime evidence without relaunching the browser.",
            persisted_attempt=attempt.to_dict(),
            evidence_refs=[existing.evidence_id],
        )

    attempt.status = STATUS_INTERRUPTED
    attempt.failure_class = "process_interrupted"
    attempt.failure_message = (
        "No owned worker/process remained for a running runtime attempt on session load; "
        "treated as interrupted, not a pass."
    )
    attempt.completed_at = attempt.completed_at or _now_iso()
    attempt.cleanup_status = "unknown_process_state_not_tracked"
    return RuntimeOrchestrationTransition(
        transition_type="reconcile_interrupted",
        changed=True,
        next_step="await_explicit_retry",
        mode="runtime_verification_fail",
        semantic_status="interrupted",
        event_message="Runtime verification attempt was interrupted; an explicit retry is required.",
        persisted_attempt=attempt.to_dict(),
    )


def build_retry_attempt(
    *,
    interrupted: RuntimeVerificationAttempt,
    session_id: str,
    mission_contract: dict[str, Any],
    ledger: list[dict[str, Any]],
    plan: BrowserRuntimeVerificationPlan,
    provider: BrowserRuntimeProvider,
    operation_records: list[dict[str, Any]] | None = None,
    reason: str = "interrupted_attempt_retry",
) -> tuple[RuntimeVerificationAttempt | None, RuntimeOrchestrationTransition]:
    """PART G.29: an explicit bounded retry preserving attempt lineage."""

    return prepare_runtime_attempt(
        session_id=session_id,
        mission_contract=mission_contract,
        ledger=ledger,
        plan=plan,
        provider=provider,
        operation_records=operation_records,
        retry_of_attempt=interrupted,
        reason=reason,
    )


# --- PART F: exactly-once evidence application -------------------------------


# unsupported_reason values plan_builder assigns when a criterion is
# genuinely unsupported because the *contract itself* declares no matching
# instrumentation yet (a specific field/control mapping is missing) -- these
# are the ones read-only instrumentation repair can plausibly fix.
# "no_safe_observable_derivable" (and no reason at all) means plan_builder
# found no phrase pattern to act on whatsoever (e.g. "collision causes
# death"): no amount of added debug fields makes that checkable through the
# existing declarative DSL, so requesting instrumentation repair for it
# would only burn a repair round for nothing.
_INSTRUMENTATION_FIXABLE_REASONS = frozenset(
    {
        "threshold_subject_not_mapped_to_declared_snapshot_field",
        "loop_counter_field_or_restart_control_not_declared",
        "control_effect_not_mapped_to_declared_snapshot_field",
        "no_debug_interface_declared",
    }
)

# unsupported_reason values that mean plan_builder found no derivable
# observable at all -- distinct from the instrumentation-fixable set above.
_NO_SAFE_OBSERVABLE_REASONS = frozenset({"no_safe_observable_derivable"})

# The fixed, ordered evaluation this module records before a runtime
# observability gap may become a final outcome (RUN_053 PART 1). Every
# gap decision records exactly this tuple regardless of which action it
# takes, so the decision is auditable even when it finalizes.
_GAP_EVALUATION_ORDER = (
    "safe_debug_observables_checked",
    "safe_input_controls_checked",
    "bounded_runtime_plan_repair_considered",
    "bounded_instrumentation_repair_considered",
    "human_observation_considered",
)


@dataclass(frozen=True)
class RuntimeObservabilityGapDecision:
    """PART 1: what a runtime_observability_gap means, and why.

    ``action`` is one of:

    - ``"repair_available"``: bounded read-only instrumentation repair
      should be attempted (first time, or a further round after a prior
      one did not fully resolve the gap).
    - ``"finalize_repair_exhausted"``: a viable instrumentation repair
      exists but the repair-round budget is used up.
    - ``"finalize_no_safe_observable"``: no gap criterion has an
      instrumentation-fixable reason (either none is derivable at all, or
      no debug interface exists to extend).

    A gap with zero criteria never reaches this function at all -- that is
    "repair not required", decided by the caller before calling this.
    """

    action: str
    reason: str
    evaluated_alternatives: tuple[str, ...]
    instrumentation_fixable_gap_ids: tuple[str, ...]
    no_safe_observable_gap_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "evaluated_alternatives": list(self.evaluated_alternatives),
            "instrumentation_fixable_gap_ids": list(self.instrumentation_fixable_gap_ids),
            "no_safe_observable_gap_ids": list(self.no_safe_observable_gap_ids),
        }


def classify_runtime_observability_gap_disposition(
    *,
    gap_results: list[dict[str, Any]],
    debug_interface: str | None,
    repair_round_count: int,
    max_repair_rounds: int,
) -> RuntimeObservabilityGapDecision:
    """PART 1: decide what to do about a runtime observability gap, in a
    fixed evaluation order, before any finalization.

    Never returns "unavailable or exhausted" phrasing when a viable
    instrumentation repair exists and repair budget remains -- distinct,
    typed reasons for: repair available (first attempt or a retry after a
    prior one did not fully resolve it), repair budget exhausted, and no
    safe observable can exist. "Repair not required" is the caller's own
    decision (never calling this function when there is no gap) and
    "existing safe input controls" is evaluated upstream, by the runtime
    plan builder, before any evidence exists for this function to see --
    every gap criterion arriving here already reflects whatever safe
    control the plan builder could discover and attempt.
    """

    fixable_ids = tuple(
        r["criterion_id"]
        for r in gap_results
        if not r.get("unsupported_reason") or r.get("unsupported_reason") in _INSTRUMENTATION_FIXABLE_REASONS
    )
    unfixable_ids = tuple(
        r["criterion_id"] for r in gap_results if r.get("unsupported_reason") in _NO_SAFE_OBSERVABLE_REASONS
    )

    if not fixable_ids:
        return RuntimeObservabilityGapDecision(
            action="finalize_no_safe_observable",
            reason=(
                "Mandatory runtime-verified criteria have no safe observable and none "
                "can be derived from any declared debug interface: "
                + ", ".join(unfixable_ids or [r["criterion_id"] for r in gap_results])
                + "."
            ),
            evaluated_alternatives=_GAP_EVALUATION_ORDER,
            instrumentation_fixable_gap_ids=fixable_ids,
            no_safe_observable_gap_ids=unfixable_ids,
        )
    if not debug_interface:
        return RuntimeObservabilityGapDecision(
            action="finalize_no_safe_observable",
            reason=(
                "Mandatory runtime-verified criteria have no safe observable: no debug "
                "interface is declared to extend with read-only instrumentation."
            ),
            evaluated_alternatives=_GAP_EVALUATION_ORDER,
            instrumentation_fixable_gap_ids=fixable_ids,
            no_safe_observable_gap_ids=unfixable_ids,
        )
    if repair_round_count >= max_repair_rounds:
        return RuntimeObservabilityGapDecision(
            action="finalize_repair_exhausted",
            reason=(
                "Runtime observability gap has a viable read-only instrumentation repair, "
                f"but repair rounds are exhausted ({repair_round_count}/{max_repair_rounds})."
            ),
            evaluated_alternatives=_GAP_EVALUATION_ORDER,
            instrumentation_fixable_gap_ids=fixable_ids,
            no_safe_observable_gap_ids=unfixable_ids,
        )
    reason = (
        "Bounded read-only instrumentation repair is available for the observability gap."
        if repair_round_count == 0
        else (
            "A previous repair round did not fully resolve the observability gap; "
            f"bounded repair budget remains ({repair_round_count}/{max_repair_rounds} used)."
        )
    )
    return RuntimeObservabilityGapDecision(
        action="repair_available",
        reason=reason,
        evaluated_alternatives=_GAP_EVALUATION_ORDER,
        instrumentation_fixable_gap_ids=fixable_ids,
        no_safe_observable_gap_ids=unfixable_ids,
    )


def apply_runtime_evidence(
    *,
    ledger: list[dict[str, Any]],
    plan: BrowserRuntimeVerificationPlan,
    evidence: BrowserRuntimeEvidence,
    mission_contract: dict[str, Any],
    attempt: RuntimeVerificationAttempt,
) -> RuntimeOrchestrationTransition:
    """PART F.20-24: apply one runtime evidence run to the ledger exactly once.

    Guarded on ``attempt.status``: a second call for the same
    already-``evidence_applied`` attempt is a stable no-op that touches
    neither the ledger nor any metric.
    """

    if attempt.status == STATUS_EVIDENCE_APPLIED:
        return RuntimeOrchestrationTransition(
            transition_type="apply_noop",
            changed=False,
            next_step="reevaluate_completion",
            mode="applying_runtime_evidence",
            semantic_status=evidence.status,
            event_message="Runtime evidence was already applied; no-op.",
            persisted_attempt=attempt.to_dict(),
        )

    apply_runtime_evidence_to_ledger(ledger, plan, evidence)

    fail_ids = [r["criterion_id"] for r in evidence.criterion_results if r["status"] == CRITERION_STATUS_FAIL]
    gap_results = [r for r in evidence.criterion_results if r["status"] == CRITERION_STATUS_GAP]
    gap_ids = [r["criterion_id"] for r in gap_results]
    instrumentation_fixable_gap_ids = [
        r["criterion_id"] for r in gap_results if r.get("unsupported_reason") in _INSTRUMENTATION_FIXABLE_REASONS
    ]
    human_ids = [r["criterion_id"] for r in evidence.criterion_results if r["status"] == CRITERION_STATUS_HUMAN]
    error_ids = [r["criterion_id"] for r in evidence.criterion_results if r["status"] == CRITERION_STATUS_ERROR]
    capability_gap = evidence.status == "verification_capability_gap"
    policy_violation = bool(evidence.policy_violations)

    if capability_gap:
        semantic_status = "runtime_verification_capability_gap"
    elif policy_violation or fail_ids or error_ids:
        semantic_status = "runtime_verification_fail"
    elif gap_ids:
        semantic_status = "runtime_observability_gap"
    elif human_ids:
        semantic_status = "awaiting_human_observation"
    else:
        semantic_status = "runtime_verification_pass"

    attempt.status = STATUS_EVIDENCE_APPLIED
    assertions = list(evidence.assertions or [])
    coverage = ledger_coverage_report(mission_contract, ledger)
    verification_plan = verification_plan_coverage_report(ledger)
    return RuntimeOrchestrationTransition(
        transition_type="evidence_applied",
        changed=True,
        next_step="reevaluate_completion",
        mode="applying_runtime_evidence",
        semantic_status=semantic_status,
        event_message=f"Applied runtime evidence {evidence.evidence_id}: {semantic_status}.",
        persisted_attempt=attempt.to_dict(),
        evidence_refs=[evidence.evidence_id],
        affected_criteria=fail_ids + gap_ids + human_ids + error_ids,
        extra={
            "fail_criterion_ids": fail_ids,
            "gap_criterion_ids": gap_ids,
            "instrumentation_fixable_gap_ids": instrumentation_fixable_gap_ids,
            "human_observation_criterion_ids": human_ids,
            "error_criterion_ids": error_ids,
            "policy_violation": policy_violation,
            "contract_ledger_coverage_report": coverage,
            "verification_plan_coverage_report": verification_plan,
            "duration_ms": evidence.duration_ms,
            "assertion_count": len(assertions),
            "assertion_pass_count": sum(1 for a in assertions if a.get("status") == "pass"),
            "assertion_fail_count": sum(1 for a in assertions if a.get("status") in ("fail", "error")),
            "input_event_count": len(evidence.input_events),
            "snapshot_count": len(evidence.debug_snapshots),
            "screenshot_count": len(evidence.screenshots),
            "external_request_attempt_count": len(evidence.external_request_attempts),
        },
    )


def build_runtime_metrics(history: list[dict[str, Any]]) -> dict[str, int]:
    """PART A canonical runtime metrics, derived from ``runtime_attempt_history``."""

    plans = {h.get("runtime_plan_sha256") for h in history if h.get("runtime_plan_sha256")}
    return {
        "runtime_plan_count": len(plans),
        "runtime_attempt_count": len(history),
        "runtime_retry_count": sum(1 for h in history if h.get("retry_of_attempt_id")),
        "runtime_pass_count": sum(1 for h in history if h.get("semantic_status") == "runtime_verification_pass"),
        "runtime_fail_count": sum(1 for h in history if h.get("semantic_status") == "runtime_verification_fail"),
        "runtime_capability_gap_count": sum(
            1 for h in history if h.get("semantic_status") == "runtime_verification_capability_gap"
        ),
        "runtime_observability_gap_count": sum(
            1 for h in history if h.get("semantic_status") == "runtime_observability_gap"
        ),
        "runtime_policy_violation_count": sum(1 for h in history if h.get("policy_violation")),
        "runtime_assertion_count": sum(int(h.get("assertion_count") or 0) for h in history),
        "runtime_assertion_pass_count": sum(int(h.get("assertion_pass_count") or 0) for h in history),
        "runtime_assertion_fail_count": sum(int(h.get("assertion_fail_count") or 0) for h in history),
        "runtime_duration_ms_total": sum(int(h.get("duration_ms") or 0) for h in history),
        "runtime_input_event_count": sum(int(h.get("input_event_count") or 0) for h in history),
        "runtime_snapshot_count": sum(int(h.get("snapshot_count") or 0) for h in history),
        "runtime_screenshot_count": sum(int(h.get("screenshot_count") or 0) for h in history),
        "runtime_external_request_attempt_count": sum(
            int(h.get("external_request_attempt_count") or 0) for h in history
        ),
        "runtime_cleanup_failure_count": sum(1 for h in history if h.get("cleanup_status") == "cleanup_incomplete"),
    }


# --- PART J: human observation -----------------------------------------------


def record_human_observation(
    *,
    ledger: list[dict[str, Any]],
    criterion_id: str,
    actor: str,
    disposition: str,
    note: str,
    evidence_refs: list[str] | None = None,
) -> tuple[HumanObservationRecord, RuntimeOrchestrationTransition]:
    """PART J.47-51: record one human observation of a subjective criterion.

    Never a generic approval gate: only valid for criteria the runtime plan
    classified ``human_observation_required``, and never counted as a
    human-authority interruption (callers must track
    ``human_observation_count`` separately from ``human_critical_pending``).
    """

    if disposition not in ("pass", "fail", "waive"):
        raise ValueError(f"invalid human observation disposition: {disposition!r}")
    if disposition == "waive" and not note.strip():
        raise ValueError("waiving a human-observation criterion requires an explicit rationale")

    criterion = next((c for c in ledger if str(c.get("criterion_id")) == criterion_id), None)
    if criterion is None:
        raise ValueError(f"unknown acceptance criterion id: {criterion_id!r}")

    record = HumanObservationRecord(
        observation_id=new_observation_id(),
        criterion_id=criterion_id,
        actor=actor,
        disposition=disposition,
        note=note.strip(),
        evidence_refs=list(evidence_refs or []),
    )
    criterion["status"] = {"pass": "verified_pass", "fail": "verified_fail", "waive": "waived"}[disposition]
    refs = criterion.setdefault("evidence_refs", [])
    if record.observation_id not in refs:
        refs.append(record.observation_id)
    criterion.setdefault("verification_notes", []).append(
        f"Human observation ({disposition}) by {actor}: {record.note}".strip()
    )

    transition = RuntimeOrchestrationTransition(
        transition_type="human_observation_recorded",
        changed=True,
        next_step="reevaluate_completion",
        mode="applying_runtime_evidence",
        semantic_status=f"human_observation_{disposition}",
        event_message=f"Recorded human observation for {criterion_id}: {disposition}.",
        affected_criteria=[criterion_id],
        evidence_refs=[record.observation_id],
    )
    return record, transition
