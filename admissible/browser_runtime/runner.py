"""Executes a validated plan against a provider and produces bounded evidence.

This is the one place that turns "a provider capable of five bounded
operations" plus "a validated declarative plan" into a single
:class:`~admissible.browser_runtime.models.BrowserRuntimeEvidence` record,
including the criterion-level aggregation Mission Contract completion
eligibility reads (PART G.36, PART H).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admissible.browser_runtime.models import (
    BrowserRuntimeEvidence,
    BrowserRuntimeVerificationPlan,
    bounded_collect,
    new_id,
    now_iso,
)
from admissible.browser_runtime.provider import BrowserRuntimeProvider


@dataclass
class RuntimeExecutionResult:
    """A run's durable evidence plus its (never-serialized) raw screenshot bytes."""

    evidence: BrowserRuntimeEvidence
    screenshot_blobs: dict[str, bytes] = field(default_factory=dict)

TERMINATION_COMPLETED = "completed"
TERMINATION_DURATION_EXCEEDED = "duration_exceeded"
TERMINATION_STEP_LIMIT = "step_limit_reached"
TERMINATION_PROVIDER_ERROR = "provider_error"
TERMINATION_CAPABILITY_GAP = "browser_capability_gap"

CRITERION_STATUS_PASS = "verified_pass"
CRITERION_STATUS_FAIL = "verified_fail"
CRITERION_STATUS_ERROR = "runtime_error"
CRITERION_STATUS_GAP = "runtime_observability_gap"
CRITERION_STATUS_HUMAN = "awaiting_human_observation"
CRITERION_STATUS_CAPABILITY_GAP = "verification_capability_gap"
CRITERION_STATUS_NOT_EXECUTED = "runtime_not_executed"


def _plan_sha256(plan: BrowserRuntimeVerificationPlan) -> str:
    payload = json.dumps(plan.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Dispositions the runtime aggregator actually has an opinion about. A
# criterion plan_builder passed through unchanged (still
# deterministic_static/deterministic_structural/evidence_required/
# ambiguous_requirement, with no runtime steps ever generated for it) is not
# runtime's concern; aggregating a "gap" for it here would let one browser
# session overwrite an unrelated static-verification criterion's disposition
# (RUN_044 integration fix -- this was reachable as soon as a real Mission
# Contract mixed runtime-checkable and purely-static criteria).
_RUNTIME_RELEVANT_DISPOSITIONS = frozenset({"deterministic_runtime", "unsupported_verifier"})


def _aggregate_criterion_results(plan: BrowserRuntimeVerificationPlan, assertions: list[dict[str, Any]], *, executed: bool) -> list[dict[str, Any]]:
    by_criterion: dict[str, list[dict[str, Any]]] = {}
    for entry in assertions:
        cid = entry.get("criterion_id")
        if cid:
            by_criterion.setdefault(cid, []).append(entry)

    results = []
    for criterion in plan.criteria:
        if criterion.disposition not in _RUNTIME_RELEVANT_DISPOSITIONS and not criterion.human_observation_required:
            continue
        cid = criterion.criterion_id
        matched = by_criterion.get(cid, [])
        if criterion.human_observation_required:
            status = CRITERION_STATUS_HUMAN
        elif not criterion.supported:
            status = CRITERION_STATUS_GAP
        elif not executed:
            status = CRITERION_STATUS_NOT_EXECUTED
        elif not matched:
            status = CRITERION_STATUS_GAP
        elif any(a.get("status") == "error" for a in matched):
            status = CRITERION_STATUS_ERROR
        elif any(a.get("status") == "fail" for a in matched):
            status = CRITERION_STATUS_FAIL
        elif all(a.get("status") == "pass" for a in matched):
            # RUN_053: a criterion can be "supported" (real assertions ran
            # and passed) while plan_builder ALSO recorded an
            # unsupported_reason for a sub-aspect no field could cover (e.g.
            # boost's boolean toggle passed but "increases speed"/"bounded
            # cost" has no declared observable). Do not claim the full
            # criterion passes solely because the checked sub-aspect did --
            # this keeps it a gap (instrumentation-repair-eligible) instead
            # of a false pass.
            status = CRITERION_STATUS_GAP if criterion.unsupported_reason else CRITERION_STATUS_PASS
        else:
            status = CRITERION_STATUS_GAP
        results.append(
            {
                "criterion_id": cid,
                "disposition": criterion.disposition,
                "status": status,
                "assertion_ids": [a.get("assertion_id") for a in matched],
                "assertions": matched,
                "unsupported_reason": criterion.unsupported_reason,
                "required_observables": list(criterion.required_observables),
            }
        )
    return results


def build_capability_gap_evidence(
    plan: BrowserRuntimeVerificationPlan,
    capability_report: dict[str, Any],
) -> BrowserRuntimeEvidence:
    """Never a false pass: browser unavailability always yields a capability gap."""

    criterion_results = [
        {
            "criterion_id": c.criterion_id,
            "disposition": c.disposition,
            "status": CRITERION_STATUS_CAPABILITY_GAP,
            "assertion_ids": [],
            "assertions": [],
            "unsupported_reason": "browser_runtime_unavailable",
            "required_observables": list(c.required_observables),
        }
        for c in plan.criteria
    ]
    started = now_iso()
    return BrowserRuntimeEvidence(
        evidence_id=new_id("runtime_evidence"),
        plan_sha256=_plan_sha256(plan),
        mission_contract_sha256=plan.mission_contract_sha256,
        workspace_root=plan.workspace_root,
        entrypoint_path=plan.entrypoint_path,
        provider=dict(capability_report),
        started_at=started,
        completed_at=started,
        duration_ms=0,
        termination_reason=TERMINATION_CAPABILITY_GAP,
        criterion_results=criterion_results,
        resource_cleanup={"browser_process_terminated": False, "http_server_stopped": False, "temporary_profile_removed": False, "orphan_processes": [], "reason": "browser_never_launched"},
        status="verification_capability_gap",
    )


TERMINATION_CANCELLED = "cancelled"


def execute_runtime_verification_plan(
    provider: BrowserRuntimeProvider,
    plan: BrowserRuntimeVerificationPlan,
    *,
    cancel_event: Any = None,
) -> RuntimeExecutionResult:
    """Run one bounded verification session end-to-end.

    Browser unavailability (PART H.42) never proceeds to a session; it is
    reported as a capability gap before any browser or server resource is
    touched. Returns evidence plus the raw (never-serialized) screenshot
    bytes so a caller can persist them via
    :mod:`admissible.browser_runtime.evidence_store`.

    ``cancel_event`` is an optional cooperative cancellation signal (any
    object with an ``is_set()`` method, e.g. ``threading.Event``), checked
    between steps only (RUN_044 PART E.16/PART L.58 explicit cancellation).
    Passing nothing preserves the exact prior behavior.
    """

    capability = provider.detect_capability()
    if not capability.available:
        return RuntimeExecutionResult(evidence=build_capability_gap_evidence(plan, capability.to_dict()), screenshot_blobs={})

    started_at = now_iso()
    session = provider.create_session(plan)
    termination_reason = TERMINATION_COMPLETED
    provider_error: str | None = None
    try:
        for step in plan.steps:
            if cancel_event is not None and cancel_event.is_set():
                termination_reason = TERMINATION_CANCELLED
                break
            if session.elapsed_ms() >= plan.max_duration_ms:
                termination_reason = TERMINATION_DURATION_EXCEEDED
                break
            if session.step_count >= plan.max_steps:
                termination_reason = TERMINATION_STEP_LIMIT
                break
            provider.execute_step(session, step)
    except Exception as exc:  # noqa: BLE001 - always terminates cleanly, never propagates
        termination_reason = TERMINATION_PROVIDER_ERROR
        provider_error = f"{type(exc).__name__}: {exc}"
    finally:
        session.termination_reason = termination_reason
        collected = provider.collect_evidence(session)
        cleanup = provider.close_session(session)

    executed = termination_reason != TERMINATION_PROVIDER_ERROR
    criterion_results = _aggregate_criterion_results(plan, collected.get("assertions") or [], executed=executed)
    overall_pass = executed and all(
        r["status"] in (CRITERION_STATUS_PASS, CRITERION_STATUS_HUMAN) for r in criterion_results
    )
    if any(r["status"] == CRITERION_STATUS_HUMAN for r in criterion_results):
        status = "awaiting_human_observation" if overall_pass else "runtime_verification_fail"
    elif any(r["status"] == CRITERION_STATUS_GAP for r in criterion_results):
        status = "runtime_observability_gap"
    elif not executed or any(r["status"] in (CRITERION_STATUS_FAIL, CRITERION_STATUS_ERROR) for r in criterion_results):
        status = "runtime_verification_fail"
    else:
        status = "runtime_verification_pass"

    evidence = BrowserRuntimeEvidence(
        evidence_id=new_id("runtime_evidence"),
        plan_sha256=_plan_sha256(plan),
        mission_contract_sha256=plan.mission_contract_sha256,
        workspace_root=plan.workspace_root,
        entrypoint_path=plan.entrypoint_path,
        provider={**capability.to_dict(), "provider_error": provider_error},
        started_at=started_at,
        completed_at=now_iso(),
        duration_ms=session.elapsed_ms(),
        termination_reason=termination_reason,
        page_load=collected.get("page_load") or {},
        console_entries=collected.get("console_entries") or [],
        page_exceptions=collected.get("page_exceptions") or [],
        network_events=collected.get("network_events") or [],
        external_request_attempts=collected.get("external_request_attempts") or [],
        dialogs=collected.get("dialogs") or [],
        popups=collected.get("popups") or [],
        downloads=collected.get("downloads") or [],
        dom_observations=collected.get("dom_observations") or [],
        debug_snapshots=collected.get("debug_snapshots") or [],
        input_events=collected.get("input_events") or [],
        screenshots=collected.get("screenshots") or [],
        assertions=collected.get("assertions") or [],
        criterion_results=criterion_results,
        resource_cleanup=cleanup,
        policy_violations=collected.get("policy_violations") or [],
        status=status,
        truncation=collected.get("truncation") or {},
    )
    return RuntimeExecutionResult(evidence=evidence, screenshot_blobs=dict(session.screenshot_blobs))
