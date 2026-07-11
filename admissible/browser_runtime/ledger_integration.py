"""Bridges runtime plans/evidence back onto the Mission Contract acceptance ledger.

Deliberately does not change
:func:`admissible.mission_contract.evaluate_completion_eligibility` at all:
that function already forbids completion for any ledger entry whose status
is not terminal, and already treats ``verification_disposition ==
"unsupported_verifier"`` as a capability gap. Writing runtime plan/evidence
results back onto the same ledger entries a static/human path would use
means every PART H.41 rule (not planned, unsupported, not executed, failed,
missing observability, awaiting human observation, policy violation) is
enforced for free through the existing, already-tested gate.
"""

from __future__ import annotations

from typing import Any

from admissible.browser_runtime.models import BrowserRuntimeEvidence, BrowserRuntimeVerificationPlan
from admissible.browser_runtime.runner import (
    CRITERION_STATUS_CAPABILITY_GAP,
    CRITERION_STATUS_ERROR,
    CRITERION_STATUS_FAIL,
    CRITERION_STATUS_GAP,
    CRITERION_STATUS_HUMAN,
    CRITERION_STATUS_NOT_EXECUTED,
    CRITERION_STATUS_PASS,
)

_RUNTIME_EVIDENCE_SOURCE = "browser_runtime"


def apply_runtime_plan_to_ledger(ledger: list[dict[str, Any]], plan: BrowserRuntimeVerificationPlan) -> list[dict[str, Any]]:
    """Announce plan-time runtime disposition/capability onto matching ledger entries.

    Safe to call before any browser session runs: it only ever records what
    the plan intends to check, never a pass/fail result.
    """

    by_id = {c.criterion_id: c for c in plan.criteria}
    for item in ledger:
        criterion = by_id.get(item.get("criterion_id"))
        if criterion is None:
            continue
        item["verification_disposition"] = criterion.disposition
        if criterion.disposition == "deterministic_runtime" and criterion.assertion_ids:
            # Kept separate from `item["verification"]` (a list of
            # VerificationRequest-shaped dicts the static bounded-verification
            # path reads via `.get("target_paths")`): these are opaque
            # `source:assertion_id` reference tags, not executable static
            # checks, so writing them into `verification` would crash the
            # static path (RUN_044 integration fix).
            item["runtime_verification_refs"] = [
                f"{_RUNTIME_EVIDENCE_SOURCE}:{aid}" for aid in criterion.assertion_ids
            ]
        item["runtime_required_observables"] = list(criterion.required_observables)
        item["runtime_unsupported_reason"] = criterion.unsupported_reason
    return ledger


_STATUS_MAP = {
    CRITERION_STATUS_PASS: "verified_pass",
    CRITERION_STATUS_FAIL: "verified_fail",
    CRITERION_STATUS_ERROR: "open",
    CRITERION_STATUS_GAP: "open",
    CRITERION_STATUS_HUMAN: "open",
    CRITERION_STATUS_CAPABILITY_GAP: "open",
    CRITERION_STATUS_NOT_EXECUTED: "open",
}

# Runtime outcomes that must keep (or force) verification_disposition at
# "unsupported_verifier" so evaluate_completion_eligibility's existing
# capability-gap check catches them.
_FORCE_UNSUPPORTED_STATUSES = {
    CRITERION_STATUS_GAP,
    CRITERION_STATUS_CAPABILITY_GAP,
    CRITERION_STATUS_ERROR,
    CRITERION_STATUS_NOT_EXECUTED,
}


def apply_runtime_evidence_to_ledger(
    ledger: list[dict[str, Any]],
    plan: BrowserRuntimeVerificationPlan,
    evidence: BrowserRuntimeEvidence,
) -> list[dict[str, Any]]:
    """Write one runtime verification run's results back onto the ledger.

    Never marks a criterion ``verified_pass`` except when the runtime
    aggregator itself reported ``verified_pass`` (PART H.35): a static
    proxy can never terminally satisfy a criterion this function touches.
    """

    apply_runtime_plan_to_ledger(ledger, plan)
    by_criterion_id = {r["criterion_id"]: r for r in evidence.criterion_results}
    for item in ledger:
        cid = item.get("criterion_id")
        result = by_criterion_id.get(cid)
        if result is None:
            continue
        runtime_status = result["status"]
        if runtime_status == CRITERION_STATUS_HUMAN:
            item["verification_disposition"] = "human_observation_required"
        elif runtime_status in _FORCE_UNSUPPORTED_STATUSES:
            item["verification_disposition"] = "unsupported_verifier"
            item["runtime_unsupported_reason"] = result.get("unsupported_reason")
        item["status"] = _STATUS_MAP.get(runtime_status, item.get("status", "open"))
        item.setdefault("evidence_refs", [])
        if evidence.evidence_id not in item["evidence_refs"]:
            item["evidence_refs"].append(evidence.evidence_id)
        notes = list(item.get("verification_notes") or [])
        for assertion in result.get("assertions") or []:
            if assertion.get("status") in ("fail", "error"):
                notes.append(f"{assertion.get('step_type')}: {assertion.get('message') or assertion.get('status')}")
        item["verification_notes"] = notes

    if evidence.policy_violations:
        # A policy violation (e.g. a blocked external request) taints every
        # criterion this same session touched, even ones the aggregator
        # reported as passing: the run's integrity is suspect, so none of
        # its results may terminally satisfy a criterion (PART H.41, test 35).
        for item in ledger:
            if item.get("criterion_id") not in by_criterion_id:
                continue
            item["runtime_policy_violation_count"] = len(evidence.policy_violations)
            if item.get("status") == "verified_pass":
                item["status"] = "open"
                item.setdefault("verification_notes", []).append(
                    "Runtime pass withheld: session recorded a policy violation."
                )
    return ledger
