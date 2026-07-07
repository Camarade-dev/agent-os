"""Long-run trace format for Admissible comparison runs (Slice I).

Builds a durable JSON artifact capturing one complete comparison:
case envelope → system decisions → scoring → comparison summary →
final smoke-test verdict. Intended for benchmark reproducibility and
future visual demo inspection. This is not Agent OS closure.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from benchmark.scoring.score_decisions import TIER_1_CLAIM_BOUNDARY, score_case

TRACE_SCHEMA_VERSION = "0.1"
TRACE_GENERATED_BY = "admissible.trace.build_run_trace"

_SYSTEM_DESCRIPTOR_TEMPLATES: dict[str, dict[str, str]] = {
    "rules_only": {
        "system_type": "rules_only",
        "description": (
            "Deterministic rules-only reference evaluator over already-enriched "
            "envelope fields."
        ),
    },
    "frontier_direct_mock": {
        "system_type": "frontier_direct_mock",
        "description": (
            "Frontier-direct baseline with a fixed mock model response reused for "
            "every case. Plumbing/mock only; not a model-performance measurement."
        ),
    },
    "frontier_direct_live": {
        "system_type": "frontier_direct_live",
        "description": "Frontier-direct baseline with a live model provider.",
    },
    "admissible_model_assisted": {
        "system_type": "admissible_model_assisted",
        "description": "Admissible model-assisted evaluator.",
    },
}

_BASE_LIMITATIONS = [
    "This trace records a Tier 1 enriched seed smoke comparison only.",
    "It does not establish benchmark validity or product readiness.",
]


def make_trace_id(
    *,
    cases_path: str | Path,
    created_at: str,
    systems: list[str],
) -> str:
    """Return a deterministic, human-readable trace identifier."""
    payload = f"{cases_path}|{created_at}|{'|'.join(sorted(systems))}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    compact_time = created_at.replace("-", "").replace(":", "").replace("T", "").replace("Z", "")
    return f"trace_{compact_time}_{digest}"


def derive_final_verdict(comparison: dict) -> dict:
    """Derive a smoke-test final verdict from a compare_systems output.

    SMOKE_PASS is returned only when every requested system produced outputs
    for all cases, every output was scored, there are no unmatched envelope
    IDs, and the claim boundary is present and exact. SMOKE_PASS does not
    claim benchmark validity.
    """
    claim_boundary = comparison.get("claim_boundary")
    limitations = list(_BASE_LIMITATIONS)

    if claim_boundary != TIER_1_CLAIM_BOUNDARY:
        return {
            "status": "SMOKE_FAIL",
            "summary": "Smoke run failed: claim boundary missing or incorrect.",
            "limitations": limitations,
            "recommended_next_step": "Fix claim boundary before re-running.",
        }

    systems: list[str] = comparison.get("systems") or []
    results: dict = comparison.get("results") or {}
    case_count = comparison.get("case_count", 0)
    issues: list[str] = []

    for system in systems:
        result = results.get(system)
        if result is None:
            issues.append(f"Missing results for system {system!r}")
            continue
        scored = result.get("total_cases", 0)
        if scored != case_count:
            issues.append(
                f"System {system!r} scored {scored} of {case_count} cases"
            )
        unmatched = result.get("unmatched_envelope_ids") or []
        if unmatched:
            issues.append(
                f"System {system!r} has {len(unmatched)} unmatched envelope ID(s)"
            )

    if not issues:
        return {
            "status": "SMOKE_PASS",
            "summary": (
                "All systems produced outputs for every case; all outputs were "
                "scored with no unmatched envelope IDs."
            ),
            "limitations": limitations + [
                "SMOKE_PASS indicates plumbing completeness only, not benchmark validity.",
            ],
            "recommended_next_step": (
                "Proceed to visual trace inspection or live provider boundary "
                "work when authorized."
            ),
        }

    status = "SMOKE_FAIL"
    if any("scored" in issue and " of " in issue for issue in issues):
        status = "INCONCLUSIVE"

    return {
        "status": status,
        "summary": "; ".join(issues),
        "limitations": limitations,
        "recommended_next_step": (
            "Investigate missing outputs or unmatched envelope IDs before "
            "drawing conclusions."
        ),
    }


def _resolve_system_id(system: str, decisions: list[dict]) -> str:
    if decisions:
        system_id = decisions[0].get("system_id")
        if isinstance(system_id, str) and system_id:
            return system_id
    return system


def _build_system_descriptors(
    systems: list[str],
    decisions_by_system: dict[str, list[dict]],
) -> list[dict]:
    descriptors: list[dict] = []
    for system in systems:
        decisions = decisions_by_system.get(system, [])
        template = _SYSTEM_DESCRIPTOR_TEMPLATES.get(
            system,
            {
                "system_type": "unknown",
                "description": f"Unknown system: {system}",
            },
        )
        descriptors.append(
            {
                "system_id": _resolve_system_id(system, decisions),
                "system_type": template["system_type"],
                "description": template["description"],
                "claim_boundary": TIER_1_CLAIM_BOUNDARY,
            }
        )
    return descriptors


def _derive_case_set(
    cases_path: str | Path,
    gold_path: str | Path,
    envelopes: list[dict],
) -> dict:
    cases_path = Path(cases_path)
    gold_path = Path(gold_path)
    benchmark_tier = cases_path.name

    envelope_tier = "unknown"
    if envelopes:
        tier = envelopes[0].get("envelope_tier")
        if isinstance(tier, str) and tier:
            envelope_tier = tier

    return {
        "cases_path": str(cases_path),
        "gold_path": str(gold_path),
        "case_count": len(envelopes),
        "benchmark_tier": benchmark_tier,
        "envelope_tier": envelope_tier,
    }


def _build_case_traces(
    envelopes: list[dict],
    gold_by_envelope_id: dict[str, dict],
    decisions_by_system: dict[str, list[dict]],
    systems: list[str],
) -> list[dict]:
    system_id_by_name = {
        system: _resolve_system_id(system, decisions_by_system.get(system, []))
        for system in systems
    }

    decisions_by_system_id: dict[str, dict[str, dict]] = {}
    for system in systems:
        system_id = system_id_by_name[system]
        by_envelope: dict[str, dict] = {}
        for decision in decisions_by_system.get(system, []):
            envelope_id = decision.get("envelope_id")
            if isinstance(envelope_id, str) and envelope_id:
                by_envelope[envelope_id] = decision
        decisions_by_system_id[system_id] = by_envelope

    case_traces: list[dict] = []
    for envelope in envelopes:
        envelope_id = envelope["envelope_id"]
        metadata = envelope.get("metadata") or {}
        benchmark_case_id = metadata.get("benchmark_case_id")
        if not isinstance(benchmark_case_id, str) or not benchmark_case_id:
            benchmark_case_id = envelope_id

        gold = gold_by_envelope_id.get(envelope_id)

        decisions_map: dict[str, dict] = {}
        scores_map: dict[str, dict] = {}
        for system_id, by_envelope in decisions_by_system_id.items():
            decision = by_envelope.get(envelope_id)
            if decision is not None:
                decisions_map[system_id] = decision
                if gold is not None:
                    scores_map[system_id] = score_case(decision, gold)

        case_traces.append(
            {
                "benchmark_case_id": benchmark_case_id,
                "envelope_id": envelope_id,
                "envelope": envelope,
                "gold_annotation": gold,
                "decisions": decisions_map,
                "scores": scores_map,
                "notes": [],
            }
        )
    return case_traces


def build_run_trace(
    *,
    cases_path: str | Path,
    gold_path: str | Path,
    systems: list[str],
    comparison: dict,
    envelopes: list[dict],
    gold_by_envelope_id: dict[str, dict],
    decisions_by_system: dict[str, list[dict]],
) -> dict:
    """Build a complete run trace dict from comparison inputs and outputs."""
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    trace_id = make_trace_id(
        cases_path=str(cases_path),
        created_at=created_at,
        systems=systems,
    )

    return {
        "trace_id": trace_id,
        "schema_version": TRACE_SCHEMA_VERSION,
        "created_at": created_at,
        "claim_boundary": TIER_1_CLAIM_BOUNDARY,
        "case_set": _derive_case_set(cases_path, gold_path, envelopes),
        "systems": _build_system_descriptors(systems, decisions_by_system),
        "case_traces": _build_case_traces(
            envelopes,
            gold_by_envelope_id,
            decisions_by_system,
            systems,
        ),
        "aggregate_results": comparison,
        "final_verdict": derive_final_verdict(comparison),
        "metadata": {
            "generated_by": TRACE_GENERATED_BY,
            "notes": [],
        },
    }
