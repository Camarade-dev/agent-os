"""Runtime repair packets (PART J).

Mirrors the shape and boundaries of
:func:`admissible.governed_run.build_repair_packet` so a runtime repair
composes with the existing repair loop, but scoped to exactly what PART J
allows: failed/gap criterion IDs, exact assertion diagnostics, observed
runtime values, console/page exceptions, blocked external attempts, missing
observables, satisfied artifacts, unchanged passing criteria, repair
boundaries, and remaining budget. Never the full transcript.
"""

from __future__ import annotations

from typing import Any

from admissible.browser_runtime.models import BrowserRuntimeEvidence

_FORBIDDEN_REPAIR_REQUESTS = (
    "state mutation methods",
    "cheat controls",
    "filesystem access",
    "network access",
    "bypasses of game rules",
    "verifier-only hidden success flags",
)


def _failing_criterion_results(evidence: BrowserRuntimeEvidence) -> list[dict[str, Any]]:
    return [r for r in evidence.criterion_results if r["status"] not in ("verified_pass", "awaiting_human_observation")]


def build_runtime_repair_packet(
    *,
    evidence: BrowserRuntimeEvidence,
    repair_round: int,
    max_repair_rounds: int,
) -> dict[str, Any]:
    """A targeted runtime-failure repair packet (PART I.46 first branch)."""

    failing = _failing_criterion_results(evidence)
    failed_ids = [r["criterion_id"] for r in failing]
    passing_ids = [r["criterion_id"] for r in evidence.criterion_results if r["status"] == "verified_pass"]

    diagnostics = []
    for result in failing:
        for assertion in result.get("assertions") or []:
            if assertion.get("status") in ("fail", "error"):
                diagnostics.append(
                    {
                        "criterion_id": result["criterion_id"],
                        "assertion_id": assertion.get("assertion_id"),
                        "step_type": assertion.get("step_type"),
                        "status": assertion.get("status"),
                        "observed_value": assertion.get("observed_value"),
                        "expected_relation": assertion.get("expected_relation"),
                        "message": assertion.get("message"),
                        "repair_hint": assertion.get("repair_hint"),
                    }
                )

    return {
        "kind": "runtime_verification_failure",
        "failed_criteria": failed_ids,
        "unchanged_passing_criteria": passing_ids,
        "assertion_diagnostics": diagnostics,
        "console_entries": list(evidence.console_entries)[:20],
        "page_exceptions": list(evidence.page_exceptions)[:20],
        "blocked_external_request_attempts": list(evidence.external_request_attempts)[:20],
        "missing_observables": [],
        "repair_boundaries": {
            "preserve_passing_artifacts": True,
            "structured_operations_only": True,
            "no_optional_polish": True,
            "forbidden_requests": list(_FORBIDDEN_REPAIR_REQUESTS),
        },
        "repair_round": repair_round,
        "max_repair_rounds": max_repair_rounds,
        "remaining_repair_budget": max(0, max_repair_rounds - repair_round),
    }


def build_instrumentation_repair_packet(
    *,
    evidence: BrowserRuntimeEvidence,
    debug_interface: str | None,
    repair_round: int,
    max_repair_rounds: int,
) -> dict[str, Any]:
    """A targeted read-only instrumentation repair packet (PART F.30, PART I.46 second branch).

    Only requested when the Mission Contract already authorizes a read-only
    debug interface. Never requests state mutation, cheat controls,
    filesystem/network access, rule bypasses, or hidden success flags.
    """

    gaps = [r for r in evidence.criterion_results if r["status"] == "runtime_observability_gap"]
    missing_observables = sorted({obs for r in gaps for obs in (r.get("required_observables") or [])}) or sorted(
        {r["criterion_id"] for r in gaps}
    )

    return {
        "kind": "runtime_instrumentation_gap",
        "gap_criteria": [r["criterion_id"] for r in gaps],
        "unchanged_passing_criteria": [r["criterion_id"] for r in evidence.criterion_results if r["status"] == "verified_pass"],
        "debug_interface": debug_interface,
        "missing_observables": missing_observables,
        "allowed_instrumentation_requests": [
            "additional snapshot fields",
            "stable DOM status markers",
            "read-only loop counters",
            "read-only entity counts",
            "read-only lifecycle state",
        ],
        "forbidden_requests": list(_FORBIDDEN_REPAIR_REQUESTS),
        "repair_boundaries": {
            "preserve_passing_artifacts": True,
            "read_only_instrumentation_only": True,
            "no_optional_polish": True,
        },
        "repair_round": repair_round,
        "max_repair_rounds": max_repair_rounds,
        "remaining_repair_budget": max(0, max_repair_rounds - repair_round),
    }


def build_runtime_repair_instruction_text(packet: dict[str, Any]) -> str:
    """Compose a bounded repair instruction from a runtime repair packet.

    Never replays the full transcript (PART J.50): only the failing
    criteria, their diagnostics, and the repair boundaries.
    """

    if packet.get("kind") == "runtime_instrumentation_gap":
        lines = [
            "TARGETED INSTRUMENTATION REPAIR: the following criteria have no safe runtime observable yet.",
            "Add only read-only instrumentation; do not add mutation methods, cheat controls, or hidden flags.",
            "",
            f"Debug interface: {packet.get('debug_interface')}",
            "Gap criteria: " + ", ".join(packet.get("gap_criteria") or []),
            "Missing observables: " + ", ".join(packet.get("missing_observables") or []),
            "",
            "Allowed instrumentation:",
        ]
        lines.extend(f"- {item}" for item in packet.get("allowed_instrumentation_requests") or [])
        lines.extend(["", f"Repair round: {packet.get('repair_round')}/{packet.get('max_repair_rounds')}"])
        return "\n".join(lines).strip()

    lines = [
        "TARGETED RUNTIME REPAIR REQUEST: real browser verification found repairable failures.",
        "Propose the smallest coherent structured repair batch only.",
        "Preserve passing artifacts; do not rewrite passing files unless required.",
        "",
        "Failed runtime criteria:",
    ]
    for entry in packet.get("assertion_diagnostics") or []:
        lines.append(f"- {entry.get('criterion_id')} ({entry.get('step_type')}): {entry.get('message') or entry.get('repair_hint')}")
    if packet.get("blocked_external_request_attempts"):
        lines.extend(["", "Blocked external request attempts (must not be required by the fix):"])
        lines.extend(f"- {a.get('url')}" for a in packet["blocked_external_request_attempts"])
    lines.extend(
        [
            "",
            "Repair boundaries:",
            ", ".join(f"{k}={v}" for k, v in (packet.get("repair_boundaries") or {}).items() if not isinstance(v, list)),
            "",
            f"Repair round: {packet.get('repair_round')}/{packet.get('max_repair_rounds')}",
        ]
    )
    return "\n".join(lines).strip()
