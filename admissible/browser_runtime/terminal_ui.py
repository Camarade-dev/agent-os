"""Runtime-verification terminal UX (PART L).

Pure presentation-shaping functions: banner selection, contract/evidence
coverage summaries, and safety status. No side effects, no printing --
callers (CLI, Control Surface) render these however fits their surface.
"""

from __future__ import annotations

from typing import Any

from admissible.browser_runtime.models import BrowserRuntimeEvidence

# PART L.59: mutually exclusive primary banners.
BANNER_IN_PROGRESS = "RUNTIME VERIFICATION IN PROGRESS"
BANNER_FAILED = "RUNTIME VERIFICATION FAILED"
BANNER_OBSERVABILITY_GAP = "RUNTIME OBSERVABILITY GAP"
BANNER_BROWSER_UNAVAILABLE = "BROWSER VERIFICATION UNAVAILABLE"
BANNER_AWAITING_HUMAN_OBSERVATION = "AWAITING HUMAN OBSERVATION"
BANNER_RUN_COMPLETED = "RUN COMPLETED"

_STATUS_TO_BANNER = {
    "runtime_verifying": BANNER_IN_PROGRESS,
    "runtime_verification_pending": BANNER_IN_PROGRESS,
    "preparing_runtime_plan": BANNER_IN_PROGRESS,
    "runtime_capability_check": BANNER_IN_PROGRESS,
    "runtime_verification_fail": BANNER_FAILED,
    "runtime_observability_gap": BANNER_OBSERVABILITY_GAP,
    "verification_capability_gap": BANNER_BROWSER_UNAVAILABLE,
    "runtime_verification_capability_gap": BANNER_BROWSER_UNAVAILABLE,
    "awaiting_human_observation": BANNER_AWAITING_HUMAN_OBSERVATION,
    "runtime_verification_pass": BANNER_RUN_COMPLETED,
    "completed": BANNER_RUN_COMPLETED,
}


def select_runtime_banner(status: str, *, completion_eligible: bool = False) -> str:
    """Return exactly one of the PART L.59 banners for one evidence/session status.

    ``runtime_verification_pass`` only ever renders as ``RUN COMPLETED`` when
    the caller also confirms overall completion eligibility (PART L.63): a
    runtime pass with an unrelated pending gap elsewhere must not show green.
    """

    if status in ("runtime_verification_pass", "completed") and not completion_eligible:
        return BANNER_IN_PROGRESS
    return _STATUS_TO_BANNER.get(status, BANNER_IN_PROGRESS)


def build_contract_and_verification_summary(
    *,
    coverage_report: dict[str, Any],
    criterion_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """PART L.60: contract coverage and verification-outcome counts, shown separately."""

    total_criteria = coverage_report.get("explicit_acceptance_criterion_count") or coverage_report.get("total_mandatory_criteria") or 0
    represented_criteria = coverage_report.get("represented_acceptance_criterion_count", total_criteria)
    total_paths = coverage_report.get("mandatory_path_count", 0)
    represented_paths = coverage_report.get("represented_path_count", total_paths)

    static_passed = sum(1 for r in criterion_results if r.get("disposition") in ("deterministic_static", "deterministic_structural") and r.get("status") == "verified_pass")
    runtime_passed = sum(1 for r in criterion_results if r.get("disposition") == "deterministic_runtime" and r.get("status") == "verified_pass")
    runtime_unverified = sum(
        1
        for r in criterion_results
        if r.get("disposition") == "deterministic_runtime" and r.get("status") != "verified_pass"
    )
    human_pending = sum(1 for r in criterion_results if r.get("status") == "awaiting_human_observation")

    return {
        "contract": {
            "criteria_represented": represented_criteria,
            "criteria_total": total_criteria,
            "exact_paths_represented": represented_paths,
            "exact_paths_total": total_paths,
        },
        "verification": {
            "static_criteria_passed": static_passed,
            "runtime_criteria_passed": runtime_passed,
            "runtime_criteria_unverified": runtime_unverified,
            "human_observation_criteria_pending": human_pending,
        },
    }


def build_runtime_safety_status(evidence: BrowserRuntimeEvidence) -> dict[str, Any]:
    """PART L.61: runtime safety status shown alongside the banner."""

    provider = dict(evidence.provider or {})
    return {
        "browser_provider": provider.get("provider_id"),
        "browser_version": provider.get("browser_version"),
        "loopback_origin_policy": "loopback_only",
        "external_network_attempts": len(evidence.external_request_attempts),
        "console_errors": sum(1 for e in evidence.console_entries if e.get("level") == "error"),
        "page_exceptions": len(evidence.page_exceptions),
        "runtime_duration_ms": evidence.duration_ms,
        "input_event_count": len(evidence.input_events),
        "snapshot_count": len(evidence.debug_snapshots),
        "screenshot_count": len(evidence.screenshots),
        "cleanup": dict(evidence.resource_cleanup),
        "policy_violation_count": len(evidence.policy_violations),
    }


def mode_stopped_is_secondary(banner: str, mode_label: str) -> dict[str, str]:
    """PART L.62: the semantic terminal banner is primary; ``Mode: stopped`` is secondary."""

    return {"primary": banner, "secondary": mode_label}
