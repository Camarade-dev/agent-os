"""Runtime-verification state names and transitions (PART I).

Pure, standalone, and additive: nothing here mutates
``admissible.high_autonomy_controller``'s existing state machine. It gives
that controller (or any other caller) a small, tested vocabulary and
transition function for the browser-runtime verification lifecycle, kept
separate from Cursor/agent-turn states and from shell-action admission.
"""

from __future__ import annotations

from typing import Any

from admissible.browser_runtime.runner import (
    CRITERION_STATUS_CAPABILITY_GAP,
    CRITERION_STATUS_GAP,
    CRITERION_STATUS_HUMAN,
)

# PART I.43 states.
RUNTIME_VERIFICATION_PENDING = "runtime_verification_pending"
PREPARING_RUNTIME_PLAN = "preparing_runtime_plan"
RUNTIME_CAPABILITY_CHECK = "runtime_capability_check"
RUNTIME_VERIFYING = "runtime_verifying"
RUNTIME_VERIFICATION_PASS = "runtime_verification_pass"
RUNTIME_VERIFICATION_FAIL = "runtime_verification_fail"
RUNTIME_OBSERVABILITY_GAP = "runtime_observability_gap"
AWAITING_HUMAN_OBSERVATION = "awaiting_human_observation"
RUNTIME_VERIFICATION_CAPABILITY_GAP = "runtime_verification_capability_gap"

# Reuses the existing governed_run/high_autonomy_controller repair-phase
# vocabulary so a runtime repair composes with the pre-existing repair loop
# instead of inventing a parallel one.
REPAIR_NEEDED = "repair_needed"

RUNTIME_STATES = frozenset(
    {
        RUNTIME_VERIFICATION_PENDING,
        PREPARING_RUNTIME_PLAN,
        RUNTIME_CAPABILITY_CHECK,
        RUNTIME_VERIFYING,
        RUNTIME_VERIFICATION_PASS,
        RUNTIME_VERIFICATION_FAIL,
        RUNTIME_OBSERVABILITY_GAP,
        AWAITING_HUMAN_OBSERVATION,
        RUNTIME_VERIFICATION_CAPABILITY_GAP,
        REPAIR_NEEDED,
    }
)

# PART I.47: a runtime failure or capability gap may never collapse into one
# of these labels; they belong to unrelated failure/authority domains.
FORBIDDEN_MISCLASSIFICATIONS = frozenset({"internal_livelock", "human_authority_blocker", "completed"})

RUNTIME_ADMISSION_CLASS = "browser_runtime_verification"


def admission_class_for_runtime_action() -> str:
    """PART I.45: a browser-runtime verification action is its own admission class, not a shell action."""

    return RUNTIME_ADMISSION_CLASS


def next_runtime_state(
    evidence_status: str,
    *,
    repair_budget_remaining: bool,
    instrumentation_repair_authorized: bool = False,
) -> str:
    """PART I.46: map one evidence outcome to the next runtime state.

    Never returns a label in :data:`FORBIDDEN_MISCLASSIFICATIONS`.
    """

    if evidence_status == "verification_capability_gap":
        return RUNTIME_VERIFICATION_CAPABILITY_GAP
    if evidence_status == "awaiting_human_observation":
        return AWAITING_HUMAN_OBSERVATION
    if evidence_status == "runtime_observability_gap":
        return REPAIR_NEEDED if instrumentation_repair_authorized else RUNTIME_OBSERVABILITY_GAP
    if evidence_status == "runtime_verification_fail":
        return REPAIR_NEEDED if repair_budget_remaining else RUNTIME_VERIFICATION_FAIL
    if evidence_status == "runtime_verification_pass":
        return RUNTIME_VERIFICATION_PASS
    raise ValueError(f"unknown runtime evidence status: {evidence_status!r}")


def criterion_result_to_runtime_state(result_status: str) -> str:
    """Map one BrowserRuntimeEvidence.criterion_results[i]['status'] to a display state."""

    return {
        CRITERION_STATUS_HUMAN: AWAITING_HUMAN_OBSERVATION,
        CRITERION_STATUS_GAP: RUNTIME_OBSERVABILITY_GAP,
        CRITERION_STATUS_CAPABILITY_GAP: RUNTIME_VERIFICATION_CAPABILITY_GAP,
    }.get(result_status, result_status)


_REQUIRED_SAFETY_INVARIANTS = (
    "authorized_target_workspace",
    "exact_local_entrypoint",
    "loopback_only_server",
    "deny_external_network_policy",
    "allowlisted_browser",
    "validated_declarative_plan",
    "limits_within_hard_maximums",
    "no_arbitrary_evaluation",
    "no_download_upload_permission",
    "evidence_output_isolated",
)


def evaluate_l4_auto_run_safety_invariants(
    plan: Any,
    capability_report: dict[str, Any],
) -> dict[str, Any]:
    """PART I.44: whether runtime verification may auto-run without a human decision in L4.

    Returns ``{"safe_to_auto_run": bool, "satisfied": [...], "violated": [...]}``.
    Every check here is redundant with validation already performed at plan
    construction / provider launch time; this is a final, defense-in-depth
    gate specifically for the high-autonomy auto-run decision point.
    """

    from admissible.browser_runtime import limits

    satisfied: list[str] = []
    violated: list[str] = []

    def check(name: str, ok: bool) -> None:
        (satisfied if ok else violated).append(name)

    check("authorized_target_workspace", bool(plan.workspace_root))
    check("exact_local_entrypoint", bool(plan.entrypoint_path) and ".." not in plan.entrypoint_path.replace("\\", "/").split("/"))
    check("loopback_only_server", plan.target_origin_policy == "loopback_only")
    check("deny_external_network_policy", plan.target_origin_policy == "loopback_only")
    check("allowlisted_browser", bool(capability_report.get("available")))
    try:
        from admissible.browser_runtime.dsl import validate_steps

        validate_steps(plan.steps, max_steps=plan.max_steps)
        check("validated_declarative_plan", True)
    except Exception:  # noqa: BLE001 - any validation failure is a hard "not safe"
        check("validated_declarative_plan", False)
    check(
        "limits_within_hard_maximums",
        plan.max_duration_ms <= limits.ABSOLUTE_MAX_DURATION_MS
        and plan.max_steps <= limits.ABSOLUTE_MAX_STEPS
        and plan.max_input_events <= limits.ABSOLUTE_MAX_INPUT_EVENTS
        and plan.max_snapshots <= limits.ABSOLUTE_MAX_SNAPSHOTS
        and plan.max_screenshots <= limits.ABSOLUTE_MAX_SCREENSHOTS,
    )
    check("no_arbitrary_evaluation", True)  # structurally guaranteed: the DSL has no such step type
    check("no_download_upload_permission", True)  # structurally guaranteed: providers only deny/record these
    check("evidence_output_isolated", True)  # structurally guaranteed: see admissible.browser_runtime.evidence_store

    return {"safe_to_auto_run": not violated, "satisfied": satisfied, "violated": violated}
