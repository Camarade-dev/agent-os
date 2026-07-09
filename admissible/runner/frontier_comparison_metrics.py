"""Deterministic comparison metrics from Admissible session exports (Slice DEMO_028).

Reads a round-trippable Control Surface session JSON export and projects
governance-oriented comparison metrics. Does not execute shell, npm, network,
deploy, or provider calls. Does not mutate workspaces.

CLI:

    python -m admissible.runner.frontier_comparison_metrics \\
        --session path/to/session.json

Optional ungoverned observation log (Condition A operator capture):

    python -m admissible.runner.frontier_comparison_metrics \\
        --observation-log path/to/observation_log.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from admissible.control_surface import ControlSurfaceController

METRICS_SCHEMA_VERSION = "admissible_frontier_comparison_metrics_v0"
CLAIM_BOUNDARY = (
    "Governance demo metrics from a session export or operator observation log. "
    "Not a SOTA benchmark result. Does not measure coding ability."
)

_GATED_DECISIONS = frozenset(
    {"REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL", "REFUSE", "ALLOW_WITH_LIMITS"}
)
_EXECUTED_STATUSES = frozenset(
    {"executed_by_bounded_executor", "executed_after_admission", "side_effect_executed"}
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _transcript_type_counts(transcript: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in transcript:
        event_type = str(entry.get("type") or "unknown")
        counts[event_type] = counts.get(event_type, 0) + 1
    return counts


def _per_turn_decisions(queue: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group queue items by turn inferred from action_id prefix (resp_tNN_)."""
    by_turn: dict[str, list[dict[str, Any]]] = {}
    for item in queue:
        action_id = str(item.get("action_id") or "")
        turn_key = "unknown"
        if action_id.startswith("resp_t") and len(action_id) >= 8:
            turn_key = action_id[5:8]  # e.g. t01
        by_turn.setdefault(turn_key, []).append(
            {
                "action_id": action_id,
                "decision": item.get("decision"),
                "execution_status": item.get("execution_status"),
                "executed": item.get("execution_status") in _EXECUTED_STATUSES,
                "tool_or_command": item.get("tool_or_command"),
            }
        )
    return by_turn


def summarize_governed_session(session_data: dict[str, Any]) -> dict[str, Any]:
    """Project comparison metrics from a canonical session export (Condition B)."""
    with tempfile.TemporaryDirectory() as tmp:
        controller = ControlSurfaceController(session_dir=tmp)
        view = controller.import_session(session_data)

    timeline = view.get("run_timeline") or {}
    governed = view.get("governed_run_overview") or {}
    verification = view.get("verification_summary") or {}
    mission = view.get("mission_summary") or {}
    diagnostics = view.get("session_diagnostics") or {}
    continuation = view.get("continuation_instruction") or {}
    queue = view.get("queue") or []

    gated_not_executed = [
        {
            "action_id": item.get("action_id"),
            "decision": item.get("decision"),
            "tool_or_command": item.get("tool_or_command"),
        }
        for item in queue
        if item.get("decision") in _GATED_DECISIONS
        and item.get("execution_status") not in _EXECUTED_STATUSES
    ]

    executed_local_ops = sum(
        1
        for item in queue
        if item.get("execution_status") in _EXECUTED_STATUSES
    )

    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "condition": "B_admissible_governed",
        "session_id": session_data.get("session_id"),
        "goal": governed.get("goal") or (session_data.get("goal_intake") or {}).get("prompt"),
        "workspace_path": session_data.get("bounded_executor_workspace"),
        "turn_count": governed.get("turn_count", timeline.get("turn_count", 0)),
        "write_evidence_count": governed.get("write_evidence_count", timeline.get("evidence_count", 0)),
        "executed_local_file_ops": executed_local_ops,
        "gated_not_executed_count": len(gated_not_executed),
        "gated_not_executed": gated_not_executed,
        "ingest_auto_executed": False,
        "verification_readiness": verification.get("readiness"),
        "verification_profile": verification.get("profile"),
        "verification_passed_count": verification.get("passed_count"),
        "verification_failed_count": verification.get("failed_count"),
        "continuation_available": bool(continuation.get("available")),
        "continuation_status": continuation.get("status"),
        "side_effect_executed_by_admissible_flag": mission.get("side_effect_executed_by_admissible"),
        "counts_by_decision": mission.get("counts_by_decision"),
        "bridge_blocked_ingest_events": len(diagnostics.get("bridge_blocked_ingest_events") or []),
        "transcript_event_counts": _transcript_type_counts(session_data.get("transcript") or []),
        "per_turn_decisions": _per_turn_decisions(queue),
        "run_timeline_status": timeline.get("status"),
    }


def summarize_ungoverned_observation_log(log_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Condition A operator observation log for side-by-side reports."""
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "condition": "A_ungoverned_frontier_agent",
        "observation_schema_version": log_data.get("schema_version"),
        "recorded_at": log_data.get("recorded_at"),
        "model_label": log_data.get("model_label"),
        "workspace_path": log_data.get("workspace_path"),
        "turns_observed": log_data.get("turns_observed"),
        "files_written_directly": list(log_data.get("files_written_directly") or []),
        "shell_or_npm_executed": bool(log_data.get("shell_or_npm_executed")),
        "deploy_proposed_or_executed": bool(log_data.get("deploy_proposed_or_executed")),
        "completion_claimed_by_agent": bool(log_data.get("completion_claimed_by_agent")),
        "audit_trail_present": bool(log_data.get("audit_trail_present")),
        "recovery_after_blocker": log_data.get("recovery_after_blocker"),
        "operator_manual_steps_approx": log_data.get("operator_manual_steps_approx"),
        "ingest_auto_executed": None,
        "write_evidence_count": None,
        "verification_readiness": None,
    }


def summarize_comparison_pair(
    *,
    governed_session: dict[str, Any] | None = None,
    ungoverned_log: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a side-by-side comparison envelope for report generation."""
    conditions: dict[str, Any] = {}
    if governed_session is not None:
        conditions["B_admissible_governed"] = summarize_governed_session(governed_session)
    if ungoverned_log is not None:
        conditions["A_ungoverned_frontier_agent"] = summarize_ungoverned_observation_log(
            ungoverned_log
        )
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "claim_boundary": CLAIM_BOUNDARY,
        "conditions": conditions,
        "condition_a_pending": ungoverned_log is None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize Admissible session exports into frontier comparison metrics."
    )
    parser.add_argument(
        "--session",
        type=Path,
        help="Path to a canonical Control Surface session.json export (Condition B).",
    )
    parser.add_argument(
        "--observation-log",
        type=Path,
        help="Path to a Condition A ungoverned observation log JSON.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Optional path to write JSON output (default: stdout).",
    )
    args = parser.parse_args(argv)

    if not args.session and not args.observation_log:
        parser.error("provide at least one of --session or --observation-log")

    governed_data = _load_json(args.session) if args.session else None
    ungoverned_data = _load_json(args.observation_log) if args.observation_log else None

    if governed_data is not None and ungoverned_data is not None:
        result = summarize_comparison_pair(
            governed_session=governed_data,
            ungoverned_log=ungoverned_data,
        )
    elif governed_data is not None:
        result = summarize_governed_session(governed_data)
    else:
        assert ungoverned_data is not None
        result = summarize_ungoverned_observation_log(ungoverned_data)

    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
