"""Durable governance primitives for Admissible high-autonomy runs.

This module is deliberately pure and local.  It creates stable operation and
gate identities, acceptance-ledger projections, completion-candidate parsing,
and canonical metrics.  It never executes a command, calls a provider, or
writes a target workspace.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


DEFAULT_MAX_STRUCTURED_OPERATIONS_PER_RESPONSE = 8
DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES = 256 * 1024
DEFAULT_CLOSURE_RESERVE_TURNS = 2

COMPLETION_CANDIDATE_MARKER = "ADMISSIBLE_COMPLETION_CANDIDATE:"

OPERATION_OUTCOMES = frozenset(
    {
        "executed_mutation",
        "executed_read",
        "executed_list",
        "duplicate_noop",
        "already_satisfied_noop",
        "blocked",
        "failed",
    }
)

ACCEPTANCE_STATUSES = frozenset(
    {"open", "evidence_available", "verified_pass", "verified_fail", "waived"}
)
FINAL_OUTCOMES = frozenset(
    {"completed", "incomplete", "failed", "stopped_by_budget", "stopped_by_operator"}
)

_UTF8_MOJIBAKE_MARKERS = ("â€", "â€™", "â€œ", "Â·", "ï¿½")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_workspace_relative_path(path: str) -> str:
    """Return a stable slash-separated workspace-relative path.

    Scope enforcement remains the bounded executor's responsibility.  This
    helper only supplies a canonical identity and therefore rejects absolute
    and traversal-shaped paths instead of trying to repair them.
    """

    raw = str(path or ".").strip().replace("\\", "/") or "."
    pure = PurePosixPath(raw)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"path is not workspace-relative: {path!r}")
    normalized = str(pure)
    return "." if normalized in ("", ".") else normalized


def canonical_operation_identity(
    operation: dict[str, Any],
    *,
    observed_sha256: str | None = None,
) -> str:
    """Build the canonical identity specified by ADMISSIBLE_RUN_038."""

    name = str(operation.get("operation") or "").strip()
    path = normalize_workspace_relative_path(str(operation.get("path") or "."))
    if name == "write_file":
        content = operation.get("content")
        if not isinstance(content, str):
            raise ValueError("write_file requires string content for fingerprinting")
        return f"write_file + {path} + {sha256_text(content)}"
    if name == "read_file":
        expected = (
            operation.get("expected_sha256")
            or operation.get("current_sha256")
            or observed_sha256
            or "sha_unknown"
        )
        return f"read_file + {path} + {expected}"
    if name == "list_files":
        return f"list_files + {path}"
    raise ValueError(f"unsupported operation for fingerprinting: {name!r}")


def canonical_operation_fingerprint(
    operation: dict[str, Any],
    *,
    observed_sha256: str | None = None,
) -> str:
    return sha256_text(
        canonical_operation_identity(operation, observed_sha256=observed_sha256)
    )


def current_file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_coherent_batch_limits(
    operations: Iterable[dict[str, Any]],
    *,
    max_operations: int = DEFAULT_MAX_STRUCTURED_OPERATIONS_PER_RESPONSE,
    max_total_write_bytes: int = DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES,
) -> dict[str, int]:
    """Validate count/size/path limits for one model response.

    Operation category/content/workspace checks still run again at admission
    and execution.  These are cost-aware proposal bounds, not new authority.
    """

    items = list(operations)
    if max_operations < 1 or len(items) > max_operations:
        raise ValueError(
            f"structured operation batch contains {len(items)} operation(s); "
            f"configured maximum is {max_operations}"
        )
    total_write_bytes = 0
    for operation in items:
        normalize_workspace_relative_path(str(operation.get("path") or "."))
        if str(operation.get("operation") or "").strip() == "write_file":
            content = operation.get("content")
            if not isinstance(content, str):
                raise ValueError("write_file content must be a string")
            total_write_bytes += len(content.encode("utf-8"))
    if total_write_bytes > max_total_write_bytes:
        raise ValueError(
            f"structured write batch contains {total_write_bytes} UTF-8 byte(s); "
            f"configured maximum is {max_total_write_bytes}"
        )
    return {"operation_count": len(items), "total_write_bytes": total_write_bytes}


def _json_after_marker(raw_text: str, marker: str) -> tuple[dict[str, Any] | None, tuple[int, int] | None]:
    match = re.search(re.escape(marker), raw_text, re.IGNORECASE)
    if not match:
        return None, None
    tail = raw_text[match.end() :]
    json_start_match = re.search(r"[\[{]", tail)
    if not json_start_match:
        return None, None
    start = match.end() + json_start_match.start()
    try:
        value, consumed = json.JSONDecoder().raw_decode(raw_text[start:])
    except json.JSONDecodeError:
        return None, None
    if not isinstance(value, dict):
        return None, None
    return dict(value), (match.start(), start + consumed)


def extract_completion_candidate(raw_text: str) -> tuple[dict[str, Any] | None, str]:
    """Extract one advisory completion proposal and blank it from action prose."""

    candidate, span = _json_after_marker(raw_text, COMPLETION_CANDIDATE_MARKER)
    if candidate is None or span is None:
        return None, raw_text
    start, end = span
    blanked = raw_text[:start] + (" " * (end - start)) + raw_text[end:]
    normalized = {
        "claimed_status": str(candidate.get("claimed_status") or "").strip().lower(),
        "criteria": [dict(entry) for entry in candidate.get("criteria") or [] if isinstance(entry, dict)],
        "remaining_work": [str(item) for item in candidate.get("remaining_work") or []],
        "self_authorized": False,
    }
    return normalized, blanked


def make_acceptance_ledger(
    criteria: list[str | dict[str, Any]] | None,
    *,
    goal_text: str,
) -> list[dict[str, Any]]:
    """Normalize operator-supplied criteria into a backward-compatible ledger."""

    raw_items: list[str | dict[str, Any]] = list(criteria or [])
    if not raw_items:
        raw_items = [
            {
                "criterion_id": "goal_deliverable",
                "source_text": goal_text.strip() or "Complete the submitted goal.",
                "mandatory": True,
                "verification": [],
            }
        ]
    ledger: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_items, start=1):
        if isinstance(raw, str):
            source_text = raw.strip()
            criterion_id = f"criterion_{index:03d}"
            mandatory = True
            verification: list[dict[str, Any]] = []
        else:
            source_text = str(raw.get("source_text") or raw.get("text") or "").strip()
            criterion_id = str(raw.get("criterion_id") or f"criterion_{index:03d}").strip()
            mandatory = bool(raw.get("mandatory", True))
            verification = [
                dict(entry) for entry in raw.get("verification") or [] if isinstance(entry, dict)
            ]
        if not source_text:
            raise ValueError(f"acceptance criterion {criterion_id!r} has no source text")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", criterion_id):
            raise ValueError(f"invalid acceptance criterion id: {criterion_id!r}")
        if criterion_id in seen:
            raise ValueError(f"duplicate acceptance criterion id: {criterion_id!r}")
        seen.add(criterion_id)
        ledger.append(
            {
                "criterion_id": criterion_id,
                "source_text": source_text,
                "status": "open",
                "mandatory": mandatory,
                "evidence_refs": [],
                "verification_notes": [],
                "verification": verification,
            }
        )
    return ledger


def acceptance_counts(criteria: Iterable[dict[str, Any]]) -> dict[str, int]:
    items = list(criteria)
    verified = sum(1 for item in items if item.get("status") in ("verified_pass", "waived"))
    failed = sum(1 for item in items if item.get("status") == "verified_fail")
    mandatory = [item for item in items if item.get("mandatory", True)]
    mandatory_verified = sum(
        1 for item in mandatory if item.get("status") in ("verified_pass", "waived")
    )
    return {
        "total": len(items),
        "verified": verified,
        "failed": failed,
        "mandatory_total": len(mandatory),
        "mandatory_verified": mandatory_verified,
    }


def apply_verification_results_to_ledger(
    criteria: list[dict[str, Any]],
    verification_record: dict[str, Any],
) -> None:
    """Update criteria only from deterministic verification evidence."""

    results_by_criterion: dict[str, list[dict[str, Any]]] = {}
    for result in verification_record.get("results") or []:
        criterion_id = result.get("criterion_id") or (result.get("evidence_payload") or {}).get(
            "criterion_id"
        )
        if criterion_id:
            results_by_criterion.setdefault(str(criterion_id), []).append(result)

    evidence_id = verification_record.get("evidence_id")
    for criterion in criteria:
        criterion_id = str(criterion.get("criterion_id") or "")
        matches = results_by_criterion.get(criterion_id, [])
        if not matches:
            continue
        passed = all(result.get("status") == "pass" for result in matches)
        criterion["status"] = "verified_pass" if passed else "verified_fail"
        refs = criterion.setdefault("evidence_refs", [])
        if evidence_id and evidence_id not in refs:
            refs.append(evidence_id)
        notes = criterion.setdefault("verification_notes", [])
        notes.extend(str(result.get("message") or result.get("check_id")) for result in matches)


def latest_file_hashes(operation_records: Iterable[dict[str, Any]]) -> dict[str, str]:
    latest: dict[str, str] = {}
    for record in operation_records:
        if record.get("outcome") != "executed_mutation":
            continue
        path = record.get("path")
        sha = record.get("result_sha256") or record.get("proposed_sha256")
        if path and sha:
            latest[str(path)] = str(sha)
    return latest


def active_blocking_action_ids(queue: Iterable[Any]) -> list[str]:
    """Canonical currently-active blocking definition used by every projection."""

    ids: list[str] = []
    for raw in queue:
        item = raw if isinstance(raw, dict) else raw.to_dict()
        if item.get("superseded_at") or item.get("suppressed_pseudo_gate"):
            continue
        if item.get("operation_outcome") in (
            "executed_mutation",
            "executed_read",
            "executed_list",
            "duplicate_noop",
            "already_satisfied_noop",
        ):
            continue
        status = item.get("execution_status")
        lifecycle = item.get("lifecycle_status")
        if status in ("executed_by_bounded_executor", "executed_after_admission"):
            continue
        if lifecycle in (
            "resolved_gate",
            "refused_closed",
            "superseded",
            "ready_for_next_agent_instruction",
        ):
            continue
        decision = item.get("decision")
        action_type = item.get("action_type")
        if (
            item.get("safe_overwrite_review_required")
            and not item.get("human_decision_ids")
        ) or (
            action_type
            in {
                "run_shell_command",
                "run_command",
                "execute_command",
                "access_secret",
                "access_env",
                "publish",
                "git_push",
                "git_commit",
            }
            and not item.get("human_decision_ids")
            and status == "proposed_only"
        ):
            ids.append(str(item.get("action_id") or ""))
            continue
        if decision in (
            "REFUSE",
            "REQUEST_MORE_EVIDENCE",
            "REQUIRE_HUMAN_APPROVAL",
            "ALLOW_WITH_LIMITS",
        ):
            ids.append(str(item.get("action_id") or ""))
    return [item for item in ids if item]


def build_canonical_metrics(
    *,
    operation_records: Iterable[dict[str, Any]],
    governance_records: Iterable[dict[str, Any]],
    verification_records: Iterable[dict[str, Any]],
    invocation_history: Iterable[dict[str, Any]],
    human_decisions: Iterable[Any],
    queue: Iterable[Any],
    work_turns_used: int,
    verification_turns_used: int,
    closure_turns_used: int,
    turns_remaining: int,
) -> dict[str, int]:
    operations = list(operation_records)
    governance = list(governance_records)
    verifications = list(verification_records)
    invocations = list(invocation_history)
    decisions = list(human_decisions)

    unique_states = {
        (record.get("path"), record.get("result_sha256") or record.get("proposed_sha256"))
        for record in operations
        if record.get("outcome") == "executed_mutation"
    }
    verification_results = [
        result for record in verifications for result in (record.get("results") or [])
    ]
    return {
        "model_invocation_count": len(invocations),
        "backend_retry_count": sum(1 for item in invocations if item.get("retry_of_invocation_id")),
        "empty_success_count": sum(1 for item in invocations if item.get("status") == "empty_success"),
        "useful_write_count": sum(1 for item in operations if item.get("outcome") == "executed_mutation"),
        "unique_file_state_count": len(unique_states),
        "duplicate_noop_count": sum(1 for item in operations if item.get("outcome") == "duplicate_noop"),
        "already_satisfied_noop_count": sum(
            1 for item in operations if item.get("outcome") == "already_satisfied_noop"
        ),
        "overwrite_count": sum(
            1
            for item in operations
            if item.get("outcome") == "executed_mutation" and item.get("overwrite")
        ),
        "read_count": sum(1 for item in operations if item.get("outcome") == "executed_read"),
        "list_count": sum(1 for item in operations if item.get("outcome") == "executed_list"),
        "verification_check_count": len(verification_results),
        "verification_pass_count": sum(
            1 for item in verification_results if item.get("status") == "pass"
        ),
        "verification_fail_count": sum(
            1 for item in verification_results if item.get("status") == "fail"
        ),
        "genuine_human_intervention_count": len(decisions)
        + sum(
            1
            for item in governance
            if item.get("event_type") == "acceptance_criterion_waived"
        ),
        "suppressed_pseudo_gate_count": sum(
            1 for item in governance if item.get("event_type") == "pseudo_gate_suppressed"
        ),
        "superseded_gate_count": sum(
            1 for item in governance if item.get("event_type") == "gate_superseded"
        ),
        "active_blocked_count": len(active_blocking_action_ids(queue)),
        "work_turns_used": int(work_turns_used),
        "verification_turns_used": int(verification_turns_used),
        "closure_turns_used": int(closure_turns_used),
        "turns_remaining": max(int(turns_remaining), 0),
    }


def has_utf8_mojibake(text: str) -> bool:
    return any(marker in text for marker in _UTF8_MOJIBAKE_MARKERS)


__all__ = [
    "ACCEPTANCE_STATUSES",
    "COMPLETION_CANDIDATE_MARKER",
    "DEFAULT_CLOSURE_RESERVE_TURNS",
    "DEFAULT_MAX_STRUCTURED_OPERATIONS_PER_RESPONSE",
    "DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES",
    "FINAL_OUTCOMES",
    "OPERATION_OUTCOMES",
    "acceptance_counts",
    "active_blocking_action_ids",
    "apply_verification_results_to_ledger",
    "build_canonical_metrics",
    "canonical_operation_fingerprint",
    "canonical_operation_identity",
    "current_file_sha256",
    "extract_completion_candidate",
    "has_utf8_mojibake",
    "latest_file_hashes",
    "make_acceptance_ledger",
    "normalize_workspace_relative_path",
    "sha256_text",
    "validate_coherent_batch_limits",
]
