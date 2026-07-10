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
DEFAULT_MAX_REPAIR_ROUNDS = 2
DEFAULT_OUTCOME_IN_PROGRESS = "in_progress"

_KNOWN_ENV_CANONICAL_KEYS = {
    "systemroot": "SystemRoot",
    "systemdrive": "SystemDrive",
    "programdata": "ProgramData",
    "userprofile": "USERPROFILE",
    "appdata": "APPDATA",
    "localappdata": "LOCALAPPDATA",
    "temp": "TEMP",
    "tmp": "TMP",
    "windir": "WINDIR",
}

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
        raw_items = derive_acceptance_criteria_from_goal(goal_text)
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
        diagnostics = criterion.setdefault("verification_diagnostics", [])
        for result in matches:
            payload = dict(result.get("evidence_payload") or {})
            if payload.get("subchecks") or payload.get("failure_class"):
                diagnostics.append(
                    {
                        "criterion_id": criterion_id,
                        "status": result.get("status"),
                        "failure_class": payload.get("failure_class"),
                        "target_path": payload.get("path")
                        or (result.get("target_paths") or [None])[0],
                        "subchecks": payload.get("subchecks") or {},
                        "passed_subchecks": payload.get("passed_subchecks") or {},
                        "failed_subchecks": payload.get("failed_subchecks") or {},
                        "missing": payload.get("missing") or payload.get("missing_paths") or [],
                        "repair_hint": payload.get("repair_hint"),
                        "message": result.get("message"),
                    }
                )


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
        if item.get("superseded_at") or item.get("suppressed_pseudo_gate") or item.get(
            "suppressed_non_action"
        ):
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
            "admitted_not_executed",
            "closed",
            "no_longer_needs_attention",
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
        "raw_human_decision_count": len(decisions),
        "genuine_human_intervention_count": count_genuine_human_interventions(
            decisions, governance
        ),
        "retrospectively_suppressed_pseudo_gate_decision_count": sum(
            1
            for item in governance
            if item.get("event_type")
            in ("retrospective_pseudo_gate_suppressed", "pseudo_gate_suppressed")
        ),
        "retrospectively_suppressed_non_action_decision_count": sum(
            1
            for item in governance
            if item.get("event_type")
            in ("retrospective_non_action_suppressed", "negated_non_action_suppressed")
        ),
        "negated_non_action_suppression_count": sum(
            1
            for item in governance
            if item.get("event_type") == "negated_non_action_suppressed"
        ),
        "goal_boundary_suppression_or_refusal_count": sum(
            1
            for item in governance
            if item.get("event_type") == "goal_boundary_suppression_or_refusal"
        ),
        "suppressed_pseudo_gate_count": sum(
            1 for item in governance if item.get("event_type") == "pseudo_gate_suppressed"
        ),
        "proposal_coverage_failure_count": sum(
            1
            for item in governance
            if item.get("event_type") == "proposal_coverage_incomplete"
        ),
        "unmatched_optional_write_count": sum(
            1 for item in operations if item.get("classification") == "deferred_optional"
        ),
        "repair_round_count": sum(
            1 for item in governance if item.get("event_type") == "repair_round_started"
        ),
        "repaired_criterion_count": sum(
            1 for item in governance if item.get("event_type") == "criterion_repaired"
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


def derive_acceptance_criteria_from_goal(goal_text: str) -> list[dict[str, Any]]:
    """Derive verifiable acceptance criteria from explicit goal deliverables/behaviors.

    Generic templates only — no product-specific names.  Returns an empty list
    when the goal does not contain enough explicit structure to verify.
    """

    text = (goal_text or "").strip()
    if not text:
        return []

    lower = text.lower()
    deliverable_names = _extract_goal_deliverable_filenames(text)
    if len(deliverable_names) < 2:
        return []

    criteria: list[dict[str, Any]] = []
    if deliverable_names:
        criteria.append(
            {
                "criterion_id": "required_files",
                "source_text": "All required deliverable files are present.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "all_required_files_present",
                        "target_paths": deliverable_names,
                    }
                ],
            }
        )

    html_targets = [name for name in deliverable_names if name.endswith(".html")]
    css_targets = [name for name in deliverable_names if name.endswith(".css")]
    js_targets = [name for name in deliverable_names if name.endswith(".js")]
    doc_targets = [
        name
        for name in deliverable_names
        if name.endswith(".md") or "dev" in name.lower() or "usage" in name.lower()
    ]

    if html_targets and css_targets and js_targets:
        criteria.append(
            {
                "criterion_id": "index_assets",
                "source_text": "HTML references the required local CSS and JS.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "file_contains",
                        "target_paths": html_targets[:1],
                        "contains": [css_targets[0], js_targets[0]],
                    }
                ],
            }
        )

    if html_targets and (
        "canvas" in lower
        or "score" in lower
        or "game" in lower
    ):
        criteria.append(
            {
                "criterion_id": "index_game_ui",
                "source_text": "HTML contains a game canvas and visible score element.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "file_contains",
                        "target_paths": html_targets[:1],
                        "contains": ["<canvas", "score"],
                    }
                ],
            }
        )

    if css_targets:
        criteria.append(
            {
                "criterion_id": "style_non_empty",
                "source_text": "CSS deliverable is non-empty.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "file_not_empty",
                        "target_paths": css_targets[:1],
                    }
                ],
            }
        )

    if js_targets and ("arrow" in lower or "wasd" in lower or "movement" in lower):
        criteria.append(
            {
                "criterion_id": "game_controls",
                "source_text": "JavaScript handles Arrow keys and WASD movement.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "game_controls_check",
                        "target_paths": js_targets[:1],
                    }
                ],
            }
        )

    if js_targets and ("collectible" in lower or "score" in lower):
        criteria.append(
            {
                "criterion_id": "game_collectible_score",
                "source_text": "JavaScript contains collectible and score behavior.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "file_contains",
                        "target_paths": js_targets[:1],
                        "contains": ["collectible", "score"],
                    }
                ],
            }
        )

    if js_targets and ("restart" in lower or " r key" in lower or "press `r`" in lower):
        criteria.append(
            {
                "criterion_id": "game_restart",
                "source_text": "JavaScript supports R-key restart behavior.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "game_restart_check",
                        "target_paths": js_targets[:1],
                    }
                ],
            }
        )

    if doc_targets and ("usage" in lower or "local" in lower or "run" in lower):
        criteria.append(
            {
                "criterion_id": "local_usage",
                "source_text": "Local usage documentation exists and contains run instructions.",
                "mandatory": True,
                "verification": [
                    {
                        "check_id": "local_usage_check",
                        "target_paths": doc_targets[:1],
                        "contains": ["open", "index.html"],
                    }
                ],
            }
        )

    return criteria


def _extract_goal_deliverable_filenames(goal_text: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"(?:^|[\s\-•*])\s*([A-Za-z0-9_.-]+\.(?:html?|css|js|mjs|md|txt))\s*(?:$|[\s,;])",
        goal_text,
        re.MULTILINE | re.IGNORECASE,
    ):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            names.append(name)
    for match in re.finditer(r"`([A-Za-z0-9_.-]+\.(?:html?|css|js|mjs|md|txt))`", goal_text):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


BLOCK_OUTCOME_PARSED_AND_QUEUED = "parsed_and_queued"
BLOCK_OUTCOME_PARSED_DUPLICATE = "parsed_duplicate"
BLOCK_OUTCOME_PARSED_ALREADY_SATISFIED = "parsed_already_satisfied"
BLOCK_OUTCOME_REJECTED_WITH_REASON = "rejected_with_reason"
BLOCK_OUTCOME_MALFORMED_WITH_REASON = "malformed_with_reason"


class ResponseExtractionFailed(ValueError):
    """Raised when structured markers were present but no actions survived ingestion."""


def build_agent_response_extraction_report(
    raw_text: str,
    *,
    built: list[dict[str, Any]] | None = None,
    completion_candidate: dict[str, Any] | None = None,
    session: Any | None = None,
    workspace_path: str | None = None,
) -> dict[str, Any]:
    """Build a durable diagnostic for one agent response extraction pass."""

    from admissible.long_run_envelope_builder import (
        STRUCTURED_OPERATION_MARKER,
        _STRUCTURED_OPERATION_MARKER_RE,
        _scan_balanced_json,
        _operations_from_payload,
    )
    from admissible.execution.bounded_local_executor import _forbidden_write_content_reason
    import json as _json

    marker_matches = list(_STRUCTURED_OPERATION_MARKER_RE.finditer(raw_text))
    structured_marker_count = len(marker_matches)
    blocks: list[dict[str, Any]] = []
    parsed_operation_count = 0
    rejected_operation_count = 0

    for index, marker in enumerate(marker_matches, start=1):
        block_id = f"block_{index:03d}"
        scanned = _scan_balanced_json(raw_text, marker.end())
        if scanned is None:
            blocks.append(
                {
                    "block_id": block_id,
                    "outcome": BLOCK_OUTCOME_MALFORMED_WITH_REASON,
                    "reason": "no_balanced_json_after_marker",
                    "operations": [],
                }
            )
            rejected_operation_count += 1
            continue
        json_text, _end = scanned
        try:
            payload = _json.loads(json_text)
        except _json.JSONDecodeError as exc:
            blocks.append(
                {
                    "block_id": block_id,
                    "outcome": BLOCK_OUTCOME_MALFORMED_WITH_REASON,
                    "reason": f"json_decode_error: {exc.msg}",
                    "operations": [],
                }
            )
            rejected_operation_count += 1
            continue
        operations = _operations_from_payload(payload)
        if not operations:
            blocks.append(
                {
                    "block_id": block_id,
                    "outcome": BLOCK_OUTCOME_MALFORMED_WITH_REASON,
                    "reason": "empty_or_unrecognized_operation_payload",
                    "operations": [],
                }
            )
            rejected_operation_count += 1
            continue
        block_outcomes: list[dict[str, Any]] = []
        for operation in operations:
            name = str(operation.get("operation") or "").strip()
            path = str(operation.get("path") or ".")
            content_guard_reason = None
            if name == "write_file":
                content = operation.get("content")
                if not isinstance(content, str):
                    content_guard_reason = "write_file_missing_string_content"
                else:
                    content_guard_reason = _forbidden_write_content_reason(path, content)
            block_outcomes.append(
                {
                    "operation": name,
                    "path": path,
                    "content_guard_decision": (
                        "rejected" if content_guard_reason else "allowed"
                    ),
                    "content_guard_reason": content_guard_reason,
                }
            )
        blocks.append(
            {
                "block_id": block_id,
                "outcome": BLOCK_OUTCOME_PARSED_AND_QUEUED,
                "reason": None,
                "operations": block_outcomes,
            }
        )
        parsed_operation_count += len(operations)

    extracted_action_ids = [entry["action_id"] for entry in built or [] if entry.get("action_id")]
    completion_status = (
        "parsed"
        if completion_candidate is not None
        else "absent"
        if STRUCTURED_OPERATION_MARKER not in raw_text
        else "not_present"
    )

    from admissible.long_run_envelope_builder import build_from_raw_output

    builder_out = build_from_raw_output(raw_text)
    polarity = builder_out.get("extraction_polarity_diagnostics") or {}

    return {
        "structured_marker_count": structured_marker_count,
        "structured_block_count": len(blocks),
        "parsed_operation_count": parsed_operation_count,
        "rejected_operation_count": rejected_operation_count,
        "blocks": blocks,
        "extracted_action_ids": extracted_action_ids,
        "surviving_action_count": len(extracted_action_ids),
        "completion_candidate_status": completion_status,
        "extraction_failed": structured_marker_count > 0 and len(extracted_action_ids) == 0,
        "extraction_polarity_diagnostics": polarity,
        "suppressed_prose_candidates": builder_out.get("suppressed_prose_candidates") or [],
    }


def repair_inconsistent_executable_lifecycle(
    queue: Iterable[Any],
    *,
    run_envelopes: dict[str, Any] | None = None,
    workspace_path: str | None = None,
    governance_records: list[dict[str, Any]] | None = None,
) -> int:
    """Normalize stranded ALLOW executable actions back to ``ready_to_execute``."""

    del workspace_path  # retained for import/load call-site compatibility

    forbidden_lifecycle_for_unexecuted_allow = {
        "ready_for_next_agent_instruction",
        "closed",
        "completed",
        "refused_closed",
        "resolved_gate",
    }
    supported_operations = {"write_file", "read_file", "list_directory"}
    repairs = 0
    records = governance_records if governance_records is not None else []
    envelopes = run_envelopes or {}

    for raw in queue:
        item = raw if isinstance(raw, dict) else raw.to_dict()
        action_id = str(item.get("action_id") or "")
        if not action_id:
            continue
        if item.get("decision") != "ALLOW":
            continue
        if item.get("operational_admissibility_action") != "execute":
            continue
        execution_status = str(item.get("execution_status") or "proposed_only")
        if execution_status not in ("proposed_only", ""):
            continue
        if item.get("execution_record"):
            continue
        envelope = envelopes.get(action_id) or {}
        candidate = (
            envelope.get("candidate")
            if isinstance(envelope, dict)
            else getattr(envelope, "candidate", {})
        ) or {}
        operations = candidate.get("structured_operations") or []
        if not any(
            str(operation.get("operation") or "").strip() in supported_operations
            for operation in operations
        ):
            continue
        lifecycle = item.get("lifecycle_status")
        if lifecycle == "ready_to_execute":
            continue
        if lifecycle not in forbidden_lifecycle_for_unexecuted_allow:
            continue
        if not isinstance(raw, dict):
            raw.lifecycle_status = "ready_to_execute"
        else:
            raw["lifecycle_status"] = "ready_to_execute"
        repairs += 1
        records.append(
            {
                "record_id": f"governance_repair_{sha256_text(action_id)[:12]}",
                "event_type": "executable_lifecycle_repaired",
                "action_id": action_id,
                "previous_lifecycle_status": lifecycle,
                "repaired_lifecycle_status": "ready_to_execute",
                "reason": "allow_execute_without_execution_record",
            }
        )
    return repairs


def extract_required_paths_from_goal(goal_text: str) -> list[str]:
    """Return explicit mandatory deliverable paths declared in a goal."""

    return _extract_goal_deliverable_filenames(goal_text)


def build_proposal_coverage_report(
    *,
    goal_text: str,
    structured_operations: list[dict[str, Any]],
    satisfied_paths: dict[str, str] | None = None,
    avoid_optional_polish: bool = False,
) -> dict[str, Any]:
    """Compare mandatory goal paths against a proposed structured batch."""

    required_paths = extract_required_paths_from_goal(goal_text)
    already_satisfied_paths = sorted(path for path in (satisfied_paths or {}) if path)
    proposed_paths = sorted(
        {
            normalize_workspace_relative_path(str(operation.get("path") or ""))
            for operation in structured_operations
            if str(operation.get("operation") or "").strip() == "write_file"
            and str(operation.get("path") or "").strip()
        }
    )
    proposed_required_paths = [path for path in proposed_paths if path in required_paths]
    missing_required_paths = [
        path for path in required_paths if path not in proposed_paths and path not in already_satisfied_paths
    ]
    additional_paths = [path for path in proposed_paths if path not in required_paths]
    coverage_complete = not missing_required_paths
    return {
        "required_paths": required_paths,
        "already_satisfied_paths": already_satisfied_paths,
        "proposed_required_paths": proposed_required_paths,
        "missing_required_paths": missing_required_paths,
        "additional_paths": additional_paths,
        "coverage_complete": coverage_complete,
        "avoid_optional_polish": avoid_optional_polish,
    }


def classify_optional_write_paths(
    coverage_report: dict[str, Any],
) -> dict[str, str]:
    """Map unmatched proposal paths to deferred_optional when polish is discouraged."""

    if not coverage_report.get("avoid_optional_polish"):
        return {}
    return {path: "deferred_optional" for path in coverage_report.get("additional_paths") or []}


def failed_mandatory_criteria(criteria: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in criteria
        if item.get("mandatory", True) and item.get("status") == "verified_fail"
    ]


def build_repair_packet(
    *,
    criteria: list[dict[str, Any]],
    verification_record: dict[str, Any] | None,
    satisfied_file_hashes: dict[str, str],
    goal_text: str,
    remaining_turn_budget: int,
    repair_round: int,
    max_repair_rounds: int = DEFAULT_MAX_REPAIR_ROUNDS,
) -> dict[str, Any]:
    """Targeted repair scope containing only failed mandatory criteria."""

    failed = failed_mandatory_criteria(criteria)
    failed_ids = [str(item.get("criterion_id") or "") for item in failed]
    diagnostics: list[dict[str, Any]] = []
    for result in (verification_record or {}).get("results") or []:
        criterion_id = result.get("criterion_id")
        if criterion_id in failed_ids and result.get("status") == "fail":
            payload = dict(result.get("evidence_payload") or {})
            diagnostics.append(
                {
                    "criterion_id": criterion_id,
                    "failure_class": payload.get("failure_class") or "verification_fail",
                    "target_path": payload.get("path")
                    or (result.get("target_paths") or [None])[0],
                    "passed_subchecks": payload.get("passed_subchecks") or {},
                    "failed_subchecks": payload.get("failed_subchecks") or payload.get("subchecks") or {},
                    "missing": payload.get("missing") or payload.get("missing_paths") or [],
                    "repair_hint": payload.get("repair_hint") or result.get("message"),
                    "message": result.get("message"),
                }
            )
    required_paths = extract_required_paths_from_goal(goal_text)
    missing_mandatory_paths = [
        path
        for path in required_paths
        if path not in satisfied_file_hashes
    ]
    return {
        "failed_criteria": failed_ids,
        "verification_diagnostics": diagnostics,
        "satisfied_file_hashes": dict(satisfied_file_hashes),
        "missing_mandatory_paths": missing_mandatory_paths,
        "repair_boundaries": {
            "preserve_passing_artifacts": True,
            "structured_operations_only": True,
            "no_optional_polish": True,
            "exact_mandatory_paths": missing_mandatory_paths,
        },
        "remaining_turn_budget": remaining_turn_budget,
        "repair_round": repair_round,
        "max_repair_rounds": max_repair_rounds,
    }


def build_repair_instruction_text(repair_packet: dict[str, Any]) -> str:
    """Compose a bounded repair instruction from a repair packet."""

    lines = [
        "TARGETED REPAIR REQUEST: deterministic verification found repairable failures.",
        "Propose the smallest coherent structured repair batch only.",
        "Preserve passing artifacts; do not rewrite passing files unless required.",
        "Use exact mandatory paths; no optional polish; structured operations only.",
        "",
        "Failed mandatory criteria:",
    ]
    for entry in repair_packet.get("verification_diagnostics") or []:
        lines.append(
            f"- {entry.get('criterion_id')}: {entry.get('message') or entry.get('repair_hint')}"
        )
    missing_paths = repair_packet.get("missing_mandatory_paths") or []
    if missing_paths:
        lines.extend(["", "Exact mandatory paths still missing:"])
        lines.extend(f"- {path}" for path in missing_paths)
    lines.extend(
        [
            "",
            "Repair boundaries:",
            json.dumps(repair_packet.get("repair_boundaries") or {}, ensure_ascii=False, sort_keys=True),
            "",
            f"Repair round: {repair_packet.get('repair_round')}/{repair_packet.get('max_repair_rounds')}",
        ]
    )
    return "\n".join(lines).strip()


def count_genuine_human_interventions(
    human_decisions: Iterable[Any],
    governance_records: Iterable[dict[str, Any]],
) -> int:
    """Count human decisions excluding retrospectively suppressed pseudo-gates."""

    suppressed_action_ids = {
        str(item.get("action_id") or "")
        for item in governance_records
        if item.get("event_type")
        in (
            "pseudo_gate_suppressed",
            "retrospective_pseudo_gate_suppressed",
            "retrospective_non_action_suppressed",
            "negated_non_action_suppressed",
        )
    }
    waived = sum(
        1
        for item in governance_records
        if item.get("event_type") == "acceptance_criterion_waived"
    )
    genuine = 0
    for raw in human_decisions:
        record = raw if isinstance(raw, dict) else raw.to_dict()
        action_id = str(record.get("action_id") or "")
        if action_id and action_id in suppressed_action_ids:
            continue
        genuine += 1
    return genuine + waived


def canonicalize_environment_paths(
    paths: dict[str, str] | None,
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Case-insensitively dedupe environment path keys for portable JSON export."""

    if not paths:
        return {}, {}
    canonical: dict[str, str] = {}
    aliases: dict[str, list[str]] = {}
    for key, value in paths.items():
        canonical_key = _KNOWN_ENV_CANONICAL_KEYS.get(key.lower(), key)
        if canonical_key in canonical and canonical[canonical_key] != value:
            aliases.setdefault(canonical_key, []).append(key)
            continue
        if canonical_key not in canonical:
            canonical[canonical_key] = value
        if key != canonical_key:
            aliases.setdefault(canonical_key, []).append(key)
    for key in list(aliases):
        aliases[key] = sorted(set(aliases[key]))
    return canonical, aliases


def validate_portable_json_no_case_colliding_keys(value: Any, *, path: str = "$") -> list[str]:
    """Return paths to objects whose keys collide case-insensitively."""

    violations: list[str] = []
    if isinstance(value, dict):
        lowered: dict[str, list[str]] = {}
        for key in value:
            lowered.setdefault(str(key).lower(), []).append(str(key))
        for keys in lowered.values():
            if len(keys) > 1:
                violations.append(f"{path}: {keys}")
        for key, child in value.items():
            violations.extend(
                validate_portable_json_no_case_colliding_keys(child, path=f"{path}.{key}")
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            violations.extend(
                validate_portable_json_no_case_colliding_keys(child, path=f"{path}[{index}]")
            )
    return violations


def reconcile_invocation_history(
    ha_data: dict[str, Any] | None,
    transcript: Iterable[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Backfill missing invocation_history rows from transcript metadata."""

    data = dict(ha_data or {})
    history = list(data.get("invocation_history") or [])
    known_ids = {str(item.get("invocation_id") or "") for item in history if item.get("invocation_id")}
    for entry in transcript or []:
        payload = entry.get("payload") if isinstance(entry, dict) else None
        if not isinstance(payload, dict):
            continue
        invocation_id = str(payload.get("invocation_id") or "").strip()
        if not invocation_id or invocation_id in known_ids:
            continue
        event_type = str(entry.get("event_type") or entry.get("type") or "")
        if "instruction_written" not in event_type and "response_ingested" not in event_type:
            continue
        history.append(
            {
                "invocation_id": invocation_id,
                "status": "response_ready" if "response_ingested" in event_type else "invoked",
                "turn_number": payload.get("turn"),
                "reconciled_from_transcript": True,
                "timestamp": entry.get("timestamp"),
            }
        )
        known_ids.add(invocation_id)
    pending = data.get("pending_agent_invocation")
    if isinstance(pending, dict):
        invocation_id = str(pending.get("invocation_id") or "").strip()
        if invocation_id and invocation_id not in known_ids:
            history.append(dict(pending))
    data["invocation_history"] = history
    return data


def migrate_high_autonomy_projection(ha_data: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize legacy null/missing projection fields on load."""

    data = dict(ha_data or {})
    if data.get("outcome") is None:
        data["outcome"] = DEFAULT_OUTCOME_IN_PROGRESS if data.get("active") else data.get("outcome")
    if data.get("outcome") is None:
        data["outcome"] = DEFAULT_OUTCOME_IN_PROGRESS
    metrics = dict(data.get("metrics") or {})
    data["metrics"] = metrics
    data.setdefault("repair_phase", "none")
    data.setdefault("repair_round_count", 0)
    data.setdefault("max_repair_rounds", DEFAULT_MAX_REPAIR_ROUNDS)
    data.setdefault("repair_history", [])
    if data.get("pending_useful_operation_count") is None:
        data["pending_useful_operation_count"] = len(data.get("pending_useful_operations") or [])
    if data.get("active_blocked_count") is None:
        data["active_blocked_count"] = int(metrics.get("active_blocked_count", 0))
    if data.get("blocking_reason") is None:
        data["blocking_reason"] = ""
    if data.get("verification_readiness") is None:
        data["verification_readiness"] = "not_run"
    if data.get("next_action") is None:
        data["next_action"] = "none"
    return data


def migrate_session_projection_fields(session_data: dict[str, Any]) -> dict[str, Any]:
    """Apply non-null projection defaults to exported/imported session payloads."""

    data = dict(session_data)
    ha = data.get("high_autonomy_run")
    if isinstance(ha, dict):
        ha = reconcile_invocation_history(ha, data.get("transcript"))
        data["high_autonomy_run"] = migrate_high_autonomy_projection(ha)
    projected = dict(data.get("projected_run_fields") or {})
    ha_migrated = data.get("high_autonomy_run") or {}
    metrics = dict((ha_migrated.get("metrics") if isinstance(ha_migrated, dict) else {}) or {})
    projected.setdefault(
        "outcome",
        (ha_migrated.get("outcome") if isinstance(ha_migrated, dict) else None)
        or DEFAULT_OUTCOME_IN_PROGRESS,
    )
    projected.setdefault(
        "pending_useful_operation_count",
        len((ha_migrated.get("pending_useful_operations") if isinstance(ha_migrated, dict) else []) or []),
    )
    projected.setdefault(
        "active_blocked_count",
        int(metrics.get("active_blocked_count", 0)),
    )
    projected.setdefault("blocking_reason", projected.get("blocking_reason") or "")
    projected.setdefault(
        "verification_readiness",
        (ha_migrated.get("verification_readiness") if isinstance(ha_migrated, dict) else None)
        or "not_run",
    )
    projected.setdefault(
        "next_action",
        (ha_migrated.get("next_action") if isinstance(ha_migrated, dict) else None) or "none",
    )
    data["projected_run_fields"] = projected
    return data


def canonicalize_session_export_payload(session_data: dict[str, Any]) -> dict[str, Any]:
    """Prepare a session dict for portable JSON export."""

    data = migrate_session_projection_fields(session_data)
    ha = data.get("high_autonomy_run")
    if isinstance(ha, dict):
        history = list(ha.get("invocation_history") or [])
        for item in history:
            env_paths = item.get("environment_paths")
            if isinstance(env_paths, dict):
                canonical, aliases = canonicalize_environment_paths(env_paths)
                item["environment_paths"] = canonical
                if aliases:
                    item["environment_path_aliases"] = aliases
        pending = ha.get("pending_agent_invocation")
        if isinstance(pending, dict) and isinstance(pending.get("environment_paths"), dict):
            canonical, aliases = canonicalize_environment_paths(pending["environment_paths"])
            pending["environment_paths"] = canonical
            if aliases:
                pending["environment_path_aliases"] = aliases
        ha["invocation_history"] = history
        data["high_autonomy_run"] = ha
    return data


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
    "build_agent_response_extraction_report",
    "build_canonical_metrics",
    "build_proposal_coverage_report",
    "build_repair_instruction_text",
    "build_repair_packet",
    "canonicalize_environment_paths",
    "canonicalize_session_export_payload",
    "canonical_operation_fingerprint",
    "canonical_operation_identity",
    "classify_optional_write_paths",
    "count_genuine_human_interventions",
    "current_file_sha256",
    "DEFAULT_MAX_REPAIR_ROUNDS",
    "DEFAULT_OUTCOME_IN_PROGRESS",
    "derive_acceptance_criteria_from_goal",
    "extract_completion_candidate",
    "extract_required_paths_from_goal",
    "failed_mandatory_criteria",
    "has_utf8_mojibake",
    "latest_file_hashes",
    "make_acceptance_ledger",
    "migrate_high_autonomy_projection",
    "migrate_session_projection_fields",
    "normalize_workspace_relative_path",
    "repair_inconsistent_executable_lifecycle",
    "ResponseExtractionFailed",
    "sha256_text",
    "validate_coherent_batch_limits",
    "validate_portable_json_no_case_colliding_keys",
]
