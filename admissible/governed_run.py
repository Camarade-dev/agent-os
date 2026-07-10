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
                        "check_id": "file_contains",
                        "target_paths": js_targets[:1],
                        "contains": ["Arrow", "'w'", "'a'", "'s'", "'d'"],
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
                        "check_id": "file_contains",
                        "target_paths": js_targets[:1],
                        "contains": ["restart", "R"],
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
                        "check_id": "file_contains",
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
    "canonical_operation_fingerprint",
    "canonical_operation_identity",
    "current_file_sha256",
    "derive_acceptance_criteria_from_goal",
    "extract_completion_candidate",
    "has_utf8_mojibake",
    "latest_file_hashes",
    "make_acceptance_ledger",
    "normalize_workspace_relative_path",
    "repair_inconsistent_executable_lifecycle",
    "ResponseExtractionFailed",
    "sha256_text",
    "validate_coherent_batch_limits",
]
