"""Bounded local file executor v0 for Admissible.

Executes only explicitly admitted, structured local file operations inside an
approved workspace. Not a shell executor; no npm/git/deploy/network.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from admissible.admitted_execution import (
    EXECUTION_ACTOR_BOUNDED_EXECUTOR,
    EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY,
    EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
    is_local_allow_without_missing_evidence,
)
from admissible.run_loop import EvidenceRecord
from admissible.execution.bounded_write import (
    BoundedWriteError,
    BoundedWriteRequest,
    execute_bounded_write,
)

ALLOWED_BOUNDED_OPERATIONS = frozenset({"list_files", "read_file", "write_file"})

DIAG_NOT_ADMITTED = "not_admitted"
DIAG_UNSUPPORTED_OPERATION = "unsupported_operation"
DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION = "not_executable_without_structured_operation"
DIAG_PATH_OUTSIDE_WORKSPACE = "path_outside_workspace"
DIAG_NO_WORKSPACE_CONFIGURED = "no_workspace_configured"
DIAG_REFUSED_DECISION = "refused_decision"
DIAG_FORBIDDEN_OPERATION_CATEGORY = "forbidden_operation_category"
DIAG_ALREADY_EXECUTED = "already_executed"

_FORBIDDEN_NATURAL_LANGUAGE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bnpm\b",
        r"\byarn\b",
        r"\bpip\b",
        r"\bpnpm\b",
        r"\bbun\b",
        r"\bgit\s+(push|commit|clone|pull|fetch)\b",
        r"\bdeploy\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bssh\b",
        r"\bsubprocess\b",
        r"\bos\.system\b",
        r"\bshell\b",
        r"\bchmod\b",
        r"\brm\s+-rf\b",
    )
)

_FORBIDDEN_OPERATION_TOKENS = frozenset(
    {
        "shell",
        "run_command",
        "execute_command",
        "npm",
        "pip",
        "install",
        "git_push",
        "git_commit",
        "deploy",
        "network",
        "delete_file",
        "delete",
        "remove_file",
    }
)


class BoundedExecutionError(ValueError):
    """Raised when bounded execution is refused or fails."""

    def __init__(self, message: str, *, diagnostic: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic
        self.detail: dict[str, Any] = dict(detail) if detail else {"diagnostic": diagnostic}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_workspace_path(workspace_path: str | Path | None) -> Path:
    """Return a resolved workspace directory or raise BoundedExecutionError."""
    if workspace_path is None or not str(workspace_path).strip():
        raise BoundedExecutionError(
            "no workspace configured for bounded local execution",
            diagnostic=DIAG_NO_WORKSPACE_CONFIGURED,
        )
    workspace = Path(str(workspace_path).strip())
    if not workspace.is_dir():
        raise BoundedExecutionError(
            f"workspace path does not exist or is not a directory: {workspace}",
            diagnostic=DIAG_NO_WORKSPACE_CONFIGURED,
            detail={"workspace_path": str(workspace), "exists": workspace.exists()},
        )
    return workspace.resolve()


def validate_relative_path_inside_workspace(workspace: Path, relative_path: str) -> Path:
    """Resolve ``relative_path`` inside ``workspace`` or raise."""
    workspace = workspace.resolve()
    raw = str(relative_path or ".").strip() or "."
    rel = Path(raw)
    if rel.is_absolute():
        raise BoundedExecutionError(
            f"absolute paths are not allowed inside workspace: {raw!r}",
            diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE,
            detail={"path": raw},
        )
    if ".." in rel.parts:
        raise BoundedExecutionError(
            f"path traversal is not allowed: {raw!r}",
            diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE,
            detail={"path": raw},
        )
    target = (workspace / rel).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise BoundedExecutionError(
            f"path resolves outside workspace: {raw!r}",
            diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE,
            detail={"path": raw, "resolved": str(target), "workspace": str(workspace)},
        ) from exc
    # Symlink escape: if an existing component is a symlink, re-check the real path.
    for ancestor in [target, *target.parents]:
        if ancestor == workspace:
            break
        if ancestor.is_symlink():
            resolved = ancestor.resolve()
            try:
                resolved.relative_to(workspace)
            except ValueError as exc:
                raise BoundedExecutionError(
                    f"symlink escape outside workspace: {raw!r}",
                    diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE,
                    detail={"path": raw, "symlink": str(ancestor), "resolved": str(resolved)},
                ) from exc
    return target


def _looks_like_forbidden_natural_language(text: str) -> bool:
    return any(pattern.search(text) for pattern in _FORBIDDEN_NATURAL_LANGUAGE_PATTERNS)


_NETWORK_SIDE_EFFECT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern) for pattern in (
        r"\bfetch\s*\(",
        r"\bXMLHttpRequest\b",
        r"\bWebSocket\s*\(",
        r"\bEventSource\s*\(",
        r"https?://",
    )
)

_EXTERNAL_RESOURCE_REFERENCE_PATTERN = re.compile(
    r"(?:src|href)\s*=\s*[\"']\s*https?://", re.IGNORECASE
)

_EXECUTABLE_OR_SECRET_CONTENT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bchild_process\b",
        r"\bsubprocess\.(?:run|popen|call)\s*\(",
        r"\bos\.system\s*\(",
        r"\bprocess\.env\b",
        r"\bDeno\.Command\s*\(",
        r"\bBun\.spawn\s*\(",
        r"\b(?:exec|spawn|system)Sync\s*\(",
    )
)


def _has_network_side_effect(content: str) -> bool:
    return any(pattern.search(content) for pattern in _NETWORK_SIDE_EFFECT_PATTERNS)


def _has_external_resource_reference(content: str) -> bool:
    return bool(_EXTERNAL_RESOURCE_REFERENCE_PATTERN.search(content))


def _forbidden_write_content_reason(path: str, content: str) -> str | None:
    """Return a refusal reason for ``content``, or ``None`` if it is safe.

    Path-aware: local browser text files (html/css/js) are allowed to contain
    harmless prose using words like npm/git/deploy/network/shell, but actual
    embedded network calls, external resource references, or external CSS
    url()/@import references are still refused. Every other file extension
    keeps the strict naive-language scan.
    """
    extension = Path(str(path).replace("\\", "/")).suffix.lower()

    if any(pattern.search(content) for pattern in _EXECUTABLE_OR_SECRET_CONTENT_PATTERNS):
        return "forbidden executable-command or secret-reference content"

    if extension == ".css":
        if _has_network_side_effect(content):
            return "forbidden network reference in write content"
        return None

    if extension == ".js":
        if _has_network_side_effect(content):
            return "forbidden network call in write content"
        return None

    if extension in (".html", ".htm"):
        if _has_external_resource_reference(content):
            return "forbidden external resource reference in write content"
        if _has_network_side_effect(content):
            return "forbidden network call in write content"
        return None

    if extension == ".md":
        if _has_network_side_effect(content):
            return "forbidden network call in write content"
        return None

    if _looks_like_forbidden_natural_language(content):
        return "forbidden operation string in write content"
    return None


def _normalize_operation_dict(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    operation = str(raw.get("operation") or "").strip()
    if not operation:
        return None
    return dict(raw)


def extract_structured_operations(
    *,
    candidate: dict[str, Any] | None = None,
    envelope: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Collect structured local operations from candidate/envelope/request body."""
    collected: list[dict[str, Any]] = []

    def extend_from(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                normalized = _normalize_operation_dict(item)
                if normalized is not None:
                    collected.append(normalized)
        else:
            normalized = _normalize_operation_dict(value)
            if normalized is not None:
                collected.append(normalized)

    if body:
        if body.get("operations"):
            extend_from(body.get("operations"))
        elif body.get("operation"):
            extend_from(body.get("operation"))

    if candidate:
        extend_from(candidate.get("structured_operations"))
        extend_from(candidate.get("structured_operation"))

    if envelope:
        proposed = envelope.get("proposed_action") or {}
        arguments = proposed.get("arguments")
        if isinstance(arguments, dict):
            extend_from(arguments.get("structured_operations"))
            extend_from(arguments.get("structured_operation"))
        extend_from(proposed.get("structured_operations"))
        extend_from(proposed.get("structured_operation"))

    return collected


def _validate_operation_shape(operation: dict[str, Any]) -> None:
    name = str(operation.get("operation") or "").strip()
    if name in _FORBIDDEN_OPERATION_TOKENS:
        raise BoundedExecutionError(
            f"forbidden operation category: {name!r}",
            diagnostic=DIAG_FORBIDDEN_OPERATION_CATEGORY,
            detail={"operation": name},
        )
    if name not in ALLOWED_BOUNDED_OPERATIONS:
        raise BoundedExecutionError(
            f"unsupported bounded operation: {name!r}",
            diagnostic=DIAG_UNSUPPORTED_OPERATION,
            detail={"operation": name, "allowed": sorted(ALLOWED_BOUNDED_OPERATIONS)},
        )
    path = str(operation.get("path") or ".").strip() or "."
    if _looks_like_forbidden_natural_language(path):
        raise BoundedExecutionError(
            f"forbidden operation string in path: {path!r}",
            diagnostic=DIAG_FORBIDDEN_OPERATION_CATEGORY,
            detail={"path": path},
        )
    if name == "write_file":
        if "content" not in operation:
            raise BoundedExecutionError(
                "write_file requires explicit content",
                diagnostic=DIAG_UNSUPPORTED_OPERATION,
                detail={"operation": name},
            )
        content = operation.get("content")
        if not isinstance(content, str):
            raise BoundedExecutionError(
                "write_file content must be a string",
                diagnostic=DIAG_UNSUPPORTED_OPERATION,
                detail={"operation": name},
            )
        violation = _forbidden_write_content_reason(path, content)
        if violation is not None:
            raise BoundedExecutionError(
                violation,
                diagnostic=DIAG_FORBIDDEN_OPERATION_CATEGORY,
            )


def _is_admitted_for_bounded_execution(
    *,
    decision_label: str,
    execution_status: str,
    lifecycle_status: str,
    decision: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[bool, str | None]:
    if decision_label == "REFUSE":
        return False, DIAG_REFUSED_DECISION
    if decision_label == "REQUEST_MORE_EVIDENCE":
        return False, DIAG_NOT_ADMITTED
    if decision_label == "ALLOW_WITH_LIMITS":
        return False, DIAG_NOT_ADMITTED
    if execution_status in (
        EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
        "executed_after_admission",
    ):
        return False, DIAG_ALREADY_EXECUTED

    admitted_via_human = (
        execution_status == "admitted_not_executed"
        or lifecycle_status == "admitted_not_executed"
    )
    if decision_label == "REQUIRE_HUMAN_APPROVAL":
        return (admitted_via_human, None if admitted_via_human else DIAG_NOT_ADMITTED)

    if decision_label == "ALLOW" and is_local_allow_without_missing_evidence(decision, candidate):
        return True, None

    if admitted_via_human:
        return True, None

    return False, DIAG_NOT_ADMITTED


def assess_bounded_execution_eligibility(
    *,
    item: Any,
    envelope: Any | None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return eligibility, diagnostic, and structured operations for one queue item."""
    decision_label = getattr(item, "decision", None) or (item.get("decision") if isinstance(item, dict) else "")
    execution_status = getattr(item, "execution_status", None) or (
        item.get("execution_status") if isinstance(item, dict) else "proposed_only"
    )
    lifecycle_status = getattr(item, "lifecycle_status", None) or (
        item.get("lifecycle_status") if isinstance(item, dict) else ""
    )

    candidate = envelope.candidate if envelope is not None else {}
    decision = envelope.decision if envelope is not None else {}
    full_envelope = envelope.envelope if envelope is not None else None

    admitted, diag = _is_admitted_for_bounded_execution(
        decision_label=str(decision_label),
        execution_status=str(execution_status),
        lifecycle_status=str(lifecycle_status),
        decision=decision,
        candidate=candidate,
    )
    if not admitted:
        message = {
            DIAG_REFUSED_DECISION: "Refused action cannot be executed.",
            DIAG_NOT_ADMITTED: "Action is not admitted for bounded local execution.",
            DIAG_ALREADY_EXECUTED: "Action was already executed.",
        }.get(diag or DIAG_NOT_ADMITTED, "Action is not admitted for bounded local execution.")
        return {
            "eligible": False,
            "diagnostic": diag,
            "message": message,
            "operations": [],
        }

    operations = extract_structured_operations(
        candidate=candidate,
        envelope=full_envelope,
        body=body,
    )
    if not operations:
        tool_or_command = (
            getattr(item, "tool_or_command", None)
            or candidate.get("tool_or_command")
            or ""
        )
        if _looks_like_forbidden_natural_language(str(tool_or_command)):
            return {
                "eligible": False,
                "diagnostic": DIAG_FORBIDDEN_OPERATION_CATEGORY,
                "message": (
                    "Not executable by bounded executor: natural-language action "
                    "implies forbidden shell/package/git/deploy/network behavior."
                ),
                "operations": [],
            }
        return {
            "eligible": False,
            "diagnostic": DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION,
            "message": "Not executable by bounded executor: no structured local operation.",
            "operations": [],
        }

    return {
        "eligible": True,
        "diagnostic": None,
        "message": "Eligible for bounded local execution.",
        "operations": operations,
    }


@dataclass
class BoundedExecutionResult:
    """Outcome of one bounded local execution attempt."""

    success: bool
    diagnostic: str | None = None
    message: str = ""
    action_id: str | None = None
    operations_executed: list[dict[str, Any]] = field(default_factory=list)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    execution_record: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "diagnostic": self.diagnostic,
            "message": self.message,
            "action_id": self.action_id,
            "operations_executed": list(self.operations_executed),
            "evidence_records": [record.to_dict() for record in self.evidence_records],
            "execution_record": self.execution_record,
        }


class BoundedLocalExecutor:
    """Execute structured local file operations inside one workspace root."""

    def __init__(self, workspace_path: str | Path) -> None:
        self.workspace = validate_workspace_path(workspace_path)

    def execute_operations(
        self,
        operations: list[dict[str, Any]],
        *,
        action_id: str,
        decision_id: str | None = None,
        envelope_id: str | None = None,
        turn_number: int | None = None,
        timestamp: str | None = None,
    ) -> BoundedExecutionResult:
        if not operations:
            return BoundedExecutionResult(
                success=False,
                diagnostic=DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION,
                message="Not executable by bounded executor: no structured local operation.",
                action_id=action_id,
            )

        executed: list[dict[str, Any]] = []
        evidence_records: list[EvidenceRecord] = []
        ts = timestamp or _now_iso()

        try:
            for operation in operations:
                _validate_operation_shape(operation)
                name = str(operation["operation"]).strip()
                rel_path = str(operation.get("path") or ".").strip() or "."
                target = validate_relative_path_inside_workspace(self.workspace, rel_path)

                if name == "list_files":
                    if not target.is_dir():
                        raise BoundedExecutionError(
                            f"list_files target is not a directory: {rel_path!r}",
                            diagnostic=DIAG_UNSUPPORTED_OPERATION,
                        )
                    entries = sorted(p.name for p in target.iterdir())
                    summary = f"Listed {len(entries)} entries under {rel_path}"
                    evidence_records.append(
                        EvidenceRecord(
                            record_id=f"bounded_evidence_{uuid.uuid4().hex[:12]}",
                            action_id=action_id,
                            decision_id=decision_id,
                            envelope_id=envelope_id,
                            actor=EXECUTION_ACTOR_BOUNDED_EXECUTOR,
                            timestamp=ts,
                            evidence_type="bounded_local_list",
                            evidence_text=summary,
                            file_path_or_note=rel_path,
                            rationale="Bounded executor workspace observation.",
                            source="bounded_executor",
                            satisfies=["local_file_observed", "workspace_scope_attested"],
                            sha256=None,
                            turn_number=turn_number,
                        )
                    )
                    executed.append(
                        {
                            "operation": name,
                            "path": rel_path,
                            "entry_count": len(entries),
                            "outcome": "executed_list",
                        }
                    )

                elif name == "read_file":
                    if not target.is_file():
                        raise BoundedExecutionError(
                            f"read_file target is not a file: {rel_path!r}",
                            diagnostic=DIAG_UNSUPPORTED_OPERATION,
                        )
                    content = target.read_bytes()
                    digest = _sha256_bytes(content)
                    summary = f"Read file {rel_path} ({len(content)} bytes)"
                    evidence_records.append(
                        EvidenceRecord(
                            record_id=f"bounded_evidence_{uuid.uuid4().hex[:12]}",
                            action_id=action_id,
                            decision_id=decision_id,
                            envelope_id=envelope_id,
                            actor=EXECUTION_ACTOR_BOUNDED_EXECUTOR,
                            timestamp=ts,
                            evidence_type="bounded_local_read",
                            evidence_text=summary,
                            file_path_or_note=rel_path,
                            rationale="Bounded executor workspace read attestation.",
                            source="bounded_executor",
                            satisfies=["local_file_observed", "workspace_scope_attested"],
                            sha256=digest,
                            turn_number=turn_number,
                        )
                    )
                    executed.append(
                        {
                            "operation": name,
                            "path": rel_path,
                            "sha256": digest,
                            "bytes": len(content),
                            "outcome": "executed_read",
                        }
                    )

                elif name == "write_file":
                    content = operation["content"]
                    try:
                        write_result = execute_bounded_write(
                            BoundedWriteRequest(
                                workspace=self.workspace,
                                relative_path=rel_path,
                                content=operation["content"],
                            )
                        )
                    except BoundedWriteError as exc:
                        raise BoundedExecutionError(str(exc), diagnostic=exc.diagnostic) from exc
                    digest = write_result.sha256
                    summary = f"Wrote file {rel_path} ({len(content)} chars)"
                    evidence_records.append(
                        EvidenceRecord(
                            record_id=f"bounded_evidence_{uuid.uuid4().hex[:12]}",
                            action_id=action_id,
                            decision_id=decision_id,
                            envelope_id=envelope_id,
                            actor=EXECUTION_ACTOR_BOUNDED_EXECUTOR,
                            timestamp=ts,
                            evidence_type="bounded_local_write",
                            evidence_text=summary,
                            file_path_or_note=rel_path,
                            rationale="Bounded executor workspace write attestation.",
                            source="bounded_executor",
                            satisfies=["local_file_written", "workspace_scope_attested"],
                            sha256=digest,
                            turn_number=turn_number,
                        )
                    )
                    executed.append(
                        {
                            "operation": name,
                            "path": rel_path,
                            "sha256": digest,
                            "prior_sha256": write_result.prior_sha256,
                            "bytes": write_result.byte_count,
                            "outcome": "executed_mutation",
                            "overwrite": write_result.overwritten,
                        }
                    )

        except BoundedExecutionError as exc:
            return BoundedExecutionResult(
                success=False,
                diagnostic=exc.diagnostic,
                message=str(exc),
                action_id=action_id,
            )

        execution_record = {
            "action_id": action_id,
            "execution_status": EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR,
            "execution_basis": {
                "decision_id": decision_id,
                "envelope_id": envelope_id,
            },
            "execution_actor": EXECUTION_ACTOR_BOUNDED_EXECUTOR,
            "execution_scope": EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY,
            "execution_timestamp": ts,
            "execution_evidence": {
                "workspace_path": str(self.workspace),
                "operations": executed,
                "notes": "Executed by Admissible bounded local executor v0 (structured file ops only).",
            },
        }
        return BoundedExecutionResult(
            success=True,
            message="Bounded local execution completed.",
            action_id=action_id,
            operations_executed=executed,
            evidence_records=evidence_records,
            execution_record=execution_record,
        )


def execute_bounded_local_action(
    *,
    workspace_path: str | Path,
    operations: list[dict[str, Any]],
    action_id: str,
    decision_id: str | None = None,
    envelope_id: str | None = None,
    turn_number: int | None = None,
) -> BoundedExecutionResult:
    """Convenience wrapper around ``BoundedLocalExecutor``."""
    executor = BoundedLocalExecutor(workspace_path)
    return executor.execute_operations(
        operations,
        action_id=action_id,
        decision_id=decision_id,
        envelope_id=envelope_id,
        turn_number=turn_number,
    )
