"""High-autonomy policy v0 — decides what the governed loop may auto-execute.

Hard gates only: admission labels and content guards are never weakened.
Auto-execution applies only when high-autonomy mode is explicitly active.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from admissible.execution.bounded_local_executor import (
    assess_bounded_execution_eligibility,
    validate_workspace_path,
)

# Per-turn cap on auto-executed actions (safety bound).
DEFAULT_MAX_AUTO_EXECUTIONS_PER_TURN = 8

HUMAN_CRITICAL_ACTION_TYPES = frozenset(
    {
        "run_shell_command",
        "run_command",
        "execute_command",
        "access_secret",
        "access_env",
        "publish",
        "git_push",
        "git_commit",
    }
)

RECOVERABLE_BLOCKED_ACTION_TYPES = frozenset(
    {
        "install_dependency",
        "deploy_code",
        "prepare_deploy",
    }
)

FORBIDDEN_AUTO_EXECUTE_DECISIONS = frozenset(
    {"REFUSE", "REQUIRE_HUMAN_APPROVAL", "REQUEST_MORE_EVIDENCE", "ALLOW_WITH_LIMITS"}
)


@dataclass(frozen=True)
class HighAutonomyActionClassification:
    """Policy outcome for one queue item under high-autonomy."""

    action_id: str
    category: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "category": self.category,
            "reason": self.reason,
        }


class HighAutonomyPolicy:
    """Decides auto-executable vs human-critical vs recoverable-blocker actions."""

    def __init__(
        self,
        *,
        max_auto_executions_per_turn: int = DEFAULT_MAX_AUTO_EXECUTIONS_PER_TURN,
    ) -> None:
        self.max_auto_executions_per_turn = max_auto_executions_per_turn

    def classify_action(
        self,
        *,
        item: Any,
        envelope: Any | None,
        workspace_path: str | None,
    ) -> HighAutonomyActionClassification:
        action_id = getattr(item, "action_id", None) or (
            item.get("action_id") if isinstance(item, dict) else ""
        )
        decision = getattr(item, "decision", None) or (
            item.get("decision") if isinstance(item, dict) else ""
        )
        action_type = getattr(item, "action_type", None) or (
            item.get("action_type") if isinstance(item, dict) else ""
        )
        tool_or_command = (
            getattr(item, "tool_or_command", None)
            or (item.get("tool_or_command") if isinstance(item, dict) else "")
            or ""
        )

        candidate = getattr(envelope, "candidate", {}) if envelope is not None else {}
        if isinstance(candidate, dict) and candidate.get("requires_safe_overwrite_review"):
            return HighAutonomyActionClassification(
                action_id=str(action_id),
                category="human_critical",
                reason=(
                    "The write targets a file that predates this governed run or whose "
                    "current sha256 is not covered by latest execution evidence."
                ),
            )

        if action_type in HUMAN_CRITICAL_ACTION_TYPES:
            return HighAutonomyActionClassification(
                action_id=str(action_id),
                category="human_critical",
                reason=f"Action type {action_type!r} requires explicit human authority.",
            )

        tool_lower = str(tool_or_command).lower()
        for forbidden in ("npm ", "npm install", "pip install", "yarn ", "deploy", "curl ", "wget ", "shell"):
            if forbidden in tool_lower:
                if action_type in RECOVERABLE_BLOCKED_ACTION_TYPES or decision in (
                    "REQUEST_MORE_EVIDENCE",
                    "REQUIRE_HUMAN_APPROVAL",
                ):
                    return HighAutonomyActionClassification(
                        action_id=str(action_id),
                        category="recoverable_blocker",
                        reason=(
                            f"Blocked proposal ({action_type or 'unknown'}) may be recovered "
                            "with a local-only alternative; not auto-executable."
                        ),
                    )
                return HighAutonomyActionClassification(
                    action_id=str(action_id),
                    category="human_critical",
                    reason=f"Forbidden capability in proposal: {forbidden.strip()}.",
                )

        if decision in FORBIDDEN_AUTO_EXECUTE_DECISIONS:
            if action_type in RECOVERABLE_BLOCKED_ACTION_TYPES:
                return HighAutonomyActionClassification(
                    action_id=str(action_id),
                    category="recoverable_blocker",
                    reason=(
                        f"Admission decision {decision!r} on {action_type!r} is recoverable "
                        "via local-only continuation."
                    ),
                )
            if decision == "REQUIRE_HUMAN_APPROVAL":
                return HighAutonomyActionClassification(
                    action_id=str(action_id),
                    category="human_critical",
                    reason="REQUIRE_HUMAN_APPROVAL cannot be auto-approved in high-autonomy v0.",
                )
            return HighAutonomyActionClassification(
                action_id=str(action_id),
                category="blocked_not_completed",
                reason=f"Admission decision {decision!r}; not auto-executable.",
            )

        assessment = assess_bounded_execution_eligibility(item=item, envelope=envelope, body={})
        if not assessment["eligible"]:
            return HighAutonomyActionClassification(
                action_id=str(action_id),
                category="blocked_not_completed",
                reason=assessment.get("message") or "Not eligible for bounded local execution.",
            )

        if workspace_path:
            try:
                workspace = validate_workspace_path(workspace_path)
            except Exception:
                return HighAutonomyActionClassification(
                    action_id=str(action_id),
                    category="human_critical",
                    reason="No valid workspace configured for auto-execution.",
                )
            for op in assessment.get("operations") or []:
                rel_path = str(op.get("path") or "")
                if rel_path.startswith("/") or ".." in rel_path.split("/"):
                    return HighAutonomyActionClassification(
                        action_id=str(action_id),
                        category="human_critical",
                        reason=f"Path {rel_path!r} is outside the configured workspace.",
                    )
                resolved = (workspace / rel_path).resolve()
                if not str(resolved).startswith(str(workspace.resolve())):
                    return HighAutonomyActionClassification(
                        action_id=str(action_id),
                        category="human_critical",
                        reason=f"Path {rel_path!r} resolves outside workspace.",
                    )

        return HighAutonomyActionClassification(
            action_id=str(action_id),
            category="auto_executable",
            reason="Admitted ALLOW local file operation inside configured workspace.",
        )

    def is_auto_executable(
        self,
        *,
        item: Any,
        envelope: Any | None,
        workspace_path: str | None,
    ) -> bool:
        return (
            self.classify_action(item=item, envelope=envelope, workspace_path=workspace_path).category
            == "auto_executable"
        )

    def is_human_critical(
        self,
        *,
        item: Any,
        envelope: Any | None,
        workspace_path: str | None,
    ) -> bool:
        return (
            self.classify_action(item=item, envelope=envelope, workspace_path=workspace_path).category
            == "human_critical"
        )

    def is_recoverable_blocker(
        self,
        *,
        item: Any,
        envelope: Any | None,
        workspace_path: str | None,
    ) -> bool:
        return (
            self.classify_action(item=item, envelope=envelope, workspace_path=workspace_path).category
            == "recoverable_blocker"
        )

    def should_run_verification(
        self,
        *,
        evidence_count: int,
        verification_readiness: str,
        ready_to_execute_local_count: int,
        awaiting_next_instruction: bool = False,
        has_recoverable_blockers: bool = False,
    ) -> bool:
        """Verification is a safe controller step when writes exist and nothing is pending."""
        del has_recoverable_blockers
        if awaiting_next_instruction:
            return False
        if evidence_count <= 0:
            return False
        if ready_to_execute_local_count > 0:
            return False
        if verification_readiness in ("pass", "fail"):
            return False
        return True
