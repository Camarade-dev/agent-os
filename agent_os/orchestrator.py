"""Deterministic orchestrator goal intake scaffolding (no LLM or execution)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent_os.paths import GOAL_INTAKE_FILE, orchestrator_intake_path, workspace_path

INTAKE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

GOAL_INTAKE_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "raw_goal",
    "normalized_goal",
    "user_visible_summary",
    "explicit_constraints",
    "inferred_assumptions",
    "open_questions",
    "non_goals",
    "risk_flags",
    "ambiguity_level",
    "planning_readiness",
    "created_at",
    "non_authority",
)

GOAL_INTAKE_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_validate_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "generated_markdown_is_not_machine_authority",
)

_BUILD_VERB_PATTERN = re.compile(r"\b(build|create|make|develop|implement|design)\b")
_BROAD_PRODUCT_PATTERN = re.compile(
    r"\b(game|app|application|platform|website|web\s+app|service|product)\b"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def validate_intake_id(intake_id: str) -> None:
    """Reject unsafe or invalid intake identifiers."""
    if not intake_id:
        raise ValueError("intake id must not be empty")
    if intake_id != intake_id.strip():
        raise ValueError("intake id must not contain leading or trailing whitespace")
    if " " in intake_id:
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if "/" in intake_id or "\\" in intake_id or ".." in intake_id:
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if intake_id.startswith(".") or any(
        part.startswith(".") for part in re.split(r"[\\/]", intake_id)
    ):
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if Path(intake_id).is_absolute():
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if not INTAKE_ID_PATTERN.match(intake_id):
        raise ValueError(f"invalid intake id: {intake_id!r}")


def normalize_goal(raw_goal: str) -> str:
    """Collapse whitespace only; do not semantically rewrite the goal."""
    return re.sub(r"\s+", " ", raw_goal).strip()


def _is_broad_product_build_goal(normalized_goal: str) -> bool:
    lowered = normalized_goal.lower()
    if "slither.io" in lowered or "slither-like" in lowered:
        return True
    return bool(_BUILD_VERB_PATTERN.search(lowered) and _BROAD_PRODUCT_PATTERN.search(lowered))


def build_goal_intake_artifact(
    intake_id: str,
    raw_goal: str,
    *,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic GOAL_INTAKE artifact payload."""
    validate_intake_id(intake_id)
    if not raw_goal or not raw_goal.strip():
        raise ValueError("goal must not be empty or whitespace-only")

    normalized_goal = normalize_goal(raw_goal)
    high_ambiguity = _is_broad_product_build_goal(normalized_goal)
    ambiguity_level = "HIGH" if high_ambiguity else "MEDIUM"
    planning_readiness = "REQUIRES_CLARIFICATION" if high_ambiguity else "NOT_READY"
    risk_flags = []
    if high_ambiguity:
        risk_flags.append(
            {
                "risk": "broad_product_goal_without_scope_boundaries",
                "basis": "deterministic keyword guard matched broad build/product language",
                "mitigation_planning_only": "Clarify scope before drafting planning artifacts",
            }
        )

    return {
        "artifact_type": "GOAL_INTAKE",
        "schema_version": "0.1",
        "intake_id": intake_id,
        "raw_goal": raw_goal,
        "normalized_goal": normalized_goal,
        "user_visible_summary": normalized_goal,
        "explicit_constraints": [],
        "inferred_assumptions": [],
        "open_questions": [
            {
                "question": "What concrete scope, constraints, and success criteria should constrain planning?",
                "impact": "Prevents treating goal intake as an approved plan.",
                "suggested_owner_action": "Clarify before any planning draft or run proposal is created.",
                "blocks_first_slice": True,
            }
        ],
        "non_goals": [],
        "risk_flags": risk_flags,
        "ambiguity_level": ambiguity_level,
        "planning_readiness": planning_readiness,
        "created_at": created_at or _utc_now(),
        "non_authority": {key: True for key in GOAL_INTAKE_NON_AUTHORITY_FLAGS},
    }


def create_goal_intake(project: Path, intake_id: str, raw_goal: str) -> Path:
    """Create a goal intake artifact under .agent-os/orchestrator/intakes/<id>/."""
    artifact = build_goal_intake_artifact(intake_id, raw_goal)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    dest = orchestrator_intake_path(project, intake_id) / GOAL_INTAKE_FILE
    if dest.exists():
        raise FileExistsError(f"goal intake artifact already exists: {intake_id}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)
    return dest
