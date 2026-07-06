"""Deterministic orchestrator goal intake scaffolding (no LLM or execution)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
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

GOAL_INTAKE_ARTIFACT_TYPE = "GOAL_INTAKE"
GOAL_INTAKE_SCHEMA_VERSION = "0.1"

GOAL_INTAKE_AMBIGUITY_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH"})
GOAL_INTAKE_PLANNING_READINESS = frozenset(
    {"NOT_READY", "DRAFT_ALLOWED", "REQUIRES_CLARIFICATION"}
)

GOAL_INTAKE_REQUIRED_STRING_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "raw_goal",
    "normalized_goal",
    "user_visible_summary",
    "created_at",
)

GOAL_INTAKE_REQUIRED_LIST_FIELDS = (
    "explicit_constraints",
    "inferred_assumptions",
    "open_questions",
    "non_goals",
    "risk_flags",
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


def _goal_intake_artifact_path(project: Path, intake_id: str) -> Path:
    return orchestrator_intake_path(project, intake_id) / GOAL_INTAKE_FILE


def _parse_created_at(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _non_empty_string(value: object, field_name: str) -> str | None:
    if not isinstance(value, str):
        return f"{field_name} must be a non-empty string"
    if not value.strip():
        return f"{field_name} must be a non-empty string"
    return None


def _validate_goal_intake_payload(
    artifact: object,
    intake_id: str,
    *,
    raw_text: str | None = None,
) -> list[str]:
    """Return structural validation errors for a loaded GOAL_INTAKE payload."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["goal intake artifact must be a JSON object"]

    for field in GOAL_INTAKE_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    for field in GOAL_INTAKE_REQUIRED_STRING_FIELDS:
        if field in artifact:
            error = _non_empty_string(artifact[field], field)
            if error:
                errors.append(error)

    for field in GOAL_INTAKE_REQUIRED_LIST_FIELDS:
        if field in artifact and not isinstance(artifact[field], list):
            errors.append(f"{field} must be a list")

    artifact_type = artifact.get("artifact_type")
    if artifact_type is not None and artifact_type != GOAL_INTAKE_ARTIFACT_TYPE:
        errors.append(
            f"wrong artifact_type: expected {GOAL_INTAKE_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if schema_version is not None and schema_version != GOAL_INTAKE_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version: expected {GOAL_INTAKE_SCHEMA_VERSION!r}, "
            f"found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in GOAL_INTAKE_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    ambiguity_level = artifact.get("ambiguity_level")
    if ambiguity_level is not None and ambiguity_level not in GOAL_INTAKE_AMBIGUITY_LEVELS:
        errors.append(f"invalid ambiguity_level: {ambiguity_level!r}")

    planning_readiness = artifact.get("planning_readiness")
    if (
        planning_readiness is not None
        and planning_readiness not in GOAL_INTAKE_PLANNING_READINESS
    ):
        errors.append(f"invalid planning_readiness: {planning_readiness!r}")

    if ambiguity_level == "HIGH":
        if planning_readiness == "DRAFT_ALLOWED":
            errors.append(
                "incoherent readiness: HIGH ambiguity must not be DRAFT_ALLOWED"
            )
        elif planning_readiness != "REQUIRES_CLARIFICATION":
            errors.append(
                "incoherent readiness: HIGH ambiguity should be REQUIRES_CLARIFICATION"
            )

    content = raw_text if raw_text is not None else json.dumps(artifact)
    if "PLANNING_RUN_SLICE" in content:
        errors.append("goal intake content must not contain PLANNING_RUN_SLICE")

    return errors


def load_goal_intake(project: Path, intake_id: str) -> dict:
    """Load a GOAL_INTAKE artifact from disk (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: expected object"
        )

    return artifact


@dataclass(frozen=True)
class GoalIntakeValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class GoalIntakeStatusReport:
    output: str
    validation_ok: bool


def _format_goal_intake_validation(
    path: Path,
    intake_id: str,
    errors: list[str],
) -> str:
    lines = [
        f"goal intake artifact: {path}",
        f"intake_id: {intake_id}",
        f"structural validation: {'OK' if not errors else 'INVALID'}",
    ]
    for error in errors:
        lines.append(f"  - {error}")
    lines.append(f"final validation result: {'OK' if not errors else 'INVALID'}")
    if not errors:
        lines.append(
            "note: validation is not approval, not planning generation, "
            "and no files were modified"
        )
    return "\n".join(lines)


def validate_goal_intake(project: Path, intake_id: str) -> GoalIntakeValidationReport:
    """Strict read-only structural validation of a GOAL_INTAKE artifact."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_goal_intake_payload(artifact, intake_id, raw_text=raw_text)

    output = _format_goal_intake_validation(path, intake_id, errors)
    return GoalIntakeValidationReport(output, not errors, tuple(errors))


def _format_goal_intake_status(
    path: Path,
    artifact: dict,
    validation_errors: list[str],
) -> str:
    goal_text = artifact.get("normalized_goal") or artifact.get("raw_goal") or "?"
    open_questions = artifact.get("open_questions")
    risk_flags = artifact.get("risk_flags")
    open_count = len(open_questions) if isinstance(open_questions, list) else "?"
    risk_count = len(risk_flags) if isinstance(risk_flags, list) else "?"

    lines = [
        f"goal intake artifact: {path}",
        f"intake_id: {artifact.get('intake_id', '?')}",
        f"artifact_type: {artifact.get('artifact_type', '?')}",
        f"schema_version: {artifact.get('schema_version', '?')}",
        f"goal: {goal_text}",
        f"ambiguity_level: {artifact.get('ambiguity_level', '?')}",
        f"planning_readiness: {artifact.get('planning_readiness', '?')}",
        f"open_questions: {open_count}",
        f"risk_flags: {risk_count}",
        f"validation: {'OK' if not validation_errors else 'INVALID'}",
    ]
    for error in validation_errors:
        lines.append(f"  - {error}")
    lines.append("next step: no planning draft was created")
    lines.append(
        "note: read-only inspection; validation is not approval or planning generation"
    )
    return "\n".join(lines)


def goal_intake_status(project: Path, intake_id: str) -> GoalIntakeStatusReport:
    """Inspect an existing GOAL_INTAKE artifact (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: expected object"
        )

    validation_errors = _validate_goal_intake_payload(
        artifact,
        intake_id,
        raw_text=raw_text,
    )
    output = _format_goal_intake_status(path, artifact, validation_errors)
    return GoalIntakeStatusReport(output, not validation_errors)


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
