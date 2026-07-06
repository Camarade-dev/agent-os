"""Deterministic orchestrator goal intake scaffolding (no LLM or execution)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_os.paths import (
    CLARIFICATIONS_DIR,
    GOAL_INTAKE_FILE,
    orchestrator_clarification_path,
    orchestrator_intake_path,
    workspace_path,
)

INTAKE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
CLARIFICATION_ID_PATTERN = INTAKE_ID_PATTERN

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

OWNER_CLARIFICATION_ARTIFACT_TYPE = "OWNER_CLARIFICATION"
OWNER_CLARIFICATION_SCHEMA_VERSION = "0.1"

OWNER_CLARIFICATION_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "clarification_id",
    "owner_answer",
    "applies_to_open_questions",
    "explicit_constraints_added",
    "non_goals_added",
    "risk_notes",
    "created_at",
    "non_authority",
)

OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_validate_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_mark_intake_draft_ready",
    "does_not_modify_goal_intake",
)

READINESS_REVIEW_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_generate_planning_draft",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_mark_intake_draft_ready",
    "requires_future_owner_readiness_decision",
)

FORBIDDEN_READINESS_REVIEW_STATES = frozenset({"DRAFT_ALLOWED", "READY_FOR_DRAFT"})

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


def validate_clarification_id(clarification_id: str) -> None:
    """Reject unsafe or invalid clarification identifiers."""
    if not clarification_id:
        raise ValueError("clarification id must not be empty")
    if clarification_id != clarification_id.strip():
        raise ValueError(
            "clarification id must not contain leading or trailing whitespace"
        )
    if " " in clarification_id:
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if "/" in clarification_id or "\\" in clarification_id or ".." in clarification_id:
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if clarification_id.startswith(".") or any(
        part.startswith(".") for part in re.split(r"[\\/]", clarification_id)
    ):
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if Path(clarification_id).is_absolute():
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if not CLARIFICATION_ID_PATTERN.match(clarification_id):
        raise ValueError(f"invalid clarification id: {clarification_id!r}")


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


def _require_valid_goal_intake(project: Path, intake_id: str) -> tuple[Path, dict]:
    """Load a GOAL_INTAKE artifact and fail closed when structurally invalid."""
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

    errors = _validate_goal_intake_payload(artifact, intake_id, raw_text=raw_text)
    if errors:
        raise ValueError(
            f"invalid goal intake artifact for {intake_id}: " + "; ".join(errors)
        )

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: expected object"
        )

    return path, artifact


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
    clarifications: tuple[OwnerClarificationRecord, ...] = (),
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
        f"owner_clarifications: {len(clarifications)}",
    ]
    if clarifications:
        latest = clarifications[-1]
        lines.append(f"latest_clarification_id: {latest.clarification_id}")
        lines.append(f"latest_clarification_created_at: {latest.created_at}")
    lines.append(f"validation: {'OK' if not validation_errors else 'INVALID'}")
    for error in validation_errors:
        lines.append(f"  - {error}")
    lines.append("next step: no planning draft was created")
    lines.append(
        "note: owner clarifications are additive context only; "
        "they do not create a planning draft and do not change planning_readiness"
    )
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
    clarifications = list_owner_clarifications(project, intake_id)
    output = _format_goal_intake_status(
        path,
        artifact,
        validation_errors,
        clarifications,
    )
    return GoalIntakeStatusReport(output, not validation_errors)


@dataclass(frozen=True)
class OwnerClarificationRecord:
    clarification_id: str
    created_at: str
    path: Path


@dataclass(frozen=True)
class OwnerClarificationValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


def build_owner_clarification_artifact(
    intake_id: str,
    clarification_id: str,
    owner_answer: str,
    *,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic OWNER_CLARIFICATION artifact payload."""
    validate_intake_id(intake_id)
    validate_clarification_id(clarification_id)
    if not owner_answer or not owner_answer.strip():
        raise ValueError("clarification answer must not be empty or whitespace-only")

    return {
        "artifact_type": OWNER_CLARIFICATION_ARTIFACT_TYPE,
        "schema_version": OWNER_CLARIFICATION_SCHEMA_VERSION,
        "intake_id": intake_id,
        "clarification_id": clarification_id,
        "owner_answer": owner_answer,
        "applies_to_open_questions": [],
        "explicit_constraints_added": [],
        "non_goals_added": [],
        "risk_notes": [],
        "created_at": created_at or _utc_now(),
        "non_authority": {
            key: True for key in OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS
        },
    }


def _validate_owner_clarification_payload(
    artifact: object,
    intake_id: str,
    clarification_id: str,
) -> list[str]:
    """Return structural validation errors for a loaded OWNER_CLARIFICATION payload."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["owner clarification artifact must be a JSON object"]

    for field in OWNER_CLARIFICATION_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    artifact_type = artifact.get("artifact_type")
    if artifact_type is not None and artifact_type != OWNER_CLARIFICATION_ARTIFACT_TYPE:
        errors.append(
            f"wrong artifact_type: expected {OWNER_CLARIFICATION_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if schema_version is not None and schema_version != OWNER_CLARIFICATION_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version: expected "
            f"{OWNER_CLARIFICATION_SCHEMA_VERSION!r}, found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    artifact_clarification_id = artifact.get("clarification_id")
    if (
        isinstance(artifact_clarification_id, str)
        and artifact_clarification_id != clarification_id
    ):
        errors.append(
            "clarification_id mismatch: "
            f"path {clarification_id!r}, artifact {artifact_clarification_id!r}"
        )

    owner_answer = artifact.get("owner_answer")
    if owner_answer is not None:
        error = _non_empty_string(owner_answer, "owner_answer")
        if error:
            errors.append(error)

    for field in (
        "applies_to_open_questions",
        "explicit_constraints_added",
        "non_goals_added",
        "risk_notes",
    ):
        if field in artifact and not isinstance(artifact[field], list):
            errors.append(f"{field} must be a list")

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    return errors


def create_owner_clarification(
    project: Path,
    intake_id: str,
    clarification_id: str,
    owner_answer: str,
) -> Path:
    """Create an OWNER_CLARIFICATION artifact without modifying goal-intake.json."""
    artifact = build_owner_clarification_artifact(
        intake_id,
        clarification_id,
        owner_answer,
    )
    _require_valid_goal_intake(project, intake_id)

    dest = orchestrator_clarification_path(project, intake_id, clarification_id)
    if dest.exists():
        raise FileExistsError(
            f"owner clarification artifact already exists: {clarification_id}"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)
    return dest


def load_owner_clarification(
    project: Path,
    intake_id: str,
    clarification_id: str,
) -> dict:
    """Load an OWNER_CLARIFICATION artifact from disk (read-only)."""
    validate_intake_id(intake_id)
    validate_clarification_id(clarification_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_clarification_path(project, intake_id, clarification_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner clarification artifact not found: {clarification_id}"
        )

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid clarification artifact for {clarification_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid clarification artifact for {clarification_id}: expected object"
        )

    return artifact


def list_owner_clarifications(
    project: Path,
    intake_id: str,
) -> tuple[OwnerClarificationRecord, ...]:
    """List owner clarification records for an intake (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    clarifications_dir = orchestrator_intake_path(project, intake_id) / CLARIFICATIONS_DIR
    if not clarifications_dir.is_dir():
        return ()

    records: list[OwnerClarificationRecord] = []
    for path in sorted(clarifications_dir.glob("*.json")):
        clarification_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(artifact, dict):
            continue
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = ""
        records.append(
            OwnerClarificationRecord(
                clarification_id=clarification_id,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.clarification_id))
    return tuple(records)


def validate_owner_clarification(
    project: Path,
    intake_id: str,
    clarification_id: str,
) -> OwnerClarificationValidationReport:
    """Strict read-only structural validation of an OWNER_CLARIFICATION artifact."""
    validate_intake_id(intake_id)
    validate_clarification_id(clarification_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_clarification_path(project, intake_id, clarification_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner clarification artifact not found: {clarification_id}"
        )

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_owner_clarification_payload(
            artifact,
            intake_id,
            clarification_id,
        )

    lines = [
        f"owner clarification artifact: {path}",
        f"intake_id: {intake_id}",
        f"clarification_id: {clarification_id}",
        f"structural validation: {'OK' if not errors else 'INVALID'}",
    ]
    for error in errors:
        lines.append(f"  - {error}")
    lines.append(f"final validation result: {'OK' if not errors else 'INVALID'}")
    if not errors:
        lines.append(
            "note: clarification is owner-provided context only; "
            "not approval, not planning generation, and goal-intake.json was not modified"
        )

    output = "\n".join(lines)
    return OwnerClarificationValidationReport(output, not errors, tuple(errors))


def _validate_clarifications_for_readiness(
    project: Path,
    intake_id: str,
) -> tuple[tuple[OwnerClarificationRecord, ...], list[str]]:
    """Validate clarification artifacts for readiness review (read-only)."""
    clarifications_dir = orchestrator_intake_path(project, intake_id) / CLARIFICATIONS_DIR
    if not clarifications_dir.is_dir():
        return (), []

    records: list[OwnerClarificationRecord] = []
    errors: list[str] = []

    for path in sorted(clarifications_dir.glob("*.json")):
        clarification_id = path.stem
        raw_text = path.read_text(encoding="utf-8")
        try:
            artifact = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            errors.append(
                f"invalid clarification artifact {clarification_id}: malformed JSON: {exc.msg}"
            )
            continue

        payload_errors = _validate_owner_clarification_payload(
            artifact,
            intake_id,
            clarification_id,
        )
        if payload_errors:
            for error in payload_errors:
                errors.append(
                    f"invalid clarification artifact {clarification_id}: {error}"
                )
            continue

        created_at = artifact.get("created_at") if isinstance(artifact, dict) else ""
        if not isinstance(created_at, str):
            created_at = ""
        records.append(
            OwnerClarificationRecord(
                clarification_id=clarification_id,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.clarification_id))
    return tuple(records), errors


def _determine_readiness_review(
    *,
    validation_errors: list[str],
    artifact: dict | None,
    clarifications: tuple[OwnerClarificationRecord, ...],
    clarification_errors: list[str],
) -> tuple[str, str, list[str]]:
    """Return readiness_review_state, next_required_action, blocking_reasons."""
    blocking: list[str] = list(validation_errors)
    if validation_errors:
        return "BLOCKED_INVALID_INTAKE", "FIX_GOAL_INTAKE_STRUCTURE", blocking

    blocking.extend(clarification_errors)
    if clarification_errors:
        return "BLOCKED_INVALID_INTAKE", "FIX_CLARIFICATION_STRUCTURE", blocking

    if artifact is None:
        return "BLOCKED_INVALID_INTAKE", "FIX_GOAL_INTAKE_STRUCTURE", blocking

    ambiguity_level = artifact.get("ambiguity_level")
    planning_readiness = artifact.get("planning_readiness")
    clarification_count = len(clarifications)

    if (
        ambiguity_level == "HIGH"
        and planning_readiness == "REQUIRES_CLARIFICATION"
    ):
        if clarification_count == 0:
            return "BLOCKED_REQUIRES_CLARIFICATION", "ADD_OWNER_CLARIFICATION", blocking
        return (
            "OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED",
            "OWNER_READINESS_DECISION_REQUIRED",
            blocking,
        )

    return "OWNER_REVIEW_REQUIRED", "OWNER_READINESS_DECISION_REQUIRED", blocking


def _format_goal_intake_readiness(
    path: Path,
    intake_id: str,
    *,
    goal_intake_valid: bool,
    artifact: dict | None,
    clarifications: tuple[OwnerClarificationRecord, ...],
    readiness_review_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
) -> str:
    ambiguity_level = (
        artifact.get("ambiguity_level", "?") if artifact is not None else "?"
    )
    planning_readiness = (
        artifact.get("planning_readiness", "?") if artifact is not None else "?"
    )
    latest_clarification_id = (
        clarifications[-1].clarification_id if clarifications else None
    )

    lines = [
        f"goal intake readiness review: {path}",
        f"intake_id: {intake_id}",
        f"goal_intake_valid: {'yes' if goal_intake_valid else 'no'}",
        f"ambiguity_level: {ambiguity_level}",
        f"planning_readiness: {planning_readiness}",
        f"owner_clarification_count: {len(clarifications)}",
    ]
    if latest_clarification_id is not None:
        lines.append(f"latest_clarification_id: {latest_clarification_id}")
    lines.append(f"readiness_review_state: {readiness_review_state}")
    lines.append(f"next_required_action: {next_required_action}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in READINESS_REVIEW_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: readiness review is read-only; not owner readiness decision, "
        "not approval, not planning generation, and no files were modified"
    )
    lines.append(
        "note: owner clarifications do not automatically make an intake draft-ready"
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class GoalIntakeReadinessReport:
    output: str
    intake_id: str
    goal_intake_valid: bool
    ambiguity_level: str | None
    planning_readiness: str | None
    owner_clarification_count: int
    latest_clarification_id: str | None
    readiness_review_state: str
    next_required_action: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def review_goal_intake_readiness(
    project: Path,
    intake_id: str,
) -> GoalIntakeReadinessReport:
    """Read-only readiness review for a GOAL_INTAKE and its clarifications."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    validation_errors: list[str] = []
    artifact: dict | None = None
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        validation_errors = [f"malformed JSON: {exc.msg}"]
    else:
        validation_errors = _validate_goal_intake_payload(
            loaded,
            intake_id,
            raw_text=raw_text,
        )
        if isinstance(loaded, dict):
            artifact = loaded
        else:
            validation_errors.append("goal intake artifact must be a JSON object")

    clarifications, clarification_errors = _validate_clarifications_for_readiness(
        project,
        intake_id,
    )
    readiness_review_state, next_required_action, blocking_reasons = (
        _determine_readiness_review(
            validation_errors=validation_errors,
            artifact=artifact,
            clarifications=clarifications,
            clarification_errors=clarification_errors,
        )
    )

    if readiness_review_state in FORBIDDEN_READINESS_REVIEW_STATES:
        raise ValueError(
            f"forbidden readiness review state: {readiness_review_state}"
        )

    goal_intake_valid = not validation_errors
    ambiguity_level = (
        artifact.get("ambiguity_level") if artifact is not None else None
    )
    planning_readiness = (
        artifact.get("planning_readiness") if artifact is not None else None
    )
    latest_clarification_id = (
        clarifications[-1].clarification_id if clarifications else None
    )
    non_authority = {key: True for key in READINESS_REVIEW_NON_AUTHORITY_FLAGS}

    output = _format_goal_intake_readiness(
        path,
        intake_id,
        goal_intake_valid=goal_intake_valid,
        artifact=artifact,
        clarifications=clarifications,
        readiness_review_state=readiness_review_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
    )
    return GoalIntakeReadinessReport(
        output=output,
        intake_id=intake_id,
        goal_intake_valid=goal_intake_valid,
        ambiguity_level=ambiguity_level,
        planning_readiness=planning_readiness,
        owner_clarification_count=len(clarifications),
        latest_clarification_id=latest_clarification_id,
        readiness_review_state=readiness_review_state,
        next_required_action=next_required_action,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


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
