"""Deterministic orchestrator goal intake scaffolding (no LLM or execution)."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_os.paths import (
    CLARIFICATIONS_DIR,
    GOAL_INTAKE_FILE,
    ORCHESTRATOR_CONTEXT_TRANSPORT_FILE,
    ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE,
    ORCHESTRATOR_DRAFT_SCAFFOLD_NOTES_FILE,
    ORCHESTRATOR_PROVENANCE_FILE,
    READINESS_DECISIONS_DIR,
    orchestrator_clarification_path,
    orchestrator_intake_path,
    orchestrator_readiness_decision_path,
    planning_path,
    workspace_path,
)
from agent_os.planning import init_planning_workspace, validate_plan_id

INTAKE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
CLARIFICATION_ID_PATTERN = INTAKE_ID_PATTERN
READINESS_DECISION_ID_PATTERN = INTAKE_ID_PATTERN

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

OWNER_READINESS_DECISION_ARTIFACT_TYPE = "OWNER_READINESS_DECISION"
OWNER_READINESS_DECISION_SCHEMA_VERSION = "0.1"

OWNER_READINESS_DECISION_VALUES = frozenset(
    {
        "REQUEST_MORE_CLARIFICATION",
        "BLOCK_INTAKE",
        "AUTHORIZE_DRAFT_PREPARATION",
    }
)

AUTHORIZE_DRAFT_PREPARATION_ALLOWED_STATES = frozenset(
    {
        "OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED",
        "OWNER_REVIEW_REQUIRED",
    }
)

AUTHORIZE_DRAFT_PREPARATION_FORBIDDEN_STATES = frozenset(
    {
        "BLOCKED_INVALID_INTAKE",
        "BLOCKED_REQUIRES_CLARIFICATION",
    }
)

OWNER_READINESS_DECISION_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "decision_id",
    "decision",
    "owner_summary",
    "readiness_review_state_at_decision",
    "next_required_action_at_decision",
    "owner_clarification_count_at_decision",
    "latest_clarification_id_at_decision",
    "created_at",
    "non_authority",
)

OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_generate_planning_draft",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_approve_architecture",
    "does_not_modify_goal_intake",
    "does_not_modify_clarifications",
    "authorizes_future_draft_preparation_only_when_decision_is_authorize",
)

DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_generate_planning_draft",
    "does_not_create_planning_workspace",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_approve_architecture",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_modify_goal_intake",
    "does_not_modify_clarifications",
    "does_not_modify_readiness_decisions",
    "requires_separate_future_draft_preparation_command",
    "requires_future_independent_validation_before_plan_approval",
    "requires_future_owner_approval_before_run_proposals",
)

FORBIDDEN_DRAFT_PREPARATION_PREFLIGHT_STATES = frozenset(
    {"DRAFT_ALLOWED", "READY_FOR_DRAFT"}
)

DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE = (
    "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED"
)
DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_NEXT_ACTION = (
    "FUTURE_DRAFT_PREPARATION_STEP_REQUIRES_SEPARATE_COMMAND"
)

ORCHESTRATOR_PLANNING_DRAFT_SOURCE_ARTIFACT_TYPE = "ORCHESTRATOR_PLANNING_DRAFT_SOURCE"
ORCHESTRATOR_PLANNING_DRAFT_SOURCE_SCHEMA_VERSION = "0.1"

ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS = (
    "does_not_generate_architecture",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "generated_workspace_is_draft_only",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

ORCHESTRATOR_CONTEXT_TRANSPORT_ARTIFACT_TYPE = "ORCHESTRATOR_CONTEXT_TRANSPORT"
ORCHESTRATOR_CONTEXT_TRANSPORT_SCHEMA_VERSION = "0.1"

ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS = (
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "transported_context_is_source_material_only",
    "requires_future_architecture_decision",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
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


def validate_readiness_decision_id(decision_id: str) -> None:
    """Reject unsafe or invalid readiness decision identifiers."""
    if not decision_id:
        raise ValueError("decision id must not be empty")
    if decision_id != decision_id.strip():
        raise ValueError(
            "decision id must not contain leading or trailing whitespace"
        )
    if " " in decision_id:
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if "/" in decision_id or "\\" in decision_id or ".." in decision_id:
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if decision_id.startswith(".") or any(
        part.startswith(".") for part in re.split(r"[\\/]", decision_id)
    ):
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if Path(decision_id).is_absolute():
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if not READINESS_DECISION_ID_PATTERN.match(decision_id):
        raise ValueError(f"invalid decision id: {decision_id!r}")


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
    readiness_decisions: tuple[OwnerReadinessDecisionRecord, ...] = (),
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
    lines.append(f"owner_readiness_decisions: {len(readiness_decisions)}")
    if readiness_decisions:
        latest_decision = readiness_decisions[-1]
        lines.append(f"latest_readiness_decision_id: {latest_decision.decision_id}")
        lines.append(f"latest_readiness_decision: {latest_decision.decision}")
    lines.append(f"validation: {'OK' if not validation_errors else 'INVALID'}")
    for error in validation_errors:
        lines.append(f"  - {error}")
    lines.append("next step: no planning draft was created")
    lines.append(
        "note: owner clarifications are additive context only; "
        "they do not create a planning draft and do not change planning_readiness"
    )
    lines.append(
        "note: owner readiness decisions are owner-provided records only; "
        "they do not generate a planning draft"
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
    readiness_decisions = list_owner_readiness_decisions(project, intake_id)
    output = _format_goal_intake_status(
        path,
        artifact,
        validation_errors,
        clarifications,
        readiness_decisions,
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
    readiness_decisions: tuple[OwnerReadinessDecisionRecord, ...],
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
    lines.append(f"owner_readiness_decision_count: {len(readiness_decisions)}")
    if readiness_decisions:
        latest_decision = readiness_decisions[-1]
        lines.append(f"latest_readiness_decision_id: {latest_decision.decision_id}")
        lines.append(f"latest_readiness_decision: {latest_decision.decision}")
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
    lines.append(
        "note: owner readiness decisions do not generate a planning draft"
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
    readiness_decisions = list_owner_readiness_decisions(project, intake_id)
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
        readiness_decisions=readiness_decisions,
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


def _validate_readiness_decision_allowed(
    decision: str,
    readiness_report: GoalIntakeReadinessReport,
) -> None:
    """Enforce decision gating from the current readiness review snapshot."""
    if decision not in OWNER_READINESS_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")

    if not readiness_report.goal_intake_valid:
        raise ValueError("decision requires a valid goal intake artifact")

    state = readiness_report.readiness_review_state
    if decision == "AUTHORIZE_DRAFT_PREPARATION":
        if state in AUTHORIZE_DRAFT_PREPARATION_FORBIDDEN_STATES:
            raise ValueError(
                f"AUTHORIZE_DRAFT_PREPARATION is not allowed when "
                f"readiness_review_state is {state!r}"
            )
        if state not in AUTHORIZE_DRAFT_PREPARATION_ALLOWED_STATES:
            raise ValueError(
                f"AUTHORIZE_DRAFT_PREPARATION is not allowed when "
                f"readiness_review_state is {state!r}"
            )


@dataclass(frozen=True)
class OwnerReadinessDecisionRecord:
    decision_id: str
    decision: str
    created_at: str
    path: Path


@dataclass(frozen=True)
class OwnerReadinessDecisionValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


def build_owner_readiness_decision_artifact(
    intake_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
    *,
    readiness_review_state_at_decision: str,
    next_required_action_at_decision: str,
    owner_clarification_count_at_decision: int,
    latest_clarification_id_at_decision: str | None,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic OWNER_READINESS_DECISION artifact payload."""
    validate_intake_id(intake_id)
    validate_readiness_decision_id(decision_id)
    if decision not in OWNER_READINESS_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    return {
        "artifact_type": OWNER_READINESS_DECISION_ARTIFACT_TYPE,
        "schema_version": OWNER_READINESS_DECISION_SCHEMA_VERSION,
        "intake_id": intake_id,
        "decision_id": decision_id,
        "decision": decision,
        "owner_summary": owner_summary,
        "readiness_review_state_at_decision": readiness_review_state_at_decision,
        "next_required_action_at_decision": next_required_action_at_decision,
        "owner_clarification_count_at_decision": owner_clarification_count_at_decision,
        "latest_clarification_id_at_decision": latest_clarification_id_at_decision,
        "created_at": created_at or _utc_now(),
        "non_authority": {
            key: True for key in OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS
        },
    }


def _validate_owner_readiness_decision_payload(
    artifact: object,
    intake_id: str,
    decision_id: str,
) -> list[str]:
    """Return structural validation errors for OWNER_READINESS_DECISION payload."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["owner readiness decision artifact must be a JSON object"]

    for field in OWNER_READINESS_DECISION_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    artifact_type = artifact.get("artifact_type")
    if (
        artifact_type is not None
        and artifact_type != OWNER_READINESS_DECISION_ARTIFACT_TYPE
    ):
        errors.append(
            f"wrong artifact_type: expected {OWNER_READINESS_DECISION_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if (
        schema_version is not None
        and schema_version != OWNER_READINESS_DECISION_SCHEMA_VERSION
    ):
        errors.append(
            f"unsupported schema_version: expected "
            f"{OWNER_READINESS_DECISION_SCHEMA_VERSION!r}, found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    artifact_decision_id = artifact.get("decision_id")
    if isinstance(artifact_decision_id, str) and artifact_decision_id != decision_id:
        errors.append(
            "decision_id mismatch: "
            f"path {decision_id!r}, artifact {artifact_decision_id!r}"
        )

    decision = artifact.get("decision")
    if decision is not None and decision not in OWNER_READINESS_DECISION_VALUES:
        errors.append(f"invalid decision value: {decision!r}")

    owner_summary = artifact.get("owner_summary")
    if owner_summary is not None:
        error = _non_empty_string(owner_summary, "owner_summary")
        if error:
            errors.append(error)

    clarification_count = artifact.get("owner_clarification_count_at_decision")
    if clarification_count is not None and not isinstance(clarification_count, int):
        errors.append("owner_clarification_count_at_decision must be an integer")

    latest_clarification = artifact.get("latest_clarification_id_at_decision")
    if latest_clarification is not None and not isinstance(
        latest_clarification, (str, type(None))
    ):
        errors.append("latest_clarification_id_at_decision must be a string or null")

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    return errors


def create_owner_readiness_decision(
    project: Path,
    intake_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
) -> Path:
    """Create an OWNER_READINESS_DECISION artifact without mutating intake or clarifications."""
    validate_readiness_decision_id(decision_id)
    if decision not in OWNER_READINESS_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    _require_valid_goal_intake(project, intake_id)
    readiness_report = review_goal_intake_readiness(project, intake_id)
    _validate_readiness_decision_allowed(decision, readiness_report)

    artifact = build_owner_readiness_decision_artifact(
        intake_id,
        decision_id,
        decision,
        owner_summary,
        readiness_review_state_at_decision=readiness_report.readiness_review_state,
        next_required_action_at_decision=readiness_report.next_required_action,
        owner_clarification_count_at_decision=readiness_report.owner_clarification_count,
        latest_clarification_id_at_decision=readiness_report.latest_clarification_id,
    )

    dest = orchestrator_readiness_decision_path(project, intake_id, decision_id)
    if dest.exists():
        raise FileExistsError(
            f"owner readiness decision artifact already exists: {decision_id}"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)
    return dest


def load_owner_readiness_decision(
    project: Path,
    intake_id: str,
    decision_id: str,
) -> dict:
    """Load an OWNER_READINESS_DECISION artifact from disk (read-only)."""
    validate_intake_id(intake_id)
    validate_readiness_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_readiness_decision_path(project, intake_id, decision_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner readiness decision artifact not found: {decision_id}"
        )

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid readiness decision artifact for {decision_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid readiness decision artifact for {decision_id}: expected object"
        )

    return artifact


def list_owner_readiness_decisions(
    project: Path,
    intake_id: str,
) -> tuple[OwnerReadinessDecisionRecord, ...]:
    """List owner readiness decision records for an intake (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    decisions_dir = (
        orchestrator_intake_path(project, intake_id) / READINESS_DECISIONS_DIR
    )
    if not decisions_dir.is_dir():
        return ()

    records: list[OwnerReadinessDecisionRecord] = []
    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(artifact, dict):
            continue
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = ""
        decision = artifact.get("decision")
        if not isinstance(decision, str):
            decision = ""
        records.append(
            OwnerReadinessDecisionRecord(
                decision_id=decision_id,
                decision=decision,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.decision_id))
    return tuple(records)


def validate_owner_readiness_decision(
    project: Path,
    intake_id: str,
    decision_id: str,
) -> OwnerReadinessDecisionValidationReport:
    """Strict read-only structural validation of an OWNER_READINESS_DECISION artifact."""
    validate_intake_id(intake_id)
    validate_readiness_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_readiness_decision_path(project, intake_id, decision_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner readiness decision artifact not found: {decision_id}"
        )

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_owner_readiness_decision_payload(
            artifact,
            intake_id,
            decision_id,
        )

    lines = [
        f"owner readiness decision artifact: {path}",
        f"intake_id: {intake_id}",
        f"decision_id: {decision_id}",
        f"structural validation: {'OK' if not errors else 'INVALID'}",
    ]
    for error in errors:
        lines.append(f"  - {error}")
    lines.append(f"final validation result: {'OK' if not errors else 'INVALID'}")
    if not errors:
        lines.append(
            "note: readiness decision is owner-provided context only; "
            "not approval, not planning generation, and no intake files were modified"
        )

    output = "\n".join(lines)
    return OwnerReadinessDecisionValidationReport(output, not errors, tuple(errors))


@dataclass(frozen=True)
class _PreflightDecisionEntry:
    record: OwnerReadinessDecisionRecord
    artifact: dict | None
    validation_errors: tuple[str, ...]


def _collect_preflight_decision_entries(
    project: Path,
    intake_id: str,
) -> tuple[tuple[_PreflightDecisionEntry, ...], list[str]]:
    """Load readiness decision files with validation metadata (read-only)."""
    decisions_dir = (
        orchestrator_intake_path(project, intake_id) / READINESS_DECISIONS_DIR
    )
    if not decisions_dir.is_dir():
        return (), []

    entries: list[_PreflightDecisionEntry] = []
    blocking: list[str] = []

    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        raw_text = path.read_text(encoding="utf-8")
        validation_errors: list[str] = []
        artifact: dict | None = None
        try:
            loaded = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            validation_errors = [f"malformed JSON: {exc.msg}"]
        else:
            validation_errors = _validate_owner_readiness_decision_payload(
                loaded,
                intake_id,
                decision_id,
            )
            if isinstance(loaded, dict):
                artifact = loaded
            else:
                validation_errors.append(
                    "owner readiness decision artifact must be a JSON object"
                )

        created_at = ""
        decision = ""
        if artifact is not None:
            created_at_value = artifact.get("created_at")
            if isinstance(created_at_value, str):
                created_at = created_at_value
            decision_value = artifact.get("decision")
            if isinstance(decision_value, str):
                decision = decision_value

        record = OwnerReadinessDecisionRecord(
            decision_id=decision_id,
            decision=decision,
            created_at=created_at,
            path=path,
        )
        if validation_errors:
            for error in validation_errors:
                blocking.append(f"invalid readiness decision {decision_id}: {error}")

        entries.append(
            _PreflightDecisionEntry(
                record=record,
                artifact=artifact,
                validation_errors=tuple(validation_errors),
            )
        )

    entries.sort(key=lambda entry: (entry.record.created_at, entry.record.decision_id))
    return tuple(entries), blocking


def _authorization_snapshot_coherent(
    artifact: dict,
    readiness_report: GoalIntakeReadinessReport,
) -> bool:
    """Return whether decision snapshot fields match the current readiness review."""
    snapshot_state = artifact.get("readiness_review_state_at_decision")
    snapshot_action = artifact.get("next_required_action_at_decision")
    snapshot_count = artifact.get("owner_clarification_count_at_decision")
    snapshot_latest = artifact.get("latest_clarification_id_at_decision")

    if snapshot_state != readiness_report.readiness_review_state:
        return False
    if snapshot_action != readiness_report.next_required_action:
        return False
    if snapshot_count != readiness_report.owner_clarification_count:
        return False
    if snapshot_latest != readiness_report.latest_clarification_id:
        return False
    return True


def _format_draft_preparation_preflight(
    path: Path,
    *,
    intake_id: str,
    goal_intake_valid: bool,
    current_readiness_review_state: str,
    current_next_required_action: str,
    owner_readiness_decision_count: int,
    latest_decision_id: str | None,
    latest_decision: str | None,
    latest_decision_created_at: str | None,
    latest_decision_snapshot_state: str | None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    non_authority: dict[str, bool],
) -> str:
    lines = [
        f"draft-preparation authorization preflight: {path}",
        f"intake_id: {intake_id}",
        f"goal_intake_valid: {'yes' if goal_intake_valid else 'no'}",
        f"current_readiness_review_state: {current_readiness_review_state}",
        f"current_next_required_action: {current_next_required_action}",
        f"owner_readiness_decision_count: {owner_readiness_decision_count}",
    ]
    if latest_decision_id is not None:
        lines.append(f"latest_decision_id: {latest_decision_id}")
    if latest_decision is not None:
        lines.append(f"latest_decision: {latest_decision}")
    if latest_decision_created_at is not None:
        lines.append(f"latest_decision_created_at: {latest_decision_created_at}")
    if latest_decision_snapshot_state is not None:
        lines.append(
            f"latest_decision_snapshot_state: {latest_decision_snapshot_state}"
        )
    lines.append(f"preflight_state: {preflight_state}")
    lines.append(f"next_required_action: {next_required_action}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: draft-preparation preflight is read-only; "
        "not draft generation, not planning workspace creation, "
        "not architecture approval, not plan approval, and no files were modified"
    )
    if (
        preflight_state
        == "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED"
    ):
        lines.append(
            "note: authorization confirmed for a future draft-preparation command only; "
            "no planning draft was generated"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class DraftPreparationPreflightReport:
    output: str
    intake_id: str
    goal_intake_valid: bool
    current_readiness_review_state: str
    current_next_required_action: str
    owner_readiness_decision_count: int
    latest_decision_id: str | None
    latest_decision: str | None
    latest_decision_created_at: str | None
    latest_decision_snapshot_state: str | None
    preflight_state: str
    next_required_action: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def preflight_draft_preparation(
    project: Path,
    intake_id: str,
) -> DraftPreparationPreflightReport:
    """Read-only draft-preparation authorization preflight for an existing intake."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    readiness_report = review_goal_intake_readiness(project, intake_id)
    decision_entries, decision_blocking = _collect_preflight_decision_entries(
        project,
        intake_id,
    )
    non_authority = {
        key: True for key in DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS
    }

    latest_decision_id: str | None = None
    latest_decision: str | None = None
    latest_decision_created_at: str | None = None
    latest_decision_snapshot_state: str | None = None
    blocking_reasons: list[str] = list(decision_blocking)
    preflight_state: str
    next_required_action: str

    if not readiness_report.goal_intake_valid:
        preflight_state = "BLOCKED_INVALID_INTAKE"
        next_required_action = "FIX_GOAL_INTAKE_STRUCTURE"
        blocking_reasons = list(readiness_report.blocking_reasons) + blocking_reasons
    elif not decision_entries:
        preflight_state = "BLOCKED_NO_READINESS_DECISION"
        next_required_action = "ADD_OWNER_READINESS_DECISION"
    else:
        latest_entry = decision_entries[-1]
        latest_decision_id = latest_entry.record.decision_id
        latest_decision = latest_entry.record.decision or None
        latest_decision_created_at = latest_entry.record.created_at or None
        if latest_entry.artifact is not None:
            snapshot_state = latest_entry.artifact.get(
                "readiness_review_state_at_decision"
            )
            if isinstance(snapshot_state, str):
                latest_decision_snapshot_state = snapshot_state

        if latest_entry.validation_errors:
            preflight_state = "BLOCKED_INVALID_READINESS_DECISION"
            next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"
        elif latest_decision == "REQUEST_MORE_CLARIFICATION":
            preflight_state = "BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION"
            next_required_action = "ADD_OWNER_CLARIFICATION"
        elif latest_decision == "BLOCK_INTAKE":
            preflight_state = "BLOCKED_LATEST_DECISION_BLOCKS_INTAKE"
            next_required_action = "STOP_INTAKE"
        elif latest_decision == "AUTHORIZE_DRAFT_PREPARATION":
            if latest_entry.artifact is None or not _authorization_snapshot_coherent(
                latest_entry.artifact,
                readiness_report,
            ):
                preflight_state = "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT"
                next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"
                blocking_reasons.append(
                    "authorization snapshot no longer matches current readiness review"
                )
            else:
                preflight_state = (
                    "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED"
                )
                next_required_action = (
                    "FUTURE_DRAFT_PREPARATION_STEP_REQUIRES_SEPARATE_COMMAND"
                )
        elif latest_decision in OWNER_READINESS_DECISION_VALUES:
            preflight_state = "BLOCKED_LATEST_DECISION_NOT_AUTHORIZE"
            next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"
        else:
            preflight_state = "BLOCKED_INVALID_READINESS_DECISION"
            next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"

    if preflight_state in FORBIDDEN_DRAFT_PREPARATION_PREFLIGHT_STATES:
        raise ValueError(f"forbidden draft-preparation preflight state: {preflight_state}")

    output = _format_draft_preparation_preflight(
        path,
        intake_id=intake_id,
        goal_intake_valid=readiness_report.goal_intake_valid,
        current_readiness_review_state=readiness_report.readiness_review_state,
        current_next_required_action=readiness_report.next_required_action,
        owner_readiness_decision_count=len(decision_entries),
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        latest_decision_created_at=latest_decision_created_at,
        latest_decision_snapshot_state=latest_decision_snapshot_state,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        non_authority=non_authority,
    )
    return DraftPreparationPreflightReport(
        output=output,
        intake_id=intake_id,
        goal_intake_valid=readiness_report.goal_intake_valid,
        current_readiness_review_state=readiness_report.readiness_review_state,
        current_next_required_action=readiness_report.next_required_action,
        owner_readiness_decision_count=len(decision_entries),
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        latest_decision_created_at=latest_decision_created_at,
        latest_decision_snapshot_state=latest_decision_snapshot_state,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def _build_orchestrator_provenance_artifact(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    preflight_report: DraftPreparationPreflightReport,
    readiness_report: GoalIntakeReadinessReport,
    intake_artifact: dict,
    created_at: str,
) -> dict:
    normalized_goal = intake_artifact.get("normalized_goal")
    raw_goal = intake_artifact.get("raw_goal")
    if isinstance(normalized_goal, str) and normalized_goal.strip():
        goal_summary = normalized_goal
    elif isinstance(raw_goal, str) and raw_goal.strip():
        goal_summary = raw_goal
    else:
        goal_summary = ""

    return {
        "artifact_type": ORCHESTRATOR_PLANNING_DRAFT_SOURCE_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_PLANNING_DRAFT_SOURCE_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_goal_intake_path": str(source_goal_intake_path),
        "source_goal_summary": goal_summary,
        "source_preflight_state": preflight_report.preflight_state,
        "source_authorize_decision_id": preflight_report.latest_decision_id,
        "source_authorize_decision_value": preflight_report.latest_decision,
        "source_readiness_review_state": readiness_report.readiness_review_state,
        "source_next_required_action": preflight_report.next_required_action,
        "owner_clarification_count": readiness_report.owner_clarification_count,
        "latest_clarification_id": readiness_report.latest_clarification_id,
        "created_at": created_at,
        "non_authority": {
            key: True for key in ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS
        },
    }


def _orchestrator_draft_scaffold_notes_markdown(
    *,
    intake_id: str,
    plan_id: str,
    goal_summary: str,
) -> str:
    return f"""\
# Orchestrator draft scaffold notes

> **Traceability only — not authority.** This file records orchestrator provenance
> boundaries for a DRAFT planning workspace scaffold. It does not approve work,
> validate planning artifacts, or authorize execution.

- **intake_id:** `{intake_id}`
- **plan_id:** `{plan_id}`
- **goal context (provenance only):** {goal_summary or "unavailable"}
- **architecture:** undecided — not generated by orchestrator
- **implementation plan:** not generated — template placeholders only
- **PLANNING_RUN_SLICE:** not generated
- **planning validation:** not performed by orchestrator
- **plan approval:** not granted
- **runner proposals / runs / executor:** not created or invoked

Future manual or agent planning, independent validation, and owner approval remain required.
"""


def _format_prepared_planning_workspace_draft(
    *,
    workspace_dest: Path,
    plan_id: str,
    intake_id: str,
    provenance_path: Path,
    scaffold_notes_path: Path,
    preflight_state: str,
    authorize_decision_id: str | None,
) -> str:
    lines = [
        f"planning workspace draft scaffold created: {workspace_dest}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        "workspace_status: DRAFT",
        f"orchestrator provenance: {provenance_path}",
        f"orchestrator scaffold notes: {scaffold_notes_path}",
        f"source_preflight_state: {preflight_state}",
    ]
    if authorize_decision_id is not None:
        lines.append(f"source_authorize_decision_id: {authorize_decision_id}")
    lines.append(
        "note: draft scaffold only; no architecture generation, "
        "no implementation plan generation, no PLANNING_RUN_SLICE"
    )
    lines.append(
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation"
    )
    lines.append(
        "note: orchestrator intake artifacts were not modified; "
        "future independent validation and owner approval remain required"
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class PreparedPlanningWorkspaceDraftReport:
    output: str
    plan_id: str
    intake_id: str
    workspace_path: Path
    provenance_path: Path
    scaffold_notes_path: Path
    workspace_status: str
    preflight_state: str
    authorize_decision_id: str | None
    non_authority: dict[str, bool]


def prepare_planning_workspace_draft(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> PreparedPlanningWorkspaceDraftReport:
    """Create a DRAFT planning workspace scaffold after draft-preflight authorization."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    intake_path, intake_artifact = _require_valid_goal_intake(project, intake_id)

    preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{preflight_report.preflight_state}"
        )
    if (
        preflight_report.next_required_action
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        raise ValueError(
            "draft-preparation preflight next action is not draft preparation: "
            f"{preflight_report.next_required_action}"
        )
    if preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    workspace_dest = planning_path(project, plan_id)
    if workspace_dest.exists():
        raise FileExistsError(f"planning workspace already exists: {plan_id}")

    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    scaffold_notes_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_DRAFT_SCAFFOLD_NOTES_FILE
    )
    if provenance_path.exists() or scaffold_notes_path.exists():
        raise FileExistsError(
            f"orchestrator provenance would overwrite existing file for plan: {plan_id}"
        )

    readiness_report = review_goal_intake_readiness(project, intake_id)
    created_at = _utc_now()
    provenance_artifact = _build_orchestrator_provenance_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        preflight_report=preflight_report,
        readiness_report=readiness_report,
        intake_artifact=intake_artifact,
        created_at=created_at,
    )
    goal_summary = provenance_artifact.get("source_goal_summary", "")
    scaffold_notes = _orchestrator_draft_scaffold_notes_markdown(
        intake_id=intake_id,
        plan_id=plan_id,
        goal_summary=str(goal_summary),
    )

    try:
        init_planning_workspace(project, plan_id)
        provenance_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(provenance_path, provenance_artifact)
        scaffold_notes_path.write_text(scaffold_notes, encoding="utf-8")
    except Exception:
        if workspace_dest.is_dir():
            shutil.rmtree(workspace_dest)
        raise

    non_authority = {
        key: True for key in ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS
    }
    output = _format_prepared_planning_workspace_draft(
        workspace_dest=workspace_dest,
        plan_id=plan_id,
        intake_id=intake_id,
        provenance_path=provenance_path,
        scaffold_notes_path=scaffold_notes_path,
        preflight_state=preflight_report.preflight_state,
        authorize_decision_id=preflight_report.latest_decision_id,
    )
    return PreparedPlanningWorkspaceDraftReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_path=workspace_dest,
        provenance_path=provenance_path,
        scaffold_notes_path=scaffold_notes_path,
        workspace_status="DRAFT",
        preflight_state=preflight_report.preflight_state,
        authorize_decision_id=preflight_report.latest_decision_id,
        non_authority=non_authority,
    )


def _load_planning_workspace_status(workspace_dest: Path, plan_id: str) -> str:
    manifest_path = workspace_dest / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"planning workspace manifest not found: {plan_id}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid manifest.json for planning workspace {plan_id}: {exc.msg}"
        ) from exc
    if not isinstance(manifest, dict):
        raise ValueError(
            f"invalid manifest.json for planning workspace {plan_id}: expected object"
        )
    status = manifest.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ValueError(f"missing manifest status for planning workspace {plan_id}")
    return status


def _require_orchestrator_provenance_for_transport(
    provenance_path: Path,
    *,
    plan_id: str,
    intake_id: str,
    preflight_report: DraftPreparationPreflightReport,
) -> dict:
    if not provenance_path.is_file():
        raise FileNotFoundError(
            f"orchestrator provenance not found for planning workspace: {plan_id}"
        )

    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid orchestrator provenance for planning workspace {plan_id}: {exc.msg}"
        ) from exc

    if not isinstance(provenance, dict):
        raise ValueError(
            f"invalid orchestrator provenance for planning workspace {plan_id}: "
            "expected object"
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        raise ValueError(
            f"orchestrator provenance plan_id mismatch: "
            f"expected {plan_id!r}, found {provenance_plan_id!r}"
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        raise ValueError(
            f"orchestrator provenance intake_id mismatch: "
            f"expected {intake_id!r}, found {provenance_intake_id!r}"
        )

    source_preflight_state = provenance.get("source_preflight_state")
    if source_preflight_state != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE:
        raise ValueError(
            "orchestrator provenance source_preflight_state is not confirmed: "
            f"{source_preflight_state!r}"
        )

    source_authorize_decision_id = provenance.get("source_authorize_decision_id")
    if source_authorize_decision_id != preflight_report.latest_decision_id:
        raise ValueError(
            "orchestrator provenance source_authorize_decision_id mismatch: "
            f"expected {preflight_report.latest_decision_id!r}, "
            f"found {source_authorize_decision_id!r}"
        )

    return provenance


def _collect_owner_clarifications_for_transport(
    project: Path,
    intake_id: str,
) -> list[dict]:
    records = list_owner_clarifications(project, intake_id)
    clarifications: list[dict] = []
    for record in records:
        artifact = load_owner_clarification(
            project,
            intake_id,
            record.clarification_id,
        )
        owner_answer = artifact.get("owner_answer")
        if not isinstance(owner_answer, str):
            owner_answer = ""
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = record.created_at
        clarifications.append(
            {
                "clarification_id": record.clarification_id,
                "owner_answer": owner_answer,
                "created_at": created_at,
            }
        )
    return clarifications


def _latest_owner_readiness_decision_for_transport(
    project: Path,
    intake_id: str,
) -> dict:
    decisions = list_owner_readiness_decisions(project, intake_id)
    if not decisions:
        raise ValueError("owner readiness decision required for context transport")

    latest = decisions[-1]
    artifact = load_owner_readiness_decision(
        project,
        intake_id,
        latest.decision_id,
    )
    owner_summary = artifact.get("owner_summary")
    if not isinstance(owner_summary, str):
        owner_summary = ""
    created_at = artifact.get("created_at")
    if not isinstance(created_at, str):
        created_at = latest.created_at
    decision = artifact.get("decision")
    if not isinstance(decision, str):
        decision = latest.decision

    return {
        "decision_id": latest.decision_id,
        "decision": decision,
        "owner_summary": owner_summary,
        "created_at": created_at,
    }


def _build_orchestrator_context_transport_artifact(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    intake_artifact: dict,
    owner_clarifications: list[dict],
    owner_readiness_decision: dict,
    preflight_report: DraftPreparationPreflightReport,
    provenance_path: Path,
    workspace_status: str,
    created_at: str,
) -> dict:
    return {
        "artifact_type": ORCHESTRATOR_CONTEXT_TRANSPORT_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_CONTEXT_TRANSPORT_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_goal_intake_path": str(source_goal_intake_path),
        "source_context": {
            "raw_goal": intake_artifact.get("raw_goal"),
            "normalized_goal": intake_artifact.get("normalized_goal"),
            "user_visible_summary": intake_artifact.get("user_visible_summary"),
            "ambiguity_level": intake_artifact.get("ambiguity_level"),
            "planning_readiness": intake_artifact.get("planning_readiness"),
            "open_questions": intake_artifact.get("open_questions"),
            "risk_flags": intake_artifact.get("risk_flags"),
        },
        "owner_clarifications": owner_clarifications,
        "owner_readiness_decision": owner_readiness_decision,
        "draft_preflight": {
            "preflight_state": preflight_report.preflight_state,
            "next_required_action": preflight_report.next_required_action,
            "latest_decision_id": preflight_report.latest_decision_id,
        },
        "planning_workspace": {
            "status_at_transport": workspace_status,
            "provenance_path": str(provenance_path),
        },
        "created_at": created_at,
        "non_authority": {
            key: True for key in ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS
        },
    }


def _orchestrator_context_transport_markdown(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    intake_artifact: dict,
    owner_clarifications: list[dict],
    owner_readiness_decision: dict,
    preflight_report: DraftPreparationPreflightReport,
    provenance_path: Path,
    workspace_status: str,
) -> str:
    raw_goal = intake_artifact.get("raw_goal", "")
    normalized_goal = intake_artifact.get("normalized_goal", "")

    lines = [
        "# Orchestrator context transport",
        "",
        "> **Source material only — not authority.** This file copies owner-provided "
        "intake context into the planning workspace for review. It does not generate "
        "architecture, implementation plans, or PLANNING_RUN_SLICE; does not validate "
        "or approve the workspace; and does not authorize execution.",
        "",
        "## Source identifiers",
        "",
        f"- **plan_id:** `{plan_id}`",
        f"- **intake_id:** `{intake_id}`",
        f"- **source goal intake:** `{source_goal_intake_path}`",
        f"- **orchestrator provenance:** `{provenance_path}`",
        f"- **planning workspace status at transport:** `{workspace_status}`",
        "",
        "## Raw goal (verbatim)",
        "",
        "```",
        str(raw_goal),
        "```",
        "",
        "## Normalized goal (from GOAL_INTAKE)",
        "",
        str(normalized_goal),
        "",
    ]

    lines.append("## Owner clarifications (verbatim answers)")
    lines.append("")
    if owner_clarifications:
        for item in owner_clarifications:
            lines.append(
                f"- **{item['clarification_id']}** "
                f"(`{item.get('created_at', '')}`): {item['owner_answer']}"
            )
    else:
        lines.append("- (none)")
    lines.append("")

    lines.extend(
        [
            "## Owner readiness decision (verbatim summary)",
            "",
            f"- **decision_id:** `{owner_readiness_decision.get('decision_id', '')}`",
            f"- **decision:** `{owner_readiness_decision.get('decision', '')}`",
            f"- **owner_summary:** {owner_readiness_decision.get('owner_summary', '')}",
            "",
            "## Draft-preparation preflight snapshot",
            "",
            f"- **preflight_state:** `{preflight_report.preflight_state}`",
            f"- **next_required_action:** `{preflight_report.next_required_action}`",
            f"- **latest_decision_id:** `{preflight_report.latest_decision_id}`",
            "",
            "## Explicit boundaries",
            "",
            "- **architecture:** undecided — not generated by orchestrator",
            "- **implementation plan:** not generated — template placeholders only",
            "- **PLANNING_RUN_SLICE:** not generated",
            "- **planning workspace:** not validated or approved",
            "- **runner proposals / runs / executor:** not created or invoked",
            "",
            "Transported context is source material only. Future architecture decision, "
            "independent validation, and owner approval remain required.",
        ]
    )
    return "\n".join(lines) + "\n"


def _format_transported_planning_context(
    *,
    json_path: Path,
    markdown_path: Path,
    plan_id: str,
    intake_id: str,
    workspace_status: str,
) -> str:
    lines = [
        f"orchestrator context transport created: {json_path.parent}",
        f"context transport json: {json_path}",
        f"context transport markdown: {markdown_path}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"workspace_status: {workspace_status}",
        "note: context transport only; copied source context, no interpretation",
        "note: no architecture generation, no implementation plan generation, "
        "no PLANNING_RUN_SLICE",
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation",
        "note: orchestrator intake artifacts and provenance were not modified; "
        "future architecture decision, independent validation, and owner approval "
        "remain required",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class TransportedPlanningContextReport:
    output: str
    plan_id: str
    intake_id: str
    json_path: Path
    markdown_path: Path
    workspace_status: str
    non_authority: dict[str, bool]


def transport_planning_context(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> TransportedPlanningContextReport:
    """Transport owner-provided intake context into an authorized DRAFT planning scaffold."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    intake_path, intake_artifact = _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for context transport, found: "
            f"{workspace_status!r}"
        )

    preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{preflight_report.preflight_state}"
        )
    if preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    _require_orchestrator_provenance_for_transport(
        provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        preflight_report=preflight_report,
    )

    json_path = workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_FILE
    markdown_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE
    )
    if json_path.exists() or markdown_path.exists():
        raise FileExistsError(
            f"context transport artifacts already exist for plan: {plan_id}"
        )

    owner_clarifications = _collect_owner_clarifications_for_transport(
        project,
        intake_id,
    )
    owner_readiness_decision = _latest_owner_readiness_decision_for_transport(
        project,
        intake_id,
    )
    created_at = _utc_now()
    transport_artifact = _build_orchestrator_context_transport_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        intake_artifact=intake_artifact,
        owner_clarifications=owner_clarifications,
        owner_readiness_decision=owner_readiness_decision,
        preflight_report=preflight_report,
        provenance_path=provenance_path,
        workspace_status=workspace_status,
        created_at=created_at,
    )
    transport_markdown = _orchestrator_context_transport_markdown(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        intake_artifact=intake_artifact,
        owner_clarifications=owner_clarifications,
        owner_readiness_decision=owner_readiness_decision,
        preflight_report=preflight_report,
        provenance_path=provenance_path,
        workspace_status=workspace_status,
    )

    json_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write_json(json_path, transport_artifact)
        markdown_path.write_text(transport_markdown, encoding="utf-8")
    except Exception:
        if json_path.is_file():
            json_path.unlink()
        if markdown_path.is_file():
            markdown_path.unlink()
        raise

    non_authority = {
        key: True for key in ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS
    }
    output = _format_transported_planning_context(
        json_path=json_path,
        markdown_path=markdown_path,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_status=workspace_status,
    )
    return TransportedPlanningContextReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        json_path=json_path,
        markdown_path=markdown_path,
        workspace_status=workspace_status,
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
