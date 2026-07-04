"""Fail-closed closure validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agent_os.paths import (
    body_errors,
    field_errors,
    is_placeholder,
    parse_frontmatter,
    read_text,
    run_path,
    section_body,
)


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


def _validate_mission(base: Path) -> list[str]:
    path = base / "mission.md"
    if not path.is_file():
        return ["mission file missing"]

    _, body = parse_frontmatter(read_text(path))
    errors: list[str] = []
    mission_statement = section_body(body, "# Mission")
    scope = section_body(body, "## Scope")

    errors.extend(body_errors(mission_statement, "mission statement"))
    errors.extend(body_errors(scope, "scope"))
    return errors


def _validate_preflight(base: Path) -> list[str]:
    path = base / "preflight.md"
    if not path.is_file():
        return [
            "authority field missing",
            "autonomy level field missing",
            "autonomy gates is placeholder/unfilled",
        ]

    text = read_text(path)
    meta, body = parse_frontmatter(text)
    errors: list[str] = []
    errors.extend(field_errors(meta, "authority", "authority"))

    autonomy_level_ok = (
        "autonomy_level" in meta and not is_placeholder(meta["autonomy_level"])
    )
    autonomy_gates = section_body(body, "## Autonomy gates")
    autonomy_gates_ok = not body_errors(autonomy_gates, "autonomy gates")

    if not autonomy_level_ok and not autonomy_gates_ok:
        if "autonomy_level" not in meta:
            errors.append("autonomy level field missing")
        elif is_placeholder(meta["autonomy_level"]):
            errors.append("autonomy level field is placeholder")
        errors.extend(body_errors(autonomy_gates, "autonomy gates"))

    return errors


def _validate_evidence(base: Path) -> list[str]:
    path = base / "evidence.md"
    if not path.is_file():
        return ["evidence file missing"]

    _, body = parse_frontmatter(read_text(path))
    return body_errors(body, "evidence")


def _validate_audit(base: Path) -> list[str]:
    path = base / "audit.md"
    if not path.is_file():
        return ["audit verdict field missing"]

    meta, _ = parse_frontmatter(read_text(path))
    return field_errors(meta, "verdict", "audit verdict")


def _validate_owner_decision(base: Path) -> list[str]:
    path = base / "owner-decision.md"
    if not path.is_file():
        return ["owner decision field missing"]

    meta, _ = parse_frontmatter(read_text(path))
    return field_errors(meta, "decision", "owner decision")


def _validate_closure(base: Path) -> list[str]:
    path = base / "closure.md"
    if not path.is_file():
        return ["closure verdict field missing"]

    meta, _ = parse_frontmatter(read_text(path))
    return field_errors(meta, "verdict", "closure verdict")


def validate_run_for_closure(project: Path, run_id: str) -> ValidationResult:
    base = run_path(project, run_id)
    errors: list[str] = []

    if not base.is_dir():
        return ValidationResult(False, [f"run not found: {run_id}"])

    errors.extend(_validate_mission(base))
    errors.extend(_validate_preflight(base))
    errors.extend(_validate_evidence(base))
    errors.extend(_validate_audit(base))
    errors.extend(_validate_owner_decision(base))
    errors.extend(_validate_closure(base))

    return ValidationResult(not errors, errors)


def missing_fields_for_run(project: Path, run_id: str) -> list[str]:
    return validate_run_for_closure(project, run_id).errors
