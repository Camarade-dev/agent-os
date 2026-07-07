"""Shared paths and frontmatter helpers."""

from __future__ import annotations

import re
from pathlib import Path

WORKSPACE_DIR = ".agent-os"
RUNS_DIR = "runs"
PLANNING_DIR = "planning"
ORCHESTRATOR_DIR = "orchestrator"
INTAKES_DIR = "intakes"
GOAL_INTAKE_FILE = "goal-intake.json"
CLARIFICATIONS_DIR = "clarifications"
READINESS_DECISIONS_DIR = "readiness-decisions"
REQUIREMENTS_EXTRACTION_DECISIONS_DIR = "requirements-extraction-decisions"
REQUIREMENTS_VALIDATION_DECISIONS_DIR = "requirements-validation-decisions"
ORCHESTRATOR_PROVENANCE_FILE = "orchestrator-provenance.json"
ORCHESTRATOR_DRAFT_SCAFFOLD_NOTES_FILE = "orchestrator-draft-scaffold-notes.md"
ORCHESTRATOR_CONTEXT_TRANSPORT_FILE = "orchestrator-context-transport.json"
ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE = "orchestrator-context-transport.md"
ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE = (
    "orchestrator-context-pack-draft-provenance.json"
)
ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_FILE = (
    "orchestrator-local-agentic-spec-scaffold-provenance.json"
)
ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_FILE = (
    "orchestrator-requirements-extraction-scaffold-provenance.json"
)
ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE = (
    "orchestrator-requirements-draft-provenance.json"
)
ORCHESTRATOR_REQUIREMENTS_DRAFT_VALIDATION_REPORT_FILE = (
    "orchestrator-requirements-draft-validation-report.json"
)
META_FILE = "run.json"

PLACEHOLDER_VALUES = frozenset(
    {"", "placeholder", "tbd", "todo", "none", "n/a", "pending"}
)

TEMPLATE_FILES = (
    "mission.md",
    "preflight.md",
    "evidence.md",
    "audit.md",
    "owner-decision.md",
    "closure.md",
    "memory-update.md",
)


def templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def planning_templates_dir() -> Path:
    return templates_dir() / "planning"


def workspace_path(project: Path) -> Path:
    return project.resolve() / WORKSPACE_DIR


def runs_path(project: Path) -> Path:
    return workspace_path(project) / RUNS_DIR


def planning_path(project: Path, plan_id: str) -> Path:
    return workspace_path(project) / PLANNING_DIR / plan_id


def orchestrator_intake_path(project: Path, intake_id: str) -> Path:
    return workspace_path(project) / ORCHESTRATOR_DIR / INTAKES_DIR / intake_id


def orchestrator_clarification_path(
    project: Path,
    intake_id: str,
    clarification_id: str,
) -> Path:
    return (
        orchestrator_intake_path(project, intake_id)
        / CLARIFICATIONS_DIR
        / f"{clarification_id}.json"
    )


def orchestrator_readiness_decision_path(
    project: Path,
    intake_id: str,
    decision_id: str,
) -> Path:
    return (
        orchestrator_intake_path(project, intake_id)
        / READINESS_DECISIONS_DIR
        / f"{decision_id}.json"
    )


def orchestrator_requirements_extraction_decision_path(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> Path:
    return (
        orchestrator_intake_path(project, intake_id)
        / REQUIREMENTS_EXTRACTION_DECISIONS_DIR
        / plan_id
        / f"{decision_id}.json"
    )


def orchestrator_requirements_validation_decision_path(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> Path:
    return (
        orchestrator_intake_path(project, intake_id)
        / REQUIREMENTS_VALIDATION_DECISIONS_DIR
        / plan_id
        / f"{decision_id}.json"
    )


def run_path(project: Path, run_id: str) -> Path:
    return runs_path(project) / run_id


def read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.DOTALL)
    if not match:
        return {}, text
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        meta[key.strip().lower()] = value.strip()
    return meta, match.group(2)


def is_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    normalized = value.strip().lower()
    if normalized in PLACEHOLDER_VALUES:
        return True
    if normalized.startswith("placeholder"):
        return True
    return False


def is_placeholder_line(line: str) -> bool:
    stripped = line.strip()
    if is_placeholder(stripped):
        return True
    if re.match(r"^placeholder\s*[—\-–:]", stripped, re.IGNORECASE):
        return True
    return False


def substantive_lines(body: str) -> list[str]:
    lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(">"):
            continue
        lines.append(stripped)
    return lines


def body_is_missing(body: str) -> bool:
    lines = substantive_lines(body)
    if not lines:
        return True
    return all(is_placeholder_line(line) for line in lines)


def section_body(body: str, heading: str) -> str:
    """Return markdown body under a heading such as '# Mission' or '## Scope'."""
    target = heading.lstrip("#").strip().lower()
    target_level = len(heading) - len(heading.lstrip("#"))
    lines = body.splitlines()
    collecting = False
    collected: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped.lstrip("#").strip().lower()
            if title == target:
                collecting = True
                continue
            if collecting and level <= target_level:
                break
        elif collecting:
            collected.append(line)

    return "\n".join(collected)


def field_errors(
    meta: dict[str, str],
    field_name: str,
    label: str,
) -> list[str]:
    """Return validation errors for a required frontmatter field."""
    if field_name not in meta:
        return [f"{label} field missing"]
    if is_placeholder(meta[field_name]):
        return [f"{label} field is placeholder"]
    return []


def body_errors(body: str, label: str) -> list[str]:
    """Return validation errors for a required markdown body section."""
    if body_is_missing(body):
        return [f"{label} is placeholder/unfilled"]
    return []
