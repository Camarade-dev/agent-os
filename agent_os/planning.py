"""Planning workspace bootstrap and read-only inspection (no execution or agent invocation)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_os.paths import planning_path, planning_templates_dir, workspace_path

PLAN_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

PLANNING_ARTIFACT_FILES = (
    "context-pack.md",
    "local-agentic-spec.md",
    "implementation-plan.md",
    "planning-audit.md",
)

PLANNING_SUBDIRS = ("evidence", "decisions", "revisions")

PLANNING_REQUIRED_FILES = (
    "manifest.json",
    "README.md",
    *PLANNING_ARTIFACT_FILES,
)

PLANNING_GATE_KEYS = (
    "planning_owner_decision_required",
    "planning_audit_required",
    "plan_revision_required",
    "run_proposal_allowed",
)

PLANNING_AUTHORITY_KEYS = (
    "no_execution",
    "no_agent_invocation",
    "no_run_creation",
    "no_self_approval",
)

PLANNING_STATUSES = (
    "DRAFT",
    "CONTEXT_READY",
    "SPEC_READY",
    "PLAN_READY",
    "PLANNING_AUDIT_READY",
    "APPROVED_FOR_RUN_PROPOSALS",
    "BLOCKED",
    "SUPERSEDED",
    "CLOSED",
)

PLANNING_ARTIFACT_PATH_KEYS = (
    "context_pack",
    "local_agentic_spec",
    "implementation_plan",
    "planning_audit",
)

PLANNING_DIRECTORY_KEYS = PLANNING_SUBDIRS

PLACEHOLDER_TOKEN_PATTERN = re.compile(r"\{\{[^}]+\}\}")

NON_AUTHORITY_PATTERN = re.compile(r"does\s+not", re.IGNORECASE)

ARTIFACT_TYPE_MARKERS = {
    "context-pack.md": "CONTEXT_PACK",
    "local-agentic-spec.md": "LOCAL_AGENTIC_SPEC",
    "implementation-plan.md": "IMPLEMENTATION_PLAN",
    "planning-audit.md": "PLANNING_AUDIT",
}

ARTIFACT_REQUIRED_SECTIONS: dict[str, tuple[str, ...]] = {
    "context-pack.md": (
        "Goal reference",
        "Source boundaries",
        "Files inspected",
        "Unknowns",
        "Evidence",
    ),
    "local-agentic-spec.md": (
        "Goal summary",
        "In-scope",
        "Out-of-scope",
        "Success criteria",
        "Non-goals",
    ),
    "implementation-plan.md": (
        "Plan summary",
        "Ordered slices",
        "allowed_paths",
        "check_command",
        "stop conditions",
    ),
    "planning-audit.md": (
        "Artifacts audited",
        "Completeness",
        "Scope consistency",
        "Verdict",
        "Required fixes",
    ),
}

_WORKSPACE_README = """\
# Planning workspace

> **Non-authority notice:** This workspace stores planning artifacts only.

- It does **not** execute code.
- It does **not** create runs.
- It does **not** approve work.
- It does **not** invoke agents.
- Implementation Plan slices are **not executable** until converted into next-run proposals and explicitly approved.

Fill artifacts in order: Context Pack → Local Agentic Spec → Implementation Plan → Planning Audit.
Record owner decisions under `decisions/` and update `manifest.json` manually.
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def validate_plan_id(plan_id: str) -> None:
    """Reject unsafe or invalid plan identifiers."""
    if not plan_id:
        raise ValueError("plan id must not be empty")
    if plan_id != plan_id.strip():
        raise ValueError("plan id must not contain leading or trailing whitespace")
    if " " in plan_id:
        raise ValueError(f"invalid plan id: {plan_id!r}")
    if "/" in plan_id or "\\" in plan_id or ".." in plan_id:
        raise ValueError(f"invalid plan id: {plan_id!r}")
    if plan_id.startswith(".") or any(part.startswith(".") for part in re.split(r"[\\/]", plan_id)):
        raise ValueError(f"invalid plan id: {plan_id!r}")
    if Path(plan_id).is_absolute():
        raise ValueError(f"invalid plan id: {plan_id!r}")
    if not PLAN_ID_PATTERN.match(plan_id):
        raise ValueError(f"invalid plan id: {plan_id!r}")


def init_planning_workspace(project: Path, plan_id: str) -> Path:
    """Create a DRAFT planning workspace under .agent-os/planning/<plan-id>/."""
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    dest = planning_path(project, plan_id)
    if dest.exists():
        raise FileExistsError(f"planning workspace already exists: {plan_id}")

    created_at = _utc_now()
    dest.mkdir(parents=True)
    for name in PLANNING_SUBDIRS:
        (dest / name).mkdir()

    templates = planning_templates_dir()
    for filename in PLANNING_ARTIFACT_FILES:
        template = templates / filename
        if not template.is_file():
            raise FileNotFoundError(f"planning template missing: {filename}")
        content = template.read_text(encoding="utf-8")
        content = content.replace("{{PLAN_ID}}", plan_id)
        content = content.replace("{{CREATED_AT}}", created_at)
        (dest / filename).write_text(content, encoding="utf-8")

    _write_json(
        dest / "manifest.json",
        {
            "plan_id": plan_id,
            "package_type": "PLANNING_WORKSPACE",
            "status": "DRAFT",
            "created_at": created_at,
            "artifact_paths": {
                "context_pack": "context-pack.md",
                "local_agentic_spec": "local-agentic-spec.md",
                "implementation_plan": "implementation-plan.md",
                "planning_audit": "planning-audit.md",
            },
            "directories": {
                "evidence": "evidence/",
                "decisions": "decisions/",
                "revisions": "revisions/",
            },
            "gates": {
                "planning_owner_decision_required": True,
                "planning_audit_required": True,
                "plan_revision_required": False,
                "run_proposal_allowed": False,
            },
            "authority": {
                "no_execution": True,
                "no_agent_invocation": True,
                "no_run_creation": True,
                "no_self_approval": True,
            },
        },
    )

    (dest / "README.md").write_text(_WORKSPACE_README, encoding="utf-8")
    return dest


@dataclass(frozen=True)
class PlanningStatusReport:
    output: str
    structural_ok: bool


def _inspect_planning_structure(
    dest: Path,
) -> tuple[dict[str, bool], dict[str, bool], bool]:
    file_status = {name: (dest / name).is_file() for name in PLANNING_REQUIRED_FILES}
    dir_status = {name: (dest / name).is_dir() for name in PLANNING_SUBDIRS}
    structural_ok = all(file_status.values()) and all(dir_status.values())
    return file_status, dir_status, structural_ok


def _load_planning_manifest(manifest_path: Path, plan_id: str) -> dict:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest.json missing in planning workspace: {plan_id}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid manifest.json in planning workspace {plan_id}: {exc.msg}"
        ) from exc

    if not isinstance(manifest, dict):
        raise ValueError(
            f"invalid manifest.json in planning workspace {plan_id}: expected object"
        )

    manifest_plan_id = manifest.get("plan_id")
    if manifest_plan_id != plan_id:
        raise ValueError(
            "manifest plan_id mismatch: "
            f"requested {plan_id!r}, found {manifest_plan_id!r}"
        )

    return manifest


def _format_bool(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def format_planning_status(
    dest: Path,
    plan_id: str,
    manifest: dict,
    file_status: dict[str, bool],
    dir_status: dict[str, bool],
    structural_ok: bool,
) -> str:
    lines = [
        f"planning workspace: {dest}",
        f"plan_id: {plan_id}",
        f"status: {manifest.get('status', '?')}",
    ]

    created_at = manifest.get("created_at")
    if created_at:
        lines.append(f"created_at: {created_at}")

    lines.append("artifacts:")
    for name in PLANNING_REQUIRED_FILES:
        state = "present" if file_status[name] else "missing"
        lines.append(f"  {name}: {state}")

    lines.append("directories:")
    for name in PLANNING_SUBDIRS:
        state = "present" if dir_status[name] else "missing"
        lines.append(f"  {name}/: {state}")

    gates = manifest.get("gates")
    if isinstance(gates, dict):
        lines.append("gates:")
        for key in PLANNING_GATE_KEYS:
            if key in gates:
                lines.append(f"  {key}: {_format_bool(gates[key])}")
            else:
                lines.append(f"  {key}: (not in manifest)")

    authority = manifest.get("authority")
    if isinstance(authority, dict):
        lines.append("authority:")
        for key in PLANNING_AUTHORITY_KEYS:
            if key in authority:
                lines.append(f"  {key}: {_format_bool(authority[key])}")

    lines.append(f"structural result: {'OK' if structural_ok else 'BROKEN'}")
    return "\n".join(lines)


def status_planning_workspace(project: Path, plan_id: str) -> PlanningStatusReport:
    """Inspect an existing planning workspace (read-only)."""
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    dest = planning_path(project, plan_id)
    if not dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    manifest = _load_planning_manifest(dest / "manifest.json", plan_id)

    file_status, dir_status, structural_ok = _inspect_planning_structure(dest)

    output = format_planning_status(
        dest,
        plan_id,
        manifest,
        file_status,
        dir_status,
        structural_ok,
    )
    return PlanningStatusReport(output, structural_ok)


def _validate_manifest_fields(manifest: dict, plan_id: str) -> list[str]:
    errors: list[str] = []

    if manifest.get("package_type") != "PLANNING_WORKSPACE":
        found = manifest.get("package_type")
        errors.append(
            f"wrong package_type: expected PLANNING_WORKSPACE, found {found!r}"
        )

    status = manifest.get("status")
    if status is None:
        errors.append("missing manifest field: status")
    elif status not in PLANNING_STATUSES:
        errors.append(f"invalid manifest status: {status!r}")

    if not manifest.get("created_at"):
        errors.append("missing manifest field: created_at")

    artifact_paths = manifest.get("artifact_paths")
    if not isinstance(artifact_paths, dict):
        errors.append("missing manifest field: artifact_paths")
    else:
        for key in PLANNING_ARTIFACT_PATH_KEYS:
            if key not in artifact_paths:
                errors.append(f"missing artifact_paths key: {key}")

    directories = manifest.get("directories")
    if not isinstance(directories, dict):
        errors.append("missing manifest field: directories")
    else:
        for key in PLANNING_DIRECTORY_KEYS:
            if key not in directories:
                errors.append(f"missing directories key: {key}")

    gates = manifest.get("gates")
    if not isinstance(gates, dict):
        errors.append("missing manifest field: gates")
    else:
        for key in PLANNING_GATE_KEYS:
            if key not in gates:
                errors.append(f"missing gate: {key}")

    authority = manifest.get("authority")
    if not isinstance(authority, dict):
        errors.append("missing manifest field: authority")
    else:
        for key in PLANNING_AUTHORITY_KEYS:
            if key not in authority:
                errors.append(f"missing authority flag: {key}")
            elif authority[key] is not True:
                errors.append(f"authority flag must be true: {key}")

    if manifest.get("plan_id") != plan_id:
        errors.append(
            f"manifest plan_id mismatch: requested {plan_id!r}, "
            f"found {manifest.get('plan_id')!r}"
        )

    return errors


def _validate_artifact_file(dest: Path, filename: str) -> list[str]:
    errors: list[str] = []
    path = dest / filename

    if not path.is_file():
        errors.append(f"artifact missing: {filename}")
        return errors

    content = path.read_text(encoding="utf-8")
    if not content.strip():
        errors.append(f"artifact empty: {filename}")
        return errors

    marker = ARTIFACT_TYPE_MARKERS[filename]
    if marker not in content:
        errors.append(f"missing artifact type marker {marker!r} in {filename}")

    if not NON_AUTHORITY_PATTERN.search(content):
        errors.append(f"missing non-authority notice in {filename}")

    for match in PLACEHOLDER_TOKEN_PATTERN.findall(content):
        errors.append(f"placeholder still present in {filename}: {match}")

    lower = content.lower()
    for section in ARTIFACT_REQUIRED_SECTIONS[filename]:
        if section.lower() not in lower:
            errors.append(f"required section missing in {filename}: {section}")

    return errors


def _validate_planning_artifacts(dest: Path) -> list[str]:
    errors: list[str] = []
    for filename in PLANNING_ARTIFACT_FILES:
        errors.extend(_validate_artifact_file(dest, filename))
    return errors


@dataclass(frozen=True)
class PlanningValidationReport:
    output: str
    structural_ok: bool
    manifest_ok: bool
    artifacts_ok: bool

    @property
    def valid(self) -> bool:
        return self.structural_ok and self.manifest_ok and self.artifacts_ok


def format_planning_validation(
    dest: Path,
    plan_id: str,
    manifest: dict,
    structural_ok: bool,
    manifest_errors: list[str],
    artifact_errors: list[str],
) -> str:
    lines = [
        f"planning workspace: {dest}",
        f"plan_id: {plan_id}",
        f"status: {manifest.get('status', '?')}",
        f"structural result: {'OK' if structural_ok else 'BROKEN'}",
        f"manifest validation: {'OK' if not manifest_errors else 'INVALID'}",
    ]
    for error in manifest_errors:
        lines.append(f"  - {error}")

    lines.append(f"artifact validation: {'OK' if not artifact_errors else 'INVALID'}")
    for error in artifact_errors:
        lines.append(f"  - {error}")

    valid = structural_ok and not manifest_errors and not artifact_errors
    lines.append(f"final validation result: {'OK' if valid else 'INVALID'}")
    if valid:
        lines.append(
            "note: no files were modified, no runs were created, no agents were invoked"
        )
    return "\n".join(lines)


def validate_planning_workspace(project: Path, plan_id: str) -> PlanningValidationReport:
    """Weak read-only validation of an existing planning workspace."""
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    dest = planning_path(project, plan_id)
    if not dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    _, _, structural_ok = _inspect_planning_structure(dest)

    manifest_errors: list[str] = []
    manifest: dict = {}
    try:
        manifest = _load_planning_manifest(dest / "manifest.json", plan_id)
        manifest_errors = _validate_manifest_fields(manifest, plan_id)
    except (FileNotFoundError, ValueError) as exc:
        manifest_errors = [str(exc)]
        structural_ok = False

    artifact_errors: list[str] = []
    if structural_ok:
        artifact_errors = _validate_planning_artifacts(dest)
    elif dest.is_dir():
        for filename in PLANNING_ARTIFACT_FILES:
            path = dest / filename
            if not path.is_file():
                artifact_errors.append(f"artifact missing: {filename}")
            elif not path.read_text(encoding="utf-8").strip():
                artifact_errors.append(f"artifact empty: {filename}")

    output = format_planning_validation(
        dest,
        plan_id,
        manifest,
        structural_ok,
        manifest_errors,
        artifact_errors,
    )
    return PlanningValidationReport(
        output,
        structural_ok,
        not manifest_errors,
        not artifact_errors,
    )
