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

    file_status = {name: (dest / name).is_file() for name in PLANNING_REQUIRED_FILES}
    dir_status = {name: (dest / name).is_dir() for name in PLANNING_SUBDIRS}
    structural_ok = all(file_status.values()) and all(dir_status.values())

    output = format_planning_status(
        dest,
        plan_id,
        manifest,
        file_status,
        dir_status,
        structural_ok,
    )
    return PlanningStatusReport(output, structural_ok)
