"""Planning workspace bootstrap (registrar only; no execution or agent invocation)."""

from __future__ import annotations

import json
import re
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
