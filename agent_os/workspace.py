"""Workspace and run lifecycle operations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agent_os.paths import (
    META_FILE,
    TEMPLATE_FILES,
    read_text,
    run_path,
    runs_path,
    templates_dir,
    workspace_path,
)
from agent_os.validate import missing_fields_for_run, validate_run_for_closure


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def init_workspace(project: Path) -> Path:
    root = workspace_path(project)
    runs = root / "runs"
    root.mkdir(parents=True, exist_ok=True)
    runs.mkdir(exist_ok=True)

    workspace_meta = root / "workspace.json"
    if not workspace_meta.exists():
        _write_json(
            workspace_meta,
            {
                "protocol": "agent-os",
                "version": "0.1.0",
                "created_at": _utc_now(),
            },
        )
    return root


def _next_run_id(project: Path) -> str:
    runs = runs_path(project)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    prefix = f"{today}-"
    existing = [
        p.name
        for p in runs.iterdir()
        if p.is_dir() and p.name.startswith(prefix)
    ]
    seq = 1
    while f"{prefix}{seq:03d}" in existing:
        seq += 1
    return f"{prefix}{seq:03d}"


def create_mission(project: Path, run_id: str | None = None) -> str:
    init_workspace(project)
    run_id = run_id or _next_run_id(project)
    dest = run_path(project, run_id)
    if dest.exists():
        raise FileExistsError(f"run already exists: {run_id}")
    dest.mkdir(parents=True)

    for name in TEMPLATE_FILES:
        template = templates_dir() / name
        if not template.is_file():
            raise FileNotFoundError(f"template missing: {name}")
        content = template.read_text(encoding="utf-8")
        content = content.replace("{{RUN_ID}}", run_id)
        content = content.replace("{{CREATED_AT}}", _utc_now())
        (dest / name).write_text(content, encoding="utf-8")

    _write_json(
        dest / META_FILE,
        {
            "run_id": run_id,
            "status": "open",
            "created_at": _utc_now(),
            "closed_at": None,
        },
    )
    return run_id


def list_runs(project: Path) -> list[dict]:
    runs = runs_path(project)
    if not runs.is_dir():
        return []

    items: list[dict] = []
    for entry in sorted(runs.iterdir()):
        if not entry.is_dir():
            continue
        meta_path = entry / META_FILE
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        else:
            meta = {"run_id": entry.name, "status": "open"}
        meta["missing"] = missing_fields_for_run(project, entry.name)
        items.append(meta)
    return items


def record_audit(project: Path, run_id: str, verdict: str, notes: str = "") -> None:
    base = run_path(project, run_id)
    if not base.is_dir():
        raise FileNotFoundError(f"run not found: {run_id}")

    audit_path = base / "audit.md"
    template = templates_dir() / "audit.md"
    text = read_text(audit_path) or template.read_text(encoding="utf-8")
    lines = text.splitlines()
    out: list[str] = []
    in_frontmatter = False
    frontmatter_done = False
    for line in lines:
        if line.strip() == "---" and not frontmatter_done:
            if not in_frontmatter:
                in_frontmatter = True
                out.append(line)
                continue
            in_frontmatter = False
            frontmatter_done = True
            out.append(line)
            continue
        if in_frontmatter:
            key = line.split(":", 1)[0].strip().lower() if ":" in line else ""
            if key == "verdict":
                out.append(f"verdict: {verdict}")
                continue
            if key == "recorded_at":
                out.append(f"recorded_at: {_utc_now()}")
                continue
        out.append(line)

    if notes.strip():
        body = "\n".join(out)
        if "## Notes" in body:
            out = [line for line in out if not line.startswith("PLACEHOLDER")]
        else:
            out.extend(["", "## Notes", "", notes.strip()])

    audit_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def close_run(project: Path, run_id: str) -> tuple[bool, list[str]]:
    base = run_path(project, run_id)
    if not base.is_dir():
        return False, [f"run not found: {run_id}"]

    meta_path = base / META_FILE
    if meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("status") == "closed":
            return False, ["run is already closed"]

    result = validate_run_for_closure(project, run_id)
    if not result.ok:
        return False, result.errors

    meta_path = run_path(project, run_id) / META_FILE
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["status"] = "closed"
    meta["closed_at"] = _utc_now()
    _write_json(meta_path, meta)
    return True, []
