"""Workspace and run lifecycle operations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
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


def add_evidence(
    project: Path,
    run_id: str,
    note: str,
    evidence_type: str = "note",
    artifact_path: str | None = None,
) -> None:
    """Append a structured evidence block to evidence.md (registrar only)."""
    base = run_path(project, run_id)
    if not base.is_dir():
        raise FileNotFoundError(f"run not found: {run_id}")

    evidence_path = base / "evidence.md"
    if not evidence_path.is_file():
        raise FileNotFoundError(f"evidence file missing: {run_id}")

    if not note.strip():
        raise ValueError("note must not be empty or whitespace-only")

    timestamp = _utc_now()
    block_lines = [
        "",
        f"## Evidence Entry — {timestamp}",
        "",
        f"type: {evidence_type}",
    ]
    if artifact_path:
        block_lines.append(f"path: {artifact_path}")
    block_lines.append(f"claim: {note.strip()}")

    existing = evidence_path.read_text(encoding="utf-8")
    if existing and not existing.endswith("\n"):
        existing += "\n"
    evidence_path.write_text(existing + "\n".join(block_lines) + "\n", encoding="utf-8")


COMMAND_OUTPUT_MAX_BYTES = 8192


def _read_bounded_text(path: Path, max_bytes: int) -> tuple[str, bool]:
    """Read file as text; return content and whether it was truncated."""
    raw = path.read_bytes()
    truncated = len(raw) > max_bytes
    excerpt = raw[:max_bytes].decode("utf-8", errors="replace")
    return excerpt, truncated


def add_evidence_command_output(
    project: Path,
    run_id: str,
    command: str,
    output_file: str,
    note: str,
) -> None:
    """Register a declared command and owner-supplied output file (registrar only; no execution)."""
    base = run_path(project, run_id)
    if not base.is_dir():
        raise FileNotFoundError(f"run not found: {run_id}")

    evidence_path = base / "evidence.md"
    if not evidence_path.is_file():
        raise FileNotFoundError(f"evidence file missing: {run_id}")

    if not command.strip():
        raise ValueError("command must not be empty or whitespace-only")

    if not note.strip():
        raise ValueError("note must not be empty or whitespace-only")

    if not output_file.strip():
        raise ValueError("output file path must not be empty")

    referenced = Path(output_file.strip())
    if not referenced.is_file():
        raise FileNotFoundError(f"output file not found: {output_file.strip()}")

    output_text, truncated = _read_bounded_text(referenced, COMMAND_OUTPUT_MAX_BYTES)
    timestamp = _utc_now()
    path_str = output_file.strip()

    block_lines = [
        "",
        f"## Evidence Entry — {timestamp}",
        "",
        "type: command-output",
        f"command: {command.strip()}",
        f"path: {path_str}",
        f"claim: {note.strip()}",
        "",
    ]
    if truncated:
        block_lines.append(
            f"(output truncated; see referenced path for full output: {path_str})"
        )
        block_lines.append("")
    block_lines.extend(["```text", output_text, "```"])

    existing = evidence_path.read_text(encoding="utf-8")
    if existing and not existing.endswith("\n"):
        existing += "\n"
    evidence_path.write_text(existing + "\n".join(block_lines) + "\n", encoding="utf-8")


def add_evidence_file(
    project: Path,
    run_id: str,
    file_path: str,
    note: str,
) -> None:
    """Register an existing local file path as evidence (registrar only; no copy)."""
    base = run_path(project, run_id)
    if not base.is_dir():
        raise FileNotFoundError(f"run not found: {run_id}")

    evidence_path = base / "evidence.md"
    if not evidence_path.is_file():
        raise FileNotFoundError(f"evidence file missing: {run_id}")

    if not file_path.strip():
        raise ValueError("file path must not be empty")

    if not note.strip():
        raise ValueError("note must not be empty or whitespace-only")

    referenced = Path(file_path.strip())
    if not referenced.is_file():
        raise FileNotFoundError(f"referenced file not found: {file_path.strip()}")

    add_evidence(
        project,
        run_id,
        note,
        evidence_type="file",
        artifact_path=file_path.strip(),
    )


_EVIDENCE_ENTRY_HEADER = re.compile(r"^## Evidence Entry — (.+)$", re.MULTILINE)


@dataclass(frozen=True)
class EvidenceEntry:
    timestamp: str
    evidence_type: str
    claim: str
    artifact_path: str | None = None
    command: str | None = None


def parse_evidence_entries(text: str) -> list[EvidenceEntry]:
    """Parse structured evidence blocks appended by add_evidence."""
    entries: list[EvidenceEntry] = []
    parts = _EVIDENCE_ENTRY_HEADER.split(text)
    for index in range(1, len(parts), 2):
        timestamp = parts[index].strip()
        block = parts[index + 1] if index + 1 < len(parts) else ""
        evidence_type = "note"
        artifact_path: str | None = None
        command: str | None = None
        claim: str | None = None
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith("type:"):
                evidence_type = stripped[5:].strip() or "note"
            elif stripped.startswith("path:"):
                artifact_path = stripped[5:].strip() or None
            elif stripped.startswith("command:"):
                command = stripped[8:].strip() or None
            elif stripped.startswith("claim:"):
                claim = stripped[6:].strip()
        if claim is not None:
            entries.append(
                EvidenceEntry(
                    timestamp=timestamp,
                    evidence_type=evidence_type,
                    claim=claim,
                    artifact_path=artifact_path,
                    command=command,
                )
            )
    return entries


def format_evidence_index(run_id: str, entries: list[EvidenceEntry]) -> str:
    lines = [f"Evidence for run {run_id}:"]
    for index, entry in enumerate(entries, start=1):
        lines.append(
            f"{index}. {entry.timestamp} [{entry.evidence_type}] {entry.claim}"
        )
        if entry.command:
            lines.append(f"   command: {entry.command}")
        if entry.artifact_path:
            lines.append(f"   path: {entry.artifact_path}")
    return "\n".join(lines)


def list_evidence(project: Path, run_id: str) -> str:
    """Read and index structured evidence entries (read-only)."""
    base = run_path(project, run_id)
    if not base.is_dir():
        raise FileNotFoundError(f"run not found: {run_id}")

    evidence_path = base / "evidence.md"
    if not evidence_path.is_file():
        raise FileNotFoundError(f"evidence file missing: {run_id}")

    text = evidence_path.read_text(encoding="utf-8")
    return format_evidence_index(run_id, parse_evidence_entries(text))


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
