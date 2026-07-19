"""Read-only discovery of persisted runs under a caller-supplied parent.

Discovery is bounded to immediate child directories, deterministically ordered,
refuses reparse-point escape, ignores unrelated directories safely and reports
duplicate run identities as explicit conflicts. It never mutates the filesystem.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from . import evidence_reader
from .enums import PresenceState


@dataclass(frozen=True)
class DiscoveredRun:
    """One directory that presents as an Admissible run."""

    run_id: str
    run_root: str
    directory_name: str
    final_status_presence: PresenceState
    session_id: str | None
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "run_id": self.run_id,
            "run_root": self.run_root,
            "directory_name": self.directory_name,
            "final_status_presence": self.final_status_presence.value,
            "session_id": self.session_id,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class RunConflict:
    """Two or more discovered runs that share the same run identity."""

    run_id: str
    run_roots: tuple[str, ...]

    def to_json(self) -> dict:
        return {"run_id": self.run_id, "run_roots": list(self.run_roots)}


@dataclass(frozen=True)
class RunDiscoveryResult:
    """Deterministic result of scanning a parent directory."""

    parent: str
    runs: tuple[DiscoveredRun, ...]
    conflicts: tuple[RunConflict, ...]
    ignored_directories: tuple[str, ...]
    skipped_reparse: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "parent": self.parent,
            "runs": [run.to_json() for run in self.runs],
            "conflicts": [conflict.to_json() for conflict in self.conflicts],
            "ignored_directories": list(self.ignored_directories),
            "skipped_reparse": list(self.skipped_reparse),
            "notes": list(self.notes),
        }


def _looks_like_run(root_real: Path) -> bool:
    """A run directory has an immediate, non-reparse ``evidence`` subdirectory."""

    evidence_dir = evidence_reader.safe_child_path(root_real, "evidence")
    if evidence_dir is None:
        return False
    try:
        return evidence_dir.is_dir()
    except OSError:
        return False


def _read_session_id(root_real: Path, max_bytes: int) -> tuple[str | None, PresenceState]:
    read = evidence_reader.read_json(root_real, "evidence/final-status.json", max_bytes=max_bytes)
    session_id: str | None = None
    if read.ok and isinstance(read.data, Mapping):
        candidate = read.data.get("session_id")
        if isinstance(candidate, str) and candidate:
            session_id = candidate
    return session_id, read.presence


def load_run_root(
    run_root: Path | str,
    *,
    max_bytes: int = evidence_reader.DEFAULT_MAX_JSON_BYTES,
) -> DiscoveredRun:
    """Load a single explicit run root directly, without scanning a parent."""

    root_real = evidence_reader.resolve_root(run_root)
    directory_name = root_real.name
    session_id, presence = _read_session_id(root_real, max_bytes)
    notes: list[str] = []
    if not _looks_like_run(root_real):
        notes.append("no immediate evidence/ directory found under this run root")
    run_id = session_id or directory_name
    return DiscoveredRun(
        run_id=run_id,
        run_root=str(root_real),
        directory_name=directory_name,
        final_status_presence=presence,
        session_id=session_id,
        notes=tuple(notes),
    )


def discover_runs(
    parent: Path | str,
    *,
    max_bytes: int = evidence_reader.DEFAULT_MAX_JSON_BYTES,
) -> RunDiscoveryResult:
    """Scan immediate children of ``parent`` for runs, deterministically."""

    parent_real = evidence_reader.resolve_root(parent)
    notes: list[str] = []
    try:
        child_names, skipped = evidence_reader.list_child_directories(parent_real)
    except NotADirectoryError:
        return RunDiscoveryResult(
            parent=str(parent_real),
            runs=(),
            conflicts=(),
            ignored_directories=(),
            skipped_reparse=(),
            notes=("parent is not a directory",),
        )

    runs: list[DiscoveredRun] = []
    ignored: list[str] = []
    for name in child_names:
        child_real = evidence_reader.resolve_root(parent_real / name)
        if not _looks_like_run(child_real):
            ignored.append(name)
            continue
        session_id, presence = _read_session_id(child_real, max_bytes)
        run_id = session_id or name
        run_notes: tuple[str, ...] = ()
        if session_id is None:
            run_notes = ("run id derived from directory name (no persisted session_id)",)
        runs.append(
            DiscoveredRun(
                run_id=run_id,
                run_root=str(child_real),
                directory_name=name,
                final_status_presence=presence,
                session_id=session_id,
                notes=run_notes,
            )
        )

    # runs is already in lexical directory order (child_names is sorted).
    by_id: dict[str, list[DiscoveredRun]] = {}
    for run in runs:
        by_id.setdefault(run.run_id, []).append(run)
    conflicts = tuple(
        RunConflict(run_id=run_id, run_roots=tuple(sorted(r.run_root for r in group)))
        for run_id, group in sorted(by_id.items())
        if len(group) > 1
    )
    if conflicts:
        notes.append(f"{len(conflicts)} duplicate run id(s) detected")

    return RunDiscoveryResult(
        parent=str(parent_real),
        runs=tuple(runs),
        conflicts=conflicts,
        ignored_directories=tuple(ignored),
        skipped_reparse=tuple(skipped),
        notes=tuple(notes),
    )
