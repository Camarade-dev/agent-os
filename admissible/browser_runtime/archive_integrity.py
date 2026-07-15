"""Umbrella archive-integrity manifest for canonical evidence archives.

``manifest.json`` inside a recovered run archive is scoped to the *recovered
Slice-4 source evidence* only. This module produces and verifies a second,
complementary artifact — ``MANIFEST.sha256`` — that covers **every committed
file** under the archive root (README, the recovery manifest, recovered
agent/session/target artifacts, and the later Slice-5A runtime sidecar,
screenshot, and serialized document).

The manifest is deterministic and repository-portable: entries use
sorted, forward-slash, archive-relative paths and a SHA-256 over exact bytes,
in the standard ``<sha256>  <relpath>`` (two-space) coreutils form. Only
``MANIFEST.sha256`` itself and transient lock/temporary files are excluded —
and transient files must never be present in a canonical archive anyway.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

MANIFEST_NAME = "MANIFEST.sha256"

# Names/patterns that must never appear in a canonical archive and are excluded
# defensively from the umbrella manifest as well.
_EXCLUDED_SUFFIXES = (".runtime.lock", ".tmp")


def _is_excluded(rel: str) -> bool:
    if rel == MANIFEST_NAME:
        return True
    return any(rel.endswith(suffix) for suffix in _EXCLUDED_SUFFIXES)


def compute_manifest_lines(archive_root: str | Path) -> list[str]:
    """Return the deterministic ``<sha256>  <relpath>`` lines for the archive."""

    root = Path(archive_root)
    entries: list[tuple[str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if _is_excluded(rel):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append((rel, digest))
    entries.sort(key=lambda e: e[0])
    return [f"{digest}  {rel}" for rel, digest in entries]


def render_manifest(archive_root: str | Path) -> str:
    """Render the manifest body (trailing newline, LF line endings)."""

    return "\n".join(compute_manifest_lines(archive_root)) + "\n"


def write_manifest(archive_root: str | Path) -> Path:
    """Write ``MANIFEST.sha256`` at the archive root and return its path."""

    root = Path(archive_root)
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_text(render_manifest(root), encoding="utf-8", newline="\n")
    return manifest_path


def verify_manifest(archive_root: str | Path) -> tuple[bool, list[str]]:
    """Verify the on-disk manifest matches the current archive bytes.

    Returns ``(ok, problems)``; ``problems`` is empty iff the umbrella manifest
    is present and byte-for-byte reproduces the current archive contents.
    """

    root = Path(archive_root)
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        return False, [f"{MANIFEST_NAME} is missing"]
    expected = compute_manifest_lines(root)
    actual = manifest_path.read_text(encoding="utf-8").splitlines()
    problems: list[str] = []
    expected_map = dict(line.split("  ", 1)[::-1] for line in expected)
    actual_map = dict(line.split("  ", 1)[::-1] for line in actual)
    for rel, digest in expected_map.items():
        if rel not in actual_map:
            problems.append(f"missing from manifest: {rel}")
        elif actual_map[rel] != digest:
            problems.append(f"hash mismatch: {rel}")
    for rel in actual_map:
        if rel not in expected_map:
            problems.append(f"stale manifest entry (file absent): {rel}")
    return (not problems), problems
