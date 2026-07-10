"""Runtime evidence storage (PART K).

Writes structured JSON evidence and bounded PNG screenshots under an
Admissible-owned evidence root -- never among application deliverables,
and never a durable copy of browser profile data.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from admissible.browser_runtime.models import BrowserRuntimeEvidence

EVIDENCE_ROOT_RELATIVE = Path(".admissible") / "runtime-evidence"
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,128}$")


class EvidenceStoreError(ValueError):
    """Raised when an evidence path would collide, escape its root, or is unsafe."""


def _validate_id(identifier: str, *, label: str) -> str:
    if not _SAFE_ID_RE.match(identifier or ""):
        raise EvidenceStoreError(f"unsafe {label}: {identifier!r}")
    return identifier


def evidence_directory_for(control_root: str | Path, evidence_id: str) -> Path:
    """Return (without creating) the isolated directory for one evidence_id.

    Raises if ``evidence_id`` is not a safe identifier or the resolved path
    would escape the evidence root (PART K.58).
    """

    _validate_id(evidence_id, label="evidence_id")
    root = (Path(control_root) / EVIDENCE_ROOT_RELATIVE).resolve()
    target = (root / evidence_id).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise EvidenceStoreError(f"evidence_id escapes the evidence root: {evidence_id!r}") from None
    return target


def _sha256_and_len(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def write_runtime_evidence(
    control_root: str | Path,
    evidence: BrowserRuntimeEvidence,
    *,
    screenshot_blobs: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Persist one run's evidence JSON and bounded screenshots.

    Returns a manifest recording each written file's relative path, sha256,
    and byte length (PART K.55). Never writes raw browser profile data
    (PART K.56) -- only the structured evidence this module is given.
    """

    directory = evidence_directory_for(control_root, evidence.evidence_id)
    directory.mkdir(parents=True, exist_ok=True)

    manifest_files: list[dict[str, Any]] = []

    evidence_payload = json.dumps(evidence.to_dict(), ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    evidence_path = directory / "evidence.json"
    evidence_path.write_bytes(evidence_payload)
    sha, length = _sha256_and_len(evidence_payload)
    manifest_files.append({"relative_path": "evidence.json", "sha256": sha, "byte_length": length})

    blobs = screenshot_blobs or {}
    if blobs:
        screenshots_dir = directory / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        known_ids = {shot.get("screenshot_id") for shot in evidence.screenshots}
        for screenshot_id, blob in blobs.items():
            if screenshot_id not in known_ids:
                continue  # only ever write screenshots the evidence itself already declared
            _validate_id(screenshot_id, label="screenshot_id")
            path = screenshots_dir / f"{screenshot_id}.png"
            path.write_bytes(blob)
            sha, length = _sha256_and_len(blob)
            manifest_files.append({"relative_path": f"screenshots/{screenshot_id}.png", "sha256": sha, "byte_length": length})

    manifest = {"evidence_id": evidence.evidence_id, "directory": str(directory), "files": manifest_files}
    manifest_path = directory / "manifest.json"
    manifest_path.write_bytes(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"))
    return manifest
