"""Bounded local verification v0 for Admissible.

Runs allowlisted, deterministic, read-only checks after bounded file execution.
Not shell authority: no arbitrary commands, npm, network, or deploy.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from admissible.execution.bounded_local_executor import (
    validate_relative_path_inside_workspace,
    validate_workspace_path,
)
from admissible.run_loop import EvidenceRecord

VERIFICATION_ACTOR = "bounded_verification"
VERIFICATION_SCHEMA_VERSION = "admissible_bounded_verification_v0"

ALLOWED_VERIFICATION_CHECKS = frozenset(
    {
        "files_exist",
        "files_non_empty",
        "sha256_matches_write_evidence",
        "html_local_asset_references",
        "no_external_references",
        "node_syntax_check",
        "file_exists",
        "file_sha_matches_latest_execution",
        "file_contains",
        "file_not_empty",
        "all_required_files_present",
        "game_controls_check",
        "game_restart_check",
        "local_usage_check",
    }
)

ALLOWED_VERIFICATION_PROFILES = frozenset({"tiny_game_demo", "acceptance_ledger"})

TINY_GAME_DEMO_FILES = (
    "index.html",
    "style.css",
    "game.js",
    "README.md",
    "LOCAL_DEV.md",
)

TINY_GAME_SCAN_FILES = ("index.html", "style.css", "game.js")

_EXTERNAL_REFERENCE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"https?://",
        r"//[a-z0-9.-]+\.[a-z]{2,}",
        r"\bcdn\.jsdelivr\.net\b",
        r"\bcdnjs\.cloudflare\.com\b",
        r"\bunpkg\.com\b",
        r"\bfonts\.googleapis\.com\b",
        r"\bfonts\.gstatic\.com\b",
        r"\bbootstrapcdn\.com\b",
    )
)

_HTML_ASSET_ATTR_PATTERN = re.compile(
    r"""(?:href|src)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_GAME_CONTROL_SUBCHECKS = (
    ("arrow_up", "ArrowUp"),
    ("arrow_down", "ArrowDown"),
    ("arrow_left", "ArrowLeft"),
    ("arrow_right", "ArrowRight"),
    ("w", "w"),
    ("a", "a"),
    ("s", "s"),
    ("d", "d"),
)

# ``event.code`` physical-key names (RUN_049 PART B.11) for the same eight
# bindings -- ``event.key``/``e.key`` is layout-dependent text, ``.code`` is
# the layout-independent physical key some legitimate implementations use
# instead, e.g. ``event.code === "KeyW"`` for the WASD keys.
_GAME_CONTROL_CODE_NAMES = {
    "ArrowUp": "ArrowUp",
    "ArrowDown": "ArrowDown",
    "ArrowLeft": "ArrowLeft",
    "ArrowRight": "ArrowRight",
    "w": "KeyW",
    "a": "KeyA",
    "s": "KeyS",
    "d": "KeyD",
}


def _js_key_present(content: str, key: str) -> bool:
    """Detect common JavaScript key-binding representations without executing code."""

    patterns = [
        rf"['\"]{re.escape(key)}['\"]",
        rf"\bkeys\.{re.escape(key)}\b",
        rf"\bkeys\[['\"]{re.escape(key)}['\"]\]",
        rf"\be\.key\s*===?\s*['\"]{re.escape(key)}['\"]",
        rf"\bevent\.key\s*===?\s*['\"]{re.escape(key)}['\"]",
    ]
    if len(key) == 1:
        upper = key.upper()
        patterns.extend(
            [
                rf"\bkeys\.{re.escape(upper)}\b",
                rf"\bkeys\[['\"]{re.escape(upper)}['\"]\]",
                rf"\be\.key\s*===?\s*['\"]{re.escape(upper)}['\"]",
                rf"\bevent\.key\s*===?\s*['\"]{re.escape(upper)}['\"]",
            ]
        )
    code_name = _GAME_CONTROL_CODE_NAMES.get(key)
    if code_name:
        patterns.extend(
            [
                rf"['\"]{re.escape(code_name)}['\"]",
                rf"\be\.code\s*===?\s*['\"]{re.escape(code_name)}['\"]",
                rf"\bevent\.code\s*===?\s*['\"]{re.escape(code_name)}['\"]",
                rf"\bkeys\[['\"]{re.escape(code_name)}['\"]\]",
            ]
        )
    return any(re.search(pattern, content) for pattern in patterns)


def _game_controls_subcheck_results(content: str) -> tuple[dict[str, str], list[str], list[str]]:
    subchecks: dict[str, str] = {}
    passed: list[str] = []
    missing: list[str] = []
    for subcheck_id, key in _GAME_CONTROL_SUBCHECKS:
        present = _js_key_present(content, key)
        subchecks[subcheck_id] = "pass" if present else "fail"
        if present:
            passed.append(subcheck_id)
        else:
            missing.append(subcheck_id)
    return subchecks, passed, missing


class BoundedVerificationError(ValueError):
    """Raised when a verification request is invalid or refused."""

    def __init__(self, message: str, *, diagnostic: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic
        self.detail: dict[str, Any] = dict(detail) if detail else {"diagnostic": diagnostic}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _file_sha256_for_write_evidence(target: Path) -> str:
    """Match bounded executor write attestation: hash logical UTF-8 text content."""
    return _sha256_text(target.read_text(encoding="utf-8"))


def _check_display_name(check_id: str) -> str:
    return check_id.replace("_", " ")


@dataclass
class VerificationRequest:
    """One allowlisted verification check with optional target paths."""

    check_id: str
    target_paths: list[str] = field(default_factory=list)
    criterion_id: str | None = None
    contains: list[str] = field(default_factory=list)
    contains_any: list[str] = field(default_factory=list)
    expected_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "target_paths": list(self.target_paths),
            "criterion_id": self.criterion_id,
            "contains": list(self.contains),
            "contains_any": list(self.contains_any),
            "expected_sha256": self.expected_sha256,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationRequest":
        return cls(
            check_id=str(data.get("check_id") or "").strip(),
            target_paths=[str(path) for path in data.get("target_paths") or []],
            criterion_id=(str(data.get("criterion_id")).strip() if data.get("criterion_id") else None),
            contains=[str(value) for value in data.get("contains") or []],
            contains_any=[str(value) for value in data.get("contains_any") or []],
            expected_sha256=(
                str(data.get("expected_sha256")).strip()
                if data.get("expected_sha256")
                else None
            ),
        )


@dataclass
class VerificationResult:
    """Outcome of one bounded verification check."""

    check_id: str
    check_name: str
    target_paths: list[str]
    status: str
    message: str
    timestamp: str
    evidence_payload: dict[str, Any] = field(default_factory=dict)
    criterion_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "target_paths": list(self.target_paths),
            "status": self.status,
            "message": self.message,
            "timestamp": self.timestamp,
            "evidence_payload": dict(self.evidence_payload),
            "criterion_id": self.criterion_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationResult":
        return cls(
            check_id=str(data.get("check_id") or ""),
            check_name=str(data.get("check_name") or ""),
            target_paths=[str(path) for path in data.get("target_paths") or []],
            status=str(data.get("status") or ""),
            message=str(data.get("message") or ""),
            timestamp=str(data.get("timestamp") or ""),
            evidence_payload=dict(data.get("evidence_payload") or {}),
            criterion_id=(str(data.get("criterion_id")) if data.get("criterion_id") else None),
        )


@dataclass
class VerificationEvidence:
    """One bounded verification run and its check results."""

    evidence_id: str
    actor: str
    timestamp: str
    workspace_path: str
    profile: str
    results: list[VerificationResult]
    overall_status: str
    requests: list[VerificationRequest] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "evidence_id": self.evidence_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "workspace_path": self.workspace_path,
            "profile": self.profile,
            "overall_status": self.overall_status,
            "requests": [request.to_dict() for request in self.requests],
            "results": [result.to_dict() for result in self.results],
            "check_count": len(self.results),
            "passed_count": sum(1 for result in self.results if result.status == "pass"),
            "failed_count": sum(1 for result in self.results if result.status == "fail"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationEvidence":
        return cls(
            evidence_id=str(data.get("evidence_id") or ""),
            actor=str(data.get("actor") or VERIFICATION_ACTOR),
            timestamp=str(data.get("timestamp") or ""),
            workspace_path=str(data.get("workspace_path") or ""),
            profile=str(data.get("profile") or ""),
            overall_status=str(data.get("overall_status") or ""),
            requests=[
                VerificationRequest.from_dict(request)
                for request in data.get("requests") or []
            ],
            results=[
                VerificationResult.from_dict(result) for result in data.get("results") or []
            ],
        )


def validate_verification_request(request: VerificationRequest) -> None:
    """Reject unknown check ids or arbitrary command strings."""
    check_id = str(request.check_id or "").strip()
    if not check_id:
        raise BoundedVerificationError(
            "verification check_id is required",
            diagnostic="missing_check_id",
        )
    if check_id not in ALLOWED_VERIFICATION_CHECKS:
        raise BoundedVerificationError(
            f"verification check_id is not allowlisted: {check_id!r}",
            diagnostic="unsupported_verification_check",
            detail={"check_id": check_id, "allowed_checks": sorted(ALLOWED_VERIFICATION_CHECKS)},
        )
    forbidden_tokens = ("npm", "shell", "deploy", "curl", "wget", "pip", "yarn", "pnpm", "git ")
    lowered = check_id.lower()
    for token in forbidden_tokens:
        if token in lowered:
            raise BoundedVerificationError(
                f"verification check_id implies forbidden capability: {check_id!r}",
                diagnostic="forbidden_verification_check",
            )
    if check_id in ("file_exists", "file_not_empty", "file_contains") and len(
        request.target_paths
    ) != 1:
        raise BoundedVerificationError(
            f"{check_id} requires exactly one target path",
            diagnostic="invalid_verification_target",
        )
    if check_id == "all_required_files_present" and not request.target_paths:
        raise BoundedVerificationError(
            "all_required_files_present requires at least one target path",
            diagnostic="invalid_verification_target",
        )
    if check_id == "file_contains" and not (request.contains or request.contains_any):
        raise BoundedVerificationError(
            "file_contains requires contains and/or contains_any text",
            diagnostic="missing_verification_expectation",
        )
    if check_id in ("game_controls_check", "local_usage_check") and len(request.target_paths) != 1:
        raise BoundedVerificationError(
            f"{check_id} requires exactly one target path",
            diagnostic="invalid_verification_target",
        )


def default_requests_for_profile(profile: str, *, include_node_syntax_check: bool = False) -> list[VerificationRequest]:
    """Return the allowlisted verification plan for one named profile."""
    if profile not in ALLOWED_VERIFICATION_PROFILES:
        raise BoundedVerificationError(
            f"verification profile is not allowlisted: {profile!r}",
            diagnostic="unsupported_verification_profile",
            detail={"profile": profile, "allowed_profiles": sorted(ALLOWED_VERIFICATION_PROFILES)},
        )

    if profile == "acceptance_ledger":
        return []

    requests = [
        VerificationRequest("files_exist", list(TINY_GAME_DEMO_FILES)),
        VerificationRequest("files_non_empty", list(TINY_GAME_DEMO_FILES)),
        VerificationRequest("sha256_matches_write_evidence", []),
        VerificationRequest("html_local_asset_references", ["index.html"]),
        VerificationRequest("no_external_references", list(TINY_GAME_SCAN_FILES)),
    ]
    if include_node_syntax_check:
        requests.append(VerificationRequest("node_syntax_check", ["game.js"]))
    return requests


def _write_evidence_records(evidence_records: list[EvidenceRecord]) -> list[EvidenceRecord]:
    return [
        record
        for record in evidence_records
        if record.source == "bounded_executor" and record.evidence_type == "bounded_local_write"
    ]


def _check_files_exist(workspace: Path, target_paths: list[str], *, timestamp: str) -> VerificationResult:
    missing = [path for path in target_paths if not (workspace / path).is_file()]
    if missing:
        return VerificationResult(
            check_id="files_exist",
            check_name=_check_display_name("files_exist"),
            target_paths=target_paths,
            status="fail",
            message=f"Missing expected files: {', '.join(missing)}",
            timestamp=timestamp,
            evidence_payload={"missing_paths": missing, "checked_paths": target_paths},
        )
    return VerificationResult(
        check_id="files_exist",
        check_name=_check_display_name("files_exist"),
        target_paths=target_paths,
        status="pass",
        message=f"All {len(target_paths)} expected files exist.",
        timestamp=timestamp,
        evidence_payload={"checked_paths": target_paths},
    )


def _check_files_non_empty(workspace: Path, target_paths: list[str], *, timestamp: str) -> VerificationResult:
    empty = [
        path
        for path in target_paths
        if (workspace / path).is_file() and (workspace / path).stat().st_size == 0
    ]
    if empty:
        return VerificationResult(
            check_id="files_non_empty",
            check_name=_check_display_name("files_non_empty"),
            target_paths=target_paths,
            status="fail",
            message=f"Expected non-empty files are empty: {', '.join(empty)}",
            timestamp=timestamp,
            evidence_payload={"empty_paths": empty, "checked_paths": target_paths},
        )
    return VerificationResult(
        check_id="files_non_empty",
        check_name=_check_display_name("files_non_empty"),
        target_paths=target_paths,
        status="pass",
        message=f"All {len(target_paths)} expected files are non-empty.",
        timestamp=timestamp,
        evidence_payload={"checked_paths": target_paths},
    )


def _check_sha256_matches_write_evidence(
    workspace: Path,
    write_records: list[EvidenceRecord],
    *,
    timestamp: str,
) -> VerificationResult:
    latest_by_path: dict[str, EvidenceRecord] = {}
    for record in write_records:
        rel_path = str(record.file_path_or_note or "").strip()
        if rel_path and record.sha256:
            latest_by_path[rel_path] = record

    mismatches: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    for rel_path, record in sorted(latest_by_path.items()):
        expected = record.sha256
        target = workspace / rel_path
        if not target.is_file():
            mismatches.append(
                {
                    "path": rel_path,
                    "reason": "file_missing",
                    "expected_sha256": expected,
                    "action_id": record.action_id,
                }
            )
            continue
        actual = _file_sha256_for_write_evidence(target)
        checked.append(
            {
                "path": rel_path,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "action_id": record.action_id,
            }
        )
        if actual != expected:
            mismatches.append(
                {
                    "path": rel_path,
                    "reason": "sha256_mismatch",
                    "expected_sha256": expected,
                    "actual_sha256": actual,
                    "action_id": record.action_id,
                }
            )
    if not checked:
        return VerificationResult(
            check_id="sha256_matches_write_evidence",
            check_name=_check_display_name("sha256_matches_write_evidence"),
            target_paths=[],
            status="fail",
            message="No bounded write evidence records were available to verify.",
            timestamp=timestamp,
            evidence_payload={"checked_records": 0},
        )
    if mismatches:
        return VerificationResult(
            check_id="sha256_matches_write_evidence",
            check_name=_check_display_name("sha256_matches_write_evidence"),
            target_paths=[entry["path"] for entry in checked],
            status="fail",
            message=f"sha256 mismatch or missing file for {len(mismatches)} write evidence record(s).",
            timestamp=timestamp,
            evidence_payload={"checked_records": checked, "mismatches": mismatches},
        )
    return VerificationResult(
        check_id="sha256_matches_write_evidence",
        check_name=_check_display_name("sha256_matches_write_evidence"),
        target_paths=[entry["path"] for entry in checked],
        status="pass",
        message=f"sha256 values match latest bounded write evidence for {len(checked)} file(s).",
        timestamp=timestamp,
        evidence_payload={"checked_records": checked},
    )


def _is_local_html_reference(value: str) -> bool:
    ref = str(value or "").strip()
    if not ref or ref.startswith("#"):
        return True
    if "://" in ref:
        return False
    if ref.startswith("//"):
        return False
    return True


def _check_html_local_asset_references(
    workspace: Path,
    target_paths: list[str],
    *,
    timestamp: str,
) -> VerificationResult:
    rel_path = target_paths[0] if target_paths else "index.html"
    target = workspace / rel_path
    if not target.is_file():
        return VerificationResult(
            check_id="html_local_asset_references",
            check_name=_check_display_name("html_local_asset_references"),
            target_paths=[rel_path],
            status="fail",
            message=f"HTML file not found: {rel_path}",
            timestamp=timestamp,
            evidence_payload={"missing_path": rel_path},
        )
    content = target.read_text(encoding="utf-8")
    external_refs = [
        match.group(1)
        for match in _HTML_ASSET_ATTR_PATTERN.finditer(content)
        if not _is_local_html_reference(match.group(1))
    ]
    if external_refs:
        return VerificationResult(
            check_id="html_local_asset_references",
            check_name=_check_display_name("html_local_asset_references"),
            target_paths=[rel_path],
            status="fail",
            message=f"Non-local asset references found in {rel_path}.",
            timestamp=timestamp,
            evidence_payload={"external_references": external_refs},
        )
    return VerificationResult(
        check_id="html_local_asset_references",
        check_name=_check_display_name("html_local_asset_references"),
        target_paths=[rel_path],
        status="pass",
        message=f"HTML asset references in {rel_path} are local-only.",
        timestamp=timestamp,
        evidence_payload={"checked_path": rel_path},
    )


def _scan_external_references(content: str) -> list[str]:
    hits: list[str] = []
    for pattern in _EXTERNAL_REFERENCE_PATTERNS:
        for match in pattern.finditer(content):
            hits.append(match.group(0))
    return hits


def _check_no_external_references(
    workspace: Path,
    target_paths: list[str],
    *,
    timestamp: str,
) -> VerificationResult:
    findings: dict[str, list[str]] = {}
    for rel_path in target_paths:
        target = workspace / rel_path
        if not target.is_file():
            findings[rel_path] = ["file_missing"]
            continue
        hits = _scan_external_references(target.read_text(encoding="utf-8"))
        if hits:
            findings[rel_path] = hits
    if findings:
        return VerificationResult(
            check_id="no_external_references",
            check_name=_check_display_name("no_external_references"),
            target_paths=target_paths,
            status="fail",
            message="Forbidden external or network references found in generated assets.",
            timestamp=timestamp,
            evidence_payload={"findings": findings},
        )
    return VerificationResult(
        check_id="no_external_references",
        check_name=_check_display_name("no_external_references"),
        target_paths=target_paths,
        status="pass",
        message="No external or network references found in generated assets.",
        timestamp=timestamp,
        evidence_payload={"checked_paths": target_paths},
    )


def _generic_target(workspace: Path, request: VerificationRequest) -> tuple[str, Path]:
    rel_path = request.target_paths[0]
    return rel_path, validate_relative_path_inside_workspace(workspace, rel_path)


def _check_file_exists(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    exists = target.is_file()
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status="pass" if exists else "fail",
        message=(f"File exists: {rel_path}" if exists else f"File is missing: {rel_path}"),
        timestamp=timestamp,
        evidence_payload={"path": rel_path, "exists": exists},
        criterion_id=request.criterion_id,
    )


def _check_file_not_empty(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    size = target.stat().st_size if target.is_file() else 0
    passed = target.is_file() and size > 0
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status="pass" if passed else "fail",
        message=(
            f"File is non-empty: {rel_path} ({size} bytes)"
            if passed
            else f"File is missing or empty: {rel_path}"
        ),
        timestamp=timestamp,
        evidence_payload={"path": rel_path, "bytes": size},
        criterion_id=request.criterion_id,
    )


def _check_file_contains(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    if not target.is_file():
        return VerificationResult(
            check_id=request.check_id,
            check_name=_check_display_name(request.check_id),
            target_paths=[rel_path],
            status="fail",
            message=f"File is missing: {rel_path}",
            timestamp=timestamp,
            evidence_payload={"path": rel_path, "missing": True},
            criterion_id=request.criterion_id,
        )
    content = target.read_text(encoding="utf-8", errors="replace")
    missing_all = [needle for needle in request.contains if needle not in content]
    any_match = not request.contains_any or any(
        needle in content for needle in request.contains_any
    )
    passed = not missing_all and any_match
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status="pass" if passed else "fail",
        message=(
            f"Expected text is present in {rel_path}."
            if passed
            else f"Expected text is missing from {rel_path}."
        ),
        timestamp=timestamp,
        evidence_payload={
            "failure_class": None if passed else "content_missing",
            "path": rel_path,
            "contains": list(request.contains),
            "contains_any": list(request.contains_any),
            "missing": missing_all,
            "contains_any_matched": any_match,
            "repair_hint": (
                None
                if passed
                else f"Add expected markers to {rel_path}: {', '.join(missing_all)}"
            ),
        },
        criterion_id=request.criterion_id,
    )


def _check_file_sha_matches_latest_execution(
    workspace: Path,
    request: VerificationRequest,
    write_records: list[EvidenceRecord],
    *,
    timestamp: str,
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    expected = request.expected_sha256
    if not expected:
        for record in write_records:
            if str(record.file_path_or_note or "") == rel_path and record.sha256:
                expected = record.sha256
    actual = _file_sha256_for_write_evidence(target) if target.is_file() else None
    passed = bool(expected and actual and expected == actual)
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status="pass" if passed else "fail",
        message=(
            f"File sha256 matches latest execution evidence: {rel_path}"
            if passed
            else f"File sha256 does not match latest execution evidence: {rel_path}"
        ),
        timestamp=timestamp,
        evidence_payload={
            "path": rel_path,
            "expected_sha256": expected,
            "actual_sha256": actual,
        },
        criterion_id=request.criterion_id,
    )


def _check_all_required_files_present(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    missing: list[str] = []
    for rel_path in request.target_paths:
        target = validate_relative_path_inside_workspace(workspace, rel_path)
        if not target.is_file():
            missing.append(rel_path)
    passed = not missing
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=list(request.target_paths),
        status="pass" if passed else "fail",
        message=(
            f"All {len(request.target_paths)} required files are present."
            if passed
            else f"Missing required files: {', '.join(missing)}"
        ),
        timestamp=timestamp,
        evidence_payload={
            "failure_class": None if passed else "file_missing",
            "checked_paths": list(request.target_paths),
            "missing_paths": missing,
            "repair_hint": (
                None
                if passed
                else f"Create missing mandatory file(s): {', '.join(missing)}"
            ),
        },
        criterion_id=request.criterion_id,
    )


def _check_game_controls(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    if not target.is_file():
        return VerificationResult(
            check_id=request.check_id,
            check_name=_check_display_name(request.check_id),
            target_paths=[rel_path],
            status="fail",
            message=f"File is missing: {rel_path}",
            timestamp=timestamp,
            evidence_payload={
                "failure_class": "file_missing",
                "path": rel_path,
                "missing": ["arrow_up", "arrow_down", "arrow_left", "arrow_right", "w", "a", "s", "d"],
                "subchecks": {name: "fail" for name, _ in _GAME_CONTROL_SUBCHECKS},
                "passed_subchecks": {},
                "failed_subchecks": {
                    "arrow_controls": "fail",
                    "wasd_controls": "fail",
                },
                "repair_hint": f"Add Arrow and WASD controls to {rel_path}.",
            },
            criterion_id=request.criterion_id,
        )
    content = target.read_text(encoding="utf-8", errors="replace")
    subchecks, passed, missing = _game_controls_subcheck_results(content)
    arrow_pass = all(subchecks[name] == "pass" for name in ("arrow_up", "arrow_down", "arrow_left", "arrow_right"))
    wasd_pass = all(subchecks[name] == "pass" for name in ("w", "a", "s", "d"))
    grouped = {
        "arrow_controls": "pass" if arrow_pass else "fail",
        "wasd_controls": "pass" if wasd_pass else "fail",
    }
    passed_group = {key: value for key, value in grouped.items() if value == "pass"}
    failed_group = {key: value for key, value in grouped.items() if value == "fail"}
    passed = not missing
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status="pass" if passed else "fail",
        message=(
            f"Game controls present in {rel_path}."
            if passed
            else f"Expected controls missing from {rel_path}."
        ),
        timestamp=timestamp,
        evidence_payload={
            "failure_class": None if passed else "content_missing",
            "path": rel_path,
            "subchecks": subchecks,
            "passed_subchecks": passed_group,
            "failed_subchecks": failed_group,
            "missing": missing,
            "repair_hint": (
                None
                if passed
                else f"Add missing control bindings to {rel_path}: {', '.join(missing)}"
            ),
        },
        criterion_id=request.criterion_id,
    )


_GAME_RESTART_RESET_FN_RE = re.compile(
    r"\b(?:resetGame|restartGame|initGame|reset|init)\s*\(",
    re.I,
)
_GAME_RESTART_INLINE_RESET_RE = re.compile(
    r"\b(?:score|player|collectibles?)\s*=\s*(?:0|\[\]|null|Object\.create\(null\)|\{\})",
    re.I,
)


def _r_key_binding_present(content: str) -> bool:
    patterns = [
        r"""e\.key\s*===?\s*['"]r['"]""",
        r"""e\.key\s*===?\s*['"]R['"]""",
        r"""event\.key\s*===?\s*['"]r['"]""",
        r"""event\.key\s*===?\s*['"]R['"]""",
        r"""e\.code\s*===?\s*['"]KeyR['"]""",
        r"""event\.code\s*===?\s*['"]KeyR['"]""",
        r"""case\s+['"]r['"]\s*:""",
        r"""case\s+['"]R['"]\s*:""",
        r"""case\s+['"]KeyR['"]\s*:""",
        r"""['"]r['"]\s*:\s*(?:true|reset|restart|init)""",
        r"""['"]R['"]\s*:\s*(?:true|reset|restart|init)""",
    ]
    return any(re.search(pattern, content) for pattern in patterns)


def _restart_handler_present(content: str) -> bool:
    if _GAME_RESTART_RESET_FN_RE.search(content):
        return True
    if re.search(r"if\s*\([^)]*(?:key|code)[^)]*['\"]r['\"]", content, re.I):
        return True
    return False


def _player_state_reset_present(content: str) -> bool:
    patterns = [
        r"player\.(?:x|y)\s*=",
        r"placePlayer\s*\(",
        r"player\s*=\s*\{",
    ]
    return any(re.search(pattern, content) for pattern in patterns)


def _score_reset_present(content: str) -> bool:
    patterns = [
        r"score\s*=\s*0",
        r"setScore\s*\(\s*0\s*\)",
        r"updateScoreDisplay\s*\(",
        r"scoreEl\.textContent\s*=\s*['\"]0['\"]",
    ]
    return any(re.search(pattern, content) for pattern in patterns)


def _collectible_or_game_state_reset_present(content: str) -> bool:
    patterns = [
        r"collectibles?\s*=\s*\[\]",
        r"spawnCollectibles?\s*\(",
        r"initCollectibles?\s*\(",
        r"initGems\s*\(",
        r"init\s*\(",
    ]
    return any(re.search(pattern, content) for pattern in patterns)


def _game_restart_subcheck_results(content: str) -> tuple[dict[str, str], list[str], list[str]]:
    checks = {
        "r_key_binding_present": _r_key_binding_present(content),
        "restart_handler_present": _restart_handler_present(content),
        "player_state_reset_present": _player_state_reset_present(content),
        "score_reset_present": _score_reset_present(content),
        "collectible_or_game_state_reset_present": _collectible_or_game_state_reset_present(
            content
        ),
    }
    subchecks = {name: "pass" if passed else "fail" for name, passed in checks.items()}
    passed = [name for name, ok in checks.items() if ok]
    missing = [name for name, ok in checks.items() if not ok]
    return subchecks, passed, missing


def _check_game_restart(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    if not target.is_file():
        return VerificationResult(
            check_id=request.check_id,
            check_name=_check_display_name(request.check_id),
            target_paths=[rel_path],
            status="fail",
            message=f"File is missing: {rel_path}",
            timestamp=timestamp,
            evidence_payload={
                "failure_class": "file_missing",
                "path": rel_path,
                "subchecks": {name: "fail" for name in (
                    "r_key_binding_present",
                    "restart_handler_present",
                    "player_state_reset_present",
                    "score_reset_present",
                    "collectible_or_game_state_reset_present",
                )},
                "failed_subchecks": {
                    "r_key_binding_present": "fail",
                    "restart_handler_present": "fail",
                    "player_state_reset_present": "fail",
                    "score_reset_present": "fail",
                    "collectible_or_game_state_reset_present": "fail",
                },
                "repair_hint": f"Add R-key restart handling to {rel_path}.",
            },
            criterion_id=request.criterion_id,
        )
    content = target.read_text(encoding="utf-8", errors="replace")
    subchecks, passed, missing = _game_restart_subcheck_results(content)
    mandatory = (
        "r_key_binding_present",
        "restart_handler_present",
        "score_reset_present",
    )
    passed_mandatory = all(name in passed for name in mandatory)
    passed_all = not missing
    status = "pass" if passed_mandatory else "fail"
    matched_patterns = [name for name in passed]
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status=status,
        message=(
            f"Restart behavior present in {rel_path}."
            if status == "pass"
            else f"Restart behavior incomplete in {rel_path}."
        ),
        timestamp=timestamp,
        evidence_payload={
            "failure_class": None if status == "pass" else "content_missing",
            "path": rel_path,
            "subchecks": subchecks,
            "passed_subchecks": {name: "pass" for name in passed},
            "failed_subchecks": {name: "fail" for name in missing},
            "matched_patterns": matched_patterns,
            "repair_hint": (
                None
                if status == "pass"
                else (
                    f"Add R-key restart to {rel_path}: bind r/R and reset score/player/collectibles "
                    f"(missing: {', '.join(missing)})"
                )
            ),
        },
        criterion_id=request.criterion_id,
    )


def _check_local_usage(
    workspace: Path, request: VerificationRequest, *, timestamp: str
) -> VerificationResult:
    rel_path, target = _generic_target(workspace, request)
    marker_groups = [list(request.contains)] if request.contains else []
    if not marker_groups:
        marker_groups = [["open", "index.html"]]
    if not target.is_file():
        return VerificationResult(
            check_id=request.check_id,
            check_name=_check_display_name(request.check_id),
            target_paths=[rel_path],
            status="fail",
            message=f"Local usage file is missing: {rel_path}",
            timestamp=timestamp,
            evidence_payload={
                "failure_class": "file_missing",
                "path": rel_path,
                "accepted_marker_groups": marker_groups,
                "missing_groups": marker_groups,
                "repair_hint": f"Create {rel_path} with local open/index.html usage instructions.",
            },
            criterion_id=request.criterion_id,
        )
    content = target.read_text(encoding="utf-8", errors="replace")
    missing_groups = [group for group in marker_groups if not all(marker in content for marker in group)]
    passed = not missing_groups
    return VerificationResult(
        check_id=request.check_id,
        check_name=_check_display_name(request.check_id),
        target_paths=[rel_path],
        status="pass" if passed else "fail",
        message=(
            f"Local usage markers present in {rel_path}."
            if passed
            else f"Local usage markers missing from {rel_path}."
        ),
        timestamp=timestamp,
        evidence_payload={
            "failure_class": None if passed else "content_missing",
            "path": rel_path,
            "accepted_marker_groups": marker_groups,
            "missing_groups": missing_groups,
            "repair_hint": (
                None
                if passed
                else f"Add local usage instructions to {rel_path} including: {', '.join(marker_groups[0])}"
            ),
        },
        criterion_id=request.criterion_id,
    )


def _check_node_syntax(
    workspace: Path,
    target_paths: list[str],
    *,
    timestamp: str,
) -> VerificationResult:
    rel_path = target_paths[0] if target_paths else "game.js"
    if rel_path != "game.js":
        return VerificationResult(
            check_id="node_syntax_check",
            check_name=_check_display_name("node_syntax_check"),
            target_paths=[rel_path],
            status="fail",
            message="node_syntax_check is bounded to game.js only.",
            timestamp=timestamp,
            evidence_payload={"rejected_path": rel_path},
        )
    target = workspace / rel_path
    if not target.is_file():
        return VerificationResult(
            check_id="node_syntax_check",
            check_name=_check_display_name("node_syntax_check"),
            target_paths=[rel_path],
            status="fail",
            message=f"JavaScript file not found: {rel_path}",
            timestamp=timestamp,
            evidence_payload={"missing_path": rel_path},
        )
    node_path = shutil.which("node")
    if not node_path:
        return VerificationResult(
            check_id="node_syntax_check",
            check_name=_check_display_name("node_syntax_check"),
            target_paths=[rel_path],
            status="pass",
            message="Skipped node syntax check: node is not available in this environment.",
            timestamp=timestamp,
            evidence_payload={"skipped": True, "reason": "node_unavailable"},
        )
    completed = subprocess.run(
        [node_path, "--check", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return VerificationResult(
            check_id="node_syntax_check",
            check_name=_check_display_name("node_syntax_check"),
            target_paths=[rel_path],
            status="fail",
            message="node --check reported a syntax error in game.js.",
            timestamp=timestamp,
            evidence_payload={
                "command": ["node", "--check", rel_path],
                "returncode": completed.returncode,
                "stderr": (completed.stderr or "").strip(),
            },
        )
    return VerificationResult(
        check_id="node_syntax_check",
        check_name=_check_display_name("node_syntax_check"),
        target_paths=[rel_path],
        status="pass",
        message="node --check passed for game.js.",
        timestamp=timestamp,
        evidence_payload={"command": ["node", "--check", rel_path], "returncode": 0},
    )


def run_single_verification_check(
    *,
    workspace_path: str | Path,
    request: VerificationRequest,
    write_evidence_records: list[EvidenceRecord] | None = None,
    timestamp: str | None = None,
) -> VerificationResult:
    validate_verification_request(request)
    workspace = validate_workspace_path(workspace_path)
    ts = timestamp or _now_iso()
    write_records = _write_evidence_records(write_evidence_records or [])

    if request.check_id == "files_exist":
        return _check_files_exist(workspace, request.target_paths, timestamp=ts)
    if request.check_id == "files_non_empty":
        return _check_files_non_empty(workspace, request.target_paths, timestamp=ts)
    if request.check_id == "sha256_matches_write_evidence":
        return _check_sha256_matches_write_evidence(workspace, write_records, timestamp=ts)
    if request.check_id == "html_local_asset_references":
        return _check_html_local_asset_references(workspace, request.target_paths, timestamp=ts)
    if request.check_id == "no_external_references":
        return _check_no_external_references(workspace, request.target_paths, timestamp=ts)
    if request.check_id == "node_syntax_check":
        return _check_node_syntax(workspace, request.target_paths, timestamp=ts)
    if request.check_id == "file_exists":
        return _check_file_exists(workspace, request, timestamp=ts)
    if request.check_id == "file_not_empty":
        return _check_file_not_empty(workspace, request, timestamp=ts)
    if request.check_id == "file_contains":
        return _check_file_contains(workspace, request, timestamp=ts)
    if request.check_id == "file_sha_matches_latest_execution":
        return _check_file_sha_matches_latest_execution(
            workspace, request, write_records, timestamp=ts
        )
    if request.check_id == "all_required_files_present":
        return _check_all_required_files_present(workspace, request, timestamp=ts)
    if request.check_id == "game_controls_check":
        return _check_game_controls(workspace, request, timestamp=ts)
    if request.check_id == "game_restart_check":
        return _check_game_restart(workspace, request, timestamp=ts)
    if request.check_id == "local_usage_check":
        return _check_local_usage(workspace, request, timestamp=ts)

    raise BoundedVerificationError(
        f"verification check is not implemented: {request.check_id!r}",
        diagnostic="unsupported_verification_check",
    )


def run_bounded_verification(
    *,
    workspace_path: str | Path,
    profile: str = "tiny_game_demo",
    requests: list[VerificationRequest] | None = None,
    write_evidence_records: list[EvidenceRecord] | None = None,
    include_node_syntax_check: bool = False,
    timestamp: str | None = None,
) -> VerificationEvidence:
    """Run one explicit bounded verification pass for an allowlisted profile."""
    if profile not in ALLOWED_VERIFICATION_PROFILES:
        raise BoundedVerificationError(
            f"verification profile is not allowlisted: {profile!r}",
            diagnostic="unsupported_verification_profile",
        )
    plan = list(requests) if requests is not None else default_requests_for_profile(
        profile,
        include_node_syntax_check=include_node_syntax_check,
    )
    for request in plan:
        validate_verification_request(request)

    ts = timestamp or _now_iso()
    workspace = validate_workspace_path(workspace_path)
    results = [
        run_single_verification_check(
            workspace_path=workspace,
            request=request,
            write_evidence_records=write_evidence_records,
            timestamp=ts,
        )
        for request in plan
    ]
    overall_status = (
        "pass" if results and all(result.status == "pass" for result in results) else "fail"
    )
    return VerificationEvidence(
        evidence_id=f"verification_{uuid.uuid4().hex[:12]}",
        actor=VERIFICATION_ACTOR,
        timestamp=ts,
        workspace_path=str(workspace),
        profile=profile,
        results=results,
        overall_status=overall_status,
        requests=plan,
    )
