"""Reconstruct the operator review model from persisted evidence only.

Everything the review surface displays is derived here, from bytes on disk:

- the immutable V0 session (``session.v0.json``);
- the recovered Slice-4 recovery manifest (``manifest.json``);
- the Slice-5A runtime sidecar (``runtime-store/<sid>.runtime.json``) and its
  screenshot / serialized DOM artifacts;
- the umbrella archive-integrity manifest (``MANIFEST.sha256``).

No authoritative fact is taken on trust. Each load is accompanied by an
integrity check that re-hashes the underlying bytes and cross-checks the three
independent records of truth (the umbrella manifest, the recovery manifest, and
the embedded evidence hashes). Any failure — a missing file, a hash mismatch, an
incomplete set of artifacts — is recorded as an explicit uncertainty entry and
surfaced in the model; it is never silently dropped or displayed as if sound.

This module performs reads only. It opens files ``rb``/``r`` and never writes,
renames, or deletes anything under the archive.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admissible.browser_runtime import archive_integrity

SCHEMA_VERSION = "admissible_v0_review_model_v1"

SESSION_FILE = "session.v0.json"
RECOVERY_MANIFEST_FILE = "manifest.json"
MISSION_FILE = "neon_serpents_mission.txt"
UMBRELLA_MANIFEST_FILE = archive_integrity.MANIFEST_NAME

# Fixed, whitelisted runtime evidence artifacts (logical name -> filename).
SCREENSHOT_ARTIFACT = "screenshot.png"
DOM_ARTIFACT = "document.html"


class ReviewEvidenceError(RuntimeError):
    """Evidence could not be located or parsed at all (hard load failure)."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


@dataclass
class IntegrityReport:
    """A visible, append-only ledger of integrity checks.

    ``ok`` is true only when every recorded check passed and no problems were
    accumulated. A false ``ok`` classifies the whole model as ``uncertain``.
    """

    checks: list[dict[str, Any]] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)

    @property
    def problems(self) -> list[dict[str, Any]]:
        return [c for c in self.checks if not c["ok"]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "uncertain": not self.ok,
            "checks": list(self.checks),
            "problems": self.problems,
        }


@dataclass(frozen=True)
class ReviewModel:
    schema_version: str
    archive_root: str
    session_id: str
    facts: dict[str, Any]
    runtime: dict[str, Any]
    integrity: dict[str, Any]
    fingerprints: dict[str, str]
    evidence_artifacts: dict[str, dict[str, Any]]

    @property
    def uncertain(self) -> bool:
        return not self.integrity.get("ok", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "archive_root": self.archive_root,
            "session_id": self.session_id,
            "uncertain": self.uncertain,
            "facts": self.facts,
            "runtime": self.runtime,
            "integrity": self.integrity,
            "fingerprints": self.fingerprints,
            "evidence_artifacts": self.evidence_artifacts,
        }


def _load_json_bytes(path: Path) -> tuple[bytes, Any]:
    raw = path.read_bytes()
    return raw, json.loads(raw.decode("utf-8"))


def build_review_model(archive_root: str | Path) -> ReviewModel:
    """Reconstruct the review model from persisted evidence under ``archive_root``.

    Read-only. Raises :class:`ReviewEvidenceError` only when the minimal
    authoritative files cannot be located or parsed at all; recoverable
    integrity failures are represented as uncertainty inside the returned model.
    """

    root = Path(archive_root)
    integ = IntegrityReport()

    if not root.is_dir():
        raise ReviewEvidenceError(f"archive root not found: {root}")

    # ---- session -------------------------------------------------------
    session_path = root / SESSION_FILE
    if not session_path.is_file():
        raise ReviewEvidenceError(f"missing {SESSION_FILE}")
    session_raw, session = _load_json_bytes(session_path)
    session_sha = _sha256_bytes(session_raw)
    session_id = str(session.get("session_id") or "")

    # ---- recovery manifest --------------------------------------------
    recovery: dict[str, Any] = {}
    recovery_path = root / RECOVERY_MANIFEST_FILE
    if recovery_path.is_file():
        try:
            _, recovery = _load_json_bytes(recovery_path)
        except (ValueError, OSError) as exc:
            integ.record("recovery_manifest_parse", False, str(exc))
    else:
        integ.record("recovery_manifest_present", False, f"missing {RECOVERY_MANIFEST_FILE}")

    archived_files = recovery.get("archived_files", {}) if isinstance(recovery, dict) else {}
    target_evidence_hashes = recovery.get("target_evidence_hashes", {}) if isinstance(recovery, dict) else {}

    # ---- umbrella manifest --------------------------------------------
    umbrella_path = root / UMBRELLA_MANIFEST_FILE
    if umbrella_path.is_file():
        ok, problems = archive_integrity.verify_manifest(root)
        integ.record(
            "umbrella_manifest",
            ok,
            "verified" if ok else "; ".join(problems),
        )
        manifest_sha = _sha256_file(umbrella_path)
    else:
        integ.record("umbrella_manifest", False, f"missing {UMBRELLA_MANIFEST_FILE}")
        manifest_sha = ""

    # Cross-check the session bytes against the recovery manifest record.
    recorded_session = archived_files.get(SESSION_FILE, {})
    if isinstance(recorded_session, dict) and recorded_session.get("sha256"):
        integ.record(
            "session_hash_matches_recovery_manifest",
            recorded_session["sha256"] == session_sha,
            f"recorded={recorded_session.get('sha256')} observed={session_sha}",
        )

    # ---- runtime sidecar ----------------------------------------------
    runtime_dir = root / "runtime-store"
    runtime_json_path = runtime_dir / f"{session_id}.runtime.json"
    runtime_view: dict[str, Any] = {}
    evidence_artifacts: dict[str, dict[str, Any]] = {}

    if not runtime_json_path.is_file():
        integ.record("runtime_sidecar_present", False, f"missing {runtime_json_path.name}")
    else:
        runtime_raw, runtime_doc = _load_json_bytes(runtime_json_path)
        runtime_sha = _sha256_bytes(runtime_raw)
        result = runtime_doc.get("result", {}) if isinstance(runtime_doc, dict) else {}
        declared_artifacts = runtime_doc.get("artifacts", []) if isinstance(runtime_doc, dict) else []
        runtime_view = _runtime_view(result)

        # Verify the two runtime evidence artifacts (screenshot + serialized DOM).
        artifacts_dir = runtime_dir / f"{session_id}.runtime.d"
        evidence_artifacts = _verify_runtime_artifacts(
            artifacts_dir=artifacts_dir,
            result=result,
            declared_artifacts=declared_artifacts,
            integ=integ,
        )
        runtime_view["runtime_sha256"] = runtime_sha
    # runtime_sha may be undefined if sidecar absent; guard below.
    runtime_sha = runtime_view.get("runtime_sha256", "")

    # ---- target files --------------------------------------------------
    materialized = session.get("materialized_evidence", []) or []
    target_files = _verify_target_files(
        root=root,
        materialized=materialized,
        target_evidence_hashes=target_evidence_hashes,
        integ=integ,
    )

    facts = _session_facts(session, target_files, root)

    fingerprints = {
        "session_sha256": session_sha,
        "runtime_sha256": runtime_sha,
        "archive_manifest_sha256": manifest_sha,
    }

    return ReviewModel(
        schema_version=SCHEMA_VERSION,
        archive_root=str(root),
        session_id=session_id,
        facts=facts,
        runtime=runtime_view,
        integrity=integ.to_dict(),
        fingerprints=fingerprints,
        evidence_artifacts=evidence_artifacts,
    )


def _session_facts(session: dict[str, Any], target_files: list[dict[str, Any]], root: Path) -> dict[str, Any]:
    contract = session.get("contract", {}) or {}
    counters = session.get("counters", {}) or {}
    batch_history = session.get("batch_history", []) or []
    receipts = session.get("execution_receipt_history", []) or []
    materialized = session.get("materialized_evidence", []) or []
    mandatory = list(contract.get("mandatory_paths") or session.get("mandatory_paths") or [])
    materialized_paths = {m.get("path") for m in materialized}
    remaining = [p for p in mandatory if p not in materialized_paths]

    admitted_ops = 0
    for batch in batch_history:
        admitted_ops += len(batch.get("admitted_operation_ids") or [])

    structural = session.get("structural_verification", {}) or {}

    # The immutable mission text: prefer the contract's embedded specification
    # (part of the immutable session); fall back to the operator mission file.
    mission_text = contract.get("mission_specification")
    if not mission_text:
        mission_path = root / MISSION_FILE
        mission_text = mission_path.read_text(encoding="utf-8") if mission_path.is_file() else ""

    return {
        "session_id": session.get("session_id"),
        "phase": session.get("phase"),
        "revision": session.get("revision"),
        "schema_version": session.get("schema_version"),
        "mission_text": mission_text,
        "contract_id": contract.get("contract_id"),
        # provider (Cursor) invocation count
        "provider_invocation_count": int(counters.get("invocations", len(session.get("invocation_history", []) or []))),
        # consumed provider results (one per admitted proposal batch)
        "consumed_result_count": len(batch_history),
        "admitted_operation_count": admitted_ops,
        "physical_receipt_count": len(receipts),
        "file_evidence_count": len(materialized),
        "mandatory_paths": mandatory,
        "mandatory_paths_remaining": remaining,
        "mandatory_paths_remaining_count": len(remaining),
        "target_files": target_files,
        "structural_verification": {
            "passed": bool(structural.get("passed")),
            "check_count": len(structural.get("checks") or []),
            "checks": [
                {
                    "path": c.get("path"),
                    "check_kind": c.get("check_kind"),
                    "passed": bool(c.get("passed")),
                    "exists": c.get("exists"),
                    "non_empty": c.get("non_empty"),
                    "inside_workspace": c.get("inside_workspace"),
                    "expected_sha256": c.get("expected_sha256"),
                    "observed_sha256": c.get("observed_sha256"),
                    "failure_code": c.get("failure_code"),
                }
                for c in (structural.get("checks") or [])
            ],
        },
    }


def _runtime_view(result: dict[str, Any]) -> dict[str, Any]:
    """Project the raw runtime result into the fields the operator must see."""

    def _count(key: str) -> int:
        value = result.get(key)
        return len(value) if isinstance(value, list) else 0

    return {
        "verdict": result.get("verdict"),
        "reason_codes": list(result.get("reason_codes") or []),
        "termination_reason": result.get("termination_reason"),
        "schema_version": result.get("schema_version"),
        "attempt_id": result.get("attempt_id"),
        "entry_point": result.get("entry_point"),
        "started_at": result.get("started_at"),
        "completed_at": result.get("completed_at"),
        "bounds": result.get("bounds"),
        # Chrome / runtime identity
        "browser_available": result.get("browser_available"),
        "browser_executable": result.get("browser_executable"),
        "browser_version": result.get("browser_version"),
        "provider_id": result.get("provider_id"),
        # navigation and load observations
        "navigation_ok": result.get("navigation_ok"),
        "page_loaded": result.get("page_loaded"),
        "dom_content_loaded": result.get("dom_content_loaded"),
        "ready_state": result.get("ready_state"),
        "final_url": result.get("final_url"),
        "loopback_origin": result.get("loopback_origin"),
        # exception / error / network observations
        "uncaught_exception_count": _count("uncaught_exceptions"),
        "uncaught_exceptions": list(result.get("uncaught_exceptions") or []),
        "console_error_count": _count("console_errors"),
        "console_errors": list(result.get("console_errors") or []),
        "external_request_attempt_count": _count("external_request_attempts"),
        "external_request_attempts": list(result.get("external_request_attempts") or []),
        # target byte-identity across verification
        "tree_hash_before": result.get("tree_hash_before"),
        "tree_hash_after": result.get("tree_hash_after"),
        "tree_byte_identical": result.get("tree_byte_identical"),
        # containment / cleanup
        "browser_exit": result.get("browser_exit"),
        "server_exit": result.get("server_exit"),
        "orphan_processes": list(result.get("orphan_processes") or []),
        "orphan_process_count": _count("orphan_processes"),
        # whether provider / retry / repair occurred (must be false)
        "provider_invoked": result.get("provider_invoked"),
        "provider_error": result.get("provider_error"),
        "retry_attempted": result.get("retry_attempted"),
        "repair_attempted": result.get("repair_attempted"),
        # evidence hashes
        "screenshot_sha256": result.get("screenshot_sha256"),
        "screenshot_byte_count": result.get("screenshot_byte_count"),
        "dom_document_sha256": result.get("dom_document_sha256"),
        "dom_document_byte_count": result.get("dom_document_byte_count"),
    }


def _verify_runtime_artifacts(
    *,
    artifacts_dir: Path,
    result: dict[str, Any],
    declared_artifacts: list[dict[str, Any]],
    integ: IntegrityReport,
) -> dict[str, dict[str, Any]]:
    declared_by_name = {a.get("relative_path"): a for a in declared_artifacts if isinstance(a, dict)}
    expected_shas = {
        SCREENSHOT_ARTIFACT: result.get("screenshot_sha256"),
        DOM_ARTIFACT: result.get("dom_document_sha256"),
    }
    out: dict[str, dict[str, Any]] = {}
    for name, expected in expected_shas.items():
        path = artifacts_dir / name
        entry: dict[str, Any] = {"filename": name, "expected_sha256": expected}
        if not expected:
            entry.update({"present": False, "integrity_ok": False, "detail": "no recorded hash"})
            integ.record(f"artifact:{name}", False, "no recorded hash in runtime result")
            out[name] = entry
            continue
        if not path.is_file():
            entry.update({"present": False, "integrity_ok": False, "detail": "file missing"})
            integ.record(f"artifact:{name}", False, "file missing")
            out[name] = entry
            continue
        observed = _sha256_file(path)
        declared = declared_by_name.get(name, {})
        matches_result = observed == expected
        matches_manifest = (declared.get("sha256") == observed) if declared else True
        ok = matches_result and matches_manifest
        entry.update(
            {
                "present": True,
                "observed_sha256": observed,
                "byte_count": path.stat().st_size,
                "integrity_ok": ok,
                "detail": "verified" if ok else "hash mismatch",
            }
        )
        integ.record(f"artifact:{name}", ok, entry["detail"])
        out[name] = entry
    return out


def _verify_target_files(
    *,
    root: Path,
    materialized: list[dict[str, Any]],
    target_evidence_hashes: dict[str, Any],
    integ: IntegrityReport,
) -> list[dict[str, Any]]:
    target_dir = root / "target"
    out: list[dict[str, Any]] = []
    for item in materialized:
        rel = item.get("path")
        expected = item.get("sha256")
        entry: dict[str, Any] = {
            "path": rel,
            "expected_sha256": expected,
            "byte_count": item.get("byte_count"),
        }
        file_path = target_dir / rel if rel else None
        if not rel or file_path is None or not file_path.is_file():
            entry.update({"present": False, "integrity_ok": False, "detail": "target file missing"})
            integ.record(f"target:{rel}", False, "target file missing")
            out.append(entry)
            continue
        observed = _sha256_file(file_path)
        recovery_sha = (target_evidence_hashes.get(rel, {}) or {}).get("sha256")
        matches_evidence = observed == expected
        matches_recovery = (recovery_sha == observed) if recovery_sha else True
        ok = matches_evidence and matches_recovery
        entry.update(
            {
                "present": True,
                "observed_sha256": observed,
                "integrity_ok": ok,
                "detail": "verified" if ok else "hash mismatch",
            }
        )
        integ.record(f"target:{rel}", ok, entry["detail"])
        out.append(entry)
    return out
