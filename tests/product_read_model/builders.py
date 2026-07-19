"""Synthetic run-root builders for product-read-model tests.

These construct temporary run directories whose evidence layout mirrors the real
persisted schema (attempt-0 native record naming under ``evidence/native-execution``).
Every builder writes only into the supplied temporary directory; no committed
test touches a real historical run root.
"""

from __future__ import annotations

import json
from pathlib import Path

SESSION_ID = "run-synthetic"
GATE_ID = "synthetic-gate"
ATTEMPT = 0


def _write(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


class RunRootBuilder:
    """Builds a synthetic run root with a controllable set of evidence records."""

    def __init__(self, root: Path, *, session_id: str = SESSION_ID, gate_id: str = GATE_ID):
        self.root = root
        self.session_id = session_id
        self.gate_id = gate_id
        self.evidence = root / "evidence"
        self.native = self.evidence / "native-execution"
        self.native.mkdir(parents=True, exist_ok=True)
        (self.evidence / "delegated-state").mkdir(parents=True, exist_ok=True)
        (self.native / "artifacts").mkdir(parents=True, exist_ok=True)

    # -- naming ---------------------------------------------------------------

    def _native(self, suffix: str) -> Path:
        return self.native / f"{self.session_id}.{self.gate_id}.attempt-{ATTEMPT}.{suffix}"

    # -- records --------------------------------------------------------------

    def final_status(self, *, status: str = "PRECAPTURE_ELIGIBILITY_FAILED", detail: str = "immutable behavioral verifier did not pass", canary_success: bool = False, **extra: object) -> "RunRootBuilder":
        payload = {
            "session_id": self.session_id,
            "status": status,
            "detail": detail,
            "canary_success": canary_success,
            "phase": "GATE_EXECUTING",
            "request_fingerprint": "rq-fp",
            "result_fingerprint": "rs-fp",
            "checkpoint_fingerprint": None,
            "behavioral_evidence_fingerprint": None,
        }
        payload.update(extra)
        _write(self.evidence / "final-status.json", payload)
        return self

    def delegated_gate(self, *, human_disposition: object = None, human_boundary_reason: object = None, objective: str = "Deliver the thing.", mission_id: str = "mission-synthetic", checkpoint_history: list | None = None) -> "RunRootBuilder":
        payload = {
            "schema_version": "admissible_delegated_gate_session_v1",
            "session_id": self.session_id,
            "phase": "GATE_EXECUTING",
            "human_disposition": human_disposition,
            "human_boundary_reason": human_boundary_reason,
            "checkpoint_history": checkpoint_history if checkpoint_history is not None else [],
            "audit_history": [],
            "mission": {"mission_id": mission_id, "mission_fingerprint": "mission-fp"},
            "gate_plan": {
                "ordered_gate_contracts": [
                    {"gate_id": self.gate_id, "objective": objective, "contract_fingerprint": "contract-fp"}
                ]
            },
        }
        _write(self.evidence / "delegated-state" / f"{self.session_id}.delegated-gate.json", payload)
        return self

    def preflight(self, *, secret: bool = False) -> "RunRootBuilder":
        payload = {
            "classification": "act-2a-native-delegated-executor-canary",
            "authorization_payload": {
                "run_id": self.session_id,
                "session_id": self.session_id,
                "mission_fingerprint": "mission-fp",
                "gate_contract_fingerprint": "contract-fp",
                "required_commit_message": "feat: deliver",
                "selected_model": "auto",
                "clean_worktree_required": True,
                "timeout_seconds": 3600,
                "budgets": {"provider_invocations": 1, "native_phase_attempts": 1},
                "canary_non_claims": ["sandboxing is not established"],
                "attestation_non_claims": ["publisher identity is not established"],
            },
        }
        if secret:
            payload["authorization_payload"]["owner_phrase"] = "hunter2-secret"
            payload["authorization_payload"]["api_key"] = "sk-should-not-appear"
            payload["authorization_payload"]["environment"] = {"PATH": "C:/x", "SECRET_ENV": "leak"}
        _write(self.evidence / "canary-preflight.json", payload)
        return self

    def request(self, **extra: object) -> "RunRootBuilder":
        payload = {
            "schema_version": "admissible_native_execution_request_v2",
            "session_id": self.session_id,
            "gate_id": self.gate_id,
            "backend_identity": "cursor-agent-native-oneshot",
            "mission_fingerprint": "mission-fp",
            "request_fingerprint": "rq-fp",
            "executable": "C:/x/node.exe",
        }
        payload.update(extra)
        _write(self._native("native-request.json"), payload)
        return self

    def attempt_reserved(self, *, timeout_seconds: int = 3600) -> "RunRootBuilder":
        _write(
            self._native("native-attempt-reserved.json"),
            {
                "schema_version": "admissible_native_attempt_reserved_v1",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "reserved_at": "2026-07-18T23:43:19.219334Z",
                "timeout_seconds": timeout_seconds,
                "execution_attempt_index": ATTEMPT,
            },
        )
        return self

    def process_started(self, *, process_id: int = 22432) -> "RunRootBuilder":
        _write(
            self._native("native-process-started.json"),
            {
                "schema_version": "admissible_native_process_started_v1",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "process_id": process_id,
                "executable": "C:/x/node.exe",
                "process_started_at": "2026-07-18T23:43:19.471619Z",
            },
        )
        return self

    def process_observation(self, *, exit_code: int = 0, ended_at: str = "2026-07-18T23:48:52.466718Z") -> "RunRootBuilder":
        _write(
            self._native("native-process-observation.json"),
            {
                "schema_version": "admissible_native_process_observation_v1",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "process_completion_observed": True,
                "process": {
                    "process_id": 22432,
                    "executable": "C:/x/node.exe",
                    "exit_code": exit_code,
                    "termination_reason": "completed",
                    "timed_out": False,
                    "started_at": "2026-07-18T23:43:19.471619Z",
                    "ended_at": ended_at,
                    "output_truncation_occurred": False,
                    "orphan_process_ids": [],
                    "cleanup_confirmed": True,
                    "cleanup_observation": "proven_empty",
                },
                "initial_workspace": {"git_head": "aaa", "material_tree_hash": "t0"},
                "final_workspace": {"git_head": "bbb", "material_tree_hash": "t1", "git_status": "", "git_remotes": []},
                "source_observation": {"mutated": False},
            },
        )
        return self

    def result(self, *, exit_code: int = 0, changed: list | None = None) -> "RunRootBuilder":
        _write(
            self._native("native-result.json"),
            {
                "schema_version": "admissible_native_execution_result_v2",
                "session_id": self.session_id,
                "status": "PROCESS_SUCCEEDED",
                "process_exit_code": exit_code,
                "executable": "C:/x/node.exe",
                "started_at": "2026-07-18T23:43:19.471619Z",
                "ended_at": "2026-07-18T23:48:52.466718Z",
                "termination_reason": "completed",
                "timed_out": False,
                "initial_git_head": "aaa",
                "final_git_head": "bbb",
                "initial_material_tree_hash": "t0",
                "final_material_tree_hash": "t1",
                "final_git_porcelain_status": "",
                "final_git_remotes": [],
                "commits_added": 1,
                "workspace_material_changed": True,
                "source_repository_mutated": False,
                "changed_material_files": changed if changed is not None else ["README.md"],
                "output_truncation_occurred": False,
                "orphan_process_ids": [],
                "cleanup_confirmed": True,
                "cleanup_observation": "proven_empty",
                "stdout_artifact": {
                    "artifact_id": "stdout",
                    "purpose": "stdout",
                    "relative_path": "artifacts/stdout.txt",
                    "byte_count": 1051977,
                    "sha256": "abc",
                    "truncated": False,
                    "schema_version": "admissible_native_execution_artifact_v2",
                },
                "stderr_artifact": {
                    "artifact_id": "stderr",
                    "purpose": "stderr",
                    "relative_path": "artifacts/stderr.txt",
                    "byte_count": 0,
                    "sha256": "e3b0",
                    "truncated": False,
                    "schema_version": "admissible_native_execution_artifact_v2",
                },
            },
        )
        return self

    def eligibility(self, *, eligible: bool = True, reasons: list | None = None) -> "RunRootBuilder":
        _write(
            self._native("native-execution-eligibility.json"),
            {
                "schema_version": "admissible_native_execution_eligibility_v1",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "eligible": eligible,
                "material_paths_compliant": eligible,
                "workspace_clean": True,
                "remotes_absent": True,
                "exactly_one_commit": True,
                "commit_message_compliant": True,
                "source_and_root_integrity": True,
                "process_status_eligible": True,
                "ineligibility_reasons": reasons if reasons is not None else ([] if eligible else ["required_material_paths_missing"]),
                "evaluated_at": "2026-07-18T23:48:54.924712Z",
            },
        )
        return self

    def behavioral(self, *, exit_code: int = 1, stderr_bytes: int = 570, stderr_text: bytes | None = None) -> "RunRootBuilder":
        stderr_rel = "artifacts/behavioral.stderr.bin"
        stdout_rel = "artifacts/behavioral.stdout.bin"
        payload_stderr = stderr_text if stderr_text is not None else (b"E" * stderr_bytes)
        (self.native / stderr_rel).write_bytes(payload_stderr)
        (self.native / stdout_rel).write_bytes(b"")
        _write(
            self._native("native-behavioral.json"),
            {
                "schema_version": "admissible_native_canary_behavioral_evidence_v1",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "exit_code": exit_code,
                "timed_out": False,
                "evidence_fingerprint": "bh-fp",
                "stdout": {
                    "artifact_id": "bh-stdout",
                    "purpose": "behavioral-stdout",
                    "relative_path": stdout_rel,
                    "byte_count": 0,
                    "sha256": "e3b0",
                    "truncated": False,
                    "schema_version": "admissible_native_execution_artifact_v2",
                },
                "stderr": {
                    "artifact_id": "bh-stderr",
                    "purpose": "behavioral-stderr",
                    "relative_path": stderr_rel,
                    "byte_count": len(payload_stderr),
                    "sha256": "bh-stderr-sha",
                    "truncated": False,
                    "schema_version": "admissible_native_execution_artifact_v2",
                },
            },
        )
        return self

    def terminal(self, *, status: str = "PRECAPTURE_FAILED", failure_category: str = "pre_capture_eligibility", diagnostic: str = "immutable behavioral verifier did not pass") -> "RunRootBuilder":
        _write(
            self._native("native-terminal.json"),
            {
                "schema_version": "admissible_native_canary_terminal_v2",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "status": status,
                "failure_category": failure_category,
                "diagnostic": diagnostic,
                "result_fingerprint": "rs-fp",
                "created_at": "2026-07-18T23:48:56.990221Z",
            },
        )
        return self

    def product_block(self, payload: dict) -> "RunRootBuilder":
        """Write an explicit persisted product-verdict block (forward-compat)."""

        _write(self.evidence / "product-verdict.json", payload)
        return self

    def raw_file(self, relative: str, content: bytes) -> "RunRootBuilder":
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return self


def build_material_refusal(root: Path) -> Path:
    """Run refused before the behavioral verifier (material paths missing)."""

    b = RunRootBuilder(root)
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).eligibility(eligible=False)
    b.terminal(status="PRECAPTURE_FAILED", failure_category="result_ineligible", diagnostic="result ineligible: required_material_paths_missing")
    b.final_status(detail="result ineligible: required_material_paths_missing")
    return root


def build_behavioral_refusal(root: Path, *, provider_exit: int = 0) -> Path:
    """Run refused after the behavioral verifier failed; provider exit configurable."""

    b = RunRootBuilder(root)
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=provider_exit).result(exit_code=provider_exit)
    b.eligibility(eligible=True).behavioral(exit_code=1)
    b.terminal().final_status()
    return root


def build_full_records(root: Path) -> RunRootBuilder:
    """A builder with the complete record chain already written (exit 0, verifier fail)."""

    b = RunRootBuilder(root)
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).result(exit_code=0)
    b.eligibility(eligible=True).behavioral(exit_code=1)
    b.terminal().final_status()
    return b


def snapshot(root: Path) -> dict[str, tuple[int, float, bytes]]:
    """Return a mutation-detecting snapshot of every file under ``root``."""

    result: dict[str, tuple[int, float, bytes]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            stat = path.stat()
            result[str(path.relative_to(root))] = (stat.st_size, stat.st_mtime_ns, path.read_bytes())
    return result
