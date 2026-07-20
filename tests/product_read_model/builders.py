"""Synthetic run-root builders for product-read-model tests.

These construct temporary run directories whose evidence layout mirrors the real
persisted schema (attempt-0 native record naming under ``evidence/native-execution``).
Every builder writes only into the supplied temporary directory; no committed
test touches a real historical run root.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SESSION_ID = "run-synthetic"
GATE_ID = "synthetic-gate"
ATTEMPT = 0

# Defaults for the checkpoint-reconstruction fixtures. The shape mirrors the real
# delegated schema: ``command_id`` lives inside the ``verification_command``
# evidence record, never on the checkpoint-history entry.
CHECKPOINT_COMMAND_ID = "npm-test"
CHECKPOINT_ARGV = ["npm.cmd", "test"]
CHECKPOINT_STDOUT = b"synthetic checkpoint stdout\n"
CHECKPOINT_STDERR = b""


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

    def delegated_gate(self, *, human_disposition: object = None, human_boundary_reason: object = None, objective: str = "Deliver the thing.", mission_id: str = "mission-synthetic", checkpoint_history: list | None = None, checkpoint_verification_commands: list | None = None) -> "RunRootBuilder":
        contract: dict[str, object] = {
            "gate_id": self.gate_id,
            "objective": objective,
            "contract_fingerprint": "contract-fp",
        }
        if checkpoint_verification_commands is not None:
            contract["checkpoint_verification_commands"] = checkpoint_verification_commands
        payload = {
            "schema_version": "admissible_delegated_gate_session_v1",
            "session_id": self.session_id,
            "phase": "GATE_EXECUTING",
            "human_disposition": human_disposition,
            "human_boundary_reason": human_boundary_reason,
            "checkpoint_history": checkpoint_history if checkpoint_history is not None else [],
            "audit_history": [],
            "mission": {"mission_id": mission_id, "mission_fingerprint": "mission-fp"},
            "gate_plan": {"ordered_gate_contracts": [contract]},
        }
        _write(self.evidence / "delegated-state" / f"{self.session_id}.delegated-gate.json", payload)
        return self

    def preflight(self, *, secret: bool = False, checkpoint_commands: list | None = None) -> "RunRootBuilder":
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
        if checkpoint_commands is not None:
            payload["authorization_payload"]["mission_profile"] = {
                "profile_id": "profile-synthetic",
                "checkpoint_commands": checkpoint_commands,
            }
        if secret:
            ap = payload["authorization_payload"]
            ap["owner_phrase"] = "hunter2-secret"
            ap["api_key"] = "sk-should-not-appear"
            ap["environment"] = {"PATH": "C:/x", "SECRET_ENV": "leak"}
            # Extended structured secret material that must never reach output.
            ap["owner_authorization"] = "owner-authorization-secret"
            ap["authorization_phrase"] = "authorization-phrase-secret"
            ap["cookie"] = "session=cookie-secret"
            ap["token"] = "token-value-secret"
            ap["secret"] = "bare-secret-value"
            ap["password"] = "password-secret"
            ap["credential"] = "credential-secret"
            ap["env"] = {"PATH": "C:/y", "ANOTHER_SECRET_ENV": "env-leak"}
            # A safe schema field that merely contains the substring must survive.
            ap["authorized_model"] = "cursor-safe-model-id"
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

    def capture_attempt(self, *, required_command_ids: list | None = None, **extra: object) -> "RunRootBuilder":
        """Write the success-lane native terminal record.

        The success lane deliberately never writes ``native-terminal.json``; this
        record is the positive evidence that the capture lane was entered.
        """

        payload = {
            "schema_version": "admissible_native_capture_attempt_v2",
            "session_id": self.session_id,
            "gate_id": self.gate_id,
            "capture_attempt_id": f"capture:{self.session_id}:{self.gate_id}:{ATTEMPT}",
            "execution_attempt_index": ATTEMPT,
            "expected_terminal_status": "CHECKPOINT_CAPTURED",
            "required_command_ids": required_command_ids if required_command_ids is not None else [CHECKPOINT_COMMAND_ID],
            "attempt_fingerprint": "capture-fp",
            "request_fingerprint": "rq-fp",
            "result_fingerprint": "rs-fp",
            "started_at": "2026-07-18T23:49:01.000000Z",
            "state_revision": 1,
            "verification_mode": "FROZEN_BEHAVIORAL",
        }
        payload.update(extra)
        _write(self._native("native-capture-attempt.json"), payload)
        return self

    def checkpoint(
        self,
        *,
        commands: list | None = None,
        record_overrides: dict | None = None,
        stdout_payloads: dict | None = None,
        declared_sha_overrides: dict | None = None,
        omit_records: tuple = (),
        omit_artifact_files: tuple = (),
        omit_references: tuple = (),
        authority: str = "preflight",
        checkpoint_fingerprint: str = "cp-fp",
        **gate_kwargs: object,
    ) -> "RunRootBuilder":
        """Write real-shaped delegated checkpoint evidence plus its artefacts.

        ``authority`` selects where the *expected* command definitions are
        persisted: ``"preflight"`` (canonical authorization payload),
        ``"gate_plan"`` (delegated gate contract) or ``"none"``. The knobs allow a
        single expected command to be dropped, mutated, or given a stale hash so a
        test can require ``INCONSISTENT`` without reimplementing the production
        reconstruction algorithm.
        """

        definitions = commands if commands is not None else [
            {
                "command_id": CHECKPOINT_COMMAND_ID,
                "argv": list(CHECKPOINT_ARGV),
                "timeout_seconds": 300,
                "max_capture_bytes": 1048576,
            }
        ]
        record_overrides = record_overrides or {}
        stdout_payloads = stdout_payloads or {}
        declared_sha_overrides = declared_sha_overrides or {}

        artifact_dir = self.evidence / "checkpoint-artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        references: list[dict] = []
        records: list[dict] = [
            {"evidence_id": "target-tree", "kind": "target_tree", "status": "observed", "file_count": 3, "tree_hash": "tree-hash"},
            {"evidence_id": "git-state", "kind": "git_state", "status": "observed", "head": "b" * 40, "porcelain_status": ""},
        ]

        for definition in definitions:
            command_id = definition["command_id"]
            stem = f"{self.session_id}.{self.gate_id}.attempt-{ATTEMPT}.{command_id}"
            for purpose, default in (("stdout", CHECKPOINT_STDOUT), ("stderr", CHECKPOINT_STDERR)):
                artifact_id = f"{stem}.{purpose}"
                relative_path = f"{stem}.{purpose}.txt"
                content = stdout_payloads.get((command_id, purpose), default)
                if command_id not in omit_artifact_files:
                    (artifact_dir / relative_path).write_bytes(content)
                declared = declared_sha_overrides.get(
                    (command_id, purpose), hashlib.sha256(content).hexdigest()
                )
                if command_id not in omit_references:
                    references.append(
                        {
                            "artifact_id": artifact_id,
                            "purpose": purpose,
                            "relative_path": relative_path,
                            "byte_count": len(content),
                            "sha256": declared,
                            "truncated": False,
                        }
                    )
            if command_id in omit_records:
                continue
            record = {
                "evidence_id": f"command.{command_id}",
                "kind": "verification_command",
                "command_id": command_id,
                "argv": list(definition["argv"]),
                "status": "passed",
                "exit_code": 0,
                "timed_out": False,
                "output_truncated": False,
                "cleanup_proven": True,
                "stdout_artifact_id": f"{stem}.stdout",
                "stderr_artifact_id": f"{stem}.stderr",
            }
            record.update(record_overrides.get(command_id, {}))
            records.append(record)

        history = [
            {
                "schema_version": "admissible_delegated_checkpoint_v1",
                "session_id": self.session_id,
                "gate_id": self.gate_id,
                "execution_attempt_index": ATTEMPT,
                "checkpoint_fingerprint": checkpoint_fingerprint,
                "git_head": "b" * 40,
                "git_worktree_status": "",
                "material_tree_hash": "tree-hash",
                "artifact_references": references,
                "evidence_records": records,
            }
        ]
        self.delegated_gate(
            checkpoint_history=history,
            checkpoint_verification_commands=definitions if authority == "gate_plan" else None,
            **gate_kwargs,
        )
        self.preflight(checkpoint_commands=definitions if authority == "preflight" else None)
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


def build_incomplete_refusal(root: Path) -> RunRootBuilder:
    """Refusal run with deliberately incomplete evidence.

    Canonical classification is ``PRECAPTURE_ELIGIBILITY_FAILED`` (NON_SUCCESS),
    the behavioral verifier failed, and required native records (process
    observation, terminal) are missing so the evidence set is INCOMPLETE. No
    product block is written; callers add one to exercise unverified claims.
    """

    b = RunRootBuilder(root)
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.eligibility(eligible=False).behavioral(exit_code=1)
    b.final_status(status="PRECAPTURE_ELIGIBILITY_FAILED")
    # Deliberately omit process_observation, result and terminal -> INCOMPLETE.
    return b


def build_full_records(root: Path) -> RunRootBuilder:
    """A builder with the complete record chain already written (exit 0, verifier fail)."""

    b = RunRootBuilder(root)
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).result(exit_code=0)
    b.eligibility(eligible=True).behavioral(exit_code=1)
    b.terminal().final_status()
    return b


def build_capture_success(root: Path, **checkpoint_kwargs: object) -> RunRootBuilder:
    """A complete success-lane run: capture-attempt persisted, terminal absent.

    Mirrors the real golden shape - the success lane writes
    ``native-capture-attempt.json`` and deliberately never writes
    ``native-terminal.json``. Callers drop or corrupt individual records to
    exercise the incomplete and inconsistent paths.
    """

    b = RunRootBuilder(root)
    b.request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).result(exit_code=0)
    b.eligibility(eligible=True).behavioral(exit_code=0)
    b.checkpoint(**checkpoint_kwargs)
    b.capture_attempt()
    b.final_status(
        status="CHECKPOINT_CAPTURED_CANARY_SUCCESS",
        detail="All native, behavioral, capture, checkpoint, and state evidence reloaded from disk.",
        canary_success=True,
        phase="CHECKPOINT_CAPTURED",
        checkpoint_status="PASSED",
        checkpoint_fingerprint="cp-fp",
        verification_mode="FROZEN_BEHAVIORAL",
    )
    return b


def snapshot(root: Path) -> dict[str, tuple[int, float, bytes]]:
    """Return a mutation-detecting snapshot of every file under ``root``."""

    result: dict[str, tuple[int, float, bytes]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            stat = path.stat()
            result[str(path.relative_to(root))] = (stat.st_size, stat.st_mtime_ns, path.read_bytes())
    return result
