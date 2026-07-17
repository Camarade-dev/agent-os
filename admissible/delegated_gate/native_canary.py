"""Deterministic Act-2A native-executor fixture, verifier, and coordinator.

Importing this module is inert.  The explicit CLI performs local capability
probes first and has no live-provider default.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint, require_exact_keys, require_identifier, require_nonempty_text, require_sha256, require_strict_int
from admissible.delegated_gate.checkpoint import capture_checkpoint
from admissible.delegated_gate.durability import (
    DurabilityCapabilityResult,
    probe_platform_durability,
)
from admissible.delegated_gate.events import CheckpointRecorded, GateExecutionStarted
from admissible.delegated_gate.models import CommandEvidence, EvidenceKind, EvidenceStatus, GateClause, GateContract, GatePlan, Mission, VerificationCommand
from admissible.delegated_gate.native_executor import (
    ATTESTATION_CLASS_PACKAGE_BIN,
    ATTESTATION_CLASS_WRAPPER_CHAIN,
    AtomicNativeExecutionStore,
    BackendAttestation,
    CAPTURE_EXPECTED_SUCCESS_STATUS,
    CURSOR_DISCOVERY_COMMAND,
    CursorNativeBackendConfig,
    NATIVE_PROMPT_HEADER,
    NativeBackendAttestation,
    PACKAGE_BIN_NON_CLAIMS,
    WRAPPER_CHAIN_NON_CLAIMS,
    WRAPPER_CHAIN_READY_REASON,
    _lexical_absolute,
    NativeCanaryTerminalRecord,
    NativeCaptureTerminalStatus,
    NativeCheckpointCaptureAttempt,
    NativeCommittedButDurabilityUncertain,
    NativeDelegatedExecutor,
    NativeEvidenceInvalid,
    NativeEvidenceNotFound,
    NativeExecutionRequest,
    NativeExecutionResult,
    NativeExecutionStatus,
    NativeArtifactReference,
    NativeFilesystemIdentity,
    NativePreflightDecision,
    NativePreflightStatus,
    _inside,
    _safe_create_directory,
    _safe_directory,
    _safe_file,
    _same_directory_identity,
    preflight_native_cursor,
)
from admissible.delegated_gate.reducer import reduce
from admissible.delegated_gate.state import DelegatedSessionState, Phase, new_session_state
from admissible.delegated_gate.store import AtomicDelegatedSessionStore


CANARY_CLASSIFICATION = "act-2a-native-delegated-executor-canary"
CANARY_FIXTURE_VERSION = "act-2a-high-score-fixture-v2"
CANARY_MISSION_ID = "act-2a-native-executor-canary"
CANARY_GATE_ID = "native-canary-gate"
REQUIRED_COMMIT_MESSAGE = "feat: add deterministic high-score persistence"
MAX_PROVIDER_INVOCATIONS = 1
MAX_NATIVE_PHASE_ATTEMPTS = 1
MAX_REPAIR_ROUNDS = 0
MAX_AUDITOR_INVOCATIONS = 0
MAX_RETRIES = 0
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_STDOUT_BYTE_LIMIT = 512 * 1024
DEFAULT_STDERR_BYTE_LIMIT = 128 * 1024
OWNER_AUTHORIZATION_DIGEST_ENV = "ADMISSIBLE_NATIVE_CANARY_OWNER_AUTHORIZATION_SHA256"
AUTHORIZATION_SCHEMA_VERSION = "admissible_native_canary_authorization_v3"
# v2 is superseded and intentionally not authorizable for a new live canary; it
# may only be parsed as inert historical data by callers that opt in explicitly.
AUTHORIZATION_SCHEMA_VERSION_LEGACY_V2 = "admissible_native_canary_authorization_v2"
# The readiness reason is the exact preflight decision reason; each attestation
# class pairs with exactly one reason and any other pairing is unauthorizable.
PACKAGE_BIN_READY_REASON = "LOCAL_CURSOR_CAPABILITIES_ATTESTED"
CLASS_READINESS_REASONS: dict[str, str] = {
    ATTESTATION_CLASS_WRAPPER_CHAIN: WRAPPER_CHAIN_READY_REASON,
    ATTESTATION_CLASS_PACKAGE_BIN: PACKAGE_BIN_READY_REASON,
}
# Deterministic run-root children the committed CLI always creates.  They are
# bound into the payload so an authorized digest cannot be reused against a
# substituted or independently redirected workspace or sidecar location.
WORKSPACE_DIRECTORY_NAME = "work"
EVIDENCE_DIRECTORY_NAME = "evidence"
NATIVE_SIDECAR_DIRECTORY_NAME = "native-execution"
# Canary-execution-boundary non-claims.  These concern the run boundary of the
# native experiment, NOT the Cursor wrapper identity (kept separate on purpose).
# Exact membership AND ordering are authoritative; any change fails validation
# even when the outer payload fingerprint is recomputed.
CANARY_NON_CLAIMS: tuple[str, ...] = (
    "os-level sandboxing of the native agent is not established",
    "credential isolation from the native agent is not established",
    "global filesystem containment is not established",
    "continuous filesystem monitoring is not performed",
    "a mutation that is perfectly restored between before/after observations is not detected",
    "safety against a hostile local process or interpreter is not established",
    "production suitability is not established",
    "the owner phrase is supplied to the current cli as a process argument and is therefore not protected against a hostile local process observing process arguments",
    "observed containment is limited to the roots and before/after measurements implemented by the committed canary harness",
    "this authorization establishes exactly one explicitly owner-authorized local experiment",
)
BEHAVIORAL_EVIDENCE_SCHEMA_VERSION = "admissible_native_canary_behavioral_evidence_v1"
EXPECTED_MATERIAL_PATHS = frozenset({"README.md", "src/game-state.js", "src/score.js", "test/game-state.test.js"})

CANARY_MISSION = """Add deterministic high-score persistence to this small game-state package.
Implement the feature across the existing source modules, add tests using the existing Node test runner,
run the complete npm test suite, update the README, and create one local Git commit with the exact message
`feat: add deterministic high-score persistence`. Do not add a remote and do not push. Stop after the local commit."""


class NativeCanaryStatus(str, Enum):
    PREFLIGHT_BLOCKED = "PREFLIGHT_BLOCKED"
    EXECUTION_RESULT_MISSING_NO_RETRY = "EXECUTION_RESULT_MISSING_NO_RETRY"
    PROCESS_FAILED = "PROCESS_FAILED"
    TIMED_OUT = "TIMED_OUT"
    CLEANUP_UNCERTAIN = "CLEANUP_UNCERTAIN"
    WORKSPACE_BOUNDARY_BLOCKED = "WORKSPACE_BOUNDARY_BLOCKED"
    PRECAPTURE_ELIGIBILITY_FAILED = "PRECAPTURE_ELIGIBILITY_FAILED"
    CAPTURE_ATTEMPT_AMBIGUOUS = "CAPTURE_ATTEMPT_AMBIGUOUS"
    CHECKPOINT_CAPTURE_FAILED = "CHECKPOINT_CAPTURE_FAILED"
    DURABILITY_UNCERTAIN = "DURABILITY_UNCERTAIN"
    CHECKPOINT_CAPTURED = "CHECKPOINT_CAPTURED"
    CHECKPOINT_CAPTURED_CANARY_SUCCESS = "CHECKPOINT_CAPTURED_CANARY_SUCCESS"


@dataclass(frozen=True)
class FixtureRepository:
    repository: Path
    initial_head: str
    initial_material_tree_hash: str
    mission: str = CANARY_MISSION
    required_commit_message: str = REQUIRED_COMMIT_MESSAGE


@dataclass(frozen=True)
class NativeCanaryOutcome:
    status: NativeCanaryStatus
    session_id: str
    phase: str
    request_fingerprint: str | None
    result_fingerprint: str | None
    checkpoint_fingerprint: str | None
    provider_invocations: int
    canary_success: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value, "session_id": self.session_id, "phase": self.phase,
            "request_fingerprint": self.request_fingerprint, "result_fingerprint": self.result_fingerprint,
            "checkpoint_fingerprint": self.checkpoint_fingerprint, "provider_invocations": self.provider_invocations,
            "canary_success": self.canary_success, "detail": self.detail,
            "budgets": {"provider_invocations": 1, "native_phase_attempts": 1, "repair_rounds": 0, "auditor_invocations": 0, "retries": 0},
        }


def _run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, env=env, shell=False, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({argv!r}): {result.stderr.strip()}")
    return result


def _fixture_files() -> dict[str, bytes]:
    package = {"name": "admissible-native-canary-game-state", "version": "1.0.0", "private": True, "type": "module", "scripts": {"test": "node --preserve-symlinks --preserve-symlinks-main --test"}}
    return {
        "package.json": (json.dumps(package, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        "src/score.js": b"""export function normalizeScore(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError('score must be a non-negative safe integer');
  }
  return value;
}

export function higherScore(left, right) {
  return Math.max(normalizeScore(left), normalizeScore(right));
}
""",
        "src/game-state.js": b"""import { normalizeScore } from './score.js';

export function createGameState() {
  return { score: 0, rounds: 0 };
}

export function finishRound(state, score) {
  return { score: normalizeScore(score), rounds: state.rounds + 1 };
}
""",
        "src/memory-storage.js": b"""export function createMemoryStorage(seed = {}) {
  const values = new Map(Object.entries(seed));
  return {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(String(key), String(value)); },
    snapshot() { return Object.fromEntries([...values.entries()].sort()); },
  };
}
""",
        "test/game-state.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { createGameState, finishRound } from '../src/game-state.js';
import { higherScore } from '../src/score.js';
import { createMemoryStorage } from '../src/memory-storage.js';

test('round completion is deterministic', () => {
  const initial = createGameState();
  assert.deepEqual(finishRound(initial, 7), { score: 7, rounds: 1 });
});

test('score helper and storage fixture use deterministic built-ins only', () => {
  assert.equal(higherScore(4, 9), 9);
  const storage = createMemoryStorage({ b: '2', a: '1' });
  storage.setItem('score', 12);
  assert.deepEqual(storage.snapshot(), { a: '1', b: '2', score: '12' });
});
""",
        "README.md": b"""# Canary game state

Small dependency-free ECMAScript module used by the Admissible native-executor canary.

Run the complete deterministic suite with `npm test`.

The initial package tracks per-round scores. High-score persistence is intentionally not implemented yet.
""",
        ".gitignore": b"node_modules/\n",
    }


def _material_tree_hash(repository: Path) -> str:
    root, _ = _safe_directory(repository, "fixture repository")
    digest = hashlib.sha256(); entries: list[tuple[str, bytes]] = []
    for path in root.rglob("*"):
        if ".git" in path.relative_to(root).parts or not path.is_file():
            continue
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("fixture material cannot contain symlinks")
        entries.append((path.relative_to(root).as_posix(), path.read_bytes()))
    for relative, data in sorted(entries):
        digest.update(relative.encode("utf-8") + b"\0" + hashlib.sha256(data).hexdigest().encode("ascii") + b"\0" + str(len(data)).encode("ascii") + b"\n")
    return digest.hexdigest()


def build_canary_repository(temporary_root: str | Path, *, repository_name: str = "work") -> FixtureRepository:
    """Create one deterministic, non-redirecting, dependency-free Git fixture."""
    parent, _ = _safe_directory(temporary_root, "fixture temporary root")
    if not repository_name or any(char in repository_name for char in "\\/\x00") or repository_name in {".", ".."}:
        raise ValueError("repository name must be one safe component")
    repository = parent / repository_name
    if repository.exists():
        raise ValueError("fixture repository path must be fresh")
    repository.mkdir(); _safe_directory(repository, "fixture repository")
    for relative, content in _fixture_files().items():
        destination = repository / relative; destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(content)
    _run(["git", "init", "--quiet", "--initial-branch=main"], cwd=repository)
    _run(["git", "config", "core.autocrlf", "false"], cwd=repository); _run(["git", "config", "core.filemode", "false"], cwd=repository); _run(["git", "config", "commit.gpgsign", "false"], cwd=repository)
    _run(["git", "add", "--all"], cwd=repository)
    git_env = dict(os.environ); git_env.update({"GIT_AUTHOR_NAME": "Admissible Canary", "GIT_AUTHOR_EMAIL": "canary@invalid.example", "GIT_COMMITTER_NAME": "Admissible Canary", "GIT_COMMITTER_EMAIL": "canary@invalid.example", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"})
    _run(["git", "commit", "--quiet", "-m", "chore: initialize native executor canary"], cwd=repository, env=git_env)
    head = _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip().lower()
    if _run(["git", "remote"], cwd=repository).stdout.strip(): raise RuntimeError("fixture unexpectedly has a remote")
    if _run(["git", "rev-list", "--count", "HEAD"], cwd=repository).stdout.strip() != "1": raise RuntimeError("fixture must have exactly one commit")
    if _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout: raise RuntimeError("fixture initial worktree is not clean")
    return FixtureRepository(repository, head, _material_tree_hash(repository))


def npm_test_argv() -> tuple[str, ...]: return ("npm.cmd" if os.name == "nt" else "npm", "test")


def create_canary_session(*, session_id: str) -> DelegatedSessionState:
    mission = Mission.create(mission_id=CANARY_MISSION_ID, specification=CANARY_MISSION)
    gate = GateContract.create(
        gate_id=CANARY_GATE_ID, objective="Complete and locally commit deterministic high-score persistence in the assigned canary repository.",
        clauses=(GateClause("native-canary.material", "The committed material implements deterministic high-score persistence."), GateClause("native-canary.tests", "The complete npm test suite passes independently at checkpoint capture."), GateClause("native-canary.git", "The exact local commit exists, the worktree is clean, and no remote exists.")),
        required_evidence_kinds=(EvidenceKind.TARGET_TREE, EvidenceKind.GIT_STATE, EvidenceKind.VERIFICATION_COMMAND),
        checkpoint_verification_commands=(VerificationCommand(command_id="npm-test", argv=npm_test_argv(), timeout_seconds=120, max_capture_bytes=256 * 1024),), repair_budget=0,
    )
    return new_session_state(session_id=session_id, mission=mission, gate_plan=GatePlan.create(mission=mission, ordered_gate_contracts=(gate,)))


def build_native_agent_prompt(*, mission: Mission, gate_contract: GateContract, work_workspace: str | Path, required_commit_message: str = REQUIRED_COMMIT_MESSAGE) -> str:
    mission.validated(); gate_contract.validated(); workspace, _ = _safe_directory(work_workspace, "assigned work workspace")
    clauses = "\n".join(f"- [{clause.clause_id}] {clause.text}" for clause in gate_contract.clauses)
    return f"""{NATIVE_PROMPT_HEADER}

Immutable mission:
{mission.specification}

Current gate objective:
{gate_contract.objective}

Gate clauses:
{clauses}

Your exact assigned workspace is:
{workspace}

You have normal native autonomy only inside that assigned workspace: inspect the repository, edit files,
run shell commands, diagnose failures, use npm, run tests, and use Git locally as needed.

Required completion conditions:
- run the complete `npm test` suite;
- create exactly one intended local feature commit with complete message `{required_commit_message}`;
- do not add or modify a Git remote;
- do not push;
- stop immediately after the local commit.

Do not merely describe changes. Perform the work inside the assigned workspace.
"""


_BEHAVIORAL_SCRIPT = r"""import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const root = process.argv[2];
const game = await import(pathToFileURL(join(root, 'src', 'game-state.js')).href);
const score = await import(pathToFileURL(join(root, 'src', 'score.js')).href);
const memory = await import(pathToFileURL(join(root, 'src', 'memory-storage.js')).href);
const fresh = memory.createMemoryStorage();
assert.equal(game.createGameState(fresh).highScore, 0);
const first = game.finishRound(game.createGameState(fresh), 7, fresh);
assert.equal(first.highScore, 7);
assert.equal(score.loadHighScore(fresh), 7);
const lower = game.finishRound(first, 4, fresh);
assert.equal(lower.highScore, 7);
assert.equal(score.loadHighScore(fresh), 7);
const higher = game.finishRound(lower, 12, fresh);
assert.equal(higher.highScore, 12);
assert.equal(score.loadHighScore(fresh), 12);
assert.equal(game.createGameState(fresh).highScore, 12);
assert.throws(() => score.loadHighScore(memory.createMemoryStorage({ highScore: 'not-a-number' })), TypeError);
const repeat = memory.createMemoryStorage({ highScore: '12' });
assert.deepEqual([game.createGameState(repeat).highScore, score.loadHighScore(repeat)], [12, 12]);
console.log('act-2a behavioral verifier passed');
"""


@dataclass(frozen=True)
class BehavioralVerifierEvidence:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    work_workspace: str
    workspace_identity: NativeFilesystemIdentity
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    script: NativeArtifactReference
    stdout: NativeArtifactReference
    stderr: NativeArtifactReference
    evidence_fingerprint: str
    def _body(self) -> dict[str, Any]: return {"schema_version": self.schema_version, "session_id": self.session_id, "gate_id": self.gate_id, "execution_attempt_index": self.execution_attempt_index, "request_fingerprint": self.request_fingerprint, "work_workspace": self.work_workspace, "workspace_identity": self.workspace_identity.to_dict(), "argv": list(self.argv), "exit_code": self.exit_code, "timed_out": self.timed_out, "script": self.script.to_dict(), "stdout": self.stdout.to_dict(), "stderr": self.stderr.to_dict()}
    def validated(self) -> "BehavioralVerifierEvidence":
        if self.schema_version != BEHAVIORAL_EVIDENCE_SCHEMA_VERSION: raise ValueError("unsupported behavioral verifier evidence")
        require_identifier(self.session_id,"behavioral session ID"); require_identifier(self.gate_id,"behavioral gate ID"); require_strict_int(self.execution_attempt_index,"behavioral attempt",minimum=0,maximum=0); require_sha256(self.request_fingerprint,"behavioral request fingerprint")
        workspace, identity = _safe_directory(self.work_workspace, "behavioral verifier workspace")
        if str(workspace) != self.work_workspace or not _same_directory_identity(identity, self.workspace_identity): raise ValueError("behavioral verifier workspace identity changed")
        self.workspace_identity.validated()
        if not isinstance(self.argv, tuple) or not self.argv: raise ValueError("behavioral verifier argv is invalid")
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)): raise ValueError("behavioral verifier exit code is invalid")
        if not isinstance(self.timed_out, bool): raise ValueError("behavioral verifier timeout is invalid")
        self.script.validated(); self.stdout.validated(); self.stderr.validated()
        if (self.script.purpose,self.stdout.purpose,self.stderr.purpose)!=("behavioral-script","behavioral-stdout","behavioral-stderr"): raise ValueError("behavioral verifier artifact roles differ")
        require_sha256(self.evidence_fingerprint, "behavioral evidence fingerprint")
        if fingerprint(self._body()) != self.evidence_fingerprint: raise ValueError("behavioral verifier evidence fingerprint mismatch")
        return self
    def to_dict(self) -> dict[str, Any]: data=self._body(); data["evidence_fingerprint"]=self.evidence_fingerprint; return data
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BehavioralVerifierEvidence":
        require_exact_keys(data, set(cls.__dataclass_fields__), "behavioral verifier evidence"); values=dict(data); values["workspace_identity"]=NativeFilesystemIdentity.from_dict(data["workspace_identity"]); values["argv"]=tuple(data["argv"]); values["script"]=NativeArtifactReference.from_dict(data["script"]); values["stdout"]=NativeArtifactReference.from_dict(data["stdout"]); values["stderr"]=NativeArtifactReference.from_dict(data["stderr"]); return cls(**values).validated()


def run_behavioral_verifier(*, request: NativeExecutionRequest, execution_store: AtomicNativeExecutionStore, timeout_seconds: int = 60, output_limit: int = 128 * 1024) -> BehavioralVerifierEvidence:
    request.validated(); workspace, identity = _safe_directory(request.work_workspace, "behavioral verifier workspace")
    if execution_store.has_behavioral_evidence(request.session_id,request.gate_id,request.execution_attempt_index):
        return load_behavioral_verifier(request=request,execution_store=execution_store)
    prefix=f"{request.session_id}.{request.gate_id}.attempt-{request.execution_attempt_index}.behavioral"
    script=execution_store.write_behavioral_artifact(request=request,artifact_id=f"{prefix}.script",purpose="behavioral-script",data=_BEHAVIORAL_SCRIPT.encode("utf-8"))
    script_path=execution_store.directory / script.relative_path
    argv=("node.exe" if os.name=="nt" else "node", "--preserve-symlinks", "--preserve-symlinks-main", str(script_path), str(workspace))
    try:
        completed=subprocess.run(list(argv), cwd=execution_store.artifact_directory, shell=False, check=False, capture_output=True, timeout=timeout_seconds)
        exit_code=completed.returncode; timed_out=False; stdout=completed.stdout[:output_limit]; stderr=completed.stderr[:output_limit]
    except subprocess.TimeoutExpired as exc:
        exit_code=None; timed_out=True; stdout=(exc.stdout or b"")[:output_limit]; stderr=(exc.stderr or b"")[:output_limit]
    stdout_ref=execution_store.write_behavioral_artifact(request=request,artifact_id=f"{prefix}.stdout",purpose="behavioral-stdout",data=stdout)
    stderr_ref=execution_store.write_behavioral_artifact(request=request,artifact_id=f"{prefix}.stderr",purpose="behavioral-stderr",data=stderr)
    provisional=BehavioralVerifierEvidence(BEHAVIORAL_EVIDENCE_SCHEMA_VERSION,request.session_id,request.gate_id,request.execution_attempt_index,request.request_fingerprint,str(workspace),identity,argv,exit_code,timed_out,script,stdout_ref,stderr_ref,"0"*64)
    evidence=BehavioralVerifierEvidence(**{**provisional.__dict__,"evidence_fingerprint":fingerprint(provisional._body())}).validated()
    return execution_store.create_behavioral_evidence(request=request,evidence=evidence,loader=BehavioralVerifierEvidence.from_dict)


def load_behavioral_verifier(*, request: NativeExecutionRequest, execution_store: AtomicNativeExecutionStore) -> BehavioralVerifierEvidence:
    try: evidence=execution_store.load_behavioral_evidence(request.session_id,request.gate_id,request.execution_attempt_index,loader=BehavioralVerifierEvidence.from_dict)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc: raise NativeEvidenceInvalid(f"behavioral verifier evidence is invalid: {exc}") from exc
    if evidence.request_fingerprint!=request.request_fingerprint: raise NativeEvidenceInvalid("behavioral verifier evidence differs from the durable request")
    script_path=execution_store.directory / evidence.script.relative_path
    if script_path.read_bytes()!=_BEHAVIORAL_SCRIPT.encode("utf-8"): raise NativeEvidenceInvalid("behavioral verifier script differs from the harness-owned source")
    return evidence


def _pre_capture_reason(result: NativeExecutionResult, behavioral: BehavioralVerifierEvidence) -> str | None:
    try: result.validated()
    except (NativeEvidenceInvalid, ValueError) as exc: return f"native result workspace observations no longer validate: {exc}"
    if result.status is not NativeExecutionStatus.PROCESS_SUCCEEDED: return "native process did not succeed"
    if result.timed_out or not result.cleanup_confirmed or result.orphan_process_ids: return "native cleanup is not confirmed"
    if result.source_repository_mutated or result.unexpected_sibling_mutations: return "measured workspace boundary changed"
    if result.final_git_remotes: return "canary repository has a remote"
    if result.initial_git_head is None or result.final_git_head is None or result.final_git_head == result.initial_git_head: return "final Git HEAD did not change"
    if result.commits_added != 1: return "exactly one new commit is required"
    if result.final_commit_message != REQUIRED_COMMIT_MESSAGE: return "final complete commit message differs"
    if result.final_git_porcelain_status != "": return "final worktree is not clean"
    if not EXPECTED_MATERIAL_PATHS.issubset(set(result.changed_material_files)): return "required material paths did not all change"
    if behavioral.timed_out or behavioral.exit_code != 0: return "immutable behavioral verifier did not pass"
    return None


def _checkpoint_success_reason(checkpoint: Any, gate_contract: GateContract) -> str | None:
    """Act-2A acceptance over the real, transient Act-1 checkpoint result."""

    if checkpoint.gate_id != gate_contract.gate_id or checkpoint.execution_attempt_index != 0:
        return "checkpoint identity differs from the active Act-2A gate"
    if checkpoint.evidence_kinds != frozenset(gate_contract.required_evidence_kinds):
        return "checkpoint evidence kinds differ from the active gate contract"
    commands = tuple(record for record in checkpoint.evidence_records if isinstance(record, CommandEvidence))
    if len(commands) != len(gate_contract.checkpoint_verification_commands):
        return "checkpoint command evidence count differs from the active contract"
    for record, command in zip(commands, gate_contract.checkpoint_verification_commands):
        if record.command_id != command.command_id or record.argv != command.argv:
            return "checkpoint command evidence identity differs from the active contract"
        if record.status is not EvidenceStatus.PASSED or record.exit_code != 0:
            return "required checkpoint command did not pass"
        if record.timed_out or record.output_truncated or not record.cleanup_proven:
            return "required checkpoint command has timeout, truncation, or cleanup uncertainty"
    return None


class NativeCanaryCoordinator:
    """One READY_FOR_GATE -> CHECKPOINT_CAPTURED canary path, with no retry."""
    def __init__(self, *, session_store: AtomicDelegatedSessionStore, execution_store: AtomicNativeExecutionStore, executor: NativeDelegatedExecutor, backend_attestation: BackendAttestation, source_repository: str | Path, work_workspace: str | Path, canary_parent: str | Path, evidence_directory: str | Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, stdout_byte_limit: int = DEFAULT_STDOUT_BYTE_LIMIT, stderr_byte_limit: int = DEFAULT_STDERR_BYTE_LIMIT) -> None:
        self.session_store=session_store; self.execution_store=execution_store; self.executor=executor; self.backend_attestation=backend_attestation.validated()
        self.source_repository,_=_safe_directory(source_repository,"source repository"); self.work_workspace,_=_safe_directory(work_workspace,"work workspace"); self.canary_parent,_=_safe_directory(canary_parent,"canary parent"); self.evidence_directory,_=_safe_directory(evidence_directory,"evidence directory")
        self.timeout_seconds=timeout_seconds; self.stdout_byte_limit=stdout_byte_limit; self.stderr_byte_limit=stderr_byte_limit
    def _outcome(self, *, status: NativeCanaryStatus, state: DelegatedSessionState, request: NativeExecutionRequest | None = None, result: NativeExecutionResult | None = None, provider_invocations: int = 0, detail: str) -> NativeCanaryOutcome:
        checkpoint=state.checkpoint_history[-1] if state.checkpoint_history else None
        return NativeCanaryOutcome(status,state.session_id,state.phase.value,request.request_fingerprint if request else None,result.result_fingerprint if result else None,checkpoint.checkpoint_fingerprint if checkpoint else None,provider_invocations,status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS,detail)
    def _terminal_outcome(self, state: DelegatedSessionState, request: NativeExecutionRequest, result: NativeExecutionResult | None, terminal: NativeCanaryTerminalRecord) -> NativeCanaryOutcome:
        mapping={NativeCaptureTerminalStatus.PRECAPTURE_FAILED:NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED,NativeCaptureTerminalStatus.CAPTURE_FAILED:NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED,NativeCaptureTerminalStatus.DURABILITY_UNCERTAIN:NativeCanaryStatus.DURABILITY_UNCERTAIN}
        return self._outcome(status=mapping[terminal.status],state=state,request=request,result=result,detail=terminal.diagnostic)
    def _load_authoritative_request(self, *, session_id: str, gate_id: str) -> NativeExecutionRequest:
        current=self.executor.attest_local_backend()
        return self.execution_store.load_request_verified_against_local_backend(session_id,gate_id,0,current_attestation=current)
    def _reconstruct_success(self, state: DelegatedSessionState, request: NativeExecutionRequest, result: NativeExecutionResult) -> NativeCanaryOutcome:
        request.validated_for_execution(current_attestation=self.executor.attest_local_backend())
        if self.execution_store.has_terminal(state.session_id,request.gate_id,0): return self._terminal_outcome(state,request,result,self.execution_store.load_terminal(state.session_id,request.gate_id,0))
        attempt=self.execution_store.load_capture_attempt(state.session_id,request.gate_id,0)
        behavioral=load_behavioral_verifier(request=request,execution_store=self.execution_store)
        if (
            attempt.session_id!=state.session_id or attempt.gate_id!=state.current_gate.gate_id or attempt.execution_attempt_index!=0
            or attempt.request_fingerprint!=request.request_fingerprint or attempt.result_fingerprint!=result.result_fingerprint
            or attempt.behavioral_evidence_fingerprint!=behavioral.evidence_fingerprint
            or attempt.gate_plan_fingerprint!=state.gate_plan.plan_fingerprint
            or attempt.checkpoint_contract_fingerprint!=state.current_gate.contract_fingerprint
            or attempt.required_command_ids!=tuple(command.command_id for command in state.current_gate.checkpoint_verification_commands)
            or attempt.capture_attempt_id!=f"capture:{state.session_id}:{state.current_gate.gate_id}:0"
            or attempt.expected_terminal_status!=CAPTURE_EXPECTED_SUCCESS_STATUS
            or state.revision!=attempt.state_revision+1
        ): raise NativeEvidenceInvalid("capture attempt does not bind the exact active durable run")
        if state.phase is not Phase.CHECKPOINT_CAPTURED or len(state.checkpoint_history)!=1 or state.audit_history or state.repair_authority is not None or state.human_boundary_reason is not None or state.human_disposition is not None or state.current_gate.gate_id!=CANARY_GATE_ID: raise NativeEvidenceInvalid("reconstructed delegated state exceeds Act-2A stop boundary")
        checkpoint=state.checkpoint_history[-1]
        if checkpoint.session_id!=state.session_id or checkpoint.gate_id!=request.gate_id or checkpoint.execution_attempt_index!=0: raise NativeEvidenceInvalid("checkpoint differs from the active request")
        checkpoint_root,_=_safe_directory(self.evidence_directory / "checkpoint-artifacts","checkpoint artifact root")
        for reference in checkpoint.artifact_references:
            path=checkpoint_root / reference.relative_path; safe,_=_safe_file(path,"checkpoint artifact")
            if not _inside(safe,checkpoint_root): raise NativeEvidenceInvalid("checkpoint artifact escapes checkpoint evidence root")
            data=safe.read_bytes()
            if len(data)!=reference.byte_count or hashlib.sha256(data).hexdigest()!=reference.sha256: raise NativeEvidenceInvalid("checkpoint artifact hash mismatch")
        if _pre_capture_reason(result, behavioral) is not None: raise NativeEvidenceInvalid("reconstructed success no longer satisfies eligibility")
        if _checkpoint_success_reason(checkpoint,state.current_gate) is not None: raise NativeEvidenceInvalid("reconstructed checkpoint command evidence does not satisfy Act-2A success")
        return self._outcome(status=NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS,state=state,request=request,result=result,detail="All native, behavioral, capture, checkpoint, and state evidence reloaded from disk.")
    def run(self, *, session_id: str) -> NativeCanaryOutcome:
        state=self.session_store.load(session_id); gate=state.current_gate; attempt=0
        if state.phase is Phase.CHECKPOINT_CAPTURED:
            return self._reconstruct_success(state,self._load_authoritative_request(session_id=session_id,gate_id=gate.gate_id),self.execution_store.load_result(session_id,gate.gate_id,attempt))
        if state.phase is Phase.READY_FOR_GATE:
            started=reduce(state,GateExecutionStarted(gate.gate_id)); self.session_store.replace(started,expected_revision=state.revision); state=self.session_store.load(session_id)
        if state.phase is not Phase.GATE_EXECUTING: raise RuntimeError(f"coordinator refuses delegated phase {state.phase.value}")
        prompt=build_native_agent_prompt(mission=state.mission,gate_contract=gate,work_workspace=self.work_workspace)
        request_exists=self.execution_store.has_request(session_id,gate.gate_id,attempt)
        if request_exists:
            request=self._load_authoritative_request(session_id=session_id,gate_id=gate.gate_id)
            result=self.execution_store.load_result(session_id,gate.gate_id,attempt) if self.execution_store.has_result(session_id,gate.gate_id,attempt) else None
            if self.execution_store.has_terminal(session_id,gate.gate_id,attempt): return self._terminal_outcome(state,request,result,self.execution_store.load_terminal(session_id,gate.gate_id,attempt))
            if self.execution_store.has_capture_attempt(session_id,gate.gate_id,attempt): return self._outcome(status=NativeCanaryStatus.CAPTURE_ATTEMPT_AMBIGUOUS,state=state,request=request,result=result,detail="A durable capture-attempt record exists without CHECKPOINT_CAPTURED; capture is never replayed.")
            if result is None: return self._outcome(status=NativeCanaryStatus.EXECUTION_RESULT_MISSING_NO_RETRY,state=state,request=request,detail="A durable request exists without a result; native execution is never reinvoked.")
            if self.execution_store.has_behavioral_evidence(session_id,gate.gate_id,attempt): return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,result=result,detail="A visible behavioral record without a capture boundary is fail-closed and never reused.")
            return self._outcome(status=NativeCanaryStatus.CAPTURE_ATTEMPT_AMBIGUOUS,state=state,request=request,result=result,detail="A durable result without terminal or capture record is an ambiguous no-retry boundary.")
        try: current=self.executor.attest_local_backend()
        except NativeEvidenceInvalid as exc: return self._outcome(status=NativeCanaryStatus.PREFLIGHT_BLOCKED,state=state,detail=str(exc))
        if current!=self.backend_attestation: return self._outcome(status=NativeCanaryStatus.PREFLIGHT_BLOCKED,state=state,detail="coordinator backend attestation differs from fresh local installation evidence")
        request=NativeExecutionRequest.create(session_id=session_id,gate_id=gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=gate.contract_fingerprint,work_workspace=self.work_workspace,evidence_store_root=self.execution_store.directory,artifact_directory=self.execution_store.artifact_directory,attestation=current,prompt=prompt,timeout_seconds=self.timeout_seconds,stdout_byte_limit=self.stdout_byte_limit,stderr_byte_limit=self.stderr_byte_limit)
        try: self.execution_store.create_request(request)
        except NativeCommittedButDurabilityUncertain as exc: return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,detail=str(exc))
        try:
            issued=self.executor.execute(request=request,prompt=prompt,source_repository=self.source_repository,canary_parent=self.canary_parent,allowed_parent_children=frozenset({self.work_workspace.name}),evidence_store_root=self.execution_store.directory,artifact_directory=self.execution_store.artifact_directory)
            result=self.execution_store.write_result(issued)
        except NativeCommittedButDurabilityUncertain as exc: return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,detail=str(exc),provider_invocations=1)
        except NativeEvidenceInvalid as exc:
            terminal=self.execution_store.create_terminal(request=request,result=None,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="executor_observation_failed",diagnostic=str(exc)); return self._terminal_outcome(state,request,None,terminal)
        try:
            behavioral=run_behavioral_verifier(request=request,execution_store=self.execution_store)
        except NativeCommittedButDurabilityUncertain as exc:
            return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,result=result,provider_invocations=1,detail=str(exc))
        except Exception as exc:
            terminal=self.execution_store.create_terminal(request=request,result=result,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="behavioral_verifier_observation",diagnostic=f"{type(exc).__name__}: {exc}")
            return self._terminal_outcome(state,request,result,terminal)
        reason=_pre_capture_reason(result,behavioral)
        if reason is not None:
            terminal=self.execution_store.create_terminal(request=request,result=result,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="pre_capture_eligibility",diagnostic=reason); return self._terminal_outcome(state,request,result,terminal)
        try: capture_attempt=self.execution_store.create_capture_attempt(request=request,result=result,gate_plan_fingerprint=state.gate_plan.plan_fingerprint,checkpoint_contract_fingerprint=gate.contract_fingerprint,behavioral_evidence_fingerprint=behavioral.evidence_fingerprint,required_command_ids=tuple(command.command_id for command in gate.checkpoint_verification_commands),state_revision=state.revision)
        except NativeCommittedButDurabilityUncertain as exc: return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,result=result,provider_invocations=1,detail=str(exc))
        try:
            captured=capture_checkpoint(repository=self.work_workspace,artifact_directory=self.evidence_directory / "checkpoint-artifacts",session_id=session_id,gate_contract=gate,execution_attempt_index=0)
        except Exception as exc:
            terminal=self.execution_store.create_terminal(request=request,result=result,status=NativeCaptureTerminalStatus.CAPTURE_FAILED,failure_category="checkpoint_capture",diagnostic=str(exc),capture_attempt=capture_attempt); return self._terminal_outcome(state,request,result,terminal)
        # Once capture returns, a state-persistence interruption is deliberately
        # left as the durable started-attempt ambiguity; capture is not replayed.
        checkpoint_state=reduce(state,CheckpointRecorded(captured))
        checkpoint_reason=_checkpoint_success_reason(checkpoint_state.checkpoint_history[-1],gate)
        if checkpoint_reason is not None:
            terminal=self.execution_store.create_terminal(request=request,result=result,status=NativeCaptureTerminalStatus.CAPTURE_FAILED,failure_category="checkpoint_verification",diagnostic=checkpoint_reason,capture_attempt=capture_attempt)
            return self._terminal_outcome(state,request,result,terminal)
        self.session_store.replace(checkpoint_state,expected_revision=state.revision)
        final=self.session_store.load(session_id); return self._reconstruct_success(final,request,result)


def _git_source_preflight(source: Path, required_head: str) -> tuple[bool, str]:
    try:
        root=_run(["git","rev-parse","--show-toplevel"],cwd=source).stdout.strip(); head=_run(["git","rev-parse","HEAD"],cwd=source).stdout.strip().lower(); status=_run(["git","status","--porcelain=v1","--untracked-files=all"],cwd=source).stdout
    except RuntimeError as exc: return False,str(exc)
    if Path(root).resolve()!=source.resolve(): return False,"source repository is not the exact Git root"
    if head!=required_head.lower(): return False,"source HEAD does not match the explicitly authorized source HEAD"
    if status: return False,"source repository is not clean"
    return True,"clean authorized source HEAD confirmed"


@dataclass(frozen=True)
class NativeCanaryAuthorizationPayload:
    schema_version: str
    source_repository: str
    source_repository_identity: NativeFilesystemIdentity
    source_head: str
    clean_worktree_required: bool
    run_id: str
    session_id: str
    mission_fingerprint: str
    gate_plan_fingerprint: str
    gate_contract_fingerprint: str
    backend_attestation_class: str
    backend_readiness_reason: str
    backend_attestation_fingerprint: str
    attestation_non_claims: tuple[str, ...]
    canary_non_claims: tuple[str, ...]
    executable: str
    launcher_prefix: tuple[str, ...]
    selected_model: str
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    budgets: tuple[int, int, int, int, int]
    fixture_version: str
    required_commit_message: str
    run_root: str
    workspace_root: str
    evidence_root: str
    native_sidecar_root: str
    payload_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["source_repository_identity"] = self.source_repository_identity.to_dict()
        data["launcher_prefix"] = list(self.launcher_prefix)
        data["budgets"] = list(self.budgets)
        data["attestation_non_claims"] = list(self.attestation_non_claims)
        data["canary_non_claims"] = list(self.canary_non_claims)
        data.pop("payload_fingerprint")
        return data

    def validated(self) -> "NativeCanaryAuthorizationPayload":
        if self.schema_version != AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("unsupported authorization payload")
        require_nonempty_text(self.source_repository, "authorization source repository", max_bytes=4096)
        source, source_identity = _safe_directory(self.source_repository, "authorization source repository")
        if str(source) != self.source_repository:
            raise ValueError("authorization source repository must be a canonical absolute path")
        if not isinstance(self.source_repository_identity, NativeFilesystemIdentity):
            raise ValueError("authorization source repository identity is invalid")
        self.source_repository_identity.validated()
        if not _same_directory_identity(source_identity, self.source_repository_identity):
            raise ValueError("authorization source repository identity changed")
        require_sha256(self.mission_fingerprint,"authorization mission fingerprint"); require_sha256(self.gate_plan_fingerprint,"authorization gate plan fingerprint"); require_sha256(self.gate_contract_fingerprint,"authorization gate contract fingerprint"); require_sha256(self.backend_attestation_fingerprint,"authorization backend fingerprint"); require_sha256(self.payload_fingerprint,"authorization payload fingerprint")
        require_identifier(self.run_id,"authorization run ID"); require_identifier(self.session_id,"authorization session ID"); require_nonempty_text(self.source_head,"authorization source HEAD",max_bytes=128); require_nonempty_text(self.selected_model,"authorization model",max_bytes=256); require_nonempty_text(self.fixture_version,"fixture version",max_bytes=128); require_nonempty_text(self.required_commit_message,"commit message",max_bytes=1024); require_nonempty_text(self.executable,"authorization executable",max_bytes=4096)
        if not isinstance(self.clean_worktree_required, bool) or not self.clean_worktree_required:
            raise ValueError("authorization must require a clean worktree")
        if not isinstance(self.launcher_prefix, tuple) or not self.launcher_prefix or len(set(self.launcher_prefix)) != len(self.launcher_prefix):
            raise ValueError("authorization launcher prefix is invalid")
        if not isinstance(self.budgets, tuple) or len(self.budgets) != 5:
            raise ValueError("authorization budgets are invalid")
        if not isinstance(self.attestation_non_claims, tuple) or not isinstance(self.canary_non_claims, tuple):
            raise ValueError("authorization non-claims must be immutable tuples")
        if self.backend_attestation_class == ATTESTATION_CLASS_PACKAGE_BIN:
            if tuple(self.attestation_non_claims) != PACKAGE_BIN_NON_CLAIMS: raise ValueError("authorization non-claims differ from the package-bin attestation class")
        elif self.backend_attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN:
            # The owner explicitly authorizes the weaker class with every
            # non-claim spelled out; a mismatch is not authorizable.
            if tuple(self.attestation_non_claims) != WRAPPER_CHAIN_NON_CLAIMS: raise ValueError("authorization non-claims differ from the wrapper-chain attestation class")
        else:
            raise ValueError("authorization attestation class is unsupported")
        # Exact class/reason pairing: the readiness reason is the concrete
        # preflight decision reason and cannot be swapped, dropped, or unknown.
        require_nonempty_text(self.backend_readiness_reason,"authorization readiness reason",max_bytes=256)
        if self.backend_readiness_reason != CLASS_READINESS_REASONS[self.backend_attestation_class]:
            raise ValueError("authorization readiness reason does not pair with the attestation class")
        # Canary-execution-boundary non-claims: exact membership and ordering.
        if tuple(self.canary_non_claims) != CANARY_NON_CLAIMS:
            raise ValueError("authorization canary non-claims differ from the exact committed canary boundary set")
        # Roots: absolute, canonical, deterministic committed children, and
        # disjoint/outside the source repository where required.
        for value, label in ((self.run_root, "authorization run root"), (self.workspace_root, "authorization workspace root"), (self.evidence_root, "authorization evidence root"), (self.native_sidecar_root, "authorization native sidecar root")):
            require_nonempty_text(value, label, max_bytes=4096)
        run_root=_lexical_absolute(self.run_root,"authorization run root"); evidence_root=_lexical_absolute(self.evidence_root,"authorization evidence root"); workspace_root=_lexical_absolute(self.workspace_root,"authorization workspace root"); sidecar_root=_lexical_absolute(self.native_sidecar_root,"authorization native sidecar root")
        if (str(run_root),str(evidence_root),str(workspace_root),str(sidecar_root)) != (self.run_root,self.evidence_root,self.workspace_root,self.native_sidecar_root):
            raise ValueError("authorization roots must be canonical absolute paths")
        if evidence_root != run_root / EVIDENCE_DIRECTORY_NAME: raise ValueError("evidence root must be the committed deterministic child of the run root")
        if workspace_root != run_root / WORKSPACE_DIRECTORY_NAME: raise ValueError("workspace root must be the committed deterministic child of the run root")
        if sidecar_root != evidence_root / NATIVE_SIDECAR_DIRECTORY_NAME: raise ValueError("native sidecar root must be the committed deterministic child of the evidence root")
        if _inside(run_root,source) or _inside(source,run_root): raise ValueError("run root must be outside the source repository")
        if workspace_root == evidence_root or _inside(workspace_root,evidence_root) or _inside(evidence_root,workspace_root): raise ValueError("workspace and evidence roots must be disjoint")
        for value in self.launcher_prefix: require_nonempty_text(value,"authorization launcher path",max_bytes=4096)
        for value in self.budgets: require_strict_int(value,"authorization budget",minimum=0,maximum=1)
        require_strict_int(self.timeout_seconds,"authorization timeout",minimum=1,maximum=3600); require_strict_int(self.stdout_byte_limit,"authorization stdout limit",minimum=1,maximum=16*1024*1024); require_strict_int(self.stderr_byte_limit,"authorization stderr limit",minimum=1,maximum=16*1024*1024)
        if fingerprint(self._body())!=self.payload_fingerprint: raise ValueError("authorization payload fingerprint mismatch")
        return self

    def validated_for_authorization(self, *, active_source_repository: str | Path) -> "NativeCanaryAuthorizationPayload":
        """Bind an already-structural payload to the trusted active source root.

        This deliberately does not run Git or launch a backend.  The caller that
        grants live authority checks HEAD and cleanliness against this same active
        root immediately before phrase-bound authorization.
        """

        self.validated()
        active, active_identity = _safe_directory(active_source_repository, "active authorization source repository")
        signed, signed_identity = _safe_directory(self.source_repository, "authorization source repository")
        if (
            str(active) != self.source_repository
            or active != signed
            or not _same_directory_identity(active_identity, signed_identity)
            or not _same_directory_identity(active_identity, self.source_repository_identity)
        ):
            raise ValueError("authorization source repository differs from the active source repository")
        return self

    def to_dict(self) -> dict[str, Any]:
        data=self._body(); data["payload_fingerprint"]=self.payload_fingerprint; return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCanaryAuthorizationPayload":
        """Parse persisted review data without granting executable authority."""

        require_exact_keys(data, set(cls.__dataclass_fields__), "native canary authorization payload")
        values = dict(data)
        values["source_repository_identity"] = NativeFilesystemIdentity.from_dict(data["source_repository_identity"])
        for key in ("launcher_prefix", "attestation_non_claims", "canary_non_claims"):
            raw = data[key]
            if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw) or len(set(raw)) != len(raw):
                raise ValueError(f"authorization {key} must be a duplicate-free JSON string array")
            values[key] = tuple(raw)
        raw_budgets = data["budgets"]
        if not isinstance(raw_budgets, list) or len(raw_budgets) != 5:
            raise ValueError("authorization budgets must be a five-item JSON array")
        values["budgets"] = tuple(raw_budgets)
        return cls(**values).validated()


def build_authorization_payload(*, source_repository: Path, source_head: str, run_id: str, session_id: str, attestation: BackendAttestation, run_root: str | Path, timeout_seconds: int, backend_readiness_reason: str | None = None) -> NativeCanaryAuthorizationPayload:
    state=create_canary_session(session_id=session_id); source, source_identity=_safe_directory(source_repository,"authorization source repository"); root=Path(os.path.abspath(os.fspath(run_root))); evidence=root / EVIDENCE_DIRECTORY_NAME; workspace=root / WORKSPACE_DIRECTORY_NAME; sidecar=evidence / NATIVE_SIDECAR_DIRECTORY_NAME; attestation=attestation.validated()
    # The readiness reason is the concrete preflight decision reason; when the
    # caller does not thread one through it defaults to the exact class pairing.
    readiness_reason=backend_readiness_reason if backend_readiness_reason is not None else CLASS_READINESS_REASONS.get(attestation.attestation_class,"")
    provisional=NativeCanaryAuthorizationPayload(AUTHORIZATION_SCHEMA_VERSION,str(source),source_identity,source_head.lower(),True,run_id,session_id,state.mission.mission_fingerprint,state.gate_plan.plan_fingerprint,state.current_gate.contract_fingerprint,attestation.attestation_class,readiness_reason,attestation.attestation_fingerprint,tuple(attestation.non_claims),CANARY_NON_CLAIMS,attestation.executable.canonical_path,tuple(item.canonical_path for item in attestation.launcher_prefix),attestation.selected_model,timeout_seconds,DEFAULT_STDOUT_BYTE_LIMIT,DEFAULT_STDERR_BYTE_LIMIT,(1,1,0,0,0),CANARY_FIXTURE_VERSION,REQUIRED_COMMIT_MESSAGE,str(root),str(workspace),str(evidence),str(sidecar),"0"*64)
    return NativeCanaryAuthorizationPayload(**{**provisional.__dict__,"payload_fingerprint":fingerprint(provisional._body())}).validated()


def _authorized(phrase: str, payload: NativeCanaryAuthorizationPayload, *, active_source_repository: str | Path) -> bool:
    try:
        if not isinstance(phrase, str):
            return False
        payload.validated_for_authorization(active_source_repository=active_source_repository)
    except (TypeError, ValueError):
        return False
    expected=os.environ.get(OWNER_AUTHORIZATION_DIGEST_ENV,"")
    if len(expected)!=64 or any(char not in "0123456789abcdefABCDEF" for char in expected): return False
    observed=hashlib.sha256(phrase.encode("utf-8")+b"\0"+canonical_bytes(payload.to_dict())).hexdigest()
    return hmac.compare_digest(observed,expected.lower())


def _write_run_metadata_once(path: Path, payload: Mapping[str, Any]) -> None:
    """Persist non-authority CLI status metadata without reusing sidecar logic.

    Native request/result/behavioral evidence has the stronger locked durable
    store boundary.  These two operator-facing CLI files are deliberately not
    execution authority and are never read to authorize a run.
    """

    parent, _ = _safe_directory(path.parent, "canary metadata parent")
    if path.parent != parent:
        raise NativeEvidenceInvalid("canary metadata parent differs from the canonical path")
    try:
        with path.open("xb") as handle:
            handle.write(canonical_bytes(dict(payload)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise NativeEvidenceInvalid("canary metadata is write-once") from exc


def _validate_future_run_root(
    *, run_root_value: str | Path, run_id: str, source: Path
) -> Path:
    run_root = _lexical_absolute(run_root_value, "future run root")
    require_identifier(run_id, "future run ID")
    if run_root.name != run_id:
        raise ValueError("run root basename must equal the fresh run ID")
    if run_root.exists() or _inside(run_root, source) or _inside(source, run_root):
        raise ValueError("run root must be fresh and non-overlapping with source")
    _safe_directory(run_root.parent, "run root parent")
    return run_root


def build_parser() -> argparse.ArgumentParser:
    parser=argparse.ArgumentParser(prog="python -m admissible.delegated_gate.native_canary",description="Future-only one-shot locally-attested native Cursor canary")
    parser.add_argument("--source-repository",required=True); parser.add_argument("--required-source-head",required=True); parser.add_argument("--run-root",required=True); parser.add_argument("--run-id",required=True); parser.add_argument("--session-id",required=True)
    parser.add_argument("--executable",required=True); parser.add_argument("--executable-prefix-arg",action="append",default=[]); parser.add_argument("--model",default="auto"); parser.add_argument("--timeout-seconds",type=int,default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--attestation-class",choices=["package-bin","wrapper-chain"],default="package-bin",help="Explicit attestation class. wrapper-chain is the weaker LOCAL_WRAPPER_CHAIN class: it derives every launcher file from canonical host cursor-agent discovery, establishes no publisher provenance, and requires owner authorization naming that exact class.")
    parser.add_argument("--owner-authorization",help="Explicit owner phrase; never persisted"); parser.add_argument("--preflight-only",action="store_true",help="Print local attestation and authorization payload without creating a run")
    return parser


def main(argv: list[str] | None = None) -> int:
    args=build_parser().parse_args(argv); blocked={"status":NativeCanaryStatus.PREFLIGHT_BLOCKED.value,"provider_invocations":0,"canary_success":False}
    if not 1<=args.timeout_seconds<=3600: print(json.dumps({**blocked,"detail":"timeout must be from 1 through 3600 seconds"},sort_keys=True)); return 2
    try: source,_=_safe_directory(args.source_repository,"source repository")
    except ValueError as exc: print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    attestation_class=ATTESTATION_CLASS_WRAPPER_CHAIN if args.attestation_class=="wrapper-chain" else ATTESTATION_CLASS_PACKAGE_BIN
    try: config=CursorNativeBackendConfig(executable=args.executable,launcher_prefix=tuple(args.executable_prefix_arg),model=args.model,attestation_class=attestation_class)
    except ValueError as exc: print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    try:
        # Gate construction/validation is part of source/backend/gate preflight
        # and has no filesystem or authorization side effect.
        create_canary_session(session_id=args.session_id)
    except ValueError as exc:
        print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    decision:NativePreflightDecision=preflight_native_cursor(config=config)
    where_diagnostic=decision.where_diagnostic.to_dict() if decision.where_diagnostic is not None else None
    if not decision.ready or decision.attestation is None: print(json.dumps({**blocked,"detail":decision.detail,"reason_code":decision.reason_code,"where_diagnostic":where_diagnostic},sort_keys=True)); return 2
    ready,detail=_git_source_preflight(source,args.required_source_head)
    if not ready: print(json.dumps({**blocked,"detail":detail,"where_diagnostic":where_diagnostic},sort_keys=True)); return 2
    try:
        future_run_root=_validate_future_run_root(
            run_root_value=args.run_root, run_id=args.run_id, source=source
        )
    except ValueError as exc:
        print(json.dumps({**blocked,"detail":str(exc),"where_diagnostic":where_diagnostic},sort_keys=True)); return 2
    capability: DurabilityCapabilityResult = probe_platform_durability(
        parent=future_run_root.parent,
        source_root=source,
        future_run_root=future_run_root,
    )
    capability_diagnostic=capability.to_dict()
    if not capability.ready:
        print(json.dumps({
            **blocked,
            "detail":capability.detail,
            "reason_code":capability.reason_code,
            "where_diagnostic":where_diagnostic,
            "durability_capability":capability_diagnostic,
        },sort_keys=True)); return 2
    try:
        payload=build_authorization_payload(source_repository=source,source_head=args.required_source_head,run_id=args.run_id,session_id=args.session_id,attestation=decision.attestation,run_root=args.run_root,timeout_seconds=args.timeout_seconds,backend_readiness_reason=decision.reason_code)
        payload.validated_for_authorization(active_source_repository=source)
    except ValueError as exc:
        print(json.dumps({**blocked,"detail":str(exc),"where_diagnostic":where_diagnostic,"durability_capability":capability_diagnostic},sort_keys=True)); return 2
    if args.preflight_only: print(json.dumps({"status":NativePreflightStatus.PREFLIGHT_READY.value,"authorization_payload":payload.to_dict(),"attestation":decision.attestation.to_dict(),"where_diagnostic":where_diagnostic,"durability_capability":capability_diagnostic},sort_keys=True)); return 0
    if not args.owner_authorization or not _authorized(args.owner_authorization,payload,active_source_repository=source): print(json.dumps({**blocked,"detail":"owner authorization did not match the exact canonical payload","durability_capability":capability_diagnostic},sort_keys=True)); return 2
    try:
        # Recheck freshness after authorization; the successful probe itself
        # never creates or reserves the future run root.
        run_root=_validate_future_run_root(
            run_root_value=args.run_root, run_id=args.run_id, source=source
        )
    except ValueError as exc:
        print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    run_root.mkdir(); _safe_directory(run_root,"run root"); fixture=build_canary_repository(run_root,repository_name=WORKSPACE_DIRECTORY_NAME); evidence=(run_root/EVIDENCE_DIRECTORY_NAME); evidence.mkdir(); _safe_directory(evidence,"evidence directory")
    _write_run_metadata_once(evidence/"canary-preflight.json",{"classification":CANARY_CLASSIFICATION,"authorization_payload":payload.to_dict(),"attestation":decision.attestation.to_dict(),"local_capability_status":decision.status.value,"durability_capability":capability_diagnostic})
    session_store=AtomicDelegatedSessionStore(evidence/"delegated-state"); execution_store=AtomicNativeExecutionStore(evidence/NATIVE_SIDECAR_DIRECTORY_NAME); session_store.create(create_canary_session(session_id=args.session_id))
    coordinator=NativeCanaryCoordinator(session_store=session_store,execution_store=execution_store,executor=NativeDelegatedExecutor(config=config),backend_attestation=decision.attestation,source_repository=source,work_workspace=fixture.repository,canary_parent=run_root,evidence_directory=evidence,timeout_seconds=args.timeout_seconds)
    outcome=coordinator.run(session_id=args.session_id); _write_run_metadata_once(evidence/"final-status.json",outcome.to_dict()); print(json.dumps(outcome.to_dict(),sort_keys=True)); return 0 if outcome.canary_success else 1


if __name__ == "__main__": sys.exit(main())


__all__=["AUTHORIZATION_SCHEMA_VERSION","AUTHORIZATION_SCHEMA_VERSION_LEGACY_V2","CANARY_NON_CLAIMS","CLASS_READINESS_REASONS","EVIDENCE_DIRECTORY_NAME","NATIVE_SIDECAR_DIRECTORY_NAME","PACKAGE_BIN_READY_REASON","WORKSPACE_DIRECTORY_NAME","BEHAVIORAL_EVIDENCE_SCHEMA_VERSION","CANARY_CLASSIFICATION","CANARY_FIXTURE_VERSION","CANARY_GATE_ID","CANARY_MISSION","CANARY_MISSION_ID","DEFAULT_STDERR_BYTE_LIMIT","DEFAULT_STDOUT_BYTE_LIMIT","DEFAULT_TIMEOUT_SECONDS","EXPECTED_MATERIAL_PATHS","FixtureRepository","MAX_AUDITOR_INVOCATIONS","MAX_NATIVE_PHASE_ATTEMPTS","MAX_PROVIDER_INVOCATIONS","MAX_REPAIR_ROUNDS","MAX_RETRIES","NativeCanaryAuthorizationPayload","NativeCanaryCoordinator","NativeCanaryOutcome","NativeCanaryStatus","OWNER_AUTHORIZATION_DIGEST_ENV","REQUIRED_COMMIT_MESSAGE","BehavioralVerifierEvidence","build_authorization_payload","build_canary_repository","build_native_agent_prompt","build_parser","create_canary_session","load_behavioral_verifier","main","npm_test_argv","run_behavioral_verifier","_validate_future_run_root"]
