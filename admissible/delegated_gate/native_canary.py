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
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping

import functools

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint, require_exact_keys, require_identifier, require_nonempty_text, require_safe_relative_path, require_sha256, require_strict_int
from admissible.delegated_gate.checkpoint import capture_checkpoint
from admissible.delegated_gate.fixture_registry import (
    INCIDENT_BOARD_FIXTURE_ID,
    INCIDENT_BOARD_FIXTURE_VERSION,
    NEON_SIEGE_FIXTURE_ID,
    NEON_SIEGE_FIXTURE_VERSION,
    WORKFLOW_CONSOLE_FIXTURE_ID,
    WORKFLOW_CONSOLE_FIXTURE_VERSION,
    build_incident_board_repository,
    build_neon_siege_blank_repository,
    build_workflow_console_repository,
    fixture_material_tree_hash,
)
from admissible.delegated_gate.mission_profile import (
    FLAGSHIP_INCIDENT_REPLAY_PROFILE,
    NEON_SIEGE_PROFILE,
    ONE_SHOT_PROFILE_BUDGETS,
    WORKFLOW_RECOVERY_PROFILE,
    WORKFLOW_RECOVERY_V2_PROFILE,
    GitEndStatePolicy,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    NativeMissionProfile,
    ProfileCheckpointCommand,
    VerificationMode,
    WorkspaceSourceKind,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
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
    NativeExecutionStoreError,
    NativeExecutionRequestBinding,
    NativeLifecycleCounts,
    NativeArtifactReference,
    NativeFilesystemIdentity,
    NativePreflightDecision,
    NativePreflightStatus,
    NativeProcessObservationPublicationError,
    NativeProcessStartError,
    NativeResultIneligible,
    _result_from_observation,
    _inside,
    _hardened_git_environment,
    _safe_create_directory,
    _safe_directory,
    _safe_file,
    _same_directory_identity,
    _same_mutable_directory_entry,
    _structural_request_binding,
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
# v4 authorization payloads embed the complete canonical mission profile and
# the independently observed initialized-workspace identity.  Legacy
# canary-004 remains exactly on v3 and is never rewritten or reinterpreted.
AUTHORIZATION_SCHEMA_VERSION_V4 = "admissible_native_canary_authorization_v4"
# Deterministic evidence-directory metadata file the committed CLI writes
# before execution.  Evidence-only reconstruction of a v4 run loads the
# authoritative mission profile from this persisted payload alone.
RUN_PREFLIGHT_METADATA_FILE_NAME = "canary-preflight.json"
LEGACY_CANARY_PROFILE_ID = "act-2a-high-score-canary-v1"
LEGACY_CANARY_FIXTURE_ID = "act-2a-canary-game-state"
LEGACY_CANARY_FIXTURE_VERSION = 2
LEGACY_CANARY_FIXTURE_INITIAL_COMMIT_MESSAGE = "chore: initialize native executor canary"
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
PRODUCT_OUTCOME_SCHEMA_VERSION = "admissible_native_product_outcome_v1"
EXPECTED_MATERIAL_PATHS = frozenset({"README.md", "src/game-state.js", "src/score.js", "test/game-state.test.js"})

CANARY_MISSION = """Add deterministic high-score persistence to this small game-state package.
Implement the feature across the existing source modules, add tests using the existing Node test runner,
run the complete npm test suite, update the README, and create one local Git commit with the exact message
`feat: add deterministic high-score persistence`. Do not add a remote and do not push. Stop after the local commit."""


class NativeCanaryStatus(str, Enum):
    PREFLIGHT_BLOCKED = "PREFLIGHT_BLOCKED"
    EXECUTION_RESULT_MISSING_NO_RETRY = "EXECUTION_RESULT_MISSING_NO_RETRY"
    ATTEMPT_RESERVED_LAUNCH_OUTCOME_UNKNOWN = "ATTEMPT_RESERVED_LAUNCH_OUTCOME_UNKNOWN"
    PROCESS_OBSERVATION_MISSING = "PROCESS_OBSERVATION_MISSING"
    EXECUTION_ELIGIBILITY_MISSING = "EXECUTION_ELIGIBILITY_MISSING"
    ACCEPTED_RESULT_MISSING = "ACCEPTED_RESULT_MISSING"
    PROCESS_SPAWN_FAILED = "PROCESS_SPAWN_FAILED"
    PROCESS_OBSERVATION_PUBLICATION_FAILED = "PROCESS_OBSERVATION_PUBLICATION_FAILED"
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


class ProductVerdict(str, Enum):
    ADMITTED_OBSERVED = "ADMITTED_OBSERVED"
    ADMITTED_VERIFIED = "ADMITTED_VERIFIED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class FixtureRepository:
    repository: Path
    initial_head: str
    initial_material_tree_hash: str
    mission: str = CANARY_MISSION
    required_commit_message: str | None = REQUIRED_COMMIT_MESSAGE


@dataclass(frozen=True)
class NativeCanaryOutcome:
    status: NativeCanaryStatus
    session_id: str
    phase: str
    request_fingerprint: str | None
    result_fingerprint: str | None
    checkpoint_fingerprint: str | None
    provider_invocations: int
    native_attempts_reserved: int
    native_processes_started: int
    native_processes_completed: int
    process_observations_published: int
    accepted_native_results_published: int
    canary_success: bool
    detail: str
    behavioral_evidence_fingerprint: str | None = None
    capture_attempt_fingerprint: str | None = None
    workspace_final_git_head: str | None = None
    product_verdict: str | None = None
    verification_mode: str | None = None
    behavioral_non_claim: str | None = None
    exact_classification: str | None = None
    failing_boundary: str | None = None
    evidence_fingerprint: str | None = None
    checkpoint_status: str | None = None
    verifier_source_sha256: str | None = None
    behavioral_verifier_passed: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "status": self.status.value, "session_id": self.session_id, "phase": self.phase,
            "request_fingerprint": self.request_fingerprint, "result_fingerprint": self.result_fingerprint,
            "checkpoint_fingerprint": self.checkpoint_fingerprint, "provider_invocations": self.provider_invocations,
            "native_attempts_reserved": self.native_attempts_reserved,
            "native_processes_started": self.native_processes_started,
            "native_processes_completed": self.native_processes_completed,
            "process_observations_published": self.process_observations_published,
            "accepted_native_results_published": self.accepted_native_results_published,
            "canary_success": self.canary_success, "detail": self.detail,
            "behavioral_evidence_fingerprint": self.behavioral_evidence_fingerprint,
            "capture_attempt_fingerprint": self.capture_attempt_fingerprint,
            "workspace_final_git_head": self.workspace_final_git_head,
            "authorized_budgets": {"provider_invocations": 1, "native_phase_attempts": 1, "repair_rounds": 0, "auditor_invocations": 0, "retries": 0},
            "budgets": {"provider_invocations": 1, "native_phase_attempts": 1, "repair_rounds": 0, "auditor_invocations": 0, "retries": 0},
        }
        if self.product_verdict is not None:
            data.update(
                product_outcome_schema_version=PRODUCT_OUTCOME_SCHEMA_VERSION,
                product_verdict=self.product_verdict,
                verification_mode=self.verification_mode,
                behavioral_non_claim=self.behavioral_non_claim,
                exact_classification=self.exact_classification,
                failing_boundary=self.failing_boundary,
                evidence_fingerprint=self.evidence_fingerprint,
                checkpoint_status=self.checkpoint_status,
                verifier_source_sha256=self.verifier_source_sha256,
                behavioral_verifier_passed=self.behavioral_verifier_passed,
            )
            data["product_outcome_fingerprint"] = fingerprint(data)
        return data


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


def _legacy_completion_conditions(required_commit_message: str) -> str:
    """The exact historical Act-2A prompt completion-conditions block."""

    return f"""Required completion conditions:
- run the complete `npm test` suite;
- create exactly one intended local feature commit with complete message `{required_commit_message}`;
- use no `--trailer` when creating or amending the commit;
- add no commit-message body, `Co-authored-by`, sign-off, attribution, or other trailer;
- before stopping, run `git log -1 --format=%B` and verify that its complete output, after removing terminal newline characters only, is exactly `{required_commit_message}`;
- if the complete message is not exact, amend that same commit during this native invocation, do not create a second commit, and run the exact `%B` verification again;
- do not add or modify a Git remote;
- do not push;
- stop immediately only after the exact full-message verification passes."""


@functools.lru_cache(maxsize=1)
def legacy_canary_profile() -> NativeMissionProfile:
    """The historical canary-004 mission as one canonical profile.

    Every value reproduces the exact Act-2A module-constant semantics so the
    legacy execution, prompt, session, and reconstruction behavior remain
    byte-identical.  It is the fail-closed default whenever no profile is
    selected and no v4 authorization payload is persisted.
    """

    return create_native_mission_profile(
        profile_id=LEGACY_CANARY_PROFILE_ID,
        fixture_id=LEGACY_CANARY_FIXTURE_ID,
        fixture_version=LEGACY_CANARY_FIXTURE_VERSION,
        run_id="native-cursor-canary-004",
        session_id="native-cursor-canary-004",
        gate_id=CANARY_GATE_ID,
        mission_id=CANARY_MISSION_ID,
        mission_text=CANARY_MISSION,
        gate_objective="Complete and locally commit deterministic high-score persistence in the assigned canary repository.",
        gate_clauses=(
            ("native-canary.material", "The committed material implements deterministic high-score persistence."),
            ("native-canary.tests", "The complete npm test suite passes independently at checkpoint capture."),
            ("native-canary.git", "The exact local commit exists, the worktree is clean, and no remote exists."),
        ),
        required_evidence_kinds=(EvidenceKind.TARGET_TREE.value, EvidenceKind.GIT_STATE.value, EvidenceKind.VERIFICATION_COMMAND.value),
        checkpoint_commands=(ProfileCheckpointCommand(command_id="npm-test", argv=npm_test_argv(), timeout_seconds=120, max_capture_bytes=256 * 1024),),
        required_commit_message=REQUIRED_COMMIT_MESSAGE,
        required_material_paths=tuple(sorted(EXPECTED_MATERIAL_PATHS)),
        completion_conditions_text=_legacy_completion_conditions(REQUIRED_COMMIT_MESSAGE),
        verifier_source=_BEHAVIORAL_SCRIPT,
        verifier_source_sha256=hashlib.sha256(_BEHAVIORAL_SCRIPT.encode("utf-8")).hexdigest(),
        verifier_timeout_seconds=60,
        verifier_output_limit_bytes=128 * 1024,
        budgets=ONE_SHOT_PROFILE_BUDGETS,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        stdout_byte_limit=DEFAULT_STDOUT_BYTE_LIMIT,
        stderr_byte_limit=DEFAULT_STDERR_BYTE_LIMIT,
        model="auto",
        fixture_initial_commit_message=LEGACY_CANARY_FIXTURE_INITIAL_COMMIT_MESSAGE,
    )


def registered_profiles() -> dict[str, NativeMissionProfile]:
    """The exact source-controlled profile registry (pre-run selection only)."""

    return {
        profile.profile_id: profile
        for profile in (
            legacy_canary_profile(),
            FLAGSHIP_INCIDENT_REPLAY_PROFILE,
            WORKFLOW_RECOVERY_PROFILE,
            WORKFLOW_RECOVERY_V2_PROFILE,
            NEON_SIEGE_PROFILE,
        )
    }


def resolve_registered_profile(profile_id: str) -> NativeMissionProfile:
    profiles = registered_profiles()
    if profile_id not in profiles:
        raise ValueError(f"unknown mission profile: {profile_id!r}")
    return profiles[profile_id].validated()


def fixture_builder_registry() -> dict[tuple[str, int], Any]:
    """Trusted executable fixture builders keyed by the exact identity pair."""

    return {
        (LEGACY_CANARY_FIXTURE_ID, LEGACY_CANARY_FIXTURE_VERSION): build_canary_repository,
        (INCIDENT_BOARD_FIXTURE_ID, INCIDENT_BOARD_FIXTURE_VERSION): build_incident_board_repository,
        (WORKFLOW_CONSOLE_FIXTURE_ID, WORKFLOW_CONSOLE_FIXTURE_VERSION): build_workflow_console_repository,
        (NEON_SIEGE_FIXTURE_ID, NEON_SIEGE_FIXTURE_VERSION): build_neon_siege_blank_repository,
    }


def resolve_fixture_builder(fixture_id: str, fixture_version: int) -> Any:
    """Exact registry hit only: no fallback, no closest version, no default."""

    builders = fixture_builder_registry()
    key = (fixture_id, fixture_version)
    if key not in builders:
        raise ValueError(f"unknown fixture builder: {fixture_id!r} version {fixture_version!r}")
    return builders[key]


def create_canary_session(*, session_id: str, profile: NativeMissionProfile | None = None) -> DelegatedSessionState:
    profile = (profile if profile is not None else legacy_canary_profile()).validated()
    if profile.has_nested_runtime_authority and not profile.is_launchable_runtime_profile:
        raise ValueError("native canary sessions require the launchable runtime-v2 schema")
    mission = Mission.create(mission_id=profile.mission_id, specification=profile.mission_text)
    gate = GateContract.create(
        gate_id=profile.gate_id, objective=profile.gate_objective,
        clauses=tuple(GateClause(clause_id, text) for clause_id, text in profile.gate_clauses),
        required_evidence_kinds=tuple(EvidenceKind(kind) for kind in profile.required_evidence_kinds),
        checkpoint_verification_commands=tuple(command.to_verification_command() for command in profile.checkpoint_commands), repair_budget=0,
    )
    return new_session_state(session_id=session_id, mission=mission, gate_plan=GatePlan.create(mission=mission, ordered_gate_contracts=(gate,)))


def build_native_agent_prompt(*, mission: Mission, gate_contract: GateContract, work_workspace: str | Path, required_commit_message: str | None = REQUIRED_COMMIT_MESSAGE, completion_conditions: str | None = None, profile: NativeMissionProfile | None = None) -> str:
    mission.validated(); gate_contract.validated(); workspace, _ = _safe_directory(work_workspace, "assigned work workspace")
    clauses = "\n".join(f"- [{clause.clause_id}] {clause.text}" for clause in gate_contract.clauses)
    if profile is not None:
        profile = profile.validated()
        if profile.has_nested_runtime_authority and not profile.is_launchable_runtime_profile:
            raise ValueError("native agent prompts require the launchable runtime-v2 schema")
    if profile is not None and profile.is_launchable_runtime_profile:
        policy = profile.effective_git_end_state_policy
        verification = profile.verification.validated()
        prompt_authority = profile.runtime_prompt.validated()
        materials = "\n".join(f"- {path}" for path in policy.required_material_paths)
        effects_allowed = "\n".join(f"- {value}" for value in prompt_authority.permitted_effects)
        effects_forbidden = "\n".join(f"- {value}" for value in prompt_authority.forbidden_effects)
        checkpoints = (
            "\n".join(
                f"- {command.command_id}: argv={json.dumps(list(command.argv), ensure_ascii=False)}; "
                f"timeout_seconds={command.timeout_seconds}; max_capture_bytes={command.max_capture_bytes}"
                for command in profile.checkpoint_commands
            )
            if profile.checkpoint_commands
            else "- none configured"
        )
        commit_message = (
            f"exact complete `%B` = {policy.required_complete_commit_message!r}; no body, trailer, "
            "sign-off or attribution is permitted"
            if policy.required_complete_commit_message is not None
            else "no exact complete commit message is configured"
        )
        verification_block = (
            "Admissible will independently inspect the resulting process, workspace,\n"
            "Git/material state and configured checkpoint commands. It will not\n"
            "independently verify the requested behavior.\n"
            "Behavior was not independently verified."
            if verification.mode is VerificationMode.OBSERVED_ONLY
            else (
                "The following complete source is the owner-frozen independent acceptance contract.\n"
                f"Verifier SHA-256: {verification.verifier_source_sha256}\n"
                "----- BEGIN OWNER-FROZEN BEHAVIORAL VERIFIER -----\n"
                f"{verification.verifier_source}\n"
                "----- END OWNER-FROZEN BEHAVIORAL VERIFIER -----"
            )
        )
        provider, attempts, repairs, auditors, retries = profile.budgets
        return f"""{NATIVE_PROMPT_HEADER}

Immutable mission:
{mission.specification}

Current gate objective:
{gate_contract.objective}

Gate clauses:
{clauses}

Your exact assigned workspace is:
{workspace}

Permitted effects:
{effects_allowed}

Forbidden effects:
{effects_forbidden}

Required material paths:
{materials}

Exact Git end-state policy:
- required commits added after initialization: {policy.required_commits_added}
- required commit message: {commit_message}
- final worktree clean: {str(policy.final_worktree_clean).lower()}
- final index clean: {str(policy.final_index_clean).lower()}
- final remotes absent: {str(policy.final_remotes_absent).lower()}

Execution budgets:
- provider invocations: {provider}
- native attempts: {attempts}
- repair rounds: {repairs}
- execution-time auditors: {auditors}
- retries: {retries}
- process timeout seconds: {profile.timeout_seconds}
- stdout byte limit: {profile.stdout_byte_limit}
- stderr byte limit: {profile.stderr_byte_limit}

Checkpoint commands and bounds:
{checkpoints}

Verification mode: {verification.mode.value}
{verification_block}

Configured completion conditions:
{profile.completion_conditions_text}

Exact stop clause:
{prompt_authority.stop_clause}

Do not merely describe changes. Perform the work inside the assigned workspace.
"""
    completion_block = completion_conditions if completion_conditions is not None else _legacy_completion_conditions(required_commit_message)
    require_nonempty_text(completion_block, "completion conditions", max_bytes=16384)
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

{completion_block}

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


def _behavioral_entry_validated(*, request: NativeExecutionRequest, execution_store: AtomicNativeExecutionStore) -> None:
    """Validate behavioral-verifier entry without re-observing the live backend.

    Backend authority follows one coherent law: before provider spawn the
    executor requires full strict wrapper-chain attestation equality, and
    after provider completion the persisted post-run eligibility decision is
    the only backend-drift authority.  Re-running the strict live attestation
    here would compare the stale pre-run selected-version-root identity
    against a catalog the provider itself legitimately touched (for example
    its own ``.running`` marker), re-refusing exactly the isolated
    metadata-only condition the eligibility lane already admitted.  This
    entry therefore validates the immutable request structure against the
    durable canonical request bytes and defers drift adjudication to the
    persisted eligibility record.  It cannot substitute for pre-spawn
    attestation: without a durable post-run eligibility decision it always
    fails closed, and blocking drift keeps ``eligible`` false upstream.
    """

    structural = _structural_request_binding(request.to_dict())
    durable = execution_store.load_request_structural(request.session_id, request.gate_id, request.execution_attempt_index)
    if structural != durable:
        raise NativeEvidenceInvalid("behavioral entry request differs from the durable native request")
    if not execution_store.has_execution_eligibility(request.session_id, request.gate_id, request.execution_attempt_index):
        raise NativeEvidenceInvalid("behavioral verification requires the persisted post-run eligibility decision")
    eligibility = execution_store.load_execution_eligibility(request.session_id, request.gate_id, request.execution_attempt_index)
    if not eligibility.eligible or eligibility.ineligibility_reasons:
        raise NativeEvidenceInvalid("persisted post-run eligibility rejects behavioral verification")


def run_behavioral_verifier(*, request: NativeExecutionRequest, execution_store: AtomicNativeExecutionStore, timeout_seconds: int = 60, output_limit: int = 128 * 1024, verifier_source: str | None = None) -> BehavioralVerifierEvidence:
    _behavioral_entry_validated(request=request, execution_store=execution_store)
    workspace, identity = _safe_directory(request.work_workspace, "behavioral verifier workspace")
    if str(workspace) != request.work_workspace or not _same_mutable_directory_entry(identity, request.work_workspace_identity):
        raise NativeEvidenceInvalid("behavioral verifier workspace path or identity changed")
    source = verifier_source if verifier_source is not None else _BEHAVIORAL_SCRIPT
    require_nonempty_text(source, "behavioral verifier source", max_bytes=262144)
    if execution_store.has_behavioral_evidence(request.session_id,request.gate_id,request.execution_attempt_index):
        return load_behavioral_verifier(request=request,execution_store=execution_store,verifier_source=source)
    prefix=f"{request.session_id}.{request.gate_id}.attempt-{request.execution_attempt_index}.behavioral"
    script=execution_store.write_behavioral_artifact(request=request,artifact_id=f"{prefix}.script",purpose="behavioral-script",data=source.encode("utf-8"))
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


def load_behavioral_verifier(*, request: NativeExecutionRequest | NativeExecutionRequestBinding, execution_store: AtomicNativeExecutionStore, verifier_source: str | None = None) -> BehavioralVerifierEvidence:
    source = verifier_source if verifier_source is not None else _BEHAVIORAL_SCRIPT
    try: evidence=execution_store.load_behavioral_evidence(request.session_id,request.gate_id,request.execution_attempt_index,loader=BehavioralVerifierEvidence.from_dict)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc: raise NativeEvidenceInvalid(f"behavioral verifier evidence is invalid: {exc}") from exc
    if evidence.request_fingerprint!=request.request_fingerprint: raise NativeEvidenceInvalid("behavioral verifier evidence differs from the durable request")
    script_path=execution_store.directory / evidence.script.relative_path
    if script_path.read_bytes()!=source.encode("utf-8"): raise NativeEvidenceInvalid("behavioral verifier script differs from the harness-owned source")
    return evidence


def _pre_capture_reason(result: NativeExecutionResult, behavioral: BehavioralVerifierEvidence | None, profile: NativeMissionProfile | None = None) -> str | None:
    profile = profile if profile is not None else legacy_canary_profile()
    policy = profile.effective_git_end_state_policy
    try: result.validated()
    except (NativeEvidenceInvalid, ValueError) as exc: return f"native result workspace observations no longer validate: {exc}"
    if result.status is not NativeExecutionStatus.PROCESS_SUCCEEDED: return "native process did not succeed"
    if result.timed_out or not result.cleanup_confirmed or result.orphan_process_ids: return "native cleanup is not confirmed"
    if result.source_repository_mutated or result.unexpected_sibling_mutations: return "measured workspace boundary changed"
    if policy.final_remotes_absent and result.final_git_remotes: return "canary repository has a remote"
    if result.initial_git_head is None or result.final_git_head is None or result.final_git_head == result.initial_git_head: return "final Git HEAD did not change"
    if result.commits_added != policy.required_commits_added: return "configured number of new commits is required"
    if policy.required_complete_commit_message is not None and result.final_commit_message != policy.required_complete_commit_message: return "final complete commit message differs"
    status_lines = tuple(line for line in result.final_git_porcelain_status.splitlines() if line)
    if policy.final_worktree_clean and any(len(line) < 2 or line[1] != " " or line.startswith("??") for line in status_lines): return "final worktree is not clean"
    if policy.final_index_clean and any(len(line) < 2 or line[0] not in {" ", "?"} for line in status_lines): return "final index is not clean"
    if not frozenset(policy.required_material_paths).issubset(set(result.changed_material_files)): return "required material paths did not all change"
    if profile.verification_mode is VerificationMode.FROZEN_BEHAVIORAL:
        if behavioral is None or behavioral.timed_out or behavioral.exit_code != 0: return "immutable behavioral verifier did not pass"
    elif behavioral is not None:
        return "observed-only execution cannot carry behavioral verifier evidence"
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


class EvidenceOnlyCanaryReconstruction:
    """Read-only interpreter of persisted canary evidence.

    It binds only the durable execution store and the evidence directory.  It
    holds no executor, backend attestation, source repository, canary parent,
    or provider handle, so a caller constructing this type alone can veto but
    never grant native execution, retry, repair, capture, or attempt one.
    """

    def __init__(self, *, execution_store: AtomicNativeExecutionStore, evidence_directory: str | Path) -> None:
        self.execution_store=execution_store; self.evidence_directory,_=_safe_directory(evidence_directory,"evidence directory")
        self._profile_cache: NativeMissionProfile | None = None
        self._payload_cache: NativeCanaryAuthorizationPayloadV4 | None = None
        self._persisted_profile_is_v4: bool | None = None

    def _persisted_profile(self) -> NativeMissionProfile:
        """Resolve the authoritative mission profile for this evidence root.

        A v4 authorization payload is the only post-run profile authority: the
        complete canonical profile is loaded and validated from the persisted
        payload bytes alone, never from the current source registry, CLI
        arguments, environment values, or module-level flagship constants.  A
        v3 (or absent) payload identifies the historical canary mission.
        """

        if self._persisted_profile_is_v4 is not None:
            assert self._profile_cache is not None
            return self._profile_cache
        path = self.evidence_directory / RUN_PREFLIGHT_METADATA_FILE_NAME
        if path.is_file():
            try:
                parsed = json.loads(path.read_bytes().decode("utf-8"))
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise NativeEvidenceInvalid(f"run preflight metadata is unreadable: {exc}") from exc
            payload = parsed.get("authorization_payload") if isinstance(parsed, Mapping) else None
            schema = payload.get("schema_version") if isinstance(payload, Mapping) else None
            if schema == AUTHORIZATION_SCHEMA_VERSION_V4:
                try:
                    persisted_payload = NativeCanaryAuthorizationPayloadV4.from_dict(payload)
                except (ValueError, TypeError) as exc:
                    raise NativeEvidenceInvalid(f"persisted v4 authorization payload is invalid: {exc}") from exc
                self._payload_cache = persisted_payload
                self._profile_cache = persisted_payload.mission_profile
                self._persisted_profile_is_v4 = True
                return self._profile_cache
        if self._profile_cache is None:
            self._profile_cache = legacy_canary_profile()
        self._persisted_profile_is_v4 = False
        return self._profile_cache
    def _outcome(self, *, status: NativeCanaryStatus, state: DelegatedSessionState, request: NativeExecutionRequest | NativeExecutionRequestBinding | None = None, result: NativeExecutionResult | None = None, result_fingerprint: str | None = None, detail: str, behavioral_evidence_fingerprint: str | None = None, capture_attempt_fingerprint: str | None = None, workspace_final_git_head: str | None = None, failing_boundary: str | None = None, evidence_fingerprint: str | None = None) -> NativeCanaryOutcome:
        checkpoint=state.checkpoint_history[-1] if state.checkpoint_history else None
        counts=NativeLifecycleCounts()
        if request is not None:
            counts=self.execution_store.lifecycle_counts(request.session_id,request.gate_id,request.execution_attempt_index)
        profile = self._profile_cache
        product_verdict: str | None = None
        verification_mode: str | None = None
        behavioral_non_claim: str | None = None
        exact_classification: str | None = None
        checkpoint_status: str | None = None
        verifier_source_sha256: str | None = None
        behavioral_verifier_passed: bool | None = None
        if profile is not None and profile.is_launchable_runtime_profile:
            verification_mode = profile.verification_mode.value
            exact_classification = status.value
            if status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS:
                product_verdict = (
                    ProductVerdict.ADMITTED_OBSERVED.value
                    if profile.verification_mode is VerificationMode.OBSERVED_ONLY
                    else ProductVerdict.ADMITTED_VERIFIED.value
                )
                checkpoint_status = "PASSED"
                if profile.verification_mode is VerificationMode.FROZEN_BEHAVIORAL:
                    verifier_source_sha256 = profile.verifier_source_sha256
                    behavioral_verifier_passed = True
                if profile.verification_mode is VerificationMode.OBSERVED_ONLY:
                    behavioral_non_claim = "Behavior was not independently verified."
            else:
                product_verdict = ProductVerdict.REFUSED.value
                checkpoint_status = "FAILED" if checkpoint is not None else "NOT_REACHED"
                failing_boundary = failing_boundary or status.value
            evidence_fingerprint = evidence_fingerprint or (
                checkpoint.checkpoint_fingerprint if checkpoint is not None
                else capture_attempt_fingerprint
                or behavioral_evidence_fingerprint
                or (result.result_fingerprint if result is not None else result_fingerprint)
                or (request.request_fingerprint if request is not None else None)
            )
        return NativeCanaryOutcome(status,state.session_id,state.phase.value,request.request_fingerprint if request else None,result.result_fingerprint if result else result_fingerprint,checkpoint.checkpoint_fingerprint if checkpoint else None,counts.provider_invocations_started,counts.native_attempts_reserved,counts.native_processes_started,counts.native_processes_completed,counts.process_observations_published,counts.accepted_native_results_published,status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS,detail,behavioral_evidence_fingerprint,capture_attempt_fingerprint,workspace_final_git_head,product_verdict,verification_mode,behavioral_non_claim,exact_classification,failing_boundary,evidence_fingerprint,checkpoint_status,verifier_source_sha256,behavioral_verifier_passed)
    def _terminal_outcome(self, state: DelegatedSessionState, request: NativeExecutionRequest | NativeExecutionRequestBinding, terminal: NativeCanaryTerminalRecord) -> NativeCanaryOutcome:
        if self._profile_cache is None:
            self._persisted_profile()
        category_mapping={"process_spawn_failure":NativeCanaryStatus.PROCESS_SPAWN_FAILED,"process_timeout":NativeCanaryStatus.TIMED_OUT,"process_exit_failure":NativeCanaryStatus.PROCESS_FAILED,"process_cleanup_failure":NativeCanaryStatus.CLEANUP_UNCERTAIN,"process_observation_publication":NativeCanaryStatus.PROCESS_OBSERVATION_PUBLICATION_FAILED}
        mapping={NativeCaptureTerminalStatus.PRECAPTURE_FAILED:NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED,NativeCaptureTerminalStatus.CAPTURE_FAILED:NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED,NativeCaptureTerminalStatus.DURABILITY_UNCERTAIN:NativeCanaryStatus.DURABILITY_UNCERTAIN}
        status=category_mapping.get(terminal.failure_category,mapping[terminal.status])
        return self._outcome(status=status,state=state,request=request,result_fingerprint=terminal.result_fingerprint,detail=terminal.diagnostic,failing_boundary=terminal.failure_category,evidence_fingerprint=terminal.terminal_fingerprint)
    def _reconstruct_success(self, state: DelegatedSessionState, request: NativeExecutionRequest | NativeExecutionRequestBinding, result: NativeExecutionResult) -> NativeCanaryOutcome:
        """Evidence-only interpretation of an already-completed success.

        This historical path validates persisted canonical records and the
        run-local workspace only.  It never consults, attests, or compares the
        live Cursor backend; it can veto but never grant execution authority,
        and no runner, provider, verifier, or checkpoint command is reachable
        from it.
        """
        if self.execution_store.has_terminal(state.session_id,request.gate_id,0): return self._terminal_outcome(state,request,self.execution_store.load_terminal(state.session_id,request.gate_id,0))
        profile=self._persisted_profile()
        if self._persisted_profile_is_v4:
            if profile.session_id != state.session_id:
                raise NativeEvidenceInvalid("persisted v4 profile session ID does not bind the durable delegated session")
            derived = create_canary_session(session_id=state.session_id, profile=profile)
            if derived.mission.mission_fingerprint != state.mission.mission_fingerprint:
                raise NativeEvidenceInvalid("persisted v4 profile-derived mission fingerprint does not bind durable delegated state")
            if derived.gate_plan.plan_fingerprint != state.gate_plan.plan_fingerprint:
                raise NativeEvidenceInvalid("persisted v4 profile-derived gate-plan fingerprint does not bind durable delegated state")
            if derived.current_gate.contract_fingerprint != state.current_gate.contract_fingerprint:
                raise NativeEvidenceInvalid("persisted v4 profile-derived gate-contract fingerprint does not bind durable delegated state")
        if (
            request.session_id!=state.session_id or request.execution_attempt_index!=0
            or request.mission_fingerprint!=state.mission.mission_fingerprint
            or request.gate_contract_fingerprint!=state.current_gate.contract_fingerprint
        ): raise NativeEvidenceInvalid("persisted request does not bind the delegated session authority")
        reservation=self.execution_store.load_attempt_reserved(state.session_id,request.gate_id,0)
        started=self.execution_store.load_process_started(state.session_id,request.gate_id,0)
        observation=self.execution_store.load_process_observation(state.session_id,request.gate_id,0)
        eligibility=self.execution_store.load_execution_eligibility(state.session_id,request.gate_id,0)
        if not eligibility.eligible or eligibility.ineligibility_reasons: raise NativeEvidenceInvalid("accepted success requires persisted successful eligibility")
        counts=self.execution_store.lifecycle_counts(state.session_id,request.gate_id,0)
        if (counts.native_attempts_reserved,counts.native_processes_started,counts.native_processes_completed,counts.process_observations_published,counts.accepted_native_results_published)!=(1,1,1,1,1): raise NativeEvidenceInvalid("one-shot lifecycle counts are contradictory")
        attempt=self.execution_store.load_capture_attempt(state.session_id,request.gate_id,0)
        if not (reservation.reserved_at<=started.process_started_at<=observation.process["ended_at"]<=eligibility.evaluated_at<=attempt.started_at): raise NativeEvidenceInvalid("lifecycle timestamps are out of order")
        expected=_result_from_observation(observation,backend_attestation_fingerprint=request.backend_attestation_fingerprint)
        if NativeExecutionResult(**{**expected.__dict__,"result_fingerprint":result.result_fingerprint})!=result: raise NativeEvidenceInvalid("accepted result contradicts the persisted process observation")
        if self._persisted_profile_is_v4:
            assert self._payload_cache is not None
            initialized = self._payload_cache.initialized_workspace
            if result.initial_git_head != initialized.initial_git_head:
                raise NativeEvidenceInvalid("accepted result initial workspace differs from v4 authorization")
            workspace = Path(result.cwd)
            try:
                initial_material_tree_hash = _git_material_tree_hash_at_commit(
                    workspace, initialized.initial_git_head
                )
                initial_count = int(
                    _git_read_only(
                        workspace, "rev-list", "--count", initialized.initial_git_head
                    ).stdout.strip()
                )
                initial_message = _git_read_only(
                    workspace,
                    "log",
                    "-1",
                    "--format=%B",
                    initialized.initial_git_head,
                ).stdout.rstrip("\r\n")
            except (RuntimeError, ValueError) as exc:
                raise NativeEvidenceInvalid(
                    f"authorized initial Git identity cannot be reconstructed: {exc}"
                ) from exc
            if (
                initial_material_tree_hash != initialized.initial_material_tree_hash
                or initial_count != initialized.initial_commit_count
                or initial_message != initialized.initial_commit_message
            ):
                raise NativeEvidenceInvalid("authorized initial Git identity contradicts run evidence")
        behavioral: BehavioralVerifierEvidence | None = None
        if profile.verification_mode is VerificationMode.FROZEN_BEHAVIORAL:
            behavioral=load_behavioral_verifier(request=request,execution_store=self.execution_store,verifier_source=profile.verifier_source)
        elif self.execution_store.has_behavioral_evidence(
            request.session_id, request.gate_id, request.execution_attempt_index
        ):
            raise NativeEvidenceInvalid("observed-only success cannot carry behavioral verifier evidence")
        expected_behavioral_fingerprint = (
            behavioral.evidence_fingerprint if behavioral is not None else None
        )
        expected_verification_mode = profile.verification_mode.value if profile.is_launchable_runtime_profile else None
        if (
            attempt.session_id!=state.session_id or attempt.gate_id!=state.current_gate.gate_id or attempt.execution_attempt_index!=0
            or attempt.request_fingerprint!=request.request_fingerprint or attempt.result_fingerprint!=result.result_fingerprint
            or attempt.behavioral_evidence_fingerprint!=expected_behavioral_fingerprint
            or attempt.verification_mode!=expected_verification_mode
            or attempt.gate_plan_fingerprint!=state.gate_plan.plan_fingerprint
            or attempt.checkpoint_contract_fingerprint!=state.current_gate.contract_fingerprint
            or attempt.required_command_ids!=tuple(command.command_id for command in state.current_gate.checkpoint_verification_commands)
            or attempt.capture_attempt_id!=f"capture:{state.session_id}:{state.current_gate.gate_id}:0"
            or attempt.expected_terminal_status!=CAPTURE_EXPECTED_SUCCESS_STATUS
            or state.revision!=attempt.state_revision+1
        ): raise NativeEvidenceInvalid("capture attempt does not bind the exact active durable run")
        if state.phase is not Phase.CHECKPOINT_CAPTURED or len(state.checkpoint_history)!=1 or state.audit_history or state.repair_authority is not None or state.human_boundary_reason is not None or state.human_disposition is not None or state.current_gate.gate_id!=profile.gate_id: raise NativeEvidenceInvalid("reconstructed delegated state exceeds the one-gate stop boundary")
        checkpoint=state.checkpoint_history[-1]
        if checkpoint.session_id!=state.session_id or checkpoint.gate_id!=request.gate_id or checkpoint.execution_attempt_index!=0: raise NativeEvidenceInvalid("checkpoint differs from the active request")
        if checkpoint.git_head!=result.final_git_head or checkpoint.git_worktree_status!=result.final_git_porcelain_status: raise NativeEvidenceInvalid("checkpoint Git facts contradict the accepted result")
        if checkpoint.artifact_references:
            checkpoint_root,_=_safe_directory(self.evidence_directory / "checkpoint-artifacts","checkpoint artifact root")
            for reference in checkpoint.artifact_references:
                path=checkpoint_root / reference.relative_path; safe,_=_safe_file(path,"checkpoint artifact")
                if not _inside(safe,checkpoint_root): raise NativeEvidenceInvalid("checkpoint artifact escapes checkpoint evidence root")
                data=safe.read_bytes()
                if len(data)!=reference.byte_count or hashlib.sha256(data).hexdigest()!=reference.sha256: raise NativeEvidenceInvalid("checkpoint artifact hash mismatch")
        if _pre_capture_reason(result, behavioral, profile) is not None: raise NativeEvidenceInvalid("reconstructed success no longer satisfies eligibility")
        if _checkpoint_success_reason(checkpoint,state.current_gate) is not None: raise NativeEvidenceInvalid("reconstructed checkpoint command evidence does not satisfy Act-2A success")
        detail = (
            "All native, behavioral, capture, checkpoint, and state evidence reloaded from disk."
            if behavioral is not None
            else "All native, Git/material, capture, checkpoint, and state evidence reloaded from disk. Behavior was not independently verified."
        )
        return self._outcome(status=NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS,state=state,request=request,result=result,detail=detail,behavioral_evidence_fingerprint=expected_behavioral_fingerprint,capture_attempt_fingerprint=attempt.attempt_fingerprint,workspace_final_git_head=result.final_git_head)


class NativeCanaryCoordinator(EvidenceOnlyCanaryReconstruction):
    """One READY_FOR_GATE -> CHECKPOINT_CAPTURED canary path, with no retry."""
    def __init__(self, *, session_store: AtomicDelegatedSessionStore, execution_store: AtomicNativeExecutionStore, executor: NativeDelegatedExecutor, backend_attestation: BackendAttestation, source_repository: str | Path, work_workspace: str | Path, canary_parent: str | Path, evidence_directory: str | Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, stdout_byte_limit: int = DEFAULT_STDOUT_BYTE_LIMIT, stderr_byte_limit: int = DEFAULT_STDERR_BYTE_LIMIT, profile: NativeMissionProfile | None = None) -> None:
        super().__init__(execution_store=execution_store, evidence_directory=evidence_directory)
        self.session_store=session_store; self.executor=executor; self.backend_attestation=backend_attestation.validated()
        self.source_repository,_=_safe_directory(source_repository,"source repository"); self.work_workspace,_=_safe_directory(work_workspace,"work workspace"); self.canary_parent,_=_safe_directory(canary_parent,"canary parent")
        self.timeout_seconds=timeout_seconds; self.stdout_byte_limit=stdout_byte_limit; self.stderr_byte_limit=stderr_byte_limit
        self.profile=(profile if profile is not None else legacy_canary_profile()).validated()
        # The live coordinator's selected profile is the reconstruction
        # authority for its own run; the CLI persists the identical profile in
        # the v4 payload before any execution begins.
        self._profile_cache=self.profile
    def _publish_failure_terminal(self, *, state: DelegatedSessionState, request: NativeExecutionRequest | NativeExecutionRequestBinding, result: NativeExecutionResult | None, status: NativeCaptureTerminalStatus, failure_category: str, diagnostic: str, capture_attempt: NativeCheckpointCaptureAttempt | None = None) -> NativeCanaryOutcome:
        try:
            terminal=self.execution_store.create_terminal(request=request,result=result,status=status,failure_category=failure_category,diagnostic=diagnostic[:1024],capture_attempt=capture_attempt)
        except (NativeCommittedButDurabilityUncertain,NativeEvidenceInvalid,NativeExecutionStoreError,OSError,ValueError) as exc:
            return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,result=result,detail=f"terminal publication failed: {type(exc).__name__}: {exc}")
        return self._terminal_outcome(state,request,terminal)
    def run(self, *, session_id: str) -> NativeCanaryOutcome:
        state=self.session_store.load(session_id); gate=state.current_gate; attempt=0
        if state.phase is Phase.CHECKPOINT_CAPTURED:
            # Historical-evidence path: recognize a persisted terminal first,
            # then reconstruct the completed success from persisted canonical
            # evidence alone.  The live Cursor backend is never consulted.
            binding=self.execution_store.load_request_structural(session_id,gate.gate_id,attempt)
            if self.execution_store.has_terminal(session_id,gate.gate_id,attempt): return self._terminal_outcome(state,binding,self.execution_store.load_terminal(session_id,gate.gate_id,attempt))
            return self._reconstruct_success(state,binding,self.execution_store.load_result(session_id,gate.gate_id,attempt))
        if state.phase is Phase.READY_FOR_GATE:
            started=reduce(state,GateExecutionStarted(gate.gate_id)); self.session_store.replace(started,expected_revision=state.revision); state=self.session_store.load(session_id)
        if state.phase is not Phase.GATE_EXECUTING: raise RuntimeError(f"coordinator refuses delegated phase {state.phase.value}")
        prompt=build_native_agent_prompt(mission=state.mission,gate_contract=gate,work_workspace=self.work_workspace,required_commit_message=self.profile.required_commit_message,completion_conditions=self.profile.completion_conditions_text,profile=self.profile)
        request_exists=self.execution_store.has_request(session_id,gate.gate_id,attempt)
        if request_exists:
            # Terminal recognition is first and uses only structural request
            # binding.  Mutable backend catalog state is never consulted.
            terminal=self.execution_store.load_terminal(session_id,gate.gate_id,attempt) if self.execution_store.has_terminal(session_id,gate.gate_id,attempt) else None
            request=self.execution_store.load_request_structural(session_id,gate.gate_id,attempt)
            if terminal is not None: return self._terminal_outcome(state,request,terminal)
            counts=self.execution_store.lifecycle_counts(session_id,gate.gate_id,attempt)
            result=self.execution_store.load_result(session_id,gate.gate_id,attempt) if counts.accepted_native_results_published else None
            if self.execution_store.has_capture_attempt(session_id,gate.gate_id,attempt): return self._outcome(status=NativeCanaryStatus.CAPTURE_ATTEMPT_AMBIGUOUS,state=state,request=request,result=result,detail="A durable capture-attempt record exists without CHECKPOINT_CAPTURED; capture is never replayed.")
            if not counts.native_attempts_reserved: return self._outcome(status=NativeCanaryStatus.EXECUTION_RESULT_MISSING_NO_RETRY,state=state,request=request,detail="A durable request exists without attempt reservation; the one-shot request is never reinvoked.")
            if not counts.native_processes_started: return self._outcome(status=NativeCanaryStatus.ATTEMPT_RESERVED_LAUNCH_OUTCOME_UNKNOWN,state=state,request=request,detail="ATTEMPT_RESERVED exists without PROCESS_STARTED; launch outcome is unknown and no second process is permitted.")
            if not counts.process_observations_published: return self._outcome(status=NativeCanaryStatus.PROCESS_OBSERVATION_MISSING,state=state,request=request,detail="PROCESS_STARTED exists without PROCESS_OBSERVATION; execution observation is ambiguous and no rerun is permitted.")
            if not self.execution_store.has_execution_eligibility(session_id,gate.gate_id,attempt): return self._outcome(status=NativeCanaryStatus.EXECUTION_ELIGIBILITY_MISSING,state=state,request=request,detail="Observed execution has no eligibility record; mutable live state is not used to recompute it.")
            eligibility=self.execution_store.load_execution_eligibility(session_id,gate.gate_id,attempt)
            if not eligibility.eligible: return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,detail="Persisted ineligibility exists without its required terminal; execution remains rejected and is never rerun.")
            if not counts.accepted_native_results_published: return self._outcome(status=NativeCanaryStatus.ACCEPTED_RESULT_MISSING,state=state,request=request,detail="Successful eligibility exists without an accepted result publication; execution is never rerun.")
            result=self.execution_store.load_result(session_id,gate.gate_id,attempt)
            if self.execution_store.has_behavioral_evidence(session_id,gate.gate_id,attempt): return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,result=result,detail="A visible behavioral record without a capture boundary is fail-closed and never reused.")
            return self._outcome(status=NativeCanaryStatus.CAPTURE_ATTEMPT_AMBIGUOUS,state=state,request=request,result=result,detail="An accepted result without terminal or capture record is an ambiguous no-retry boundary.")
        try: current=self.executor.attest_local_backend()
        except NativeEvidenceInvalid as exc: return self._outcome(status=NativeCanaryStatus.PREFLIGHT_BLOCKED,state=state,detail=str(exc))
        if current!=self.backend_attestation: return self._outcome(status=NativeCanaryStatus.PREFLIGHT_BLOCKED,state=state,detail="coordinator backend attestation differs from fresh local installation evidence")
        request=NativeExecutionRequest.create(session_id=session_id,gate_id=gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=gate.contract_fingerprint,work_workspace=self.work_workspace,evidence_store_root=self.execution_store.directory,artifact_directory=self.execution_store.artifact_directory,attestation=current,prompt=prompt,timeout_seconds=self.timeout_seconds,stdout_byte_limit=self.stdout_byte_limit,stderr_byte_limit=self.stderr_byte_limit)
        try: self.execution_store.create_request(request)
        except NativeCommittedButDurabilityUncertain as exc: return self._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,state=state,request=request,detail=str(exc))
        try:
            git_policy = self.profile.effective_git_end_state_policy
            issued=self.executor.execute(request=request,prompt=prompt,source_repository=self.source_repository,canary_parent=self.canary_parent,allowed_parent_children=frozenset({self.work_workspace.name}),evidence_store_root=self.execution_store.directory,artifact_directory=self.execution_store.artifact_directory,required_commit_message=git_policy.required_complete_commit_message,required_material_paths=frozenset(git_policy.required_material_paths),required_commits_added=git_policy.required_commits_added,final_worktree_clean_required=git_policy.final_worktree_clean,final_index_clean_required=git_policy.final_index_clean,final_remotes_absent_required=git_policy.final_remotes_absent,execution_store=self.execution_store)
            result=self.execution_store.write_result(issued)
        except NativeResultIneligible as exc:
            observation=self.execution_store.load_process_observation(session_id,gate.gate_id,0)
            process=observation.process
            category="process_timeout" if process["timed_out"] else "process_cleanup_failure" if not process["cleanup_confirmed"] else "process_exit_failure" if process["exit_code"]!=0 else "result_ineligible"
            return self._publish_failure_terminal(state=state,request=request,result=None,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category=category,diagnostic=f"result ineligible: {'; '.join(exc.eligibility.ineligibility_reasons)}")
        except NativeProcessStartError as exc:
            return self._publish_failure_terminal(state=state,request=request,result=None,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="process_spawn_failure",diagnostic=f"process spawn failure: {exc}")
        except NativeProcessObservationPublicationError as exc:
            return self._publish_failure_terminal(state=state,request=request,result=None,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="process_observation_publication",diagnostic=str(exc))
        except NativeCommittedButDurabilityUncertain as exc:
            return self._publish_failure_terminal(state=state,request=request,result=None,status=NativeCaptureTerminalStatus.DURABILITY_UNCERTAIN,failure_category="lifecycle_durability_uncertain",diagnostic=str(exc))
        except NativeEvidenceInvalid as exc:
            if self.execution_store.has_attempt_reserved(session_id,gate.gate_id,0): return self._publish_failure_terminal(state=state,request=request,result=None,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="executor_observation_failed",diagnostic=str(exc))
            return self._outcome(status=NativeCanaryStatus.PREFLIGHT_BLOCKED,state=state,request=request,detail=str(exc))
        except NativeExecutionStoreError as exc:
            if self.execution_store.has_attempt_reserved(session_id,gate.gate_id,0): return self._publish_failure_terminal(state=state,request=request,result=None,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="lifecycle_publication_failure",diagnostic=f"{type(exc).__name__}: {exc}")
            return self._outcome(status=NativeCanaryStatus.PREFLIGHT_BLOCKED,state=state,request=request,detail=str(exc))
        behavioral: BehavioralVerifierEvidence | None = None
        if self.profile.verification_mode is VerificationMode.FROZEN_BEHAVIORAL:
            try:
                behavioral=run_behavioral_verifier(request=request,execution_store=self.execution_store,timeout_seconds=self.profile.verifier_timeout_seconds,output_limit=self.profile.verifier_output_limit_bytes,verifier_source=self.profile.verifier_source)
            except NativeCommittedButDurabilityUncertain as exc:
                return self._publish_failure_terminal(state=state,request=request,result=result,status=NativeCaptureTerminalStatus.DURABILITY_UNCERTAIN,failure_category="behavioral_durability_uncertain",diagnostic=str(exc))
            except Exception as exc:
                return self._publish_failure_terminal(state=state,request=request,result=result,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="behavioral_verifier_observation",diagnostic=f"{type(exc).__name__}: {exc}")
        reason=_pre_capture_reason(result,behavioral,self.profile)
        if reason is not None:
            return self._publish_failure_terminal(state=state,request=request,result=result,status=NativeCaptureTerminalStatus.PRECAPTURE_FAILED,failure_category="pre_capture_eligibility",diagnostic=reason)
        try: capture_attempt=self.execution_store.create_capture_attempt(request=request,result=result,gate_plan_fingerprint=state.gate_plan.plan_fingerprint,checkpoint_contract_fingerprint=gate.contract_fingerprint,behavioral_evidence_fingerprint=behavioral.evidence_fingerprint if behavioral is not None else None,required_command_ids=tuple(command.command_id for command in gate.checkpoint_verification_commands),state_revision=state.revision,verification_mode=self.profile.verification_mode.value if self.profile.is_launchable_runtime_profile else None)
        except NativeCommittedButDurabilityUncertain as exc: return self._publish_failure_terminal(state=state,request=request,result=result,status=NativeCaptureTerminalStatus.DURABILITY_UNCERTAIN,failure_category="capture_attempt_durability_uncertain",diagnostic=str(exc))
        try:
            captured=capture_checkpoint(repository=self.work_workspace,artifact_directory=self.evidence_directory / "checkpoint-artifacts",session_id=session_id,gate_contract=gate,execution_attempt_index=0)
        except Exception as exc:
            return self._publish_failure_terminal(state=state,request=request,result=result,status=NativeCaptureTerminalStatus.CAPTURE_FAILED,failure_category="checkpoint_capture",diagnostic=str(exc),capture_attempt=capture_attempt)
        # Once capture returns, a state-persistence interruption is deliberately
        # left as the durable started-attempt ambiguity; capture is not replayed.
        checkpoint_state=reduce(state,CheckpointRecorded(captured))
        checkpoint_reason=_checkpoint_success_reason(checkpoint_state.checkpoint_history[-1],gate)
        if checkpoint_reason is not None:
            return self._publish_failure_terminal(state=state,request=request,result=result,status=NativeCaptureTerminalStatus.CAPTURE_FAILED,failure_category="checkpoint_verification",diagnostic=checkpoint_reason,capture_attempt=capture_attempt)
        self.session_store.replace(checkpoint_state,expected_revision=state.revision)
        final=self.session_store.load(session_id); return self._reconstruct_success(final,request,result)


def reconstruct_completed_canary_success(*, session_store: AtomicDelegatedSessionStore, execution_store: AtomicNativeExecutionStore, evidence_directory: str | Path, session_id: str) -> NativeCanaryOutcome:
    """Evidence-only outcome for an already ``CHECKPOINT_CAPTURED`` canary run.

    This entry point constructs no executor, backend attestation, runner,
    provider, behavioral verifier, or checkpoint capability, so it can never
    spawn, authorize, retry, verify, capture, or create attempt one.  A
    persisted terminal is recognized first; otherwise the completed success is
    reconstructed exclusively from persisted canonical records and read-only
    run-local workspace facts.
    """

    state=session_store.load(session_id)
    if state.phase is not Phase.CHECKPOINT_CAPTURED:
        raise NativeEvidenceInvalid(f"evidence-only reconstruction requires CHECKPOINT_CAPTURED, found {state.phase.value}")
    gate=state.current_gate
    reconstruction=EvidenceOnlyCanaryReconstruction(execution_store=execution_store,evidence_directory=evidence_directory)
    binding=execution_store.load_request_structural(session_id,gate.gate_id,0)
    if execution_store.has_terminal(session_id,gate.gate_id,0):
        return reconstruction._terminal_outcome(state,binding,execution_store.load_terminal(session_id,gate.gate_id,0))
    return reconstruction._reconstruct_success(state,binding,execution_store.load_result(session_id,gate.gate_id,0))


def reconstruct_completed_native_mission(*, session_store: AtomicDelegatedSessionStore, execution_store: AtomicNativeExecutionStore, evidence_directory: str | Path, session_id: str) -> NativeCanaryOutcome:
    """Reconstruct one runtime-v2 admission or refusal from persisted evidence.

    Registry lookup, provider execution, behavioral execution and checkpoint
    capture are unreachable.  The write-once final product record must equal
    the verdict independently derived from the embedded v4 profile and native
    evidence, so tampering with either side fails closed.
    """

    evidence, _ = _safe_directory(evidence_directory, "evidence directory")
    state = session_store.load(session_id)
    gate = state.current_gate
    reconstruction = EvidenceOnlyCanaryReconstruction(
        execution_store=execution_store, evidence_directory=evidence
    )
    profile = reconstruction._persisted_profile()
    if not profile.is_launchable_runtime_profile:
        raise NativeEvidenceInvalid("general product reconstruction requires a runtime-v2 profile")
    binding = execution_store.load_request_structural(session_id, gate.gate_id, 0)
    if execution_store.has_terminal(session_id, gate.gate_id, 0):
        outcome = reconstruction._terminal_outcome(
            state, binding, execution_store.load_terminal(session_id, gate.gate_id, 0)
        )
    elif state.phase is Phase.CHECKPOINT_CAPTURED:
        outcome = reconstruction._reconstruct_success(
            state, binding, execution_store.load_result(session_id, gate.gate_id, 0)
        )
    else:
        raise NativeEvidenceInvalid("runtime mission has no durable terminal outcome")
    final_path = evidence / "final-status.json"
    try:
        persisted = json.loads(final_path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise NativeEvidenceInvalid(f"runtime final status is unreadable: {exc}") from exc
    if not isinstance(persisted, Mapping) or dict(persisted) != outcome.to_dict():
        raise NativeEvidenceInvalid("persisted product verdict contradicts reconstructed evidence")
    return outcome


def _git_source_preflight_run(
    source: Path, *arguments: str, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    """Run a read-only Git observation for protocol-repository preflight.

    Ordinary Git may refresh ``.git/index`` during otherwise observational
    commands.  Protocol preflight must force ``GIT_OPTIONAL_LOCKS=0`` in the
    child only, leave the parent environment untouched, and never depend on the
    caller's ambient setting.
    """

    return _git_read_only(source, *arguments, timeout=timeout)


def _git_source_preflight(source: Path, required_head: str) -> tuple[bool, str]:
    try:
        _inspect_local_git_metadata(source)
        root = _git_source_preflight_run(source, "rev-parse", "--show-toplevel").stdout.strip()
        head = _git_source_preflight_run(source, "rev-parse", "HEAD").stdout.strip().lower()
        status = _git_source_preflight_run(
            source, "status", "--porcelain=v1", "--untracked-files=all"
        ).stdout
    except RuntimeError as exc:
        return False, str(exc)
    if Path(root).resolve() != source.resolve():
        return False, "source repository is not the exact Git root"
    if head != required_head.lower():
        return False, "source HEAD does not match the explicitly authorized source HEAD"
    if status:
        return False, "source repository is not clean"
    return True, "clean authorized source HEAD confirmed"


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


@dataclass(frozen=True)
class InitializedWorkspaceIdentity:
    """Independently observed identity of one freshly initialized workspace."""

    initial_git_head: str
    initial_material_tree_hash: str
    initial_commit_count: int
    initial_commit_message: str
    source_kind: str | None = None
    source_identity: str | None = None

    def validated(self) -> "InitializedWorkspaceIdentity":
        if (
            not isinstance(self.initial_git_head, str) or len(self.initial_git_head) not in {40, 64}
            or self.initial_git_head != self.initial_git_head.lower()
            or any(char not in "0123456789abcdef" for char in self.initial_git_head)
        ):
            raise ValueError("initialized workspace HEAD must be a lowercase Git object ID")
        require_sha256(self.initial_material_tree_hash, "initialized workspace material tree hash")
        maximum_count = 1 if self.source_kind is None else 1_000_000
        require_strict_int(
            self.initial_commit_count,
            "initialized workspace commit count",
            minimum=1,
            maximum=maximum_count,
        )
        require_nonempty_text(
            self.initial_commit_message,
            "initialized workspace commit message",
            max_bytes=16_384 if self.source_kind is not None else 1024,
        )
        if self.source_kind is None:
            if self.source_identity is not None:
                raise ValueError("legacy initialized workspace cannot invent source identity")
            if "\n" in self.initial_commit_message or "\r" in self.initial_commit_message:
                raise ValueError("initialized workspace commit message must be one exact single line")
        else:
            if self.source_kind not in {kind.value for kind in WorkspaceSourceKind}:
                raise ValueError("initialized workspace source kind is invalid")
            require_sha256(self.source_identity, "initialized workspace source identity")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        if self.source_kind is None:
            data.pop("source_kind")
            data.pop("source_identity")
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InitializedWorkspaceIdentity":
        legacy = set(cls.__dataclass_fields__) - {"source_kind", "source_identity"}
        if set(data) == legacy:
            return cls(**data, source_kind=None, source_identity=None).validated()
        require_exact_keys(data, set(cls.__dataclass_fields__), "initialized workspace identity")
        return cls(**data).validated()


def _remove_tree_force(root: Path) -> None:
    """Remove a scratch tree, clearing Windows read-only Git object bits."""

    def _on_error(func: Any, path: Any, _exc_info: Any) -> None:
        os.chmod(path, stat.S_IWRITE)
        func(path)

    shutil.rmtree(root, onexc=_on_error)


@dataclass(frozen=True)
class _LocalGitConfigEntry:
    section: str
    subsection: str | None
    name: str
    value: str

    @property
    def canonical_key(self) -> str:
        pieces = [self.section.casefold()]
        if self.subsection is not None:
            pieces.append(self.subsection.casefold())
        pieces.append(self.name.casefold())
        return ".".join(pieces)


_GIT_CONFIG_SECTION = re.compile(
    r'^\[([A-Za-z0-9-]+)(?:[ \t]+"([^"\\#;\r\n]+)")?\]$'
)
_GIT_CONFIG_VARIABLE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)[ \t]*=[ \t]*(.*)$")
_SOURCE_LOCAL_CONFIG_ALLOWLIST = frozenset(
    {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.symlinks",
        "core.ignorecase",
        "core.precomposeunicode",
        "core.autocrlf",
        "core.safecrlf",
        "user.name",
        "user.email",
        "commit.gpgsign",
        "tag.gpgsign",
        "extensions.objectformat",
        "extensions.refstorage",
    }
)
_TARGET_LOCAL_USER_NAME = "Admissible Native Mission"
_TARGET_LOCAL_USER_EMAIL = "admissible-native@local.invalid"


def _is_redirecting_metadata(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _ordinary_git_directory(repository: Path) -> Path:
    git_directory = repository / ".git"
    try:
        metadata = os.lstat(git_directory)
    except OSError as exc:
        raise NativeEvidenceInvalid("local repository must own an ordinary .git directory") from exc
    if _is_redirecting_metadata(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise NativeEvidenceInvalid("local repository must own an ordinary .git directory")
    return git_directory


def _parse_local_git_config(config_path: Path) -> tuple[_LocalGitConfigEntry, ...]:
    """Parse the deliberately small v0 source-repository config grammar.

    This is intentionally not a Git-compatible parser.  Physical lines that
    need quoting, escaping, continuation, inline comments, valueless keys, or
    any other non-trivial Git grammar are rejected before Git is invoked.
    """
    try:
        metadata = os.lstat(config_path)
        if _is_redirecting_metadata(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise NativeEvidenceInvalid("local Git config is not an ordinary regular file")
        if metadata.st_size > 1024 * 1024:
            raise NativeEvidenceInvalid("local Git config exceeds the direct-inspection bound")
        raw = config_path.read_bytes()
        if b"\x00" in raw:
            raise NativeEvidenceInvalid("local Git config contains a NUL byte")
        text = raw.decode("utf-8-sig")
    except NativeEvidenceInvalid:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise NativeEvidenceInvalid(f"local Git config is unreadable: {exc}") from exc
    if "\r" in text.replace("\r\n", ""):
        raise NativeEvidenceInvalid("local Git config contains a bare carriage return")
    for character in text:
        if (ord(character) < 32 and character not in {"\t", "\r", "\n"}) or ord(character) == 127:
            raise NativeEvidenceInvalid("local Git config contains a control character")
    entries: list[_LocalGitConfigEntry] = []
    section: str | None = None
    subsection: str | None = None
    for line_number, physical in enumerate(text.split("\n"), 1):
        line = physical[:-1] if physical.endswith("\r") else physical
        if line.rstrip(" \t").endswith("\\"):
            raise NativeEvidenceInvalid(
                f"local Git config line {line_number} uses forbidden continuation syntax"
            )
        if "\\" in line:
            raise NativeEvidenceInvalid(
                f"local Git config line {line_number} uses unsupported escape syntax"
            )
        line = line.strip(" \t")
        if not line:
            continue
        if line[0] in {"#", ";"}:
            continue
        if "#" in line or ";" in line:
            raise NativeEvidenceInvalid(
                f"local Git config line {line_number} uses an inline comment"
            )
        modern = _GIT_CONFIG_SECTION.fullmatch(line)
        if modern:
            section = modern.group(1)
            subsection = modern.group(2)
            continue
        if section is None:
            raise NativeEvidenceInvalid("local Git config variable precedes its section")
        variable = _GIT_CONFIG_VARIABLE.fullmatch(line)
        if not variable:
            raise NativeEvidenceInvalid(
                f"local Git config line {line_number} is outside the accepted Git grammar"
            )
        entries.append(
            _LocalGitConfigEntry(
                section=section,
                subsection=subsection,
                name=variable.group(1),
                value=variable.group(2).strip(" \t"),
            )
        )
        if len(entries) > 10_000:
            raise NativeEvidenceInvalid("local Git config has too many entries")
    return tuple(entries)


def _git_config_boolean(value: str, label: str) -> bool:
    normalized = value.strip().casefold()
    if normalized in {"true", "yes", "on", "1"}:
        return True
    if normalized in {"false", "no", "off", "0"}:
        return False
    raise NativeEvidenceInvalid(f"{label} is not a canonical Git boolean")


def _validate_attributes_file(repository: Path, value: str) -> None:
    if not value or value.startswith("~") or value.startswith("%("):
        raise NativeEvidenceInvalid("core.attributesFile is external or indeterminate")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = repository / candidate
    try:
        resolved = candidate.resolve(strict=True)
        metadata = os.lstat(resolved)
    except OSError as exc:
        raise NativeEvidenceInvalid("core.attributesFile is unreadable") from exc
    if not _inside(resolved, repository) or _is_redirecting_metadata(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise NativeEvidenceInvalid("core.attributesFile must be an ordinary file inside the repository")


def _validate_local_git_config_security(
    repository: Path,
    entries: tuple[_LocalGitConfigEntry, ...],
    *,
    allowed_hooks_path: Path | None = None,
) -> None:
    for entry in entries:
        section = entry.section.casefold()
        subsection = entry.subsection.casefold() if entry.subsection is not None else None
        name = entry.name.casefold()
        key = entry.canonical_key
        if allowed_hooks_path is None:
            if entry.subsection is not None or key not in _SOURCE_LOCAL_CONFIG_ALLOWLIST:
                raise NativeEvidenceInvalid(
                    f"local Git configuration key is outside the source allowlist: {key}"
                )
            if key in {
                "core.filemode",
                "core.bare",
                "core.logallrefupdates",
                "core.symlinks",
                "core.ignorecase",
                "core.precomposeunicode",
            }:
                _git_config_boolean(entry.value, key)
            elif key == "core.repositoryformatversion" and entry.value not in {"0", "1"}:
                raise NativeEvidenceInvalid("core.repositoryformatversion is unsupported")
            elif key == "core.autocrlf" and entry.value.casefold() not in {"true", "false", "input"}:
                raise NativeEvidenceInvalid("core.autocrlf is unsupported")
            elif key == "core.safecrlf" and entry.value.casefold() not in {"true", "false", "warn"}:
                raise NativeEvidenceInvalid("core.safecrlf is unsupported")
            elif key == "extensions.objectformat" and entry.value.casefold() not in {"sha1", "sha256"}:
                raise NativeEvidenceInvalid("extensions.objectformat is unsupported")
            elif key == "extensions.refstorage" and entry.value.casefold() not in {"files", "reftable"}:
                raise NativeEvidenceInvalid("extensions.refstorage is unsupported")
            elif key in {"user.name", "user.email"} and not entry.value:
                raise NativeEvidenceInvalid(f"{key} must not be empty")
            elif key in {"commit.gpgsign", "tag.gpgsign"} and entry.value.casefold() != "false":
                raise NativeEvidenceInvalid(f"{key} must be explicitly disabled")
            continue
        if section == "include" and name == "path":
            raise NativeEvidenceInvalid("local Git configuration contains include.path")
        if section == "includeif" and name == "path":
            raise NativeEvidenceInvalid("local Git configuration contains includeIf.*.path")
        if (section, name) in {
            ("core", "worktree"),
            ("extensions", "worktreeconfig"),
            ("core", "fsmonitor"),
            ("core", "sshcommand"),
            ("core", "pager"),
            ("core", "editor"),
            ("core", "askpass"),
            ("core", "gitproxy"),
            ("sequence", "editor"),
            ("interactive", "difffilter"),
            ("diff", "external"),
            ("ssh", "askpass"),
            ("gpg", "program"),
        }:
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "core" and name == "hookspath":
            if allowed_hooks_path is None:
                raise NativeEvidenceInvalid("local Git configuration redirects core.hooksPath")
            configured = Path(entry.value)
            try:
                configured = configured.resolve(strict=True)
                expected = allowed_hooks_path.resolve(strict=True)
            except OSError as exc:
                raise NativeEvidenceInvalid("target core.hooksPath is unreadable") from exc
            if configured != expected or not _inside(configured, repository):
                raise NativeEvidenceInvalid("target core.hooksPath escapes its repository")
            continue
        if section == "core" and name == "attributesfile":
            _validate_attributes_file(repository, entry.value)
        if section == "alias" and entry.value.lstrip().startswith("!"):
            raise NativeEvidenceInvalid(f"local Git configuration contains shell alias: {key}")
        if section == "pager":
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        # Git documents these as direct external driver/tool program hooks.
        if section == "diff" and subsection is not None and name in {"textconv", "command"}:
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "difftool" and subsection is not None and name in {"cmd", "path"}:
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "merge" and subsection is not None and name == "driver":
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "mergetool" and subsection is not None and name in {"cmd", "path"}:
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "filter" and subsection is not None and name in {"clean", "smudge", "process"}:
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "credential" and (name == "helper" or name.endswith("command")):
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "gpg" and subsection is not None and name == "program":
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section in {"browser", "guitool", "man"} and subsection is not None and name == "cmd":
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section == "tar" and subsection is not None and name == "command":
            raise NativeEvidenceInvalid(f"local Git configuration is command-bearing: {key}")
        if section in {"commit", "tag"} and name == "gpgsign" and _git_config_boolean(
            entry.value, key
        ):
            raise NativeEvidenceInvalid(f"local Git configuration enables signing: {key}")


def _inspect_local_git_metadata(
    repository: Path, *, allowed_hooks_path: Path | None = None
) -> tuple[_LocalGitConfigEntry, ...]:
    """Inspect ordinary local Git metadata without invoking Git or includes."""

    git_directory = _ordinary_git_directory(repository)
    hooks = git_directory / "hooks"
    if _lexists(hooks):
        metadata = os.lstat(hooks)
        if _is_redirecting_metadata(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise NativeEvidenceInvalid("local Git hooks path is redirecting or not a directory")
        for entry in os.scandir(hooks):
            entry_metadata = entry.stat(follow_symlinks=False)
            if (
                not entry.name.endswith(".sample")
                or _is_redirecting_metadata(entry_metadata)
                or not stat.S_ISREG(entry_metadata.st_mode)
            ):
                raise NativeEvidenceInvalid(
                    f"local Git hooks directory contains unsafe entry: {entry.name}"
                )
    config_path = git_directory / "config"
    entries = _parse_local_git_config(config_path)
    _validate_local_git_config_security(
        repository, entries, allowed_hooks_path=allowed_hooks_path
    )
    forbidden_metadata = (
        git_directory / "config.worktree",
        git_directory / "commondir",
        git_directory / "objects" / "info" / "alternates",
        git_directory / "objects" / "info" / "http-alternates",
        git_directory / "info" / "grafts",
    )
    for candidate in forbidden_metadata:
        if _lexists(candidate):
            raise NativeEvidenceInvalid(
                f"local repository contains forbidden Git authority metadata: {candidate.name}"
            )
    for name in (
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-apply",
        "rebase-merge",
    ):
        if _lexists(git_directory / name):
            raise NativeEvidenceInvalid(f"local repository source has in-progress Git state: {name}")
    if _lexists(repository / ".gitmodules"):
        raise NativeEvidenceInvalid("local repository source contains submodule metadata")
    return entries


def _inspect_runtime_git_metadata(repository: Path, sanitized_target: bool) -> None:
    """Executor callback for the source-kind-gated pre/post Git boundary."""

    allowed_hooks = repository / ".git" / "hooks" if sanitized_target else None
    _inspect_local_git_metadata(repository, allowed_hooks_path=allowed_hooks)


def _filesystem_byte_inventory_hash(root: Path) -> str:
    """Hash every path and file byte without following redirecting entries."""

    digest = hashlib.sha256()
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            path = base / name
            metadata = os.lstat(path)
            if _is_redirecting_metadata(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise NativeEvidenceInvalid(f"repository byte inventory contains unsafe entry: {path}")
            digest.update(b"D\0" + path.relative_to(root).as_posix().encode("utf-8") + b"\n")
        for name in filenames:
            path = base / name
            metadata = os.lstat(path)
            if _is_redirecting_metadata(metadata) or not stat.S_ISREG(metadata.st_mode):
                raise NativeEvidenceInvalid(f"repository byte inventory contains unsafe entry: {path}")
            relative = path.relative_to(root).as_posix().encode("utf-8")
            file_digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    file_digest.update(block)
            digest.update(
                b"F\0" + relative + b"\0" + str(metadata.st_size).encode("ascii")
                + b"\0" + file_digest.hexdigest().encode("ascii") + b"\n"
            )
    return digest.hexdigest()


@dataclass(frozen=True)
class LocalRepositoryAuthorityObservation:
    """Read-only source facts used to prove preparation did not mutate it."""

    repository: str
    git_directory: str
    head: str
    material_tree_hash: str
    worktree_material_tree_hash: str
    commit_count: int
    complete_commit_message: str
    porcelain_status: str
    remotes: tuple[str, ...]
    config_sha256: str
    refs_sha256: str
    index_sha256: str
    byte_inventory_sha256: str

    @property
    def authority_fingerprint(self) -> str:
        data = dict(self.__dict__)
        data["remotes"] = list(self.remotes)
        return fingerprint(data)


def _sha256_file_or_absent(path: Path) -> str:
    if not path.exists():
        return hashlib.sha256(b"<ABSENT>").hexdigest()
    if not path.is_file():
        raise NativeEvidenceInvalid(f"Git authority path is not a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_no_redirecting_entries(root: Path) -> None:
    """Reject symlinks and Windows reparse points before an authority copy."""

    for path in (root, *root.rglob("*")):
        metadata = os.lstat(path)
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if stat.S_ISLNK(metadata.st_mode) or reparse:
            raise NativeEvidenceInvalid(f"local repository contains redirecting entry: {path}")


def _git_read_only(
    repository: Path, *arguments: str, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    environment = _hardened_git_environment()
    return _run(
        ["git", "-c", "core.fsmonitor=false", "--no-pager", *arguments],
        cwd=repository,
        env=environment,
        timeout=timeout,
    )


def _git_binary_read_only(repository: Path, *arguments: str) -> bytes:
    environment = _hardened_git_environment()
    completed = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "--no-pager", *arguments],
        cwd=repository,
        env=environment,
        shell=False,
        check=False,
        capture_output=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise NativeEvidenceInvalid(
            f"binary Git observation failed: {completed.stderr[:4096]!r}"
        )
    if len(completed.stdout) > 64 * 1024 * 1024:
        raise NativeEvidenceInvalid("binary Git observation exceeded its bound")
    return completed.stdout


def _git_material_tree_hash_at_commit(repository: Path, commit: str) -> str:
    """Rebuild the authorized content-only material hash without checkout."""

    records = _git_binary_read_only(repository, "ls-tree", "-r", "-z", commit)
    entries: list[tuple[str, bytes]] = []
    for record in records.split(b"\0"):
        if not record:
            continue
        try:
            header, path_bytes = record.split(b"\t", 1)
            mode, object_type, object_id = header.split(b" ", 2)
            relative = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise NativeEvidenceInvalid("Git tree entry is not canonical UTF-8 material") from exc
        if object_type != b"blob" or mode in {b"120000", b"160000"}:
            raise NativeEvidenceInvalid("Git initial tree contains redirecting or submodule material")
        require_safe_relative_path(relative, "Git initial material path")
        entries.append(
            (relative, _git_binary_read_only(repository, "cat-file", "blob", object_id.decode("ascii")))
        )
    digest = hashlib.sha256()
    for relative, data in sorted(entries):
        digest.update(
            relative.encode("utf-8")
            + b"\0"
            + hashlib.sha256(data).hexdigest().encode("ascii")
            + b"\0"
            + str(len(data)).encode("ascii")
            + b"\n"
        )
    return digest.hexdigest()


def _observe_local_repository_source(
    repository_value: str | Path,
    *,
    _allowed_hooks_path: Path | None = None,
) -> LocalRepositoryAuthorityObservation:
    """Fail-closed, network-free observation of one ordinary local Git root."""

    repository, _ = _safe_directory(repository_value, "local workspace source repository")
    if repository / ".git" == repository:
        raise NativeEvidenceInvalid("local workspace source repository is invalid")
    _inspect_local_git_metadata(repository, allowed_hooks_path=_allowed_hooks_path)
    _assert_no_redirecting_entries(repository)
    byte_inventory_before = _filesystem_byte_inventory_hash(repository)
    try:
        root = Path(_git_read_only(repository, "rev-parse", "--show-toplevel").stdout.strip())
        inside = _git_read_only(repository, "rev-parse", "--is-inside-work-tree").stdout.strip()
        git_directory_value = _git_read_only(repository, "rev-parse", "--absolute-git-dir").stdout.strip()
        head = _git_read_only(repository, "rev-parse", "--verify", "HEAD^{commit}").stdout.strip().lower()
        count_text = _git_read_only(repository, "rev-list", "--count", "HEAD").stdout.strip()
        message = _git_read_only(repository, "log", "-1", "--format=%B").stdout.rstrip("\r\n")
        status = _git_read_only(
            repository, "status", "--porcelain=v1", "--untracked-files=all"
        ).stdout
        unmerged = _git_read_only(repository, "ls-files", "--unmerged", "-z").stdout
        stage_records = _git_read_only(repository, "ls-files", "--stage", "-z").stdout
        tracked_records = _git_read_only(repository, "ls-files", "--cached", "-z").stdout
        remotes = tuple(
            line for line in _git_read_only(repository, "remote", "-v").stdout.splitlines() if line
        )
        refs = _git_read_only(
            repository, "for-each-ref", "--format=%(refname)%00%(objectname)"
        ).stdout.encode("utf-8")
    except (OSError, RuntimeError, ValueError) as exc:
        raise NativeEvidenceInvalid(f"local repository observation failed: {exc}") from exc
    if inside != "true" or root.resolve() != repository.resolve():
        raise NativeEvidenceInvalid("local repository source must be the exact non-bare Git worktree root")
    git_directory = Path(git_directory_value)
    if not git_directory.is_absolute():
        git_directory = repository / git_directory
    if git_directory != repository / ".git" or not git_directory.is_dir():
        raise NativeEvidenceInvalid("local repository source must own an ordinary .git directory")
    if status:
        raise NativeEvidenceInvalid("local repository source worktree or index is not clean")
    if unmerged:
        raise NativeEvidenceInvalid("local repository source has unresolved conflicts")
    if any(record.startswith("160000 ") for record in stage_records.split("\x00") if record):
        raise NativeEvidenceInvalid("local repository source contains Git submodules")
    tracked = {record for record in tracked_records.split("\x00") if record}
    material_files = {
        path.relative_to(repository).as_posix()
        for path in repository.rglob("*")
        if ".git" not in path.relative_to(repository).parts and path.is_file()
    }
    if material_files != tracked:
        raise NativeEvidenceInvalid(
            "local repository source contains ignored or otherwise untracked material"
        )
    try:
        commit_count = int(count_text)
    except ValueError as exc:
        raise NativeEvidenceInvalid("local repository commit count is invalid") from exc
    config_path = git_directory / "config"
    index_path = git_directory / "index"
    byte_inventory_after = _filesystem_byte_inventory_hash(repository)
    if byte_inventory_after != byte_inventory_before:
        raise NativeEvidenceInvalid("local repository bytes changed during observation")
    return LocalRepositoryAuthorityObservation(
        repository=str(repository),
        git_directory=str(git_directory),
        head=head,
        material_tree_hash=_git_material_tree_hash_at_commit(repository, head),
        worktree_material_tree_hash=fixture_material_tree_hash(repository),
        commit_count=commit_count,
        complete_commit_message=message,
        porcelain_status=status,
        remotes=remotes,
        config_sha256=_sha256_file_or_absent(config_path),
        refs_sha256=hashlib.sha256(refs).hexdigest(),
        index_sha256=_sha256_file_or_absent(index_path),
        byte_inventory_sha256=byte_inventory_after,
    )


def _initialized_identity_from_local_source(
    observation: LocalRepositoryAuthorityObservation,
    profile: NativeMissionProfile,
) -> InitializedWorkspaceIdentity:
    source = profile.effective_workspace_source
    if source.kind is not WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY:
        raise NativeEvidenceInvalid("profile does not authorize a local repository source")
    if observation.repository != source.local_repository_path:
        raise NativeEvidenceInvalid("observed local repository path contradicts the profile")
    return InitializedWorkspaceIdentity(
        initial_git_head=observation.head,
        initial_material_tree_hash=observation.material_tree_hash,
        initial_commit_count=observation.commit_count,
        initial_commit_message=observation.complete_commit_message,
        source_kind=source.kind.value,
        source_identity=source.identity_fingerprint,
    ).validated()


def _last_git_config_value(
    entries: tuple[_LocalGitConfigEntry, ...], key: str, default: str
) -> str:
    values = [entry.value for entry in entries if entry.canonical_key == key]
    return values[-1] if values else default


def _normalized_target_config_settings(
    copied_entries: tuple[_LocalGitConfigEntry, ...], hooks: Path
) -> tuple[tuple[str, str, str], ...]:
    repository_format = _last_git_config_value(
        copied_entries, "core.repositoryformatversion", "0"
    )
    if repository_format not in {"0", "1"}:
        raise NativeEvidenceInvalid("source repository format is unsupported for sanitization")
    bare = _git_config_boolean(
        _last_git_config_value(copied_entries, "core.bare", "false"), "core.bare"
    )
    if bare:
        raise NativeEvidenceInvalid("local workspace source cannot be bare")

    settings: list[tuple[str, str, str]] = [
        ("core", "repositoryformatversion", repository_format),
        (
            "core",
            "filemode",
            "true" if _git_config_boolean(
                _last_git_config_value(copied_entries, "core.filemode", "false"),
                "core.filemode",
            ) else "false",
        ),
        ("core", "bare", "false"),
        (
            "core",
            "logallrefupdates",
            "true" if _git_config_boolean(
                _last_git_config_value(copied_entries, "core.logallrefupdates", "true"),
                "core.logallrefupdates",
            ) else "false",
        ),
    ]
    for name in ("symlinks", "ignorecase", "precomposeunicode"):
        key = f"core.{name}"
        values = [entry.value for entry in copied_entries if entry.canonical_key == key]
        if values:
            settings.append(
                ("core", name, "true" if _git_config_boolean(values[-1], key) else "false")
            )
    autocrlf = _last_git_config_value(copied_entries, "core.autocrlf", "false").casefold()
    if autocrlf not in {"true", "false", "input"}:
        raise NativeEvidenceInvalid("core.autocrlf is unsupported for deterministic sanitization")
    safecrlf = _last_git_config_value(copied_entries, "core.safecrlf", "false").casefold()
    if safecrlf not in {"true", "false", "warn"}:
        raise NativeEvidenceInvalid("core.safecrlf is unsupported for deterministic sanitization")
    settings.extend(
        (
            ("core", "autocrlf", autocrlf),
            ("core", "safecrlf", safecrlf),
            ("core", "hooksPath", hooks.as_posix()),
        )
    )
    object_format = [
        entry.value.casefold()
        for entry in copied_entries
        if entry.canonical_key == "extensions.objectformat"
    ]
    if object_format:
        if object_format[-1] not in {"sha1", "sha256"}:
            raise NativeEvidenceInvalid("extensions.objectFormat is unsupported")
        settings.append(("extensions", "objectFormat", object_format[-1]))
    ref_storage = [
        entry.value.casefold()
        for entry in copied_entries
        if entry.canonical_key == "extensions.refstorage"
    ]
    if ref_storage:
        if ref_storage[-1] not in {"files", "reftable"}:
            raise NativeEvidenceInvalid("extensions.refStorage is unsupported")
        settings.append(("extensions", "refStorage", ref_storage[-1]))
    settings.extend(
        (
            ("user", "name", _TARGET_LOCAL_USER_NAME),
            ("user", "email", _TARGET_LOCAL_USER_EMAIL),
            ("commit", "gpgSign", "false"),
            ("tag", "gpgSign", "false"),
        )
    )
    return tuple(settings)


def _render_target_git_config(settings: tuple[tuple[str, str, str], ...]) -> bytes:
    sections: list[str] = []
    current: str | None = None
    for section, name, value in settings:
        if section != current:
            sections.append(f"[{section}]\n")
            current = section
        sections.append(f"\t{name} = {value}\n")
    return "".join(sections).encode("utf-8")


def _remove_target_git_metadata_path(path: Path) -> None:
    if not _lexists(path):
        return
    metadata = os.lstat(path)
    if _is_redirecting_metadata(metadata):
        raise NativeEvidenceInvalid(f"target Git metadata is redirecting: {path}")
    if stat.S_ISDIR(metadata.st_mode):
        _remove_tree_force(path)
    elif stat.S_ISREG(metadata.st_mode):
        path.unlink()
    else:
        raise NativeEvidenceInvalid(f"target Git metadata is special: {path}")


def _sanitize_target_git_metadata(
    target: Path,
) -> tuple[Path, tuple[tuple[str, str, str], ...]]:
    """Replace all copied behavior-bearing Git metadata before target Git use."""

    git_directory = _ordinary_git_directory(target)
    copied_entries = _parse_local_git_config(git_directory / "config")
    hooks = git_directory / "hooks"
    _remove_target_git_metadata_path(hooks)
    hooks.mkdir()
    for candidate in (
        git_directory / "config.worktree",
        git_directory / "commondir",
        git_directory / "objects" / "info" / "alternates",
        git_directory / "objects" / "info" / "http-alternates",
    ):
        _remove_target_git_metadata_path(candidate)
    settings = _normalized_target_config_settings(copied_entries, hooks)
    (git_directory / "config").write_bytes(_render_target_git_config(settings))
    return hooks, settings


def _verify_sanitized_target_git_metadata(
    target: Path,
    hooks: Path,
    expected_settings: tuple[tuple[str, str, str], ...],
) -> None:
    try:
        hook_entries = tuple(os.scandir(hooks))
    except OSError as exc:
        raise NativeEvidenceInvalid("sanitized target hooks directory is unreadable") from exc
    if hook_entries:
        raise NativeEvidenceInvalid("sanitized target hooks directory is not empty")
    entries = _inspect_local_git_metadata(target, allowed_hooks_path=hooks)
    observed = tuple(
        (entry.section.casefold(), entry.name.casefold(), entry.value)
        for entry in entries
    )
    expected = tuple(
        (section.casefold(), name.casefold(), value)
        for section, name, value in expected_settings
    )
    if observed != expected or any(entry.subsection is not None for entry in entries):
        raise NativeEvidenceInvalid("sanitized target local Git config differs from its allowlist")
    environment = _hardened_git_environment()
    required_environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if any(environment.get(name) != value for name, value in required_environment.items()):
        raise NativeEvidenceInvalid("sanitized target Git environment is not hardened")
    configured_hooks = Path(
        _git_read_only(target, "config", "--local", "--get", "core.hooksPath").stdout.strip()
    )
    if configured_hooks.resolve(strict=True) != hooks.resolve(strict=True):
        raise NativeEvidenceInvalid("sanitized target effective hooks path differs")
    origins = _git_read_only(
        target, "config", "--show-origin", "--show-scope", "--list"
    ).stdout.splitlines()
    if any(line.casefold().startswith(("global\t", "system\t")) for line in origins):
        raise NativeEvidenceInvalid("sanitized target consulted owner Git configuration")


def _materialize_local_repository_copy(
    *, profile: NativeMissionProfile, destination_parent: Path, repository_name: str
) -> tuple[FixtureRepository, InitializedWorkspaceIdentity]:
    """Copy an ordinary repository without shared Git authority or network.

    A byte copy of the owned ``.git`` directory avoids shared objects, refs,
    index and worktree.  Copied behavior-bearing Git metadata is replaced by an
    allowlisted local config plus an empty in-target hooks directory before any
    target Git command.  The source is independently observed before and after
    the copy, so any source-byte drift fails before spawn.
    """

    source_authority = profile.effective_workspace_source
    if source_authority.kind is not WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY:
        raise NativeEvidenceInvalid("profile does not authorize a local repository copy")
    source = Path(source_authority.local_repository_path)
    before = _observe_local_repository_source(source)
    target = destination_parent / repository_name
    if target.exists():
        raise NativeEvidenceInvalid("isolated target workspace must be fresh")
    try:
        shutil.copytree(source, target, copy_function=shutil.copy2, symlinks=False)
        _assert_no_redirecting_entries(target)
        hooks, target_settings = _sanitize_target_git_metadata(target)
        _verify_sanitized_target_git_metadata(target, hooks, target_settings)
        target_observation = _observe_local_repository_source(
            target, _allowed_hooks_path=hooks
        )
        after = _observe_local_repository_source(source)
    except Exception:
        if target.exists():
            _remove_tree_force(target)
        raise
    if before != after:
        _remove_tree_force(target)
        raise NativeEvidenceInvalid("local repository source changed during materialization")
    expected = _initialized_identity_from_local_source(before, profile)
    observed = InitializedWorkspaceIdentity(
        target_observation.head,
        target_observation.material_tree_hash,
        target_observation.commit_count,
        target_observation.complete_commit_message,
        source_authority.kind.value,
        source_authority.identity_fingerprint,
    ).validated()
    if target_observation.porcelain_status or target_observation.remotes:
        _remove_tree_force(target)
        raise NativeEvidenceInvalid("isolated local repository target is not clean and remote-free")
    if target_observation.worktree_material_tree_hash != before.worktree_material_tree_hash:
        _remove_tree_force(target)
        raise NativeEvidenceInvalid("isolated local repository worktree bytes differ from source")
    source_git = Path(before.git_directory)
    target_git = target / ".git"
    try:
        independent_objects = not os.path.samefile(
            source_git / "objects", target_git / "objects"
        )
        independent_index = not os.path.samefile(
            source_git / "index", target_git / "index"
        )
    except OSError as exc:
        _remove_tree_force(target)
        raise NativeEvidenceInvalid("independent target Git authority is unreadable") from exc
    if not independent_objects or not independent_index:
        _remove_tree_force(target)
        raise NativeEvidenceInvalid("isolated target shares its object database or index")
    if observed != expected:
        _remove_tree_force(target)
        raise NativeEvidenceInvalid("isolated local repository target differs from authorized identity")
    return FixtureRepository(
        target,
        target_observation.head,
        target_observation.material_tree_hash,
        profile.mission_text,
        profile.required_commit_message,
    ), observed


def _observe_built_fixture(built: Any, profile: NativeMissionProfile) -> InitializedWorkspaceIdentity:
    """Independently observe one built fixture and bind its exact identity."""

    repository = Path(built.repository)
    try:
        head = _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip().lower()
        count_text = _run(["git", "rev-list", "--count", "HEAD"], cwd=repository).stdout.strip()
        message = _run(["git", "log", "-1", "--format=%B"], cwd=repository).stdout.rstrip("\r\n")
        status = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout
        remotes = _run(["git", "remote"], cwd=repository).stdout.strip()
    except RuntimeError as exc:
        raise NativeEvidenceInvalid(f"initialized workspace observation failed: {exc}") from exc
    tree = fixture_material_tree_hash(repository)
    if head != built.initial_head or tree != built.initial_material_tree_hash:
        raise NativeEvidenceInvalid("fixture builder facts contradict the independent observation")
    if count_text != "1":
        raise NativeEvidenceInvalid("initialized workspace must contain exactly one commit")
    if not profile.has_nested_runtime_authority and message != profile.fixture_initial_commit_message:
        raise NativeEvidenceInvalid("initialized workspace initial commit message is not exact")
    if status:
        raise NativeEvidenceInvalid("initialized workspace worktree is not clean")
    if remotes:
        raise NativeEvidenceInvalid("initialized workspace has a remote")
    source = profile.effective_workspace_source
    if source.kind is not WorkspaceSourceKind.REGISTERED_FIXTURE:
        raise NativeEvidenceInvalid("fixture observation requires registered fixture authority")
    if profile.has_nested_runtime_authority:
        return InitializedWorkspaceIdentity(
            head,
            tree,
            1,
            message,
            source.kind.value,
            source.identity_fingerprint,
        ).validated()
    return InitializedWorkspaceIdentity(head, tree, 1, message).validated()


def observe_initialized_workspace_identity(profile: NativeMissionProfile) -> InitializedWorkspaceIdentity:
    """Observe the deterministic fixture identity via one scratch rehearsal.

    The rehearsal builds the registered fixture in a temporary directory,
    independently observes its Git and material identity, and removes every
    scratch file.  It creates no run state and reserves nothing.
    """

    profile.validated()
    if profile.has_nested_runtime_authority and not profile.is_launchable_runtime_profile:
        raise ValueError("initialized workspace observation requires the launchable runtime-v2 schema")
    source = profile.effective_workspace_source
    scratch = Path(tempfile.mkdtemp(prefix="admissible-fixture-rehearsal-"))
    try:
        if source.kind is WorkspaceSourceKind.REGISTERED_FIXTURE:
            builder = resolve_fixture_builder(source.fixture_id, source.fixture_version)
            built = builder(scratch, repository_name="work")
            return _observe_built_fixture(built, profile)
        _built, observed = _materialize_local_repository_copy(
            profile=profile,
            destination_parent=scratch,
            repository_name="work",
        )
        return observed
    finally:
        _remove_tree_force(scratch)


def materialize_authorized_workspace(
    *,
    profile: NativeMissionProfile,
    destination_parent: str | Path,
    authorized_identity: InitializedWorkspaceIdentity,
    repository_name: str = WORKSPACE_DIRECTORY_NAME,
) -> FixtureRepository:
    """Materialize once and compare independently before provider authority."""

    profile = profile.validated()
    parent, _ = _safe_directory(destination_parent, "workspace destination parent")
    source = profile.effective_workspace_source
    if source.kind is WorkspaceSourceKind.REGISTERED_FIXTURE:
        builder = resolve_fixture_builder(source.fixture_id, source.fixture_version)
        built = builder(parent, repository_name=repository_name)
        observed = _observe_built_fixture(built, profile)
    else:
        built, observed = _materialize_local_repository_copy(
            profile=profile,
            destination_parent=parent,
            repository_name=repository_name,
        )
    if observed != authorized_identity.validated():
        repository = Path(built.repository)
        if repository.exists():
            _remove_tree_force(repository)
        raise NativeEvidenceInvalid(
            "initialized workspace contradicts the authorized workspace identity"
        )
    return built


def _profile_fixture_version_label(profile: NativeMissionProfile) -> str:
    source = profile.effective_workspace_source
    if source.kind is WorkspaceSourceKind.REGISTERED_FIXTURE:
        return f"{source.fixture_id}@v{source.fixture_version}"
    return f"local-git@{source.identity_fingerprint}"


@dataclass(frozen=True)
class NativeCanaryAuthorizationPayloadV4:
    """Profile-bound v4 authorization payload for new native runs.

    It carries every v3 authorization and backend binding plus the complete
    canonical mission-profile body (with its recomputed non-self-referential
    fingerprint) and the independently observed initialized-workspace
    identity.  For a registered profile the profile values are the only
    authority for identity and budgets; every mirrored payload field must
    equal its profile counterpart exactly.
    """

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
    required_commit_message: str | None
    run_root: str
    workspace_root: str
    evidence_root: str
    native_sidecar_root: str
    mission_profile: NativeMissionProfile
    initialized_workspace: InitializedWorkspaceIdentity
    payload_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["source_repository_identity"] = self.source_repository_identity.to_dict()
        data["launcher_prefix"] = list(self.launcher_prefix)
        data["budgets"] = list(self.budgets)
        data["attestation_non_claims"] = list(self.attestation_non_claims)
        data["canary_non_claims"] = list(self.canary_non_claims)
        data["mission_profile"] = self.mission_profile.to_dict()
        data["initialized_workspace"] = self.initialized_workspace.to_dict()
        data.pop("payload_fingerprint")
        return data

    def validated(self) -> "NativeCanaryAuthorizationPayloadV4":
        if self.schema_version != AUTHORIZATION_SCHEMA_VERSION_V4:
            raise ValueError("unsupported v4 authorization payload")
        if not isinstance(self.mission_profile, NativeMissionProfile):
            raise ValueError("v4 authorization payload must embed the complete mission profile")
        profile = self.mission_profile.validated()
        if profile.has_nested_runtime_authority and not profile.is_launchable_runtime_profile:
            raise ValueError("runtime-v4 authorization requires the launchable runtime-v2 schema")
        if not isinstance(self.initialized_workspace, InitializedWorkspaceIdentity):
            raise ValueError("v4 authorization payload must bind the initialized workspace identity")
        self.initialized_workspace.validated()
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
        require_identifier(self.run_id,"authorization run ID"); require_identifier(self.session_id,"authorization session ID"); require_nonempty_text(self.source_head,"authorization source HEAD",max_bytes=128); require_nonempty_text(self.selected_model,"authorization model",max_bytes=256); require_nonempty_text(self.fixture_version,"fixture version",max_bytes=128); require_nonempty_text(self.executable,"authorization executable",max_bytes=4096)
        if self.required_commit_message is not None:
            require_nonempty_text(self.required_commit_message,"commit message",max_bytes=1024)
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
            if tuple(self.attestation_non_claims) != WRAPPER_CHAIN_NON_CLAIMS: raise ValueError("authorization non-claims differ from the wrapper-chain attestation class")
        else:
            raise ValueError("authorization attestation class is unsupported")
        require_nonempty_text(self.backend_readiness_reason,"authorization readiness reason",max_bytes=256)
        if self.backend_readiness_reason != CLASS_READINESS_REASONS[self.backend_attestation_class]:
            raise ValueError("authorization readiness reason does not pair with the attestation class")
        if tuple(self.canary_non_claims) != CANARY_NON_CLAIMS:
            raise ValueError("authorization canary non-claims differ from the exact committed canary boundary set")
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
        # One authority: every mirrored value must equal the embedded profile.
        for label, mirrored, authoritative in (
            ("run ID", self.run_id, profile.run_id),
            ("session ID", self.session_id, profile.session_id),
            ("model", self.selected_model, profile.model),
            ("timeout", self.timeout_seconds, profile.timeout_seconds),
            ("stdout limit", self.stdout_byte_limit, profile.stdout_byte_limit),
            ("stderr limit", self.stderr_byte_limit, profile.stderr_byte_limit),
            ("budgets", self.budgets, profile.budgets),
            ("commit message", self.required_commit_message, profile.required_commit_message),
            ("fixture version", self.fixture_version, _profile_fixture_version_label(profile)),
        ):
            if mirrored != authoritative:
                raise ValueError(f"authorization {label} contradicts the embedded mission profile")
        if Path(self.run_root).name != profile.run_id:
            raise ValueError("authorization run root basename must equal the profile run ID")
        source_authority = profile.effective_workspace_source
        if profile.is_launchable_runtime_profile:
            if (
                self.initialized_workspace.source_kind != source_authority.kind.value
                or self.initialized_workspace.source_identity != source_authority.identity_fingerprint
            ):
                raise ValueError("initialized workspace source identity contradicts the embedded mission profile")
        elif self.initialized_workspace.initial_commit_message != profile.fixture_initial_commit_message:
            raise ValueError("initialized workspace commit message contradicts the embedded mission profile")
        # Derived mission/plan/contract fingerprints are recomputed from the
        # embedded profile, never trusted from the caller.
        derived = create_canary_session(session_id=profile.session_id, profile=profile)
        if (
            derived.mission.mission_fingerprint != self.mission_fingerprint
            or derived.gate_plan.plan_fingerprint != self.gate_plan_fingerprint
            or derived.current_gate.contract_fingerprint != self.gate_contract_fingerprint
        ):
            raise ValueError("authorization mission/plan/contract fingerprints are not derived from the embedded profile")
        if fingerprint(self._body())!=self.payload_fingerprint: raise ValueError("authorization payload fingerprint mismatch")
        return self

    def validated_for_authorization(self, *, active_source_repository: str | Path) -> "NativeCanaryAuthorizationPayloadV4":
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
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCanaryAuthorizationPayloadV4":
        """Parse a persisted v4 payload without granting executable authority."""

        require_exact_keys(data, set(cls.__dataclass_fields__), "native canary authorization payload v4")
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
        if not isinstance(data["mission_profile"], Mapping):
            raise ValueError("authorization mission profile must be a complete canonical object")
        values["mission_profile"] = NativeMissionProfile.from_dict(data["mission_profile"])
        if not isinstance(data["initialized_workspace"], Mapping):
            raise ValueError("authorization initialized workspace must be a canonical object")
        values["initialized_workspace"] = InitializedWorkspaceIdentity.from_dict(data["initialized_workspace"])
        return cls(**values).validated()


def build_profile_authorization_payload(*, source_repository: Path, source_head: str, attestation: BackendAttestation, run_root: str | Path, profile: NativeMissionProfile, initialized_workspace: InitializedWorkspaceIdentity, backend_readiness_reason: str | None = None) -> NativeCanaryAuthorizationPayloadV4:
    """Build the profile-bound v4 payload; the profile is the one authority."""

    profile = profile.validated()
    if attestation.selected_model != profile.model:
        raise ValueError("attested selected model contradicts the mission profile model")
    state = create_canary_session(session_id=profile.session_id, profile=profile)
    source, source_identity = _safe_directory(source_repository, "authorization source repository")
    root = Path(os.path.abspath(os.fspath(run_root))); evidence = root / EVIDENCE_DIRECTORY_NAME; workspace = root / WORKSPACE_DIRECTORY_NAME; sidecar = evidence / NATIVE_SIDECAR_DIRECTORY_NAME
    attestation = attestation.validated()
    readiness_reason = backend_readiness_reason if backend_readiness_reason is not None else CLASS_READINESS_REASONS.get(attestation.attestation_class, "")
    provisional = NativeCanaryAuthorizationPayloadV4(
        AUTHORIZATION_SCHEMA_VERSION_V4, str(source), source_identity, source_head.lower(), True,
        profile.run_id, profile.session_id,
        state.mission.mission_fingerprint, state.gate_plan.plan_fingerprint, state.current_gate.contract_fingerprint,
        attestation.attestation_class, readiness_reason, attestation.attestation_fingerprint,
        tuple(attestation.non_claims), CANARY_NON_CLAIMS,
        attestation.executable.canonical_path, tuple(item.canonical_path for item in attestation.launcher_prefix),
        profile.model, profile.timeout_seconds, profile.stdout_byte_limit, profile.stderr_byte_limit,
        profile.budgets, _profile_fixture_version_label(profile), profile.required_commit_message,
        str(root), str(workspace), str(evidence), str(sidecar),
        profile, initialized_workspace.validated(), "0" * 64,
    )
    return NativeCanaryAuthorizationPayloadV4(**{**provisional.__dict__, "payload_fingerprint": fingerprint(provisional._body())}).validated()


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
    parser.add_argument("--executable",required=True); parser.add_argument("--executable-prefix-arg",action="append",default=[]); parser.add_argument("--model",default=None); parser.add_argument("--timeout-seconds",type=int,default=None)
    parser.add_argument("--stdout-byte-limit",type=int,default=None,help="Native stdout evidence budget in bytes; for a selected profile it may only repeat the profile value")
    parser.add_argument("--stderr-byte-limit",type=int,default=None,help="Native stderr evidence budget in bytes; for a selected profile it may only repeat the profile value")
    profile_selection = parser.add_mutually_exclusive_group()
    profile_selection.add_argument("--profile-id",default=None,help="Explicit registered mission-profile selection; omitted with no document selects the historical canary mission with its exact historical defaults. No environment fallback exists.")
    profile_selection.add_argument("--profile-document",default=None,help="Absolute path to one exact runtime-v2 NativeMissionProfile JSON document. No registry fallback or insertion occurs.")
    parser.add_argument("--attestation-class",choices=["package-bin","wrapper-chain"],default="package-bin",help="Explicit attestation class. wrapper-chain is the weaker LOCAL_WRAPPER_CHAIN class: it derives every launcher file from canonical host cursor-agent discovery, establishes no publisher provenance, and requires owner authorization naming that exact class.")
    parser.add_argument("--owner-authorization",help="Explicit owner phrase; never persisted"); parser.add_argument("--preflight-only",action="store_true",help="Print local attestation and authorization payload without creating a run")
    return parser


def main(argv: list[str] | None = None, *, _validated_profile: NativeMissionProfile | None = None) -> int:
    args=build_parser().parse_args(argv); blocked={"status":NativeCanaryStatus.PREFLIGHT_BLOCKED.value,"provider_invocations":0,"native_attempts_reserved":0,"native_processes_started":0,"native_processes_completed":0,"process_observations_published":0,"accepted_native_results_published":0,"authorized_budgets":{"provider_invocations":1,"native_phase_attempts":1,"repair_rounds":0,"auditor_invocations":0,"retries":0},"canary_success":False}
    # Profile selection and budget-authority resolution run before any local
    # probe, payload, or filesystem effect.  For a selected profile the profile
    # values are the one authority; a differing CLI value fails immediately.
    profile: NativeMissionProfile | None = (
        _validated_profile.validated() if _validated_profile is not None else None
    )
    if profile is not None and (args.profile_id is not None or args.profile_document is not None):
        print(json.dumps({**blocked,"detail":"programmatic profile authority cannot be combined with CLI profile selection"},sort_keys=True)); return 2
    if args.profile_id is not None or args.profile_document is not None:
        try:
            profile=(
                resolve_registered_profile(args.profile_id)
                if args.profile_id is not None
                else load_native_mission_profile_document(args.profile_document)
            )
        except ValueError as exc: print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    if profile is not None:
        for label, supplied, authoritative in (("--timeout-seconds",args.timeout_seconds,profile.timeout_seconds),("--stdout-byte-limit",args.stdout_byte_limit,profile.stdout_byte_limit),("--stderr-byte-limit",args.stderr_byte_limit,profile.stderr_byte_limit),("--model",args.model,profile.model)):
            if supplied is not None and supplied != authoritative:
                print(json.dumps({**blocked,"detail":f"{label} contradicts the selected profile; the registered profile is the one authority"},sort_keys=True)); return 2
        if args.run_id != profile.run_id or args.session_id != profile.session_id:
            print(json.dumps({**blocked,"detail":"run and session IDs are profile authority and must equal the selected profile exactly"},sort_keys=True)); return 2
        timeout_seconds=profile.timeout_seconds; stdout_byte_limit=profile.stdout_byte_limit; stderr_byte_limit=profile.stderr_byte_limit; model=profile.model
    else:
        timeout_seconds=args.timeout_seconds if args.timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS
        model=args.model if args.model is not None else "auto"
        for label, supplied, historical in (("--stdout-byte-limit",args.stdout_byte_limit,DEFAULT_STDOUT_BYTE_LIMIT),("--stderr-byte-limit",args.stderr_byte_limit,DEFAULT_STDERR_BYTE_LIMIT)):
            if supplied is not None and supplied != historical:
                print(json.dumps({**blocked,"detail":f"{label} is fixed to the exact historical default for the profile-less historical canary invocation"},sort_keys=True)); return 2
        stdout_byte_limit=DEFAULT_STDOUT_BYTE_LIMIT; stderr_byte_limit=DEFAULT_STDERR_BYTE_LIMIT
    if not 1<=timeout_seconds<=3600: print(json.dumps({**blocked,"detail":"timeout must be from 1 through 3600 seconds"},sort_keys=True)); return 2
    try: source,_=_safe_directory(args.source_repository,"source repository")
    except ValueError as exc: print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    attestation_class=ATTESTATION_CLASS_WRAPPER_CHAIN if args.attestation_class=="wrapper-chain" else ATTESTATION_CLASS_PACKAGE_BIN
    try: config=CursorNativeBackendConfig(executable=args.executable,launcher_prefix=tuple(args.executable_prefix_arg),model=model,attestation_class=attestation_class)
    except ValueError as exc: print(json.dumps({**blocked,"detail":str(exc)},sort_keys=True)); return 2
    try:
        # Gate construction/validation is part of source/backend/gate preflight
        # and has no filesystem or authorization side effect.
        create_canary_session(session_id=args.session_id, profile=profile)
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
        if profile is None:
            payload=build_authorization_payload(source_repository=source,source_head=args.required_source_head,run_id=args.run_id,session_id=args.session_id,attestation=decision.attestation,run_root=args.run_root,timeout_seconds=timeout_seconds,backend_readiness_reason=decision.reason_code)
        else:
            rehearsed_identity=observe_initialized_workspace_identity(profile)
            payload=build_profile_authorization_payload(source_repository=source,source_head=args.required_source_head,attestation=decision.attestation,run_root=args.run_root,profile=profile,initialized_workspace=rehearsed_identity,backend_readiness_reason=decision.reason_code)
        payload.validated_for_authorization(active_source_repository=source)
    except (ValueError, NativeEvidenceInvalid, RuntimeError) as exc:
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
    run_root.mkdir(); _safe_directory(run_root,"run root")
    if profile is None:
        fixture=build_canary_repository(run_root,repository_name=WORKSPACE_DIRECTORY_NAME)
    else:
        try:
            fixture = materialize_authorized_workspace(
                profile=profile,
                destination_parent=run_root,
                authorized_identity=payload.initialized_workspace,
                repository_name=WORKSPACE_DIRECTORY_NAME,
            )
        except (ValueError, NativeEvidenceInvalid, RuntimeError) as exc:
            print(json.dumps({**blocked,"detail":f"initialized workspace is not launchable: {exc}"},sort_keys=True)); return 2
    evidence=(run_root/EVIDENCE_DIRECTORY_NAME); evidence.mkdir(); _safe_directory(evidence,"evidence directory")
    _write_run_metadata_once(evidence/RUN_PREFLIGHT_METADATA_FILE_NAME,{"classification":CANARY_CLASSIFICATION,"authorization_payload":payload.to_dict(),"attestation":decision.attestation.to_dict(),"local_capability_status":decision.status.value,"durability_capability":capability_diagnostic})
    session_store=AtomicDelegatedSessionStore(evidence/"delegated-state"); execution_store=AtomicNativeExecutionStore(evidence/NATIVE_SIDECAR_DIRECTORY_NAME); session_store.create(create_canary_session(session_id=args.session_id, profile=profile))
    execution_source = (
        Path(profile.effective_workspace_source.local_repository_path)
        if profile is not None
        and profile.effective_workspace_source.kind is WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY
        else source
    )
    harden_local_git=bool(profile is not None and profile.effective_workspace_source.kind is WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY)
    coordinator=NativeCanaryCoordinator(session_store=session_store,execution_store=execution_store,executor=NativeDelegatedExecutor(config=config,harden_git_environment=harden_local_git,git_metadata_inspector=_inspect_runtime_git_metadata if harden_local_git else None),backend_attestation=decision.attestation,source_repository=execution_source,work_workspace=fixture.repository,canary_parent=run_root,evidence_directory=evidence,timeout_seconds=timeout_seconds,stdout_byte_limit=stdout_byte_limit,stderr_byte_limit=stderr_byte_limit,profile=profile)
    outcome=coordinator.run(session_id=args.session_id); _write_run_metadata_once(evidence/"final-status.json",outcome.to_dict()); print(json.dumps(outcome.to_dict(),sort_keys=True)); return 0 if outcome.canary_success else 1


def run_native_mission_application(
    *,
    source_repository: str | Path,
    required_source_head: str,
    run_root: str | Path,
    run_id: str,
    session_id: str,
    executable: str,
    profile: NativeMissionProfile | None = None,
    profile_document: str | Path | None = None,
    executable_prefix_args: tuple[str, ...] = (),
    model: str | None = None,
    timeout_seconds: int | None = None,
    stdout_byte_limit: int | None = None,
    stderr_byte_limit: int | None = None,
    attestation_class: str = "package-bin",
    owner_authorization: str | None = None,
    preflight_only: bool = False,
) -> int:
    """Small application-facing boundary over the unchanged native pipeline.

    Exactly one validated profile object or absolute runtime document is the
    mission authority.  All source, backend, authorization, materialization,
    coordinator, final-status and reconstruction behavior remains in
    :func:`main`, so this seam cannot become a second executor.
    """

    if (profile is None) == (profile_document is None):
        raise ValueError("exactly one profile object or profile document is required")
    selected = (
        profile.validated()
        if profile is not None
        else load_native_mission_profile_document(profile_document)
    )
    if selected.has_nested_runtime_authority and not selected.is_launchable_runtime_profile:
        raise ValueError("native mission execution requires the launchable runtime-v2 schema")
    arguments = [
        "--source-repository", str(source_repository),
        "--required-source-head", required_source_head,
        "--run-root", str(run_root),
        "--run-id", run_id,
        "--session-id", session_id,
        "--executable", executable,
        "--attestation-class", attestation_class,
    ]
    for value in executable_prefix_args:
        arguments.extend(("--executable-prefix-arg", value))
    for flag, value in (
        ("--model", model),
        ("--timeout-seconds", timeout_seconds),
        ("--stdout-byte-limit", stdout_byte_limit),
        ("--stderr-byte-limit", stderr_byte_limit),
        ("--owner-authorization", owner_authorization),
    ):
        if value is not None:
            arguments.extend((flag, str(value)))
    if preflight_only:
        arguments.append("--preflight-only")
    return main(arguments, _validated_profile=selected)


if __name__ == "__main__": sys.exit(main())


__all__=["AUTHORIZATION_SCHEMA_VERSION","AUTHORIZATION_SCHEMA_VERSION_LEGACY_V2","AUTHORIZATION_SCHEMA_VERSION_V4","LEGACY_CANARY_PROFILE_ID","LEGACY_CANARY_FIXTURE_ID","LEGACY_CANARY_FIXTURE_VERSION","RUN_PREFLIGHT_METADATA_FILE_NAME","InitializedWorkspaceIdentity","LocalRepositoryAuthorityObservation","NativeCanaryAuthorizationPayloadV4","build_profile_authorization_payload","fixture_builder_registry","legacy_canary_profile","observe_initialized_workspace_identity","registered_profiles","resolve_fixture_builder","resolve_registered_profile","CANARY_NON_CLAIMS","CLASS_READINESS_REASONS","EVIDENCE_DIRECTORY_NAME","NATIVE_SIDECAR_DIRECTORY_NAME","PACKAGE_BIN_READY_REASON","WORKSPACE_DIRECTORY_NAME","BEHAVIORAL_EVIDENCE_SCHEMA_VERSION","CANARY_CLASSIFICATION","CANARY_FIXTURE_VERSION","CANARY_GATE_ID","CANARY_MISSION","CANARY_MISSION_ID","DEFAULT_STDERR_BYTE_LIMIT","DEFAULT_STDOUT_BYTE_LIMIT","DEFAULT_TIMEOUT_SECONDS","EXPECTED_MATERIAL_PATHS","FixtureRepository","MAX_AUDITOR_INVOCATIONS","MAX_NATIVE_PHASE_ATTEMPTS","MAX_PROVIDER_INVOCATIONS","MAX_REPAIR_ROUNDS","MAX_RETRIES","NativeCanaryAuthorizationPayload","NativeCanaryCoordinator","NativeCanaryOutcome","NativeCanaryStatus","ProductVerdict","OWNER_AUTHORIZATION_DIGEST_ENV","REQUIRED_COMMIT_MESSAGE","BehavioralVerifierEvidence","EvidenceOnlyCanaryReconstruction","build_authorization_payload","build_canary_repository","build_workflow_console_repository","build_native_agent_prompt","build_parser","create_canary_session","load_behavioral_verifier","main","npm_test_argv","reconstruct_completed_canary_success","reconstruct_completed_native_mission","run_behavioral_verifier","run_native_mission_application","_materialize_local_repository_copy","_observe_local_repository_source","_validate_future_run_root"]
