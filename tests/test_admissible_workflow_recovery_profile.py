"""Bounded registration proof for the workflow-recovery flagship profile.

No live provider is reachable from this module.  The one synthetic success
case proves protocol wiring only: its fake native mutation is intentionally
not a workflow engine, while behavioral success is explicitly synthesized.
The real embedded verifier is separately required to reject the untouched
fixture, and completed-solution correctness remains future run evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from test_admissible_delegated_gate_native_executor import (
    Clock,
    FakeNativeProcessRunner,
    _command,
    _commit,
    _injected_test_cursor,
)

from admissible.delegated_gate import native_canary as nc
from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.fixture_registry import (
    WORKFLOW_CONSOLE_FIXTURE_ID,
    WORKFLOW_CONSOLE_FIXTURE_VERSION,
    WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE,
    build_workflow_console_repository,
    fixture_material_tree_hash,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION,
    WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT,
    WORKFLOW_RECOVERY_MISSION_TEXT,
    WORKFLOW_RECOVERY_PROFILE,
    WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE,
    WORKFLOW_RECOVERY_VERIFIER_SOURCE,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    AUTHORIZATION_SCHEMA_VERSION_V4,
    BEHAVIORAL_EVIDENCE_SCHEMA_VERSION,
    CANARY_CLASSIFICATION,
    RUN_PREFLIGHT_METADATA_FILE_NAME,
    BehavioralVerifierEvidence,
    NativeCanaryCoordinator,
    NativeCanaryStatus,
    _observe_built_fixture,
    _write_run_metadata_once,
    build_canary_repository,
    build_native_agent_prompt,
    build_profile_authorization_payload,
    create_canary_session,
    reconstruct_completed_canary_success,
    resolve_fixture_builder,
    resolve_registered_profile,
)
from admissible.delegated_gate.native_executor import (
    AtomicNativeExecutionStore,
    NativeDelegatedExecutor,
    NativeEvidenceInvalid,
    NativeFilesystemIdentity,
)
from admissible.delegated_gate.state import Phase
from admissible.delegated_gate.store import AtomicDelegatedSessionStore


PROFILE = WORKFLOW_RECOVERY_PROFILE
MATERIAL_PATHS = (
    "README.md",
    "index.html",
    "src/app.js",
    "src/execution/engine.js",
    "src/storage/run-store.js",
    "src/ui/render.js",
)
FIXTURE_FILES = frozenset(
    {
        ".gitignore",
        "README.md",
        "package.json",
        "index.html",
        "style.css",
        "src/app.js",
        "src/domain/workflow.js",
        "src/domain/task.js",
        "src/domain/configuration.js",
        "src/serialization/config-export.js",
        "src/storage/config-store.js",
        "src/storage/memory-storage.js",
        "src/storage/local-storage.js",
        "src/ui/controller.js",
        "src/ui/render.js",
        "src/ui/forms.js",
        "test/workflow-definition.test.js",
        "test/config-store.test.js",
        "test/controller.test.js",
        "test/render.test.js",
        "test/fixtures/sample-workflows.json",
        "test/fixtures/legacy-run-state-v0.json",
    }
)
FORBIDDEN_FIXTURE_SYMBOLS = (
    "createWorkflowEngine",
    "startRun",
    "advanceRun",
    "cancelRun",
    "recoverRun",
    "exportRuns",
    "importRuns",
    "topologicalOrder",
    "retry-wait",
    "run history",
    "execution timeline",
    "run-state migration",
)


def _material_files(repository: Path) -> frozenset[str]:
    return frozenset(
        path.relative_to(repository).as_posix()
        for path in repository.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(repository).parts
    )


def _line_count(repository: Path) -> int:
    return sum(
        len((repository / relative).read_text(encoding="utf-8").splitlines())
        for relative in FIXTURE_FILES
    )


def _source_head(source: Path) -> str:
    return _command(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip().lower()


def _profile_variant(**changes) -> NativeMissionProfile:
    data = dict(PROFILE.to_dict())
    data.update(changes)
    if "verifier_source" in changes:
        data["verifier_source_sha256"] = hashlib.sha256(
            changes["verifier_source"].encode("utf-8")
        ).hexdigest()
    body = {key: value for key, value in data.items() if key != "profile_fingerprint"}
    data["profile_fingerprint"] = fingerprint(body)
    return NativeMissionProfile.from_dict(data)


@pytest.fixture(scope="module")
def built_fixture(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    root = tmp_path_factory.mktemp("workflow-console")
    first = build_workflow_console_repository(root, repository_name="first")
    npm = _command(["npm.cmd", "test"], cwd=first.repository)
    second_root = root / "rebuild"
    second_root.mkdir()
    second = build_workflow_console_repository(second_root, repository_name="second")
    return SimpleNamespace(root=root, first=first, second=second, npm=npm)


def test_profile_exact_identity_budgets_and_canonical_round_trip():
    assert PROFILE.schema_version == MISSION_PROFILE_SCHEMA_VERSION == "admissible_native_mission_profile_v1"
    assert PROFILE.profile_id == "workflow-recovery-v1"
    assert (PROFILE.fixture_id, PROFILE.fixture_version) == ("local-workflow-console", 1)
    assert PROFILE.run_id == PROFILE.session_id == "native-cursor-flagship-002"
    assert PROFILE.mission_id == "native-flagship-workflow-recovery"
    assert PROFILE.gate_id == "workflow-recovery-gate"
    assert PROFILE.model == "auto"
    assert PROFILE.timeout_seconds == 3600
    assert (PROFILE.stdout_byte_limit, PROFILE.stderr_byte_limit) == (8_388_608, 1_048_576)
    assert PROFILE.fixture_initial_commit_message == WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE
    assert PROFILE.required_commit_message == WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE
    assert PROFILE.budgets == (1, 1, 0, 0, 0)
    assert PROFILE.required_evidence_kinds == ("target_tree", "git_state", "verification_command")
    assert PROFILE.required_material_paths == MATERIAL_PATHS
    assert PROFILE.mission_text == WORKFLOW_RECOVERY_MISSION_TEXT
    assert PROFILE.completion_conditions_text == WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT
    assert PROFILE.verifier_source == WORKFLOW_RECOVERY_VERIFIER_SOURCE
    assert PROFILE.verifier_source_sha256 == hashlib.sha256(
        WORKFLOW_RECOVERY_VERIFIER_SOURCE.encode("utf-8")
    ).hexdigest()
    assert (PROFILE.verifier_timeout_seconds, PROFILE.verifier_output_limit_bytes) == (120, 524_288)
    (checkpoint,) = PROFILE.checkpoint_commands
    assert (checkpoint.command_id, checkpoint.argv) == ("npm-test", ("npm.cmd", "test"))
    assert (checkpoint.timeout_seconds, checkpoint.max_capture_bytes) == (300, 1_048_576)
    assert fingerprint(PROFILE._body()) == PROFILE.profile_fingerprint
    assert NativeMissionProfile.from_dict(json.loads(json.dumps(PROFILE.to_dict()))) == PROFILE


def test_profile_and_fixture_registries_are_exact_and_preserve_existing_entries():
    assert resolve_registered_profile("workflow-recovery-v1") == PROFILE
    assert resolve_registered_profile("incident-replay-v1").profile_id == "incident-replay-v1"
    assert resolve_registered_profile("act-2a-high-score-canary-v1").profile_id == "act-2a-high-score-canary-v1"
    with pytest.raises(ValueError, match="unknown mission profile"):
        resolve_registered_profile("workflow-recovery-v2")
    assert resolve_fixture_builder(WORKFLOW_CONSOLE_FIXTURE_ID, WORKFLOW_CONSOLE_FIXTURE_VERSION) is build_workflow_console_repository
    assert resolve_fixture_builder("local-incident-board", 1) is not build_workflow_console_repository
    assert resolve_fixture_builder("act-2a-canary-game-state", 2) is not build_workflow_console_repository
    with pytest.raises(ValueError, match="unknown fixture builder"):
        resolve_fixture_builder(WORKFLOW_CONSOLE_FIXTURE_ID, 2)
    with pytest.raises(ValueError, match="unknown fixture builder"):
        resolve_fixture_builder("workflow-console-alias", 1)


def test_rendered_prompt_exposes_material_and_git_contract_without_hidden_filename(tmp_path: Path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    state = create_canary_session(session_id=PROFILE.session_id, profile=PROFILE)
    prompt = build_native_agent_prompt(
        mission=state.mission,
        gate_contract=state.current_gate,
        work_workspace=workspace,
        required_commit_message=PROFILE.required_commit_message,
        completion_conditions=PROFILE.completion_conditions_text,
    )
    mission_block = prompt.split("Immutable mission:\n", 1)[1].split("\n\nCurrent gate objective:", 1)[0]
    completion_block = prompt.split("Required completion conditions:\n", 1)[1]
    for path in MATERIAL_PATHS:
        assert path in mission_block
        assert path in completion_block
    assert "test/event-replay.test.js" not in prompt
    assert "git log -1 --format=%B" in completion_block
    assert "%s" not in completion_block
    assert "no commit-message body" in completion_block
    assert "use no `--trailer`" in completion_block
    assert "sibling run roots" in mission_block and "evidence directories" in mission_block
    assert "sibling run roots" in completion_block and "evidence directories" in completion_block
    assert "Do not perform\nfurther exploration or changes after those checks." in completion_block


def test_fixture_has_exact_inventory_size_behavior_and_mission_absences(built_fixture):
    repository = built_fixture.first.repository
    assert _material_files(repository) == FIXTURE_FILES
    assert len(FIXTURE_FILES) == 22
    assert 850 <= _line_count(repository) <= 1_100
    assert not (repository / "src" / "execution").exists()
    assert not (repository / "src" / "storage" / "run-store.js").exists()
    combined = "\n".join(
        (repository / relative).read_text(encoding="utf-8") for relative in sorted(FIXTURE_FILES)
    )
    for symbol in FORBIDDEN_FIXTURE_SYMBOLS:
        assert symbol not in combined
    assert "createApp(storage, options = {})" in (repository / "README.md").read_text(encoding="utf-8")
    legacy = json.loads((repository / "test/fixtures/legacy-run-state-v0.json").read_text(encoding="utf-8"))
    assert legacy["schemaVersion"] == 0
    assert legacy["runs"][0]["runId"] == "legacy-run-001"
    assert legacy["runs"][0]["workflowId"] == "legacy-release"
    assert [task["status"] for task in legacy["runs"][0]["tasks"]] == ["completed", "running", "pending"]


def test_fixture_is_passing_clean_offline_and_deterministic(built_fixture):
    first, second = built_fixture.first, built_fixture.second
    assert built_fixture.npm.returncode == 0
    count = re.search(r"# tests (\d+)", built_fixture.npm.stdout)
    assert count and int(count.group(1)) >= 18
    assert first.initial_commit_message == WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE
    assert _command(["git", "rev-list", "--count", "HEAD"], cwd=first.repository).stdout.strip() == "1"
    assert _command(["git", "log", "-1", "--format=%B"], cwd=first.repository).stdout.rstrip("\r\n") == WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE
    assert _command(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=first.repository).stdout == ""
    assert _command(["git", "diff", "--cached", "--name-only"], cwd=first.repository).stdout == ""
    assert _command(["git", "remote"], cwd=first.repository).stdout.strip() == ""
    assert first.initial_material_tree_hash == fixture_material_tree_hash(first.repository)
    assert (second.initial_head, second.initial_material_tree_hash, second.initial_commit_message) == (
        first.initial_head,
        first.initial_material_tree_hash,
        first.initial_commit_message,
    )
    assert _command(["git", "rev-list", "--count", "HEAD"], cwd=second.repository).stdout.strip() == "1"


def test_real_embedded_verifier_rejects_the_untouched_fixture(built_fixture):
    script = built_fixture.root / "workflow-recovery-verifier.mjs"
    script.write_text(PROFILE.verifier_source, encoding="utf-8", newline="\n")
    completed = subprocess.run(
        ["node", "--preserve-symlinks", "--preserve-symlinks-main", str(script), str(built_fixture.first.repository)],
        cwd=built_fixture.root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=PROFILE.verifier_timeout_seconds,
    )
    assert completed.returncode != 0
    assert "src/execution/engine.js" in completed.stderr.replace("\\", "/")


def _payload_harness(tmp_path: Path, profile: NativeMissionProfile = PROFILE) -> SimpleNamespace:
    source_parent = tmp_path / "source-parent"
    source_parent.mkdir()
    source = build_canary_repository(source_parent, repository_name="source").repository
    fixture_parent = tmp_path / "fixture-parent"
    fixture_parent.mkdir()
    fixture = build_workflow_console_repository(fixture_parent, repository_name="work")
    config, attestor = _injected_test_cursor(tmp_path)
    attestation = attestor(config)
    identity = _observe_built_fixture(fixture, profile)
    run_root = tmp_path / profile.run_id
    payload = build_profile_authorization_payload(
        source_repository=source,
        source_head=_source_head(source),
        attestation=attestation,
        run_root=run_root,
        profile=profile,
        initialized_workspace=identity,
    )
    return SimpleNamespace(
        source=source,
        fixture=fixture,
        config=config,
        attestor=attestor,
        attestation=attestation,
        identity=identity,
        run_root=run_root,
        payload=payload,
    )


def test_v4_payload_embeds_complete_profile_and_substitution_changes_identity(tmp_path: Path):
    harness = _payload_harness(tmp_path)
    payload = harness.payload
    assert payload.schema_version == AUTHORIZATION_SCHEMA_VERSION_V4
    assert payload.mission_profile == PROFILE
    assert payload.run_id == payload.session_id == PROFILE.run_id
    assert payload.initialized_workspace.initial_git_head == harness.fixture.initial_head
    parsed = type(payload).from_dict(json.loads(json.dumps(payload.to_dict())))
    assert parsed == payload

    substituted = _profile_variant(mission_text=PROFILE.mission_text + "\nUnauthorized substitution.")
    substituted_payload = build_profile_authorization_payload(
        source_repository=harness.source,
        source_head=_source_head(harness.source),
        attestation=harness.attestation,
        run_root=harness.run_root,
        profile=substituted,
        initialized_workspace=harness.identity,
    )
    assert substituted.profile_fingerprint != PROFILE.profile_fingerprint
    assert substituted_payload.payload_fingerprint != payload.payload_fingerprint


def _materialize_protocol_only_placeholder(repository: Path) -> None:
    """Satisfy Git/material eligibility without implementing mission behavior."""

    (repository / "README.md").write_text(
        (repository / "README.md").read_text(encoding="utf-8")
        + "\nSynthetic protocol placeholder; this is not correctness evidence.\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "index.html").write_text(
        (repository / "index.html").read_text(encoding="utf-8")
        + "\n<!-- synthetic protocol placeholder only -->\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "src/app.js").write_text(
        (repository / "src/app.js").read_text(encoding="utf-8")
        + "\n// Synthetic protocol placeholder only.\n",
        encoding="utf-8",
        newline="\n",
    )
    execution = repository / "src" / "execution"
    execution.mkdir()
    (execution / "engine.js").write_text(
        "export function createWorkflowEngine() { throw new Error('synthetic protocol placeholder'); }\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "src/storage/run-store.js").write_text(
        "export function createRunStore() { throw new Error('synthetic protocol placeholder'); }\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "src/ui/render.js").write_text(
        (repository / "src/ui/render.js").read_text(encoding="utf-8")
        + "\n// Synthetic protocol placeholder only.\n",
        encoding="utf-8",
        newline="\n",
    )
    _commit(repository, PROFILE.required_commit_message)


def _publish_synthetic_behavioral_success(
    *,
    request,
    execution_store,
    timeout_seconds,
    output_limit,
    verifier_source,
) -> BehavioralVerifierEvidence:
    """Publish explicit fake success while preserving real evidence bindings."""

    assert timeout_seconds == PROFILE.verifier_timeout_seconds
    assert output_limit == PROFILE.verifier_output_limit_bytes
    assert verifier_source == PROFILE.verifier_source
    prefix = f"{request.session_id}.{request.gate_id}.attempt-0.behavioral"
    script = execution_store.write_behavioral_artifact(
        request=request,
        artifact_id=f"{prefix}.script",
        purpose="behavioral-script",
        data=verifier_source.encode("utf-8"),
    )
    stdout = execution_store.write_behavioral_artifact(
        request=request,
        artifact_id=f"{prefix}.stdout",
        purpose="behavioral-stdout",
        data=b"synthetic protocol-only behavioral success\n",
    )
    stderr = execution_store.write_behavioral_artifact(
        request=request,
        artifact_id=f"{prefix}.stderr",
        purpose="behavioral-stderr",
        data=b"",
    )
    provisional = BehavioralVerifierEvidence(
        schema_version=BEHAVIORAL_EVIDENCE_SCHEMA_VERSION,
        session_id=request.session_id,
        gate_id=request.gate_id,
        execution_attempt_index=0,
        request_fingerprint=request.request_fingerprint,
        work_workspace=request.work_workspace,
        workspace_identity=NativeFilesystemIdentity.from_stat(os.lstat(request.work_workspace)),
        argv=("synthetic-protocol-only",),
        exit_code=0,
        timed_out=False,
        script=script,
        stdout=stdout,
        stderr=stderr,
        evidence_fingerprint="0" * 64,
    )
    evidence = BehavioralVerifierEvidence(
        **{**provisional.__dict__, "evidence_fingerprint": fingerprint(provisional._body())}
    ).validated()
    return execution_store.create_behavioral_evidence(
        request=request,
        evidence=evidence,
        loader=BehavioralVerifierEvidence.from_dict,
    )


@pytest.fixture(scope="module")
def synthetic_protocol(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One protocol-only synthetic success; never workflow correctness proof."""

    tmp = tmp_path_factory.mktemp("workflow-protocol")
    source_parent = tmp / "source-parent"
    source_parent.mkdir()
    source = build_canary_repository(source_parent, repository_name="source").repository
    root = tmp / PROFILE.run_id
    root.mkdir()
    fixture = build_workflow_console_repository(root, repository_name="work")
    evidence = root / "evidence"
    evidence.mkdir()
    config, attestor = _injected_test_cursor(tmp)
    attestation = attestor(config)
    identity = _observe_built_fixture(fixture, PROFILE)
    payload = build_profile_authorization_payload(
        source_repository=source,
        source_head=_source_head(source),
        attestation=attestation,
        run_root=root,
        profile=PROFILE,
        initialized_workspace=identity,
    )
    _write_run_metadata_once(
        evidence / RUN_PREFLIGHT_METADATA_FILE_NAME,
        {
            "classification": CANARY_CLASSIFICATION,
            "authorization_payload": payload.to_dict(),
            "attestation": attestation.to_dict(),
            "local_capability_status": "PREFLIGHT_READY",
            "durability_capability": {"ready": True},
        },
    )
    execution_store = AtomicNativeExecutionStore(evidence / "native-execution")
    session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
    session_store.create(create_canary_session(session_id=PROFILE.session_id, profile=PROFILE))
    runner = FakeNativeProcessRunner(mutation=_materialize_protocol_only_placeholder)
    executor = NativeDelegatedExecutor(
        config=config,
        process_runner=runner,
        clock=Clock(),
        local_attestor=attestor,
    )
    coordinator = NativeCanaryCoordinator(
        session_store=session_store,
        execution_store=execution_store,
        executor=executor,
        backend_attestation=attestation,
        source_repository=source,
        work_workspace=fixture.repository,
        canary_parent=root,
        evidence_directory=evidence,
        timeout_seconds=PROFILE.timeout_seconds,
        stdout_byte_limit=PROFILE.stdout_byte_limit,
        stderr_byte_limit=PROFILE.stderr_byte_limit,
        profile=PROFILE,
    )
    with mock.patch.object(
        nc,
        "run_behavioral_verifier",
        side_effect=_publish_synthetic_behavioral_success,
    ):
        outcome = coordinator.run(session_id=PROFILE.session_id)
    return SimpleNamespace(
        tmp=tmp,
        root=root,
        source=source,
        work=fixture.repository,
        evidence=evidence,
        payload=payload,
        execution_store=execution_store,
        session_store=session_store,
        runner=runner,
        outcome=outcome,
    )


def test_synthetic_protocol_success_keeps_real_eligibility_and_lifecycle_only(synthetic_protocol):
    """Protocol wiring succeeds; the placeholder proves no workflow claim."""

    outcome = synthetic_protocol.outcome
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert outcome.canary_success
    assert (
        outcome.provider_invocations,
        outcome.native_attempts_reserved,
        outcome.native_processes_started,
        outcome.native_processes_completed,
        outcome.process_observations_published,
        outcome.accepted_native_results_published,
    ) == (1, 1, 1, 1, 1, 1)
    result = synthetic_protocol.execution_store.load_result(PROFILE.session_id, PROFILE.gate_id, 0)
    assert result.commits_added == 1
    assert result.final_commit_message == PROFILE.required_commit_message
    assert result.final_git_porcelain_status == ""
    assert result.final_git_remotes == ()
    assert set(MATERIAL_PATHS).issubset(result.changed_material_files)
    assert "synthetic protocol placeholder" in (
        synthetic_protocol.work / "src/execution/engine.js"
    ).read_text(encoding="utf-8")
    state = synthetic_protocol.session_store.load(PROFILE.session_id)
    assert state.phase is Phase.CHECKPOINT_CAPTURED
    assert state.checkpoint_history[-1].evidence_kinds == frozenset(
        {nc.EvidenceKind.TARGET_TREE, nc.EvidenceKind.GIT_STATE, nc.EvidenceKind.VERIFICATION_COMMAND}
    )


def test_evidence_only_reconstruction_uses_persisted_v4_profile_without_registry(synthetic_protocol):
    def trap(*_args, **_kwargs):
        raise AssertionError("evidence-only reconstruction consulted a current registry")

    with mock.patch.object(nc, "registered_profiles", trap), mock.patch.object(nc, "legacy_canary_profile", trap):
        outcome = reconstruct_completed_canary_success(
            session_store=synthetic_protocol.session_store,
            execution_store=synthetic_protocol.execution_store,
            evidence_directory=synthetic_protocol.evidence,
            session_id=PROFILE.session_id,
        )
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert outcome.canary_success


def test_tampered_persisted_profile_and_payload_fail_closed(synthetic_protocol):
    metadata = synthetic_protocol.evidence / RUN_PREFLIGHT_METADATA_FILE_NAME
    original = metadata.read_bytes()
    try:
        parsed = json.loads(original.decode("utf-8"))
        parsed["authorization_payload"]["mission_profile"]["mission_text"] += "\nTampered."
        metadata.write_bytes(canonical_bytes(parsed) + b"\n")
        with pytest.raises(NativeEvidenceInvalid, match="persisted v4 authorization payload is invalid"):
            reconstruct_completed_canary_success(
                session_store=synthetic_protocol.session_store,
                execution_store=synthetic_protocol.execution_store,
                evidence_directory=synthetic_protocol.evidence,
                session_id=PROFILE.session_id,
            )

        profile_data = parsed["authorization_payload"]["mission_profile"]
        profile_body = {key: value for key, value in profile_data.items() if key != "profile_fingerprint"}
        profile_data["profile_fingerprint"] = fingerprint(profile_body)
        payload_data = parsed["authorization_payload"]
        payload_body = {key: value for key, value in payload_data.items() if key != "payload_fingerprint"}
        payload_data["payload_fingerprint"] = fingerprint(payload_body)
        metadata.write_bytes(canonical_bytes(parsed) + b"\n")
        with pytest.raises(NativeEvidenceInvalid):
            reconstruct_completed_canary_success(
                session_store=synthetic_protocol.session_store,
                execution_store=synthetic_protocol.execution_store,
                evidence_directory=synthetic_protocol.evidence,
                session_id=PROFILE.session_id,
            )
    finally:
        metadata.write_bytes(original)

    assert reconstruct_completed_canary_success(
        session_store=synthetic_protocol.session_store,
        execution_store=synthetic_protocol.execution_store,
        evidence_directory=synthetic_protocol.evidence,
        session_id=PROFILE.session_id,
    ).canary_success
