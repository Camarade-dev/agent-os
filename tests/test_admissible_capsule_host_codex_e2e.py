"""Provider-free app-server-to-capsule integration and acceptance E2E.

Every app-server event is synthetic and pinned to Codex 0.145.0 shapes. The
only subprocess effects are local Docker/Git operations over disposable test
directories. No Codex binary, target model, provider/API request, login, real
mission run, remote, or push is reachable from this module.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from admissible.capsule.backend import CapsuleAuthority
from admissible.capsule.docker_controller import (
    ControllerCleanupEvidence,
    DockerCapsuleController,
    DockerCapsuleLimits,
)
from admissible.capsule.events import (
    BehaviorVerified,
    CapsuleExecutionStarted,
    CheckpointVerificationStarted,
    CheckpointVerified,
    FinalizationCompleted,
    FinalizationStarted,
    IntakeEvaluated,
    IntakeStarted,
    ProviderOutputFrozen,
)
from admissible.capsule.finalizer import (
    AcceptedBlob,
    AdmissibleFinalizer,
    FinalizationOutcome,
    initialize_disposable_repository,
)
from admissible.capsule.host_codex_backend import (
    AppServerReceiveTimeout,
    HostCodexAppServerCapsuleBackend,
    ScriptedCodexAppServerConnection,
    ScriptedCodexConnectionFactory,
)
from admissible.capsule.host_control import AuthenticatedControlAuthority
from admissible.capsule.intake import IntakeAuthority, validate_and_copy
from admissible.capsule.reducer import reduce
from admissible.capsule.session_store import (
    DurableCapsuleSessionStore,
    SessionTerminalClassification,
    ToolTerminalClassification,
)
from admissible.capsule.state import Phase, new_session_state
from admissible.capsule.verification import (
    BehavioralVerifierIdentity,
    BehaviorRefusalCode,
    BehaviorResult,
    ByteHashPair,
    CheckpointIdentity,
    CheckpointRefusalCode,
    CheckpointResult,
    CommandCapture,
    VerificationCopy,
)


THREAD_ID = "thread-synthetic-001"
TURN_ID = "turn-synthetic-001"
SYNTHETIC_INTAKE_AUTHORITY = IntakeAuthority.create(
    authority_id="synthetic_host_codex_witness_v1",
    authority_paths=("index.html", "shell.txt"),
    allowed_directories=(),
    per_file_bytes=4096,
    aggregate_bytes=8192,
    observed_entries=8,
)
PARENT_IDENTITY = {
    "author_name": "Synthetic Capsule Parent",
    "author_email": "synthetic-capsule@example.invalid",
    "author_date": "1999-12-31T00:00:00+00:00",
    "committer_name": "Synthetic Capsule Parent",
    "committer_email": "synthetic-capsule@example.invalid",
    "committer_date": "1999-12-31T00:00:00+00:00",
}
SYNTHETIC_FINALIZATION_MESSAGE = (
    "test: synthetic provider-free capsule acceptance (not Neon Relay)\n"
)


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("docker", *arguments),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


@pytest.fixture(scope="module")
def local_ubuntu_identity() -> str:
    result = _docker("image", "inspect", "--format", "{{.Id}}", "ubuntu:24.04")
    if result.returncode != 0:
        pytest.skip("provider-free Docker E2E requires the already-present ubuntu:24.04 image")
    return result.stdout.strip()


class _CleanupEvidenceRefusalController(DockerCapsuleController):
    """Perform real cleanup, then inject unconfirmed evidence for the boundary."""

    def cleanup(self, handle):
        actual = super().cleanup(handle)
        assert actual.cleanup_proven
        return ControllerCleanupEvidence(
            container_removed=False,
            complete_process_tree_reaped=True,
            disposable_workspace_removed=True,
            frozen_output_retained=actual.frozen_output_retained,
        )


def _backend(
    tmp_path: Path,
    image_identity: str,
    *,
    connection_returncode: int = 0,
    controller_type=DockerCapsuleController,
    output_limit: int = 64 * 1024,
    command_timeout: float = 2.0,
    event_timeout: float = 2.0,
):
    limits = DockerCapsuleLimits(
        image_identity=image_identity,
        command_timeout_seconds=command_timeout,
        session_timeout_seconds=max(10.0, command_timeout),
        output_limit_bytes=output_limit,
    )
    controller = controller_type(
        workspace_root=tmp_path / "disposable-capsules",
        frozen_output_root=tmp_path / "provider-output",
        limits=limits,
    )
    connection = ScriptedCodexAppServerConnection(
        (),
        returncode=connection_returncode,
    )
    store = DurableCapsuleSessionStore(tmp_path / "session-store")
    capsule_authority = CapsuleAuthority.create(
        backend_kind="host_codex_app_server_capsule_v1",
        capsule_image_identity=image_identity,
        mission_fingerprint="b" * 64,
    )
    control_authority = AuthenticatedControlAuthority.create(
        codex_protocol_version="0.145.0",
        executable_identity="synthetic-codex-app-server-0.145.0",
        policy_fingerprint="c" * 64,
    )
    backend = HostCodexAppServerCapsuleBackend(
        authority=capsule_authority,
        control_authority=control_authority,
        controller=controller,
        session_store=store,
        connection_factory=ScriptedCodexConnectionFactory(connection),
        mission_prompt="Create the two authorized synthetic witness files using capsule_effects only.",
        event_timeout_seconds=event_timeout,
    )
    workspace = backend.prepare_workspace()
    session_id = backend.reconstruct(workspace).session_id
    return backend, workspace, connection, session_id


def _protocol_prefix(session_id: str):
    return [
        {
            "id": f"init-{session_id}",
            "result": {
                "serverInfo": {
                    "name": "synthetic-codex-app-server",
                    "version": "0.145.0",
                }
            },
        },
        {
            "id": f"thread-{session_id}",
            "result": {
                "thread": {
                    "id": THREAD_ID,
                    "modelProvider": "synthetic-provider-free",
                }
            },
        },
        {
            "id": f"turn-{session_id}",
            "result": {
                "turn": {
                    "id": TURN_ID,
                    "status": "inProgress",
                    "items": [],
                }
            },
        },
        {
            "method": "turn/started",
            "params": {
                "turn": {
                    "id": TURN_ID,
                    "status": "inProgress",
                    "items": [],
                }
            },
        },
    ]


def _tool_call(rpc_id: int, call_id: str, tool: str, arguments):
    return {
        "method": "item/tool/call",
        "id": rpc_id,
        "params": {
            "threadId": THREAD_ID,
            "turnId": TURN_ID,
            "callId": call_id,
            "namespace": "capsule_effects",
            "tool": tool,
            "arguments": arguments,
        },
    }


def _dynamic_item(method: str, call_id: str, tool: str, arguments, status: str):
    return {
        "method": method,
        "params": {
            "threadId": THREAD_ID,
            "turnId": TURN_ID,
            "item": {
                "id": call_id,
                "type": "dynamicToolCall",
                "tool": tool,
                "arguments": arguments,
                "status": status,
            },
        },
    }


def _turn_completed():
    return {
        "method": "turn/completed",
        "params": {
            "turn": {
                "id": TURN_ID,
                "status": "completed",
                "items": [],
            }
        },
    }


def _successful_events(session_id: str):
    write_arguments = {
        "path": "index.html",
        "content": "<html><body>synthetic capsule witness</body></html>\n",
        "operation": "create",
    }
    shell_arguments = {
        "argv": [
            "/bin/sh",
            "-c",
            (
                "test ! -e /control/codex-home/auth.json "
                "&& test ! -e /root/.codex/auth.json "
                "&& test -z \"${OPENAI_API_KEY:-}\" "
                "&& printf 'synthetic shell effect\\n' > shell.txt"
            ),
        ],
        "cwd": ".",
        "timeout_ms": 1500,
    }
    outside_arguments = {"path": "../outside.txt"}
    return [
        *_protocol_prefix(session_id),
        _dynamic_item("item/started", "call-write", "write_file", write_arguments, "inProgress"),
        _tool_call(60, "call-write", "write_file", write_arguments),
        _dynamic_item("item/completed", "call-write", "write_file", write_arguments, "completed"),
        _dynamic_item("item/started", "call-shell", "run_command", shell_arguments, "inProgress"),
        _tool_call(61, "call-shell", "run_command", shell_arguments),
        _dynamic_item("item/completed", "call-shell", "run_command", shell_arguments, "completed"),
        _dynamic_item("item/started", "call-outside", "read_file", outside_arguments, "inProgress"),
        _tool_call(62, "call-outside", "read_file", outside_arguments),
        _dynamic_item("item/completed", "call-outside", "read_file", outside_arguments, "failed"),
        {
            "method": "item/completed",
            "params": {
                "threadId": THREAD_ID,
                "turnId": TURN_ID,
                "item": {
                    "id": "agent-message-001",
                    "type": "agentMessage",
                    "text": "Synthetic provider claims completion; downstream verification remains required.",
                },
            },
        },
        _turn_completed(),
    ]


def _run_success(tmp_path: Path, image_identity: str):
    backend, workspace, connection, session_id = _backend(tmp_path, image_identity)
    connection.queue_messages(_successful_events(session_id))
    output = backend.run(workspace)
    return backend, workspace, connection, session_id, output


def _capture(*, exit_code=0, timed_out=False, truncated=False) -> CommandCapture:
    return CommandCapture.create(
        argv=("./synthetic-verify.sh",),
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        stdout_truncated=truncated,
        stderr_truncated=False,
    )


def _checkpoint(output, evidence, *, passed: bool) -> CheckpointResult:
    return CheckpointResult(
        identity=CheckpointIdentity.create(tree_hash=output.observation.tree_hash),
        copy=VerificationCopy.create(
            copy_id="synthetic-checkpoint-copy",
            purpose="checkpoint",
            root_fingerprint=evidence.aggregate_fingerprint,
        ),
        capture=_capture(exit_code=0 if passed else 1),
        byte_hashes=ByteHashPair(
            before_hash=evidence.aggregate_fingerprint,
            after_hash=evidence.aggregate_fingerprint,
        ).validated(),
        passed=passed,
        refusal_code=None if passed else CheckpointRefusalCode.NONZERO_EXIT,
    ).validated()


def _behavior(evidence, *, passed: bool) -> BehaviorResult:
    return BehaviorResult(
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256="1" * 64),
        copy=VerificationCopy.create(
            copy_id="synthetic-behavior-copy",
            purpose="behavior",
            root_fingerprint=evidence.aggregate_fingerprint,
        ),
        capture=_capture(exit_code=0 if passed else 1),
        byte_hashes=ByteHashPair(
            before_hash=evidence.aggregate_fingerprint,
            after_hash=evidence.aggregate_fingerprint,
        ).validated(),
        passed=passed,
        refusal_code=None if passed else BehaviorRefusalCode.ASSERTION_FAILED,
    ).validated()


def _intake(tmp_path: Path, backend, workspace):
    evidence = validate_and_copy(
        backend.frozen_output_path(workspace),
        SYNTHETIC_INTAKE_AUTHORITY,
        tmp_path / "accepted-by-intake",
        tmp_path / "intake-evidence.json",
    )
    assert evidence.ruling == "ACCEPTED"
    assert evidence.published is True
    return evidence


def test_successful_synthetic_app_server_witness_has_no_provider_git_authority(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id, output = _run_success(
        tmp_path, local_ubuntu_identity
    )
    snapshot = backend.reconstruct(workspace)
    assert snapshot.effective_terminal_classification == SessionTerminalClassification.COMPLETED
    assert len(snapshot.requests) == 3
    assert [result.classification for result in snapshot.results] == [
        ToolTerminalClassification.SUCCEEDED,
        ToolTerminalClassification.SUCCEEDED,
        ToolTerminalClassification.REFUSED,
    ]
    frozen = backend.frozen_output_path(workspace)
    assert (frozen / "index.html").read_text() == (
        "<html><body>synthetic capsule witness</body></html>\n"
    )
    assert (frozen / "shell.txt").read_text() == "synthetic shell effect\n"
    assert not (tmp_path / "outside.txt").exists()
    assert not (frozen / ".git").exists()
    assert output.cleanup_result.cleanup_proven is True
    assert output.completion_claim.claimed_complete is True
    assert not any(
        "git" in field or "commit" in field
        for field in output.to_dict()
    )
    sent = str(connection.sent)
    assert str(backend.controller.workspace_root) not in sent
    assert str(frozen) not in sent
    assert "/workspace" not in sent
    assert "/control/empty" in sent
    assert "OPENAI_API_KEY" not in sent
    assert snapshot.capsule_process_identity["container_id"]
    assert snapshot.app_server_process_identity["provider_request_capable"] is False
    assert snapshot.cleanup["container_removed"] is True
    assert snapshot.cleanup["complete_process_tree_reaped"] is True
    assert _docker("inspect", snapshot.capsule_process_identity["container_id"]).returncode != 0
    assert session_id in str(backend.session_store.session_directory(session_id))


def test_provider_process_failure_is_frozen_and_cleaned(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(
        tmp_path,
        local_ubuntu_identity,
        connection_returncode=17,
    )
    connection.queue_messages(_protocol_prefix(session_id))
    output = backend.run(workspace)
    snapshot = backend.reconstruct(workspace)
    assert (
        snapshot.effective_terminal_classification
        == SessionTerminalClassification.PROVIDER_PROCESS_FAILED
    )
    assert output.process_result.exit_code == 17
    assert output.transport_result.closed_cleanly is False
    assert output.cleanup_result.cleanup_proven is True


def test_app_server_protocol_failure_fails_closed(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(tmp_path, local_ubuntu_identity)
    connection.queue_messages(
        [
            *_protocol_prefix(session_id),
            {"method": "future/unknown", "params": {"effect": "maybe"}},
        ]
    )
    output = backend.run(workspace)
    assert (
        backend.reconstruct(workspace).effective_terminal_classification
        == SessionTerminalClassification.APP_SERVER_PROTOCOL_FAILED
    )
    assert output.transport_result.closed_cleanly is False
    assert output.cleanup_result.cleanup_proven is True


def test_capsule_failure_is_terminal_and_still_cleans_resources(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(tmp_path, local_ubuntu_identity)
    handle = backend.controller.get(workspace.workspace_id)
    assert _docker("kill", handle.container_id).returncode == 0
    arguments = {
        "path": "never-written.txt",
        "content": "must not be created",
        "operation": "create",
    }
    connection.queue_messages(
        [
            *_protocol_prefix(session_id),
            _tool_call(60, "call-dead-capsule", "write_file", arguments),
        ]
    )
    output = backend.run(workspace)
    assert (
        backend.reconstruct(workspace).effective_terminal_classification
        == SessionTerminalClassification.CAPSULE_FAILED
    )
    assert output.cleanup_result.cleanup_proven is True
    assert not (backend.frozen_output_path(workspace) / "never-written.txt").exists()


def test_cleanup_failure_overrides_an_otherwise_successful_turn(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(
        tmp_path,
        local_ubuntu_identity,
        controller_type=_CleanupEvidenceRefusalController,
    )
    connection.queue_messages([*_protocol_prefix(session_id), _turn_completed()])
    output = backend.run(workspace)
    assert (
        backend.reconstruct(workspace).effective_terminal_classification
        == SessionTerminalClassification.CLEANUP_FAILED
    )
    assert output.cleanup_result.cleanup_proven is False
    container_id = backend.reconstruct(workspace).capsule_process_identity["container_id"]
    assert _docker("inspect", container_id).returncode != 0


def test_app_server_timeout_is_terminal_and_cleanup_is_complete(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(tmp_path, local_ubuntu_identity)
    connection.queue_messages(
        [
            *_protocol_prefix(session_id),
            AppServerReceiveTimeout("synthetic app-server event timeout"),
        ]
    )
    output = backend.run(workspace)
    assert (
        backend.reconstruct(workspace).effective_terminal_classification
        == SessionTerminalClassification.TIMED_OUT
    )
    assert output.process_result.timed_out is True
    assert output.cleanup_result.cleanup_proven is True


def test_capsule_command_timeout_kills_the_complete_container_tree(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(
        tmp_path,
        local_ubuntu_identity,
        command_timeout=1,
    )
    arguments = {"argv": ["/bin/sleep", "5"], "cwd": ".", "timeout_ms": 50}
    connection.queue_messages(
        [*_protocol_prefix(session_id), _tool_call(60, "call-timeout", "run_command", arguments)]
    )
    output = backend.run(workspace)
    snapshot = backend.reconstruct(workspace)
    assert snapshot.effective_terminal_classification == SessionTerminalClassification.TIMED_OUT
    assert snapshot.results[0].classification == ToolTerminalClassification.TIMED_OUT
    assert output.process_result.timed_out is True
    assert snapshot.cleanup["complete_process_tree_reaped"] is True


def test_output_limit_refusal_kills_the_capsule_and_bounds_durable_result(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(
        tmp_path,
        local_ubuntu_identity,
        output_limit=4096,
    )
    arguments = {
        "argv": ["/bin/sh", "-c", "yes x | head -c 12000"],
        "cwd": ".",
        "timeout_ms": 1500,
    }
    connection.queue_messages(
        [*_protocol_prefix(session_id), _tool_call(60, "call-output", "run_command", arguments)]
    )
    output = backend.run(workspace)
    snapshot = backend.reconstruct(workspace)
    assert (
        snapshot.effective_terminal_classification
        == SessionTerminalClassification.OUTPUT_LIMIT_REFUSED
    )
    assert snapshot.results[0].classification == ToolTerminalClassification.OUTPUT_LIMIT_REFUSED
    assert len(snapshot.results[0].stdout.encode()) == 4096
    assert snapshot.results[0].stdout_truncated is True
    assert output.cleanup_result.cleanup_proven is True


def test_native_file_or_command_item_fails_the_session_closed(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, connection, session_id = _backend(tmp_path, local_ubuntu_identity)
    connection.queue_messages(
        [
            *_protocol_prefix(session_id),
            {
                "method": "item/started",
                "params": {
                    "threadId": THREAD_ID,
                    "turnId": TURN_ID,
                    "item": {
                        "id": "native-command-001",
                        "type": "commandExecution",
                        "command": "touch forbidden",
                        "cwd": "/control/empty",
                        "status": "inProgress",
                        "commandActions": [],
                    },
                },
            },
        ]
    )
    output = backend.run(workspace)
    assert (
        backend.reconstruct(workspace).effective_terminal_classification
        == SessionTerminalClassification.NATIVE_EFFECT_REFUSED
    )
    assert output.transport_result.closed_cleanly is False
    assert not (backend.frozen_output_path(workspace) / "forbidden").exists()


@pytest.mark.parametrize(
    "conflicting, expected",
    [
        (False, SessionTerminalClassification.DUPLICATE_TOOL_ID_REFUSED),
        (True, SessionTerminalClassification.CONFLICTING_TOOL_ID_REFUSED),
    ],
)
def test_duplicate_and_conflicting_tool_ids_refuse_without_a_second_effect(
    tmp_path: Path,
    local_ubuntu_identity: str,
    conflicting: bool,
    expected: SessionTerminalClassification,
):
    backend, workspace, connection, session_id = _backend(tmp_path, local_ubuntu_identity)
    first_arguments = {
        "path": "once.txt",
        "content": "executed once\n",
        "operation": "create",
    }
    repeated_arguments = (
        {"path": "other.txt", "content": "conflict\n", "operation": "create"}
        if conflicting
        else first_arguments
    )
    connection.queue_messages(
        [
            *_protocol_prefix(session_id),
            _tool_call(60, "call-replay", "write_file", first_arguments),
            _tool_call(60, "call-replay", "write_file", repeated_arguments),
        ]
    )
    backend.run(workspace)
    snapshot = backend.reconstruct(workspace)
    assert snapshot.effective_terminal_classification == expected
    assert len(snapshot.requests) == 1
    assert len(snapshot.results) == 1
    frozen = backend.frozen_output_path(workspace)
    assert (frozen / "once.txt").read_text() == "executed once\n"
    assert not (frozen / "other.txt").exists()


def test_evidence_only_reconstruction_recovers_frozen_provider_output(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, _connection, session_id, output = _run_success(
        tmp_path, local_ubuntu_identity
    )
    fresh_store = DurableCapsuleSessionStore(backend.session_store.root)
    reconstructed = fresh_store.reconstruct(session_id)
    assert reconstructed.provider_output == output
    assert reconstructed.effective_terminal_classification == SessionTerminalClassification.COMPLETED
    assert reconstructed.unpaired_requests == ()
    assert len(reconstructed.requests) == len(reconstructed.results) == 3


def test_successful_intake_followed_by_checkpoint_refusal(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, _connection, _session_id, output = _run_success(
        tmp_path, local_ubuntu_identity
    )
    evidence = _intake(tmp_path, backend, workspace)
    state = new_session_state(
        session_id="acceptance-session-checkpoint-refusal",
        capsule_authority=backend.authority,
    )
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(state, ProviderOutputFrozen(provider_output=output))
    state = reduce(state, IntakeStarted())
    state = reduce(state, IntakeEvaluated(intake_evidence=evidence))
    state = reduce(state, CheckpointVerificationStarted())
    state = reduce(state, CheckpointVerified(checkpoint_result=_checkpoint(output, evidence, passed=False)))
    assert state.phase == Phase.REFUSED
    assert state.behavior_result is None
    assert state.finalization_result is None


def test_checkpoint_pass_followed_by_synthetic_behavioral_refusal(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, _connection, _session_id, output = _run_success(
        tmp_path, local_ubuntu_identity
    )
    evidence = _intake(tmp_path, backend, workspace)
    state = new_session_state(
        session_id="acceptance-session-behavior-refusal",
        capsule_authority=backend.authority,
    )
    for event in (
        CapsuleExecutionStarted(),
        ProviderOutputFrozen(provider_output=output),
        IntakeStarted(),
        IntakeEvaluated(intake_evidence=evidence),
        CheckpointVerificationStarted(),
        CheckpointVerified(checkpoint_result=_checkpoint(output, evidence, passed=True)),
        BehaviorVerified(behavior_result=_behavior(evidence, passed=False)),
    ):
        state = reduce(state, event)
    assert state.phase == Phase.REFUSED
    assert state.checkpoint_result.passed is True
    assert state.behavior_result.passed is False
    assert state.finalization_result is None


def test_complete_provider_free_acceptance_uses_only_synthetic_verification_and_finalizer(
    tmp_path: Path, local_ubuntu_identity: str
):
    backend, workspace, _connection, _session_id, output = _run_success(
        tmp_path, local_ubuntu_identity
    )
    evidence = _intake(tmp_path, backend, workspace)
    state = new_session_state(
        session_id="synthetic-provider-free-finalization",
        capsule_authority=backend.authority,
    )
    for event in (
        CapsuleExecutionStarted(),
        ProviderOutputFrozen(provider_output=output),
        IntakeStarted(),
        IntakeEvaluated(intake_evidence=evidence),
        CheckpointVerificationStarted(),
        CheckpointVerified(checkpoint_result=_checkpoint(output, evidence, passed=True)),
        BehaviorVerified(behavior_result=_behavior(evidence, passed=True)),
    ):
        state = reduce(state, event)
    assert state.phase == Phase.FINALIZATION_READY

    repository = tmp_path / "synthetic-finalizer.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    finalizer = AdmissibleFinalizer(repository)
    state = reduce(state, FinalizationStarted())
    blobs = tuple(
        AcceptedBlob.create(
            relative_path=record.relative_path,
            data=(tmp_path / "accepted-by-intake" / record.relative_path).read_bytes(),
        )
        for record in evidence.files
    )
    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=blobs,
        private_index=tmp_path / "synthetic-private-index",
        message=SYNTHETIC_FINALIZATION_MESSAGE,
        evidence_is_durable=evidence.published and state.behavior_result.passed,
    )
    assert result.outcome == FinalizationOutcome.PUBLISHED
    state = reduce(state, FinalizationCompleted(finalization_result=result))
    assert state.phase == Phase.ACCEPTED
    proof = finalizer.verify(
        parent=parent,
        accepted_blobs=blobs,
        message=SYNTHETIC_FINALIZATION_MESSAGE,
    )
    assert proof["ok"] is True
    assert proof["remotes"] == []
    assert "synthetic provider-free" in proof["message"]
    assert "Neon Relay" in proof["message"]
    assert output.completion_claim.claimed_complete is True
    assert state.finalization_result == result
