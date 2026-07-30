"""Provider-free rehearsal of the complete future owner-rooted launch order.

The rehearsal walks the exact order the real canary will use:

1. verify repository and preparation identity;
2. classify the local ChatGPT login from metadata only;
3. verify candidate witness evidence and the closed-world preflight seal;
4. request the owner phrase on its dedicated descriptor;
5. verify the exact canonical owner payload;
6. create the owner-bound witness receipt;
7. atomically consume the authorization once;
8. start the single target turn;
9. permit effects only after every model and receipt guard passes.

Everything outside the pinned Codex witness is synthetic: the app server is
scripted, the endpoint is loopback-only inside a routeless namespace, the owner
phrase is synthetic, and the authentication file is a synthetic fixture whose
bytes are never read.  This rehearsal never creates or consumes the future real
canary authorization.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from admissible.capsule.backend import CapsuleAuthority
from admissible.capsule.common import sha256_bytes
from admissible.capsule.docker_controller import (
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
    HostCodexAppServerCapsuleBackend,
    OwnerBoundWitnessAuthority,
    ScriptedCodexAppServerConnection,
    ScriptedCodexConnectionFactory,
)
from admissible.capsule.host_control import AuthenticatedControlAuthority
from admissible.capsule.intake import IntakeAuthority, validate_and_copy
from admissible.capsule.owner_authorization import (
    OwnerAuthorizationError,
    classify_local_chatgpt_login,
    revalidate_owner_bound_receipt,
)
from admissible.capsule.preflight_seal import (
    OWNER_AUTHORIZATION_CONSUMED,
    OWNER_BOUND_READY_FOR_SINGLE_LAUNCH,
    SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION,
    validate_future_preflight_seal,
)
from admissible.capsule.reducer import reduce
from admissible.capsule.session_store import (
    DurableCapsuleSessionStore,
    SessionTerminalClassification,
)
from admissible.capsule.state import Phase, new_session_state
from tests._candidate_canary_binding import (
    SYNTHETIC_MISSION_BYTES,
    authorize_synthetic_owner_binding,
    build_owner_payload,
    build_sealed_candidate_preparation,
    candidate_canary_binding,
    retain_synthetic_authorization,
)
from tests.test_admissible_capsule_host_codex_e2e import (
    PARENT_IDENTITY,
    THREAD_ID,
    TURN_ID,
    _behavior,
    _checkpoint,
    _dynamic_item,
    _protocol_prefix,
    _tool_call,
    _turn_completed,
)


REHEARSAL_MISSION_PROMPT = (
    "Create the single authorized synthetic witness file using capsule_effects only."
)
REHEARSAL_INTAKE_AUTHORITY = IntakeAuthority.create(
    authority_id="synthetic_owner_bound_rehearsal_v1",
    authority_paths=("index.html",),
    allowed_directories=(),
    per_file_bytes=4096,
    aggregate_bytes=4096,
    observed_entries=4,
)
WRITE_ARGUMENTS = {
    "path": "index.html",
    "content": "<html><body>owner-bound synthetic canary</body></html>\n",
    "operation": "create",
}


@pytest.fixture(scope="module")
def local_ubuntu_identity() -> str:
    result = subprocess.run(
        ("docker", "image", "inspect", "--format", "{{.Id}}", "ubuntu:24.04"),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if result.returncode != 0:
        pytest.skip(
            "the provider-free rehearsal requires the already-present ubuntu:24.04 image"
        )
    return result.stdout.strip()


def _one_write_events(session_id: str):
    """The single authorized write turn: one effect, then a terminal turn."""

    completed = _dynamic_item(
        "item/completed",
        "call-write",
        "write_file",
        WRITE_ARGUMENTS,
        "completed",
    )
    message = {
        "id": "agent-message-owner-bound",
        "type": "agentMessage",
        "text": "Synthetic claim of completion; downstream verification remains required.",
    }
    return [
        *_protocol_prefix(session_id),
        _dynamic_item(
            "item/started", "call-write", "write_file", WRITE_ARGUMENTS, "inProgress"
        ),
        _tool_call(70, "call-write", "write_file", WRITE_ARGUMENTS),
        completed,
        {
            "method": "item/started",
            "params": {
                "threadId": THREAD_ID,
                "turnId": TURN_ID,
                "startedAtMs": 1,
                "item": {**message, "text": ""},
            },
        },
        {
            "method": "item/completed",
            "params": {
                "threadId": THREAD_ID,
                "turnId": TURN_ID,
                "completedAtMs": 2,
                "item": message,
            },
        },
        _turn_completed([completed["params"]["item"], message]),
    ]


def _owner_bound_backend(
    tmp_path: Path,
    image_identity: str,
    prepared,
    owner_bound_receipt,
    authorization_state,
    *,
    label: str = "launch",
):
    limits = DockerCapsuleLimits(
        image_identity=image_identity,
        command_timeout_seconds=5.0,
        session_timeout_seconds=15.0,
        output_limit_bytes=64 * 1024,
    )
    controller = DockerCapsuleController(
        workspace_root=tmp_path / f"{label}-capsules",
        frozen_output_root=tmp_path / f"{label}-provider-output",
        limits=limits,
    )
    connection = ScriptedCodexAppServerConnection(())
    connection_factory = ScriptedCodexConnectionFactory(
        connection,
        codex_component_identity=prepared["identity"].to_dict(),
    )
    session_store = DurableCapsuleSessionStore(
        tmp_path / f"{label}-session-store",
        candidate_witness_store=prepared["store"],
    )
    capsule_authority = CapsuleAuthority.create(
        backend_kind="host_codex_app_server_capsule_v1",
        capsule_image_identity=image_identity,
        mission_fingerprint=sha256_bytes(SYNTHETIC_MISSION_BYTES),
    )
    control_authority = AuthenticatedControlAuthority.create(
        codex_protocol_version="0.145.0",
        executable_identity=connection_factory.codex_component_identity,
        policy_fingerprint=connection_factory.host_policy_fingerprint,
        authentication_boundary_state=(
            connection_factory.authentication_boundary_state
        ),
    )
    backend = HostCodexAppServerCapsuleBackend(
        authority=capsule_authority,
        control_authority=control_authority,
        controller=controller,
        session_store=session_store,
        connection_factory=connection_factory,
        mission_prompt=REHEARSAL_MISSION_PROMPT,
        mission_bytes=SYNTHETIC_MISSION_BYTES,
        witness_authority=OwnerBoundWitnessAuthority(
            owner_bound_receipt=owner_bound_receipt,
            authorization_state=authorization_state,
            preparation_root=prepared["preparation_root"],
            retained_seal_identity=prepared["retained_seal_identity"],
        ),
        event_timeout_seconds=2.0,
    )
    return backend, connection


def test_provider_free_rehearsal_of_the_complete_owner_rooted_order(
    tmp_path: Path, local_ubuntu_identity: str
):
    binding = candidate_canary_binding()

    # 1. repository and preparation identity, over real candidate evidence
    #    created by the real pinned Codex binary.
    prepared = build_sealed_candidate_preparation(
        tmp_path / "preparation-workspace", binding=binding
    )
    assert prepared["sealed"]["classification"] == (
        SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION
    )
    assert prepared["sealed"]["closed_world"] is True

    # 2. local ChatGPT login classification, metadata only.
    synthetic_auth = tmp_path / "synthetic-codex-home" / "auth.json"
    synthetic_auth.parent.mkdir(parents=True)
    synthetic_auth.write_text('{"synthetic": "provider-free"}', encoding="utf-8")
    synthetic_auth.chmod(0o600)
    login = classify_local_chatgpt_login(synthetic_auth)
    assert login["classification"] == "LOCAL_CHATGPT_LOGIN_PRESENT_METADATA_ONLY"
    assert login["credential_bytes_read"] == 0
    assert login["credential_content_observed"] is False

    # 3. candidate witness evidence and the externally retained seal.
    revalidated = validate_future_preflight_seal(
        root=prepared["preparation_root"],
        expected_model_binding_policy=prepared["policy"],
        expected_candidate_witness_receipt=prepared["receipt"],
        candidate_witness_store=prepared["store"],
        retained_seal_identity=prepared["retained_seal_identity"],
    )
    assert revalidated == prepared["sealed"]

    # 4-5. the owner phrase arrives on its dedicated descriptor and must verify
    #      the exact canonical payload.
    payload = build_owner_payload(prepared, mission_bytes=SYNTHETIC_MISSION_BYTES)
    state = retain_synthetic_authorization(
        prepared, payload, workspace=tmp_path / "preparation-workspace"
    )
    assert state.retained_state()["classification"] == (
        SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION
    )

    # 6. the owner-bound receipt.
    owner_bound = authorize_synthetic_owner_binding(prepared, payload, state)
    consumption = owner_bound.authorization_consumption_identity
    assert owner_bound.trust_state == "OWNER_BOUND_PRODUCTION_AUTHORITY"
    assert state.classification(consumption) == OWNER_BOUND_READY_FOR_SINGLE_LAUNCH

    # 7-9. the single launch: construction revalidates the binding, preparing the
    #      workspace consumes the authorization, and effects run only afterwards.
    backend, connection = _owner_bound_backend(
        tmp_path,
        local_ubuntu_identity,
        prepared,
        owner_bound,
        state,
    )
    assert backend.owner_binding_state == "OWNER_BOUND"
    assert backend.owner_bound_receipt_identity == owner_bound.receipt_identity
    assert state.classification(consumption) == OWNER_BOUND_READY_FOR_SINGLE_LAUNCH

    workspace = backend.prepare_workspace()
    assert state.classification(consumption) == OWNER_AUTHORIZATION_CONSUMED
    assert backend._authorization_consumption["consumed"] is True

    session_id = backend.reconstruct(workspace).session_id
    connection.queue_messages(_one_write_events(session_id))
    output = backend.run(workspace)

    snapshot = backend.reconstruct(workspace)
    assert snapshot.effective_terminal_classification == (
        SessionTerminalClassification.COMPLETED
    )
    frozen = backend.frozen_output_path(workspace)
    assert (frozen / "index.html").read_text() == WRITE_ARGUMENTS["content"]

    # The durable execution authority records the owner binding.
    authority = snapshot.authority_identity["backend_execution_authority"]
    assert authority["owner_binding_state"] == "OWNER_BOUND"
    assert authority["owner_bound_receipt_identity"] == owner_bound.receipt_identity
    assert authority["owner_payload_fingerprint"] == payload.payload_fingerprint
    assert (
        authority["owner_authorization_consumption_identity"] == consumption
    )

    # intake, both verifiers and finalization over the one accepted file.
    evidence = validate_and_copy(
        frozen,
        REHEARSAL_INTAKE_AUTHORITY,
        tmp_path / "accepted-by-intake",
        tmp_path / "intake-evidence.json",
    )
    assert evidence.ruling == "ACCEPTED"
    assert evidence.published is True

    run_state = new_session_state(
        session_id="synthetic-owner-bound-rehearsal",
        capsule_authority=backend.authority,
    )
    checkpoint = _checkpoint(output, evidence, passed=True)
    behavior = _behavior(evidence, passed=True)
    for event in (
        CapsuleExecutionStarted(),
        ProviderOutputFrozen(provider_output=output),
        IntakeStarted(),
        IntakeEvaluated(intake_evidence=evidence),
        CheckpointVerificationStarted(),
        CheckpointVerified(checkpoint_result=checkpoint),
        BehaviorVerified(behavior_result=behavior),
    ):
        run_state = reduce(run_state, event)
    assert run_state.phase == Phase.FINALIZATION_READY
    backend.bind_accepted_material(workspace, run_state.accepted_material)
    backend.record_checkpoint_verification(workspace, checkpoint)
    backend.record_behavior_verification(workspace, behavior)

    repository = tmp_path / "synthetic-owner-bound-finalizer.git"
    parent = initialize_disposable_repository(
        repository, parent_identity=PARENT_IDENTITY
    )
    finalizer = AdmissibleFinalizer(repository)
    blobs = tuple(
        AcceptedBlob.create(
            relative_path=record.relative_path,
            data=(
                tmp_path / "accepted-by-intake" / record.relative_path
            ).read_bytes(),
            git_mode=record.git_mode,
        )
        for record in evidence.files
    )
    prepared_finalization = finalizer.prepare(
        parent=parent,
        accepted_material=run_state.accepted_material,
        accepted_blobs=blobs,
        private_index=tmp_path / "synthetic-owner-bound-index",
        message="test: synthetic owner-bound provider-free rehearsal\n",
    )
    backend.record_finalization_prepared(
        workspace,
        prepared_finalization.evidence,
        prepared_finalization.durability_receipt,
    )
    run_state = reduce(
        run_state,
        FinalizationStarted(
            finalization_evidence=prepared_finalization.evidence,
            durability_receipt=prepared_finalization.durability_receipt,
        ),
    )
    result = finalizer.finalize(prepared=prepared_finalization)
    backend.record_finalization_result(workspace, result)
    assert result.outcome == FinalizationOutcome.PUBLISHED
    run_state = reduce(run_state, FinalizationCompleted(finalization_result=result))
    assert run_state.phase == Phase.ACCEPTED
    assert finalizer.verify(prepared=prepared_finalization)["ok"] is True

    # A second launch on the same authorization refuses at construction.
    with pytest.raises(OwnerAuthorizationError) as reuse:
        _owner_bound_backend(
            tmp_path,
            local_ubuntu_identity,
            prepared,
            owner_bound,
            state,
            label="second",
        )
    assert reuse.value.classification == "OWNER_AUTHORIZATION_ALREADY_CONSUMED"

    # And the gate now classifies the authorization as spent, which is the
    # classification a fresh backend refuses on.
    gate = revalidate_owner_bound_receipt(
        owner_bound_receipt=owner_bound,
        candidate_witness_store=prepared["store"],
        authorization_state=state,
        preparation_root=prepared["preparation_root"],
        retained_seal_identity=prepared["retained_seal_identity"],
        expected_model_binding_policy=prepared["policy"],
    )
    assert gate["classification"] == OWNER_AUTHORIZATION_CONSUMED
    backend.cleanup(workspace)
