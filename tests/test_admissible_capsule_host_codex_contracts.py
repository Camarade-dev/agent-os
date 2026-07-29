"""Provider-free host-control, protocol, and durable-pairing contract tests.

No Codex binary, model, provider, network request, or Docker container is
started in this module. Authentication fixtures are synthetic placeholders.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from admissible.capsule.backend import CapsuleAuthority, CapsuleBackend
from admissible.capsule.common import fingerprint
from admissible.capsule.docker_controller import (
    ALLOWED_DYNAMIC_TOOLS,
    CapsuleExecutionAuthority,
    DockerCapsuleLimits,
    DurableControllerAuthority,
)
from admissible.capsule.host_codex_backend import (
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    HostCodexAppServerCapsuleBackend,
    dynamic_tools_grammar,
    initialize_request,
    thread_start_request,
)
from admissible.capsule.host_control import (
    AuthenticatedControlAuthority,
    HostControlBwrapPolicy,
    assert_no_forbidden_launch_source,
)
from admissible.capsule.intake import (
    AcceptedMaterialIdentity,
    IntakeEvidence,
    IntakeFileRecord,
    IntakePublicationState,
)
from admissible.capsule.models import (
    ByteTreeObservation,
    CleanupResult,
    ObservedEntry,
    ProcessResult,
    ProviderCompletionClaim,
    ProviderOutput,
    TransportResult,
    WorkspaceReference,
)
from admissible.capsule.session_store import (
    DurableCapsuleSessionStore,
    DurableToolResult,
    SessionTerminalClassification,
    ToolIdDisposition,
    ToolTerminalClassification,
)


def _synthetic_policy(tmp_path: Path) -> HostControlBwrapPolicy:
    runtime = tmp_path / "synthetic-runtime"
    authentication = tmp_path / "synthetic-auth.json"
    configuration = tmp_path / "synthetic-config.toml"
    runtime.write_bytes(b"synthetic app-server executable placeholder\n")
    runtime.chmod(0o700)
    authentication.write_text('{"synthetic":"not-a-real-login"}\n', encoding="utf-8")
    configuration.write_text("synthetic = true\n", encoding="utf-8")
    return HostControlBwrapPolicy(
        bwrap_executable=Path("/usr/bin/bwrap"),
        codex_executable=runtime,
        authentication_file=authentication,
        configuration_file=configuration,
        certificate_bundle=None,
        resolver_file=None,
        hosts_file=None,
        forbidden_host_roots=(
            tmp_path / "provider-workspace",
            tmp_path / "agent-os",
            tmp_path / "historical-runs",
            tmp_path / "external-spike",
            tmp_path / "intake",
            tmp_path / "verifier",
            tmp_path / "finalizer",
        ),
    ).validated()


def _store(tmp_path: Path, session_id: str = "session-001") -> DurableCapsuleSessionStore:
    store = DurableCapsuleSessionStore(tmp_path / "session-store")
    store.create_session(
        session_id=session_id,
        authority_identity={"capsule": "synthetic", "control": "synthetic"},
        controller_authority={"controller": "durable-pairing-v1"},
        workspace={"workspace_id": "workspace-001", "host_owned": False},
    )
    store.record_capsule_process(
        session_id,
        {"kind": "synthetic_capsule", "process_id": "capsule-process-001"},
    )
    store.record_app_server_process(
        session_id,
        {"kind": "synthetic_app_server", "process_id": "app-server-process-001"},
    )
    store.bind_protocol(session_id, thread_id="thread-001", turn_id="turn-001")
    return store


def _request(
    store: DurableCapsuleSessionStore,
    *,
    session_id: str = "session-001",
    rpc_id: int = 60,
    call_id: str = "call-001",
    arguments=None,
):
    return store.make_tool_request(
        session_id,
        rpc_id=rpc_id,
        call_id=call_id,
        thread_id="thread-001",
        turn_id="turn-001",
        namespace="capsule_effects",
        tool="write_file",
        arguments=arguments
        or {"path": "index.html", "content": "<html></html>\n", "operation": "create"},
    )


def _accepted_material(content_hash: str = "1" * 64) -> AcceptedMaterialIdentity:
    record = IntakeFileRecord(
        relative_path="index.html",
        size=12,
        sha256=content_hash,
        git_mode="100644",
    ).validated()
    evidence = IntakeEvidence.create(
        authority_fingerprint="a" * 64,
        ruling="ACCEPTED",
        rejection_reasons=(),
        files=(record,),
        aggregate_fingerprint=fingerprint([record.to_dict()]),
        publication_state=IntakePublicationState.ACCEPTED_INTAKE_PUBLISHED,
    )
    return AcceptedMaterialIdentity.from_intake_evidence(evidence)


def _freeze_terminal_provider_output(store: DurableCapsuleSessionStore) -> None:
    authority_fingerprint = "b" * 64
    workspace = WorkspaceReference.create(
        workspace_id="workspace-001",
        capsule_authority_fingerprint=authority_fingerprint,
        host_owned=False,
    )
    output = ProviderOutput.create(
        capsule_authority_fingerprint=authority_fingerprint,
        workspace=workspace,
        observation=ByteTreeObservation.create(
            entries=(
                ObservedEntry(
                    relative_path="index.html",
                    kind="regular",
                    size=12,
                    sha256="1" * 64,
                ),
            )
        ),
        process_result=ProcessResult(
            schema_version="admissible_capsule_process_result_v1",
            exit_code=0,
            timed_out=False,
            signal=None,
        ),
        transport_result=TransportResult(
            schema_version="admissible_capsule_transport_result_v1",
            transport_kind="synthetic_transport_v1",
            connected=True,
            closed_cleanly=True,
        ),
        cleanup_result=CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1",
            workspace_removed=True,
            processes_reaped=True,
        ),
        completion_claim=ProviderCompletionClaim(
            schema_version="admissible_capsule_provider_completion_claim_v1",
            claimed_complete=True,
            claim_text="synthetic completion",
        ),
    )
    store.freeze_provider_output("session-001", output)
    store.record_terminal(
        "session-001",
        SessionTerminalClassification.COMPLETED,
        "synthetic terminal evidence",
    )


def test_concrete_backend_implements_the_existing_generic_contract():
    assert issubclass(HostCodexAppServerCapsuleBackend, CapsuleBackend)
    assert HostCodexAppServerCapsuleBackend.__abstractmethods__ == frozenset()
    assert CapsuleBackend.__abstractmethods__ >= {"authority", "prepare_workspace", "run", "cleanup"}


def test_control_authority_and_capsule_execution_authority_are_distinct(tmp_path: Path):
    policy = _synthetic_policy(tmp_path)
    control = AuthenticatedControlAuthority.create(
        codex_protocol_version=CODEX_APP_SERVER_PROTOCOL_VERSION,
        executable_identity="synthetic-codex-0.145.0",
        policy_fingerprint=policy.policy_fingerprint,
    )
    execution = CapsuleExecutionAuthority.create(
        DockerCapsuleLimits(image_identity="sha256:" + "a" * 64)
    )
    controller = DurableControllerAuthority.create(execution)
    assert control.authority_fingerprint != execution.authority_fingerprint
    assert controller.execution_authority_fingerprint == execution.authority_fingerprint
    assert set(controller.dynamic_tools) == set(ALLOWED_DYNAMIC_TOOLS)


def test_bwrap_policy_has_an_empty_explicit_view_and_no_workspace_or_socket(tmp_path: Path):
    policy = _synthetic_policy(tmp_path)
    argv = policy.build_argv()
    rendered = "\n".join(argv)
    assert "--unshare-all" in argv
    assert "--share-net" in argv
    assert "--clearenv" in argv
    assert "--ro-bind" in argv
    assert "--bind" not in argv
    assert "/runtime/codex" in argv
    assert "/control/codex-home/auth.json" in argv
    assert "/control/codex-home/config.toml" in argv
    assert "/control/empty" in argv
    assert "/bin" not in argv
    assert "/usr/bin" not in policy.visible_destinations
    assert "docker.sock" not in rendered
    for forbidden in policy.forbidden_host_roots:
        assert str(forbidden) not in rendered
    assert_no_forbidden_launch_source(argv, policy.forbidden_host_roots)
    evidence = policy.evidence()
    assert evidence["host_root_visible"] is False
    assert evidence["host_shell_visible"] is False
    assert evidence["workspace_visible"] is False
    assert evidence["docker_socket_visible"] is False


def test_policy_identity_does_not_read_or_hash_synthetic_authentication_contents(tmp_path: Path):
    policy = _synthetic_policy(tmp_path)
    first = policy.policy_fingerprint
    # The test owns this explicitly synthetic placeholder. Changing only its
    # bytes must not change policy identity because production auth bytes are
    # never inspected or hashed by the policy.
    policy.authentication_file.write_text("different synthetic placeholder\n", encoding="utf-8")
    second = policy.policy_fingerprint
    assert second == first
    assert json.dumps(policy.evidence()).find("different synthetic") == -1


def test_actual_bwrap_synthetic_control_process_cannot_see_workspace_shell_or_socket(
    tmp_path: Path,
):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("static synthetic bwrap witness requires gcc")
    forbidden_workspace = tmp_path / "provider-workspace"
    forbidden_workspace.mkdir()
    (forbidden_workspace / "secret.txt").write_text("not visible to control\n", encoding="utf-8")
    executable = tmp_path / "synthetic-control"
    source = f"""
    #include <stdio.h>
    #include <unistd.h>
    int main(void) {{
      int ok = 1;
      ok &= access("/control/codex-home/auth.json", F_OK) == 0;
      ok &= access("/control/empty", F_OK) == 0;
      ok &= access("/workspace", F_OK) != 0;
      ok &= access("{forbidden_workspace}/secret.txt", F_OK) != 0;
      ok &= access("/bin/sh", F_OK) != 0;
      ok &= access("/var/run/docker.sock", F_OK) != 0;
      puts(ok ? "SYNTHETIC_CONTROL_CONFINEMENT_PASS" : "SYNTHETIC_CONTROL_CONFINEMENT_FAIL");
      return ok ? 0 : 1;
    }}
    """
    compiled = subprocess.run(
        (compiler, "-static", "-x", "c", "-o", executable, "-"),
        input=source,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if compiled.returncode != 0:
        pytest.skip(f"static toolchain unavailable: {compiled.stderr[:200]}")
    authentication = tmp_path / "synthetic-auth.json"
    authentication.write_text('{"placeholder":"synthetic-only"}\n', encoding="utf-8")
    policy = HostControlBwrapPolicy(
        bwrap_executable=Path("/usr/bin/bwrap"),
        codex_executable=executable,
        authentication_file=authentication,
        configuration_file=None,
        certificate_bundle=None,
        resolver_file=None,
        hosts_file=None,
        forbidden_host_roots=(forbidden_workspace,),
    ).validated()
    completed = subprocess.run(
        policy.build_argv(("synthetic-app-server",)),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "SYNTHETIC_CONTROL_CONFINEMENT_PASS\n"


def test_pinned_initialize_and_dynamic_tools_wire_shape_is_closed():
    initialize = initialize_request("init-001")
    assert initialize == {
        "method": "initialize",
        "id": "init-001",
        "params": {
            "clientInfo": {
                "name": "admissible_host_capsule",
                "title": "Admissible Host Capsule Controller",
                "version": "1.0.0",
            },
            "capabilities": {"experimentalApi": True},
        },
    }
    request = thread_start_request("thread-request-001")
    assert request["method"] == "thread/start"
    assert request["params"]["cwd"] == "/control/empty"
    assert request["params"]["approvalPolicy"] == "never"
    assert request["params"]["sandbox"] == "readOnly"
    assert request["params"]["dynamicTools"] == dynamic_tools_grammar()
    namespace = request["params"]["dynamicTools"][0]
    assert namespace["type"] == "namespace"
    assert namespace["name"] == "capsule_effects"
    assert {tool["name"] for tool in namespace["tools"]} == set(ALLOWED_DYNAMIC_TOOLS)
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in namespace["tools"])
    encoded = json.dumps(request, sort_keys=True)
    assert "docker.sock" not in encoded
    assert "provider-workspace" not in encoded


def test_tool_request_is_durable_before_exactly_one_paired_result(tmp_path: Path):
    store = _store(tmp_path)
    request = _request(store)
    store.record_tool_request(request)
    reconstructed = store.reconstruct("session-001")
    assert reconstructed.unpaired_requests == (request,)
    assert (
        reconstructed.effective_terminal_classification
        == SessionTerminalClassification.CRASH_UNPAIRED_REQUEST
    )

    result = DurableToolResult.create(
        request=request,
        classification=ToolTerminalClassification.SUCCEEDED,
        exit_code=0,
        timed_out=False,
        stdout="",
        stderr="",
    )
    store.record_tool_result(result)
    reconstructed = store.reconstruct("session-001")
    assert reconstructed.unpaired_requests == ()
    assert reconstructed.results == (result,)
    with pytest.raises(ValueError, match="exactly one result"):
        store.record_tool_result(result)


def test_duplicate_and_conflicting_ids_are_distinguished_without_reexecution(tmp_path: Path):
    store = _store(tmp_path)
    original = _request(store)
    store.record_tool_request(original)
    store.record_tool_result(
        DurableToolResult.create(
            request=original,
            classification=ToolTerminalClassification.SUCCEEDED,
            exit_code=0,
            timed_out=False,
            stdout="",
            stderr="",
        )
    )
    duplicate = _request(store)
    disposition, existing = store.tool_id_disposition("session-001", duplicate)
    assert disposition == ToolIdDisposition.DUPLICATE
    assert existing == original

    conflict = _request(
        store,
        arguments={"path": "other.txt", "content": "different", "operation": "create"},
    )
    disposition, existing = store.tool_id_disposition("session-001", conflict)
    assert disposition == ToolIdDisposition.CONFLICT
    assert existing == original
    assert len(store.reconstruct("session-001").requests) == 1


def test_hash_chain_tampering_is_refused(tmp_path: Path):
    store = _store(tmp_path)
    path = store.session_directory("session-001") / "evidence.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["payload"]["identity"]["process_id"] = "tampered"
    lines[1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        store.reconstruct("session-001")


def test_session_store_reconstructs_one_canonical_accepted_material_identity(tmp_path: Path):
    store = _store(tmp_path)
    _freeze_terminal_provider_output(store)
    material = _accepted_material()
    store.record_accepted_material("session-001", material)
    reconstructed = store.reconstruct("session-001")
    assert reconstructed.accepted_material == material


def test_conflicting_replayed_accepted_material_events_fail_closed(tmp_path: Path):
    store = _store(tmp_path)
    _freeze_terminal_provider_output(store)
    first = _accepted_material()
    second = _accepted_material("2" * 64)
    store.record_accepted_material("session-001", first)
    store._append(  # adversarial valid hash-chain event, bypassing the guarded writer
        "session-001",
        "accepted_material_bound",
        {"accepted_material": second.to_dict()},
    )
    with pytest.raises(ValueError, match="duplicate accepted-material"):
        store.reconstruct("session-001")


def test_provider_output_contract_still_has_no_git_authority():
    from admissible.capsule.models import ProviderOutput

    fields = {field.name for field in dataclasses.fields(ProviderOutput)}
    assert not any("git" in field.lower() or "commit" in field.lower() for field in fields)


def test_capsule_authority_remains_provider_agnostic():
    authority = CapsuleAuthority.create(
        backend_kind="host_control_capsule_v1",
        capsule_image_identity="sha256:" + "a" * 64,
        mission_fingerprint="b" * 64,
    )
    assert authority.backend_kind == "host_control_capsule_v1"
