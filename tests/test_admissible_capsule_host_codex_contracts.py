"""Provider-free host-control, protocol, and durable-pairing contract tests.

No Codex binary, model, provider, network request, or Docker container is
started in this module. Authentication fixtures are synthetic placeholders.
"""

from __future__ import annotations

import dataclasses
import errno
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

import admissible.capsule.host_codex_backend as host_backend_module
import admissible.capsule.session_store as session_store_module
from admissible.capsule.backend import CapsuleAuthority, CapsuleBackend
from admissible.capsule.codex_protocol import protocol_schema_identity, validate_schema
from admissible.capsule.common import fingerprint, sha256_bytes, strict_json_loads
from admissible.capsule.docker_controller import (
    ALLOWED_DYNAMIC_TOOLS,
    CapsuleExecutionAuthority,
    DockerCapsuleLimits,
    DurableControllerAuthority,
)
from admissible.capsule.host_codex_backend import (
    BwrapCodexAppServerConnection,
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    HostCodexAppServerCapsuleBackend,
    dynamic_tools_grammar,
    initialize_request,
    preventive_control_config,
    protocol_request_policy_fingerprint,
    thread_start_request,
)
from admissible.capsule.host_control import (
    AuthenticationBoundary,
    AuthenticatedControlAuthority,
    HostControlBwrapPolicy,
    PendingAuthenticationBoundary,
    SYNTHETIC_MINIMAL_CONFIG,
    SyntheticAuthenticationBoundary,
    assert_no_forbidden_launch_source,
)
from admissible.capsule.execution_authority import (
    BackendExecutionAuthority,
    ExecutableFileIdentity,
    synthetic_component_identity,
)
from admissible.capsule.model_authority import (
    CANARY_CONFIGURED_MODEL,
    CANARY_CONFIGURED_REASONING_EFFORT,
    CodexModelAuthority,
)
from admissible.capsule.serialization_witness import serialization_witness_identity
from admissible.capsule.intake import (
    AcceptedMaterialIdentity,
    IntakeEvidence,
    IntakeFileRecord,
    IntakePublicationState,
)
from tests._verified_canary_binding import verified_canary_binding
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
    DurableSessionEvent,
    DurableToolResult,
    SessionTerminalClassification,
    ToolIdDisposition,
    ToolTerminalClassification,
)


def _model_authority(component=None):
    if component is None:
        component = synthetic_component_identity(
            component="contract-fixture",
            fixture_material={"source": "unit-test"},
        )
    return CodexModelAuthority.create(
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        codex_executable_identity=component,
        serialization_witness_identity=serialization_witness_identity(),
    )


def _backend_authority() -> BackendExecutionAuthority:
    binding = verified_canary_binding()
    component = synthetic_component_identity(
        component="contract-fixture",
        fixture_material={"source": "unit-test"},
    )
    model_authority = binding["authority"]
    return BackendExecutionAuthority.create(
        capsule_authority_fingerprint="1" * 64,
        generic_mission_fingerprint=sha256_bytes(b"mission"),
        codex_executable_identity=binding["identity"].to_dict(),
        model_authority=model_authority,
        verified_witness_receipt=binding["receipt"],
        trusted_witness_store=binding["store"],
        host_control_policy_fingerprint="2" * 64,
        bwrap_executable_identity=component,
        bwrap_argv_policy_fingerprint="3" * 64,
        controller_identity="4" * 64,
        capsule_image_content_id="sha256:" + "5" * 64,
        docker_executable_identity=component,
        dynamic_tools_schema_identity=fingerprint(dynamic_tools_grammar()),
        protocol_request_policy_fingerprint=protocol_request_policy_fingerprint(
            model_authority
        ),
        mission_bytes=b"mission",
        prompt_bytes=b"prompt",
        backend_session_id="backend-session-001",
        run_id="run-001",
        connection_mode="synthetic_provider_free",
        connection_factory_identity=component,
        authentication_boundary_state="SYNTHETIC_PROVIDER_FREE",
        budgets={
            "event_timeout_ms": 1000,
            "protocol_drain_timeout_ms": 1000,
            "protocol_drain_records": 16,
            "app_server_message_bytes": 1024,
            "agent_text_bytes": 1024,
            "capsule_command_timeout_ms": 1000,
            "capsule_session_timeout_ms": 5000,
            "capsule_output_bytes": 4096,
            "capsule_workspace_bytes": 8192,
            "capsule_pids": 8,
            "capsule_cpu_millis": 500,
            "capsule_memory_bytes": 16 * 1024 * 1024,
        },
        terminal_policy={
            "post_terminal_drain": "BOUNDED_UNTIL_PROCESS_CLOSED",
            "late_record_policy": "FAIL_SESSION",
            "completion_requires": [
                "protocol_terminal",
                "app_server_process_closed",
                "capsule_cleanup",
                "frozen_provider_output",
            ],
        },
    )


def _synthetic_policy(tmp_path: Path) -> HostControlBwrapPolicy:
    runtime = tmp_path / "synthetic-runtime"
    authentication = tmp_path / "synthetic-auth.json"
    configuration = tmp_path / "synthetic-config.toml"
    runtime.write_bytes(b"synthetic app-server executable placeholder\n")
    runtime.chmod(0o700)
    authentication.write_text('{"synthetic":"not-a-real-login"}\n', encoding="utf-8")
    configuration.write_bytes(SYNTHETIC_MINIMAL_CONFIG)
    return HostControlBwrapPolicy(
        bwrap_executable=Path("/usr/bin/bwrap"),
        codex_executable=runtime,
        authentication_boundary=SyntheticAuthenticationBoundary(authentication),
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
    store.bind_protocol(
        session_id,
        app_server_session_id="app-session-001",
        thread_id="thread-001",
        turn_id="turn-001",
    )
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


def _freeze_terminal_provider_output(
    store: DurableCapsuleSessionStore,
    *,
    terminal: bool = True,
) -> None:
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
    store.record_cleanup(
        "session-001",
        {
            "container_removed": True,
            "complete_process_tree_reaped": True,
            "disposable_workspace_removed": True,
            "frozen_output_retained": True,
            "volume_removed": True,
        },
    )
    store.freeze_provider_output("session-001", output)
    if terminal:
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
        executable_identity=policy.codex_identity.to_dict(),
        policy_fingerprint=policy.policy_fingerprint,
        authentication_boundary_state=policy.authentication_boundary.state,
    )
    execution = CapsuleExecutionAuthority.create(
        DockerCapsuleLimits(image_identity="sha256:" + "a" * 64)
    )
    controller = DurableControllerAuthority.create(execution)
    assert control.authority_fingerprint != execution.authority_fingerprint
    assert controller.execution_authority_fingerprint == execution.authority_fingerprint
    assert len(controller.implementation_source_sha256) == 64
    assert set(controller.dynamic_tools) == set(ALLOWED_DYNAMIC_TOOLS)


def test_backend_execution_authority_cross_binds_bytes_modes_and_schema():
    authority = _backend_authority()
    assert authority.backend_kind == "host_codex_app_server_capsule_v1"
    assert authority.app_server_protocol_version == "0.145.0"
    assert authority.protocol_schema_identity == protocol_schema_identity()
    assert (
        authority.protocol_request_policy_fingerprint
        == protocol_request_policy_fingerprint(
            verified_canary_binding()["authority"]
        )
    )
    assert authority.mission_fingerprint == sha256_bytes(b"mission")
    assert authority.prompt_fingerprint == sha256_bytes(b"prompt")

    with pytest.raises(ValueError, match="production launch requires"):
        dataclasses.replace(
            authority,
            connection_mode="production_bwrap",
            authority_fingerprint=fingerprint(
                {
                    **authority._body(),
                    "connection_mode": "production_bwrap",
                }
            ),
        ).validated()
    production_body = {
        **authority._body(),
        "connection_mode": "production_bwrap",
        "authentication_boundary_state": "OS_ENFORCED",
    }
    with pytest.raises(ValueError, match="provider-capable source attestation"):
        dataclasses.replace(
            authority,
            connection_mode="production_bwrap",
            authentication_boundary_state="OS_ENFORCED",
            authority_fingerprint=fingerprint(production_body),
        ).validated()
    with pytest.raises(ValueError, match="prompt bytes and fingerprint"):
        dataclasses.replace(
            authority,
            prompt_base64="c3Vic3RpdHV0ZWQ=",
            authority_fingerprint=fingerprint(
                {
                    **authority._body(),
                    "prompt_base64": "c3Vic3RpdHV0ZWQ=",
                }
            ),
        ).validated()


def test_wrong_backend_or_app_server_protocol_is_refused():
    authority = _backend_authority()
    for field, value, expected in (
        ("backend_kind", "arbitrary", "backend kind"),
        ("app_server_protocol_version", "0.146.0", "protocol version"),
    ):
        body = {**authority._body(), field: value}
        with pytest.raises(ValueError, match=expected):
            dataclasses.replace(
                authority,
                **{field: value, "authority_fingerprint": fingerprint(body)},
            ).validated()


def test_executable_symlink_drift_is_not_an_attestation(tmp_path: Path):
    target = tmp_path / "codex-real"
    target.write_bytes(b"provider-free executable fixture\n")
    target.chmod(0o700)
    alias = tmp_path / "codex"
    alias.symlink_to(target.name)
    with pytest.raises(ValueError, match="symlinked component"):
        ExecutableFileIdentity.attest(alias, label="Codex executable")

    identity = ExecutableFileIdentity.attest(target, label="Codex executable")
    replacement = tmp_path / "codex-replacement"
    replacement.write_bytes(b"different provider-free fixture\n")
    replacement.chmod(0o700)
    os.replace(replacement, target)
    with pytest.raises(ValueError, match="identity changed"):
        identity.reattest(label="Codex executable")


def test_bwrap_policy_has_an_empty_explicit_view_and_no_workspace_or_socket(tmp_path: Path):
    policy = _synthetic_policy(tmp_path)
    argv = policy.build_argv()
    rendered = "\n".join(argv)
    assert "--unshare-all" in argv
    assert "--share-net" not in argv
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


def test_pending_authentication_boundary_blocks_production_before_launch(tmp_path: Path):
    runtime = tmp_path / "synthetic-runtime"
    runtime.write_bytes(b"provider-free executable fixture\n")
    runtime.chmod(0o700)
    policy = HostControlBwrapPolicy(
        bwrap_executable=Path("/usr/bin/bwrap"),
        codex_executable=runtime,
        authentication_boundary=PendingAuthenticationBoundary(),
    )
    assert policy.evidence()["production_ready"] is False
    assert policy.evidence()["network"] == "isolated"
    with pytest.raises(RuntimeError, match="OS-enforced"):
        policy.build_argv()


def test_caller_asserted_os_enforcement_cannot_open_the_authentication_gate(
    tmp_path: Path,
):
    class CallerAssertedBoundary(AuthenticationBoundary):
        state = "OS_ENFORCED"
        provider_request_capable = True
        authentication_sources = ()
        network_argv = ("--share-net",)
        boundary_fingerprint = "0" * 64

        def attest_ready(self) -> None:
            return None

    runtime = tmp_path / "synthetic-runtime"
    runtime.write_bytes(b"provider-free executable fixture\n")
    runtime.chmod(0o700)
    with pytest.raises(ValueError, match="architecture-approved"):
        HostControlBwrapPolicy(
            bwrap_executable=Path("/usr/bin/bwrap"),
            codex_executable=runtime,
            authentication_boundary=CallerAssertedBoundary(),
        )


def test_symlinked_forbidden_root_is_refused(tmp_path: Path):
    policy = _synthetic_policy(tmp_path)
    real_forbidden = tmp_path / "real-forbidden"
    real_forbidden.mkdir()
    alias = tmp_path / "forbidden-alias"
    alias.symlink_to(real_forbidden.name, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked component"):
        HostControlBwrapPolicy(
            bwrap_executable=policy.bwrap_executable,
            codex_executable=policy.codex_executable,
            authentication_boundary=policy.authentication_boundary,
            configuration_file=policy.configuration_file,
            forbidden_host_roots=(alias,),
        )


def test_policy_identity_does_not_read_or_hash_synthetic_authentication_contents(tmp_path: Path):
    policy = _synthetic_policy(tmp_path)
    first = policy.policy_fingerprint
    # The test owns this explicitly synthetic placeholder. Changing only its
    # bytes must not change policy identity because production auth bytes are
    # never inspected or hashed by the policy.
    policy.authentication_boundary.authentication_file.write_text(
        "different synthetic placeholder\n",
        encoding="utf-8",
    )
    second = policy.policy_fingerprint
    assert second == first
    assert json.dumps(policy.evidence()).find("different synthetic") == -1
    with pytest.raises(ValueError, match="changed after attestation"):
        policy.attest_launch()


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
    #include <errno.h>
    #include <fcntl.h>
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
      for (int fd = 3; fd < 64; fd++) {{
        errno = 0;
        if (!(fcntl(fd, F_GETFD) == -1 && errno == EBADF)) {{
          fprintf(stderr, "LEAKED_FD=%d\\n", fd);
          ok = 0;
        }}
      }}
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
    configuration = tmp_path / "synthetic-config.toml"
    configuration.write_bytes(SYNTHETIC_MINIMAL_CONFIG)
    policy = HostControlBwrapPolicy(
        bwrap_executable=Path("/usr/bin/bwrap"),
        codex_executable=executable,
        authentication_boundary=SyntheticAuthenticationBoundary(authentication),
        configuration_file=configuration,
        certificate_bundle=None,
        resolver_file=None,
        hosts_file=None,
        forbidden_host_roots=(forbidden_workspace,),
    ).validated()
    with policy.descriptor_argv(("synthetic-app-server",)) as launch:
        rendered = "\n".join(launch.argv)
        assert str(executable) not in rendered
        assert str(authentication) not in rendered
        assert str(configuration) not in rendered
        completed = subprocess.run(
            launch.argv,
            executable=launch.executable,
            pass_fds=launch.pass_fds,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "SYNTHETIC_CONTROL_CONFINEMENT_PASS\n"


def test_pinned_initialize_and_dynamic_tools_wire_shape_is_closed():
    assert (
        protocol_schema_identity()
        == "cec0eb5631a013b3be09670f9aa05193b43cf47b9ad7443d6266fff8b7fe960f"
    )
    initialize = initialize_request("init-001")
    validate_schema("v1/InitializeParams.json", initialize["params"])
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
    request = thread_start_request(
        "thread-request-001", model_authority=_model_authority()
    )
    assert request["method"] == "thread/start"
    assert request["params"]["cwd"] == "/control/empty"
    assert request["params"]["approvalPolicy"] == "never"
    assert request["params"]["sandbox"] == "read-only"
    assert request["params"]["dynamicTools"] == dynamic_tools_grammar()
    namespace = request["params"]["dynamicTools"][0]
    assert namespace["type"] == "namespace"
    assert namespace["name"] == "capsule_effects"
    assert {tool["name"] for tool in namespace["tools"]} == set(ALLOWED_DYNAMIC_TOOLS)
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in namespace["tools"])
    encoded = json.dumps(request, sort_keys=True)
    assert "docker.sock" not in encoded
    assert "provider-workspace" not in encoded


def test_readonly_alias_is_refused_and_exact_read_only_is_schema_valid():
    request = thread_start_request(
        "thread-request-001", model_authority=_model_authority()
    )
    validate_schema("v2/ThreadStartParams.json", request["params"])
    substituted = json.loads(json.dumps(request["params"]))
    substituted["sandbox"] = "readOnly"
    with pytest.raises(ValueError, match="anyOf"):
        validate_schema("v2/ThreadStartParams.json", substituted)


def test_duplicate_json_keys_are_refused_before_semantics():
    with pytest.raises(ValueError, match="duplicate object key"):
        strict_json_loads(
            b'{"method":"turn/completed","method":"item/tool/call"}',
            label="app-server JSON",
        )


def test_preventive_configuration_closes_native_web_and_mcp_capabilities():
    configuration = preventive_control_config()
    assert configuration["hooks"] == {}
    assert configuration["mcp_servers"] == {}
    assert configuration["project_doc_max_bytes"] == 0
    assert all(value is False for value in configuration["features"].values())
    assert {
        "apps",
        "memories",
        "plugins",
        "shell_snapshot",
        "skills",
        "web_search",
    } == set(configuration["features"])
    request = thread_start_request(
        "thread-request-001", model_authority=_model_authority()
    )
    assert request["params"]["environments"] == []
    assert request["params"]["runtimeWorkspaceRoots"] == []
    assert request["params"]["selectedCapabilityRoots"] == []


def test_host_launcher_drops_loader_environment_and_closes_file_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    policy = _synthetic_policy(tmp_path)
    authority = AuthenticatedControlAuthority.create(
        codex_protocol_version=CODEX_APP_SERVER_PROTOCOL_VERSION,
        executable_identity=policy.codex_identity.to_dict(),
        policy_fingerprint=policy.policy_fingerprint,
        authentication_boundary_state=policy.authentication_boundary.state,
    )
    captured = {}

    class LaunchCaptured(Exception):
        pass

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        raise LaunchCaptured

    monkeypatch.setenv("LD_PRELOAD", "/forbidden/inject.so")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/forbidden/lib")
    monkeypatch.setenv("PYTHONPATH", "/forbidden/python")
    monkeypatch.setenv("HTTPS_PROXY", "http://forbidden.invalid")
    monkeypatch.setattr(host_backend_module.subprocess, "Popen", fake_popen)
    with pytest.raises(LaunchCaptured):
        BwrapCodexAppServerConnection(policy=policy, authority=authority)
    assert captured["kwargs"]["env"] == {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    assert captured["kwargs"]["close_fds"] is True
    assert captured["kwargs"]["cwd"] == "/"
    assert captured["kwargs"]["executable"].startswith("/proc/self/fd/")
    assert captured["kwargs"]["pass_fds"]
    rendered = "\n".join(captured["args"][0])
    assert str(policy.codex_executable) not in rendered
    assert str(policy.authentication_boundary.authentication_file) not in rendered


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


def test_journal_concurrent_writers_cannot_allocate_the_same_sequence(tmp_path: Path):
    store = _store(tmp_path)
    first = _request(store, rpc_id=60, call_id="call-first")
    second = _request(store, rpc_id=61, call_id="call-second")
    assert first.sequence == second.sequence == 1
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def write(request):
        barrier.wait()
        try:
            store.record_tool_request(request)
        except ValueError:
            outcomes.append("refused")
        else:
            outcomes.append("appended")

    threads = [
        threading.Thread(target=write, args=(first,)),
        threading.Thread(target=write, args=(second,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert sorted(outcomes) == ["appended", "refused"]
    assert len(store.reconstruct("session-001").requests) == 1


def test_first_journal_creation_fsyncs_anchor_and_session_parents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    observed: list[Path] = []
    actual = session_store_module.fsync_directory

    def recording_fsync(path: Path):
        observed.append(path)
        actual(path)

    monkeypatch.setattr(session_store_module, "fsync_directory", recording_fsync)
    store = DurableCapsuleSessionStore(tmp_path / "session-store")
    store.create_session(
        session_id="session-fsync",
        authority_identity={"authority": "synthetic"},
        controller_authority={"controller": "synthetic"},
        workspace={"workspace_id": "workspace-fsync", "host_owned": False},
    )
    assert store.root in observed
    assert store._anchors in observed
    assert store.session_directory("session-fsync") in observed


def test_directory_fsync_failure_prevents_first_mutable_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    store = DurableCapsuleSessionStore(tmp_path / "session-store")
    actual = session_store_module.fsync_directory

    def fail_session_parent(path: Path):
        if path == store.root:
            raise OSError("synthetic directory fsync failure")
        actual(path)

    monkeypatch.setattr(session_store_module, "fsync_directory", fail_session_parent)
    with pytest.raises(OSError, match="directory fsync failure"):
        store.create_session(
            session_id="session-fsync-fail",
            authority_identity={"authority": "synthetic"},
            controller_authority={"controller": "synthetic"},
            workspace={"workspace_id": "workspace-fsync-fail", "host_owned": False},
        )
    assert store._anchor_path("session-fsync-fail").is_file()
    assert not store._log_path("session-fsync-fail").exists()


def test_disk_full_partial_append_is_never_a_durable_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _store(tmp_path)
    request = _request(store)
    actual_write = session_store_module.os.write
    append_writes = 0

    def partial_then_full(descriptor: int, data: bytes) -> int:
        nonlocal append_writes
        append_writes += 1
        if append_writes == 1:
            return actual_write(descriptor, data[:17])
        raise OSError(errno.ENOSPC, "synthetic disk full")

    monkeypatch.setattr(session_store_module.os, "write", partial_then_full)
    with pytest.raises(OSError, match="disk full"):
        store.record_tool_request(request)
    with pytest.raises(ValueError, match="partial final record"):
        store.reconstruct("session-001")


def test_recomputed_mutable_chain_cannot_substitute_external_authority(tmp_path: Path):
    store = _store(tmp_path)
    path = store._log_path("session-001")
    decoded = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    previous = "0" * 64
    substituted = []
    for index, value in enumerate(decoded):
        payload = value["payload"]
        if index == 0:
            payload = json.loads(json.dumps(payload))
            payload["authority_identity"]["control"] = "substituted"
        event = DurableSessionEvent.create(
            index=index,
            session_id="session-001",
            kind=value["kind"],
            payload=payload,
            previous_fingerprint=previous,
        )
        substituted.append(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")))
        previous = event.event_fingerprint
    path.write_text("\n".join(substituted) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="externally durable tail"):
        store.reconstruct("session-001")


def test_completion_cannot_precede_cleanup_and_frozen_provider_output(tmp_path: Path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="cleanup and ProviderOutput"):
        store.record_terminal(
            "session-001",
            SessionTerminalClassification.COMPLETED,
            "premature completion",
        )


def test_provider_output_without_terminal_record_is_not_reconstructible(tmp_path: Path):
    store = _store(tmp_path)
    _freeze_terminal_provider_output(store, terminal=False)
    with pytest.raises(ValueError, match="lacks an exact terminal"):
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


def test_terminal_session_refuses_another_effect_request(tmp_path: Path):
    store = _store(tmp_path)
    _freeze_terminal_provider_output(store)
    with pytest.raises(ValueError, match="terminal"):
        _request(store)


def test_control_process_terminal_immediately_refuses_another_effect_request(
    tmp_path: Path,
):
    store = _store(tmp_path)
    store.record_control_terminal(
        "session-001",
        {
            "protocol_terminal_classification": "FAILED",
            "app_server_exit_code": 1,
            "app_server_exit_normal": True,
            "app_server_forced": False,
            "app_server_eof_observed": True,
            "controller_classification": "PROVIDER_PROCESS_FAILED",
        },
    )
    with pytest.raises(ValueError, match="terminal"):
        _request(store)


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
