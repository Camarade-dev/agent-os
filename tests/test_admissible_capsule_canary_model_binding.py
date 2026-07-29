"""Explicit Codex model / reasoning-effort binding for the ChatGPT canary.

Every assertion here is provider-free: no public DNS name, no public endpoint,
no real model turn and no real authentication material.  The real-binary
serialization witness lives in
``test_admissible_capsule_codex_serialization_witness.py``.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from admissible.capsule.boundary_launcher import (
    CODEX_APP_SERVER_ARGUMENTS,
    CodexConfinementLaunchPolicy,
)
from admissible.capsule.broker_transport import make_seqpacket_socketpair
from admissible.capsule.codex_protocol import (
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    protocol_schema_identity,
)
from admissible.capsule.common import canonical_bytes, fingerprint, sha256_bytes
from admissible.capsule.execution_authority import (
    BackendExecutionAuthority,
    ExecutableFileIdentity,
    synthetic_component_identity,
)
from admissible.capsule.host_codex_backend import (
    dynamic_tools_grammar,
    protocol_request_policy_fingerprint,
    thread_start_request,
    turn_start_request,
)
from admissible.capsule.model_authority import (
    CANARY_CONFIGURED_MODEL,
    CANARY_CONFIGURED_REASONING_EFFORT,
    MODEL_CONFIGURATION_CHANNEL,
    CodexModelAuthority,
    ModelConfigurationError,
    canary_model_authority,
    ephemeral_config_bytes,
    require_exact_model,
    require_exact_reasoning_effort,
    validate_effective_thread_configuration,
    validate_launch_configuration_bytes,
)
from admissible.capsule.serialization_witness import (
    SerializationWitnessError,
    evaluate_serialization_witness,
    extract_witness_record,
    serialization_witness_identity,
    witness_capture_policy,
)


def _codex_component(name: str = "canary-codex"):
    return synthetic_component_identity(
        component=name,
        fixture_material={"source": "canary-model-binding-test"},
    )


def _authority(model=CANARY_CONFIGURED_MODEL, effort=CANARY_CONFIGURED_REASONING_EFFORT):
    return CodexModelAuthority.create(
        configured_model=model,
        configured_reasoning_effort=effort,
        codex_executable_identity=_codex_component(),
        serialization_witness_identity=serialization_witness_identity(),
    )


def _serialized(model: str, effort: str | None):
    body = {"model": model, "input": ["prompt bytes"], "instructions": "secret"}
    if effort is not None:
        body["reasoning"] = {"effort": effort, "summary": "auto"}
    return body


# --- configured binding ------------------------------------------------


def test_canary_authority_binds_the_exact_model_and_low_effort():
    authority = canary_model_authority(
        codex_executable_identity=_codex_component(),
        serialization_witness_identity=serialization_witness_identity(),
    )
    assert authority.configured_model == "gpt-5.3-codex"
    assert authority.configured_reasoning_effort == "low"
    assert authority.configuration_channel == MODEL_CONFIGURATION_CHANNEL
    assert authority.to_dict()["app_server_protocol_version"] == (
        CODEX_APP_SERVER_PROTOCOL_VERSION
    )
    assert authority.to_dict()["protocol_schema_identity"] == protocol_schema_identity()
    assert authority.serialization_witness_identity == serialization_witness_identity()
    prohibitions = authority.configuration["prohibitions"]
    assert prohibitions["auto_model_refused"] is True
    assert prohibitions["omitted_reasoning_effort_refused"] is True
    assert prohibitions["mutable_client_default_refused"] is True
    assert "auto" in prohibitions["prohibited_values"]
    assert "xhigh" not in prohibitions["reasoning_effort_vocabulary"]


def test_thread_and_turn_requests_serialize_the_exact_model_and_effort():
    authority = _authority()
    thread = thread_start_request("thread-1", model_authority=authority)["params"]
    turn = turn_start_request(
        "turn-1",
        thread_id="thread-abc",
        prompt="mission",
        model_authority=authority,
    )["params"]
    assert thread["model"] == "gpt-5.3-codex"
    assert thread["allowProviderModelFallback"] is False
    assert thread["config"]["model"] == "gpt-5.3-codex"
    assert thread["config"]["model_reasoning_effort"] == "low"
    # The preventive control overlay is preserved, not replaced.
    assert thread["config"]["features"]["web_search"] is False
    assert turn["model"] == "gpt-5.3-codex"
    assert turn["effort"] == "low"


def test_ephemeral_configuration_bytes_are_canonical_and_non_secret():
    authority = _authority()
    raw = authority.ephemeral_config_bytes
    assert raw == ephemeral_config_bytes(model="gpt-5.3-codex", reasoning_effort="low")
    assert sha256_bytes(raw) == authority.ephemeral_config_sha256
    assert b'model = "gpt-5.3-codex"' in raw
    assert b'model_reasoning_effort = "low"' in raw
    assert b"auth.json" not in raw
    assert b"access_token" not in raw
    assert b"OPENAI_API_KEY" not in raw
    assert validate_launch_configuration_bytes(raw, authority) == (
        authority.ephemeral_config_sha256
    )


# --- refusals ----------------------------------------------------------


@pytest.mark.parametrize("model", ["auto", "", "default", "none"])
def test_auto_and_omitted_model_values_are_refused(model):
    with pytest.raises(ModelConfigurationError):
        require_exact_model(model)
    with pytest.raises(ModelConfigurationError):
        _authority(model=model)


def test_omitted_model_is_refused():
    with pytest.raises(ModelConfigurationError):
        require_exact_model(None)
    with pytest.raises(ModelConfigurationError):
        CodexModelAuthority.create(
            configured_model=None,
            configured_reasoning_effort="low",
            codex_executable_identity=_codex_component(),
            serialization_witness_identity=serialization_witness_identity(),
        )


@pytest.mark.parametrize("model", ["GPT-5.3-Codex", "gpt-5.3-Codex", " gpt-5.3-codex"])
def test_changed_model_casing_or_padding_is_refused(model):
    with pytest.raises(ModelConfigurationError):
        require_exact_model(model)


@pytest.mark.parametrize("effort", ["auto", "", "xhigh", "ultra", "Low", "LOW"])
def test_auto_omitted_and_out_of_vocabulary_effort_is_refused(effort):
    with pytest.raises(ModelConfigurationError):
        require_exact_reasoning_effort(effort)


def test_omitted_reasoning_effort_is_refused():
    with pytest.raises(ModelConfigurationError):
        require_exact_reasoning_effort(None)


def test_model_substitution_changes_the_complete_authority():
    bound = _authority()
    substituted = _authority(model="gpt-5.6-sol")
    assert substituted.authority_fingerprint != bound.authority_fingerprint
    assert substituted.configuration_fingerprint != bound.configuration_fingerprint
    assert substituted.ephemeral_config_sha256 != bound.ephemeral_config_sha256


def test_reasoning_effort_substitution_changes_the_complete_authority():
    bound = _authority()
    substituted = _authority(effort="high")
    assert substituted.authority_fingerprint != bound.authority_fingerprint
    assert substituted.configuration_fingerprint != bound.configuration_fingerprint
    assert substituted.ephemeral_config_sha256 != bound.ephemeral_config_sha256


def test_caller_asserted_configuration_is_not_an_attestation():
    authority = _authority()
    forged = authority.to_dict()
    forged["configuration"]["configured_model"] = "gpt-5.6-sol"
    with pytest.raises(ModelConfigurationError):
        CodexModelAuthority.from_dict(forged)

    rederived = authority.to_dict()
    rederived["configuration"]["ephemeral_config_base64"] = "aGk="
    with pytest.raises(ModelConfigurationError):
        CodexModelAuthority.from_dict(rederived)


def test_configuration_channel_substitution_is_refused():
    authority = _authority()
    forged = authority.to_dict()
    forged["configuration"]["configuration_channel"] = "some_other_channel"
    with pytest.raises(ModelConfigurationError):
        CodexModelAuthority.from_dict(forged)


# --- effective configuration before effects ---------------------------


def test_effective_thread_configuration_accepts_only_the_bound_values():
    authority = _authority()
    evidence = validate_effective_thread_configuration(
        {"model": "gpt-5.3-codex", "reasoningEffort": "low"},
        authority,
    )
    assert evidence["configured_model"] == "gpt-5.3-codex"
    assert evidence["app_server_effective_model"] == "gpt-5.3-codex"
    assert evidence["app_server_effective_reasoning_effort"] == "low"
    # Offline/configured evidence never claims real routing.
    assert evidence["real_service_selected_model"] == "CANARY_TIME_OBSERVATION_ONLY"


@pytest.mark.parametrize(
    "response",
    [
        {"reasoningEffort": "low"},
        {"model": "gpt-5.3-codex"},
        {"model": "gpt-5.6-sol", "reasoningEffort": "low"},
        {"model": "GPT-5.3-Codex", "reasoningEffort": "low"},
        {"model": "auto", "reasoningEffort": "low"},
        {"model": "gpt-5.3-codex", "reasoningEffort": "high"},
        {"model": "gpt-5.3-codex", "reasoningEffort": "xhigh"},
        {"model": "gpt-5.3-codex", "reasoningEffort": None},
    ],
)
def test_effective_thread_configuration_mismatch_is_refused(response):
    with pytest.raises(ModelConfigurationError):
        validate_effective_thread_configuration(response, _authority())


# --- serialization witness policy --------------------------------------


def test_witness_records_only_the_minimum_non_secret_metadata():
    record = extract_witness_record(
        request_path="/v1/responses",
        request_body=_serialized("gpt-5.3-codex", "low"),
    )
    rendered = canonical_bytes(record.to_dict())
    assert b"prompt bytes" not in rendered
    assert b"secret" not in rendered
    assert set(record.to_dict()) == {
        "schema_version",
        "witness_policy_identity",
        "request_path",
        "serialized_model",
        "serialized_reasoning_effort",
        "record_fingerprint",
    }
    policy = witness_capture_policy()
    assert policy["real_model_or_provider_execution"] is False
    assert policy["public_dns_or_endpoint"] is False
    assert "provider_entitlement" in policy["does_not_prove"]


def test_witness_accepts_the_exact_bound_serialization():
    authority = _authority()
    record = extract_witness_record(
        request_path="/v1/responses",
        request_body=_serialized("gpt-5.3-codex", "low"),
    )
    evidence = evaluate_serialization_witness([record], authority)
    assert evidence["provider_free_serialized_model"] == "gpt-5.3-codex"
    assert evidence["provider_free_serialized_reasoning_effort"] == "low"
    assert evidence["real_service_selected_model"] == "CANARY_TIME_OBSERVATION_ONLY"


@pytest.mark.parametrize(
    ("model", "effort"),
    [
        ("auto", "low"),
        ("gpt-5.6-sol", "low"),
        ("GPT-5.3-Codex", "low"),
        ("gpt-5.3-codex", "medium"),
        ("gpt-5.3-codex", "high"),
        ("gpt-5.3-codex", "xhigh"),
        ("gpt-5.3-codex", "Low"),
    ],
)
def test_witness_refuses_every_substituted_serialization(model, effort):
    authority = _authority()
    with pytest.raises(SerializationWitnessError):
        record = extract_witness_record(
            request_path="/v1/responses",
            request_body=_serialized(model, effort),
        )
        evaluate_serialization_witness([record], authority)


@pytest.mark.parametrize(
    "body",
    [
        {"input": []},
        {"model": "gpt-5.3-codex"},
        {"model": "gpt-5.3-codex", "reasoning": {}},
        {"reasoning": {"effort": "low"}},
    ],
)
def test_witness_refuses_omitted_model_or_effort(body):
    with pytest.raises(SerializationWitnessError):
        extract_witness_record(request_path="/v1/responses", request_body=body)


def test_witness_refuses_when_no_request_was_serialized():
    with pytest.raises(SerializationWitnessError):
        evaluate_serialization_witness([], _authority())


def test_witness_refuses_requests_outside_the_responses_endpoint():
    authority = _authority()
    record = extract_witness_record(
        request_path="/v1/chat/completions",
        request_body=_serialized("gpt-5.3-codex", "low"),
    )
    with pytest.raises(SerializationWitnessError):
        evaluate_serialization_witness([record], authority)


# --- executable identity / mutable symlink drift ------------------------


def test_mutable_codex_symlink_is_refused_as_an_executable_authority(tmp_path: Path):
    real = tmp_path / "codex-0.145.0"
    real.write_bytes(b"#!/bin/sh\nexit 0\n")
    real.chmod(0o755)
    mutable = tmp_path / "codex"
    mutable.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        ExecutableFileIdentity.attest(mutable, label="mutable Codex symlink")


def test_codex_content_drift_invalidates_the_model_authority(tmp_path: Path):
    pinned = tmp_path / "codex"
    pinned.write_bytes(b"#!/bin/sh\nexit 0\n")
    pinned.chmod(0o755)
    identity = ExecutableFileIdentity.attest(pinned, label="pinned Codex")
    authority = CodexModelAuthority.create(
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        codex_executable_identity=identity.to_dict(),
        serialization_witness_identity=serialization_witness_identity(),
    )
    pinned.write_bytes(b"#!/bin/sh\nexit 1\n")
    pinned.chmod(0o755)
    with pytest.raises(ValueError, match="identity changed"):
        identity.reattest(label="pinned Codex")
    drifted = ExecutableFileIdentity.attest(pinned, label="drifted Codex")
    assert drifted.sha256 != identity.sha256
    assert (
        CodexModelAuthority.create(
            configured_model=CANARY_CONFIGURED_MODEL,
            configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
            codex_executable_identity=drifted.to_dict(),
            serialization_witness_identity=serialization_witness_identity(),
        ).authority_fingerprint
        != authority.authority_fingerprint
    )


# --- launch channel -----------------------------------------------------


def _static_probe(tmp_path: Path) -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("launch-shape witness requires local gcc")
    source = tmp_path / "probe.c"
    executable = tmp_path / "probe"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    compiled = subprocess.run(
        ("gcc", "-static", "-O2", "-o", executable, source),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if compiled.returncode != 0:
        pytest.skip("static launch-shape executable unavailable")
    return executable


def _launch_policy(
    tmp_path: Path,
    authority: CodexModelAuthority,
    executable: Path,
    *,
    config: bytes,
    home_suffix: str = "",
):
    home = tmp_path / f"home-{authority.configuration_fingerprint[:8]}{home_suffix}"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_bytes(config)
    home_descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    app_left, app_right = socket.socketpair()
    transfer_left, transfer_right = make_seqpacket_socketpair()
    policy = CodexConfinementLaunchPolicy(
        bwrap_identity=ExecutableFileIdentity.attest(
            Path("/usr/bin/bwrap"), label="launch bwrap"
        ),
        codex_identity=ExecutableFileIdentity.attest(
            executable, label="synthetic pinned Codex"
        ),
        namespace_bootstrap_identity=ExecutableFileIdentity.attest(
            executable, label="synthetic namespace bootstrap"
        ),
        codex_home_descriptor=home_descriptor,
        app_server_descriptor=app_right.fileno(),
        proxy_transfer_descriptor=transfer_right.fileno(),
        session_id="canary-model-launch",
        pin_fingerprint="9" * 64,
        runtime_dependency_descriptors={},
        model_authority=authority,
    )
    closers = (home_descriptor, app_left, app_right, transfer_left, transfer_right)
    return policy, closers


def _close(closers):
    os.close(closers[0])
    for item in closers[1:]:
        item.close()


def _authority_for(executable: Path, *, model, effort):
    return CodexModelAuthority.create(
        configured_model=model,
        configured_reasoning_effort=effort,
        codex_executable_identity=ExecutableFileIdentity.attest(
            executable, label="synthetic pinned Codex"
        ).to_dict(),
        serialization_witness_identity=serialization_witness_identity(),
    )


def test_launch_fingerprint_changes_with_the_bound_model(tmp_path: Path):
    executable = _static_probe(tmp_path)
    fingerprints = {}
    for label, model, effort in (
        ("bound", CANARY_CONFIGURED_MODEL, CANARY_CONFIGURED_REASONING_EFFORT),
        ("other-model", "gpt-5.6-sol", CANARY_CONFIGURED_REASONING_EFFORT),
        ("other-effort", CANARY_CONFIGURED_MODEL, "high"),
    ):
        authority = _authority_for(executable, model=model, effort=effort)
        policy, closers = _launch_policy(
            tmp_path, authority, executable, config=authority.ephemeral_config_bytes
        )
        try:
            with policy.descriptor_launch() as launch:
                fingerprints[label] = launch.launch_fingerprint
                arguments = os.read(int(launch.argv[2]), 128 * 1024).split(b"\0")
                assert b"-c" not in arguments and b"--config" not in arguments
                assert launch.argv[-2:] == tuple(CODEX_APP_SERVER_ARGUMENTS)
        finally:
            _close(closers)
    assert len(set(fingerprints.values())) == 3


def test_launch_denies_user_and_project_configuration_discovery(tmp_path: Path):
    """No host config is visible and no override argument is ever passed."""

    executable = _static_probe(tmp_path)
    authority = _authority_for(
        executable,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    policy, closers = _launch_policy(
        tmp_path, authority, executable, config=authority.ephemeral_config_bytes
    )
    try:
        with policy.descriptor_launch() as launch:
            arguments = os.read(int(launch.argv[2]), 128 * 1024).split(b"\0")
            joined = b"\0".join(arguments)
            # HOME and CODEX_HOME both point at the broker-owned ephemeral home,
            # so ~/.codex and any project config are unreachable.
            assert arguments.count(b"/control/codex-home") == 3
            for index, item in enumerate(arguments):
                if item in {b"HOME", b"CODEX_HOME"}:
                    assert arguments[index + 1] == b"/control/codex-home"
            assert b"--clearenv" in arguments
            assert b"--unshare-all" in arguments
            assert os.fspath(Path.home()).encode() not in joined
            assert b".codex" not in joined
            assert b"config.toml" not in joined
            for override in (b"-c", b"--config", b"--profile", b"-p", b"--oss"):
                assert override not in arguments
                assert override not in launch.argv[3:]
    finally:
        _close(closers)


def test_launch_refuses_a_substituted_or_overriding_configuration(tmp_path: Path):
    executable = _static_probe(tmp_path)
    authority = _authority_for(
        executable,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    substituted = authority.ephemeral_config_bytes.replace(
        b'model = "gpt-5.3-codex"', b'model = "gpt-5.3-codey"'
    )
    assert len(substituted) == len(authority.ephemeral_config_bytes)
    policy, closers = _launch_policy(
        tmp_path, authority, executable, config=substituted, home_suffix="-sub"
    )
    try:
        with pytest.raises(ModelConfigurationError, match="differs from the bound"):
            with policy.descriptor_launch():
                pass
    finally:
        _close(closers)

    appended = authority.ephemeral_config_bytes + b'\nmodel = "gpt-5.6-sol"\n'
    policy, closers = _launch_policy(
        tmp_path, authority, executable, config=appended, home_suffix="-app"
    )
    try:
        with pytest.raises(ValueError, match="size differs"):
            with policy.descriptor_launch():
                pass
    finally:
        _close(closers)


def test_launch_refuses_a_model_authority_for_another_executable(tmp_path: Path):
    executable = _static_probe(tmp_path)
    other = tmp_path / "other-codex"
    other.write_bytes(b"#!/bin/sh\nexit 0\n")
    other.chmod(0o755)
    foreign = _authority_for(
        other,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    policy, closers = _launch_policy(
        tmp_path, foreign, executable, config=foreign.ephemeral_config_bytes
    )
    try:
        with pytest.raises(ValueError, match="another Codex executable"):
            with policy.descriptor_launch():
                pass
    finally:
        _close(closers)
    assert executable.exists()


def test_namespace_bootstrap_refuses_any_other_codex_arguments():
    from admissible.capsule.boundary_launcher import namespace_bootstrap_main

    for arguments in (
        ["app-server", "--stdio", "-c", "model=auto"],
        ["app-server", "--strict-config", "--stdio"],
        ["exec"],
    ):
        with pytest.raises(ValueError, match="non-app-server"):
            namespace_bootstrap_main(
                ["--codex-executable", "/runtime/codex", "--", *arguments]
            )


# --- execution authority binding ---------------------------------------


def _execution_authority(model_authority: CodexModelAuthority):
    component = model_authority.codex_executable_identity
    return BackendExecutionAuthority.create(
        capsule_authority_fingerprint="1" * 64,
        generic_mission_fingerprint=sha256_bytes(b"mission"),
        codex_executable_identity=component,
        model_authority=model_authority.to_dict(),
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


def test_model_authority_changes_the_complete_execution_authority():
    bound = _execution_authority(_authority())
    other_model = _execution_authority(_authority(model="gpt-5.6-sol"))
    other_effort = _execution_authority(_authority(effort="high"))
    assert bound.model_authority_fingerprint == _authority().authority_fingerprint
    assert len(
        {
            bound.authority_fingerprint,
            other_model.authority_fingerprint,
            other_effort.authority_fingerprint,
        }
    ) == 3
    assert (
        bound.protocol_request_policy_fingerprint
        != other_effort.protocol_request_policy_fingerprint
    )


def test_execution_authority_refuses_a_swapped_model_authority():
    bound = _execution_authority(_authority())
    forged = bound.to_dict()
    forged["model_authority"] = _authority(model="gpt-5.6-sol").to_dict()
    with pytest.raises(ValueError, match="model authority binding differs"):
        BackendExecutionAuthority(**forged).validated()


def test_execution_authority_refuses_a_foreign_codex_in_the_model_authority():
    foreign = CodexModelAuthority.create(
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        codex_executable_identity=_codex_component("another-codex"),
        serialization_witness_identity=serialization_witness_identity(),
    )
    with pytest.raises(ValueError, match="another Codex executable"):
        BackendExecutionAuthority.create(
            **{
                **{
                    key: value
                    for key, value in _execution_authority(_authority())
                    .to_dict()
                    .items()
                    if key
                    in {
                        "capsule_authority_fingerprint",
                        "generic_mission_fingerprint",
                        "host_control_policy_fingerprint",
                        "bwrap_argv_policy_fingerprint",
                        "controller_identity",
                        "capsule_image_content_id",
                        "dynamic_tools_schema_identity",
                        "backend_session_id",
                        "run_id",
                        "connection_mode",
                        "authentication_boundary_state",
                        "budgets",
                        "terminal_policy",
                    }
                },
                "codex_executable_identity": _codex_component(),
                "model_authority": foreign.to_dict(),
                "bwrap_executable_identity": _codex_component(),
                "docker_executable_identity": _codex_component(),
                "connection_factory_identity": _codex_component(),
                "protocol_request_policy_fingerprint": (
                    protocol_request_policy_fingerprint(foreign)
                ),
                "mission_bytes": b"mission",
                "prompt_bytes": b"prompt",
            }
        )
