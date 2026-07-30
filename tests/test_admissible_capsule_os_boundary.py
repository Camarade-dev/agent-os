"""Provider-free witnesses for the Codex authentication/Docker/egress boundary.

Only synthetic authentication bytes and local synthetic TLS are used.  No
Codex binary, model, provider, public endpoint, login, API request, remote, or
push is reachable from this module.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from admissible.capsule.authentication_broker import (
    AUTH_FILENAME,
    AuthenticationBrokerProcess,
)
from admissible.capsule.boundary_authority import (
    DESTINATION_MANIFEST_SCHEMA_VERSION,
    DestinationManifest,
    SealedDestinationPinManifest,
)
from admissible.capsule.boundary_launcher import (
    CodexConfinementLaunchPolicy,
    ControllerConfinementLaunchPolicy,
    apply_landlock_deny_new_path_access,
    provider_free_os_boundary_authority,
)
from admissible.capsule.broker_transport import (
    BrokerProtocolError,
    MAX_BROKER_MESSAGE_BYTES,
    make_seqpacket_socketpair,
    protocol_schema_identities,
    receive_packet,
    send_packet,
)
from admissible.capsule.capsule_broker import (
    CapsuleBrokerClient,
    CapsuleBrokerConfig,
    CapsuleBrokerProcess,
)
from admissible.capsule.common import canonical_bytes, fingerprint
from admissible.capsule.docker_controller import DockerCapsuleLimits
from admissible.capsule.egress_relay import (
    DurableEgressJournal,
    EgressBudgets,
    PreventiveEgressRelay,
    receive_listener_descriptor,
    resolve_and_seal,
    send_listener_descriptor,
)
from admissible.capsule.execution_authority import (
    ExecutableFileIdentity,
    synthetic_component_identity,
)
from admissible.capsule.model_authority import (
    CANARY_CONFIGURED_MODEL,
    CANARY_CONFIGURED_REASONING_EFFORT,
    CodexModelAuthority,
)
from admissible.capsule.serialization_witness import serialization_witness_identity
from tests._candidate_canary_binding import candidate_canary_binding


def _witness_model_authority():
    return CodexModelAuthority.create(
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        codex_executable_identity=synthetic_component_identity(
            component="os-boundary-witness-codex",
            fixture_material={"source": "os-boundary-test"},
        ),
        serialization_witness_identity=serialization_witness_identity(),
    )
from admissible.capsule.session_store import (
    DurableToolRequest,
    ToolTerminalClassification,
)


SYNTHETIC_AUTHENTICATION = (
    b'{"synthetic_fixture":true,"opaque_fixture":"provider-free-only"}\n'
)
IMAGE_IDENTITY = (
    "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
)


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("docker", *arguments),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": "/nonexistent",
            "DOCKER_CONFIG": "/nonexistent",
        },
    )


def _process_descendants(root_pid: int) -> tuple[int, ...]:
    pending = [root_pid]
    found: list[int] = []
    while pending:
        parent = pending.pop()
        children_file = Path(f"/proc/{parent}/task/{parent}/children")
        try:
            children = tuple(
                int(value) for value in children_file.read_text().split()
            )
        except (FileNotFoundError, ProcessLookupError):
            children = ()
        found.extend(children)
        pending.extend(children)
    return tuple(found)


@pytest.fixture(scope="module")
def docker_ready():
    result = _docker("image", "inspect", "--format", "{{.Id}}", "ubuntu:24.04")
    if result.returncode != 0 or result.stdout.strip() != IMAGE_IDENTITY:
        pytest.skip("provider-free broker witness requires the pinned local image")


def _synthetic_manifest(hostname: str = "synthetic.test") -> DestinationManifest:
    body = {
        "schema_version": DESTINATION_MANIFEST_SCHEMA_VERSION,
        "codex_version": "0.145.0",
        "policy_revision": "synthetic_provider_free_tls_v1",
        "destinations": [
            {
                "hostname": hostname,
                "port": 443,
                "evidence": "OBSERVED_REQUIRED",
                "canary_requirement": "REFUSE_RUN_IF_UNSEALED_REQUESTED",
            }
        ],
        "dynamic_widening": False,
    }
    return DestinationManifest.from_dict(
        {**body, "manifest_fingerprint": fingerprint(body)}
    )


def test_boundary_authority_binds_every_component_schema_and_manifest():
    dependency = synthetic_component_identity(
        component="boundary-test-dependency",
        fixture_material={"revision": 1},
    )
    changed = synthetic_component_identity(
        component="boundary-test-dependency",
        fixture_material={"revision": 2},
    )
    first = provider_free_os_boundary_authority(
        dependent_identities=(dependency,)
    )
    second = provider_free_os_boundary_authority(
        dependent_identities=(changed,)
    )

    assert first.authority_fingerprint != second.authority_fingerprint
    assert first.launch_fingerprint != second.launch_fingerprint
    assert (
        first.destination_manifest_identity
        == DestinationManifest.load_packaged().manifest_fingerprint
    )
    assert dict(first.broker_protocol_schema_identities) == (
        protocol_schema_identities()
    )
    assert first.controller_confinement_policy["docker_socket_visible"] is False
    assert first.controller_confinement_policy["docker_executable_visible"] is False
    assert first.codex_confinement_policy["resolver"] == "absent"
    assert (
        first.capsule_broker_confinement_policy["caller_host_bind_paths"]
        is False
    )
    assert first.network_namespace_policy["tls"] == "end_to_end_not_terminated"
    rendered = canonical_bytes(first.to_dict()).lower()
    assert b"access_token" not in rendered
    assert b"authorization_header" in rendered  # policy name, never a value


def test_authentication_broker_fd_handoff_contains_no_path_or_bytes_and_wipes(
    tmp_path: Path,
):
    source = tmp_path / "synthetic-login.json"
    source.write_bytes(SYNTHETIC_AUTHENTICATION)
    source.chmod(0o600)
    homes = tmp_path / "private-auth-broker-homes"
    process = AuthenticationBrokerProcess.start(
        source_descriptor=os.open(
            source,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        ),
        ephemeral_root=homes,
        session_id="synthetic-auth-session",
        authority_fingerprint="a" * 64,
        configuration_bytes=_witness_model_authority().ephemeral_config_bytes,
    )
    prepared = process.prepare()
    handed_off, home_descriptor = process.handoff()

    auth_descriptor = os.open(
        AUTH_FILENAME,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=home_descriptor,
    )
    try:
        # This is the synthetic Codex consumer, never the general controller.
        assert os.read(auth_descriptor, len(SYNTHETIC_AUTHENTICATION)) == (
            SYNTHETIC_AUTHENTICATION
        )
    finally:
        os.close(auth_descriptor)

    serialized = canonical_bytes(
        {
            "prepared": prepared.to_dict(),
            "handoff": handed_off.to_dict(),
        }
    )
    assert os.fspath(source).encode() not in serialized
    assert SYNTHETIC_AUTHENTICATION.strip() not in serialized
    assert b"provider-free-only" not in serialized
    assert prepared.evidence["source_descriptor_closed"] is True
    assert handed_off.evidence["source_present_in_codex_namespace"] is False

    cleaned = process.cleanup()
    exit_code, shutdown = process.shutdown()
    assert cleaned.evidence["wipe_completed"] is True
    assert cleaned.evidence["ephemeral_home_removed"] is True
    assert shutdown.evidence["ephemeral_home_removed"] is True
    assert exit_code == 0
    assert list(homes.iterdir()) == []


def test_authentication_broker_forced_exit_is_failed_and_recovery_wipes(
    tmp_path: Path,
):
    source = tmp_path / "synthetic-crash-auth.json"
    source.write_bytes(SYNTHETIC_AUTHENTICATION)
    source.chmod(0o600)
    homes = tmp_path / "crash-homes"
    process = AuthenticationBrokerProcess.start(
        source_descriptor=os.open(source, os.O_RDONLY | os.O_CLOEXEC),
        ephemeral_root=homes,
        session_id="synthetic-auth-crash",
        authority_fingerprint="e" * 64,
        configuration_bytes=_witness_model_authority().ephemeral_config_bytes,
    )
    process.prepare()
    evidence = process.force_terminate_and_recover()
    assert evidence["terminal_classification"] == "FAILED_CLEANED"
    assert evidence["ephemeral_home_removed"] is True
    assert list(homes.iterdir()) == []


def _compile_static_controller_probe(
    tmp_path: Path,
    *,
    auth_source: Path,
    auth_homes: Path,
    unrelated_repository: Path,
    host_socket: Path,
    abstract_name: str,
) -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("mechanical namespace witness requires local gcc")
    source = tmp_path / "controller-probe.c"
    executable = tmp_path / "controller-probe"
    source.write_text(
        f"""
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int visible(const char *path) {{
    struct stat st;
    return stat(path, &st) == 0;
}}

int main(void) {{
    if (visible({json.dumps(os.fspath(auth_source))})) return 11;
    if (visible({json.dumps(os.fspath(auth_homes))})) return 12;
    if (visible("/var/run/docker.sock")) return 13;
    if (visible("/usr/bin/docker")) return 14;
    if (visible({json.dumps(os.fspath(unrelated_repository))})) return 15;
    const char *a = getenv("APP_SERVER_FD");
    const char *b = getenv("CAPSULE_BROKER_FD");
    struct stat st;
    if (!a || !b || fstat(atoi(a), &st) || !S_ISSOCK(st.st_mode)) return 16;
    if (fstat(atoi(b), &st) || !S_ISSOCK(st.st_mode)) return 17;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un un = {{0}};
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, {json.dumps(os.fspath(host_socket))}, sizeof(un.sun_path)-1);
    if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == 0) return 18;
    close(fd);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    const char *name = {json.dumps(abstract_name)};
    memcpy(un.sun_path + 1, name, strlen(name));
    if (connect(fd, (struct sockaddr *)&un,
                offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name)) == 0) return 19;
    close(fd);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in remote = {{0}};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(443);
    inet_pton(AF_INET, "1.1.1.1", &remote.sin_addr);
    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) == 0) return 20;
    close(fd);
    return 0;
}}
""",
        encoding="utf-8",
    )
    compiled = subprocess.run(
        ("gcc", "-static", "-O2", "-o", executable, source),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if compiled.returncode != 0:
        pytest.skip(f"static namespace probe unavailable: {compiled.stderr[:200]}")
    return executable


def test_controller_mount_and_network_namespace_mechanically_exclude_authority(
    tmp_path: Path,
):
    auth_source = tmp_path / "synthetic-auth.json"
    auth_source.write_bytes(SYNTHETIC_AUTHENTICATION)
    auth_homes = tmp_path / "private-homes"
    auth_homes.mkdir()
    unrelated = tmp_path / "unrelated-source-repository"
    unrelated.mkdir()
    host_socket_path = tmp_path / "host-manager.sock"
    host_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    host_listener.bind(os.fspath(host_socket_path))
    abstract_name = f"admissible-host-abstract-{os.getpid()}"
    abstract_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abstract_listener.bind("\0" + abstract_name)
    probe = _compile_static_controller_probe(
        tmp_path,
        auth_source=auth_source,
        auth_homes=auth_homes,
        unrelated_repository=unrelated,
        host_socket=host_socket_path,
        abstract_name=abstract_name,
    )
    control_data = tmp_path / "authority.json"
    control_data.write_text('{"synthetic":true}\n', encoding="utf-8")
    control_descriptor = os.open(control_data, os.O_RDONLY | os.O_CLOEXEC)
    app_parent, app_child = socket.socketpair()
    broker_parent, broker_child = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    try:
        policy = ControllerConfinementLaunchPolicy(
            bwrap_identity=ExecutableFileIdentity.attest(
                Path("/usr/bin/bwrap"), label="test bubblewrap"
            ),
            controller_identity=ExecutableFileIdentity.attest(
                probe, label="static controller probe"
            ),
            control_data_descriptors={
                "/control/data/authority.json": control_descriptor
            },
            app_server_descriptor=app_child.fileno(),
            capsule_broker_descriptor=broker_child.fileno(),
        )
        with policy.descriptor_launch() as launch:
            completed = subprocess.run(
                launch.argv,
                executable=launch.executable,
                pass_fds=launch.pass_fds,
                capture_output=True,
                env=dict(launch.environment),
                cwd=launch.cwd,
                check=False,
                timeout=10,
            )
        assert completed.returncode == 0, completed.stderr.decode(
            "utf-8", "replace"
        )
    finally:
        os.close(control_descriptor)
        for item in (app_parent, app_child, broker_parent, broker_child):
            item.close()
        host_listener.close()
        abstract_listener.close()


def test_landlock_defense_in_depth_denies_new_path_opens(tmp_path: Path):
    target = tmp_path / "synthetic-secret"
    target.write_bytes(SYNTHETIC_AUTHENTICATION)
    pid = os.fork()
    if pid == 0:
        try:
            available = apply_landlock_deny_new_path_access()
            if not available:
                os._exit(77)
            try:
                os.open(target, os.O_RDONLY)
            except PermissionError:
                os._exit(0)
            os._exit(3)
        except BaseException:
            os._exit(4)
    _waited, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 77:
        pytest.skip("Landlock unavailable; mount namespace remains primary")
    assert code == 0


def test_codex_launch_uses_sealed_fd_arguments_private_namespaces_and_no_auth_path(
    tmp_path: Path,
):
    if shutil.which("gcc") is None:
        pytest.skip("Codex launch-shape witness requires local gcc")
    source = tmp_path / "minimal.c"
    executable = tmp_path / "minimal-static"
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
    synthetic_source = tmp_path / "synthetic-login-source.json"
    synthetic_source.write_bytes(SYNTHETIC_AUTHENTICATION)
    home = tmp_path / "broker-owned-home"
    home.mkdir(mode=0o700)
    binding = candidate_canary_binding()
    launch_model_authority = binding["authority"]
    (home / "config.toml").write_bytes(
        launch_model_authority.ephemeral_config_bytes
    )
    home_descriptor = os.open(
        home,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    app_left, app_right = socket.socketpair()
    transfer_left, transfer_right = make_seqpacket_socketpair()
    try:
        policy = CodexConfinementLaunchPolicy(
            bwrap_identity=ExecutableFileIdentity.attest(
                Path("/usr/bin/bwrap"), label="Codex launch bwrap"
            ),
            codex_identity=ExecutableFileIdentity.attest(
                binding["codex"], label="verified pinned Codex"
            ),
            namespace_bootstrap_identity=ExecutableFileIdentity.attest(
                executable, label="synthetic namespace bootstrap"
            ),
            codex_home_descriptor=home_descriptor,
            app_server_descriptor=app_right.fileno(),
            proxy_transfer_descriptor=transfer_right.fileno(),
            session_id="synthetic-codex-launch",
            pin_fingerprint="9" * 64,
            runtime_dependency_descriptors={},
            model_authority=launch_model_authority,
        )
        with policy.descriptor_launch() as launch:
            assert launch.argv[:2] == ("bwrap-content-attested", "--args")
            assert os.fspath(synthetic_source) not in launch.argv
            assert set(launch.environment) == {"LANG", "LC_ALL", "HOME"}
            arguments_descriptor = int(launch.argv[2])
            os.lseek(arguments_descriptor, 0, os.SEEK_SET)
            arguments = os.read(arguments_descriptor, 64 * 1024).split(b"\0")
            assert b"--unshare-all" in arguments
            assert b"--unshare-user" in arguments
            assert b"--disable-userns" in arguments
            assert b"--clearenv" in arguments
            assert b"--bind-fd" in arguments
            assert b"/control/codex-home" in arguments
            assert b"/etc/resolv.conf" not in arguments
            assert b"/var/run/docker.sock" not in arguments
            assert os.fspath(synthetic_source).encode() not in b"\0".join(
                arguments
            )
            os.lseek(arguments_descriptor, 0, os.SEEK_SET)
            completed = subprocess.run(
                launch.argv,
                executable=launch.executable,
                pass_fds=launch.pass_fds,
                capture_output=True,
                env=dict(launch.environment),
                cwd=launch.cwd,
                check=False,
                timeout=10,
            )
            assert completed.returncode == 0, completed.stderr.decode(
                "utf-8", "replace"
            )
    finally:
        os.close(home_descriptor)
        for item in (app_left, app_right, transfer_left, transfer_right):
            item.close()


def test_capsule_broker_refuses_host_bind_escalation_and_cleans_exact_objects(
    tmp_path: Path,
    docker_ready,
):
    synthetic_auth = tmp_path / "synthetic-auth.json"
    synthetic_auth.write_bytes(SYNTHETIC_AUTHENTICATION)
    client = CapsuleBrokerProcess.start(
        CapsuleBrokerConfig(
            workspace_root=tmp_path / "broker-workspaces",
            frozen_output_root=tmp_path / "broker-output",
            limits=DockerCapsuleLimits(image_identity=IMAGE_IDENTITY),
        )
    )
    assert not hasattr(client, "docker_executable")
    assert not hasattr(client, "docker_identity")
    assert client.controller_authority.to_dict()["docker_socket_visible"] is False
    broker_descendants = _process_descendants(client.process_pid)
    sandboxed = tuple(
        pid
        for pid in broker_descendants
        if Path(f"/proc/{pid}/root/runtime/docker").exists()
    )
    assert sandboxed, "capsule broker did not enter its empty mount namespace"
    synthetic_from_broker_root = synthetic_auth.relative_to("/")
    for pid in sandboxed:
        assert not (
            Path(f"/proc/{pid}/root") / synthetic_from_broker_root
        ).exists()
        command_line = Path(f"/proc/{pid}/cmdline").read_bytes()
        environment = Path(f"/proc/{pid}/environ").read_bytes()
        assert os.fspath(synthetic_auth).encode() not in command_line
        assert os.fspath(synthetic_auth).encode() not in environment
        assert SYNTHETIC_AUTHENTICATION.strip() not in command_line
        assert SYNTHETIC_AUTHENTICATION.strip() not in environment

    with pytest.raises(BrokerProtocolError, match="refused"):
        client._request(
            operation="CREATE_SESSION",
            handle=None,
            backend_session_id="attack-session",
            controller_session_id="attack-controller",
            capsule_session_id="attack-capsule",
            tool_call_identity="docker-escalation-attack",
            payload={
                "workspace_id": "attack-workspace",
                "mission_authority_fingerprint": "b" * 64,
                "host_bind_path": os.fspath(synthetic_auth),
                "docker_command": [
                    "run",
                    "-v",
                    f"{synthetic_auth}:/loot/auth.json",
                ],
            },
        )

    handle = client.prepare(
        session_id="authorized-session",
        workspace_id="authorized-workspace",
        mission_authority_fingerprint="c" * 64,
    )
    container_name = handle.container_name
    volume_name = handle.volume_name
    for sequence, argv in (
        (
            1,
            ["/usr/bin/test", "!", "-e", os.fspath(synthetic_auth)],
        ),
        (
            2,
            ["/usr/bin/test", "!", "-S", "/var/run/docker.sock"],
        ),
    ):
        request = DurableToolRequest.create(
            session_id=handle.session_id,
            controller_session_id=handle.controller_session_id,
            capsule_handle=handle.capsule_handle,
            mission_authority_fingerprint=handle.mission_authority_fingerprint,
            sequence=sequence,
            rpc_id=sequence,
            call_id=f"call-{sequence}",
            thread_id="thread-synthetic",
            turn_id="turn-synthetic",
            namespace="capsule_effects",
            tool="run_command",
            arguments={"argv": argv, "cwd": ".", "timeout_ms": 3000},
        )
        result = client.execute(handle, request)
        assert result.classification == ToolTerminalClassification.SUCCEEDED

    observation = client.freeze_output(handle)
    cleanup = client.cleanup(handle)
    binding = client.bind_frozen_snapshot(
        handle,
        journal_tail_fingerprint="d" * 64,
        cleanup_fingerprint=fingerprint(cleanup.to_dict()),
    )
    assert observation.file_count == 0
    assert cleanup.cleanup_proven
    assert len(binding) == 64
    terminal = client.shutdown()
    assert terminal["broker_exit_normal"] is True
    assert _docker("inspect", container_name).returncode != 0
    assert _docker("volume", "inspect", volume_name).returncode != 0


def test_capsule_broker_forced_exit_recovery_proves_ownership_and_cleans(
    tmp_path: Path,
    docker_ready,
):
    config = CapsuleBrokerConfig(
        workspace_root=tmp_path / "crash-workspaces",
        frozen_output_root=tmp_path / "crash-output",
        limits=DockerCapsuleLimits(image_identity=IMAGE_IDENTITY),
    )
    client = CapsuleBrokerProcess.start(config)
    handle = client.prepare(
        session_id="broker-crash-session",
        workspace_id="broker-crash-workspace",
        mission_authority_fingerprint="f" * 64,
    )
    os.kill(client.process_pid, 9)
    os.waitpid(client.process_pid, 0)
    client._transport.close()
    recovery = CapsuleBrokerProcess.recover_after_forced_exit(
        config,
        (handle,),
    )
    assert recovery["classification"] == "FAILED_CLEANED"
    assert recovery["ownership_proved_before_removal"] is True
    assert recovery["docker_absence_inferred_from_failure"] is False
    assert _docker("inspect", handle.container_name).returncode != 0
    assert _docker("volume", "inspect", handle.volume_name).returncode != 0


def test_capsule_broker_endpoint_handoff_reconstructs_closed_controller_client(
    tmp_path: Path,
    docker_ready,
):
    original = CapsuleBrokerProcess.start(
        CapsuleBrokerConfig(
            workspace_root=tmp_path / "handoff-workspaces",
            frozen_output_root=tmp_path / "handoff-output",
            limits=DockerCapsuleLimits(image_identity=IMAGE_IDENTITY),
        )
    )
    descriptor, metadata = original.release_for_confined_controller()
    rendered = canonical_bytes(metadata)
    assert b"synthetic-auth" not in rendered
    assert b"/var/run/docker.sock" not in rendered
    attached = CapsuleBrokerClient.from_inherited_controller_handoff(
        descriptor,
        metadata,
    )
    terminal = attached.shutdown()
    assert terminal["broker_reap_owner"] == "boundary_launcher"
    assert terminal["broker_exit_code"] is None
    waited, status = os.waitpid(original.process_pid, 0)
    assert waited == original.process_pid
    assert os.waitstatus_to_exitcode(status) == 0


def test_broker_transport_refuses_duplicate_keys_oversize_and_descriptors():
    left, right = make_seqpacket_socketpair()
    try:
        left.send(b'{"operation":"x","operation":"y"}')
        with pytest.raises(ValueError, match="duplicate"):
            receive_packet(right)
        with pytest.raises(BrokerProtocolError, match="byte bound"):
            send_packet(left, {"value": "x" * MAX_BROKER_MESSAGE_BYTES})
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        try:
            send_packet(left, {"value": "bounded"}, descriptors=(descriptor,))
            with pytest.raises(BrokerProtocolError, match="truncated|too many"):
                receive_packet(right, max_descriptors=0)
        finally:
            os.close(descriptor)
    finally:
        left.close()
        right.close()


def _generate_local_certificate(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("synthetic TLS witness requires local openssl")
    key = tmp_path / "tls-key.pem"
    certificate = tmp_path / "tls-cert.pem"
    result = subprocess.run(
        (
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=synthetic.test",
            "-addext",
            "subjectAltName=DNS:synthetic.test",
            "-keyout",
            key,
            "-out",
            certificate,
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return certificate, key


def test_egress_relay_seals_dns_tunnels_tls_and_records_no_plaintext(
    tmp_path: Path,
):
    certificate, key = _generate_local_certificate(tmp_path)
    tls_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_listener.bind(("127.0.0.1", 0))
    tls_listener.listen(4)
    tls_port = tls_listener.getsockname()[1]
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    server_errors: list[str] = []

    def tls_server():
        for _ in range(2):
            raw, _address = tls_listener.accept()
            try:
                with server_context.wrap_socket(raw, server_side=True) as secured:
                    value = secured.recv(4096)
                    if value:
                        secured.sendall(b"synthetic-response:" + value)
            except ssl.SSLError as error:
                server_errors.append(type(error).__name__)
            finally:
                raw.close()

    server_thread = threading.Thread(target=tls_server, daemon=True)
    server_thread.start()

    manifest = _synthetic_manifest()
    resolver_calls: list[tuple[str, int]] = []

    def resolver(hostname: str, port: int):
        resolver_calls.append((hostname, port))
        return ["127.0.0.1"]

    pins = resolve_and_seal(
        manifest,
        session_id="synthetic-egress-session",
        resolver=resolver,
        synthetic_provider_free=True,
    )
    assert resolver_calls == [("synthetic.test", 443)]
    with pytest.raises(ValueError, match="exact destination"):
        SealedDestinationPinManifest.create(
            authority_manifest=manifest,
            session_id="synthetic-egress-session",
            resolved={("unauthorized.test", 443): ["127.0.0.1"]},
            synthetic_provider_free=True,
        )

    namespace_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    namespace_listener.bind(("127.0.0.1", 0))
    namespace_listener.listen(8)
    transfer_left, transfer_right = make_seqpacket_socketpair()
    send_listener_descriptor(
        transfer_left,
        namespace_listener,
        session_id=pins.session_id,
        pin_fingerprint=pins.pin_fingerprint,
    )
    relay_listener = receive_listener_descriptor(
        transfer_right,
        expected_session_id=pins.session_id,
        expected_pin_fingerprint=pins.pin_fingerprint,
    )
    namespace_listener.close()
    transfer_left.close()
    transfer_right.close()

    def synthetic_connector(address: str, port: int, timeout: float):
        assert address == "127.0.0.1"
        assert port == 443
        return socket.create_connection(("127.0.0.1", tls_port), timeout=timeout)

    journal = DurableEgressJournal(
        tmp_path / "egress-journal",
        session_id=pins.session_id,
    )
    relay = PreventiveEgressRelay(
        listener=relay_listener,
        pins=pins,
        journal=journal,
        budgets=EgressBudgets(
            connection_timeout_seconds=2,
            connection_duration_seconds=10,
            per_connection_bytes=1024 * 1024,
            session_bytes=2 * 1024 * 1024,
            concurrency=2,
            connections=4,
        ),
        synthetic_connector=synthetic_connector,
    )
    relay_address = relay_listener.getsockname()
    relay_thread = threading.Thread(target=relay.serve, daemon=True)
    relay_thread.start()

    plaintext = b"synthetic-application-plaintext"
    proxy = socket.create_connection(relay_address, timeout=3)
    proxy.sendall(
        b"CONNECT synthetic.test:443 HTTP/1.1\r\n"
        b"Host: synthetic.test:443\r\n\r\n"
    )
    assert b"200 Connection Established" in proxy.recv(4096)
    trusted_context = ssl.create_default_context(cafile=os.fspath(certificate))
    with trusted_context.wrap_socket(
        proxy,
        server_hostname="synthetic.test",
    ) as secured:
        secured.sendall(plaintext)
        assert secured.recv(4096) == b"synthetic-response:" + plaintext

    wrong_ca = socket.create_connection(relay_address, timeout=3)
    wrong_ca.sendall(
        b"CONNECT synthetic.test:443 HTTP/1.1\r\n"
        b"Host: synthetic.test:443\r\n\r\n"
    )
    assert b"200 Connection Established" in wrong_ca.recv(4096)
    with pytest.raises(ssl.SSLError):
        ssl.create_default_context().wrap_socket(
            wrong_ca,
            server_hostname="synthetic.test",
        )

    unauthorized = socket.create_connection(relay_address, timeout=3)
    unauthorized.sendall(
        b"CONNECT redirect.test:443 HTTP/1.1\r\n"
        b"Host: redirect.test:443\r\n\r\n"
    )
    assert b"403 Forbidden" in unauthorized.recv(4096)
    unauthorized.close()

    server_thread.join(timeout=5)
    tls_listener.close()
    terminal = relay.stop()
    relay_thread.join(timeout=5)
    assert terminal["tls_terminated"] is False
    assert terminal["headers_or_bodies_recorded"] is False
    assert terminal["live_workers"] == 0
    assert resolver_calls == [("synthetic.test", 443)]
    evidence_bytes = (
        tmp_path
        / "egress-journal"
        / "synthetic-egress-session.egress.jsonl"
    ).read_bytes()
    assert plaintext not in evidence_bytes
    assert b"Host:" not in evidence_bytes
    assert b"CONNECT " not in evidence_bytes
    assert any(
        item.terminal_classification == "PROTOCOL_REFUSED"
        for item in relay.records
    )
    assert server_errors  # wrong-CA client abort is observed only as TLS failure


def test_production_pin_manifest_rejects_private_loopback_and_link_local():
    manifest = _synthetic_manifest()
    for address in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fe80::1"):
        with pytest.raises(ValueError, match="not public"):
            SealedDestinationPinManifest.create(
                authority_manifest=manifest,
                session_id="production-pin-session",
                resolved={("synthetic.test", 443): [address]},
                synthetic_provider_free=False,
            )
