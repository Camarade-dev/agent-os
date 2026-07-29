"""Provider-free Docker E2E for the sealed capsule execution authority.

The local, already-present Ubuntu image runs only synthetic file/shell
requests. No model, app-server, provider, API, login, or network is used.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from admissible.capsule.docker_controller import DockerCapsuleController, DockerCapsuleLimits
from admissible.capsule.session_store import DurableToolRequest, ToolTerminalClassification


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
    identity = result.stdout.strip()
    assert identity.startswith("sha256:") and len(identity) == 71
    return identity


def _request(
    handle,
    sequence: int,
    tool: str,
    arguments,
    *,
    rpc_id: int | None = None,
) -> DurableToolRequest:
    return DurableToolRequest.create(
        session_id=handle.session_id,
        controller_session_id=handle.controller_session_id,
        capsule_handle=handle.capsule_handle,
        mission_authority_fingerprint=handle.mission_authority_fingerprint,
        sequence=sequence,
        rpc_id=rpc_id or 100 + sequence,
        call_id=f"call-{sequence:03d}",
        thread_id="thread-001",
        turn_id="turn-001",
        namespace="capsule_effects",
        tool=tool,
        arguments=arguments,
    )


def test_sealed_docker_controller_executes_only_in_capsule_and_reaps_descendants(
    tmp_path: Path, local_ubuntu_identity: str
):
    limits = DockerCapsuleLimits(
        image_identity=local_ubuntu_identity,
        command_timeout_seconds=4,
        session_timeout_seconds=30,
        output_limit_bytes=16 * 1024,
    )
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=limits,
    )
    handle = controller.prepare(
        session_id="docker-session-001",
        workspace_id="workspace-docker-001",
    )
    try:
        inspect_result = _docker("inspect", handle.container_id)
        assert inspect_result.returncode == 0
        inspection = json.loads(inspect_result.stdout)[0]
        host_config = inspection["HostConfig"]
        configuration = inspection["Config"]
        assert configuration["User"] == f"{os.getuid()}:{os.getgid()}"
        assert host_config["ReadonlyRootfs"] is True
        assert host_config["CapDrop"] == ["ALL"]
        assert host_config["SecurityOpt"] == ["no-new-privileges:true"]
        assert host_config["NetworkMode"] == "none"
        assert host_config["PidsLimit"] == limits.pids
        assert host_config["Memory"] == 256 * 1024 * 1024
        assert inspection["State"]["Running"] is True
        assert any(mount["Destination"] == "/workspace" for mount in inspection["Mounts"])
        inspect_text = json.dumps(inspection, sort_keys=True)
        assert "/var/run/docker.sock" not in inspect_text
        assert "OPENAI_API_KEY" not in inspect_text
        assert "auth.json" not in inspect_text

        write = controller.execute(
            handle,
            _request(
                handle,
                1,
                "write_file",
                {
                    "path": "src/inside.txt",
                    "content": "written only through docker exec\n",
                    "operation": "create",
                },
            ),
        )
        assert write.classification == ToolTerminalClassification.SUCCEEDED
        assert not (handle.source_path / "src" / "inside.txt").exists()
        assert not (tmp_path / "src" / "inside.txt").exists()
        duplicate_create = controller.execute(
            handle,
            _request(
                handle,
                8,
                "write_file",
                {
                    "path": "src/inside.txt",
                    "content": "must not replace\n",
                    "operation": "create",
                },
            ),
        )
        assert duplicate_create.classification == ToolTerminalClassification.FAILED
        missing_replace = controller.execute(
            handle,
            _request(
                handle,
                9,
                "write_file",
                {
                    "path": "missing.txt",
                    "content": "must not create\n",
                    "operation": "replace",
                },
            ),
        )
        assert missing_replace.classification == ToolTerminalClassification.FAILED

        shell = controller.execute(
            handle,
            _request(
                handle,
                2,
                "run_command",
                {
                    "argv": [
                        "/bin/sh",
                        "-c",
                        "printf 'shell ran only in capsule\\n' > shell.txt",
                    ],
                    "cwd": ".",
                    "timeout_ms": 2000,
                },
            ),
        )
        assert shell.classification == ToolTerminalClassification.SUCCEEDED

        auth_absence = controller.execute(
            handle,
            _request(
                handle,
                3,
                "run_command",
                {
                    "argv": [
                        "/bin/sh",
                        "-c",
                        (
                            "test ! -e /control/codex-home/auth.json "
                            "&& test ! -e /root/.codex/auth.json "
                            "&& test -z \"${OPENAI_API_KEY:-}\" "
                            "&& printf 'AUTHENTICATION_ABSENT\\n'"
                        ),
                    ],
                    "cwd": ".",
                    "timeout_ms": 2000,
                },
            ),
        )
        assert auth_absence.classification == ToolTerminalClassification.SUCCEEDED
        assert auth_absence.stdout == "AUTHENTICATION_ABSENT\n"

        outside = controller.execute(
            handle,
            _request(
                handle,
                4,
                "read_file",
                {"path": "../outside.txt"},
            ),
        )
        assert outside.classification == ToolTerminalClassification.REFUSED
        assert "traversal" in outside.stderr

        listing = controller.execute(
            handle,
            _request(handle, 5, "list_files", {"path": ".", "max_depth": 3}),
        )
        assert listing.classification == ToolTerminalClassification.SUCCEEDED
        assert "src/inside.txt" in listing.stdout
        assert "shell.txt" in listing.stdout

        read = controller.execute(
            handle,
            _request(handle, 6, "read_file", {"path": "shell.txt"}),
        )
        assert read.classification == ToolTerminalClassification.SUCCEEDED
        assert read.stdout == "shell ran only in capsule\n"

        descendant = controller.execute(
            handle,
            _request(
                handle,
                7,
                "run_command",
                {
                    "argv": [
                        "/bin/sh",
                        "-c",
                        "sleep 300 >/dev/null 2>&1 & printf '%s\\n' \"$!\"",
                    ],
                    "cwd": ".",
                    "timeout_ms": 2000,
                },
            ),
        )
        assert descendant.classification == ToolTerminalClassification.REFUSED
        assert "surviving descendant" in descendant.stderr
        assert handle.container_alive is True
        assert handle.container_quarantined is True

        observation = controller.freeze_output(handle)
        observed_paths = {entry.relative_path for entry in observation.entries}
        assert {"src", "src/inside.txt", "shell.txt"} <= observed_paths
        assert (handle.frozen_path / "src" / "inside.txt").read_text() == (
            "written only through docker exec\n"
        )
        assert not (handle.frozen_path / "missing.txt").exists()
        assert ".git" not in observed_paths
        cleanup = controller.cleanup(handle)
        assert cleanup.cleanup_proven is True
        assert cleanup.frozen_output_retained is True
        assert not handle.source_path.exists()
        assert handle.frozen_path.is_dir()
        assert _docker("inspect", handle.container_id).returncode != 0
        assert (
            _docker(
                "ps",
                "--all",
                "--quiet",
                "--filter",
                "label=admissible.capsule.session=docker-session-001",
            ).stdout.strip()
            == ""
        )
    finally:
        try:
            controller.cleanup(handle)
        except RuntimeError:
            pass


def test_controller_command_line_contains_every_required_security_boundary(
    tmp_path: Path, local_ubuntu_identity: str
):
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity=local_ubuntu_identity),
    )
    argv = controller.docker_run_argv(
        session_id="docker-session-001",
        volume_name="admissible-workspace-test",
        container_name="admissible-capsule-policy-test",
        capsule_handle="capsule-policy-test",
        mission_authority_fingerprint="a" * 64,
    )
    joined = " ".join(argv)
    for boundary in (
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--network none",
        "--pids-limit 64",
        "--memory 256m",
        "--memory-swap 256m",
        "--cpus 0.50",
        "--init",
        f"--user {os.getuid()}:{os.getgid()}",
    ):
        assert boundary in joined
    assert "/var/run/docker.sock" not in joined
    assert "OPENAI_API_KEY" not in joined
    assert ".codex" not in joined
    assert local_ubuntu_identity in argv
    assert "ubuntu:24.04" not in argv


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"cpus": "0.5"}, "canonical"),
        ({"cpus": "nan"}, "canonical"),
        ({"memory": "256M"}, "canonical"),
        ({"memory": "0m"}, "canonical"),
        ({"pids": 0}, "PID"),
    ],
)
def test_invalid_docker_resource_strings_are_refused(changes, message):
    values = {
        "image_identity": "sha256:" + "a" * 64,
        **changes,
    }
    with pytest.raises(ValueError, match=message):
        DockerCapsuleLimits(**values).validated()


def test_ambient_fake_docker_executable_is_never_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake = fake_bin / "docker"
    fake.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    fake.chmod(0o700)
    monkeypatch.setenv("PATH", str(fake_bin))
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity="sha256:" + "a" * 64),
    )
    assert controller.docker_executable != str(fake)
    assert Path(controller.docker_executable).is_absolute()
    assert controller.docker_identity.reattest(label="Docker executable")


def test_symlinked_or_overlapping_docker_roots_are_refused(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real.name, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked component"):
        DockerCapsuleController(
            workspace_root=alias / "workspaces",
            frozen_output_root=tmp_path / "frozen",
            limits=DockerCapsuleLimits(image_identity="sha256:" + "a" * 64),
        )
    with pytest.raises(ValueError, match="must not overlap"):
        DockerCapsuleController(
            workspace_root=tmp_path / "same",
            frozen_output_root=tmp_path / "same" / "frozen",
            limits=DockerCapsuleLimits(image_identity="sha256:" + "a" * 64),
        )


def test_docker_inspect_communication_failure_is_unknown_not_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity="sha256:" + "a" * 64),
    )
    monkeypatch.setattr(
        controller,
        "_capture",
        lambda *args, **kwargs: SimpleNamespace(
            timed_out=False,
            exit_code=1,
            stdout=b"",
            stderr=b"Cannot connect to the Docker daemon",
        ),
    )
    with pytest.raises(RuntimeError, match="UNKNOWN"):
        controller._inspect_object("container", "container-unknown")


def test_colliding_docker_object_without_exact_labels_is_never_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity="sha256:" + "a" * 64),
    )
    removed = []
    monkeypatch.setattr(
        controller,
        "_inspect_object",
        lambda kind, identifier: {
            "Config": {"Labels": {"admissible.capsule.session": "another-session"}}
        },
    )
    monkeypatch.setattr(
        controller,
        "_capture",
        lambda *args, **kwargs: removed.append(args) or None,
    )
    with pytest.raises(RuntimeError, match="authority labels"):
        controller._remove_owned_object(
            "container",
            "colliding-name",
            {
                "admissible.capsule.session": "this-session",
                "admissible.capsule.controller": "a" * 64,
                "admissible.capsule.handle": "this-handle",
                "admissible.capsule.mission": "b" * 64,
            },
        )
    assert removed == []


def test_image_tag_mutation_is_refused_before_capsule_launch(
    tmp_path: Path,
    local_ubuntu_identity: str,
):
    wrong_identity = (
        "sha256:" + ("0" if local_ubuntu_identity[7] != "0" else "1") + local_ubuntu_identity[8:]
    )
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity=wrong_identity),
    )
    with pytest.raises(RuntimeError, match="content identity"):
        controller.prepare(
            session_id="tag-mutation-session",
            workspace_id="tag-mutation-workspace",
        )
    assert not (tmp_path / "disposable" / "tag-mutation-workspace").exists()


def test_cross_session_request_cannot_execute_against_supplied_handle(
    tmp_path: Path,
    local_ubuntu_identity: str,
):
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity=local_ubuntu_identity),
    )
    handle = controller.prepare(
        session_id="exact-session",
        workspace_id="exact-workspace",
    )
    try:
        request = DurableToolRequest.create(
            session_id="another-session",
            controller_session_id=handle.controller_session_id,
            capsule_handle=handle.capsule_handle,
            mission_authority_fingerprint=handle.mission_authority_fingerprint,
            sequence=1,
            rpc_id=60,
            call_id="cross-session-call",
            thread_id="thread-001",
            turn_id="turn-001",
            namespace="capsule_effects",
            tool="write_file",
            arguments={
                "path": "must-not-exist.txt",
                "content": "forbidden\n",
                "operation": "create",
            },
        )
        result = controller.execute(handle, request)
        assert result.classification == ToolTerminalClassification.REFUSED
        listing = controller.execute(
            handle,
            _request(handle, 2, "list_files", {"path": ".", "max_depth": 1}),
        )
        assert "must-not-exist.txt" not in listing.stdout
    finally:
        controller.freeze_output(handle)
        assert controller.cleanup(handle).cleanup_proven


def test_hard_workspace_quota_is_enforced_during_execution(
    tmp_path: Path,
    local_ubuntu_identity: str,
):
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(
            image_identity=local_ubuntu_identity,
            tree_bytes_limit=4096,
            write_limit_bytes=4096,
        ),
    )
    handle = controller.prepare(
        session_id="hard-quota-session",
        workspace_id="hard-quota-workspace",
    )
    try:
        result = controller.execute(
            handle,
            _request(
                handle,
                1,
                "run_command",
                {
                    "argv": [
                        "/bin/sh",
                        "-c",
                        "dd if=/dev/zero of=overflow.bin bs=8192 count=1 status=none",
                    ],
                    "cwd": ".",
                    "timeout_ms": 2000,
                },
            ),
        )
        assert result.classification != ToolTerminalClassification.SUCCEEDED
        observation = controller.freeze_output(handle)
        assert sum(
            entry.size for entry in observation.entries if entry.kind == "regular"
        ) <= 4096
    finally:
        assert controller.cleanup(handle).cleanup_proven


@pytest.mark.parametrize(
    "command, expected",
    [
        ("ln -s target forbidden-link", "symlink or special"),
        ("printf x > hard-a; ln hard-a hard-b", "hard-linked"),
        ("mkfifo forbidden-fifo", "symlink or special"),
        ("touch Case.txt case.txt", "collision"),
    ],
)
def test_ambiguous_execution_tree_is_quarantined_before_another_effect(
    tmp_path: Path,
    local_ubuntu_identity: str,
    command: str,
    expected: str,
):
    controller = DockerCapsuleController(
        workspace_root=tmp_path / "disposable",
        frozen_output_root=tmp_path / "provider-output",
        limits=DockerCapsuleLimits(image_identity=local_ubuntu_identity),
    )
    handle = controller.prepare(
        session_id="ambiguous-tree-session",
        workspace_id="ambiguous-tree-workspace",
    )
    try:
        result = controller.execute(
            handle,
            _request(
                handle,
                1,
                "run_command",
                {
                    "argv": ["/bin/sh", "-c", command],
                    "cwd": ".",
                    "timeout_ms": 2000,
                },
            ),
        )
        assert result.classification == ToolTerminalClassification.REFUSED
        assert expected in result.stderr
        assert handle.container_quarantined is True
        second = controller.execute(
            handle,
            _request(handle, 2, "list_files", {"path": ".", "max_depth": 1}),
        )
        assert second.classification == ToolTerminalClassification.REFUSED
        assert "quarantined" in second.stderr
        # The frozen publication must fail closed. Some invalid source types
        # (notably hard links) can be refused by the no-capability extraction
        # process before the host-side manifest observer sees them.
        with pytest.raises((ValueError, RuntimeError)):
            controller.freeze_output(handle)
    finally:
        assert controller.cleanup(handle).cleanup_proven
