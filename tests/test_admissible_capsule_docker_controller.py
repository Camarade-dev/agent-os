"""Provider-free Docker E2E for the sealed capsule execution authority.

The local, already-present Ubuntu image runs only synthetic file/shell
requests. No model, app-server, provider, API, login, or network is used.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

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
    sequence: int,
    tool: str,
    arguments,
    *,
    rpc_id: int | None = None,
) -> DurableToolRequest:
    return DurableToolRequest.create(
        session_id="docker-session-001",
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
        assert (handle.source_path / "src" / "inside.txt").read_text() == (
            "written only through docker exec\n"
        )
        assert not (tmp_path / "src" / "inside.txt").exists()

        shell = controller.execute(
            handle,
            _request(
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
                4,
                "read_file",
                {"path": "../outside.txt"},
            ),
        )
        assert outside.classification == ToolTerminalClassification.REFUSED
        assert "escapes" in outside.stderr

        listing = controller.execute(
            handle,
            _request(5, "list_files", {"path": ".", "max_depth": 3}),
        )
        assert listing.classification == ToolTerminalClassification.SUCCEEDED
        assert "src/inside.txt" in listing.stdout
        assert "shell.txt" in listing.stdout

        read = controller.execute(
            handle,
            _request(6, "read_file", {"path": "shell.txt"}),
        )
        assert read.classification == ToolTerminalClassification.SUCCEEDED
        assert read.stdout == "shell ran only in capsule\n"

        descendant = controller.execute(
            handle,
            _request(
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
        assert descendant.classification == ToolTerminalClassification.SUCCEEDED
        assert descendant.stdout.strip().isdigit()

        observation = controller.freeze_output(handle)
        observed_paths = {entry.relative_path for entry in observation.entries}
        assert {"src", "src/inside.txt", "shell.txt"} <= observed_paths
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
        _docker("rm", "--force", handle.container_name)


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
        source_path=tmp_path / "workspace",
        container_name="admissible-capsule-policy-test",
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

