"""Packaging and isolated-import compatibility for the capsule package."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_package_discovery_configuration_includes_the_capsule_package():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    includes = project["tool"]["setuptools"]["packages"]["find"]["include"]
    assert "admissible*" in includes
    assert (ROOT / "admissible" / "capsule" / "__init__.py").is_file()
    assert project["build-system"]["requires"] == [
        "setuptools==75.8.2",
        "wheel==0.45.1",
    ]
    assert project["tool"]["setuptools"]["data-files"]["share/doc/agent-os"] == [
        "docs/admissible-host-codex-capsule-backend.md",
        "docs/admissible-codex-os-boundary.md",
    ]


def test_capsule_imports_from_an_isolated_package_tree(tmp_path: Path):
    installation = tmp_path / "installation"
    shutil.copytree(
        ROOT / "admissible",
        installation / "admissible",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    program = textwrap.dedent(
        f"""
        import json
        import pathlib
        import sys
        installation = pathlib.Path({str(installation)!r})
        sys.path.insert(0, str(installation))
        import admissible.capsule as capsule
        origins = {{
            name: str(pathlib.Path(getattr(capsule, name).__module__.replace(".", "/")))
            for name in (
                "AcceptedMaterialIdentity",
                "CheckpointResult",
                "BehaviorResult",
                "FinalizationResult",
                "HostCodexAppServerCapsuleBackend",
            )
        }}
        package_origin = pathlib.Path(capsule.__file__).resolve()
        assert package_origin.is_relative_to(installation.resolve())
        print(json.dumps({{"origin": str(package_origin), "exports": sorted(origins)}}))
        """
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["exports"] == [
        "AcceptedMaterialIdentity",
        "BehaviorResult",
        "CheckpointResult",
        "FinalizationResult",
        "HostCodexAppServerCapsuleBackend",
    ]


def test_sdist_and_wheel_contain_backend_documentation_and_generated_schemas(
    tmp_path: Path,
):
    artifacts = tmp_path / "artifacts"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "build",
            "--outdir",
            str(artifacts),
            str(ROOT),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    sdist = next(artifacts.glob("*.tar.gz"))
    wheel = next(artifacts.glob("*.whl"))
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_names = set(archive.getnames())
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
        runtime_sources = {
            name: archive.read(name).decode("utf-8")
            for name in wheel_names
            if name.startswith("admissible/capsule/") and name.endswith(".py")
        }
        installation = tmp_path / "wheel-installation"
        archive.extractall(installation)

    assert any(
        name.endswith("/docs/admissible-host-codex-capsule-backend.md")
        for name in sdist_names
    )
    assert any(
        name.endswith("/docs/admissible-codex-os-boundary.md")
        for name in sdist_names
    )
    assert any(
        name.endswith(
            ".data/data/share/doc/agent-os/admissible-host-codex-capsule-backend.md"
        )
        for name in wheel_names
    )
    assert any(
        name.endswith(
            ".data/data/share/doc/agent-os/admissible-codex-os-boundary.md"
        )
        for name in wheel_names
    )
    required_schema_suffixes = {
        "admissible/capsule/protocol_schemas/manifest.json",
        "admissible/capsule/protocol_schemas/v1/InitializeParams.json",
        "admissible/capsule/protocol_schemas/v1/InitializeResponse.json",
        "admissible/capsule/protocol_schemas/v2/ThreadStartParams.json",
        "admissible/capsule/protocol_schemas/v2/TurnCompletedNotification.json",
        "admissible/capsule/broker_schemas/CapsuleBrokerRequest.json",
        "admissible/capsule/broker_schemas/CapsuleBrokerResult.json",
        "admissible/capsule/broker_schemas/AuthenticationBrokerRequest.json",
        "admissible/capsule/broker_schemas/AuthenticationBrokerResult.json",
        "admissible/capsule/broker_schemas/EgressRelayEvidence.json",
        "admissible/capsule/destination_manifests/codex-0.145.0-chatgpt.json",
    }
    assert required_schema_suffixes <= wheel_names
    assert all(
        "_agent-runs/" not in name
        and "spike" not in name.lower()
        and "\\" not in name
        and ":/" not in name
        for name in wheel_names
    )
    assert all(
        "/home/stris" not in source
        and re.search(r"(?<![A-Za-z])[A-Za-z]:[\\\\/]", source) is None
        for source in runtime_sources.values()
    )

    program = textwrap.dedent(
        f"""
        import pathlib
        import sys
        installation = pathlib.Path({str(installation)!r})
        sys.path.insert(0, str(installation))
        import admissible.capsule as capsule
        from admissible.capsule.codex_protocol import protocol_schema_identity
        assert pathlib.Path(capsule.__file__).resolve().is_relative_to(installation.resolve())
        assert len(protocol_schema_identity()) == 64
        assert capsule.PendingAuthenticationBoundary().state == "BLOCKED_PENDING_OS_ENFORCEMENT"
        """
    )
    imported = subprocess.run(
        [sys.executable, "-I", "-c", program],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env={"PATH": "/nonexistent", "HOME": "/nonexistent"},
    )
    assert imported.returncode == 0, imported.stderr
