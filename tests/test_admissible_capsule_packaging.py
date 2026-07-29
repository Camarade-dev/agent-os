"""Packaging and isolated-import compatibility for the capsule package."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_package_discovery_configuration_includes_the_capsule_package():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    includes = project["tool"]["setuptools"]["packages"]["find"]["include"]
    assert "admissible*" in includes
    assert (ROOT / "admissible" / "capsule" / "__init__.py").is_file()


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
