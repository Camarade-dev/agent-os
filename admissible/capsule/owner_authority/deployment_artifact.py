"""Build the unprivileged, deterministic broker deployment artifact.

The systemd unit the installer writes never runs ``python3 -m
admissible.capsule.owner_authority.broker_service`` against a developer
checkout --- a checkout is caller-writable, and a root service must never
execute a path an ordinary user can edit.  Instead it runs a single
deterministic zipapp built here, copied into place at a fixed root-owned path
by the privileged installer.

This module never runs as root and never needs to: building the artifact is
purely reading source files, filtering out anything that is not runtime
capsule code, and writing a zip.  The privileged half is only ever "copy these
exact, already-verified bytes to a root-owned path without executing them",
implemented below as :func:`copy_deployment_artifact_without_execute`.

What goes in
------------

Importing ``admissible.capsule.owner_authority.broker_service`` requires
Python to first import the ``admissible`` and ``admissible.capsule`` packages,
so the artifact stages the whole ``admissible`` source tree rather than trying
to hand-pick a minimal import closure.  It is filtered, deterministically, to
exclude:

* anything under a ``tests`` directory;
* ``__pycache__`` and compiled bytecode;
* any historical preparation, run or owner-preflight tree
  (``_agent-runs``, ``preparation``, ``owner-preflight``);
* private keys, installed installation records, sockets, lock files and
  authentication fixtures by exact name;
* any ``.py`` source that contains a forbidden byte marker (a PEM header, a
  known synthetic test phrase, a synthetic API key literal) --- staging
  refuses outright rather than silently omitting the file.

The result is exactly the runtime source this repository already ships in its
wheel, restaged as a single self-contained zipapp with a fixed, minimal
``__main__.py`` that does nothing but call the broker service entry point.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Sequence

from admissible.capsule.common import fingerprint, require_sha256, sha256_bytes
from admissible.capsule.owner_authority.layout import OwnerAuthorityError

ARTIFACT_SCHEMA_VERSION = "admissible_owner_authority_deployment_artifact_v1"

#: Fixed root-owned path the systemd unit must reference.
DEPLOYMENT_ARTIFACT_PATH = Path(
    "/opt/admissible-owner-authority-v1/broker.pyz"
)

#: Directory names never staged, wherever they occur in the tree.
_EXCLUDED_DIR_NAMES = frozenset(
    {
        "__pycache__",
        "tests",
        "_agent-runs",
        "owner-preflight",
        "preparation",
        ".git",
        ".pytest_cache",
    }
)

#: File suffixes never staged.
_EXCLUDED_FILE_SUFFIXES = (".pyc", ".pyo", ".pem")

#: Exact basenames never staged, even if something under ``admissible/`` were
#: ever to be named this way.
_EXCLUDED_FILE_NAMES = frozenset(
    {
        "owner-authority-signing-key.v1.pem",
        "owner-authority-signing-key.v1.pub.pem",
        "installation-v1.json",
        "broker.sock",
        "pending.json",
        "phrase-verified.json",
        "consumed.json",
        "receipt.json",
        "launch-result.json",
        "authorization.lock",
        "auth.json",
    }
)

#: Byte markers that must never appear in a staged ``.py`` source file.  This
#: mirrors the packaging test's forbidden-material list so the artifact and
#: the wheel make the same promise.
_FORBIDDEN_BYTE_MARKERS = (
    b"BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN PRIVATE KEY-----",
    b"BEGIN CERTIFICATE",
    b"synthetic-privilege-witness-owner-phrase",
    b"synthetic-external-owner-authority-phrase",
    b"synthetic-provider-free-owner-phrase-not-the-real-one",
    b"attacker-chosen-owner-phrase",
    b"attacker-chosen-phrase",
    b"synthetic-provider-free-key",
    b"SYNTHETIC_API_KEY",
)

_MAIN_SOURCE = (
    '"""Deterministic broker deployment artifact entry point.\n\n'
    "Does nothing but call the broker service entry point; every check the\n"
    "broker performs still runs from this same restaged source.\n"
    '"""\n\n'
    "import sys\n\n"
    "from admissible.capsule.owner_authority.broker_service import main\n\n"
    "if __name__ == \"__main__\":\n"
    "    raise SystemExit(main(sys.argv[1:]))\n"
)


class OwnerAuthorityDeploymentArtifactError(OwnerAuthorityError):
    """A refusal while building, staging or verifying the deployment artifact."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_ARTIFACT_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def _default_repository_root() -> Path:
    # owner_authority/deployment_artifact.py -> owner_authority -> capsule ->
    # admissible -> repository root.
    return Path(__file__).resolve().parents[3]


def _excluded(relative_parts: Sequence[str]) -> bool:
    return any(part in _EXCLUDED_DIR_NAMES for part in relative_parts[:-1])


def _verify_no_forbidden_material(path: Path, data: bytes) -> None:
    if path.suffix != ".py":
        return
    # This module itself defines the denylist markers as bytes literals.
    if path.name == "deployment_artifact.py":
        return
    for marker in _FORBIDDEN_BYTE_MARKERS:
        if marker in data:
            raise OwnerAuthorityDeploymentArtifactError(
                f"refusing to package {path}: contains a forbidden material "
                "marker",
                classification="OWNER_AUTHORITY_ARTIFACT_FORBIDDEN_MATERIAL",
            )


def _stage_admissible_tree(
    *, repository_root: Path, staging_root: Path
) -> list[tuple[str, str]]:
    """Copy the filtered ``admissible`` tree into ``staging_root``.

    Returns the sorted ``(relative_posix_path, sha256)`` manifest of every
    staged file, which becomes the artifact's contents fingerprint.
    """

    admissible_root = repository_root / "admissible"
    if not admissible_root.is_dir():
        raise OwnerAuthorityDeploymentArtifactError(
            f"no admissible package found under {repository_root}"
        )
    manifest: list[tuple[str, str]] = []
    for source in sorted(admissible_root.rglob("*")):
        if source.is_dir():
            continue
        relative = source.relative_to(repository_root)
        if _excluded(relative.parts):
            continue
        if source.suffix in _EXCLUDED_FILE_SUFFIXES:
            continue
        if source.name in _EXCLUDED_FILE_NAMES:
            continue
        data = source.read_bytes()
        _verify_no_forbidden_material(source, data)
        destination = staging_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        os.chmod(destination, 0o644)
        manifest.append((relative.as_posix(), sha256_bytes(data)))
    return manifest


def _write_deterministic_zipapp(*, staging_root: Path, output_path: Path) -> None:
    """Write a reproducible zipapp: fixed timestamps, sorted entries."""

    entries = sorted(path for path in staging_root.rglob("*") if path.is_file())
    descriptor, temp_name = tempfile.mkstemp(
        prefix=".broker-artifact-", dir=str(output_path.parent)
    )
    os.close(descriptor)
    temp_path = Path(temp_name)
    try:
        with open(temp_path, "wb") as handle:
            handle.write(b"#!/usr/bin/env python3\n")
            with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for entry in entries:
                    relative = entry.relative_to(staging_root).as_posix()
                    info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                    info.external_attr = 0o644 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, entry.read_bytes())
        os.chmod(temp_path, 0o755)
        os.replace(temp_path, output_path)
    finally:
        temp_path.unlink(missing_ok=True)


def build_broker_deployment_artifact(
    output_path: Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Build the deterministic broker zipapp.  Never requires privilege.

    Refuses to overwrite a pre-existing artifact at ``output_path``: a caller
    that wants a fresh build removes the old one explicitly first.
    """

    output = Path(output_path)
    if output.exists():
        raise OwnerAuthorityDeploymentArtifactError(
            f"refusing to overwrite a pre-existing artifact at {output}",
            classification="OWNER_AUTHORITY_ARTIFACT_ALREADY_PRESENT",
        )
    root = (
        Path(repository_root)
        if repository_root is not None
        else _default_repository_root()
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="admissible-owner-authority-artifact-"
    ) as workspace:
        staging_root = Path(workspace) / "staging"
        staging_root.mkdir()
        manifest = _stage_admissible_tree(
            repository_root=root, staging_root=staging_root
        )
        (staging_root / "__main__.py").write_text(_MAIN_SOURCE, encoding="utf-8")
        manifest.append(("__main__.py", sha256_bytes(_MAIN_SOURCE.encode("utf-8"))))
        manifest.sort()
        _write_deterministic_zipapp(
            staging_root=staging_root, output_path=output
        )
    artifact_bytes = output.read_bytes()
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "path": str(output),
        "sha256": sha256_bytes(artifact_bytes),
        "size": len(artifact_bytes),
        "file_count": len(manifest),
        "contents_fingerprint": fingerprint({"manifest": manifest}),
    }


def verify_deployment_artifact(
    path: Path, expected_sha256: str
) -> dict[str, Any]:
    """Refuse unless the bytes at ``path`` are exactly the expected artifact."""

    target = Path(path)
    require_sha256(expected_sha256, "expected deployment artifact sha256")
    if not target.is_file():
        raise OwnerAuthorityDeploymentArtifactError(
            f"deployment artifact not found at {target}",
            classification="OWNER_AUTHORITY_ARTIFACT_ABSENT",
        )
    data = target.read_bytes()
    observed = sha256_bytes(data)
    if observed != expected_sha256:
        raise OwnerAuthorityDeploymentArtifactError(
            "deployment artifact sha256 does not match the expected value",
            classification="OWNER_AUTHORITY_ARTIFACT_HASH_MISMATCH",
        )
    return {"verified": True, "sha256": observed, "size": len(data), "path": str(target)}


def copy_deployment_artifact_without_execute(
    *, source: Path, destination: Path, expected_sha256: str
) -> dict[str, Any]:
    """Copy a verified artifact to its fixed install path.  Never executes it.

    This is the only privileged step in the whole artifact lifecycle: reading
    already-verified bytes and writing them, unexecuted, to a root-owned
    destination.  The destination is never adopted if it already exists, and
    the copied bytes are re-verified against the same digest before this
    returns.
    """

    verify_deployment_artifact(source, expected_sha256)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise OwnerAuthorityDeploymentArtifactError(
            f"refusing to overwrite an existing object at {destination}",
            classification="OWNER_AUTHORITY_ARTIFACT_ALREADY_PRESENT",
        )
    data = Path(source).read_bytes()
    descriptor = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
    )
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o755)
    copied = destination.read_bytes()
    if sha256_bytes(copied) != expected_sha256:
        raise OwnerAuthorityDeploymentArtifactError(
            "the copied deployment artifact failed byte verification",
            classification="OWNER_AUTHORITY_ARTIFACT_HASH_MISMATCH",
        )
    return {"path": str(destination), "sha256": expected_sha256, "size": len(copied)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admissible-owner-authority-deployment-artifact",
        description="Build and verify the unprivileged broker deployment artifact.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build the deterministic zipapp")
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--repository-root", default=None, type=Path)
    verify = commands.add_parser("verify", help="verify an artifact's sha256")
    verify.add_argument("--path", required=True, type=Path)
    verify.add_argument("--sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "build":
            result = build_broker_deployment_artifact(
                arguments.output, repository_root=arguments.repository_root
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if arguments.command == "verify":
            result = verify_deployment_artifact(arguments.path, arguments.sha256)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    return 2  # pragma: no cover - argparse enforces a command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
