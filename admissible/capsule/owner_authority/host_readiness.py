"""Read-only host readiness for the external owner-authority canary.

Reports every canary precondition without mutating the host.  Distinguishes
code defects (broken generated plans, unit files or phrase recipes) from
missing host prerequisites (Docker Desktop integration, launcher account not
yet created, pinned Codex absent).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.boundary_authority import DestinationManifest
from admissible.capsule.model_authority import CANARY_PINNED_CODEX_VERSION
from admissible.capsule.owner_authority.deployment_artifact import (
    DEPLOYMENT_ARTIFACT_PATH,
)
from admissible.capsule.owner_authority.installation import (
    attest_production_installation,
    production_installation_is_present,
)
from admissible.capsule.owner_authority.installer import (
    BROKER_UNIT_NAME,
    _journal_root,
    _lstat_or_none,
    broker_unit_definition,
    preinstall_conflict_checks,
    production_layout,
    validate_service_unit_text,
)
from admissible.capsule.owner_authority.launcher_account import (
    LauncherAccountError,
    RECOMMENDED_LAUNCHER_USERNAME,
    validate_launcher_username,
)
from admissible.capsule.owner_authority.layout import (
    LAUNCH_RESULT_RECORDED,
    OwnerAuthorityError,
)
from admissible.capsule.owner_authority.provisioner import phrase_fd_from_ask_password
from admissible.capsule.owner_authority.signing import discover_system_openssl

SCHEMA_VERSION = "admissible_owner_authority_host_readiness_v1"

_HOST_PREREQUISITE = "HOST_PREREQUISITE"
_CODE_DEFECT = "CODE_DEFECT"

_FORBIDDEN_PHRASE_PATTERNS = ("3<&0", "3< <(cat)")


def _condition(
    condition_id: str,
    *,
    passed: bool,
    classification: str,
    detail: str,
    observation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": condition_id,
        "status": "PASS" if passed else "FAIL",
        "classification": classification,
        "detail": detail,
    }
    if observation is not None:
        item["observation"] = dict(observation)
    return item


def _detect_service_manager() -> dict[str, Any]:
    if shutil.which("systemctl") is not None:
        return {"name": "systemd", "supported": True}
    return {"name": "unknown", "supported": False}


def _detect_os() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "supported": platform.system() == "Linux",
    }


def _launcher_readiness() -> dict[str, Any]:
    try:
        validated = validate_launcher_username(RECOMMENDED_LAUNCHER_USERNAME)
        return _condition(
            "dedicated_launcher_identity",
            passed=True,
            classification=_HOST_PREREQUISITE,
            detail="dedicated launcher account is present and authorized",
            observation=validated,
        )
    except LauncherAccountError as error:
        return _condition(
            "dedicated_launcher_identity",
            passed=False,
            classification=_HOST_PREREQUISITE,
            detail=str(error),
            observation={"classification": error.classification},
        )


def _deployment_artifact_readiness() -> dict[str, Any]:
    info = _lstat_or_none(DEPLOYMENT_ARTIFACT_PATH)
    if info is None:
        return _condition(
            "deployment_artifact_present",
            passed=False,
            classification=_HOST_PREREQUISITE,
            detail=f"deployment artifact is absent at {DEPLOYMENT_ARTIFACT_PATH}",
        )
    if stat.S_ISLNK(info.st_mode):
        return _condition(
            "deployment_artifact_present",
            passed=False,
            classification=_HOST_PREREQUISITE,
            detail="deployment artifact path is a symlink",
        )
    return _condition(
        "deployment_artifact_present",
        passed=stat.S_ISREG(info.st_mode),
        classification=_HOST_PREREQUISITE,
        detail=(
            "deployment artifact is present"
            if stat.S_ISREG(info.st_mode)
            else "deployment artifact path is not a regular file"
        ),
        observation={
            "path": str(DEPLOYMENT_ARTIFACT_PATH),
            "mode": oct(stat.S_IMODE(info.st_mode)),
            "owner_uid": info.st_uid,
            "size": info.st_size,
        },
    )


def _broker_installation_readiness() -> list[dict[str, Any]]:
    layout = production_layout()
    conditions: list[dict[str, Any]] = []
    unit_path = Path("/etc/systemd/system") / BROKER_UNIT_NAME
    unit_info = _lstat_or_none(unit_path)
    conditions.append(
        _condition(
            "broker_unit_installed",
            passed=unit_info is not None and stat.S_ISREG(unit_info.st_mode),
            classification=_HOST_PREREQUISITE,
            detail=(
                "broker systemd unit is installed"
                if unit_info is not None
                else f"broker unit is absent at {unit_path}"
            ),
            observation={"path": str(unit_path)} if unit_info else None,
        )
    )
    if not production_installation_is_present():
        conditions.append(
            _condition(
                "broker_installation_record",
                passed=False,
                classification=_HOST_PREREQUISITE,
                detail="production installation record is absent",
            )
        )
        conditions.append(
            _condition(
                "broker_runtime_ready",
                passed=False,
                classification=_HOST_PREREQUISITE,
                detail="broker cannot be ready without a production installation",
            )
        )
        return conditions
    try:
        installation = attest_production_installation()
        conditions.append(
            _condition(
                "broker_installation_record",
                passed=True,
                classification=_HOST_PREREQUISITE,
                detail="production installation attests from fixed paths",
                observation={
                    "installation_identity": installation.installation_identity,
                    "authorized_launcher_uid": installation.authorized_launcher_uid,
                },
            )
        )
    except OwnerAuthorityError as error:
        conditions.append(
            _condition(
                "broker_installation_record",
                passed=False,
                classification=_HOST_PREREQUISITE,
                detail=str(error),
                observation={"classification": error.classification},
            )
        )
        conditions.append(
            _condition(
                "broker_runtime_ready",
                passed=False,
                classification=_HOST_PREREQUISITE,
                detail="broker runtime readiness cannot be assessed",
            )
        )
        return conditions

    socket_path = layout.broker_socket_path
    socket_info = _lstat_or_none(socket_path)
    ready_marker = socket_path.parent / "broker-ready"
    ready_info = _lstat_or_none(ready_marker)
    socket_ready = (
        socket_info is not None
        and stat.S_ISSOCK(socket_info.st_mode)
        and socket_info.st_uid == 0
    )
    marker_ready = ready_info is not None and stat.S_ISREG(ready_info.st_mode)
    conditions.append(
        _condition(
            "broker_runtime_ready",
            passed=socket_ready or marker_ready,
            classification=_HOST_PREREQUISITE,
            detail=(
                "broker socket or readiness marker is present"
                if socket_ready or marker_ready
                else "broker socket and readiness marker are absent"
            ),
            observation={
                "socket_path": str(socket_path),
                "socket_present": socket_info is not None,
                "ready_marker_present": ready_info is not None,
            },
        )
    )
    return conditions


def _docker_readiness() -> dict[str, Any]:
    docker_binary = shutil.which("docker")
    socket_paths = (
        Path("/var/run/docker.sock"),
        Path("/mnt/wsl/docker-desktop"),
    )
    socket_observations = []
    socket_available = False
    for path in socket_paths:
        info = _lstat_or_none(path)
        present = info is not None and (
            stat.S_ISSOCK(info.st_mode) or stat.S_ISDIR(info.st_mode)
        )
        socket_observations.append(
            {"path": str(path), "present": present, "is_symlink": False}
            if info is None
            else {
                "path": str(path),
                "present": present,
                "is_symlink": stat.S_ISLNK(info.st_mode),
                "mode": oct(stat.S_IMODE(info.st_mode)),
            }
        )
        socket_available = socket_available or present
    passed = docker_binary is not None and socket_available
    return _condition(
        "docker_execution_environment",
        passed=passed,
        classification=_HOST_PREREQUISITE,
        detail=(
            "docker binary and socket are available in this execution environment"
            if passed
            else "docker is unavailable in this execution environment"
        ),
        observation={
            "docker_binary": docker_binary,
            "socket_paths": socket_observations,
        },
    )


def _pytest_readiness() -> dict[str, Any]:
    pytest_binary = shutil.which("pytest")
    detected = pytest_binary is not None
    return _condition(
        "pytest_present",
        passed=detected,
        classification=_HOST_PREREQUISITE,
        detail=(
            "pytest is available on PATH"
            if detected
            else "pytest was not detected on PATH"
        ),
        observation={"pytest_binary": pytest_binary},
    )


def _crypto_attestation_readiness() -> dict[str, Any]:
    try:
        executable = discover_system_openssl()
        return _condition(
            "crypto_executable_attestation",
            passed=True,
            classification=_HOST_PREREQUISITE,
            detail="system cryptographic executable resolves and attests",
            observation=executable,
        )
    except OwnerAuthorityError as error:
        return _condition(
            "crypto_executable_attestation",
            passed=False,
            classification=_HOST_PREREQUISITE,
            detail=str(error),
            observation={"classification": error.classification},
        )


def _pending_authorization_conflicts() -> dict[str, Any]:
    from admissible.capsule.owner_authority.state import (
        AUTHORIZATION_ABSENT,
        AuthorizationStateDirectory,
    )

    layout = production_layout()
    root = layout.authorizations_root
    if not root.is_dir():
        return _condition(
            "pending_authorization_conflicts",
            passed=True,
            classification=_HOST_PREREQUISITE,
            detail="no authorization state directory is present",
        )
    pending = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        directory = AuthorizationStateDirectory(layout, entry.name)
        state = directory.current_state()
        if state not in (AUTHORIZATION_ABSENT, LAUNCH_RESULT_RECORDED):
            pending.append({"authorization_record_id": entry.name, "state": state})
    return _condition(
        "pending_authorization_conflicts",
        passed=not pending,
        classification=_HOST_PREREQUISITE,
        detail=(
            "no pending or in-flight authorization conflicts"
            if not pending
            else "pending or in-flight authorization state exists"
        ),
        observation={"conflicts": pending},
    )


def _stale_runtime_roots() -> dict[str, Any]:
    layout = production_layout()
    stale: list[dict[str, Any]] = []
    complete = production_installation_is_present()
    for label, path in (
        ("runtime_root", layout.runtime_root),
        ("state_root", layout.state_root),
        ("configuration_root", layout.configuration_root),
    ):
        info = _lstat_or_none(path)
        if info is None:
            continue
        if not complete:
            stale.append(
                {
                    "label": label,
                    "path": str(path),
                    "reason": "present_without_complete_installation_record",
                }
            )
            continue
        if label == "runtime_root":
            socket = layout.broker_socket_path
            socket_info = _lstat_or_none(socket)
            if socket_info is not None and stat.S_ISSOCK(socket_info.st_mode):
                probe = None
                try:
                    import socket as socket_module

                    probe = socket_module.socket(
                        socket_module.AF_UNIX, socket_module.SOCK_STREAM
                    )
                    probe.settimeout(0.2)
                    probe.connect(os.fspath(socket))
                    stale.append(
                        {
                            "label": "broker_socket",
                            "path": str(socket),
                            "reason": "socket_exists_with_live_listener",
                        }
                    )
                except OSError:
                    stale.append(
                        {
                            "label": "broker_socket",
                            "path": str(socket),
                            "reason": "stale_socket_without_live_listener",
                        }
                    )
                finally:
                    if probe is not None:
                        probe.close()
    journal_root = _journal_root(layout)
    journal_info = _lstat_or_none(journal_root)
    if journal_info is not None:
        try:
            entries = list(journal_root.iterdir())
        except OSError:
            entries = []
        if entries:
            stale.append(
                {
                    "label": "install_transaction_journal",
                    "path": str(journal_root),
                    "reason": "incomplete_install_journal_present",
                    "entry_count": len(entries),
                }
            )
    return _condition(
        "stale_runtime_or_install_roots",
        passed=not stale,
        classification=_HOST_PREREQUISITE,
        detail=(
            "no stale runtime, install or journal roots were observed"
            if not stale
            else "stale runtime, install or journal residue was observed"
        ),
        observation={"stale": stale},
    )


def _pinned_codex_candidates() -> list[Path]:
    candidates: list[Path] = []
    override = os.environ.get("ADMISSIBLE_PINNED_CODEX")
    if override:
        candidates.append(Path(override))
    releases = Path.home() / ".codex" / "packages" / "standalone" / "releases"
    if releases.is_dir():
        candidates.extend(
            sorted(
                item / "bin" / "codex"
                for item in releases.iterdir()
                if item.name.startswith(f"{CANARY_PINNED_CODEX_VERSION}-")
            )
        )
    return candidates


def _codex_executable_readiness() -> dict[str, Any]:
    observed = []
    for candidate in _pinned_codex_candidates():
        info = _lstat_or_none(candidate)
        present = (
            info is not None
            and stat.S_ISREG(info.st_mode)
            and os.access(candidate, os.X_OK)
        )
        observed.append(
            {
                "path": str(candidate),
                "present": present,
                "executable": present,
            }
        )
        if present:
            return _condition(
                "production_codex_executable_present",
                passed=True,
                classification=_HOST_PREREQUISITE,
                detail="pinned production Codex executable is present",
                observation={"candidates": observed},
            )
    return _condition(
        "production_codex_executable_present",
        passed=False,
        classification=_HOST_PREREQUISITE,
        detail="pinned production Codex executable was not found",
        observation={"candidates": observed},
    )


def _auth_metadata_readiness() -> dict[str, Any]:
    auth_path = Path.home() / ".codex" / "auth.json"
    info = _lstat_or_none(auth_path)
    if info is None:
        return _condition(
            "login_metadata_presence",
            passed=False,
            classification=_HOST_PREREQUISITE,
            detail="login metadata path is absent",
            observation={"path": str(auth_path), "present": False},
        )
    mode = stat.S_IMODE(info.st_mode)
    safe_mode = mode in {0o600, 0o400, 0o440, 0o640} and not (mode & 0o077)
    return _condition(
        "login_metadata_presence",
        passed=True,
        classification=_HOST_PREREQUISITE,
        detail="login metadata path is present; contents were not inspected",
        observation={
            "path": str(auth_path),
            "present": True,
            "mode": oct(mode),
            "owner_uid": info.st_uid,
            "safe_mode": safe_mode,
            "contents_inspected": False,
        },
    )


def _sealed_destination_manifest_readiness() -> dict[str, Any]:
    try:
        manifest = DestinationManifest.load_packaged()
        manifest.validated()
        return _condition(
            "sealed_destination_manifest_identity",
            passed=True,
            classification=_HOST_PREREQUISITE,
            detail="packaged destination manifest identity is available",
            observation={
                "manifest_fingerprint": manifest.manifest_fingerprint,
                "codex_version": manifest.codex_version,
            },
        )
    except (OSError, ValueError) as error:
        return _condition(
            "sealed_destination_manifest_identity",
            passed=False,
            classification=_HOST_PREREQUISITE,
            detail=f"sealed destination manifest is absent or invalid: {error}",
        )


def _generated_unit_readiness() -> dict[str, Any]:
    unit = broker_unit_definition(production_layout())
    try:
        validate_service_unit_text(unit)
        passed = True
        detail = "generated broker unit passes static validation"
    except OwnerAuthorityError as error:
        passed = False
        detail = str(error)
    notify_present = "Type=notify" in unit
    if not notify_present:
        passed = False
        detail = "generated broker unit is missing Type=notify"
    return _condition(
        "broker_unit_definition",
        passed=passed and notify_present,
        classification=_CODE_DEFECT,
        detail=detail,
        observation={"type_notify": notify_present},
    )


def _phrase_recipe_readiness() -> dict[str, Any]:
    recipe = phrase_fd_from_ask_password(owner_payload_path="<payload.json>")
    forbidden = [item for item in _FORBIDDEN_PHRASE_PATTERNS if item in recipe]
    passed = not forbidden
    return _condition(
        "phrase_entry_recipe",
        passed=passed,
        classification=_CODE_DEFECT,
        detail=(
            "phrase-entry recipe avoids forbidden stdin redirection patterns"
            if passed
            else "phrase-entry recipe contains forbidden patterns: "
            + ", ".join(forbidden)
        ),
        observation={"forbidden_patterns_present": forbidden},
    )


def _preinstall_conflict_readiness() -> dict[str, Any]:
    report = preinstall_conflict_checks()
    conflicts = report.get("conflicts", [])
    return _condition(
        "preinstall_conflicts_absent",
        passed=not conflicts,
        classification=_HOST_PREREQUISITE,
        detail=(
            "no blocking preinstall conflicts were observed"
            if not conflicts
            else "preinstall conflicts block a fresh install"
        ),
        observation={"conflicts": conflicts, "installable": report.get("installable")},
    )


def host_readiness_report() -> dict[str, Any]:
    """Build the full host-readiness report without mutating the host."""

    os_info = _detect_os()
    service_manager = _detect_service_manager()
    conditions: list[dict[str, Any]] = [
        _condition(
            "supported_os",
            passed=os_info["supported"],
            classification=_HOST_PREREQUISITE,
            detail=(
                "host OS is supported"
                if os_info["supported"]
                else f"unsupported host OS {os_info['system']!r}"
            ),
            observation=os_info,
        ),
        _condition(
            "supported_service_manager",
            passed=service_manager["supported"],
            classification=_HOST_PREREQUISITE,
            detail=(
                "systemd is available"
                if service_manager["supported"]
                else "systemd is not available"
            ),
            observation=service_manager,
        ),
        _launcher_readiness(),
        _deployment_artifact_readiness(),
        *_broker_installation_readiness(),
        _docker_readiness(),
        _pytest_readiness(),
        _crypto_attestation_readiness(),
        _pending_authorization_conflicts(),
        _stale_runtime_roots(),
        _codex_executable_readiness(),
        _auth_metadata_readiness(),
        _sealed_destination_manifest_readiness(),
        _preinstall_conflict_readiness(),
        _generated_unit_readiness(),
        _phrase_recipe_readiness(),
    ]

    host_prerequisites_missing = sorted(
        {
            item["id"]
            for item in conditions
            if item["status"] == "FAIL" and item["classification"] == _HOST_PREREQUISITE
        }
    )
    code_defects = sorted(
        {
            item["id"]
            for item in conditions
            if item["status"] == "FAIL" and item["classification"] == _CODE_DEFECT
        }
    )
    if code_defects:
        overall = "CODE_DEFECT"
    elif host_prerequisites_missing:
        overall = "HOST_PREREQUISITES_MISSING"
    else:
        overall = "PASS"

    return {
        "schema_version": SCHEMA_VERSION,
        "overall": overall,
        "canary_conditions": conditions,
        "host_prerequisites_missing": host_prerequisites_missing,
        "code_defects": code_defects,
    }


def host_readiness_exit_code(report: Mapping[str, Any]) -> int:
    overall = report["overall"]
    if overall == "PASS":
        return 0
    if overall == "HOST_PREREQUISITES_MISSING":
        return 2
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admissible-owner-authority-host-readiness",
        description="Report owner-authority host readiness without mutation.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    arguments = parser.parse_args(argv)
    report = host_readiness_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return host_readiness_exit_code(report)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
