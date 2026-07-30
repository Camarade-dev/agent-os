"""The root-only owner-authority installer (section C).

This module can describe an installation from any identity, and can *perform*
one only as uid 0.  The implementation task deliberately never executes it: it
produces the plan and the dry-run validation, and the real privileged install
remains an explicit owner action taken after independent audit.

The installer performs only bounded operations: create the fixed directories,
create the signing identity, publish the fixed public installation record,
install the broker unit definition, and set exact ownership and modes.  It
never reads a credential, never contacts a network, and never provisions an
authorization --- provisioning is a separate privileged action with its own
entry point.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.common import canonical_bytes, fsync_directory
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallationError,
    build_installation_record,
)
from admissible.capsule.owner_authority.layout import (
    AUTHORIZATIONS_SUBDIRECTORY,
    BROKER_PROTOCOL_VERSION,
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    PRIVATE_SUBDIRECTORY,
    production_layout,
)
from admissible.capsule.owner_authority.signing import (
    SIGNING_ALGORITHM,
    discover_system_openssl,
    generate_signing_identity,
    public_key_fingerprint,
)

#: The systemd unit the installer writes.  It is a definition only; this task
#: neither enables nor starts it.
BROKER_UNIT_NAME = "admissible-owner-authority-broker-v1.service"

#: Exact ownership and mode of every installed object.
INSTALLED_OBJECTS: tuple[dict[str, Any], ...] = (
    {
        "kind": "directory",
        "path": "{configuration_root}",
        "owner": "root:root",
        "mode": 0o755,
        "purpose": "immutable owner-authority configuration",
    },
    {
        "kind": "file",
        "path": "{configuration_root}/installation-v1.json",
        "owner": "root:root",
        "mode": 0o444,
        "purpose": "the fixed public installation record",
    },
    {
        "kind": "file",
        "path": "{configuration_root}/owner-authority-signing-key.v1.pub.pem",
        "owner": "root:root",
        "mode": 0o444,
        "purpose": "the public verification key",
    },
    {
        "kind": "directory",
        "path": "{state_root}",
        "owner": "root:root",
        "mode": 0o700,
        "purpose": "durable authorization state, unreadable by the launcher",
    },
    {
        "kind": "directory",
        "path": "{state_root}/" + PRIVATE_SUBDIRECTORY,
        "owner": "root:root",
        "mode": 0o700,
        "purpose": "private signing material",
    },
    {
        "kind": "file",
        "path": "{state_root}/"
        + PRIVATE_SUBDIRECTORY
        + "/owner-authority-signing-key.v1.pem",
        "owner": "root:root",
        "mode": 0o600,
        "purpose": "the Ed25519 private signing key; broker use only",
    },
    {
        "kind": "directory",
        "path": "{state_root}/" + AUTHORIZATIONS_SUBDIRECTORY,
        "owner": "root:root",
        "mode": 0o700,
        "purpose": "pending and consumed authorization records",
    },
    {
        "kind": "directory",
        "path": "{runtime_root}",
        "owner": "root:root",
        "mode": 0o755,
        "purpose": "runtime broker socket directory",
    },
    {
        "kind": "socket",
        "path": "{runtime_root}/broker.sock",
        "owner": "root:{launcher_group}",
        "mode": 0o660,
        "purpose": "the broker socket; every peer is still checked by uid",
    },
    {
        "kind": "file",
        "path": "/etc/systemd/system/" + BROKER_UNIT_NAME,
        "owner": "root:root",
        "mode": 0o644,
        "purpose": "broker service definition (installed, not started)",
    },
)


class OwnerAuthorityInstallerError(OwnerAuthorityError):
    """A refusal on the privileged installation path."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_INSTALLER_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def require_privileged_identity(action: str) -> int:
    """Refuse unless genuinely running with the privileged OS identity.

    An unprivileged copy of this executable fails here.  It cannot be argued
    around: the check is on the effective uid the kernel reports, and every
    operation that follows would fail on root-owned paths anyway.
    """

    euid = os.geteuid()
    if euid != 0:
        raise OwnerAuthorityInstallerError(
            f"{action} requires the privileged installer identity (uid 0); "
            f"this process runs as uid {euid}",
            classification="OWNER_AUTHORITY_NOT_PRIVILEGED",
        )
    return euid


def broker_unit_definition(layout: OwnerAuthorityLayout) -> str:
    """The minimal broker service definition.  Installed, never started here."""

    return "\n".join(
        [
            "[Unit]",
            "Description=Admissible owner-authority broker v1",
            "Documentation=file:///usr/share/doc/agent-os/"
            "admissible-external-owner-authority.md",
            "After=local-fs.target",
            "",
            "[Service]",
            "Type=simple",
            "User=root",
            "Group=root",
            "ExecStart=/usr/bin/python3 -m "
            "admissible.capsule.owner_authority.broker_service",
            f"RuntimeDirectory={layout.runtime_root.name}",
            "RuntimeDirectoryMode=0755",
            f"StateDirectory={layout.state_root.name}",
            "StateDirectoryMode=0700",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            f"ReadWritePaths={layout.state_root} {layout.runtime_root}",
            "RestrictAddressFamilies=AF_UNIX",
            "MemoryDenyWriteExecute=yes",
            "Restart=no",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def preinstall_conflict_checks(
    layout: OwnerAuthorityLayout | None = None,
) -> dict[str, Any]:
    """Report conflicts that must be resolved before a privileged install.

    Safe to run unprivileged: it only stats fixed paths and attests the
    cryptographic executable.
    """

    active = (layout or production_layout()).validated()
    conflicts: list[dict[str, Any]] = []
    for path in (
        active.configuration_root,
        active.state_root,
        active.runtime_root,
        active.installation_record_path,
        active.public_key_path,
    ):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as error:
            conflicts.append(
                {
                    "path": str(path),
                    "conflict": "UNSTATTABLE",
                    "detail": error.strerror or "unstattable",
                }
            )
            continue
        conflicts.append(
            {
                "path": str(path),
                "conflict": "ALREADY_PRESENT",
                "owner_uid": info.st_uid,
                "mode": stat.S_IMODE(info.st_mode),
                "is_symlink": stat.S_ISLNK(info.st_mode),
            }
        )
    try:
        executable = discover_system_openssl()
        crypto = {
            "resolved": True,
            "path": executable["path"],
            "sha256": executable["sha256"],
            "algorithm": SIGNING_ALGORITHM,
        }
    except OwnerAuthorityError as error:
        crypto = {"resolved": False, "classification": error.classification}
    return {
        "schema_version": "admissible_owner_authority_preinstall_checks_v1",
        "layout": active.to_dict(),
        "conflicts": conflicts,
        "installable": not conflicts and crypto["resolved"],
        "cryptographic_primitive": crypto,
        "privileged_identity_present": os.geteuid() == 0,
    }


def installation_plan(
    *,
    layout: OwnerAuthorityLayout | None = None,
    authorized_launcher_uid: int,
    authorized_launcher_gid: int,
    launcher_username: str = "<launcher>",
    launcher_group: str = "<launcher-group>",
) -> dict[str, Any]:
    """A complete, human-readable, non-executed installation plan."""

    active = (layout or production_layout()).validated()
    substitutions = {
        "configuration_root": str(active.configuration_root),
        "state_root": str(active.state_root),
        "runtime_root": str(active.runtime_root),
        "launcher_group": launcher_group,
    }
    objects = [
        {
            **item,
            "path": item["path"].format(**substitutions),
            "owner": item["owner"].format(**substitutions),
        }
        for item in INSTALLED_OBJECTS
    ]
    return {
        "schema_version": "admissible_owner_authority_installation_plan_v1",
        "layout": active.to_dict(),
        "broker_protocol": BROKER_PROTOCOL_VERSION,
        "signing_algorithm": SIGNING_ALGORITHM,
        "authorized_launcher_uid": authorized_launcher_uid,
        "authorized_launcher_gid": authorized_launcher_gid,
        "authorized_launcher_username": launcher_username,
        "objects": objects,
        "install_commands": [
            "sudo python3 -m admissible.capsule.owner_authority.installer "
            f"install --authorized-launcher {launcher_username}",
        ],
        "dry_run_commands": [
            "python3 -m admissible.capsule.owner_authority.installer "
            "preinstall-checks",
            "python3 -m admissible.capsule.owner_authority.installer plan "
            f"--authorized-launcher {launcher_username}",
        ],
        "broker_commands": {
            "start": f"sudo systemctl start {BROKER_UNIT_NAME}",
            "stop": f"sudo systemctl stop {BROKER_UNIT_NAME}",
            "status": f"sudo systemctl status {BROKER_UNIT_NAME}",
            "enable": f"sudo systemctl enable {BROKER_UNIT_NAME}",
        },
        "provisioning_command": (
            "sudo python3 -m admissible.capsule.owner_authority.provisioner "
            "provision --owner-payload <payload.json> --phrase-fd 3 3<&0"
        ),
        "uninstall_commands": [
            f"sudo systemctl stop {BROKER_UNIT_NAME}",
            f"sudo systemctl disable {BROKER_UNIT_NAME}",
            "sudo python3 -m admissible.capsule.owner_authority.installer "
            "uninstall --confirm-destroys-authorizations",
        ],
        "postinstall_verification_commands": [
            "python3 -m admissible.capsule.owner_authority.installer verify",
        ],
        "not_executed_by_implementation_task": True,
    }


def render_installation_plan(plan: Mapping[str, Any]) -> str:
    """Render the plan as bounded, human-readable text."""

    lines = [
        "Admissible external owner-authority installation plan",
        "=" * 52,
        "",
        f"broker protocol      : {plan['broker_protocol']}",
        f"signing algorithm    : {plan['signing_algorithm']}",
        f"configuration root   : {plan['layout']['configuration_root']}",
        f"state root           : {plan['layout']['state_root']}",
        f"runtime root         : {plan['layout']['runtime_root']}",
        f"authorized launcher  : {plan['authorized_launcher_username']} "
        f"(uid {plan['authorized_launcher_uid']}, "
        f"gid {plan['authorized_launcher_gid']})",
        "",
        "Objects created by the privileged installer",
        "-" * 43,
    ]
    for item in plan["objects"]:
        lines.append(
            f"  {item['kind']:<9} {item['owner']:<20} "
            f"{oct(item['mode'])[2:]:>4}  {item['path']}"
        )
        lines.append(f"            {item['purpose']}")
    for title, key in (
        ("Dry-run (unprivileged)", "dry_run_commands"),
        ("Install (privileged)", "install_commands"),
        ("Uninstall / rollback", "uninstall_commands"),
        ("Post-install verification", "postinstall_verification_commands"),
    ):
        lines.extend(["", title, "-" * len(title)])
        lines.extend(f"  $ {command}" for command in plan[key])
    lines.extend(["", "Broker service", "-" * 14])
    for name, command in plan["broker_commands"].items():
        lines.append(f"  {name:<7} $ {command}")
    lines.extend(
        [
            "",
            "Owner authorization provisioning (privileged, per launch)",
            "-" * 57,
            f"  $ {plan['provisioning_command']}",
            "",
            "This plan was generated but NOT executed.",
        ]
    )
    return "\n".join(lines) + "\n"


def perform_installation(
    *,
    layout: OwnerAuthorityLayout,
    installation_id: str,
    authorized_launcher_uid: int,
    authorized_launcher_gid: int,
    install_unit: bool = True,
) -> dict[str, Any]:
    """Perform the bounded privileged installation.  Requires uid 0."""

    require_privileged_identity("owner-authority installation")
    active = layout.validated()
    if active.installation_record_path.exists():
        raise OwnerAuthorityInstallerError(
            "an owner-authority installation is already present",
            classification="OWNER_AUTHORITY_ALREADY_INSTALLED",
        )
    executable = discover_system_openssl()

    for directory, mode in (
        (active.configuration_root, 0o755),
        (active.state_root, 0o700),
        (active.private_directory, 0o700),
        (active.authorizations_root, 0o700),
        (active.runtime_root, 0o755),
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=mode)
        os.chmod(directory, mode)
        os.chown(directory, 0, 0)

    identity = generate_signing_identity(
        executable=executable,
        private_key_path=active.private_key_path,
        public_key_path=active.public_key_path,
    )
    os.chown(active.private_key_path, 0, 0)
    os.chmod(active.private_key_path, 0o600)
    os.chown(active.public_key_path, 0, 0)
    os.chmod(active.public_key_path, 0o444)

    record = build_installation_record(
        layout=active,
        installation_id=installation_id,
        signing_key_fingerprint=identity["signing_key_fingerprint"],
        public_key_sha256=identity["public_key_sha256"],
        cryptographic_executable_identity=executable,
        authorized_launcher_uid=authorized_launcher_uid,
        authorized_launcher_gid=authorized_launcher_gid,
        installer_uid=0,
    )
    encoded = canonical_bytes(record)
    descriptor = os.open(
        active.installation_record_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o444,
    )
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(active.installation_record_path, 0, 0)
    os.chmod(active.installation_record_path, 0o444)
    fsync_directory(active.configuration_root)

    unit_path = None
    if install_unit:
        unit_path = Path("/etc/systemd/system") / BROKER_UNIT_NAME
        unit_path.write_text(broker_unit_definition(active), encoding="utf-8")
        os.chown(unit_path, 0, 0)
        os.chmod(unit_path, 0o644)

    return {
        "schema_version": "admissible_owner_authority_installation_result_v1",
        "installation_id": installation_id,
        "record_identity": record["record_identity"],
        "signing_key_fingerprint": identity["signing_key_fingerprint"],
        "installation_record_path": str(active.installation_record_path),
        "broker_unit_path": str(unit_path) if unit_path else None,
        "broker_started": False,
    }


def verify_installation() -> dict[str, Any]:
    """Post-install verification, provider-free and unprivileged."""

    from admissible.capsule.owner_authority.installation import (
        attest_production_installation,
    )

    try:
        installation = attest_production_installation()
    except OwnerAuthorityError as error:
        return {
            "verified": False,
            "classification": error.classification,
            "detail": str(error),
        }
    return {
        "verified": True,
        "attestation": dict(installation.to_dict()),
        "cryptographic_executable": dict(
            installation.reattest_cryptographic_executable()
        ),
    }


def _resolve_launcher(name: str) -> tuple[int, int, str, str]:
    import grp
    import pwd

    try:
        entry = pwd.getpwnam(name)
    except KeyError as error:
        raise OwnerAuthorityInstallerError(
            f"unknown authorized launcher account {name!r}",
            classification="OWNER_AUTHORITY_LAUNCHER_UNKNOWN",
        ) from error
    try:
        group = grp.getgrgid(entry.pw_gid).gr_name
    except KeyError:  # pragma: no cover - unnamed gid
        group = str(entry.pw_gid)
    return entry.pw_uid, entry.pw_gid, entry.pw_name, group


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admissible-owner-authority-installer",
        description=(
            "Plan, validate and perform the privileged owner-authority "
            "installation."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="print the installation plan")
    plan_parser.add_argument("--authorized-launcher", required=True)
    plan_parser.add_argument("--json", action="store_true")
    commands.add_parser("preinstall-checks", help="report install conflicts")
    commands.add_parser("verify", help="verify an existing installation")
    install_parser = commands.add_parser("install", help="perform the install")
    install_parser.add_argument("--authorized-launcher", required=True)
    install_parser.add_argument("--installation-id", default=None)
    uninstall_parser = commands.add_parser("uninstall", help="remove the install")
    uninstall_parser.add_argument(
        "--confirm-destroys-authorizations", action="store_true"
    )
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "preinstall-checks":
            print(json.dumps(preinstall_conflict_checks(), indent=2, sort_keys=True))
            return 0
        if arguments.command == "verify":
            result = verify_installation()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["verified"] else 1
        if arguments.command == "plan":
            uid, gid, username, group = _resolve_launcher(
                arguments.authorized_launcher
            )
            plan = installation_plan(
                authorized_launcher_uid=uid,
                authorized_launcher_gid=gid,
                launcher_username=username,
                launcher_group=group,
            )
            if arguments.json:
                print(json.dumps(plan, indent=2, sort_keys=True))
            else:
                print(render_installation_plan(plan), end="")
            return 0
        if arguments.command == "install":
            uid, gid, _username, _group = _resolve_launcher(
                arguments.authorized_launcher
            )
            result = perform_installation(
                layout=production_layout(),
                installation_id=(
                    arguments.installation_id or os.urandom(16).hex()
                ),
                authorized_launcher_uid=uid,
                authorized_launcher_gid=gid,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if arguments.command == "uninstall":
            if not arguments.confirm_destroys_authorizations:
                print(
                    "refusing: uninstall destroys every provisioned "
                    "authorization; pass --confirm-destroys-authorizations",
                    file=sys.stderr,
                )
                return 2
            require_privileged_identity("owner-authority uninstall")
            print(
                json.dumps(
                    {
                        "uninstall": "MANUAL",
                        "remove": [
                            str(production_layout().configuration_root),
                            str(production_layout().state_root),
                            str(production_layout().runtime_root),
                            f"/etc/systemd/system/{BROKER_UNIT_NAME}",
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
    except (OwnerAuthorityError, OwnerAuthorityInstallationError) as error:
        print(f"{error}", file=sys.stderr)
        return 1
    return 2  # pragma: no cover - argparse enforces a command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
