"""The root-only owner-authority installer (section C).

This module can describe an installation from any identity, and can *perform*
one only as uid 0.  The privileged paths --- ``perform_installation`` and
``perform_uninstall`` --- are symlink-safe and transactional: every ancestor
and target is ``lstat``-checked without following symlinks, nothing already
present is silently adopted, every object this process creates is recorded in
a durable journal before the next step runs, and any failure before the final
commit removes exactly the objects this transaction created and nothing else.

Nothing here is executed by the implementation task itself: the real
privileged install remains an explicit owner action taken after independent
audit, and every test that exercises the privileged path either runs inside a
disposable namespace or is skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from admissible.capsule.common import canonical_bytes, fsync_directory
from admissible.capsule.owner_authority.deployment_artifact import (
    DEPLOYMENT_ARTIFACT_PATH,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallationError,
    attest_production_installation,
    attest_synthetic_non_production_installation,
    build_installation_record,
)
from admissible.capsule.owner_authority.launcher_account import (
    RECOMMENDED_LAUNCHER_GROUP,
    RECOMMENDED_LAUNCHER_USERNAME,
    OwnerAuthorityLauncherAccountError,
    launcher_account_creation_commands,
    validate_authorized_launcher,
)
from admissible.capsule.owner_authority.layout import (
    AUTHORIZATIONS_SUBDIRECTORY,
    BROKER_PROTOCOL_VERSION,
    LAUNCH_RESULT_RECORDED,
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    PRIVATE_SUBDIRECTORY,
    production_layout,
)
from admissible.capsule.owner_authority.signing import (
    SIGNING_ALGORITHM,
    discover_system_openssl,
    generate_signing_identity,
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
    {
        "kind": "file",
        "path": str(DEPLOYMENT_ARTIFACT_PATH),
        "owner": "root:root",
        "mode": 0o755,
        "purpose": "the deterministic unprivileged broker deployment artifact",
    },
)

#: Uninstall preserves or destroys the signing identity.  Exactly one applies.
UNINSTALL_MODE_PRESERVE = "PRESERVE_SIGNING_IDENTITY"
UNINSTALL_MODE_DESTROY = "DESTROY_SIGNING_IDENTITY"

#: Fixed, root-owned archive location for a preserved signing identity.
ARCHIVE_DIRECTORY_NAME = "admissible-owner-authority-v1-archives"

class ServiceManager(Protocol):
    """Injectable service-manager seam for uninstall and rollback."""

    def stop_broker_unit(self, unit_name: str = BROKER_UNIT_NAME) -> dict[str, Any]:
        ...

    def disable_broker_unit(
        self, unit_name: str = BROKER_UNIT_NAME
    ) -> dict[str, Any]:
        ...

    def reload_systemd(self) -> dict[str, Any]:
        ...


class _SystemdServiceManager:
    def stop_broker_unit(self, unit_name: str = BROKER_UNIT_NAME) -> dict[str, Any]:
        return stop_broker_unit(unit_name)

    def disable_broker_unit(
        self, unit_name: str = BROKER_UNIT_NAME
    ) -> dict[str, Any]:
        return disable_broker_unit(unit_name)

    def reload_systemd(self) -> dict[str, Any]:
        return reload_systemd()


_DEFAULT_SERVICE_MANAGER = _SystemdServiceManager()


#: Durable install-transaction journal directory name.
_TRANSACTION_JOURNAL_DIRNAME = "admissible-owner-authority-install-txn"


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


# ---------------------------------------------------------------------------
# Symlink-safe path helpers.  These are pure and need no privilege, so the
# refusal behaviour they implement is directly unit-testable.
# ---------------------------------------------------------------------------


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OwnerAuthorityInstallerError(
            f"cannot stat {path} on the owner-authority install path: "
            f"{error.strerror or error}",
            classification="OWNER_AUTHORITY_INSTALL_PATH_UNSTATTABLE",
        ) from error


def _ancestors_inclusive(path: Path) -> list[Path]:
    parts = path.parts
    return [Path(*parts[: index + 1]) for index in range(1, len(parts) + 1)]


def _refuse_symlink_targets(layout: OwnerAuthorityLayout) -> None:
    """Refuse if any ancestor or target of the layout is a symlink.

    This is the whole defence against a configuration-root (or any other
    fixed-path ancestor) symlink attack, and it needs no privilege to run: it
    only ``lstat``s fixed paths.  ``perform_installation`` calls this before
    it creates anything, and again immediately before publication.
    """

    active = layout.validated()
    checked: set[Path] = set()
    targets = (
        active.configuration_root,
        active.state_root,
        active.runtime_root,
        active.installation_record_path,
        active.public_key_path,
        active.private_directory,
        active.private_key_path,
        active.authorizations_root,
        active.broker_socket_path,
    )
    for target in targets:
        for ancestor in _ancestors_inclusive(target):
            if ancestor in checked:
                continue
            checked.add(ancestor)
            info = _lstat_or_none(ancestor)
            if info is not None and stat.S_ISLNK(info.st_mode):
                raise OwnerAuthorityInstallerError(
                    f"refusing: {ancestor} is a symlink on the owner-authority "
                    "install path",
                    classification="OWNER_AUTHORITY_INSTALL_SYMLINK_REFUSED",
                )


def _inventory_targets(layout: OwnerAuthorityLayout) -> list[Path]:
    active = layout.validated()
    return [
        active.configuration_root,
        active.installation_record_path,
        active.public_key_path,
        active.state_root,
        active.private_directory,
        active.private_key_path,
        active.authorizations_root,
        active.runtime_root,
    ]


def _refuse_unknown_prior_state(layout: OwnerAuthorityLayout) -> None:
    """Refuse an install over any unknown or partial prior state.

    Every fixed target is inventoried with ``lstat``.  A completely absent
    installation has none of them; anything else --- a leftover file, a
    half-finished previous transaction, or a genuinely completed install ---
    refuses rather than guessing which objects are safe to adopt.
    """

    present = [str(target) for target in _inventory_targets(layout) if _lstat_or_none(target) is not None]
    if present:
        raise OwnerAuthorityInstallerError(
            "refusing: unknown or partial prior owner-authority installation "
            "state exists at " + ", ".join(present),
            classification="OWNER_AUTHORITY_INSTALL_PARTIAL_STATE",
        )


def _mkdir_chain_no_symlink(path: Path, mode: int) -> None:
    """Create ``path`` and any missing ancestors, refusing symlink adoption."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise OwnerAuthorityInstallerError("refusing a relative installer path")
    built = Path(path.anchor)
    for part in path.relative_to(path.anchor).parts:
        built = built / part
        info = _lstat_or_none(built)
        if info is None:
            os.mkdir(built, mode)
            continue
        if stat.S_ISLNK(info.st_mode):
            raise OwnerAuthorityInstallerError(
                f"refusing: {built} is a symlink on the owner-authority "
                "install path",
                classification="OWNER_AUTHORITY_INSTALL_SYMLINK_REFUSED",
            )
        if not stat.S_ISDIR(info.st_mode):
            raise OwnerAuthorityInstallerError(
                f"refusing: {built} exists and is not a directory",
                classification="OWNER_AUTHORITY_INSTALL_PATH_REFUSED",
            )


def _create_directory_no_adoption(path: Path, mode: int) -> None:
    if _lstat_or_none(path) is not None:
        raise OwnerAuthorityInstallerError(
            f"refusing to adopt a pre-existing object at {path}",
            classification="OWNER_AUTHORITY_INSTALL_ADOPTION_REFUSED",
        )
    os.mkdir(path, mode)


# ---------------------------------------------------------------------------
# The install transaction journal
# ---------------------------------------------------------------------------


def _journal_root(layout: OwnerAuthorityLayout) -> Path:
    """Where the install journal lives: outside every caller-writable path.

    For production this is ``/var/lib`` --- root-only-writable, and never the
    configuration root itself, which is what a symlink attack would target.
    For a synthetic layout it is the parent of the synthetic state root, which
    the test that built the layout already owns.
    """

    return layout.state_root.parent / _TRANSACTION_JOURNAL_DIRNAME


class _InstallTransaction:
    """A durable, journaled record of every object one install created."""

    def __init__(self, layout: OwnerAuthorityLayout):
        self.layout = layout
        self.txn_id = os.urandom(16).hex()
        self.journal_root = _journal_root(layout)
        self.journal_dir = self.journal_root / self.txn_id
        self.entries: list[dict[str, Any]] = []

    def open(self) -> None:
        _mkdir_chain_no_symlink(self.journal_root, 0o700)
        if _lstat_or_none(self.journal_dir) is not None:
            raise OwnerAuthorityInstallerError(
                "an install transaction with this identity already exists",
                classification="OWNER_AUTHORITY_INSTALL_TRANSACTION_COLLISION",
            )
        os.mkdir(self.journal_dir, 0o700)

    def record(self, kind: str, path: Path) -> None:
        info = os.lstat(path)
        self.entries.append(
            {
                "kind": kind,
                "path": str(path),
                "device": info.st_dev,
                "inode": info.st_ino,
            }
        )
        self._write()

    def _write(self) -> None:
        payload = canonical_bytes({"txn_id": self.txn_id, "entries": self.entries})
        temporary = self.journal_dir / "journal.json.tmp"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.journal_dir / "journal.json")
        fsync_directory(self.journal_dir)

    def rollback(self) -> list[str]:
        """Remove exactly what this transaction created, in reverse order.

        Every removal is preceded by a device/inode re-check: if the object at
        a journaled path is no longer the exact object this transaction
        created, the rollback refuses rather than removing an unknown path.
        """

        removed: list[str] = []
        for entry in reversed(self.entries):
            path = Path(entry["path"])
            info = _lstat_or_none(path)
            if info is None:
                continue
            if info.st_dev != entry["device"] or info.st_ino != entry["inode"]:
                raise OwnerAuthorityInstallerError(
                    f"refusing rollback: {path} no longer matches the object "
                    "this transaction created",
                    classification="OWNER_AUTHORITY_INSTALL_ROLLBACK_REFUSED",
                )
            if entry["kind"] == "directory":
                os.rmdir(path)
            else:
                os.unlink(path)
            removed.append(str(path))
        return removed

    def close(self) -> None:
        shutil.rmtree(self.journal_dir, ignore_errors=True)


def _revalidate_before_publication(txn: "_InstallTransaction") -> None:
    """Re-check every journaled object immediately before publication.

    This is the "complete revalidation" step: a race that swapped a created
    directory or key file for a symlink or another object between creation
    and publication is caught here, before the installation record --- the
    thing every verifier trusts --- is ever written.
    """

    for entry in txn.entries:
        path = Path(entry["path"])
        info = os.lstat(path)
        if info.st_dev != entry["device"] or info.st_ino != entry["inode"]:
            raise OwnerAuthorityInstallerError(
                f"refusing publication: {path} changed identity after "
                "creation",
                classification="OWNER_AUTHORITY_INSTALL_REVALIDATION_FAILED",
            )
        if stat.S_ISLNK(info.st_mode):
            raise OwnerAuthorityInstallerError(
                f"refusing publication: {path} became a symlink",
                classification="OWNER_AUTHORITY_INSTALL_SYMLINK_REFUSED",
            )
        if info.st_uid != 0:
            raise OwnerAuthorityInstallerError(
                f"refusing publication: {path} is not root-owned",
                classification="OWNER_AUTHORITY_INSTALL_REVALIDATION_FAILED",
            )


def broker_unit_definition(layout: OwnerAuthorityLayout) -> str:
    """The broker service definition.  Installed, never started here.

    ``ExecStart`` names the fixed root-owned deployment artifact, never a
    checkout path: a checkout is caller-writable and must never be what a
    root service executes.  Restart is bounded (``on-failure``, capped
    ``RestartSec``, a ``StartLimitBurst``) so a persistently crashing broker
    cannot restart-loop forever, and a clean stop never triggers a restart.
    """

    return "\n".join(
        [
            "[Unit]",
            "Description=Admissible owner-authority broker v1",
            "Documentation=file:///usr/share/doc/agent-os/"
            "admissible-external-owner-authority.md",
            "After=local-fs.target",
            "StartLimitIntervalSec=60",
            "StartLimitBurst=5",
            "",
            "[Service]",
            "Type=notify",
            "NotifyAccess=main",
            "User=root",
            "Group=root",
            f"ExecStart=/usr/bin/python3 {DEPLOYMENT_ARTIFACT_PATH}",
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
            "Restart=on-failure",
            "RestartSec=2",
            "SuccessExitStatus=0",
            "TimeoutStartSec=30",
            "WatchdogSec=0",
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
    for path in _inventory_targets(active):
        info = _lstat_or_none(path)
        if info is None:
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
    deployment_artifact_path: str = "/tmp/admissible-broker.pyz",
    deployment_artifact_sha256: str = "<audited-sha256>",
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
    from admissible.capsule.owner_authority.provisioner import (
        phrase_fd_from_ask_password,
    )

    install_command = (
        "sudo python3 -m admissible.capsule.owner_authority.installer install "
        f"--authorized-launcher {launcher_username} "
        f"--deployment-artifact {deployment_artifact_path} "
        f"--deployment-artifact-sha256 {deployment_artifact_sha256}"
    )
    return {
        "schema_version": "admissible_owner_authority_installation_plan_v1",
        "layout": active.to_dict(),
        "broker_protocol": BROKER_PROTOCOL_VERSION,
        "signing_algorithm": SIGNING_ALGORITHM,
        "authorized_launcher_uid": authorized_launcher_uid,
        "authorized_launcher_gid": authorized_launcher_gid,
        "authorized_launcher_username": launcher_username,
        "objects": objects,
        "deployment_artifact_path": str(DEPLOYMENT_ARTIFACT_PATH),
        "launcher_account_commands": launcher_account_creation_commands(
            username=launcher_username
            if launcher_username != "<launcher>"
            else RECOMMENDED_LAUNCHER_USERNAME,
            group=launcher_group
            if launcher_group != "<launcher-group>"
            else RECOMMENDED_LAUNCHER_GROUP,
        ),
        "install_commands": [
            "python3 -m admissible.capsule.owner_authority.deployment_artifact "
            f"build --output {deployment_artifact_path}",
            f"sha256sum {deployment_artifact_path}",
            install_command,
            "sudo systemctl daemon-reload",
            f"sudo systemctl enable {BROKER_UNIT_NAME}",
            f"sudo systemctl start {BROKER_UNIT_NAME}",
        ],
        "dry_run_commands": [
            "python3 -m admissible.capsule.owner_authority.installer "
            "preinstall-checks",
            "python3 -m admissible.capsule.owner_authority.installer plan "
            f"--authorized-launcher {launcher_username}",
        ],
        "broker_commands": {
            "daemon-reload": "sudo systemctl daemon-reload",
            "enable": f"sudo systemctl enable {BROKER_UNIT_NAME}",
            "start": f"sudo systemctl start {BROKER_UNIT_NAME}",
            "stop": f"sudo systemctl stop {BROKER_UNIT_NAME}",
            "status": f"sudo systemctl status {BROKER_UNIT_NAME}",
            "disable": f"sudo systemctl disable {BROKER_UNIT_NAME}",
        },
        "provisioning_command": phrase_fd_from_ask_password(
            owner_payload_path="<payload.json>"
        ),
        "uninstall_commands": [
            f"sudo systemctl stop {BROKER_UNIT_NAME}",
            f"sudo systemctl disable {BROKER_UNIT_NAME}",
            "sudo python3 -m admissible.capsule.owner_authority.installer "
            "rollback-failed-install",
            "sudo python3 -m admissible.capsule.owner_authority.installer "
            "uninstall --preserve-signing-identity "
            "--acknowledge-destructive-pending-state",
            "sudo systemctl daemon-reload",
        ],
        "postinstall_verification_commands": [
            "python3 -m admissible.capsule.owner_authority.installer verify",
        ],
        "dedicated_account_removal_commands": [
            f"# only after verify reports no remaining installation references "
            f"{launcher_username}",
            f"sudo userdel {launcher_username}",
            f"sudo groupdel {launcher_group}",
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
        f"deployment artifact  : {plan['deployment_artifact_path']}",
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
            "Launcher account (not created by this task)",
            "-" * 44,
        ]
    )
    lines.extend(f"  $ {command}" for command in plan["launcher_account_commands"])
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


# ---------------------------------------------------------------------------
# The transactional install
# ---------------------------------------------------------------------------


def perform_installation(
    *,
    layout: OwnerAuthorityLayout,
    installation_id: str,
    authorized_launcher_uid: int,
    authorized_launcher_gid: int,
    authorized_launcher_username: str | None = None,
    deployment_artifact_source: Path | None = None,
    deployment_artifact_sha256: str | None = None,
    install_unit: bool = True,
    crash_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Perform the bounded, symlink-safe, transactional privileged install.

    Requires uid 0.  Every filesystem object this call creates is journaled
    before the next step runs; on any failure before the final commit, exactly
    the journaled objects are removed --- nothing else --- and the
    unpublished, still-private signing key never survives a failed install.
    ``crash_hook``, when supplied, is called with a checkpoint name after each
    step; it exists only so tests can inject a failure at an exact point and
    assert the rollback it produces.

    Production installs require ``deployment_artifact_source`` and
    ``deployment_artifact_sha256``.  Synthetic privilege-witness installs may
    omit the artifact.
    """

    require_privileged_identity("owner-authority installation")
    active = layout.validated()
    _refuse_symlink_targets(active)
    _refuse_unknown_prior_state(active)

    if authorized_launcher_username is not None:
        import pwd

        entry = pwd.getpwuid(authorized_launcher_uid)
        if entry.pw_name != authorized_launcher_username:
            raise OwnerAuthorityInstallerError(
                "authorized launcher username does not match uid",
                classification="OWNER_AUTHORITY_LAUNCHER_IDENTITY_MISMATCH",
            )
        validate_authorized_launcher(
            username=entry.pw_name,
            uid=authorized_launcher_uid,
            gid=authorized_launcher_gid,
            shell=entry.pw_shell,
            layout=active,
            deployment_artifact=(
                Path(deployment_artifact_source)
                if deployment_artifact_source is not None
                else DEPLOYMENT_ARTIFACT_PATH
            ),
        )
    elif active.is_production:
        raise OwnerAuthorityInstallerError(
            "production installation requires a validated authorized launcher",
            classification="OWNER_AUTHORITY_LAUNCHER_REQUIRED",
        )

    require_artifact = active.is_production or (
        deployment_artifact_source is not None
        or deployment_artifact_sha256 is not None
    )
    if require_artifact and (
        deployment_artifact_source is None or deployment_artifact_sha256 is None
    ):
        raise OwnerAuthorityInstallerError(
            "installation requires --deployment-artifact and "
            "--deployment-artifact-sha256",
            classification="OWNER_AUTHORITY_ARTIFACT_REQUIRED",
        )

    from admissible.capsule.owner_authority.deployment_artifact import (
        copy_deployment_artifact_without_execute,
    )
    from admissible.capsule.owner_authority.crypto_revision import (
        write_crypto_attestation_current_pointer,
    )
    from admissible.capsule.owner_authority.installation import (
        INITIAL_CRYPTO_ATTESTATION_REVISION,
    )

    txn = _InstallTransaction(active)
    txn.open()
    artifact_identity = None
    try:
        _refuse_symlink_targets(active)
        executable = discover_system_openssl()

        for directory, mode in (
            (active.configuration_root, 0o755),
            (active.state_root, 0o700),
            (active.private_directory, 0o700),
            (active.authorizations_root, 0o700),
            (active.runtime_root, 0o755),
        ):
            _create_directory_no_adoption(directory, mode)
            os.chown(directory, 0, 0)
            os.chmod(directory, mode)
            txn.record("directory", directory)
            if crash_hook is not None:
                crash_hook(f"after_directory:{directory.name}")

        if deployment_artifact_source is not None:
            parent = DEPLOYMENT_ARTIFACT_PATH.parent
            if _lstat_or_none(parent) is None:
                _create_directory_no_adoption(parent, 0o755)
                os.chown(parent, 0, 0)
                os.chmod(parent, 0o755)
                txn.record("directory", parent)
            copied = copy_deployment_artifact_without_execute(
                source=Path(deployment_artifact_source),
                destination=DEPLOYMENT_ARTIFACT_PATH,
                expected_sha256=deployment_artifact_sha256,
            )
            txn.record("file", DEPLOYMENT_ARTIFACT_PATH)
            os.chown(DEPLOYMENT_ARTIFACT_PATH, 0, 0)
            os.chmod(DEPLOYMENT_ARTIFACT_PATH, 0o755)
            fsync_directory(parent)
            artifact_identity = {
                "path": copied["path"],
                "sha256": copied["sha256"],
                "size": copied["size"],
            }
            if crash_hook is not None:
                crash_hook("after_deployment_artifact")

        identity = generate_signing_identity(
            executable=executable,
            private_key_path=active.private_key_path,
            public_key_path=active.public_key_path,
        )
        txn.record("file", active.private_key_path)
        txn.record("file", active.public_key_path)
        os.chown(active.private_key_path, 0, 0)
        os.chmod(active.private_key_path, 0o600)
        os.chown(active.public_key_path, 0, 0)
        os.chmod(active.public_key_path, 0o444)
        if crash_hook is not None:
            crash_hook("after_signing_identity")

        record = build_installation_record(
            layout=active,
            installation_id=installation_id,
            signing_key_fingerprint=identity["signing_key_fingerprint"],
            public_key_sha256=identity["public_key_sha256"],
            cryptographic_executable_identity=executable,
            authorized_launcher_uid=authorized_launcher_uid,
            authorized_launcher_gid=authorized_launcher_gid,
            installer_uid=0,
            deployment_artifact_identity=artifact_identity,
        )

        # Complete revalidation immediately before publication: every object
        # created above must still be exactly what this transaction made.
        _revalidate_before_publication(txn)
        if crash_hook is not None:
            crash_hook("before_publication")

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
        txn.record("file", active.installation_record_path)
        os.chown(active.installation_record_path, 0, 0)
        os.chmod(active.installation_record_path, 0o444)
        fsync_directory(active.configuration_root)
        from admissible.capsule.owner_authority.crypto_revision import (
            CRYPTO_ATTESTATION_CURRENT_POINTER,
            _crypto_attestation_directory,
        )

        crypto_dir = _crypto_attestation_directory(active)
        if not any(
            entry["path"] == str(crypto_dir) for entry in txn.entries
        ):
            txn.record("directory", crypto_dir)
        write_crypto_attestation_current_pointer(
            active, INITIAL_CRYPTO_ATTESTATION_REVISION
        )
        pointer = crypto_dir / CRYPTO_ATTESTATION_CURRENT_POINTER
        txn.record("file", pointer)
        if crash_hook is not None:
            crash_hook("after_record_published")

        unit_path = None
        if install_unit:
            unit_path = Path("/etc/systemd/system") / BROKER_UNIT_NAME
            if _lstat_or_none(unit_path) is not None:
                raise OwnerAuthorityInstallerError(
                    f"refusing to adopt a pre-existing object at {unit_path}",
                    classification="OWNER_AUTHORITY_INSTALL_ADOPTION_REFUSED",
                )
            unit_path.write_text(broker_unit_definition(active), encoding="utf-8")
            txn.record("file", unit_path)
            os.chown(unit_path, 0, 0)
            os.chmod(unit_path, 0o644)
            reload_systemd()

        # Final full re-attestation: prove the published installation is
        # exactly what a genuine unprivileged verifier would observe.
        if active.is_production:
            attest_production_installation()
        else:
            attest_synthetic_non_production_installation(active)
        if crash_hook is not None:
            crash_hook("after_final_attestation")
    except BaseException:
        txn.rollback()
        raise
    finally:
        txn.close()

    return {
        "schema_version": "admissible_owner_authority_installation_result_v1",
        "installation_id": installation_id,
        "record_identity": record["record_identity"],
        "signing_key_fingerprint": identity["signing_key_fingerprint"],
        "installation_record_path": str(active.installation_record_path),
        "deployment_artifact_identity": artifact_identity,
        "authorized_launcher_uid": authorized_launcher_uid,
        "authorized_launcher_gid": authorized_launcher_gid,
        "broker_unit_path": str(unit_path) if unit_path else None,
        "broker_started": False,
    }


# ---------------------------------------------------------------------------
# Real uninstall
# ---------------------------------------------------------------------------


def stop_broker_unit(unit_name: str = BROKER_UNIT_NAME) -> dict[str, Any]:
    """Stop the broker unit.  A thin, stubbable wrapper around ``systemctl``."""

    if shutil.which("systemctl") is None:
        return {"action": "stop", "skipped": True, "reason": "systemctl not present"}
    completed = subprocess.run(
        ["systemctl", "stop", unit_name], capture_output=True, check=False
    )
    return {
        "action": "stop",
        "skipped": False,
        "returncode": completed.returncode,
    }


def disable_broker_unit(unit_name: str = BROKER_UNIT_NAME) -> dict[str, Any]:
    """Disable the broker unit.  A thin, stubbable wrapper around ``systemctl``."""

    if shutil.which("systemctl") is None:
        return {
            "action": "disable",
            "skipped": True,
            "reason": "systemctl not present",
        }
    completed = subprocess.run(
        ["systemctl", "disable", unit_name], capture_output=True, check=False
    )
    return {
        "action": "disable",
        "skipped": False,
        "returncode": completed.returncode,
    }


def reload_systemd() -> dict[str, Any]:
    """Best-effort ``systemctl daemon-reload``.  A thin, stubbable wrapper."""

    if shutil.which("systemctl") is None:
        return {
            "action": "daemon-reload",
            "skipped": True,
            "reason": "systemctl not present",
        }
    completed = subprocess.run(
        ["systemctl", "daemon-reload"], capture_output=True, check=False
    )
    return {
        "action": "daemon-reload",
        "skipped": False,
        "returncode": completed.returncode,
    }


def _pending_authorization_record_ids(layout: OwnerAuthorityLayout) -> list[str]:
    from admissible.capsule.owner_authority.state import (
        AUTHORIZATION_ABSENT,
        AuthorizationStateDirectory,
    )

    root = layout.authorizations_root
    if not root.is_dir():
        return []
    pending = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        directory = AuthorizationStateDirectory(layout, entry.name)
        state = directory.current_state()
        if state not in (AUTHORIZATION_ABSENT, LAUNCH_RESULT_RECORDED):
            pending.append(entry.name)
    return pending


def _authorization_inventory(layout: OwnerAuthorityLayout) -> dict[str, list[str]]:
    from admissible.capsule.owner_authority.layout import (
        CONSUMED_LAUNCH_COMMITTED,
        PHRASE_VERIFIED,
        PROVISIONED_PENDING,
        RECEIPT_ISSUED,
    )
    from admissible.capsule.owner_authority.state import (
        AuthorizationStateDirectory,
    )

    inventory = {
        "pending": [],
        "phrase_verified": [],
        "consumed": [],
        "receipted": [],
        "launch_result_recorded": [],
    }
    root = layout.authorizations_root
    if not root.is_dir():
        return inventory
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        directory = AuthorizationStateDirectory(layout, entry.name)
        state = directory.current_state()
        if state == PROVISIONED_PENDING:
            inventory["pending"].append(entry.name)
        elif state == PHRASE_VERIFIED:
            inventory["phrase_verified"].append(entry.name)
        elif state == CONSUMED_LAUNCH_COMMITTED:
            inventory["consumed"].append(entry.name)
        elif state == RECEIPT_ISSUED:
            inventory["receipted"].append(entry.name)
        elif state == LAUNCH_RESULT_RECORDED:
            inventory["launch_result_recorded"].append(entry.name)
    return inventory


def _install_journal_entries(layout: OwnerAuthorityLayout) -> list[Path]:
    journal_root = _journal_root(layout)
    if _lstat_or_none(journal_root) is None:
        return []
    try:
        return sorted(path for path in journal_root.iterdir() if path.is_dir())
    except OSError:
        return []


def _incomplete_installation_state(
    layout: OwnerAuthorityLayout,
) -> tuple[bool, dict[str, Any]]:
    active = layout.validated()
    record_present = _lstat_or_none(active.installation_record_path) is not None
    private_key_present = _lstat_or_none(active.private_key_path) is not None
    partial_targets = [
        str(target)
        for target in _inventory_targets(active)
        if _lstat_or_none(target) is not None
    ]
    journal_entries = [str(path) for path in _install_journal_entries(active)]
    complete = record_present and private_key_present
    incomplete = bool(
        journal_entries
        or (private_key_present and not record_present)
        or (partial_targets and not complete)
    )
    return incomplete, {
        "complete_installation_present": complete,
        "installation_record_present": record_present,
        "private_key_present": private_key_present,
        "partial_targets_present": partial_targets,
        "install_journal_entries": journal_entries,
    }


def _best_effort_broker_processes() -> list[str]:
    patterns = (
        BROKER_UNIT_NAME,
        str(DEPLOYMENT_ARTIFACT_PATH),
        "admissible.capsule.owner_authority.broker_service",
    )
    observed: list[str] = []
    if shutil.which("pgrep") is None:
        return observed
    for pattern in patterns:
        completed = subprocess.run(
            ["pgrep", "-af", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            observed.extend(
                line.strip()
                for line in completed.stdout.splitlines()
                if line.strip()
            )
    return sorted(set(observed))


def perform_rollback_failed_install(
    *,
    layout: OwnerAuthorityLayout,
    service_manager: ServiceManager | None = None,
    remove_unit: bool = True,
) -> dict[str, Any]:
    """Remove only the residue of an incomplete installation.  Requires uid 0.

    Refuses when a complete installation record and private signing key both
    exist; established signing identities must be removed with uninstall.
    """

    require_privileged_identity("owner-authority rollback-failed-install")
    active = layout.validated()
    manager = service_manager or _DEFAULT_SERVICE_MANAGER
    incomplete, observation = _incomplete_installation_state(active)
    if observation["complete_installation_present"]:
        raise OwnerAuthorityInstallerError(
            "refusing rollback-failed-install: a complete installation record "
            "and private signing key both exist; use uninstall instead",
            classification="OWNER_AUTHORITY_ROLLBACK_COMPLETE_INSTALL_REFUSED",
        )
    if not incomplete:
        return {
            "schema_version": (
                "admissible_owner_authority_rollback_failed_install_result_v1"
            ),
            "rolled_back": False,
            "idempotent_noop": True,
            "observation": observation,
            "residual_processes": _best_effort_broker_processes(),
            "verification": {
                "configuration_root_absent": _lstat_or_none(
                    active.configuration_root
                )
                is None,
                "state_root_absent": _lstat_or_none(active.state_root) is None,
                "runtime_root_absent": _lstat_or_none(active.runtime_root) is None,
                "deployment_artifact_absent": (
                    not active.is_production
                    or _lstat_or_none(DEPLOYMENT_ARTIFACT_PATH) is None
                ),
            },
        }

    broker_stop = manager.stop_broker_unit()
    broker_disable = manager.disable_broker_unit()
    removed: list[str] = []

    for journal_dir in _install_journal_entries(active):
        _remove_tree_no_follow(journal_dir)
        removed.append(str(journal_dir))
    journal_root = _journal_root(active)
    if _lstat_or_none(journal_root) is not None and not any(
        journal_root.iterdir()
    ):
        os.rmdir(journal_root)
        removed.append(str(journal_root))

    _remove_tree_no_follow(active.runtime_root)
    if _lstat_or_none(active.runtime_root) is not None:
        removed.append(str(active.runtime_root))

    for path in (
        active.installation_record_path,
        active.public_key_path,
        active.private_key_path,
    ):
        if _lstat_or_none(path):
            os.unlink(path)
            removed.append(str(path))

    for target in (
        active.configuration_root,
        active.state_root,
    ):
        if _lstat_or_none(target) is not None:
            _remove_tree_no_follow(target)
            removed.append(str(target))

    crypto_dir = active.configuration_root / "crypto-attestations"
    if _lstat_or_none(crypto_dir) is not None:
        _remove_tree_no_follow(crypto_dir)
        removed.append(str(crypto_dir))

    if active.is_production and _lstat_or_none(DEPLOYMENT_ARTIFACT_PATH):
        os.unlink(DEPLOYMENT_ARTIFACT_PATH)
        removed.append(str(DEPLOYMENT_ARTIFACT_PATH))
        parent = DEPLOYMENT_ARTIFACT_PATH.parent
        if _lstat_or_none(parent) is not None and not any(parent.iterdir()):
            os.rmdir(parent)
            removed.append(str(parent))

    unit_removed = False
    if remove_unit:
        unit_path = Path("/etc/systemd/system") / BROKER_UNIT_NAME
        if _lstat_or_none(unit_path):
            os.unlink(unit_path)
            unit_removed = True
            removed.append(str(unit_path))

    reload_result = manager.reload_systemd()
    residual_processes = _best_effort_broker_processes()
    verification = {
        "configuration_root_absent": _lstat_or_none(active.configuration_root)
        is None,
        "state_root_absent": _lstat_or_none(active.state_root) is None,
        "runtime_root_absent": _lstat_or_none(active.runtime_root) is None,
        "deployment_artifact_absent": (
            not active.is_production
            or _lstat_or_none(DEPLOYMENT_ARTIFACT_PATH) is None
        ),
        "broker_socket_absent": _lstat_or_none(active.broker_socket_path) is None,
        "residual_processes_absent": not residual_processes,
    }
    if not all(verification.values()):
        raise OwnerAuthorityInstallerError(
            "rollback-failed-install did not remove every incomplete path: "
            + json.dumps(verification, sort_keys=True),
            classification="OWNER_AUTHORITY_ROLLBACK_INCOMPLETE",
        )
    return {
        "schema_version": (
            "admissible_owner_authority_rollback_failed_install_result_v1"
        ),
        "rolled_back": True,
        "idempotent_noop": False,
        "observation": observation,
        "removed": sorted(set(removed)),
        "broker_stop": broker_stop,
        "broker_disable": broker_disable,
        "unit_removed": unit_removed,
        "systemd_reload": reload_result,
        "residual_processes": residual_processes,
        "verification": verification,
    }


def _remove_tree_no_follow(root: Path) -> None:
    """Remove exactly this tree.  Never follows a directory symlink."""

    if _lstat_or_none(root) is None:
        return

    def _remove(path: Path) -> None:
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if entry.is_symlink():
                        os.unlink(child)
                    elif entry.is_dir(follow_symlinks=False):
                        _remove(child)
                        os.rmdir(child)
                    else:
                        os.unlink(child)
        except NotADirectoryError:
            os.unlink(path)

    info = os.lstat(root)
    if stat.S_ISLNK(info.st_mode):
        os.unlink(root)
        return
    if stat.S_ISDIR(info.st_mode):
        _remove(root)
        os.rmdir(root)
        return
    os.unlink(root)


def perform_uninstall(
    *,
    layout: OwnerAuthorityLayout,
    mode: str,
    acknowledge_destructive_pending_state: bool = False,
    remove_unit: bool = True,
    service_manager: ServiceManager | None = None,
) -> dict[str, Any]:
    """Uninstall a real installation.  Requires uid 0.

    Refuses while a pending or incomplete launch state exists (anything short
    of ``LAUNCH_RESULT_RECORDED``) unless the caller explicitly acknowledges
    the destruction.  Either preserves the signing identity in a fixed,
    root-owned archive, or destroys it; this function makes no claim about
    physical media sanitization in either case --- it only unlinks filesystem
    objects.
    """

    require_privileged_identity("owner-authority uninstall")
    if mode not in (UNINSTALL_MODE_PRESERVE, UNINSTALL_MODE_DESTROY):
        raise OwnerAuthorityInstallerError(
            "uninstall mode must be preserve or destroy signing identity",
            classification="OWNER_AUTHORITY_UNINSTALL_MODE_REFUSED",
        )
    active = layout.validated()
    manager = service_manager or _DEFAULT_SERVICE_MANAGER
    authorization_inventory = _authorization_inventory(active)

    pending = _pending_authorization_record_ids(active)
    if pending and not acknowledge_destructive_pending_state:
        raise OwnerAuthorityInstallerError(
            "refusing: pending or incomplete launch state exists for "
            + ", ".join(pending)
            + "; pass --acknowledge-destructive-pending-state to proceed "
            "anyway",
            classification="OWNER_AUTHORITY_UNINSTALL_PENDING_STATE",
        )

    broker_stop = manager.stop_broker_unit()
    broker_disable = manager.disable_broker_unit()

    archived_to = None
    if mode == UNINSTALL_MODE_PRESERVE and _lstat_or_none(
        active.private_key_path
    ):
        archive_root = (
            active.configuration_root.parent
            / ARCHIVE_DIRECTORY_NAME
            / active.configuration_root.name
        )
        _mkdir_chain_no_symlink(archive_root, 0o700)
        for source, name in (
            (active.private_key_path, "owner-authority-signing-key.v1.pem"),
            (active.public_key_path, "owner-authority-signing-key.v1.pub.pem"),
            (active.installation_record_path, "installation-v1.json"),
        ):
            if not _lstat_or_none(source):
                continue
            data = source.read_bytes()
            destination = archive_root / name
            if _lstat_or_none(destination):
                raise OwnerAuthorityInstallerError(
                    f"refusing to overwrite a pre-existing archive object "
                    f"at {destination}",
                    classification="OWNER_AUTHORITY_INSTALL_ADOPTION_REFUSED",
                )
            descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            try:
                offset = 0
                while offset < len(data):
                    offset += os.write(descriptor, data[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if destination.read_bytes() != data:
                raise OwnerAuthorityInstallerError(
                    f"archived signing material at {destination} failed byte "
                    "verification"
                )
        os.chmod(archive_root, 0o700)
        archived_to = str(archive_root)

    signing_key_destroyed = bool(_lstat_or_none(active.private_key_path))
    _remove_tree_no_follow(active.runtime_root)
    _remove_tree_no_follow(active.state_root)
    crypto_dir = active.configuration_root / "crypto-attestations"
    if _lstat_or_none(crypto_dir) is not None:
        _remove_tree_no_follow(crypto_dir)
    for path in (active.installation_record_path, active.public_key_path):
        if _lstat_or_none(path):
            os.chmod(path.parent, 0o755)
            os.unlink(path)
    if _lstat_or_none(active.configuration_root):
        # Remove any remaining non-directory entries then the root itself.
        for entry in sorted(active.configuration_root.iterdir()):
            info = os.lstat(entry)
            if stat.S_ISDIR(info.st_mode):
                _remove_tree_no_follow(entry)
            else:
                os.unlink(entry)
        os.rmdir(active.configuration_root)

    artifact_removed = False
    artifact_parent_removed = False
    if active.is_production and _lstat_or_none(DEPLOYMENT_ARTIFACT_PATH):
        os.unlink(DEPLOYMENT_ARTIFACT_PATH)
        artifact_removed = True
        parent = DEPLOYMENT_ARTIFACT_PATH.parent
        if _lstat_or_none(parent) is not None and not any(parent.iterdir()):
            os.rmdir(parent)
            artifact_parent_removed = True

    unit_removed = False
    if remove_unit:
        unit_path = Path("/etc/systemd/system") / BROKER_UNIT_NAME
        if _lstat_or_none(unit_path):
            os.unlink(unit_path)
            unit_removed = True

    reload_result = manager.reload_systemd()

    verification = {
        "configuration_root_absent": _lstat_or_none(active.configuration_root)
        is None,
        "state_root_absent": _lstat_or_none(active.state_root) is None,
        "runtime_root_absent": _lstat_or_none(active.runtime_root) is None,
        "deployment_artifact_absent": (
            not active.is_production
            or _lstat_or_none(DEPLOYMENT_ARTIFACT_PATH) is None
        ),
    }
    if not all(verification.values()):
        raise OwnerAuthorityInstallerError(
            "uninstall did not remove every production path: "
            + json.dumps(verification, sort_keys=True),
            classification="OWNER_AUTHORITY_UNINSTALL_INCOMPLETE",
        )

    result = {
        "schema_version": "admissible_owner_authority_uninstall_result_v1",
        "mode": mode,
        "authorization_inventory": authorization_inventory,
        "pending_state_acknowledged": bool(pending)
        and acknowledge_destructive_pending_state,
        "broker_stop": broker_stop,
        "broker_disable": broker_disable,
        "signing_identity_archived_to": archived_to,
        "signing_key_destroyed": signing_key_destroyed,
        "deployment_artifact_removed": artifact_removed,
        "deployment_artifact_parent_removed": artifact_parent_removed,
        "unit_removed": unit_removed,
        "systemd_reload": reload_result,
        "verification": verification,
        "dedicated_launcher_account_removed": False,
        "dedicated_launcher_account_removal_note": (
            "uninstall never removes the dedicated launcher account; that is "
            "a separate explicit owner action after verify reports no remaining "
            "installation references"
        ),
        "physical_media_sanitization_performed": False,
        "physical_media_sanitization_note": (
            "this uninstall unlinks filesystem objects only; it makes no "
            "claim about erasure of the underlying storage media"
        ),
    }
    if mode == UNINSTALL_MODE_DESTROY:
        result["signing_key_destroyed_note"] = (
            "destroying the signing key makes every receipt issued under this "
            "installation permanently unverifiable"
        )
    return result


def verify_installation() -> dict[str, Any]:
    """Post-install verification, provider-free and unprivileged."""

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
    install_parser.add_argument(
        "--deployment-artifact", required=True, type=Path
    )
    install_parser.add_argument(
        "--deployment-artifact-sha256", required=True
    )
    uninstall_parser = commands.add_parser("uninstall", help="remove the install")
    uninstall_mode = uninstall_parser.add_mutually_exclusive_group(required=True)
    uninstall_mode.add_argument(
        "--preserve-signing-identity", action="store_true"
    )
    uninstall_mode.add_argument("--destroy-signing-identity", action="store_true")
    uninstall_parser.add_argument(
        "--acknowledge-destructive-pending-state", action="store_true"
    )
    commands.add_parser(
        "rollback-failed-install",
        help="remove residue from an incomplete installation",
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
            uid, gid, username, _group = _resolve_launcher(
                arguments.authorized_launcher
            )
            result = perform_installation(
                layout=production_layout(),
                installation_id=(
                    arguments.installation_id or os.urandom(16).hex()
                ),
                authorized_launcher_uid=uid,
                authorized_launcher_gid=gid,
                authorized_launcher_username=username,
                deployment_artifact_source=arguments.deployment_artifact,
                deployment_artifact_sha256=arguments.deployment_artifact_sha256,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if arguments.command == "uninstall":
            mode = (
                UNINSTALL_MODE_PRESERVE
                if arguments.preserve_signing_identity
                else UNINSTALL_MODE_DESTROY
            )
            result = perform_uninstall(
                layout=production_layout(),
                mode=mode,
                acknowledge_destructive_pending_state=(
                    arguments.acknowledge_destructive_pending_state
                ),
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if arguments.command == "rollback-failed-install":
            result = perform_rollback_failed_install(layout=production_layout())
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except (
        OwnerAuthorityError,
        OwnerAuthorityInstallationError,
        OwnerAuthorityLauncherAccountError,
    ) as error:
        print(f"{error}", file=sys.stderr)
        return 1
    return 2  # pragma: no cover - argparse enforces a command


refuse_symlink_or_special_targets = _refuse_symlink_targets


def validate_service_unit_text(text: str) -> dict[str, Any]:
    """Static validation of the broker unit without installing it."""

    required = (
        "Type=notify",
        "Restart=on-failure",
        "RestartSec=2",
        str(DEPLOYMENT_ARTIFACT_PATH),
        "RuntimeDirectory=",
        "NotifyAccess=main",
    )
    forbidden = (
        "PYTHONPATH",
        "/home/",
        "pip install",
        "Type=simple",
        "Restart=no",
        "-m admissible.capsule.owner_authority.broker_service",
    )
    missing = [item for item in required if item not in text]
    present_forbidden = [item for item in forbidden if item in text]
    if missing or present_forbidden:
        raise OwnerAuthorityInstallerError(
            "broker unit failed static validation: "
            f"missing={missing} forbidden={present_forbidden}",
            classification="OWNER_AUTHORITY_UNIT_INVALID",
        )
    return {"valid": True, "references_deployment_artifact": True}


__all__ = [
    "ARCHIVE_DIRECTORY_NAME",
    "BROKER_UNIT_NAME",
    "DEPLOYMENT_ARTIFACT_PATH",
    "INSTALLED_OBJECTS",
    "OwnerAuthorityInstallerError",
    "OwnerAuthorityLauncherAccountError",
    "RECOMMENDED_LAUNCHER_GROUP",
    "RECOMMENDED_LAUNCHER_USERNAME",
    "ServiceManager",
    "UNINSTALL_MODE_DESTROY",
    "UNINSTALL_MODE_PRESERVE",
    "broker_unit_definition",
    "disable_broker_unit",
    "installation_plan",
    "launcher_account_creation_commands",
    "perform_installation",
    "perform_rollback_failed_install",
    "perform_uninstall",
    "preinstall_conflict_checks",
    "refuse_symlink_or_special_targets",
    "reload_systemd",
    "render_installation_plan",
    "require_privileged_identity",
    "stop_broker_unit",
    "validate_authorized_launcher",
    "validate_service_unit_text",
    "verify_installation",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
