"""Dedicated non-privileged launcher identity for production execution.

The production launcher must be a dedicated account such as
``admissible-launcher``.  It must not be root, must not belong to sudo/docker
or other configured privileged groups, must not write the installation or
state roots, and must not own the deployment artifact.

This module validates that identity and emits exact creation commands for
later owner execution.  It never creates the account.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.owner_authority.deployment_artifact import (
    DEPLOYMENT_ARTIFACT_PATH,
)
from admissible.capsule.owner_authority.layout import (
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    production_layout,
)

RECOMMENDED_LAUNCHER_USERNAME = "admissible-launcher"
RECOMMENDED_LAUNCHER_GROUP = "admissible-launcher"
DEFAULT_PRIVILEGED_GROUPS = frozenset(
    {"sudo", "docker", "wheel", "root", "adm"}
)
NONINTERACTIVE_SHELLS = frozenset(
    {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}
)


class LauncherAccountError(OwnerAuthorityError):
    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_LAUNCHER_REFUSED",
    ):
        super().__init__(detail, classification=classification)


#: Alias preferred by the installer module.
OwnerAuthorityLauncherAccountError = LauncherAccountError


def launcher_account_creation_commands(
    *,
    username: str = RECOMMENDED_LAUNCHER_USERNAME,
    group: str = RECOMMENDED_LAUNCHER_GROUP,
) -> list[str]:
    """Exact commands for later owner execution.  Not run by this task."""

    return [
        f"sudo groupadd --system {group}",
        f"sudo useradd --system --gid {group} --home-dir /nonexistent "
        f"--shell /usr/sbin/nologin --comment 'Admissible boundary launcher' "
        f"{username}",
        f"id {username}",
        f"groups {username}",
        # Prove the account is outside sudo and docker.
        f"! id -nG {username} | tr ' ' '\\n' | grep -Ex 'sudo|docker|wheel|root'",
    ]


def auth_boundary_identity_integration_note() -> Mapping[str, Any]:
    """How ephemeral CODEX_HOME reaches the dedicated launcher without bytes.

    The existing authentication broker forks from the boundary launcher and
    requires the same uid on both ends of its SEQPACKET channel.  Credential
    bytes are read only inside the broker child from an already-open source
    FD, then an ephemeral home directory FD is handed back over SCM_RIGHTS.

    Across a launcher identity split the required host pattern is:

    1. a privileged wrapper opens the ChatGPT auth source with O_RDONLY;
    2. the wrapper drops privileges to ``admissible-launcher`` while keeping
       the FD;
    3. ``BoundaryLauncher`` (running as ``admissible-launcher``) starts the
       authentication broker as the same uid and passes that FD;
    4. the broker alone reads credential bytes, writes the ephemeral home,
       and returns only a directory FD for bwrap ``--bind-fd``.

    No credential bytes cross argv, environment, or the handoff packet.  The
    dedicated launcher never needs filesystem permission on the durable auth
    file.  The exact runbook and bounded entry point live in
    ``admissible.capsule.owner_authority.auth_wrapper``.
    """

    from admissible.capsule.owner_authority.auth_wrapper import (
        AUTH_WRAPPER_STATUS_EXECUTABLE,
        auth_wrapper_runbook,
    )

    runbook = auth_wrapper_runbook()
    return {
        "schema_version": "admissible_launcher_auth_identity_integration_v1",
        "status": AUTH_WRAPPER_STATUS_EXECUTABLE,
        "recommended_launcher": RECOMMENDED_LAUNCHER_USERNAME,
        "credential_bytes_exposed_to_launcher": False,
        "mechanism": (
            "privileged_open_fd_then_drop_to_launcher_then_same_uid_auth_broker"
        ),
        "entry_point": runbook["exact_entry_point"],
        "runbook_schema": runbook["schema_version"],
        "never_run_as": ["stris"],
        "creation_commands": launcher_account_creation_commands(),
    }


def _group_names_for_user(username: str, primary_gid: int) -> set[str]:
    names = set()
    try:
        names.add(grp.getgrgid(primary_gid).gr_name)
    except KeyError:
        pass
    for entry in grp.getgrall():
        if username in entry.gr_mem:
            names.add(entry.gr_name)
    return names


def validate_authorized_launcher(
    *,
    username: str,
    uid: int,
    gid: int,
    shell: str,
    layout: OwnerAuthorityLayout | None = None,
    privileged_groups: Sequence[str] = tuple(sorted(DEFAULT_PRIVILEGED_GROUPS)),
    allow_interactive_shell: bool = False,
    deployment_artifact: Path = DEPLOYMENT_ARTIFACT_PATH,
    group_names: set[str] | None = None,
) -> dict[str, Any]:
    """Refuse a launcher that is root, privileged, or writable on install roots."""

    active = (layout or production_layout()).validated()
    if uid == 0:
        raise LauncherAccountError(
            "authorized launcher must not be uid 0",
            classification="OWNER_AUTHORITY_LAUNCHER_IS_ROOT",
        )
    groups = (
        set(group_names)
        if group_names is not None
        else _group_names_for_user(username, gid)
    )
    forbidden = groups.intersection(privileged_groups)
    if forbidden:
        raise LauncherAccountError(
            f"authorized launcher belongs to privileged groups: "
            f"{', '.join(sorted(forbidden))}",
            classification="OWNER_AUTHORITY_LAUNCHER_PRIVILEGED_GROUP",
        )
    if not allow_interactive_shell and shell not in NONINTERACTIVE_SHELLS:
        raise LauncherAccountError(
            f"authorized launcher has unexpected interactive shell {shell!r}; "
            "pass allow_interactive_shell only with explicit owner justification",
            classification="OWNER_AUTHORITY_LAUNCHER_INTERACTIVE_SHELL",
        )
    for path in (
        active.configuration_root,
        active.state_root,
        active.runtime_root,
        deployment_artifact,
        deployment_artifact.parent,
    ):
        try:
            info = os.stat(path)
        except FileNotFoundError:
            continue
        if info.st_uid == uid:
            raise LauncherAccountError(
                f"authorized launcher owns installation path {path}",
                classification="OWNER_AUTHORITY_LAUNCHER_OWNS_INSTALLATION",
            )
        # Writable by the launcher uid via owner/group/other write bits.
        mode = info.st_mode
        if info.st_uid == uid and mode & stat.S_IWUSR:
            raise LauncherAccountError(
                f"authorized launcher can write {path}",
                classification="OWNER_AUTHORITY_LAUNCHER_CAN_WRITE_INSTALLATION",
            )
        if info.st_gid == gid and mode & stat.S_IWGRP:
            raise LauncherAccountError(
                f"authorized launcher group can write {path}",
                classification="OWNER_AUTHORITY_LAUNCHER_CAN_WRITE_INSTALLATION",
            )
    return {
        "validated": True,
        "username": username,
        "uid": uid,
        "gid": gid,
        "shell": shell,
        "groups": sorted(groups),
        "auth_boundary_integration": dict(auth_boundary_identity_integration_note()),
    }


def validate_launcher_username(name: str) -> dict[str, Any]:
    """Resolve and validate a launcher account that already exists on the host."""

    try:
        entry = pwd.getpwnam(name)
    except KeyError as error:
        raise LauncherAccountError(
            f"unknown authorized launcher account {name!r}",
            classification="OWNER_AUTHORITY_LAUNCHER_UNKNOWN",
        ) from error
    return validate_authorized_launcher(
        username=entry.pw_name,
        uid=entry.pw_uid,
        gid=entry.pw_gid,
        shell=entry.pw_shell,
    )
