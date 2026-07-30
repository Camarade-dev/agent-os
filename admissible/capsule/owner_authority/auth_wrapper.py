"""Bounded authentication-wrapper entry point for the dedicated launcher.

This module turns the designed ChatGPT-auth identity split into an exact,
non-executed runbook plus a mechanical entry point that can validate the
wrapper plan without reading credential bytes.

It never falls back to running Codex or the launcher as ``stris``.  It never
opens, copies or prints durable authentication contents.  Host-side privilege
and account creation remain owner actions.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.owner_authority.launcher_account import (
    RECOMMENDED_LAUNCHER_USERNAME,
    LauncherAccountError,
    validate_launcher_username,
)
from admissible.capsule.owner_authority.layout import OwnerAuthorityError

AUTH_WRAPPER_RUNBOOK_SCHEMA = "admissible_launcher_auth_wrapper_runbook_v1"
AUTH_WRAPPER_STATUS_EXECUTABLE = "RUNBOOK_EXECUTABLE_REQUIRES_HOST_SETUP"


class AuthWrapperError(OwnerAuthorityError):
    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_AUTH_WRAPPER_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def auth_wrapper_runbook(
    *,
    durable_auth_source: str = "<durable-chatgpt-auth.json>",
    launcher_username: str = RECOMMENDED_LAUNCHER_USERNAME,
) -> dict[str, Any]:
    """Exact non-executed runbook for the privileged-open → drop → SCM_RIGHTS path."""

    return {
        "schema_version": AUTH_WRAPPER_RUNBOOK_SCHEMA,
        "status": AUTH_WRAPPER_STATUS_EXECUTABLE,
        "credential_bytes_exposed_to_launcher": False,
        "never_run_as": ["stris"],
        "recommended_launcher": launcher_username,
        "steps": [
            {
                "order": 1,
                "actor": "privileged_wrapper (uid 0)",
                "action": (
                    "open the durable Codex authentication source with "
                    "O_RDONLY|O_CLOEXEC|O_NOFOLLOW without reading bytes"
                ),
                "path": durable_auth_source,
            },
            {
                "order": 2,
                "actor": "privileged_wrapper",
                "action": (
                    "fstat the directory and file descriptors; refuse unless "
                    "root-owned regular file, mode forbids other-write, and "
                    "path is not a symlink"
                ),
            },
            {
                "order": 3,
                "actor": "privileged_wrapper",
                "action": (
                    f"setuid/setgid permanently to {launcher_username}; keep "
                    "only the already-open durable auth FD"
                ),
            },
            {
                "order": 4,
                "actor": launcher_username,
                "action": (
                    "start BoundaryLauncher; fork the same-uid authentication "
                    "broker and pass the durable auth FD over SEQPACKET"
                ),
            },
            {
                "order": 5,
                "actor": "authentication_broker (same uid)",
                "action": (
                    "read credential bytes only inside the broker child; write "
                    "ephemeral CODEX_HOME; return only a directory FD via "
                    "SCM_RIGHTS"
                ),
            },
            {
                "order": 6,
                "actor": "controller and Codex",
                "action": (
                    "receive only the ephemeral home FD; never reopen the "
                    "durable source; never inherit launcher filesystem rights "
                    "on the durable path"
                ),
            },
            {
                "order": 7,
                "actor": "authentication_broker",
                "action": (
                    "on cleanup or restart wipe the ephemeral home; the durable "
                    "source remains untouched; a restart reopens only through "
                    "the privileged wrapper"
                ),
            },
        ],
        "exact_entry_point": (
            "python3 -m admissible.capsule.owner_authority.auth_wrapper "
            "validate-plan --durable-auth-source <path> "
            f"--launcher {launcher_username}"
        ),
        "not_executed_by_implementation_task": True,
    }


def validate_auth_wrapper_plan(
    *,
    durable_auth_source: Path,
    launcher_username: str = RECOMMENDED_LAUNCHER_USERNAME,
    require_existing_source: bool = False,
) -> dict[str, Any]:
    """Validate the wrapper plan without reading credential bytes.

    When ``require_existing_source`` is true, opens the path with O_RDONLY and
    fstats it, then immediately closes the descriptor without reading content.
    """

    if launcher_username == "stris":
        raise AuthWrapperError(
            "refusing to plan the auth wrapper for stris; use the dedicated "
            "launcher account",
            classification="OWNER_AUTHORITY_AUTH_WRAPPER_STRIS_REFUSED",
        )
    try:
        launcher = validate_launcher_username(launcher_username)
    except LauncherAccountError as error:
        # Host may not have created the account yet; record that as host-setup.
        launcher = {
            "validated": False,
            "username": launcher_username,
            "classification": error.classification,
            "detail": str(error),
            "host_setup_required": True,
        }

    source = Path(durable_auth_source)
    source_attestation: dict[str, Any] = {
        "path": str(source),
        "opened": False,
        "bytes_read": 0,
    }
    if require_existing_source:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(source, flags)
        except FileNotFoundError as error:
            raise AuthWrapperError(
                f"durable auth source is absent: {source}",
                classification="OWNER_AUTHORITY_AUTH_SOURCE_ABSENT",
            ) from error
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise AuthWrapperError(
                    "durable auth source is not a regular file",
                    classification="OWNER_AUTHORITY_AUTH_SOURCE_REFUSED",
                )
            if info.st_uid != 0:
                raise AuthWrapperError(
                    "durable auth source must be root-owned for the privileged "
                    "open step",
                    classification="OWNER_AUTHORITY_AUTH_SOURCE_REFUSED",
                )
            source_attestation.update(
                {
                    "opened": True,
                    "owner_uid": info.st_uid,
                    "owner_gid": info.st_gid,
                    "mode": stat.S_IMODE(info.st_mode),
                    "size": info.st_size,
                    "bytes_read": 0,
                }
            )
        finally:
            os.close(descriptor)

    runbook = auth_wrapper_runbook(
        durable_auth_source=str(source),
        launcher_username=launcher_username,
    )
    return {
        "schema_version": "admissible_launcher_auth_wrapper_validation_v1",
        "status": AUTH_WRAPPER_STATUS_EXECUTABLE,
        "runbook": runbook,
        "launcher": launcher,
        "durable_auth_source": source_attestation,
        "credential_bytes_exposed": False,
        "falls_back_to_stris": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admissible-owner-authority-auth-wrapper",
        description=(
            "Render or validate the dedicated-launcher authentication wrapper "
            "runbook without reading credential bytes."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render-runbook", help="print the exact runbook")
    render.add_argument(
        "--durable-auth-source", default="<durable-chatgpt-auth.json>"
    )
    render.add_argument("--launcher", default=RECOMMENDED_LAUNCHER_USERNAME)
    validate = commands.add_parser(
        "validate-plan", help="validate the wrapper plan without reading bytes"
    )
    validate.add_argument("--durable-auth-source", required=True, type=Path)
    validate.add_argument("--launcher", default=RECOMMENDED_LAUNCHER_USERNAME)
    validate.add_argument(
        "--require-existing-source",
        action="store_true",
        help="open and fstat the source without reading content",
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "render-runbook":
            result = auth_wrapper_runbook(
                durable_auth_source=arguments.durable_auth_source,
                launcher_username=arguments.launcher,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if arguments.command == "validate-plan":
            result = validate_auth_wrapper_plan(
                durable_auth_source=arguments.durable_auth_source,
                launcher_username=arguments.launcher,
                require_existing_source=arguments.require_existing_source,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
