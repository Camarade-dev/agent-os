"""Root-only authorization provisioning (section D).

Provisioning one specific future launch is a privileged owner action, separate
from installation and separate from the runtime broker.  There is no
provisioning RPC: the running broker cannot create an authorization, and no
public library function callable by an ordinary process can create a production
pending-authorization record.  The two mechanical reasons are that this entry
point refuses a non-root effective uid, and that the production
``authorizations`` directory is root-owned and mode 0700, so an unprivileged
copy of this executable fails on both counts.

The owner sees a bounded, human-readable summary of exactly what will be
authorized, confirms its fingerprint, and supplies the phrase only on a
dedicated descriptor.  Only the digest is retained --- the phrase is never
written, logged, returned or fingerprinted on its own.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    require_identifier,
    strict_json_loads,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallation,
    attest_production_installation,
)
from admissible.capsule.owner_authority.installer import (
    require_privileged_identity,
)
from admissible.capsule.owner_authority.layout import (
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    OwnerAuthorityError,
    PROVISIONED_PENDING,
)
from admissible.capsule.owner_authority.records import (
    build_pending_authorization_record,
    external_owner_authorization_digest,
    new_authorization_record_id,
)
from admissible.capsule.owner_authority.state import AuthorizationStateDirectory

OWNER_PHRASE_MAX_BYTES = 4096
OWNER_PHRASE_MIN_BYTES = 8

#: The dedicated descriptor the owner phrase may arrive on.
OWNER_PHRASE_DESCRIPTOR_ENV = "ADMISSIBLE_OWNER_AUTHORITY_PHRASE_FD"


class OwnerAuthorityProvisioningError(OwnerAuthorityError):
    """A refusal on the privileged provisioning path."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_PROVISIONING_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def read_owner_phrase_from_descriptor(descriptor: int) -> str:
    """Read the owner phrase from its dedicated bounded descriptor.

    A terminal or character device is refused so the phrase can never be
    scraped from a shared console.  The result is used for exactly one digest
    computation and is never persisted.
    """

    if isinstance(descriptor, bool) or not isinstance(descriptor, int):
        raise OwnerAuthorityProvisioningError(
            "owner phrase descriptor must be an integer",
            classification="OWNER_AUTHORITY_PHRASE_CHANNEL_REFUSED",
        )
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise OwnerAuthorityProvisioningError(
            "owner phrase descriptor is not open",
            classification="OWNER_AUTHORITY_PHRASE_CHANNEL_REFUSED",
        ) from error
    if os.isatty(descriptor) or not (
        stat.S_ISFIFO(info.st_mode)
        or stat.S_ISSOCK(info.st_mode)
        or stat.S_ISREG(info.st_mode)
    ):
        raise OwnerAuthorityProvisioningError(
            "the owner phrase must arrive on a private pipe, socket or memfd",
            classification="OWNER_AUTHORITY_PHRASE_CHANNEL_REFUSED",
        )
    collected = bytearray()
    while len(collected) <= OWNER_PHRASE_MAX_BYTES:
        block = os.read(descriptor, OWNER_PHRASE_MAX_BYTES + 1 - len(collected))
        if not block:
            break
        collected.extend(block)
    if len(collected) > OWNER_PHRASE_MAX_BYTES:
        raise OwnerAuthorityProvisioningError(
            "owner phrase exceeds its byte bound",
            classification="OWNER_AUTHORITY_PHRASE_CHANNEL_REFUSED",
        )
    try:
        phrase = bytes(collected).decode("utf-8").strip("\r\n")
    except UnicodeDecodeError as error:
        raise OwnerAuthorityProvisioningError(
            "owner phrase is not UTF-8 text",
            classification="OWNER_AUTHORITY_PHRASE_CHANNEL_REFUSED",
        ) from error
    finally:
        for index in range(len(collected)):
            collected[index] = 0
    if len(phrase.encode("utf-8")) < OWNER_PHRASE_MIN_BYTES or "\x00" in phrase:
        raise OwnerAuthorityProvisioningError(
            "owner phrase is empty, too short, or contains NUL",
            classification="OWNER_AUTHORITY_PHRASE_CHANNEL_REFUSED",
        )
    return phrase


def owner_payload_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The bounded summary the owner must read before confirming."""

    body = dict(payload)
    policy = dict(body.get("model_binding_policy") or {})
    return {
        "schema_version": "admissible_owner_authority_payload_summary_v1",
        "repository_head": body.get("repository_head"),
        "implementation_head": body.get("implementation_head"),
        "run_id": body.get("run_id"),
        "preparation_id": body.get("preparation_id"),
        "mission_fingerprint": body.get("mission_fingerprint"),
        "model": policy.get("configured_model"),
        "reasoning_effort": policy.get("configured_reasoning_effort"),
        "destination_authority": body.get("destination_manifest_identity"),
        "effect_authority": body.get("tool_authority_identity"),
        "budgets": dict(body.get("budgets") or {}),
        "retries_authorized": 0,
        "repairs_authorized": 0,
        "launches_authorized": 1,
        "payload_fingerprint": fingerprint(body),
    }


def render_owner_payload_summary(summary: Mapping[str, Any]) -> str:
    """Render the summary as bounded, human-readable text."""

    budgets = summary["budgets"]
    lines = [
        "Owner authorization request",
        "=" * 27,
        "",
        f"  repository HEAD      : {summary['repository_head']}",
        f"  implementation HEAD  : {summary['implementation_head']}",
        f"  run identity         : {summary['run_id']}",
        f"  preparation identity : {summary['preparation_id']}",
        f"  mission              : {summary['mission_fingerprint']}",
        f"  model                : {summary['model']}",
        f"  reasoning effort     : {summary['reasoning_effort']}",
        f"  destination authority: {summary['destination_authority']}",
        f"  effect authority     : {summary['effect_authority']}",
        "  budgets              : "
        + (
            ", ".join(f"{name}={limit}" for name, limit in sorted(budgets.items()))
            or "(none)"
        ),
        f"  retries              : {summary['retries_authorized']}",
        f"  repairs              : {summary['repairs_authorized']}",
        f"  launches authorized  : {summary['launches_authorized']}",
        "",
        f"  payload fingerprint  : {summary['payload_fingerprint']}",
        "",
        "This authorizes exactly one launch.  Nothing else may reuse it.",
    ]
    return "\n".join(lines) + "\n"


def provision_authorization(
    *,
    installation: OwnerAuthorityInstallation,
    owner_payload: Mapping[str, Any],
    owner_phrase: str,
    authorization_record_id: str | None = None,
) -> dict[str, Any]:
    """Write the immutable root-owned pending-authorization record.

    This function requires the privileged identity, and every path it writes is
    derived from the attested installation --- never from a caller argument.
    """

    require_privileged_identity("owner authorization provisioning")
    attested = installation.validated()
    payload_body = dict(owner_payload)
    payload_bytes = canonical_bytes(payload_body)
    payload_fingerprint = fingerprint(payload_body)
    record_id = authorization_record_id or new_authorization_record_id()
    digest = external_owner_authorization_digest(
        phrase=owner_phrase,
        payload_bytes=payload_bytes,
        authorization_record_id=record_id,
    )
    del owner_phrase
    record = build_pending_authorization_record(
        authorization_record_id=record_id,
        installation=attested,
        expected_owner_authorization_digest=digest,
        owner_payload=payload_body,
        owner_payload_fingerprint=payload_fingerprint,
    )
    directory = AuthorizationStateDirectory(attested.layout, record_id)
    marker = directory.provision(record)
    return {
        "schema_version": "admissible_owner_authority_provisioning_result_v1",
        "state": PROVISIONED_PENDING,
        "authorization_record_id": record_id,
        "authorization_record_identity": record["record_identity"],
        "owner_payload_fingerprint": payload_fingerprint,
        "installation_identity": attested.installation_identity,
        "digest_construction": EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
        "pending_record_identity": marker,
        "launches_authorized": 1,
        "phrase_retained": False,
    }


def _load_payload(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    payload = strict_json_loads(raw, label="owner payload")
    if not isinstance(payload, Mapping):
        raise OwnerAuthorityProvisioningError("owner payload is not an object")
    body = {
        key: item for key, item in payload.items() if key != "payload_fingerprint"
    }
    supplied = payload.get("payload_fingerprint")
    if supplied is not None and supplied != fingerprint(body):
        raise OwnerAuthorityProvisioningError(
            "owner payload fingerprint does not match its own bytes",
            classification="OWNER_AUTHORITY_PAYLOAD_REFUSED",
        )
    return body


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admissible-owner-authority-provisioner",
        description=(
            "Provision exactly one future launch as the privileged owner."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    summarize = commands.add_parser(
        "summarize", help="print the payload summary without provisioning"
    )
    summarize.add_argument("--owner-payload", required=True, type=Path)
    provision = commands.add_parser("provision", help="provision one launch")
    provision.add_argument("--owner-payload", required=True, type=Path)
    provision.add_argument("--phrase-fd", type=int, default=None)
    provision.add_argument(
        "--confirm-payload-fingerprint",
        default=None,
        help="the exact payload fingerprint the owner has read and accepts",
    )
    arguments = parser.parse_args(argv)

    try:
        payload = _load_payload(arguments.owner_payload)
        summary = owner_payload_summary(payload)
        if arguments.command == "summarize":
            print(render_owner_payload_summary(summary), end="")
            return 0

        require_privileged_identity("owner authorization provisioning")
        print(render_owner_payload_summary(summary), end="")
        confirmation = arguments.confirm_payload_fingerprint
        if confirmation is None:
            confirmation = input(
                "Re-type the payload fingerprint to authorize this launch: "
            ).strip()
        if confirmation != summary["payload_fingerprint"]:
            print(
                "refusing: the confirmed fingerprint does not match the "
                "payload the owner was shown",
                file=sys.stderr,
            )
            return 1

        descriptor = arguments.phrase_fd
        if descriptor is None:
            environment = os.environ.get(OWNER_PHRASE_DESCRIPTOR_ENV)
            if environment is None:
                print(
                    "refusing: the owner phrase must arrive on a dedicated "
                    f"descriptor (--phrase-fd or {OWNER_PHRASE_DESCRIPTOR_ENV})",
                    file=sys.stderr,
                )
                return 1
            descriptor = int(environment)
        phrase = read_owner_phrase_from_descriptor(descriptor)
        try:
            result = provision_authorization(
                installation=attest_production_installation(),
                owner_payload=payload,
                owner_phrase=phrase,
            )
        finally:
            del phrase
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
