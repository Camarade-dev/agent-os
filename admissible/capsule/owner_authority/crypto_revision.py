"""Root-only crypto-attestation revision: authorize a new OpenSSL, keep the key.

The signing key never rotates through this path --- only the *cryptographic
executable identity* the installation trusts to use it does.  That is a
narrower, safer operation than reinstalling, and it is the one an operator
actually needs after a host package upgrade replaces ``/usr/bin/openssl``: the
old attested executable identity (path, device, inode, owner, mode, SHA-256)
no longer matches what is on disk, and every effect that reattests it before
signing or verifying would otherwise refuse forever.

Every revision is explicit, owner-confirmed, append-only and bound to the
installation and public key it was issued for:

* the owner supplies the new executable's SHA-256 and version out of band and
  it must match exactly what this module independently attests from the fixed
  candidate path --- never a ``PATH`` lookup, never a symlink;
* the candidate executable must pass a real Ed25519 sign/verify round-trip
  before it is ever trusted;
* every revision is appended under
  ``configuration_root/crypto-attestations/<revision_id>.json`` and never
  overwritten --- the full history stays on disk;
* a revision that does not chain from the currently committed revision, or
  that would change the signing key fingerprint, is refused;
* a revision is refused outright while any authorization is pending or
  in-flight;
* the stable installation identity is preserved across revisions so historical
  receipts remain verifiable against the append-only history;
* the installation record's ``cryptographic_executable_identity`` and
  ``crypto_attestation_revision`` fields are updated atomically, in the same
  replace, and nothing else in the record changes.

There is no broker RPC for any of this.  A running broker only ever reads the
one field --- ``crypto_attestation_revision`` --- of the record it re-attests
on every use; it has no operation that lets a caller request, propose or
commit a revision.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    fsync_directory,
    require_identifier,
    require_sha256,
    strict_json_loads,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallation,
    build_installation_record,
)
from admissible.capsule.owner_authority.installer import require_privileged_identity
from admissible.capsule.owner_authority.layout import (
    AUTHORIZATIONS_SUBDIRECTORY,
    LAUNCH_RESULT_RECORDED,
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    production_layout,
)
from admissible.capsule.owner_authority.signing import (
    SIGNING_ALGORITHM,
    SYSTEM_OPENSSL_CANDIDATES,
    executable_identity,
    generate_signing_identity,
    sign_message,
    validate_executable_identity,
    verify_signature,
)

CRYPTO_ATTESTATION_REVISION_SCHEMA_VERSION = (
    "admissible_owner_authority_crypto_attestation_revision_v1"
)
CRYPTO_PROBE_SCHEMA_VERSION = "admissible_owner_authority_crypto_probe_v1"

#: Where revisions live, under the fixed root-owned configuration root.
CRYPTO_ATTESTATION_SUBDIRECTORY = "crypto-attestations"

_REVISION_KEYS = frozenset(
    {
        "schema_version",
        "revision_id",
        "installation_id",
        "installation_identity",
        "signing_key_fingerprint",
        "public_key_sha256",
        "previous_crypto_attestation_revision",
        "owner_confirmed_sha256",
        "owner_confirmed_version",
        "cryptographic_executable_identity",
        "ed25519_capability_probe",
        "revision_identity",
    }
)


class OwnerAuthorityCryptoRevisionError(OwnerAuthorityError):
    """A refusal on the crypto-attestation revision path."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_CRYPTO_REVISION_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def crypto_attestation_revision_id() -> str:
    """Unpredictable identity for one crypto-attestation revision."""

    return "crypto-attestation-" + os.urandom(16).hex()


def attest_candidate_executable(path: Path) -> dict[str, Any]:
    """Attest a candidate executable at an exact, fixed, non-``PATH`` path.

    Refuses anything not one of the fixed system OpenSSL candidate paths, so
    an owner cannot be tricked into authorizing an arbitrary executable or a
    copy planted elsewhere; :func:`~admissible.capsule.owner_authority.
    signing.executable_identity` separately refuses a symlink or a
    group/world-writable file.
    """

    target = Path(path)
    if target not in SYSTEM_OPENSSL_CANDIDATES:
        raise OwnerAuthorityCryptoRevisionError(
            f"{target} is not one of the fixed candidate cryptographic "
            "executable paths",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_PATH_REFUSED",
        )
    return executable_identity(target)


def probe_ed25519_capability(executable: Mapping[str, Any]) -> dict[str, Any]:
    """Prove the candidate executable can genuinely sign and verify Ed25519.

    Uses a throwaway keypair in a private temporary directory; nothing here
    touches the installation's real signing key.
    """

    with tempfile.TemporaryDirectory(
        prefix="owner-authority-crypto-probe-"
    ) as workspace:
        root = Path(workspace)
        private_path = root / "probe.pem"
        public_path = root / "probe.pub.pem"
        generate_signing_identity(
            executable=executable,
            private_key_path=private_path,
            public_key_path=public_path,
        )
        message = (
            b"admissible-owner-authority-crypto-attestation-revision-probe"
        )
        signature = sign_message(
            executable=executable, private_key_path=private_path, message=message
        )
        verified = verify_signature(
            executable=executable,
            public_key_pem=public_path.read_bytes(),
            message=message,
            signature=signature,
        )
    if not verified:
        raise OwnerAuthorityCryptoRevisionError(
            "the candidate executable failed the Ed25519 sign/verify probe",
            classification="OWNER_AUTHORITY_CRYPTO_PROBE_FAILED",
        )
    return {
        "schema_version": CRYPTO_PROBE_SCHEMA_VERSION,
        "algorithm": SIGNING_ALGORITHM,
        "verified": True,
    }


def build_crypto_attestation_revision(
    *,
    installation: OwnerAuthorityInstallation,
    new_executable_path: Path,
    owner_confirmed_sha256: str,
    owner_confirmed_version: str,
    revision_id: str | None = None,
) -> dict[str, Any]:
    """Build one candidate revision.  Does not touch any durable state."""

    attested = installation.validated()
    candidate = attest_candidate_executable(Path(new_executable_path))
    if owner_confirmed_sha256 != candidate["sha256"]:
        raise OwnerAuthorityCryptoRevisionError(
            "the owner-confirmed SHA-256 does not match the candidate "
            "executable",
            classification="OWNER_AUTHORITY_CRYPTO_CONFIRMATION_MISMATCH",
        )
    if (
        not isinstance(owner_confirmed_version, str)
        or not owner_confirmed_version.strip()
        or "\x00" in owner_confirmed_version
    ):
        raise OwnerAuthorityCryptoRevisionError(
            "owner-confirmed version must be non-empty text"
        )
    probe = probe_ed25519_capability(candidate)
    body = {
        "schema_version": CRYPTO_ATTESTATION_REVISION_SCHEMA_VERSION,
        "revision_id": require_identifier(
            revision_id or crypto_attestation_revision_id(),
            "crypto attestation revision id",
        ),
        "installation_id": attested.installation_id,
        "installation_identity": attested.installation_identity,
        "signing_key_fingerprint": attested.signing_key_fingerprint,
        "public_key_sha256": attested.record["public_key_sha256"],
        "previous_crypto_attestation_revision": (
            attested.crypto_attestation_revision()
        ),
        "owner_confirmed_sha256": require_sha256(
            owner_confirmed_sha256, "owner confirmed sha256"
        ),
        "owner_confirmed_version": owner_confirmed_version,
        "cryptographic_executable_identity": validate_executable_identity(
            candidate
        ),
        "ed25519_capability_probe": probe,
    }
    return {**body, "revision_identity": fingerprint(body)}


def validate_crypto_attestation_revision(
    value: Any, label: str = "crypto attestation revision"
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerAuthorityCryptoRevisionError(f"{label} is not an object")
    revision = dict(value)
    if set(revision) != set(_REVISION_KEYS):
        raise OwnerAuthorityCryptoRevisionError(f"invalid {label} keys")
    if revision["schema_version"] != CRYPTO_ATTESTATION_REVISION_SCHEMA_VERSION:
        raise OwnerAuthorityCryptoRevisionError(f"unsupported {label} schema")
    body = {key: item for key, item in revision.items() if key != "revision_identity"}
    if fingerprint(body) != revision["revision_identity"]:
        raise OwnerAuthorityCryptoRevisionError(
            f"{label} fingerprint mismatch",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_INVALID",
        )
    return revision


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _crypto_attestation_directory(layout: OwnerAuthorityLayout) -> Path:
    directory = layout.configuration_root / CRYPTO_ATTESTATION_SUBDIRECTORY
    info = _lstat_or_none(directory)
    if info is None:
        os.mkdir(directory, 0o755)
        os.chown(directory, 0, 0)
    else:
        import stat as _stat

        if _stat.S_ISLNK(info.st_mode) or not _stat.S_ISDIR(info.st_mode):
            raise OwnerAuthorityCryptoRevisionError(
                f"refusing: {directory} exists and is not a plain directory",
                classification="OWNER_AUTHORITY_CRYPTO_REVISION_PATH_REFUSED",
            )
    return directory


def append_crypto_attestation_revision(
    layout: OwnerAuthorityLayout, revision: Mapping[str, Any]
) -> dict[str, Any]:
    """Append one immutable revision.  Never overwrites an earlier one."""

    validated = validate_crypto_attestation_revision(revision)
    directory = _crypto_attestation_directory(layout)
    path = directory / f"{validated['revision_id']}.json"
    if _lstat_or_none(path) is not None:
        raise OwnerAuthorityCryptoRevisionError(
            "this crypto-attestation revision identity is already recorded",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_ALREADY_APPENDED",
        )
    encoded = canonical_bytes(validated)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(path, 0, 0)
    os.chmod(path, 0o444)
    fsync_directory(directory)
    return {"path": str(path), "revision_id": validated["revision_id"]}


def list_crypto_attestation_revisions(
    layout: OwnerAuthorityLayout,
) -> list[dict[str, Any]]:
    """Every historical revision, oldest first.  Unprivileged and read-only."""

    directory = layout.configuration_root / CRYPTO_ATTESTATION_SUBDIRECTORY
    if not directory.is_dir():
        return []
    revisions = []
    for entry in sorted(directory.glob("*.json")):
        raw = entry.read_bytes()
        value = strict_json_loads(raw, label="crypto attestation revision")
        revisions.append(validate_crypto_attestation_revision(value))
    return revisions


#: Filename of the current crypto-revision pointer under the attestation dir.
CRYPTO_ATTESTATION_CURRENT_POINTER = "CURRENT"


def load_crypto_attestation_revision_for_verification(
    *,
    layout: OwnerAuthorityLayout,
    revision_id: str,
    installation_identity: str,
    signing_key_fingerprint: str,
    public_key_sha256: str,
    allow_initial: bool = False,
    initial_executable: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Load one historical revision for receipt verification.

    The revision need not be the current pointer.  Deleted, altered or
    re-fingerprinted history refuses.  The initial install revision may be
    reconstructed from terminal evidence when no append-only file yet exists.
    """

    from admissible.capsule.owner_authority.installation import (
        INITIAL_CRYPTO_ATTESTATION_REVISION,
    )

    require_identifier(revision_id, "crypto attestation revision id")
    directory = layout.configuration_root / CRYPTO_ATTESTATION_SUBDIRECTORY
    path = directory / f"{revision_id}.json"
    info = _lstat_or_none(path)
    if info is None:
        if (
            allow_initial
            and revision_id == INITIAL_CRYPTO_ATTESTATION_REVISION
            and initial_executable is not None
        ):
            return {
                "revision_id": revision_id,
                "installation_identity": installation_identity,
                "signing_key_fingerprint": signing_key_fingerprint,
                "public_key_sha256": public_key_sha256,
                "cryptographic_executable_identity": validate_executable_identity(
                    initial_executable
                ),
            }
        raise OwnerAuthorityCryptoRevisionError(
            f"historical crypto-attestation revision {revision_id!r} is absent",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_HISTORY_MISSING",
        )
    import stat as _stat

    if _stat.S_ISLNK(info.st_mode) or not _stat.S_ISREG(info.st_mode):
        raise OwnerAuthorityCryptoRevisionError(
            "historical crypto-attestation revision is not a regular file",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_HISTORY_TAMPERED",
        )
    raw = path.read_bytes()
    try:
        value = strict_json_loads(raw, label="crypto attestation revision")
    except ValueError as error:
        raise OwnerAuthorityCryptoRevisionError(
            "historical crypto-attestation revision is not canonical JSON",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_HISTORY_TAMPERED",
        ) from error
    revision = validate_crypto_attestation_revision(value)
    if revision["revision_id"] != revision_id:
        raise OwnerAuthorityCryptoRevisionError(
            "historical crypto-attestation revision identity mismatch",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_HISTORY_TAMPERED",
        )
    if revision["installation_identity"] != installation_identity:
        raise OwnerAuthorityCryptoRevisionError(
            "historical crypto-attestation revision belongs to another "
            "installation",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_FOREIGN_INSTALLATION",
        )
    if (
        revision["signing_key_fingerprint"] != signing_key_fingerprint
        or revision["public_key_sha256"] != public_key_sha256
    ):
        raise OwnerAuthorityCryptoRevisionError(
            "historical crypto-attestation revision names another signing key",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_KEY_MISMATCH",
        )
    return revision


def write_crypto_attestation_current_pointer(
    layout: OwnerAuthorityLayout, revision_id: str
) -> dict[str, Any]:
    """Atomically publish the current crypto-revision pointer and fsync it."""

    require_identifier(revision_id, "crypto attestation revision id")
    directory = _crypto_attestation_directory(layout)
    pointer = directory / CRYPTO_ATTESTATION_CURRENT_POINTER
    encoded = (revision_id + "\n").encode("ascii")
    temp = directory / f".CURRENT.tmp-{os.urandom(8).hex()}"
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(temp, 0, 0)
    os.chmod(temp, 0o444)
    os.replace(temp, pointer)
    fsync_directory(directory)
    return {"path": str(pointer), "revision_id": revision_id}


def refuse_if_pending_authorization_exists(layout: OwnerAuthorityLayout) -> None:
    """Refuse if any authorization has not reached its terminal state.

    A crypto-attestation revision must not publish while an authorization is
    pending, phrase-verified, consumed or receipt-issued but not yet recorded.
    """

    from admissible.capsule.owner_authority.state import (
        AUTHORIZATION_ABSENT,
        AuthorizationStateDirectory,
    )

    root = layout.authorizations_root
    if not root.is_dir():
        return
    pending = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        directory = AuthorizationStateDirectory(layout, entry.name)
        state = directory.current_state()
        if state not in (AUTHORIZATION_ABSENT, LAUNCH_RESULT_RECORDED):
            pending.append(entry.name)
    if pending:
        raise OwnerAuthorityCryptoRevisionError(
            "refusing: a pending or in-flight authorization exists ("
            + ", ".join(pending)
            + "); a crypto-attestation revision is refused while any "
            "authorization is pending",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_PENDING_AUTHORIZATION",
        )


def update_installation_cryptographic_identity(
    *,
    layout: OwnerAuthorityLayout,
    installation: OwnerAuthorityInstallation,
    revision: Mapping[str, Any],
) -> dict[str, Any]:
    """Commit one revision: append it, then atomically replace the record.

    Preserves the signing key and every other field of the installation
    record; only ``cryptographic_executable_identity`` and
    ``crypto_attestation_revision`` change.  Requires uid 0.
    """

    require_privileged_identity("owner-authority crypto-attestation revision")
    active = layout.validated()
    refuse_if_pending_authorization_exists(active)
    attested = installation.validated()
    validated = validate_crypto_attestation_revision(revision)

    if validated["installation_identity"] != attested.installation_identity:
        raise OwnerAuthorityCryptoRevisionError(
            "this crypto-attestation revision was built for another "
            "installation",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_FOREIGN_INSTALLATION",
        )
    if (
        validated["signing_key_fingerprint"] != attested.signing_key_fingerprint
        or validated["public_key_sha256"] != attested.record["public_key_sha256"]
    ):
        raise OwnerAuthorityCryptoRevisionError(
            "this operation preserves the signing key; it must not change "
            "the signing key fingerprint or public key",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_KEY_MISMATCH",
        )
    if validated["previous_crypto_attestation_revision"] != (
        attested.crypto_attestation_revision()
    ):
        raise OwnerAuthorityCryptoRevisionError(
            "this crypto-attestation revision does not chain from the "
            "currently committed revision; refusing a rollback or a "
            "concurrent, already-superseded revision",
            classification="OWNER_AUTHORITY_CRYPTO_REVISION_STALE",
        )

    appended = append_crypto_attestation_revision(active, validated)
    write_crypto_attestation_current_pointer(active, validated["revision_id"])

    new_record = build_installation_record(
        layout=active,
        installation_id=attested.installation_id,
        signing_key_fingerprint=attested.signing_key_fingerprint,
        public_key_sha256=attested.record["public_key_sha256"],
        cryptographic_executable_identity=(
            validated["cryptographic_executable_identity"]
        ),
        authorized_launcher_uid=attested.record["authorized_launcher_uid"],
        authorized_launcher_gid=attested.record["authorized_launcher_gid"],
        installer_uid=attested.record["installer_uid"],
        crypto_attestation_revision=validated["revision_id"],
        deployment_artifact_identity=attested.record.get(
            "deployment_artifact_identity"
        ),
    )
    encoded = canonical_bytes(new_record)
    temp_path = (
        active.installation_record_path.parent
        / f".installation-v1.json.tmp-{validated['revision_id']}"
    )
    descriptor = os.open(
        temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444
    )
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(temp_path, 0, 0)
    os.chmod(temp_path, 0o444)
    os.replace(temp_path, active.installation_record_path)
    fsync_directory(active.configuration_root)

    return {
        "schema_version": "admissible_owner_authority_crypto_revision_result_v1",
        "installation_record_path": str(active.installation_record_path),
        "new_record_identity": new_record["record_identity"],
        "crypto_attestation_revision": validated["revision_id"],
        "appended_revision_path": appended["path"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    from admissible.capsule.owner_authority.installation import (
        attest_production_installation,
    )

    parser = argparse.ArgumentParser(
        prog="admissible-owner-authority-crypto-revision",
        description=(
            "Authorize a new content-attested OpenSSL executable without "
            "replacing the owner-authority signing key."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list every historical revision")
    authorize = commands.add_parser(
        "authorize", help="authorize a new cryptographic executable revision"
    )
    authorize.add_argument("--executable-path", required=True, type=Path)
    authorize.add_argument("--confirm-sha256", required=True)
    authorize.add_argument("--confirm-version", required=True)
    authorize.add_argument(
        "--acknowledge-explicit-reattestation",
        action="store_true",
        help=(
            "explicit operator acknowledgement that this replaces the "
            "attested cryptographic executable without rotating the signing key"
        ),
    )
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "list":
            revisions = list_crypto_attestation_revisions(production_layout())
            print(json.dumps(revisions, indent=2, sort_keys=True))
            return 0
        if arguments.command == "authorize":
            if not arguments.acknowledge_explicit_reattestation:
                print(
                    "refusing: crypto re-attestation requires "
                    "--acknowledge-explicit-reattestation",
                    file=sys.stderr,
                )
                return 2
            require_privileged_identity(
                "owner-authority crypto-attestation revision"
            )
            installation = attest_production_installation()
            revision = build_crypto_attestation_revision(
                installation=installation,
                new_executable_path=arguments.executable_path,
                owner_confirmed_sha256=arguments.confirm_sha256,
                owner_confirmed_version=arguments.confirm_version,
            )
            result = update_installation_cryptographic_identity(
                layout=production_layout(),
                installation=installation,
                revision=revision,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    return 2  # pragma: no cover - argparse enforces a command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
