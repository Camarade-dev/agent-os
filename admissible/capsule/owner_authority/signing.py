"""Ed25519 signing and verification through a content-attested system OpenSSL.

Section B of the repair allows either a justified pinned Python dependency or a
content-attested system cryptographic executable.  This module takes the second
route, deliberately:

* the wheel and sdist gain no new dependency, so nothing about the packaged
  distribution changes when the owner authority is installed;
* the isolated test environment needs no index access, so the privilege witness
  runs with the same primitive the real installation would use;
* the primitive is a well-reviewed implementation (OpenSSL's Ed25519, RFC 8032)
  and no cryptography is implemented here --- this module only marshals bytes
  in and out of ``openssl``.

The executable is *content attested*: its path, device, inode, owner, mode and
SHA-256 are recorded by the privileged installer and re-verified on every use.
Substituting an ``openssl`` on ``PATH``, or a copy at another path, does not
validate.  Private key material is never passed through argv, an environment
variable or IPC --- ``openssl`` reads it from a root-owned file by path, and
only the broker ever names that path.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    mode_type,
    require_exact_keys,
    require_sha256,
    require_strict_int,
    sha256_bytes,
)
from admissible.capsule.owner_authority.layout import OwnerAuthorityError

#: The signature algorithm.  Ed25519 is used in its pure form (``-rawin``), so
#: the signed message is exactly the canonical receipt payload bytes.
SIGNING_ALGORITHM = "ed25519"

#: Where a system OpenSSL may legitimately live.  A caller cannot extend this,
#: and ``PATH`` is never consulted.
SYSTEM_OPENSSL_CANDIDATES = (
    Path("/usr/bin/openssl"),
    Path("/bin/openssl"),
    Path("/usr/local/bin/openssl"),
)

_EXECUTABLE_IDENTITY_KEYS = {
    "path",
    "sha256",
    "device",
    "inode",
    "owner_uid",
    "owner_gid",
    "mode",
    "size",
    "file_type",
}

_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_SIGNATURE_BYTES = 64


class OwnerAuthoritySigningError(OwnerAuthorityError):
    """A refusal on the signing/verification path."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_SIGNING_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def _stat_executable(path: Path) -> os.stat_result:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OwnerAuthoritySigningError(
            f"cryptographic executable is not an openable regular file: {path}",
            classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_REFUSED",
        ) from error
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def executable_identity(path: Path) -> dict[str, Any]:
    """Content-attest a cryptographic executable at an exact path.

    The identity binds the content hash *and* the inode, so neither replacing
    the file in place nor pointing at a copy elsewhere reproduces it.
    """

    if not isinstance(path, Path) or not path.is_absolute():
        raise OwnerAuthoritySigningError(
            "cryptographic executable requires an absolute path",
            classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_REFUSED",
        )
    info = _stat_executable(path)
    if not stat.S_ISREG(info.st_mode):
        raise OwnerAuthoritySigningError(
            "cryptographic executable is not a regular file",
            classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_REFUSED",
        )
    if info.st_size > _MAX_EXECUTABLE_BYTES:
        raise OwnerAuthoritySigningError(
            "cryptographic executable exceeds its attestation bound",
            classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_REFUSED",
        )
    # Not group- or world-writable is the invariant that matters here: anyone
    # who can write the binary can sign anything.  The *owner* of the binary is
    # recorded in the identity and additionally required to be uid 0 by
    # production installation validation --- under a user namespace the host
    # root appears unmapped, so that check belongs to the production boundary
    # rather than to attestation itself.
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise OwnerAuthoritySigningError(
            "cryptographic executable is group- or world-writable",
            classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_REFUSED",
        )
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "file_type": mode_type(info.st_mode),
    }


def discover_system_openssl() -> dict[str, Any]:
    """Attest the first system OpenSSL that satisfies the content rules."""

    failures: list[str] = []
    for candidate in SYSTEM_OPENSSL_CANDIDATES:
        try:
            return executable_identity(candidate)
        except OwnerAuthoritySigningError as error:
            failures.append(f"{candidate}: {error.classification}")
    raise OwnerAuthoritySigningError(
        "no content-attestable system cryptographic executable was found "
        f"({'; '.join(failures) or 'no candidates'})",
        classification="OWNER_AUTHORITY_CRYPTO_UNRESOLVED",
    )


def validate_executable_identity(
    value: Any, label: str = "cryptographic executable identity"
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerAuthoritySigningError(f"{label} is not an object")
    require_exact_keys(dict(value), set(_EXECUTABLE_IDENTITY_KEYS), label)
    require_sha256(value["sha256"], f"{label} sha256")
    for key, maximum in (
        ("device", 2**63 - 1),
        ("inode", 2**63 - 1),
        ("owner_uid", 2**31 - 1),
        ("owner_gid", 2**31 - 1),
        ("mode", 0o7777),
        ("size", _MAX_EXECUTABLE_BYTES),
    ):
        require_strict_int(value[key], f"{label} {key}", minimum=0, maximum=maximum)
    if value["file_type"] != "regular":
        raise OwnerAuthoritySigningError(f"{label} is not a regular file")
    return dict(value)


def reattest_executable(expected: Mapping[str, Any]) -> dict[str, Any]:
    """Re-verify a recorded executable identity, refusing any drift."""

    recorded = validate_executable_identity(expected)
    observed = executable_identity(Path(recorded["path"]))
    if observed != recorded:
        raise OwnerAuthoritySigningError(
            "the attested cryptographic executable changed since installation",
            classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_CHANGED",
        )
    return observed


class _PrivateWorkspace:
    """A 0700 scratch directory for the bounded ``openssl`` invocations."""

    def __init__(self) -> None:
        self._path: Path | None = None

    def __enter__(self) -> Path:
        self._path = Path(tempfile.mkdtemp(prefix="owner-authority-crypto-"))
        os.chmod(self._path, 0o700)
        return self._path

    def __exit__(self, *_exc: object) -> None:
        if self._path is not None:
            shutil.rmtree(self._path, ignore_errors=True)
            self._path = None


def _run_openssl(
    executable: Mapping[str, Any],
    arguments: list[str],
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[bytes]:
    identity = reattest_executable(executable)
    return subprocess.run(
        [identity["path"], *arguments],
        capture_output=True,
        check=False,
        timeout=timeout,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def _write_private(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def public_key_fingerprint(
    executable: Mapping[str, Any], public_key_pem: bytes
) -> str:
    """The SHA-256 of the DER SubjectPublicKeyInfo --- the key's identity."""

    with _PrivateWorkspace() as workspace:
        public_path = workspace / "public.pem"
        _write_private(public_path, public_key_pem, 0o600)
        completed = _run_openssl(
            executable,
            ["pkey", "-pubin", "-in", str(public_path), "-outform", "DER"],
        )
    if completed.returncode != 0 or not completed.stdout:
        raise OwnerAuthoritySigningError(
            "the owner-authority public key is not a readable Ed25519 key",
            classification="OWNER_AUTHORITY_PUBLIC_KEY_REFUSED",
        )
    return sha256_bytes(completed.stdout)


def generate_signing_identity(
    *,
    executable: Mapping[str, Any],
    private_key_path: Path,
    public_key_path: Path,
) -> dict[str, Any]:
    """Generate the owner-authority signing identity.  Installer use only.

    The private key is created directly at its final root-owned path with mode
    0600 and never leaves it.  Only the caller's umask-independent explicit mode
    applies, and the key bytes are never returned.
    """

    if private_key_path.exists() or public_key_path.exists():
        raise OwnerAuthoritySigningError(
            "an owner-authority signing identity already exists at this path",
            classification="OWNER_AUTHORITY_KEY_ALREADY_PRESENT",
        )
    previous_umask = os.umask(0o077)
    try:
        completed = _run_openssl(
            executable,
            [
                "genpkey",
                "-algorithm",
                SIGNING_ALGORITHM,
                "-out",
                str(private_key_path),
            ],
        )
        if completed.returncode != 0 or not private_key_path.exists():
            raise OwnerAuthoritySigningError(
                "the privileged installer could not generate an Ed25519 "
                "signing identity",
                classification="OWNER_AUTHORITY_CRYPTO_UNRESOLVED",
            )
        os.chmod(private_key_path, 0o600)
        completed = _run_openssl(
            executable,
            [
                "pkey",
                "-in",
                str(private_key_path),
                "-pubout",
                "-out",
                str(public_key_path),
            ],
        )
        if completed.returncode != 0 or not public_key_path.exists():
            raise OwnerAuthoritySigningError(
                "the privileged installer could not publish the public "
                "verification key",
                classification="OWNER_AUTHORITY_CRYPTO_UNRESOLVED",
            )
        os.chmod(public_key_path, 0o644)
    finally:
        os.umask(previous_umask)
    public_key_pem = public_key_path.read_bytes()
    return {
        "algorithm": SIGNING_ALGORITHM,
        "public_key_sha256": sha256_bytes(public_key_pem),
        "signing_key_fingerprint": public_key_fingerprint(
            executable, public_key_pem
        ),
    }


def sign_message(
    *,
    executable: Mapping[str, Any],
    private_key_path: Path,
    message: bytes,
) -> bytes:
    """Sign exact bytes with the root-owned private key.  Broker use only."""

    if not isinstance(message, (bytes, bytearray)) or not message:
        raise OwnerAuthoritySigningError("refusing to sign empty material")
    with _PrivateWorkspace() as workspace:
        message_path = workspace / "message.bin"
        signature_path = workspace / "signature.bin"
        _write_private(message_path, bytes(message), 0o600)
        completed = _run_openssl(
            executable,
            [
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key_path),
                "-rawin",
                "-in",
                str(message_path),
                "-out",
                str(signature_path),
            ],
        )
        if completed.returncode != 0 or not signature_path.exists():
            raise OwnerAuthoritySigningError(
                "the owner-authority broker could not sign the receipt",
                classification="OWNER_AUTHORITY_SIGNATURE_UNAVAILABLE",
            )
        signature = signature_path.read_bytes()
    if len(signature) != _SIGNATURE_BYTES:
        raise OwnerAuthoritySigningError(
            "the owner-authority signature is not an Ed25519 signature",
            classification="OWNER_AUTHORITY_SIGNATURE_UNAVAILABLE",
        )
    return signature


def verify_signature(
    *,
    executable: Mapping[str, Any],
    public_key_pem: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify a signature against an exact public key.  Refuses on any doubt.

    The caller must have obtained ``public_key_pem`` from the attested
    root-owned installation record; this function deliberately has no idea
    where a key "should" come from and never searches for one.
    """

    if not isinstance(signature, (bytes, bytearray)) or len(signature) != (
        _SIGNATURE_BYTES
    ):
        return False
    if not isinstance(message, (bytes, bytearray)) or not message:
        return False
    with _PrivateWorkspace() as workspace:
        public_path = workspace / "public.pem"
        message_path = workspace / "message.bin"
        signature_path = workspace / "signature.bin"
        _write_private(public_path, bytes(public_key_pem), 0o600)
        _write_private(message_path, bytes(message), 0o600)
        _write_private(signature_path, bytes(signature), 0o600)
        completed = _run_openssl(
            executable,
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ],
        )
    return completed.returncode == 0
