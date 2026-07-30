"""The root-owned installation record and its runtime attestation.

The installation record is the only place a verifier learns which public key is
the owner authority.  It is published once by the privileged installer at a
fixed path, and every runtime consumer re-derives its identity from the file it
actually opened: path, device, inode, owner, mode and content.  Nothing here
searches for a key, accepts a key from a caller, or falls back to another path.

``installation_identity`` is the *stable* installation identity bound into the
signed receipt, into ``BackendExecutionAuthority`` and into the launch
fingerprint.  It is deliberately independent of the cryptographic executable
revision and of the mutable record content hash: a crypto-attestation revision
preserves this identity so historical receipts remain verifiable.  It still
changes if the installation id, signing key, public key or layout roots change.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    mode_type,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    sha256_bytes,
    strict_json_loads,
)
from admissible.capsule.owner_authority.layout import (
    BROKER_PROTOCOL_VERSION,
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    INSTALLATION_RECORD_SCHEMA_VERSION,
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    PRODUCTION_CONFIGURATION_ROOT,
    PRODUCTION_LAYOUT,
    PRODUCTION_RUNTIME_ROOT,
    PRODUCTION_STATE_ROOT,
    RECEIPT_SIGNATURE_CONSTRUCTION,
    SYNTHETIC_LAYOUT,
    production_layout,
)
from admissible.capsule.owner_authority.signing import (
    SIGNING_ALGORITHM,
    reattest_executable,
    validate_executable_identity,
)

_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "installation_id",
        "layout_classification",
        "configuration_root",
        "state_root",
        "runtime_root",
        "public_key_path",
        "broker_socket_path",
        "broker_protocol",
        "digest_construction",
        "signature_construction",
        "signing_key_algorithm",
        "signing_key_fingerprint",
        "public_key_sha256",
        "cryptographic_executable_identity",
        "crypto_attestation_revision",
        "authorized_launcher_uid",
        "authorized_launcher_gid",
        "installer_uid",
        "deployment_artifact_identity",
        "record_identity",
    }
)

INITIAL_CRYPTO_ATTESTATION_REVISION = "crypto-attestation-revision-v1-initial"

_FILE_IDENTITY_KEYS = frozenset(
    {
        "path",
        "sha256",
        "device",
        "inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "size",
        "file_type",
        "link_count",
    }
)

_MAX_RECORD_BYTES = 256 * 1024


class OwnerAuthorityInstallationError(OwnerAuthorityError):
    """A refusal while attesting the owner-authority installation."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_INSTALLATION_REFUSED",
    ):
        super().__init__(detail, classification=classification)


def _read_root_owned_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    required_mode_mask: int = 0o022,
) -> tuple[bytes, dict[str, Any]]:
    """Open an exact path, refuse anything not root-owned and unwritable.

    The file is opened once and both the identity and the content come from
    that same descriptor, so nothing can be swapped between the check and the
    read.
    """

    if not isinstance(path, Path) or not path.is_absolute():
        raise OwnerAuthorityInstallationError(
            f"{label} requires an absolute path"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise OwnerAuthorityInstallationError(
            f"{label} is not installed at its fixed path: {path}",
            classification="OWNER_AUTHORITY_NOT_INSTALLED",
        ) from error
    except OSError as error:
        raise OwnerAuthorityInstallationError(
            f"{label} is not an openable regular file at its fixed path: {path}",
        ) from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OwnerAuthorityInstallationError(
                f"{label} is not a regular file"
            )
        if info.st_size > max_bytes:
            raise OwnerAuthorityInstallationError(
                f"{label} exceeds its byte bound"
            )
        if info.st_uid != 0:
            raise OwnerAuthorityInstallationError(
                f"{label} is not owned by the privileged installer identity",
                classification="OWNER_AUTHORITY_INSTALLATION_NOT_ROOT_OWNED",
            )
        if stat.S_IMODE(info.st_mode) & required_mode_mask:
            raise OwnerAuthorityInstallationError(
                f"{label} is group- or world-writable",
                classification="OWNER_AUTHORITY_INSTALLATION_NOT_ROOT_OWNED",
            )
        content = b""
        while len(content) < info.st_size:
            block = os.read(descriptor, info.st_size - len(content))
            if not block:
                break
            content += block
    finally:
        os.close(descriptor)
    identity = {
        "path": str(path),
        "sha256": sha256_bytes(content),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "file_type": mode_type(info.st_mode),
        "link_count": info.st_nlink,
    }
    return content, identity


def validate_file_identity(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerAuthorityInstallationError(f"{label} is not an object")
    require_exact_keys(dict(value), set(_FILE_IDENTITY_KEYS), label)
    require_sha256(value["sha256"], f"{label} sha256")
    for key, maximum in (
        ("device", 2**63 - 1),
        ("inode", 2**63 - 1),
        ("owner_uid", 2**31 - 1),
        ("owner_gid", 2**31 - 1),
        ("mode", 0o7777),
        ("size", _MAX_RECORD_BYTES),
        ("link_count", 4096),
    ):
        require_strict_int(value[key], f"{label} {key}", minimum=0, maximum=maximum)
    if value["file_type"] != "regular":
        raise OwnerAuthorityInstallationError(f"{label} is not a regular file")
    return dict(value)


def build_installation_record(
    *,
    layout: OwnerAuthorityLayout,
    installation_id: str,
    signing_key_fingerprint: str,
    public_key_sha256: str,
    cryptographic_executable_identity: Mapping[str, Any],
    authorized_launcher_uid: int,
    authorized_launcher_gid: int,
    installer_uid: int,
    crypto_attestation_revision: str = INITIAL_CRYPTO_ATTESTATION_REVISION,
    deployment_artifact_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the installation record body.  Called only by the installer."""

    layout.validated()
    artifact = None
    if deployment_artifact_identity is not None:
        if not isinstance(deployment_artifact_identity, Mapping):
            raise OwnerAuthorityInstallationError(
                "deployment artifact identity is not an object"
            )
        artifact = {
            "path": str(deployment_artifact_identity["path"]),
            "sha256": require_sha256(
                deployment_artifact_identity["sha256"],
                "deployment artifact sha256",
            ),
            "size": require_strict_int(
                deployment_artifact_identity["size"],
                "deployment artifact size",
                minimum=1,
                maximum=512 * 1024 * 1024,
            ),
        }
    body = {
        "schema_version": INSTALLATION_RECORD_SCHEMA_VERSION,
        "installation_id": require_identifier(
            installation_id, "installation id"
        ),
        "layout_classification": layout.classification,
        "configuration_root": str(layout.configuration_root),
        "state_root": str(layout.state_root),
        "runtime_root": str(layout.runtime_root),
        "public_key_path": str(layout.public_key_path),
        "broker_socket_path": str(layout.broker_socket_path),
        "broker_protocol": BROKER_PROTOCOL_VERSION,
        "digest_construction": EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
        "signature_construction": RECEIPT_SIGNATURE_CONSTRUCTION,
        "signing_key_algorithm": SIGNING_ALGORITHM,
        "signing_key_fingerprint": require_sha256(
            signing_key_fingerprint, "signing key fingerprint"
        ),
        "public_key_sha256": require_sha256(
            public_key_sha256, "public key sha256"
        ),
        "cryptographic_executable_identity": validate_executable_identity(
            cryptographic_executable_identity
        ),
        "crypto_attestation_revision": require_identifier(
            crypto_attestation_revision, "crypto attestation revision"
        ),
        "authorized_launcher_uid": require_strict_int(
            authorized_launcher_uid,
            "authorized launcher uid",
            minimum=0,
            maximum=2**31 - 1,
        ),
        "authorized_launcher_gid": require_strict_int(
            authorized_launcher_gid,
            "authorized launcher gid",
            minimum=0,
            maximum=2**31 - 1,
        ),
        "installer_uid": require_strict_int(
            installer_uid, "installer uid", minimum=0, maximum=0
        ),
        "deployment_artifact_identity": artifact,
    }
    return {**body, "record_identity": fingerprint(body)}


@dataclass(frozen=True)
class OwnerAuthorityInstallation:
    """An attested owner-authority installation, as observed right now.

    Instances are produced only by :func:`attest_production_installation` (no
    arguments, fixed paths) or by the explicitly named synthetic attestation
    used by the privilege witness.  The ``layout`` classification --- not a
    naming convention --- decides what production will accept.
    """

    layout: OwnerAuthorityLayout
    record: Mapping[str, Any]
    record_file_identity: Mapping[str, Any]
    public_key_file_identity: Mapping[str, Any]
    public_key_pem: bytes
    installation_identity: str

    @property
    def is_production(self) -> bool:
        return self.layout.is_production

    @property
    def installation_id(self) -> str:
        return self.record["installation_id"]

    @property
    def signing_key_fingerprint(self) -> str:
        return self.record["signing_key_fingerprint"]

    @property
    def authorized_launcher_uid(self) -> int:
        return self.record["authorized_launcher_uid"]

    @property
    def cryptographic_executable_identity(self) -> Mapping[str, Any]:
        return dict(self.record["cryptographic_executable_identity"])

    def to_dict(self) -> dict[str, Any]:
        """The attestation, without the public key bytes."""

        return {
            "schema_version": "admissible_owner_authority_installation_attestation_v1",
            "installation_identity": self.installation_identity,
            "installation_id": self.installation_id,
            "layout_classification": self.layout.classification,
            "record_identity": self.record["record_identity"],
            "record_file_identity": dict(self.record_file_identity),
            "public_key_file_identity": dict(self.public_key_file_identity),
            "signing_key_fingerprint": self.signing_key_fingerprint,
            "signing_key_algorithm": self.record["signing_key_algorithm"],
            "broker_protocol": self.record["broker_protocol"],
            "digest_construction": self.record["digest_construction"],
            "signature_construction": self.record["signature_construction"],
            "authorized_launcher_uid": self.authorized_launcher_uid,
            "broker_socket_path": self.record["broker_socket_path"],
        }

    def validated(self) -> "OwnerAuthorityInstallation":
        self.layout.validated()
        record = dict(self.record)
        require_exact_keys(record, set(_RECORD_KEYS), "installation record")
        if record["schema_version"] != INSTALLATION_RECORD_SCHEMA_VERSION:
            raise OwnerAuthorityInstallationError(
                "unsupported installation record schema"
            )
        if record["layout_classification"] != self.layout.classification:
            raise OwnerAuthorityInstallationError(
                "installation record describes another layout classification"
            )
        if (
            record["broker_protocol"] != BROKER_PROTOCOL_VERSION
            or record["digest_construction"] != EXTERNAL_OWNER_DIGEST_CONSTRUCTION
            or record["signature_construction"] != RECEIPT_SIGNATURE_CONSTRUCTION
            or record["signing_key_algorithm"] != SIGNING_ALGORITHM
        ):
            raise OwnerAuthorityInstallationError(
                "installation record binds an unsupported protocol, digest "
                "construction, signature construction or algorithm"
            )
        if (
            record["configuration_root"] != str(self.layout.configuration_root)
            or record["state_root"] != str(self.layout.state_root)
            or record["runtime_root"] != str(self.layout.runtime_root)
            or record["public_key_path"] != str(self.layout.public_key_path)
            or record["broker_socket_path"]
            != str(self.layout.broker_socket_path)
        ):
            raise OwnerAuthorityInstallationError(
                "installation record does not describe the layout it was read "
                "from",
                classification="OWNER_AUTHORITY_INSTALLATION_PATHS_DIFFER",
            )
        body = {key: item for key, item in record.items() if key != "record_identity"}
        if fingerprint(body) != record["record_identity"]:
            raise OwnerAuthorityInstallationError(
                "installation record fingerprint mismatch",
                classification="OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
            )
        record_identity = validate_file_identity(
            self.record_file_identity, "installation record file identity"
        )
        key_identity = validate_file_identity(
            self.public_key_file_identity, "installation public key file identity"
        )
        if record_identity["path"] != str(self.layout.installation_record_path):
            raise OwnerAuthorityInstallationError(
                "the installation record was not read from its fixed path",
                classification="OWNER_AUTHORITY_INSTALLATION_PATHS_DIFFER",
            )
        if key_identity["path"] != str(self.layout.public_key_path):
            raise OwnerAuthorityInstallationError(
                "the public verification key was not read from its fixed path",
                classification="OWNER_AUTHORITY_INSTALLATION_PATHS_DIFFER",
            )
        if record_identity["owner_uid"] != 0 or key_identity["owner_uid"] != 0:
            raise OwnerAuthorityInstallationError(
                "the installation is not owned by the privileged installer "
                "identity",
                classification="OWNER_AUTHORITY_INSTALLATION_NOT_ROOT_OWNED",
            )
        if sha256_bytes(bytes(self.public_key_pem)) != key_identity["sha256"]:
            raise OwnerAuthorityInstallationError(
                "the attested public key bytes differ from the installed file",
                classification="OWNER_AUTHORITY_PUBLIC_KEY_REFUSED",
            )
        if record["public_key_sha256"] != key_identity["sha256"]:
            raise OwnerAuthorityInstallationError(
                "the installed public key is not the key the record names",
                classification="OWNER_AUTHORITY_PUBLIC_KEY_REFUSED",
            )
        require_sha256(self.installation_identity, "installation identity")
        if _installation_identity(
            record=record,
            record_file_identity=record_identity,
            public_key_file_identity=key_identity,
            layout=self.layout,
        ) != self.installation_identity:
            raise OwnerAuthorityInstallationError(
                "installation identity mismatch",
                classification="OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
            )
        return self

    def validated_production(self) -> "OwnerAuthorityInstallation":
        """Refuse anything but a genuine fixed production installation.

        Production status is re-derived from the validated fixed layout paths
        and the installation record itself.  An overridable ``is_production``
        property, subclass assertion, caller flag or serialized classification
        alone is never enough.
        """

        validated = self.validated()
        fixed = production_layout().validated()
        if (
            validated.layout.classification != PRODUCTION_LAYOUT
            or validated.layout.configuration_root != fixed.configuration_root
            or validated.layout.state_root != fixed.state_root
            or validated.layout.runtime_root != fixed.runtime_root
            or validated.record["layout_classification"] != PRODUCTION_LAYOUT
            or validated.record["configuration_root"]
            != str(fixed.configuration_root)
            or validated.record["state_root"] != str(fixed.state_root)
            or validated.record["runtime_root"] != str(fixed.runtime_root)
            or validated.record_file_identity["path"]
            != str(fixed.installation_record_path)
            or validated.public_key_file_identity["path"]
            != str(fixed.public_key_path)
        ):
            raise OwnerAuthorityInstallationError(
                "a production execution authority requires the fixed "
                "root-owned production installation, not "
                f"{validated.layout.classification}",
                classification="OWNER_AUTHORITY_NON_PRODUCTION_INSTALLATION_REFUSED",
            )
        if validated.cryptographic_executable_identity["owner_uid"] != 0:
            raise OwnerAuthorityInstallationError(
                "the production owner authority requires a root-owned "
                "cryptographic executable",
                classification="OWNER_AUTHORITY_CRYPTO_EXECUTABLE_REFUSED",
            )
        return validated

    def reattest_cryptographic_executable(self) -> Mapping[str, Any]:
        return reattest_executable(self.cryptographic_executable_identity)

    def crypto_attestation_revision(self) -> str:
        """The committed crypto-attestation revision used for new receipts."""

        return require_identifier(
            self.record["crypto_attestation_revision"],
            "crypto attestation revision",
        )

    def reattested(self) -> "OwnerAuthorityInstallation":
        """Re-read the installation from disk and refuse any drift.

        The pre-effect gate calls this on every effect, so a record replaced,
        re-owned, re-moded or repointed at another key after construction is
        caught even though the original attestation object still exists.
        """

        # Re-derive production status from the fixed layout constants rather
        # than trusting an overridable property on a possibly subclassed
        # instance that still holds a stale ``layout`` reference.
        must_be_production = (
            self.layout.classification == PRODUCTION_LAYOUT
            and self.layout.configuration_root == PRODUCTION_CONFIGURATION_ROOT
            and self.layout.state_root == PRODUCTION_STATE_ROOT
            and self.layout.runtime_root == PRODUCTION_RUNTIME_ROOT
        )
        fresh = _attest_layout(
            production_layout() if must_be_production else self.layout
        )
        if fresh.installation_identity != self.installation_identity:
            raise OwnerAuthorityInstallationError(
                "the owner-authority installation changed since it was attested",
                classification="OWNER_AUTHORITY_INSTALLATION_CHANGED",
            )
        return fresh.validated_production() if must_be_production else fresh


def _installation_identity(
    *,
    record: Mapping[str, Any],
    record_file_identity: Mapping[str, Any],
    public_key_file_identity: Mapping[str, Any],
    layout: OwnerAuthorityLayout,
) -> str:
    """Stable installation identity.

    Deliberately excludes ``record_identity``, crypto-attestation revision and
    cryptographic executable identity so an OpenSSL revision does not change
    the installation identity bound into historical receipts.  The public key
    path and content digest, the installation id and the layout roots remain.
    """

    return fingerprint(
        {
            "schema_version": "admissible_owner_authority_stable_installation_identity_v1",
            "layout_classification": layout.classification,
            "installation_id": record["installation_id"],
            "signing_key_fingerprint": record["signing_key_fingerprint"],
            "public_key_sha256": record["public_key_sha256"],
            "configuration_root": record["configuration_root"],
            "state_root": record["state_root"],
            "runtime_root": record["runtime_root"],
            "public_key_path": record["public_key_path"],
            "public_key_file_path": public_key_file_identity["path"],
            "public_key_file_sha256": public_key_file_identity["sha256"],
            # Bound to the fixed record path, not the mutable content hash.
            "installation_record_path": record_file_identity["path"],
        }
    )


def _attest_layout(layout: OwnerAuthorityLayout) -> OwnerAuthorityInstallation:
    layout.validated()
    record_bytes, record_file_identity = _read_root_owned_file(
        layout.installation_record_path,
        label="the owner-authority installation record",
        max_bytes=_MAX_RECORD_BYTES,
    )
    try:
        record = strict_json_loads(
            record_bytes, label="owner-authority installation record"
        )
    except ValueError as error:
        raise OwnerAuthorityInstallationError(
            "the owner-authority installation record is not canonical JSON",
            classification="OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
        ) from error
    if not isinstance(record, Mapping):
        raise OwnerAuthorityInstallationError(
            "the owner-authority installation record is not an object",
            classification="OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
        )
    if canonical_bytes(dict(record)) != record_bytes:
        raise OwnerAuthorityInstallationError(
            "the owner-authority installation record is not in canonical form",
            classification="OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
        )
    public_key_pem, public_key_file_identity = _read_root_owned_file(
        layout.public_key_path,
        label="the owner-authority public verification key",
        max_bytes=_MAX_RECORD_BYTES,
    )
    return OwnerAuthorityInstallation(
        layout=layout,
        record=MappingProxyType(dict(record)),
        record_file_identity=MappingProxyType(record_file_identity),
        public_key_file_identity=MappingProxyType(public_key_file_identity),
        public_key_pem=public_key_pem,
        installation_identity=_installation_identity(
            record=record,
            record_file_identity=record_file_identity,
            public_key_file_identity=public_key_file_identity,
            layout=layout,
        ),
    ).validated()


def attest_production_installation() -> OwnerAuthorityInstallation:
    """Attest the one production installation.  It accepts no arguments.

    There is deliberately no parameter through which a backend, controller,
    launcher or coding agent could name another root, record or key.
    """

    installation = _attest_layout(production_layout())
    if installation.layout.classification != PRODUCTION_LAYOUT:  # pragma: no cover
        raise OwnerAuthorityInstallationError(
            "the production attestation returned a non-production layout"
        )
    return installation.validated_production()


def attest_synthetic_non_production_installation(
    layout: OwnerAuthorityLayout,
) -> OwnerAuthorityInstallation:
    """Attest a synthetic installation for the provider-free privilege witness.

    This is *not* a production installation and no production acceptance point
    accepts what it returns.
    """

    if layout.classification != SYNTHETIC_LAYOUT:
        raise OwnerAuthorityInstallationError(
            "the synthetic attestation accepts only a synthetic layout",
            classification="OWNER_AUTHORITY_LAYOUT_REFUSED",
        )
    return _attest_layout(layout)


def production_installation_is_present() -> bool:
    """Whether the fixed production installation record exists at all."""

    return production_layout().installation_record_path.exists()
