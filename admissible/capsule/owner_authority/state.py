"""The durable, fail-closed, one-time authorization state (section H).

Each state transition is the creation of a distinct marker file with
``O_CREAT|O_EXCL`` under an exclusive lock, followed by ``fsync`` of the file
and of its directory.  Two properties follow directly and are tested:

**Exactly one winner.**  ``consumed.json`` is created with ``O_EXCL``.  Two
concurrent launchers race on a single atomic filesystem operation; the loser
gets ``EEXIST`` and refuses.  The lock only orders the work --- correctness
does not depend on it.

**No crash restores launchability.**  ``VERIFY_AND_CONSUME`` proceeds only from
:data:`PROVISIONED_PENDING`.  ``consumed.json`` is durably fsynced *before* the
broker asks OpenSSL for a signature, so at every crash point either no receipt
was ever produced (and the state is at or past the commit point, which refuses)
or a receipt exists and the consumption is already durable.  There is no
interleaving in which a receipt exists without a durable consumption, and none
in which a crash returns the record to a launchable state.

The chosen rule is therefore: **consumption strictly precedes receipt
issuance**, inside one broker-side transaction.  The alternative --- signing
first and consuming afterwards --- has a crash window in which a valid receipt
exists over a still-launchable authorization, which is exactly the failure this
repair exists to remove.
"""

from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    fsync_directory,
    mode_type,
    sha256_bytes,
    strict_json_loads,
)
from admissible.capsule.owner_authority.layout import (
    CONSUMED_LAUNCH_COMMITTED,
    LAUNCH_RESULT_RECORDED,
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    PHRASE_VERIFIED,
    PROVISIONED_PENDING,
    RECEIPT_ISSUED,
)
from admissible.capsule.owner_authority.records import (
    read_pending_authorization_record,
    require_authorization_record_id,
)

#: The state marker for each state, in transition order.
PENDING_MARKER = "pending.json"
PHRASE_VERIFIED_MARKER = "phrase-verified.json"
CONSUMED_MARKER = "consumed.json"
RECEIPT_MARKER = "receipt.json"
LAUNCH_RESULT_MARKER = "launch-result.json"
LOCK_NAME = "authorization.lock"

#: Highest-precedence marker first: the observed state is the furthest marker
#: that exists.
_STATE_MARKERS = (
    (LAUNCH_RESULT_MARKER, LAUNCH_RESULT_RECORDED),
    (RECEIPT_MARKER, RECEIPT_ISSUED),
    (CONSUMED_MARKER, CONSUMED_LAUNCH_COMMITTED),
    (PHRASE_VERIFIED_MARKER, PHRASE_VERIFIED),
    (PENDING_MARKER, PROVISIONED_PENDING),
)

#: No authorization record exists under this identity at all.
AUTHORIZATION_ABSENT = "AUTHORIZATION_ABSENT"

_MAX_MARKER_BYTES = 512 * 1024


class OwnerAuthorityStateError(OwnerAuthorityError):
    """A refusal while reading or advancing durable authorization state."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_STATE_REFUSED",
    ):
        super().__init__(detail, classification=classification)


class _ExclusiveLock:
    def __init__(self, path: Path):
        self._path = path
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        self._descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._descriptor, fcntl.LOCK_EX)

    def __exit__(self, *_exc: object) -> None:
        assert self._descriptor is not None
        fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        os.close(self._descriptor)
        self._descriptor = None


def _write_immutable(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    """Create a marker exactly once, durably, and return its file identity."""

    encoded = canonical_bytes(dict(value))
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError as error:
        raise OwnerAuthorityStateError(
            f"the {path.name} state transition already happened",
            classification="OWNER_AUTHORITY_STATE_ALREADY_ADVANCED",
        ) from error
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)
    return {
        "path": str(path),
        "sha256": sha256_bytes(encoded),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "file_type": mode_type(info.st_mode),
        "link_count": info.st_nlink,
    }


class AuthorizationStateDirectory:
    """Privileged-side durable state for exactly one authorization.

    This class is used by the privileged provisioner and the privileged broker.
    An unprivileged launcher cannot construct a usable instance against
    production state: the production ``authorizations`` directory is root-owned
    and mode 0700, so every operation here fails with ``EACCES`` before any
    check in this module runs.
    """

    def __init__(self, layout: OwnerAuthorityLayout, record_id: str):
        self.layout = layout.validated()
        self.record_id = require_authorization_record_id(
            record_id, "authorization record id"
        )
        self.root = self.layout.authorizations_root / self.record_id

    # -- inspection -------------------------------------------------------

    def current_state(self) -> str:
        for marker, state in _STATE_MARKERS:
            if (self.root / marker).exists():
                return state
        return AUTHORIZATION_ABSENT

    def marker(self, name: str) -> dict[str, Any]:
        path = self.root / name
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise OwnerAuthorityStateError(
                f"the {name} state marker is unreadable",
                classification="OWNER_AUTHORITY_STATE_MARKER_ABSENT",
            ) from error
        if len(raw) > _MAX_MARKER_BYTES:
            raise OwnerAuthorityStateError(
                f"the {name} state marker exceeds its byte bound"
            )
        value = strict_json_loads(raw, label=f"{name} state marker")
        if canonical_bytes(value) != raw:
            raise OwnerAuthorityStateError(
                f"the {name} state marker is not in canonical form",
                classification="OWNER_AUTHORITY_STATE_MARKER_INVALID",
            )
        return dict(value)

    def pending_record(self) -> dict[str, Any]:
        record = read_pending_authorization_record(self.root / PENDING_MARKER)
        if record["authorization_record_id"] != self.record_id:
            raise OwnerAuthorityStateError(
                "the pending authorization record is filed under another "
                "record identity",
                classification="OWNER_AUTHORITY_RECORD_INVALID",
            )
        return record

    def status(self) -> dict[str, Any]:
        state = self.current_state()
        summary: dict[str, Any] = {
            "authorization_record_id": self.record_id,
            "state": state,
            "launchable": state == PROVISIONED_PENDING,
        }
        if state == AUTHORIZATION_ABSENT:
            return summary
        record = self.pending_record()
        summary["owner_payload_fingerprint"] = record["owner_payload_fingerprint"]
        summary["installation_identity"] = record["installation_identity"]
        summary["record_identity"] = record["record_identity"]
        if (self.root / RECEIPT_MARKER).exists():
            summary["receipt_identity"] = self.marker(RECEIPT_MARKER)[
                "receipt_identity"
            ]
        return summary

    # -- transitions ------------------------------------------------------

    def lock(self) -> _ExclusiveLock:
        return _ExclusiveLock(self.root / LOCK_NAME)

    def provision(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Write the immutable pending record.  Privileged provisioner only."""

        if self.root.exists():
            raise OwnerAuthorityStateError(
                "this authorization record identity is already provisioned",
                classification="OWNER_AUTHORITY_ALREADY_PROVISIONED",
            )
        self.root.mkdir(parents=True, mode=0o700)
        fsync_directory(self.layout.authorizations_root)
        return _write_immutable(self.root / PENDING_MARKER, record)

    def record_phrase_verified(self, body: Mapping[str, Any]) -> dict[str, Any]:
        self._require_state(PROVISIONED_PENDING, "phrase verification")
        return _write_immutable(self.root / PHRASE_VERIFIED_MARKER, body)

    def commit_consumption(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """The commit point.  Durable before any signature exists."""

        self._require_state(PHRASE_VERIFIED, "consumption")
        return _write_immutable(self.root / CONSUMED_MARKER, body)

    def record_receipt(self, body: Mapping[str, Any]) -> dict[str, Any]:
        self._require_state(CONSUMED_LAUNCH_COMMITTED, "receipt issuance")
        return _write_immutable(self.root / RECEIPT_MARKER, body)

    def record_launch_result(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Terminal audit append.  It never restores launchability."""

        self._require_state(RECEIPT_ISSUED, "launch result")
        return _write_immutable(self.root / LAUNCH_RESULT_MARKER, body)

    def _require_state(self, expected: str, action: str) -> None:
        observed = self.current_state()
        if observed != expected:
            raise OwnerAuthorityStateError(
                f"{action} requires state {expected} but observed {observed}",
                classification="OWNER_AUTHORITY_STATE_NOT_ELIGIBLE",
            )


def consumption_body(
    *,
    record_id: str,
    consumption_identity: str,
    owner_payload_fingerprint: str,
    installation_identity: str,
    peer_uid: int,
) -> dict[str, Any]:
    """The durable consumption commit body, written before any signature."""

    body = {
        "schema_version": "admissible_owner_authority_consumption_commit_v1",
        "state": CONSUMED_LAUNCH_COMMITTED,
        "authorization_record_id": record_id,
        "authorization_consumption_identity": consumption_identity,
        "owner_payload_fingerprint": owner_payload_fingerprint,
        "installation_identity": installation_identity,
        "peer_uid": peer_uid,
        "launches_authorized": 1,
        "commit_rule": "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED",
    }
    return {**body, "commit_identity": fingerprint(body)}
