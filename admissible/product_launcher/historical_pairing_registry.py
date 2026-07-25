"""Server-configurable registry of standalone historical V4 payload documents.

The registry is the single place where a server operator names the historical
execution authorizations that a later product surface may pair for post-run
evaluation.  Every configured document is opened exactly once during registry
construction, structurally loaded through the accepted historical V4 loader,
required to be the exact canonical bytes of its own mapping, and then pinned as
an immutable in-memory record.

After construction the registry is a pure in-memory lookup: it performs no
filesystem access at all.  Replacing, truncating, or deleting a source document
therefore has no effect on an already-constructed registry, and no stat, reopen,
or freshness check ever happens behind a caller's back.  A new registry must be
constructed to observe new bytes.

Form A only
-----------

The one supported document shape is a standalone canonical V4 authorization
payload: the complete JSON mapping produced by
``NativeCanaryAuthorizationPayloadV4.to_dict()`` and nothing else.  A
``canary-preflight.json`` wrapper, an ``authorization_payload`` nested key, a run
root, an evidence directory, a manifest, and a sibling or adjacent file are all
unsupported; a wrapper fails as a malformed standalone V4 document.  The
operator is responsible for extracting one standalone document outside the
historical evidence directory.

Evidence blindness
------------------

This module opens only its explicitly configured document paths.  It never
lists a directory, globs, scans, recurses, constructs a parent or sibling path,
opens a run root or evidence root, reads ``canary-preflight.json``, or
dereferences any filesystem path carried inside a loaded V4 payload: every such
value stays an inert historical string.

The module also names no execution store, checkpoint, behavioral-evidence,
reconstruction, or acceptance/disposition module in its own imports.  It does
not and cannot claim that the accepted historical V4 loader it depends on has no
transitive imports of its own -- that loader lives beside the execution modules
by construction.  What is proven here is the direct import graph of this module
and the exact set of paths it opens.

Deliberate, load-bearing limitations
------------------------------------

* The configuration is explicitly non-secret.  It carries no confirmation
  secret, expected tag, presented tag, owner phrase, runtime digest, evidence
  store location, or mutable preparation state.
* ``payload_id`` is a product locator only.  It is non-canonical,
  non-authoritative, never fingerprinted, never persisted into a V4, V5,
  pairing authority, or archive document, and never enters a confirmation
  message.
* A directly configured symbolic link or known reparse-point form is refused,
  to the exact extent the platform's own metadata checks report it.  The
  pre-open ``lstat`` decides the configured path itself and the post-open
  ``fstat`` decides the handle that was actually opened, so the bytes that are
  validated are always the bytes of that opened regular-file descriptor.  The
  guarantee stops exactly there and is deliberately narrow.  A symlinked
  ancestor directory of the configured path is not inspected and may therefore
  go undetected, because no parent is ever constructed or scanned.  A hostile
  local process that can replace the path between those two observations is
  outside the stated trust model.  No complete race-proof guarantee is claimed.
* Loading a payload proves only canonical execution-authorization structure.
  It never establishes that a source repository, run root, workspace, artifact,
  or evidence record currently exists.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)


# The recommended standalone-document bound.  Exactly this many bytes plus one
# are ever requested from a configured document, so an unbounded or deliberately
# enormous file can never be pulled into memory.
MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_CONFIGURED_HISTORICAL_PAYLOADS = 256

MIN_PAYLOAD_ID_LENGTH = 3
MAX_PAYLOAD_ID_LENGTH = 64

DEFAULT_PREPARATION_TTL_SECONDS = 900
MAX_PREPARATION_TTL_SECONDS = 86_400
DEFAULT_MAX_PREPARATIONS = 64
MAX_PREPARATION_CAPACITY = 4_096

# Exact narrow product-locator grammar: 3 to 64 characters, lowercase ASCII
# letters, decimal digits and hyphen only, first character alphanumeric.  No
# dot, slash, backslash, colon, percent, tilde, whitespace, NUL, URI scheme, or
# drive letter can pass, so a payload_id can never be read as a path or locator
# by any later surface.
_PAYLOAD_ID = re.compile(
    r"[a-z0-9][a-z0-9-]{%d,%d}"
    % (MIN_PAYLOAD_ID_LENGTH - 1, MAX_PAYLOAD_ID_LENGTH - 1)
)

_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class HistoricalPayloadRegistryError(RuntimeError):
    """Base class for bounded historical payload registry failures."""


class InvalidHistoricalPairingConfiguration(HistoricalPayloadRegistryError):
    pass


class MalformedHistoricalPayloadDocument(HistoricalPayloadRegistryError):
    pass


class HistoricalPayloadNotFound(HistoricalPayloadRegistryError):
    pass


def _validated_payload_id(payload_id: Any, *, label: str) -> str:
    if type(payload_id) is not str or not _PAYLOAD_ID.fullmatch(payload_id):
        raise InvalidHistoricalPairingConfiguration(
            f"historical {label} must be {MIN_PAYLOAD_ID_LENGTH} to "
            f"{MAX_PAYLOAD_ID_LENGTH} characters of lowercase ASCII letters, "
            "digits and hyphen beginning with a letter or digit"
        )
    return payload_id


def _validated_absolute_path(value: Any, *, label: str) -> Path:
    """Require one lexically canonical absolute path without touching the disk.

    No relative segment, dot segment, parent segment, request-derived component,
    or path arithmetic is accepted or performed: the configured value must
    already equal its own lexical absolutization.
    """

    # ``Path`` is the concrete-flavour factory, so the established repository
    # rule is an isinstance check against it rather than an exact-type check.
    if not isinstance(value, Path):
        raise InvalidHistoricalPairingConfiguration(
            f"configured historical {label} must be an explicit Path"
        )
    raw = os.fspath(value)
    if (
        "\x00" in raw
        or not value.is_absolute()
        or not value.anchor
        or Path(os.path.abspath(raw)) != value
    ):
        raise InvalidHistoricalPairingConfiguration(
            f"configured historical {label} must be a canonical absolute path"
        )
    return value


def _validated_bound(value: Any, *, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise InvalidHistoricalPairingConfiguration(
            f"configured historical pairing {label} must be an integer in "
            f"[1, {maximum}]"
        )
    return value


def _is_redirecting(metadata: os.stat_result) -> bool:
    """Report the known symbolic-link and reparse-point forms as redirecting."""

    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_FLAG)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True, kw_only=True)
class HistoricalPayloadEntry:
    """One configured standalone historical V4 authorization document.

    ``payload_id`` is a product locator and never becomes canonical material.
    ``document_path`` is server configuration and is never derived from, joined
    with, or influenced by any request value.
    """

    payload_id: str
    document_path: Path

    def validated(self) -> "HistoricalPayloadEntry":
        _validated_payload_id(self.payload_id, label="payload_id")
        _validated_absolute_path(self.document_path, label="payload document path")
        return self


@dataclass(frozen=True, kw_only=True)
class HistoricalPairingConfiguration:
    """Explicitly non-secret startup configuration for historical pairing.

    Nothing secret or mutable may appear here: no configured confirmation
    secret, expected tag, presented tag, owner phrase, runtime digest, evidence
    store location, or preparation state.  This type is standalone and
    deliberately does not extend, wrap, or replace the accepted launcher
    configuration type.
    """

    archive_root: Path
    payload_entries: tuple[HistoricalPayloadEntry, ...]
    preparation_ttl_seconds: int = DEFAULT_PREPARATION_TTL_SECONDS
    max_preparations: int = DEFAULT_MAX_PREPARATIONS

    def validated(self) -> "HistoricalPairingConfiguration":
        """Validate every entry's syntax and both duplicate laws, opening nothing.

        This runs completely before any configured document is opened, so a
        configuration defect is always reported as a configuration defect and
        never as a document failure discovered halfway through loading.
        """

        _validated_absolute_path(self.archive_root, label="archive root")
        if not isinstance(self.payload_entries, tuple):
            raise InvalidHistoricalPairingConfiguration(
                "configured historical payload entries must be an ordered tuple"
            )
        if len(self.payload_entries) > MAX_CONFIGURED_HISTORICAL_PAYLOADS:
            raise InvalidHistoricalPairingConfiguration(
                "configured historical payload entries cannot exceed "
                f"{MAX_CONFIGURED_HISTORICAL_PAYLOADS}"
            )
        seen_ids: set[str] = set()
        seen_paths: set[Path] = set()
        for entry in self.payload_entries:
            if type(entry) is not HistoricalPayloadEntry:
                raise InvalidHistoricalPairingConfiguration(
                    "configured historical payload entry has an invalid type"
                )
            entry.validated()
            # Never first-wins and never last-wins: a duplicate is refused.
            if entry.payload_id in seen_ids:
                raise InvalidHistoricalPairingConfiguration(
                    "configured historical payload identifiers must be unique"
                )
            if entry.document_path in seen_paths:
                raise InvalidHistoricalPairingConfiguration(
                    "configured historical payload document paths must be unique"
                )
            seen_ids.add(entry.payload_id)
            seen_paths.add(entry.document_path)
        _validated_bound(
            self.preparation_ttl_seconds,
            label="preparation TTL seconds",
            maximum=MAX_PREPARATION_TTL_SECONDS,
        )
        _validated_bound(
            self.max_preparations,
            label="preparation capacity",
            maximum=MAX_PREPARATION_CAPACITY,
        )
        return self


@dataclass(frozen=True)
class HistoricalPayloadMetadata:
    """Bounded immutable description of one pinned registry record.

    No configured document path, archive root, canonical mapping, or local path
    carried by the payload appears here.
    """

    payload_id: str
    payload_fingerprint: str
    document_sha256: str
    document_byte_length: int


@dataclass(frozen=True)
class _PinnedHistoricalPayload:
    """One immutable registry record.  Never returned and never persisted."""

    payload_id: str
    payload: NativeCanaryAuthorizationPayloadV4
    payload_fingerprint: str
    document_sha256: str
    document_byte_length: int


def _read_configured_document(document_path: Path) -> bytes:
    """Open exactly the configured path and read at most the bound plus one byte.

    The pre-open ``lstat`` refuses a configured symbolic link or reparse point,
    and the post-open ``fstat`` refuses anything that is not a regular file
    through the handle actually opened.  No parent, sibling, or derived path is
    ever constructed or inspected.
    """

    try:
        metadata = os.lstat(document_path)
    except OSError as exc:
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document cannot be inspected"
        ) from exc
    if _is_redirecting(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document must be an ordinary "
            "non-redirecting regular file"
        )
    try:
        with open(document_path, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _is_redirecting(opened) or not stat.S_ISREG(opened.st_mode):
                raise MalformedHistoricalPayloadDocument(
                    "configured historical payload document must be an ordinary "
                    "non-redirecting regular file"
                )
            raw = handle.read(MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES + 1)
    except MalformedHistoricalPayloadDocument:
        raise
    except OSError as exc:
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document cannot be read"
        ) from exc
    if not isinstance(raw, bytes):
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document did not yield exact bytes"
        )
    # The extra byte is the whole point: its presence proves the document is
    # larger than the bound, and the document is refused rather than truncated.
    if len(raw) > MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES:
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document exceeds its "
            f"{MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES} byte bound"
        )
    return raw


def _load_configured_payload(entry: HistoricalPayloadEntry) -> _PinnedHistoricalPayload:
    """Load one standalone Form-A document into one immutable pinned record."""

    raw = _read_configured_document(entry.document_path)
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document is not one exact UTF-8 JSON "
            "object"
        ) from exc
    if not isinstance(document, Mapping):
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document root must be one JSON object"
        )
    try:
        payload = load_historical_native_canary_authorization_payload_v4(document)
    except (TypeError, ValueError) as exc:
        # A canary-preflight wrapper, an authorization_payload nesting, and any
        # other non-Form-A shape all land here as a malformed standalone V4.
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document is not one exact standalone "
            "canonical historical v4 authorization payload"
        ) from exc
    if raw != canonical_bytes(payload.to_dict()):
        raise MalformedHistoricalPayloadDocument(
            "configured historical payload document bytes are not the exact "
            "canonical standalone v4 document"
        )
    return _PinnedHistoricalPayload(
        payload_id=entry.payload_id,
        payload=payload,
        payload_fingerprint=payload.payload_fingerprint,
        document_sha256=hashlib.sha256(raw).hexdigest(),
        document_byte_length=len(raw),
    )


class HistoricalPayloadRegistry:
    """Startup-loaded, immutable lookup over configured standalone V4 documents.

    Construction opens every configured document exactly once.  Lookup after
    construction touches no filesystem, retains no open handle, and exposes no
    configured path, archive root, mutable record, or canonical mapping.
    """

    def __init__(self, *, configuration: HistoricalPairingConfiguration) -> None:
        if type(configuration) is not HistoricalPairingConfiguration:
            raise InvalidHistoricalPairingConfiguration(
                "historical payload registry requires an exact "
                "HistoricalPairingConfiguration"
            )
        # Every entry's syntax and both duplicate laws are decided before the
        # first open, so no document is read for an already-invalid configuration.
        validated = configuration.validated()

        records: dict[str, _PinnedHistoricalPayload] = {}
        fingerprints: set[str] = set()
        for entry in validated.payload_entries:
            record = _load_configured_payload(entry)
            if record.payload_fingerprint in fingerprints:
                raise InvalidHistoricalPairingConfiguration(
                    "configured historical payload documents must describe "
                    "distinct authorization payloads"
                )
            fingerprints.add(record.payload_fingerprint)
            records[record.payload_id] = record

        # Declaration order is the public order; nothing here sorts or reorders.
        self._payload_ids: tuple[str, ...] = tuple(
            entry.payload_id for entry in validated.payload_entries
        )
        self._records: Mapping[str, _PinnedHistoricalPayload] = MappingProxyType(records)
        self._metadata: tuple[HistoricalPayloadMetadata, ...] = tuple(
            HistoricalPayloadMetadata(
                payload_id=record.payload_id,
                payload_fingerprint=record.payload_fingerprint,
                document_sha256=record.document_sha256,
                document_byte_length=record.document_byte_length,
            )
            for record in (records[payload_id] for payload_id in self._payload_ids)
        )

    def __repr__(self) -> str:
        """Fixed bounded repr without an address, a path, or a fingerprint."""

        return f"<HistoricalPayloadRegistry payloads={len(self._payload_ids)}>"

    @property
    def payload_ids(self) -> tuple[str, ...]:
        """Configured payload identifiers in exact declaration order."""

        return self._payload_ids

    @property
    def metadata(self) -> tuple[HistoricalPayloadMetadata, ...]:
        """Bounded immutable per-record view in exact declaration order."""

        return self._metadata

    def get(self, *, payload_id: str) -> NativeCanaryAuthorizationPayloadV4:
        """Return one pinned payload.  This performs zero filesystem access."""

        identifier = _validated_payload_id(payload_id, label="payload_id")
        record = self._records.get(identifier)
        if record is None:
            raise HistoricalPayloadNotFound(
                "configured historical payload identifier is not registered"
            )
        return record.payload


__all__ = [
    "DEFAULT_MAX_PREPARATIONS",
    "DEFAULT_PREPARATION_TTL_SECONDS",
    "HistoricalPairingConfiguration",
    "HistoricalPayloadEntry",
    "HistoricalPayloadMetadata",
    "HistoricalPayloadNotFound",
    "HistoricalPayloadRegistry",
    "HistoricalPayloadRegistryError",
    "InvalidHistoricalPairingConfiguration",
    "MAX_CONFIGURED_HISTORICAL_PAYLOADS",
    "MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES",
    "MAX_PAYLOAD_ID_LENGTH",
    "MAX_PREPARATION_CAPACITY",
    "MAX_PREPARATION_TTL_SECONDS",
    "MIN_PAYLOAD_ID_LENGTH",
    "MalformedHistoricalPayloadDocument",
]
