"""Bounded startup-only loader for the non-secret historical pairing enablement document.

This module translates exactly one explicitly configured JSON document into the
accepted :class:`HistoricalPairingConfiguration`.  It is a transport adapter,
not a second authority: it owns only the facts that belong to reading one JSON
file, and it hands every configuration question to the accepted type.

What this loader owns
---------------------

* one bounded read of one explicitly configured absolute path;
* strict UTF-8 with no byte-order mark;
* duplicate JSON key rejection at every nesting depth;
* one JSON object root, one JSON value, no trailing non-whitespace bytes;
* the exact top-level key set and the exact per-payload key set;
* primitive JSON type checks;
* exact schema-version equality;
* ordered translation into the accepted configuration types.

What this loader deliberately does not own
------------------------------------------

The payload-identifier grammar, the duplicate payload-identifier rule, the
duplicate document-path rule, the duplicate payload-fingerprint rule, payload
document loading, Form-A validation, V4 canonical reload, the TTL and capacity
bounds, and archive-root semantics all belong to the accepted registry layer and
are never reimplemented here.  This module calls
``HistoricalPairingConfiguration.validated()`` and lets that accepted type's own
bounded ``InvalidHistoricalPairingConfiguration`` reach the caller unchanged: a
relative archive root or a relative payload document path is refused by the
accepted type, not by a parallel copy of its law living here.  Mapping the
downstream registry's document-loading failures is not part of this slice.

Explicit paths only
-------------------

The enablement document's own path must already be an absolute, lexically
canonical ``Path`` without a NUL byte.  Every path *inside* the document stays
equally explicit: a JSON path string is converted directly into a ``Path`` and
is never interpreted relative to the current working directory, the
configuration file's parent, the repository root, or a user home directory, and
is never expanded.  This module never lists, globs, recurses, resolves, or
inspects a sibling, and it never constructs a parent path.

Deliberate, load-bearing limitations
------------------------------------

* A directly configured symbolic link or known reparse-point form is refused to
  the exact extent the platform's own metadata reports it.  The pre-open
  ``lstat`` decides the configured final component and the post-open ``fstat``
  decides the handle that was actually opened.
* A symlinked ancestor directory of the configured path is not inspected and may
  therefore go undetected, because no parent is ever constructed or scanned.
* A hostile local process that can replace the configured path between those two
  observations is outside the stated trust model.  No complete race-proof
  guarantee is made.
* The document is explicitly non-secret.  It carries no confirmation secret, no
  expected or presented tag, no owner phrase, and no runtime digest, and this
  module never reads a secret file and never returns an object that stores
  secret bytes.

The function is one-shot.  It opens exactly the configured document and nothing
else: no configured V4 payload document is opened, no archive root is created,
no directory, worker, socket, archive, or product service is created, and no
background work is started.  After it returns, no handle remains open, no raw
document bytes and no parsed mapping remain reachable, and replacing or deleting
the source file cannot alter the frozen configuration already returned.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
)


HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION = (
    "admissible_historical_pairing_enablement_v1"
)
# Exactly this many bytes plus one are ever requested, so an unbounded or
# deliberately enormous document can never be pulled into memory.
MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES = 65536

# Fixed, bounded, path-free failure codes.  A code carries no document byte, no
# parsed mapping, no archive root, no payload identifier, no configured path,
# and no lower exception text.
HISTORICAL_PAIRING_CONFIG_PATH_INVALID = "HISTORICAL_PAIRING_CONFIG_PATH_INVALID"
HISTORICAL_PAIRING_CONFIG_UNAVAILABLE = "HISTORICAL_PAIRING_CONFIG_UNAVAILABLE"
HISTORICAL_PAIRING_CONFIG_TOO_LARGE = "HISTORICAL_PAIRING_CONFIG_TOO_LARGE"
HISTORICAL_PAIRING_CONFIG_MALFORMED = "HISTORICAL_PAIRING_CONFIG_MALFORMED"
HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID = "HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID"

HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES = frozenset(
    {
        HISTORICAL_PAIRING_CONFIG_PATH_INVALID,
        HISTORICAL_PAIRING_CONFIG_UNAVAILABLE,
        HISTORICAL_PAIRING_CONFIG_TOO_LARGE,
        HISTORICAL_PAIRING_CONFIG_MALFORMED,
        HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID,
    }
)

HISTORICAL_PAIRING_ENABLEMENT_FIELDS = frozenset(
    {
        "schema_version",
        "archive_root",
        "payloads",
        "preparation_ttl_seconds",
        "max_preparations",
    }
)
HISTORICAL_PAIRING_ENABLEMENT_PAYLOAD_FIELDS = frozenset(
    {"payload_id", "document_path"}
)

_UTF8_BOM = b"\xef\xbb\xbf"
_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class HistoricalPairingEnablementDocumentError(RuntimeError):
    """Bounded failure carrying one fixed code and nothing else.

    The constructor structurally cannot be talked into carrying document bytes,
    a parsed mapping, an archive root, a payload identifier, a configured path,
    or an operating-system message: anything outside the fixed code set
    collapses to ``HISTORICAL_PAIRING_CONFIG_UNAVAILABLE``.
    """

    def __init__(self, code: str = HISTORICAL_PAIRING_CONFIG_UNAVAILABLE) -> None:
        bounded = (
            code
            if code in HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES
            else HISTORICAL_PAIRING_CONFIG_UNAVAILABLE
        )
        super().__init__(bounded)
        self._code = bounded

    @property
    def code(self) -> str:
        """The fixed failure code.  Never a path, a mapping, or a document byte."""

        return self._code

    def __str__(self) -> str:
        return self._code

    def __repr__(self) -> str:
        """Fixed bounded repr without an address, a path, or document content."""

        return f"<HistoricalPairingEnablementDocumentError code={self._code}>"


def _is_explicit_absolute_path(value: object) -> bool:
    """Report one lexically canonical absolute ``Path`` without touching disk.

    This is the same explicit-path law the accepted registry applies to a
    configured historical path, expressed locally for the loader's own transport
    concern; a committed test requires the two to agree exactly on a shared
    corpus so they cannot drift apart.  The absoluteness test is evaluated
    before the lexical absolutization, so a relative value is refused outright
    and its current-working-directory expansion is never even computed.
    """

    if not isinstance(value, Path):
        return False
    raw = os.fspath(value)
    if "\x00" in raw or not value.is_absolute() or not value.anchor:
        return False
    return Path(os.path.abspath(raw)) == value


def _is_redirecting(metadata: os.stat_result) -> bool:
    """Report the known symbolic-link and reparse-point forms as redirecting."""

    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_FLAG)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a repeated key in *every* JSON object, at every nesting depth."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_name: str) -> Any:
    """Refuse ``NaN``, ``Infinity`` and ``-Infinity``: they are not valid JSON."""

    raise ValueError("non-finite JSON constant")


def _read_enablement_document(path: object) -> tuple[str | None, bytes]:
    """Return ``(None, raw)`` or ``(code, b"")`` and never raise a bounded error.

    Every lower failure is converted into a fixed code and *returned*, so the
    public exception is always raised with no exception being handled.
    """

    if not _is_explicit_absolute_path(path):
        return HISTORICAL_PAIRING_CONFIG_PATH_INVALID, b""
    try:
        metadata = os.lstat(path)
    except (OSError, ValueError):
        return HISTORICAL_PAIRING_CONFIG_UNAVAILABLE, b""
    if _is_redirecting(metadata) or not stat.S_ISREG(metadata.st_mode):
        return HISTORICAL_PAIRING_CONFIG_UNAVAILABLE, b""
    try:
        with open(path, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _is_redirecting(opened) or not stat.S_ISREG(opened.st_mode):
                return HISTORICAL_PAIRING_CONFIG_UNAVAILABLE, b""
            # The extra byte proves an over-bound document rather than silently
            # truncating it into a parseable prefix.
            raw = handle.read(MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES + 1)
    except (OSError, ValueError):
        return HISTORICAL_PAIRING_CONFIG_UNAVAILABLE, b""
    if type(raw) is not bytes:
        return HISTORICAL_PAIRING_CONFIG_UNAVAILABLE, b""
    if len(raw) > MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES:
        return HISTORICAL_PAIRING_CONFIG_TOO_LARGE, b""
    return None, raw


def _translated_fields(
    raw: bytes,
) -> tuple[str | None, tuple[str, tuple[tuple[str, str], ...], int, int] | None]:
    """Convert bounded document bytes into bounded immutable primitives.

    The parsed mapping is local to this function and unreachable once it
    returns: only strings, integers and tuples cross the boundary, so no mutable
    parsed mapping and no raw document byte can be retained by anything the
    caller receives.
    """

    if raw.startswith(_UTF8_BOM):
        return HISTORICAL_PAIRING_CONFIG_MALFORMED, None
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError):
        # json.JSONDecodeError, the duplicate-key refusal, the non-finite
        # constant refusal, a second JSON value, and trailing non-whitespace
        # bytes all land here as one malformed document.
        return HISTORICAL_PAIRING_CONFIG_MALFORMED, None
    if type(document) is not dict:
        return HISTORICAL_PAIRING_CONFIG_MALFORMED, None
    if set(document) != HISTORICAL_PAIRING_ENABLEMENT_FIELDS:
        # One check refuses both a missing field and an unknown field.
        return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
    schema_version = document["schema_version"]
    if (
        type(schema_version) is not str
        or schema_version != HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION
    ):
        return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
    archive_root = document["archive_root"]
    if type(archive_root) is not str:
        return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
    payloads = document["payloads"]
    if type(payloads) is not list:
        return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
    entries: list[tuple[str, str]] = []
    for member in payloads:
        if (
            type(member) is not dict
            or set(member) != HISTORICAL_PAIRING_ENABLEMENT_PAYLOAD_FIELDS
        ):
            return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
        payload_id = member["payload_id"]
        document_path = member["document_path"]
        if type(payload_id) is not str or type(document_path) is not str:
            return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
        # Declaration order is the public order; nothing here sorts or reorders.
        entries.append((payload_id, document_path))
    ttl_seconds = document["preparation_ttl_seconds"]
    max_preparations = document["max_preparations"]
    # ``type(...) is not int`` also refuses ``True`` and ``False``, which an
    # isinstance check would silently accept as 1 and 0.
    if type(ttl_seconds) is not int or type(max_preparations) is not int:
        return HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID, None
    return None, (archive_root, tuple(entries), ttl_seconds, max_preparations)


def load_historical_pairing_configuration(
    *,
    path: Path,
) -> HistoricalPairingConfiguration:
    """Load one enablement document into one accepted, frozen configuration.

    JSON transport defects raise a bounded
    ``HistoricalPairingEnablementDocumentError``.  Configuration defects -- a
    relative or non-canonical archive root or payload document path, a payload
    identifier outside the accepted grammar, a duplicate identifier or path, and
    an out-of-bounds TTL or capacity -- are decided and reported by the accepted
    configuration type itself, whose own bounded
    ``InvalidHistoricalPairingConfiguration`` is deliberately not wrapped.

    The secret is never read here and the returned object never stores it.
    """

    code, raw = _read_enablement_document(path)
    if code is not None:
        raise HistoricalPairingEnablementDocumentError(code)
    code, fields = _translated_fields(raw)
    if code is not None or fields is None:
        raise HistoricalPairingEnablementDocumentError(code)
    archive_root, entries, ttl_seconds, max_preparations = fields
    # A JSON path string becomes a Path and nothing more: no join, no parent, no
    # resolution against any base.  The accepted types own every path law.
    return HistoricalPairingConfiguration(
        archive_root=Path(archive_root),
        payload_entries=tuple(
            HistoricalPayloadEntry(payload_id=payload_id, document_path=Path(document))
            for payload_id, document in entries
        ),
        preparation_ttl_seconds=ttl_seconds,
        max_preparations=max_preparations,
    ).validated()


__all__ = [
    "HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID",
    "HISTORICAL_PAIRING_CONFIG_MALFORMED",
    "HISTORICAL_PAIRING_CONFIG_PATH_INVALID",
    "HISTORICAL_PAIRING_CONFIG_TOO_LARGE",
    "HISTORICAL_PAIRING_CONFIG_UNAVAILABLE",
    "HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES",
    "HISTORICAL_PAIRING_ENABLEMENT_FIELDS",
    "HISTORICAL_PAIRING_ENABLEMENT_PAYLOAD_FIELDS",
    "HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION",
    "MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES",
    "HistoricalPairingEnablementDocumentError",
    "load_historical_pairing_configuration",
]
