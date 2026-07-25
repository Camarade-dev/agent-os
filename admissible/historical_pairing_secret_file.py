"""Bounded startup-only reader for one exact-byte historical pairing secret file.

This module is a neutral leaf.  It converts exactly one explicitly configured
absolute filesystem path into exactly the bytes that path's regular-file
descriptor yielded, and it does nothing else.  It names no product launcher,
product service, product UI, delegated gate, historical evaluation, archive,
store, execution, or evidence module, imports only ``os``, ``stat`` and
``pathlib``, and therefore cannot reach any of them even indirectly through its
own import graph.

Exact bytes
-----------

The returned value is the exact byte sequence read from the opened descriptor.
This module never decodes the file as text, never UTF-8 encodes, never
Base64-decodes or hex-decodes, never trims, strips, or normalizes, never
removes a carriage return or line feed, never changes case, and never
truncates.  A trailing ``\\n``, ``\\r\\n``, NUL byte, space, or tab is therefore
part of the secret whenever the total length remains inside the accepted
bounds, and two files that differ only in such a trailing byte are two
different secrets that produce two different confirmation tags.

Bounds
------

The accepted length window is exactly the accepted confirmation primitive's
window: ``MIN_HISTORICAL_PAIRING_SECRET_BYTES`` through
``MAX_HISTORICAL_PAIRING_SECRET_BYTES`` inclusive.  The values are restated
here rather than imported because this module must stay a neutral leaf, and a
committed test pins them equal to the accepted primitive's own constants so the
two can never drift apart silently.

Explicit paths only
-------------------

The configured value must already be an absolute, lexically canonical ``Path``
without a NUL byte.  A relative path is invalid, never resolved: this module
performs no current-working-directory resolution, no configuration-parent
resolution, no implicit expansion, no environment-variable expansion, and no
home-directory expansion.  It never lists, globs, recurses, resolves, or
inspects a sibling, and it never constructs a parent path.

Deliberate, load-bearing limitations
------------------------------------

* A directly configured symbolic link or known reparse-point form is refused to
  the exact extent the platform's own metadata reports it.  The pre-open
  ``lstat`` decides the configured final component and the post-open ``fstat``
  decides the handle that was actually opened, so the bytes returned are always
  the bytes of that opened regular-file descriptor.
* A symlinked ancestor directory of the configured path is not inspected and
  may therefore go undetected, because no parent is ever constructed or
  scanned.
* A hostile local process that can replace the configured path between those
  two observations is outside the stated trust model.  No complete race-proof
  guarantee is made.
* Reading a secret proves only that bounded bytes were configured locally.  It
  establishes nothing about the entropy, the provenance, or the confidentiality
  of those bytes.
* The product minimizes application-owned references but cannot guarantee
  zeroization of immutable language-runtime strings or bytes.  Rebinding a
  local variable does not erase the bytes it previously referenced, and this
  module makes no such claim.

The function is one-shot.  It retains no handle, no path, and no bytes after it
returns, performs no background work, and creates no worker, directory, socket,
archive, or service.  Replacing or deleting the source file after the call
cannot alter the bytes already returned.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat


# Exactly the accepted confirmation primitive's key window.  A committed test
# requires these to stay equal to MIN_CONFIRMATION_SECRET_BYTES and
# MAX_CONFIRMATION_SECRET_BYTES; the accepted primitive is never modified to
# share them, because this module must remain importable as a neutral leaf.
MIN_HISTORICAL_PAIRING_SECRET_BYTES = 16
MAX_HISTORICAL_PAIRING_SECRET_BYTES = 4096

# Fixed, bounded, path-free failure codes.  A code carries no length, no byte,
# no fragment, no encoding of the secret, no configured path, and no lower
# exception text.
HISTORICAL_PAIRING_SECRET_PATH_INVALID = "HISTORICAL_PAIRING_SECRET_PATH_INVALID"
HISTORICAL_PAIRING_SECRET_UNAVAILABLE = "HISTORICAL_PAIRING_SECRET_UNAVAILABLE"
HISTORICAL_PAIRING_SECRET_LENGTH_INVALID = "HISTORICAL_PAIRING_SECRET_LENGTH_INVALID"

HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES = frozenset(
    {
        HISTORICAL_PAIRING_SECRET_PATH_INVALID,
        HISTORICAL_PAIRING_SECRET_UNAVAILABLE,
        HISTORICAL_PAIRING_SECRET_LENGTH_INVALID,
    }
)

_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class HistoricalPairingSecretFileError(RuntimeError):
    """Bounded failure carrying one fixed code and nothing else.

    The constructor structurally cannot be talked into carrying a secret, a
    secret fragment, an observed length, a path, or an operating-system message:
    anything outside the fixed code set collapses to
    ``HISTORICAL_PAIRING_SECRET_UNAVAILABLE``.
    """

    def __init__(self, code: str = HISTORICAL_PAIRING_SECRET_UNAVAILABLE) -> None:
        bounded = (
            code
            if code in HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES
            else HISTORICAL_PAIRING_SECRET_UNAVAILABLE
        )
        super().__init__(bounded)
        self._code = bounded

    @property
    def code(self) -> str:
        """The fixed failure code.  Never a path, a length, or a fragment."""

        return self._code

    def __str__(self) -> str:
        return self._code

    def __repr__(self) -> str:
        """Fixed bounded repr without an address, a path, or a length."""

        return f"<HistoricalPairingSecretFileError code={self._code}>"


def _is_explicit_absolute_path(value: object) -> bool:
    """Report one lexically canonical absolute ``Path`` without touching disk.

    ``Path`` is the concrete-flavour factory, so the established repository rule
    is an ``isinstance`` check against it.  The absoluteness test is evaluated
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


def _read_bounded_secret(path: object) -> tuple[str | None, bytes]:
    """Return ``(None, secret)`` or ``(code, b"")`` and never raise a bounded error.

    Every lower failure is converted into a fixed code and *returned*.  The
    public exception is therefore always raised by the caller with no exception
    being handled, which is what keeps ``__cause__`` and ``__context__`` free of
    operating-system text.
    """

    if not _is_explicit_absolute_path(path):
        return HISTORICAL_PAIRING_SECRET_PATH_INVALID, b""
    try:
        metadata = os.lstat(path)
    except (OSError, ValueError):
        return HISTORICAL_PAIRING_SECRET_UNAVAILABLE, b""
    if _is_redirecting(metadata) or not stat.S_ISREG(metadata.st_mode):
        return HISTORICAL_PAIRING_SECRET_UNAVAILABLE, b""
    try:
        with open(path, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _is_redirecting(opened) or not stat.S_ISREG(opened.st_mode):
                return HISTORICAL_PAIRING_SECRET_UNAVAILABLE, b""
            # The extra byte is the whole point: its presence proves the file is
            # larger than the bound, so an over-long secret is refused rather
            # than silently truncated into a valid-looking key.
            raw = handle.read(MAX_HISTORICAL_PAIRING_SECRET_BYTES + 1)
    except (OSError, ValueError):
        return HISTORICAL_PAIRING_SECRET_UNAVAILABLE, b""
    if type(raw) is not bytes:
        return HISTORICAL_PAIRING_SECRET_UNAVAILABLE, b""
    if not (
        MIN_HISTORICAL_PAIRING_SECRET_BYTES
        <= len(raw)
        <= MAX_HISTORICAL_PAIRING_SECRET_BYTES
    ):
        return HISTORICAL_PAIRING_SECRET_LENGTH_INVALID, b""
    return None, raw


def read_historical_pairing_secret_file(*, path: Path) -> bytes:
    """Read exactly one configured secret file and return its exact bytes.

    The handle is opened exactly once, validated through ``fstat``, read once
    for at most ``MAX_HISTORICAL_PAIRING_SECRET_BYTES + 1`` bytes, and closed
    before the length is decided.  Nothing about the bytes is normalized.
    """

    code, secret = _read_bounded_secret(path)
    # Raised here, outside every ``except`` block, so no operating-system
    # exception is active and neither ``__cause__`` nor ``__context__`` can
    # retain one.
    if code is not None:
        raise HistoricalPairingSecretFileError(code)
    return secret


__all__ = [
    "HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES",
    "HISTORICAL_PAIRING_SECRET_LENGTH_INVALID",
    "HISTORICAL_PAIRING_SECRET_PATH_INVALID",
    "HISTORICAL_PAIRING_SECRET_UNAVAILABLE",
    "MAX_HISTORICAL_PAIRING_SECRET_BYTES",
    "MIN_HISTORICAL_PAIRING_SECRET_BYTES",
    "HistoricalPairingSecretFileError",
    "read_historical_pairing_secret_file",
]
