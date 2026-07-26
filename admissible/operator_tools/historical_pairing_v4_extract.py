"""Independent standalone historical V4 document-extraction command.

Real native-canary outputs carry the authorization payload nested under one
top-level ``authorization_payload`` member, while the product's historical
payload registry deliberately accepts only the standalone canonical Form-A
document.  This separately invoked operator utility closes exactly that gap: it
reads one explicitly selected wrapper file, lifts the top-level
``authorization_payload`` mapping out of it, validates that mapping through the
accepted historical V4 loader, and writes one standalone canonical document.

Document extraction only
------------------------

The utility executes nothing, attests nothing, authorizes nothing, evaluates
nothing, confirms nothing, archives nothing and infers no run outcome.  It is
never called by the product launcher, the product service, the transport, the
browser UI, the historical payload registry, the confirmation coordinator, or
archive loading and persistence.  ``STANDALONE_V4_WRITTEN`` names this file
writing operation and nothing else: the written document is not thereby
verified, accepted, authorized, admissible, a successful run, or proven
execution.

Sibling non-interpretation
--------------------------

A selected wrapper may also carry ``status``, ``classification``,
``attestation``, ``where_diagnostic``, ``local_capability_status`` and
``durability_capability`` members.  None of them is required, validated,
interpreted, branched on, displayed, or copied into the output, and nothing is
inferred from their presence or their value.  Only the top-level
``authorization_payload`` mapping is extracted; the field is never searched for
recursively, so a nested occurrence below the top level is never discovered and
a bare standalone Form-A document is refused here for having no wrapper member.

Deliberate, load-bearing limitations
------------------------------------

* Exactly two paths are ever touched: the configured wrapper is read and the
  configured output is created.  No parent, sibling, run root, evidence
  directory or derived path is constructed, listed, globbed, scanned or opened.
* A directly configured symbolic link or reported reparse point is refused to
  the exact extent the platform's own metadata reports it.  A symlinked
  *ancestor* directory is never inspected and may go undetected, a hostile
  local process able to replace a path between two observations is outside the
  trust model, and no complete race-proof guarantee is made.
* Output publication is create-only, not crash-atomic.  An abrupt process
  termination may leave a partial create-only output behind.  Such a file is
  never silently overwritten; the operator must remove it explicitly before
  retrying.  No temporary sibling, directory scan or automatic backup exists.
* Rebinding a local name is reference minimization only.  It does not zeroize
  immutable Python objects or language-runtime internals.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)


# Exactly this many bytes plus one are ever requested from the selected wrapper,
# so an unbounded or deliberately enormous file can never be pulled into memory.
MAX_HISTORICAL_PAIRING_V4_WRAPPER_BYTES = 8 * 1024 * 1024

# The standalone document the product may later consume must fit the registry's
# own document bound.  The value is restated here rather than imported: the
# production extractor must not import the product registry, and a focused test
# pins this constant against the registry's real bound.
MAX_STANDALONE_HISTORICAL_V4_BYTES = 4 * 1024 * 1024

# The one wrapper member that is ever read.  It is looked up exactly once, at
# the top level only, and never searched for recursively.
WRAPPER_AUTHORIZATION_PAYLOAD_FIELD = "authorization_payload"

HISTORICAL_PAIRING_V4_EXTRACT_EXIT_CODE = 3

STANDALONE_V4_WRITTEN = "STANDALONE_V4_WRITTEN"

HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID = (
    "HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID"
)
HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE = (
    "HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE"
)
HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE = "HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE"
HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED = "HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED"
HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING = (
    "HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING"
)
HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED = (
    "HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED"
)
HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID = (
    "HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID"
)
HISTORICAL_PAIRING_V4_OUTPUT_EXISTS = "HISTORICAL_PAIRING_V4_OUTPUT_EXISTS"
HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE = "HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE"
HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED = (
    "HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED"
)

# The one generic code a forged, unknown or non-member code collapses to.  It is
# deliberately not a member of the frozen set below, so it can never be reached
# by forging a value that merely looks like a bounded code.
HISTORICAL_PAIRING_V4_EXTRACT_REFUSED = "HISTORICAL_PAIRING_V4_EXTRACT_REFUSED"

HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES = frozenset(
    {
        HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID,
        HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE,
        HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE,
        HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED,
        HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING,
        HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED,
        HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID,
        HISTORICAL_PAIRING_V4_OUTPUT_EXISTS,
        HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE,
        HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED,
    }
)

# The exact accepted-loader refusal types.  Membership is decided by exact type
# identity, never by ``isinstance``, class name, message, ``str``, ``repr`` or
# ``args``, so an unregistered subclass never inherits a bounded code and
# propagates as an ordinary unrelated defect instead.
ACCEPTED_HISTORICAL_V4_REFUSAL_TYPES = frozenset({TypeError, ValueError})

_UTF8_BOM = b"\xef\xbb\xbf"

_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class HistoricalPairingV4ExtractError(RuntimeError):
    """Bounded extraction refusal carrying one fixed code."""

    def __init__(
        self,
        code: str = HISTORICAL_PAIRING_V4_EXTRACT_REFUSED,
    ) -> None:
        bounded = (
            code
            if type(code) is str and code in HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES
            else HISTORICAL_PAIRING_V4_EXTRACT_REFUSED
        )
        super().__init__(bounded)
        self._code = bounded

    @property
    def code(self) -> str:
        return self._code

    def __str__(self) -> str:
        return self._code

    def __repr__(self) -> str:
        return f"<HistoricalPairingV4ExtractError code={self._code}>"


def _is_explicit_absolute_path(value: object) -> bool:
    """Require one lexically canonical, NUL-free absolute ``Path`` locator.

    Nothing is resolved, absolutized into acceptance, ``~``-expanded,
    environment-expanded, or interpreted relative to the working directory or
    the repository: the supplied value must already equal its own lexical
    absolutization and is then used exactly as supplied.
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


def _read_wrapper_file(path: Path) -> bytes:
    """Read exactly the selected wrapper and at most its bound plus one byte.

    Ancestor symlinks may remain undetected, a hostile local replacement between
    the pre-open ``lstat`` and the post-open ``fstat`` remains outside the trust
    model, and no complete race-proof guarantee is made.
    """

    if not _is_explicit_absolute_path(path):
        code = HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID
    else:
        try:
            metadata = os.lstat(path)
        except (OSError, ValueError):
            code = HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE
        else:
            if _is_redirecting(metadata) or not stat.S_ISREG(metadata.st_mode):
                code = HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE
            else:
                try:
                    with open(path, "rb") as handle:
                        opened = os.fstat(handle.fileno())
                        if _is_redirecting(opened) or not stat.S_ISREG(
                            opened.st_mode
                        ):
                            code = HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE
                            raw = b""
                        else:
                            # The extra byte is the whole point: its presence
                            # proves the file is larger than the bound, so an
                            # oversized wrapper is refused, never truncated.
                            raw = handle.read(
                                MAX_HISTORICAL_PAIRING_V4_WRAPPER_BYTES + 1
                            )
                            code = None
                except (OSError, ValueError):
                    code = HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE
                    raw = b""
                if code is None:
                    if type(raw) is not bytes or not raw:
                        # An empty file is no JSON document at all.
                        code = HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED
                    elif len(raw) > MAX_HISTORICAL_PAIRING_V4_WRAPPER_BYTES:
                        code = HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE
    if code is not None:
        raise HistoricalPairingV4ExtractError(code)
    return raw


def _decoded_wrapper_text(raw: bytes) -> str:
    """Decode the wrapper as strict UTF-8 only after the byte bound has passed."""

    code = None
    text = ""
    if raw[:3] == _UTF8_BOM:
        code = HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED
    else:
        try:
            text = raw.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            code = HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED
        else:
            if text[:1] == "\ufeff" or not text.strip():
                code = HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED
    if code is not None:
        raise HistoricalPairingV4ExtractError(code)
    return text


def _reject_duplicate_json_keys(pairs: list) -> dict:
    """Refuse a duplicate JSON field at every nesting depth."""

    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_name: str) -> None:
    """Refuse ``NaN``, ``Infinity`` and ``-Infinity``."""

    raise ValueError("non-finite JSON constant")


def _parsed_wrapper_root(text: str) -> dict:
    """Parse exactly one JSON object root; trailing values are refused."""

    code = None
    document = None
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        code = HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED
    if code is None and type(document) is not dict:
        code = HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED
        document = None
    if code is not None:
        raise HistoricalPairingV4ExtractError(code)
    return document


def _extracted_authorization_payload(root: dict) -> dict:
    """Lift exactly the top-level ``authorization_payload`` object.

    Every other top-level member is allowed, ignored, and never read: the
    lookup is one exact top-level subscript, so no recursive search happens and
    a nested occurrence below the top level is never discovered.
    """

    code = None
    nested = None
    if WRAPPER_AUTHORIZATION_PAYLOAD_FIELD not in root:
        code = HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING
    else:
        nested = root[WRAPPER_AUTHORIZATION_PAYLOAD_FIELD]
        if type(nested) is not dict:
            code = HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING
            nested = None
    if code is not None:
        raise HistoricalPairingV4ExtractError(code)
    return nested


def _accepted_historical_payload(
    mapping: dict,
) -> NativeCanaryAuthorizationPayloadV4:
    """Validate the extracted mapping only through the accepted historical API.

    No parallel V4 schema, key set, field grammar, fingerprint, profile or
    workspace identity, source or backend structure, budget, attestation
    semantic or historical structural rule is reimplemented here.
    """

    code = None
    payload = None
    try:
        payload = load_historical_native_canary_authorization_payload_v4(mapping)
    except (TypeError, ValueError) as failure:
        # Exact accepted types only.  An unregistered subclass propagates.
        if type(failure) not in ACCEPTED_HISTORICAL_V4_REFUSAL_TYPES:
            raise
        code = HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
    # Raised outside the handler so no bounded refusal carries the lower
    # exception as its context, cause or traceback.
    if code is None and type(payload) is not NativeCanaryAuthorizationPayloadV4:
        code = HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
        payload = None
    if code is not None:
        raise HistoricalPairingV4ExtractError(code)
    return payload


def _canonical_standalone_bytes(
    payload: NativeCanaryAuthorizationPayloadV4,
) -> bytes:
    """Produce exactly ``canonical_bytes(payload.to_dict())`` and bound it."""

    code = None
    document = None
    canonical = None
    try:
        document = payload.to_dict()
        canonical = canonical_bytes(document)
    finally:
        document = None
    if type(canonical) is not bytes or not canonical:
        code = HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
    elif len(canonical) > MAX_STANDALONE_HISTORICAL_V4_BYTES:
        # Refuse rather than write a document the product cannot consume.
        code = HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
    if code is not None:
        canonical = None
        raise HistoricalPairingV4ExtractError(code)
    return canonical


def _extract_standalone_v4_bytes(wrapper_path: Path) -> bytes:
    """Run the exact wrapper-to-canonical order and release every intermediate.

    The output locator is never inspected and the output file is never touched
    from here: a malformed wrapper or a refused V4 is decided completely before
    the caller looks at the output path.
    """

    raw = None
    text = None
    root = None
    nested = None
    payload = None
    canonical = None
    try:
        raw = _read_wrapper_file(wrapper_path)
        text = _decoded_wrapper_text(raw)
        raw = None
        root = _parsed_wrapper_root(text)
        text = None
        nested = _extracted_authorization_payload(root)
        # Every sibling field dies with the root wrapper mapping here, before
        # the extracted mapping is validated or serialized.
        root = None
        payload = _accepted_historical_payload(nested)
        nested = None
        canonical = _canonical_standalone_bytes(payload)
        payload = None
        return canonical
    finally:
        raw = None
        text = None
        root = None
        nested = None
        payload = None
        canonical = None


def _write_complete_bytes(handle, data: bytes) -> None:
    """Write every byte through a bounded loop that cannot spin without progress."""

    view = memoryview(data)
    try:
        total = len(data)
        offset = 0
        while offset < total:
            chunk = view[offset:]
            try:
                written = handle.write(chunk)
            finally:
                chunk.release()
            if type(written) is not int or written <= 0 or offset + written > total:
                raise OSError("incomplete standalone document write")
            offset += written
    finally:
        view.release()


def _remove_created_output(path: Path) -> None:
    """Delete only the exact output file this invocation created."""

    try:
        os.unlink(path)
    except (OSError, ValueError):
        pass


def _write_standalone_v4_document(path: Path, canonical: bytes) -> None:
    """Create exactly the configured output and write the canonical bytes once.

    No parent directory is created, no sibling or default filename is derived,
    and any existing final component -- regular file, directory, symlink,
    junction or dangling symlink -- is a refusal rather than an overwrite.
    Publication is create-only and is deliberately not crash-atomic.
    """

    code = None
    created = False
    handle = None
    try:
        if not _is_explicit_absolute_path(path):
            code = HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID
        else:
            try:
                os.lstat(path)
            except FileNotFoundError:
                code = None
            except (OSError, ValueError):
                code = HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE
            else:
                # ``lstat`` succeeds for a dangling symlink too, so a dangling
                # final component is an existing component and never a target.
                code = HISTORICAL_PAIRING_V4_OUTPUT_EXISTS
        if code is None:
            try:
                handle = open(path, "xb")
                created = True
            except FileExistsError:
                code = HISTORICAL_PAIRING_V4_OUTPUT_EXISTS
            except (OSError, ValueError):
                code = HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE
        if code is None:
            try:
                opened = os.fstat(handle.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    code = HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE
                else:
                    _write_complete_bytes(handle, canonical)
                    handle.flush()
                    os.fsync(handle.fileno())
            except (OSError, ValueError):
                code = HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED
    finally:
        canonical = None
        if handle is not None:
            try:
                handle.close()
            except (OSError, ValueError):
                if code is None:
                    code = HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED
        handle = None
    if code is not None:
        if created:
            _remove_created_output(path)
        raise HistoricalPairingV4ExtractError(code)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--wrapper-file", required=True, type=Path)
    parser.add_argument("--output-file", required=True, type=Path)
    return parser


def _bounded_refusal_code(failure: HistoricalPairingV4ExtractError) -> str:
    candidate = failure.code
    if (
        type(candidate) is str
        and candidate in HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES
    ):
        return candidate
    return HISTORICAL_PAIRING_V4_EXTRACT_REFUSED


def _write_refusal(code: str) -> None:
    payload = f"error={code}".encode("ascii") + os.linesep.encode("ascii")
    try:
        sys.stderr.buffer.write(payload)
    finally:
        payload = None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    canonical = None

    try:
        canonical = _extract_standalone_v4_bytes(args.wrapper_file)
    except HistoricalPairingV4ExtractError as failure:
        if type(failure) is not HistoricalPairingV4ExtractError:
            raise
        _write_refusal(_bounded_refusal_code(failure))
        return HISTORICAL_PAIRING_V4_EXTRACT_EXIT_CODE

    try:
        _write_standalone_v4_document(args.output_file, canonical)
    except HistoricalPairingV4ExtractError as failure:
        if type(failure) is not HistoricalPairingV4ExtractError:
            raise
        _write_refusal(_bounded_refusal_code(failure))
        return HISTORICAL_PAIRING_V4_EXTRACT_EXIT_CODE
    finally:
        canonical = None
        # Rebinding a local name does not zeroize immutable Python bytes or
        # language-runtime internals.

    line = None
    try:
        # This names the file-writing operation only.  It asserts no run
        # outcome, verification, admission, acceptance or authorization.
        line = (
            f"status={STANDALONE_V4_WRITTEN}".encode("ascii")
            + os.linesep.encode("ascii")
        )
        sys.stdout.buffer.write(line)
    finally:
        line = None
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "ACCEPTED_HISTORICAL_V4_REFUSAL_TYPES",
    "HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING",
    "HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED",
    "HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES",
    "HISTORICAL_PAIRING_V4_EXTRACT_EXIT_CODE",
    "HISTORICAL_PAIRING_V4_EXTRACT_REFUSED",
    "HISTORICAL_PAIRING_V4_OUTPUT_EXISTS",
    "HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID",
    "HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE",
    "HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED",
    "HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED",
    "HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID",
    "HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE",
    "HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE",
    "MAX_HISTORICAL_PAIRING_V4_WRAPPER_BYTES",
    "MAX_STANDALONE_HISTORICAL_V4_BYTES",
    "STANDALONE_V4_WRITTEN",
    "WRAPPER_AUTHORIZATION_PAYLOAD_FIELD",
    "HistoricalPairingV4ExtractError",
    "main",
]
