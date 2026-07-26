"""Independent exact-byte HMAC tag command."""

import argparse
import hashlib
import hmac
import os
from pathlib import Path
import stat
import sys

from admissible.historical_pairing_secret_file import (
    HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES,
    HistoricalPairingSecretFileError,
    read_historical_pairing_secret_file,
)


MAX_HISTORICAL_PAIRING_MESSAGE_BYTES = 65536

HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID = (
    "HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID"
)
HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE = (
    "HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE"
)
HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID = (
    "HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID"
)
HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED = (
    "HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED"
)
HISTORICAL_PAIRING_TAG_EXIT_CODE = 3

HISTORICAL_PAIRING_TAG_MESSAGE_ERROR_CODES = frozenset(
    {
        HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID,
        HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE,
        HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID,
    }
)

_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class HistoricalPairingTagMessageFileError(RuntimeError):
    """Bounded message-file refusal carrying one fixed code."""

    def __init__(
        self,
        code: str = HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE,
    ) -> None:
        bounded = (
            code
            if type(code) is str
            and code in HISTORICAL_PAIRING_TAG_MESSAGE_ERROR_CODES
            else HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED
        )
        super().__init__(bounded)
        self._code = bounded

    @property
    def code(self) -> str:
        return self._code

    def __str__(self) -> str:
        return self._code

    def __repr__(self) -> str:
        return f"<HistoricalPairingTagMessageFileError code={self._code}>"


def _is_explicit_absolute_path(value: object) -> bool:
    if not isinstance(value, Path):
        return False
    raw = os.fspath(value)
    if "\x00" in raw or not value.is_absolute() or not value.anchor:
        return False
    return Path(os.path.abspath(raw)) == value


def _is_redirecting(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_FLAG)


def _read_historical_pairing_message_file(path: Path) -> bytes:
    """Read one exact bounded public-message file.

    Ancestor symlinks may remain undetected.  Hostile local replacement races
    remain outside the trust model, and no complete race-proof guarantee is
    made.
    """

    if not _is_explicit_absolute_path(path):
        code = HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID
    else:
        try:
            metadata = os.lstat(path)
        except (OSError, ValueError):
            code = HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
        else:
            if _is_redirecting(metadata) or not stat.S_ISREG(metadata.st_mode):
                code = HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
            else:
                try:
                    with open(path, "rb") as handle:
                        opened = os.fstat(handle.fileno())
                        if _is_redirecting(opened) or not stat.S_ISREG(
                            opened.st_mode
                        ):
                            code = HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
                            raw = b""
                        else:
                            raw = handle.read(
                                MAX_HISTORICAL_PAIRING_MESSAGE_BYTES + 1
                            )
                            code = None
                except (OSError, ValueError):
                    code = HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
                    raw = b""
                if code is None and (
                    type(raw) is not bytes
                    or not 1 <= len(raw) <= MAX_HISTORICAL_PAIRING_MESSAGE_BYTES
                ):
                    code = HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID
    if code is not None:
        raise HistoricalPairingTagMessageFileError(code)
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--message-file", required=True, type=Path)
    parser.add_argument("--secret-file", required=True, type=Path)
    return parser


def _write_refusal(code: str) -> None:
    payload = f"error={code}".encode("ascii") + os.linesep.encode("ascii")
    try:
        sys.stderr.buffer.write(payload)
    finally:
        payload = None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    message = None
    secret = None
    tag = None

    try:
        message = _read_historical_pairing_message_file(args.message_file)
    except HistoricalPairingTagMessageFileError as failure:
        if type(failure) is not HistoricalPairingTagMessageFileError:
            raise
        candidate = failure.code
        code = (
            candidate
            if type(candidate) is str
            and candidate in HISTORICAL_PAIRING_TAG_MESSAGE_ERROR_CODES
            else HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED
        )
        _write_refusal(code)
        return HISTORICAL_PAIRING_TAG_EXIT_CODE

    try:
        try:
            secret = read_historical_pairing_secret_file(path=args.secret_file)
        except HistoricalPairingSecretFileError as failure:
            if type(failure) is not HistoricalPairingSecretFileError:
                raise
            candidate = failure.code
            code = (
                candidate
                if type(candidate) is str
                and candidate in HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES
                else HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED
            )
            _write_refusal(code)
            return HISTORICAL_PAIRING_TAG_EXIT_CODE

        # Distinct source byte strings can be HMAC-equivalent because HMAC
        # normalizes short keys.  This helper applies no normalization itself.
        tag = hmac.new(
            key=secret,
            msg=message,
            digestmod=hashlib.sha256,
        ).hexdigest()
    finally:
        secret = None
        message = None
        # Rebinding local references does not zeroize immutable Python bytes or
        # language-runtime internals.

    payload = None
    try:
        payload = tag.encode("ascii") + os.linesep.encode("ascii")
        sys.stdout.buffer.write(payload)
    finally:
        payload = None
        tag = None
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED",
    "HISTORICAL_PAIRING_TAG_EXIT_CODE",
    "HISTORICAL_PAIRING_TAG_MESSAGE_ERROR_CODES",
    "HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID",
    "HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID",
    "HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE",
    "MAX_HISTORICAL_PAIRING_MESSAGE_BYTES",
    "HistoricalPairingTagMessageFileError",
    "main",
]
