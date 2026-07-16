"""Canonical serialization and validation helpers for delegated-gate data."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any, Mapping


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json(value).encode("utf-8")


def fingerprint(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_exact_keys(data: Mapping[str, Any], keys: set[str], label: str) -> None:
    if not isinstance(data, Mapping) or set(data) != keys:
        missing = sorted(keys - set(data)) if isinstance(data, Mapping) else sorted(keys)
        extra = sorted(set(data) - keys) if isinstance(data, Mapping) else []
        raise ValueError(f"invalid {label} keys (missing={missing}, extra={extra})")


def require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a stable identifier")
    return value


def require_nonempty_text(value: Any, label: str, *, max_bytes: int = 65536) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL characters")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} exceeds its byte bound")
    return value


def require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_optional_git_oid(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be a lowercase Git object ID")
    return value


def require_strict_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def require_safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{label} must be a canonical relative POSIX path")
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    if (
        windows.is_absolute()
        or windows.drive
        or posix.is_absolute()
        or str(posix) != value
        or any(part in ("", ".", "..") or ":" in part for part in posix.parts)
    ):
        raise ValueError(f"{label} must be a canonical relative POSIX path")
    return value


def require_string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be an array of strings")
    return tuple(value)
