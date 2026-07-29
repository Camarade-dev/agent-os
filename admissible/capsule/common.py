"""Shared provider-free helpers for the capsule product architecture.

Standard library only. Nothing here invokes a provider, Docker, or a
network transport; these are pure filesystem, hashing, and subprocess
plumbing helpers reused by intake and finalization.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a stable identifier")
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


def require_git_oid(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be a lowercase Git object ID")
    return value


def require_optional_git_oid(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return require_git_oid(value, label)


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def require_strict_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def require_nonempty_text(value: Any, label: str, *, max_bytes: int = 65536) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL characters")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} exceeds its byte bound")
    return value


def require_exact_keys(data: Mapping[str, Any], keys: set[str], label: str) -> None:
    if not isinstance(data, Mapping) or set(data) != keys:
        missing = sorted(keys - set(data)) if isinstance(data, Mapping) else sorted(keys)
        extra = sorted(set(data) - keys) if isinstance(data, Mapping) else []
        raise ValueError(f"invalid {label} keys (missing={missing}, extra={extra})")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_bytes(
    path: Path,
    data: bytes,
    *,
    mode: int = 0o644,
    crash_before_replace: bool = False,
) -> None:
    """Publish bytes via same-directory write, fsync, then atomic replace."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)
    if crash_before_replace:
        raise CrashInjected(f"crash injected before publishing {path}")
    os.replace(temporary, path)
    fsync_directory(path.parent)


class CrashInjected(RuntimeError):
    """Raised by test-only crash injection points; never raised in normal operation."""


def atomic_json(path: Path, value: Any, **kwargs: Any) -> None:
    atomic_bytes(path, canonical_bytes(value), **kwargs)


def mode_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "unknown"


def run_capture(
    argv: Iterable[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | float = 60,
    input_bytes: bytes | None = None,
    output_limit: int = 1024 * 1024,
) -> dict[str, Any]:
    """Run a bounded subprocess and capture truncated, hashed output."""

    command = [str(part) for part in argv]
    started = time.monotonic_ns()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        exit_code: int | None = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        exit_code = None
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    stdout_truncated = len(stdout) > output_limit
    stderr_truncated = len(stderr) > output_limit
    stdout = stdout[:output_limit]
    stderr = stderr[:output_limit]
    return {
        "argv": command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def git(
    repository: Path,
    *arguments: str,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command = ["git", f"--git-dir={repository}", *arguments]
    completed = subprocess.run(
        command,
        env=dict(env) if env is not None else None,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Git command failed ({completed.returncode}): {command!r}: "
            f"{completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed
