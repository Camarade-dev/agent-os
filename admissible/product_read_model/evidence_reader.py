"""Read-only, defensive reader for persisted Admissible evidence.

Guarantees enforced here:

* exact JSON parsing with duplicate-key rejection (no last-wins merging);
* per-file byte-size bounds (oversized files are ``INCONSISTENT``, not read);
* no symlink / junction / reparse-point traversal or escape;
* no writes, no locks, no repair, no normalisation;
* explicit ``PRESENT`` / ``ABSENT`` / ``INCONSISTENT`` states
  (missing != malformed);
* secret-like structured fields and whole environment maps are never exposed.

Nothing in this module mutates the filesystem or acquires a lock.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath

from .enums import PresenceState

# Per-file byte ceiling for structured JSON evidence. Larger files are reported
# as INCONSISTENT rather than parsed, bounding memory and parse time.
DEFAULT_MAX_JSON_BYTES = 4 * 1024 * 1024

# Bounded excerpt window for large diagnostic streams (stdout/stderr/detail).
DEFAULT_MAX_EXCERPT_BYTES = 4096

_MAX_REDACT_DEPTH = 64

# Windows reparse-point attribute; present in ``stat`` on all supported hosts but
# defaulted defensively for portability.
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# Structured keys whose values are redacted wherever they appear. Matched as
# case-insensitive substrings so ``session_token``, ``owner_phrase`` and
# ``owner_authorization`` are all caught. The ``authorization`` / ``phrase``
# substrings deliberately cover owner-authorization material and authorization
# phrases; the ``_SAFE_KEY_ALLOWLIST`` below carves out the known structural
# container keys so ordinary evidence fingerprints are not redacted.
_SECRET_KEY_SUBSTRINGS = (
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "api_key",
    "apikey",
    "private_key",
    "owner_phrase",
    "access_key",
    "passphrase",
    "authorization",  # covers owner_authorization, authorization_phrase, a bare authorization key
    "phrase",         # covers authorization_phrase, owner_phrase, passphrase
    "cookie",
)

# Structural / label keys that are known-safe schema fields and must NOT be
# redacted even though they contain a denied substring. This is a narrow,
# documented carve-out: the value is still recursed, so any secret-like *nested*
# key inside remains redacted. ``authorization_payload`` is the container from
# which only explicit safe authorization facts (run_id, mission_fingerprint, ...)
# are lifted; ``authorized_model`` is a model identifier, not a secret.
_SAFE_KEY_ALLOWLIST = frozenset({"authorization_payload", "authorized_model"})

# Keys that name a full environment map. Never expanded; replaced with a marker.
_ENV_MAP_KEYS = ("env", "environ", "environment", "envvars", "environment_variables")

REDACTED_MARKER = "[REDACTED]"
ENV_OMITTED_MARKER = "[ENVIRONMENT_MAP_OMITTED]"


class _DuplicateKey(Exception):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


@dataclass(frozen=True)
class EvidenceRead:
    """Outcome of reading one structured JSON evidence file."""

    relative_path: str
    presence: PresenceState
    reason: str | None
    data: object | None
    byte_size: int | None

    @property
    def ok(self) -> bool:
        return self.presence is PresenceState.PRESENT and self.data is not None


@dataclass(frozen=True)
class ExcerptRead:
    """Outcome of reading a bounded text excerpt from a diagnostic stream."""

    relative_path: str
    presence: PresenceState
    reason: str | None
    excerpt: str
    truncated: bool
    source_byte_size: int | None
    encoding_note: str | None


def resolve_root(path: Path | str) -> Path:
    """Return the real, absolute form of ``path`` for containment checks."""

    return Path(os.path.realpath(os.fspath(path)))


def _is_reparse_point(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def safe_child_path(root_real: Path, relative: str) -> Path | None:
    """Resolve ``relative`` under ``root_real`` refusing any escape.

    Returns ``None`` when the relative path is absolute, contains ``..``, or when
    any component (including the leaf) is a reparse point / symlink, or when the
    fully resolved path escapes ``root_real``.
    """

    rel = PurePath(relative)
    if rel.is_absolute() or any(part == ".." for part in rel.parts):
        return None
    current = root_real
    for part in rel.parts:
        if part in ("", "."):
            continue
        current = current / part
        if _is_reparse_point(current):
            return None
    try:
        resolved = Path(os.path.realpath(current))
    except OSError:
        return None
    if resolved != current:
        try:
            resolved.relative_to(root_real)
        except ValueError:
            return None
    return current


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _redact(value: object, depth: int = 0) -> object:
    if depth > _MAX_REDACT_DEPTH:
        return "[REDACTED_DEPTH_LIMIT]"
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            key_str = str(key)
            lowered = key_str.lower()
            if lowered in _ENV_MAP_KEYS:
                redacted[key_str] = ENV_OMITTED_MARKER
            elif lowered in _SAFE_KEY_ALLOWLIST:
                # Known-safe container/label: keep the key but recurse so nested
                # secret-like fields (owner_authorization, api_key, ...) redact.
                redacted[key_str] = _redact(item, depth + 1)
            elif any(token in lowered for token in _SECRET_KEY_SUBSTRINGS):
                redacted[key_str] = REDACTED_MARKER
            else:
                redacted[key_str] = _redact(item, depth + 1)
        return redacted
    if isinstance(value, list):
        return [_redact(item, depth + 1) for item in value]
    return value


def read_json(
    root_real: Path,
    relative: str,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> EvidenceRead:
    """Read and parse one JSON evidence file, redacting secret-like fields."""

    target = safe_child_path(root_real, relative)
    if target is None:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, "unsafe path (traversal or reparse point)", None, None)
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return EvidenceRead(relative, PresenceState.ABSENT, None, None, None)
    except OSError as exc:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, f"unreadable: {type(exc).__name__}", None, None)
    if not stat.S_ISREG(st.st_mode):
        return EvidenceRead(relative, PresenceState.INCONSISTENT, "not a regular file", None, st.st_size)
    if st.st_size > max_bytes:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, f"oversized ({st.st_size} > {max_bytes} bytes)", None, st.st_size)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, f"read failed: {type(exc).__name__}", None, st.st_size)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, "not valid utf-8", None, st.st_size)
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicates)
    except _DuplicateKey as exc:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, f"duplicate JSON key: {exc.key}", None, st.st_size)
    except json.JSONDecodeError as exc:
        return EvidenceRead(relative, PresenceState.INCONSISTENT, f"malformed JSON: {exc.msg}", None, st.st_size)
    return EvidenceRead(relative, PresenceState.PRESENT, None, _redact(parsed), st.st_size)


def read_text_excerpt(
    root_real: Path,
    relative: str,
    *,
    max_bytes: int = DEFAULT_MAX_EXCERPT_BYTES,
) -> ExcerptRead:
    """Read a bounded, truncation-marked text excerpt from a diagnostic stream.

    The excerpt is decoded permissively (``errors='replace'``) because these
    streams are raw provider output, not trusted structured claims. It is not
    HTML-escaped here; the renderer escapes at emit time.
    """

    target = safe_child_path(root_real, relative)
    if target is None:
        return ExcerptRead(relative, PresenceState.INCONSISTENT, "unsafe path (traversal or reparse point)", "", False, None, None)
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return ExcerptRead(relative, PresenceState.ABSENT, None, "", False, None, None)
    except OSError as exc:
        return ExcerptRead(relative, PresenceState.INCONSISTENT, f"unreadable: {type(exc).__name__}", "", False, None, None)
    if not stat.S_ISREG(st.st_mode):
        return ExcerptRead(relative, PresenceState.INCONSISTENT, "not a regular file", "", False, st.st_size, None)
    window = max(0, int(max_bytes))
    try:
        with open(target, "rb") as handle:
            chunk = handle.read(window)
    except OSError as exc:
        return ExcerptRead(relative, PresenceState.INCONSISTENT, f"read failed: {type(exc).__name__}", "", False, st.st_size, None)
    truncated = st.st_size > len(chunk)
    encoding_note = None
    text = chunk.decode("utf-8", errors="replace")
    if "�" in text:
        encoding_note = "utf-8 with replacement characters"
    return ExcerptRead(relative, PresenceState.PRESENT, None, text, truncated, st.st_size, encoding_note)


def file_presence(root_real: Path, relative: str) -> PresenceState:
    """Classify whether a plain (non-parsed) file is present, absent or unsafe."""

    target = safe_child_path(root_real, relative)
    if target is None:
        return PresenceState.INCONSISTENT
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return PresenceState.ABSENT
    except OSError:
        return PresenceState.INCONSISTENT
    if not stat.S_ISREG(st.st_mode):
        return PresenceState.INCONSISTENT
    return PresenceState.PRESENT


def list_child_directories(parent: Path | str) -> tuple[list[str], list[str]]:
    """Return ``(child_dir_names, skipped_reparse_names)`` for a parent directory.

    Only immediate children are considered. Reparse-point children are never
    descended into and are reported separately. The lists are lexically sorted
    for deterministic ordering. Raises ``NotADirectoryError`` if ``parent`` is
    not a directory (callers handle discovery-level errors explicitly).
    """

    root_real = resolve_root(parent)
    if not root_real.is_dir():
        raise NotADirectoryError(str(parent))
    children: list[str] = []
    skipped: list[str] = []
    with os.scandir(root_real) as entries:
        for entry in entries:
            try:
                is_reparse = _is_reparse_point(Path(entry.path))
                if is_reparse:
                    skipped.append(entry.name)
                    continue
                if entry.is_dir(follow_symlinks=False):
                    children.append(entry.name)
            except OSError:
                skipped.append(entry.name)
    return sorted(children), sorted(skipped)
