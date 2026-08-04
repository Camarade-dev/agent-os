"""Observe a Git repository without executing a single repository-selected program.

Milestone 2's observer ran ``git status`` inside the capsule with a long list of
``-c`` overrides that neutralised ``core.fsmonitor``, hooks, external diff,
credential helpers, and pagers.  That list is a denylist, and it was incomplete:
a repository can name an arbitrary *filter driver* through ``.gitattributes``
(``*.txt filter=whatever``) and define it in its own ``.git/config``
(``filter.whatever.clean``).  ``git status`` must apply that driver to decide
whether a working-tree file matches the index, so it executes the repository's
chosen program -- after the durable STARTED record, during what the evidence
calls an *observation*, and outside the proposed tool semantics entirely.  The
independent audit reproduced exactly that with the shipped override list.

No denylist can close this, because the set of filter names is unbounded.  The
observer is therefore rebuilt to execute nothing at all.  It reads:

* ``HEAD`` and the ref it names, including ``packed-refs``;
* the binary index (``DIRC`` v2/v3), with its trailing SHA-1 verified;
* Git objects from loose storage and from packfiles, resolving offset and
  reference deltas, so the HEAD tree can be compared with the index;
* the working tree, hashing each file into a Git blob identity with the same
  ``sha1("blob <len>\\0" + bytes)`` construction Git uses.

Where the answer would depend on running a program, it fails closed.  A
repository that declares any content conversion -- a ``filter``, ``text``,
``eol``, ``ident``, or ``working-tree-encoding`` attribute, a ``[filter ...]``
configuration section, or ``core.autocrlf`` -- makes the working-tree-to-blob
mapping a repository-defined computation.  This observer will not perform that
computation and will not delegate it, so it records
``GIT_CONVERSION_REQUIRED`` and observes nothing further.  An unparsable layout
records ``GIT_REPOSITORY_UNSUPPORTED_LAYOUT`` and unreadable metadata records
``GIT_METADATA_UNREADABLE``.  None of those states is a fallback to executing
``git``; there is no such fallback anywhere in this module.

Every filesystem access descends one path component at a time from a directory
descriptor with ``O_NOFOLLOW``, so a symlink planted inside ``.git`` cannot
redirect the observer at a host file.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
from typing import Any, Iterator
import zlib

from .canonical import Fingerprint, fingerprint
from .observation import GitObservation


GIT_STATUS_FINGERPRINT_DOMAIN = "admissible.paired_runner.m2.git_observation.status"

OBSERVATION_METHOD = "NON_EXECUTING_REFS_INDEX_AND_OBJECTS"

#: Ignore rules are a second repository-controlled language.  This observer does
#: not evaluate them, and says so rather than silently reporting a different
#: quantity than the field name suggests.
UNTRACKED_SEMANTICS = (
    "Every working-tree path the index does not track is counted.  Ignore rules "
    "(.gitignore, .git/info/exclude, core.excludesFile) are deliberately not evaluated, so this "
    "count is a superset of the paths a git client would call untracked."
)

#: Attribute names whose presence means the working-tree bytes and the blob
#: bytes are related by a repository-defined computation rather than by identity.
CONVERSION_ATTRIBUTE_TOKENS = ("filter", "text", "eol", "ident", "working-tree-encoding")

#: Bounds.  A repository is untrusted input, so every parser here is bounded.
MAX_INDEX_BYTES = 256 * 1024 * 1024
MAX_INDEX_ENTRIES = 500_000
MAX_OBJECT_BYTES = 256 * 1024 * 1024
MAX_DELTA_DEPTH = 64
MAX_TREE_ENTRIES = 500_000
MAX_WORKTREE_ENTRIES = 500_000
MAX_ATTRIBUTES_BYTES = 4 * 1024 * 1024
MAX_REF_BYTES = 64 * 1024
MAX_PACKED_REFS_BYTES = 64 * 1024 * 1024

_OBJECT_TYPE_NAMES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_OFS_DELTA = 6
_REF_DELTA = 7

GITLINK_MODE = 0o160000
SYMLINK_MODE = 0o120000


class GitObservationRefused(Exception):
    """The repository cannot be observed without executing something."""

    def __init__(self, availability: str, reason: str) -> None:
        super().__init__(f"{availability}: {reason}")
        self.availability = availability
        self.reason = reason


def _refuse(availability: str, reason: str) -> GitObservationRefused:
    return GitObservationRefused(availability, reason)


# --- descriptor-relative access ---------------------------------------------

class _Anchored:
    """Read-only access anchored at one directory descriptor, never following links.

    Every component is opened with ``O_NOFOLLOW``.  A repository that replaces
    ``.git/objects`` with a symlink to a host directory therefore cannot make
    this observer read host bytes into the evidence record.
    """

    def __init__(self, root_fd: int) -> None:
        self._root_fd = root_fd

    def _descend(self, parts: tuple[str, ...]) -> tuple[int, list[int]]:
        opened: list[int] = []
        current = self._root_fd
        for part in parts:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current
                )
            except OSError as error:
                for handle in opened:
                    os.close(handle)
                raise error
            opened.append(child)
            current = child
        return current, opened

    @staticmethod
    def _split(relative: str) -> tuple[tuple[str, ...], str]:
        parts = tuple(part for part in relative.split("/") if part not in {"", "."})
        if not parts:
            raise ValueError("an anchored path must name something")
        return parts[:-1], parts[-1]

    def lstat(self, relative: str) -> os.stat_result | None:
        parts, leaf = self._split(relative)
        try:
            parent, opened = self._descend(parts)
        except OSError:
            return None
        try:
            return os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except OSError:
            return None
        finally:
            for handle in opened:
                os.close(handle)

    def read_bytes(self, relative: str, *, limit: int) -> bytes | None:
        """Read one regular file, or ``None`` when it is absent or not regular."""

        parts, leaf = self._split(relative)
        try:
            parent, opened = self._descend(parts)
        except OSError:
            return None
        try:
            handle = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        except OSError:
            return None
        finally:
            for descriptor in opened:
                os.close(descriptor)
        try:
            info = os.fstat(handle)
            if not stat.S_ISREG(info.st_mode):
                return None
            if info.st_size > limit:
                raise _refuse("GIT_METADATA_UNREADABLE", f"{relative} exceeds its parser bound")
            chunks: list[bytes] = []
            total = 0
            while total <= limit:
                chunk = os.read(handle, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > limit:
                raise _refuse("GIT_METADATA_UNREADABLE", f"{relative} exceeds its parser bound")
            return b"".join(chunks)
        finally:
            os.close(handle)

    def readlink(self, relative: str) -> bytes | None:
        parts, leaf = self._split(relative)
        try:
            parent, opened = self._descend(parts)
        except OSError:
            return None
        try:
            return os.readlink(leaf, dir_fd=parent).encode("utf-8", "surrogateescape")
        except OSError:
            return None
        finally:
            for handle in opened:
                os.close(handle)

    def listdir(self, relative: str) -> list[str] | None:
        parts = tuple(part for part in relative.split("/") if part not in {"", "."})
        try:
            parent, opened = self._descend(parts)
        except OSError:
            return None
        try:
            return sorted(os.listdir(parent))
        except OSError:
            return None
        finally:
            for handle in opened:
                os.close(handle)


# --- object storage ----------------------------------------------------------

@dataclass(frozen=True)
class _PackIndex:
    """One parsed ``.idx`` v2 file: sorted names and their pack offsets."""

    names: bytes
    offsets: tuple[int, ...]
    count: int
    fanout: tuple[int, ...]

    def lookup(self, sha: bytes) -> int | None:
        first = sha[0]
        low = self.fanout[first - 1] if first else 0
        high = self.fanout[first]
        while low < high:
            middle = (low + high) // 2
            candidate = self.names[middle * 20 : middle * 20 + 20]
            if candidate == sha:
                return self.offsets[middle]
            if candidate < sha:
                low = middle + 1
            else:
                high = middle
        return None


def _parse_pack_index(raw: bytes) -> _PackIndex:
    if len(raw) < 8 + 1024 + 40 or raw[:4] != b"\xfftOc" or struct.unpack(">I", raw[4:8])[0] != 2:
        raise _refuse("GIT_REPOSITORY_UNSUPPORTED_LAYOUT", "only pack index version 2 is parsed")
    fanout = struct.unpack(">256I", raw[8 : 8 + 1024])
    count = fanout[255]
    if count > MAX_TREE_ENTRIES * 8:
        raise _refuse("GIT_METADATA_UNREADABLE", "the pack index exceeds its parser bound")
    names_at = 8 + 1024
    crc_at = names_at + count * 20
    offsets_at = crc_at + count * 4
    large_at = offsets_at + count * 4
    if len(raw) < large_at + 40:
        raise _refuse("GIT_METADATA_UNREADABLE", "the pack index is truncated")
    names = raw[names_at:crc_at]
    raw_offsets = struct.unpack(f">{count}I", raw[offsets_at:large_at]) if count else ()
    offsets: list[int] = []
    for value in raw_offsets:
        if value & 0x80000000:
            slot = value & 0x7FFFFFFF
            start = large_at + slot * 8
            if start + 8 > len(raw) - 40:
                raise _refuse("GIT_METADATA_UNREADABLE", "a large pack offset is out of range")
            offsets.append(struct.unpack(">Q", raw[start : start + 8])[0])
        else:
            offsets.append(value)
    return _PackIndex(names=names, offsets=tuple(offsets), count=count, fanout=fanout)


class _ObjectStore:
    """Loose and packed Git object access, with bounded delta resolution."""

    def __init__(self, anchored: _Anchored, git_dir: str) -> None:
        self._anchored = anchored
        self._git_dir = git_dir
        self._packs: list[tuple[_PackIndex, bytes]] | None = None
        self._cache: dict[bytes, tuple[str, bytes]] = {}

    def _load_packs(self) -> list[tuple[_PackIndex, bytes]]:
        if self._packs is not None:
            return self._packs
        packs: list[tuple[_PackIndex, bytes]] = []
        names = self._anchored.listdir(f"{self._git_dir}/objects/pack") or []
        for name in names:
            if not name.endswith(".idx"):
                continue
            index_raw = self._anchored.read_bytes(
                f"{self._git_dir}/objects/pack/{name}", limit=MAX_OBJECT_BYTES
            )
            pack_raw = self._anchored.read_bytes(
                f"{self._git_dir}/objects/pack/{name[:-4]}.pack", limit=MAX_OBJECT_BYTES
            )
            if index_raw is None or pack_raw is None:
                continue
            packs.append((_parse_pack_index(index_raw), pack_raw))
        self._packs = packs
        return packs

    def read(self, sha_hex: str, *, depth: int = 0) -> tuple[str, bytes]:
        """Return ``(type_name, payload)`` for one object identity."""

        if depth > MAX_DELTA_DEPTH:
            raise _refuse("GIT_METADATA_UNREADABLE", "the delta chain exceeds its bound")
        key = bytes.fromhex(sha_hex)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        loose = self._anchored.read_bytes(
            f"{self._git_dir}/objects/{sha_hex[:2]}/{sha_hex[2:]}", limit=MAX_OBJECT_BYTES
        )
        if loose is not None:
            result = _parse_loose_object(loose)
            self._cache[key] = result
            return result
        for index, pack in self._load_packs():
            offset = index.lookup(key)
            if offset is None:
                continue
            result = self._read_packed(pack, offset, depth=depth)
            self._cache[key] = result
            return result
        raise _refuse("GIT_METADATA_UNREADABLE", f"object {sha_hex} is not in this repository's object store")

    def _read_packed(self, pack: bytes, offset: int, *, depth: int) -> tuple[str, bytes]:
        if depth > MAX_DELTA_DEPTH:
            raise _refuse("GIT_METADATA_UNREADABLE", "the delta chain exceeds its bound")
        type_id, size, cursor = _parse_pack_object_header(pack, offset)
        if type_id == _OFS_DELTA:
            distance, cursor = _parse_pack_offset_delta(pack, cursor)
            base_offset = offset - distance
            if base_offset < 0:
                raise _refuse("GIT_METADATA_UNREADABLE", "an offset delta names a base outside the pack")
            base_type, base_data = self._read_packed(pack, base_offset, depth=depth + 1)
            delta = _inflate_at(pack, cursor, size)
            return base_type, _apply_delta(base_data, delta)
        if type_id == _REF_DELTA:
            base_sha = pack[cursor : cursor + 20]
            if len(base_sha) != 20:
                raise _refuse("GIT_METADATA_UNREADABLE", "a reference delta is truncated")
            base_type, base_data = self.read(base_sha.hex(), depth=depth + 1)
            delta = _inflate_at(pack, cursor + 20, size)
            return base_type, _apply_delta(base_data, delta)
        name = _OBJECT_TYPE_NAMES.get(type_id)
        if name is None:
            raise _refuse("GIT_REPOSITORY_UNSUPPORTED_LAYOUT", f"unknown packed object type {type_id}")
        return name, _inflate_at(pack, cursor, size)


def _parse_loose_object(raw: bytes) -> tuple[str, bytes]:
    try:
        decompressed = zlib.decompress(raw)
    except zlib.error as error:
        raise _refuse("GIT_METADATA_UNREADABLE", "a loose object is not valid zlib") from error
    separator = decompressed.find(b"\x00")
    if separator < 0:
        raise _refuse("GIT_METADATA_UNREADABLE", "a loose object has no header terminator")
    header = decompressed[:separator].split(b" ")
    if len(header) != 2:
        raise _refuse("GIT_METADATA_UNREADABLE", "a loose object header is malformed")
    return header[0].decode("ascii", "replace"), decompressed[separator + 1 :]


def _parse_pack_object_header(pack: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(pack):
        raise _refuse("GIT_METADATA_UNREADABLE", "a pack offset is out of range")
    byte = pack[offset]
    offset += 1
    type_id = (byte >> 4) & 0x07
    size = byte & 0x0F
    shift = 4
    while byte & 0x80:
        if offset >= len(pack) or shift > 60:
            raise _refuse("GIT_METADATA_UNREADABLE", "a pack object header is malformed")
        byte = pack[offset]
        offset += 1
        size |= (byte & 0x7F) << shift
        shift += 7
    if size > MAX_OBJECT_BYTES:
        raise _refuse("GIT_METADATA_UNREADABLE", "a packed object exceeds its parser bound")
    return type_id, size, offset


def _parse_pack_offset_delta(pack: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(pack):
        raise _refuse("GIT_METADATA_UNREADABLE", "an offset delta header is truncated")
    byte = pack[offset]
    offset += 1
    value = byte & 0x7F
    while byte & 0x80:
        if offset >= len(pack):
            raise _refuse("GIT_METADATA_UNREADABLE", "an offset delta header is truncated")
        byte = pack[offset]
        offset += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, offset


def _inflate_at(pack: bytes, offset: int, expected_size: int) -> bytes:
    decompressor = zlib.decompressobj()
    chunks: list[bytes] = []
    total = 0
    cursor = offset
    while not decompressor.eof:
        if cursor >= len(pack):
            raise _refuse("GIT_METADATA_UNREADABLE", "a packed object stream is truncated")
        chunk = decompressor.decompress(pack[cursor : cursor + 65536])
        cursor += 65536
        total += len(chunk)
        if total > MAX_OBJECT_BYTES:
            raise _refuse("GIT_METADATA_UNREADABLE", "a packed object exceeds its parser bound")
        chunks.append(chunk)
    payload = b"".join(chunks)
    if len(payload) != expected_size:
        raise _refuse("GIT_METADATA_UNREADABLE", "a packed object size does not match its header")
    return payload


def _apply_delta(base: bytes, delta: bytes) -> bytes:
    cursor = 0

    def varint() -> int:
        nonlocal cursor
        value = 0
        shift = 0
        while True:
            if cursor >= len(delta):
                raise _refuse("GIT_METADATA_UNREADABLE", "a delta size varint is truncated")
            byte = delta[cursor]
            cursor += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value

    source_size = varint()
    target_size = varint()
    if source_size != len(base):
        raise _refuse("GIT_METADATA_UNREADABLE", "a delta declares the wrong base size")
    if target_size > MAX_OBJECT_BYTES:
        raise _refuse("GIT_METADATA_UNREADABLE", "a delta target exceeds its parser bound")
    out: list[bytes] = []
    while cursor < len(delta):
        opcode = delta[cursor]
        cursor += 1
        if opcode & 0x80:
            copy_offset = 0
            copy_size = 0
            for shift, bit in enumerate((0x01, 0x02, 0x04, 0x08)):
                if opcode & bit:
                    copy_offset |= delta[cursor] << (8 * shift)
                    cursor += 1
            for shift, bit in enumerate((0x10, 0x20, 0x40)):
                if opcode & bit:
                    copy_size |= delta[cursor] << (8 * shift)
                    cursor += 1
            if copy_size == 0:
                copy_size = 0x10000
            if copy_offset + copy_size > len(base):
                raise _refuse("GIT_METADATA_UNREADABLE", "a delta copy is out of range")
            out.append(base[copy_offset : copy_offset + copy_size])
        elif opcode:
            out.append(delta[cursor : cursor + opcode])
            cursor += opcode
        else:
            raise _refuse("GIT_METADATA_UNREADABLE", "a delta contains a reserved opcode")
    payload = b"".join(out)
    if len(payload) != target_size:
        raise _refuse("GIT_METADATA_UNREADABLE", "a delta produced the wrong target size")
    return payload


# --- refs --------------------------------------------------------------------

def _resolve_head(anchored: _Anchored, git_dir: str) -> tuple[str | None, str | None]:
    """Return ``(reference_name, commit_sha)`` without executing anything."""

    raw = anchored.read_bytes(f"{git_dir}/HEAD", limit=MAX_REF_BYTES)
    if raw is None:
        raise _refuse("GIT_METADATA_UNREADABLE", "HEAD is absent or unreadable")
    text = raw.decode("utf-8", "replace").strip()
    if not text.startswith("ref: "):
        if _is_sha1(text):
            return None, text
        raise _refuse("GIT_METADATA_UNREADABLE", "HEAD is neither a symbolic ref nor an object name")
    reference = text[5:].strip()
    seen: set[str] = set()
    while True:
        if reference in seen or len(seen) > 16:
            raise _refuse("GIT_METADATA_UNREADABLE", "the HEAD reference chain does not terminate")
        seen.add(reference)
        if "/.." in reference or reference.startswith("/") or "\x00" in reference:
            raise _refuse("GIT_METADATA_UNREADABLE", "the HEAD reference names an unsafe path")
        loose = anchored.read_bytes(f"{git_dir}/{reference}", limit=MAX_REF_BYTES)
        if loose is not None:
            value = loose.decode("utf-8", "replace").strip()
            if value.startswith("ref: "):
                reference = value[5:].strip()
                continue
            if _is_sha1(value):
                return reference, value
            raise _refuse("GIT_METADATA_UNREADABLE", "a ref file does not hold an object name")
        packed = _packed_ref(anchored, git_dir, reference)
        if packed is not None:
            return reference, packed
        # An unborn branch is a legitimate, fully determined state: the ref
        # exists as a name and resolves to nothing.
        return reference, None


def _packed_ref(anchored: _Anchored, git_dir: str, reference: str) -> str | None:
    raw = anchored.read_bytes(f"{git_dir}/packed-refs", limit=MAX_PACKED_REFS_BYTES)
    if raw is None:
        return None
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].strip() == reference and _is_sha1(parts[0]):
            return parts[0]
    return None


def _is_sha1(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value.lower())


# --- the index ---------------------------------------------------------------

@dataclass(frozen=True)
class IndexEntry:
    """One stage-0-or-conflicted entry of a parsed Git index."""

    path: str
    mode: int
    sha: str
    stage: int
    size: int


def _parse_index(raw: bytes) -> tuple[IndexEntry, ...]:
    if len(raw) < 12 + 20 or raw[:4] != b"DIRC":
        raise _refuse("GIT_REPOSITORY_UNSUPPORTED_LAYOUT", "the index is not a DIRC file")
    version, count = struct.unpack(">II", raw[4:12])
    if version not in {2, 3}:
        # Version 4 prefix-compresses path names.  Rather than guess at a format
        # this parser has not been proven against, the observation fails closed.
        raise _refuse("GIT_REPOSITORY_UNSUPPORTED_LAYOUT", f"index version {version} is not parsed")
    if count > MAX_INDEX_ENTRIES:
        raise _refuse("GIT_METADATA_UNREADABLE", "the index exceeds its parser bound")
    # The trailing checksum is verified, so a truncated or edited index is a
    # refusal rather than a partially decoded observation.
    if hashlib.sha1(raw[:-20], usedforsecurity=False).digest() != raw[-20:]:
        raise _refuse("GIT_METADATA_UNREADABLE", "the index checksum does not verify")

    entries: list[IndexEntry] = []
    cursor = 12
    for _ in range(count):
        if cursor + 62 > len(raw) - 20:
            raise _refuse("GIT_METADATA_UNREADABLE", "the index is truncated")
        start = cursor
        fields = struct.unpack(">10I20sH", raw[cursor : cursor + 62])
        mode = fields[6]
        size = fields[9]
        sha = fields[10].hex()
        flags = fields[11]
        cursor += 62
        if flags & 0x4000:  # extended flag: two more bytes of flags
            cursor += 2
        stage = (flags >> 12) & 0x3
        name_length = flags & 0x0FFF
        if name_length < 0x0FFF:
            path_bytes = raw[cursor : cursor + name_length]
            cursor += name_length
        else:
            terminator = raw.find(b"\x00", cursor)
            if terminator < 0:
                raise _refuse("GIT_METADATA_UNREADABLE", "an index path is unterminated")
            path_bytes = raw[cursor:terminator]
            cursor = terminator
        # Entries are padded with NULs to a multiple of eight bytes.
        cursor += 8 - ((cursor - start) % 8)
        try:
            path = path_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise _refuse("GIT_METADATA_UNREADABLE", "an index path is not valid UTF-8") from error
        entries.append(IndexEntry(path=path, mode=mode, sha=sha, stage=stage, size=size))
    return tuple(entries)


# --- trees -------------------------------------------------------------------

def _flatten_tree(store: _ObjectStore, tree_sha: str, prefix: str = "") -> dict[str, tuple[int, str]]:
    flattened: dict[str, tuple[int, str]] = {}
    stack: list[tuple[str, str]] = [(tree_sha, prefix)]
    while stack:
        sha, current = stack.pop()
        kind, payload = store.read(sha)
        if kind != "tree":
            raise _refuse("GIT_METADATA_UNREADABLE", f"{sha} is a {kind} where a tree was required")
        for mode, name, entry_sha in _iterate_tree(payload):
            path = f"{current}{name}"
            if stat.S_ISDIR(mode) or mode == 0o40000:
                stack.append((entry_sha, f"{path}/"))
                continue
            flattened[path] = (mode, entry_sha)
            if len(flattened) > MAX_TREE_ENTRIES:
                raise _refuse("GIT_METADATA_UNREADABLE", "the HEAD tree exceeds its parser bound")
    return flattened


def _iterate_tree(payload: bytes) -> Iterator[tuple[int, str, str]]:
    cursor = 0
    while cursor < len(payload):
        space = payload.find(b" ", cursor)
        terminator = payload.find(b"\x00", space + 1)
        if space < 0 or terminator < 0 or terminator + 20 > len(payload):
            raise _refuse("GIT_METADATA_UNREADABLE", "a tree object is malformed")
        try:
            mode = int(payload[cursor:space], 8)
            name = payload[space + 1 : terminator].decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise _refuse("GIT_METADATA_UNREADABLE", "a tree entry is malformed") from error
        yield mode, name, payload[terminator + 1 : terminator + 21].hex()
        cursor = terminator + 21


# --- conversion detection ----------------------------------------------------

def _declares_conversion(text: str) -> bool:
    """True when any attribute line declares a working-tree-to-blob conversion.

    Attribute *names* are compared, not raw substrings: a pattern like
    ``notes/*.txt`` must not be mistaken for the ``text`` attribute.  A macro
    definition is treated as a conversion outright, because it can attach one
    indirectly under a name this function has no way to follow.
    """

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[attr]"):
            return True
        fields = stripped.split()
        for field in fields[1:]:
            name = field.lstrip("-!").split("=", 1)[0].strip().lower()
            if name in CONVERSION_ATTRIBUTE_TOKENS:
                return True
    return False


def _conversion_is_declared(
    anchored: _Anchored, git_dir: str, worktree_paths: tuple[str, ...], index_entries: tuple[IndexEntry, ...], store: _ObjectStore
) -> str | None:
    """Name the source of a declared content conversion, or ``None``."""

    for relative in worktree_paths:
        raw = anchored.read_bytes(relative, limit=MAX_ATTRIBUTES_BYTES)
        if raw is not None and _declares_conversion(raw.decode("utf-8", "replace")):
            return f"the working-tree {relative} declares a content conversion"
    info = anchored.read_bytes(f"{git_dir}/info/attributes", limit=MAX_ATTRIBUTES_BYTES)
    if info is not None and _declares_conversion(info.decode("utf-8", "replace")):
        return f"{git_dir}/info/attributes declares a content conversion"
    # Attributes can live only in the index or the tree, with no working-tree
    # file at all, so the tracked copies are read from object storage.
    for entry in index_entries:
        if os.path.basename(entry.path) != ".gitattributes" or entry.stage != 0:
            continue
        kind, payload = store.read(entry.sha)
        if kind == "blob" and _declares_conversion(payload.decode("utf-8", "replace")):
            return f"the tracked {entry.path} declares a content conversion"
    config = anchored.read_bytes(f"{git_dir}/config", limit=MAX_ATTRIBUTES_BYTES)
    if config is not None:
        text = config.decode("utf-8", "replace")
        for line in text.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("[filter "):
                return f"{git_dir}/config defines a filter driver"
            if stripped.startswith("autocrlf") and not stripped.endswith("false"):
                return f"{git_dir}/config enables core.autocrlf"
            if stripped.startswith("eol ") or stripped.startswith("eol="):
                return f"{git_dir}/config sets core.eol"
    return None


# --- the observation ---------------------------------------------------------

def _blob_identity(payload: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(b"blob %d\x00" % len(payload))
    digest.update(payload)
    return digest.hexdigest()


def _walk_worktree(anchored: _Anchored, root_fd: int) -> tuple[tuple[str, int], tuple[str, ...]]:
    """Every working-tree path with its inode mode, and the ``.gitattributes``.

    ``.git`` is never descended into: it is repository metadata, read explicitly
    elsewhere, and never a tracked working-tree path.
    """

    found: list[tuple[str, int]] = []
    attributes: list[str] = []
    stack: list[tuple[int, str, bool]] = [(root_fd, "", False)]
    try:
        while stack:
            directory_fd, prefix, owned = stack.pop()
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError:
                names = []
            for name in names:
                relative = f"{prefix}{name}"
                if relative == ".git" or name == ".git":
                    continue
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    try:
                        child = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory_fd,
                        )
                    except OSError:
                        continue
                    stack.append((child, f"{relative}/", True))
                    continue
                found.append((relative, info.st_mode))
                if name == ".gitattributes":
                    attributes.append(relative)
                if len(found) > MAX_WORKTREE_ENTRIES:
                    raise _refuse("GIT_METADATA_UNREADABLE", "the working tree exceeds its parser bound")
            if owned:
                os.close(directory_fd)
    finally:
        for directory_fd, _, owned in stack:
            if owned:
                try:
                    os.close(directory_fd)
                except OSError:  # pragma: no cover
                    pass
    return tuple(found), tuple(sorted(attributes))  # type: ignore[return-value]


def observe_git_unobserved(phase: str, availability: str, *, reason: str | None = None) -> GitObservation:
    """A Git record that ran no process and determined nothing."""

    return GitObservation.create(
        phase=phase,
        availability=availability,
        repository_present=True,
        refusal_reason=reason,
    )


def observe_repository(root: Path, root_fd: int, *, phase: str) -> GitObservation:
    """Observe one repository, executing nothing at all.

    The result is a complete, determinate observation or an explicit refusal.
    There is no path through this function that starts a process, and none that
    guesses at a value it could not derive.
    """

    anchored = _Anchored(root_fd)
    git_stat = anchored.lstat(".git")
    if git_stat is None:
        return GitObservation.create(phase=phase, availability="REPOSITORY_ABSENT", repository_present=False)
    if not stat.S_ISDIR(git_stat.st_mode):
        return observe_git_unobserved(
            phase,
            "GIT_REPOSITORY_UNSUPPORTED_LAYOUT",
            reason="the .git entry is not a directory, so this is a linked worktree or submodule",
        )

    try:
        return _observe(anchored, root_fd, phase=phase, git_dir=".git")
    except GitObservationRefused as refusal:
        return observe_git_unobserved(phase, refusal.availability, reason=refusal.reason)
    except (OSError, ValueError, struct.error, zlib.error) as error:
        return observe_git_unobserved(
            phase, "GIT_METADATA_UNREADABLE", reason=f"{type(error).__name__}: {error}"[:1000]
        )


def _observe(anchored: _Anchored, root_fd: int, *, phase: str, git_dir: str) -> GitObservation:
    reference, head_commit = _resolve_head(anchored, git_dir)
    store = _ObjectStore(anchored, git_dir)

    index_raw = anchored.read_bytes(f"{git_dir}/index", limit=MAX_INDEX_BYTES)
    entries: tuple[IndexEntry, ...] = () if index_raw is None else _parse_index(index_raw)
    index_by_path = {entry.path: entry for entry in entries if entry.stage == 0}
    unmerged = {entry.path for entry in entries if entry.stage != 0}

    worktree, attribute_files = _walk_worktree(anchored, root_fd)
    conversion = _conversion_is_declared(anchored, git_dir, attribute_files, entries, store)
    if conversion is not None:
        # The working-tree-to-blob mapping is a repository-defined computation.
        # This observer will not perform it and will not delegate it.
        raise _refuse("GIT_CONVERSION_REQUIRED", conversion)

    head_tree: dict[str, tuple[int, str]] = {}
    if head_commit is not None:
        kind, payload = store.read(head_commit)
        if kind != "commit":
            raise _refuse("GIT_METADATA_UNREADABLE", "HEAD does not name a commit")
        tree_sha = _commit_tree(payload)
        head_tree = _flatten_tree(store, tree_sha)

    staged = {
        path
        for path in set(head_tree) | set(index_by_path)
        if _tree_slot(head_tree, path) != _index_slot(index_by_path, path)
    }

    modified: list[str] = []
    missing: list[str] = []
    worktree_modes = dict(worktree)
    for path, entry in sorted(index_by_path.items()):
        if entry.mode == GITLINK_MODE:
            # A submodule's own repository is out of this observation's scope,
            # exactly as --ignore-submodules=all was before.
            continue
        mode = worktree_modes.get(path)
        if mode is None:
            missing.append(path)
            continue
        identity = _worktree_blob_identity(anchored, path, mode)
        if identity is None or identity != entry.sha or not _mode_matches(entry.mode, mode):
            modified.append(path)

    untracked = sorted(path for path, _ in worktree if path not in index_by_path)

    status_payload = {
        "head": head_commit,
        "head_reference": reference,
        "staged": sorted(staged),
        "modified": sorted(modified),
        "missing": sorted(missing),
        "unmerged": sorted(unmerged),
        "untracked": untracked,
    }
    return GitObservation.create(
        phase=phase,
        availability="OBSERVED",
        repository_present=True,
        head_commit=head_commit or "0" * 40,
        index_dirty=bool(staged or unmerged),
        worktree_dirty=bool(modified or missing),
        untracked_present=bool(untracked),
        status_fingerprint=fingerprint(status_payload, domain=GIT_STATUS_FINGERPRINT_DOMAIN),
        observation_method=OBSERVATION_METHOD,
        head_reference=reference,
        index_entry_count=len(index_by_path),
        staged_change_count=len(staged),
        modified_entry_count=len(modified),
        missing_entry_count=len(missing),
        untracked_entry_count=len(untracked),
        unmerged_entry_count=len(unmerged),
        untracked_semantics=UNTRACKED_SEMANTICS,
    )


def _commit_tree(payload: bytes) -> str:
    for line in payload.split(b"\n"):
        if line.startswith(b"tree "):
            candidate = line[5:].decode("ascii", "replace").strip()
            if _is_sha1(candidate):
                return candidate
            break
        if not line:
            break
    raise _refuse("GIT_METADATA_UNREADABLE", "the HEAD commit names no tree")


def _tree_slot(head_tree: dict[str, tuple[int, str]], path: str) -> tuple[int, str] | None:
    return head_tree.get(path)


def _index_slot(index_by_path: dict[str, IndexEntry], path: str) -> tuple[int, str] | None:
    entry = index_by_path.get(path)
    return None if entry is None else (entry.mode, entry.sha)


def _mode_matches(index_mode: int, worktree_mode: int) -> bool:
    if index_mode == SYMLINK_MODE:
        return stat.S_ISLNK(worktree_mode)
    if not stat.S_ISREG(worktree_mode):
        return False
    executable = bool(worktree_mode & 0o111)
    return executable == (index_mode == 0o100755)


def _worktree_blob_identity(anchored: _Anchored, path: str, mode: int) -> str | None:
    if stat.S_ISLNK(mode):
        target = anchored.readlink(path)
        return None if target is None else _blob_identity(target)
    if not stat.S_ISREG(mode):
        return None
    payload = anchored.read_bytes(path, limit=MAX_OBJECT_BYTES)
    return None if payload is None else _blob_identity(payload)


__all__ = [
    "CONVERSION_ATTRIBUTE_TOKENS",
    "GIT_STATUS_FINGERPRINT_DOMAIN",
    "GitObservationRefused",
    "IndexEntry",
    "OBSERVATION_METHOD",
    "UNTRACKED_SEMANTICS",
    "observe_git_unobserved",
    "observe_repository",
]
