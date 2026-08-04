"""Private per-effect execution view and trusted export.

A live writable bind of the authorized host workspace cannot satisfy the
governing invariant that the effect process never observes a host-backed IPC
endpoint: a host can create a FIFO after admission, and ``open`` of that FIFO is
indistinguishable from ``open`` of a regular file under seccomp.

This module replaces that construction.  Every effect process runs against a
private materialized view.  After process-domain quiescence a trusted controller
computes a closed change set and exports only regular files, directories, and
in-tree relative symlinks into the authorized workspace.  Sockets, FIFOs,
devices, and escaping symlinks are never exported.  Source mutation between
snapshot and export refuses the export rather than merging.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Any, Callable, ClassVar, Iterator

from .canonical import Fingerprint, fingerprint
from .observation import (
    M2_PREFIX,
    M2_SCHEMA_VERSION,
    ObservationError,
    _decode_fp,
    _decode_strings,
    _encode_fp,
    _encode_strings,
    _M2Record,
    _require_int,
    _require_text,
    m2_schema_descriptor,
)


SCHEMA_SOURCE_SNAPSHOT_IDENTITY = f"{M2_PREFIX}.source_snapshot_identity"
SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY = f"{M2_PREFIX}.private_execution_view_identity"
SCHEMA_PROPOSED_EXPORT_CHANGE_SET = f"{M2_PREFIX}.proposed_export_change_set"
SCHEMA_EXPORT_RESERVATION = f"{M2_PREFIX}.export_reservation"
SCHEMA_EXPORT_RECEIPT = f"{M2_PREFIX}.export_receipt"
SCHEMA_EXPORT_RECONCILIATION = f"{M2_PREFIX}.export_reconciliation"

EXPORT_OPERATIONS = (
    "CREATE_REGULAR_FILE",
    "UPDATE_REGULAR_FILE",
    "DELETE_REGULAR_FILE",
    "CREATE_DIRECTORY",
    "DELETE_DIRECTORY",
    "CREATE_SYMLINK",
    "UPDATE_SYMLINK",
    "DELETE_SYMLINK",
)

EXPORT_STATES = (
    "RESERVED",
    "APPLIED",
    "REFUSED_SOURCE_MUTATED",
    "REFUSED_UNSUPPORTED_INODE",
    "REFUSED_PARTIAL",
    "REFUSED_CRASH_CLASSIFIABLE",
)

MAX_EXPORT_ENTRIES = 100_000
MAX_MATERIALIZE_BYTES = 2 * 1024 * 1024 * 1024
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


class PrivateWorkspaceError(RuntimeError):
    """The private view or trusted export cannot proceed."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}:{detail}" if detail else code)
        self.code = code
        self.detail = detail


def _entry_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular_file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "other"


def _is_ipc_or_special(kind: str) -> bool:
    return kind in {"socket", "fifo", "block_device", "character_device", "other"}


def _symlink_is_exportable(target: str) -> bool:
    if not target or "\x00" in target:
        return False
    if target.startswith("/") or target.startswith("\\"):
        return False
    parts = Path(target).parts
    return ".." not in parts


def _walk_tree(root_fd: int) -> Iterator[tuple[str, os.stat_result]]:
    """Yield relative paths and lstat results under an open directory descriptor."""

    stack: list[tuple[int, str]] = [(root_fd, ".")]
    owned: list[int] = []
    try:
        while stack:
            dir_fd, prefix = stack.pop()
            with os.scandir(dir_fd) as entries:
                for entry in entries:
                    relative = entry.name if prefix == "." else f"{prefix}/{entry.name}"
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise PrivateWorkspaceError("tree_walk_failed", f"{relative}:{error.errno}") from error
                    yield relative, info
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
                        owned.append(child)
                        stack.append((child, relative))
    finally:
        for handle in owned:
            try:
                os.close(handle)
            except OSError:
                pass


def _hash_regular_at(dir_fd: int, name: str) -> tuple[str, int]:
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(handle, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MATERIALIZE_BYTES:
                raise PrivateWorkspaceError("materialize_byte_limit", name)
            digest.update(chunk)
        return digest.hexdigest(), total
    finally:
        os.close(handle)


def _open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    if relative in {"", "."}:
        return os.dup(root_fd), "."
    parts = relative.split("/")
    leaf = parts[-1]
    dir_fd = root_fd
    owned: list[int] = []
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            owned.append(nxt)
            dir_fd = nxt
        # Return a dup of the final parent; close intermediates except when parent is root.
        result = os.dup(dir_fd)
        return result, leaf
    finally:
        for handle in owned:
            try:
                os.close(handle)
            except OSError:
                pass


def snapshot_tree_identity(root_fd: int) -> tuple[str, int, int, tuple[str, ...]]:
    """Content identity of a tree: digest, entry count, byte count, specials found."""

    digest = hashlib.sha256()
    entries = 0
    total_bytes = 0
    specials: list[str] = []
    for relative, info in _walk_tree(root_fd):
        entries += 1
        if entries > MAX_EXPORT_ENTRIES:
            raise PrivateWorkspaceError("tree_entry_limit", str(entries))
        kind = _entry_kind(info.st_mode)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(kind.encode("utf-8"))
        digest.update(b"\x00")
        if kind == "regular_file":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                sha, size = _hash_regular_at(parent_fd, leaf)
            finally:
                os.close(parent_fd)
            total_bytes += size
            digest.update(sha.encode("ascii"))
            digest.update(b"\x00")
            digest.update(str(size).encode("ascii"))
        elif kind == "symlink":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                target = os.readlink(leaf, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            digest.update(target.encode("utf-8", "surrogateescape"))
        elif kind == "directory":
            digest.update(b"dir")
        else:
            specials.append(f"{kind}:{relative}")
            digest.update(b"special")
        digest.update(b"\n")
    return digest.hexdigest(), entries, total_bytes, tuple(specials)


@dataclass(frozen=True)
class SourceSnapshotIdentity(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_SOURCE_SNAPSHOT_IDENTITY
    LABEL: ClassVar[str] = "source snapshot identity"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "source_root",
        "device",
        "inode",
        "tree_sha256",
        "entry_count",
        "total_regular_file_bytes",
        "special_inode_count",
    )

    source_root: str
    device: int
    inode: int
    tree_sha256: str
    entry_count: int
    total_regular_file_bytes: int
    special_inode_count: int
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "SourceSnapshotIdentity":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.source_root, "source_root", max_bytes=4096)
        _require_text(self.tree_sha256, "tree_sha256", max_bytes=64)
        if len(self.tree_sha256) != 64:
            raise ObservationError("tree_sha256 must be a sha256 hex digest")
        for name in ("device", "inode", "entry_count", "total_regular_file_bytes", "special_inode_count"):
            _require_int(getattr(self, name), name)


@dataclass(frozen=True)
class PrivateExecutionViewIdentity(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY
    LABEL: ClassVar[str] = "private execution view identity"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "view_root",
        "device",
        "inode",
        "source_snapshot_fingerprint",
        "tree_sha256",
        "entry_count",
        "materialization_kind",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _decode_fp,
    }

    view_root: str
    device: int
    inode: int
    source_snapshot_fingerprint: Fingerprint
    tree_sha256: str
    entry_count: int
    materialization_kind: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "PrivateExecutionViewIdentity":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.view_root, "view_root", max_bytes=4096)
        _require_text(self.tree_sha256, "tree_sha256", max_bytes=64)
        _require_text(self.materialization_kind, "materialization_kind", max_bytes=64)
        self.source_snapshot_fingerprint.validated()
        for name in ("device", "inode", "entry_count"):
            _require_int(getattr(self, name), name)


@dataclass(frozen=True)
class ProposedExportChangeSet(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_PROPOSED_EXPORT_CHANGE_SET
    LABEL: ClassVar[str] = "proposed export change set"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "change_count",
        "operations",
        "paths",
        "change_set_sha256",
        "unsupported_inode_count",
        "unsupported_inodes",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "operations": _encode_strings,
        "paths": _encode_strings,
        "unsupported_inodes": _encode_strings,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "operations": _decode_strings,
        "paths": _decode_strings,
        "unsupported_inodes": _decode_strings,
    }

    change_count: int
    operations: tuple[str, ...]
    paths: tuple[str, ...]
    change_set_sha256: str
    unsupported_inode_count: int
    unsupported_inodes: tuple[str, ...]
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ProposedExportChangeSet":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_int(self.change_count, "change_count")
        _require_int(self.unsupported_inode_count, "unsupported_inode_count")
        _require_text(self.change_set_sha256, "change_set_sha256", max_bytes=64)
        _encode_strings(self.operations)
        _encode_strings(self.paths)
        _encode_strings(self.unsupported_inodes)
        if self.change_count != len(self.operations) or self.change_count != len(self.paths):
            raise ObservationError("change set counts do not agree")
        if self.unsupported_inode_count != len(self.unsupported_inodes):
            raise ObservationError("unsupported inode counts do not agree")
        for operation in self.operations:
            if operation not in EXPORT_OPERATIONS:
                raise ObservationError(f"unsupported export operation {operation}")


@dataclass(frozen=True)
class ExportReservation(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RESERVATION
    LABEL: ClassVar[str] = "export reservation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "source_snapshot_fingerprint",
        "private_view_fingerprint",
        "change_set_fingerprint",
        "state",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _encode_fp,
        "private_view_fingerprint": _encode_fp,
        "change_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _decode_fp,
        "private_view_fingerprint": _decode_fp,
        "change_set_fingerprint": _decode_fp,
    }

    reservation_id: str
    source_snapshot_fingerprint: Fingerprint
    private_view_fingerprint: Fingerprint
    change_set_fingerprint: Fingerprint
    state: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReservation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        self.source_snapshot_fingerprint.validated()
        self.private_view_fingerprint.validated()
        self.change_set_fingerprint.validated()


@dataclass(frozen=True)
class ExportReceipt(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RECEIPT
    LABEL: ClassVar[str] = "export receipt"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "applied_count",
        "state",
        "refusal_code",
        "change_set_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "change_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "change_set_fingerprint": _decode_fp,
    }

    reservation_id: str
    applied_count: int
    state: str
    refusal_code: str
    change_set_fingerprint: Fingerprint
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReceipt":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        _require_text(self.refusal_code, "refusal_code", max_bytes=256)
        _require_int(self.applied_count, "applied_count")
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        self.change_set_fingerprint.validated()


@dataclass(frozen=True)
class ExportReconciliation(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RECONCILIATION
    LABEL: ClassVar[str] = "export reconciliation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "verified",
        "state",
        "source_mutated",
        "private_ipc_exported",
        "partial_export",
        "note",
    )

    reservation_id: str
    verified: bool
    state: str
    source_mutated: bool
    private_ipc_exported: bool
    partial_export: bool
    note: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReconciliation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        _require_text(self.note, "note", max_bytes=2048)
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        for name in ("verified", "source_mutated", "private_ipc_exported", "partial_export"):
            if not isinstance(getattr(self, name), bool):
                raise ObservationError(f"{name} must be a boolean")


M2_PRIVATE_WORKSPACE_SCHEMAS = {
    record_type.SCHEMA_ID: m2_schema_descriptor(
        record_type.SCHEMA_ID,
        record_type.__name__,
        ("schema_id", "schema_version") + record_type.FIELDS + ("record_fingerprint",),
    )
    for record_type in (
        SourceSnapshotIdentity,
        PrivateExecutionViewIdentity,
        ProposedExportChangeSet,
        ExportReservation,
        ExportReceipt,
        ExportReconciliation,
    )
}
for _descriptor in M2_PRIVATE_WORKSPACE_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.private_workspace")


@dataclass
class PrivateExecutionView:
    """One private per-effect filesystem view and the descriptors that name it."""

    parent_dir: Path
    view_root: Path
    view_fd: int
    source_snapshot: SourceSnapshotIdentity
    view_identity: PrivateExecutionViewIdentity
    _closed: bool = False

    @classmethod
    def materialize(cls, source_root: Path, source_fd: int) -> "PrivateExecutionView":
        """Copy the authorized source into a private directory the effect will see.

        Special inodes in the source are refused rather than copied: the private
        view must not begin life as an IPC bridge.
        """

        info = os.fstat(source_fd)
        tree_sha, entry_count, total_bytes, specials = snapshot_tree_identity(source_fd)
        if specials:
            raise PrivateWorkspaceError(
                "source_contains_special_inode",
                specials[0],
            )
        snapshot = SourceSnapshotIdentity.create(
            source_root=str(Path(os.path.realpath(source_root))),
            device=info.st_dev,
            inode=info.st_ino,
            tree_sha256=tree_sha,
            entry_count=entry_count,
            total_regular_file_bytes=total_bytes,
            special_inode_count=0,
        )
        parent = Path(tempfile.mkdtemp(prefix="admissible-private-effect-"))
        os.chmod(parent, DIRECTORY_MODE)
        view_root = parent / "view"
        view_root.mkdir(mode=DIRECTORY_MODE)
        try:
            _materialize_copy(source_fd, view_root)
            view_fd = os.open(view_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                view_info = os.fstat(view_fd)
                view_sha, view_entries, _, view_specials = snapshot_tree_identity(view_fd)
                if view_specials:
                    raise PrivateWorkspaceError("private_view_contains_special_inode", view_specials[0])
                if view_sha != tree_sha:
                    raise PrivateWorkspaceError("private_view_digest_mismatch", f"{view_sha}!={tree_sha}")
                identity = PrivateExecutionViewIdentity.create(
                    view_root=str(view_root),
                    device=view_info.st_dev,
                    inode=view_info.st_ino,
                    source_snapshot_fingerprint=snapshot.record_fingerprint,
                    tree_sha256=view_sha,
                    entry_count=view_entries,
                    materialization_kind="PRIVATE_MATERIALIZED_COPY",
                )
                return cls(
                    parent_dir=parent,
                    view_root=view_root,
                    view_fd=view_fd,
                    source_snapshot=snapshot,
                    view_identity=identity,
                )
            except BaseException:
                os.close(view_fd)
                raise
        except BaseException:
            shutil.rmtree(parent, ignore_errors=True)
            raise

    def source_mutated(self, source_fd: int) -> bool:
        tree_sha, _, _, _ = snapshot_tree_identity(source_fd)
        return tree_sha != self.source_snapshot.tree_sha256

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self.view_fd)
        except OSError:
            pass
        shutil.rmtree(self.parent_dir, ignore_errors=True)


def _materialize_copy(source_fd: int, dest_root: Path) -> None:
    dest_fd = os.open(dest_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for relative, info in _walk_tree(source_fd):
            kind = _entry_kind(info.st_mode)
            if _is_ipc_or_special(kind):
                raise PrivateWorkspaceError("source_contains_special_inode", f"{kind}:{relative}")
            parent_rel, _, leaf = relative.rpartition("/")
            if parent_rel:
                dest_parent = dest_root / parent_rel
            else:
                dest_parent = dest_root
            if kind == "directory":
                (dest_root / relative).mkdir(mode=DIRECTORY_MODE, exist_ok=True)
            elif kind == "regular_file":
                src_parent, src_leaf = _open_parent(source_fd, relative)
                try:
                    src_handle = os.open(src_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src_parent)
                finally:
                    os.close(src_parent)
                try:
                    dest_path = dest_root / relative
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                    dst_handle = os.open(str(dest_path), flags, FILE_MODE)
                    try:
                        while True:
                            chunk = os.read(src_handle, 1 << 20)
                            if not chunk:
                                break
                            os.write(dst_handle, chunk)
                        os.fchmod(dst_handle, FILE_MODE)
                    finally:
                        os.close(dst_handle)
                finally:
                    os.close(src_handle)
            elif kind == "symlink":
                src_parent, src_leaf = _open_parent(source_fd, relative)
                try:
                    target = os.readlink(src_leaf, dir_fd=src_parent)
                finally:
                    os.close(src_parent)
                if not _symlink_is_exportable(target):
                    raise PrivateWorkspaceError("source_symlink_not_exportable", relative)
                os.symlink(target, dest_root / relative)
            else:  # pragma: no cover
                raise PrivateWorkspaceError("source_contains_special_inode", f"{kind}:{relative}")
    finally:
        os.close(dest_fd)


def _tree_map(root_fd: int) -> dict[str, tuple[str, str | None]]:
    """Map relative path -> (kind, payload) where payload is sha or symlink target."""

    mapping: dict[str, tuple[str, str | None]] = {}
    for relative, info in _walk_tree(root_fd):
        kind = _entry_kind(info.st_mode)
        if kind == "regular_file":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                sha, _ = _hash_regular_at(parent_fd, leaf)
            finally:
                os.close(parent_fd)
            mapping[relative] = (kind, sha)
        elif kind == "symlink":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                target = os.readlink(leaf, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            mapping[relative] = (kind, target)
        elif kind == "directory":
            mapping[relative] = (kind, None)
        else:
            mapping[relative] = (kind, None)
    return mapping


def compute_change_set(
    *,
    baseline_fd: int,
    private_fd: int,
) -> ProposedExportChangeSet:
    """Diff the private view against the snapshot baseline (source at snapshot time).

    ``baseline_fd`` is a descriptor onto a tree that still matches the source
    snapshot identity.  Callers that already detected source mutation must not
    call this intending to export.
    """

    before = _tree_map(baseline_fd)
    after = _tree_map(private_fd)
    operations: list[str] = []
    paths: list[str] = []
    unsupported: list[str] = []

    # Deletes: present before, absent after.  Delete deepest paths first later.
    for relative, (kind, _) in sorted(before.items()):
        if relative in after:
            continue
        if kind == "regular_file":
            operations.append("DELETE_REGULAR_FILE")
        elif kind == "directory":
            operations.append("DELETE_DIRECTORY")
        elif kind == "symlink":
            operations.append("DELETE_SYMLINK")
        else:
            unsupported.append(f"{kind}:{relative}")
            continue
        paths.append(relative)

    # Creates and updates.
    for relative, (kind, payload) in sorted(after.items()):
        if _is_ipc_or_special(kind):
            unsupported.append(f"{kind}:{relative}")
            continue
        previous = before.get(relative)
        if previous is None:
            if kind == "regular_file":
                operations.append("CREATE_REGULAR_FILE")
            elif kind == "directory":
                operations.append("CREATE_DIRECTORY")
            elif kind == "symlink":
                if payload is None or not _symlink_is_exportable(payload):
                    unsupported.append(f"symlink:{relative}")
                    continue
                operations.append("CREATE_SYMLINK")
            else:
                unsupported.append(f"{kind}:{relative}")
                continue
            paths.append(relative)
            continue
        prev_kind, prev_payload = previous
        if prev_kind == kind and prev_payload == payload:
            continue
        if kind == "regular_file" and prev_kind == "regular_file":
            operations.append("UPDATE_REGULAR_FILE")
            paths.append(relative)
        elif kind == "symlink" and prev_kind == "symlink":
            if payload is None or not _symlink_is_exportable(payload):
                unsupported.append(f"symlink:{relative}")
                continue
            operations.append("UPDATE_SYMLINK")
            paths.append(relative)
        else:
            # Type changes are refused rather than guessed.
            unsupported.append(f"type_change:{relative}:{prev_kind}->{kind}")

    digest = hashlib.sha256()
    for operation, path in zip(operations, paths):
        digest.update(operation.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.encode("utf-8"))
        digest.update(b"\n")
    return ProposedExportChangeSet.create(
        change_count=len(operations),
        operations=tuple(operations),
        paths=tuple(paths),
        change_set_sha256=digest.hexdigest(),
        unsupported_inode_count=len(unsupported),
        unsupported_inodes=tuple(unsupported),
    )


def apply_export(
    *,
    source_root_fd: int,
    private_fd: int,
    change_set: ProposedExportChangeSet,
    reservation_id: str,
    source_snapshot: SourceSnapshotIdentity,
    view_identity: PrivateExecutionViewIdentity,
) -> tuple[ExportReservation, ExportReceipt, ExportReconciliation]:
    """Apply a validated change set from the private view into the source root."""

    reservation = ExportReservation.create(
        reservation_id=reservation_id,
        source_snapshot_fingerprint=source_snapshot.record_fingerprint,
        private_view_fingerprint=view_identity.record_fingerprint,
        change_set_fingerprint=change_set.record_fingerprint,
        state="RESERVED",
    )
    if change_set.unsupported_inode_count:
        receipt = ExportReceipt.create(
            reservation_id=reservation_id,
            applied_count=0,
            state="REFUSED_UNSUPPORTED_INODE",
            refusal_code="unsupported_inode_in_private_view",
            change_set_fingerprint=change_set.record_fingerprint,
        )
        reconciliation = ExportReconciliation.create(
            reservation_id=reservation_id,
            verified=False,
            state="REFUSED_UNSUPPORTED_INODE",
            source_mutated=False,
            private_ipc_exported=False,
            partial_export=False,
            note="export refused: private view contains an unsupported inode type",
        )
        return reservation, receipt, reconciliation

    # Re-check source identity immediately before any mutation of the source.
    current_sha, _, _, _ = snapshot_tree_identity(source_root_fd)
    if current_sha != source_snapshot.tree_sha256:
        receipt = ExportReceipt.create(
            reservation_id=reservation_id,
            applied_count=0,
            state="REFUSED_SOURCE_MUTATED",
            refusal_code="source_mutated_during_effect",
            change_set_fingerprint=change_set.record_fingerprint,
        )
        reconciliation = ExportReconciliation.create(
            reservation_id=reservation_id,
            verified=False,
            state="REFUSED_SOURCE_MUTATED",
            source_mutated=True,
            private_ipc_exported=False,
            partial_export=False,
            note="export refused: authorized source mutated between snapshot and export",
        )
        return reservation, receipt, reconciliation

    applied = 0
    try:
        # Deletes deepest-first; creates shallowest-first.
        paired = list(zip(change_set.operations, change_set.paths))
        deletes = [(op, path) for op, path in paired if op.startswith("DELETE_")]
        others = [(op, path) for op, path in paired if not op.startswith("DELETE_")]
        deletes.sort(key=lambda item: item[1].count("/"), reverse=True)
        others.sort(key=lambda item: item[1].count("/"))
        for operation, relative in deletes + others:
            _apply_one(source_root_fd, private_fd, operation, relative)
            applied += 1
    except PrivateWorkspaceError as error:
        receipt = ExportReceipt.create(
            reservation_id=reservation_id,
            applied_count=applied,
            state="REFUSED_PARTIAL" if applied else "REFUSED_CRASH_CLASSIFIABLE",
            refusal_code=error.code,
            change_set_fingerprint=change_set.record_fingerprint,
        )
        reconciliation = ExportReconciliation.create(
            reservation_id=reservation_id,
            verified=False,
            state=receipt.state,
            source_mutated=False,
            private_ipc_exported=False,
            partial_export=applied > 0,
            note=f"export failed after {applied} operations: {error.code}",
        )
        return reservation, receipt, reconciliation

    receipt = ExportReceipt.create(
        reservation_id=reservation_id,
        applied_count=applied,
        state="APPLIED",
        refusal_code="none",
        change_set_fingerprint=change_set.record_fingerprint,
    )
    reconciliation = ExportReconciliation.create(
        reservation_id=reservation_id,
        verified=True,
        state="APPLIED",
        source_mutated=False,
        private_ipc_exported=False,
        partial_export=False,
        note="trusted export applied only validated regular-file, directory, and symlink changes",
    )
    return reservation, receipt, reconciliation


def _apply_one(source_fd: int, private_fd: int, operation: str, relative: str) -> None:
    parent_fd, leaf = _open_parent(source_fd, relative)
    try:
        if operation in {"DELETE_REGULAR_FILE", "DELETE_SYMLINK"}:
            try:
                os.unlink(leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_delete_failed", f"{relative}:{error.errno}") from error
            return
        if operation == "DELETE_DIRECTORY":
            try:
                os.rmdir(leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_rmdir_failed", f"{relative}:{error.errno}") from error
            return
        if operation == "CREATE_DIRECTORY":
            try:
                os.mkdir(leaf, DIRECTORY_MODE, dir_fd=parent_fd)
            except FileExistsError:
                info = os.lstat(leaf, dir_fd=parent_fd)
                if not stat.S_ISDIR(info.st_mode):
                    raise PrivateWorkspaceError("export_mkdir_conflict", relative)
            except OSError as error:
                raise PrivateWorkspaceError("export_mkdir_failed", f"{relative}:{error.errno}") from error
            return
        if operation in {"CREATE_REGULAR_FILE", "UPDATE_REGULAR_FILE"}:
            _export_regular_file(source_fd, private_fd, relative, parent_fd, leaf, replace=operation.startswith("UPDATE"))
            return
        if operation in {"CREATE_SYMLINK", "UPDATE_SYMLINK"}:
            priv_parent, priv_leaf = _open_parent(private_fd, relative)
            try:
                target = os.readlink(priv_leaf, dir_fd=priv_parent)
            finally:
                os.close(priv_parent)
            if not _symlink_is_exportable(target):
                raise PrivateWorkspaceError("export_symlink_not_exportable", relative)
            if operation.startswith("UPDATE"):
                try:
                    os.unlink(leaf, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            try:
                os.symlink(target, leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_symlink_failed", f"{relative}:{error.errno}") from error
            return
        raise PrivateWorkspaceError("export_unknown_operation", operation)
    finally:
        os.close(parent_fd)


def _export_regular_file(
    source_fd: int,
    private_fd: int,
    relative: str,
    parent_fd: int,
    leaf: str,
    *,
    replace: bool,
) -> None:
    priv_parent, priv_leaf = _open_parent(private_fd, relative)
    try:
        src = os.open(priv_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=priv_parent)
    finally:
        os.close(priv_parent)
    try:
        info = os.fstat(src)
        if not stat.S_ISREG(info.st_mode):
            raise PrivateWorkspaceError("export_not_regular_file", relative)
        tmp_name = f".admissible-export-{os.getpid()}-{leaf}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        try:
            dst = os.open(tmp_name, flags, FILE_MODE, dir_fd=parent_fd)
        except OSError as error:
            raise PrivateWorkspaceError("export_temp_create_failed", f"{relative}:{error.errno}") from error
        try:
            while True:
                chunk = os.read(src, 1 << 20)
                if not chunk:
                    break
                os.write(dst, chunk)
            os.fchmod(dst, FILE_MODE)
        finally:
            os.close(dst)
        try:
            os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError as error:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
            raise PrivateWorkspaceError("export_replace_failed", f"{relative}:{error.errno}") from error
    finally:
        os.close(src)


def private_ipc_host_visible(source_root: Path, private_view: PrivateExecutionView) -> tuple[str, ...]:
    """Special inodes under the private view that also appear under the source root."""

    source_fd = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _, _, _, source_specials = snapshot_tree_identity(source_fd)
    finally:
        os.close(source_fd)
    _, _, _, private_specials = snapshot_tree_identity(private_view.view_fd)
    # A private special is "host-visible" in the authorized workspace only if
    # the same relative path exists there as a special — which trusted export
    # must never create.  Paths that exist only under the private parent are
    # not part of the authorized workspace.
    source_set = set(source_specials)
    return tuple(item for item in private_specials if item in source_set)


__all__ = [
    "EXPORT_OPERATIONS",
    "EXPORT_STATES",
    "ExportReceipt",
    "ExportReconciliation",
    "ExportReservation",
    "M2_PRIVATE_WORKSPACE_SCHEMAS",
    "PrivateExecutionView",
    "PrivateExecutionViewIdentity",
    "PrivateWorkspaceError",
    "ProposedExportChangeSet",
    "SCHEMA_EXPORT_RECEIPT",
    "SCHEMA_EXPORT_RECONCILIATION",
    "SCHEMA_EXPORT_RESERVATION",
    "SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY",
    "SCHEMA_PROPOSED_EXPORT_CHANGE_SET",
    "SCHEMA_SOURCE_SNAPSHOT_IDENTITY",
    "SourceSnapshotIdentity",
    "apply_export",
    "compute_change_set",
    "private_ipc_host_visible",
    "snapshot_tree_identity",
]
